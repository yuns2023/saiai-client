//! `saiai uninstall`: a read-only discovery builds the plan; execution removes
//! only SAIAI-created files and values exactly equal to what SAIAI wrote.
use crate::{environment_scope, vscode};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
#[cfg(any(target_os = "linux", test))]
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{BufRead, ErrorKind, IsTerminal, Write};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", windows))]
use std::time::Duration;
use toml_edit::DocumentMut;

const PLAN_MARKER: &str = "SAIAI uninstall plan";
#[cfg(windows)]
const RELAUNCH_FLAG: &str = "--relaunched-from";
const ENVIRONMENTS_DIR: &str = "environments";
const SAIAI_HOME_FILES: &[&str] = &[
    crate::SAIAI_CONFIG_FILENAME,
    crate::SAIAI_CA_FILENAME,
    crate::SAIAI_CA_KEY_FILENAME,
    "initialization.lock",
    "saiai.lock",
    "saiai.pid",
    "saiai.log",
    "client-device-key",
    "client-device.json",
    "client-device.lock",
    "client-device-key.corrupt",
    "windows-packaged-proxy-lease.json",
];
const SAIAI_HOME_DIRS: &[&str] = &["log-followers", "desktop"];
const CLAUDE_GENERIC_ENV: &[&str] = &[
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "ENABLE_PROMPT_CACHING_1H",
    "ENABLE_TOOL_SEARCH",
    "CLAUDE_STREAM_IDLE_TIMEOUT_MS",
];
const CLAUDE_PROXY_ENV: &[&str] = &["http_proxy", "https_proxy", "all_proxy"];

#[derive(Debug, Default)]
pub(crate) struct Args {
    yes: bool,
    dry_run: bool,
    forget_unknown: bool,
    #[cfg(windows)]
    relaunched_from: Option<PathBuf>,
}

pub(crate) fn parse_args(args: &[String]) -> Result<Args> {
    let mut parsed = Args::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" | "-y" => parsed.yes = true,
            "--dry-run" => parsed.dry_run = true,
            "--forget-unknown-environments" => parsed.forget_unknown = true,
            #[cfg(windows)]
            RELAUNCH_FLAG => {
                index += 1;
                let path = args
                    .get(index)
                    .context("missing value for an internal flag")?;
                parsed.relaunched_from = Some(PathBuf::from(path));
            }
            other => bail!(
                "Unexpected argument for `uninstall`: {other}\n\n{}",
                crate::USAGE
            ),
        }
        index += 1;
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Area {
    Services,
    Claude,
    Codex,
    VSCode,
    Certificates,
    Data,
    Program,
}

const AREAS: [Area; 7] = [
    Area::Services,
    Area::Claude,
    Area::Codex,
    Area::VSCode,
    Area::Certificates,
    Area::Data,
    Area::Program,
];

impl Area {
    fn label(self) -> &'static str {
        match self {
            Self::Services => "Services",
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
            Self::VSCode => "VSCode",
            Self::Certificates => "Certificates",
            Self::Data => "SAIAI data",
            Self::Program => "Program",
        }
    }

    /// Data and program removal run only after everything else succeeded.
    fn gated(self) -> bool {
        matches!(self, Self::Data | Self::Program)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Pending,
    Done,
    Kept(String),
    Absent,
    Failed(String),
    Skipped,
    Manual(String),
}

impl Outcome {
    fn succeeded(&self) -> bool {
        !matches!(self, Self::Failed(_) | Self::Skipped | Self::Pending)
    }
}

enum Action {
    None,
    Edit {
        path: PathBuf,
        original: Vec<u8>,
        replacement: Option<Vec<u8>>,
    },
    RemoveFile(PathBuf),
    RemoveTree(PathBuf),
    RemoveEmptyDir(PathBuf),
    #[cfg(any(target_os = "linux", windows))]
    StopBackground {
        dir: PathBuf,
        isolated: bool,
        #[cfg(windows)]
        executables: Vec<PathBuf>,
    },
    #[cfg(target_os = "linux")]
    SystemdUnit {
        name: String,
        files: Vec<PathBuf>,
        loaded: bool,
    },
    #[cfg(target_os = "linux")]
    SystemdReload,
    #[cfg(target_os = "linux")]
    Nss {
        db: String,
        known: BTreeSet<String>,
    },
    /// Write `<env>/product-dir` once the steps in `after` succeeded.
    RecordProductDir {
        environment: PathBuf,
        product_dir: PathBuf,
        after: std::ops::Range<usize>,
    },
    #[cfg(target_os = "macos")]
    Launchd {
        target: String,
        plist: PathBuf,
    },
    #[cfg(windows)]
    Lease(PathBuf),
    #[cfg(windows)]
    RootCa(String),
    #[cfg(windows)]
    UserPath {
        directory: PathBuf,
        value: String,
        kind: String,
        replacement: String,
    },
}

struct Item {
    area: Area,
    text: String,
    action: Action,
    outcome: Outcome,
}

#[derive(Default)]
struct Plan {
    items: Vec<Item>,
    planned_paths: BTreeSet<PathBuf>,
    edit_targets: std::collections::BTreeMap<PathBuf, usize>,
    backups: Vec<PathBuf>,
}

impl Plan {
    fn act(&mut self, area: Area, text: impl Into<String>, action: Action) {
        if let Action::Edit {
            path, replacement, ..
        } = &action
        {
            let key = fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            if let Some(&index) = self.edit_targets.get(&key) {
                // Several references share one file: edit it once and keep it
                // when any reference is a symlink (those never delete).
                let item = &mut self.items[index];
                if let Action::Edit {
                    replacement: existing,
                    ..
                } = &mut item.action
                {
                    if existing.is_none() {
                        existing.clone_from(replacement);
                    } else if replacement.is_some() && existing != replacement {
                        item.action = Action::None;
                        item.outcome = Outcome::Failed(
                            "is shared by several SAIAI configurations that would remove different values; clean it manually".into(),
                        );
                    }
                }
                return;
            }
            self.edit_targets.insert(key, self.items.len());
        }
        self.items.push(Item {
            area,
            text: text.into(),
            action,
            outcome: Outcome::Pending,
        });
    }

    fn note(&mut self, area: Area, text: impl Into<String>, outcome: Outcome) {
        self.items.push(Item {
            area,
            text: text.into(),
            action: Action::None,
            outcome,
        });
    }

    fn remove_file(&mut self, area: Area, path: PathBuf) {
        if self.planned_paths.insert(path.clone()) {
            self.act(
                area,
                format!("remove {}", path.display()),
                Action::RemoveFile(path),
            );
        }
    }

    fn remove_tree(&mut self, area: Area, path: PathBuf) {
        if self.planned_paths.insert(path.clone()) {
            self.act(
                area,
                format!("remove directory {}", path.display()),
                Action::RemoveTree(path),
            );
        }
    }

    fn remove_empty_dir(&mut self, area: Area, path: PathBuf) {
        if self.planned_paths.insert(path.clone()) {
            self.act(
                area,
                format!("remove {} if it is empty", path.display()),
                Action::RemoveEmptyDir(path),
            );
        }
    }

    fn pending(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.outcome == Outcome::Pending)
            .count()
    }
}

struct Instance {
    dir: PathBuf,
    isolated: bool,
    env_name: Option<String>,
    product: Option<&'static str>,
    listen: Option<String>,
    ca_cert: Option<String>,
    claude_keys: Vec<String>,
    matched: bool,
    /// config.json exists; `has_config` when it is a SAIAI configuration.
    config_present: bool,
    has_config: bool,
    product_dir: Option<PathBuf>,
}

struct ProductDir {
    product: &'static str,
    dir: PathBuf,
    default: bool,
    candidates: Vec<usize>,
}

struct Discovery {
    home: PathBuf,
    root: PathBuf,
    home_is_link: bool,
    linked_environments: Vec<PathBuf>,
    instances: Vec<Instance>,
    products: Vec<ProductDir>,
    install_dirs: Vec<PathBuf>,
    default_install_dir: Option<PathBuf>,
    #[cfg(windows)]
    worker_executables: Vec<PathBuf>,
}

pub(crate) fn run(args: Args) -> Result<()> {
    let discovery = discover_layout(&args)?;
    let mut plan = build_plan(&discovery, &args)?;
    print_plan(&discovery, &plan);
    if args.dry_run {
        println!();
        println!("Dry run: nothing was changed.");
        return Ok(());
    }
    if plan.pending() == 0 {
        println!();
        println!("Nothing to remove.");
        return finish(&plan);
    }
    if !args.yes && !confirm()? {
        bail!("Uninstall cancelled; nothing was changed.");
    }
    #[cfg(windows)]
    if args.relaunched_from.is_none()
        && let Some(code) = relaunch_outside_install_dir(&plan, &args)?
    {
        std::process::exit(code);
    }
    execute(&mut plan, &args);
    print_summary(&plan);
    #[cfg(windows)]
    if args.relaunched_from.is_some() {
        schedule_temporary_copy_removal();
    }
    finish(&plan)
}

fn discover_layout(args: &Args) -> Result<Discovery> {
    #[cfg(not(windows))]
    let _ = args;
    let (home, root) = environment_scope::layout()?;
    let mut instances = Vec::new();
    let mut linked_environments = Vec::new();
    if root.is_dir() {
        instances.push(read_instance(root.clone(), false, None, None));
        let environments = root.join(ENVIRONMENTS_DIR);
        match fs::read_dir(&environments) {
            Ok(entries) => {
                let mut found = Vec::new();
                for entry in entries {
                    let entry = entry
                        .with_context(|| format!("failed to list {}", environments.display()))?;
                    let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    let Some(product) = environment_scope::environment_product(&name) else {
                        continue;
                    };
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        found.push((name, product));
                    } else if entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
                        linked_environments.push(entry.path());
                    }
                }
                found.sort();
                for (name, product) in found {
                    let dir = environments.join(&name);
                    instances.push(read_instance(dir, true, Some(name), Some(product)));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to list {}", environments.display()));
            }
        }
    }

    let mut products = Vec::new();
    for (product, default_name) in [("claude", ".claude"), ("codex", ".codex")] {
        let default_dir = environment_scope::normalize(&home.join(default_name))?;
        products.push(ProductDir {
            product,
            dir: default_dir.clone(),
            default: true,
            candidates: if instances.is_empty() {
                Vec::new()
            } else {
                vec![0]
            },
        });
        if let Some(dir) = environment_scope::product_override(product)?
            && dir != default_dir
        {
            let name = environment_scope::environment_name(product, &dir);
            let candidates = match instances
                .iter()
                .position(|instance| instance.env_name.as_deref() == Some(name.as_str()))
            {
                Some(index) => vec![index],
                // Older clients configured project directories against the
                // shared default proxy before isolated environments existed.
                None if !instances.is_empty() => vec![0],
                None => Vec::new(),
            };
            products.push(ProductDir {
                product,
                dir,
                default: false,
                candidates,
            });
        }
    }
    for (index, instance) in instances.iter().enumerate() {
        let (Some(product), Some(dir)) = (instance.product, &instance.product_dir) else {
            continue;
        };
        if !products
            .iter()
            .any(|known| known.product == product && known.dir == *dir)
        {
            products.push(ProductDir {
                product,
                dir: dir.clone(),
                default: false,
                candidates: vec![index],
            });
        }
    }
    for product in &products {
        for index in &product.candidates {
            instances[*index].matched = true;
        }
    }
    if let Some(default) = instances.first_mut() {
        default.matched = true;
    }

    #[cfg(windows)]
    let exe = match &args.relaunched_from {
        Some(path) => Some(path.clone()),
        None => env::current_exe().ok(),
    };
    #[cfg(not(windows))]
    let exe = env::current_exe().ok();
    let exe_dir = exe.as_ref().and_then(|exe| {
        let name = exe.file_name()?.to_str()?;
        matches!(name, "saiai" | "saiai.exe")
            .then(|| exe.parent().map(Path::to_path_buf))
            .flatten()
    });
    let default_install_dir = default_install_dir();
    let mut install_dirs = Vec::new();
    match crate::env_dir_override("SAIAI_INSTALL_DIR") {
        Some(dir) => install_dirs.push(dir),
        None => install_dirs.extend(default_install_dir.clone()),
    }
    if let Some(dir) = exe_dir
        && !install_dirs.iter().any(|known| same_directory(known, &dir))
    {
        install_dirs.push(dir);
    }
    // Legacy bare-PID workers are recognized by their exact executable, which
    // is the installed program even when this process runs from a copy.
    #[cfg(windows)]
    let worker_executables = install_dirs
        .iter()
        .map(|dir| dir.join("saiai.exe"))
        .chain(exe)
        .chain(env::current_exe().ok())
        .collect();
    let raw_home = crate::env_dir_override("SAIAI_HOME")
        .or_else(|| crate::home_dir().map(|home| home.join(".saiai")));
    let home_is_link = raw_home.is_some_and(|path| {
        fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
    });
    Ok(Discovery {
        home,
        root,
        home_is_link,
        linked_environments,
        instances,
        products,
        install_dirs,
        default_install_dir,
        #[cfg(windows)]
        worker_executables,
    })
}

fn read_instance(
    dir: PathBuf,
    isolated: bool,
    env_name: Option<String>,
    product: Option<&'static str>,
) -> Instance {
    let mut instance = Instance {
        dir,
        isolated,
        env_name,
        product,
        listen: None,
        ca_cert: None,
        claude_keys: Vec::new(),
        matched: false,
        config_present: false,
        has_config: false,
        product_dir: None,
    };
    if let (Some(product), Some(name)) = (instance.product, &instance.env_name)
        && let Ok(raw) =
            fs::read_to_string(instance.dir.join(environment_scope::PRODUCT_DIR_FILENAME))
    {
        let dir = PathBuf::from(raw.trim_end_matches(['\r', '\n']));
        // Trust the record only when it names exactly this environment.
        if dir.is_absolute() && environment_scope::environment_name(product, &dir) == *name {
            instance.product_dir = Some(dir);
        }
    }
    let raw = match fs::read(instance.dir.join(crate::SAIAI_CONFIG_FILENAME)) {
        Ok(raw) => raw,
        Err(error) => {
            instance.config_present = error.kind() != ErrorKind::NotFound;
            return instance;
        }
    };
    instance.config_present = true;
    let Ok(config) = serde_json::from_slice::<Value>(&raw) else {
        return instance;
    };
    instance.has_config = is_saiai_config(&config);
    if !instance.has_config {
        return instance;
    }
    let text = |value: &Value| {
        value
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
    };
    instance.listen = text(&config["listen"]);
    instance.ca_cert = text(&config["ca_cert_path"]);
    match config["providers"].get("claude") {
        Some(claude) => instance.claude_keys.extend(text(&claude["api_key"])),
        None => instance.claude_keys.extend(text(&config["api_key"])),
    }
    instance
}

/// Fields every SAIAI config.json carries (version 2, or the version-less v1 shape).
fn is_saiai_config(config: &Value) -> bool {
    let text = |key: &str| config.get(key).is_some_and(Value::is_string);
    config.is_object()
        && text("listen")
        && text("ca_cert_path")
        && match config.get("version") {
            Some(version) => {
                version.as_u64() == Some(u64::from(crate::SAIAI_CONFIG_VERSION))
                    || version.as_u64() == Some(1)
            }
            None => text("base_url") && text("api_key"),
        }
}

/// An `environments/<name>` directory SAIAI created: a real directory holding
/// a SAIAI config.json, or only the product-dir record.
fn owned_environment(instance: &Instance) -> bool {
    if !fs::symlink_metadata(&instance.dir).is_ok_and(|meta| meta.is_dir()) {
        return false;
    }
    if instance.has_config {
        return true;
    }
    // Without a config, only an environment holding nothing but SAIAI files.
    let Ok(entries) = fs::read_dir(&instance.dir) else {
        return false;
    };
    let mut record = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if name == environment_scope::PRODUCT_DIR_FILENAME {
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                return false;
            }
            record = true;
        } else if name == crate::SAIAI_CONFIG_FILENAME
            || !is_saiai_home_file(name)
            || !entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            return false;
        }
    }
    record && !instance.config_present
}

fn build_plan(discovery: &Discovery, args: &Args) -> Result<Plan> {
    let mut plan = Plan::default();
    plan_services(discovery, &mut plan)?;
    for product in &discovery.products {
        match product.product {
            "claude" => plan_claude(discovery, product, &mut plan),
            _ => plan_codex(discovery, product, &mut plan),
        }
        // A legacy environment mapped through the current variable is recorded,
        // so later runs find it without that variable.
        if let [index] = product.candidates[..]
            && let Some(instance) = discovery.instances.get(index)
            && !product.default
            && instance.env_name.as_deref()
                == Some(environment_scope::environment_name(product.product, &product.dir).as_str())
            && instance.has_config
            && fs::symlink_metadata(instance.dir.join(environment_scope::PRODUCT_DIR_FILENAME))
                .is_err_and(|error| error.kind() == ErrorKind::NotFound)
            && fs::symlink_metadata(&instance.dir).is_ok_and(|meta| meta.is_dir())
        {
            // Every earlier step, including edits shared with another product
            // directory, must have succeeded.
            let after = 0..plan.items.len();
            plan.act(
                if product.product == "claude" {
                    Area::Claude
                } else {
                    Area::Codex
                },
                format!(
                    "record {} as the project directory of {}",
                    product.dir.display(),
                    instance.dir.display()
                ),
                Action::RecordProductDir {
                    environment: instance.dir.clone(),
                    product_dir: product.dir.clone(),
                    after,
                },
            );
        }
    }
    // Its config.json is the only evidence of what SAIAI wrote into that
    // project, so keep it unless the user explicitly gives up on the project.
    for instance in discovery
        .instances
        .iter()
        .filter(|i| !i.matched && i.has_config)
    {
        let (area, variable) = match instance.product {
            Some("claude") => (Area::Claude, "CLAUDE_CONFIG_DIR"),
            _ => (Area::Codex, "CODEX_HOME"),
        };
        let text = format!(
            "environment {}: its project configuration directory is unknown",
            instance.dir.display()
        );
        if args.forget_unknown {
            plan.note(
                area,
                text,
                Outcome::Manual(
                    "not cleaned (--forget-unknown-environments); its service is stopped and its data deleted"
                        .into(),
                ),
            );
        } else {
            plan.note(
                area,
                text,
                Outcome::Failed(format!(
                    "rerun with {variable}=<that project's directory> set to clean it, or add --forget-unknown-environments to leave that project's settings as they are"
                )),
            );
        }
    }
    plan_vscode(discovery, &mut plan);
    plan_certificates(discovery, &mut plan)?;
    plan_data(discovery, &mut plan)?;
    plan_program(discovery, &mut plan)?;
    Ok(plan)
}

/// Edits go to a symlink's target so the user's link is kept.
fn edit_target(path: &Path, area: Area, plan: &mut Plan) -> Option<(PathBuf, String, bool)> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => match fs::canonicalize(path) {
            Ok(target) => Some((
                target.clone(),
                format!("{} (symlink to {})", path.display(), target.display()),
                true,
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                plan.note(
                    area,
                    path.display().to_string(),
                    Outcome::Failed(format!("cannot resolve symbolic link: {error}")),
                );
                None
            }
        },
        _ => Some((path.to_path_buf(), path.display().to_string(), false)),
    }
}

fn mask_secret(value: &str) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    if characters.len() < 12 {
        return "****".into();
    }
    let tail = characters[characters.len() - 4..]
        .iter()
        .collect::<String>();
    format!("****{tail}")
}

fn read_existing(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn json_bytes(map: &Map<String, Value>) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec_pretty(&Value::Object(map.clone())).expect("JSON serialization");
    bytes.push(b'\n');
    bytes
}

fn parse_json_object(bytes: &[u8]) -> Option<Map<String, Value>> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Some(Map::new());
    }
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(crate::as_object)
}

fn collect_backups(dir: &Path, exclude_saiai_ca: bool, plan: &mut Plan) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut found = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            (name.contains(".bak-")
                && !(exclude_saiai_ca && name.starts_with("saiai-ca."))
                && entry.file_type().is_ok_and(|kind| kind.is_file()))
            .then(|| entry.path())
        })
        .collect::<Vec<_>>();
    found.sort();
    plan.backups.extend(found);
}

// ---------------------------------------------------------------- Claude

struct ClaudeOwned {
    api_keys: Vec<String>,
    proxies: Vec<String>,
    ca_paths: Vec<String>,
}

#[derive(Debug, PartialEq)]
struct ClaudeRemoval {
    settings: Map<String, Value>,
    removed: Vec<String>,
    modified: Vec<String>,
    generic: Vec<String>,
}

fn claude_settings_removal(settings: &Map<String, Value>, owned: &ClaudeOwned) -> ClaudeRemoval {
    let mut result = ClaudeRemoval {
        settings: settings.clone(),
        removed: Vec::new(),
        modified: Vec::new(),
        generic: Vec::new(),
    };
    let Some(env) = settings.get("env").and_then(Value::as_object) else {
        return result;
    };
    let mut remaining = env.clone();
    let mut check = |key: &str, owned_values: &[String]| {
        let Some(value) = env.get(key) else {
            return;
        };
        if value
            .as_str()
            .is_some_and(|value| owned_values.iter().any(|owned| owned == value))
        {
            remaining.remove(key);
            result.removed.push(key.to_string());
        } else {
            result.modified.push(key.to_string());
        }
    };
    check("CLAUDE_CODE_OAUTH_TOKEN", &owned.api_keys);
    for key in CLAUDE_PROXY_ENV {
        check(key, &owned.proxies);
    }
    check("no_proxy", &[crate::DEFAULT_NO_PROXY.to_string()]);
    check("NODE_EXTRA_CA_CERTS", &owned.ca_paths);
    result.generic = CLAUDE_GENERIC_ENV
        .iter()
        .filter(|key| remaining.contains_key(**key))
        .map(|key| key.to_string())
        .collect();
    if remaining.is_empty() {
        result.settings.remove("env");
    } else {
        result
            .settings
            .insert("env".to_string(), Value::Object(remaining));
    }
    result
}

fn plan_claude(discovery: &Discovery, product: &ProductDir, plan: &mut Plan) {
    let candidates = product
        .candidates
        .iter()
        .map(|index| &discovery.instances[*index])
        .collect::<Vec<_>>();
    let owned = ClaudeOwned {
        api_keys: candidates
            .iter()
            .flat_map(|instance| instance.claude_keys.clone())
            .collect(),
        proxies: candidates
            .iter()
            .filter_map(|instance| instance.listen.as_ref())
            .map(|listen| format!("http://{listen}"))
            .collect(),
        ca_paths: candidates
            .iter()
            .filter_map(|instance| instance.ca_cert.clone())
            .collect(),
    };
    collect_backups(&product.dir, true, plan);
    if product.default {
        collect_prefixed_backups(&discovery.home, ".claude.json.bak-", plan);
    }
    let Some((path, label, _)) =
        edit_target(&product.dir.join("settings.json"), Area::Claude, plan)
    else {
        return;
    };
    match read_existing(&path) {
        Ok(None) => {}
        Err(error) => plan.note(
            Area::Claude,
            label.clone(),
            Outcome::Failed(format!("{error:#}")),
        ),
        Ok(Some(original)) => match parse_json_object(&original) {
            None => plan.note(
                Area::Claude,
                label.clone(),
                Outcome::Failed("could not be parsed as a JSON object; not changed".into()),
            ),
            Some(settings) => {
                let removal = claude_settings_removal(&settings, &owned);
                let modified_reason = if product.candidates.is_empty() {
                    "no SAIAI configuration was found to verify that SAIAI wrote it"
                } else {
                    "value differs from what SAIAI wrote"
                };
                if !removal.removed.is_empty() {
                    let described = removal
                        .removed
                        .iter()
                        .map(|key| {
                            if key == "CLAUDE_CODE_OAUTH_TOKEN" {
                                let value = settings["env"][key].as_str().unwrap_or_default();
                                format!("env.{key} (SAIAI API key {})", mask_secret(value))
                            } else {
                                format!("env.{key}")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    plan.act(
                        Area::Claude,
                        format!("edit {}: remove {described}", label),
                        Action::Edit {
                            path: path.clone(),
                            original,
                            replacement: Some(json_bytes(&removal.settings)),
                        },
                    );
                }
                if !removal.modified.is_empty() {
                    plan.note(
                        Area::Claude,
                        format!("{}: env.{}", label, removal.modified.join(", env.")),
                        Outcome::Kept(modified_reason.into()),
                    );
                }
                if !removal.generic.is_empty() {
                    plan.note(
                        Area::Claude,
                        format!("{}: env.{}", label, removal.generic.join(", env.")),
                        Outcome::Kept(
                            "generic Claude Code settings; may have been set by SAIAI".into(),
                        ),
                    );
                }
            }
        },
    }
}

fn collect_prefixed_backups(dir: &Path, prefix: &str, plan: &mut Plan) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut found = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(prefix))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    found.sort();
    plan.backups.extend(found);
}

// ----------------------------------------------------------------- Codex

#[derive(Debug, PartialEq)]
enum AuthRemoval {
    Unchanged {
        foreign_tokens: bool,
    },
    Changed {
        auth: Map<String, Value>,
        removed: Vec<&'static str>,
    },
}

fn is_codex_placeholder_tokens(tokens: &Value) -> bool {
    let Some(tokens) = tokens.as_object() else {
        return false;
    };
    let expected = [
        ("id_token", crate::CODEX_PLACEHOLDER_ID_TOKEN),
        ("access_token", crate::CODEX_PLACEHOLDER_ACCESS_TOKEN),
        ("refresh_token", ""),
        ("account_id", crate::CODEX_PLACEHOLDER_ACCOUNT_ID),
    ];
    tokens.len() == expected.len()
        && expected
            .iter()
            .all(|(key, value)| tokens.get(*key).and_then(Value::as_str) == Some(*value))
}

fn codex_auth_removal(auth: &Map<String, Value>) -> AuthRemoval {
    let Some(tokens) = auth.get("tokens") else {
        return AuthRemoval::Unchanged {
            foreign_tokens: false,
        };
    };
    if !is_codex_placeholder_tokens(tokens) {
        return AuthRemoval::Unchanged {
            foreign_tokens: true,
        };
    }
    let mut updated = auth.clone();
    updated.remove("tokens");
    let mut removed = vec!["tokens"];
    if auth.get("auth_mode").and_then(Value::as_str) == Some("chatgptAuthTokens") {
        updated.remove("auth_mode");
        removed.push("auth_mode");
    }
    if auth.get("OPENAI_API_KEY").is_some_and(Value::is_null) {
        updated.remove("OPENAI_API_KEY");
        removed.push("OPENAI_API_KEY");
    }
    if auth.get("last_refresh").is_some_and(Value::is_string) {
        updated.remove("last_refresh");
        removed.push("last_refresh");
    }
    AuthRemoval::Changed {
        auth: updated,
        removed,
    }
}

fn codex_generic_config(document: &DocumentMut) -> Vec<&'static str> {
    let mut kept = Vec::new();
    if document
        .get("model_provider")
        .and_then(|item| item.as_str())
        == Some("openai")
    {
        kept.push("model_provider");
    }
    if document
        .get(crate::CODEX_ENVIRONMENT_CONTEXT_TIME_KEY)
        .and_then(|item| item.as_bool())
        == Some(false)
    {
        kept.push(crate::CODEX_ENVIRONMENT_CONTEXT_TIME_KEY);
    }
    if document
        .get("features")
        .and_then(|item| item.get("respect_system_proxy"))
        .and_then(|item| item.as_bool())
        == Some(crate::codex_respect_system_proxy_enabled())
    {
        kept.push("features.respect_system_proxy");
    }
    kept
}

fn plan_codex(_discovery: &Discovery, product: &ProductDir, plan: &mut Plan) {
    if let Some((env_path, env_label, env_linked)) =
        edit_target(&product.dir.join(".env"), Area::Codex, plan)
    {
        match read_existing(&env_path) {
            Ok(None) => {}
            Err(error) => plan.note(
                Area::Codex,
                env_label.clone(),
                Outcome::Failed(format!("{error:#}")),
            ),
            Ok(Some(original)) => match String::from_utf8(original.clone()) {
                Err(_) => plan.note(
                    Area::Codex,
                    env_label.clone(),
                    Outcome::Failed("is not valid UTF-8; not changed".into()),
                ),
                Ok(raw) => {
                    let stripped = crate::strip_codex_ide_env_block(&raw);
                    if !stripped.complete {
                        plan.note(
                            Area::Codex,
                            env_label.clone(),
                            Outcome::Failed(
                                "the SAIAI managed block has no END marker; not changed".into(),
                            ),
                        );
                    } else if stripped.content != raw {
                        let delete = stripped.content.trim().is_empty() && !env_linked;
                        plan.act(
                            Area::Codex,
                            if delete {
                                format!(
                                    "remove {} (only the SAIAI managed block remains)",
                                    env_label
                                )
                            } else {
                                format!("edit {}: remove the SAIAI managed block", env_label)
                            },
                            Action::Edit {
                                path: env_path.clone(),
                                original,
                                replacement: (!delete).then(|| stripped.content.into_bytes()),
                            },
                        );
                    }
                }
            },
        }
    }

    if let Some((auth_path, auth_label, auth_linked)) =
        edit_target(&product.dir.join("auth.json"), Area::Codex, plan)
    {
        match read_existing(&auth_path) {
            Ok(None) => {}
            Err(error) => plan.note(
                Area::Codex,
                auth_label.clone(),
                Outcome::Failed(format!("{error:#}")),
            ),
            Ok(Some(original)) => match parse_json_object(&original) {
                None => plan.note(
                    Area::Codex,
                    auth_label.clone(),
                    Outcome::Failed("could not be parsed as a JSON object; not changed".into()),
                ),
                Some(auth) => match codex_auth_removal(&auth) {
                    AuthRemoval::Changed { auth, removed } => {
                        let delete = auth.is_empty() && !auth_linked;
                        plan.act(
                            Area::Codex,
                            if delete {
                                format!(
                                    "remove {} (only the SAIAI placeholder login remains)",
                                    auth_label
                                )
                            } else {
                                format!("edit {}: remove {}", auth_label, removed.join(", "))
                            },
                            Action::Edit {
                                path: auth_path.clone(),
                                original,
                                replacement: (!delete).then(|| json_bytes(&auth)),
                            },
                        );
                    }
                    AuthRemoval::Unchanged {
                        foreign_tokens: true,
                    } => plan.note(
                        Area::Codex,
                        format!("{}: tokens", auth_label),
                        Outcome::Kept("not the SAIAI placeholder login".into()),
                    ),
                    AuthRemoval::Unchanged { .. } => {}
                },
            },
        }
    }

    if product.dir.is_dir() {
        let configs = crate::managed_codex_config_paths(&product.dir).unwrap_or_default();
        for path in &configs {
            let parsed = fs::read_to_string(path)
                .ok()
                .and_then(|raw| raw.parse::<DocumentMut>().ok());
            match parsed {
                Some(document) => {
                    let kept = codex_generic_config(&document);
                    if !kept.is_empty() {
                        plan.note(
                            Area::Codex,
                            format!("{}: {}", path.display(), kept.join(", ")),
                            Outcome::Kept(
                                "generic Codex settings; may have been set by SAIAI".into(),
                            ),
                        );
                    }
                }
                None => plan.note(
                    Area::Codex,
                    path.display().to_string(),
                    Outcome::Kept("could not be parsed; not inspected or changed".into()),
                ),
            }
        }
        if !configs.is_empty() {
            plan.note(
                Area::Codex,
                format!(
                    "{}: keys SAIAI removed during setup (base_url, openai_base_url, chatgpt_base_url, model_providers, features.responses_websockets[_v2])",
                    product.dir.display()
                ),
                Outcome::Kept(
                    "not restored; the config.toml.bak-* backups next to it hold earlier versions"
                        .into(),
                ),
            );
        }
        collect_backups(&product.dir, false, plan);
    }
}

// ---------------------------------------------------------------- VSCode

fn plan_vscode(discovery: &Discovery, plan: &mut Plan) {
    let Some(home) = crate::home_dir() else {
        return;
    };
    let proxies = discovery
        .instances
        .iter()
        .filter_map(|instance| instance.listen.as_deref())
        .filter_map(vscode::managed_proxy_url)
        .collect::<Vec<_>>();
    for settings in vscode::settings_paths(&home) {
        let Some((path, label, _)) = edit_target(&settings, Area::VSCode, plan) else {
            continue;
        };
        let original = match read_existing(&path) {
            Ok(Some(original)) => original,
            Ok(None) => continue,
            Err(error) => {
                plan.note(
                    Area::VSCode,
                    label.clone(),
                    Outcome::Failed(format!("{error:#}")),
                );
                continue;
            }
        };
        let Ok(raw) = String::from_utf8(original.clone()) else {
            continue;
        };
        match vscode::remove_managed_proxy(&raw, &proxies) {
            Ok(vscode::ManagedRemoval::NotManaged) => {}
            Ok(vscode::ManagedRemoval::OtherProxy(proxy)) => plan.note(
                Area::VSCode,
                label.clone(),
                Outcome::Kept(format!(
                    "managed for {proxy}, which is not a configured SAIAI proxy"
                )),
            ),
            Ok(vscode::ManagedRemoval::Owned {
                content,
                removed,
                kept,
            }) => {
                let mut listed = removed.join(", ");
                if !listed.is_empty() {
                    listed.push_str(" and ");
                }
                plan.act(
                    Area::VSCode,
                    format!("edit {}: remove {listed}the SAIAI marker", label),
                    Action::Edit {
                        path: path.clone(),
                        original,
                        replacement: Some(content.into_bytes()),
                    },
                );
                if !kept.is_empty() {
                    plan.note(
                        Area::VSCode,
                        format!("{}: {}", label, kept.join(", ")),
                        Outcome::Kept("value differs from what SAIAI wrote".into()),
                    );
                }
            }
            Err(error) => plan.note(
                Area::VSCode,
                label.clone(),
                Outcome::Failed(format!("{error:#}; not changed")),
            ),
        }
    }
}

// ---------------------------------------------------------- Certificates

fn ca_backup_paths(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let prefixes = [
        format!("{}.bak-", crate::SAIAI_CA_FILENAME),
        format!("{}.bak-", crate::SAIAI_CA_KEY_FILENAME),
    ];
    let mut paths = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| prefixes.iter().any(|prefix| name.starts_with(prefix)))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn claude_dirs(discovery: &Discovery) -> Vec<&Path> {
    discovery
        .products
        .iter()
        .filter(|product| product.product == "claude")
        .map(|product| product.dir.as_path())
        .collect()
}

fn known_ca_files(discovery: &Discovery) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    let mut directories = discovery
        .instances
        .iter()
        .map(|instance| instance.dir.as_path())
        .collect::<Vec<_>>();
    directories.extend(claude_dirs(discovery));
    for instance in &discovery.instances {
        if let Some(path) = &instance.ca_cert {
            files.insert(PathBuf::from(path));
        }
    }
    for directory in directories {
        files.insert(directory.join(crate::SAIAI_CA_FILENAME));
        for path in ca_backup_paths(directory) {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(crate::SAIAI_CA_FILENAME))
            {
                files.insert(path);
            }
        }
    }
    files.into_iter().filter(|path| path.is_file()).collect()
}

#[cfg(any(target_os = "linux", test))]
fn certificate_fingerprints(pem: &[u8]) -> Vec<String> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .filter_map(|certificate| certificate.ok())
        .map(|certificate| format!("{:x}", Sha256::digest(certificate.as_ref())))
        .collect()
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
enum NssDecision {
    Remove,
    Keep,
}

#[cfg(any(target_os = "linux", test))]
fn nss_decision(exported_pem: &[u8], known: &BTreeSet<String>) -> NssDecision {
    let fingerprints = certificate_fingerprints(exported_pem);
    if !fingerprints.is_empty() && fingerprints.iter().all(|value| known.contains(value)) {
        NssDecision::Remove
    } else {
        NssDecision::Keep
    }
}

fn plan_certificates(discovery: &Discovery, plan: &mut Plan) -> Result<()> {
    let files = known_ca_files(discovery);
    #[cfg(target_os = "linux")]
    plan_nss(&files, plan);
    #[cfg(windows)]
    plan_windows_certificates(discovery, &files, plan)?;
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = (discovery, files, plan);
    Ok(())
}

#[cfg(target_os = "linux")]
/// `Ok(None)` when the nickname is absent; launch failures are errors.
fn certutil_export(db: &str) -> Result<Option<Vec<u8>>> {
    let output = std::process::Command::new("certutil")
        .args([
            "-L",
            "-d",
            db,
            "-n",
            crate::SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME,
            "-a",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .context("failed to run certutil")?;
    Ok(output.status.success().then_some(output.stdout))
}

#[cfg(target_os = "linux")]
fn plan_nss(files: &[PathBuf], plan: &mut Plan) {
    let Some(home) = crate::home_dir() else {
        return;
    };
    let db_dir = crate::nss_database_dir(&home);
    if !db_dir.is_dir() || !crate::nss_certutil_available() {
        return;
    }
    let db = format!("sql:{}", db_dir.display());
    let exported = match certutil_export(&db) {
        Ok(Some(exported)) => exported,
        Ok(None) => return,
        Err(error) => {
            plan.note(
                Area::Certificates,
                format!("NSS database {}", db_dir.display()),
                Outcome::Failed(format!("{error:#}")),
            );
            return;
        }
    };
    let known = files
        .iter()
        .filter_map(|path| fs::read(path).ok())
        .flat_map(|pem| certificate_fingerprints(&pem))
        .collect::<BTreeSet<_>>();
    let label = format!(
        "NSS certificate {} in {}",
        crate::SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME,
        db_dir.display()
    );
    match nss_decision(&exported, &known) {
        NssDecision::Remove => plan.act(
            Area::Certificates,
            format!("remove {label}"),
            Action::Nss { db, known },
        ),
        NssDecision::Keep => plan.note(
            Area::Certificates,
            label,
            Outcome::Kept("not a known SAIAI CA".into()),
        ),
    }
}

// ------------------------------------------------------------------ Data

fn is_saiai_home_file(name: &str) -> bool {
    SAIAI_HOME_FILES.iter().any(|file| {
        name == *file
            || name.starts_with(&format!("{file}.bak-"))
            || name.starts_with(&format!(".{file}.saiai-tmp-"))
    })
}

fn is_claude_ca_file(name: &str) -> bool {
    [crate::SAIAI_CA_FILENAME, crate::SAIAI_CA_KEY_FILENAME]
        .iter()
        .any(|file| name == *file || name.starts_with(&format!("{file}.bak-")))
}

fn matching_files(dir: &Path, filter: fn(&str) -> bool) -> Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to list {}", dir.display()));
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to list {}", dir.display()))?;
        if entry.file_name().to_str().is_some_and(filter)
            && entry.file_type().is_ok_and(|kind| !kind.is_dir())
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn plan_data(discovery: &Discovery, plan: &mut Plan) -> Result<()> {
    let root = &discovery.root;
    let is_link =
        |path: &Path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
    let link_kept = || Outcome::Kept("symbolic link; nothing is removed through it".into());
    if root.is_dir() && discovery.home_is_link {
        plan.note(
            Area::Data,
            root.display().to_string(),
            Outcome::Kept(
                "SAIAI home is reached through a symbolic link; no SAIAI data inside it is deleted (its services are still stopped), delete it yourself"
                    .into(),
            ),
        );
    } else if root.is_dir() {
        let saiai_config = discovery.instances.first().is_some_and(|i| i.has_config);
        for path in matching_files(root, is_saiai_home_file)? {
            if path
                .file_name()
                .is_some_and(|name| name == crate::SAIAI_CONFIG_FILENAME)
                && !saiai_config
            {
                plan.note(
                    Area::Data,
                    path.display().to_string(),
                    Outcome::Kept("not a SAIAI configuration".into()),
                );
                continue;
            }
            plan.remove_file(Area::Data, path);
        }
        for name in SAIAI_HOME_DIRS {
            let path = root.join(name);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => plan.remove_tree(Area::Data, path),
                Ok(_) => plan.note(Area::Data, path.display().to_string(), link_kept()),
                Err(_) => {}
            }
        }
        let environments = root.join(ENVIRONMENTS_DIR);
        let environments_linked = is_link(&environments);
        for instance in discovery.instances.iter().filter(|i| i.isolated) {
            let label = instance.dir.display().to_string();
            if environments_linked {
                plan.note(Area::Data, label, link_kept());
            } else if owned_environment(instance) {
                plan.remove_tree(Area::Data, instance.dir.clone());
            } else {
                plan.note(
                    Area::Data,
                    label,
                    Outcome::Kept("not a SAIAI environment (no SAIAI config.json)".into()),
                );
            }
        }
        for path in &discovery.linked_environments {
            plan.note(Area::Data, path.display().to_string(), link_kept());
        }
        if environments.is_dir() && !environments_linked {
            plan.remove_empty_dir(Area::Data, environments);
        }
        plan.remove_empty_dir(Area::Data, root.clone());
    }
    for dir in claude_dirs(discovery) {
        for path in matching_files(dir, is_claude_ca_file)? {
            plan.remove_file(Area::Data, path);
        }
    }
    #[cfg(windows)]
    if let Some(local) = env::var_os("LOCALAPPDATA") {
        let runtime = PathBuf::from(local).join("SAIAI").join("desktop-runtime");
        if runtime.is_dir() {
            plan.remove_tree(Area::Data, runtime);
        }
    }
    Ok(())
}

// --------------------------------------------------------------- Program

fn is_program_file(name: &str) -> bool {
    matches!(
        name,
        "saiai" | "saiai.exe" | "saiai-previous" | "saiai-previous.exe"
    ) || name.starts_with("saiai.bak-")
        || name.starts_with(".saiai-update-")
        || name.starts_with(".saiai.install.")
        || name.starts_with(".saiai.replace.")
}

fn default_install_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .map(|local| PathBuf::from(local).join("SAIAI").join("bin"))
            .or_else(|| {
                env::var_os("USERPROFILE")
                    .filter(|value| !value.is_empty())
                    .map(|home| PathBuf::from(home).join("AppData/Local/SAIAI/bin"))
            })
    }
    #[cfg(not(windows))]
    {
        crate::home_dir().map(|home| home.join(".local/bin"))
    }
}

fn same_directory(left: &Path, right: &Path) -> bool {
    let canonical = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let (left, right) = (canonical(left), canonical(right));
    if cfg!(windows) {
        left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
    } else {
        left == right
    }
}

#[cfg(windows)]
fn same_file(left: &Path, right: &Path) -> bool {
    left.parent()
        .zip(right.parent())
        .is_some_and(|(left, right)| same_directory(left, right))
        && left
            .file_name()
            .map(|name| name.to_string_lossy().to_lowercase())
            == right
                .file_name()
                .map(|name| name.to_string_lossy().to_lowercase())
}

fn is_main_program(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "saiai" || name == "saiai.exe")
}

/// Auxiliary files go first and the main program last, so any failure keeps
/// a runnable client, its directory and its PATH entry.
fn plan_program(discovery: &Discovery, plan: &mut Plan) -> Result<()> {
    let default = &discovery.default_install_dir;
    let mut files = Vec::new();
    for dir in &discovery.install_dirs {
        files.extend(matching_files(dir, is_program_file)?);
    }
    let (main, auxiliary): (Vec<_>, Vec<_>) =
        files.into_iter().partition(|path| is_main_program(path));
    for path in auxiliary.into_iter().chain(main) {
        plan.remove_file(Area::Program, path);
    }
    for dir in &discovery.install_dirs {
        let windows_default = cfg!(windows)
            && default
                .as_ref()
                .is_some_and(|default| same_directory(default, dir));
        if windows_default && dir.is_dir() {
            plan.remove_empty_dir(Area::Program, dir.clone());
            if let Some(parent) = dir.parent() {
                plan.remove_empty_dir(Area::Program, parent.to_path_buf());
            }
        } else if cfg!(windows) && !windows_default && dir.is_dir() {
            plan.note(
                Area::Program,
                format!("user PATH entry for {}", dir.display()),
                Outcome::Kept("custom install directory; PATH is not changed".into()),
            );
        }
    }
    // Also when the directory is already gone or the install is custom, so
    // a rerun converges.
    #[cfg(windows)]
    if let Some(default) = default {
        plan_windows_user_path(default, plan)?;
    }
    Ok(())
}

// --------------------------------------------------------------- Services

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_service_file_name(name: &str, prefix: &str, suffix: &str) -> bool {
    let Some(middle) = name
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    middle.is_empty()
        || middle.strip_prefix('-').is_some_and(|hash| {
            hash.len() == 24
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(target_os = "linux")]
fn systemd_load_state(name: &str) -> Option<String> {
    let output = crate::systemctl_user_command()
        .args(["--user", "show", name, "--property", "LoadState", "--value"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn plan_services(discovery: &Discovery, plan: &mut Plan) -> Result<()> {
    for instance in &discovery.instances {
        match crate::linux_background_state_at(&instance.dir) {
            Ok(Some(state))
                if crate::linux_background_state_matches_at(
                    &state,
                    &instance.dir,
                    instance.isolated,
                )
                .unwrap_or(false) =>
            {
                plan.act(
                    Area::Services,
                    format!(
                        "stop the background proxy of {} (pid {})",
                        instance.dir.display(),
                        state.pid
                    ),
                    Action::StopBackground {
                        dir: instance.dir.clone(),
                        isolated: instance.isolated,
                    },
                );
            }
            Ok(_) => {}
            Err(error) => plan.note(
                Area::Services,
                format!("background proxy state of {}", instance.dir.display()),
                Outcome::Failed(format!(
                    "{error:#}; it cannot identify a process. Stop any remaining SAIAI proxy, delete the state file, then rerun"
                )),
            ),
        }
    }

    let systemd = crate::ensure_systemd_user_available().is_ok();
    let unit_dir = crate::user_systemd_dir()?;
    let wants_dir = unit_dir.join("default.target.wants");
    let mut names = discovery
        .instances
        .iter()
        .map(|instance| {
            format!(
                "saiai{}.service",
                environment_scope::service_suffix_for(&discovery.root, &instance.dir)
            )
        })
        .collect::<BTreeSet<_>>();
    for dir in [&unit_dir, &wants_dir] {
        if let Ok(entries) = fs::read_dir(dir) {
            names.extend(entries.flatten().filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_string();
                is_service_file_name(&name, "saiai", ".service").then_some(name)
            }));
        }
    }
    let mut units = 0;
    for name in names {
        let files = [unit_dir.join(&name), wants_dir.join(&name)]
            .into_iter()
            .filter(|path| fs::symlink_metadata(path).is_ok())
            .collect::<Vec<_>>();
        let loaded = if systemd {
            match systemd_load_state(&name) {
                Some(state) => !state.is_empty() && state != "not-found",
                None => {
                    plan.note(
                        Area::Services,
                        format!("systemd user unit {name}"),
                        Outcome::Failed("could not query its state; it was not stopped".into()),
                    );
                    continue;
                }
            }
        } else {
            false
        };
        if !loaded && files.is_empty() {
            continue;
        }
        if !systemd {
            plan.note(
                Area::Services,
                format!("systemd user unit {name}"),
                Outcome::Failed(format!(
                    "systemd --user is not reachable, so it cannot be stopped. Run `systemctl --user disable --now {name}` in a login session, or delete {} if it no longer runs, then rerun",
                    files
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" and ")
                )),
            );
            continue;
        }
        units += 1;
        plan.act(
            Area::Services,
            format!("stop, disable and delete systemd user unit {name}"),
            Action::SystemdUnit {
                name,
                files,
                loaded,
            },
        );
    }
    if systemd && units > 0 {
        plan.act(
            Area::Services,
            "reload the systemd user manager",
            Action::SystemdReload,
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn plan_services(discovery: &Discovery, plan: &mut Plan) -> Result<()> {
    let domain = crate::launchctl_gui_domain()?;
    let agents = crate::launchd_agents_dir()?;
    let mut labels = discovery
        .instances
        .iter()
        .map(|instance| {
            format!(
                "top.saiai.local-proxy{}",
                environment_scope::service_suffix_for(&discovery.root, &instance.dir)
            )
        })
        .collect::<BTreeSet<_>>();
    if let Ok(entries) = fs::read_dir(&agents) {
        labels.extend(entries.flatten().filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            is_service_file_name(&name, "top.saiai.local-proxy", ".plist")
                .then(|| name.trim_end_matches(".plist").to_string())
        }));
    }
    for label in labels {
        let target = format!("{domain}/{label}");
        let plist = agents.join(format!("{label}.plist"));
        let loaded = crate::macos_launchd_loaded(&target);
        if !loaded && fs::symlink_metadata(&plist).is_err() {
            continue;
        }
        plan.act(
            Area::Services,
            format!("stop and delete LaunchAgent {label}"),
            Action::Launchd { target, plist },
        );
    }
    Ok(())
}

#[cfg(windows)]
fn plan_services(discovery: &Discovery, plan: &mut Plan) -> Result<()> {
    for instance in &discovery.instances {
        let followers_dir = instance.dir.join("log-followers");
        if fs::symlink_metadata(&followers_dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
            plan.note(
                Area::Services,
                followers_dir.display().to_string(),
                Outcome::Failed(
                    "is a symbolic link; SAIAI does not follow it. Remove the link and rerun"
                        .into(),
                ),
            );
            continue;
        }
        let followers =
            fs::read_dir(&followers_dir).is_ok_and(|mut entries| entries.next().is_some());
        match crate::windows_background_process_at(
            &instance.dir,
            instance.isolated,
            false,
            &discovery.worker_executables,
        ) {
            Ok(process) if process.is_some() || followers => {
                let pid = process
                    .map(|process| format!(" (pid {})", process.pid))
                    .unwrap_or_default();
                plan.act(
                    Area::Services,
                    format!(
                        "stop the background proxy and log followers of {}{pid}",
                        instance.dir.display()
                    ),
                    Action::StopBackground {
                        dir: instance.dir.clone(),
                        isolated: instance.isolated,
                        executables: discovery.worker_executables.clone(),
                    },
                );
            }
            Ok(_) => {}
            Err(error) => plan.note(
                Area::Services,
                format!("background proxy state of {}", instance.dir.display()),
                Outcome::Failed(format!(
                    "{error:#}; it cannot identify a process. Close any remaining SAIAI proxy, delete the state file, then rerun"
                )),
            ),
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn plan_services(_discovery: &Discovery, _plan: &mut Plan) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------- Windows

#[cfg(windows)]
fn powershell(
    script: &str,
    variables: &[(&str, &std::ffi::OsStr)],
    timeout: Duration,
) -> Result<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("powershell")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .envs(variables.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start PowerShell")?;
    let deadline = std::time::Instant::now() + timeout;
    while child.try_wait()?.is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "PowerShell did not finish within {} seconds",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "PowerShell failed: {}",
            stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("unknown error")
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(windows)]
fn plan_windows_certificates(
    discovery: &Discovery,
    files: &[PathBuf],
    plan: &mut Plan,
) -> Result<()> {
    let mut thumbprints = Vec::new();
    for instance in &discovery.instances {
        for lease in [
            instance
                .dir
                .join("desktop")
                .join(crate::WINDOWS_PACKAGED_PROXY_LEASE_FILENAME),
            instance
                .dir
                .join(crate::WINDOWS_PACKAGED_PROXY_LEASE_FILENAME),
        ] {
            // The lease's directories below SAIAI home must not be links.
            if lease
                .ancestors()
                .skip(1)
                .take_while(|parent| {
                    parent.starts_with(&discovery.root) && *parent != discovery.root
                })
                .any(|parent| {
                    fs::symlink_metadata(parent).is_ok_and(|meta| meta.file_type().is_symlink())
                })
            {
                plan.note(
                    Area::Certificates,
                    lease.display().to_string(),
                    Outcome::Failed(
                        "its directory is a symbolic link; SAIAI does not follow it. Remove the link and rerun"
                            .into(),
                    ),
                );
                continue;
            }
            match crate::read_legacy_windows_packaged_proxy_lease_marker(&lease) {
                Ok(Some(marker)) => {
                    thumbprints.extend(marker.added_ca_thumbprints.iter().cloned());
                    plan.act(
                        Area::Certificates,
                        format!(
                            "restore the legacy Windows Desktop proxy lease {}",
                            lease.display()
                        ),
                        Action::Lease(lease),
                    );
                }
                Ok(None) => {}
                Err(error) => plan.note(
                    Area::Certificates,
                    lease.display().to_string(),
                    Outcome::Failed(format!("{error:#}")),
                ),
            }
        }
    }
    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$found=New-Object System.Collections.Generic.List[string]
foreach($file in ($env:SAIAI_CA_FILES -split "`n")){
  if([string]::IsNullOrWhiteSpace($file)){continue}
  try{
    $pem=[IO.File]::ReadAllText($file)
    foreach($m in [regex]::Matches($pem,'-----BEGIN CERTIFICATE-----(?<der>[A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')){
      $c=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($m.Groups['der'].Value))
      $found.Add($c.Thumbprint.ToUpperInvariant()); $c.Dispose()
    }
  }catch{}
}
foreach($t in ($env:SAIAI_CA_THUMBPRINTS -split "`n")){ $t=$t.Trim(); if($t -match '^[0-9A-Fa-f]{40}$'){ $found.Add($t.ToUpperInvariant()) } }
$present=@($found | Sort-Object -Unique | Where-Object { Test-Path -LiteralPath ('Cert:\CurrentUser\Root\'+$_) })
ConvertTo-Json -Compress -InputObject $present
"#;
    let files = files
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let thumbprints = thumbprints.join("\n");
    let output = match powershell(
        SCRIPT,
        &[
            ("SAIAI_CA_FILES", std::ffi::OsStr::new(&files)),
            ("SAIAI_CA_THUMBPRINTS", std::ffi::OsStr::new(&thumbprints)),
        ],
        Duration::from_secs(60),
    ) {
        Ok(output) => output,
        Err(error) => {
            plan.note(
                Area::Certificates,
                "Windows CurrentUser\\Root certificates",
                Outcome::Failed(format!("could not inspect: {error:#}")),
            );
            return Ok(());
        }
    };
    let present = match serde_json::from_str::<Value>(&output) {
        Ok(Value::Array(values)) => values,
        Ok(Value::String(value)) => vec![Value::String(value)],
        _ => Vec::new(),
    };
    for thumbprint in present.iter().filter_map(Value::as_str) {
        plan.act(
            Area::Certificates,
            format!(
                "remove SAIAI CA {thumbprint} from Windows CurrentUser\\Root (Windows may ask you to confirm)"
            ),
            Action::RootCa(thumbprint.to_string()),
        );
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn remove_path_entries(value: &str, directory: &str) -> Option<String> {
    let target = directory.trim_end_matches('\\').to_uppercase();
    let parts = value.split(';').collect::<Vec<_>>();
    let kept = parts
        .iter()
        .filter(|part| part.trim_end_matches('\\').to_uppercase() != target)
        .copied()
        .collect::<Vec<_>>();
    (kept.len() != parts.len()).then(|| kept.join(";"))
}

#[cfg(windows)]
fn plan_windows_user_path(directory: &Path, plan: &mut Plan) -> Result<()> {
    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment',$false)
if($null -eq $k){'{}';exit 0}
try{
  $v=$k.GetValue('Path',$null,'DoNotExpandEnvironmentNames')
  if($null -eq $v){'{}';exit 0}
  [pscustomobject]@{value=[string]$v;kind=[string]$k.GetValueKind('Path')}|ConvertTo-Json -Compress
}finally{$k.Close()}
"#;
    let output = match powershell(SCRIPT, &[], Duration::from_secs(30)) {
        Ok(output) => output,
        Err(error) => {
            plan.note(
                Area::Program,
                "user PATH",
                Outcome::Failed(format!("could not inspect: {error:#}")),
            );
            return Ok(());
        }
    };
    let parsed = serde_json::from_str::<Value>(&output).unwrap_or(Value::Null);
    let (Some(value), Some(kind)) = (parsed["value"].as_str(), parsed["kind"].as_str()) else {
        return Ok(());
    };
    if let Some(replacement) = remove_path_entries(value, &directory.to_string_lossy()) {
        plan.act(
            Area::Program,
            format!(
                "remove {} from the user PATH once the directory is removed",
                directory.display()
            ),
            Action::UserPath {
                directory: directory.to_path_buf(),
                value: value.to_string(),
                kind: kind.to_string(),
                replacement,
            },
        );
    }
    Ok(())
}

#[cfg(windows)]
fn execute_user_path(
    directory: &Path,
    value: &str,
    kind: &str,
    replacement: &str,
) -> Result<Outcome> {
    if directory.exists() {
        return Ok(Outcome::Kept(format!(
            "{} still exists (a running copy is removed a few seconds after this window's command exits). Rerun after a few seconds: `irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai uninstall` (it downloads a temporary client, since the installed one is gone)",
            directory.display()
        )));
    }
    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment',$true)
try{
  $current=[string]$k.GetValue('Path',$null,'DoNotExpandEnvironmentNames')
  if($current -cne $env:SAIAI_PATH_OLD -or [string]$k.GetValueKind('Path') -cne $env:SAIAI_PATH_KIND){throw 'the user PATH changed since the plan was shown'}
  if([string]::IsNullOrEmpty($env:SAIAI_PATH_NEW)){$k.DeleteValue('Path',$false)}
  else{$k.SetValue('Path',$env:SAIAI_PATH_NEW,[Microsoft.Win32.RegistryValueKind]$env:SAIAI_PATH_KIND)}
}finally{$k.Close()}
Add-Type -Namespace SaiaiUninstall -Name Native -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
$result=[UIntPtr]::Zero
[void][SaiaiUninstall.Native]::SendMessageTimeout([IntPtr]0xffff,0x1A,[UIntPtr]::Zero,'Environment',2,5000,[ref]$result)
'updated'
"#;
    powershell(
        SCRIPT,
        &[
            ("SAIAI_PATH_OLD", std::ffi::OsStr::new(value)),
            ("SAIAI_PATH_NEW", std::ffi::OsStr::new(replacement)),
            ("SAIAI_PATH_KIND", std::ffi::OsStr::new(kind)),
        ],
        Duration::from_secs(30),
    )?;
    Ok(Outcome::Done)
}

#[cfg(windows)]
fn execute_root_ca(thumbprint: &str) -> Result<()> {
    if thumbprint.len() != 40 || !thumbprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid certificate thumbprint");
    }
    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$p='Cert:\CurrentUser\Root\'+$env:SAIAI_CA_THUMBPRINT
if(Test-Path -LiteralPath $p){ Remove-Item -LiteralPath $p }
if(Test-Path -LiteralPath $p){ throw 'the certificate is still trusted' }
'removed'
"#;
    powershell(
        SCRIPT,
        &[("SAIAI_CA_THUMBPRINT", std::ffi::OsStr::new(thumbprint))],
        Duration::from_secs(120),
    )?;
    Ok(())
}

#[cfg(windows)]
fn relaunch_outside_install_dir(plan: &Plan, args: &Args) -> Result<Option<i32>> {
    let exe = env::current_exe().context("failed to resolve the current executable")?;
    let locked = plan
        .items
        .iter()
        .any(|item| matches!(&item.action, Action::RemoveFile(path) if same_file(path, &exe)));
    if !locked {
        return Ok(None);
    }
    let directory =
        env::temp_dir().join(format!("saiai-uninstall-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let copy = directory.join("saiai.exe");
    fs::copy(&exe, &copy).with_context(|| format!("failed to copy {}", exe.display()))?;
    println!();
    println!("Continuing from a temporary copy so the installed program can be removed.");
    let status = std::process::Command::new(&copy)
        .args(["uninstall", "--yes"])
        .args(
            args.forget_unknown
                .then_some("--forget-unknown-environments"),
        )
        .arg(RELAUNCH_FLAG)
        .arg(&exe)
        .status();
    match status {
        Ok(status) => Ok(Some(status.code().unwrap_or(1))),
        Err(error) => {
            let _ = fs::remove_dir_all(&directory);
            Err(error).context("failed to run the temporary uninstall copy")
        }
    }
}

#[cfg(windows)]
/// Parked executables, and whether their (default install) directory may go.
static PARKED: std::sync::Mutex<Vec<(PathBuf, bool)>> = std::sync::Mutex::new(Vec::new());

#[cfg(windows)]
fn schedule_temporary_copy_removal() {
    let Some(directory) = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .filter(|dir| {
            dir.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("saiai-uninstall-"))
        })
    else {
        return;
    };
    // Paths travel in the environment, never through command text.
    const SCRIPT: &str = r#"
Start-Sleep -Seconds 3
foreach($file in ($env:SAIAI_CLEANUP_FILES -split "`n")){
  if([string]::IsNullOrWhiteSpace($file)){continue}
  Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
}
foreach($directory in ($env:SAIAI_CLEANUP_DIRS -split "`n")){
  if([string]::IsNullOrWhiteSpace($directory)){continue}
  try{[IO.Directory]::Delete($directory)}catch{}
}
Remove-Item -LiteralPath $env:SAIAI_CLEANUP_DIR -Recurse -Force -ErrorAction SilentlyContinue
"#;
    let parked = PARKED.lock().unwrap();
    let files = parked
        .iter()
        .map(|(path, _)| path.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let directories = parked
        .iter()
        .filter(|(_, remove_parent)| *remove_parent)
        .filter_map(|(path, _)| path.parent().map(|dir| dir.display().to_string()))
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .env("SAIAI_CLEANUP_FILES", files)
        .env("SAIAI_CLEANUP_DIRS", directories)
        .env("SAIAI_CLEANUP_DIR", &directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

// -------------------------------------------------------------- Execution

fn file_mode(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).map_or(0o600, |meta| meta.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0o600
    }
}

fn execute_edit(path: &Path, original: &[u8], replacement: Option<&[u8]>) -> Result<Outcome> {
    let Some(current) = read_existing(path)? else {
        bail!("disappeared since the plan was shown; rerun `saiai uninstall`");
    };
    if current != original {
        bail!("changed since the plan was shown; not modified. Rerun `saiai uninstall`");
    }
    match replacement {
        Some(bytes) => crate::write_bytes_atomic(path, bytes, file_mode(path))?,
        None => {
            fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?
        }
    }
    Ok(Outcome::Done)
}

fn execute_remove_file(path: &Path, args: &Args) -> Result<Outcome> {
    #[cfg(not(windows))]
    let _ = args;
    match fs::remove_file(path) {
        Ok(()) => Ok(Outcome::Done),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Outcome::Absent),
        #[cfg(windows)]
        Err(error)
            if args
                .relaunched_from
                .as_ref()
                .is_some_and(|original| same_file(original, path)) =>
        {
            // The waiting parent still runs this image. Windows allows moving
            // it on the same volume; it is deleted after the parent exits.
            let temporary = env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join("installed-saiai.exe")));
            let beside = path.with_file_name(format!(
                ".saiai.replace.{}.bak",
                uuid::Uuid::new_v4().simple()
            ));
            let remove_parent = default_install_dir()
                .zip(path.parent())
                .is_some_and(|(default, parent)| same_directory(&default, parent));
            for (parked, remove_parent) in temporary
                .map(|parked| (parked, false))
                .into_iter()
                .chain([(beside, remove_parent)])
            {
                if fs::rename(path, &parked).is_ok() {
                    PARKED.lock().unwrap().push((parked, remove_parent));
                    return Ok(Outcome::Done);
                }
            }
            Err(error).with_context(|| format!("failed to remove {}", path.display()))
        }
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn execute_remove_empty_dir(path: &Path) -> Result<Outcome> {
    match fs::read_dir(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Outcome::Absent),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Ok(Outcome::Kept("not empty".into()));
            }
        }
    }
    fs::remove_dir(path).with_context(|| format!("failed to remove {}", path.display()))?;
    Ok(Outcome::Done)
}

#[cfg(target_os = "linux")]
fn execute_nss(db: &str, known: &BTreeSet<String>) -> Result<Outcome> {
    let Some(exported) = certutil_export(db)? else {
        return Ok(Outcome::Absent);
    };
    if nss_decision(&exported, known) != NssDecision::Remove {
        return Ok(Outcome::Kept(
            "changed since the plan was shown; not a known SAIAI CA".into(),
        ));
    }
    for _ in 0..certificate_fingerprints(&exported).len() {
        let status = std::process::Command::new("certutil")
            .args([
                "-D",
                "-d",
                db,
                "-n",
                crate::SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .context("failed to run certutil")?;
        if !status.success() {
            bail!("certutil could not delete the SAIAI certificate");
        }
    }
    if certutil_export(db)?.is_some() {
        bail!("the SAIAI certificate is still present after deletion");
    }
    Ok(Outcome::Done)
}

#[cfg(target_os = "linux")]
fn execute_systemd_unit(name: &str, files: &[PathBuf], loaded: bool) -> Result<Outcome> {
    if loaded {
        crate::run_systemctl(&["disable", "--now", name])?;
    }
    for path in files {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to remove {}", path.display()));
            }
        }
    }
    Ok(Outcome::Done)
}

#[cfg(target_os = "macos")]
fn execute_launchd(target: &str, plist: &Path) -> Result<Outcome> {
    if crate::macos_launchd_loaded(target) {
        let output = std::process::Command::new(crate::MACOS_LAUNCHCTL_COMMAND)
            .args(["bootout", target])
            .output()
            .context("failed to run launchctl")?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while crate::macos_launchd_loaded(target) {
            if std::time::Instant::now() >= deadline {
                bail!(
                    "launchctl bootout {target} did not unload it: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    match fs::remove_file(plist) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to remove {}", plist.display()));
        }
    }
    Ok(Outcome::Done)
}

fn execute_item(action: &Action, args: &Args) -> Result<Outcome> {
    match action {
        Action::None => Ok(Outcome::Absent),
        Action::Edit {
            path,
            original,
            replacement,
        } => execute_edit(path, original, replacement.as_deref()),
        Action::RemoveFile(path) => execute_remove_file(path, args),
        Action::RemoveTree(path) => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Outcome::Absent),
            Ok(meta) if !meta.is_dir() => {
                fs::remove_file(path)
                    .with_context(|| format!("failed to remove {}", path.display()))?;
                Ok(Outcome::Done)
            }
            _ => {
                fs::remove_dir_all(path)
                    .with_context(|| format!("failed to remove {}", path.display()))?;
                Ok(Outcome::Done)
            }
        },
        Action::RemoveEmptyDir(path) => execute_remove_empty_dir(path),
        Action::RecordProductDir {
            environment,
            product_dir,
            ..
        } => {
            if !fs::symlink_metadata(environment).is_ok_and(|meta| meta.is_dir()) {
                bail!("{} is not a directory", environment.display());
            }
            let text = product_dir
                .to_str()
                .context("project directory is not valid UTF-8")?;
            let path = environment.join(environment_scope::PRODUCT_DIR_FILENAME);
            let mut options = fs::OpenOptions::new();
            // Never replace a record that appeared since discovery.
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .with_context(|| format!("failed to write {}", path.display()))?;
            Ok(Outcome::Done)
        }
        #[cfg(target_os = "linux")]
        Action::StopBackground { dir, isolated } => {
            let _lock = crate::acquire_linux_service_lock_at(dir)?;
            crate::stop_linux_background_proxy_at(dir, *isolated)?;
            Ok(Outcome::Done)
        }
        #[cfg(windows)]
        Action::StopBackground {
            dir,
            isolated,
            executables,
        } => {
            let _lock = crate::lock_windows_service_at(dir)?;
            crate::stop_windows_background_proxy_at(dir, *isolated, executables)?;
            Ok(Outcome::Done)
        }
        #[cfg(target_os = "linux")]
        Action::SystemdUnit {
            name,
            files,
            loaded,
        } => execute_systemd_unit(name, files, *loaded),
        #[cfg(target_os = "linux")]
        Action::SystemdReload => {
            crate::run_systemctl(&["daemon-reload"])?;
            Ok(Outcome::Done)
        }
        #[cfg(target_os = "linux")]
        Action::Nss { db, known } => execute_nss(db, known),
        #[cfg(target_os = "macos")]
        Action::Launchd { target, plist } => execute_launchd(target, plist),
        #[cfg(windows)]
        Action::Lease(path) => {
            crate::restore_legacy_windows_packaged_proxy_lease_at(path)?;
            Ok(Outcome::Done)
        }
        #[cfg(windows)]
        Action::RootCa(thumbprint) => {
            execute_root_ca(thumbprint)?;
            Ok(Outcome::Done)
        }
        #[cfg(windows)]
        Action::UserPath {
            directory,
            value,
            kind,
            replacement,
        } => execute_user_path(directory, value, kind, replacement),
    }
}

/// Data and program steps run only while nothing at all has failed or been
/// skipped; the program also needs every data step done.
fn gate_blocked(items: &[Item], area: Area) -> bool {
    items
        .iter()
        .any(|other| other.outcome != Outcome::Pending && !other.outcome.succeeded())
        || (area == Area::Program
            && items
                .iter()
                .any(|other| other.area == Area::Data && !other.outcome.succeeded()))
}

fn execute(plan: &mut Plan, args: &Args) {
    println!();
    for gated in [false, true] {
        for index in 0..plan.items.len() {
            let item = &plan.items[index];
            if item.area.gated() != gated || item.outcome != Outcome::Pending {
                continue;
            }
            let dependency_failed = matches!(&item.action, Action::RecordProductDir { after, .. }
                if plan.items[after.clone()].iter().any(|other| !other.outcome.succeeded()));
            let outcome = if dependency_failed || (gated && gate_blocked(&plan.items, item.area)) {
                Outcome::Skipped
            } else {
                match execute_item(&item.action, args) {
                    Ok(outcome) => outcome,
                    Err(error) => Outcome::Failed(format!("{error:#}")),
                }
            };
            plan.items[index].outcome = outcome;
            print_result(&plan.items[index]);
        }
    }
}

// ----------------------------------------------------------------- Output

fn print_result(item: &Item) {
    match &item.outcome {
        Outcome::Done => println!("DONE {}", item.text),
        Outcome::Absent => println!("GONE {} (already absent)", item.text),
        Outcome::Kept(reason) => println!("KEEP {}: {reason}", item.text),
        Outcome::Failed(reason) => println!("FAIL {}: {reason}", item.text),
        Outcome::Skipped => println!("SKIP {} (an earlier step failed)", item.text),
        Outcome::Manual(reason) => println!("NOTE {}: {reason}", item.text),
        Outcome::Pending => {}
    }
}

fn print_plan(discovery: &Discovery, plan: &Plan) {
    println!("{PLAN_MARKER}");
    println!("SAIAI home: {}", discovery.root.display());
    for area in AREAS {
        let items = plan
            .items
            .iter()
            .filter(|item| item.area == area)
            .collect::<Vec<_>>();
        if items.is_empty() {
            continue;
        }
        println!();
        println!("{}:", area.label());
        for item in items {
            match &item.outcome {
                Outcome::Pending => println!("  - {}", item.text),
                Outcome::Kept(reason) => println!("  = keep {}: {reason}", item.text),
                Outcome::Manual(reason) => println!("  ! manual: {}: {reason}", item.text),
                Outcome::Failed(reason) => println!("  x cannot change {}: {reason}", item.text),
                _ => {}
            }
        }
    }
    if plan
        .items
        .iter()
        .any(|item| item.area.gated() && item.outcome == Outcome::Pending)
    {
        println!();
        println!("SAIAI data and the program are removed only if every earlier step succeeds.");
    }
}

fn print_summary(plan: &Plan) {
    let count = |predicate: fn(&Outcome) -> bool| {
        plan.items
            .iter()
            .filter(|item| predicate(&item.outcome))
            .count()
    };
    println!();
    println!(
        "uninstall summary: {} done, {} kept, {} already absent, {} manual, {} failed, {} skipped",
        count(|o| *o == Outcome::Done),
        count(|o| matches!(o, Outcome::Kept(_))),
        count(|o| *o == Outcome::Absent),
        count(|o| matches!(o, Outcome::Manual(_))),
        count(|o| matches!(o, Outcome::Failed(_))),
        count(|o| *o == Outcome::Skipped),
    );
    let failed = plan
        .items
        .iter()
        .filter(|item| matches!(item.outcome, Outcome::Failed(_)))
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        println!("Failed:");
        for item in failed {
            if let Outcome::Failed(reason) = &item.outcome {
                println!("  - {}: {reason}", item.text);
            }
        }
    }
    let kept = plan
        .items
        .iter()
        .filter(|item| matches!(item.outcome, Outcome::Kept(_) | Outcome::Manual(_)))
        .collect::<Vec<_>>();
    if !kept.is_empty() {
        println!("Kept or needs your attention:");
        for item in kept {
            if let Outcome::Kept(reason) | Outcome::Manual(reason) = &item.outcome {
                println!("  - {}: {reason}", item.text);
            }
        }
    }
    if !plan.backups.is_empty() {
        println!(
            "Backups kept (they may contain old settings or keys; delete them yourself when no longer needed):"
        );
        for path in &plan.backups {
            println!("  - {}", path.display());
        }
    }
    println!("Next steps:");
    println!(
        "  - Claude Code: log in again (`claude`, then /login). SAIAI did not change ~/.claude.json, .credentials.json or oauthAccount."
    );
    println!("  - Codex: run `codex login` to sign in again.");
    println!(
        "  - If you use the Codex app-server daemon, run `codex app-server daemon update`; it may still be pinned to the SAIAI setup."
    );
    println!(
        "  - Close and reopen running Claude Code, Codex, Codex Desktop and VSCode windows; they keep the old settings until restarted."
    );
}

fn finish(plan: &Plan) -> Result<()> {
    let failed = plan
        .items
        .iter()
        .filter(|item| !item.outcome.succeeded())
        .count();
    if failed > 0 {
        bail!(
            "SAIAI uninstall is incomplete: {failed} item(s) failed or were skipped. Fix the failure and rerun `saiai uninstall`."
        );
    }
    Ok(())
}

fn confirm() -> Result<bool> {
    const PROMPT: &str = "Remove the items above? Type y or yes to continue: ";
    let mut answer = String::new();
    if std::io::stdin().is_terminal() {
        eprint!("{PROMPT}");
        let _ = std::io::stderr().flush();
        std::io::stdin().lock().read_line(&mut answer)?;
    } else {
        // `curl | bash` gives this process the script as stdin.
        let terminal = open_terminal().context(
            "no terminal is available to confirm the uninstall; nothing was changed. Rerun with --yes to proceed without a prompt",
        )?;
        // CONIN$ is input-only; Windows prompts on stderr instead.
        if cfg!(windows) {
            eprint!("{PROMPT}");
            let _ = std::io::stderr().flush();
        } else {
            let mut writer = terminal.try_clone()?;
            let _ = write!(writer, "{PROMPT}");
            let _ = writer.flush();
        }
        std::io::BufReader::new(terminal).read_line(&mut answer)?;
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn open_terminal() -> std::io::Result<fs::File> {
    let name = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
    fs::OpenOptions::new().read(true).write(true).open(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn owned() -> ClaudeOwned {
        ClaudeOwned {
            api_keys: vec!["TEST_ONLY_SAIAI_CLAUDE_KEY".into()],
            proxies: vec!["http://127.0.0.1:41000".into()],
            ca_paths: vec!["/home/u/.claude/saiai-ca.crt".into()],
        }
    }

    #[test]
    fn claude_env_removes_only_exact_saiai_values() {
        let settings = json!({
            "theme": "dark",
            "env": {
                "CLAUDE_CODE_OAUTH_TOKEN": "TEST_ONLY_SAIAI_CLAUDE_KEY",
                "http_proxy": "http://127.0.0.1:41000",
                "https_proxy": "http://127.0.0.1:7890",
                "all_proxy": "http://127.0.0.1:41000",
                "no_proxy": crate::DEFAULT_NO_PROXY,
                "NODE_EXTRA_CA_CERTS": "/home/u/.claude/saiai-ca.crt",
                "ENABLE_TOOL_SEARCH": "true",
                "USER_VALUE": "1"
            }
        });
        let removal = claude_settings_removal(settings.as_object().unwrap(), &owned());
        assert_eq!(
            removal.removed,
            [
                "CLAUDE_CODE_OAUTH_TOKEN",
                "http_proxy",
                "all_proxy",
                "no_proxy",
                "NODE_EXTRA_CA_CERTS"
            ]
        );
        assert_eq!(removal.modified, ["https_proxy"]);
        assert_eq!(removal.generic, ["ENABLE_TOOL_SEARCH"]);
        assert_eq!(
            Value::Object(removal.settings),
            json!({
                "theme": "dark",
                "env": {
                    "https_proxy": "http://127.0.0.1:7890",
                    "ENABLE_TOOL_SEARCH": "true",
                    "USER_VALUE": "1"
                }
            })
        );
    }

    #[test]
    fn claude_env_object_is_removed_only_when_empty() {
        let settings = json!({"env": {"CLAUDE_CODE_OAUTH_TOKEN": "TEST_ONLY_SAIAI_CLAUDE_KEY"}});
        let removal = claude_settings_removal(settings.as_object().unwrap(), &owned());
        assert_eq!(Value::Object(removal.settings), json!({}));
        let foreign = json!({"env": {"CLAUDE_CODE_OAUTH_TOKEN": "TEST_ONLY_USER_TOKEN"}});
        let removal = claude_settings_removal(foreign.as_object().unwrap(), &owned());
        assert!(removal.removed.is_empty());
        assert_eq!(Value::Object(removal.settings), foreign);
        let no_env = json!({"env": "not an object"});
        let removal = claude_settings_removal(no_env.as_object().unwrap(), &owned());
        assert_eq!(Value::Object(removal.settings), no_env);
    }

    fn placeholder() -> Value {
        json!({
            "id_token": crate::CODEX_PLACEHOLDER_ID_TOKEN,
            "access_token": crate::CODEX_PLACEHOLDER_ACCESS_TOKEN,
            "refresh_token": "",
            "account_id": crate::CODEX_PLACEHOLDER_ACCOUNT_ID
        })
    }

    #[test]
    fn codex_auth_removes_placeholder_fields_only() {
        let auth = json!({
            "auth_mode": "chatgptAuthTokens",
            "tokens": placeholder(),
            "OPENAI_API_KEY": null,
            "last_refresh": "2026-10-30T00:00:00Z",
            "user_field": 1
        });
        let AuthRemoval::Changed { auth, removed } = codex_auth_removal(auth.as_object().unwrap())
        else {
            panic!("placeholder was not removed");
        };
        assert_eq!(
            removed,
            ["tokens", "auth_mode", "OPENAI_API_KEY", "last_refresh"]
        );
        assert_eq!(Value::Object(auth), json!({"user_field": 1}));

        let partial = json!({"tokens": placeholder(), "auth_mode": "chatgpt", "OPENAI_API_KEY": "TEST_ONLY_USER_KEY"});
        let AuthRemoval::Changed { auth, removed } =
            codex_auth_removal(partial.as_object().unwrap())
        else {
            panic!("placeholder was not removed");
        };
        assert_eq!(removed, ["tokens"]);
        assert_eq!(
            Value::Object(auth),
            json!({"auth_mode": "chatgpt", "OPENAI_API_KEY": "TEST_ONLY_USER_KEY"})
        );
    }

    #[test]
    fn codex_auth_keeps_real_or_modified_tokens() {
        let mut extra = placeholder();
        extra["extra"] = json!(true);
        let mut changed = placeholder();
        changed["refresh_token"] = json!("TEST_ONLY_REFRESH");
        for tokens in [extra, changed, json!("text")] {
            let auth =
                json!({"auth_mode": "chatgptAuthTokens", "tokens": tokens, "OPENAI_API_KEY": null});
            assert_eq!(
                codex_auth_removal(auth.as_object().unwrap()),
                AuthRemoval::Unchanged {
                    foreign_tokens: true
                }
            );
        }
        let api_key_only = json!({"OPENAI_API_KEY": null});
        assert_eq!(
            codex_auth_removal(api_key_only.as_object().unwrap()),
            AuthRemoval::Unchanged {
                foreign_tokens: false
            }
        );
    }

    #[test]
    fn codex_env_strip_preserves_user_bytes() {
        let block = crate::merge_codex_ide_env("", "127.0.0.1:41000", "/ca.crt");
        let user = "# user comment\r\nFOO=1\n\n";
        let merged = crate::merge_codex_ide_env(user, "127.0.0.1:41000", "/ca.crt");
        assert_eq!(
            crate::strip_codex_ide_env_block(&merged).content,
            "# user comment\nFOO=1\n"
        );
        let middle = format!("A=1\n\n{block}B=2\r\n");
        let stripped = crate::strip_codex_ide_env_block(&middle);
        assert!(stripped.complete);
        assert_eq!(stripped.content, "A=1\n\nB=2\r\n");
        assert_eq!(crate::strip_codex_ide_env_block(&block).content, "");
        let unterminated = format!("A=1\n{}\nB=2\n", crate::CODEX_IDE_ENV_BEGIN);
        assert!(!crate::strip_codex_ide_env_block(&unterminated).complete);
        assert_eq!(
            crate::strip_codex_ide_env_block("A=1\r\nB=2").content,
            "A=1\r\nB=2"
        );
        // Merging remains idempotent on top of the shared helper.
        assert_eq!(
            crate::merge_codex_ide_env(&merged, "127.0.0.1:41000", "/ca.crt"),
            merged
        );
    }

    #[test]
    fn nss_certificate_is_removed_only_when_every_copy_is_known() {
        let (cert_a, _) = crate::generate_installation_ca().unwrap();
        let (cert_b, _) = crate::generate_installation_ca().unwrap();
        let known = certificate_fingerprints(cert_a.as_bytes())
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(known.len(), 1);
        assert_eq!(nss_decision(cert_a.as_bytes(), &known), NssDecision::Remove);
        assert_eq!(nss_decision(cert_b.as_bytes(), &known), NssDecision::Keep);
        let both = format!("{cert_a}{cert_b}");
        assert_eq!(nss_decision(both.as_bytes(), &known), NssDecision::Keep);
        assert_eq!(nss_decision(b"", &known), NssDecision::Keep);
        assert_eq!(
            nss_decision(b"garbage", &BTreeSet::new()),
            NssDecision::Keep
        );
    }

    #[test]
    fn user_path_filter_removes_only_the_default_directory() {
        let dir = r"C:\Users\u\AppData\Local\SAIAI\bin";
        assert_eq!(
            remove_path_entries(
                r"C:\Tools;c:\users\U\appdata\local\saiai\BIN\;%USERPROFILE%\bin",
                dir
            ),
            Some(r"C:\Tools;%USERPROFILE%\bin".into())
        );
        assert_eq!(remove_path_entries(dir, dir), Some(String::new()));
        assert_eq!(
            remove_path_entries(r"C:\Tools;;C:\Users\u\AppData\Local\SAIAI\bin2", dir),
            None
        );
    }

    #[test]
    fn install_directory_filter_matches_only_saiai_program_files() {
        for name in [
            "saiai",
            "saiai.exe",
            "saiai-previous",
            "saiai-previous.exe",
            "saiai.bak-20261030-010203",
            "saiai.bak-20261030-010203.exe",
            ".saiai-update-1-2.exe",
            ".saiai-update-status.txt",
            ".saiai.install.AbC123",
            ".saiai.replace.0123.bak",
        ] {
            assert!(is_program_file(name), "{name}");
        }
        for name in [
            "claude",
            "saiai-other",
            "saiai.sh",
            "my-saiai",
            ".saiai",
            "saiai.bak",
        ] {
            assert!(!is_program_file(name), "{name}");
        }
    }

    #[test]
    fn saiai_home_filter_matches_only_known_files() {
        for name in [
            "config.json",
            "config.json.bak-20261030-010203",
            "saiai-ca.key.bak-1",
            "client-device-key.corrupt",
            ".config.json.saiai-tmp-1-abc",
            "saiai.log",
        ] {
            assert!(is_saiai_home_file(name), "{name}");
        }
        for name in ["notes.txt", "config.json.orig", "environments", "desktop"] {
            assert!(!is_saiai_home_file(name), "{name}");
        }
        assert!(is_claude_ca_file("saiai-ca.crt.bak-1"));
        assert!(!is_claude_ca_file("settings.json"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn service_file_names_follow_the_saiai_pattern() {
        assert!(is_service_file_name("saiai.service", "saiai", ".service"));
        assert!(is_service_file_name(
            "saiai-0123456789abcdef01234567.service",
            "saiai",
            ".service"
        ));
        assert!(!is_service_file_name(
            "saiai-other.service",
            "saiai",
            ".service"
        ));
        assert!(!is_service_file_name("saiaix.service", "saiai", ".service"));
        assert!(is_service_file_name(
            "top.saiai.local-proxy.plist",
            "top.saiai.local-proxy",
            ".plist"
        ));
    }

    #[test]
    fn saiai_configuration_shapes_are_recognized() {
        for config in [
            json!({"version": 2, "listen": "127.0.0.1:1", "ca_cert_path": "/ca", "base_url": "u", "api_key": "k"}),
            json!({"version": 1, "listen": "127.0.0.1:1", "ca_cert_path": "/ca"}),
            json!({"listen": "127.0.0.1:1", "ca_cert_path": "/ca", "base_url": "u", "api_key": "k"}),
        ] {
            assert!(is_saiai_config(&config), "{config}");
        }
        for config in [
            json!({"theme": "dark"}),
            json!({"version": 2, "listen": "127.0.0.1:1"}),
            json!({"version": 3, "listen": "127.0.0.1:1", "ca_cert_path": "/ca"}),
            json!({"listen": "127.0.0.1:1", "ca_cert_path": "/ca"}),
            json!([1]),
        ] {
            assert!(!is_saiai_config(&config), "{config}");
        }
    }

    fn item(area: Area, executed: bool, outcome: Outcome) -> Item {
        Item {
            area,
            text: String::new(),
            action: if executed {
                Action::RemoveFile(PathBuf::from("/unused"))
            } else {
                Action::None
            },
            outcome,
        }
    }

    #[test]
    fn data_and_program_are_gated_on_every_earlier_failure() {
        let done = || item(Area::Claude, true, Outcome::Done);
        assert!(!gate_blocked(
            &[
                done(),
                item(Area::Codex, false, Outcome::Manual("forget".into()))
            ],
            Area::Data
        ));
        for failure in [
            item(Area::Codex, false, Outcome::Failed("plan".into())),
            item(
                Area::Program,
                false,
                Outcome::Failed("PATH inspection".into()),
            ),
            item(Area::Data, true, Outcome::Failed("earlier data".into())),
            item(Area::Data, true, Outcome::Skipped),
        ] {
            assert!(gate_blocked(&[done(), failure], Area::Data));
        }
        // Any failure, including an earlier program step, blocks the rest;
        // an unfinished data step blocks the program.
        let program_failure = item(Area::Program, true, Outcome::Failed("locked".into()));
        assert!(gate_blocked(&[done(), program_failure], Area::Program));
        assert!(gate_blocked(
            &[done(), item(Area::Data, true, Outcome::Pending)],
            Area::Program
        ));
        assert!(!gate_blocked(
            &[
                done(),
                item(Area::Data, true, Outcome::Kept("not empty".into()))
            ],
            Area::Program
        ));
    }

    #[test]
    fn secrets_are_masked() {
        assert_eq!(mask_secret("TEST_ONLY_SECRET_VALUE_1234"), "****1234");
        assert_eq!(mask_secret("short"), "****");
    }

    #[test]
    fn arguments_reject_unknown_flags() {
        let parsed = parse_args(&[
            "--yes".into(),
            "--dry-run".into(),
            "--forget-unknown-environments".into(),
        ])
        .unwrap();
        assert!(parsed.yes && parsed.dry_run && parsed.forget_unknown);
        assert!(parse_args(&["--force".into()]).is_err());
        assert!(parse_args(&["extra".into()]).is_err());
    }
}
