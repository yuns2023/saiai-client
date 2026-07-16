use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use toml_edit::{DocumentMut, Item, Table, value};
use url::Url;

const USAGE: &str = "\
Usage:
  saiai <base_url> <api_key>                              # configure Claude Code
  saiai init <base_url> <api_key>                         # configure Claude Code
  saiai init --base-url <url> --api-key <key>             # configure Claude Code
  saiai init-codex <base_url> <api_key> [--websockets]    # configure Codex CLI
  saiai doctor                                             # verify global Claude config
  saiai --version";

const CLAUDE_STREAM_IDLE_TIMEOUT_MS: &str = "600000";

// These values can redirect authentication, provider selection, models, or
// transport after Claude Code reads user settings. The V1 config client owns
// this exact routing surface and removes stale values before writing its own
// direct-gateway configuration. Unrelated user settings are preserved.
const CLAUDE_CONFLICTING_ENV: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "ANTHROPIC_CUSTOM_HEADERS",
    "AWS_BEARER_TOKEN_BEDROCK",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_SKIP_VERTEX_AUTH",
    "ANTHROPIC_VERTEX_BASE_URL",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "CLOUD_ML_REGION",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "ANTHROPIC_FOUNDRY_RESOURCE",
    "ANTHROPIC_FOUNDRY_API_KEY",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL_DESCRIPTION",
    "ANTHROPIC_DEFAULT_OPUS_MODEL_NAME",
    "ANTHROPIC_DEFAULT_OPUS_MODEL_SUPPORTED_CAPABILITIES",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_DESCRIPTION",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_SUPPORTED_CAPABILITIES",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL_DESCRIPTION",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL_SUPPORTED_CAPABILITIES",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL_AWS_REGION",
    "ANTHROPIC_CUSTOM_MODEL_OPTION",
    "ANTHROPIC_CUSTOM_MODEL_OPTION_DESCRIPTION",
    "ANTHROPIC_CUSTOM_MODEL_OPTION_NAME",
    "CLAUDE_CODE_SUBAGENT_MODEL",
    "CLAUDE_CODE_EFFORT_LEVEL",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_ATTRIBUTION_HEADER",
    "API_TIMEOUT_MS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "CLAUDE_CODE_PROXY_RESOLVES_HOSTS",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CLAUDE_CODE_CLIENT_CERT",
    "CLAUDE_CODE_CLIENT_KEY",
    "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

const CLAUDE_CONFLICTING_ENV_PREFIXES: &[&str] = &["VERTEX_REGION_CLAUDE_"];

fn is_conflicting_claude_env(key: &str) -> bool {
    CLAUDE_CONFLICTING_ENV
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
        || CLAUDE_CONFLICTING_ENV_PREFIXES
            .iter()
            .any(|prefix| key.to_ascii_uppercase().starts_with(prefix))
}

fn main() -> Result<()> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&arguments)? {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("saiai {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Init(arguments) => init_claude(arguments),
        Command::InitCodex(arguments) => init_codex(arguments),
        Command::Doctor => doctor_claude(),
    }
}

enum Command {
    Help,
    Version,
    Init(InitArgs),
    InitCodex(InitArgs),
    Doctor,
}

struct InitArgs {
    base_url: String,
    api_key: String,
    websockets: bool,
}

fn parse_command(arguments: &[String]) -> Result<Command> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    match command {
        "-h" | "--help" | "help" if arguments.len() == 1 => return Ok(Command::Help),
        "-V" | "--version" | "version" if arguments.len() == 1 => return Ok(Command::Version),
        "doctor" if arguments.len() == 1 => return Ok(Command::Doctor),
        "init" => return Ok(Command::Init(parse_init_args("init", &arguments[1..])?)),
        "init-codex" => {
            return Ok(Command::InitCodex(parse_init_args(
                "init-codex",
                &arguments[1..],
            )?));
        }
        _ => {}
    }

    // Backward-compatible one-command Claude form used by the public wrappers.
    if arguments.len() == 2 && !arguments[0].starts_with('-') {
        return Ok(Command::Init(finalize_init_args(
            arguments[0].clone(),
            arguments[1].clone(),
            false,
        )?));
    }
    bail!("Unsupported arguments. Run `saiai --help` for usage.")
}

fn parse_init_args(command: &str, arguments: &[String]) -> Result<InitArgs> {
    let mut base_url = None;
    let mut api_key = None;
    let mut websockets = false;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--base-url" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    bail!("Missing value for --base-url");
                };
                if base_url.replace(value.clone()).is_some() {
                    bail!("--base-url may only be provided once");
                }
            }
            "--api-key" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    bail!("Missing value for --api-key");
                };
                if api_key.replace(value.clone()).is_some() {
                    bail!("--api-key may only be provided once");
                }
            }
            "--websockets" if command == "init-codex" => websockets = true,
            "-h" | "--help" => bail!(USAGE),
            value if value.starts_with('-') => bail!("Unsupported option for `{command}`"),
            value => positionals.push(value.to_string()),
        }
        index += 1;
    }

    let mut positionals = positionals.into_iter();
    if base_url.is_none() {
        base_url = positionals.next();
    }
    if api_key.is_none() {
        api_key = positionals.next();
    }
    if positionals.next().is_some() {
        bail!("Too many arguments for `{command}`");
    }
    let Some(base_url) = base_url else {
        bail!("A base URL is required.\n\n{USAGE}");
    };
    let Some(api_key) = api_key else {
        bail!("An API key is required.\n\n{USAGE}");
    };
    finalize_init_args(base_url, api_key, websockets)
}

fn finalize_init_args(base_url: String, api_key: String, websockets: bool) -> Result<InitArgs> {
    let base_url = normalize_base_url(&base_url)?;
    validate_api_key(&api_key)?;
    Ok(InitArgs {
        base_url,
        api_key,
        websockets,
    })
}

fn normalize_base_url(raw: &str) -> Result<String> {
    if raw.trim() != raw || raw.is_empty() {
        bail!("The base URL must be non-empty and contain no surrounding whitespace");
    }
    let mut url = Url::parse(raw).context("The base URL is not a valid absolute URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("The base URL scheme must be http or https");
    }
    if url.host_str().is_none() {
        bail!("The base URL must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("The base URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("The base URL must not contain a query or fragment");
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn validate_api_key(api_key: &str) -> Result<()> {
    if api_key.trim().is_empty() {
        bail!("The API key must not be empty");
    }
    if api_key.contains('\r') || api_key.contains('\n') {
        bail!("The API key must be a single line");
    }
    Ok(())
}

struct ClaudeConfigPaths {
    config_dir: PathBuf,
    settings_path: PathBuf,
    state_path: PathBuf,
    credentials_path: PathBuf,
    ca_path: PathBuf,
}

fn resolve_claude_config_paths() -> Result<ClaudeConfigPaths> {
    if let Some(config_dir) = env_dir_override("CLAUDE_CONFIG_DIR") {
        return Ok(ClaudeConfigPaths {
            settings_path: config_dir.join("settings.json"),
            state_path: config_dir.join(".claude.json"),
            credentials_path: config_dir.join(".credentials.json"),
            ca_path: config_dir.join("saiai-ca.crt"),
            config_dir,
        });
    }
    let home = home_dir().context("Could not resolve the user home directory")?;
    let config_dir = home.join(".claude");
    Ok(ClaudeConfigPaths {
        settings_path: config_dir.join("settings.json"),
        state_path: home.join(".claude.json"),
        credentials_path: config_dir.join(".credentials.json"),
        ca_path: config_dir.join("saiai-ca.crt"),
        config_dir,
    })
}

fn init_claude(arguments: InitArgs) -> Result<()> {
    let paths = resolve_claude_config_paths()?;
    init_claude_at(&paths, &arguments)?;
    println!("SAIAI configured the global Claude Code settings.");
    println!("Updated: {}", paths.settings_path.display());
    println!("Updated: {}", paths.state_path.display());
    println!("Stale Claude OAuth credentials and SAIAI proxy CA were removed if present.");
    println!("Start Claude Code normally with `claude` or from VSCode.");
    Ok(())
}

fn init_claude_at(paths: &ClaudeConfigPaths, arguments: &InitArgs) -> Result<()> {
    let settings_snapshot = FileSnapshot::capture(&paths.settings_path)?;
    let state_snapshot = FileSnapshot::capture(&paths.state_path)?;
    let credentials_snapshot = FileSnapshot::capture(&paths.credentials_path)?;
    let ca_snapshot = FileSnapshot::capture(&paths.ca_path)?;

    // Parse every preserved configuration file before making any filesystem
    // mutation. A malformed file therefore leaves settings and credentials as-is.
    let mut settings = json_object_from_snapshot(&settings_snapshot)?;
    let mut state = json_object_from_snapshot(&state_snapshot)?;

    settings.remove("oauthAccount");
    let mut settings_env = match settings.remove("env") {
        None => Map::new(),
        Some(Value::Object(values)) => values,
        Some(_) => bail!(
            "{} has a non-object `env`; refusing to overwrite it",
            paths.settings_path.display()
        ),
    };
    settings_env.retain(|key, _| !is_conflicting_claude_env(key));
    settings_env.insert(
        "ANTHROPIC_BASE_URL".to_string(),
        Value::String(arguments.base_url.clone()),
    );
    settings_env.insert(
        "CLAUDE_CODE_OAUTH_TOKEN".to_string(),
        Value::String(arguments.api_key.clone()),
    );
    settings_env.insert(
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_string(),
        Value::String("1".to_string()),
    );
    settings_env.insert(
        "CLAUDE_STREAM_IDLE_TIMEOUT_MS".to_string(),
        Value::String(CLAUDE_STREAM_IDLE_TIMEOUT_MS.to_string()),
    );
    settings_env.insert(
        "ENABLE_PROMPT_CACHING_1H".to_string(),
        Value::String("1".to_string()),
    );
    settings_env.insert(
        "ENABLE_TOOL_SEARCH".to_string(),
        Value::String("true".to_string()),
    );
    settings.insert("env".to_string(), Value::Object(settings_env));

    state.remove("oauthAccount");
    state.insert("hasCompletedOnboarding".to_string(), Value::Bool(true));

    ensure_private_directory(&paths.config_dir)?;
    let changes = vec![
        FileChange::replace(settings_snapshot, pretty_json(Value::Object(settings))?),
        FileChange::replace(state_snapshot, pretty_json(Value::Object(state))?),
        FileChange::remove(credentials_snapshot),
        FileChange::remove(ca_snapshot),
    ];
    apply_transaction(changes)
}

fn doctor_claude() -> Result<()> {
    let paths = resolve_claude_config_paths()?;
    let settings_snapshot = FileSnapshot::capture(&paths.settings_path)?;
    let state_snapshot = FileSnapshot::capture(&paths.state_path)?;
    let settings = json_object_from_snapshot(&settings_snapshot)?;
    let state = json_object_from_snapshot(&state_snapshot)?;
    let settings_env = settings
        .get("env")
        .and_then(Value::as_object)
        .context("Claude settings do not contain an `env` object")?;
    for key in ["ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN"] {
        if settings_env
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("Claude settings are missing the SAIAI-managed {key}");
        }
    }
    if settings_env
        .get("CLAUDE_STREAM_IDLE_TIMEOUT_MS")
        .and_then(Value::as_str)
        != Some(CLAUDE_STREAM_IDLE_TIMEOUT_MS)
    {
        bail!("Claude settings have an unexpected stream idle timeout");
    }
    if let Some(key) = settings_env
        .keys()
        .find(|key| is_conflicting_claude_env(key))
    {
        bail!("Claude settings still contain conflicting environment key {key}");
    }
    if state.contains_key("oauthAccount") {
        bail!("Claude state still contains oauthAccount");
    }
    if path_present_no_follow(&paths.credentials_path)? {
        bail!("Claude OAuth credentials still exist");
    }
    println!("Claude global configuration is ready for SAIAI.");
    println!("Settings: {}", paths.settings_path.display());
    println!("State: {}", paths.state_path.display());
    println!("API key: configured (value hidden)");
    Ok(())
}

fn init_codex(arguments: InitArgs) -> Result<()> {
    let config_dir = codex_config_dir()?;
    let config_path = config_dir.join("config.toml");
    let auth_path = config_dir.join("auth.json");
    let config_snapshot = FileSnapshot::capture(&config_path)?;
    let auth_snapshot = FileSnapshot::capture(&auth_path)?;

    let mut config = toml_document_from_snapshot(&config_snapshot)?;
    merge_codex_config(
        &mut config,
        &arguments.base_url,
        arguments.websockets,
        &config_path,
    )?;
    let mut auth = json_object_from_snapshot(&auth_snapshot)?;
    auth.insert(
        "OPENAI_API_KEY".to_string(),
        Value::String(arguments.api_key),
    );

    ensure_private_directory(&config_dir)?;
    apply_transaction(vec![
        FileChange::replace(config_snapshot, config.to_string().into_bytes()),
        FileChange::replace(auth_snapshot, pretty_json(Value::Object(auth))?),
    ])?;
    println!("SAIAI configured the global Codex CLI settings.");
    println!("Updated: {}", config_path.display());
    println!("Updated: {}", auth_path.display());
    Ok(())
}

fn codex_config_dir() -> Result<PathBuf> {
    if let Some(path) = env_dir_override("CODEX_HOME") {
        return Ok(path);
    }
    Ok(home_dir()
        .context("Could not resolve the user home directory")?
        .join(".codex"))
}

fn merge_codex_config(
    document: &mut DocumentMut,
    base_url: &str,
    websockets: bool,
    path: &Path,
) -> Result<()> {
    document["model"] = value("gpt-5.4");
    document["review_model"] = value("gpt-5.4");
    document["model_reasoning_effort"] = value("xhigh");
    document["disable_response_storage"] = value(true);
    document["network_access"] = value("enabled");
    document["windows_wsl_setup_acknowledged"] = value(true);
    document["model_context_window"] = value(1_000_000_i64);
    document["model_auto_compact_token_limit"] = value(900_000_i64);
    document["model_provider"] = value("OpenAI");

    match document.get("model_providers") {
        None => document["model_providers"] = Item::Table(Table::new()),
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has a non-table `model_providers`; refusing to overwrite it",
            path.display()
        ),
    }
    let providers = document["model_providers"]
        .as_table_mut()
        .expect("model_providers was checked above");
    match providers.get("OpenAI") {
        None => {
            providers.insert("OpenAI", Item::Table(Table::new()));
        }
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has a non-table `[model_providers.OpenAI]`; refusing to overwrite it",
            path.display()
        ),
    }
    let provider = providers
        .get_mut("OpenAI")
        .and_then(Item::as_table_mut)
        .expect("OpenAI provider was checked above");
    provider.insert("name", value("OpenAI"));
    provider.insert("base_url", value(base_url));
    provider.insert("wire_api", value("responses"));
    provider.insert("requires_openai_auth", value(false));
    provider.remove("env_key");
    if websockets {
        provider.insert("supports_websockets", value(true));
    } else {
        provider.remove("supports_websockets");
    }

    match (websockets, document.get("features")) {
        (true, None) => document["features"] = Item::Table(Table::new()),
        (_, Some(item)) if !item.is_table() => bail!(
            "{} has a non-table `features`; refusing to overwrite it",
            path.display()
        ),
        _ => {}
    }
    if websockets {
        document["features"]
            .as_table_mut()
            .expect("features was checked above")
            .insert("responses_websockets_v2", value(true));
    } else if let Some(features) = document.get_mut("features").and_then(Item::as_table_mut) {
        features.remove("responses_websockets_v2");
        if features.is_empty() {
            document.as_table_mut().remove("features");
        }
    }
    Ok(())
}

fn env_dir_override(name: &str) -> Option<PathBuf> {
    let raw = env::var_os(name)?;
    if raw.is_empty() || raw.to_string_lossy().trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(raw))
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(
                || match (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
                    (Some(drive), Some(path)) => {
                        let mut full = PathBuf::from(drive);
                        full.push(path);
                        Some(full)
                    }
                    _ => None,
                },
            )
            .or_else(|| env::var_os("HOME").map(PathBuf::from))
    }
    #[cfg(not(windows))]
    {
        env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
    }
}

struct FileSnapshot {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl FileSnapshot {
    fn capture(path: &Path) -> Result<Self> {
        let contents = match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!("Refusing to modify symbolic link: {}", path.display());
                }
                if !metadata.is_file() {
                    bail!(
                        "Configuration path is not a regular file: {}",
                        path.display()
                    );
                }
                Some(fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| format!("Failed to inspect {}", path.display()));
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            contents,
        })
    }
}

struct FileChange {
    snapshot: FileSnapshot,
    replacement: Option<Vec<u8>>,
}

impl FileChange {
    fn replace(snapshot: FileSnapshot, replacement: Vec<u8>) -> Self {
        Self {
            snapshot,
            replacement: Some(replacement),
        }
    }

    fn remove(snapshot: FileSnapshot) -> Self {
        Self {
            snapshot,
            replacement: None,
        }
    }

    fn changed(&self) -> bool {
        self.snapshot.contents.as_deref() != self.replacement.as_deref()
    }
}

fn apply_transaction(changes: Vec<FileChange>) -> Result<()> {
    let changes = changes
        .into_iter()
        .filter(FileChange::changed)
        .collect::<Vec<_>>();
    if changes.is_empty() {
        return Ok(());
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    for change in &changes {
        if let Some(contents) = change.snapshot.contents.as_deref() {
            create_private_backup(&change.snapshot.path, contents, stamp)?;
        }
    }

    for (applied, change) in changes.iter().enumerate() {
        if let Err(error) = apply_change(change) {
            let rollback_error = rollback_changes(&changes[..applied]);
            return match rollback_error {
                Ok(()) => Err(error).context("Configuration update failed and was rolled back"),
                Err(rollback) => Err(error).context(format!(
                    "Configuration update failed; rollback also failed: {rollback:#}"
                )),
            };
        }
    }
    Ok(())
}

fn apply_change(change: &FileChange) -> Result<()> {
    match change.replacement.as_deref() {
        Some(contents) => atomic_write_private(&change.snapshot.path, contents),
        None => match fs::remove_file(&change.snapshot.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("Failed to remove {}", change.snapshot.path.display())),
        },
    }
}

fn rollback_changes(changes: &[FileChange]) -> Result<()> {
    for change in changes.iter().rev() {
        match change.snapshot.contents.as_deref() {
            Some(contents) => atomic_write_private(&change.snapshot.path, contents)?,
            None => match fs::remove_file(&change.snapshot.path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Failed to roll back {}", change.snapshot.path.display())
                    });
                }
            },
        }
    }
    Ok(())
}

fn create_private_backup(path: &Path, contents: &[u8], stamp: u128) -> Result<PathBuf> {
    let parent = path.parent().context("Configuration path has no parent")?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    for suffix in 0..1000_u16 {
        let suffix = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let backup = parent.join(format!("{name}.saiai-backup-{stamp}{suffix}"));
        match write_private_new(&backup, contents) {
            Ok(()) => return Ok(backup),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|value| value.kind() == ErrorKind::AlreadyExists) => {}
            Err(error) => {
                return Err(error).context("Failed to create a private configuration backup");
            }
        }
    }
    bail!("Could not allocate a unique configuration backup name")
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("Configuration path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("Failed to create {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let temporary = parent.join(format!(
        ".{name}.saiai-tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    write_private_new(&temporary, contents)?;
    if let Err(error) = replace_file(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("Failed to replace {}", path.display()));
    }
    sync_parent_best_effort(parent);
    Ok(())
}

fn write_private_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both buffers are NUL-terminated and stay alive for the call.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(unix)]
fn sync_parent_best_effort(path: &Path) {
    if let Ok(directory) = fs::File::open(path) {
        let _ = directory.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent_best_effort(_path: &Path) {}

fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("Failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to protect {}", path.display()))?;
    }
    Ok(())
}

fn json_object_from_snapshot(snapshot: &FileSnapshot) -> Result<Map<String, Value>> {
    let Some(contents) = snapshot.contents.as_deref() else {
        return Ok(Map::new());
    };
    if contents.iter().all(u8::is_ascii_whitespace) {
        return Ok(Map::new());
    }
    let parsed: Value = serde_json::from_slice(contents)
        .with_context(|| format!("Failed to parse {} as JSON", snapshot.path.display()))?;
    match parsed {
        Value::Object(values) => Ok(values),
        _ => bail!(
            "{} is not a JSON object; refusing to overwrite it",
            snapshot.path.display()
        ),
    }
}

fn toml_document_from_snapshot(snapshot: &FileSnapshot) -> Result<DocumentMut> {
    let Some(contents) = snapshot.contents.as_deref() else {
        return Ok(DocumentMut::new());
    };
    let text = std::str::from_utf8(contents)
        .with_context(|| format!("{} is not valid UTF-8", snapshot.path.display()))?;
    if text.trim().is_empty() {
        return Ok(DocumentMut::new());
    }
    text.parse::<DocumentMut>()
        .with_context(|| format!("Failed to parse {} as TOML", snapshot.path.display()))
}

fn pretty_json(value: Value) -> Result<Vec<u8>> {
    let mut contents = serde_json::to_vec_pretty(&value)?;
    contents.push(b'\n');
    Ok(contents)
}

fn path_present_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fake_init(base_url: &str, api_key: &str) -> InitArgs {
        InitArgs {
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
            websockets: false,
        }
    }

    fn test_claude_paths(root: &Path) -> ClaudeConfigPaths {
        let config_dir = root.join(".claude");
        ClaudeConfigPaths {
            settings_path: config_dir.join("settings.json"),
            state_path: root.join(".claude.json"),
            credentials_path: config_dir.join(".credentials.json"),
            ca_path: config_dir.join("saiai-ca.crt"),
            config_dir,
        }
    }

    #[test]
    fn parses_one_command_and_named_forms() {
        for arguments in [
            vec!["https://api.example.test".into(), "TEST_ONLY_KEY".into()],
            vec![
                "init".into(),
                "https://api.example.test/".into(),
                "TEST_ONLY_KEY".into(),
            ],
            vec![
                "init".into(),
                "--base-url".into(),
                "https://api.example.test".into(),
                "--api-key".into(),
                "TEST_ONLY_KEY".into(),
            ],
        ] {
            match parse_command(&arguments).unwrap() {
                Command::Init(init) => {
                    assert_eq!(init.base_url, "https://api.example.test");
                    assert_eq!(init.api_key, "TEST_ONLY_KEY");
                }
                _ => panic!("expected Claude initialization"),
            }
        }
    }

    #[test]
    fn parse_errors_do_not_repeat_api_keys() {
        let key = "TEST_ONLY_SECRET_THAT_MUST_NOT_BE_ECHOED";
        for arguments in [
            vec!["init".into(), "--api-key".into(), key.into()],
            vec!["doctor".into(), key.into()],
            vec!["unsupported".into(), key.into(), "extra".into()],
        ] {
            let error = parse_command(&arguments).err().unwrap().to_string();
            assert!(!error.contains(key));
        }
    }

    #[test]
    fn validates_and_normalizes_base_urls() {
        assert_eq!(
            normalize_base_url("https://api.example.test/tenant///").unwrap(),
            "https://api.example.test/tenant"
        );
        for invalid in [
            "ftp://api.example.test",
            "https://user:pass@api.example.test",
            "https://api.example.test?key=value",
            " relative ",
        ] {
            assert!(normalize_base_url(invalid).is_err());
        }
    }

    #[test]
    fn claude_init_is_repeatable_and_removes_conflicts() {
        let root = TempDir::new().unwrap();
        let paths = test_claude_paths(root.path());
        fs::create_dir_all(&paths.config_dir).unwrap();
        fs::write(
            &paths.settings_path,
            r#"{
  "permissions": {"allow": ["Read"]},
  "env": {
    "KEEP_ME": "yes",
    "ANTHROPIC_AUTH_TOKEN": "old",
    "ANTHROPIC_MODEL": "old-model",
    "AWS_BEARER_TOKEN_BEDROCK": "old-bedrock-token",
    "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME": "old-sonnet",
    "VERTEX_REGION_CLAUDE_4_6_SONNET": "old-region",
    "HTTP_PROXY": "http://127.0.0.1:19908",
    "NODE_EXTRA_CA_CERTS": "/tmp/saiai-ca.crt",
    "CLAUDE_CODE_CLIENT_CERT": "/tmp/old-client.crt",
    "SSL_CERT_FILE": "/tmp/old-ca.crt"
  }
}"#,
        )
        .unwrap();
        fs::write(
            &paths.state_path,
            r#"{"oauthAccount":{"email":"old"},"userID":"machine-local"}"#,
        )
        .unwrap();
        fs::write(&paths.credentials_path, r#"{"oauth":"old"}"#).unwrap();
        fs::write(&paths.ca_path, "old ca").unwrap();

        init_claude_at(
            &paths,
            &fake_init("https://old.example", "TEST_ONLY_OLD_KEY"),
        )
        .unwrap();
        init_claude_at(
            &paths,
            &fake_init("https://new.example", "TEST_ONLY_NEW_KEY"),
        )
        .unwrap();

        let settings: Value =
            serde_json::from_slice(&fs::read(&paths.settings_path).unwrap()).unwrap();
        let env = settings["env"].as_object().unwrap();
        assert_eq!(env["ANTHROPIC_BASE_URL"], "https://new.example");
        assert_eq!(env["CLAUDE_CODE_OAUTH_TOKEN"], "TEST_ONLY_NEW_KEY");
        assert_eq!(env["CLAUDE_STREAM_IDLE_TIMEOUT_MS"], "600000");
        assert_eq!(env["KEEP_ME"], "yes");
        for key in env.keys() {
            assert!(
                !is_conflicting_claude_env(key),
                "conflict was retained: {key}"
            );
        }
        assert_eq!(settings["permissions"]["allow"][0], "Read");

        let state: Value = serde_json::from_slice(&fs::read(&paths.state_path).unwrap()).unwrap();
        assert!(state.get("oauthAccount").is_none());
        assert_eq!(state["userID"], "machine-local");
        assert_eq!(state["hasCompletedOnboarding"], true);
        assert!(!paths.credentials_path.exists());
        assert!(!paths.ca_path.exists());

        let backups = fs::read_dir(&paths.config_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains("saiai-backup"))
            .count();
        assert!(
            backups >= 3,
            "changed settings, credentials, and CA need backups"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&paths.settings_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn malformed_state_prevents_every_mutation() {
        let root = TempDir::new().unwrap();
        let paths = test_claude_paths(root.path());
        fs::create_dir_all(&paths.config_dir).unwrap();
        let original_settings = br#"{"env":{"KEEP_ME":"yes"}}"#;
        let original_credentials = br#"{"oauth":"old"}"#;
        fs::write(&paths.settings_path, original_settings).unwrap();
        fs::write(&paths.state_path, "not json").unwrap();
        fs::write(&paths.credentials_path, original_credentials).unwrap();

        assert!(
            init_claude_at(&paths, &fake_init("https://api.example", "TEST_ONLY_KEY")).is_err()
        );
        assert_eq!(fs::read(&paths.settings_path).unwrap(), original_settings);
        assert_eq!(
            fs::read(&paths.credentials_path).unwrap(),
            original_credentials
        );
    }

    #[test]
    fn codex_merge_preserves_unrelated_values_and_toggles_websockets() {
        let mut document = r#"
custom = "kept"
[features]
other = true
[model_providers.OpenAI]
env_key = "OPENAI_API_KEY"
custom_header = "kept"
"#
        .parse::<DocumentMut>()
        .unwrap();
        let path = Path::new("config.toml");
        merge_codex_config(&mut document, "https://api.example/v1", true, path).unwrap();
        assert_eq!(document["custom"].as_str(), Some("kept"));
        assert_eq!(
            document["model_providers"]["OpenAI"]["custom_header"].as_str(),
            Some("kept")
        );
        assert!(
            document["model_providers"]["OpenAI"]
                .get("env_key")
                .is_none()
        );
        assert_eq!(
            document["features"]["responses_websockets_v2"].as_bool(),
            Some(true)
        );
        merge_codex_config(&mut document, "https://api.example/v1", false, path).unwrap();
        assert!(
            document["features"]
                .get("responses_websockets_v2")
                .is_none()
        );
        assert_eq!(document["features"]["other"].as_bool(), Some(true));
    }
}
