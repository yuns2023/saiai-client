//! Resolve once, before side effects. Config paths and service identities must
//! use the same selection, including children started by a launcher.
use crate::{Command, DoctorTarget};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

static ACTIVE: OnceLock<Scope> = OnceLock::new();

/// Records which product directory an isolated environment serves.
pub(crate) const PRODUCT_DIR_FILENAME: &str = "product-dir";

#[derive(Debug)]
pub(crate) struct Scope {
    pub root: PathBuf,
    pub directory: PathBuf,
    pub isolated: bool,
    product_dir: Option<PathBuf>,
}

impl Scope {
    fn new(root: PathBuf, directory: PathBuf) -> Self {
        let isolated = root != directory;
        Self {
            root,
            directory,
            isolated,
            product_dir: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn service_suffix(&self) -> String {
        service_suffix_for(&self.root, &self.directory)
    }
}

/// Service suffix of any environment directory, independent of the active scope.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn service_suffix_for(root: &Path, directory: &Path) -> String {
    if root != directory {
        format!("-{}", digest(directory))
    } else {
        String::new()
    }
}

/// `<product>-<digest>` for an already normalized product directory.
pub(crate) fn environment_name(product: &str, directory: &Path) -> String {
    format!("{product}-{}", digest(directory))
}

/// Product of an `environments/<name>` directory created by SAIAI.
pub(crate) fn environment_product(name: &str) -> Option<&'static str> {
    let (product, hash) = name.split_once('-')?;
    let product = match product {
        "claude" => "claude",
        "codex" => "codex",
        _ => return None,
    };
    (hash.len() == 24
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(product)
}

/// Normalized user home and SAIAI root, resolved exactly like `initialize`.
pub(crate) fn layout() -> Result<(PathBuf, PathBuf)> {
    let home = normalize(&crate::home_dir().context("failed to resolve home directory")?)?;
    let root = match override_dir("SAIAI_HOME")? {
        Some(directory) => directory,
        None => normalize(&home.join(".saiai"))?,
    };
    Ok((home, root))
}

pub(crate) fn product_override(product: &str) -> Result<Option<PathBuf>> {
    override_dir(match product {
        "claude" => "CLAUDE_CONFIG_DIR",
        _ => "CODEX_HOME",
    })
}

fn digest(path: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(path.as_os_str().as_encoded_bytes());
    format!("{:x}", digest.finalize())[..24].to_string()
}

// Resolve existing ancestors (including symlinks) without creating a directory.
// Do not collapse `..` before following a symlink.
pub(crate) fn normalize(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) => {
                resolved.push(component.as_os_str());
                continue;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            _ => {
                resolved.push(component.as_os_str());
                match fs::symlink_metadata(&resolved) {
                    Ok(_) => {
                        resolved = fs::canonicalize(&resolved).with_context(|| {
                            format!("cannot resolve directory {}", resolved.display())
                        })?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).context("cannot inspect configuration directory");
                    }
                }
            }
        }
        if resolved.exists() && !resolved.is_dir() {
            bail!(
                "configuration directory is not a directory: {}",
                resolved.display()
            );
        }
    }
    // Windows canonicalize returns a verbatim path. Use ordinary spelling when
    // semantically equivalent, so Desktop/user-data and CA consumers keep working.
    #[cfg(windows)]
    let resolved = dunce::simplified(&resolved).to_path_buf();
    Ok(resolved)
}

fn override_dir(name: &str) -> Result<Option<PathBuf>> {
    let Some(raw) = env::var_os(name) else {
        return Ok(None);
    };
    let text = raw
        .to_str()
        .with_context(|| format!("{name} must be valid UTF-8"))?;
    if text.contains(['\r', '\n']) {
        bail!("{name} must be a single-line directory path");
    }
    if text.trim().is_empty() {
        bail!("{name} is set but empty; unset it to select the default environment");
    }
    Ok(Some(normalize(Path::new(&raw))?))
}

/// Environment directory and, when isolated, the product directory it serves.
fn product_directory(
    root: &Path,
    home: &Path,
    product: &str,
) -> Result<(PathBuf, Option<PathBuf>)> {
    let (variable, default) = match product {
        "claude" => ("CLAUDE_CONFIG_DIR", ".claude"),
        "codex" => ("CODEX_HOME", ".codex"),
        _ => bail!("unknown environment: {product}; expected default, claude, or codex"),
    };
    let Some(directory) = override_dir(variable)? else {
        return Ok((root.to_path_buf(), None));
    };
    if normalize(&home.join(default)).ok().as_ref() == Some(&directory) {
        return Ok((root.to_path_buf(), None));
    }
    let environment = root
        .join("environments")
        .join(environment_name(product, &directory));
    Ok((environment, Some(directory)))
}

/// Leading selector is deliberately separate from forwarded product arguments.
pub(crate) fn parse_selector(args: &mut Vec<String>) -> Result<Option<(String, String)>> {
    if !args
        .first()
        .is_some_and(|a| a == "--environment" || a == "--instance-dir")
    {
        return Ok(None);
    }
    if args.len() < 2 {
        bail!("environment selector requires a value");
    }
    let selector = args.remove(0);
    let value = args.remove(0);
    Ok(Some((selector, value)))
}

pub(crate) fn initialize(command: &Command, selector: Option<(String, String)>) -> Result<()> {
    // Uninstall enumerates every environment itself and never uses a scope.
    if matches!(
        command,
        Command::Help | Command::Version | Command::Uninstall(_)
    ) {
        return Ok(());
    }
    let (home, root) = layout()?;
    let product = match command {
        Command::Init(_) | Command::Claude(_) | Command::Doctor(DoctorTarget::Claude) => {
            Some("claude")
        }
        Command::InitCodex(_)
        | Command::Codex(_)
        | Command::VSCode
        | Command::Desktop { .. }
        | Command::Doctor(DoctorTarget::Codex) => Some("codex"),
        _ => None,
    };
    let (selected, product_dir) = match selector.as_ref() {
        Some((flag, value)) if flag == "--instance-dir" => {
            if product.is_some() {
                bail!("--instance-dir is only for proxy service commands");
            }
            (normalize(Path::new(value))?, None)
        }
        Some((_, value)) => {
            if product.is_some_and(|p| p != value) {
                bail!("environment selector conflicts with the product command");
            }
            if value == "default" {
                (root.clone(), None)
            } else {
                product_directory(&root, &home, value)?
            }
        }
        None => match product {
            Some(p) => product_directory(&root, &home, p)?,
            None => {
                let claude = product_directory(&root, &home, "claude")?;
                let codex = product_directory(&root, &home, "codex")?;
                match (claude.0 != root, codex.0 != root) {
                    (true, true) => bail!(
                        "both Claude and Codex environments are selected; use saiai --environment claude|codex|default <command>"
                    ),
                    (true, false) => claude,
                    (false, true) => codex,
                    _ => (root.clone(), None),
                }
            }
        },
    };
    let mut scope = Scope::new(root, selected);
    scope.product_dir = product_dir;
    // Keep an already configured legacy launcher route until explicit init.
    // Never silently fall back for start/stop/restart or a fresh project.
    if scope.isolated
        && !scope.directory.join("config.json").exists()
        && matches!(command, Command::Claude(_) | Command::Codex(_))
        && legacy_route_matches(&scope.root, product.unwrap())?
    {
        eprintln!(
            "Using this environment's existing shared proxy route; rerun initialization to create an isolated proxy."
        );
        scope = Scope::new(scope.root.clone(), scope.root);
    }
    if scope.isolated {
        eprintln!("SAIAI environment: {}", scope.directory.display());
    }
    ACTIVE
        .set(scope)
        .map_err(|_| anyhow::anyhow!("environment was already resolved"))?;
    Ok(())
}

fn legacy_route_matches(root: &Path, product: &str) -> Result<bool> {
    let Ok(raw) = fs::read(root.join("config.json")) else {
        return Ok(false);
    };
    let Ok(config) = serde_json::from_slice::<crate::SaiaiConfig>(&raw) else {
        return Ok(false);
    };
    let proxy = format!("http://{}", config.listen);
    if product == "claude" {
        let path = crate::resolve_claude_config_paths()?.settings_path;
        let Ok(raw) = fs::read(path) else {
            return Ok(false);
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            return Ok(false);
        };
        return Ok(value["env"]["https_proxy"].as_str() == Some(&proxy)
            && value["env"]["NODE_EXTRA_CA_CERTS"].as_str() == Some(&config.ca_cert_path));
    }
    let Ok(raw) = fs::read_to_string(crate::codex_config_dir()?.join(".env")) else {
        return Ok(false);
    };
    // Match the exact managed block, not unrelated text/comments in the file.
    let expected = crate::merge_codex_ide_env("", &config.listen, &config.ca_cert_path);
    Ok(raw.contains(expected.trim()))
}

/// Let `saiai uninstall` map this isolated environment to its product
/// directory later. Only initialization creates a missing environment.
pub(crate) fn record_product_dir(create: bool) -> Result<()> {
    let Some(scope) = active().filter(|scope| scope.isolated) else {
        return Ok(());
    };
    let Some(product_dir) = &scope.product_dir else {
        return Ok(());
    };
    if !create && !scope.directory.is_dir() {
        return Ok(());
    }
    let path = scope.directory.join(PRODUCT_DIR_FILENAME);
    let text = product_dir
        .to_str()
        .context("product directory must be valid UTF-8")?;
    if fs::read_to_string(&path).ok().as_deref() == Some(text) {
        return Ok(());
    }
    crate::write_bytes_atomic(&path, text.as_bytes(), 0o600)
        .with_context(|| format!("failed to record {}", path.display()))
}

pub(crate) fn active() -> Option<&'static Scope> {
    ACTIVE.get()
}
pub(crate) fn isolated() -> bool {
    active().is_some_and(|scope| scope.isolated)
}
#[cfg(target_os = "linux")]
pub(crate) fn service_name() -> String {
    format!(
        "saiai{}.service",
        active().map_or_else(String::new, Scope::service_suffix)
    )
}
#[cfg(target_os = "macos")]
pub(crate) fn launchd_label() -> String {
    format!(
        "top.saiai.local-proxy{}",
        active().map_or_else(String::new, Scope::service_suffix)
    )
}

// Pin the already resolved directory: never re-infer from two inherited vars.
pub(crate) fn pin_start(command: &mut std::process::Command) -> Result<()> {
    command
        .arg("--instance-dir")
        .arg(crate::saiai_config_dir()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_aliases_share_identity() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("a")).unwrap();
        assert_eq!(
            normalize(&temp.path().join("a/../b")).unwrap(),
            normalize(&temp.path().join("b")).unwrap()
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(temp.path().join("a"), temp.path().join("alias")).unwrap();
            assert_eq!(
                normalize(&temp.path().join("alias/new")).unwrap(),
                normalize(&temp.path().join("a/new")).unwrap()
            );
        }
        assert!(normalize(&temp.path().join("a/file/child")).is_ok());
        fs::write(temp.path().join("a/file"), "x").unwrap();
        assert!(normalize(&temp.path().join("a/file/child")).is_err());
    }
    #[test]
    fn default_and_projects_have_distinct_service_identities() {
        let root = PathBuf::from("/saiai");
        let default = Scope::new(root.clone(), root.clone());
        let a = Scope::new(root.clone(), root.join("environments/a"));
        let b = Scope::new(root.clone(), root.join("environments/b"));
        assert!(!default.isolated);
        assert!(default.service_suffix().is_empty());
        assert!(a.isolated && b.isolated);
        assert_ne!(a.service_suffix(), b.service_suffix());
        assert_eq!(
            a.service_suffix(),
            service_suffix_for(&root, &root.join("environments/a"))
        );
    }
    #[test]
    fn environment_names_round_trip_and_reject_foreign_directories() {
        let name = environment_name("codex", Path::new("/work/project/codex"));
        assert_eq!(environment_product(&name), Some("codex"));
        assert_eq!(
            environment_product("claude-0123456789abcdef01234567"),
            Some("claude")
        );
        for foreign in [
            "codex",
            "codex-0123",
            "codex-0123456789ABCDEF01234567",
            "other-0123456789abcdef01234567",
            "codex-0123456789abcdef012345678",
        ] {
            assert_eq!(environment_product(foreign), None, "{foreign}");
        }
    }
}
