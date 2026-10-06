use anyhow::{Context, Result, bail};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{
    CLAUDE_STREAM_IDLE_TIMEOUT_MS, SaiaiConfig, ensure_local_proxy_running_with_start, home_dir,
    read_runtime_ca, read_saiai_config,
};

const LOCAL_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local";

const CONFLICTING_ENV: &[&str] = &[
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "ANTHROPIC_CUSTOM_HEADERS",
    "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "AWS_BEARER_TOKEN_BEDROCK",
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
    "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "CLAUDE_CODE_PROXY_RESOLVES_HOSTS",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CLAUDE_CODE_CLIENT_CERT",
    "CLAUDE_CODE_CLIENT_KEY",
    "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
];

pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut command = process_command()?;
    let config = read_saiai_config()
        .context("SAIAI local proxy is not configured; run the SAIAI Claude setup first")?;
    let token = claude_token(&config)?;
    validate_listen(&config.listen)?;
    let _runtime_ca = read_runtime_ca(&config)
        .context("SAIAI local proxy CA is unavailable; rerun the SAIAI setup")?;
    ensure_local_proxy_running_with_start(&config.listen, || {
        let mut start =
            Command::new(env::current_exe().context("failed to resolve SAIAI executable")?);
        apply_environment(&mut start, &config, token);
        let status = start
            .arg("start")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .context("failed to start the SAIAI local proxy service")?;
        if !status.success() {
            bail!("SAIAI local proxy service failed to start ({status})");
        }
        Ok(())
    })?;
    apply_environment(&mut command, &config, token);
    command.args(args);
    eprintln!(
        "Starting Claude with SAIAI child environment; explicit Claude settings still apply."
    );

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec()).context("failed to start Claude")
    }
    #[cfg(not(unix))]
    {
        let status = command.status().context("failed to start Claude")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn claude_token(config: &SaiaiConfig) -> Result<&str> {
    let token = if let Some(credential) = config.providers.claude.as_ref() {
        &credential.api_key
    } else if config.providers.is_empty() {
        &config.api_key
    } else {
        bail!("SAIAI Claude route is not configured; run the SAIAI Claude setup first");
    };
    if token.trim().is_empty() {
        bail!("SAIAI Claude Key is missing; rerun the SAIAI Claude setup");
    }
    Ok(token)
}

fn validate_listen(listen: &str) -> Result<()> {
    let address = listen
        .parse::<SocketAddr>()
        .context("invalid SAIAI local proxy listen address")?;
    if !address.ip().is_loopback() || address.port() == 0 {
        bail!("SAIAI local proxy must listen on a nonzero loopback port");
    }
    Ok(())
}

fn apply_environment(command: &mut Command, config: &SaiaiConfig, token: &str) {
    for name in CONFLICTING_ENV {
        command.env_remove(name);
    }
    for (name, _) in env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("VERTEX_REGION_CLAUDE_")
        {
            command.env_remove(name);
        }
    }
    let proxy = format!("http://{}", config.listen);
    command
        .env("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        .env("CLAUDE_CODE_OAUTH_TOKEN", token)
        .env("NODE_EXTRA_CA_CERTS", &config.ca_cert_path)
        .env(
            "CLAUDE_STREAM_IDLE_TIMEOUT_MS",
            CLAUDE_STREAM_IDLE_TIMEOUT_MS,
        )
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", LOCAL_NO_PROXY)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("no_proxy", LOCAL_NO_PROXY);
}

#[cfg(not(windows))]
fn process_command() -> Result<Command> {
    let directories = env::var_os("PATH")
        .map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    resolve_unix_program(&directories, home_dir().as_deref()).map(Command::new)
}

#[cfg(not(windows))]
fn resolve_unix_program(directories: &[PathBuf], home: Option<&Path>) -> Result<PathBuf> {
    crate::find_unix_executable(directories, "claude")
        .or_else(|| {
            home.map(|directory| directory.join(".local/bin/claude"))
                .filter(|path| crate::is_unix_executable(path))
        })
        .context(
            "Claude executable was not found in PATH or ~/.local/bin; install Claude Code first",
        )
}

#[cfg(windows)]
fn process_command() -> Result<Command> {
    let search_path = env::var_os("PATH").unwrap_or_default();
    let directories = env::split_paths(&search_path).collect::<Vec<_>>();
    let launch = resolve_windows_launch(&directories, home_dir().as_deref())?;
    let mut command = Command::new(launch.program);
    command.args(launch.prefix_args);
    Ok(command)
}

#[cfg(windows)]
struct WindowsLaunch {
    program: PathBuf,
    prefix_args: Vec<std::ffi::OsString>,
}

#[cfg(windows)]
fn resolve_windows_launch(directories: &[PathBuf], home: Option<&Path>) -> Result<WindowsLaunch> {
    for directory in directories {
        let program = directory.join("claude.exe");
        if program.is_file() {
            return Ok(WindowsLaunch {
                program,
                prefix_args: Vec::new(),
            });
        }
        if ["claude.cmd", "claude.bat"]
            .iter()
            .any(|name| directory.join(name).is_file())
        {
            let entrypoint = directory.join("node_modules/@anthropic-ai/claude-code/cli.js");
            let node = std::iter::once(directory)
                .chain(directories.iter())
                .map(|directory| directory.join("node.exe"))
                .find(|program| program.is_file());
            if let Some(program) = node.filter(|_| entrypoint.is_file()) {
                return Ok(WindowsLaunch {
                    program,
                    prefix_args: vec![entrypoint.into_os_string()],
                });
            }
        }
    }
    if let Some(program) = home
        .map(|directory| directory.join(".local/bin/claude.exe"))
        .filter(|program| program.is_file())
    {
        return Ok(WindowsLaunch {
            program,
            prefix_args: Vec::new(),
        });
    }
    bail!(
        "Claude executable was not found; install native Claude Code or repair its npm installation"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderCredential, ProviderCredentials, SAIAI_CONFIG_VERSION};
    #[cfg(unix)]
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use tempfile::TempDir;

    fn config() -> SaiaiConfig {
        SaiaiConfig {
            version: SAIAI_CONFIG_VERSION,
            base_url: "https://gateway.invalid".to_string(),
            api_key: "synthetic-legacy-key".to_string(),
            listen: "127.0.0.1:19908".to_string(),
            ca_cert_path: "/synthetic/ca.crt".to_string(),
            ca_key_path: "/synthetic/ca.key".to_string(),
            chatgpt_chat_passthrough: false,
            providers: ProviderCredentials::default(),
        }
    }

    fn assert_child_environment(command: &Command, name: &str, expected: Option<&str>) {
        let value = command
            .get_envs()
            .find(|(key, _)| {
                if cfg!(windows) {
                    key.to_string_lossy().eq_ignore_ascii_case(name)
                } else {
                    *key == OsStr::new(name)
                }
            })
            .map(|(_, value)| value);
        assert_eq!(
            value,
            Some(expected.map(OsStr::new)),
            "child environment {name}"
        );
    }

    #[test]
    fn claude_launcher_environment_names_follow_platform_case_rules() {
        let mut command = Command::new("claude");
        command
            .env("HTTP_PROXY", "synthetic-uppercase")
            .env("http_proxy", "synthetic-lowercase");
        let uppercase_value = if cfg!(windows) {
            "synthetic-lowercase"
        } else {
            "synthetic-uppercase"
        };
        assert_child_environment(&command, "HTTP_PROXY", Some(uppercase_value));
        assert_child_environment(&command, "http_proxy", Some("synthetic-lowercase"));
        assert_eq!(
            command.get_envs().count(),
            if cfg!(windows) { 1 } else { 2 }
        );
    }

    #[test]
    fn claude_launcher_replaces_only_child_routing_environment() {
        let config = config();
        let mut command = Command::new("claude");
        for name in CONFLICTING_ENV {
            command.env(name, "synthetic-conflict");
        }
        command
            .env("HOME", "/original-home")
            .env("CLAUDE_CONFIG_DIR", "/original-config")
            .env("ANTHROPIC_MODEL", "user-model")
            .env("UNRELATED", "keep");
        apply_environment(&mut command, &config, "synthetic-child-key");
        for (name, value) in [
            ("HOME", "/original-home"),
            ("CLAUDE_CONFIG_DIR", "/original-config"),
            ("ANTHROPIC_MODEL", "user-model"),
            ("UNRELATED", "keep"),
            ("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-child-key"),
            ("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
            ("NODE_EXTRA_CA_CERTS", "/synthetic/ca.crt"),
            ("CLAUDE_STREAM_IDLE_TIMEOUT_MS", "600000"),
            ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        ] {
            assert_child_environment(&command, name, Some(value));
        }
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert_child_environment(&command, name, Some("http://127.0.0.1:19908"));
        }
        for name in [
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_USE_VERTEX",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
        ] {
            assert_child_environment(&command, name, None);
        }
        for name in ["NO_PROXY", "no_proxy"] {
            assert_child_environment(&command, name, Some(LOCAL_NO_PROXY));
        }
        assert!(command.get_args().next().is_none());
    }

    #[test]
    fn claude_launcher_reuses_reachable_proxy_without_starting_service() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap().to_string();
        ensure_local_proxy_running_with_start(&listen, || panic!("proxy was already reachable"))
            .unwrap();
    }

    #[test]
    fn claude_launcher_proxy_start_callback_is_checked_and_retried() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let replacement = std::cell::RefCell::new(None);
        ensure_local_proxy_running_with_start(&address.to_string(), || {
            replacement.replace(Some(std::net::TcpListener::bind(address)?));
            Ok(())
        })
        .unwrap();
        let failure = ensure_local_proxy_running_with_start("127.0.0.1:0", || {
            bail!("synthetic start failure")
        })
        .unwrap_err();
        assert!(format!("{failure:#}").contains("synthetic start failure"));
    }

    #[test]
    fn claude_launcher_selects_claude_route_and_rejects_codex_only_config() {
        let mut config = config();
        assert_eq!(claude_token(&config).unwrap(), "synthetic-legacy-key");
        config.providers.codex = Some(ProviderCredential {
            base_url: "https://codex.invalid".to_string(),
            api_key: "synthetic-codex-key".to_string(),
        });
        assert!(claude_token(&config).is_err());
        config.providers.claude = Some(ProviderCredential {
            base_url: "https://claude.invalid".to_string(),
            api_key: "synthetic-claude-key".to_string(),
        });
        assert_eq!(claude_token(&config).unwrap(), "synthetic-claude-key");
        config.providers.claude.as_mut().unwrap().api_key.clear();
        assert!(claude_token(&config).is_err());
    }

    #[test]
    fn claude_launcher_requires_loopback_listener() {
        for listen in ["127.0.0.1:19908", "[::1]:19908"] {
            validate_listen(listen).unwrap();
        }
        for listen in ["0.0.0.0:19908", "192.0.2.1:19908", "127.0.0.1:0", "invalid"] {
            assert!(validate_listen(listen).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn claude_launcher_child_process_preserves_profile_and_parent_environment() {
        let temporary = TempDir::new().unwrap();
        let home = temporary.path().join("original-home");
        let config_directory = temporary.path().join("original-config");
        let workspace = temporary.path().join("workspace");
        for directory in [&home, &config_directory, &workspace] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let workspace = workspace.canonicalize().unwrap();
        let files = [
            (
                config_directory.join("settings.json"),
                b"user-settings".as_slice(),
            ),
            (
                config_directory.join(".claude.json"),
                b"user-state".as_slice(),
            ),
            (
                config_directory.join(".credentials.json"),
                b"synthetic-user-credentials".as_slice(),
            ),
            (
                config_directory.join("history.jsonl"),
                b"user-history".as_slice(),
            ),
        ];
        for (path, contents) in &files {
            std::fs::write(path, contents).unwrap();
        }
        let parent_environment = env::vars_os().collect::<HashMap<_, _>>();
        let mut command = Command::new("/bin/sh");
        for name in CONFLICTING_ENV {
            command.env(name, "synthetic-inherited-conflict");
        }
        command
            .current_dir(&workspace)
            .env("HOME", &home)
            .env("CLAUDE_CONFIG_DIR", &config_directory)
            .env("ANTHROPIC_MODEL", "user-model")
            .env("UNRELATED", "keep");
        apply_environment(&mut command, &config(), "synthetic-child-key");
        let result = command
            .args([
                "-c",
                r#"test "$HOME" = "$1" && test "$CLAUDE_CONFIG_DIR" = "$2" && test "$PWD" = "$3" && test "$ANTHROPIC_MODEL" = user-model && test "$UNRELATED" = keep && test "$CLAUDE_CODE_OAUTH_TOKEN" = synthetic-child-key && test "$ANTHROPIC_BASE_URL" = https://api.anthropic.com && test "$HTTP_PROXY" = http://127.0.0.1:19908 && test "$http_proxy" = "$HTTP_PROXY" && test "$NODE_EXTRA_CA_CERTS" = /synthetic/ca.crt && test "$CLAUDE_STREAM_IDLE_TIMEOUT_MS" = 600000 && test -z "${ANTHROPIC_AUTH_TOKEN+x}" && test -z "${ANTHROPIC_API_KEY+x}" && test -z "${NODE_TLS_REJECT_UNAUTHORIZED+x}" && test -z "${CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST+x}""#,
                "fixture-child",
            ])
            .arg(&home)
            .arg(&config_directory)
            .arg(&workspace)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
        assert!(parent_environment == env::vars_os().collect::<HashMap<_, _>>());
        for (path, contents) in files {
            assert_eq!(std::fs::read(path).unwrap(), contents);
        }
        assert_eq!(std::fs::read_dir(&config_directory).unwrap().count(), 4);
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 3);
    }

    #[cfg(not(windows))]
    #[test]
    fn claude_launcher_resolves_path_then_native_installer_fallback() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = TempDir::new().unwrap();
        let fallback = temporary.path().join(".local/bin/claude");
        std::fs::create_dir_all(fallback.parent().unwrap()).unwrap();
        std::fs::write(&fallback, "synthetic executable").unwrap();
        std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            resolve_unix_program(&[], Some(temporary.path())).unwrap(),
            fallback
        );
        let preferred = temporary.path().join("claude");
        std::fs::write(&preferred, "synthetic executable").unwrap();
        std::fs::set_permissions(&preferred, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            resolve_unix_program(&[temporary.path().to_path_buf()], Some(temporary.path()))
                .unwrap(),
            preferred
        );
        assert!(resolve_unix_program(&[], None).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn claude_launcher_resolves_native_and_npm_without_shell() {
        let temporary = TempDir::new().unwrap();
        let directory = temporary.path();
        let native = directory.join("claude.exe");
        std::fs::write(&native, "synthetic executable").unwrap();
        assert_eq!(
            resolve_windows_launch(&[directory.to_path_buf()], None)
                .unwrap()
                .program,
            native
        );
        std::fs::remove_file(native).unwrap();
        std::fs::write(directory.join("claude.cmd"), "synthetic shim").unwrap();
        assert!(resolve_windows_launch(&[directory.to_path_buf()], None).is_err());
        let entrypoint = directory.join("node_modules/@anthropic-ai/claude-code/cli.js");
        std::fs::create_dir_all(entrypoint.parent().unwrap()).unwrap();
        std::fs::write(&entrypoint, "synthetic script").unwrap();
        let node = directory.join("node.exe");
        std::fs::write(&node, "synthetic executable").unwrap();
        let launch = resolve_windows_launch(&[directory.to_path_buf()], None).unwrap();
        assert_eq!(launch.program, node);
        assert_eq!(launch.prefix_args, vec![entrypoint.into_os_string()]);
    }
}
