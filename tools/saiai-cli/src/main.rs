use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use base64::Engine;
use chrono::Utc;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::env;
#[cfg(windows)]
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::io::{BufRead, BufReader as StdBufReader};
use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use toml_edit::{DocumentMut, Item, Table, value};
use url::Url;
use uuid::Uuid;

mod desktop_product;
mod local_proxy;

use desktop_product::DesktopProduct;

const ANTHROPIC_HOST: &str = "api.anthropic.com";
#[cfg(target_os = "linux")]
const SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME: &str = "saiai-local-proxy";
const USAGE: &str = "\
Usage:
  saiai                                                           # run local Claude Code proxy
  saiai --verbose                                                 # run local proxy with request logs
  saiai start                                                     # install and start user service
  saiai stop                                                      # stop and disable user service
  saiai status                                                    # show user service status
  saiai logs                                                      # follow user service logs
  saiai update                                                    # update this client binary
  saiai restart                                                   # restart user service
  saiai doctor [claude|codex]                                    # check proxy and product config
  saiai --version                                                 # print version
  saiai init <base_url> <api_key>                                 # initialize Claude Code
  saiai init-codex <base_url> <api_key> [--websockets]            # initialize Codex CLI
  saiai codex [-- <codex arguments>]                              # launch Codex through SAIAI local proxy
  saiai vscode                                                    # configure the Codex VSCode extension for SAIAI
  saiai desktop [codex] [-- <Desktop arguments>]                # launch Codex Desktop through SAIAI
  saiai init       --base-url <base_url> --api-key <api_key>      # initialize Claude Code
  saiai init-codex --base-url <base_url> --api-key <api_key> [--websockets]";

const SAIAI_CA_FILENAME: &str = "saiai-ca.crt";
const SAIAI_CA_KEY_FILENAME: &str = "saiai-ca.key";
#[cfg(target_os = "windows")]
const WINDOWS_PACKAGED_PROXY_LEASE_FILENAME: &str = "windows-packaged-proxy-lease.json";
const SAIAI_CONFIG_VERSION: u32 = 2;
const CLAUDE_STREAM_IDLE_TIMEOUT_MS: &str = "600000";
const DEFAULT_LOCAL_PROXY_LISTEN: &str = "127.0.0.1:19908";
// Claude's updater must use the user's normal network path. Model/API
// traffic remains routed through the SAIAI local proxy.
const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local,downloads.claude.ai";
const SAIAI_CONFIG_FILENAME: &str = "config.json";

// `saiai codex` owns these variables only in the Codex child process. The
// invoking shell and the user's system environment are never modified.
const CODEX_MANAGED_ENV: &[&str] = &[
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "CODEX_ACCESS_TOKEN",
    "CODEX_CA_CERTIFICATE",
    "SSL_CERT_FILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];
const CODEX_LOCAL_PROXY_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local";
const CODEX_IDE_ENV_BEGIN: &str = "# BEGIN SAIAI CODEX IDE (managed)";
const CODEX_IDE_ENV_END: &str = "# END SAIAI CODEX IDE (managed)";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CODEX_CERTIFICATE_CONTROL_HOST: &str = "certificate.saiai.local";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CODEX_CERTIFICATE_SPKI_HEADER: &str = "x-saiai-leaf-spki-sha256";
const CODEX_PLACEHOLDER_ACCOUNT_ID: &str = "saiai-local-proxy-account";
// Structurally valid but unsigned and therefore unusable against OpenAI. The
// local proxy replaces request authentication at the Gateway boundary; these
// claims only let Codex's local app-server expose an authenticated UI state.
const CODEX_PLACEHOLDER_ID_TOKEN: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InNhaWFpLWxvY2FsLXByb3h5QGludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3VzZXJfaWQiOiJzYWlhaS1sb2NhbC1wcm94eS11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoic2FpYWktbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.c2FpYWktbG9jYWwtcHJveHk";
// Electron's Desktop shell decodes the access token as a JWT before it asks
// its app-server for account state. Reuse the unsigned local-only token for
// both fields; the local proxy replaces authorization before Gateway egress.
const CODEX_PLACEHOLDER_ACCESS_TOKEN: &str = CODEX_PLACEHOLDER_ID_TOKEN;

// Optional fixed timezone for ChatGPT Desktop ordinary Chat. It is read by
// the launcher and applied only to the Desktop child process; the parent
// shell and system timezone are never modified.
const SAIAI_CHATGPT_TIMEZONE_ENV: &str = "SAIAI_CHATGPT_TIMEZONE";
const DEFAULT_CHATGPT_TIMEZONE: &str = "America/Los_Angeles";

// Remove stale routing, authentication, model, proxy, and CA values before
// installing the exact local-proxy environment. Unrelated user settings are
// preserved.
const CLAUDE_MANAGED_ROUTING_ENV: &[&str] = &[
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
const CLAUDE_MANAGED_ROUTING_ENV_PREFIXES: &[&str] = &["VERTEX_REGION_CLAUDE_"];
const CLAUDE_PROXY_ENV_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];
const CLAUDE_PROXY_ENV_UNSET_KEYS: &str =
    "HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy";
const SAIAI_SERVICE_NAME: &str = "saiai.service";
#[cfg(target_os = "macos")]
const SAIAI_LAUNCHD_LABEL: &str = "top.saiai.local-proxy";
#[cfg(target_os = "macos")]
const MACOS_ID_COMMAND: &str = "/usr/bin/id";
#[cfg(target_os = "macos")]
const MACOS_LAUNCHCTL_COMMAND: &str = "/bin/launchctl";
#[cfg(target_os = "macos")]
const MACOS_TAIL_COMMAND: &str = "/usr/bin/tail";
#[cfg(target_os = "linux")]
const SAIAI_LINUX_PID_FILENAME: &str = "saiai.pid";
#[cfg(target_os = "linux")]
const SAIAI_LINUX_LOCK_FILENAME: &str = "saiai.lock";
#[cfg(target_os = "linux")]
const SAIAI_LINUX_BACKGROUND_COMMAND: &str = "__run-background-proxy";
#[cfg(target_os = "linux")]
const SAIAI_LINUX_BACKGROUND_STATE_VERSION: u32 = 1;
#[cfg(target_os = "windows")]
const SAIAI_WINDOWS_PID_FILENAME: &str = "saiai.pid";
#[cfg(target_os = "windows")]
const SAIAI_WINDOWS_BACKGROUND_COMMAND: &str = "__run-background-proxy";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const SAIAI_SERVICE_LOG_FILENAME: &str = "saiai.log";

fn is_managed_claude_env(key: &str) -> bool {
    CLAUDE_MANAGED_ROUTING_ENV
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
        || CLAUDE_MANAGED_ROUTING_ENV_PREFIXES
            .iter()
            .any(|prefix| key.to_ascii_uppercase().starts_with(prefix))
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args)? {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::RunProxy { verbose } => run_local_proxy(verbose),
        Command::Start => run_service_start(),
        Command::Stop => run_service_stop(),
        Command::Status => run_service_status(),
        Command::Logs => run_service_logs(),
        Command::Update => run_update(),
        Command::Restart => run_service_restart(),
        Command::Doctor(target) => run_doctor(target),
        Command::Version => print_version(),
        Command::Init(init) => init_claude(init),
        Command::InitCodex(init) => init_codex(init),
        Command::Codex(args) => run_codex(&args),
        Command::VSCode => configure_vscode(),
        Command::Desktop { product, args } => run_desktop(product, &args),
        #[cfg(target_os = "linux")]
        Command::RunLinuxBackgroundProxy => run_linux_background_proxy_worker(),
        #[cfg(target_os = "windows")]
        Command::RunWindowsBackgroundProxy => run_windows_background_proxy_worker(),
    }
}

#[derive(Debug)]
enum Command {
    Help,
    RunProxy {
        verbose: bool,
    },
    Start,
    Stop,
    Status,
    Logs,
    Update,
    Restart,
    Doctor(DoctorTarget),
    Version,
    Init(InitArgs),
    InitCodex(InitArgs),
    Codex(Vec<String>),
    VSCode,
    Desktop {
        product: DesktopProduct,
        args: Vec<String>,
    },
    #[cfg(target_os = "linux")]
    RunLinuxBackgroundProxy,
    #[cfg(target_os = "windows")]
    RunWindowsBackgroundProxy,
}

#[derive(Debug)]
struct InitArgs {
    base_url: String,
    api_key: String,
    /// Only consulted by `init-codex`. `init` (Claude) ignores this field.
    websockets: bool,
}

fn parse_command(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Ok(Command::RunProxy { verbose: false });
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" if args.len() == 1 => return Ok(Command::Help),
        "-v" | "--verbose" => {
            if args.len() == 1 {
                return Ok(Command::RunProxy { verbose: true });
            }
            bail!(
                "Unexpected argument after {}: {}\n\n{}",
                args[0],
                args[1],
                USAGE
            );
        }
        "start" => return parse_no_arg_command("start", &args[1..], Command::Start),
        "stop" => return parse_no_arg_command("stop", &args[1..], Command::Stop),
        "status" => return parse_no_arg_command("status", &args[1..], Command::Status),
        "logs" => return parse_no_arg_command("logs", &args[1..], Command::Logs),
        "update" => return parse_no_arg_command("update", &args[1..], Command::Update),
        "restart" => return parse_no_arg_command("restart", &args[1..], Command::Restart),
        "doctor" => {
            return match args.get(1).map(String::as_str) {
                None => Ok(Command::Doctor(DoctorTarget::All)),
                Some("claude") if args.len() == 2 => Ok(Command::Doctor(DoctorTarget::Claude)),
                Some("codex") if args.len() == 2 => Ok(Command::Doctor(DoctorTarget::Codex)),
                Some(value) => bail!("Unexpected doctor target: {value}\n\n{USAGE}"),
            };
        }
        "-V" | "--version" | "version" => return Ok(Command::Version),
        "init" => return Ok(Command::Init(parse_named_args("init", &args[1..])?)),
        "init-codex" => {
            return Ok(Command::InitCodex(parse_named_args(
                "init-codex",
                &args[1..],
            )?));
        }
        "codex" => {
            let mut codex_args = args[1..].to_vec();
            if codex_args.first().is_some_and(|arg| arg == "--") {
                codex_args.remove(0);
            }
            return Ok(Command::Codex(codex_args));
        }
        "vscode" => return parse_no_arg_command("vscode", &args[1..], Command::VSCode),
        "desktop" | "chatgpt" => {
            let (product, start) = if args[0] == "chatgpt" {
                (DesktopProduct::ChatGPT, 1)
            } else if args
                .get(1)
                .is_some_and(|value| value != "--" && !value.starts_with('-'))
            {
                (DesktopProduct::parse(&args[1])?, 2)
            } else {
                (DesktopProduct::Codex, 1)
            };
            let mut desktop_args = args[start..].to_vec();
            if desktop_args.first().is_some_and(|arg| arg == "--") {
                desktop_args.remove(0);
            }
            return Ok(Command::Desktop {
                product,
                args: desktop_args,
            });
        }
        #[cfg(target_os = "linux")]
        SAIAI_LINUX_BACKGROUND_COMMAND => {
            return parse_no_arg_command(
                SAIAI_LINUX_BACKGROUND_COMMAND,
                &args[1..],
                Command::RunLinuxBackgroundProxy,
            );
        }
        #[cfg(target_os = "windows")]
        SAIAI_WINDOWS_BACKGROUND_COMMAND => {
            return parse_no_arg_command(
                SAIAI_WINDOWS_BACKGROUND_COMMAND,
                &args[1..],
                Command::RunWindowsBackgroundProxy,
            );
        }
        _ => {}
    }

    bail!("Unknown command: {}\n\n{}", args[0], USAGE);
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DoctorTarget {
    All,
    Claude,
    Codex,
}

fn parse_no_arg_command(command: &str, rest: &[String], parsed: Command) -> Result<Command> {
    if rest.is_empty() {
        return Ok(parsed);
    }
    bail!(
        "Unexpected argument after {}: {}\n\n{}",
        command,
        rest[0],
        USAGE
    );
}

fn parse_named_args(command: &str, args: &[String]) -> Result<InitArgs> {
    let mut base_url = String::new();
    let mut api_key = String::new();
    let mut websockets = false;
    let mut positionals = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--base-url" => {
                i += 1;
                if i >= args.len() {
                    bail!("Missing value for --base-url");
                }
                base_url = args[i].clone();
            }
            "--api-key" => {
                i += 1;
                if i >= args.len() {
                    bail!("Missing value for --api-key");
                }
                api_key = args[i].clone();
            }
            // Retain this legacy WebUI flag as a no-op on the local-proxy
            // route. The proxy supports both HTTP and WebSocket Responses;
            // `init-codex` no longer writes a direct-provider transport mode.
            "--websockets" if command == "init-codex" => {
                websockets = true;
            }
            "-h" | "--help" => {
                bail!(USAGE);
            }
            unknown if unknown.starts_with('-') => {
                bail!("Unknown option for `{}`: {}", command, unknown);
            }
            value => {
                positionals.push(value.to_string());
            }
        }
        i += 1;
    }

    let mut positional_iter = positionals.into_iter();
    if base_url.is_empty()
        && let Some(value) = positional_iter.next()
    {
        base_url = value;
    }
    if api_key.is_empty()
        && let Some(value) = positional_iter.next()
    {
        api_key = value;
    }
    if let Some(extra) = positional_iter.next() {
        bail!(
            "Unexpected positional argument for `{}`: {}",
            command,
            extra
        );
    }

    if base_url.is_empty() || api_key.is_empty() {
        bail!(USAGE);
    }
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

fn ensure_installation_ca(cert_path: &Path, key_path: &Path, timestamp: &str) -> Result<bool> {
    if let (Ok(cert_pem), Ok(key_pem)) =
        (fs::read_to_string(cert_path), fs::read_to_string(key_path))
        && local_proxy::validate_tls_config(&cert_pem, &key_pem).is_ok()
    {
        return Ok(false);
    }

    backup_if_exists(cert_path, timestamp)?;
    backup_if_exists(key_path, timestamp)?;
    let (cert_pem, key_pem) = generate_installation_ca()?;
    local_proxy::validate_tls_config(&cert_pem, &key_pem)
        .context("generated SAIAI installation CA did not validate")?;
    write_bytes_atomic(cert_path, cert_pem.as_bytes(), 0o644)
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    write_bytes_atomic(key_path, key_pem.as_bytes(), 0o600)
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok(true)
}

fn generate_installation_ca() -> Result<(String, String)> {
    let key = KeyPair::generate().context("failed to generate SAIAI installation CA key")?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .context("failed to create SAIAI installation CA parameters")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "SAIAI local installation CA");
    distinguished_name.push(DnType::OrganizationName, "SAIAI");
    params.distinguished_name = distinguished_name;
    let certificate = params
        .self_signed(&key)
        .context("failed to self-sign SAIAI installation CA")?;
    Ok((certificate.pem(), key.serialize_pem()))
}

fn init_claude(args: InitArgs) -> Result<()> {
    warn_process_env_conflicts();
    let paths = resolve_claude_config_paths().context("failed to resolve Claude config paths")?;
    let claude_dir = &paths.config_dir;
    let settings_path = &paths.settings_path;
    let state_path = &paths.state_path;
    let credentials_path = &paths.credentials_path;
    let default_ca_path = claude_dir.join(SAIAI_CA_FILENAME);
    let default_ca_key_path = claude_dir.join(SAIAI_CA_KEY_FILENAME);
    let (ca_path, ca_key_path) =
        existing_runtime_ca_paths().unwrap_or((default_ca_path, default_ca_key_path));

    fs::create_dir_all(claude_dir)
        .with_context(|| format!("failed to create {}", claude_dir.display()))?;
    fs::create_dir_all(saiai_config_dir()?).context("failed to create SAIAI config directory")?;

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(settings_path, &timestamp)?;
    backup_if_exists(state_path, &timestamp)?;
    remove_if_exists_with_backup(credentials_path, &timestamp)?;

    let ca_changed = ensure_installation_ca(&ca_path, &ca_key_path, &timestamp)?;

    let saiai_config = update_saiai_provider_config(
        ProviderKind::Claude,
        ProviderCredential {
            base_url: args.base_url.clone(),
            api_key: args.api_key.clone(),
        },
        Some((ca_path.clone(), ca_key_path.clone())),
    )?;

    let mut settings = load_json_object(settings_path)?;
    clean_claude_settings(&mut settings);
    let env_value = settings
        .remove("env")
        .and_then(as_object)
        .unwrap_or_default();
    let mut env_obj = env_value;
    apply_common_claude_env(&mut env_obj, &args.api_key);
    apply_claude_local_proxy_env(&mut env_obj, &saiai_config.config.listen, &ca_path);
    settings.insert("env".to_string(), Value::Object(env_obj));
    write_json_object(settings_path, Value::Object(settings))?;

    let mut state = load_json_object(state_path)?;
    clean_claude_state(&mut state);
    state.insert("hasCompletedOnboarding".to_string(), Value::Bool(true));
    write_json_object(state_path, Value::Object(state))?;

    println!("SAIAI configured Claude Code for local proxy mode.");
    println!("Updated:");
    println!("  {}", settings_path.display());
    println!("  {}", state_path.display());
    println!("  {}", ca_path.display());
    println!("  {}", ca_key_path.display());
    println!("  {}", saiai_config_path()?.display());
    println!("Removed stale Claude OAuth credentials if present:");
    println!("  {}", credentials_path.display());
    warn_claude_settings_overrides_for_paths(&paths);
    start_managed_service_after_initialization(saiai_config.changed || ca_changed)?;

    Ok(())
}

fn init_codex(args: InitArgs) -> Result<()> {
    let codex_dir = codex_config_dir().context("failed to resolve Codex config directory")?;
    fs::create_dir_all(&codex_dir)
        .with_context(|| format!("failed to create {}", codex_dir.display()))?;

    let config_path = codex_dir.join("config.toml");
    let auth_path = codex_dir.join("auth.json");

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    backup_if_exists(&config_path, &timestamp)?;
    backup_if_exists(&auth_path, &timestamp)?;

    let proxy_init = initialize_codex_local_proxy(&args, &timestamp)?;
    let oauth_init = configure_codex_oauth_local_proxy(&codex_dir, &proxy_init)?;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    prepare_desktop_onboarding_state(&codex_dir)?;
    #[cfg(target_os = "linux")]
    ensure_direct_linux_desktop_trust(&proxy_init.ca_cert_path);

    println!("SAIAI configured Codex for local-proxy OAuth mode.");
    println!("Updated:");
    println!("  {}", config_path.display());
    println!("  {}", oauth_init.auth_path.display());
    println!("  {}", oauth_init.env_path.display());
    println!("  {}", codex_dir.join(".codex-global-state.json").display());
    println!("  {}", proxy_init.config_path.display());
    println!("  {}", proxy_init.ca_cert_path.display());
    println!("  {}", proxy_init.ca_key_path.display());
    println!("  proxy=http://{}", proxy_init.listen);
    println!(
        "Migrated {} Codex config file(s) to the built-in OpenAI provider with backups.",
        oauth_init.files.len()
    );
    if args.websockets {
        println!(
            "`--websockets` is no longer needed: the local proxy supports Responses HTTP and WebSocket traffic."
        );
    }
    println!(
        "SAIAI local-proxy OAuth configuration is ready; run `saiai codex` or restart VSCode."
    );
    warn_claude_settings_overrides();
    start_managed_service_after_initialization(proxy_init.config_changed)?;

    Ok(())
}

struct CodexLocalProxyInit {
    config_path: PathBuf,
    config_changed: bool,
    listen: String,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
}

struct SaiaiConfigUpdate {
    config: SaiaiConfig,
    changed: bool,
}

struct CodexOAuthInitialization {
    auth_path: PathBuf,
    env_path: PathBuf,
    files: Vec<PathBuf>,
}

fn configure_codex_oauth_local_proxy(
    codex_dir: &Path,
    proxy_init: &CodexLocalProxyInit,
) -> Result<CodexOAuthInitialization> {
    let auth_path = codex_dir.join("auth.json");
    ensure_codex_local_proxy_auth(&auth_path)?;
    validate_codex_oauth_auth(&auth_path)?;
    let files = prepare_codex_oauth_files(codex_dir, true)?;
    let env_path = codex_dir.join(".env");
    let ca_cert_path = proxy_init.ca_cert_path.to_string_lossy();
    write_codex_ide_env(&env_path, &proxy_init.listen, &ca_cert_path)?;
    Ok(CodexOAuthInitialization {
        auth_path,
        env_path,
        files,
    })
}

fn initialize_codex_local_proxy(args: &InitArgs, timestamp: &str) -> Result<CodexLocalProxyInit> {
    let config_dir = saiai_config_dir()?;
    initialize_codex_local_proxy_at(&config_dir, args, timestamp)
}

fn initialize_codex_local_proxy_at(
    config_dir: &Path,
    args: &InitArgs,
    timestamp: &str,
) -> Result<CodexLocalProxyInit> {
    fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;
    let config_path = config_dir.join(SAIAI_CONFIG_FILENAME);
    let proxy_base_url = codex_proxy_gateway_root(&args.base_url)?;

    if let Ok(raw) = fs::read_to_string(&config_path)
        && let Ok(existing) = serde_json::from_str::<SaiaiConfig>(&raw)
        && read_runtime_ca(&existing).is_ok()
    {
        let mut migrated_legacy = false;
        if existing.providers.claude.is_none()
            && existing.providers.codex.is_none()
            && legacy_claude_proxy_configured()
        {
            let mut migrated = existing;
            migrated.providers.claude = Some(ProviderCredential {
                base_url: migrated.base_url.clone(),
                api_key: migrated.api_key.clone(),
            });
            write_saiai_config_at(&config_path, &migrated)?;
            migrated_legacy = true;
        }
        let updated = update_saiai_provider_config_at(
            &config_path,
            ProviderKind::Codex,
            ProviderCredential {
                base_url: proxy_base_url,
                api_key: args.api_key.clone(),
            },
            None,
        )?;
        return Ok(CodexLocalProxyInit {
            config_path,
            config_changed: migrated_legacy || updated.changed,
            listen: updated.config.listen,
            ca_cert_path: PathBuf::from(updated.config.ca_cert_path),
            ca_key_path: PathBuf::from(updated.config.ca_key_path),
        });
    }

    backup_if_exists(&config_path, timestamp)?;
    let ca_cert_path = config_dir.join(SAIAI_CA_FILENAME);
    let ca_key_path = config_dir.join(SAIAI_CA_KEY_FILENAME);
    let _ca_changed = ensure_installation_ca(&ca_cert_path, &ca_key_path, timestamp)?;
    let mut config = SaiaiConfig {
        version: SAIAI_CONFIG_VERSION,
        base_url: proxy_base_url.clone(),
        api_key: args.api_key.clone(),
        listen: select_local_proxy_listen(None)?,
        ca_cert_path: ca_cert_path.display().to_string(),
        ca_key_path: ca_key_path.display().to_string(),
        chatgpt_chat_passthrough: true,
        providers: ProviderCredentials::default(),
    };
    config.providers.codex = Some(ProviderCredential {
        base_url: proxy_base_url,
        api_key: args.api_key.clone(),
    });
    write_saiai_config_at(&config_path, &config)?;
    Ok(CodexLocalProxyInit {
        config_path,
        config_changed: true,
        listen: config.listen,
        ca_cert_path,
        ca_key_path,
    })
}

fn codex_proxy_gateway_root(base_url: &str) -> Result<String> {
    let mut url = Url::parse(base_url).context("failed to parse Codex Gateway base URL")?;
    let path = url.path().trim_end_matches('/');
    let root_path = path.strip_suffix("/v1").unwrap_or(path).to_string();
    url.set_path(if root_path.is_empty() {
        "/"
    } else {
        &root_path
    });
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// Launch the real Codex executable with a child-only SAIAI proxy environment.
///
/// This mode deliberately keeps Codex's built-in OpenAI provider and ChatGPT
/// OAuth credential. The local proxy changes the network route and performs
/// the Gateway authentication at its own upstream boundary; it does not write
/// a third-party `base_url` into Codex configuration.
fn run_codex(args: &[String]) -> Result<()> {
    let codex_dir = codex_config_dir().context("failed to resolve Codex config directory")?;
    let auth_path = codex_dir.join("auth.json");
    // Resolve the executable before mutating auth/config or starting the
    // proxy. Official installers may add ~/.local/bin only for future
    // terminals, and Windows npm installs expose a .cmd shim that Rust's
    // Command cannot execute directly.
    let mut command = codex_process_command().context("failed to resolve Codex executable")?;
    let cfg = read_saiai_config()
        .context("SAIAI local proxy is not configured; run the SAIAI Claude setup first")?;
    let _runtime_ca = read_runtime_ca(&cfg)
        .context("SAIAI local proxy CA is unavailable; rerun the SAIAI setup")?;
    let files = prepare_codex_oauth_files(&codex_dir, false)?;
    ensure_codex_local_proxy_auth(&auth_path)?;
    validate_codex_oauth_auth(&auth_path)?;
    ensure_local_proxy_running(&cfg.listen)?;

    let proxy = format!("http://{}", cfg.listen);
    // The local-proxy launcher owns proxy variables only in this child
    // process. Linux/macOS need Codex's system-proxy resolver, while Windows
    // must keep it off: WinHTTP can resolve DIRECT before Codex considers the
    // child environment, bypassing the loopback proxy entirely.
    command.args(codex_launcher_args(args));
    command.env("CODEX_HOME", &codex_dir);
    command.env("CODEX_CA_CERTIFICATE", &cfg.ca_cert_path);
    command
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", CODEX_LOCAL_PROXY_NO_PROXY)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("no_proxy", CODEX_LOCAL_PROXY_NO_PROXY);
    for name in CODEX_MANAGED_ENV {
        if !matches!(
            *name,
            "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "NO_PROXY"
                | "http_proxy"
                | "https_proxy"
                | "all_proxy"
                | "no_proxy"
                | "CODEX_CA_CERTIFICATE"
        ) {
            command.env_remove(*name);
        }
    }

    println!("Starting Codex through the SAIAI local proxy.");
    println!("  CODEX_HOME={}", codex_dir.display());
    println!("  proxy={proxy}");
    println!(
        "  migrated {} Codex config file(s) with backups",
        files.len()
    );
    let status = command.status().context("failed to start codex")?;
    if status.success() {
        Ok(())
    } else {
        bail!("codex exited with {status}")
    }
}

#[cfg(not(windows))]
fn codex_process_command() -> Result<ProcessCommand> {
    let path_directories = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    if let Some(program) = find_unix_executable(&path_directories, "codex") {
        return Ok(ProcessCommand::new(program));
    }

    if let Some(home) = home_dir() {
        let official_installer_program = home.join(".local/bin/codex");
        if is_unix_executable(&official_installer_program) {
            return Ok(ProcessCommand::new(official_installer_program));
        }
    }

    bail!(
        "Codex executable was not found in PATH or ~/.local/bin; install Codex and open a new terminal"
    )
}

#[cfg(not(windows))]
fn find_unix_executable(directories: &[PathBuf], name: &str) -> Option<PathBuf> {
    directories
        .iter()
        .map(|directory| directory.join(name))
        .find(|candidate| is_unix_executable(candidate))
}

#[cfg(not(windows))]
fn is_unix_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn codex_process_command() -> Result<ProcessCommand> {
    let search_path = env::var_os("PATH").context("PATH is unavailable")?;
    let launch = resolve_windows_codex_launch(&search_path)?;
    let mut command = ProcessCommand::new(launch.program);
    command.args(launch.prefix_args);
    Ok(command)
}

#[cfg(windows)]
struct WindowsCodexLaunch {
    program: PathBuf,
    prefix_args: Vec<OsString>,
}

#[cfg(windows)]
fn resolve_windows_codex_launch(search_path: &OsStr) -> Result<WindowsCodexLaunch> {
    let mut npm_shim_seen = false;
    for directory in env::split_paths(search_path) {
        for name in ["codex.exe", "codex.com"] {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Ok(WindowsCodexLaunch {
                    program: candidate,
                    prefix_args: Vec::new(),
                });
            }
        }

        for name in ["codex.cmd", "codex.bat"] {
            let shim = directory.join(name);
            if !shim.is_file() {
                continue;
            }
            npm_shim_seen = true;
            let entrypoint = directory.join("node_modules/@openai/codex/bin/codex.js");
            if !entrypoint.is_file() {
                continue;
            }
            let node = [directory.join("node.exe"), directory.join("node.com")]
                .into_iter()
                .find(|candidate| candidate.is_file())
                .or_else(|| find_windows_program(search_path, &["node.exe", "node.com"]));
            if let Some(node) = node {
                return Ok(WindowsCodexLaunch {
                    program: node,
                    prefix_args: vec![entrypoint.into_os_string()],
                });
            }
        }
    }

    if npm_shim_seen {
        bail!(
            "Codex npm command shim was found, but its Node.js entrypoint could not be resolved; reinstall Codex CLI and open a new terminal"
        );
    }
    bail!("Codex executable was not found in PATH; install Codex CLI and open a new terminal")
}

#[cfg(windows)]
fn find_windows_program(search_path: &OsStr, names: &[&str]) -> Option<PathBuf> {
    for directory in env::split_paths(search_path) {
        for name in names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Configure Codex's application-local environment for the official VSCode
/// extension. Unlike `saiai codex`, the extension is not our direct child, so
/// the proxy variables must live in Codex's own `.env` file. This never
/// changes the invoking shell or the operating-system environment.
fn configure_vscode() -> Result<()> {
    let codex_dir = codex_config_dir().context("failed to resolve Codex config directory")?;
    fs::create_dir_all(&codex_dir)
        .with_context(|| format!("failed to create {}", codex_dir.display()))?;
    let auth_path = codex_dir.join("auth.json");
    let cfg = read_saiai_config()
        .context("SAIAI local proxy is not configured; run the SAIAI setup first")?;
    let _runtime_ca = read_runtime_ca(&cfg)
        .context("SAIAI local proxy CA is unavailable; rerun the SAIAI setup")?;

    let files = prepare_codex_oauth_files(&codex_dir, true)?;
    ensure_codex_local_proxy_auth(&auth_path)?;
    validate_codex_oauth_auth(&auth_path)?;
    let env_path = codex_dir.join(".env");
    write_codex_ide_env(&env_path, &cfg.listen, &cfg.ca_cert_path)?;
    ensure_local_proxy_running(&cfg.listen)?;

    println!("SAIAI configured the Codex VSCode extension for local proxy mode.");
    println!("  CODEX_HOME={}", codex_dir.display());
    println!("  environment={}", env_path.display());
    println!("  proxy=http://{}", cfg.listen);
    println!(
        "  migrated {} Codex config file(s) with backups",
        files.len()
    );
    println!("Restart VSCode (or reload its window) before starting a new Codex session.");
    println!(
        "If VSCode has an explicit `http.proxy`, remove it when it overrides the SAIAI proxy."
    );
    Ok(())
}

fn write_codex_ide_env(path: &Path, listen: &str, ca_cert_path: &str) -> Result<()> {
    let raw = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };
    let merged = merge_codex_ide_env(&raw, listen, ca_cert_path);
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(path, &timestamp)?;
    write_bytes_atomic(path, merged.as_bytes(), 0o600)
}

fn merge_codex_ide_env(raw: &str, listen: &str, ca_cert_path: &str) -> String {
    let mut kept = Vec::new();
    let mut in_managed_block = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed == CODEX_IDE_ENV_BEGIN {
            in_managed_block = true;
            continue;
        }
        if trimmed == CODEX_IDE_ENV_END {
            in_managed_block = false;
            continue;
        }
        if in_managed_block || dotenv_assignment_key(line).is_some_and(is_managed_codex_env) {
            continue;
        }
        kept.push(line);
    }
    while kept.last().is_some_and(|line| line.trim().is_empty()) {
        kept.pop();
    }

    let proxy = format!("http://{listen}");
    if !kept.is_empty() {
        kept.push("");
    }
    kept.push(CODEX_IDE_ENV_BEGIN);
    let mut output = kept.join("\n");
    for (key, value) in [
        // Codex loads standard TLS variables from CODEX_HOME/.env before it
        // constructs the IDE/app-server HTTP clients. Its Codex-specific CA
        // variable is only reliable when present in the process environment,
        // which is why the direct CLI launcher still uses that variable.
        ("SSL_CERT_FILE", ca_cert_path),
        ("HTTP_PROXY", proxy.as_str()),
        ("HTTPS_PROXY", proxy.as_str()),
        ("ALL_PROXY", proxy.as_str()),
        ("NO_PROXY", CODEX_LOCAL_PROXY_NO_PROXY),
        ("http_proxy", proxy.as_str()),
        ("https_proxy", proxy.as_str()),
        ("all_proxy", proxy.as_str()),
        ("no_proxy", CODEX_LOCAL_PROXY_NO_PROXY),
    ] {
        output.push('\n');
        output.push_str(key);
        output.push('=');
        output.push_str(&serde_json::to_string(value).expect("string serialization cannot fail"));
    }
    output.push('\n');
    output.push_str(CODEX_IDE_ENV_END);
    output.push('\n');
    output
}

fn dotenv_assignment_key(line: &str) -> Option<&str> {
    let mut assignment = line.trim_start();
    if let Some(rest) = assignment.strip_prefix("export ") {
        assignment = rest.trim_start();
    }
    let (key, _) = assignment.split_once('=')?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key)
}

fn is_managed_codex_env(key: &str) -> bool {
    CODEX_MANAGED_ENV
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

fn codex_launcher_args(args: &[String]) -> Vec<String> {
    let mut launch_args = Vec::with_capacity(args.len() + 6);
    if !codex_args_override_feature(args, "respect_system_proxy") {
        launch_args.push("-c".to_string());
        launch_args.push(format!(
            "features.respect_system_proxy={}",
            codex_respect_system_proxy_enabled()
        ));
    }
    // Codex defaults OTEL metrics to its hosted Statsig endpoint at
    // ab.chatgpt.com. That non-model control plane can be unreachable on the
    // same networks that require SAIAI and should not delay or add errors to
    // a local-proxy model session. Keep this child-only and honor an explicit
    // caller override.
    if !codex_args_override_config_key(args, "otel.metrics_exporter") {
        launch_args.push("-c".to_string());
        launch_args.push("otel.metrics_exporter=\"none\"".to_string());
    }
    // A synthetic SAIAI identity cannot authenticate Codex's hosted Apps MCP
    // endpoint. Disable that optional control plane for this launcher so it
    // does not emit a misleading startup failure. A caller can explicitly
    // re-enable it and that later argument wins.
    if !codex_args_override_feature(args, "apps") {
        launch_args.push("-c".to_string());
        launch_args.push("features.apps=false".to_string());
    }
    launch_args.extend(args.iter().cloned());
    launch_args
}

fn codex_respect_system_proxy_enabled() -> bool {
    // On Windows and macOS the feature gives platform system-proxy discovery
    // precedence over HTTP_PROXY/HTTPS_PROXY. A DIRECT system decision
    // therefore bypasses the child-only SAIAI proxy environment. Reqwest and
    // Tungstenite both honor those variables in transport-default mode.
    cfg!(target_os = "linux")
}

fn codex_args_override_feature(args: &[String], feature: &str) -> bool {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = if arg == "-c" || arg == "--config" || arg == "--enable" || arg == "--disable" {
            i += 1;
            args.get(i).map(String::as_str)
        } else if let Some(value) = arg.strip_prefix("--config=") {
            Some(value)
        } else if let Some(value) = arg.strip_prefix("--enable=") {
            Some(value)
        } else {
            arg.strip_prefix("--disable=")
        };

        if value.is_some_and(|value| {
            let key = value.split_once('=').map_or(value, |(key, _)| key).trim();
            key == feature || key == format!("features.{feature}")
        }) {
            return true;
        }
        i += 1;
    }
    false
}

fn codex_args_override_config_key(args: &[String], expected_key: &str) -> bool {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let value = if arg == "-c" || arg == "--config" {
            i += 1;
            args.get(i).map(String::as_str)
        } else {
            arg.strip_prefix("--config=")
        };
        if value.is_some_and(|value| {
            value.split_once('=').map_or(value, |(key, _)| key).trim() == expected_key
        }) {
            return true;
        }
        i += 1;
    }
    false
}

fn ensure_codex_local_proxy_auth(path: &Path) -> Result<()> {
    write_codex_local_proxy_auth(path, false)
}

fn replace_codex_local_proxy_auth(path: &Path) -> Result<()> {
    write_codex_local_proxy_auth(path, true)
}

fn write_codex_local_proxy_auth(path: &Path, replace_existing: bool) -> Result<()> {
    let existed = path.exists();
    let mut auth = if existed {
        load_json_object(path)?
    } else {
        Map::new()
    };
    if existed && !replace_existing {
        let existing_access = auth
            .get("tokens")
            .and_then(Value::as_object)
            .and_then(|tokens| tokens.get("access_token"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let existing_auth_mode = auth.get("auth_mode").and_then(Value::as_str).unwrap_or("");
        let has_real_oauth = matches!(existing_auth_mode, "chatgpt" | "chatgptAuthTokens")
            && !existing_access.trim().is_empty()
            && !is_codex_placeholder_access_token(existing_access);
        if has_real_oauth {
            return Ok(());
        }
    }

    auth.insert(
        "auth_mode".to_string(),
        // Codex owns refresh-token rotation in `chatgpt` mode. SAIAI's
        // synthetic local identity is supplied by an external host and must
        // never be sent to the provider refresh endpoint, so use Codex's
        // dedicated external-token mode instead.
        Value::String("chatgptAuthTokens".to_string()),
    );
    auth.insert(
        "tokens".to_string(),
        serde_json::json!({
            "id_token": CODEX_PLACEHOLDER_ID_TOKEN,
            "access_token": CODEX_PLACEHOLDER_ACCESS_TOKEN,
            "refresh_token": "",
            "account_id": CODEX_PLACEHOLDER_ACCOUNT_ID
        }),
    );
    auth.insert("OPENAI_API_KEY".to_string(), Value::Null);
    auth.insert(
        "last_refresh".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    write_json_object(path, Value::Object(auth)).with_context(|| {
        format!(
            "failed to create local-proxy OAuth auth file {}; the placeholder is only safe when the local proxy is active",
            path.display()
        )
    })?;
    let verb = if existed { "Updated" } else { "Created" };
    println!(
        "{verb} local-proxy OAuth auth placeholder at {} (no provider login required).",
        path.display()
    );
    Ok(())
}

fn is_codex_placeholder_access_token(token: &str) -> bool {
    token.starts_with("saiai-local-proxy-placeholder-") || token == CODEX_PLACEHOLDER_ACCESS_TOKEN
}

fn run_desktop(product: DesktopProduct, args: &[String]) -> Result<()> {
    if !product.has_adapter() {
        bail!(
            "SAIAI Desktop currently supports Codex only; ordinary ChatGPT history and settings are not supported. Use `saiai desktop codex`."
        );
    }

    println!(
        "SAIAI Desktop scope: Codex only; the official ChatGPT sidebar, ordinary Chat history, and settings are not supported."
    );

    #[cfg(target_os = "linux")]
    {
        run_linux_desktop(product, args)
    }

    #[cfg(target_os = "macos")]
    {
        run_macos_desktop(product, args)
    }

    #[cfg(target_os = "windows")]
    {
        run_windows_desktop(product, args)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = args;
        bail!(
            "SAIAI Desktop integration is currently implemented for Linux, macOS, and Windows only"
        );
    }
}

#[cfg(target_os = "linux")]
fn run_linux_desktop(product: DesktopProduct, args: &[String]) -> Result<()> {
    let cfg = read_saiai_config().context("SAIAI local proxy is not configured")?;
    let _runtime_ca = read_runtime_ca(&cfg)
        .context("SAIAI local proxy CA is unavailable; rerun the SAIAI setup")?;
    ensure_local_proxy_running(&cfg.listen)?;

    let desktop_root = saiai_config_dir()?.join("desktop");
    let desktop_home = desktop_root.join("home");
    let desktop_codex = desktop_root.join("codex");
    let desktop_user_data = desktop_root.join("user-data");
    fs::create_dir_all(&desktop_codex)
        .with_context(|| format!("failed to create {}", desktop_codex.display()))?;
    fs::create_dir_all(&desktop_user_data)
        .with_context(|| format!("failed to create {}", desktop_user_data.display()))?;
    prepare_isolated_desktop_state(&desktop_root, &desktop_codex)?;
    ensure_desktop_nss_ca(&desktop_home, &cfg.ca_cert_path)?;

    let executable = env::var_os("SAIAI_CHATGPT_BIN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            ["/usr/bin/chatgpt", "/usr/lib/chatgpt/ChatGPT"]
                .iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
        })
        .context("ChatGPT Desktop was not found; install the ChatGPT Desktop package first")?;
    let fixed_timezone = resolve_chatgpt_timezone()?;

    let proxy = format!("http://{}", cfg.listen);
    let spki = local_proxy_chatgpt_spki(&cfg.listen)?;
    let mut launch_args = vec![
        format!("--user-data-dir={}", desktop_user_data.display()),
        format!("--proxy-server={proxy}"),
        format!("--ignore-certificate-errors-spki-list={spki}"),
    ];
    launch_args.extend(args.iter().cloned());
    let mut command = ProcessCommand::new(&executable);
    command.args(launch_args);
    // Electron writes diagnostic messages through Node's console even after
    // its parent terminal/TTY has gone away. Do not let a closed terminal
    // pipe turn a healthy Desktop process into `write EIO`.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in CODEX_MANAGED_ENV {
        command.env_remove(*name);
    }
    // Do not pass the SAIAI control variable into Electron. If configured,
    // apply the validated IANA timezone only to this Desktop child process.
    command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV);
    command
        .env("HOME", &desktop_home)
        .env("USERPROFILE", &desktop_home)
        .env("CODEX_HOME", &desktop_codex)
        .env("CODEX_ELECTRON_USER_DATA_PATH", &desktop_user_data)
        .env("CODEX_CA_CERTIFICATE", &cfg.ca_cert_path)
        .env("NSS_DEFAULT_DB_TYPE", "sql")
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", CODEX_LOCAL_PROXY_NO_PROXY)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("no_proxy", CODEX_LOCAL_PROXY_NO_PROXY);
    // The isolated Desktop home deliberately prevents the app from sharing
    // normal Codex state. On X11, however, Chromium falls back to
    // `$HOME/.Xauthority` when XAUTHORITY is not exported. Preserve a readable
    // authority file from the invoking user's home for this child only, or
    // Electron exits before it can reach the local proxy.
    if env::var_os("XAUTHORITY").is_none()
        && let Some(xauthority) =
            fallback_linux_xauthority(home_dir().as_deref(), env::var_os("DISPLAY").is_some())
    {
        command.env("XAUTHORITY", xauthority);
    }
    if let Some(timezone) = &fixed_timezone {
        command.env("TZ", timezone);
    }

    println!("Starting ChatGPT Desktop through the SAIAI local proxy.");
    println!("  product={}", product.label());
    println!("  CODEX_HOME={}", desktop_codex.display());
    println!("  user-data-dir={}", desktop_user_data.display());
    println!("  proxy={proxy}");
    if let Some(timezone) = &fixed_timezone {
        println!("  timezone={timezone} (Desktop child only)");
    }
    let status = command
        .status()
        .with_context(|| format!("failed to start {}", executable.display()))?;
    if status.success() {
        Ok(())
    } else {
        bail!("ChatGPT Desktop exited with {status}")
    }
}

#[cfg(target_os = "macos")]
fn run_macos_desktop(product: DesktopProduct, args: &[String]) -> Result<()> {
    let cfg = read_saiai_config().context("SAIAI local proxy is not configured")?;
    let _runtime_ca = read_runtime_ca(&cfg)
        .context("SAIAI local proxy CA is unavailable; rerun the SAIAI setup")?;
    ensure_local_proxy_running(&cfg.listen)?;

    let packaged_bundle = if resolve_macos_desktop_override()?.is_none() {
        resolve_macos_codex_bundle()?
    } else {
        None
    };

    let desktop_root = saiai_config_dir()?.join("desktop");
    let desktop_home = desktop_root.join("home");
    let desktop_codex = desktop_root.join("codex");
    let desktop_user_data = desktop_root.join("user-data");
    for directory in [&desktop_home, &desktop_codex, &desktop_user_data] {
        fs::create_dir_all(directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
    }
    prepare_isolated_desktop_state(&desktop_root, &desktop_codex)?;

    let executable = resolve_macos_chatgpt_executable()?;
    if let Some(bundle) = &packaged_bundle {
        verify_macos_codex_bundle(bundle)?;
        stop_macos_packaged_desktop(bundle)?;
    }
    let fixed_timezone = resolve_chatgpt_timezone()?;
    let proxy = format!("http://{}", cfg.listen);
    let spki = local_proxy_chatgpt_spki(&cfg.listen)?;
    let mut launch_args = vec![
        format!("--user-data-dir={}", desktop_user_data.display()),
        format!("--proxy-server={proxy}"),
        format!("--ignore-certificate-errors-spki-list={spki}"),
    ];
    launch_args.extend(
        args.iter()
            .filter(|arg| !arg.starts_with("--ignore-certificate-errors-spki-list="))
            .cloned(),
    );

    let mut command = ProcessCommand::new(&executable);
    command.args(launch_args);
    // See the Linux launcher: Desktop diagnostics must not inherit a fragile
    // terminal pipe from the SAIAI wrapper.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in CODEX_MANAGED_ENV {
        command.env_remove(*name);
    }
    command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV);
    command
        .env("HOME", &desktop_home)
        .env("USERPROFILE", &desktop_home)
        .env("CODEX_HOME", &desktop_codex)
        .env("CODEX_ELECTRON_USER_DATA_PATH", &desktop_user_data)
        .env("CODEX_CA_CERTIFICATE", &cfg.ca_cert_path)
        .env("SSL_CERT_FILE", &cfg.ca_cert_path)
        .env("NODE_EXTRA_CA_CERTS", &cfg.ca_cert_path)
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", CODEX_LOCAL_PROXY_NO_PROXY)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("no_proxy", CODEX_LOCAL_PROXY_NO_PROXY);
    if let Some(timezone) = &fixed_timezone {
        command.env("TZ", timezone);
    }

    println!("Starting ChatGPT Desktop through the SAIAI local proxy.");
    println!("  product={}", product.label());
    println!("  application={}", executable.display());
    println!("  CODEX_HOME={}", desktop_codex.display());
    println!("  user-data-dir={}", desktop_user_data.display());
    println!("  proxy={proxy}");
    if let Some(timezone) = &fixed_timezone {
        println!("  timezone={timezone} (Desktop child only)");
    }
    if let Some(bundle) = packaged_bundle {
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start {}", executable.display()))?;
        std::thread::sleep(Duration::from_millis(750));
        let workspace = env::current_dir().context("failed to resolve the Desktop workspace")?;
        let target = codex_new_thread_url(&workspace);
        let mut activation_error = String::new();
        let mut activated = false;
        for attempt in 1..=10 {
            let output = ProcessCommand::new("/usr/bin/open")
                .arg("-a")
                .arg(&bundle)
                .arg(&target)
                .output()
                .context("failed to activate packaged OpenAI Desktop")?;
            if output.status.success() {
                activated = true;
                break;
            }
            activation_error = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if attempt < 10 {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        if !activated {
            let _ = child.kill();
            bail!("packaged OpenAI Desktop activation failed after retries: {activation_error}");
        }
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect packaged OpenAI Desktop")?
        {
            bail!("ChatGPT Desktop exited with {status}");
        }
        Ok(())
    } else {
        let status = command
            .status()
            .with_context(|| format!("failed to start {}", executable.display()))?;
        if status.success() {
            Ok(())
        } else {
            bail!("ChatGPT Desktop exited with {status}")
        }
    }
}

#[cfg(target_os = "macos")]
fn resolve_macos_chatgpt_executable() -> Result<PathBuf> {
    if let Some(path) = resolve_macos_desktop_override()? {
        return Ok(path);
    }

    let mut bundles = Vec::with_capacity(4);
    if let Some(home) = home_dir() {
        bundles.push(home.join("Applications/ChatGPT.app"));
        bundles.push(home.join("Applications/Codex.app"));
    }
    bundles.push(PathBuf::from("/Applications/ChatGPT.app"));
    bundles.push(PathBuf::from("/Applications/Codex.app"));
    for bundle in bundles {
        if let Some(path) = resolve_macos_bundle_executable(&bundle) {
            return Ok(path);
        }
    }
    bail!(
        "ChatGPT.app or Codex.app was not found in /Applications or ~/Applications; install an official Desktop app or set SAIAI_DESKTOP_BIN"
    )
}

#[cfg(target_os = "macos")]
fn resolve_macos_desktop_override() -> Result<Option<PathBuf>> {
    for variable in ["SAIAI_DESKTOP_BIN", "SAIAI_CHATGPT_BIN"] {
        if let Some(raw) = env::var_os(variable) {
            let path = PathBuf::from(raw);
            if !is_unix_executable(&path) {
                bail!(
                    "{variable} does not name an executable file: {}",
                    path.display()
                );
            }
            return Ok(Some(path));
        }
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
fn resolve_macos_bundle_executable(bundle: &Path) -> Option<PathBuf> {
    let plist = bundle.join("Contents/Info.plist");
    let plist_text = plist.as_os_str().to_str()?;
    let executable = command_output(
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleExecutable",
            "raw",
            "-o",
            "-",
            plist_text,
        ],
    )
    .ok()?;
    let executable = executable.trim();
    if executable.is_empty() || executable.contains('/') || executable.contains('\\') {
        return None;
    }
    let path = bundle.join("Contents/MacOS").join(executable);
    is_unix_executable(&path).then_some(path)
}

#[cfg(target_os = "macos")]
fn resolve_macos_codex_bundle() -> Result<Option<PathBuf>> {
    let mut application_dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = home_dir() {
        application_dirs.push(home.join("Applications"));
    }
    for directory in application_dirs {
        for name in ["ChatGPT.app", "Codex.app"] {
            let bundle = directory.join(name);
            let plist = bundle.join("Contents/Info.plist");
            if !plist.is_file() {
                continue;
            }
            let Some(plist_text) = plist.as_os_str().to_str() else {
                continue;
            };
            let identifier = command_output(
                "/usr/bin/plutil",
                &[
                    "-extract",
                    "CFBundleIdentifier",
                    "raw",
                    "-o",
                    "-",
                    plist_text,
                ],
            )?;
            if identifier.trim() == "com.openai.codex" {
                return Ok(Some(bundle));
            }
        }
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
fn verify_macos_codex_bundle(bundle: &Path) -> Result<()> {
    let requirement = "identifier \"com.openai.codex\" and anchor apple generic and certificate leaf[subject.OU] = \"2DC432GLL2\"";
    let status = ProcessCommand::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(format!("-R={requirement}"))
        .arg(bundle)
        .status()
        .context("failed to verify the OpenAI Desktop signature")?;
    if !status.success() {
        bail!(
            "OpenAI Desktop failed signature verification: {}",
            bundle.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn stop_macos_packaged_desktop(bundle: &Path) -> Result<()> {
    let bundles = macos_packaged_desktop_cleanup_bundles(bundle);
    if !macos_packaged_desktop_processes_running(&bundles) {
        return Ok(());
    }
    let _ = ProcessCommand::new("/usr/bin/osascript")
        .args(["-e", "tell application id \"com.openai.codex\" to quit"])
        .status();
    let graceful_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < graceful_deadline {
        if !macos_packaged_desktop_processes_running(&bundles) {
            std::thread::sleep(Duration::from_millis(750));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    for candidate in &bundles {
        let pattern = candidate.join("Contents/").display().to_string();
        let _ = ProcessCommand::new("/usr/bin/pkill")
            .args(["-TERM", "-f", &pattern])
            .status();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if !macos_packaged_desktop_processes_running(&bundles) {
            std::thread::sleep(Duration::from_millis(750));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for candidate in &bundles {
        let pattern = candidate.join("Contents/").display().to_string();
        let _ = ProcessCommand::new("/usr/bin/pkill")
            .args(["-KILL", "-f", &pattern])
            .status()
            .context("failed to force-stop packaged OpenAI Desktop")?;
    }
    if macos_packaged_desktop_processes_running(&bundles) {
        bail!("packaged OpenAI Desktop did not exit before relaunch");
    }
    std::thread::sleep(Duration::from_millis(750));
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn codex_new_thread_url(workspace: &Path) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("path", &workspace.display().to_string());
    format!("codex://threads/new?{}", serializer.finish())
}

#[cfg(target_os = "macos")]
fn macos_packaged_desktop_cleanup_bundles(selected: &Path) -> Vec<PathBuf> {
    let mut bundles = vec![selected.to_path_buf()];
    if let Some(home) = home_dir() {
        bundles.push(home.join("Applications/ChatGPT.app"));
        bundles.push(home.join("Applications/Codex.app"));
    }
    bundles.push(PathBuf::from("/Applications/ChatGPT.app"));
    bundles.push(PathBuf::from("/Applications/Codex.app"));
    bundles.sort();
    bundles.dedup();
    bundles
}

#[cfg(target_os = "macos")]
fn macos_packaged_desktop_processes_running(bundles: &[PathBuf]) -> bool {
    bundles
        .iter()
        .any(|bundle| macos_packaged_desktop_bundle_process_running(bundle).unwrap_or(false))
}

#[cfg(target_os = "macos")]
fn macos_packaged_desktop_bundle_process_running(bundle: &Path) -> Result<bool> {
    let pattern = bundle.join("Contents/").display().to_string();
    let status = ProcessCommand::new("/usr/bin/pgrep")
        .args(["-f", &pattern])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to inspect packaged OpenAI Desktop process tree")?;
    Ok(status.success())
}

#[cfg(target_os = "windows")]
fn run_windows_desktop(product: DesktopProduct, args: &[String]) -> Result<()> {
    let cfg = read_saiai_config().context("SAIAI local proxy is not configured")?;
    let _runtime_ca = read_runtime_ca(&cfg)
        .context("SAIAI local proxy CA is unavailable; rerun the SAIAI setup")?;
    ensure_local_proxy_running(&cfg.listen)?;

    if resolve_windows_desktop_override()?.is_none()
        && let Some(package) = resolve_windows_packaged_desktop()?
    {
        return run_windows_packaged_desktop(product, args, &cfg, &package);
    }

    let desktop_root = saiai_config_dir()?.join("desktop");
    let desktop_home = desktop_root.join("home");
    let desktop_codex = desktop_root.join("codex");
    let desktop_user_data = desktop_root.join("user-data");
    let desktop_roaming_app_data = desktop_home.join("AppData/Roaming");
    let desktop_local_app_data = desktop_home.join("AppData/Local");
    for directory in [
        &desktop_home,
        &desktop_codex,
        &desktop_user_data,
        &desktop_roaming_app_data,
        &desktop_local_app_data,
    ] {
        fs::create_dir_all(directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
    }
    prepare_isolated_desktop_state(&desktop_root, &desktop_codex)?;

    let executable = resolve_windows_desktop_executable()?;
    let fixed_timezone = resolve_chatgpt_timezone()?;
    let proxy = format!("http://{}", cfg.listen);
    let spki = local_proxy_chatgpt_spki(&cfg.listen)?;
    let mut launch_args = vec![
        format!("--user-data-dir={}", desktop_user_data.display()),
        format!("--proxy-server={proxy}"),
        format!("--ignore-certificate-errors-spki-list={spki}"),
    ];
    launch_args.extend(
        args.iter()
            .filter(|arg| !arg.starts_with("--ignore-certificate-errors-spki-list="))
            .cloned(),
    );

    let mut command = ProcessCommand::new(&executable);
    command.args(launch_args);
    for name in CODEX_MANAGED_ENV {
        command.env_remove(*name);
    }
    command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV);
    command
        .env("HOME", &desktop_home)
        .env("USERPROFILE", &desktop_home)
        .env("APPDATA", &desktop_roaming_app_data)
        .env("LOCALAPPDATA", &desktop_local_app_data)
        .env("CODEX_HOME", &desktop_codex)
        .env("CODEX_ELECTRON_USER_DATA_PATH", &desktop_user_data)
        .env("CODEX_CA_CERTIFICATE", &cfg.ca_cert_path)
        .env("SSL_CERT_FILE", &cfg.ca_cert_path)
        .env("NODE_EXTRA_CA_CERTS", &cfg.ca_cert_path)
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", CODEX_LOCAL_PROXY_NO_PROXY)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("no_proxy", CODEX_LOCAL_PROXY_NO_PROXY);
    if let Some(timezone) = &fixed_timezone {
        command.env("TZ", timezone);
    }

    println!("Starting OpenAI Desktop through the SAIAI local proxy.");
    println!("  product={}", product.label());
    println!("  application={}", executable.display());
    println!("  CODEX_HOME={}", desktop_codex.display());
    println!("  user-data-dir={}", desktop_user_data.display());
    println!("  proxy={proxy}");
    if let Some(timezone) = &fixed_timezone {
        println!("  timezone={timezone} (Desktop child only)");
    }
    let status = command
        .status()
        .with_context(|| format!("failed to start {}", executable.display()))?;
    if status.success() {
        Ok(())
    } else {
        bail!("OpenAI Desktop exited with {status}")
    }
}

#[cfg(target_os = "windows")]
fn run_windows_packaged_desktop(
    product: DesktopProduct,
    args: &[String],
    cfg: &SaiaiConfig,
    package: &WindowsPackagedDesktop,
) -> Result<()> {
    if !args.is_empty() {
        bail!("packaged Windows Desktop does not accept passthrough arguments");
    }
    let desktop_root = saiai_config_dir()?.join("desktop");
    let desktop_home = desktop_root.join("home");
    let desktop_codex = desktop_root.join("codex");
    let desktop_user_data = desktop_root.join("user-data");
    let desktop_roaming_app_data = desktop_home.join("AppData/Roaming");
    let desktop_local_app_data = desktop_home.join("AppData/Local");
    for directory in [
        &desktop_home,
        &desktop_codex,
        &desktop_user_data,
        &desktop_roaming_app_data,
        &desktop_local_app_data,
    ] {
        fs::create_dir_all(directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
    }
    prepare_isolated_desktop_state(&desktop_root, &desktop_codex)?;
    let env_path = desktop_codex.join(".env");
    write_codex_ide_env(&env_path, &cfg.listen, &cfg.ca_cert_path)?;

    let executable = windows_packaged_desktop_executable(package)?;
    let proxy = format!("http://{}", cfg.listen);
    let spki = local_proxy_chatgpt_spki(&cfg.listen)?;
    let fixed_timezone = resolve_chatgpt_timezone()?;
    stop_windows_packaged_desktop(package)?;
    restore_legacy_windows_packaged_proxy_lease()?;

    let workspace = env::current_dir().context("failed to resolve the Desktop workspace")?;
    let target = codex_new_thread_url(&workspace);
    let mut command = ProcessCommand::new(&executable);
    command
        .arg(format!("--user-data-dir={}", desktop_user_data.display()))
        .arg(format!("--proxy-server={proxy}"))
        .arg(format!("--ignore-certificate-errors-spki-list={spki}"))
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in CODEX_MANAGED_ENV {
        command.env_remove(*name);
    }
    command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV);
    command
        .env("HOME", &desktop_home)
        .env("USERPROFILE", &desktop_home)
        .env("APPDATA", &desktop_roaming_app_data)
        .env("LOCALAPPDATA", &desktop_local_app_data)
        .env("CODEX_HOME", &desktop_codex)
        .env("CODEX_ELECTRON_USER_DATA_PATH", &desktop_user_data)
        .env("CODEX_CA_CERTIFICATE", &cfg.ca_cert_path)
        .env("SSL_CERT_FILE", &cfg.ca_cert_path)
        .env("NODE_EXTRA_CA_CERTS", &cfg.ca_cert_path)
        .env("HTTP_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("NO_PROXY", CODEX_LOCAL_PROXY_NO_PROXY)
        .env("http_proxy", &proxy)
        .env("https_proxy", &proxy)
        .env("all_proxy", &proxy)
        .env("no_proxy", CODEX_LOCAL_PROXY_NO_PROXY);
    if let Some(timezone) = &fixed_timezone {
        command.env("TZ", timezone);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", executable.display()))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect packaged OpenAI Desktop")?
        {
            bail!("packaged OpenAI Desktop exited during startup with {status}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("Starting packaged OpenAI Desktop through the SAIAI local proxy.");
    println!("  product={}", product.label());
    println!("  app_id={}", package.app_id);
    println!("  application={}", executable.display());
    println!("  CODEX_HOME={}", desktop_codex.display());
    println!("  user-data-dir={}", desktop_user_data.display());
    println!("  environment={}", env_path.display());
    println!("  proxy={proxy} (Desktop process tree only)");
    println!("  certificate-trust=process-scoped SPKI pins");
    println!("  Windows system proxy=unchanged");
    if let Some(timezone) = &fixed_timezone {
        println!("  timezone={timezone} (Desktop child only)");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Deserialize)]
struct LegacyWindowsInternetProxySettings {
    proxy_enable: Option<i32>,
    proxy_server: Option<String>,
    auto_config_url: Option<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Deserialize)]
struct LegacyWindowsPackagedProxyLeaseMarker {
    previous: LegacyWindowsInternetProxySettings,
    managed_server: String,
    #[serde(default)]
    added_ca_thumbprints: Vec<String>,
}

#[cfg(target_os = "windows")]
fn restore_legacy_windows_packaged_proxy_lease() -> Result<()> {
    let marker_path = windows_packaged_proxy_lease_marker_path()?;
    let Some(marker) = read_legacy_windows_packaged_proxy_lease_marker(&marker_path)? else {
        return Ok(());
    };

    let current = windows_read_internet_proxy()?;
    if windows_proxy_matches_managed(&current, &marker.managed_server) {
        windows_write_internet_proxy(&marker.previous)?;
        println!("Restored the Windows proxy left by a legacy SAIAI Desktop lease.");
    } else {
        eprintln!(
            "warning: legacy SAIAI Desktop lease found, but the current Windows proxy was changed externally; preserving the current proxy"
        );
    }
    for thumbprint in &marker.added_ca_thumbprints {
        windows_remove_user_ca(Some(thumbprint))?;
    }
    remove_windows_packaged_proxy_lease_marker(&marker_path)
}

#[cfg(target_os = "windows")]
fn windows_packaged_proxy_lease_marker_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?
        .join("desktop")
        .join(WINDOWS_PACKAGED_PROXY_LEASE_FILENAME))
}

#[cfg(target_os = "windows")]
fn read_legacy_windows_packaged_proxy_lease_marker(
    path: &Path,
) -> Result<Option<LegacyWindowsPackagedProxyLeaseMarker>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("failed to parse {}", path.display()))
}

#[cfg(target_os = "windows")]
fn remove_windows_packaged_proxy_lease_marker(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(target_os = "windows")]
fn windows_remove_user_ca(thumbprint: Option<&str>) -> Result<()> {
    let Some(thumbprint) = thumbprint else {
        return Ok(());
    };
    command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($thumb) Remove-Item \"Cert:\\CurrentUser\\Root\\$thumb\" -ErrorAction SilentlyContinue }",
            thumbprint,
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_read_internet_proxy() -> Result<LegacyWindowsInternetProxySettings> {
    let output = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; [pscustomobject]@{proxy_enable=if($null -eq $p.ProxyEnable){$null}else{[int]$p.ProxyEnable}; proxy_server=if([string]::IsNullOrEmpty([string]$p.ProxyServer)){$null}else{[string]$p.ProxyServer}; auto_config_url=if([string]::IsNullOrEmpty([string]$p.AutoConfigURL)){$null}else{[string]$p.AutoConfigURL}} | ConvertTo-Json -Compress",
        ],
    )?;
    serde_json::from_str(&output).context("failed to parse Windows Internet proxy settings")
}

#[cfg(target_os = "windows")]
fn windows_proxy_matches_managed(
    settings: &LegacyWindowsInternetProxySettings,
    managed: &str,
) -> bool {
    if settings.proxy_enable != Some(1) || settings.auto_config_url.is_some() {
        return false;
    }
    let current = settings
        .proxy_server
        .as_deref()
        .unwrap_or("")
        .trim()
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let managed = managed
        .trim()
        .trim_start_matches("http://")
        .trim_end_matches('/');
    current.eq_ignore_ascii_case(managed)
}

#[cfg(target_os = "windows")]
fn windows_write_internet_proxy(settings: &LegacyWindowsInternetProxySettings) -> Result<()> {
    let enable = settings
        .proxy_enable
        .map(|value| value.to_string())
        .unwrap_or_else(|| "__SAIAI_NULL__".to_string());
    let server = settings
        .proxy_server
        .as_deref()
        .unwrap_or("__SAIAI_NULL__")
        .to_string();
    let auto = settings
        .auto_config_url
        .as_deref()
        .unwrap_or("__SAIAI_NULL__")
        .to_string();
    command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($e,$s,$a) $path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; if($e -eq '__SAIAI_NULL__'){Remove-ItemProperty $path -Name ProxyEnable -ErrorAction SilentlyContinue}else{Set-ItemProperty $path -Name ProxyEnable -Type DWord -Value ([int]$e)}; if($s -eq '__SAIAI_NULL__'){Remove-ItemProperty $path -Name ProxyServer -ErrorAction SilentlyContinue}else{Set-ItemProperty $path -Name ProxyServer -Type String -Value $s}; if($a -eq '__SAIAI_NULL__'){Remove-ItemProperty $path -Name AutoConfigURL -ErrorAction SilentlyContinue}else{Set-ItemProperty $path -Name AutoConfigURL -Type String -Value $a} }",
            &enable,
            &server,
            &auto,
        ],
    )?;
    Ok(())
}
#[cfg(target_os = "windows")]
fn resolve_windows_desktop_override() -> Result<Option<PathBuf>> {
    for variable in ["SAIAI_DESKTOP_BIN", "SAIAI_CHATGPT_BIN"] {
        if let Some(raw) = env::var_os(variable) {
            let path = PathBuf::from(raw);
            if !path.is_file() {
                bail!(
                    "{variable} does not name an executable file: {}",
                    path.display()
                );
            }
            return Ok(Some(path));
        }
    }
    Ok(None)
}

#[cfg(target_os = "windows")]
fn resolve_windows_desktop_executable() -> Result<PathBuf> {
    if let Some(path) = resolve_windows_desktop_override()? {
        return Ok(path);
    }

    let mut candidates = Vec::with_capacity(4);
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        candidates.push(local_app_data.join("Programs/ChatGPT/ChatGPT.exe"));
        candidates.push(local_app_data.join("Programs/Codex/Codex.exe"));
    }
    if let Some(program_files) = env::var_os("ProgramFiles").map(PathBuf::from) {
        candidates.push(program_files.join("ChatGPT/ChatGPT.exe"));
        candidates.push(program_files.join("Codex/Codex.exe"));
    }
    if let Some(path) = candidates.into_iter().find(|path| path.is_file()) {
        return Ok(path);
    }
    bail!(
        "OpenAI Codex/ChatGPT Desktop was not found in standard application directories; install the official Desktop app or set SAIAI_DESKTOP_BIN"
    )
}

#[cfg(target_os = "windows")]
struct WindowsPackagedDesktop {
    app_id: String,
    install_location: PathBuf,
}

#[cfg(target_os = "windows")]
fn windows_packaged_desktop_executable(package: &WindowsPackagedDesktop) -> Result<PathBuf> {
    [
        package.install_location.join("app/ChatGPT.exe"),
        package.install_location.join("app/Codex.exe"),
        package.install_location.join("ChatGPT.exe"),
        package.install_location.join("Codex.exe"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .with_context(|| {
        format!(
            "OpenAI Codex AppX executable is unavailable under {}",
            package.install_location.display()
        )
    })
}

#[cfg(target_os = "windows")]
fn resolve_windows_packaged_desktop() -> Result<Option<WindowsPackagedDesktop>> {
    let app_id = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-StartApps | Where-Object AppID -Like 'OpenAI.Codex_*!App' | Select-Object -First 1 -ExpandProperty AppID",
        ],
    )?;
    if app_id.trim().is_empty() {
        return Ok(None);
    }
    let install_location = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-AppxPackage -Name 'OpenAI.Codex' | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty InstallLocation",
        ],
    )?;
    if install_location.trim().is_empty() {
        return Ok(None);
    }
    let install_location = PathBuf::from(install_location.trim());
    if !install_location.is_dir() {
        bail!(
            "OpenAI.Codex AppX install location is unavailable: {}",
            install_location.display()
        );
    }
    Ok(Some(WindowsPackagedDesktop {
        app_id: app_id.trim().to_string(),
        install_location,
    }))
}

#[cfg(target_os = "windows")]
fn stop_windows_packaged_desktop(package: &WindowsPackagedDesktop) -> Result<()> {
    let root = package.install_location.display().to_string();
    command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($root) $deadline=(Get-Date).AddSeconds(10); do { $processes=@(Get-Process -Name ChatGPT,Codex -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) }); $processes | Stop-Process -Force; if($processes.Count -eq 0){ return }; Start-Sleep -Milliseconds 200 } while((Get-Date) -lt $deadline); $remaining=@(Get-Process -Name ChatGPT,Codex -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) }); if($remaining.Count -gt 0){ throw 'packaged OpenAI Desktop top-level process did not exit' } }",
            &root,
        ],
    )?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn resolve_chatgpt_timezone() -> Result<Option<String>> {
    let raw = env::var_os(SAIAI_CHATGPT_TIMEZONE_ENV);
    let Some(raw) = raw else {
        return resolve_chatgpt_timezone_value(None);
    };
    let value = raw
        .to_str()
        .context("SAIAI_CHATGPT_TIMEZONE must be valid UTF-8")?
        .trim();
    resolve_chatgpt_timezone_value(Some(value))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn resolve_chatgpt_timezone_value(value: Option<&str>) -> Result<Option<String>> {
    let value = value.unwrap_or(DEFAULT_CHATGPT_TIMEZONE).trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.eq_ignore_ascii_case("system") {
        return Ok(None);
    }
    validate_chatgpt_timezone(value)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_chatgpt_timezone_name(value: &str) -> Result<()> {
    if value.len() > 128
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '+' | '-' | '.'))
    {
        bail!("{SAIAI_CHATGPT_TIMEZONE_ENV} must be an IANA timezone such as America/Los_Angeles");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_chatgpt_timezone(value: &str) -> Result<Option<String>> {
    validate_chatgpt_timezone_name(value)?;
    let zoneinfo_path = Path::new("/usr/share/zoneinfo").join(value);
    let metadata = fs::metadata(&zoneinfo_path).with_context(|| {
        format!(
            "{SAIAI_CHATGPT_TIMEZONE_ENV} does not exist in {}",
            zoneinfo_path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "{SAIAI_CHATGPT_TIMEZONE_ENV} is not a zoneinfo file: {}",
            zoneinfo_path.display()
        );
    }
    Ok(Some(value.to_string()))
}

#[cfg(target_os = "windows")]
fn validate_chatgpt_timezone(value: &str) -> Result<Option<String>> {
    validate_chatgpt_timezone_name(value)?;
    Ok(Some(value.to_string()))
}

#[cfg(target_os = "linux")]
fn ensure_desktop_nss_ca(home: &Path, ca_cert: &str) -> Result<()> {
    // Chromium can use the pinned local-proxy leaf SPKI passed by the Linux
    // launcher. `certutil` is supplied by `libnss3-tools`, which is not part
    // of every ChatGPT Desktop package; absence must not prevent launch.
    if !ensure_nss_ca(home, Path::new(ca_cert))? {
        eprintln!(
            "warning: certutil is unavailable; using the Desktop SPKI certificate pin instead of an NSS database"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fallback_linux_xauthority(
    invoking_home: Option<&Path>,
    has_x11_display: bool,
) -> Option<PathBuf> {
    if !has_x11_display {
        return None;
    }
    let candidate = invoking_home?.join(".Xauthority");
    candidate.is_file().then_some(candidate)
}

#[cfg(target_os = "linux")]
fn ensure_direct_linux_desktop_trust(ca_cert: &Path) {
    let result = (|| -> Result<bool> {
        let home = home_dir().context("failed to resolve the current user's home directory")?;
        ensure_nss_ca(&home, ca_cert)
    })();
    match result {
        Ok(true) => println!(
            "Trusted the SAIAI CA in the current user's NSS database for direct Linux Desktop (no system trust store or dialog)."
        ),
        Ok(false) => eprintln!(
            "WARN direct Linux Desktop trust was not installed because certutil is unavailable; install libnss3-tools, rerun `saiai init-codex`, or use `saiai desktop codex`."
        ),
        Err(err) => eprintln!(
            "WARN direct Linux Desktop trust could not be updated ({err:#}); Codex CLI remains configured, and `saiai desktop codex` remains the supported isolated fallback."
        ),
    }
}

#[cfg(target_os = "linux")]
fn ensure_nss_ca(home: &Path, ca_cert: &Path) -> Result<bool> {
    if !nss_certutil_available() {
        return Ok(false);
    }
    let db_dir = nss_database_dir(home);
    fs::create_dir_all(&db_dir)
        .with_context(|| format!("failed to create {}", db_dir.display()))?;
    let db = format!("sql:{}", db_dir.display());
    let cert_db = db_dir.join("cert9.db");
    if !cert_db.exists() {
        let status = ProcessCommand::new("certutil")
            .args(["-N", "-d", &db, "--empty-password"])
            .status()
            .context("failed to initialize the Desktop NSS database")?;
        if !status.success() {
            bail!("certutil failed to initialize the Desktop NSS database");
        }
    }
    let _ = ProcessCommand::new("certutil")
        .args(["-D", "-d", &db, "-n", SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = ProcessCommand::new("certutil")
        .args([
            "-A",
            "-d",
            &db,
            "-n",
            SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME,
            "-t",
            "C,,",
            "-a",
            "-i",
            ca_cert
                .to_str()
                .context("SAIAI CA path is not valid UTF-8")?,
        ])
        .status()
        .context("failed to import the SAIAI CA into the Desktop NSS database")?;
    if !status.success() {
        bail!("certutil failed to import the SAIAI CA into the Desktop NSS database");
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn nss_database_dir(home: &Path) -> PathBuf {
    home.join(".pki/nssdb")
}

#[cfg(target_os = "linux")]
fn nss_certutil_available() -> bool {
    ProcessCommand::new("certutil")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

#[cfg(target_os = "linux")]
fn check_direct_linux_desktop_trust(report: &mut DoctorReport) {
    if !nss_certutil_available() {
        report.warn(
            "direct Linux Desktop trust",
            "certutil is unavailable; install libnss3-tools and rerun `saiai init-codex`, or use `saiai desktop codex`",
        );
        return;
    }
    let Some(home) = home_dir() else {
        report.warn(
            "direct Linux Desktop trust",
            "could not resolve the current user's NSS database; use `saiai desktop codex`",
        );
        return;
    };
    let db_dir = nss_database_dir(&home);
    let db = format!("sql:{}", db_dir.display());
    let present = ProcessCommand::new("certutil")
        .args(["-L", "-d", &db, "-n", SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if present {
        report.ok(
            "direct Linux Desktop trust",
            format!("SAIAI CA entry is present in {}", db_dir.display()),
        );
    } else {
        report.warn(
            "direct Linux Desktop trust",
            "SAIAI CA entry is absent from the current user's NSS database; rerun `saiai init-codex` or use `saiai desktop codex`",
        );
    }
}

#[cfg(target_os = "macos")]
fn check_direct_macos_desktop_trust(report: &mut DoctorReport) {
    // A direct LaunchServices/Dock launch cannot inherit the launcher's
    // process-specific SPKI pin. Setting a user trust root in Keychain is an
    // authorization-protected macOS action, so never attempt it from a
    // non-interactive bootstrap or claim that a certificate merely present in
    // Keychain is trusted. The managed launcher is deliberately the reliable
    // no-Keychain fallback.
    report.warn(
        "direct macOS Desktop trust",
        "SAIAI does not modify the login Keychain. A directly launched official App needs a user-approved SAIAI CA trust root; otherwise use `saiai desktop codex` (managed per-process SPKI pin)",
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn prepare_desktop_onboarding_state(codex_home: &Path) -> Result<()> {
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    prepare_desktop_onboarding_state_at(codex_home, &timestamp)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn prepare_desktop_onboarding_state_at(codex_home: &Path, timestamp: &str) -> Result<()> {
    let path = codex_home.join(".codex-global-state.json");
    let mut root = if path.exists() {
        Value::Object(load_json_object(&path)?)
    } else {
        Value::Object(Map::new())
    };
    let original = root.clone();
    let object = root
        .as_object_mut()
        .context("Desktop global state must contain a JSON object")?;
    let atom_state = object
        .entry("electron-persisted-atom-state".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let atom_state = atom_state
        .as_object_mut()
        .context("Desktop persisted atom state must contain a JSON object")?;
    atom_state.insert(
        "electron:onboarding-projectless-completed".to_string(),
        Value::Bool(true),
    );
    atom_state.insert(
        "electron:onboarding-hide-first-new-thread-promos".to_string(),
        Value::Bool(true),
    );
    // This Desktop-owned persisted atom controls whether the permission
    // selector exposes every available profile. It does not select a profile,
    // change approval policy, or grant Full Access. Some Windows profiles can
    // retain a stale false value even when app-server reports all profiles as
    // allowed, leaving the composer control disabled.
    atom_state.insert(
        "composer-permission-mode-visibility".to_string(),
        Value::Bool(true),
    );
    if root == original {
        return Ok(());
    }
    backup_if_exists(&path, timestamp)?;
    write_json_object(&path, root).with_context(|| {
        format!(
            "failed to prepare Desktop onboarding state {}",
            path.display()
        )
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn check_desktop_permission_visibility(report: &mut DoctorReport) {
    let codex_dir = match codex_config_dir() {
        Ok(path) => path,
        Err(err) => {
            report.warn("Desktop permission selector", err.to_string());
            return;
        }
    };
    let path = codex_dir.join(".codex-global-state.json");
    if !path.is_file() {
        report.warn(
            "Desktop permission selector",
            "Desktop state is absent; run `saiai init-codex` before launching Desktop",
        );
        return;
    }
    let state = match load_json_object(&path) {
        Ok(state) => state,
        Err(err) => {
            report.warn("Desktop permission selector", err.to_string());
            return;
        }
    };
    let visible = state
        .get("electron-persisted-atom-state")
        .and_then(Value::as_object)
        .and_then(|state| state.get("composer-permission-mode-visibility"))
        .and_then(Value::as_bool);
    match visible {
        Some(true) => report.ok(
            "Desktop permission selector",
            "all available permission profiles are visible",
        ),
        Some(false) => report.warn(
            "Desktop permission selector",
            "permission profile visibility is disabled; rerun `saiai init-codex` or use `saiai desktop codex`",
        ),
        None => report.warn(
            "Desktop permission selector",
            "visibility state is missing or invalid; rerun `saiai init-codex` or use `saiai desktop codex`",
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn prepare_isolated_desktop_state(desktop_root: &Path, desktop_codex: &Path) -> Result<()> {
    let auth_path = desktop_codex.join("auth.json");
    let source_auth_path = codex_config_dir()?.join("auth.json");
    if !copy_real_codex_oauth_auth(&source_auth_path, &auth_path)?
        && !copy_real_codex_oauth_auth(&auth_path, &auth_path)?
    {
        replace_codex_local_proxy_auth(&auth_path)?;
    }
    validate_codex_oauth_auth(&auth_path)?;
    prepare_codex_oauth_files(desktop_codex, true)?;
    disable_codex_apps(&desktop_codex.join("config.toml"))?;
    write_desktop_account_id(&auth_path, desktop_root)?;
    prepare_desktop_onboarding_state(desktop_codex)
}

fn copy_real_codex_oauth_auth(source: &Path, target: &Path) -> Result<bool> {
    if !source.is_file() {
        return Ok(false);
    }
    let auth = match load_json_object(source) {
        Ok(auth) => auth,
        Err(_) => return Ok(false),
    };
    let access_token = auth
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    // API-key-only legacy auth is a valid source for Desktop local-proxy
    // mode. It has no OAuth token to copy; the caller will create an isolated
    // SAIAI placeholder instead of requiring `saiai codex` first.
    if access_token.trim().is_empty()
        || is_codex_placeholder_access_token(access_token)
        || codex_access_token_is_expired(access_token, Utc::now().timestamp())
    {
        return Ok(false);
    }
    validate_codex_oauth_auth(source)?;
    let bytes = fs::read(source)
        .with_context(|| format!("failed to read OAuth auth file {}", source.display()))?;
    write_bytes_atomic(target, &bytes, 0o600)
        .with_context(|| format!("failed to copy OAuth auth file to {}", target.display()))?;
    Ok(true)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn codex_access_token_is_expired(token: &str, now_epoch_seconds: i64) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&decoded) else {
        return false;
    };
    claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_some_and(|expires_at| expires_at <= now_epoch_seconds.saturating_add(60))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn disable_codex_apps(path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read Desktop config {}", path.display()))?;
    let mut document = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("failed to parse Desktop config {} as TOML", path.display()))?;
    match document.get("features") {
        None => document["features"] = Item::Table(Table::new()),
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has a `features` entry that is not a table",
            path.display()
        ),
    }
    document["features"]
        .as_table_mut()
        .expect("features ensured to be a table")
        .insert("apps", value(false));
    write_bytes_atomic(path, document.to_string().as_bytes(), 0o600)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn write_desktop_account_id(auth_path: &Path, desktop_root: &Path) -> Result<()> {
    let auth = load_json_object(auth_path)?;
    let account_id = auth
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get("account_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Desktop OAuth auth.json has no account_id")?;
    let path = desktop_root.join("account-id");
    write_bytes_atomic(&path, account_id.as_bytes(), 0o600).with_context(|| {
        format!(
            "failed to write Desktop account identity {}",
            path.display()
        )
    })
}

fn validate_codex_oauth_auth(path: &Path) -> Result<()> {
    let auth = load_json_object(path)
        .with_context(|| format!("failed to load OAuth auth file {}", path.display()))?;
    let auth_mode = auth.get("auth_mode").and_then(Value::as_str).unwrap_or("");
    if !matches!(auth_mode, "chatgpt" | "chatgptAuthTokens") {
        bail!(
            "{} is not in ChatGPT token mode; first-phase `saiai codex` does not accept API-key-only auth",
            path.display()
        );
    }
    let access_token = auth
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if access_token.trim().is_empty() {
        bail!(
            "{} has no ChatGPT OAuth access token; run `codex login` before `saiai codex`",
            path.display()
        );
    }
    Ok(())
}

fn prepare_codex_oauth_files(codex_dir: &Path, persist_system_proxy: bool) -> Result<Vec<PathBuf>> {
    let config_path = codex_dir.join("config.toml");
    let auth_path = codex_dir.join("auth.json");
    let mut documents = Vec::new();

    let raw = if config_path.exists() {
        fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?
    } else {
        String::new()
    };
    let document = if raw.trim().is_empty() {
        DocumentMut::new()
    } else {
        raw.parse::<DocumentMut>().with_context(|| {
            format!(
                "failed to parse {} as TOML; no file was modified",
                config_path.display()
            )
        })?
    };
    documents.push((config_path.clone(), document));

    if codex_dir.is_dir() {
        for entry in fs::read_dir(codex_dir)
            .with_context(|| format!("failed to list {}", codex_dir.display()))?
        {
            let path = entry?.path();
            if path == config_path
                || !path.is_file()
                || !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".config.toml"))
            {
                continue;
            }
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let document = raw.parse::<DocumentMut>().with_context(|| {
                format!(
                    "failed to parse {} as TOML; no file was modified",
                    path.display()
                )
            })?;
            documents.push((path, document));
        }
    }

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(&config_path, &timestamp)?;
    backup_if_exists(&auth_path, &timestamp)?;
    for (path, _) in &documents {
        if path != &config_path {
            backup_if_exists(path, &timestamp)?;
        }
    }

    let mut written = Vec::with_capacity(documents.len());
    for (path, mut document) in documents {
        clean_codex_oauth_document(&mut document);
        if persist_system_proxy {
            enable_codex_system_proxy(&mut document, &path)?;
        }
        write_bytes_atomic(path.as_path(), document.to_string().as_bytes(), 0o600)?;
        written.push(path);
    }

    let mut auth = load_json_object(&auth_path)?;
    // Keep the OAuth token object intact. A null API-key field matches Codex's
    // normal OAuth shape while preventing API-key precedence in mixed installs.
    auth.insert("OPENAI_API_KEY".to_string(), Value::Null);
    write_json_object(&auth_path, Value::Object(auth))?;
    Ok(written)
}

fn enable_codex_system_proxy(document: &mut DocumentMut, path: &Path) -> Result<()> {
    match document.get("features") {
        None => document["features"] = Item::Table(Table::new()),
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has a `features` entry that is not a table; refusing to overwrite (backup is preserved)",
            path.display()
        ),
    }
    document["features"]
        .as_table_mut()
        .expect("features ensured to be a table")
        .insert(
            "respect_system_proxy",
            value(codex_respect_system_proxy_enabled()),
        );
    Ok(())
}

fn clean_codex_oauth_document(document: &mut DocumentMut) {
    document["model_provider"] = value("openai");
    for key in ["base_url", "openai_base_url", "chatgpt_base_url"] {
        document.as_table_mut().remove(key);
    }
    // A custom provider can override the built-in endpoint even when the root
    // provider looks harmless. The managed OAuth route deliberately does not
    // retain a compatibility alias for historical direct-Gateway sessions.
    document.as_table_mut().remove("model_providers");

    // Let the built-in OpenAI provider keep its official Responses transport
    // defaults. The local proxy supports both HTTP fallback and WebSocket.
    if !document.get("features").is_some_and(Item::is_table) {
        return;
    }
    let features = document["features"]
        .as_table_mut()
        .expect("features table created above");
    features.remove("responses_websockets");
    features.remove("responses_websockets_v2");
    if features.is_empty() {
        document.as_table_mut().remove("features");
    }
}

fn ensure_local_proxy_running(listen: &str) -> Result<()> {
    let addr = listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {listen}"))?;
    if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
        return Ok(());
    }
    run_service_start().context("failed to start the SAIAI local proxy")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("SAIAI local proxy did not become reachable at {listen}")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn local_proxy_chatgpt_spki(listen: &str) -> Result<String> {
    let addr = listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {listen}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .with_context(|| format!("failed to connect to SAIAI local proxy at {listen}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream
        .write_all(
            format!(
                "CONNECT {CODEX_CERTIFICATE_CONTROL_HOST}:443 HTTP/1.1\r\nHost: {CODEX_CERTIFICATE_CONTROL_HOST}:443\r\n\r\n"
            )
            .as_bytes(),
        )
        .context("failed to request the local proxy certificate identity")?;
    stream.flush()?;

    let mut reader = StdBufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code == "200")
    {
        bail!("SAIAI local proxy did not accept the certificate identity request");
    }
    let mut spki = None;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name
                .trim()
                .eq_ignore_ascii_case(CODEX_CERTIFICATE_SPKI_HEADER)
        {
            spki = Some(value.trim().to_string());
        }
    }
    let spki = spki.context(
        "running SAIAI proxy does not expose a Desktop certificate pin; run `saiai restart` and retry",
    )?;
    let pins = spki.split(',').collect::<Vec<_>>();
    if pins.is_empty() || pins.iter().any(|pin| pin.trim().is_empty()) {
        bail!("SAIAI local proxy returned an empty Desktop certificate pin");
    }
    for pin in pins {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(pin.trim())
            .context("SAIAI local proxy returned an invalid Desktop certificate pin")?;
        if decoded.len() != 32 {
            bail!("SAIAI local proxy returned an invalid Desktop certificate pin length");
        }
    }
    Ok(spki)
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
struct SaiaiConfig {
    version: u32,
    base_url: String,
    api_key: String,
    listen: String,
    ca_cert_path: String,
    #[serde(default)]
    ca_key_path: String,
    #[serde(default = "default_true")]
    chatgpt_chat_passthrough: bool,
    #[serde(default)]
    providers: ProviderCredentials,
}

#[derive(Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
struct ProviderCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claude: Option<ProviderCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    codex: Option<ProviderCredential>,
}

impl ProviderCredentials {
    fn is_empty(&self) -> bool {
        self.claude.is_none() && self.codex.is_none()
    }
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
struct ProviderCredential {
    base_url: String,
    api_key: String,
}

fn select_local_proxy_listen(existing: Option<&str>) -> Result<String> {
    if let Some(listen) = existing.filter(|value| !value.trim().is_empty())
        && let Ok(addr) = listen.parse::<SocketAddr>()
        && addr.ip().is_loopback()
    {
        // Keep the current port when our managed service owns it. On a
        // repeat initialization this avoids needless proxy churn.
        if managed_service_is_active()
            && TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
        {
            return Ok(listen.to_string());
        }
        // Preserve an available existing port; only replace it when an
        // unrelated process has claimed it.
        if StdTcpListener::bind(addr).is_ok() {
            return Ok(listen.to_string());
        }
    }

    let listener = StdTcpListener::bind(("127.0.0.1", 0))
        .context("failed to allocate a loopback port for the SAIAI local proxy")?;
    let port = listener
        .local_addr()
        .context("failed to read the allocated SAIAI local proxy port")?
        .port();
    Ok(format!("127.0.0.1:{port}"))
}

#[derive(Clone, Copy)]
enum ProviderKind {
    Claude,
    Codex,
}

impl ProviderKind {
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Codex => "Codex",
        }
    }
}

fn update_saiai_provider_config(
    provider: ProviderKind,
    credential: ProviderCredential,
    ca_paths: Option<(PathBuf, PathBuf)>,
) -> Result<SaiaiConfigUpdate> {
    let path = saiai_config_path()?;
    update_saiai_provider_config_at(&path, provider, credential, ca_paths)
}

fn update_saiai_provider_config_at(
    path: &Path,
    provider: ProviderKind,
    credential: ProviderCredential,
    ca_paths: Option<(PathBuf, PathBuf)>,
) -> Result<SaiaiConfigUpdate> {
    let existing = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<SaiaiConfig>(&raw).ok());
    let previous = existing.clone();
    let mut config = existing.unwrap_or_else(|| SaiaiConfig {
        version: SAIAI_CONFIG_VERSION,
        base_url: credential.base_url.clone(),
        api_key: credential.api_key.clone(),
        listen: String::new(),
        ca_cert_path: ca_paths
            .as_ref()
            .map(|(cert, _)| cert.display().to_string())
            .unwrap_or_default(),
        ca_key_path: ca_paths
            .as_ref()
            .map(|(_, key)| key.display().to_string())
            .unwrap_or_default(),
        chatgpt_chat_passthrough: true,
        providers: ProviderCredentials::default(),
    });
    let existing_listen = (!config.listen.trim().is_empty()).then_some(config.listen.as_str());
    config.listen = select_local_proxy_listen(existing_listen)?;

    if config.version != SAIAI_CONFIG_VERSION
        || config.ca_cert_path.trim().is_empty()
        || config.ca_key_path.trim().is_empty()
    {
        if let Some((cert, key)) = ca_paths.as_ref() {
            config.version = SAIAI_CONFIG_VERSION;
            config.ca_cert_path = cert.display().to_string();
            config.ca_key_path = key.display().to_string();
        } else {
            bail!(
                "SAIAI config is obsolete; initialize {} again with the one-command setup",
                provider.name()
            );
        }
    }
    if let Some((cert, key)) = ca_paths.as_ref()
        && read_runtime_ca(&config).is_err()
    {
        config.version = SAIAI_CONFIG_VERSION;
        config.ca_cert_path = cert.display().to_string();
        config.ca_key_path = key.display().to_string();
    }
    if let Some((cert, key)) = ca_paths {
        if config.ca_cert_path.trim().is_empty() {
            config.ca_cert_path = cert.display().to_string();
        }
        if config.ca_key_path.trim().is_empty() {
            config.ca_key_path = key.display().to_string();
        }
    }

    match provider {
        ProviderKind::Claude => config.providers.claude = Some(credential),
        ProviderKind::Codex => config.providers.codex = Some(credential),
    }
    let selected = match provider {
        ProviderKind::Claude => config.providers.claude.as_ref(),
        ProviderKind::Codex => config.providers.codex.as_ref(),
    }
    .expect("selected provider credential was just inserted");
    config.base_url = selected.base_url.clone();
    config.api_key = selected.api_key.clone();
    write_saiai_config_at(path, &config)?;
    Ok(SaiaiConfigUpdate {
        changed: proxy_runtime_config_changed(previous.as_ref(), &config),
        config,
    })
}

fn proxy_runtime_config_changed(previous: Option<&SaiaiConfig>, current: &SaiaiConfig) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    previous.version != current.version
        || previous.listen != current.listen
        || previous.ca_cert_path != current.ca_cert_path
        || previous.ca_key_path != current.ca_key_path
        || previous.chatgpt_chat_passthrough != current.chatgpt_chat_passthrough
        || previous.providers != current.providers
        || (previous.providers.is_empty()
            && (previous.base_url != current.base_url || previous.api_key != current.api_key))
}

fn default_true() -> bool {
    true
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone, Deserialize)]
struct UpdateManifest {
    version: String,
    assets: HashMap<String, UpdateManifestAsset>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone, Deserialize)]
struct UpdateManifestAsset {
    sha256: String,
    #[allow(dead_code)]
    size: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
struct LinuxBackgroundState {
    schema_version: u32,
    pid: u32,
    start_time_ticks: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct LinuxProcessIdentity {
    state: char,
    start_time_ticks: u64,
}

#[cfg(target_os = "linux")]
struct LinuxServiceLock {
    _file: fs::File,
}

fn print_version() -> Result<()> {
    println!("saiai {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

fn run_local_proxy(verbose: bool) -> Result<()> {
    warn_process_env_conflicts();
    warn_claude_settings_overrides();
    let cfg = read_saiai_config()?;
    let (ca_cert_pem, ca_key_pem) = read_runtime_ca(&cfg)?;
    ensure_listen_available(&cfg.listen)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start async runtime")?;
    let claude = cfg
        .providers
        .claude
        .as_ref()
        .map(|credential| local_proxy::RouteConfig {
            base_url: credential.base_url.clone(),
            api_key: credential.api_key.clone(),
        });
    let codex = cfg
        .providers
        .codex
        .as_ref()
        .map(|credential| local_proxy::RouteConfig {
            base_url: credential.base_url.clone(),
            api_key: credential.api_key.clone(),
        });
    runtime.block_on(local_proxy::run(local_proxy::Config {
        listen: cfg.listen,
        base_url: cfg.base_url,
        api_key: cfg.api_key,
        claude,
        codex,
        ca_cert_pem,
        ca_key_pem,
        verbose,
        chatgpt_chat_passthrough: cfg.chatgpt_chat_passthrough,
    }))
}

fn read_runtime_ca(cfg: &SaiaiConfig) -> Result<(String, String)> {
    if cfg.version != SAIAI_CONFIG_VERSION || cfg.ca_key_path.trim().is_empty() {
        bail!("SAIAI local proxy configuration is obsolete; rerun the one-command SAIAI setup");
    }
    let cert_pem = fs::read_to_string(&cfg.ca_cert_path)
        .with_context(|| format!("failed to read SAIAI CA certificate {}", cfg.ca_cert_path))?;
    let key_pem = fs::read_to_string(&cfg.ca_key_path)
        .with_context(|| format!("failed to read SAIAI CA key {}", cfg.ca_key_path))?;
    local_proxy::validate_tls_config(&cert_pem, &key_pem)
        .context("SAIAI installation CA is invalid; rerun the one-command SAIAI setup")?;
    Ok((cert_pem, key_pem))
}

#[cfg(target_os = "linux")]
fn run_service_start() -> Result<()> {
    let _service_lock = acquire_linux_service_lock()?;
    warn_process_env_conflicts();
    warn_claude_settings_overrides();
    let cfg = read_saiai_config()?;
    match ensure_systemd_user_available() {
        Ok(()) => {
            stop_linux_background_proxy()?;
            warn_systemd_user_env_conflicts();
            let was_active = service_is_active().unwrap_or(false);
            if !was_active {
                ensure_listen_available(&cfg.listen)?;
            }
            let service_path = write_user_service()?;
            run_systemctl(&["daemon-reload"])?;
            run_systemctl(&["enable", SAIAI_SERVICE_NAME])?;
            if was_active {
                run_systemctl(&["restart", SAIAI_SERVICE_NAME])?;
            } else {
                run_systemctl(&["start", SAIAI_SERVICE_NAME])?;
            }
            println!("SAIAI user service started or refreshed.");
            println!("Service: {}", service_path.display());
        }
        Err(systemd_error) => {
            eprintln!(
                "WARN systemd --user unavailable; using a managed background process: {systemd_error}"
            );
            let pid = start_linux_background_proxy(&cfg)?;
            println!("SAIAI background proxy started or refreshed.");
            println!("Service manager: background process");
            println!("PID: {pid}");
        }
    }
    println!("Listening: http://{}", cfg.listen);
    println!("Status: saiai status");
    println!("Logs: saiai logs");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_service_start() -> Result<()> {
    warn_process_env_conflicts();
    warn_claude_settings_overrides();
    let cfg = read_saiai_config()?;
    let domain = launchctl_gui_domain()?;
    let target = launchctl_service_target(&domain);
    let loaded = macos_launchd_loaded(&target);
    let plist = write_launchd_plist()?;
    let plist_path = &plist.path;
    let plist_text = plist_path.display().to_string();

    // The proxy reads its current Gateway, key, CA, and listen address from
    // config.json on every process start. Re-bootstrap only when LaunchAgent
    // metadata itself changed; bootout/bootstrap can take several seconds on
    // Intel macOS and is unnecessary for an ordinary init refresh.
    if !loaded || plist.changed {
        if loaded {
            run_launchctl(&["bootout", &domain, &plist_text])?;
        }
        ensure_listen_available(&cfg.listen)?;
        run_launchctl(&["bootstrap", &domain, &plist_text])?;
    }
    run_launchctl(&["enable", &target])?;
    run_launchctl(&["kickstart", "-k", &target])?;
    println!("SAIAI LaunchAgent started.");
    println!("Service: {}", plist_path.display());
    println!("Listening: http://{}", cfg.listen);
    println!("Status: saiai status");
    println!("Logs: saiai logs");
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_service_start() -> Result<()> {
    warn_process_env_conflicts();
    warn_claude_settings_overrides();
    let cfg = read_saiai_config()?;
    if let Some(pid) = windows_background_pid()? {
        if windows_pid_is_running(pid).unwrap_or(false) {
            stop_windows_background_proxy()?;
        }
    }
    ensure_listen_available(&cfg.listen)?;
    let pid = start_windows_background_proxy()?;
    println!("SAIAI background proxy started or refreshed.");
    println!("PID: {pid}");
    println!("Listening: http://{}", cfg.listen);
    println!("Status: saiai status");
    println!("Logs: saiai logs");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_start() -> Result<()> {
    bail!("saiai start currently supports Linux, macOS, and Windows only");
}

#[cfg(target_os = "linux")]
fn run_service_stop() -> Result<()> {
    let _service_lock = acquire_linux_service_lock()?;
    let background_stopped = stop_linux_background_proxy()?;
    match ensure_systemd_user_available() {
        Ok(()) => {
            if stop_systemd_user_service_if_present()? {
                println!("SAIAI user service stopped and disabled.");
            } else if background_stopped {
                println!("SAIAI background proxy stopped.");
            } else {
                println!("SAIAI service is not running.");
            }
        }
        Err(systemd_error) => {
            if background_stopped {
                println!("SAIAI background proxy stopped.");
            } else if linux_configured_listen_has_saiai_owner()? {
                bail!(
                    "a SAIAI process is listening, but it is not the managed background process and systemd --user is unavailable: {systemd_error}"
                );
            } else {
                println!("SAIAI background proxy is not running.");
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_service_stop() -> Result<()> {
    let domain = launchctl_gui_domain()?;
    let plist_path = launchd_plist_path()?;
    let plist = plist_path.display().to_string();
    let _ = run_launchctl(&["bootout", &domain, &plist]);
    println!("SAIAI LaunchAgent stopped.");
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_service_stop() -> Result<()> {
    stop_windows_background_proxy()?;
    println!("SAIAI background proxy stopped.");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_stop() -> Result<()> {
    bail!("saiai stop currently supports Linux, macOS, and Windows only");
}

#[cfg(target_os = "linux")]
fn run_service_status() -> Result<()> {
    println!("saiai {}", env!("CARGO_PKG_VERSION"));
    print_process_env_conflicts_for_status();
    print_claude_settings_overrides_for_status();
    match read_saiai_config() {
        Ok(cfg) => {
            println!("config: {}", saiai_config_path()?.display());
            println!("base_url: {}", cfg.base_url.trim().trim_end_matches('/'));
            println!("listen: http://{}", cfg.listen);
        }
        Err(err) => println!("config: not ready ({err})"),
    }

    let background = linux_background_state();
    if let Ok(Some(state)) = background.as_ref()
        && linux_background_state_is_running(state)
    {
        println!("service manager: background process");
        println!("service active: yes");
        println!("pid: {}", state.pid);
        println!("logs: {}", linux_service_log_path()?.display());
        if ensure_systemd_user_available().is_ok() && service_is_active().unwrap_or(false) {
            println!("service warning: systemd and background instances are both active");
        }
        return Ok(());
    }

    let systemd_status = ensure_systemd_user_available();
    if let Err(err) = &systemd_status {
        println!("service manager: background process");
        println!("service active: no");
        match background.as_ref() {
            Ok(Some(state)) => println!("stale pid: {}", state.pid),
            Ok(None) => {}
            Err(state_error) => println!("background state: invalid ({state_error})"),
        }
        println!("systemd user: unavailable ({err})");
        println!("logs: {}", linux_service_log_path()?.display());
        return Ok(());
    }

    println!("service manager: systemd --user");
    if let Ok(Some(state)) = background.as_ref() {
        println!("stale background pid: {}", state.pid);
    } else if let Err(state_error) = background.as_ref() {
        println!("background state: invalid ({state_error})");
    }
    print_systemd_user_env_conflicts_for_status();

    match systemctl_value("LoadState") {
        Ok(value) => println!("service load: {value}"),
        Err(err) => println!("service load: unknown ({err})"),
    }
    match systemctl_value("UnitFileState") {
        Ok(value) => println!("service enabled: {value}"),
        Err(err) => println!("service enabled: unknown ({err})"),
    }
    match systemctl_value("ActiveState") {
        Ok(value) => println!("service active: {value}"),
        Err(err) => println!("service active: unknown ({err})"),
    }
    match systemctl_value("SubState") {
        Ok(value) => println!("service state: {value}"),
        Err(err) => println!("service state: unknown ({err})"),
    }
    match systemctl_value("MainPID") {
        Ok(value) if value != "0" && !value.is_empty() => println!("pid: {value}"),
        _ => {}
    }

    print_recent_logs(8)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_service_status() -> Result<()> {
    println!("saiai {}", env!("CARGO_PKG_VERSION"));
    print_process_env_conflicts_for_status();
    print_claude_settings_overrides_for_status();
    match read_saiai_config() {
        Ok(cfg) => {
            println!("config: {}", saiai_config_path()?.display());
            println!("base_url: {}", cfg.base_url.trim().trim_end_matches('/'));
            println!("listen: http://{}", cfg.listen);
        }
        Err(err) => println!("config: not ready ({err})"),
    }
    let domain = launchctl_gui_domain()?;
    let target = launchctl_service_target(&domain);
    match command_output(MACOS_LAUNCHCTL_COMMAND, &["print", &target]) {
        Ok(output) => {
            println!("service active: yes");
            for line in output.lines().take(8) {
                println!("  {line}");
            }
        }
        Err(err) => println!("service active: no ({err})"),
    }
    println!("logs: {}", launchd_log_path()?.display());
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_service_status() -> Result<()> {
    println!("saiai {}", env!("CARGO_PKG_VERSION"));
    print_process_env_conflicts_for_status();
    print_claude_settings_overrides_for_status();
    match read_saiai_config() {
        Ok(cfg) => {
            println!("config: {}", saiai_config_path()?.display());
            println!("base_url: {}", cfg.base_url.trim().trim_end_matches('/'));
            println!("listen: http://{}", cfg.listen);
        }
        Err(err) => println!("config: not ready ({err})"),
    }
    match windows_background_pid()? {
        Some(pid) if windows_pid_is_running(pid).unwrap_or(false) => {
            println!("service active: yes");
            println!("pid: {pid}");
        }
        Some(pid) => {
            println!("service active: no");
            println!("stale pid: {pid}");
        }
        None => println!("service active: no"),
    }
    println!("logs: {}", windows_log_path()?.display());
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_status() -> Result<()> {
    bail!("saiai status currently supports Linux, macOS, and Windows only");
}

#[cfg(target_os = "linux")]
fn run_service_logs() -> Result<()> {
    let background_active = linux_background_state()?
        .as_ref()
        .is_some_and(linux_background_state_is_running);
    if background_active || ensure_systemd_user_available().is_err() {
        return run_linux_background_logs();
    }
    ensure_command("journalctl")?;
    let mut command = ProcessCommand::new("journalctl");
    apply_systemd_user_environment(&mut command);
    let status = command
        .args(["--user", "-u", SAIAI_SERVICE_NAME, "-f"])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to run journalctl")?;
    if !status.success() {
        bail!("journalctl exited with {status}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_service_logs() -> Result<()> {
    let log_path = launchd_log_path()?;
    let status = ProcessCommand::new(MACOS_TAIL_COMMAND)
        .arg("-n")
        .arg("80")
        .arg("-f")
        .arg(&log_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to tail {}", log_path.display()))?;
    if !status.success() {
        bail!("tail exited with {status}");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_service_logs() -> Result<()> {
    let log_path = windows_log_path()?;
    let command = format!(
        "Get-Content -LiteralPath {} -Tail 80 -Wait",
        powershell_quote_path(&log_path)?
    );
    let status = ProcessCommand::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to read {}", log_path.display()))?;
    if !status.success() {
        bail!("PowerShell exited with {status}");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_logs() -> Result<()> {
    bail!("saiai logs currently supports Linux, macOS, and Windows only");
}

#[cfg(target_os = "linux")]
fn run_service_restart() -> Result<()> {
    run_service_start()
}

#[cfg(target_os = "macos")]
fn run_service_restart() -> Result<()> {
    let _ = run_service_stop();
    run_service_start()
}

#[cfg(target_os = "windows")]
fn run_service_restart() -> Result<()> {
    let _ = run_service_stop();
    run_service_start()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_restart() -> Result<()> {
    bail!("saiai restart currently supports Linux, macOS, and Windows only");
}

#[cfg(target_os = "linux")]
fn managed_service_is_active() -> bool {
    if linux_background_state()
        .ok()
        .flatten()
        .is_some_and(|state| linux_background_state_is_running(&state))
    {
        return true;
    }
    ensure_systemd_user_available().is_ok() && service_is_active().unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn managed_service_is_active() -> bool {
    macos_launchd_running().unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn managed_service_is_active() -> bool {
    windows_background_pid()
        .ok()
        .flatten()
        .is_some_and(|pid| windows_pid_is_running(pid).unwrap_or(false))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn managed_service_is_active() -> bool {
    false
}

fn should_skip_initialization_proxy_start(value: Option<&str>) -> bool {
    value == Some("1")
}

fn binary_changed_during_initialization(value: Option<&str>) -> bool {
    value == Some("1")
}

fn initialization_requires_proxy_refresh(
    config_changed: bool,
    binary_changed: bool,
    managed_service_active: bool,
    proxy_reachable: bool,
) -> bool {
    config_changed || binary_changed || !managed_service_active || !proxy_reachable
}

fn configured_local_proxy_reachable() -> bool {
    let Ok(config) = read_saiai_config() else {
        return false;
    };
    let Ok(address) = config.listen.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok()
}

fn update_refresh_failure_is_recoverable(proxy_reachable: bool) -> bool {
    proxy_reachable
}

fn start_managed_service_after_initialization(config_changed: bool) -> Result<()> {
    if should_skip_initialization_proxy_start(env::var("SAIAI_SKIP_START").ok().as_deref()) {
        println!("SAIAI local proxy start skipped (SAIAI_SKIP_START=1).");
        return Ok(());
    }
    let binary_changed =
        binary_changed_during_initialization(env::var("SAIAI_BINARY_UPDATED").ok().as_deref());
    let managed_service_active = managed_service_is_active();
    let proxy_reachable = configured_local_proxy_reachable();
    if !initialization_requires_proxy_refresh(
        config_changed,
        binary_changed,
        managed_service_active,
        proxy_reachable,
    ) {
        println!("SAIAI local proxy left running; binary and runtime configuration are unchanged.");
        return Ok(());
    }
    run_service_start().context("failed to start or refresh the SAIAI local proxy")?;
    println!("SAIAI local proxy started or refreshed after configuration update.");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_update() -> Result<()> {
    let service_was_active = managed_service_is_active();
    let cfg = read_saiai_config()?;
    let asset = current_platform_asset_name()?;
    let base = cfg.base_url.trim().trim_end_matches('/');
    let manifest_url = format!("{base}/saiai-cli/manifest.json");
    let url = format!("{}/saiai-cli/{asset}", base);
    let current_exe = env::current_exe().context("failed to resolve current saiai executable")?;
    let current_exe = fs::canonicalize(&current_exe).unwrap_or_else(|_| current_exe.clone());
    let parent = current_exe
        .parent()
        .context("failed to resolve current executable directory")?;
    if !current_exe.is_file() {
        bail!(
            "current executable is not a regular file: {}",
            current_exe.display()
        );
    }
    let current_bytes = fs::read(&current_exe)
        .with_context(|| format!("failed to read {}", current_exe.display()))?;
    let current_sha256 = sha256_hex(&current_bytes);

    println!("Current: saiai {}", env!("CARGO_PKG_VERSION"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start async runtime")?;

    println!("Checking: {manifest_url}");
    let manifest = runtime.block_on(download_update_manifest(&manifest_url))?;
    let expected_sha256 = if let Some(manifest) = manifest {
        let remote_version = manifest.version.trim();
        let ordering = compare_versions(remote_version, env!("CARGO_PKG_VERSION"))
            .with_context(|| format!("failed to compare remote version {remote_version:?}"))?;
        let asset_info = manifest
            .assets
            .get(asset)
            .with_context(|| format!("manifest does not include asset {asset}"))?;
        let expected = asset_info.sha256.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("manifest asset {asset} has invalid sha256 {expected:?}");
        }

        println!("Latest: saiai {remote_version}");
        if ordering == Ordering::Less {
            println!(
                "Already current: saiai {} (remote saiai {remote_version})",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        if ordering == Ordering::Equal && current_sha256 == expected {
            println!("Already current: saiai {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        if ordering == Ordering::Equal {
            println!("Same version but local binary hash differs; refreshing {asset}");
        }
        Some(expected)
    } else {
        println!("Manifest unavailable; falling back to binary download.");
        None
    };

    println!("Downloading: {url}");
    let bytes = runtime.block_on(download_update_asset(&url))?;
    validate_update_asset(&bytes, asset)?;
    if let Some(expected) = &expected_sha256 {
        let actual = sha256_hex(&bytes);
        if actual != *expected {
            bail!("downloaded {asset} sha256 mismatch: expected {expected}, got {actual}");
        }
    }

    let unique = update_suffix();
    let candidate_name = update_candidate_name(&unique);
    let backup_name = update_backup_name();
    let candidate_path = parent.join(candidate_name);
    let backup_path = parent.join(backup_name);
    write_update_candidate(&candidate_path, &bytes)
        .with_context(|| format!("failed to write {}", candidate_path.display()))?;

    let candidate_version = command_stdout(&candidate_path, &["--version"])
        .with_context(|| format!("failed to run {}", candidate_path.display()))?;
    if !candidate_version.trim_start().starts_with("saiai ") {
        let _ = fs::remove_file(&candidate_path);
        bail!("downloaded binary did not report a SAIAI version: {candidate_version:?}");
    }

    if current_bytes == bytes {
        let _ = fs::remove_file(&candidate_path);
        println!("Already current: {}", candidate_version.trim());
        return Ok(());
    }

    finalize_update(
        &current_exe,
        &candidate_path,
        &backup_path,
        service_was_active,
    )?;

    #[cfg(target_os = "windows")]
    println!(
        "Update staged: {}. Replacement completes automatically after this command exits; run `saiai --version` to confirm.",
        candidate_version.trim()
    );
    #[cfg(not(target_os = "windows"))]
    println!("Updated: {}", candidate_version.trim());
    println!("Backup: {}", backup_path.display());
    if service_was_active {
        #[cfg(not(target_os = "windows"))]
        {
            if let Err(err) = run_service_restart() {
                // A user manager can race a completed replacement: for
                // example, systemd or launchd may already have kept the
                // managed proxy alive even though the refresh command reports
                // an error. Do not misreport a successful binary replacement
                // as a failed update when the local proxy remains reachable.
                if update_refresh_failure_is_recoverable(configured_local_proxy_reachable()) {
                    eprintln!(
                        "WARN SAIAI client was updated and the local proxy remains reachable, but its automatic service refresh reported: {err:#}. Run `saiai restart` later to retry the refresh."
                    );
                } else {
                    return Err(err).context("failed to restart the active SAIAI service");
                }
            } else {
                println!("Managed SAIAI service was active; restarted automatically.");
            }
        }
        #[cfg(target_os = "windows")]
        println!("Managed SAIAI service was active; restart was scheduled automatically.");
    } else {
        println!("SAIAI service was not active; run `saiai start` when needed.");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_update() -> Result<()> {
    bail!("saiai update currently supports Linux, macOS, and Windows assets only");
}

fn run_doctor(target: DoctorTarget) -> Result<()> {
    let check_claude = matches!(target, DoctorTarget::All | DoctorTarget::Claude);
    let check_codex = matches!(target, DoctorTarget::All | DoctorTarget::Codex);
    let mut report = DoctorReport::new();
    report.ok(
        "version",
        format!("saiai {} ({target:?})", env!("CARGO_PKG_VERSION")),
    );
    check_current_binary(&mut report);
    check_process_env_conflicts(&mut report);
    check_systemd_user_env_conflicts(&mut report);
    check_persistent_env_conflicts(&mut report);

    let config_path = saiai_config_path().context("failed to resolve SAIAI config path")?;
    let cfg = match read_saiai_config() {
        Ok(cfg) => {
            report.ok("config", config_path.display().to_string());
            Some(cfg)
        }
        Err(err) => {
            report.error("config", err.to_string());
            None
        }
    };

    if let Some(cfg) = &cfg {
        check_saiai_config(&mut report, cfg);
        if check_claude {
            check_provider_route(&mut report, cfg, ProviderKind::Claude);
        }
        if check_codex {
            check_provider_route(&mut report, cfg, ProviderKind::Codex);
        }
        check_process_proxy_env_conflicts(&mut report, &cfg.listen);
        check_persistent_proxy_env_conflicts(&mut report);
        check_systemd_user_proxy_env_conflicts(&mut report);
    } else {
        check_process_proxy_env_conflicts(&mut report, DEFAULT_LOCAL_PROXY_LISTEN);
        check_persistent_proxy_env_conflicts(&mut report);
        check_systemd_user_proxy_env_conflicts(&mut report);
    }

    if check_claude {
        match resolve_claude_config_paths() {
            Ok(paths) => check_claude_config(&mut report, cfg.as_ref(), &paths),
            Err(err) => report.error("Claude config", err.to_string()),
        }
    }
    if check_codex {
        check_codex_config(
            &mut report,
            cfg.as_ref(),
            matches!(target, DoctorTarget::Codex),
        );
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        check_desktop_permission_visibility(&mut report);
        #[cfg(target_os = "linux")]
        check_direct_linux_desktop_trust(&mut report);
        #[cfg(target_os = "macos")]
        check_direct_macos_desktop_trust(&mut report);
    }

    if let Some(cfg) = &cfg {
        match read_runtime_ca(cfg) {
            Ok(_) => report.ok(
                "TLS certificate",
                "installation CA can generate api.anthropic.com leaf cert",
            ),
            Err(err) => report.error("TLS certificate", err.to_string()),
        }
    }

    check_service_config(&mut report);

    if let Some(cfg) = &cfg {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to start async runtime")?;
        match runtime.block_on(check_local_proxy_mitm(cfg)) {
            Ok(status) => report.ok("local proxy MITM", status),
            Err(err) if is_local_proxy_connect_error(&err) => report.warn(
                "local proxy MITM",
                format!("{err:#}; start it with `saiai start`"),
            ),
            Err(err) => report.error("local proxy MITM", format!("{err:#}")),
        }
        let health_base = match target {
            DoctorTarget::Claude => provider_route(cfg, ProviderKind::Claude).0,
            DoctorTarget::Codex => provider_route(cfg, ProviderKind::Codex).0,
            DoctorTarget::All => cfg.base_url.as_str(),
        };
        match runtime.block_on(check_gateway_health(health_base)) {
            Ok(status) => report.ok("SAIAI health", status),
            Err(err) => report.error("SAIAI health", err.to_string()),
        }
    }

    report.finish()
}

struct DoctorReport {
    errors: usize,
    warnings: usize,
}

impl DoctorReport {
    fn new() -> Self {
        Self {
            errors: 0,
            warnings: 0,
        }
    }

    fn ok(&self, label: &str, detail: impl AsRef<str>) {
        println!("OK   {label}: {}", detail.as_ref());
    }

    fn warn(&mut self, label: &str, detail: impl AsRef<str>) {
        self.warnings += 1;
        println!("WARN {label}: {}", detail.as_ref());
    }

    fn error(&mut self, label: &str, detail: impl AsRef<str>) {
        self.errors += 1;
        println!("FAIL {label}: {}", detail.as_ref());
    }

    fn finish(&self) -> Result<()> {
        println!();
        println!(
            "doctor summary: {} error(s), {} warning(s)",
            self.errors, self.warnings
        );
        if self.errors > 0 {
            bail!("SAIAI doctor found {} error(s)", self.errors);
        }
        Ok(())
    }
}

const CONFLICTING_ENV_VARS: [&str; 3] = [
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_ATTRIBUTION_HEADER",
];
const CONFLICTING_ENV_UNSET_KEYS: &str =
    "ANTHROPIC_BASE_URL CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_ATTRIBUTION_HEADER";
const CONFLICTING_ENV_LABEL: &str =
    "ANTHROPIC_BASE_URL, CLAUDE_CODE_OAUTH_TOKEN, and CLAUDE_CODE_ATTRIBUTION_HEADER";
const CLAUDE_SETTINGS_LEGACY_ENV_OVERRIDES: [&str; 9] = [
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "API_TIMEOUT_MS",
    "CLAUDE_CODE_ATTRIBUTION_HEADER",
    "CLAUDE_CODE_EFFORT_LEVEL",
    "CLAUDE_CODE_SUBAGENT_MODEL",
];

fn warn_process_env_conflicts() {
    for key in process_env_conflicts() {
        eprintln!(
            "WARN environment: {key} is set in this shell. For SAIAI local proxy mode, unset it before launching Claude Code: unset {CONFLICTING_ENV_UNSET_KEYS}"
        );
    }
    for key in process_proxy_env_conflicts(&format!("http://{DEFAULT_LOCAL_PROXY_LISTEN}")) {
        eprintln!(
            "WARN environment: {key} is set in this shell. For SAIAI local proxy mode, remove conflicting proxy variables before launching Claude Code: unset {CLAUDE_PROXY_ENV_UNSET_KEYS}"
        );
    }
}

fn warn_claude_settings_overrides() {
    match resolve_claude_config_paths() {
        Ok(paths) => warn_claude_settings_overrides_for_paths(&paths),
        Err(err) => eprintln!(
            "WARN Claude settings: could not resolve Claude config path to inspect legacy overrides ({err})"
        ),
    }
}

fn warn_claude_settings_overrides_for_paths(paths: &ClaudeConfigPaths) {
    match claude_settings_override_locations_from_disk(paths) {
        Ok(locations) if !locations.is_empty() => eprintln!(
            "WARN Claude settings: {} contains legacy Claude Code overrides: {}. Remove these entries before launching Claude Code with SAIAI.",
            paths.settings_path.display(),
            format_claude_settings_override_locations(&locations)
        ),
        Ok(_) => {}
        Err(err) => eprintln!(
            "WARN Claude settings: could not inspect legacy overrides in {} ({err})",
            paths.settings_path.display()
        ),
    }
}

fn print_claude_settings_overrides_for_status() {
    match resolve_claude_config_paths() {
        Ok(paths) => match claude_settings_override_locations_from_disk(&paths) {
            Ok(locations) if !locations.is_empty() => println!(
                "Claude settings warning: {} contains legacy Claude Code overrides: {}; remove these entries before launching Claude Code with SAIAI",
                paths.settings_path.display(),
                format_claude_settings_override_locations(&locations)
            ),
            Ok(_) => {}
            Err(err) => println!(
                "Claude settings warning: could not inspect legacy overrides in {} ({err})",
                paths.settings_path.display()
            ),
        },
        Err(err) => println!(
            "Claude settings warning: could not resolve Claude config path to inspect legacy overrides ({err})"
        ),
    }
}

fn claude_settings_override_locations_from_disk(paths: &ClaudeConfigPaths) -> Result<Vec<String>> {
    if !paths.settings_path.exists() {
        return Ok(Vec::new());
    }
    let settings = load_json_object(&paths.settings_path)?;
    Ok(claude_settings_override_locations(&settings))
}

fn claude_settings_override_locations(settings: &Map<String, Value>) -> Vec<String> {
    let mut locations = Vec::new();
    if let Some(env) = settings.get("env").and_then(Value::as_object) {
        for key in CLAUDE_SETTINGS_LEGACY_ENV_OVERRIDES {
            if json_value_is_set(env.get(key)) {
                locations.push(format!("env.{key}"));
            }
        }
    }
    locations
}

fn json_value_is_set(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) | None => false,
        Some(Value::String(value)) => !value.trim().is_empty(),
        Some(_) => true,
    }
}

fn format_claude_settings_override_locations(locations: &[String]) -> String {
    let limit = 8;
    let mut parts = locations.iter().take(limit).cloned().collect::<Vec<_>>();
    if locations.len() > limit {
        parts.push(format!("and {} more", locations.len() - limit));
    }
    parts.join(", ")
}

fn print_process_env_conflicts_for_status() {
    for key in process_env_conflicts() {
        println!(
            "env warning: {key} is set in this shell; run `unset {CONFLICTING_ENV_UNSET_KEYS}` before launching Claude Code"
        );
    }
    for key in process_proxy_env_conflicts(&format!("http://{DEFAULT_LOCAL_PROXY_LISTEN}")) {
        println!(
            "proxy env warning: {key} is set in this shell; remove conflicting proxy variables before launching Claude Code: unset {CLAUDE_PROXY_ENV_UNSET_KEYS}"
        );
    }
}

fn check_process_env_conflicts(report: &mut DoctorReport) {
    let conflicts = process_env_conflicts();
    if conflicts.is_empty() {
        report.ok("shell env", format!("{CONFLICTING_ENV_LABEL} absent"));
        return;
    }
    report.warn(
        "shell env",
        format!(
            "{} set; run `unset {CONFLICTING_ENV_UNSET_KEYS}` before launching Claude Code",
            conflicts.join(", ")
        ),
    );
}

fn check_process_proxy_env_conflicts(report: &mut DoctorReport, listen: &str) {
    let expected_proxy = format!("http://{listen}");
    let conflicts = process_proxy_env_conflicts(&expected_proxy);
    if conflicts.is_empty() {
        report.ok("proxy shell env", "no conflicting proxy variables");
        return;
    }
    report.warn(
        "proxy shell env",
        format!(
            "{} set to a value that may override the lowercase local proxy; unset {CLAUDE_PROXY_ENV_UNSET_KEYS} before launching Claude Code",
            conflicts.join(", ")
        ),
    );
}

fn check_persistent_env_conflicts(report: &mut DoctorReport) {
    match persistent_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => report.ok(
            "profile env",
            format!("{CONFLICTING_ENV_LABEL} absent from shell startup files"),
        ),
        Ok(conflicts) => report.warn(
            "profile env",
            format!(
                "{}; remove or comment these stale entries before launching Claude Code",
                format_persistent_env_conflicts(&conflicts)
            ),
        ),
        Err(err) => report.warn(
            "profile env",
            format!("could not scan shell startup files: {err}"),
        ),
    }
}

fn check_persistent_proxy_env_conflicts(report: &mut DoctorReport) {
    match persistent_proxy_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => report.ok(
            "proxy profile env",
            "no proxy variables in shell startup files",
        ),
        Ok(conflicts) => report.warn(
            "proxy profile env",
            format!(
                "{}; remove or comment these proxy entries before launching Claude Code",
                format_persistent_env_conflicts(&conflicts)
            ),
        ),
        Err(err) => report.warn(
            "proxy profile env",
            format!("could not scan shell startup files: {err}"),
        ),
    }
}

fn process_env_conflicts() -> Vec<&'static str> {
    CONFLICTING_ENV_VARS
        .iter()
        .copied()
        .filter(|key| env_var_is_set(key))
        .collect()
}

fn process_proxy_env_conflicts(expected_proxy: &str) -> Vec<&'static str> {
    CLAUDE_PROXY_ENV_VARS
        .iter()
        .copied()
        .filter(|key| {
            let Some(value) = env::var(key).ok().filter(|value| !value.trim().is_empty()) else {
                return false;
            };
            proxy_value_conflicts(key, &value, expected_proxy)
        })
        .collect()
}

fn proxy_value_conflicts(key: &str, value: &str, expected_proxy: &str) -> bool {
    if key.eq_ignore_ascii_case("NO_PROXY") {
        !value
            .split(',')
            .any(|item| matches!(item.trim(), "127.0.0.1" | "localhost" | "::1"))
    } else {
        value.trim() != expected_proxy
    }
}

fn env_var_is_set(key: &str) -> bool {
    env::var_os(key)
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
fn env_value_is_set(value: Option<&str>) -> bool {
    value.map(|value| !value.is_empty()).unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistentEnvConflict {
    path: PathBuf,
    line: usize,
    key: &'static str,
}

fn persistent_env_conflicts() -> Result<Vec<PersistentEnvConflict>> {
    let mut paths = persistent_env_scan_paths()?;
    paths.sort();
    paths.dedup();

    let mut conflicts = Vec::new();
    for path in paths {
        if !path.exists() || !path.is_file() {
            continue;
        }
        scan_persistent_env_file(&path, &mut conflicts, &CONFLICTING_ENV_VARS)?;
    }
    Ok(conflicts)
}

fn persistent_proxy_env_conflicts() -> Result<Vec<PersistentEnvConflict>> {
    let mut paths = persistent_env_scan_paths()?;
    paths.sort();
    paths.dedup();

    let mut conflicts = Vec::new();
    for path in paths {
        if !path.exists() || !path.is_file() {
            continue;
        }
        scan_persistent_env_file(&path, &mut conflicts, &CLAUDE_PROXY_ENV_VARS)?;
    }
    Ok(conflicts)
}

fn persistent_env_scan_paths() -> Result<Vec<PathBuf>> {
    let home = home_dir().context("failed to resolve home directory")?;
    let mut paths = vec![
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
        home.join(".zshrc"),
        home.join(".zprofile"),
        home.join(".zshenv"),
        home.join(".config").join("fish").join("config.fish"),
    ];

    let environment_dir = match env_dir_override("XDG_CONFIG_HOME") {
        Some(dir) => dir.join("environment.d"),
        None => home.join(".config").join("environment.d"),
    };
    if environment_dir.is_dir() {
        let mut entries = fs::read_dir(&environment_dir)
            .with_context(|| format!("failed to read {}", environment_dir.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("conf"))
            .collect::<Vec<_>>();
        entries.sort();
        paths.extend(entries);
    }

    Ok(paths)
}

fn scan_persistent_env_file(
    path: &Path,
    conflicts: &mut Vec<PersistentEnvConflict>,
    keys: &[&'static str],
) -> Result<()> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    for (idx, line) in raw.lines().enumerate() {
        for key in keys {
            if persistent_env_line_sets_key(line, key) {
                conflicts.push(PersistentEnvConflict {
                    path: path.to_path_buf(),
                    line: idx + 1,
                    key,
                });
            }
        }
    }
    Ok(())
}

fn persistent_env_line_sets_key(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }

    starts_env_assignment(trimmed, key)
        || starts_env_assignment_after_prefix(trimmed, "export", key)
        || starts_env_assignment_after_prefix(trimmed, "declare -x", key)
        || starts_env_assignment_after_prefix(trimmed, "typeset -x", key)
        || starts_env_assignment_after_prefix(trimmed, "set -gx", key)
        || starts_env_assignment_after_prefix(trimmed, "set -x", key)
        || starts_env_assignment_after_prefix(trimmed, "setenv", key)
}

fn starts_env_assignment_after_prefix(line: &str, prefix: &str, key: &str) -> bool {
    let Some(rest) = line.strip_prefix(prefix) else {
        return false;
    };
    if rest
        .chars()
        .next()
        .map(|ch| !ch.is_whitespace())
        .unwrap_or(true)
    {
        return false;
    }
    starts_env_assignment(rest.trim_start(), key)
}

fn starts_env_assignment(line: &str, key: &str) -> bool {
    let Some(rest) = line.strip_prefix(key) else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some(first) = rest.chars().next() else {
        return true;
    };
    first == '=' || first.is_whitespace()
}

fn format_persistent_env_conflicts(conflicts: &[PersistentEnvConflict]) -> String {
    let limit = 6;
    let mut parts = conflicts
        .iter()
        .take(limit)
        .map(|conflict| {
            format!(
                "{} at {}:{}",
                conflict.key,
                conflict.path.display(),
                conflict.line
            )
        })
        .collect::<Vec<_>>();
    if conflicts.len() > limit {
        parts.push(format!("and {} more", conflicts.len() - limit));
    }
    parts.join("; ")
}

#[cfg(target_os = "linux")]
fn print_systemd_user_env_conflicts_for_status() {
    match systemd_user_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => {}
        Ok(conflicts) => println!(
            "systemd env warning: {} set in systemd --user manager; run `systemctl --user unset-environment {CONFLICTING_ENV_UNSET_KEYS}`",
            conflicts.join(", ")
        ),
        Err(err) => {
            println!("systemd env warning: could not inspect systemd --user environment ({err})")
        }
    }
    match systemd_user_proxy_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => {}
        Ok(conflicts) => println!(
            "proxy env warning: {} set in systemd --user manager; remove them before launching Claude Code: systemctl --user unset-environment {CLAUDE_PROXY_ENV_UNSET_KEYS}",
            conflicts.join(", ")
        ),
        Err(err) => {
            println!("proxy env warning: could not inspect systemd --user environment ({err})")
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn print_systemd_user_env_conflicts_for_status() {}

#[cfg(target_os = "linux")]
fn warn_systemd_user_env_conflicts() {
    match systemd_user_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => {}
        Ok(conflicts) => eprintln!(
            "WARN systemd environment: {} set in systemd --user manager. For SAIAI local proxy mode, clear it before launching Claude Code: systemctl --user unset-environment {CONFLICTING_ENV_UNSET_KEYS}",
            conflicts.join(", ")
        ),
        Err(err) => eprintln!(
            "WARN systemd environment: could not inspect systemd --user environment ({err})"
        ),
    }
}

#[cfg(target_os = "linux")]
fn check_systemd_user_env_conflicts(report: &mut DoctorReport) {
    // Headless/root installations may intentionally use the managed
    // background fallback. The service check reports that mode directly.
    if ensure_systemd_user_available().is_err() {
        return;
    }
    match systemd_user_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => report.ok(
            "systemd user env",
            format!("{CONFLICTING_ENV_LABEL} absent"),
        ),
        Ok(conflicts) => report.warn(
            "systemd user env",
            format!(
                "{} set; run `systemctl --user unset-environment {CONFLICTING_ENV_UNSET_KEYS}`",
                conflicts.join(", ")
            ),
        ),
        Err(err) => report.warn(
            "systemd user env",
            format!("could not inspect systemd --user environment: {err}"),
        ),
    }
}

#[cfg(target_os = "linux")]
fn check_systemd_user_proxy_env_conflicts(report: &mut DoctorReport) {
    if ensure_systemd_user_available().is_err() {
        return;
    }
    match systemd_user_proxy_env_conflicts() {
        Ok(conflicts) if conflicts.is_empty() => {
            report.ok("proxy systemd env", "no proxy variables in systemd --user manager")
        }
        Ok(conflicts) => report.warn(
            "proxy systemd env",
            format!(
                "{} set in systemd --user manager; remove them before launching Claude Code: systemctl --user unset-environment {CLAUDE_PROXY_ENV_UNSET_KEYS}",
                conflicts.join(", ")
            ),
        ),
        Err(err) => report.warn(
            "proxy systemd env",
            format!("could not inspect systemd --user environment: {err}"),
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn check_systemd_user_env_conflicts(_report: &mut DoctorReport) {}

#[cfg(not(target_os = "linux"))]
fn check_systemd_user_proxy_env_conflicts(_report: &mut DoctorReport) {}

#[cfg(target_os = "linux")]
fn systemd_user_env_conflicts() -> Result<Vec<&'static str>> {
    ensure_systemd_user_available()?;
    let output = systemctl_user_command()
        .args(["--user", "show-environment"])
        .output()
        .context("failed to run systemctl --user show-environment")?;
    if !output.status.success() {
        bail!(
            "systemctl --user show-environment failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(CONFLICTING_ENV_VARS
        .iter()
        .copied()
        .filter(|key| systemd_env_contains_key(&stdout, key))
        .collect())
}

#[cfg(target_os = "linux")]
fn systemd_user_proxy_env_conflicts() -> Result<Vec<&'static str>> {
    ensure_systemd_user_available()?;
    let output = systemctl_user_command()
        .args(["--user", "show-environment"])
        .output()
        .context("failed to run systemctl --user show-environment")?;
    if !output.status.success() {
        bail!(
            "systemctl --user show-environment failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(CLAUDE_PROXY_ENV_VARS
        .iter()
        .copied()
        .filter(|key| systemd_env_contains_key(&stdout, key))
        .collect())
}

#[cfg(target_os = "linux")]
fn systemd_env_contains_key(output: &str, key: &str) -> bool {
    let prefix = format!("{key}=");
    output.lines().any(|line| line.starts_with(&prefix))
}

fn provider_route(cfg: &SaiaiConfig, provider: ProviderKind) -> (&str, &str) {
    let explicit = match provider {
        ProviderKind::Claude => cfg.providers.claude.as_ref(),
        ProviderKind::Codex => cfg.providers.codex.as_ref(),
    };
    match explicit {
        Some(value) => (value.base_url.as_str(), value.api_key.as_str()),
        None => (cfg.base_url.as_str(), cfg.api_key.as_str()),
    }
}

fn check_provider_route(report: &mut DoctorReport, cfg: &SaiaiConfig, provider: ProviderKind) {
    let explicit = match provider {
        ProviderKind::Claude => cfg.providers.claude.is_some(),
        ProviderKind::Codex => cfg.providers.codex.is_some(),
    };
    let (base_url, api_key) = provider_route(cfg, provider);
    let label = format!("{} provider", provider.name());
    if explicit {
        report.ok(&label, "dedicated route configured");
    } else {
        report.warn(&label, "using legacy root base_url/api_key fallback");
    }
    match Url::parse(base_url.trim()) {
        Ok(url)
            if matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none() => {}
        Ok(url) => report.error(
            &format!("{} base_url", provider.name()),
            format!("invalid or credential-bearing URL: {url}"),
        ),
        Err(err) => report.error(&format!("{} base_url", provider.name()), err.to_string()),
    }
    if api_key.trim().is_empty() {
        report.error(&format!("{} api_key", provider.name()), "missing");
    } else {
        report.ok(&format!("{} api_key", provider.name()), "configured");
    }
}

fn check_saiai_config(report: &mut DoctorReport, cfg: &SaiaiConfig) {
    if cfg.version == SAIAI_CONFIG_VERSION {
        report.ok("config version", SAIAI_CONFIG_VERSION.to_string());
    } else {
        report.warn(
            "config version",
            format!("unexpected version {}", cfg.version),
        );
    }

    match Url::parse(cfg.base_url.trim()) {
        Ok(url)
            if matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none() =>
        {
            report.ok("base_url", cfg.base_url.trim().trim_end_matches('/'));
        }
        Ok(url) => report.error(
            "base_url",
            format!("must be http(s), include a host, and not include credentials; got {url}"),
        ),
        Err(err) => report.error("base_url", err.to_string()),
    }

    if cfg.api_key.trim().is_empty() {
        report.error("api_key", "missing");
    } else {
        report.ok("api_key", "configured");
    }

    match cfg.listen.parse::<SocketAddr>() {
        Ok(addr) => {
            if addr.ip().is_loopback() {
                report.ok("listen", addr.to_string());
            } else {
                report.error("listen", format!("{addr} is not loopback-only"));
            }
            check_listen_owner(report, addr);
            match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                Ok(_) => report.ok("local proxy", format!("reachable at http://{addr}")),
                Err(err) => report.warn(
                    "local proxy",
                    format!("not reachable at http://{addr} ({err}); start it with `saiai start`"),
                ),
            }
        }
        Err(err) => report.error("listen", format!("invalid listen address: {err}")),
    }

    let ca_path = PathBuf::from(&cfg.ca_cert_path);
    check_ca_cert(report, "configured CA", &ca_path);
    if cfg.ca_key_path.trim().is_empty() {
        report.error("configured CA key", "missing; rerun SAIAI setup");
    } else {
        report.ok(
            "configured CA key",
            "private installation key path configured",
        );
    }
}

fn check_claude_config(
    report: &mut DoctorReport,
    cfg: Option<&SaiaiConfig>,
    paths: &ClaudeConfigPaths,
) {
    if paths.settings_path.exists() {
        report.ok("Claude settings", paths.settings_path.display().to_string());
    } else {
        report.error(
            "Claude settings",
            format!("{} does not exist", paths.settings_path.display()),
        );
        return;
    }

    let settings = match load_json_object(&paths.settings_path) {
        Ok(settings) => settings,
        Err(err) => {
            report.error("Claude settings", err.to_string());
            return;
        }
    };

    let Some(env) = settings.get("env").and_then(Value::as_object) else {
        report.error("Claude env", "settings.json has no object-valued env");
        return;
    };

    if env.get("ANTHROPIC_BASE_URL").is_some() {
        report.error(
            "Claude env",
            "ANTHROPIC_BASE_URL should be removed for local proxy mode",
        );
    } else {
        report.ok("Claude env", "ANTHROPIC_BASE_URL absent");
    }

    let overrides = claude_settings_override_locations(&settings);
    if overrides.is_empty() {
        report.ok(
            "Claude overrides",
            "no legacy routing or authentication overrides",
        );
    } else {
        report.warn(
            "Claude overrides",
            format!(
                "{} contains {}; remove these entries before launching Claude Code with SAIAI",
                paths.settings_path.display(),
                format_claude_settings_override_locations(&overrides)
            ),
        );
    }

    let expected_proxy = cfg
        .map(|cfg| format!("http://{}", cfg.listen))
        .unwrap_or_else(|| format!("http://{DEFAULT_LOCAL_PROXY_LISTEN}"));
    check_env_equals(report, env, "http_proxy", &expected_proxy);
    check_env_equals(report, env, "https_proxy", &expected_proxy);
    check_env_equals(report, env, "all_proxy", &expected_proxy);
    check_env_contains(report, env, "no_proxy", "127.0.0.1");
    check_proxy_setting_case_conflicts(report, env);

    match env_string(env, "NODE_EXTRA_CA_CERTS") {
        Some(value) => {
            let path = PathBuf::from(value);
            if let Some(cfg) = cfg
                && value != cfg.ca_cert_path
            {
                report.warn(
                    "NODE_EXTRA_CA_CERTS",
                    format!("{} differs from SAIAI config CA path", value),
                );
            }
            check_ca_cert(report, "NODE_EXTRA_CA_CERTS", &path);
        }
        None => report.error("NODE_EXTRA_CA_CERTS", "missing or not a string"),
    }

    match env_string(env, "CLAUDE_CODE_OAUTH_TOKEN") {
        Some(value) if !value.trim().is_empty() => {
            if let Some(cfg) = cfg {
                if value == provider_route(cfg, ProviderKind::Claude).1 {
                    report.ok(
                        "CLAUDE_CODE_OAUTH_TOKEN",
                        "configured and matches SAIAI config",
                    );
                } else {
                    report.error(
                        "CLAUDE_CODE_OAUTH_TOKEN",
                        "does not match SAIAI config api_key",
                    );
                }
            } else {
                report.ok("CLAUDE_CODE_OAUTH_TOKEN", "configured");
            }
        }
        _ => report.error("CLAUDE_CODE_OAUTH_TOKEN", "missing or empty"),
    }

    check_claude_state(report, &paths.state_path);
    if paths.credentials_path.exists() {
        report.warn(
            "Claude credentials",
            format!(
                "{} still exists; rerun `saiai init ...` to remove stale OAuth state",
                paths.credentials_path.display()
            ),
        );
    } else {
        report.ok("Claude credentials", "stale .credentials.json absent");
    }
}

fn check_claude_state(report: &mut DoctorReport, path: &Path) {
    if !path.exists() {
        report.error("Claude state", format!("{} does not exist", path.display()));
        return;
    }
    let state = match load_json_object(path) {
        Ok(state) => state,
        Err(err) => {
            report.error("Claude state", err.to_string());
            return;
        }
    };
    if state
        .get("hasCompletedOnboarding")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        report.ok("Claude state", path.display().to_string());
    } else {
        report.warn("Claude state", "hasCompletedOnboarding is not true");
    }
}

fn check_codex_config(report: &mut DoctorReport, cfg: Option<&SaiaiConfig>, required: bool) {
    let codex_dir = match codex_config_dir() {
        Ok(path) => path,
        Err(err) => {
            if required {
                report.error("Codex home", err.to_string());
            } else {
                report.warn("Codex home", err.to_string());
            }
            return;
        }
    };
    let config_path = codex_dir.join("config.toml");
    let auth_path = codex_dir.join("auth.json");
    if !config_path.is_file() {
        let message = format!("{} does not exist", config_path.display());
        if required {
            report.error("Codex config", message);
        } else {
            report.warn("Codex config", message);
        }
    } else {
        match fs::read_to_string(&config_path) {
            Ok(raw) => match raw.parse::<DocumentMut>() {
                Ok(document) => {
                    if document
                        .get("model_provider")
                        .and_then(Item::as_str)
                        .is_some_and(|value| value == "openai")
                    {
                        report.ok("Codex provider", "built-in OpenAI provider selected");
                    } else {
                        report.warn(
                            "Codex provider",
                            "model_provider is not explicitly set to openai",
                        );
                    }
                    if document.get("base_url").is_some()
                        || document.get("openai_base_url").is_some()
                        || document.get("chatgpt_base_url").is_some()
                    {
                        report.warn(
                            "Codex base_url",
                            "direct endpoint override remains; run `saiai init-codex` to migrate it",
                        );
                    } else {
                        report.ok("Codex base_url", "no direct root endpoint override");
                    }
                    if document.get("model_providers").is_some() {
                        report.warn(
                            "Codex providers",
                            "custom provider configuration remains; run `saiai init-codex` to remove it",
                        );
                    } else {
                        report.ok("Codex providers", "no custom provider compatibility route");
                    }
                }
                Err(err) => report.error("Codex config", format!("invalid TOML: {err}")),
            },
            Err(err) => report.error("Codex config", err.to_string()),
        }
    }
    if !auth_path.is_file() {
        let message = format!("{} does not exist", auth_path.display());
        if required {
            report.error("Codex auth", message);
        } else {
            report.warn("Codex auth", message);
        }
    } else {
        match validate_codex_oauth_auth(&auth_path) {
            Ok(()) => report.ok("Codex auth", "ChatGPT OAuth token mode configured"),
            Err(err) => report.error("Codex auth", format!("{err:#}")),
        }
    }
    let env_path = codex_dir.join(".env");
    if env_path.is_file() {
        match fs::read_to_string(&env_path) {
            Ok(raw) => {
                if raw.lines().any(|line| line.contains("HTTP_PROXY=")) {
                    report.ok("Codex .env", env_path.display().to_string());
                } else {
                    report.warn("Codex .env", "exists but has no managed HTTP_PROXY entry");
                }
            }
            Err(err) => report.warn("Codex .env", format!("could not read: {err}")),
        }
    } else if required {
        report.error(
            "Codex .env",
            "missing; run `saiai init-codex` to configure the local proxy route",
        );
    } else {
        report.warn(
            "Codex .env",
            "missing; run `saiai init-codex` before using an external Codex app-server",
        );
    }
    if cfg.is_none() {
        report.warn("Codex route", "SAIAI config is unavailable");
    }
}

fn check_ca_cert(report: &mut DoctorReport, label: &str, path: &Path) {
    match fs::read_to_string(path) {
        Ok(pem)
            if CertificateParams::from_ca_cert_pem(&pem)
                .is_ok_and(|params| matches!(params.is_ca, IsCa::Ca(_))) =>
        {
            report.ok(label, path.display().to_string())
        }
        Ok(_) => report.error(label, format!("{} is not a valid CA", path.display())),
        Err(err) => report.error(label, format!("{}: {err}", path.display())),
    }
}

fn check_env_equals(
    report: &mut DoctorReport,
    env: &Map<String, Value>,
    key: &str,
    expected: &str,
) {
    match env_string(env, key) {
        Some(value) if value == expected => report.ok(key, expected),
        Some(value) => report.error(key, format!("expected {expected}, got {value}")),
        None => report.error(key, "missing or not a string"),
    }
}

fn check_env_contains(
    report: &mut DoctorReport,
    env: &Map<String, Value>,
    key: &str,
    expected_token: &str,
) {
    match env_string(env, key) {
        Some(value) if value.split(',').any(|item| item.trim() == expected_token) => {
            report.ok(key, format!("contains {expected_token}"))
        }
        Some(value) => report.warn(key, format!("does not contain {expected_token}: {value}")),
        None => report.error(key, "missing or not a string"),
    }
}

fn env_string<'a>(env: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    env.get(key).and_then(Value::as_str)
}

fn check_proxy_setting_case_conflicts(report: &mut DoctorReport, env: &Map<String, Value>) {
    let uppercase = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];
    let mut conflicts = Vec::new();
    for key in uppercase {
        if env.contains_key(key) {
            conflicts.push(key);
        }
    }
    if conflicts.is_empty() {
        report.ok("Claude proxy case", "canonical lowercase proxy keys only");
    } else {
        report.warn(
            "Claude proxy case",
            format!(
                "{} also present; remove uppercase proxy keys so lowercase settings take precedence",
                conflicts.join(", ")
            ),
        );
    }
}

fn ensure_listen_available(listen: &str) -> Result<()> {
    let addr = listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {listen:?}"))?;
    if !addr.ip().is_loopback() {
        bail!("local proxy listen address must be loopback-only, got {addr}");
    }

    match StdTcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::AddrInUse => {
            let owners = listen_port_owners(addr);
            // Linux can report EADDRINUSE for a recently closed connection
            // even though no process owns the listening socket. The Tokio
            // listener uses the normal Unix reuse semantics, so let the real
            // bind make the final decision in that case.
            #[cfg(target_os = "linux")]
            if owners.is_empty() {
                return Ok(());
            }
            let owner_summary = if owners.is_empty() {
                format!("an unknown process on port {}", addr.port())
            } else {
                format_listen_owners(&owners)
            };
            bail!(
                "local proxy listen address {addr} is already in use by {}. \
Stop the existing process, or if it is a SAIAI service run `saiai stop` first.",
                owner_summary
            )
        }
        Err(err) => bail!("local proxy listen address {addr} is not available: {err}"),
    }
}

fn check_listen_owner(report: &mut DoctorReport, addr: SocketAddr) {
    let owners = listen_port_owners(addr);
    if owners.is_empty() {
        return;
    }
    let summary = format_listen_owners(&owners);
    if owners.iter().any(|owner| owner.is_saiai()) {
        report.ok("listen owner", summary);
    } else {
        report.warn(
            "listen owner",
            format!("non-SAIAI process on {addr}: {summary}"),
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ListenPortOwner {
    pid: u32,
    name: String,
}

impl ListenPortOwner {
    fn is_saiai(&self) -> bool {
        self.name.eq_ignore_ascii_case("saiai") || self.name.to_ascii_lowercase().contains("saiai")
    }
}

fn format_listen_owners(owners: &[ListenPortOwner]) -> String {
    owners
        .iter()
        .map(|owner| format!("pid {} ({})", owner.pid, owner.name))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(target_os = "linux")]
fn listen_port_owners(addr: SocketAddr) -> Vec<ListenPortOwner> {
    let inodes = listen_socket_inodes(addr.port());
    if inodes.is_empty() {
        return Vec::new();
    }

    let mut owners = HashMap::<u32, String>::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        let mut matched = false;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            else {
                continue;
            };
            if inodes.contains(inode) {
                matched = true;
                break;
            }
        }
        if matched {
            owners
                .entry(pid)
                .or_insert_with(|| process_name(pid).unwrap_or_else(|| "unknown".to_string()));
        }
    }

    let mut owners = owners
        .into_iter()
        .map(|(pid, name)| ListenPortOwner { pid, name })
        .collect::<Vec<_>>();
    owners.sort_by_key(|owner| owner.pid);
    owners
}

#[cfg(not(target_os = "linux"))]
fn listen_port_owners(_addr: SocketAddr) -> Vec<ListenPortOwner> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn listen_socket_inodes(port: u16) -> HashSet<String> {
    let mut inodes = HashSet::new();
    collect_listen_socket_inodes("/proc/net/tcp", port, &mut inodes);
    collect_listen_socket_inodes("/proc/net/tcp6", port, &mut inodes);
    inodes
}

#[cfg(target_os = "linux")]
fn collect_listen_socket_inodes(path: &str, port: u16, inodes: &mut HashSet<String>) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        if let Some(inode) = parse_proc_net_tcp_listen_inode(line, port) {
            inodes.insert(inode.to_string());
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp_listen_inode(line: &str, port: u16) -> Option<&str> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 9 || fields.get(3).copied() != Some("0A") {
        return None;
    }
    let local = fields.get(1)?;
    let (_, port_hex) = local.rsplit_once(':')?;
    let parsed_port = u16::from_str_radix(port_hex, 16).ok()?;
    if parsed_port != port {
        return None;
    }
    fields.get(9).copied()
}

#[cfg(target_os = "linux")]
fn process_name(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if comm.is_some() {
        return comm;
    }

    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .filter(|value| !value.is_empty())
}

async fn check_gateway_health(base_url: &str) -> Result<String> {
    let health_url = format!("{}/health", base_url.trim().trim_end_matches('/'));
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build health-check HTTP client")?
        .get(&health_url)
        .send()
        .await
        .with_context(|| format!("failed to GET {health_url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("GET {health_url} returned {}", status);
    }
    Ok(format!("GET {health_url} returned {}", status))
}

async fn check_local_proxy_mitm(cfg: &SaiaiConfig) -> Result<String> {
    let addr = cfg
        .listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {}", cfg.listen))?;
    let mut stream = timeout(Duration::from_secs(2), TokioTcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to local proxy at http://{addr}"))?
        .with_context(|| format!("failed to connect to local proxy at http://{addr}"))?;

    let connect_request = format!(
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Connection: keep-alive\r\n\r\n",
        host = ANTHROPIC_HOST
    );
    stream
        .write_all(connect_request.as_bytes())
        .await
        .context("failed to send CONNECT probe to local proxy")?;
    let connect_head = read_http_response_head(&mut stream, "CONNECT response").await?;
    let connect_status = http_status_code(&connect_head)?;
    if connect_status != 200 {
        bail!("CONNECT {ANTHROPIC_HOST}:443 returned HTTP {connect_status}");
    }

    let roots = load_ca_root_store(Path::new(&cfg.ca_cert_path))?;
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(ANTHROPIC_HOST.to_string())
        .context("failed to build Anthropic TLS server name")?;
    let mut tls = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await
    .context("timed out during local proxy MITM TLS handshake")?
    .context("local proxy MITM TLS handshake failed")?;

    tls.write_all(
        b"GET /api/claude_code/settings HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: keep-alive\r\n\r\n",
    )
    .await
    .context("failed to send sidecar settings probe")?;
    let settings_head = read_http_response_head(&mut tls, "sidecar settings response").await?;
    let settings_status = http_status_code(&settings_head)?;
    if settings_status != 204 {
        bail!("sidecar settings probe returned HTTP {settings_status}, expected 204");
    }

    tls.write_all(
        b"GET /api/claude_code/policy_limits HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .context(
        "local proxy closed before the reused sidecar probe; restart the proxy with `saiai restart`",
    )?;
    let policy_head = read_http_response_head(&mut tls, "sidecar policy_limits response")
        .await
        .context(
            "local proxy did not keep the sidecar TLS connection alive; restart the proxy with `saiai restart`",
        )?;
    let policy_status = http_status_code(&policy_head)?;
    if policy_status != 200 {
        bail!("sidecar policy_limits probe returned HTTP {policy_status}, expected 200");
    }

    Ok(format!(
        "CONNECT + TLS + sidecar keep-alive at http://{addr} returned 204 then 200"
    ))
}

fn load_ca_root_store(path: &Path) -> Result<rustls::RootCertStore> {
    let ca_bytes = fs::read(path)
        .with_context(|| format!("failed to read configured CA {}", path.display()))?;
    let mut cursor = std::io::Cursor::new(ca_bytes);
    let certs = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse configured SAIAI CA PEM")?;
    if certs.is_empty() {
        bail!(
            "configured SAIAI CA {} did not contain a PEM certificate",
            path.display()
        );
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .context("failed to trust configured SAIAI CA")?;
    }
    Ok(roots)
}

async fn read_http_response_head<R>(reader: &mut R, label: &str) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let read = timeout(Duration::from_secs(5), reader.read(&mut tmp))
            .await
            .with_context(|| format!("timed out reading {label}"))?
            .with_context(|| format!("failed to read {label}"))?;
        if read == 0 {
            bail!("connection closed while reading {label}");
        }
        buf.extend_from_slice(&tmp[..read]);
        if let Some(end) = find_header_end(&buf) {
            return Ok(String::from_utf8_lossy(&buf[..end]).to_string());
        }
        if buf.len() > 64 * 1024 {
            bail!("{label} headers are too large");
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn http_status_code(head: &str) -> Result<u16> {
    let status_line = head
        .lines()
        .next()
        .context("HTTP response is missing a status line")?;
    let parts = status_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 || !parts[0].starts_with("HTTP/") {
        bail!("invalid HTTP response status line: {status_line:?}");
    }
    parts[1]
        .parse::<u16>()
        .with_context(|| format!("invalid HTTP status code in {status_line:?}"))
}

fn is_local_proxy_connect_error(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    message.contains("failed to connect to local proxy")
        || message.contains("timed out connecting to local proxy")
}

fn check_current_binary(report: &mut DoctorReport) {
    match env::current_exe() {
        Ok(path) => report.ok("binary", path.display().to_string()),
        Err(err) => report.warn(
            "binary",
            format!("failed to resolve current executable: {err}"),
        ),
    }
}

#[cfg(target_os = "linux")]
fn check_service_config(report: &mut DoctorReport) {
    match linux_background_state() {
        Ok(Some(state)) if linux_background_state_is_running(&state) => {
            report.ok(
                "service",
                format!("managed background process active (pid {})", state.pid),
            );
            if ensure_systemd_user_available().is_ok() && service_is_active().unwrap_or(false) {
                report.warn(
                    "service manager",
                    "systemd and managed background instances are both active; run `saiai restart`",
                );
            }
            return;
        }
        Ok(Some(state)) => report.warn(
            "service state",
            format!(
                "stale managed background state for pid {}; run `saiai start`",
                state.pid
            ),
        ),
        Ok(None) => {}
        Err(err) => report.warn("service state", err.to_string()),
    }

    if let Err(err) = ensure_systemd_user_available() {
        report.warn(
            "service",
            format!(
                "not running; systemd --user unavailable ({err}); `saiai start` will use the managed background fallback"
            ),
        );
        return;
    }

    let load_state = match systemctl_value("LoadState") {
        Ok(value) => value,
        Err(err) => {
            report.warn(
                "service",
                format!("failed to read service load state: {err}"),
            );
            return;
        }
    };
    if load_state == "not-found" || load_state.is_empty() {
        report.warn("service", "not installed; run `saiai start` to install it");
        return;
    }
    report.ok("service load", load_state);

    let current_exe = match env::current_exe() {
        Ok(path) => fs::canonicalize(&path).unwrap_or(path),
        Err(err) => {
            report.warn(
                "service ExecStart",
                format!("failed to resolve current executable: {err}"),
            );
            return;
        }
    };
    let expected = current_exe.display().to_string();
    match systemctl_value("ExecStart") {
        Ok(value) if value.contains(&expected) => report.ok("service ExecStart", expected),
        Ok(value) => report.warn(
            "service ExecStart",
            format!(
                "does not point at current binary {}; got {}",
                expected, value
            ),
        ),
        Err(err) => report.warn("service ExecStart", err.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn check_service_config(_report: &mut DoctorReport) {}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn download_update_manifest(url: &str) -> Result<Option<UpdateManifest>> {
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build update manifest HTTP client")?
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("GET {url} returned {status}");
    }
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read {url}"))?;
    let manifest = serde_json::from_slice::<UpdateManifest>(&bytes)
        .with_context(|| format!("failed to parse {url}"))?;
    Ok(Some(manifest))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn download_update_asset(url: &str) -> Result<Vec<u8>> {
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build update HTTP client")?
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("GET {url} returned {status}");
    }
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read {url}"))?;
    if bytes.len() < 1024 * 1024 {
        bail!(
            "downloaded asset is unexpectedly small: {} bytes",
            bytes.len()
        );
    }
    if bytes.len() > 64 * 1024 * 1024 {
        bail!(
            "downloaded asset is unexpectedly large: {} bytes",
            bytes.len()
        );
    }
    Ok(bytes.to_vec())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn compare_versions(left: &str, right: &str) -> Result<Ordering> {
    let left = parse_version_parts(left)?;
    let right = parse_version_parts(right)?;
    let max_len = left.len().max(right.len());
    for idx in 0..max_len {
        let l = left.get(idx).copied().unwrap_or(0);
        let r = right.get(idx).copied().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            other => return Ok(other),
        }
    }
    Ok(Ordering::Equal)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_version_parts(raw: &str) -> Result<Vec<u64>> {
    let version = raw
        .trim()
        .strip_prefix("saiai ")
        .unwrap_or(raw.trim())
        .trim()
        .trim_start_matches('v');
    let parts = version
        .split('.')
        .map(|part| {
            if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
                bail!("invalid version component {part:?} in {raw:?}");
            }
            part.parse::<u64>()
                .with_context(|| format!("invalid version component {part:?} in {raw:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if parts.is_empty() {
        bail!("empty version {raw:?}");
    }
    Ok(parts)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn current_platform_asset_name() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("saiai-linux-x86_64"),
        ("linux", "aarch64") => Ok("saiai-linux-aarch64"),
        ("macos", "x86_64") => Ok("saiai-macos-x86_64"),
        ("macos", "aarch64") => Ok("saiai-macos-aarch64"),
        ("windows", "x86_64") => Ok("saiai-windows-x86_64.exe"),
        ("windows", "aarch64") => Ok("saiai-windows-aarch64.exe"),
        (os, arch) => bail!("unsupported {os} architecture for update: {arch}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_update_asset(bytes: &[u8], asset: &str) -> Result<()> {
    if asset.starts_with("saiai-linux-") {
        return validate_elf_asset(bytes, asset);
    }
    if asset.starts_with("saiai-macos-") {
        return validate_macho_asset(bytes, asset);
    }
    if asset.starts_with("saiai-windows-") {
        return validate_pe_asset(bytes, asset);
    }
    bail!("unsupported update asset {asset}");
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_elf_asset(bytes: &[u8], asset: &str) -> Result<()> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7FELF" {
        bail!("downloaded {asset} is not an ELF executable");
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    match (asset, machine) {
        ("saiai-linux-x86_64", 62) | ("saiai-linux-aarch64", 183) => Ok(()),
        _ => bail!("downloaded {asset} has unexpected ELF machine id {machine}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_macho_asset(bytes: &[u8], asset: &str) -> Result<()> {
    if bytes.len() < 8 || bytes[..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        bail!("downloaded {asset} is not a 64-bit Mach-O executable");
    }
    let cpu_type = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    match (asset, cpu_type) {
        ("saiai-macos-x86_64", 0x0100_0007) | ("saiai-macos-aarch64", 0x0100_000c) => Ok(()),
        _ => bail!("downloaded {asset} has unexpected Mach-O CPU type {cpu_type:#x}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_pe_asset(bytes: &[u8], asset: &str) -> Result<()> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        bail!("downloaded {asset} is not a Windows PE executable");
    }
    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    if pe_offset.checked_add(6).is_none_or(|end| end > bytes.len()) {
        bail!("downloaded {asset} has an invalid PE header offset");
    }
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        bail!("downloaded {asset} is missing a PE signature");
    }
    let machine = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);
    match (asset, machine) {
        ("saiai-windows-x86_64.exe", 0x8664) | ("saiai-windows-aarch64.exe", 0xaa64) => Ok(()),
        _ => bail!("downloaded {asset} has unexpected PE machine id {machine:#x}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn write_update_candidate(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn command_stdout(path: &Path, args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new(path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to execute {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "{} exited with {}: {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn update_candidate_name(unique: &str) -> String {
    if cfg!(windows) {
        format!(".saiai-update-{unique}.exe")
    } else {
        format!(".saiai-update-{unique}")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn update_backup_name() -> String {
    if cfg!(windows) {
        format!("saiai.bak-{}.exe", Utc::now().format("%Y%m%d-%H%M%S"))
    } else {
        format!("saiai.bak-{}", Utc::now().format("%Y%m%d-%H%M%S"))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finalize_update(
    current_exe: &Path,
    candidate_path: &Path,
    backup_path: &Path,
    _restart_service: bool,
) -> Result<()> {
    fs::copy(current_exe, backup_path).with_context(|| {
        format!(
            "failed to back up {} to {}",
            current_exe.display(),
            backup_path.display()
        )
    })?;
    fs::rename(candidate_path, current_exe).with_context(|| {
        format!(
            "failed to replace {} with {}",
            current_exe.display(),
            candidate_path.display()
        )
    })?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn finalize_update(
    current_exe: &Path,
    candidate_path: &Path,
    backup_path: &Path,
    restart_service: bool,
) -> Result<()> {
    fs::copy(current_exe, backup_path).with_context(|| {
        format!(
            "failed to back up {} to {}",
            current_exe.display(),
            backup_path.display()
        )
    })?;
    let script_path = candidate_path.with_extension("ps1");
    let script = render_windows_update_script(
        std::process::id(),
        current_exe,
        candidate_path,
        backup_path,
        &script_path,
        restart_service,
    )?;
    fs::write(&script_path, script)
        .with_context(|| format!("failed to write {}", script_path.display()))?;
    ProcessCommand::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start Windows update helper")?;
    println!(
        "Windows update helper started; replacement will finish automatically after this process exits."
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn render_windows_update_script(
    pid: u32,
    current_exe: &Path,
    candidate_path: &Path,
    backup_path: &Path,
    script_path: &Path,
    restart_service: bool,
) -> Result<String> {
    let restart = if restart_service {
        format!(
            "Start-Process -FilePath {} -ArgumentList 'restart' -WindowStyle Hidden\r\n",
            powershell_quote_path(current_exe)?
        )
    } else {
        String::new()
    };
    Ok(format!(
        "$ErrorActionPreference = 'Stop'\r\n\
try {{ Wait-Process -Id {pid} -Timeout 30 -ErrorAction SilentlyContinue }} catch {{}}\r\n\
Start-Sleep -Milliseconds 300\r\n\
Copy-Item -LiteralPath {} -Destination {} -Force\r\n\
Move-Item -LiteralPath {} -Destination {} -Force\r\n\
Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue\r\n\
{}",
        powershell_quote_path(current_exe)?,
        powershell_quote_path(backup_path)?,
        powershell_quote_path(candidate_path)?,
        powershell_quote_path(current_exe)?,
        powershell_quote_path(script_path)?,
        restart,
    ))
}

#[cfg(target_os = "windows")]
fn powershell_quote_path(path: &Path) -> Result<String> {
    let value = path.as_os_str().to_string_lossy().to_string();
    if value.contains('\0') || value.contains('\n') || value.trim().is_empty() {
        bail!("unsupported path for PowerShell script: {}", path.display());
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn update_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )
}

#[cfg(target_os = "linux")]
fn write_user_service() -> Result<PathBuf> {
    ensure_systemd_user_available()?;
    let service_dir = user_systemd_dir()?;
    fs::create_dir_all(&service_dir)
        .with_context(|| format!("failed to create {}", service_dir.display()))?;

    let exe = env::current_exe().context("failed to resolve current saiai executable")?;
    let saiai_home = absolute_existing_or_raw(saiai_config_dir()?);
    let working_dir = home_dir().context("failed to resolve home directory")?;
    let service_path = service_dir.join(SAIAI_SERVICE_NAME);
    let content = render_user_service(&exe, &saiai_home, &working_dir)?;
    write_bytes_atomic(&service_path, content.as_bytes(), 0o644)
        .with_context(|| format!("failed to write {}", service_path.display()))?;
    Ok(service_path)
}

#[cfg(target_os = "linux")]
fn render_user_service(exe: &Path, saiai_home: &Path, working_dir: &Path) -> Result<String> {
    let exe = path_to_string(exe)?;
    let saiai_home = path_to_string(saiai_home)?;
    let working_dir = path_to_string(working_dir)?;
    Ok(format!(
        "[Unit]\n\
Description=SAIAI local Claude Code proxy\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
Environment={}\n\
WorkingDirectory={}\n\
ExecStart={}\n\
Restart=on-failure\n\
RestartSec=2s\n\
StandardOutput=journal\n\
StandardError=journal\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        systemd_quote(&format!("SAIAI_HOME={saiai_home}"))?,
        systemd_path_setting(&working_dir)?,
        systemd_quote(&exe)?
    ))
}

#[cfg(target_os = "linux")]
fn user_systemd_dir() -> Result<PathBuf> {
    let config_dir = match env_dir_override("XDG_CONFIG_HOME") {
        Some(dir) => dir,
        None => home_dir()
            .context("failed to resolve home directory")?
            .join(".config"),
    };
    Ok(config_dir.join("systemd").join("user"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn absolute_existing_or_raw(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn path_to_string(path: &Path) -> Result<String> {
    let value = path.as_os_str().to_string_lossy().to_string();
    if value.contains('\0') || value.contains('\n') || value.trim().is_empty() {
        bail!("unsupported path: {}", path.display());
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> Result<String> {
    if value.contains('\0') || value.contains('\n') {
        bail!("unsupported value for systemd unit");
    }
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

#[cfg(target_os = "linux")]
fn systemd_path_setting(value: &str) -> Result<String> {
    if value.contains('\0') || value.contains('\n') {
        bail!("unsupported path for systemd unit");
    }
    if !value.starts_with('/') {
        bail!("systemd path is not absolute: {value}");
    }

    let mut escaped = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match *byte {
            b'\\' | b'"' | b'\'' | b' ' | b'\t' | b'\r' => {
                use std::fmt::Write as _;
                let _ = write!(&mut escaped, "\\x{byte:02x}");
            }
            0x21..=0x7e => escaped.push(*byte as char),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(&mut escaped, "\\x{byte:02x}");
            }
        }
    }
    Ok(escaped)
}

#[cfg(target_os = "macos")]
struct LaunchdPlist {
    path: PathBuf,
    changed: bool,
}

#[cfg(target_os = "macos")]
fn write_launchd_plist() -> Result<LaunchdPlist> {
    let launch_agents_dir = launchd_agents_dir()?;
    fs::create_dir_all(&launch_agents_dir)
        .with_context(|| format!("failed to create {}", launch_agents_dir.display()))?;
    let log_path = launchd_log_path()?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let exe = env::current_exe().context("failed to resolve current saiai executable")?;
    let exe = absolute_existing_or_raw(exe);
    let saiai_home = absolute_existing_or_raw(saiai_config_dir()?);
    let working_dir = home_dir().context("failed to resolve home directory")?;
    let plist_path = launchd_plist_path()?;
    let content = render_launchd_plist(&exe, &saiai_home, &working_dir, &log_path)?;
    let changed = match fs::read_to_string(&plist_path) {
        Ok(existing) => existing != content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", plist_path.display()));
        }
    };
    if changed {
        write_bytes_atomic(&plist_path, content.as_bytes(), 0o644)
            .with_context(|| format!("failed to write {}", plist_path.display()))?;
    }
    Ok(LaunchdPlist {
        path: plist_path,
        changed,
    })
}

#[cfg(target_os = "macos")]
fn render_launchd_plist(
    exe: &Path,
    saiai_home: &Path,
    working_dir: &Path,
    log_path: &Path,
) -> Result<String> {
    let exe = xml_escape(&path_to_string(exe)?);
    let saiai_home = xml_escape(&path_to_string(saiai_home)?);
    let working_dir = xml_escape(&path_to_string(working_dir)?);
    let log_path = xml_escape(&path_to_string(log_path)?);
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n\
  <string>{}</string>\n\
  <key>ProgramArguments</key>\n\
  <array>\n\
    <string>{exe}</string>\n\
  </array>\n\
  <key>EnvironmentVariables</key>\n\
  <dict>\n\
    <key>SAIAI_HOME</key>\n\
    <string>{saiai_home}</string>\n\
  </dict>\n\
  <key>WorkingDirectory</key>\n\
  <string>{working_dir}</string>\n\
  <key>RunAtLoad</key>\n\
  <true/>\n\
  <key>KeepAlive</key>\n\
  <true/>\n\
  <key>StandardOutPath</key>\n\
  <string>{log_path}</string>\n\
  <key>StandardErrorPath</key>\n\
  <string>{log_path}</string>\n\
</dict>\n\
</plist>\n",
        SAIAI_LAUNCHD_LABEL
    ))
}

#[cfg(target_os = "macos")]
fn launchd_agents_dir() -> Result<PathBuf> {
    Ok(home_dir()
        .context("failed to resolve home directory")?
        .join("Library")
        .join("LaunchAgents"))
}

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> Result<PathBuf> {
    Ok(launchd_agents_dir()?.join(format!("{SAIAI_LAUNCHD_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn launchd_log_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?.join(SAIAI_SERVICE_LOG_FILENAME))
}

#[cfg(target_os = "macos")]
fn launchctl_gui_domain() -> Result<String> {
    let uid =
        command_output(MACOS_ID_COMMAND, &["-u"]).context("failed to resolve current macOS uid")?;
    Ok(format!("gui/{}", uid.trim()))
}

#[cfg(target_os = "macos")]
fn launchctl_service_target(domain: &str) -> String {
    format!("{domain}/{SAIAI_LAUNCHD_LABEL}")
}

#[cfg(target_os = "macos")]
fn run_launchctl(args: &[&str]) -> Result<()> {
    let output = ProcessCommand::new(MACOS_LAUNCHCTL_COMMAND)
        .args(args)
        .output()
        .context("failed to run launchctl")?;
    if !output.status.success() {
        bail!(
            "launchctl {:?} exited with {}: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_launchd_running() -> Result<bool> {
    let domain = launchctl_gui_domain()?;
    let target = launchctl_service_target(&domain);
    Ok(macos_launchd_loaded(&target))
}

#[cfg(target_os = "macos")]
fn macos_launchd_loaded(target: &str) -> bool {
    command_output(MACOS_LAUNCHCTL_COMMAND, &["print", target]).is_ok()
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "linux")]
fn run_linux_background_proxy_worker() -> Result<()> {
    // This command is reached only through a fresh child process created by
    // `start_linux_background_proxy`, so it is not a process-group leader and
    // can safely detach from the invoking terminal session.
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error())
            .context("failed to detach SAIAI background proxy session");
    }
    run_local_proxy(false)
}

#[cfg(target_os = "linux")]
fn start_linux_background_proxy(cfg: &SaiaiConfig) -> Result<u32> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    stop_linux_background_proxy()?;
    ensure_listen_available(&cfg.listen)?;

    let saiai_home = saiai_config_dir()?;
    fs::create_dir_all(&saiai_home)
        .with_context(|| format!("failed to create {}", saiai_home.display()))?;
    let log_path = linux_service_log_path()?;
    match fs::symlink_metadata(&log_path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("refusing non-regular SAIAI log path {}", log_path.display())
        }
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", log_path.display()));
        }
    }
    let mut log_options = OpenOptions::new();
    log_options
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let stdout = log_options
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    stdout
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to protect {}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    let exe = env::current_exe().context("failed to resolve current saiai executable")?;
    let mut child = ProcessCommand::new(exe)
        .arg(SAIAI_LINUX_BACKGROUND_COMMAND)
        .env("SAIAI_HOME", &saiai_home)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("failed to start SAIAI background proxy")?;
    let pid = child.id();
    let startup = (|| -> Result<u32> {
        let identity_deadline = std::time::Instant::now() + Duration::from_secs(1);
        let identity = loop {
            if let Some(status) = child
                .try_wait()
                .context("failed to inspect SAIAI background proxy")?
            {
                bail!(
                    "SAIAI background proxy exited during startup with {status}; inspect {}",
                    log_path.display()
                );
            }
            if let Some(identity) = linux_process_identity(pid)?
                && linux_process_has_background_marker(pid)?
            {
                break identity;
            }
            if std::time::Instant::now() >= identity_deadline {
                bail!(
                    "timed out recording SAIAI background process identity; inspect {}",
                    log_path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let state = LinuxBackgroundState {
            schema_version: SAIAI_LINUX_BACKGROUND_STATE_VERSION,
            pid,
            start_time_ticks: identity.start_time_ticks,
        };
        write_linux_background_state(&state)?;

        let addr = cfg
            .listen
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid local proxy listen address {:?}", cfg.listen))?;
        let ready_deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child
                .try_wait()
                .context("failed to inspect SAIAI background proxy")?
            {
                bail!(
                    "SAIAI background proxy exited during startup with {status}; inspect {}",
                    log_path.display()
                );
            }
            let owns_listener = listen_port_owners(addr)
                .iter()
                .any(|owner| owner.pid == pid);
            if owns_listener
                && TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok()
            {
                return Ok(pid);
            }
            if std::time::Instant::now() >= ready_deadline {
                bail!(
                    "timed out waiting for SAIAI background proxy at {addr}; inspect {}",
                    log_path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();

    if startup.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        if let Ok(path) = linux_background_state_path() {
            let _ = fs::remove_file(path);
        }
    }
    startup
}

#[cfg(target_os = "linux")]
fn stop_linux_background_proxy() -> Result<bool> {
    let Some(state) = linux_background_state()? else {
        return Ok(false);
    };
    if !linux_background_state_matches(&state)? {
        fs::remove_file(linux_background_state_path()?)
            .with_context(|| format!("failed to remove stale SAIAI state for pid {}", state.pid))?;
        return Ok(false);
    }

    signal_linux_background_process(&state, libc::SIGTERM)?;
    let term_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < term_deadline {
        if !linux_background_state_matches(&state)? {
            let _ = fs::remove_file(linux_background_state_path()?);
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Revalidate the original process identity immediately before escalation;
    // never signal a PID that has been reused or exec'd into another command.
    if linux_background_state_matches(&state)? {
        signal_linux_background_process(&state, libc::SIGKILL)?;
    }
    let kill_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < kill_deadline {
        if !linux_background_state_matches(&state)? {
            let _ = fs::remove_file(linux_background_state_path()?);
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!(
        "failed to stop managed SAIAI background process {}",
        state.pid
    )
}

#[cfg(target_os = "linux")]
fn signal_linux_background_process(state: &LinuxBackgroundState, signal: i32) -> Result<()> {
    if !linux_background_state_matches(state)? {
        return Ok(());
    }
    let pid = i32::try_from(state.pid).context("SAIAI background pid is out of range")?;
    if unsafe { libc::kill(pid, signal) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).with_context(|| format!("failed to signal SAIAI process {pid}"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_background_state() -> Result<Option<LinuxBackgroundState>> {
    let path = linux_background_state_path()?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if !metadata.file_type().is_file() {
        bail!("refusing non-regular SAIAI state path {}", path.display());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let state: LinuxBackgroundState = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if state.schema_version != SAIAI_LINUX_BACKGROUND_STATE_VERSION
        || state.pid <= 1
        || state.start_time_ticks == 0
    {
        bail!("invalid SAIAI background state in {}", path.display());
    }
    Ok(Some(state))
}

#[cfg(target_os = "linux")]
fn write_linux_background_state(state: &LinuxBackgroundState) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(state).context("failed to serialize SAIAI state")?;
    data.push(b'\n');
    write_bytes_atomic(&linux_background_state_path()?, &data, 0o600)
}

#[cfg(target_os = "linux")]
fn linux_background_state_matches(state: &LinuxBackgroundState) -> Result<bool> {
    let Some(identity) = linux_process_identity(state.pid)? else {
        return Ok(false);
    };
    if matches!(identity.state, 'Z' | 'X' | 'x')
        || identity.start_time_ticks != state.start_time_ticks
    {
        return Ok(false);
    }
    linux_process_has_background_marker(state.pid)
}

#[cfg(target_os = "linux")]
fn linux_background_state_is_running(state: &LinuxBackgroundState) -> bool {
    linux_background_state_matches(state).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn linux_process_identity(pid: u32) -> Result<Option<LinuxProcessIdentity>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    parse_linux_proc_stat(&raw)
        .map(Some)
        .with_context(|| format!("failed to parse {}", path.display()))
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_stat(raw: &str) -> Result<LinuxProcessIdentity> {
    let close = raw
        .rfind(')')
        .context("process stat is missing command terminator")?;
    let fields = raw[close + 1..].split_whitespace().collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|value| value.chars().next())
        .context("process stat is missing state")?;
    let start_time_ticks = fields
        .get(19)
        .context("process stat is missing start time")?
        .parse::<u64>()
        .context("process stat has invalid start time")?;
    Ok(LinuxProcessIdentity {
        state,
        start_time_ticks,
    })
}

#[cfg(target_os = "linux")]
fn linux_process_has_background_marker(pid: u32) -> Result<bool> {
    let path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    Ok(bytes
        .split(|byte| *byte == 0)
        .any(|arg| arg == SAIAI_LINUX_BACKGROUND_COMMAND.as_bytes()))
}

#[cfg(target_os = "linux")]
fn acquire_linux_service_lock() -> Result<LinuxServiceLock> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = saiai_config_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(SAIAI_LINUX_LOCK_FILENAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("refusing non-regular SAIAI lock path {}", path.display())
        }
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let mut options = OpenOptions::new();
    options
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to protect {}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to lock {}", path.display()));
    }
    Ok(LinuxServiceLock { _file: file })
}

#[cfg(target_os = "linux")]
fn linux_background_state_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?.join(SAIAI_LINUX_PID_FILENAME))
}

#[cfg(target_os = "linux")]
fn linux_service_log_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?.join(SAIAI_SERVICE_LOG_FILENAME))
}

#[cfg(target_os = "linux")]
fn run_linux_background_logs() -> Result<()> {
    let path = linux_service_log_path()?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("SAIAI background log is unavailable at {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("refusing non-regular SAIAI log path {}", path.display());
    }
    let status = ProcessCommand::new("tail")
        .args(["-n", "80", "-f", "--"])
        .arg(&path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("tail is required but failed to run")?;
    if !status.success() {
        bail!("tail exited with {status}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_configured_listen_has_saiai_owner() -> Result<bool> {
    let cfg = match read_saiai_config() {
        Ok(cfg) => cfg,
        Err(_) => return Ok(false),
    };
    let addr = cfg
        .listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {:?}", cfg.listen))?;
    Ok(listen_port_owners(addr)
        .iter()
        .any(ListenPortOwner::is_saiai))
}

#[cfg(target_os = "windows")]
fn run_windows_background_proxy_worker() -> Result<()> {
    run_local_proxy(false)
}

#[cfg(target_os = "windows")]
fn start_windows_background_proxy() -> Result<u32> {
    use std::fs::OpenOptions;
    use std::os::windows::process::CommandExt;

    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let exe = env::current_exe().context("failed to resolve current saiai executable")?;
    let saiai_home = saiai_config_dir()?;
    fs::create_dir_all(&saiai_home)
        .with_context(|| format!("failed to create {}", saiai_home.display()))?;
    let log_path = windows_log_path()?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    let child = ProcessCommand::new(exe)
        .arg(SAIAI_WINDOWS_BACKGROUND_COMMAND)
        .env("SAIAI_HOME", &saiai_home)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .spawn()
        .context("failed to start SAIAI background proxy")?;
    let pid = child.id();
    write_bytes_atomic(&windows_pid_path()?, pid.to_string().as_bytes(), 0o600)?;
    Ok(pid)
}

#[cfg(target_os = "windows")]
fn stop_windows_background_proxy() -> Result<()> {
    if let Some(pid) = windows_background_pid()? {
        if windows_pid_is_running(pid).unwrap_or(false) {
            let status = ProcessCommand::new("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .status()
                .context("failed to run taskkill")?;
            if !status.success() {
                // Detached/background workers can reject taskkill's tree walk even
                // when the owning user can still terminate the exact process.
                // Retry narrowly through PowerShell before surfacing an error.
                let fallback = ProcessCommand::new("powershell")
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "& { param($pid) Stop-Process -Id $pid -Force -ErrorAction Stop }",
                        &pid.to_string(),
                    ])
                    .status();
                if fallback
                    .as_ref()
                    .map(|value| !value.success())
                    .unwrap_or(true)
                    && windows_pid_is_running(pid).unwrap_or(false)
                {
                    bail!(
                        "could not stop SAIAI background process {pid}; taskkill exited with {status} and the exact-process fallback was rejected. Run PowerShell as the same user or Administrator and retry."
                    );
                }
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                if !windows_pid_is_running(pid).unwrap_or(false) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if windows_pid_is_running(pid).unwrap_or(false) {
                bail!("SAIAI background process {pid} did not exit after forced termination");
            }
        }
    }
    stop_windows_exact_path_stragglers()?;
    let _ = fs::remove_file(windows_pid_path()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn stop_windows_exact_path_stragglers() -> Result<()> {
    let executable = env::current_exe().context("failed to resolve the SAIAI executable path")?;
    let executable = executable.display().to_string();
    let self_pid = std::process::id().to_string();
    let status = ProcessCommand::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($path, $selfPid) Get-CimInstance Win32_Process -Filter \"Name = 'saiai.exe'\" | Where-Object { $_.ProcessId -ne [uint32]$selfPid -and $_.ExecutablePath -and [string]::Equals([IO.Path]::GetFullPath($_.ExecutablePath), $path, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } }",
            &executable,
            &self_pid,
        ])
        .status()
        .context("failed to inspect same-path SAIAI processes")?;
    if !status.success() {
        bail!(
            "could not terminate an exact-path SAIAI process; run PowerShell as the same user or Administrator and retry"
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_background_pid() -> Result<Option<u32>> {
    let path = windows_pid_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let pid = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid pid in {}", path.display()))?;
    Ok(Some(pid))
}

#[cfg(target_os = "windows")]
fn windows_pid_is_running(pid: u32) -> Result<bool> {
    let filter = format!("PID eq {pid}");
    let output = ProcessCommand::new("tasklist")
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .output()
        .context("failed to run tasklist")?;
    if !output.status.success() {
        bail!("tasklist exited with {}", output.status);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(&format!("\"{pid}\"")) || stdout.contains(&format!(",{pid},")))
}

#[cfg(target_os = "windows")]
fn windows_pid_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?.join(SAIAI_WINDOWS_PID_FILENAME))
}

#[cfg(target_os = "windows")]
fn windows_log_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?.join(SAIAI_SERVICE_LOG_FILENAME))
}

#[cfg(target_os = "linux")]
fn ensure_systemd_user_available() -> Result<()> {
    ensure_command("systemctl")?;
    let output = systemctl_user_command()
        .args(["--user", "show-environment"])
        .output()
        .context("failed to run systemctl --user show-environment")?;
    if !output.status.success() {
        bail!(
            "systemctl --user is not available: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_systemd_user_environment(command: &mut ProcessCommand) {
    let uid = unsafe { libc::geteuid() };
    let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    let runtime_env_missing = env::var_os("XDG_RUNTIME_DIR").is_none_or(|value| value.is_empty());
    if runtime_env_missing && runtime_dir.is_dir() {
        command.env("XDG_RUNTIME_DIR", &runtime_dir);
    }

    let bus_path = runtime_dir.join("bus");
    let bus_env_missing =
        env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none_or(|value| value.is_empty());
    if bus_env_missing && bus_path.exists() {
        command.env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus_path.display()),
        );
    }
}

#[cfg(target_os = "linux")]
fn systemctl_user_command() -> ProcessCommand {
    let mut command = ProcessCommand::new("systemctl");
    apply_systemd_user_environment(&mut command);
    command
}

#[cfg(target_os = "linux")]
fn ensure_command(name: &str) -> Result<()> {
    let status = ProcessCommand::new(name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("{name} is required but was not found"))?;
    if !status.success() {
        bail!("{name} is required but failed to run");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str]) -> Result<()> {
    ensure_systemd_user_available()?;
    let output = systemctl_user_command()
        .arg("--user")
        .args(args)
        .output()
        .with_context(|| format!("failed to run systemctl --user {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stop_systemd_user_service_if_present() -> Result<bool> {
    let load_state = systemctl_value("LoadState")?;
    if load_state == "not-found" || load_state.is_empty() {
        return Ok(false);
    }
    run_systemctl(&["disable", "--now", SAIAI_SERVICE_NAME])?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn service_is_active() -> Result<bool> {
    let status = systemctl_user_command()
        .args(["--user", "is-active", "--quiet", SAIAI_SERVICE_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run systemctl --user is-active")?;
    Ok(status.success())
}

#[cfg(target_os = "linux")]
fn systemctl_value(property: &str) -> Result<String> {
    ensure_systemd_user_available()?;
    let output = systemctl_user_command()
        .args([
            "--user",
            "show",
            SAIAI_SERVICE_NAME,
            "--property",
            property,
            "--value",
        ])
        .output()
        .with_context(|| format!("failed to query {property}"))?;
    if !output.status.success() {
        bail!(
            "systemctl --user show failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn print_recent_logs(lines: usize) -> Result<()> {
    if ensure_command("journalctl").is_err() {
        return Ok(());
    }
    let mut command = ProcessCommand::new("journalctl");
    apply_systemd_user_environment(&mut command);
    let output = command
        .args([
            "--user",
            "-u",
            SAIAI_SERVICE_NAME,
            "-n",
            &lines.to_string(),
            "--no-pager",
        ])
        .output()
        .context("failed to read recent service logs")?;
    if output.stdout.is_empty() && output.stderr.is_empty() {
        return Ok(());
    }
    println!();
    println!("recent logs:");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

fn apply_common_claude_env(env_obj: &mut Map<String, Value>, api_key: &str) {
    env_obj.retain(|key, _| !is_managed_claude_env(key));
    env_obj.insert(
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_string(),
        Value::String("1".to_string()),
    );
    env_obj.insert(
        "ENABLE_PROMPT_CACHING_1H".to_string(),
        Value::String("1".to_string()),
    );
    env_obj.insert(
        "ENABLE_TOOL_SEARCH".to_string(),
        Value::String("true".to_string()),
    );
    env_obj.insert(
        "CLAUDE_CODE_OAUTH_TOKEN".to_string(),
        Value::String(api_key.to_string()),
    );
    env_obj.insert(
        "CLAUDE_STREAM_IDLE_TIMEOUT_MS".to_string(),
        Value::String(CLAUDE_STREAM_IDLE_TIMEOUT_MS.to_string()),
    );
}

fn clean_claude_settings(settings: &mut Map<String, Value>) {
    settings.remove("oauthAccount");
}

fn clean_claude_state(state: &mut Map<String, Value>) {
    state.remove("oauthAccount");
}

fn apply_claude_local_proxy_env(env_obj: &mut Map<String, Value>, listen: &str, ca_path: &Path) {
    let proxy_url = format!("http://{listen}");
    env_obj.remove("ANTHROPIC_BASE_URL");
    env_obj.insert("http_proxy".to_string(), Value::String(proxy_url.clone()));
    env_obj.insert("https_proxy".to_string(), Value::String(proxy_url.clone()));
    env_obj.insert("all_proxy".to_string(), Value::String(proxy_url));
    env_obj.insert(
        "no_proxy".to_string(),
        Value::String(DEFAULT_NO_PROXY.to_string()),
    );
    env_obj.insert(
        "NODE_EXTRA_CA_CERTS".to_string(),
        Value::String(ca_path.display().to_string()),
    );
}

struct ClaudeConfigPaths {
    config_dir: PathBuf,
    settings_path: PathBuf,
    state_path: PathBuf,
    credentials_path: PathBuf,
}

fn resolve_claude_config_paths() -> Result<ClaudeConfigPaths> {
    if let Some(config_dir) = env_dir_override("CLAUDE_CONFIG_DIR") {
        return Ok(ClaudeConfigPaths {
            settings_path: config_dir.join("settings.json"),
            state_path: config_dir.join(".claude.json"),
            credentials_path: config_dir.join(".credentials.json"),
            config_dir,
        });
    }

    let home = home_dir().context("failed to resolve home directory")?;
    let config_dir = home.join(".claude");
    Ok(ClaudeConfigPaths {
        settings_path: config_dir.join("settings.json"),
        state_path: home.join(".claude.json"),
        credentials_path: config_dir.join(".credentials.json"),
        config_dir,
    })
}

fn codex_config_dir() -> Result<PathBuf> {
    if let Some(dir) = env_dir_override("CODEX_HOME") {
        return Ok(dir);
    }
    let home = home_dir().context("failed to resolve home directory")?;
    Ok(home.join(".codex"))
}

fn saiai_config_dir() -> Result<PathBuf> {
    if let Some(dir) = env_dir_override("SAIAI_HOME") {
        return Ok(dir);
    }
    let home = home_dir().context("failed to resolve home directory")?;
    Ok(home.join(".saiai"))
}

fn saiai_config_path() -> Result<PathBuf> {
    Ok(saiai_config_dir()?.join(SAIAI_CONFIG_FILENAME))
}

fn write_saiai_config_at(path: &Path, config: &SaiaiConfig) -> Result<()> {
    let parent = path
        .parent()
        .context("failed to resolve SAIAI config parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let value = serde_json::to_value(config).context("failed to serialize SAIAI config")?;
    write_json_object(path, value)
}

fn read_saiai_config() -> Result<SaiaiConfig> {
    let path = saiai_config_path()?;
    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read {}; run the SAIAI setup command first",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn existing_runtime_ca_paths() -> Option<(PathBuf, PathBuf)> {
    let path = saiai_config_path().ok()?;
    let raw = fs::read_to_string(path).ok()?;
    let config = serde_json::from_str::<SaiaiConfig>(&raw).ok()?;
    if config.version != SAIAI_CONFIG_VERSION
        || config.ca_cert_path.trim().is_empty()
        || config.ca_key_path.trim().is_empty()
    {
        return None;
    }
    let cert = PathBuf::from(config.ca_cert_path);
    let key = PathBuf::from(config.ca_key_path);
    let cert_pem = fs::read_to_string(&cert).ok()?;
    let key_pem = fs::read_to_string(&key).ok()?;
    local_proxy::validate_tls_config(&cert_pem, &key_pem).ok()?;
    Some((cert, key))
}

fn legacy_claude_proxy_configured() -> bool {
    let Ok(paths) = resolve_claude_config_paths() else {
        return false;
    };
    let Ok(settings) = load_json_object(&paths.settings_path) else {
        return false;
    };
    let Some(env) = settings.get("env").and_then(Value::as_object) else {
        return false;
    };
    [
        "CLAUDE_CODE_OAUTH_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NODE_EXTRA_CA_CERTS",
    ]
    .into_iter()
    .any(|key| {
        env.get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    })
}

fn env_dir_override(var: &str) -> Option<PathBuf> {
    let raw = env::var_os(var)?;
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(&raw);
    // Treat whitespace-only values as unset to avoid surprising rooting at "/ ".
    if path.as_os_str().to_string_lossy().trim().is_empty() {
        return None;
    }
    Some(path)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn command_output(command: &str, args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {command}"))?;
    if !output.status.success() {
        bail!(
            "{command} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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

fn backup_if_exists(path: &Path, timestamp: &str) -> Result<()> {
    if path.exists() {
        let backup_path = PathBuf::from(format!("{}.bak-{}", path.display(), timestamp));
        fs::copy(path, &backup_path).with_context(|| {
            format!(
                "failed to back up {} to {}",
                path.display(),
                backup_path.display()
            )
        })?;
    }
    Ok(())
}

fn remove_if_exists_with_backup(path: &Path, timestamp: &str) -> Result<()> {
    if path.exists() {
        backup_if_exists(path, timestamp)?;
        fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

fn load_json_object(path: &Path) -> Result<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }

    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }

    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    value
        .as_object()
        .cloned()
        .with_context(|| format!("{} must contain a JSON object", path.display()))
}

fn write_json_object(path: &Path, value: Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(&value)?;
    let mut data = bytes;
    data.push(b'\n');
    write_bytes_atomic(path, &data, 0o600)
}

fn write_bytes_atomic(path: &Path, data: &[u8], unix_mode: u32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = unix_mode;

    let parent = path
        .parent()
        .context("failed to resolve atomic-write parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("saiai");
    let tmp_path = parent.join(format!(
        ".{name}.saiai-tmp-{}-{}",
        std::process::id(),
        Uuid::new_v4().simple()
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }
    let mut file = options
        .open(&tmp_path)
        .with_context(|| format!("failed to create {}", tmp_path.display()))?;
    if let Err(error) = file.write_all(data).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(error).with_context(|| format!("failed to write {}", tmp_path.display()));
    }
    drop(file);
    if let Err(error) = replace_file(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(unix_mode);
        fs::set_permissions(path, perm)
            .with_context(|| format!("failed to protect {}", path.display()))?;
    }

    sync_parent_best_effort(parent);
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
    // SAFETY: both buffers are NUL-terminated and remain alive for the call.
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

fn as_object(value: Value) -> Option<Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_str(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
    }

    fn read_str(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[cfg(not(windows))]
    #[test]
    fn resolves_only_executable_unix_codex_candidates() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let candidate = dir.path().join("codex");
        write_str(&candidate, "#!/bin/sh\nexit 0\n");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            find_unix_executable(&[dir.path().to_path_buf()], "codex"),
            None
        );

        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            find_unix_executable(&[dir.path().to_path_buf()], "codex"),
            Some(candidate)
        );
    }

    fn parse(path: &Path) -> DocumentMut {
        read_str(path).parse::<DocumentMut>().unwrap()
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn prepares_desktop_permission_visibility_without_selecting_a_mode() {
        let codex = TempDir::new().unwrap();
        let state_path = codex.path().join(".codex-global-state.json");
        write_str(
            &state_path,
            r#"{
  "electron-persisted-atom-state": {
    "composer-permission-mode-visibility": false,
    "agent-mode-by-host-id": {"local": "granular"}
  },
  "unrelated": "keep"
}"#,
        );

        prepare_desktop_onboarding_state_at(codex.path(), "test-first").unwrap();

        let state = load_json_object(&state_path).unwrap();
        let atoms = state["electron-persisted-atom-state"].as_object().unwrap();
        assert_eq!(
            atoms["composer-permission-mode-visibility"],
            Value::Bool(true)
        );
        assert_eq!(atoms["agent-mode-by-host-id"]["local"], "granular");
        assert_eq!(state["unrelated"], "keep");
        assert_eq!(
            atoms["electron:onboarding-projectless-completed"],
            Value::Bool(true)
        );
        assert_eq!(
            atoms["electron:onboarding-hide-first-new-thread-promos"],
            Value::Bool(true)
        );

        let backup_path = PathBuf::from(format!("{}.bak-test-first", state_path.display()));
        let backup = load_json_object(&backup_path).unwrap();
        assert_eq!(
            backup["electron-persisted-atom-state"]["composer-permission-mode-visibility"],
            Value::Bool(false)
        );

        let prepared = read_str(&state_path);
        prepare_desktop_onboarding_state_at(codex.path(), "test-second").unwrap();
        assert_eq!(read_str(&state_path), prepared);
        assert!(!PathBuf::from(format!("{}.bak-test-second", state_path.display())).exists());
    }

    #[test]
    fn cleans_third_party_codex_routes_for_oauth_launcher() {
        let mut doc = r#"
model_provider = "third_party"
openai_base_url = "https://third-party.example/v1"
chatgpt_base_url = "https://another.example"
base_url = "https://legacy.example"

[features]
other_flag = true
responses_websockets = true
responses_websockets_v2 = true

[model_providers.third_party]
name = "third_party"
base_url = "https://third-party.example/v1"

[model_providers.OpenAI]
name = "Old OpenAI"
base_url = "https://test.saiai.top"
wire_api = "chat"
env_key = "OPENAI_API_KEY"
experimental_bearer_token = "stale-token"
query_params = { tenant = "old" }
"#
        .parse::<DocumentMut>()
        .unwrap();

        clean_codex_oauth_document(&mut doc);

        assert_eq!(doc["model_provider"].as_str(), Some("openai"));
        for key in ["base_url", "openai_base_url", "chatgpt_base_url"] {
            assert!(doc.get(key).is_none(), "{key} should be removed");
        }
        assert!(doc.get("model_providers").is_none());
        assert_eq!(doc["features"]["other_flag"].as_bool(), Some(true));
        assert!(doc["features"].get("responses_websockets").is_none());
        assert!(doc["features"].get("responses_websockets_v2").is_none());
    }

    #[test]
    fn configures_platform_proxy_mode_for_codex_ide() {
        let mut doc = r#"
model_provider = "third_party"

[features]
other_flag = true
responses_websockets_v2 = true

[model_providers.third_party]
base_url = "https://third-party.example/v1"
"#
        .parse::<DocumentMut>()
        .unwrap();
        let path = Path::new("config.toml");

        clean_codex_oauth_document(&mut doc);
        enable_codex_system_proxy(&mut doc, path).unwrap();

        assert_eq!(doc["model_provider"].as_str(), Some("openai"));
        assert!(doc.get("model_providers").is_none());
        assert_eq!(doc["features"]["other_flag"].as_bool(), Some(true));
        assert_eq!(
            doc["features"]["respect_system_proxy"].as_bool(),
            Some(codex_respect_system_proxy_enabled())
        );
        assert!(doc["features"].get("responses_websockets_v2").is_none());
    }

    #[test]
    fn init_codex_oauth_setup_replaces_direct_route_and_syncs_env_port() {
        let codex = TempDir::new().unwrap();
        let config_path = codex.path().join("config.toml");
        let auth_path = codex.path().join("auth.json");
        let env_path = codex.path().join(".env");
        write_str(
            &config_path,
            r#"model_provider = "OpenAI"
base_url = "https://legacy.example/v1"

[model_providers.OpenAI]
name = "OpenAI"
base_url = "https://legacy.example/v1"
wire_api = "responses"
requires_openai_auth = true
"#,
        );
        write_str(&auth_path, r#"{"OPENAI_API_KEY":"TEST_ONLY_OLD_KEY"}"#);
        write_str(
            &env_path,
            "USER_SETTING=keep\nHTTP_PROXY=http://127.0.0.1:19908\n",
        );
        let proxy_init = CodexLocalProxyInit {
            config_path: codex.path().join("saiai-config.json"),
            config_changed: true,
            listen: "127.0.0.1:31234".to_string(),
            ca_cert_path: PathBuf::from("/tmp/saiai-ca.crt"),
            ca_key_path: PathBuf::from("/tmp/saiai-ca.key"),
        };

        let initialized = configure_codex_oauth_local_proxy(codex.path(), &proxy_init).unwrap();

        assert_eq!(initialized.auth_path, auth_path);
        assert_eq!(initialized.env_path, env_path);
        let document = parse(&config_path);
        assert_eq!(document["model_provider"].as_str(), Some("openai"));
        assert!(document.get("base_url").is_none());
        assert!(document.get("model_providers").is_none());
        let auth = load_json_object(&auth_path).unwrap();
        assert_eq!(auth["auth_mode"].as_str(), Some("chatgptAuthTokens"));
        assert_eq!(auth["OPENAI_API_KEY"], Value::Null);
        let env = read_str(&env_path);
        assert!(env.contains("USER_SETTING=keep"));
        assert!(env.contains("HTTP_PROXY=\"http://127.0.0.1:31234\""));
        assert!(!env.contains("19908"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scopes_direct_desktop_nss_database_to_the_current_user_home() {
        assert_eq!(
            nss_database_dir(Path::new("/tmp/saiai-user")),
            PathBuf::from("/tmp/saiai-user/.pki/nssdb")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn falls_back_to_invoking_xauthority_only_for_x11() {
        let home = TempDir::new().unwrap();
        let xauthority = home.path().join(".Xauthority");
        write_str(&xauthority, "test-only-x11-cookie");

        assert_eq!(
            fallback_linux_xauthority(Some(home.path()), true),
            Some(xauthority)
        );
        assert_eq!(fallback_linux_xauthority(Some(home.path()), false), None);
        assert_eq!(fallback_linux_xauthority(None, true), None);
    }

    #[test]
    fn codex_ide_env_replaces_conflicts_and_preserves_unrelated_values() {
        let raw = r#"# user comment
USER_SETTING=keep-me
export HTTP_PROXY=https://old-proxy.example
CUSTOM_BASE_URL=https://unrelated.example/v1
OPENAI_API_KEY=remove-me

# BEGIN SAIAI CODEX IDE (managed)
HTTPS_PROXY="http://127.0.0.1:1111"
# END SAIAI CODEX IDE (managed)
"#;

        let merged = merge_codex_ide_env(raw, "127.0.0.1:19908", "/tmp/SAIAI CA/saiai-ca.crt");

        assert!(merged.contains("# user comment\nUSER_SETTING=keep-me"));
        assert!(!merged.contains("old-proxy"));
        assert!(!merged.contains("remove-me"));
        assert!(merged.contains("CUSTOM_BASE_URL=https://unrelated.example/v1"));
        assert_eq!(merged.matches(CODEX_IDE_ENV_BEGIN).count(), 1);
        assert_eq!(merged.matches(CODEX_IDE_ENV_END).count(), 1);
        assert!(merged.contains("HTTP_PROXY=\"http://127.0.0.1:19908\""));
        assert!(merged.contains("http_proxy=\"http://127.0.0.1:19908\""));
        assert!(merged.contains("SSL_CERT_FILE=\"/tmp/SAIAI CA/saiai-ca.crt\""));
        assert!(!merged.contains("OPENAI_API_KEY="));
        assert_eq!(
            merge_codex_ide_env(&merged, "127.0.0.1:19908", "/tmp/SAIAI CA/saiai-ca.crt",),
            merged
        );
    }

    #[test]
    fn accepts_chatgpt_managed_and_external_token_auth_for_codex_launcher() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_str(
            &path,
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"oauth-test"}}"#,
        );
        validate_codex_oauth_auth(&path).unwrap();

        write_str(
            &path,
            r#"{"auth_mode":"chatgptAuthTokens","tokens":{"access_token":"external-oauth-test"}}"#,
        );
        validate_codex_oauth_auth(&path).unwrap();

        write_str(&path, r#"{"OPENAI_API_KEY":"sk-test"}"#);
        assert!(validate_codex_oauth_auth(&path).is_err());
    }

    #[test]
    fn creates_and_upgrades_app_server_shaped_codex_placeholder_auth() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        ensure_codex_local_proxy_auth(&path).unwrap();

        let created = load_json_object(&path).unwrap();
        let created_tokens = created["tokens"].as_object().unwrap();
        assert_eq!(created["auth_mode"].as_str(), Some("chatgptAuthTokens"));
        assert_eq!(created["OPENAI_API_KEY"], Value::Null);
        assert_eq!(
            created_tokens["access_token"].as_str(),
            Some(CODEX_PLACEHOLDER_ACCESS_TOKEN)
        );
        assert_eq!(created_tokens["refresh_token"].as_str(), Some(""));
        assert_eq!(
            created_tokens["account_id"].as_str(),
            Some("saiai-local-proxy-account")
        );
        let token_payload = created_tokens["id_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token_payload)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            claims["https://api.openai.com/auth"]["chatgpt_account_id"],
            created_tokens["account_id"]
        );
        assert_eq!(
            created_tokens["id_token"]
                .as_str()
                .unwrap()
                .split('.')
                .count(),
            3
        );
        assert!(
            created["last_refresh"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
        );

        write_str(
            &path,
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"saiai-local-proxy-placeholder-old","refresh_token":"old","account_id":"old"},"unrelated":"keep"}"#,
        );
        ensure_codex_local_proxy_auth(&path).unwrap();
        let upgraded = load_json_object(&path).unwrap();
        assert_eq!(upgraded["unrelated"].as_str(), Some("keep"));
        assert_eq!(upgraded["auth_mode"].as_str(), Some("chatgptAuthTokens"));
        assert_eq!(
            upgraded["tokens"]["id_token"].as_str(),
            Some(CODEX_PLACEHOLDER_ID_TOKEN)
        );
    }

    #[test]
    fn migrates_any_api_auth_to_local_proxy_oauth() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_str(&path, r#"{"OPENAI_API_KEY":"TEST_ONLY_MANAGED_KEY"}"#);

        ensure_codex_local_proxy_auth(&path).unwrap();
        let upgraded = load_json_object(&path).unwrap();
        assert_eq!(upgraded["auth_mode"].as_str(), Some("chatgptAuthTokens"));
        assert_eq!(
            upgraded["tokens"]["access_token"].as_str(),
            Some(CODEX_PLACEHOLDER_ACCESS_TOKEN)
        );
        assert_eq!(upgraded["OPENAI_API_KEY"], Value::Null);

        write_str(&path, r#"{"OPENAI_API_KEY":"TEST_ONLY_UNRELATED_KEY"}"#);
        ensure_codex_local_proxy_auth(&path).unwrap();
        assert_eq!(
            load_json_object(&path).unwrap()["tokens"]["access_token"].as_str(),
            Some(CODEX_PLACEHOLDER_ACCESS_TOKEN)
        );
        validate_codex_oauth_auth(&path).unwrap();
    }

    #[test]
    fn preserves_existing_real_codex_oauth_auth() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        let real = r#"{"auth_mode":"chatgpt","tokens":{"id_token":"real.id.token","access_token":"real-access","refresh_token":"real-refresh","account_id":"real-account"},"last_refresh":"2026-09-09T00:00:00Z"}"#;
        write_str(&path, real);

        ensure_codex_local_proxy_auth(&path).unwrap();

        assert_eq!(read_str(&path), real);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn treats_legacy_api_credential_auth_as_desktop_placeholder_source() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("auth.json");
        let target = dir.path().join("desktop-auth.json");
        write_str(&source, r#"{"OPENAI_API_KEY":"TEST_ONLY_KEY"}"#);

        assert!(!copy_real_codex_oauth_auth(&source, &target).unwrap());
        assert!(!target.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn detects_expired_parseable_codex_access_tokens() {
        let expired = "e30.eyJleHAiOjEwMH0.signature";
        let unexpired = "e30.eyJleHAiOjIwMH0.signature";
        assert!(codex_access_token_is_expired(expired, 100));
        assert!(!codex_access_token_is_expired(unexpired, 100));
        assert!(!codex_access_token_is_expired("opaque-token", 100));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn treats_expired_real_oauth_as_desktop_placeholder_source() {
        let dir = TempDir::new().unwrap();
        let source = dir.path().join("auth.json");
        let target = dir.path().join("desktop-auth.json");
        write_str(
            &source,
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"e30.eyJleHAiOjEwMH0.signature","refresh_token":"revoked","account_id":"expired-account"}}"#,
        );

        assert!(!copy_real_codex_oauth_auth(&source, &target).unwrap());
        assert!(!target.exists());
        assert!(source.exists(), "the normal profile must remain untouched");
    }

    fn json_str<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
        map.get(key).and_then(Value::as_str).unwrap_or("")
    }

    #[test]
    fn common_claude_env_replaces_routing_and_preserves_user_preferences() {
        let mut env_obj = Map::new();
        for key in [
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_DISABLE_ANALYTICS",
            "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
            "DISABLE_AUTOUPDATER",
            "DISABLE_ERROR_REPORTING",
            "DISABLE_TELEMETRY",
            "DO_NOT_TRACK",
        ] {
            env_obj.insert(key.to_string(), Value::String("old".to_string()));
        }

        apply_common_claude_env(&mut env_obj, "sk-test");

        assert_eq!(json_str(&env_obj, "CLAUDE_CODE_OAUTH_TOKEN"), "sk-test");
        assert_eq!(
            json_str(&env_obj, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"),
            "1",
        );
        assert_eq!(json_str(&env_obj, "ENABLE_PROMPT_CACHING_1H"), "1");
        assert_eq!(json_str(&env_obj, "ENABLE_TOOL_SEARCH"), "true");
        assert_eq!(
            json_str(&env_obj, "CLAUDE_STREAM_IDLE_TIMEOUT_MS"),
            "600000",
        );
        for key in ["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"] {
            assert!(
                env_obj.get(key).is_none(),
                "{key} should be removed from Claude env",
            );
        }
        for key in [
            "CLAUDE_CODE_DISABLE_ANALYTICS",
            "CLAUDE_CODE_DISABLE_TERMINAL_TITLE",
            "DISABLE_AUTOUPDATER",
            "DISABLE_ERROR_REPORTING",
            "DISABLE_TELEMETRY",
            "DO_NOT_TRACK",
        ] {
            assert_eq!(json_str(&env_obj, key), "old", "{key} should be preserved");
        }
    }

    #[test]
    fn no_args_runs_local_proxy() {
        match parse_command(&[]).unwrap() {
            Command::RunProxy { verbose: false } => {}
            _ => panic!("expected local proxy command"),
        }
    }

    #[test]
    fn verbose_flag_runs_local_proxy_with_request_logs() {
        match parse_command(&["--verbose".to_string()]).unwrap() {
            Command::RunProxy { verbose: true } => {}
            _ => panic!("expected verbose local proxy command"),
        }
    }

    #[test]
    fn parses_doctor_and_version_commands() {
        match parse_command(&["doctor".to_string()]).unwrap() {
            Command::Doctor(DoctorTarget::All) => {}
            _ => panic!("expected doctor command"),
        }
        assert!(matches!(
            parse_command(&["doctor".to_string(), "claude".to_string()]).unwrap(),
            Command::Doctor(DoctorTarget::Claude)
        ));
        assert!(matches!(
            parse_command(&["doctor".to_string(), "codex".to_string()]).unwrap(),
            Command::Doctor(DoctorTarget::Codex)
        ));
        assert!(parse_command(&["doctor".to_string(), "other".to_string()]).is_err());
        match parse_command(&["--version".to_string()]).unwrap() {
            Command::Version => {}
            _ => panic!("expected version command"),
        }
    }

    #[test]
    fn parses_codex_launcher_arguments_without_consuming_them() {
        let args = [
            "codex".to_string(),
            "--".to_string(),
            "app-server".to_string(),
            "--stdio".to_string(),
        ];
        match parse_command(&args).unwrap() {
            Command::Codex(codex_args) => assert_eq!(
                codex_args,
                vec!["app-server".to_string(), "--stdio".to_string()]
            ),
            _ => panic!("expected codex launcher command"),
        }
    }

    #[test]
    fn parses_vscode_configuration_command_without_arguments() {
        assert!(matches!(
            parse_command(&["vscode".to_string()]).unwrap(),
            Command::VSCode
        ));
        assert!(parse_command(&["vscode".to_string(), "extra".to_string()]).is_err());
    }

    #[test]
    fn parses_desktop_launcher_aliases_without_consuming_arguments() {
        for command in ["desktop", "chatgpt"] {
            let args = vec![command.to_string(), "--".to_string(), "--help".to_string()];
            match parse_command(&args).unwrap() {
                Command::Desktop { product, args } => {
                    assert_eq!(
                        product,
                        if command == "chatgpt" {
                            DesktopProduct::ChatGPT
                        } else {
                            DesktopProduct::Codex
                        }
                    );
                    assert_eq!(args, vec!["--help".to_string()]);
                }
                _ => panic!("expected Desktop launcher command"),
            }
        }

        let claude = parse_command(&[
            "desktop".to_string(),
            "claude".to_string(),
            "--".to_string(),
            "--help".to_string(),
        ])
        .unwrap();
        assert!(matches!(
            claude,
            Command::Desktop {
                product: DesktopProduct::Claude,
                args
            } if args == vec!["--help".to_string()]
        ));
        assert!(parse_command(&["desktop".to_string(), "unknown".to_string()]).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn validates_optional_chatgpt_timezone() {
        assert_eq!(
            resolve_chatgpt_timezone_value(None).unwrap().as_deref(),
            Some(DEFAULT_CHATGPT_TIMEZONE)
        );
        assert_eq!(
            resolve_chatgpt_timezone_value(Some("system")).unwrap(),
            None
        );
        let resolved =
            validate_chatgpt_timezone("America/Los_Angeles").expect("valid zoneinfo timezone");
        assert_eq!(resolved.as_deref(), Some("America/Los_Angeles"));

        assert!(validate_chatgpt_timezone("../etc/passwd").is_err());
        assert!(validate_chatgpt_timezone("/etc/passwd").is_err());
    }

    #[test]
    fn existing_saiai_config_defaults_chatgpt_passthrough_on() {
        let config: SaiaiConfig = serde_json::from_value(serde_json::json!({
            "version": SAIAI_CONFIG_VERSION,
            "base_url": "https://gateway.example.test",
            "api_key": "TEST_ONLY_KEY",
            "listen": "127.0.0.1:19908",
            "ca_cert_path": "/tmp/test-ca.crt",
            "ca_key_path": "/tmp/test-ca.key"
        }))
        .unwrap();
        assert!(config.chatgpt_chat_passthrough);
    }

    #[test]
    fn initialization_proxy_start_can_be_explicitly_skipped() {
        assert!(!should_skip_initialization_proxy_start(None));
        assert!(!should_skip_initialization_proxy_start(Some("0")));
        assert!(!should_skip_initialization_proxy_start(Some("true")));
        assert!(should_skip_initialization_proxy_start(Some("1")));
    }

    #[test]
    fn initialization_only_refreshes_when_runtime_state_requires_it() {
        assert!(!initialization_requires_proxy_refresh(
            false, false, true, true
        ));
        assert!(initialization_requires_proxy_refresh(
            true, false, true, true
        ));
        assert!(initialization_requires_proxy_refresh(
            false, true, true, true
        ));
        assert!(initialization_requires_proxy_refresh(
            false, false, false, true
        ));
        assert!(initialization_requires_proxy_refresh(
            false, false, true, false
        ));
        assert!(!binary_changed_during_initialization(None));
        assert!(!binary_changed_during_initialization(Some("0")));
        assert!(binary_changed_during_initialization(Some("1")));
        assert!(update_refresh_failure_is_recoverable(true));
        assert!(!update_refresh_failure_is_recoverable(false));
    }

    #[test]
    fn ignores_legacy_root_mirror_when_provider_routes_are_unchanged() {
        let providers = ProviderCredentials {
            claude: Some(ProviderCredential {
                base_url: "https://claude.example.test".to_string(),
                api_key: "TEST_ONLY_CLAUDE_KEY".to_string(),
            }),
            codex: Some(ProviderCredential {
                base_url: "https://codex.example.test".to_string(),
                api_key: "TEST_ONLY_CODEX_KEY".to_string(),
            }),
        };
        let previous = SaiaiConfig {
            version: SAIAI_CONFIG_VERSION,
            base_url: "https://claude.example.test".to_string(),
            api_key: "TEST_ONLY_CLAUDE_KEY".to_string(),
            listen: "127.0.0.1:19908".to_string(),
            ca_cert_path: "/tmp/saiai-ca.crt".to_string(),
            ca_key_path: "/tmp/saiai-ca.key".to_string(),
            chatgpt_chat_passthrough: true,
            providers: providers.clone(),
        };
        let current = SaiaiConfig {
            base_url: "https://codex.example.test".to_string(),
            api_key: "TEST_ONLY_CODEX_KEY".to_string(),
            providers,
            ..previous.clone()
        };
        assert!(!proxy_runtime_config_changed(Some(&previous), &current));
    }

    #[test]
    fn init_codex_prepares_standalone_local_proxy_config() {
        let temporary = tempfile::tempdir().unwrap();
        let args = InitArgs {
            base_url: "https://gateway.example.test/v1".to_string(),
            api_key: "TEST_ONLY_CODEX_PROXY_KEY".to_string(),
            websockets: false,
        };

        let initialized =
            initialize_codex_local_proxy_at(temporary.path(), &args, "test-create").unwrap();
        let config: SaiaiConfig =
            serde_json::from_slice(&fs::read(&initialized.config_path).unwrap()).unwrap();

        assert_eq!(config.version, SAIAI_CONFIG_VERSION);
        assert_eq!(config.base_url, "https://gateway.example.test");
        assert_eq!(config.api_key, args.api_key);
        assert_eq!(
            config.providers.codex.as_ref().map(|value| &value.api_key),
            Some(&args.api_key)
        );
        let listen_addr = config.listen.parse::<SocketAddr>().unwrap();
        assert!(listen_addr.ip().is_loopback());
        assert_ne!(listen_addr.port(), 0);
        assert_eq!(
            config.ca_cert_path,
            initialized.ca_cert_path.display().to_string()
        );
        assert_eq!(
            config.ca_key_path,
            initialized.ca_key_path.display().to_string()
        );
        assert!(config.chatgpt_chat_passthrough);
        read_runtime_ca(&config).unwrap();
    }

    #[test]
    fn codex_proxy_gateway_root_strips_only_terminal_v1() {
        assert_eq!(
            codex_proxy_gateway_root("https://gateway.example.test/v1").unwrap(),
            "https://gateway.example.test"
        );
        assert_eq!(
            codex_proxy_gateway_root("https://gateway.example.test/prefix/v1").unwrap(),
            "https://gateway.example.test/prefix"
        );
        assert_eq!(
            codex_proxy_gateway_root("https://gateway.example.test/prefix").unwrap(),
            "https://gateway.example.test/prefix"
        );
    }

    #[test]
    fn init_codex_reuses_existing_proxy_ca_and_local_preferences() {
        let temporary = tempfile::tempdir().unwrap();
        let first_args = InitArgs {
            base_url: "https://first.example.test".to_string(),
            api_key: "TEST_ONLY_FIRST_CODEX_PROXY_KEY".to_string(),
            websockets: false,
        };
        let first =
            initialize_codex_local_proxy_at(temporary.path(), &first_args, "test-first").unwrap();
        let cert_before = fs::read(&first.ca_cert_path).unwrap();
        let key_before = fs::read(&first.ca_key_path).unwrap();
        let mut config: SaiaiConfig =
            serde_json::from_slice(&fs::read(&first.config_path).unwrap()).unwrap();
        config.providers.claude = Some(ProviderCredential {
            base_url: "https://claude.example.test".to_string(),
            api_key: "TEST_ONLY_CLAUDE_PROXY_KEY".to_string(),
        });
        config.listen = "127.0.0.1:29908".to_string();
        config.chatgpt_chat_passthrough = false;
        write_saiai_config_at(&first.config_path, &config).unwrap();

        let second_args = InitArgs {
            base_url: "https://second.example.test".to_string(),
            api_key: "TEST_ONLY_SECOND_CODEX_PROXY_KEY".to_string(),
            websockets: true,
        };
        let second =
            initialize_codex_local_proxy_at(temporary.path(), &second_args, "test-second").unwrap();
        let updated: SaiaiConfig =
            serde_json::from_slice(&fs::read(&second.config_path).unwrap()).unwrap();

        assert_eq!(second.ca_cert_path, first.ca_cert_path);
        assert_eq!(second.ca_key_path, first.ca_key_path);
        assert_eq!(fs::read(&second.ca_cert_path).unwrap(), cert_before);
        assert_eq!(fs::read(&second.ca_key_path).unwrap(), key_before);
        assert!(second.config_changed);
        assert_eq!(updated.base_url, second_args.base_url);
        assert_eq!(updated.api_key, second_args.api_key);
        assert_eq!(
            updated.providers.codex.as_ref().map(|value| &value.api_key),
            Some(&second_args.api_key)
        );
        assert_eq!(
            updated
                .providers
                .claude
                .as_ref()
                .map(|value| &value.api_key),
            Some(&"TEST_ONLY_CLAUDE_PROXY_KEY".to_string())
        );
        assert_eq!(updated.listen, "127.0.0.1:29908");
        assert!(!updated.chatgpt_chat_passthrough);
    }

    #[test]
    fn updates_only_selected_saiai_provider_config() {
        let temporary = tempfile::tempdir().unwrap();
        let config_path = temporary.path().join(SAIAI_CONFIG_FILENAME);
        let cert_path = temporary.path().join("saiai-ca.crt");
        let key_path = temporary.path().join("saiai-ca.key");
        let _initial = update_saiai_provider_config_at(
            &config_path,
            ProviderKind::Claude,
            ProviderCredential {
                base_url: "https://claude.example.test".to_string(),
                api_key: "TEST_ONLY_CLAUDE_KEY".to_string(),
            },
            Some((cert_path.clone(), key_path.clone())),
        )
        .unwrap();
        let updated = update_saiai_provider_config_at(
            &config_path,
            ProviderKind::Codex,
            ProviderCredential {
                base_url: "https://codex.example.test".to_string(),
                api_key: "TEST_ONLY_CODEX_KEY".to_string(),
            },
            None,
        )
        .unwrap();

        assert!(updated.changed);
        assert_eq!(updated.config.base_url, "https://codex.example.test");
        assert_eq!(updated.config.api_key, "TEST_ONLY_CODEX_KEY");
        assert_eq!(
            updated
                .config
                .providers
                .claude
                .as_ref()
                .map(|value| &value.api_key),
            Some(&"TEST_ONLY_CLAUDE_KEY".to_string())
        );
        assert_eq!(
            updated
                .config
                .providers
                .codex
                .as_ref()
                .map(|value| &value.api_key),
            Some(&"TEST_ONLY_CODEX_KEY".to_string())
        );

        let unchanged = update_saiai_provider_config_at(
            &config_path,
            ProviderKind::Codex,
            ProviderCredential {
                base_url: "https://codex.example.test".to_string(),
                api_key: "TEST_ONLY_CODEX_KEY".to_string(),
            },
            None,
        )
        .unwrap();
        assert!(!unchanged.changed);
    }

    #[test]
    fn codex_launcher_enables_child_only_system_proxy_support() {
        let args = vec!["exec".to_string(), "probe".to_string()];
        assert_eq!(
            codex_launcher_args(&args),
            vec![
                "-c".to_string(),
                format!(
                    "features.respect_system_proxy={}",
                    codex_respect_system_proxy_enabled()
                ),
                "-c".to_string(),
                "otel.metrics_exporter=\"none\"".to_string(),
                "-c".to_string(),
                "features.apps=false".to_string(),
                "exec".to_string(),
                "probe".to_string(),
            ]
        );
    }

    #[test]
    fn codex_launcher_preserves_explicit_feature_overrides() {
        for args in [
            vec![
                "-c".to_string(),
                "features.respect_system_proxy=false".to_string(),
            ],
            vec!["--enable=respect_system_proxy".to_string()],
            vec!["--disable".to_string(), "respect_system_proxy".to_string()],
        ] {
            assert_eq!(
                codex_launcher_args(&args),
                [
                    vec![
                        "-c".to_string(),
                        "otel.metrics_exporter=\"none\"".to_string(),
                        "-c".to_string(),
                        "features.apps=false".to_string(),
                    ],
                    args,
                ]
                .concat()
            );
        }

        let args = vec![
            "--enable".to_string(),
            "apps".to_string(),
            "exec".to_string(),
        ];
        let launch_args = codex_launcher_args(&args);
        assert!(launch_args.contains(&format!(
            "features.respect_system_proxy={}",
            codex_respect_system_proxy_enabled()
        )));
        assert!(launch_args.contains(&"otel.metrics_exporter=\"none\"".to_string()));
        assert!(!launch_args.contains(&"features.apps=false".to_string()));
        assert!(launch_args.ends_with(&args));

        let args = vec![
            "--config".to_string(),
            "otel.metrics_exporter=\"statsig\"".to_string(),
            "exec".to_string(),
        ];
        let launch_args = codex_launcher_args(&args);
        assert_eq!(
            launch_args
                .iter()
                .filter(|value| value.starts_with("otel.metrics_exporter="))
                .count(),
            1
        );
        assert!(launch_args.ends_with(&args));
    }

    #[test]
    fn parses_http_response_status_codes() {
        assert_eq!(
            http_status_code("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").unwrap(),
            204
        );
        assert_eq!(
            http_status_code("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap(),
            200
        );
        assert!(http_status_code("not-http\r\n\r\n").is_err());
        assert!(http_status_code("HTTP/1.1 nope\r\n\r\n").is_err());
    }

    #[test]
    fn finds_http_header_end() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\n\n"), None);
        assert_eq!(find_header_end(b"partial"), None);
    }

    #[test]
    fn treats_local_proxy_connection_failures_as_warnings() {
        let connect = anyhow::anyhow!("failed to connect to local proxy at http://127.0.0.1:19908");
        assert!(is_local_proxy_connect_error(&connect));

        let timeout =
            anyhow::anyhow!("timed out connecting to local proxy at http://127.0.0.1:19908");
        assert!(is_local_proxy_connect_error(&timeout));

        let tls = anyhow::anyhow!("local proxy MITM TLS handshake failed");
        assert!(!is_local_proxy_connect_error(&tls));
    }

    #[test]
    fn loads_generated_ca_into_rustls_roots() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("saiai-ca.crt");
        let (ca_cert_pem, _) = generate_installation_ca().unwrap();
        fs::write(&ca_path, ca_cert_pem).unwrap();
        load_ca_root_store(&ca_path).unwrap();

        let invalid_path = dir.path().join("invalid-ca.crt");
        fs::write(&invalid_path, b"not a pem certificate").unwrap();
        assert!(load_ca_root_store(&invalid_path).is_err());
    }

    #[test]
    fn parses_service_commands() {
        for (raw, expected) in [
            ("start", "start"),
            ("stop", "stop"),
            ("status", "status"),
            ("logs", "logs"),
            ("update", "update"),
            ("restart", "restart"),
        ] {
            match (raw, parse_command(&[raw.to_string()]).unwrap()) {
                ("start", Command::Start)
                | ("stop", Command::Stop)
                | ("status", Command::Status)
                | ("logs", Command::Logs)
                | ("update", Command::Update)
                | ("restart", Command::Restart) => {}
                _ => panic!("expected {expected} command"),
            }
        }
        assert!(parse_command(&["start".to_string(), "extra".to_string()]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn renders_user_service_without_secrets() {
        let unit = render_user_service(
            Path::new("/home/test/.local/bin/saiai"),
            Path::new("/home/test/.saiai"),
            Path::new("/home/test"),
        )
        .unwrap();
        assert!(unit.contains("ExecStart=\"/home/test/.local/bin/saiai\""));
        assert!(unit.contains("Environment=\"SAIAI_HOME=/home/test/.saiai\""));
        assert!(unit.contains("WorkingDirectory=/home/test"));
        assert!(!unit.contains("api_key"));
        assert!(!unit.contains("sk-"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_net_tcp_listen_inode() {
        let line = "   0: 0100007F:46A1 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 100 0 0 10 0";
        assert_eq!(parse_proc_net_tcp_listen_inode(line, 18081), Some("123456"));
        assert_eq!(parse_proc_net_tcp_listen_inode(line, 18082), None);

        let established = line.replacen(" 0A ", " 01 ", 1);
        assert_eq!(parse_proc_net_tcp_listen_inode(&established, 18081), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_stat_with_closing_parenthesis_in_command() {
        let mut fields = vec!["S"; 19];
        fields.push("4242");
        let raw = format!("123 (saiai worker ) name) {}", fields.join(" "));
        assert_eq!(
            parse_linux_proc_stat(&raw).unwrap(),
            LinuxProcessIdentity {
                state: 'S',
                start_time_ticks: 4242,
            }
        );
        assert!(parse_linux_proc_stat("123 (broken) S").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_private_linux_background_worker_command() {
        match parse_command(&[SAIAI_LINUX_BACKGROUND_COMMAND.to_string()]).unwrap() {
            Command::RunLinuxBackgroundProxy => {}
            _ => panic!("expected Linux background proxy worker command"),
        }
        assert!(
            parse_command(&[
                SAIAI_LINUX_BACKGROUND_COMMAND.to_string(),
                "extra".to_string(),
            ])
            .is_err()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parses_private_windows_background_worker_command() {
        match parse_command(&[SAIAI_WINDOWS_BACKGROUND_COMMAND.to_string()]).unwrap() {
            Command::RunWindowsBackgroundProxy => {}
            _ => panic!("expected Windows background proxy worker command"),
        }
        assert!(
            parse_command(&[
                SAIAI_WINDOWS_BACKGROUND_COMMAND.to_string(),
                "extra".to_string(),
            ])
            .is_err()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn recognizes_a_legacy_packaged_proxy_lease_for_cleanup() {
        let original = LegacyWindowsInternetProxySettings {
            proxy_enable: Some(0),
            proxy_server: None,
            auto_config_url: None,
        };
        let marker = LegacyWindowsPackagedProxyLeaseMarker {
            previous: original.clone(),
            managed_server: "127.0.0.1:64196".to_string(),
            added_ca_thumbprints: vec!["TEST-CA".to_string()],
        };
        let active = LegacyWindowsInternetProxySettings {
            proxy_enable: Some(1),
            proxy_server: Some("http://127.0.0.1:64196/".to_string()),
            auto_config_url: None,
        };

        assert!(windows_proxy_matches_managed(
            &active,
            &marker.managed_server
        ));
        assert_eq!(marker.previous.proxy_enable, Some(0));
        assert_eq!(marker.added_ca_thumbprints, vec!["TEST-CA"]);
    }

    #[test]
    fn formats_listen_port_owners_without_command_args() {
        let owners = vec![ListenPortOwner {
            pid: 42,
            name: "saiai".to_string(),
        }];
        assert_eq!(format_listen_owners(&owners), "pid 42 (saiai)");
        assert!(owners[0].is_saiai());
    }

    #[test]
    fn detects_nonempty_conflicting_environment_values() {
        assert!(!env_value_is_set(None));
        assert!(!env_value_is_set(Some("")));
        assert!(env_value_is_set(Some("https://api.anthropic.com")));
    }

    #[test]
    fn detects_proxy_values_that_can_override_local_proxy() {
        let expected = "http://127.0.0.1:19908";
        assert!(proxy_value_conflicts(
            "HTTP_PROXY",
            "http://172.26.0.1:7890",
            expected
        ));
        assert!(proxy_value_conflicts(
            "http_proxy",
            "http://172.26.0.1:7890",
            expected
        ));
        assert!(!proxy_value_conflicts("HTTP_PROXY", expected, expected));
        assert!(!proxy_value_conflicts(
            "NO_PROXY",
            "localhost,127.0.0.1",
            expected
        ));
        assert!(proxy_value_conflicts("NO_PROXY", "172.26.0.1", expected));
    }

    #[test]
    fn detects_persistent_environment_assignments() {
        assert!(persistent_env_line_sets_key(
            "export ANTHROPIC_BASE_URL=https://example.test",
            "ANTHROPIC_BASE_URL"
        ));
        assert!(persistent_env_line_sets_key(
            "CLAUDE_CODE_OAUTH_TOKEN=sk-test",
            "CLAUDE_CODE_OAUTH_TOKEN"
        ));
        assert!(persistent_env_line_sets_key(
            "CLAUDE_CODE_ATTRIBUTION_HEADER=old-attribution",
            "CLAUDE_CODE_ATTRIBUTION_HEADER"
        ));
        assert!(persistent_env_line_sets_key(
            "set -gx ANTHROPIC_BASE_URL https://example.test",
            "ANTHROPIC_BASE_URL"
        ));
        assert!(persistent_env_line_sets_key(
            "setenv CLAUDE_CODE_OAUTH_TOKEN sk-test",
            "CLAUDE_CODE_OAUTH_TOKEN"
        ));
        assert!(!persistent_env_line_sets_key(
            "# export ANTHROPIC_BASE_URL=https://example.test",
            "ANTHROPIC_BASE_URL"
        ));
        assert!(!persistent_env_line_sets_key(
            "export ANTHROPIC_BASE_URL_BACKUP=https://example.test",
            "ANTHROPIC_BASE_URL"
        ));
        assert!(!persistent_env_line_sets_key(
            "echo ANTHROPIC_BASE_URL=https://example.test",
            "ANTHROPIC_BASE_URL"
        ));
    }

    #[test]
    fn formats_persistent_environment_conflicts_with_locations() {
        let conflicts = vec![PersistentEnvConflict {
            path: PathBuf::from("/home/test/.bashrc"),
            line: 12,
            key: "ANTHROPIC_BASE_URL",
        }];
        assert_eq!(
            format_persistent_env_conflicts(&conflicts),
            "ANTHROPIC_BASE_URL at /home/test/.bashrc:12"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detects_systemd_user_environment_keys() {
        let output = "PATH=/usr/bin\nANTHROPIC_BASE_URL=https://example.test\nCLAUDE_CODE_ATTRIBUTION_HEADER=old-attribution\nOTHER=1\n";
        assert!(systemd_env_contains_key(output, "ANTHROPIC_BASE_URL"));
        assert!(systemd_env_contains_key(
            output,
            "CLAUDE_CODE_ATTRIBUTION_HEADER"
        ));
        assert!(!systemd_env_contains_key(output, "CLAUDE_CODE_OAUTH_TOKEN"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn validates_update_asset_architecture() {
        let mut elf_x86 = vec![0u8; 64];
        elf_x86[..4].copy_from_slice(b"\x7FELF");
        elf_x86[18..20].copy_from_slice(&62u16.to_le_bytes());
        validate_update_asset(&elf_x86, "saiai-linux-x86_64").unwrap();
        assert!(validate_update_asset(&elf_x86, "saiai-linux-aarch64-wrong").is_err());

        let mut macho = vec![0u8; 64];
        macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        validate_update_asset(&macho, "saiai-macos-aarch64").unwrap();
        assert!(validate_update_asset(&macho, "saiai-macos-x86_64").is_err());

        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        validate_update_asset(&pe, "saiai-windows-x86_64.exe").unwrap();
        assert!(validate_update_asset(&pe, "saiai-windows-aarch64.exe").is_err());

        let expected_current_asset = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "saiai-linux-x86_64",
            ("linux", "aarch64") => "saiai-linux-aarch64",
            ("macos", "x86_64") => "saiai-macos-x86_64",
            ("macos", "aarch64") => "saiai-macos-aarch64",
            ("windows", "x86_64") => "saiai-windows-x86_64.exe",
            ("windows", "aarch64") => "saiai-windows-aarch64.exe",
            (os, arch) => panic!("unexpected test platform {os}/{arch}"),
        };
        assert_eq!(
            current_platform_asset_name().unwrap(),
            expected_current_asset
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn compares_update_versions_numerically() {
        assert_eq!(
            compare_versions("0.7.0", "0.6.1").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("saiai 0.7.0", "0.7").unwrap(),
            Ordering::Equal
        );
        assert_eq!(compare_versions("v0.6.1", "0.7.0").unwrap(), Ordering::Less);
        assert_eq!(
            compare_versions("0.10.0", "0.9.9").unwrap(),
            Ordering::Greater
        );
        assert!(compare_versions("0.7.x", "0.7.0").is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn computes_sha256_hex() {
        assert_eq!(
            sha256_hex(b"saiai"),
            "6fea1fb5062fe02a6c45282f53fe6e35645dde10ecb69414f3fa0a79e0b09482"
        );
    }

    #[test]
    fn parses_init_named_args() {
        let args = vec![
            "init".to_string(),
            "--base-url".to_string(),
            "https://api.saiai.top".to_string(),
            "--api-key".to_string(),
            "sk-test".to_string(),
        ];
        match parse_command(&args).unwrap() {
            Command::Init(init) => {
                assert_eq!(init.base_url, "https://api.saiai.top");
                assert_eq!(init.api_key, "sk-test");
            }
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn local_proxy_env_removes_base_url_and_sets_ca() {
        let mut env_obj = Map::new();
        env_obj.insert(
            "ANTHROPIC_BASE_URL".to_string(),
            Value::String("https://old.example".to_string()),
        );
        env_obj.insert(
            "ANTHROPIC_AUTH_TOKEN".to_string(),
            Value::String("old-token".to_string()),
        );
        env_obj.insert(
            "CLAUDE_CODE_ATTRIBUTION_HEADER".to_string(),
            Value::String("old-attribution".to_string()),
        );
        apply_common_claude_env(&mut env_obj, "sk-test");
        apply_claude_local_proxy_env(
            &mut env_obj,
            "127.0.0.1:19908",
            Path::new("/tmp/saiai-ca.crt"),
        );

        assert!(env_obj.get("ANTHROPIC_BASE_URL").is_none());
        assert!(env_obj.get("ANTHROPIC_AUTH_TOKEN").is_none());
        assert!(env_obj.get("CLAUDE_CODE_ATTRIBUTION_HEADER").is_none());
        assert_eq!(json_str(&env_obj, "CLAUDE_CODE_OAUTH_TOKEN"), "sk-test");
        assert_eq!(json_str(&env_obj, "http_proxy"), "http://127.0.0.1:19908");
        assert_eq!(json_str(&env_obj, "https_proxy"), "http://127.0.0.1:19908");
        assert_eq!(json_str(&env_obj, "all_proxy"), "http://127.0.0.1:19908");
        assert_eq!(json_str(&env_obj, "no_proxy"), DEFAULT_NO_PROXY);
        assert!(env_obj.get("HTTP_PROXY").is_none());
        assert!(env_obj.get("HTTPS_PROXY").is_none());
        assert!(env_obj.get("ALL_PROXY").is_none());
        assert!(env_obj.get("NO_PROXY").is_none());
        assert!(json_str(&env_obj, "no_proxy").contains("downloads.claude.ai"));
        assert_eq!(
            json_str(&env_obj, "NODE_EXTRA_CA_CERTS"),
            "/tmp/saiai-ca.crt"
        );
    }

    #[test]
    fn detects_legacy_claude_settings_overrides() {
        let settings = serde_json::json!({
            "env": {
                "ANTHROPIC_MODEL": "deepseek-v4-pro[1m]",
                "CLAUDE_CODE_ATTRIBUTION_HEADER": "old-attribution",
                "CLAUDE_CODE_SUBAGENT_MODEL": "deepseek-v4-pro[1m]",
                "CLAUDE_CODE_EFFORT_LEVEL": "",
                "http_proxy": "http://127.0.0.1:19908"
            },
            "model": "opus[1m]",
            "permissions": {}
        });
        let locations = claude_settings_override_locations(settings.as_object().unwrap());

        assert_eq!(
            locations,
            vec![
                "ANTHROPIC_MODEL",
                "CLAUDE_CODE_ATTRIBUTION_HEADER",
                "CLAUDE_CODE_SUBAGENT_MODEL"
            ]
            .into_iter()
            .map(|key| format!("env.{key}"))
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn allows_any_claude_root_model_preference() {
        let settings = serde_json::json!({
            "env": {
                "http_proxy": "http://127.0.0.1:19908"
            },
            "model": "deepseek-v4-pro[1m]"
        });

        assert!(claude_settings_override_locations(settings.as_object().unwrap()).is_empty());
    }

    #[test]
    fn formats_legacy_claude_settings_overrides_with_limit() {
        let locations = (0..10)
            .map(|idx| format!("env.KEY_{idx}"))
            .collect::<Vec<_>>();

        assert_eq!(
            format_claude_settings_override_locations(&locations),
            "env.KEY_0, env.KEY_1, env.KEY_2, env.KEY_3, env.KEY_4, env.KEY_5, env.KEY_6, env.KEY_7, and 2 more"
        );
    }

    #[test]
    fn claude_settings_cleanup_removes_oauth_account() {
        let mut settings = Map::new();
        settings.insert("oauthAccount".to_string(), Value::Object(Map::new()));
        settings.insert("permissions".to_string(), Value::Object(Map::new()));

        clean_claude_settings(&mut settings);

        assert!(settings.get("oauthAccount").is_none());
        assert!(
            settings.get("permissions").is_some(),
            "unrelated settings must be preserved",
        );
    }

    #[test]
    fn claude_state_cleanup_removes_oauth_account() {
        let mut state = Map::new();
        state.insert("oauthAccount".to_string(), Value::Object(Map::new()));
        state.insert("hasCompletedOnboarding".to_string(), Value::Bool(false));
        state.insert(
            "userID".to_string(),
            Value::String("local-user".to_string()),
        );

        clean_claude_state(&mut state);

        assert!(state.get("oauthAccount").is_none());
        assert_eq!(
            state.get("hasCompletedOnboarding").and_then(Value::as_bool),
            Some(false),
            "onboarding state should be updated by init, not this cleanup helper",
        );
        assert_eq!(json_str(&state, "userID"), "local-user");
    }

    #[test]
    fn removes_credentials_file_after_backup() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".credentials.json");
        write_str(&path, r#"{"claudeAiOauth":{"accessToken":"old"}}"#);

        remove_if_exists_with_backup(&path, "20260527-010203").unwrap();

        assert!(!path.exists());
        let backup_path = PathBuf::from(format!("{}.bak-{}", path.display(), "20260527-010203"));
        assert_eq!(
            fs::read_to_string(backup_path).unwrap(),
            r#"{"claudeAiOauth":{"accessToken":"old"}}"#,
        );
    }
}
