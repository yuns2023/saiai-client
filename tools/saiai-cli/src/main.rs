use anyhow::{Context, Result, bail};
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
use std::fs::{self, OpenOptions};
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

mod local_proxy;

const ANTHROPIC_HOST: &str = "api.anthropic.com";
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
  saiai doctor                                                    # check local proxy and Claude config
  saiai --version                                                 # print version
  saiai init <base_url> <api_key>                                 # initialize Claude Code
  saiai init-codex <base_url> <api_key> [--websockets]            # initialize Codex CLI
  saiai init       --base-url <base_url> --api-key <api_key>      # initialize Claude Code
  saiai init-codex --base-url <base_url> --api-key <api_key> [--websockets]";

const SAIAI_CA_FILENAME: &str = "saiai-ca.crt";
const SAIAI_CA_KEY_FILENAME: &str = "saiai-ca.key";
const SAIAI_CONFIG_VERSION: u32 = 2;
const CLAUDE_STREAM_IDLE_TIMEOUT_MS: &str = "600000";
const DEFAULT_LOCAL_PROXY_LISTEN: &str = "127.0.0.1:19908";
const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local";
const SAIAI_CONFIG_FILENAME: &str = "config.json";

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
        Command::Doctor => run_doctor(),
        Command::Version => print_version(),
        Command::Init(init) => init_claude(init),
        Command::InitCodex(init) => init_codex(init),
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
    Doctor,
    Version,
    Init(InitArgs),
    InitCodex(InitArgs),
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
            if args.len() == 1 {
                return Ok(Command::Doctor);
            }
            bail!("Unexpected argument after doctor: {}\n\n{}", args[1], USAGE);
        }
        "-V" | "--version" | "version" => return Ok(Command::Version),
        "init" => return Ok(Command::Init(parse_named_args("init", &args[1..])?)),
        "init-codex" => {
            return Ok(Command::InitCodex(parse_named_args(
                "init-codex",
                &args[1..],
            )?));
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
            // `--websockets` is a boolean flag (no value). Only meaningful for
            // `init-codex`; reject it on `init` to surface mistakes early.
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

fn ensure_installation_ca(cert_path: &Path, key_path: &Path, timestamp: &str) -> Result<()> {
    if let (Ok(cert_pem), Ok(key_pem)) =
        (fs::read_to_string(cert_path), fs::read_to_string(key_path))
        && local_proxy::validate_tls_config(&cert_pem, &key_pem).is_ok()
    {
        return Ok(());
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
    Ok(())
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
    let ca_path = claude_dir.join(SAIAI_CA_FILENAME);
    let ca_key_path = claude_dir.join(SAIAI_CA_KEY_FILENAME);

    fs::create_dir_all(claude_dir)
        .with_context(|| format!("failed to create {}", claude_dir.display()))?;
    fs::create_dir_all(saiai_config_dir()?).context("failed to create SAIAI config directory")?;

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(settings_path, &timestamp)?;
    backup_if_exists(state_path, &timestamp)?;
    remove_if_exists_with_backup(credentials_path, &timestamp)?;

    ensure_installation_ca(&ca_path, &ca_key_path, &timestamp)?;

    let mut settings = load_json_object(settings_path)?;
    clean_claude_settings(&mut settings);
    let env_value = settings
        .remove("env")
        .and_then(as_object)
        .unwrap_or_default();
    let mut env_obj = env_value;
    apply_common_claude_env(&mut env_obj, &args.api_key);
    apply_claude_local_proxy_env(&mut env_obj, DEFAULT_LOCAL_PROXY_LISTEN, &ca_path);
    settings.insert("env".to_string(), Value::Object(env_obj));
    write_json_object(settings_path, Value::Object(settings))?;

    let mut state = load_json_object(state_path)?;
    clean_claude_state(&mut state);
    state.insert("hasCompletedOnboarding".to_string(), Value::Bool(true));
    write_json_object(state_path, Value::Object(state))?;

    write_saiai_config(&SaiaiConfig {
        version: SAIAI_CONFIG_VERSION,
        base_url: args.base_url,
        api_key: args.api_key,
        listen: DEFAULT_LOCAL_PROXY_LISTEN.to_string(),
        ca_cert_path: ca_path.display().to_string(),
        ca_key_path: ca_key_path.display().to_string(),
    })?;

    println!("SAIAI configured Claude Code for local proxy mode.");
    println!("Updated:");
    println!("  {}", settings_path.display());
    println!("  {}", state_path.display());
    println!("  {}", ca_path.display());
    println!("  {}", ca_key_path.display());
    println!("  {}", saiai_config_path()?.display());
    println!("Removed stale Claude OAuth credentials if present:");
    println!("  {}", credentials_path.display());
    println!();
    println!("Start the local proxy before using Claude Code:");
    println!("  saiai start");
    println!("Foreground mode is still available with:");
    println!("  saiai");
    warn_claude_settings_overrides_for_paths(&paths);

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

    merge_codex_config(&config_path, &args.base_url, args.websockets)?;
    merge_codex_auth(&auth_path, &args.api_key)?;

    println!("SAIAI configured Codex CLI for saiai gateway.");
    println!("Updated:");
    println!("  {}", config_path.display());
    println!("  {}", auth_path.display());
    if args.websockets {
        println!(
            "Default provider set to `OpenAI` pointing at SAIAI (wire_api = responses, websockets enabled)."
        );
    } else {
        println!("Default provider set to `OpenAI` pointing at SAIAI (wire_api = responses).");
    }
    println!("Existing TOML keys and JSON auth fields outside our scope were preserved.");
    warn_claude_settings_overrides();

    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
struct SaiaiConfig {
    version: u32,
    base_url: String,
    api_key: String,
    listen: String,
    ca_cert_path: String,
    #[serde(default)]
    ca_key_path: String,
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
    runtime.block_on(local_proxy::run(local_proxy::Config {
        listen: cfg.listen,
        base_url: cfg.base_url,
        api_key: cfg.api_key,
        ca_cert_pem,
        ca_key_pem,
        verbose,
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
    if !macos_launchd_running().unwrap_or(false) {
        ensure_listen_available(&cfg.listen)?;
    }
    let plist_path = write_launchd_plist()?;
    let domain = launchctl_gui_domain()?;
    let target = launchctl_service_target(&domain);
    let plist = plist_path.display().to_string();
    let _ = run_launchctl(&["bootout", &domain, &plist]);
    run_launchctl(&["bootstrap", &domain, &plist])?;
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_update() -> Result<()> {
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

    finalize_update(&current_exe, &candidate_path, &backup_path)?;

    println!("Updated: {}", candidate_version.trim());
    println!("Backup: {}", backup_path.display());
    println!("Restart service with: saiai restart");
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_update() -> Result<()> {
    bail!("saiai update currently supports Linux, macOS, and Windows assets only");
}

fn run_doctor() -> Result<()> {
    let mut report = DoctorReport::new();
    report.ok("version", format!("saiai {}", env!("CARGO_PKG_VERSION")));
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
    }

    match resolve_claude_config_paths() {
        Ok(paths) => check_claude_config(&mut report, cfg.as_ref(), &paths),
        Err(err) => report.error("Claude config", err.to_string()),
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
        match runtime.block_on(check_gateway_health(&cfg.base_url)) {
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
    if claude_root_model_looks_legacy_override(settings.get("model")) {
        locations.push("model".to_string());
    }
    locations
}

fn claude_root_model_looks_legacy_override(value: Option<&Value>) -> bool {
    let Some(Value::String(value)) = value else {
        return false;
    };
    let value = value.trim();
    !value.is_empty() && (value.contains('[') || value.starts_with("deepseek-"))
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

fn process_env_conflicts() -> Vec<&'static str> {
    CONFLICTING_ENV_VARS
        .iter()
        .copied()
        .filter(|key| env_var_is_set(key))
        .collect()
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
        scan_persistent_env_file(&path, &mut conflicts)?;
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

fn scan_persistent_env_file(path: &Path, conflicts: &mut Vec<PersistentEnvConflict>) -> Result<()> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    for (idx, line) in raw.lines().enumerate() {
        for key in CONFLICTING_ENV_VARS {
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

#[cfg(not(target_os = "linux"))]
fn check_systemd_user_env_conflicts(_report: &mut DoctorReport) {}

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
fn systemd_env_contains_key(output: &str, key: &str) -> bool {
    let prefix = format!("{key}=");
    output.lines().any(|line| line.starts_with(&prefix))
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
        report.ok("Claude overrides", "no legacy model/behavior overrides");
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
    check_env_equals(report, env, "HTTP_PROXY", &expected_proxy);
    check_env_equals(report, env, "HTTPS_PROXY", &expected_proxy);
    check_env_equals(report, env, "ALL_PROXY", &expected_proxy);
    check_env_contains(report, env, "NO_PROXY", "127.0.0.1");

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
                if value == cfg.api_key {
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
fn finalize_update(current_exe: &Path, candidate_path: &Path, backup_path: &Path) -> Result<()> {
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
fn finalize_update(current_exe: &Path, candidate_path: &Path, backup_path: &Path) -> Result<()> {
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
        "Windows update staged; replacement will finish after this process exits. If needed, run {} manually.",
        candidate_path.display()
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
) -> Result<String> {
    Ok(format!(
        "$ErrorActionPreference = 'Stop'\r\n\
try {{ Wait-Process -Id {pid} -Timeout 30 -ErrorAction SilentlyContinue }} catch {{}}\r\n\
Start-Sleep -Milliseconds 300\r\n\
Copy-Item -LiteralPath {} -Destination {} -Force\r\n\
Move-Item -LiteralPath {} -Destination {} -Force\r\n\
Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue\r\n",
        powershell_quote_path(current_exe)?,
        powershell_quote_path(backup_path)?,
        powershell_quote_path(candidate_path)?,
        powershell_quote_path(current_exe)?,
        powershell_quote_path(script_path)?,
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
fn write_launchd_plist() -> Result<PathBuf> {
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
    write_bytes_atomic(&plist_path, content.as_bytes(), 0o644)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;
    Ok(plist_path)
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
    Ok(command_output(MACOS_LAUNCHCTL_COMMAND, &["print", &target]).is_ok())
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
    let Some(pid) = windows_background_pid()? else {
        let _ = fs::remove_file(windows_pid_path()?);
        return Ok(());
    };
    if windows_pid_is_running(pid).unwrap_or(false) {
        let status = ProcessCommand::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .context("failed to run taskkill")?;
        if !status.success() {
            bail!("taskkill exited with {status}");
        }
    }
    let _ = fs::remove_file(windows_pid_path()?);
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
    env_obj.insert("HTTP_PROXY".to_string(), Value::String(proxy_url.clone()));
    env_obj.insert("HTTPS_PROXY".to_string(), Value::String(proxy_url.clone()));
    env_obj.insert("ALL_PROXY".to_string(), Value::String(proxy_url));
    env_obj.insert(
        "NO_PROXY".to_string(),
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

fn write_saiai_config(config: &SaiaiConfig) -> Result<()> {
    let path = saiai_config_path()?;
    let parent = path
        .parent()
        .context("failed to resolve SAIAI config parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let value = serde_json::to_value(config).context("failed to serialize SAIAI config")?;
    write_json_object(&path, value)
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

/// Merge SAIAI's provider definition into `~/.codex/config.toml`, preserving any
/// unrelated tables, comments and field ordering already written by the user
/// or by `codex login`. CLI-managed root defaults are always rewritten to the
/// values shipped with this binary (idempotent overwrite); unrelated keys are
/// left untouched. When `websockets` is true, the SAIAI WebSocket transport is
/// enabled; when false, any previously-written WebSocket config is removed.
///
/// The provider is written under the `OpenAI` namespace (matching the
/// historical name produced by both `codex login` and the admin UI's earlier
/// manual config), keeping Codex's session/cache identity continuous across
/// the manual-config → init-codex transition.
fn merge_codex_config(path: &Path, base_url: &str, websockets: bool) -> Result<()> {
    let raw = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    let mut doc: DocumentMut = if raw.trim().is_empty() {
        DocumentMut::new()
    } else {
        raw.parse::<DocumentMut>().with_context(|| {
            format!(
                "failed to parse {} as TOML (existing file preserved as backup; not modified)",
                path.display()
            )
        })?
    };

    merge_codex_root_defaults(&mut doc);
    merge_codex_openai_provider(&mut doc, base_url, websockets, path)?;
    merge_codex_features(&mut doc, websockets, path)?;

    fs::write(path, doc.to_string())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Write CLI-managed root-level defaults. Each call rewrites these keys to the
/// values shipped with this binary, even if the user previously customized
/// them — same idempotent-overwrite contract as `init` (Claude). Unknown root
/// keys are left untouched.
fn merge_codex_root_defaults(doc: &mut DocumentMut) {
    doc["model"] = value("gpt-5.6-sol");
    doc["review_model"] = value("gpt-5.4");
    doc["model_reasoning_effort"] = value("xhigh");
    doc["disable_response_storage"] = value(true);
    doc["network_access"] = value("enabled");
    doc["windows_wsl_setup_acknowledged"] = value(true);
    doc["model_context_window"] = value(1_000_000_i64);
    doc["model_auto_compact_token_limit"] = value(900_000_i64);
    doc["model_provider"] = value("OpenAI");
}

/// Upsert `[model_providers.OpenAI]` with the gateway's contract fields. Other
/// providers under `[model_providers]` (e.g. a user's experimental local
/// proxy registered as `[model_providers.local]`) and any unknown keys inside
/// `[model_providers.OpenAI]` itself (e.g. user-set `query_params`, custom
/// headers) are preserved. When `websockets` is false, the managed
/// `supports_websockets` key is explicitly removed so toggling off via
/// `init-codex` (no flag) is reversible.
///
/// `name` is intentionally pinned to `"OpenAI"`, matching the namespace key.
/// We do NOT preserve a user-set `name` — Codex CLI may use this string in
/// internal indices/UI, and aligning name with namespace minimizes surprises
/// when a user is migrating from manual config or v0.3.0.
fn merge_codex_openai_provider(
    doc: &mut DocumentMut,
    base_url: &str,
    websockets: bool,
    path: &Path,
) -> Result<()> {
    // Refuse to silently overwrite if `model_providers` exists but isn't a
    // table — same posture as `merge_codex_auth`'s non-object guard. The
    // backup is already on disk, so the user can inspect and resolve.
    match doc.get("model_providers") {
        None => doc["model_providers"] = Item::Table(Table::new()),
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has a `model_providers` entry that is not a table; refusing to overwrite (backup is preserved)",
            path.display()
        ),
    }
    let providers = doc["model_providers"]
        .as_table_mut()
        .expect("model_providers ensured to be a table above");

    match providers.get("OpenAI") {
        None => {
            providers.insert("OpenAI", Item::Table(Table::new()));
        }
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has `[model_providers.OpenAI]` set to a non-table value; refusing to overwrite (backup is preserved)",
            path.display()
        ),
    }
    let openai = providers
        .get_mut("OpenAI")
        .and_then(Item::as_table_mut)
        .expect("[model_providers.OpenAI] ensured to be a table above");

    // `Table::insert` replaces in-place when the key already exists, preserving
    // surrounding formatting; new keys append.
    openai.insert("name", value("OpenAI"));
    openai.insert("base_url", value(base_url));
    // wire_api must remain "responses": the saiai backend dropped the
    // /v1/chat/completions compatibility layer (see backend changelog).
    openai.insert("wire_api", value("responses"));
    // Codex 0.149.0+ requires this flag for custom providers to use the
    // credential stored in auth.json instead of rejecting the request with
    // API_KEY_REQUIRED / 401.
    openai.insert("requires_openai_auth", value(true));
    // Drop any `env_key` written by older SAIAI helper builds. Setting it to
    // `OPENAI_API_KEY` made Codex prefer the shell env over the api_key
    // SAIAI writes into ~/.codex/auth.json — a footgun whenever the user
    // already had OPENAI_API_KEY exported. We rely on auth.json instead.
    openai.remove("env_key");
    if websockets {
        openai.insert("supports_websockets", value(true));
    } else {
        openai.remove("supports_websockets");
    }
    Ok(())
}

/// Toggle the managed `[features].responses_websockets_v2` key. Other
/// `[features]` entries written by the user are preserved. When the table is
/// left empty after removing our managed key, the entire `[features]` table is
/// dropped to keep the file clean.
fn merge_codex_features(doc: &mut DocumentMut, websockets: bool, path: &Path) -> Result<()> {
    if websockets {
        match doc.get("features") {
            None => doc["features"] = Item::Table(Table::new()),
            Some(item) if item.is_table() => {}
            Some(_) => bail!(
                "{} has a `features` entry that is not a table; refusing to overwrite (backup is preserved)",
                path.display()
            ),
        }
        let features = doc["features"]
            .as_table_mut()
            .expect("features ensured to be a table above");
        features.insert("responses_websockets_v2", value(true));
        return Ok(());
    }

    // websockets == false: refuse non-table `features` symmetrically with the
    // ws=true branch (the user's malformed value would otherwise be silently
    // left in place, defeating the intent of "explicit cleanup"). Then remove
    // our managed key and drop the table if empty.
    match doc.get("features") {
        None => return Ok(()),
        Some(item) if item.is_table() => {}
        Some(_) => bail!(
            "{} has a `features` entry that is not a table; refusing to overwrite (backup is preserved)",
            path.display()
        ),
    }
    let features_now_empty;
    {
        let features = doc["features"]
            .as_table_mut()
            .expect("features ensured to be a table above");
        features.remove("responses_websockets_v2");
        features_now_empty = features.is_empty();
    }
    if features_now_empty {
        doc.as_table_mut().remove("features");
    }
    Ok(())
}

/// Upsert `OPENAI_API_KEY` into `~/.codex/auth.json` while preserving every
/// other field. If the file exists but isn't a JSON object, refuse to write so
/// we don't silently destroy a non-standard auth payload (the backup is
/// already on disk).
fn merge_codex_auth(path: &Path, api_key: &str) -> Result<()> {
    let mut auth: Map<String, Value> = if !path.exists() {
        Map::new()
    } else {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if raw.trim().is_empty() {
            Map::new()
        } else {
            let parsed: Value = serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            match parsed {
                Value::Object(map) => map,
                _ => bail!(
                    "{} exists but is not a JSON object; refusing to overwrite (backup is preserved)",
                    path.display()
                ),
            }
        }
    };

    auth.insert(
        "OPENAI_API_KEY".to_string(),
        Value::String(api_key.to_string()),
    );
    write_json_object(path, Value::Object(auth))
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

    fn parse(path: &Path) -> DocumentMut {
        read_str(path).parse::<DocumentMut>().unwrap()
    }

    fn temp_config() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        (dir, path)
    }

    fn assert_managed_root(doc: &DocumentMut) {
        assert_eq!(doc["model"].as_str(), Some("gpt-5.6-sol"));
        assert_eq!(doc["review_model"].as_str(), Some("gpt-5.4"));
        assert_eq!(doc["model_reasoning_effort"].as_str(), Some("xhigh"));
        assert_eq!(doc["disable_response_storage"].as_bool(), Some(true));
        assert_eq!(doc["network_access"].as_str(), Some("enabled"));
        assert_eq!(doc["windows_wsl_setup_acknowledged"].as_bool(), Some(true));
        assert_eq!(doc["model_context_window"].as_integer(), Some(1_000_000));
        assert_eq!(
            doc["model_auto_compact_token_limit"].as_integer(),
            Some(900_000),
        );
        assert_eq!(doc["model_provider"].as_str(), Some("OpenAI"));
    }

    fn assert_managed_provider(doc: &DocumentMut, base_url: &str, websockets: bool) {
        let openai = &doc["model_providers"]["OpenAI"];
        assert_eq!(openai["name"].as_str(), Some("OpenAI"));
        assert_eq!(openai["base_url"].as_str(), Some(base_url));
        assert_eq!(openai["wire_api"].as_str(), Some("responses"));
        assert_eq!(openai["requires_openai_auth"].as_bool(), Some(true));
        assert!(
            openai.get("env_key").is_none(),
            "env_key must not be set; Codex would otherwise prefer shell env over auth.json",
        );
        if websockets {
            assert_eq!(openai["supports_websockets"].as_bool(), Some(true));
        } else {
            assert!(
                openai.get("supports_websockets").is_none(),
                "expected supports_websockets to be absent when websockets=false",
            );
        }
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
            Command::Doctor => {}
            _ => panic!("expected doctor command"),
        }
        match parse_command(&["--version".to_string()]).unwrap() {
            Command::Version => {}
            _ => panic!("expected version command"),
        }
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
        assert_eq!(json_str(&env_obj, "HTTP_PROXY"), "http://127.0.0.1:19908");
        assert_eq!(json_str(&env_obj, "HTTPS_PROXY"), "http://127.0.0.1:19908");
        assert_eq!(json_str(&env_obj, "ALL_PROXY"), "http://127.0.0.1:19908");
        assert_eq!(json_str(&env_obj, "NO_PROXY"), DEFAULT_NO_PROXY);
        assert!(
            !json_str(&env_obj, "NO_PROXY").contains("downloads.claude.ai"),
            "product domains should not be maintained in NO_PROXY",
        );
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
                "HTTP_PROXY": "http://127.0.0.1:19908"
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
                "CLAUDE_CODE_SUBAGENT_MODEL",
                "model"
            ]
            .into_iter()
            .map(|key| {
                if key == "model" {
                    key.to_string()
                } else {
                    format!("env.{key}")
                }
            })
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn allows_native_claude_root_model_preference() {
        let settings = serde_json::json!({
            "env": {
                "HTTP_PROXY": "http://127.0.0.1:19908"
            },
            "model": "sonnet"
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

    #[test]
    fn fresh_dir_ws_off_writes_managed_defaults_and_no_features_table() {
        let (_dir, path) = temp_config();
        merge_codex_config(&path, "https://example.com", false).unwrap();

        let doc = parse(&path);
        assert_managed_root(&doc);
        assert_managed_provider(&doc, "https://example.com", false);
        assert!(
            doc.get("features").is_none(),
            "features table should not exist when websockets=false on fresh file",
        );
    }

    #[test]
    fn fresh_dir_ws_on_writes_supports_websockets_and_features_flag() {
        let (_dir, path) = temp_config();
        merge_codex_config(&path, "https://example.com", true).unwrap();

        let doc = parse(&path);
        assert_managed_root(&doc);
        assert_managed_provider(&doc, "https://example.com", true);
        assert_eq!(
            doc["features"]["responses_websockets_v2"].as_bool(),
            Some(true),
        );
    }

    #[test]
    fn preserves_unrelated_tables_and_overwrites_managed_openai_keys() {
        let (_dir, path) = temp_config();
        write_str(
            &path,
            r#"model = "gpt-5.5"
custom_root = "kept"

[foo]
bar = "baz"

[features]
other_flag = true
responses_websockets_v2 = false

[model_providers.local]
name = "Local"
base_url = "https://local.example"

[model_providers.OpenAI]
name = "Old OpenAI"
base_url = "https://old.example"
wire_api = "chat"
requires_openai_auth = true
env_key = "OLD_KEY"
query_params = { foo = "bar" }
custom_header = "kept"
"#,
        );

        merge_codex_config(&path, "https://example.com", true).unwrap();

        let doc = parse(&path);
        // Unrelated tables preserved.
        assert_eq!(doc["custom_root"].as_str(), Some("kept"));
        assert_eq!(doc["foo"]["bar"].as_str(), Some("baz"));
        assert_eq!(doc["features"]["other_flag"].as_bool(), Some(true));
        assert_eq!(
            doc["model_providers"]["local"]["name"].as_str(),
            Some("Local"),
        );
        // Unknown keys inside [model_providers.OpenAI] preserved.
        assert_eq!(
            doc["model_providers"]["OpenAI"]["custom_header"].as_str(),
            Some("kept"),
        );
        assert_eq!(
            doc["model_providers"]["OpenAI"]["query_params"]["foo"].as_str(),
            Some("bar"),
        );

        // Managed fields rewritten — including the previously-overridden ones.
        assert_managed_root(&doc);
        assert_managed_provider(&doc, "https://example.com", true);
        assert_eq!(
            doc["features"]["responses_websockets_v2"].as_bool(),
            Some(true),
        );
    }

    #[test]
    fn ws_toggle_off_clears_managed_ws_keys_and_keeps_unrelated_features() {
        let (_dir, path) = temp_config();
        write_str(&path, "[features]\nother_flag = true\n");

        merge_codex_config(&path, "https://example.com", true).unwrap();
        merge_codex_config(&path, "https://example.com", false).unwrap();

        let doc = parse(&path);
        assert!(
            doc["model_providers"]["OpenAI"]
                .get("supports_websockets")
                .is_none(),
        );
        assert!(doc["features"].get("responses_websockets_v2").is_none());
        assert_eq!(doc["features"]["other_flag"].as_bool(), Some(true));
    }

    #[test]
    fn ws_off_drops_features_table_when_only_managed_key_remained() {
        let (_dir, path) = temp_config();
        write_str(&path, "[features]\nresponses_websockets_v2 = true\n");

        merge_codex_config(&path, "https://example.com", false).unwrap();

        let doc = parse(&path);
        assert!(
            doc.get("features").is_none(),
            "empty features table should be dropped",
        );
    }

    #[test]
    fn ws_off_keeps_features_table_when_unrelated_keys_remain() {
        let (_dir, path) = temp_config();
        write_str(
            &path,
            "[features]\nother_flag = true\nresponses_websockets_v2 = true\n",
        );

        merge_codex_config(&path, "https://example.com", false).unwrap();

        let doc = parse(&path);
        assert!(doc.get("features").is_some());
        assert_eq!(doc["features"]["other_flag"].as_bool(), Some(true));
        assert!(doc["features"].get("responses_websockets_v2").is_none());
    }

    #[test]
    fn idempotent_when_run_twice_with_same_args() {
        let (_dir, path) = temp_config();
        merge_codex_config(&path, "https://example.com", true).unwrap();
        let first = read_str(&path);
        merge_codex_config(&path, "https://example.com", true).unwrap();
        let second = read_str(&path);
        assert_eq!(second, first);
    }

    #[test]
    fn user_root_override_is_reset_to_managed_default() {
        let (_dir, path) = temp_config();
        write_str(&path, "model = \"gpt-5.5\"\nreview_model = \"gpt-5.5\"\n");

        merge_codex_config(&path, "https://example.com", false).unwrap();

        let doc = parse(&path);
        assert_eq!(doc["model"].as_str(), Some("gpt-5.6-sol"));
        assert_eq!(doc["review_model"].as_str(), Some("gpt-5.4"));
    }

    #[test]
    fn rejects_non_table_model_providers() {
        let (_dir, path) = temp_config();
        write_str(&path, "model_providers = \"not a table\"\n");
        let err = merge_codex_config(&path, "https://example.com", false).unwrap_err();
        assert!(
            format!("{err}").contains("model_providers"),
            "error should mention model_providers, got: {err}",
        );
    }

    #[test]
    fn rejects_non_table_features() {
        let (_dir, path) = temp_config();
        write_str(&path, "features = \"not a table\"\n");
        let err = merge_codex_config(&path, "https://example.com", true).unwrap_err();
        assert!(
            format!("{err}").contains("features"),
            "error should mention features, got: {err}",
        );
    }

    #[test]
    fn rejects_non_table_features_on_ws_off_too() {
        // Symmetric guard: ws=false should also refuse a malformed `features`
        // entry rather than silently leaving it in place.
        let (_dir, path) = temp_config();
        write_str(&path, "features = \"not a table\"\n");
        let err = merge_codex_config(&path, "https://example.com", false).unwrap_err();
        assert!(
            format!("{err}").contains("features"),
            "error should mention features, got: {err}",
        );
    }

    #[test]
    fn ws_off_rejects_inline_features_table_same_as_ws_on() {
        // Both `merge_codex_features` and the existing `merge_codex_saiai_provider`
        // guard accept only standard tables (`is_table`), not inline tables
        // (`features = { ... }`). Codex itself always writes standard tables, so
        // an inline-table value indicates user-edited unusual state — we refuse
        // and let the user resolve via the on-disk backup. This test pins that
        // contract and matches the symmetric ws=true behavior.
        let (_dir, path) = temp_config();
        write_str(&path, "features = { responses_websockets_v2 = true }\n");
        let err = merge_codex_config(&path, "https://example.com", false).unwrap_err();
        assert!(
            format!("{err}").contains("features"),
            "error should mention features, got: {err}",
        );
    }

    #[test]
    fn merge_codex_auth_unaffected_by_ws_flag() {
        let (_dir_cfg, cfg_path) = temp_config();
        let auth_dir = TempDir::new().unwrap();
        let auth_path = auth_dir.path().join("auth.json");

        merge_codex_auth(&auth_path, "sk-test").unwrap();
        let auth_after_first = fs::read(&auth_path).unwrap();

        // Toggle ws on then off through the config path; auth.json must not
        // change.
        merge_codex_config(&cfg_path, "https://example.com", true).unwrap();
        merge_codex_config(&cfg_path, "https://example.com", false).unwrap();

        merge_codex_auth(&auth_path, "sk-test").unwrap();
        let auth_after_second = fs::read(&auth_path).unwrap();
        assert_eq!(auth_after_first, auth_after_second);
    }
}
