use anyhow::{Context, Result, bail};
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

mod brand;
// The kernel's test brand (unit-test fallback brand).
#[cfg(test)]
mod brand_test;
mod claude_desktop;
mod claude_desktop_fixtures;
mod claude_launcher;
mod codex_daemon;
mod codex_diagnostics;
#[cfg(any(test, feature = "contract"))]
#[doc(hidden)]
pub mod contract;
mod desktop_product;
mod environment_scope;
mod gateway;
// The kernel's test Gateway extension (unit-test runtime fallback).
#[cfg(test)]
mod gateway_test;
mod local_proxy;
mod runtime;
mod script_brand;
mod uninstall;
// Fixed-URL self-update: redirects, limits, manifest and asset checks.
#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod update_fixed_tests;
mod upstream_proxy;
mod upstream_tls;
mod vscode;
#[cfg(target_os = "windows")]
mod windows_background;
#[cfg(any(windows, test))]
mod windows_desktop_runtime;

use brand::{BRAND, BrandText, BrandValue};
pub use brand::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, FixedUpdateSource, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames, UpdateSource,
};
use desktop_product::DesktopProduct;
pub use gateway::{
    ConfiguredRoute, GatewayExtension, GatewayHttp, GatewaySession, GatewayStart,
    NativeChatProtocol, NoGatewayExtension, SignInput, StateFile, Transport, wire_target,
};
pub use runtime::RuntimeContext;

const ANTHROPIC_HOST: &str = "api.anthropic.com";
#[cfg(target_os = "linux")]
const LOCAL_PROXY_NSS_CERT_NICKNAME: BrandValue<&'static str> =
    BrandValue(|brand| brand.certificates.nss_nickname);
const USAGE: BrandText = BrandText(|| {
    format!(
        "\
Usage:
  {brand_binary} --environment claude|codex|default <command>              # select a proxy environment
  {brand_binary}                                                           # run the local proxy (Claude Code and Codex)
  {brand_binary} --verbose                                                 # run local proxy with request logs
  {brand_binary} start                                                     # install and start user service
  {brand_binary} stop                                                      # stop and disable user service
  {brand_binary} status                                                    # show user service status
  {brand_binary} logs                                                      # follow user service logs
  {brand_binary} update                                                    # update this client binary
  {brand_binary} restart                                                   # restart user service
  {brand_binary} doctor [claude|codex]                                    # check proxy and product config
  {brand_binary} --version                                                 # print version
  {brand_binary} init <base_url> <api_key>                                 # initialize Claude Code
  {brand_binary} init-codex <base_url> <api_key> [--websockets]            # initialize Codex CLI
  {brand_binary} claude [-- <claude arguments>]                            # launch Claude with a child-only {brand_product} environment
  {brand_binary} codex [-- <codex arguments>]                              # launch Codex through {brand_product} local proxy
  {brand_binary} vscode                                                    # configure the Codex VSCode extension for {brand_product}
  {brand_binary} desktop [codex|claude] [-- <Desktop arguments>]         # Claude: Linux Code only
  {brand_binary} doctor --desktop claude                                  # check Claude Desktop adapter
  {brand_binary} uninstall [--yes] [--dry-run] [--forget-unknown-environments]  # remove {brand_product} services, settings, data and program
  {brand_binary} upstream-proxy [system|direct|http://host:port]         # show or set the proxy {brand_product} itself uses
  {brand_binary} init       --base-url <base_url> --api-key <api_key>      # initialize Claude Code
  {brand_binary} init-codex --base-url <base_url> --api-key <api_key> [--websockets]
Initialization uses provider-specific CA files and preserves VSCode editor settings.
Use --configure-vscode-editor with init/init-codex to opt into the editor-wide proxy.
On Windows, --trust-vscode-ca also opts into CurrentUser Root trust and editor setup;
use it only after consenting to this user-wide trust.",
        brand_binary = BRAND.binary_name,
        brand_product = BRAND.product_name
    )
});

const CA_FILENAME: BrandValue<&'static str> =
    BrandValue(|brand| brand.certificates.ca_cert_filename);
const CA_KEY_FILENAME: BrandValue<&'static str> =
    BrandValue(|brand| brand.certificates.ca_key_filename);
#[cfg(target_os = "windows")]
const WINDOWS_PACKAGED_PROXY_LEASE_FILENAME: &str = "windows-packaged-proxy-lease.json";
const CONFIG_VERSION: BrandValue<u32> = BrandValue(|brand| brand.config.version);
const CLAUDE_STREAM_IDLE_TIMEOUT_MS: &str = "600000";
const DEFAULT_LOCAL_PROXY_LISTEN: &str = "127.0.0.1:19908";
// Claude's updater goes through the local proxy like everything else; the
// local proxy follows the user's network (proxy or direct) for passthrough
// destinations such as downloads.claude.ai.
const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local";
// Written by Client 1.1.0–1.1.57; recognized by uninstall and migrated at
// local proxy startup.
const LEGACY_DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local,downloads.claude.ai";
const CONFIG_FILENAME: BrandValue<&'static str> = BrandValue(|brand| brand.config.filename);

// The `codex` command owns these variables only in the Codex child process. The
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
const CODEX_IDE_ENV_BEGIN: BrandValue<&'static str> =
    BrandValue(|brand| brand.markers.codex_ide_env_begin);
const CODEX_IDE_ENV_END: BrandValue<&'static str> =
    BrandValue(|brand| brand.markers.codex_ide_env_end);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CODEX_CERTIFICATE_CONTROL_HOST: BrandValue<&'static str> =
    BrandValue(|brand| brand.certificates.control_host);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CODEX_CERTIFICATE_SPKI_HEADER: BrandValue<&'static str> =
    BrandValue(|brand| brand.certificates.spki_header);
const CODEX_PLACEHOLDER_ACCOUNT_ID: BrandValue<&'static str> =
    BrandValue(|brand| brand.placeholders.codex_account_id);
// Structurally valid but unsigned and therefore unusable against OpenAI. The
// local proxy replaces request authentication at the Gateway boundary; these
// claims only let Codex's local app-server expose an authenticated UI state.
const CODEX_PLACEHOLDER_ID_TOKEN: BrandValue<&'static str> =
    BrandValue(|brand| brand.placeholders.codex_token);
// Electron's Desktop shell decodes the access token as a JWT before it asks
// its app-server for account state. Reuse the unsigned local-only token for
// both fields; the local proxy replaces authorization before Gateway egress.
const CODEX_PLACEHOLDER_ACCESS_TOKEN: BrandValue<&'static str> = CODEX_PLACEHOLDER_ID_TOKEN;

// Explicit opt-in only: when set to an IANA zone, the launcher exports `TZ`
// to the Desktop child process (never the parent shell or the system). There
// is no default override. It is not a privacy control for Codex requests:
// Codex resolves its timezone through iana-time-zone, which ignores `TZ` on
// Linux and Windows. Codex time reporting is disabled through the managed
// `include_environment_context_time = false` configuration key instead.
const CHATGPT_TIMEZONE_ENV: BrandValue<&'static str> =
    BrandValue(|brand| brand.env.chatgpt_timezone);

// Codex >= 0.163.0 omits the machine timezone and current date from the
// model-visible <environment_context> only when this top-level key is false.
// The program manages it in every Codex profile it prepares.
const CODEX_ENVIRONMENT_CONTEXT_TIME_KEY: &str = "include_environment_context_time";

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

#[cfg(target_os = "macos")]
const MACOS_ID_COMMAND: &str = "/usr/bin/id";
#[cfg(target_os = "macos")]
const MACOS_LAUNCHCTL_COMMAND: &str = "/bin/launchctl";
#[cfg(target_os = "macos")]
const MACOS_TAIL_COMMAND: &str = "/usr/bin/tail";
#[cfg(target_os = "linux")]
const LINUX_PID_FILENAME: BrandValue<&'static str> = BrandValue(|brand| brand.service.pid_filename);
#[cfg(target_os = "linux")]
const LINUX_LOCK_FILENAME: BrandValue<&'static str> =
    BrandValue(|brand| brand.service.lock_filename);
#[cfg(target_os = "linux")]
const LINUX_BACKGROUND_COMMAND: &str = "__run-background-proxy";
#[cfg(target_os = "linux")]
const LINUX_BACKGROUND_STATE_VERSION: u32 = 1;
#[cfg(target_os = "windows")]
const WINDOWS_PID_FILENAME: BrandValue<&'static str> =
    BrandValue(|brand| brand.service.pid_filename);
#[cfg(target_os = "windows")]
const WINDOWS_BACKGROUND_COMMAND: &str = "__run-background-proxy";
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const SERVICE_LOG_FILENAME: BrandValue<&'static str> =
    BrandValue(|brand| brand.service.log_filename);

fn is_managed_claude_env(key: &str) -> bool {
    CLAUDE_MANAGED_ROUTING_ENV
        .iter()
        .any(|candidate| key.eq_ignore_ascii_case(candidate))
        || CLAUDE_MANAGED_ROUTING_ENV_PREFIXES
            .iter()
            .any(|prefix| key.to_ascii_uppercase().starts_with(prefix))
}

/// Runs one command of the client as the program described by `distribution`
/// (names, directories, services, certificates, …). A process runs as one
/// brand: pass the same `static` instance if `run` is called again. `context` carries facts
/// about the final program (its release version) that the library must not
/// take from its own package metadata.
pub fn run(distribution: &'static Brand, context: RuntimeContext) -> Result<()> {
    brand::install(distribution)?;
    runtime::install(context)?;
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let selector = environment_scope::parse_selector(&mut args)?;
    let command = parse_command(&args)?;
    if matches!(command, Command::Uninstall(_)) && selector.is_some() {
        bail!(
            "`{brand_binary} uninstall` covers every {brand_product} environment; remove the environment selector\n\n{USAGE}",
            brand_binary = BRAND.binary_name,
            brand_product = BRAND.product_name
        );
    }
    environment_scope::initialize(&command, selector)?;
    match &command {
        Command::Init(_) | Command::InitCodex(_) => environment_scope::record_product_dir(true)?,
        Command::Start | Command::Restart => environment_scope::record_product_dir(false)?,
        _ => {}
    }
    #[cfg(target_os = "windows")]
    if matches!(
        &command,
        Command::Version | Command::Status | Command::Update | Command::Doctor(_)
    ) {
        warn_incomplete_windows_update();
    }
    match command {
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
        Command::ClaudeDesktopDoctor => claude_desktop::doctor(),
        Command::Version => print_version(),
        Command::Init(init) => init_claude(init),
        Command::InitCodex(init) => init_codex(init),
        Command::Claude(args) => claude_launcher::run(&args),
        Command::Codex(args) => run_codex(&args),
        Command::VSCode => configure_vscode(),
        Command::Desktop { product, args } => run_desktop(product, &args),
        Command::Uninstall(args) => uninstall::run(args),
        Command::UpstreamProxy(value) => run_upstream_proxy_command(value),
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
    ClaudeDesktopDoctor,
    Version,
    Init(InitArgs),
    InitCodex(InitArgs),
    Claude(Vec<String>),
    Codex(Vec<String>),
    VSCode,
    Desktop {
        product: DesktopProduct,
        args: Vec<String>,
    },
    Uninstall(uninstall::Args),
    UpstreamProxy(Option<String>),
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
    /// Opt into editor-wide proxy settings independently of provider setup.
    configure_vscode_editor: bool,
    /// Explicit consent for optional Windows current-user CA trust and editor setup.
    trust_vscode_ca: bool,
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
            if args.get(1).map(String::as_str) == Some("--desktop")
                && args.get(2).map(String::as_str) == Some("claude")
                && args.len() == 3
            {
                return Ok(Command::ClaudeDesktopDoctor);
            }
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
        "claude" => {
            let mut claude_args = args[1..].to_vec();
            if claude_args.first().is_some_and(|arg| arg == "--") {
                claude_args.remove(0);
            }
            return Ok(Command::Claude(claude_args));
        }
        "codex" => {
            let mut codex_args = args[1..].to_vec();
            if codex_args.first().is_some_and(|arg| arg == "--") {
                codex_args.remove(0);
            }
            return Ok(Command::Codex(codex_args));
        }
        "vscode" => return parse_no_arg_command("vscode", &args[1..], Command::VSCode),
        "uninstall" => return Ok(Command::Uninstall(uninstall::parse_args(&args[1..])?)),
        "upstream-proxy" => {
            return match &args[1..] {
                [] => Ok(Command::UpstreamProxy(None)),
                [value] => Ok(Command::UpstreamProxy(Some(value.clone()))),
                [_, extra, ..] => {
                    bail!("Unexpected argument after upstream-proxy: {extra}\n\n{USAGE}")
                }
            };
        }
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
        LINUX_BACKGROUND_COMMAND => {
            return parse_no_arg_command(
                LINUX_BACKGROUND_COMMAND,
                &args[1..],
                Command::RunLinuxBackgroundProxy,
            );
        }
        #[cfg(target_os = "windows")]
        WINDOWS_BACKGROUND_COMMAND => {
            if args.len() == 2 && args[1] == "--instance-v2" {
                return Ok(Command::RunWindowsBackgroundProxy);
            }
            return parse_no_arg_command(
                WINDOWS_BACKGROUND_COMMAND,
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
    let mut configure_vscode_editor = false;
    let mut trust_vscode_ca = false;
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
            "--trust-vscode-ca" if cfg!(windows) => {
                trust_vscode_ca = true;
            }
            "--configure-vscode-editor" => {
                configure_vscode_editor = true;
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
        configure_vscode_editor,
        trust_vscode_ca,
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
    local_proxy::validate_tls_config(&cert_pem, &key_pem).with_context(|| {
        format!(
            "generated {brand_product} installation CA did not validate",
            brand_product = BRAND.product_name
        )
    })?;
    write_bytes_atomic(cert_path, cert_pem.as_bytes(), 0o644)
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    write_bytes_atomic(key_path, key_pem.as_bytes(), 0o600)
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok(true)
}

fn generate_installation_ca() -> Result<(String, String)> {
    let key = KeyPair::generate().with_context(|| {
        format!(
            "failed to generate {brand_product} installation CA key",
            brand_product = BRAND.product_name
        )
    })?;
    let mut params = CertificateParams::new(Vec::<String>::new()).with_context(|| {
        format!(
            "failed to create {brand_product} installation CA parameters",
            brand_product = BRAND.product_name
        )
    })?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut distinguished_name = DistinguishedName::new();
    // A per-installation suffix keeps a regenerated CA from sharing its
    // subject name with a stale installation CA of this program left in an OS trust store.
    let suffix: String = Sha256::digest(key.public_key_der())[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    distinguished_name.push(
        DnType::CommonName,
        format!("{} {suffix}", BRAND.certificates.ca_common_name_prefix),
    );
    distinguished_name.push(DnType::OrganizationName, BRAND.certificates.ca_organization);
    params.distinguished_name = distinguished_name;
    let certificate = params.self_signed(&key).with_context(|| {
        format!(
            "failed to self-sign {brand_product} installation CA",
            brand_product = BRAND.product_name
        )
    })?;
    Ok((certificate.pem(), key.serialize_pem()))
}

fn lock_initialization() -> Result<fs::File> {
    let file = open_initialization_lock()?;
    file.lock().with_context(|| {
        format!(
            "failed to lock {brand_product} initialization",
            brand_product = BRAND.product_name
        )
    })?;
    Ok(file)
}

/// `None` while another process initializes.
fn try_lock_initialization() -> Result<Option<fs::File>> {
    let file = open_initialization_lock()?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(error)) => Err(error).with_context(|| {
            format!(
                "failed to lock {brand_product} initialization",
                brand_product = BRAND.product_name
            )
        }),
    }
}

fn open_initialization_lock() -> Result<fs::File> {
    let directory = environment_scope::active()
        .map(|s| s.root.clone())
        .unwrap_or(app_config_dir()?);
    fs::create_dir_all(&directory)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(directory.join("initialization.lock"))?)
}

fn init_claude(args: InitArgs) -> Result<()> {
    let _initialization_lock = lock_initialization()?;
    warn_process_env_conflicts();
    let paths = resolve_claude_config_paths().context("failed to resolve Claude config paths")?;
    let claude_dir = &paths.config_dir;
    let settings_path = &paths.settings_path;
    let state_path = &paths.state_path;
    let credentials_path = &paths.credentials_path;
    let ca_dir = if environment_scope::isolated() {
        app_config_dir()?
    } else {
        claude_dir.clone()
    };
    let default_ca_path = ca_dir.join(CA_FILENAME.get());
    let default_ca_key_path = ca_dir.join(CA_KEY_FILENAME.get());
    let (ca_path, ca_key_path) =
        existing_runtime_ca_paths().unwrap_or((default_ca_path, default_ca_key_path));

    fs::create_dir_all(claude_dir)
        .with_context(|| format!("failed to create {}", claude_dir.display()))?;
    fs::create_dir_all(app_config_dir()?).with_context(|| {
        format!(
            "failed to create {brand_product} config directory",
            brand_product = BRAND.product_name
        )
    })?;

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(settings_path, &timestamp)?;
    backup_if_exists(state_path, &timestamp)?;
    remove_if_exists_with_backup(credentials_path, &timestamp)?;

    let ca_changed = ensure_installation_ca(&ca_path, &ca_key_path, &timestamp)?;

    let app_config = update_app_provider_config(
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
    apply_claude_local_proxy_env(&mut env_obj, &app_config.config.listen, &ca_path);
    settings.insert("env".to_string(), Value::Object(env_obj));
    write_json_object(settings_path, Value::Object(settings))?;

    let mut state = load_json_object(state_path)?;
    clean_claude_state(&mut state);
    state.insert("hasCompletedOnboarding".to_string(), Value::Bool(true));
    write_json_object(state_path, Value::Object(state))?;

    println!(
        "{brand_product} configured Claude Code for local proxy mode.",
        brand_product = BRAND.product_name
    );
    println!("Updated:");
    println!("  {}", settings_path.display());
    println!("  {}", state_path.display());
    println!("  {}", ca_path.display());
    println!("  {}", ca_key_path.display());
    println!("  {}", app_config_path()?.display());
    println!("Removed stale Claude OAuth credentials if present:");
    println!("  {}", credentials_path.display());
    warn_claude_settings_overrides_for_paths(&paths);
    configure_vscode_editor_after_initialization(
        &app_config.config.listen,
        &ca_path,
        "Claude Code",
        args.configure_vscode_editor,
        args.trust_vscode_ca,
    );
    start_managed_service_after_initialization(app_config.changed || ca_changed)?;

    Ok(())
}

fn init_codex(args: InitArgs) -> Result<()> {
    let _initialization_lock = lock_initialization()?;
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
    if !environment_scope::isolated() {
        ensure_direct_linux_desktop_trust(&proxy_init.ca_cert_path);
    }
    configure_vscode_editor_after_initialization(
        &proxy_init.listen,
        &proxy_init.ca_cert_path,
        "Codex CLI",
        args.configure_vscode_editor,
        args.trust_vscode_ca,
    );

    println!(
        "{brand_product} configured Codex for local-proxy OAuth mode.",
        brand_product = BRAND.product_name
    );
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
        "{brand_product} local-proxy OAuth configuration is ready; run `{brand_binary} codex`. Fully quit and reopen VSCode after its editor setup succeeds.",
        brand_binary = BRAND.binary_name,
        brand_product = BRAND.product_name
    );
    start_managed_service_after_initialization(proxy_init.config_changed)?;
    codex_daemon::after_initialization(&codex_dir);

    Ok(())
}

struct CodexLocalProxyInit {
    config_path: PathBuf,
    config_changed: bool,
    listen: String,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
}

struct AppConfigUpdate {
    config: AppConfig,
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
    migrate_codex_local_proxy_auth(&auth_path)?;
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
    let config_dir = app_config_dir()?;
    initialize_codex_local_proxy_at(&config_dir, args, timestamp)
}

fn initialize_codex_local_proxy_at(
    config_dir: &Path,
    args: &InitArgs,
    timestamp: &str,
) -> Result<CodexLocalProxyInit> {
    fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create {}", config_dir.display()))?;
    let config_path = config_dir.join(CONFIG_FILENAME.get());
    let proxy_base_url = codex_proxy_gateway_root(&args.base_url)?;

    if let Ok(raw) = fs::read_to_string(&config_path)
        && let Ok(existing) = serde_json::from_str::<AppConfig>(&raw)
        && read_runtime_ca(&existing).is_ok()
    {
        let mut migrated_legacy = false;
        if existing.providers.claude.is_none()
            && existing.providers.codex.is_none()
            && !environment_scope::isolated()
            && legacy_claude_proxy_configured()
        {
            let mut migrated = existing;
            migrated.providers.claude = Some(ProviderCredential {
                base_url: migrated.base_url.clone(),
                api_key: migrated.api_key.clone(),
            });
            write_app_config_at(&config_path, &migrated)?;
            migrated_legacy = true;
        }
        let updated = update_app_provider_config_at(
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

    // A missing CA or an obsolete layout forces a rebuild, but an explicit
    // choice to turn off Desktop browser and Computer Use control, or an
    // upstream proxy choice, must survive it.
    let existing = fs::read_to_string(&config_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    let desktop_browser_use = existing
        .as_ref()
        .and_then(|existing| existing.get("desktop_browser_use")?.as_bool())
        .unwrap_or(true);
    let upstream_proxy = existing
        .as_ref()
        .and_then(|existing| existing.get("upstream_proxy")?.as_str())
        .map(str::to_string);
    backup_if_exists(&config_path, timestamp)?;
    let ca_cert_path = config_dir.join(CA_FILENAME.get());
    let ca_key_path = config_dir.join(CA_KEY_FILENAME.get());
    let _ca_changed = ensure_installation_ca(&ca_cert_path, &ca_key_path, timestamp)?;
    let mut config = AppConfig {
        version: CONFIG_VERSION.get(),
        base_url: proxy_base_url.clone(),
        api_key: args.api_key.clone(),
        listen: select_local_proxy_listen(None)?,
        ca_cert_path: ca_cert_path.display().to_string(),
        ca_key_path: ca_key_path.display().to_string(),
        chatgpt_chat_passthrough: true,
        desktop_browser_use,
        upstream_proxy,
        providers: ProviderCredentials::default(),
    };
    config.providers.codex = Some(ProviderCredential {
        base_url: proxy_base_url,
        api_key: args.api_key.clone(),
    });
    write_app_config_at(&config_path, &config)?;
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

/// Launch the real Codex executable with a child-only local proxy environment.
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
    let cfg = read_app_config().with_context(|| {
        format!(
            "{brand_product} local proxy is not configured; run `{brand_binary} init-codex` first",
            brand_binary = BRAND.binary_name,
            brand_product = BRAND.product_name
        )
    })?;
    let _runtime_ca = read_runtime_ca(&cfg).with_context(|| {
        format!(
            "{brand_product} local proxy CA is unavailable; rerun the {brand_product} setup",
            brand_product = BRAND.product_name
        )
    })?;
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

    println!(
        "Starting Codex through the {brand_product} local proxy.",
        brand_product = BRAND.product_name
    );
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

/// Configure both the Codex app-server environment and the VSCode editor's
/// native HTTP route. Windows current-user CA trust requires explicit consent.
fn configure_vscode() -> Result<()> {
    let codex_dir = codex_config_dir().context("failed to resolve Codex config directory")?;
    fs::create_dir_all(&codex_dir)
        .with_context(|| format!("failed to create {}", codex_dir.display()))?;
    let auth_path = codex_dir.join("auth.json");
    let cfg = read_app_config().with_context(|| {
        format!(
            "{brand_product} local proxy is not configured; run the {brand_product} setup first",
            brand_product = BRAND.product_name
        )
    })?;
    let _runtime_ca = read_runtime_ca(&cfg).with_context(|| {
        format!(
            "{brand_product} local proxy CA is unavailable; rerun the {brand_product} setup",
            brand_product = BRAND.product_name
        )
    })?;

    let files = prepare_codex_oauth_files(&codex_dir, true)?;
    ensure_codex_local_proxy_auth(&auth_path)?;
    validate_codex_oauth_auth(&auth_path)?;
    let env_path = codex_dir.join(".env");
    write_codex_ide_env(&env_path, &cfg.listen, &cfg.ca_cert_path)?;
    configure_vscode_editor_proxy(&cfg.listen, Path::new(&cfg.ca_cert_path))?;
    ensure_local_proxy_running(&cfg.listen)?;

    println!(
        "{brand_product} configured the Codex VSCode extension for local proxy mode.",
        brand_product = BRAND.product_name
    );
    println!("  CODEX_HOME={}", codex_dir.display());
    println!("  environment={}", env_path.display());
    println!("  proxy=http://{}", cfg.listen);
    println!(
        "  migrated {} Codex config file(s) with backups",
        files.len()
    );
    println!("Fully quit and reopen VSCode before starting a new Codex session.");
    Ok(())
}

fn configure_vscode_editor_after_initialization(
    listen: &str,
    ca_cert: &Path,
    provider: &str,
    configure_editor: bool,
    trust_vscode_ca: bool,
) {
    if !configure_editor && !trust_vscode_ca {
        println!(
            "{provider} uses its CA file. VSCode editor settings and OS certificate stores were preserved; editor-wide proxy setup is optional (--configure-vscode-editor)."
        );
        return;
    }
    if let Err(error) = configure_vscode_editor_proxy_with_consent(listen, ca_cert, trust_vscode_ca)
    {
        eprintln!(
            "WARN VSCode editor setup is incomplete: {error:#}; {provider} remains configured."
        );
    }
}

fn configure_vscode_editor_proxy(listen: &str, ca_cert: &Path) -> Result<()> {
    configure_vscode_editor_proxy_with_consent(listen, ca_cert, false)
}

fn configure_vscode_editor_proxy_with_consent(
    listen: &str,
    ca_cert: &Path,
    trust_vscode_ca: bool,
) -> Result<()> {
    let home = home_dir().context("failed to resolve VSCode's home directory")?;
    let paths = vscode::settings_paths(&home);
    if paths.is_empty() {
        println!("No existing VSCode user settings directory was found; editor setup was skipped.");
        return Ok(());
    }
    vscode::preflight(&home, listen)?;
    let trusted = vscode::certificate_trust(&home, ca_cert)?;
    #[cfg(windows)]
    let trusted = if !trusted && trust_vscode_ca {
        println!(
            "Trusting this installation's {brand_product} CA in Windows CurrentUser\\Root. Other applications of this Windows user also trust it; the system proxy and TLS verification are unchanged.",
            brand_product = BRAND.product_name
        );
        vscode::trust_windows_current_user_ca(ca_cert)?;
        vscode::certificate_trust(&home, ca_cert)?
    } else {
        trusted
    };
    #[cfg(not(windows))]
    let _ = trust_vscode_ca;
    if !trusted {
        bail!(
            "Optional editor-wide setup requires VSCode's certificate loader to trust the {brand_product} CA; editor settings were preserved. Provider-specific CA configuration remains available. On Windows, --trust-vscode-ca explicitly authorizes CurrentUser Root trust; TLS verification will not be disabled.",
            brand_product = BRAND.product_name
        );
    }
    let changed = vscode::configure(&home, listen)?;
    println!(
        "Configured VSCode's editor-wide HTTP proxy ({} settings file(s) updated with backups). Other extensions share this route; the system proxy is unchanged.",
        changed.len()
    );
    println!(
        "VSCode's certificate loader recognizes the {brand_product} CA. TLS verification remains enabled; fully quit and reopen the editor to load the new route.",
        brand_product = BRAND.product_name
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

struct StrippedCodexIdeEnv {
    content: String,
    /// Every BEGIN marker had a matching END marker.
    complete: bool,
}

/// Remove only the managed BEGIN/END block lines, byte-for-byte preserving the
/// rest. The blank separator the program writes before a trailing block goes too.
fn strip_codex_ide_env_block(raw: &str) -> StrippedCodexIdeEnv {
    let lines = raw.split_inclusive('\n').collect::<Vec<_>>();
    let mut keep = vec![true; lines.len()];
    let mut in_managed_block = false;
    let mut last_begin = None;
    let mut last_end = None;
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == CODEX_IDE_ENV_BEGIN.get() {
            in_managed_block = true;
            last_begin = Some(index);
            keep[index] = false;
        } else if trimmed == CODEX_IDE_ENV_END.get() {
            in_managed_block = false;
            last_end = Some(index);
            keep[index] = false;
        } else if in_managed_block {
            keep[index] = false;
        }
    }
    let trailing_block = match (last_begin, last_end) {
        (Some(_), _) if in_managed_block => last_begin,
        (Some(begin), Some(end)) if lines[end + 1..].iter().all(|l| l.trim().is_empty()) => {
            Some(begin)
        }
        _ => None,
    };
    if let Some(begin) = trailing_block
        && begin > 0
        && keep[begin - 1]
        && lines[begin - 1].trim().is_empty()
    {
        keep[begin - 1] = false;
    }
    StrippedCodexIdeEnv {
        content: lines
            .iter()
            .zip(keep)
            .filter_map(|(line, keep)| keep.then_some(*line))
            .collect(),
        complete: !in_managed_block,
    }
}

fn merge_codex_ide_env(raw: &str, listen: &str, ca_cert_path: &str) -> String {
    let stripped = strip_codex_ide_env_block(raw).content;
    let mut kept = Vec::new();
    for line in stripped.lines() {
        if dotenv_assignment_key(line).is_some_and(is_managed_codex_env) {
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
    kept.push(CODEX_IDE_ENV_BEGIN.get());
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
    output.push_str(CODEX_IDE_ENV_END.get());
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
    let mut launch_args = Vec::with_capacity(args.len() + 8);
    if !codex_args_override_feature(args, "respect_system_proxy") {
        launch_args.push("-c".to_string());
        launch_args.push(format!(
            "features.respect_system_proxy={}",
            codex_respect_system_proxy_enabled()
        ));
    }
    // Codex defaults OTEL metrics to its hosted Statsig endpoint at
    // ab.chatgpt.com. That non-model control plane can be unreachable on the
    // same networks that require this proxy and should not delay or add errors to
    // a local-proxy model session. Keep this child-only and honor an explicit
    // caller override.
    if !codex_args_override_config_key(args, "otel.metrics_exporter") {
        launch_args.push("-c".to_string());
        launch_args.push("otel.metrics_exporter=\"none\"".to_string());
    }
    // The synthetic local identity cannot authenticate Codex's hosted Apps MCP
    // endpoint. Disable that optional control plane for this launcher so it
    // does not emit a misleading startup failure. A caller can explicitly
    // re-enable it and that later argument wins.
    if !codex_args_override_feature(args, "apps") {
        launch_args.push("-c".to_string());
        launch_args.push("features.apps=false".to_string());
    }
    // Keep Codex time reporting off for this launch even if a config layer
    // outside the managed files re-enables it. An explicit caller override
    // wins.
    if !codex_args_override_config_key(args, CODEX_ENVIRONMENT_CONTEXT_TIME_KEY) {
        launch_args.push("-c".to_string());
        launch_args.push("include_environment_context_time=false".to_string());
    }
    launch_args.extend(args.iter().cloned());
    launch_args
}

fn codex_respect_system_proxy_enabled() -> bool {
    // On Windows and macOS the feature gives platform system-proxy discovery
    // precedence over HTTP_PROXY/HTTPS_PROXY. A DIRECT system decision
    // therefore bypasses the child-only local proxy environment. Reqwest and
    // Tungstenite both honor those variables in transport-default mode.
    // Linux has no platform resolver, so the feature only falls back to the
    // same variables there; keep it off too, because Codex 0.167+ lists
    // enabled experimental features in `x-codex-beta-features`.
    false
}

fn codex_args_override_feature(args: &[String], feature: &str) -> bool {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        // Everything after `--` is positional (for example a prompt), not a
        // Codex configuration override.
        if arg == "--" {
            break;
        }
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
        // Everything after `--` is positional (for example a prompt), not a
        // Codex configuration override.
        if arg == "--" {
            break;
        }
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

/// What to do with a real ChatGPT login already present in auth.json.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExistingCodexAuth {
    /// Keep it; warn when its access token has expired.
    Keep,
    /// `init-codex`: back up and replace it once its access token has
    /// expired. Desktop shows its sign-in page when the refresh token behind
    /// an expired login has been revoked, and the program cannot check that offline.
    ReplaceExpired,
    /// Always write the local placeholder.
    Replace,
}

fn ensure_codex_local_proxy_auth(path: &Path) -> Result<()> {
    write_codex_local_proxy_auth(path, ExistingCodexAuth::Keep)
}

fn migrate_codex_local_proxy_auth(path: &Path) -> Result<()> {
    write_codex_local_proxy_auth(path, ExistingCodexAuth::ReplaceExpired)
}

fn replace_codex_local_proxy_auth(path: &Path) -> Result<()> {
    write_codex_local_proxy_auth(path, ExistingCodexAuth::Replace)
}

fn write_codex_local_proxy_auth(path: &Path, existing: ExistingCodexAuth) -> Result<()> {
    write_codex_local_proxy_auth_at(path, existing, Utc::now().timestamp())
}

fn write_codex_local_proxy_auth_at(
    path: &Path,
    existing: ExistingCodexAuth,
    now_epoch_seconds: i64,
) -> Result<()> {
    let existed = path.exists();
    let original = if existed {
        Some(fs::read(path).with_context(|| format!("failed to read {}", path.display()))?)
    } else {
        None
    };
    let mut auth = match &original {
        Some(bytes) => parse_json_object_bytes(path, bytes)?,
        None => Map::new(),
    };
    let mut expired_backup = None;
    if existing != ExistingCodexAuth::Replace {
        match real_codex_oauth_expiry(&auth) {
            None => {}
            Some(Some(expires_at)) if expires_at <= now_epoch_seconds => {
                let expired = format_epoch_seconds(expires_at);
                if existing == ExistingCodexAuth::Keep {
                    eprintln!(
                        "WARN {}: the ChatGPT access token expired at {expired}; if Codex asks you to sign in, quit it and run `{brand_binary} init-codex` to switch to the {brand_product} local-proxy login.",
                        path.display(),
                        brand_binary = BRAND.binary_name,
                        brand_product = BRAND.product_name
                    );
                    return Ok(());
                }
                let original = original.as_deref().unwrap_or_default();
                let backup = write_expired_login_backup(path, original, now_epoch_seconds)?;
                println!(
                    "The ChatGPT access token in {} expired at {expired}; saved the original login to {}.",
                    path.display(),
                    backup.display()
                );
                // Skip the replacement when Codex rewrote the login after it
                // was read. This narrows, but cannot close, the race window.
                let current = fs::read(path)
                    .with_context(|| format!("failed to re-read {}", path.display()))?;
                if current != original {
                    bail!(
                        "{} changed while {brand_product} was replacing its expired login and was left unchanged; quit Codex and rerun `{brand_binary} init-codex`",
                        path.display(),
                        brand_binary = BRAND.binary_name,
                        brand_product = BRAND.product_name
                    );
                }
                expired_backup = Some(backup);
            }
            Some(_) => return Ok(()),
        }
    }

    auth.insert(
        "auth_mode".to_string(),
        // Codex owns refresh-token rotation in `chatgpt` mode. The program's
        // synthetic local identity is supplied by an external host and must
        // never be sent to the provider refresh endpoint, so use Codex's
        // dedicated external-token mode instead.
        Value::String("chatgptAuthTokens".to_string()),
    );
    auth.insert(
        "tokens".to_string(),
        serde_json::json!({
            "id_token": CODEX_PLACEHOLDER_ID_TOKEN.get(),
            "access_token": CODEX_PLACEHOLDER_ACCESS_TOKEN.get(),
            "refresh_token": "",
            "account_id": CODEX_PLACEHOLDER_ACCOUNT_ID.get()
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
    if let Some(backup) = expired_backup {
        println!(
            "To use your own ChatGPT login again, quit Codex, copy {} back to {} and sign in again if Codex asks.",
            backup.display(),
            path.display()
        );
    }
    Ok(())
}

fn is_codex_placeholder_access_token(token: &str) -> bool {
    token.starts_with(BRAND.placeholders.legacy_codex_token_prefix)
        || token == CODEX_PLACEHOLDER_ACCESS_TOKEN.get()
}

/// `None` when auth.json holds no real ChatGPT login; otherwise the access
/// token's `exp`, which is `None` when the token is not a readable JWT.
fn real_codex_oauth_expiry(auth: &Map<String, Value>) -> Option<Option<i64>> {
    let auth_mode = auth.get("auth_mode").and_then(Value::as_str).unwrap_or("");
    let access_token = auth
        .get("tokens")
        .and_then(Value::as_object)
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(auth_mode, "chatgpt" | "chatgptAuthTokens")
        || access_token.trim().is_empty()
        || is_codex_placeholder_access_token(access_token)
    {
        return None;
    }
    Some(codex_jwt_expiry(access_token))
}

/// Reads `exp` from a three-part JWT without verifying it.
fn codex_jwt_expiry(token: &str) -> Option<i64> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice::<Value>(&decoded)
        .ok()?
        .get("exp")?
        .as_i64()
}

fn format_epoch_seconds(epoch_seconds: i64) -> String {
    chrono::DateTime::<Utc>::from_timestamp(epoch_seconds, 0)
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("epoch {epoch_seconds}"))
}

/// Writes `data` to a new `<path>.bak-expired-login-<timestamp>[-n]` and
/// returns its path. The `expired-login` infix keeps it out of the names
/// `backup_if_exists` overwrites, and an existing file is never replaced.
fn write_expired_login_backup(path: &Path, data: &[u8], now_epoch_seconds: i64) -> Result<PathBuf> {
    let timestamp = chrono::DateTime::<Utc>::from_timestamp(now_epoch_seconds, 0)
        .unwrap_or_default()
        .format("%Y%m%d-%H%M%S");
    for attempt in 0..100 {
        let suffix = if attempt == 0 {
            String::new()
        } else {
            format!("-{attempt}")
        };
        let backup = PathBuf::from(format!(
            "{}.bak-expired-login-{timestamp}{suffix}",
            path.display()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&backup) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to create backup {}", backup.display()));
            }
        };
        if let Err(err) = file.write_all(data).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&backup);
            return Err(err)
                .with_context(|| format!("failed to write backup {}", backup.display()));
        }
        return Ok(backup);
    }
    bail!("could not find a free backup name for {}", path.display())
}

/// A warning when auth.json holds a real ChatGPT login whose access token has
/// expired. Read-only; used by the Desktop launcher and doctor.
fn codex_auth_expiry_warning(path: &Path) -> Result<Option<String>> {
    let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let auth = parse_json_object_bytes(path, &raw)?;
    let Some(Some(expires_at)) = real_codex_oauth_expiry(&auth) else {
        return Ok(None);
    };
    Ok((expires_at <= Utc::now().timestamp()).then(|| {
        format!(
            "the ChatGPT access token in {} expired at {}; Codex shows its sign-in page if the login can no longer be refreshed. Quit Codex and run `{brand_binary} init-codex` to switch to the {brand_product} local-proxy login.",
            path.display(),
            format_epoch_seconds(expires_at), brand_binary = BRAND.binary_name, brand_product = BRAND.product_name
        )
    }))
}

fn run_desktop(product: DesktopProduct, args: &[String]) -> Result<()> {
    if product == DesktopProduct::Claude {
        return claude_desktop::run(args);
    }
    if !product.has_adapter() {
        bail!(
            "{brand_product} Desktop currently supports Codex only; ordinary ChatGPT history and settings are not supported. Use `{brand_binary} desktop codex`.",
            brand_binary = BRAND.binary_name,
            brand_product = BRAND.product_name
        );
    }

    println!(
        "{brand_product} Desktop scope: Codex only; the official ChatGPT sidebar, ordinary Chat history, and settings are not supported.",
        brand_product = BRAND.product_name
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
            "{brand_product} Desktop integration is currently implemented for Linux, macOS, and Windows only",
            brand_product = BRAND.product_name
        );
    }
}

#[cfg(target_os = "linux")]
fn run_linux_desktop(product: DesktopProduct, args: &[String]) -> Result<()> {
    let cfg = read_app_config().with_context(|| {
        format!(
            "{brand_product} local proxy is not configured",
            brand_product = BRAND.product_name
        )
    })?;
    let _runtime_ca = read_runtime_ca(&cfg).with_context(|| {
        format!(
            "{brand_product} local proxy CA is unavailable; rerun the {brand_product} setup",
            brand_product = BRAND.product_name
        )
    })?;
    ensure_local_proxy_running(&cfg.listen)?;

    let desktop_root = app_config_dir()?.join("desktop");
    let desktop_home = desktop_root.join("home");
    let desktop_codex = desktop_root.join("codex");
    let desktop_user_data = desktop_root.join("user-data");
    fs::create_dir_all(&desktop_codex)
        .with_context(|| format!("failed to create {}", desktop_codex.display()))?;
    fs::create_dir_all(&desktop_user_data)
        .with_context(|| format!("failed to create {}", desktop_user_data.display()))?;
    prepare_isolated_desktop_state(&desktop_root, &desktop_codex)?;
    ensure_desktop_nss_ca(&desktop_home, &cfg.ca_cert_path)?;

    let executable = env::var_os(BRAND.env.chatgpt_bin)
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
    // Do not pass the program's control variable into Electron. If configured,
    // apply the validated IANA timezone only to this Desktop child process.
    command.env_remove(CHATGPT_TIMEZONE_ENV.get());
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

    println!(
        "Starting ChatGPT Desktop through the {brand_product} local proxy.",
        brand_product = BRAND.product_name
    );
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
    let cfg = read_app_config().with_context(|| {
        format!(
            "{brand_product} local proxy is not configured",
            brand_product = BRAND.product_name
        )
    })?;
    let _runtime_ca = read_runtime_ca(&cfg).with_context(|| {
        format!(
            "{brand_product} local proxy CA is unavailable; rerun the {brand_product} setup",
            brand_product = BRAND.product_name
        )
    })?;
    ensure_local_proxy_running(&cfg.listen)?;

    let packaged_bundle = if resolve_macos_desktop_override()?.is_none() {
        resolve_macos_codex_bundle()?
    } else {
        None
    };

    let desktop_root = app_config_dir()?.join("desktop");
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
    // terminal pipe from the program's wrapper.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in CODEX_MANAGED_ENV {
        command.env_remove(*name);
    }
    command.env_remove(CHATGPT_TIMEZONE_ENV.get());
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

    println!(
        "Starting ChatGPT Desktop through the {brand_product} local proxy.",
        brand_product = BRAND.product_name
    );
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
        "ChatGPT.app or Codex.app was not found in /Applications or ~/Applications; install an official Desktop app or set {brand_desktop_bin_env}",
        brand_desktop_bin_env = BRAND.env.desktop_bin
    )
}

#[cfg(target_os = "macos")]
fn resolve_macos_desktop_override() -> Result<Option<PathBuf>> {
    for variable in [BRAND.env.desktop_bin, BRAND.env.chatgpt_bin] {
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
    let cfg = read_app_config().with_context(|| {
        format!(
            "{brand_product} local proxy is not configured",
            brand_product = BRAND.product_name
        )
    })?;
    let _runtime_ca = read_runtime_ca(&cfg).with_context(|| {
        format!(
            "{brand_product} local proxy CA is unavailable; rerun the {brand_product} setup",
            brand_product = BRAND.product_name
        )
    })?;
    if resolve_windows_desktop_override()?.is_none()
        && let Some(package) = resolve_windows_packaged_desktop()?
    {
        return run_windows_packaged_desktop(product, args, &cfg, &package);
    }
    ensure_local_proxy_running(&cfg.listen)?;

    let desktop_root = app_config_dir()?.join("desktop");
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
    command.env_remove(CHATGPT_TIMEZONE_ENV.get());
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

    println!(
        "Starting OpenAI Desktop through the {brand_product} local proxy.",
        brand_product = BRAND.product_name
    );
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
    cfg: &AppConfig,
    package: &WindowsPackagedDesktop,
) -> Result<()> {
    if !args.is_empty() {
        bail!("packaged Windows Desktop does not accept passthrough arguments");
    }
    // AppX activation is brokered by Windows. Unlike CreateProcess, it cannot
    // inherit a child-only CODEX_HOME or proxy environment from this launcher.
    // Require the user's already-managed Codex profile before touching the
    // running Desktop; never silently start against an unconfigured profile.
    if env::var_os("CODEX_HOME").is_some() {
        bail!(
            "packaged Windows Desktop cannot inherit CODEX_HOME; use the standard Windows Codex profile or a non-packaged Desktop override"
        );
    }
    if env::var_os(CHATGPT_TIMEZONE_ENV.get()).is_some() {
        bail!("packaged Windows Desktop cannot inherit a child-only timezone override");
    }
    let codex_home = codex_config_dir()?;
    let env_path = codex_home.join(".env");
    let current_env = fs::read_to_string(&env_path).with_context(|| {
        format!(
            "failed to read {}; run `{brand_binary} init-codex` first",
            env_path.display(),
            brand_binary = BRAND.binary_name
        )
    })?;
    if !current_env.contains(CODEX_IDE_ENV_BEGIN.get())
        || current_env != merge_codex_ide_env(&current_env, &cfg.listen, &cfg.ca_cert_path)
    {
        bail!(
            "packaged Windows Desktop needs the current {brand_product} Codex profile; run `{brand_binary} vscode` or `{brand_binary} init-codex` and retry",
            brand_binary = BRAND.binary_name,
            brand_product = BRAND.product_name
        );
    }
    validate_codex_oauth_auth(&codex_home.join("auth.json")).with_context(|| format!("packaged Windows Desktop needs a configured Codex account; run `{brand_binary} init-codex` first", brand_binary = BRAND.binary_name))?;
    match codex_auth_expiry_warning(&codex_home.join("auth.json")) {
        Ok(None) => {}
        Ok(Some(warning)) => eprintln!("WARN {warning}"),
        Err(err) => eprintln!("WARN could not check the Codex login expiry: {err:#}"),
    }
    // The packaged Desktop reads the standard profile that the `init-codex`
    // and `vscode` commands prepare; this launcher never rewrites it. Point at the
    // fix instead of silently launching with Codex time reporting enabled.
    if !matches!(
        read_codex_environment_context_time(&codex_home.join("config.toml")),
        Ok(CodexEnvironmentContextTime::Disabled)
    ) {
        eprintln!(
            "WARN {} does not set `{CODEX_ENVIRONMENT_CONTEXT_TIME_KEY} = false`; Codex may report the local timezone. Run `{brand_binary} init-codex`, then fully quit and reopen Desktop.",
            codex_home.join("config.toml").display(),
            brand_binary = BRAND.binary_name
        );
    }
    let session_id = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Process -Id $PID).SessionId",
        ],
    )?;
    if session_id.trim() == "0" {
        bail!(
            "packaged Windows Desktop must be started from the signed-in desktop session, not SSH or a Windows service session"
        );
    }
    let profile = windows_packaged_profile(cfg, &codex_home)?;
    let mut observer = windows_desktop_runtime::PackageObserver::new(package.clone());
    let initial = observer.inspect()?;
    let directory = PathBuf::from(&initial.runtime_directory);
    let receipt_path = directory.join("instance.json");
    let receipt = if initial.actor_count == 0 {
        None
    } else {
        windows_desktop_runtime::read_receipt(&receipt_path)?
    };
    windows_desktop_runtime::decide(&initial, &profile, receipt.as_ref())?;
    windows_desktop_runtime::protect_directory(&directory)?;
    let _launch_lock = windows_desktop_runtime::lock(&directory)?;
    let snapshot = observer.inspect()?;
    if snapshot.runtime_directory != initial.runtime_directory {
        bail!("Windows Desktop runtime directory changed during startup");
    }
    let receipt = if snapshot.actor_count == 0 {
        None
    } else {
        windows_desktop_runtime::read_receipt(&receipt_path)?
    };
    let decision = windows_desktop_runtime::decide(&snapshot, &profile, receipt.as_ref())?;
    if matches!(decision, windows_desktop_runtime::Decision::Cold) {
        ensure_local_proxy_running(&cfg.listen)?;
    }
    let proxy = &profile.proxy;
    let spki = local_proxy_chatgpt_spki(&cfg.listen).context(
        "Desktop proxy is unavailable; a running Desktop is never silently rebound or restarted",
    )?;
    if let windows_desktop_runtime::Decision::Reuse(prior) = &decision
        && prior.window.spki.as_deref() != Some(spki.as_str())
    {
        bail!("Desktop certificate binding changed; use normal File > Quit and retry");
    }
    if matches!(decision, windows_desktop_runtime::Decision::Cold) {
        restore_legacy_windows_packaged_proxy_lease()?;
    }

    // Toast replies and other shell activations carry no launcher arguments.
    // Use the package's default Electron profile so those activations join
    // this proxy-bound instance instead of opening an unproxied second one.
    let target = if matches!(decision, windows_desktop_runtime::Decision::Cold) {
        let workspace = env::current_dir().context("failed to resolve the Desktop workspace")?;
        Some(codex_new_thread_url(&workspace))
    } else {
        None
    };
    let activation_args =
        windows_packaged_desktop_activation_args(&proxy, &spki, target.as_deref());
    let before = observer.inspect()?;
    if windows_packaged_profile(cfg, &codex_home)? != profile
        || windows_desktop_runtime::decide(&before, &profile, receipt.as_ref())? != decision
        || local_proxy_chatgpt_spki(&cfg.listen)? != spki
    {
        bail!("Desktop context changed; use normal File > Quit and retry");
    }
    let not_before = u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() / 100 + 116_444_736_000_000_000,
    )?;
    let _broker_pid = activate_windows_packaged_desktop(&package.app_id, &activation_args)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let observed = loop {
        if std::time::Instant::now() >= deadline {
            bail!("Signed Windows Desktop window was not observed before the startup deadline");
        }
        let current = observer
            .inspect()
            .context("Could not inspect the newly activated Windows Desktop")?;
        if let Some(observed) = windows_desktop_runtime::accept_window(
            &current,
            observer.identity()?,
            &profile,
            &spki,
            &decision,
            not_before,
        )
        .context("Could not verify the newly activated Windows Desktop window")?
        {
            break observed;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    std::thread::sleep(Duration::from_millis(300));
    let stable = observer
        .inspect()
        .context("Could not inspect Windows Desktop after activation settled")?;
    if windows_desktop_runtime::accept_window(
        &stable,
        observer.identity()?,
        &profile,
        &spki,
        &decision,
        not_before,
    )
    .context("Could not verify Windows Desktop after activation settled")?
        != Some(observed.clone())
        || windows_packaged_profile(cfg, &codex_home)? != profile
        || local_proxy_chatgpt_spki(&cfg.listen)? != spki
    {
        bail!("Desktop window or proxy binding changed during startup; no instance was adopted");
    }
    if matches!(decision, windows_desktop_runtime::Decision::Cold) {
        windows_desktop_runtime::write_receipt(&directory, &observed)?;
    }
    let pid = observed.window.process_id;
    println!(
        "Starting packaged OpenAI Desktop through the {brand_product} local proxy.",
        brand_product = BRAND.product_name
    );
    println!("  product={}", product.label());
    println!("  app_id={}", package.app_id);
    println!("  pid={pid}");
    println!(
        "  existing-instance={}",
        if matches!(decision, windows_desktop_runtime::Decision::Reuse(_)) {
            "reused"
        } else {
            "cold launch"
        }
    );
    println!("  CODEX_HOME={} (standard profile)", codex_home.display());
    println!("  user-data-dir=packaged Desktop default (shared with notification activation)");
    println!("  environment={}", env_path.display());
    println!("  proxy={proxy} (Desktop activation arguments only)");
    println!("  certificate-trust=process-scoped SPKI pins");
    println!("  Windows system proxy=unchanged");
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_packaged_profile(
    cfg: &AppConfig,
    codex_home: &Path,
) -> Result<windows_desktop_runtime::Profile> {
    use std::io::Read;
    let current_env = fs::read_to_string(codex_home.join(".env"))?;
    if !current_env.contains(CODEX_IDE_ENV_BEGIN.get())
        || current_env != merge_codex_ide_env(&current_env, &cfg.listen, &cfg.ca_cert_path)
    {
        bail!(
            "Desktop managed profile changed; run `{brand_binary} init-codex` and retry after normal Quit",
            brand_binary = BRAND.binary_name
        );
    }
    validate_codex_oauth_auth(&codex_home.join("auth.json"))?;
    let mut certificate = Vec::new();
    fs::File::open(&cfg.ca_cert_path)?
        .take(65537)
        .read_to_end(&mut certificate)?;
    if certificate.is_empty() || certificate.len() > 65536 {
        bail!("Desktop CA certificate exceeds its supported bounds");
    }
    Ok(windows_desktop_runtime::Profile {
        codex_home: codex_home
            .canonicalize()?
            .to_str()
            .context("Windows Codex home is not valid Unicode")?
            .to_string(),
        proxy: format!("http://{}", cfg.listen),
        ca_sha256: sha256_hex(&certificate),
    })
}

#[cfg(any(windows, test))]
fn windows_packaged_desktop_activation_args(
    proxy: &str,
    spki: &str,
    target: Option<&str>,
) -> String {
    let mut arguments = vec![
        format!("--proxy-server={proxy}"),
        format!("--ignore-certificate-errors-spki-list={spki}"),
    ];
    if let Some(target) = target {
        arguments.push(target.to_string());
    }
    arguments
        .iter()
        .map(|argument| windows_quote_activation_arg(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(windows, test))]
fn windows_quote_activation_arg(arg: &str) -> String {
    // Windows command-line quoting: escape a backslash only when it precedes
    // a quote or the final quote. Paths may contain spaces and trailing slashes.
    let mut quoted = String::from("\"");
    let mut slashes = 0;
    for character in arg.chars() {
        match character {
            '\\' => slashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(slashes * 2 + 1));
                quoted.push('"');
                slashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(slashes));
                quoted.push(character);
                slashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

/// Activates a Store package by AppUserModelID (brand template).
#[cfg(any(target_os = "windows", test, feature = "contract"))]
const PACKAGE_ACTIVATION_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$source=@'
using System;
using System.Runtime.InteropServices;
[ComImport, Guid("2e941141-7f97-4756-ba1d-9decde894a3d"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IApplicationActivationManager {
    void ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appUserModelId,
        [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint processId);
}
public static class @@ID@@PackageActivation {
    public static uint Activate(string appId, string arguments) {
        var clsid = new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C");
        var manager = (IApplicationActivationManager)Activator.CreateInstance(Type.GetTypeFromCLSID(clsid));
        uint pid;
        manager.ActivateApplication(appId, arguments, 0, out pid);
        return pid;
    }
}
'@
Add-Type -TypeDefinition $source
[@@ID@@PackageActivation]::Activate($env:@@ENV@@DESKTOP_APP_ID,$env:@@ENV@@DESKTOP_ACTIVATION_ARGS)
"#;

#[cfg(target_os = "windows")]
fn activate_windows_packaged_desktop(app_id: &str, arguments: &str) -> Result<u32> {
    // The Store package must be activated by AppUserModelID. Starting its
    // WindowsApps executable directly creates an unpackaged process and the
    // official app then fails with "The process has no package identity".
    // Pass only non-secret Chromium arguments through the broker.
    let output = windows_desktop_runtime::powershell(
        &script_brand::render(PACKAGE_ACTIVATION_SCRIPT),
        &[
            (
                script_brand::env("DESKTOP_APP_ID").as_str(),
                OsStr::new(app_id),
            ),
            (
                script_brand::env("DESKTOP_ACTIVATION_ARGS").as_str(),
                OsStr::new(arguments),
            ),
        ],
    )?;
    output
        .trim()
        .parse::<u32>()
        .context("Windows package activation did not return a process ID")
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
    restore_legacy_windows_packaged_proxy_lease_at(&windows_packaged_proxy_lease_marker_path()?)
}

#[cfg(target_os = "windows")]
fn restore_legacy_windows_packaged_proxy_lease_at(marker_path: &Path) -> Result<()> {
    let Some(marker) = read_legacy_windows_packaged_proxy_lease_marker(marker_path)? else {
        return Ok(());
    };

    let current = windows_read_internet_proxy()?;
    if windows_proxy_matches_managed(&current, &marker.managed_server) {
        windows_write_internet_proxy(&marker.previous)?;
        println!(
            "Restored the Windows proxy left by a legacy {brand_product} Desktop lease.",
            brand_product = BRAND.product_name
        );
    } else {
        eprintln!(
            "warning: legacy {brand_product} Desktop lease found, but the current Windows proxy was changed externally; preserving the current proxy",
            brand_product = BRAND.product_name
        );
    }
    for thumbprint in &marker.added_ca_thumbprints {
        windows_remove_user_ca(Some(thumbprint))?;
    }
    remove_windows_packaged_proxy_lease_marker(marker_path)
}

#[cfg(target_os = "windows")]
fn windows_packaged_proxy_lease_marker_path() -> Result<PathBuf> {
    Ok(app_config_dir()?
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
        .unwrap_or_else(script_brand::null_sentinel);
    let server = settings
        .proxy_server
        .as_deref()
        .map_or_else(script_brand::null_sentinel, str::to_string);
    let auto = settings
        .auto_config_url
        .as_deref()
        .map_or_else(script_brand::null_sentinel, str::to_string);
    let script = script_brand::render(
        "& { param($e,$s,$a) $path='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; if($e -eq '__@@ENV@@NULL__'){Remove-ItemProperty $path -Name ProxyEnable -ErrorAction SilentlyContinue}else{Set-ItemProperty $path -Name ProxyEnable -Type DWord -Value ([int]$e)}; if($s -eq '__@@ENV@@NULL__'){Remove-ItemProperty $path -Name ProxyServer -ErrorAction SilentlyContinue}else{Set-ItemProperty $path -Name ProxyServer -Type String -Value $s}; if($a -eq '__@@ENV@@NULL__'){Remove-ItemProperty $path -Name AutoConfigURL -ErrorAction SilentlyContinue}else{Set-ItemProperty $path -Name AutoConfigURL -Type String -Value $a} }",
    );
    command_output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script.as_str(),
            &enable,
            &server,
            &auto,
        ],
    )?;
    Ok(())
}
#[cfg(target_os = "windows")]
fn resolve_windows_desktop_override() -> Result<Option<PathBuf>> {
    for variable in [BRAND.env.desktop_bin, BRAND.env.chatgpt_bin] {
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
        "OpenAI Codex/ChatGPT Desktop was not found in standard application directories; install the official Desktop app or set {brand_desktop_bin_env}",
        brand_desktop_bin_env = BRAND.env.desktop_bin
    )
}

#[cfg(target_os = "windows")]
type WindowsPackagedDesktop = windows_desktop_runtime::Package;

#[cfg(target_os = "windows")]
fn resolve_windows_packaged_desktop() -> Result<Option<WindowsPackagedDesktop>> {
    windows_desktop_runtime::resolve_package()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn resolve_chatgpt_timezone() -> Result<Option<String>> {
    let raw = env::var_os(CHATGPT_TIMEZONE_ENV.get());
    let Some(raw) = raw else {
        return resolve_chatgpt_timezone_value(None);
    };
    let value = raw
        .to_str()
        .with_context(|| format!("{CHATGPT_TIMEZONE_ENV} must be valid UTF-8"))?
        .trim();
    resolve_chatgpt_timezone_value(Some(value))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn resolve_chatgpt_timezone_value(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value.map(str::trim) else {
        return Ok(None);
    };
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
        bail!("{CHATGPT_TIMEZONE_ENV} must be an IANA timezone such as America/Los_Angeles");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_chatgpt_timezone(value: &str) -> Result<Option<String>> {
    validate_chatgpt_timezone_name(value)?;
    let zoneinfo_path = Path::new("/usr/share/zoneinfo").join(value);
    let metadata = fs::metadata(&zoneinfo_path).with_context(|| {
        format!(
            "{CHATGPT_TIMEZONE_ENV} does not exist in {}",
            zoneinfo_path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "{CHATGPT_TIMEZONE_ENV} is not a zoneinfo file: {}",
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
            "Trusted the {brand_product} CA in the current user's NSS database for direct Linux Desktop (no system trust store or dialog).",
            brand_product = BRAND.product_name
        ),
        Ok(false) => eprintln!(
            "WARN direct Linux Desktop trust was not installed because certutil is unavailable; install libnss3-tools, rerun `{brand_binary} init-codex`, or use `{brand_binary} desktop codex`.",
            brand_binary = BRAND.binary_name
        ),
        Err(err) => eprintln!(
            "WARN direct Linux Desktop trust could not be updated ({err:#}); Codex CLI remains configured, and `{brand_binary} desktop codex` remains the supported isolated fallback.",
            brand_binary = BRAND.binary_name
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
        .args(["-D", "-d", &db, "-n", LOCAL_PROXY_NSS_CERT_NICKNAME.get()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = ProcessCommand::new("certutil")
        .args([
            "-A",
            "-d",
            &db,
            "-n",
            LOCAL_PROXY_NSS_CERT_NICKNAME.get(),
            "-t",
            "C,,",
            "-a",
            "-i",
            ca_cert.to_str().with_context(|| {
                format!(
                    "{brand_product} CA path is not valid UTF-8",
                    brand_product = BRAND.product_name
                )
            })?,
        ])
        .status()
        .with_context(|| {
            format!(
                "failed to import the {brand_product} CA into the Desktop NSS database",
                brand_product = BRAND.product_name
            )
        })?;
    if !status.success() {
        bail!(
            "certutil failed to import the {brand_product} CA into the Desktop NSS database",
            brand_product = BRAND.product_name
        );
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
            format!("certutil is unavailable; install libnss3-tools and rerun `{brand_binary} init-codex`, or use `{brand_binary} desktop codex`", brand_binary = BRAND.binary_name),
        );
        return;
    }
    let Some(home) = home_dir() else {
        report.warn(
            "direct Linux Desktop trust",
            format!("could not resolve the current user's NSS database; use `{brand_binary} desktop codex`", brand_binary = BRAND.binary_name),
        );
        return;
    };
    let db_dir = nss_database_dir(&home);
    let db = format!("sql:{}", db_dir.display());
    let present = ProcessCommand::new("certutil")
        .args(["-L", "-d", &db, "-n", LOCAL_PROXY_NSS_CERT_NICKNAME.get()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if present {
        report.ok(
            "direct Linux Desktop trust",
            format!(
                "{brand_product} CA entry is present in {}",
                db_dir.display(),
                brand_product = BRAND.product_name
            ),
        );
    } else {
        report.warn(
            "direct Linux Desktop trust",
            format!("{brand_product} CA entry is absent from the current user's NSS database; rerun `{brand_binary} init-codex` or use `{brand_binary} desktop codex`", brand_binary = BRAND.binary_name, brand_product = BRAND.product_name),
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
        format!("{brand_product} does not modify the login Keychain. A directly launched official App needs a user-approved {brand_product} CA trust root; otherwise use `{brand_binary} desktop codex` (managed per-process SPKI pin)", brand_binary = BRAND.binary_name, brand_product = BRAND.product_name),
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
            format!(
                "Desktop state is absent; run `{brand_binary} init-codex` before launching Desktop",
                brand_binary = BRAND.binary_name
            ),
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
            format!("permission profile visibility is disabled; rerun `{brand_binary} init-codex` or use `{brand_binary} desktop codex`", brand_binary = BRAND.binary_name),
        ),
        None => report.warn(
            "Desktop permission selector",
            format!("visibility state is missing or invalid; rerun `{brand_binary} init-codex` or use `{brand_binary} desktop codex`", brand_binary = BRAND.binary_name),
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
    // local placeholder instead of requiring the `codex` command first.
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
            "{} is not in ChatGPT token mode; first-phase `{brand_binary} codex` does not accept API-key-only auth",
            path.display(),
            brand_binary = BRAND.binary_name
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
            "{} has no ChatGPT OAuth access token; run `codex login` before `{brand_binary} codex`",
            path.display(),
            brand_binary = BRAND.binary_name
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
        if disable_codex_environment_context_time(&mut document) {
            println!(
                "NOTE {}: `{CODEX_ENVIRONMENT_CONTEXT_TIME_KEY}` was not false; {brand_product} manages this key and set it to false so Codex does not report the local timezone and date.",
                path.display(),
                brand_product = BRAND.product_name
            );
        }
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

/// State of the managed top-level Codex time-reporting key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexEnvironmentContextTime {
    Disabled,
    Missing,
    Enabled,
    Invalid,
}

fn codex_environment_context_time(document: &DocumentMut) -> CodexEnvironmentContextTime {
    match document.get(CODEX_ENVIRONMENT_CONTEXT_TIME_KEY) {
        None => CodexEnvironmentContextTime::Missing,
        Some(item) => match item.as_bool() {
            Some(false) => CodexEnvironmentContextTime::Disabled,
            Some(true) => CodexEnvironmentContextTime::Enabled,
            None => CodexEnvironmentContextTime::Invalid,
        },
    }
}

fn read_codex_environment_context_time(path: &Path) -> Result<CodexEnvironmentContextTime> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let document = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("failed to parse {} as TOML", path.display()))?;
    Ok(codex_environment_context_time(&document))
}

/// Set the top-level `include_environment_context_time = false`, keeping the
/// rest of the document (including comments on an existing entry) intact.
/// Returns true when an explicit non-false value was overwritten.
fn disable_codex_environment_context_time(document: &mut DocumentMut) -> bool {
    let previous = codex_environment_context_time(document);
    if previous == CodexEnvironmentContextTime::Disabled {
        return false;
    }
    let mut replacement = toml_edit::Value::from(false);
    // Replace the item in place: `Table::insert` would reset the key's
    // formatting and drop comments placed above an existing entry.
    match document.get_mut(CODEX_ENVIRONMENT_CONTEXT_TIME_KEY) {
        Some(item) => {
            if let Some(existing) = item.as_value() {
                *replacement.decor_mut() = existing.decor().clone();
            }
            *item = Item::Value(replacement);
        }
        None => {
            document
                .as_table_mut()
                .insert(CODEX_ENVIRONMENT_CONTEXT_TIME_KEY, Item::Value(replacement));
        }
    }
    previous != CodexEnvironmentContextTime::Missing
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
    ensure_local_proxy_running_with_start(listen, run_service_start)
}

fn verify_selected_proxy_identity(listen: &str) -> Result<()> {
    let config = read_app_config()?;
    if config.listen != listen {
        bail!("the environment configuration changed during launch; retry the command");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(connect_local_proxy_tls(&config))
        .context("the listener does not authenticate with this environment's CA; rerun initialization to allocate an available port")?;
    Ok(())
}

fn ensure_local_proxy_running_with_start(
    listen: &str,
    start: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let addr = listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {listen}"))?;
    if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
        if environment_scope::isolated() {
            verify_selected_proxy_identity(listen)?;
        }
        return Ok(());
    }
    start().with_context(|| {
        format!(
            "failed to start the {brand_product} local proxy",
            brand_product = BRAND.product_name
        )
    })?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
            if environment_scope::isolated() {
                verify_selected_proxy_identity(listen)?;
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!(
        "{brand_product} local proxy did not become reachable at {listen}",
        brand_product = BRAND.product_name
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn local_proxy_chatgpt_spki(listen: &str) -> Result<String> {
    let addr = listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {listen}"))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).with_context(|| {
            format!(
                "failed to connect to {brand_product} local proxy at {listen}",
                brand_product = BRAND.product_name
            )
        })?;
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
        bail!(
            "{brand_product} local proxy did not accept the certificate identity request",
            brand_product = BRAND.product_name
        );
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
                .eq_ignore_ascii_case(CODEX_CERTIFICATE_SPKI_HEADER.get())
        {
            spki = Some(value.trim().to_string());
        }
    }
    let spki = spki.with_context(|| format!("running {brand_product} proxy does not expose a Desktop certificate pin; run `{brand_binary} restart` and retry", brand_binary = BRAND.binary_name, brand_product = BRAND.product_name))?;
    let pins = spki.split(',').collect::<Vec<_>>();
    if pins.is_empty() || pins.iter().any(|pin| pin.trim().is_empty()) {
        bail!(
            "{brand_product} local proxy returned an empty Desktop certificate pin",
            brand_product = BRAND.product_name
        );
    }
    for pin in pins {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(pin.trim())
            .with_context(|| {
                format!(
                    "{brand_product} local proxy returned an invalid Desktop certificate pin",
                    brand_product = BRAND.product_name
                )
            })?;
        if decoded.len() != 32 {
            bail!(
                "{brand_product} local proxy returned an invalid Desktop certificate pin length",
                brand_product = BRAND.product_name
            );
        }
    }
    Ok(spki)
}

// The derived code below is used through `AppConfig::serialize` /
// `AppConfig::deserialize` (`remote = "Self"`); the trait impls after the
// struct name the brand's config type in shape errors, which derived code
// would take from the Rust type name.
// Fields: keep in sync with `APP_CONFIG_FIELDS` and the hand-written
// `AppConfigVisitor::visit_seq`.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(remote = "Self")]
struct AppConfig {
    version: u32,
    base_url: String,
    api_key: String,
    listen: String,
    ca_cert_path: String,
    #[serde(default)]
    ca_key_path: String,
    #[serde(default = "default_true")]
    chatgpt_chat_passthrough: bool,
    #[serde(default = "default_true")]
    desktop_browser_use: bool,
    /// `system` (default when absent), `direct`, or an http:// proxy URL for
    /// the program's own egress; see `upstream_proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream_proxy: Option<String>,
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

// Initialization holds the shared root lock, so stopped environments also
// reserve their configured ports. Never copy another environment's credentials.
fn other_environment_listeners() -> Result<Vec<String>> {
    let Some(scope) = environment_scope::active() else {
        return Ok(Vec::new());
    };
    let mut paths = vec![scope.root.join(CONFIG_FILENAME.get())];
    match fs::read_dir(scope.root.join("environments")) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    paths.push(entry.path().join(CONFIG_FILENAME.get()));
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "cannot inspect {brand_product} environments",
                    brand_product = BRAND.product_name
                )
            });
        }
    }
    let own = scope.directory.join(CONFIG_FILENAME.get());
    let mut reserved = Vec::new();
    for path in paths.into_iter().filter(|path| path != &own) {
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).context("cannot read another environment's port reservation");
            }
        };
        let value: Value = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "invalid {brand_product} environment configuration",
                brand_product = BRAND.product_name
            )
        })?;
        if let Some(listen) = value["listen"].as_str() {
            reserved.push(listen.to_string());
        }
    }
    Ok(reserved)
}

#[cfg(target_os = "linux")]
fn selected_service_owns_listener(addr: SocketAddr) -> bool {
    let pid = linux_background_state()
        .ok()
        .flatten()
        .filter(linux_background_state_is_running)
        .map(|s| s.pid)
        .or_else(|| {
            if ensure_systemd_user_available().is_ok() {
                systemctl_value("MainPID")
                    .ok()?
                    .parse::<u32>()
                    .ok()
                    .filter(|pid| *pid != 0)
            } else {
                None
            }
        });
    pid.is_some_and(|pid| {
        listen_port_owners(addr)
            .iter()
            .any(|owner| owner.pid == pid)
    })
}

#[cfg(not(target_os = "linux"))]
fn selected_service_owns_listener(addr: SocketAddr) -> bool {
    managed_service_is_active() && verify_selected_proxy_identity(&addr.to_string()).is_ok()
}

fn select_local_proxy_listen(existing: Option<&str>) -> Result<String> {
    let reserved = other_environment_listeners()?;
    if let Some(listen) =
        existing.filter(|value| !value.trim().is_empty() && !reserved.iter().any(|r| r == value))
        && let Ok(addr) = listen.parse::<SocketAddr>()
        && addr.ip().is_loopback()
    {
        // Keep the current port when our managed service owns it. On a
        // repeat initialization this avoids needless proxy churn.
        if selected_service_owns_listener(addr)
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

    for _ in 0..128 {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).with_context(|| {
            format!(
                "failed to allocate a loopback port for the {brand_product} local proxy",
                brand_product = BRAND.product_name
            )
        })?;
        let listen = listener.local_addr()?.to_string();
        if !reserved.contains(&listen) {
            return Ok(listen);
        }
    }
    bail!("failed to allocate a distinct local proxy port")
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

fn update_app_provider_config(
    provider: ProviderKind,
    credential: ProviderCredential,
    ca_paths: Option<(PathBuf, PathBuf)>,
) -> Result<AppConfigUpdate> {
    let path = app_config_path()?;
    update_app_provider_config_at(&path, provider, credential, ca_paths)
}

fn update_app_provider_config_at(
    path: &Path,
    provider: ProviderKind,
    credential: ProviderCredential,
    ca_paths: Option<(PathBuf, PathBuf)>,
) -> Result<AppConfigUpdate> {
    let existing = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<AppConfig>(&raw).ok());
    let previous = existing.clone();
    let mut config = existing.unwrap_or_else(|| AppConfig {
        version: CONFIG_VERSION.get(),
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
        desktop_browser_use: true,
        upstream_proxy: None,
        providers: ProviderCredentials::default(),
    });
    let existing_listen = (!config.listen.trim().is_empty()).then_some(config.listen.as_str());
    config.listen = select_local_proxy_listen(existing_listen)?;

    if config.version != CONFIG_VERSION.get()
        || config.ca_cert_path.trim().is_empty()
        || config.ca_key_path.trim().is_empty()
    {
        if let Some((cert, key)) = ca_paths.as_ref() {
            config.version = CONFIG_VERSION.get();
            config.ca_cert_path = cert.display().to_string();
            config.ca_key_path = key.display().to_string();
        } else {
            bail!(
                "{brand_product} config is obsolete; initialize {} again with the one-command setup",
                provider.name(),
                brand_product = BRAND.product_name
            );
        }
    }
    if let Some((cert, key)) = ca_paths.as_ref()
        && read_runtime_ca(&config).is_err()
    {
        config.version = CONFIG_VERSION.get();
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
    write_app_config_at(path, &config)?;
    Ok(AppConfigUpdate {
        changed: proxy_runtime_config_changed(previous.as_ref(), &config),
        config,
    })
}

fn proxy_runtime_config_changed(previous: Option<&AppConfig>, current: &AppConfig) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    previous.version != current.version
        || previous.listen != current.listen
        || previous.ca_cert_path != current.ca_cert_path
        || previous.ca_key_path != current.ca_key_path
        || previous.chatgpt_chat_passthrough != current.chatgpt_chat_passthrough
        || previous.desktop_browser_use != current.desktop_browser_use
        || previous.upstream_proxy != current.upstream_proxy
        || previous.providers != current.providers
        || (previous.providers.is_empty()
            && (previous.base_url != current.base_url || previous.api_key != current.api_key))
}

/// Field order of an array-form config.json (the struct's field order).
/// Keep in sync with the `AppConfig` fields and `AppConfigVisitor::visit_seq`
/// (`app_config_field_order_is_consistent` checks all three).
const APP_CONFIG_FIELDS: &[&str] = &[
    "version",
    "base_url",
    "api_key",
    "listen",
    "ca_cert_path",
    "ca_key_path",
    "chatgpt_chat_passthrough",
    "desktop_browser_use",
    "upstream_proxy",
    "providers",
];

impl Serialize for AppConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AppConfig::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for AppConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct(
            "AppConfig",
            APP_CONFIG_FIELDS,
            AppConfigVisitor(crate::brand::brand()),
        )
    }
}

/// `struct <brand type name> with <n> elements`: the expectation of an
/// array-form config that is too short.
struct AppConfigElements(&'static brand::Brand);

impl serde::de::Expected for AppConfigElements {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "struct {} with {} elements",
            self.0.config.type_name,
            APP_CONFIG_FIELDS.len()
        )
    }
}

/// Reads a config for `brand`, whose config type name the shape errors use.
struct AppConfigVisitor(&'static brand::Brand);

impl<'de> serde::de::Visitor<'de> for AppConfigVisitor {
    type Value = AppConfig;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "struct {}", self.0.config.type_name)
    }

    // Field errors (missing, duplicate, mistyped) name fields, not the type,
    // so the derived code handles objects as before.
    fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<AppConfig, A::Error> {
        AppConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))
    }

    // As derived code reads an array: fields in order, a defaulted field may
    // be missing at the end, a missing required one is a length error.
    // Keep in sync with the `AppConfig` fields and `APP_CONFIG_FIELDS`.
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<AppConfig, A::Error> {
        let brand = self.0;
        let required_error =
            |index| serde::de::Error::invalid_length(index, &AppConfigElements(brand));
        fn required<'de, A: serde::de::SeqAccess<'de>, T: Deserialize<'de>>(
            seq: &mut A,
            index: &mut usize,
            error: impl Fn(usize) -> A::Error,
        ) -> Result<T, A::Error> {
            let element = seq.next_element()?.ok_or_else(|| error(*index));
            *index += 1;
            element
        }
        let mut index = 0;
        let version = required(&mut seq, &mut index, required_error)?;
        let base_url = required(&mut seq, &mut index, required_error)?;
        let api_key = required(&mut seq, &mut index, required_error)?;
        let listen = required(&mut seq, &mut index, required_error)?;
        let ca_cert_path = required(&mut seq, &mut index, required_error)?;
        Ok(AppConfig {
            version,
            base_url,
            api_key,
            listen,
            ca_cert_path,
            ca_key_path: seq.next_element()?.unwrap_or_default(),
            chatgpt_chat_passthrough: seq.next_element()?.unwrap_or_else(default_true),
            desktop_browser_use: seq.next_element()?.unwrap_or_else(default_true),
            upstream_proxy: seq.next_element()?.unwrap_or_default(),
            providers: seq.next_element()?.unwrap_or_default(),
        })
    }
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
    #[serde(default)]
    instance: Option<String>,
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
    println!("{} {}", BRAND.binary_name, runtime::version());
    Ok(())
}

fn run_local_proxy(verbose: bool) -> Result<()> {
    let cfg = read_app_config()?;
    let (ca_cert_pem, ca_key_pem) = read_runtime_ca(&cfg)?;
    ensure_listen_available(&cfg.listen)?;
    if let Err(error) = migrate_legacy_claude_no_proxy_for_instance(&cfg.listen) {
        eprintln!("warning: could not update Claude no_proxy: {error:#}");
    }
    if cfg!(target_os = "linux")
        && let Err(error) = migrate_legacy_codex_system_proxy_for_instance(&cfg)
    {
        eprintln!("warning: could not update Codex respect_system_proxy: {error:#}");
    }
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
        desktop_browser_use: cfg.desktop_browser_use,
        gateway_state_dir: app_config_dir().ok(),
        desktop_config_root: if cfg!(target_os = "linux") {
            Some(app_config_dir()?)
        } else {
            None
        },
        upstream_proxy: cfg.upstream_proxy,
    }))
}

fn run_upstream_proxy_command(value: Option<String>) -> Result<()> {
    let Some(value) = value else {
        let cfg = read_app_config()?;
        println!(
            "setting: {}",
            upstream_proxy::describe_setting(cfg.upstream_proxy.as_deref())
        );
        println!(
            "this shell resolves it to: {}",
            Egress::for_config(&cfg).upstream.description()
        );
        println!("the running service logs its own resolution at startup and on every change");
        return Ok(());
    };
    upstream_proxy::validate_setting(&value)?;
    let _initialization_lock = lock_initialization()?;
    let mut cfg = read_app_config()?;
    let value = value.trim();
    cfg.upstream_proxy = (!value.eq_ignore_ascii_case("system")).then(|| value.to_string());
    write_app_config_at(&app_config_path()?, &cfg)?;
    println!(
        "upstream proxy set to {}; run `{brand_binary} restart` to apply it to the running service",
        upstream_proxy::describe_setting(cfg.upstream_proxy.as_deref()),
        brand_binary = BRAND.binary_name
    );
    Ok(())
}

/// HTTP egress for one-shot CLI requests (health check, self-update), routed
/// like the local proxy's own Gateway traffic.
#[derive(Clone)]
struct Egress {
    /// `None`: not installed (no configuration), so no installation CA is
    /// excluded from the system roots.
    installation_ca_pem: Option<String>,
    upstream: Arc<upstream_proxy::Snapshot>,
}

impl Egress {
    /// Egress of an uninitialized installation: the default (system) route
    /// and no installation CA to exclude.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn for_optional_config(cfg: Option<&AppConfig>) -> Self {
        match cfg {
            Some(cfg) => Self::for_config(cfg),
            None => Self {
                installation_ca_pem: None,
                upstream: upstream_proxy::UpstreamProxy::new(None, None, Vec::new()).snapshot(),
            },
        }
    }

    fn for_config(cfg: &AppConfig) -> Self {
        let upstream = upstream_proxy::UpstreamProxy::new(
            cfg.upstream_proxy.as_deref(),
            cfg.listen.parse().ok(),
            Vec::new(),
        );
        Self {
            installation_ca_pem: Some(installation_ca_pem(cfg)),
            upstream: upstream.snapshot(),
        }
    }

    /// Client builder for requests to `url` (a single host: redirects are
    /// never followed). Fails instead of going direct when the configured
    /// proxy cannot be used.
    fn client_builder(&self, url: &str) -> Result<reqwest::ClientBuilder> {
        let route = upstream_proxy::route_for_url_blocking(&self.upstream, url)?;
        let builder = match &self.installation_ca_pem {
            Some(pem) => upstream_tls::upstream_http_client_builder(pem),
            None => upstream_tls::uninstalled_http_client_builder(),
        };
        upstream_proxy::client_builder_for_route(builder, &route)
    }
}

/// The installation CA certificate, excluded from upstream trust. Empty when
/// unreadable, which limits upstream trust to the bundled roots.
fn installation_ca_pem(cfg: &AppConfig) -> String {
    fs::read_to_string(&cfg.ca_cert_path).unwrap_or_default()
}

fn read_runtime_ca(cfg: &AppConfig) -> Result<(String, String)> {
    if cfg.version != CONFIG_VERSION.get() || cfg.ca_key_path.trim().is_empty() {
        bail!(
            "{brand_product} local proxy configuration is obsolete; rerun the one-command {brand_product} setup",
            brand_product = BRAND.product_name
        );
    }
    let cert_pem = fs::read_to_string(&cfg.ca_cert_path).with_context(|| {
        format!(
            "failed to read {brand_product} CA certificate {}",
            cfg.ca_cert_path,
            brand_product = BRAND.product_name
        )
    })?;
    let key_pem = fs::read_to_string(&cfg.ca_key_path).with_context(|| {
        format!(
            "failed to read {brand_product} CA key {}",
            cfg.ca_key_path,
            brand_product = BRAND.product_name
        )
    })?;
    local_proxy::validate_tls_config(&cert_pem, &key_pem)
        .with_context(|| format!("{brand_product} installation CA is invalid; rerun the one-command {brand_product} setup", brand_product = BRAND.product_name))?;
    Ok((cert_pem, key_pem))
}

#[cfg(target_os = "linux")]
fn run_service_start() -> Result<()> {
    let _service_lock = acquire_linux_service_lock()?;
    let cfg = read_app_config()?;
    match ensure_systemd_user_available() {
        Ok(()) => {
            stop_linux_background_proxy()?;
            let was_active = service_is_active().unwrap_or(false);
            if !was_active {
                ensure_listen_available(&cfg.listen)?;
            }
            let service_path = write_user_service()?;
            run_systemctl(&["daemon-reload"])?;
            run_systemctl(&["enable", &environment_scope::service_name()])?;
            if was_active {
                run_systemctl(&["restart", &environment_scope::service_name()])?;
            } else {
                run_systemctl(&["start", &environment_scope::service_name()])?;
            }
            println!(
                "{brand_product} user service started or refreshed.",
                brand_product = BRAND.product_name
            );
            println!("Service: {}", service_path.display());
        }
        Err(systemd_error) => {
            eprintln!(
                "WARN systemd --user unavailable; using a managed background process: {systemd_error}"
            );
            let pid = start_linux_background_proxy(&cfg)?;
            println!(
                "{brand_product} background proxy started or refreshed.",
                brand_product = BRAND.product_name
            );
            println!("Service manager: background process");
            println!("PID: {pid}");
        }
    }
    println!("Listening: http://{}", cfg.listen);
    println!(
        "Status: {brand_binary} status",
        brand_binary = BRAND.binary_name
    );
    println!(
        "Logs: {brand_binary} logs",
        brand_binary = BRAND.binary_name
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_service_start() -> Result<()> {
    let cfg = read_app_config()?;
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
    // kickstart can return before the restarted proxy binds. Report "started"
    // only once it listens, so an immediately following init sees the managed
    // listener instead of racing it and reallocating the port.
    if !wait_for_local_listener(&cfg.listen, MACOS_LISTENER_READY_TIMEOUT) {
        eprintln!(
            "{brand_product} LaunchAgent was started but is not listening on {} yet; check `{brand_binary} logs`.",
            cfg.listen,
            brand_binary = BRAND.binary_name,
            brand_product = BRAND.product_name
        );
    }
    println!(
        "{brand_product} LaunchAgent started.",
        brand_product = BRAND.product_name
    );
    println!("Service: {}", plist_path.display());
    println!("Listening: http://{}", cfg.listen);
    println!(
        "Status: {brand_binary} status",
        brand_binary = BRAND.binary_name
    );
    println!(
        "Logs: {brand_binary} logs",
        brand_binary = BRAND.binary_name
    );
    Ok(())
}

// launchd may hold a respawn for its 10 s throttle interval after a recent
// start; allow for that plus process startup.
#[cfg(target_os = "macos")]
const MACOS_LISTENER_READY_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(target_os = "macos")]
fn wait_for_local_listener(listen: &str, wait: Duration) -> bool {
    let Ok(addr) = listen.parse::<SocketAddr>() else {
        return false;
    };
    let deadline = std::time::Instant::now() + wait;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "windows")]
fn run_service_start() -> Result<()> {
    let _service_lock = lock_windows_service()?;
    let cfg = read_app_config()?;
    if let Some(pid) = windows_background_pid()? {
        if windows_pid_is_running(pid).unwrap_or(false) {
            stop_windows_background_proxy()?;
        }
    }
    ensure_listen_available(&cfg.listen)?;
    let pid = start_windows_background_proxy()?;
    println!(
        "{brand_product} background proxy started or refreshed.",
        brand_product = BRAND.product_name
    );
    println!("PID: {pid}");
    println!("Listening: http://{}", cfg.listen);
    println!(
        "Status: {brand_binary} status",
        brand_binary = BRAND.binary_name
    );
    println!(
        "Logs: {brand_binary} logs",
        brand_binary = BRAND.binary_name
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_start() -> Result<()> {
    bail!(
        "{brand_binary} start currently supports Linux, macOS, and Windows only",
        brand_binary = BRAND.binary_name
    );
}

#[cfg(target_os = "linux")]
fn run_service_stop() -> Result<()> {
    let _service_lock = acquire_linux_service_lock()?;
    let background_stopped = stop_linux_background_proxy()?;
    match ensure_systemd_user_available() {
        Ok(()) => {
            if stop_systemd_user_service_if_present()? {
                println!(
                    "{brand_product} user service stopped and disabled.",
                    brand_product = BRAND.product_name
                );
            } else if background_stopped {
                println!(
                    "{brand_product} background proxy stopped.",
                    brand_product = BRAND.product_name
                );
            } else {
                println!(
                    "{brand_product} service is not running.",
                    brand_product = BRAND.product_name
                );
            }
        }
        Err(systemd_error) => {
            if background_stopped {
                println!(
                    "{brand_product} background proxy stopped.",
                    brand_product = BRAND.product_name
                );
            } else if linux_configured_listen_has_app_owner()? {
                bail!(
                    "a {brand_product} process is listening, but it is not the managed background process and systemd --user is unavailable: {systemd_error}",
                    brand_product = BRAND.product_name
                );
            } else {
                println!(
                    "{brand_product} background proxy is not running.",
                    brand_product = BRAND.product_name
                );
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
    println!(
        "{brand_product} LaunchAgent stopped.",
        brand_product = BRAND.product_name
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_service_stop() -> Result<()> {
    let _service_lock = lock_windows_service()?;
    stop_windows_background_proxy()?;
    println!(
        "{brand_product} background proxy stopped.",
        brand_product = BRAND.product_name
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_stop() -> Result<()> {
    bail!(
        "{brand_binary} stop currently supports Linux, macOS, and Windows only",
        brand_binary = BRAND.binary_name
    );
}

#[cfg(target_os = "linux")]
fn run_service_status() -> Result<()> {
    println!("{} {}", BRAND.binary_name, runtime::version());
    print_process_env_conflicts_for_status();
    print_claude_settings_overrides_for_status();
    match read_app_config() {
        Ok(cfg) => {
            println!("config: {}", app_config_path()?.display());
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
    println!("{} {}", BRAND.binary_name, runtime::version());
    print_process_env_conflicts_for_status();
    print_claude_settings_overrides_for_status();
    match read_app_config() {
        Ok(cfg) => {
            println!("config: {}", app_config_path()?.display());
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
    println!("{} {}", BRAND.binary_name, runtime::version());
    print_process_env_conflicts_for_status();
    print_claude_settings_overrides_for_status();
    match read_app_config() {
        Ok(cfg) => {
            println!("config: {}", app_config_path()?.display());
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
    bail!(
        "{brand_binary} status currently supports Linux, macOS, and Windows only",
        brand_binary = BRAND.binary_name
    );
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
        .args(["--user", "-u", &environment_scope::service_name(), "-f"])
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
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Get-Content -LiteralPath {} -Encoding UTF8 -Tail 80 -Wait",
        powershell_quote_path(&log_path)?
    );
    let service_lock = lock_windows_service()?;
    let mut child = ProcessCommand::new("powershell")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to read {}", log_path.display()))?;
    let registration = register_windows_log_follower(child.id());
    if registration.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let registration = registration?;
    drop(service_lock);
    let status = child.wait()?;
    let _ = fs::remove_file(registration);
    if !status.success() {
        bail!("PowerShell exited with {status}");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_service_logs() -> Result<()> {
    bail!(
        "{brand_binary} logs currently supports Linux, macOS, and Windows only",
        brand_binary = BRAND.binary_name
    );
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
    bail!(
        "{brand_binary} restart currently supports Linux, macOS, and Windows only",
        brand_binary = BRAND.binary_name
    );
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
    let Ok(config) = read_app_config() else {
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
    if should_skip_initialization_proxy_start(env::var(BRAND.env.skip_start).ok().as_deref()) {
        println!(
            "{brand_product} local proxy start skipped ({brand_skip_start_env}=1).",
            brand_product = BRAND.product_name,
            brand_skip_start_env = BRAND.env.skip_start
        );
        return Ok(());
    }
    let binary_changed =
        binary_changed_during_initialization(env::var(BRAND.env.binary_updated).ok().as_deref());
    let managed_service_active = managed_service_is_active();
    let proxy_reachable = configured_local_proxy_reachable();
    if !initialization_requires_proxy_refresh(
        config_changed,
        binary_changed,
        managed_service_active,
        proxy_reachable,
    ) {
        println!(
            "{brand_product} local proxy left running; binary and runtime configuration are unchanged.",
            brand_product = BRAND.product_name
        );
        return Ok(());
    }
    run_service_start().with_context(|| {
        format!(
            "failed to start or refresh the {brand_product} local proxy",
            brand_product = BRAND.product_name
        )
    })?;
    println!(
        "{brand_product} local proxy started or refreshed after configuration update.",
        brand_product = BRAND.product_name
    );
    Ok(())
}

/// Manifest and asset URLs of a Gateway update channel below a Gateway
/// base URL; an error for a brand that updates from fixed URLs.
#[cfg(any(test, feature = "contract"))]
fn update_urls(base_url: &str, asset: &str) -> Result<(String, String)> {
    match &BRAND.update.source {
        UpdateSource::GatewayChannel { channel_path } => {
            Ok(gateway_update_urls(channel_path, base_url, asset))
        }
        UpdateSource::Fixed(_) => bail!(
            "{brand_binary} updates from fixed URLs, not below a Gateway base URL",
            brand_binary = BRAND.binary_name
        ),
    }
}

fn gateway_update_urls(channel: &str, base_url: &str, asset: &str) -> (String, String) {
    let base = base_url.trim().trim_end_matches('/');
    (
        format!("{base}/{channel}/manifest.json"),
        format!("{base}/{channel}/{asset}"),
    )
}

/// Where this run downloads its update from.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
enum UpdateOrigin {
    Gateway {
        cfg: AppConfig,
        manifest_url: String,
        url: String,
    },
    Fixed {
        source: &'static FixedUpdateSource,
        cfg: Option<AppConfig>,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_update() -> Result<()> {
    let service_was_active = managed_service_is_active();
    let (origin, asset) = match &BRAND.update.source {
        UpdateSource::GatewayChannel { channel_path } => {
            let cfg = read_app_config()?;
            let asset = current_platform_asset_name()?;
            let (manifest_url, url) = gateway_update_urls(channel_path, &cfg.base_url, &asset);
            let origin = UpdateOrigin::Gateway {
                cfg,
                manifest_url,
                url,
            };
            (origin, asset)
        }
        // Fixed URLs need no Gateway: an uninitialized installation updates
        // through the default (system) route, but a configuration that
        // exists and cannot be read is an error, not a silent default.
        UpdateSource::Fixed(source) => {
            let cfg = read_app_config_if_present()?;
            let asset = current_platform_asset_name()?;
            (UpdateOrigin::Fixed { source, cfg }, asset)
        }
    };
    let current_exe = env::current_exe().with_context(|| {
        format!(
            "failed to resolve current {brand_binary} executable",
            brand_binary = BRAND.binary_name
        )
    })?;
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
    // One fixed-source update at a time per installation directory. The lock
    // is held until this command returns; on Windows the replacement helper
    // started at the end runs after that (it serializes on the executable).
    let _update_lock = match &origin {
        UpdateOrigin::Fixed { .. } => Some(lock_update_directory(parent)?),
        UpdateOrigin::Gateway { .. } => None,
    };
    let current_bytes = fs::read(&current_exe)
        .with_context(|| format!("failed to read {}", current_exe.display()))?;
    let current_sha256 = sha256_hex(&current_bytes);

    println!(
        "Current: {brand_binary} {}",
        runtime::version(),
        brand_binary = BRAND.binary_name
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start async runtime")?;

    let (bytes, expected_version) = match origin {
        UpdateOrigin::Gateway {
            cfg,
            manifest_url,
            url,
        } => {
            println!("Checking: {manifest_url}");
            let egress = Egress::for_config(&cfg);
            let manifest = runtime.block_on(download_update_manifest(&manifest_url, &egress))?;
            let expected_sha256 = if let Some(manifest) = manifest {
                let remote_version = manifest.version.trim();
                let ordering =
                    compare_versions(remote_version, runtime::version()).with_context(|| {
                        format!("failed to compare remote version {remote_version:?}")
                    })?;
                let asset_info = manifest
                    .assets
                    .get(&asset)
                    .with_context(|| format!("manifest does not include asset {asset}"))?;
                let expected = asset_info.sha256.trim().to_ascii_lowercase();
                if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
                    bail!("manifest asset {asset} has invalid sha256 {expected:?}");
                }

                println!(
                    "Latest: {brand_binary} {remote_version}",
                    brand_binary = BRAND.binary_name
                );
                if ordering == Ordering::Less {
                    println!(
                        "Already current: {brand_binary} {} (remote {brand_binary} {remote_version})",
                        runtime::version(),
                        brand_binary = BRAND.binary_name
                    );
                    return Ok(());
                }
                if ordering == Ordering::Equal && current_sha256 == expected {
                    println!(
                        "Already current: {brand_binary} {}",
                        runtime::version(),
                        brand_binary = BRAND.binary_name
                    );
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
            let bytes = runtime.block_on(download_update_asset(&url, &egress))?;
            validate_update_asset(&bytes, &asset)?;
            if let Some(expected) = &expected_sha256 {
                let actual = sha256_hex(&bytes);
                if actual != *expected {
                    bail!("downloaded {asset} sha256 mismatch: expected {expected}, got {actual}");
                }
            }
            (bytes, None)
        }
        UpdateOrigin::Fixed { source, cfg } => {
            match fixed_download(
                &FixedUrlPolicy::https(source.hosts),
                source.manifest_url,
                source.asset_url_template,
                cfg,
                &asset,
                runtime::version(),
                &current_sha256,
            )? {
                FixedUpdate::Current(message) => {
                    println!("{message}");
                    return Ok(());
                }
                FixedUpdate::Download { bytes, version } => {
                    validate_update_asset(&bytes, &asset)?;
                    (bytes, Some(version))
                }
            }
        }
    };

    let unique = update_suffix();
    let candidate_name = update_candidate_name(&unique);
    let backup_name = update_backup_name();
    let candidate_path = parent.join(candidate_name);
    let backup_path = parent.join(backup_name);
    let candidate_raw = if expected_version.is_some() {
        // Fixed source: a new file only, and a bounded probe; a candidate
        // that cannot be probed is removed.
        write_new_update_candidate(&candidate_path, &bytes)
            .with_context(|| format!("failed to write {}", candidate_path.display()))?;
        match probe_candidate_version(
            &candidate_path,
            CANDIDATE_PROBE_TIMEOUT,
            CANDIDATE_PROBE_LIMIT,
        ) {
            Ok(output) => output,
            Err(error) => {
                let _ = fs::remove_file(&candidate_path);
                return Err(error)
                    .with_context(|| format!("failed to run {}", candidate_path.display()));
            }
        }
    } else {
        write_update_candidate(&candidate_path, &bytes)
            .with_context(|| format!("failed to write {}", candidate_path.display()))?;
        command_stdout_raw(&candidate_path, &["--version"])
            .with_context(|| format!("failed to run {}", candidate_path.display()))?
    };
    let candidate_version = candidate_raw.trim().to_string();
    if !candidate_version
        .trim_start()
        .strip_prefix(BRAND.binary_name)
        .is_some_and(|rest| rest.starts_with(' '))
        || expected_version.as_ref().is_some_and(|version| {
            !reports_exact_version(&candidate_raw, BRAND.binary_name, version)
        })
    {
        let _ = fs::remove_file(&candidate_path);
        bail!(
            "downloaded binary did not report a {brand_product} version: {candidate_version:?}",
            brand_product = BRAND.product_name
        );
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
        &sha256_hex(&bytes),
    )?;

    #[cfg(target_os = "windows")]
    println!(
        "Update staged (not yet installed): {}. After this command exits, run `{brand_binary} --version` to confirm; a failed replacement is reported there.",
        candidate_version.trim(),
        brand_binary = BRAND.binary_name
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
                        "WARN {brand_product} client was updated and the local proxy remains reachable, but its automatic service refresh reported: {err:#}. Run `{brand_binary} restart` later to retry the refresh.",
                        brand_binary = BRAND.binary_name,
                        brand_product = BRAND.product_name
                    );
                } else {
                    return Err(err).with_context(|| {
                        format!(
                            "failed to restart the active {brand_product} service",
                            brand_product = BRAND.product_name
                        )
                    });
                }
            } else {
                println!(
                    "Managed {brand_product} service was active; restarted automatically.",
                    brand_product = BRAND.product_name
                );
            }
        }
        #[cfg(target_os = "windows")]
        println!(
            "Managed {brand_product} service was active; restart was scheduled automatically.",
            brand_product = BRAND.product_name
        );
    } else {
        println!(
            "{brand_product} service was not active; run `{brand_binary} start` when needed.",
            brand_binary = BRAND.binary_name,
            brand_product = BRAND.product_name
        );
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn run_update() -> Result<()> {
    bail!(
        "{brand_binary} update currently supports Linux, macOS, and Windows assets only",
        brand_binary = BRAND.binary_name
    );
}

fn run_doctor(target: DoctorTarget) -> Result<()> {
    let check_claude = matches!(target, DoctorTarget::All | DoctorTarget::Claude);
    let check_codex = matches!(target, DoctorTarget::All | DoctorTarget::Codex);
    let mut report = DoctorReport::new();
    report.ok(
        "version",
        format!("{} {} ({target:?})", BRAND.binary_name, runtime::version()),
    );
    check_current_binary(&mut report);
    // These checks apply Claude Code's conflict rules; program-managed Codex
    // launchers set their own child-only routing environment.
    if check_claude {
        check_process_env_conflicts(&mut report);
        check_systemd_user_env_conflicts(&mut report);
        check_persistent_env_conflicts(&mut report);
    }

    let config_path = app_config_path().with_context(|| {
        format!(
            "failed to resolve {brand_product} config path",
            brand_product = BRAND.product_name
        )
    })?;
    let cfg = match read_app_config() {
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
        check_app_config(&mut report, cfg);
        if check_claude {
            check_provider_route(&mut report, cfg, ProviderKind::Claude);
        }
        if check_codex {
            check_provider_route(&mut report, cfg, ProviderKind::Codex);
        }
    }
    if check_claude {
        let listen = cfg
            .as_ref()
            .map_or(DEFAULT_LOCAL_PROXY_LISTEN, |cfg| cfg.listen.as_str());
        check_process_proxy_env_conflicts(&mut report, listen);
        check_persistent_proxy_env_conflicts(&mut report);
        check_systemd_user_proxy_env_conflicts(&mut report);
        match resolve_claude_config_paths() {
            Ok(paths) => check_claude_config(&mut report, cfg.as_ref(), &paths),
            Err(err) => report.error("Claude config", err.to_string()),
        }
    }
    if check_codex {
        codex_diagnostics::check(&mut report);
        check_codex_config(
            &mut report,
            cfg.as_ref(),
            matches!(target, DoctorTarget::Codex),
        );
        codex_daemon::check(&mut report);
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        check_desktop_permission_visibility(&mut report);
        #[cfg(target_os = "linux")]
        check_direct_linux_desktop_trust(&mut report);
        #[cfg(target_os = "macos")]
        check_direct_macos_desktop_trust(&mut report);
    }

    if let Some(cfg) = &cfg
        && check_codex
    {
        check_vscode_editor_config(&mut report, cfg);
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
                format!(
                    "{err:#}; start it with `{brand_binary} start`",
                    brand_binary = BRAND.binary_name
                ),
            ),
            Err(err) => report.error("local proxy MITM", format!("{err:#}")),
        }
        let health_base = match target {
            DoctorTarget::Claude => provider_route(cfg, ProviderKind::Claude).0,
            DoctorTarget::Codex => provider_route(cfg, ProviderKind::Codex).0,
            DoctorTarget::All => cfg.base_url.as_str(),
        };
        let egress = Egress::for_config(cfg);
        report.ok(
            "upstream proxy",
            format!(
                "{} (as seen by this doctor process; the service logs its own at startup)",
                egress.upstream.description()
            ),
        );
        if let Some(message) = egress.upstream.unavailable() {
            report.error("upstream proxy", message);
        }
        for (label, url) in [
            (
                format!("{brand_product} egress", brand_product = BRAND.product_name),
                health_base,
            ),
            (
                "Claude downloads egress".to_string(),
                "https://downloads.claude.ai",
            ),
        ] {
            match upstream_proxy::route_for_url_blocking(&egress.upstream, url) {
                Ok(route) => report.ok(&label, format!("{url} {route}")),
                Err(error) => report.error(&label, format!("{url}: {error:#}")),
            }
        }
        match runtime.block_on(check_gateway_health(health_base, &egress)) {
            Ok(status) => report.ok(
                &format!("{brand_product} health", brand_product = BRAND.product_name),
                status,
            ),
            Err(err) => report.error(
                &format!("{brand_product} health", brand_product = BRAND.product_name),
                format!("{err:#}"),
            ),
        }
    }

    report.finish()
}

fn check_vscode_editor_config(report: &mut DoctorReport, cfg: &AppConfig) {
    let Some(home) = home_dir() else {
        report.warn(
            "VSCode settings",
            "could not resolve the current user's home",
        );
        return;
    };
    let paths = vscode::settings_paths(&home);
    if paths.is_empty() {
        return;
    }
    let mut managed = false;
    for path in paths {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        if !vscode::has_managed_proxy(&raw) {
            continue;
        }
        managed = true;
        match vscode::validate_settings(&raw, &cfg.listen) {
            Ok(()) => report.ok("VSCode settings", path.display().to_string()),
            Err(error) => report.warn(
                "VSCode settings",
                format!(
                    "{}: {error}; repeat optional editor setup with --configure-vscode-editor after resolving explicit conflicts",
                    path.display()
                ),
            ),
        }
    }
    if !managed {
        report.ok(
            "VSCode editor integration",
            "optional editor-wide proxy is not configured; provider-specific CA configuration is checked separately",
        );
        return;
    }
    match vscode::certificate_trust(&home, Path::new(&cfg.ca_cert_path)) {
        Ok(true) => report.ok("VSCode certificate loader", format!("recognizes the current {brand_product} CA; this is not a live UI or model-request test", brand_product = BRAND.product_name)),
        Ok(false) => report.warn("VSCode certificate loader", format!("does not trust the {brand_product} CA; provider-specific CA settings do not establish editor-host trust", brand_product = BRAND.product_name)),
        Err(error) => report.warn("VSCode certificate loader", error.to_string()),
    }
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
            bail!(
                "{brand_product} doctor found {} error(s)",
                self.errors,
                brand_product = BRAND.product_name
            );
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
            "WARN environment: {key} is set in this shell. For {brand_product} local proxy mode, unset it before launching Claude Code: unset {CONFLICTING_ENV_UNSET_KEYS}",
            brand_product = BRAND.product_name
        );
    }
    for key in process_proxy_env_conflicts(&format!("http://{DEFAULT_LOCAL_PROXY_LISTEN}")) {
        eprintln!(
            "WARN environment: {key} is set in this shell. For {brand_product} local proxy mode, remove conflicting proxy variables before launching Claude Code: unset {CLAUDE_PROXY_ENV_UNSET_KEYS}",
            brand_product = BRAND.product_name
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
            "WARN Claude settings: {} contains legacy Claude Code overrides: {}. Remove these entries before launching Claude Code with {brand_product}.",
            paths.settings_path.display(),
            format_claude_settings_override_locations(&locations),
            brand_product = BRAND.product_name
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
                "Claude settings warning: {} contains legacy Claude Code overrides: {}; remove these entries before launching Claude Code with {brand_product}",
                paths.settings_path.display(),
                format_claude_settings_override_locations(&locations),
                brand_product = BRAND.product_name
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

fn provider_route(cfg: &AppConfig, provider: ProviderKind) -> (&str, &str) {
    let explicit = match provider {
        ProviderKind::Claude => cfg.providers.claude.as_ref(),
        ProviderKind::Codex => cfg.providers.codex.as_ref(),
    };
    match explicit {
        Some(value) => (value.base_url.as_str(), value.api_key.as_str()),
        None => (cfg.base_url.as_str(), cfg.api_key.as_str()),
    }
}

fn check_provider_route(report: &mut DoctorReport, cfg: &AppConfig, provider: ProviderKind) {
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

fn check_app_config(report: &mut DoctorReport, cfg: &AppConfig) {
    if cfg.version == CONFIG_VERSION.get() {
        report.ok("config version", CONFIG_VERSION.get().to_string());
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
                    format!("not reachable at http://{addr} ({err}); start it with `{brand_binary} start`", brand_binary = BRAND.binary_name),
                ),
            }
        }
        Err(err) => report.error("listen", format!("invalid listen address: {err}")),
    }

    let ca_path = PathBuf::from(&cfg.ca_cert_path);
    check_ca_cert(report, "configured CA", &ca_path);
    #[cfg(target_os = "windows")]
    check_stale_windows_app_cas(report, &ca_path);
    if cfg.ca_key_path.trim().is_empty() {
        report.error(
            "configured CA key",
            format!(
                "missing; rerun {brand_product} setup",
                brand_product = BRAND.product_name
            ),
        );
    } else {
        report.ok(
            "configured CA key",
            "private installation key path configured",
        );
    }
}

fn check_claude_config(
    report: &mut DoctorReport,
    cfg: Option<&AppConfig>,
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
                "{} contains {}; remove these entries before launching Claude Code with {brand_product}",
                paths.settings_path.display(),
                format_claude_settings_override_locations(&overrides), brand_product = BRAND.product_name
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
                    format!(
                        "{} differs from {brand_product} config CA path",
                        value,
                        brand_product = BRAND.product_name
                    ),
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
                        format!(
                            "configured and matches {brand_product} config",
                            brand_product = BRAND.product_name
                        ),
                    );
                } else {
                    report.error(
                        "CLAUDE_CODE_OAUTH_TOKEN",
                        format!(
                            "does not match {brand_product} config api_key",
                            brand_product = BRAND.product_name
                        ),
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
                "{} still exists; rerun `{brand_binary} init ...` to remove stale OAuth state",
                paths.credentials_path.display(),
                brand_binary = BRAND.binary_name
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

fn check_codex_config(report: &mut DoctorReport, cfg: Option<&AppConfig>, required: bool) {
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
                            format!("direct endpoint override remains; run `{brand_binary} init-codex` to migrate it", brand_binary = BRAND.binary_name),
                        );
                    } else {
                        report.ok("Codex base_url", "no direct root endpoint override");
                    }
                    if document.get("model_providers").is_some() {
                        report.warn(
                            "Codex providers",
                            format!("custom provider configuration remains; run `{brand_binary} init-codex` to remove it", brand_binary = BRAND.binary_name),
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
            Ok(()) => match codex_auth_expiry_warning(&auth_path) {
                Ok(None) => report.ok("Codex auth", "ChatGPT OAuth token mode configured"),
                Ok(Some(warning)) => report.warn("Codex auth", warning),
                Err(err) => report.error("Codex auth", format!("{err:#}")),
            },
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
            format!(
                "missing; run `{brand_binary} init-codex` to configure the local proxy route",
                brand_binary = BRAND.binary_name
            ),
        );
    } else {
        report.warn(
            "Codex .env",
            format!("missing; run `{brand_binary} init-codex` before using an external Codex app-server", brand_binary = BRAND.binary_name),
        );
    }
    if cfg.is_none() {
        report.warn(
            "Codex route",
            format!(
                "{brand_product} config is unavailable",
                brand_product = BRAND.product_name
            ),
        );
    }
    check_codex_environment_context_time(report, &codex_dir);
}

fn managed_codex_config_paths(codex_dir: &Path) -> Result<Vec<PathBuf>> {
    let config_path = codex_dir.join("config.toml");
    let mut paths = Vec::new();
    if config_path.is_file() {
        paths.push(config_path);
    }
    let mut extra = Vec::new();
    for entry in fs::read_dir(codex_dir)
        .with_context(|| format!("failed to list {}", codex_dir.display()))?
    {
        let path = entry
            .with_context(|| format!("failed to list {}", codex_dir.display()))?
            .path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".config.toml"))
        {
            extra.push(path);
        }
    }
    extra.sort();
    paths.extend(extra);
    Ok(paths)
}

fn check_codex_environment_context_time(report: &mut DoctorReport, codex_dir: &Path) {
    const LABEL: &str = "Codex time reporting";
    let mut profiles = vec![(codex_dir.to_path_buf(), false)];
    match app_config_dir() {
        Ok(app_root) => {
            let desktop_codex = app_root.join("desktop").join("codex");
            if desktop_codex.is_dir() {
                profiles.push((desktop_codex, true));
            }
        }
        Err(error) => report.warn(
            LABEL,
            format!("check incomplete: isolated Desktop profile could not be located: {error:#}"),
        ),
    }
    for (directory, isolated_desktop) in profiles {
        // A missing standard config.toml is reported by the general Codex
        // config check; the isolated Desktop profile needs its own warning.
        let config_path = directory.join("config.toml");
        if isolated_desktop && !config_path.is_file() {
            report.warn(
                LABEL,
                format!(
                    "{} is missing; time reporting is not turned off for the isolated Desktop profile. Relaunch `{brand_binary} desktop codex` to recreate it",
                    config_path.display(), brand_binary = BRAND.binary_name
                ),
            );
        }
        let paths = match managed_codex_config_paths(&directory) {
            Ok(paths) => paths,
            Err(error) => {
                report.warn(LABEL, format!("check incomplete: {error:#}"));
                continue;
            }
        };
        let remedy = if isolated_desktop {
            format!(
                "relaunch `{brand_binary} desktop codex`",
                brand_binary = BRAND.binary_name
            )
        } else {
            format!(
                "re-run `{brand_binary} init-codex`",
                brand_binary = BRAND.binary_name
            )
        };
        for path in paths {
            let path_text = path.display();
            match read_codex_environment_context_time(&path) {
                Ok(CodexEnvironmentContextTime::Disabled) => report.ok(
                    LABEL,
                    format!("{path_text}: {CODEX_ENVIRONMENT_CONTEXT_TIME_KEY} = false"),
                ),
                Ok(CodexEnvironmentContextTime::Missing | CodexEnvironmentContextTime::Enabled) => {
                    report.warn(
                        LABEL,
                        format!(
                            "{path_text}: time reporting is not turned off by this config; {remedy}, then restart Codex and start a new session"
                        ),
                    )
                }
                Ok(CodexEnvironmentContextTime::Invalid) => report.warn(
                    LABEL,
                    format!(
                        "{path_text}: invalid type for {CODEX_ENVIRONMENT_CONTEXT_TIME_KEY}; fix it or {remedy}"
                    ),
                ),
                Err(error) => report.warn(LABEL, format!("check incomplete: {error:#}")),
            }
        }
    }
}

// Another installation CA of this program left trusted in a Windows root store is harmless for
// leaves that carry an authority key identifier, but older leaves did
// not, and clients that build chains by subject name then fail with a
// signature error. Report it; removal stays a user decision.
/// Lists root CAs whose subject carries this brand's CA organization.
#[cfg(any(target_os = "windows", test, feature = "contract"))]
const STALE_CA_LISTING_SCRIPT: &str = "$ErrorActionPreference='Stop'; foreach ($store in 'CurrentUser','LocalMachine') { Get-ChildItem \"Cert:\\$store\\Root\" | Where-Object { $_.Subject -match '(^|, )O=@@CA_ORG@@(,|$)' } | ForEach-Object { $_.Thumbprint + ' ' + $store + ' ' + [Convert]::ToBase64String($_.RawData) } }";

#[cfg(target_os = "windows")]
fn check_stale_windows_app_cas(report: &mut DoctorReport, ca_path: &Path) {
    let current = fs::read(ca_path).ok().and_then(|pem| {
        rustls_pemfile::certs(&mut pem.as_slice())
            .next()
            .and_then(Result::ok)
            .map(|der| base64::engine::general_purpose::STANDARD.encode(der.as_ref()))
    });
    let Some(current) = current else {
        return;
    };
    let script = script_brand::render(STALE_CA_LISTING_SCRIPT);
    let listing = command_output(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script.as_str()],
    );
    match listing {
        Ok(listing) => {
            let stale = stale_app_ca_thumbprints(&listing, &current);
            if !stale.is_empty() {
                report.warn(
                    &format!("other {brand_product} CAs", brand_product = BRAND.product_name),
                    format!(
                        "{} other {brand_product} CA(s) are trusted in Windows root stores ({}); they may belong to another {brand_product} instance or an earlier installation, so confirm before removing them",
                        stale.len(),
                        stale.join(", "), brand_product = BRAND.product_name
                    ),
                );
            }
        }
        Err(error) => report.warn(
            &format!(
                "other {brand_product} CAs",
                brand_product = BRAND.product_name
            ),
            format!("could not inspect: {error:#}"),
        ),
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn stale_app_ca_thumbprints(listing: &str, current_der_base64: &str) -> Vec<String> {
    let mut stale = Vec::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let (Some(thumbprint), Some(store), Some(der)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let entry = format!("{thumbprint} in {store}\\Root");
        if der != current_der_base64 && !stale.contains(&entry) {
            stale.push(entry);
        }
    }
    stale
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
Stop the existing process, or if it is a {brand_product} service run `{brand_binary} stop` first.",
                owner_summary,
                brand_binary = BRAND.binary_name,
                brand_product = BRAND.product_name
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
    if owners.iter().any(|owner| owner.is_app()) {
        report.ok("listen owner", summary);
    } else {
        report.warn(
            "listen owner",
            format!(
                "non-{brand_product} process on {addr}: {summary}",
                brand_product = BRAND.product_name
            ),
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ListenPortOwner {
    pid: u32,
    name: String,
}

impl ListenPortOwner {
    fn is_app(&self) -> bool {
        let binary = BRAND.binary_name.to_ascii_lowercase();
        self.name.eq_ignore_ascii_case(&binary) || self.name.to_ascii_lowercase().contains(&binary)
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

async fn check_gateway_health(base_url: &str, egress: &Egress) -> Result<String> {
    let health_url = format!("{}/health", base_url.trim().trim_end_matches('/'));
    let response = egress
        .client_builder(&health_url)?
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

async fn connect_local_proxy_tls(
    cfg: &AppConfig,
) -> Result<tokio_rustls::client::TlsStream<TokioTcpStream>> {
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
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(ANTHROPIC_HOST.to_string())
        .context("failed to build Anthropic TLS server name")?;
    let tls = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await
    .context("timed out during local proxy MITM TLS handshake")?
    .context("local proxy MITM TLS handshake failed")?;
    Ok(tls)
}

async fn check_local_proxy_mitm(cfg: &AppConfig) -> Result<String> {
    let addr = &cfg.listen;
    let mut tls = connect_local_proxy_tls(cfg).await?;
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
    .with_context(|| format!("local proxy closed before the reused sidecar probe; restart the proxy with `{brand_binary} restart`", brand_binary = BRAND.binary_name))?;
    let policy_head = read_http_response_head(&mut tls, "sidecar policy_limits response")
        .await
        .with_context(|| format!("local proxy did not keep the sidecar TLS connection alive; restart the proxy with `{brand_binary} restart`", brand_binary = BRAND.binary_name))?;
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
        .with_context(|| {
            format!(
                "failed to parse configured {brand_product} CA PEM",
                brand_product = BRAND.product_name
            )
        })?;
    if certs.is_empty() {
        bail!(
            "configured {brand_product} CA {} did not contain a PEM certificate",
            path.display(),
            brand_product = BRAND.product_name
        );
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).with_context(|| {
            format!(
                "failed to trust configured {brand_product} CA",
                brand_product = BRAND.product_name
            )
        })?;
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
                    format!("systemd and managed background instances are both active; run `{brand_binary} restart`", brand_binary = BRAND.binary_name),
                );
            }
            return;
        }
        Ok(Some(state)) => report.warn(
            "service state",
            format!(
                "stale managed background state for pid {}; run `{brand_binary} start`",
                state.pid,
                brand_binary = BRAND.binary_name
            ),
        ),
        Ok(None) => {}
        Err(err) => report.warn("service state", err.to_string()),
    }

    if let Err(err) = ensure_systemd_user_available() {
        report.warn(
            "service",
            format!(
                "not running; systemd --user unavailable ({err}); `{brand_binary} start` will use the managed background fallback", brand_binary = BRAND.binary_name
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
        report.warn(
            "service",
            format!(
                "not installed; run `{brand_binary} start` to install it",
                brand_binary = BRAND.binary_name
            ),
        );
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
async fn download_update_manifest(url: &str, egress: &Egress) -> Result<Option<UpdateManifest>> {
    let response = egress
        .client_builder(url)?
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
async fn download_update_asset(url: &str, egress: &Egress) -> Result<Vec<u8>> {
    let response = egress
        .client_builder(url)?
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
const EGRESS_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// The whole fixed-source download on an abandonable runtime: egress setup
/// (which may block on system proxy discovery, such as `scutil --proxy`)
/// and the fetch each run within their time budgets.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[allow(clippy::too_many_arguments)]
fn fixed_download(
    policy: &FixedUrlPolicy<'_>,
    manifest_url: &str,
    asset_url_template: &str,
    cfg: Option<AppConfig>,
    asset: &str,
    current_version: &str,
    current_sha256: &str,
) -> Result<FixedUpdate> {
    block_on_abandoning(async move {
        let egress = tokio::time::timeout(
            EGRESS_SETUP_TIMEOUT,
            tokio::task::spawn_blocking(move || Egress::for_optional_config(cfg.as_ref())),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "proxy discovery did not complete within {}s",
                EGRESS_SETUP_TIMEOUT.as_secs()
            )
        })?
        .context("proxy discovery failed")?;
        fetch_fixed_update(
            policy,
            manifest_url,
            asset_url_template,
            asset,
            current_version,
            current_sha256,
            &egress,
        )
        .await
    })?
}

/// Runs `future` on its own runtime and then shuts that runtime down without
/// waiting for blocking work a timed-out future left behind (route
/// selection stuck on proxy auto-configuration, for example): the command
/// returns when the future does. Such work ends with the process.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn block_on_abandoning<F: std::future::Future>(future: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start async runtime")?;
    let output = runtime.block_on(future);
    runtime.shutdown_background();
    Ok(output)
}

/// The URLs a fixed update source may request: exact hosts, a scheme and
/// (for HTTPS) the default port only, no user information.
pub(crate) struct FixedUrlPolicy<'a> {
    hosts: &'a [&'a str],
    scheme: &'static str,
    /// Ports allowed besides none; empty: the scheme's default port only.
    ports: &'a [u16],
}

impl<'a> FixedUrlPolicy<'a> {
    pub(crate) fn https(hosts: &'a [&'a str]) -> Self {
        Self {
            hosts,
            scheme: "https",
            ports: &[],
        }
    }

    pub(crate) fn check(&self, url: &str) -> Result<url::Url> {
        let parsed = url::Url::parse(url).with_context(|| format!("invalid URL {url:?}"))?;
        if parsed.scheme() != self.scheme {
            bail!("{url} does not use {}", self.scheme);
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("{url} carries user information");
        }
        if parsed.fragment().is_some() {
            bail!("{url} carries a fragment");
        }
        if parsed
            .port()
            .is_some_and(|port| !self.ports.contains(&port))
        {
            bail!("{url} names a port that is not allowed");
        }
        let host = parsed.host_str().unwrap_or_default();
        if !self.hosts.contains(&host) {
            bail!("{url} is not on an allowed update host");
        }
        Ok(parsed)
    }
}

/// The asset URL of a fixed source for one release `version` (`X.Y.Z`).
pub(crate) fn fixed_asset_url(template: &str, version: &str, asset: &str) -> String {
    template
        .replace("{version}", version)
        .replace("{asset}", asset)
}

/// `X.Y.Z`, three decimal numbers without signs, spaces, prefixes or
/// suffixes (leading zeros only for a lone `0`).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_release_version(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 9
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIXED_MANIFEST_LIMIT: u64 = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIXED_ASSET_MIN: u64 = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIXED_ASSET_MAX: u64 = 64 * 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const FIXED_MAX_REDIRECTS: usize = 5;

/// Body of a fixed-source GET, or `None` for 404 at the end of the chain.
/// Each hop is checked against `policy` and routed for its own URL (a proxy
/// that cannot be used fails the request instead of going direct); only
/// 301/302/303/307/308 are followed, at most `FIXED_MAX_REDIRECTS` times,
/// within `total` for the whole chain; the body is read up to `limit` bytes.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn fixed_get(
    policy: &FixedUrlPolicy<'_>,
    url: &str,
    limit: u64,
    total: Duration,
    egress: &Egress,
) -> Result<Option<Vec<u8>>> {
    let deadline = tokio::time::Instant::now() + total;
    let mut current = policy.check(url)?;
    let mut redirects = 0;
    let expired = || anyhow::anyhow!("GET {url} did not complete within {}s", total.as_secs());
    loop {
        // Route selection (which may block on proxy auto-configuration) and
        // the request both count against the chain's deadline.
        let builder = {
            let egress = egress.clone();
            let target = current.to_string();
            tokio::time::timeout_at(
                deadline,
                tokio::task::spawn_blocking(move || egress.client_builder(&target)),
            )
            .await
            .map_err(|_| expired())?
            .context("update route selection failed")??
        };
        // The deadline below bounds connect, response head and body alike.
        let request = builder
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build update HTTP client")?
            .get(current.as_str())
            .send();
        let response = tokio::time::timeout_at(deadline, request)
            .await
            .map_err(|_| expired())?
            .with_context(|| format!("failed to GET {current}"))?;
        let status = response.status();
        if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            redirects += 1;
            if redirects > FIXED_MAX_REDIRECTS {
                bail!("GET {url} redirected more than {FIXED_MAX_REDIRECTS} times");
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .with_context(|| format!("GET {current} returned {status} without a Location"))?
                .to_str()
                .map_err(|_| {
                    anyhow::anyhow!(
                        "GET {current} returned {status} with a Location that is not plain ASCII"
                    )
                })?;
            let next = current
                .join(location)
                .with_context(|| format!("GET {current} redirected to an invalid Location"))?;
            current = policy.check(next.as_str()).with_context(|| {
                format!("GET {current} redirected to a URL that is not allowed")
            })?;
            continue;
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            bail!("GET {current} returned {status}");
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit)
        {
            bail!("GET {current} is larger than {limit} bytes");
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = tokio::time::timeout_at(deadline, response.chunk())
            .await
            .map_err(|_| expired())?
            .with_context(|| format!("failed to read {current}"))?
        {
            if body.len() as u64 + chunk.len() as u64 > limit {
                bail!("GET {current} is larger than {limit} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        return Ok(Some(body));
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
enum FixedUpdate {
    /// Nothing to download; the message says why.
    Current(String),
    /// The verified asset of release `version`.
    Download { bytes: Vec<u8>, version: String },
}

/// Fetches and verifies the update from a fixed source: the manifest is
/// required (a missing one is an error, never an unverified download), its
/// version must be `X.Y.Z`, and the asset of exactly that version must match
/// the manifest's size and SHA-256.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn fetch_fixed_update(
    policy: &FixedUrlPolicy<'_>,
    manifest_url: &str,
    asset_url_template: &str,
    asset: &str,
    current_version: &str,
    current_sha256: &str,
    egress: &Egress,
) -> Result<FixedUpdate> {
    println!("Checking: {manifest_url}");
    let Some(raw) = fixed_get(
        policy,
        manifest_url,
        FIXED_MANIFEST_LIMIT,
        Duration::from_secs(30),
        egress,
    )
    .await?
    else {
        bail!(
            "the {brand_product} update manifest is unavailable (HTTP 404 at {manifest_url}); no release may have been published yet",
            brand_product = BRAND.product_name
        );
    };
    let manifest = serde_json::from_slice::<UpdateManifest>(&raw)
        .with_context(|| format!("failed to parse {manifest_url}"))?;
    let version = manifest.version.as_str();
    if !is_release_version(version) {
        bail!("{manifest_url} names version {version:?}, not X.Y.Z");
    }
    let info = manifest
        .assets
        .get(asset)
        .with_context(|| format!("manifest does not include asset {asset}"))?;
    let expected = info.sha256.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("manifest asset {asset} has invalid sha256 {expected:?}");
    }
    let size = info
        .size
        .filter(|size| (FIXED_ASSET_MIN..=FIXED_ASSET_MAX).contains(size))
        .with_context(|| {
            format!(
                "manifest asset {asset} has no size between {FIXED_ASSET_MIN} and {FIXED_ASSET_MAX} bytes"
            )
        })?;
    println!(
        "Latest: {brand_binary} {version}",
        brand_binary = BRAND.binary_name
    );
    let ordering = compare_versions(version, current_version)
        .with_context(|| format!("failed to compare remote version {version:?}"))?;
    if ordering == Ordering::Less {
        return Ok(FixedUpdate::Current(format!(
            "Already current: {brand_binary} {current_version} (remote {brand_binary} {version})",
            brand_binary = BRAND.binary_name
        )));
    }
    if ordering == Ordering::Equal && current_sha256 == expected {
        return Ok(FixedUpdate::Current(format!(
            "Already current: {brand_binary} {current_version}",
            brand_binary = BRAND.binary_name
        )));
    }
    if ordering == Ordering::Equal {
        println!("Same version but local binary hash differs; refreshing {asset}");
    }
    let url = fixed_asset_url(asset_url_template, version, asset);
    println!("Downloading: {url}");
    let bytes = fixed_get(policy, &url, size, Duration::from_secs(300), egress)
        .await?
        .with_context(|| {
            format!("release asset {asset} of {version} is missing (HTTP 404 at {url})")
        })?;
    if bytes.len() as u64 != size {
        bail!(
            "downloaded {asset} has {} bytes, the manifest says {size}",
            bytes.len()
        );
    }
    let actual = sha256_hex(&bytes);
    if actual != expected {
        bail!("downloaded {asset} sha256 mismatch: expected {expected}, got {actual}");
    }
    Ok(FixedUpdate::Download {
        bytes,
        version: version.to_string(),
    })
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
        .strip_prefix(BRAND.binary_name)
        .and_then(|rest| rest.strip_prefix(' '))
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
fn current_platform_asset_name() -> Result<String> {
    let platform = match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-aarch64",
        ("windows", "x86_64") => "windows-x86_64.exe",
        ("windows", "aarch64") => "windows-aarch64.exe",
        (os, arch) => bail!("unsupported {os} architecture for update: {arch}"),
    };
    Ok(format!("{}{platform}", BRAND.update.asset_prefix))
}

/// Platform part of a release asset name of this brand (`linux-x86_64`, …).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn asset_platform(asset: &str) -> &str {
    asset
        .strip_prefix(BRAND.update.asset_prefix)
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_update_asset(bytes: &[u8], asset: &str) -> Result<()> {
    let platform = asset_platform(asset);
    if platform.starts_with("linux-") {
        return validate_elf_asset(bytes, asset);
    }
    if platform.starts_with("macos-") {
        return validate_macho_asset(bytes, asset);
    }
    if platform.starts_with("windows-") {
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
    match (asset_platform(asset), machine) {
        ("linux-x86_64", 62) | ("linux-aarch64", 183) => Ok(()),
        _ => bail!("downloaded {asset} has unexpected ELF machine id {machine}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn validate_macho_asset(bytes: &[u8], asset: &str) -> Result<()> {
    if bytes.len() < 8 || bytes[..4] != [0xcf, 0xfa, 0xed, 0xfe] {
        bail!("downloaded {asset} is not a 64-bit Mach-O executable");
    }
    let cpu_type = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    match (asset_platform(asset), cpu_type) {
        ("macos-x86_64", 0x0100_0007) | ("macos-aarch64", 0x0100_000c) => Ok(()),
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
    match (asset_platform(asset), machine) {
        ("windows-x86_64.exe", 0x8664) | ("windows-aarch64.exe", 0xaa64) => Ok(()),
        _ => bail!("downloaded {asset} has unexpected PE machine id {machine:#x}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
/// Like [`write_update_candidate`], but only as a new file (never through
/// an existing file or link at that name).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn write_new_update_candidate(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CANDIDATE_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CANDIDATE_PROBE_LIMIT: usize = 4096;

/// `<candidate> --version` standard output, bounded: the candidate is killed
/// and reaped when it runs past `timeout` or prints more than `limit` bytes,
/// and a failed exit is an error.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn probe_candidate_version(path: &Path, timeout: Duration, limit: usize) -> Result<String> {
    use std::io::Read;
    let mut child = ProcessCommand::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to execute {}", path.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("candidate stdout is not captured")?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout.take(limit as u64 + 1).read_to_end(&mut output);
        output
    });
    let deadline = std::time::Instant::now() + timeout;
    let stop = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let status = loop {
        if reader.is_finished() && child.try_wait()?.is_none() {
            // The reader stops at the limit or at end of output; a child
            // still running after printing too much is stopped now.
            let output = reader.join().unwrap_or_default();
            if output.len() > limit {
                stop(&mut child);
                bail!("{} printed more than {limit} bytes", path.display());
            }
            return finish_probe(path, &mut child, output, deadline, stop);
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            stop(&mut child);
            bail!(
                "{} did not exit within {}s",
                path.display(),
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Exited: the reader ends when the pipe closes (a descendant keeping it
    // open is not waited for past the deadline).
    while !reader.is_finished() {
        if std::time::Instant::now() >= deadline {
            bail!("{} left its output open", path.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = reader.join().unwrap_or_default();
    if output.len() > limit {
        bail!("{} printed more than {limit} bytes", path.display());
    }
    if !status.success() {
        bail!("{} exited with {status}", path.display());
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// The child finished printing (within `limit`) but has not exited yet: wait
/// for it until `deadline`.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn finish_probe(
    path: &Path,
    child: &mut std::process::Child,
    output: Vec<u8>,
    deadline: std::time::Instant,
    stop: impl Fn(&mut std::process::Child),
) -> Result<String> {
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("{} exited with {status}", path.display());
            }
            return Ok(String::from_utf8_lossy(&output).into_owned());
        }
        if std::time::Instant::now() >= deadline {
            stop(child);
            bail!("{} did not exit after printing its version", path.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Exclusive lock of an installation directory's update (`<candidate
/// prefix>lock` next to the executable); a second update fails at once.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn lock_update_directory(directory: &Path) -> Result<fs::File> {
    let path = directory.join(format!("{}lock", BRAND.update.candidate_prefix));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => bail!(
            "another {brand_binary} update is running in {}",
            directory.display(),
            brand_binary = BRAND.binary_name
        ),
        Err(fs::TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("failed to lock {}", path.display()))
        }
    }
}

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
/// Standard output of a successful run, as printed (lossy UTF-8).
fn command_stdout_raw(path: &Path, args: &[&str]) -> Result<String> {
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
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether `--version` output is exactly `<binary> <version>`, optionally
/// followed by one line ending (`\n` or `\r\n`), nothing else.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn reports_exact_version(output: &str, binary: &str, version: &str) -> bool {
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    line == format!("{binary} {version}")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn update_candidate_name(unique: &str) -> String {
    if cfg!(windows) {
        format!("{}{unique}.exe", BRAND.update.candidate_prefix)
    } else {
        format!("{}{unique}", BRAND.update.candidate_prefix)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn update_backup_name() -> String {
    if cfg!(windows) {
        format!(
            "{}{}.exe",
            BRAND.update.backup_prefix,
            Utc::now().format("%Y%m%d-%H%M%S")
        )
    } else {
        format!(
            "{}{}",
            BRAND.update.backup_prefix,
            Utc::now().format("%Y%m%d-%H%M%S")
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finalize_update(
    current_exe: &Path,
    candidate_path: &Path,
    backup_path: &Path,
    _restart_service: bool,
    _expected_sha256: &str,
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
    expected_sha256: &str,
) -> Result<()> {
    fs::copy(current_exe, backup_path).with_context(|| {
        format!(
            "failed to back up {} to {}",
            current_exe.display(),
            backup_path.display()
        )
    })?;
    let script_path = candidate_path.with_extension("ps1");
    let status_path = windows_update_status_path(current_exe)?;
    fs::write(&status_path, "pending\n")
        .with_context(|| format!("failed to write {}", status_path.display()))?;
    let script = render_windows_update_script(
        std::process::id(),
        current_exe,
        candidate_path,
        &script_path,
        &status_path,
        restart_service,
        expected_sha256,
    )?;
    fs::write(&script_path, script)
        .with_context(|| format!("failed to write {}", script_path.display()))?;
    if let Err(err) = ProcessCommand::new("powershell")
        .env(BRAND.env.home, app_config_dir()?)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(&script_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        let _ = fs::write(
            &status_path,
            format!("failed: could not start update helper: {err}\n"),
        );
        return Err(err).context("failed to start Windows update helper");
    }
    println!(
        "Windows update helper started; replacement result: {}",
        status_path.display()
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn render_windows_update_script(
    pid: u32,
    current_exe: &Path,
    candidate_path: &Path,
    script_path: &Path,
    status_path: &Path,
    restart_service: bool,
    expected_sha256: &str,
) -> Result<String> {
    if expected_sha256.len() != 64 || !expected_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid expected Windows update sha256");
    }
    Ok(format!(
        "$ErrorActionPreference = 'Stop'\r\n\
$currentExe = {}\r\n\
$candidate = {}\r\n\
$statusPath = {}\r\n\
$expectedHash = '{expected_sha256}'\r\n\
$restartService = ${}\r\n\
$stopped = $false\r\n\
function Invoke-{id}Command([string]$verb) {{\r\n\
    $info = [Diagnostics.ProcessStartInfo]::new()\r\n\
    $info.FileName = $currentExe\r\n\
    $info.Arguments = $verb\r\n\
    $info.UseShellExecute = $false\r\n\
    $info.CreateNoWindow = $true\r\n\
    $process = [Diagnostics.Process]::Start($info)\r\n\
    try {{\r\n\
        if (-not $process.WaitForExit(30000)) {{\r\n\
            try {{ $process.Kill() }} catch {{}}\r\n\
            throw \"{brand_product} $verb did not exit within 30 seconds\"\r\n\
        }}\r\n\
        if ($process.ExitCode -ne 0) {{ throw \"{brand_product} $verb exited with $($process.ExitCode)\" }}\r\n\
    }} finally {{ $process.Dispose() }}\r\n\
}}\r\n\
try {{\r\n\
    Set-Content -LiteralPath $statusPath -Value 'pending: waiting for updater' -Encoding UTF8\r\n\
    Wait-Process -Id {pid} -Timeout 30 -ErrorAction SilentlyContinue\r\n\
    if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ throw 'Updater process did not exit within 30 seconds' }}\r\n\
    Set-Content -LiteralPath $statusPath -Value 'pending: stopping {brand_product} processes' -Encoding UTF8\r\n\
    Invoke-{id}Command 'stop'\r\n\
    $stopped = $true\r\n\
    Set-Content -LiteralPath $statusPath -Value 'pending: replacing binary' -Encoding UTF8\r\n\
    $lastError = $null\r\n\
    foreach ($attempt in 1..120) {{\r\n\
        try {{\r\n\
            $replacementBackup = $currentExe + '.replace.' + [guid]::NewGuid().ToString('N') + '.bak'\r\n\
            try {{ [IO.File]::Replace($candidate, $currentExe, $replacementBackup, $true) }}\r\n\
            finally {{ Remove-Item -LiteralPath $replacementBackup -Force -ErrorAction SilentlyContinue }}\r\n\
            $lastError = $null\r\n\
            break\r\n\
        }} catch {{\r\n\
            $lastError = $_\r\n\
            if ($attempt -lt 120) {{ Start-Sleep -Milliseconds 250 }}\r\n\
        }}\r\n\
    }}\r\n\
    if ($null -ne $lastError) {{ throw \"Could not replace {brand_product} binary after 120 attempts: $($lastError.Exception.Message)\" }}\r\n\
    Set-Content -LiteralPath $statusPath -Value 'pending: verifying binary' -Encoding UTF8\r\n\
    $stream = [IO.File]::OpenRead($currentExe)\r\n\
    try {{\r\n\
        $sha = [Security.Cryptography.SHA256]::Create()\r\n\
        try {{ $actualHash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }}\r\n\
        finally {{ $sha.Dispose() }}\r\n\
    }} finally {{ $stream.Dispose() }}\r\n\
    if ($actualHash -cne $expectedHash) {{ throw \"Installed {brand_product} binary hash mismatch: $actualHash\" }}\r\n\
    if ($restartService) {{\r\n\
        Set-Content -LiteralPath $statusPath -Value 'pending: restarting proxy' -Encoding UTF8\r\n\
        Invoke-{id}Command 'restart'\r\n\
    }}\r\n\
    Set-Content -LiteralPath $statusPath -Value \"updated: $actualHash\" -Encoding UTF8\r\n\
    Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue\r\n\
}} catch {{\r\n\
    $failure = $_.Exception.Message\r\n\
    Set-Content -LiteralPath $statusPath -Value \"failed: $failure\" -Encoding UTF8\r\n\
    if ($stopped -and $restartService -and (Test-Path -LiteralPath $currentExe -PathType Leaf)) {{\r\n\
        try {{ Invoke-{id}Command 'start' }} catch {{}}\r\n\
    }}\r\n\
    exit 1\r\n\
}}",
        powershell_quote_path(current_exe)?,
        powershell_quote_path(candidate_path)?,
        powershell_quote_path(status_path)?,
        if restart_service { "true" } else { "false" },
        powershell_quote_path(script_path)?,
        id = script_brand::identifier_prefix(),
        brand_product = BRAND.product_name,
    ))
}

#[cfg(target_os = "windows")]
fn windows_update_status_path(current_exe: &Path) -> Result<PathBuf> {
    Ok(current_exe
        .parent()
        .with_context(|| {
            format!(
                "failed to resolve {brand_product} executable directory",
                brand_product = BRAND.product_name
            )
        })?
        .join(BRAND.update.status_filename))
}

#[cfg(target_os = "windows")]
fn warn_incomplete_windows_update() {
    let Ok(exe) = env::current_exe() else { return };
    let Ok(path) = windows_update_status_path(&exe) else {
        return;
    };
    let Ok(status) = fs::read_to_string(&path) else {
        return;
    };
    let status = status.trim_start_matches('\u{feff}').trim();
    if status.starts_with("failed:") {
        eprintln!(
            "WARN Previous {brand_product} update {status}. Details: {}",
            path.display(),
            brand_product = BRAND.product_name
        );
    } else if status.starts_with("pending") {
        eprintln!(
            "WARN Previous {brand_product} update has not completed; check again shortly. Status: {}",
            path.display(),
            brand_product = BRAND.product_name
        );
    }
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

    let exe = env::current_exe().with_context(|| {
        format!(
            "failed to resolve current {brand_binary} executable",
            brand_binary = BRAND.binary_name
        )
    })?;
    let app_home = absolute_existing_or_raw(app_config_dir()?);
    let working_dir = home_dir().context("failed to resolve home directory")?;
    let service_path = service_dir.join(environment_scope::service_name());
    let content = render_user_service(&exe, &app_home, &working_dir)?;
    write_bytes_atomic(&service_path, content.as_bytes(), 0o644)
        .with_context(|| format!("failed to write {}", service_path.display()))?;
    Ok(service_path)
}

#[cfg(target_os = "linux")]
fn render_user_service(exe: &Path, app_home: &Path, working_dir: &Path) -> Result<String> {
    let exe = path_to_string(exe)?;
    let app_home = path_to_string(app_home)?;
    let working_dir = path_to_string(working_dir)?;
    Ok(format!(
        "[Unit]\n\
Description={brand_product} local Claude Code proxy\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
Environment={}\n\
WorkingDirectory={}\n\
ExecStart={} --instance-dir {}\n\
Restart=on-failure\n\
RestartSec=2s\n\
StandardOutput=journal\n\
StandardError=journal\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        systemd_quote(&format!("{}={app_home}", BRAND.env.home))?,
        systemd_path_setting(&working_dir)?,
        systemd_quote(&exe)?,
        systemd_quote(&app_home)?,
        brand_product = BRAND.product_name
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

    let exe = env::current_exe().with_context(|| {
        format!(
            "failed to resolve current {brand_binary} executable",
            brand_binary = BRAND.binary_name
        )
    })?;
    let exe = absolute_existing_or_raw(exe);
    let app_home = absolute_existing_or_raw(app_config_dir()?);
    let working_dir = home_dir().context("failed to resolve home directory")?;
    let plist_path = launchd_plist_path()?;
    let content = render_launchd_plist(&exe, &app_home, &working_dir, &log_path)?;
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
    app_home: &Path,
    working_dir: &Path,
    log_path: &Path,
) -> Result<String> {
    let exe = xml_escape(&path_to_string(exe)?);
    let app_home = xml_escape(&path_to_string(app_home)?);
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
    <string>--instance-dir</string>\n\
    <string>{app_home}</string>\n\
  </array>\n\
  <key>EnvironmentVariables</key>\n\
  <dict>\n\
    <key>{home_variable}</key>\n\
    <string>{app_home}</string>\n\
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
        environment_scope::launchd_label(),
        home_variable = BRAND.env.home,
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
    Ok(launchd_agents_dir()?.join(format!("{}.plist", environment_scope::launchd_label())))
}

#[cfg(target_os = "macos")]
fn launchd_log_path() -> Result<PathBuf> {
    Ok(app_config_dir()?.join(SERVICE_LOG_FILENAME.get()))
}

#[cfg(target_os = "macos")]
fn launchctl_gui_domain() -> Result<String> {
    let uid =
        command_output(MACOS_ID_COMMAND, &["-u"]).context("failed to resolve current macOS uid")?;
    Ok(format!("gui/{}", uid.trim()))
}

#[cfg(target_os = "macos")]
fn launchctl_service_target(domain: &str) -> String {
    format!("{domain}/{}", environment_scope::launchd_label())
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
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to detach {brand_product} background proxy session",
                brand_product = BRAND.product_name
            )
        });
    }
    run_local_proxy(false)
}

#[cfg(target_os = "linux")]
fn start_linux_background_proxy(cfg: &AppConfig) -> Result<u32> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    stop_linux_background_proxy()?;
    ensure_listen_available(&cfg.listen)?;

    let app_home = app_config_dir()?;
    fs::create_dir_all(&app_home)
        .with_context(|| format!("failed to create {}", app_home.display()))?;
    let log_path = linux_service_log_path()?;
    match fs::symlink_metadata(&log_path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!(
                "refusing non-regular {brand_product} log path {}",
                log_path.display(),
                brand_product = BRAND.product_name
            )
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

    let exe = env::current_exe().with_context(|| {
        format!(
            "failed to resolve current {brand_binary} executable",
            brand_binary = BRAND.binary_name
        )
    })?;
    let mut child = ProcessCommand::new(exe)
        .arg(LINUX_BACKGROUND_COMMAND)
        .env(BRAND.env.home, &app_home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| {
            format!(
                "failed to start {brand_product} background proxy",
                brand_product = BRAND.product_name
            )
        })?;
    let pid = child.id();
    let startup = (|| -> Result<u32> {
        let identity_deadline = std::time::Instant::now() + Duration::from_secs(1);
        let identity = loop {
            if let Some(status) = child.try_wait().with_context(|| {
                format!(
                    "failed to inspect {brand_product} background proxy",
                    brand_product = BRAND.product_name
                )
            })? {
                bail!(
                    "{brand_product} background proxy exited during startup with {status}; inspect {}",
                    log_path.display(),
                    brand_product = BRAND.product_name
                );
            }
            if let Some(identity) = linux_process_identity(pid)?
                && linux_process_has_background_marker(pid)?
            {
                break identity;
            }
            if std::time::Instant::now() >= identity_deadline {
                bail!(
                    "timed out recording {brand_product} background process identity; inspect {}",
                    log_path.display(),
                    brand_product = BRAND.product_name
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let state = LinuxBackgroundState {
            schema_version: LINUX_BACKGROUND_STATE_VERSION,
            pid,
            start_time_ticks: identity.start_time_ticks,
            instance: Some(app_config_dir()?.display().to_string()),
        };
        write_linux_background_state(&state)?;

        let addr = cfg
            .listen
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid local proxy listen address {:?}", cfg.listen))?;
        let ready_deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().with_context(|| {
                format!(
                    "failed to inspect {brand_product} background proxy",
                    brand_product = BRAND.product_name
                )
            })? {
                bail!(
                    "{brand_product} background proxy exited during startup with {status}; inspect {}",
                    log_path.display(),
                    brand_product = BRAND.product_name
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
                    "timed out waiting for {brand_product} background proxy at {addr}; inspect {}",
                    log_path.display(),
                    brand_product = BRAND.product_name
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
    stop_linux_background_proxy_at(&app_config_dir()?, environment_scope::isolated())
}

#[cfg(target_os = "linux")]
fn stop_linux_background_proxy_at(dir: &Path, isolated: bool) -> Result<bool> {
    let state_path = dir.join(LINUX_PID_FILENAME.get());
    let Some(state) = linux_background_state_at(dir)? else {
        return Ok(false);
    };
    if !linux_background_state_matches_at(&state, dir, isolated)? {
        fs::remove_file(&state_path).with_context(|| {
            format!(
                "failed to remove stale {brand_product} state for pid {}",
                state.pid,
                brand_product = BRAND.product_name
            )
        })?;
        return Ok(false);
    }

    signal_linux_background_process(&state, dir, isolated, libc::SIGTERM)?;
    let term_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < term_deadline {
        if !linux_background_state_matches_at(&state, dir, isolated)? {
            let _ = fs::remove_file(&state_path);
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Revalidate the original process identity immediately before escalation;
    // never signal a PID that has been reused or exec'd into another command.
    if linux_background_state_matches_at(&state, dir, isolated)? {
        signal_linux_background_process(&state, dir, isolated, libc::SIGKILL)?;
    }
    let kill_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < kill_deadline {
        if !linux_background_state_matches_at(&state, dir, isolated)? {
            let _ = fs::remove_file(&state_path);
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!(
        "failed to stop managed {brand_product} background process {}",
        state.pid,
        brand_product = BRAND.product_name
    )
}

#[cfg(target_os = "linux")]
fn signal_linux_background_process(
    state: &LinuxBackgroundState,
    dir: &Path,
    isolated: bool,
    signal: i32,
) -> Result<()> {
    if !linux_background_state_matches_at(state, dir, isolated)? {
        return Ok(());
    }
    let pid = i32::try_from(state.pid).with_context(|| {
        format!(
            "{brand_product} background pid is out of range",
            brand_product = BRAND.product_name
        )
    })?;
    if unsafe { libc::kill(pid, signal) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).with_context(|| {
                format!(
                    "failed to signal {brand_product} process {pid}",
                    brand_product = BRAND.product_name
                )
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_background_state() -> Result<Option<LinuxBackgroundState>> {
    linux_background_state_at(&app_config_dir()?)
}

#[cfg(target_os = "linux")]
fn linux_background_state_at(dir: &Path) -> Result<Option<LinuxBackgroundState>> {
    let path = dir.join(LINUX_PID_FILENAME.get());
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if !metadata.file_type().is_file() {
        bail!(
            "refusing non-regular {brand_product} state path {}",
            path.display(),
            brand_product = BRAND.product_name
        );
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let state: LinuxBackgroundState = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if state.schema_version != LINUX_BACKGROUND_STATE_VERSION
        || state.pid <= 1
        || state.start_time_ticks == 0
    {
        bail!(
            "invalid {brand_product} background state in {}",
            path.display(),
            brand_product = BRAND.product_name
        );
    }
    Ok(Some(state))
}

#[cfg(target_os = "linux")]
fn write_linux_background_state(state: &LinuxBackgroundState) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(state).with_context(|| {
        format!(
            "failed to serialize {brand_product} state",
            brand_product = BRAND.product_name
        )
    })?;
    data.push(b'\n');
    write_bytes_atomic(&linux_background_state_path()?, &data, 0o600)
}

#[cfg(target_os = "linux")]
fn linux_background_state_matches(state: &LinuxBackgroundState) -> Result<bool> {
    linux_background_state_matches_at(state, &app_config_dir()?, environment_scope::isolated())
}

#[cfg(target_os = "linux")]
fn linux_background_state_matches_at(
    state: &LinuxBackgroundState,
    dir: &Path,
    isolated: bool,
) -> Result<bool> {
    if let Some(instance) = &state.instance {
        if instance != &dir.display().to_string() {
            return Ok(false);
        }
    } else if isolated {
        return Ok(false);
    }
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
        .any(|arg| arg == LINUX_BACKGROUND_COMMAND.as_bytes()))
}

#[cfg(target_os = "linux")]
fn acquire_linux_service_lock() -> Result<LinuxServiceLock> {
    acquire_linux_service_lock_at(&app_config_dir()?)
}

#[cfg(target_os = "linux")]
fn acquire_linux_service_lock_at(dir: &Path) -> Result<LinuxServiceLock> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(LINUX_LOCK_FILENAME.get());
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!(
                "refusing non-regular {brand_product} lock path {}",
                path.display(),
                brand_product = BRAND.product_name
            )
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
    Ok(app_config_dir()?.join(LINUX_PID_FILENAME.get()))
}

#[cfg(target_os = "linux")]
fn linux_service_log_path() -> Result<PathBuf> {
    Ok(app_config_dir()?.join(SERVICE_LOG_FILENAME.get()))
}

#[cfg(target_os = "linux")]
fn run_linux_background_logs() -> Result<()> {
    let path = linux_service_log_path()?;
    let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
            "{brand_product} background log is unavailable at {}",
            path.display(),
            brand_product = BRAND.product_name
        )
    })?;
    if !metadata.file_type().is_file() {
        bail!(
            "refusing non-regular {brand_product} log path {}",
            path.display(),
            brand_product = BRAND.product_name
        );
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
fn linux_configured_listen_has_app_owner() -> Result<bool> {
    let cfg = match read_app_config() {
        Ok(cfg) => cfg,
        Err(_) => return Ok(false),
    };
    let addr = cfg
        .listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid local proxy listen address {:?}", cfg.listen))?;
    Ok(listen_port_owners(addr).iter().any(ListenPortOwner::is_app))
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

    let exe = env::current_exe().with_context(|| {
        format!(
            "failed to resolve current {brand_binary} executable",
            brand_binary = BRAND.binary_name
        )
    })?;
    let app_home = app_config_dir()?;
    fs::create_dir_all(&app_home)
        .with_context(|| format!("failed to create {}", app_home.display()))?;
    let log_path = windows_log_path()?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    let mut child = ProcessCommand::new(exe)
        .arg(WINDOWS_BACKGROUND_COMMAND)
        .arg("--instance-v2")
        .env(BRAND.env.home, &app_home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| {
            format!(
                "failed to start {brand_product} background proxy",
                brand_product = BRAND.product_name
            )
        })?;
    let pid = child.id();
    let result = (|| -> Result<u32> {
        let process = windows_background::Process::open(pid, false)?
            .context("background proxy exited before its identity could be recorded")?;
        let state = WindowsBackgroundState {
            version: 2,
            pid,
            created: process.created,
            instance: app_config_dir()?.display().to_string(),
        };
        write_bytes_atomic(&windows_pid_path()?, &serde_json::to_vec(&state)?, 0o600)?;
        Ok(pid)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(target_os = "windows")]
fn stop_windows_background_proxy() -> Result<()> {
    stop_windows_background_proxy_at(
        &app_config_dir()?,
        environment_scope::isolated(),
        &[env::current_exe()?],
    )
}

#[cfg(target_os = "windows")]
fn stop_windows_background_proxy_at(
    dir: &Path,
    isolated: bool,
    legacy_executables: &[PathBuf],
) -> Result<()> {
    if let Some(process) = windows_background_process_at(dir, isolated, true, legacy_executables)? {
        process.stop()?;
    }
    stop_windows_log_followers_at(dir)?;
    let _ = fs::remove_file(dir.join(WINDOWS_PID_FILENAME.get()));
    Ok(())
}

#[cfg(target_os = "windows")]
#[derive(Serialize, Deserialize)]
struct WindowsBackgroundState {
    version: u32,
    pid: u32,
    created: u64,
    instance: String,
}

#[cfg(target_os = "windows")]
fn windows_background_process(terminate: bool) -> Result<Option<windows_background::Process>> {
    windows_background_process_at(
        &app_config_dir()?,
        environment_scope::isolated(),
        terminate,
        &[env::current_exe()?],
    )
}

#[cfg(target_os = "windows")]
fn windows_background_process_at(
    dir: &Path,
    isolated: bool,
    terminate: bool,
    legacy_executables: &[PathBuf],
) -> Result<Option<windows_background::Process>> {
    let path = dir.join(WINDOWS_PID_FILENAME.get());
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("cannot read background process state"),
    };
    if let Ok(state) = serde_json::from_str::<WindowsBackgroundState>(&raw) {
        if state.version != 2 || state.instance != dir.display().to_string() {
            bail!("background process state belongs to a different environment");
        }
        let Some(process) = windows_background::Process::open(state.pid, terminate)? else {
            return Ok(None);
        };
        return Ok((process.created == state.created && process.running()).then_some(process));
    }
    // Upgrade compatibility: only the default instance may own a legacy bare PID.
    // Verify its exact executable and old worker command before touching it.
    let pid = raw
        .trim()
        .parse::<u32>()
        .context("invalid background process state")?;
    if isolated {
        bail!("isolated environment has unverified legacy process state");
    }
    let Some(process) = windows_background::Process::open(pid, terminate)? else {
        return Ok(None);
    };
    if !process.running() {
        return Ok(None);
    }
    if !legacy_windows_worker_matches(pid, legacy_executables)? {
        return Ok(None);
    }
    Ok(Some(process))
}

#[cfg(target_os = "windows")]
fn legacy_windows_worker_matches(pid: u32, executables: &[PathBuf]) -> Result<bool> {
    let executables = executables
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let output = ProcessCommand::new("powershell")
        .env(script_brand::env("CHECK_PID"), pid.to_string())
        .env(script_brand::env("CHECK_EXE"), executables)
        .args(["-NoProfile", "-NonInteractive", "-Command",
            &script_brand::render(r#"$ErrorActionPreference='Stop'; $p=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$env:@@ENV@@CHECK_PID); if (!$p) { exit 1 }; $actual=$p.ExecutablePath -replace '^\\\\\?\\',''; $expected=@($env:@@ENV@@CHECK_EXE -split "`n" | Where-Object { ($_ -replace '^\\\\\?\\','') -ieq $actual }); if ($expected.Count -gt 0 -and $p.CommandLine -match '\s__run-background-proxy\s*$') { exit 0 }; exit 1"#)])
        .stdout(Stdio::null()).stderr(Stdio::null()).status()
        .with_context(|| format!("cannot verify legacy {brand_product} worker identity", brand_product = BRAND.product_name))?;
    Ok(output.success())
}

#[cfg(target_os = "windows")]
#[derive(Serialize, Deserialize)]
struct WindowsLogFollower {
    parent: WindowsBackgroundState,
    child: WindowsBackgroundState,
}

#[cfg(target_os = "windows")]
fn register_windows_log_follower(child: u32) -> Result<PathBuf> {
    let directory = app_config_dir()?;
    let state = |pid| -> Result<WindowsBackgroundState> {
        let process =
            windows_background::Process::open(pid, false)?.context("log follower exited")?;
        Ok(WindowsBackgroundState {
            version: 2,
            pid,
            created: process.created,
            instance: directory.display().to_string(),
        })
    };
    let parent = std::process::id();
    let record = WindowsLogFollower {
        parent: state(parent)?,
        child: state(child)?,
    };
    let path = directory
        .join("log-followers")
        .join(format!("{parent}.json"));
    fs::create_dir_all(path.parent().unwrap())?;
    write_bytes_atomic(&path, &serde_json::to_vec(&record)?, 0o600)?;
    Ok(path)
}

#[cfg(target_os = "windows")]
fn stop_windows_log_followers_at(directory: &Path) -> Result<()> {
    let entries = match fs::read_dir(directory.join("log-followers")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).context("cannot inspect selected environment log followers");
        }
    };
    for entry in entries {
        let path = entry?.path();
        let record: WindowsLogFollower =
            serde_json::from_slice(&fs::read(&path)?).context("invalid log follower record")?;
        for state in [&record.child, &record.parent] {
            if state.version != 2 || state.instance != directory.display().to_string() {
                bail!("log follower record belongs to another environment");
            }
            if let Some(process) = windows_background::Process::open(state.pid, true)?
                && process.created == state.created
            {
                process.stop()?;
            }
        }
        let _ = fs::remove_file(path);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn lock_windows_service() -> Result<fs::File> {
    lock_windows_service_at(&app_config_dir()?)
}

#[cfg(target_os = "windows")]
fn lock_windows_service_at(dir: &Path) -> Result<fs::File> {
    fs::create_dir_all(dir)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(BRAND.service.lock_filename))?;
    file.lock().with_context(|| {
        format!(
            "cannot lock selected {brand_product} service",
            brand_product = BRAND.product_name
        )
    })?;
    Ok(file)
}

#[cfg(target_os = "windows")]
fn windows_background_pid() -> Result<Option<u32>> {
    Ok(windows_background_process(false)?.map(|process| process.pid))
}

#[cfg(target_os = "windows")]
fn windows_pid_is_running(pid: u32) -> Result<bool> {
    Ok(windows_background_process(false)?.is_some_and(|process| process.pid == pid))
}

#[cfg(target_os = "windows")]
fn windows_pid_path() -> Result<PathBuf> {
    Ok(app_config_dir()?.join(WINDOWS_PID_FILENAME.get()))
}

#[cfg(target_os = "windows")]
fn windows_log_path() -> Result<PathBuf> {
    Ok(app_config_dir()?.join(SERVICE_LOG_FILENAME.get()))
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
    run_systemctl(&["disable", "--now", &environment_scope::service_name()])?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn service_is_active() -> Result<bool> {
    let status = systemctl_user_command()
        .args([
            "--user",
            "is-active",
            "--quiet",
            &environment_scope::service_name(),
        ])
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
            &environment_scope::service_name(),
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
            &environment_scope::service_name(),
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

fn migrate_legacy_claude_no_proxy_for_instance(listen: &str) -> Result<()> {
    // A running init rewrites the settings itself and may be waiting for
    // this service to start, so never wait for it.
    let Some(_initialization_lock) = try_lock_initialization()? else {
        return Ok(());
    };
    // The background service does not inherit CLAUDE_CONFIG_DIR; an isolated
    // environment records its Claude directory instead.
    let settings_path = match environment_scope::recorded_product_dir() {
        Some(directory) => directory.join("settings.json"),
        None => resolve_claude_config_paths()?.settings_path,
    };
    migrate_legacy_claude_no_proxy(&settings_path, listen)
}

/// Older clients sent Claude's updater (downloads.claude.ai) around the
/// local proxy. Drop that bypass from settings this listener manages, so
/// existing installations follow the user's network without re-running init.
fn migrate_legacy_claude_no_proxy(settings_path: &Path, listen: &str) -> Result<()> {
    let original = fs::read(settings_path).ok();
    let mut settings = load_json_object(settings_path)?;
    let Some(env) = settings.get_mut("env").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    let proxy = format!("http://{listen}");
    if env.get("no_proxy").and_then(Value::as_str) != Some(LEGACY_DEFAULT_NO_PROXY)
        || env.get("https_proxy").and_then(Value::as_str) != Some(proxy.as_str())
    {
        return Ok(());
    }
    env.insert(
        "no_proxy".to_string(),
        Value::String(DEFAULT_NO_PROXY.to_string()),
    );
    // Claude may have rewritten the file meanwhile; leave its version.
    if fs::read(settings_path).ok() != original {
        return Ok(());
    }
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(settings_path, &timestamp)?;
    write_json_object(settings_path, Value::Object(settings))?;
    eprintln!(
        "Claude updater downloads now follow the {brand_product} upstream proxy ({} updated)",
        settings_path.display(),
        brand_product = BRAND.product_name
    );
    Ok(())
}

fn migrate_legacy_codex_system_proxy_for_instance(cfg: &AppConfig) -> Result<()> {
    let Some(_initialization_lock) = try_lock_initialization()? else {
        return Ok(());
    };
    let codex_dir = match environment_scope::recorded_product_dir() {
        Some(directory) => directory,
        None => codex_config_dir()?,
    };
    migrate_legacy_codex_system_proxy(&codex_dir, &cfg.listen, &cfg.ca_cert_path)
}

/// Linux clients up to 1.1.58 persisted `features.respect_system_proxy = true`
/// into the Codex config they manage. Turn it off in a directory whose `.env`
/// carries this listener's managed block, so IDE and daemon sessions stop
/// advertising it without re-running init.
fn migrate_legacy_codex_system_proxy(
    codex_dir: &Path,
    listen: &str,
    ca_cert_path: &str,
) -> Result<()> {
    let env = fs::read_to_string(codex_dir.join(".env")).unwrap_or_default();
    if !env.contains(merge_codex_ide_env("", listen, ca_cert_path).trim()) {
        return Ok(());
    }
    let path = codex_dir.join("config.toml");
    let Ok(original) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let Ok(mut document) = original.parse::<DocumentMut>() else {
        return Ok(());
    };
    let Some(features) = document.get_mut("features").and_then(Item::as_table_mut) else {
        return Ok(());
    };
    if features.get("respect_system_proxy").and_then(Item::as_bool) != Some(true) {
        return Ok(());
    }
    features.insert("respect_system_proxy", value(false));
    // Codex or the user may have rewritten the file meanwhile; leave theirs.
    if fs::read_to_string(&path).ok().as_deref() != Some(original.as_str()) {
        return Ok(());
    }
    let timestamp = Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    backup_if_exists(&path, &timestamp)?;
    write_bytes_atomic(&path, document.to_string().as_bytes(), 0o600)?;
    eprintln!(
        "Codex respect_system_proxy turned off ({} updated)",
        path.display()
    );
    Ok(())
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

fn app_config_dir() -> Result<PathBuf> {
    if let Some(scope) = environment_scope::active() {
        return Ok(scope.directory.clone());
    }
    if let Some(dir) = env_dir_override(BRAND.env.home) {
        return Ok(dir);
    }
    let home = home_dir().context("failed to resolve home directory")?;
    Ok(home.join(BRAND.home_dir_name))
}

fn app_config_path() -> Result<PathBuf> {
    Ok(app_config_dir()?.join(CONFIG_FILENAME.get()))
}

fn write_app_config_at(path: &Path, config: &AppConfig) -> Result<()> {
    let parent = path.parent().with_context(|| {
        format!(
            "failed to resolve {brand_product} config parent directory",
            brand_product = BRAND.product_name
        )
    })?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let value = serde_json::to_value(config).with_context(|| {
        format!(
            "failed to serialize {brand_product} config",
            brand_product = BRAND.product_name
        )
    })?;
    write_json_object(path, value)
}

/// The configuration, or `None` when none was written yet; a configuration
/// that exists but cannot be read or parsed is an error.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn read_app_config_if_present() -> Result<Option<AppConfig>> {
    read_app_config_at_if_present(&app_config_path()?)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn read_app_config_at_if_present(path: &Path) -> Result<Option<AppConfig>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        _ => {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            serde_json::from_str(&raw)
                .map(Some)
                .with_context(|| format!("failed to parse {}", path.display()))
        }
    }
}

fn read_app_config() -> Result<AppConfig> {
    let path = app_config_path()?;
    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read {}; run the {brand_product} setup command first",
            path.display(),
            brand_product = BRAND.product_name
        )
    })?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn existing_runtime_ca_paths() -> Option<(PathBuf, PathBuf)> {
    let path = app_config_path().ok()?;
    let raw = fs::read_to_string(path).ok()?;
    let config = serde_json::from_str::<AppConfig>(&raw).ok()?;
    if config.version != CONFIG_VERSION.get()
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

    let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_json_object_bytes(path, &raw)
}

fn parse_json_object_bytes(path: &Path, raw: &[u8]) -> Result<Map<String, Value>> {
    let raw =
        std::str::from_utf8(raw).with_context(|| format!("failed to read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }

    let value: Value =
        serde_json::from_str(raw).with_context(|| format!("failed to parse {}", path.display()))?;
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

/// Replaces `path` with `data` in one step, for Gateway extensions keeping
/// state (the installed brand provides the temporary-name infix).
///
/// The bytes go to a new temporary file `.<file name>.<temp infix>-<pid>-
/// <random>` in the same directory (created if missing; the file is created
/// with `unix_mode` on Unix and flushed to disk), which then replaces `path`
/// (`rename` on Unix, a replacing move on Windows), so readers see the old
/// or the new contents, never a mix. If writing or replacing fails, `path`
/// keeps its old contents and the temporary file is removed (best effort).
/// On Unix `unix_mode` is applied to `path` again after the replacement; if
/// that fails the error is returned although `path` already has the new
/// contents. Syncing the directory afterwards is best effort.
pub fn write_file_atomically(path: &Path, data: &[u8], unix_mode: u32) -> Result<()> {
    write_bytes_atomic(path, data, unix_mode)
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
        .unwrap_or(BRAND.binary_name);
    let tmp_path = parent.join(format!(
        ".{name}.{}-{}-{}",
        BRAND.config.temp_file_infix,
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

    // Brand-neutral contracts of the background proxy and its listener:
    // installed services and earlier releases depend on these, whatever the
    // brand. The brand's own file names are frozen by its program's tests.

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_background_command_and_state_are_stable() {
        assert_eq!(LINUX_BACKGROUND_COMMAND, "__run-background-proxy");
        assert_eq!(LINUX_BACKGROUND_STATE_VERSION, 1);
        assert!(matches!(
            parse_command(&["__run-background-proxy".to_string()]).unwrap(),
            Command::RunLinuxBackgroundProxy
        ));
        let state = LinuxBackgroundState {
            schema_version: 1,
            pid: 42,
            start_time_ticks: 7,
            instance: Some("/home/u/.proxy-home".into()),
        };
        assert_eq!(
            serde_json::to_value(&state).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "pid": 42,
                "start_time_ticks": 7,
                "instance": "/home/u/.proxy-home"
            })
        );
        // Upgrades read state files written before `instance` existed.
        let legacy: LinuxBackgroundState =
            serde_json::from_str(r#"{"schema_version":1,"pid":42,"start_time_ticks":7}"#).unwrap();
        assert_eq!(legacy.instance, None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_background_command_and_state_are_stable() {
        assert_eq!(WINDOWS_BACKGROUND_COMMAND, "__run-background-proxy");
        assert_eq!(
            WINDOWS_PACKAGED_PROXY_LEASE_FILENAME,
            "windows-packaged-proxy-lease.json"
        );
        for args in [
            vec!["__run-background-proxy".to_string()],
            vec![
                "__run-background-proxy".to_string(),
                "--instance-v2".to_string(),
            ],
        ] {
            assert!(matches!(
                parse_command(&args).unwrap(),
                Command::RunWindowsBackgroundProxy
            ));
        }
        let state = WindowsBackgroundState {
            version: 2,
            pid: 42,
            created: 7,
            instance: r"C:\Users\u\.proxy-home".into(),
        };
        assert_eq!(
            serde_json::to_value(&state).unwrap(),
            serde_json::json!({
                "version": 2,
                "pid": 42,
                "created": 7,
                "instance": r"C:\Users\u\.proxy-home"
            })
        );
        // The update status file sits next to the executable.
        assert_eq!(
            windows_update_status_path(Path::new(r"C:\Programs\tool\tool.exe")).unwrap(),
            Path::new(r"C:\Programs\tool").join(BRAND.update.status_filename)
        );
    }

    /// Brand-neutral defaults earlier releases already wrote to disk.
    #[test]
    fn default_listen_address_and_product_marker_are_stable() {
        assert_eq!(DEFAULT_LOCAL_PROXY_LISTEN, "127.0.0.1:19908");
        assert_eq!(environment_scope::PRODUCT_DIR_FILENAME, "product-dir");
    }

    /// A listener whose process name contains the binary name (any case) is
    /// this program's own proxy.
    #[test]
    fn listen_port_owner_is_recognized_by_binary_name() {
        let binary = BRAND.binary_name;
        for (name, ours) in [
            (binary.to_string(), true),
            (binary.to_ascii_uppercase(), true),
            (format!("{binary}.exe"), true),
            (format!("my-{binary}-worker"), true),
            ("node".to_string(), false),
            (String::new(), false),
        ] {
            let owner = ListenPortOwner {
                pid: 1,
                name: name.clone(),
            };
            assert_eq!(owner.is_app(), ours, "{name}");
        }
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
base_url = "https://test.ktest.test"
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
            Some(false)
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
            config_path: codex.path().join("ktest-config.json"),
            config_changed: true,
            listen: "127.0.0.1:31234".to_string(),
            ca_cert_path: PathBuf::from("/tmp/ktest-ca.crt"),
            ca_key_path: PathBuf::from("/tmp/ktest-ca.key"),
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
        assert_eq!(
            document[CODEX_ENVIRONMENT_CONTEXT_TIME_KEY].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn disables_codex_time_reporting_and_preserves_user_content() {
        let raw = r#"# user header
model = "gpt-5" # keep model

# comment above the managed key
include_environment_context_time = true # user wanted time

[profiles.work]
model = "other"
include_environment_context_time = true
"#;
        let mut doc = raw.parse::<DocumentMut>().unwrap();
        assert_eq!(
            codex_environment_context_time(&doc),
            CodexEnvironmentContextTime::Enabled
        );
        assert!(disable_codex_environment_context_time(&mut doc));
        assert_eq!(
            doc.to_string(),
            raw.replacen(
                "include_environment_context_time = true # user",
                "include_environment_context_time = false # user",
                1
            )
        );
        assert_eq!(
            codex_environment_context_time(&doc),
            CodexEnvironmentContextTime::Disabled
        );
        // Idempotent and silent once managed.
        let managed = doc.to_string();
        assert!(!disable_codex_environment_context_time(&mut doc));
        assert_eq!(doc.to_string(), managed);

        // A missing key is added at the top level without a notice, even when
        // the document only has tables.
        let mut doc = "[features]\napps = false\n".parse::<DocumentMut>().unwrap();
        assert_eq!(
            codex_environment_context_time(&doc),
            CodexEnvironmentContextTime::Missing
        );
        assert!(!disable_codex_environment_context_time(&mut doc));
        let reparsed = doc.to_string().parse::<DocumentMut>().unwrap();
        assert_eq!(
            reparsed[CODEX_ENVIRONMENT_CONTEXT_TIME_KEY].as_bool(),
            Some(false)
        );
        assert!(
            reparsed["features"]
                .get(CODEX_ENVIRONMENT_CONTEXT_TIME_KEY)
                .is_none()
        );

        // A non-boolean value is replaced as a managed key.
        let mut doc = "include_environment_context_time = \"yes\"\n"
            .parse::<DocumentMut>()
            .unwrap();
        assert_eq!(
            codex_environment_context_time(&doc),
            CodexEnvironmentContextTime::Invalid
        );
        assert!(disable_codex_environment_context_time(&mut doc));
        assert_eq!(
            doc.to_string(),
            "include_environment_context_time = false\n"
        );
    }

    #[test]
    fn prepares_codex_time_reporting_in_every_managed_profile_file() {
        let codex = TempDir::new().unwrap();
        let config_path = codex.path().join("config.toml");
        let extra_path = codex.path().join("work.config.toml");
        let unrelated_path = codex.path().join("notes.toml");
        write_str(&config_path, "# keep\nmodel = \"gpt-5\"\n");
        write_str(&extra_path, "include_environment_context_time = true\n");
        write_str(&unrelated_path, "include_environment_context_time = true\n");
        write_str(
            &codex.path().join("auth.json"),
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"TEST_ONLY"}}"#,
        );

        let written = prepare_codex_oauth_files(codex.path(), false).unwrap();

        assert_eq!(written.len(), 2);
        for path in [&config_path, &extra_path] {
            assert_eq!(
                read_codex_environment_context_time(path).unwrap(),
                CodexEnvironmentContextTime::Disabled,
                "{}",
                path.display()
            );
        }
        assert!(read_str(&config_path).starts_with("# keep\nmodel = \"gpt-5\"\n"));
        assert_eq!(
            read_str(&unrelated_path),
            "include_environment_context_time = true\n"
        );
        assert_eq!(
            managed_codex_config_paths(codex.path()).unwrap(),
            vec![config_path, extra_path]
        );
        assert!(managed_codex_config_paths(&codex.path().join("absent")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scopes_direct_desktop_nss_database_to_the_current_user_home() {
        assert_eq!(
            nss_database_dir(Path::new("/tmp/ktest-user")),
            PathBuf::from("/tmp/ktest-user/.pki/nssdb")
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

# BEGIN KTEST CODEX IDE (managed)
HTTPS_PROXY="http://127.0.0.1:1111"
# END KTEST CODEX IDE (managed)
"#;

        let merged = merge_codex_ide_env(raw, "127.0.0.1:19908", "/tmp/KTEST CA/ktest-ca.crt");

        assert!(merged.contains("# user comment\nUSER_SETTING=keep-me"));
        assert!(!merged.contains("old-proxy"));
        assert!(!merged.contains("remove-me"));
        assert!(merged.contains("CUSTOM_BASE_URL=https://unrelated.example/v1"));
        assert_eq!(merged.matches(CODEX_IDE_ENV_BEGIN.get()).count(), 1);
        assert_eq!(merged.matches(CODEX_IDE_ENV_END.get()).count(), 1);
        assert!(merged.contains("HTTP_PROXY=\"http://127.0.0.1:19908\""));
        assert!(merged.contains("http_proxy=\"http://127.0.0.1:19908\""));
        assert!(merged.contains("SSL_CERT_FILE=\"/tmp/KTEST CA/ktest-ca.crt\""));
        assert!(!merged.contains("OPENAI_API_KEY="));
        assert_eq!(
            merge_codex_ide_env(&merged, "127.0.0.1:19908", "/tmp/KTEST CA/ktest-ca.crt",),
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
            Some(CODEX_PLACEHOLDER_ACCESS_TOKEN.get())
        );
        assert_eq!(created_tokens["refresh_token"].as_str(), Some(""));
        assert_eq!(
            created_tokens["account_id"].as_str(),
            Some("ktest-local-proxy-account")
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
            r#"{"auth_mode":"chatgpt","tokens":{"access_token":"ktest-local-proxy-placeholder-old","refresh_token":"old","account_id":"old"},"unrelated":"keep"}"#,
        );
        ensure_codex_local_proxy_auth(&path).unwrap();
        let upgraded = load_json_object(&path).unwrap();
        assert_eq!(upgraded["unrelated"].as_str(), Some("keep"));
        assert_eq!(upgraded["auth_mode"].as_str(), Some("chatgptAuthTokens"));
        assert_eq!(
            upgraded["tokens"]["id_token"].as_str(),
            Some(CODEX_PLACEHOLDER_ID_TOKEN.get())
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
            Some(CODEX_PLACEHOLDER_ACCESS_TOKEN.get())
        );
        assert_eq!(upgraded["OPENAI_API_KEY"], Value::Null);

        write_str(&path, r#"{"OPENAI_API_KEY":"TEST_ONLY_UNRELATED_KEY"}"#);
        ensure_codex_local_proxy_auth(&path).unwrap();
        assert_eq!(
            load_json_object(&path).unwrap()["tokens"]["access_token"].as_str(),
            Some(CODEX_PLACEHOLDER_ACCESS_TOKEN.get())
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

    fn test_jwt_with_payload(payload: &str) -> String {
        format!(
            "e30.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    fn real_auth_json(auth_mode: &str, access_token: &str) -> String {
        // Odd spacing and an unknown field prove the backup is byte-exact.
        format!(
            "{{ \"auth_mode\":\"{auth_mode}\",\n  \"tokens\":{{\"id_token\":\"real.id.token\",\"access_token\":\"{access_token}\",\"refresh_token\":\"real-refresh\",\"account_id\":\"real-account\"}},\"unrelated\":\"keep\"}}"
        )
    }

    fn backup_files(dir: &Path) -> Vec<PathBuf> {
        let mut backups: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.to_string_lossy().contains("auth.json.bak-"))
            .collect();
        backups.sort();
        backups
    }

    const TEST_NOW: i64 = 1_800_000_000;

    fn test_jwt_expiring_at(exp: i64) -> String {
        test_jwt_with_payload(&format!(r#"{{"exp":{exp}}}"#))
    }

    #[test]
    fn init_replaces_expired_real_codex_oauth_after_exact_backup() {
        for auth_mode in ["chatgpt", "chatgptAuthTokens"] {
            for exp in [TEST_NOW, TEST_NOW - 1, 0, -5] {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("auth.json");
                let real = real_auth_json(auth_mode, &test_jwt_expiring_at(exp));
                write_str(&path, &real);

                write_codex_local_proxy_auth_at(&path, ExistingCodexAuth::ReplaceExpired, TEST_NOW)
                    .unwrap();

                let backups = backup_files(dir.path());
                assert_eq!(backups.len(), 1, "{auth_mode} exp={exp}");
                assert!(
                    backups[0]
                        .to_string_lossy()
                        .ends_with("auth.json.bak-expired-login-20270115-080000"),
                    "{}",
                    backups[0].display()
                );
                assert_eq!(read_str(&backups[0]), real);
                let auth = load_json_object(&path).unwrap();
                assert_eq!(auth["auth_mode"].as_str(), Some("chatgptAuthTokens"));
                assert_eq!(
                    auth["tokens"]["access_token"].as_str(),
                    Some(CODEX_PLACEHOLDER_ACCESS_TOKEN.get())
                );
                assert_eq!(auth["tokens"]["refresh_token"].as_str(), Some(""));
                assert_eq!(
                    auth["tokens"]["account_id"].as_str(),
                    Some(CODEX_PLACEHOLDER_ACCOUNT_ID.get())
                );
                validate_codex_oauth_auth(&path).unwrap();

                // The placeholder is not a real login, so a rerun makes no backup.
                write_codex_local_proxy_auth_at(&path, ExistingCodexAuth::ReplaceExpired, TEST_NOW)
                    .unwrap();
                assert_eq!(backup_files(dir.path()).len(), 1);
                assert_eq!(codex_auth_expiry_warning(&path).unwrap(), None);
            }
        }
    }

    #[test]
    fn init_keeps_unexpired_or_unreadable_real_codex_oauth() {
        for auth_mode in ["chatgpt", "chatgptAuthTokens"] {
            for access_token in [
                test_jwt_expiring_at(TEST_NOW + 1),
                // Replacement has no early window, unlike the Desktop copy check.
                test_jwt_expiring_at(TEST_NOW + 60),
                "opaque-real-access".to_string(),
                test_jwt_with_payload(r#"{"sub":"no-exp"}"#),
                test_jwt_with_payload(r#"{"exp":"100"}"#),
                test_jwt_with_payload(r#"{"exp":100.5}"#),
                format!("{}.extra", test_jwt_expiring_at(100)),
            ] {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("auth.json");
                let real = real_auth_json(auth_mode, &access_token);
                write_str(&path, &real);

                write_codex_local_proxy_auth_at(&path, ExistingCodexAuth::ReplaceExpired, TEST_NOW)
                    .unwrap();

                assert_eq!(read_str(&path), real, "{auth_mode} {access_token}");
                assert!(backup_files(dir.path()).is_empty(), "{access_token}");
            }
        }
    }

    #[test]
    fn keep_mode_leaves_expired_real_codex_oauth_and_warning_names_the_fix() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        let real = real_auth_json("chatgpt", &test_jwt_expiring_at(0));
        write_str(&path, &real);

        ensure_codex_local_proxy_auth(&path).unwrap();

        assert_eq!(read_str(&path), real);
        assert!(backup_files(dir.path()).is_empty());
        let warning = codex_auth_expiry_warning(&path).unwrap().unwrap();
        assert!(warning.contains("1970-01-01 00:00:00 UTC"), "{warning}");
        assert!(warning.contains("ktest init-codex"), "{warning}");

        write_str(&path, "not json");
        assert!(codex_auth_expiry_warning(&path).is_err());
    }

    #[test]
    fn reads_jwt_expiry_only_from_three_part_tokens() {
        assert_eq!(codex_jwt_expiry(&test_jwt_expiring_at(0)), Some(0));
        assert_eq!(codex_jwt_expiry(&test_jwt_expiring_at(-5)), Some(-5));
        assert_eq!(codex_jwt_expiry("e30.eyJleHAiOjEwMH0"), None);
        assert_eq!(codex_jwt_expiry("e30.eyJleHAiOjEwMH0.sig.extra"), None);
        assert_eq!(codex_jwt_expiry("e30.not base64.sig"), None);
        assert_eq!(codex_jwt_expiry("opaque"), None);
    }

    #[test]
    fn expired_login_backups_survive_name_collisions_and_init_backups() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        let taken = dir
            .path()
            .join("auth.json.bak-expired-login-20270115-080000");
        write_str(&taken, "earlier");
        let real = real_auth_json("chatgpt", &test_jwt_expiring_at(TEST_NOW));
        write_str(&path, &real);

        write_codex_local_proxy_auth_at(&path, ExistingCodexAuth::ReplaceExpired, TEST_NOW)
            .unwrap();
        // `init_codex` backs up auth.json with the same timestamp format
        // before every run; it must not reach the expired-login backups.
        backup_if_exists(&path, "20270115-080000").unwrap();

        let suffixed = dir
            .path()
            .join("auth.json.bak-expired-login-20270115-080000-1");
        assert_eq!(read_str(&taken), "earlier");
        assert_eq!(read_str(&suffixed), real);
        assert_eq!(backup_files(dir.path()).len(), 3);
    }

    #[test]
    fn init_keeps_expired_login_when_no_backup_name_is_free() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        for attempt in 0..100 {
            let suffix = if attempt == 0 {
                String::new()
            } else {
                format!("-{attempt}")
            };
            write_str(
                &dir.path().join(format!(
                    "auth.json.bak-expired-login-20270115-080000{suffix}"
                )),
                "taken",
            );
        }
        let real = real_auth_json("chatgpt", &test_jwt_expiring_at(0));
        write_str(&path, &real);

        assert!(
            write_codex_local_proxy_auth_at(&path, ExistingCodexAuth::ReplaceExpired, TEST_NOW)
                .is_err()
        );
        assert_eq!(read_str(&path), real);
    }

    #[cfg(unix)]
    #[test]
    fn expired_login_backup_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let backup =
            write_expired_login_backup(&dir.path().join("auth.json"), b"login", TEST_NOW).unwrap();
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
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
    fn parses_claude_launcher_arguments_without_consuming_them() {
        for separator in [false, true] {
            let mut args = vec!["claude".to_string()];
            if separator {
                args.push("--".to_string());
            }
            args.extend([
                "-p".to_string(),
                "fixture with spaces".to_string(),
                "--help".to_string(),
            ]);
            match parse_command(&args).unwrap() {
                Command::Claude(claude_args) => assert_eq!(
                    claude_args,
                    vec![
                        "-p".to_string(),
                        "fixture with spaces".to_string(),
                        "--help".to_string()
                    ]
                ),
                _ => panic!("expected claude launcher command"),
            }
        }
        assert!(
            matches!(parse_command(&["claude".to_string()]).unwrap(), Command::Claude(args) if args.is_empty())
        );
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
        assert_eq!(resolve_chatgpt_timezone_value(None).unwrap(), None);
        assert_eq!(resolve_chatgpt_timezone_value(Some("  ")).unwrap(), None);
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

    /// The shared name check (Linux, macOS and Windows) names the brand's
    /// environment variable exactly as before.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn chatgpt_timezone_name_error_names_the_environment_variable() {
        let error = validate_chatgpt_timezone_name("../etc/passwd").unwrap_err();
        assert_eq!(
            error.to_string(),
            "KTEST_CHATGPT_TIMEZONE must be an IANA timezone such as America/Los_Angeles"
        );
    }

    /// The timezone diagnostics name the brand's environment variable
    /// exactly as before (outer message; the I/O cause follows in the chain).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn chatgpt_timezone_errors_name_the_environment_variable() {
        for (value, message) in [
            (
                "Mars/Olympus_Mons",
                "KTEST_CHATGPT_TIMEZONE does not exist in /usr/share/zoneinfo/Mars/Olympus_Mons",
            ),
            (
                "America",
                "KTEST_CHATGPT_TIMEZONE is not a zoneinfo file: /usr/share/zoneinfo/America",
            ),
        ] {
            let error = validate_chatgpt_timezone(value).unwrap_err();
            assert_eq!(error.to_string(), message, "{value}");
        }
    }

    /// Serialization omits an absent upstream proxy and absent provider
    /// routes, and a config from an older client decodes to the defaults —
    /// checked on the struct itself, not through a round trip that a
    /// matching decode/encode mistake would hide.
    #[test]
    fn app_config_omits_absent_fields_and_defaults_missing_ones() {
        let config = AppConfig {
            version: 1,
            base_url: "b".into(),
            api_key: "k".into(),
            listen: "l".into(),
            ca_cert_path: "cc".into(),
            ca_key_path: "ck".into(),
            chatgpt_chat_passthrough: true,
            desktop_browser_use: false,
            upstream_proxy: None,
            providers: ProviderCredentials {
                claude: Some(ProviderCredential {
                    base_url: "cb".into(),
                    api_key: "ck2".into(),
                }),
                codex: None,
            },
        };
        let value = serde_json::to_value(&config).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(!keys.contains(&"upstream_proxy"), "{keys:?}");
        assert_eq!(
            value["providers"],
            serde_json::json!({"claude": {"base_url": "cb", "api_key": "ck2"}})
        );
        let empty = AppConfig {
            providers: ProviderCredentials::default(),
            ..config.clone()
        };
        assert_eq!(
            serde_json::to_value(&empty).unwrap()["providers"],
            serde_json::json!({})
        );

        let legacy: AppConfig = serde_json::from_str(
            r#"{"version":1,"base_url":"b","api_key":"k","listen":"l","ca_cert_path":"cc"}"#,
        )
        .unwrap();
        assert_eq!(legacy.ca_key_path, "");
        assert!(legacy.chatgpt_chat_passthrough);
        assert!(legacy.desktop_browser_use);
        assert_eq!(legacy.upstream_proxy, None);
        assert!(legacy.providers.is_empty());
        assert!(legacy.providers.claude.is_none() && legacy.providers.codex.is_none());
    }

    /// Each config file key lands in its own struct field (a renamed or
    /// swapped key would still round-trip as JSON, so read the fields).
    #[test]
    fn app_config_keys_map_to_their_fields() {
        let config: AppConfig = serde_json::from_str(
            r#"{"version":7,"base_url":"b","api_key":"k","listen":"l","ca_cert_path":"cc","ca_key_path":"ck","chatgpt_chat_passthrough":false,"desktop_browser_use":true,"upstream_proxy":"u","providers":{"claude":{"base_url":"cb","api_key":"ck2"},"codex":{"base_url":"xb","api_key":"xk"}}}"#,
        )
        .unwrap();
        assert_eq!(config.version, 7);
        assert_eq!(config.base_url, "b");
        assert_eq!(config.api_key, "k");
        assert_eq!(config.listen, "l");
        assert_eq!(config.ca_cert_path, "cc");
        assert_eq!(config.ca_key_path, "ck");
        assert!(!config.chatgpt_chat_passthrough);
        assert!(config.desktop_browser_use);
        assert_eq!(config.upstream_proxy.as_deref(), Some("u"));
        let claude = config.providers.claude.as_ref().unwrap();
        assert_eq!(
            (claude.base_url.as_str(), claude.api_key.as_str()),
            ("cb", "ck2")
        );
        let codex = config.providers.codex.as_ref().unwrap();
        assert_eq!(
            (codex.base_url.as_str(), codex.api_key.as_str()),
            ("xb", "xk")
        );
    }

    /// The struct's field order, `APP_CONFIG_FIELDS` and the array reader
    /// agree: an object serializes its keys in that order, and the same
    /// values as an array read back the same config.
    #[test]
    fn app_config_field_order_is_consistent() {
        let object = serde_json::json!({
            "version": 7,
            "base_url": "https://gateway.example.test",
            "api_key": "TEST_ONLY_KEY",
            "listen": "127.0.0.1:19908",
            "ca_cert_path": "/tmp/ca.crt",
            "ca_key_path": "/tmp/ca.key",
            "chatgpt_chat_passthrough": false,
            "desktop_browser_use": true,
            "upstream_proxy": "direct",
            "providers": {}
        });
        let config: AppConfig = serde_json::from_value(object).unwrap();
        let serialized = serde_json::to_value(&config).unwrap();
        let keys: Vec<&str> = serialized
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // serde_json keeps insertion order only with preserve_order; compare
        // the serialized text instead for the struct's field order.
        let text = serde_json::to_string(&config).unwrap();
        let mut positions: Vec<usize> = APP_CONFIG_FIELDS
            .iter()
            .map(|field| text.find(&format!("\"{field}\":")).unwrap())
            .collect();
        let sorted = {
            let mut copy = positions.clone();
            copy.sort_unstable();
            copy
        };
        assert_eq!(positions, sorted, "{text}");
        positions.dedup();
        assert_eq!(positions.len(), APP_CONFIG_FIELDS.len());
        assert_eq!(keys.len(), APP_CONFIG_FIELDS.len());
        let array: Vec<Value> = APP_CONFIG_FIELDS
            .iter()
            .map(|field| serialized[*field].clone())
            .collect();
        let from_array: AppConfig = serde_json::from_value(Value::Array(array)).unwrap();
        assert!(from_array == config);
    }

    /// The config type name in shape errors is the brand's.
    #[test]
    fn config_shape_errors_name_the_brand_config_type() {
        use serde::Deserializer as _;
        static ACME: brand::Brand = brand::Brand {
            config: brand::ConfigNames {
                type_name: "AcmeConfig",
                ..crate::brand_test::KTEST_VALUES.config
            },
            ..crate::brand_test::KTEST_VALUES
        };
        for (input, message) in [
            (
                "null",
                "invalid type: null, expected struct AcmeConfig at line 1 column 4",
            ),
            (
                "[2]",
                "invalid length 1, expected struct AcmeConfig with 10 elements at line 1 column 3",
            ),
        ] {
            let mut deserializer = serde_json::Deserializer::from_str(input);
            let error = (&mut deserializer)
                .deserialize_struct("AppConfig", APP_CONFIG_FIELDS, AppConfigVisitor(&ACME))
                .err()
                .unwrap();
            assert_eq!(error.to_string(), message, "{input}");
        }
    }

    #[test]
    fn existing_program_config_defaults_chatgpt_passthrough_on() {
        let config: AppConfig = serde_json::from_value(serde_json::json!({
            "version": CONFIG_VERSION.get(),
            "base_url": "https://gateway.example.test",
            "api_key": "TEST_ONLY_KEY",
            "listen": "127.0.0.1:19908",
            "ca_cert_path": "/tmp/test-ca.crt",
            "ca_key_path": "/tmp/test-ca.key"
        }))
        .unwrap();
        assert!(config.chatgpt_chat_passthrough);
        assert!(config.desktop_browser_use);
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
        let previous = AppConfig {
            version: CONFIG_VERSION.get(),
            base_url: "https://claude.example.test".to_string(),
            api_key: "TEST_ONLY_CLAUDE_KEY".to_string(),
            listen: "127.0.0.1:19908".to_string(),
            ca_cert_path: "/tmp/ktest-ca.crt".to_string(),
            ca_key_path: "/tmp/ktest-ca.key".to_string(),
            chatgpt_chat_passthrough: true,
            desktop_browser_use: true,
            upstream_proxy: None,
            providers: providers.clone(),
        };
        let current = AppConfig {
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
            configure_vscode_editor: false,
            trust_vscode_ca: false,
        };

        let initialized =
            initialize_codex_local_proxy_at(temporary.path(), &args, "test-create").unwrap();
        let config: AppConfig =
            serde_json::from_slice(&fs::read(&initialized.config_path).unwrap()).unwrap();

        assert_eq!(config.version, CONFIG_VERSION.get());
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
    fn init_codex_rebuild_keeps_desktop_browser_use_off() {
        let temporary = tempfile::tempdir().unwrap();
        let args = InitArgs {
            base_url: "https://first.example.test".to_string(),
            api_key: "TEST_ONLY_CODEX_PROXY_KEY".to_string(),
            websockets: false,
            configure_vscode_editor: false,
            trust_vscode_ca: false,
        };
        let first = initialize_codex_local_proxy_at(temporary.path(), &args, "test-first").unwrap();
        let mut config: AppConfig =
            serde_json::from_slice(&fs::read(&first.config_path).unwrap()).unwrap();
        config.desktop_browser_use = false;
        write_app_config_at(&first.config_path, &config).unwrap();
        // An unreadable CA sends init down the rebuild branch.
        fs::remove_file(&first.ca_cert_path).unwrap();

        let second =
            initialize_codex_local_proxy_at(temporary.path(), &args, "test-second").unwrap();
        let rebuilt: AppConfig =
            serde_json::from_slice(&fs::read(&second.config_path).unwrap()).unwrap();
        assert!(read_runtime_ca(&rebuilt).is_ok());
        assert!(!rebuilt.desktop_browser_use);
    }

    #[test]
    fn init_codex_reuses_existing_proxy_ca_and_local_preferences() {
        let temporary = tempfile::tempdir().unwrap();
        let first_args = InitArgs {
            base_url: "https://first.example.test".to_string(),
            api_key: "TEST_ONLY_FIRST_CODEX_PROXY_KEY".to_string(),
            websockets: false,
            configure_vscode_editor: false,
            trust_vscode_ca: false,
        };
        let first =
            initialize_codex_local_proxy_at(temporary.path(), &first_args, "test-first").unwrap();
        let cert_before = fs::read(&first.ca_cert_path).unwrap();
        let key_before = fs::read(&first.ca_key_path).unwrap();
        let mut config: AppConfig =
            serde_json::from_slice(&fs::read(&first.config_path).unwrap()).unwrap();
        config.providers.claude = Some(ProviderCredential {
            base_url: "https://claude.example.test".to_string(),
            api_key: "TEST_ONLY_CLAUDE_PROXY_KEY".to_string(),
        });
        config.listen = "127.0.0.1:29908".to_string();
        config.chatgpt_chat_passthrough = false;
        config.desktop_browser_use = false;
        write_app_config_at(&first.config_path, &config).unwrap();

        let second_args = InitArgs {
            base_url: "https://second.example.test".to_string(),
            api_key: "TEST_ONLY_SECOND_CODEX_PROXY_KEY".to_string(),
            websockets: true,
            configure_vscode_editor: false,
            trust_vscode_ca: false,
        };
        let second =
            initialize_codex_local_proxy_at(temporary.path(), &second_args, "test-second").unwrap();
        let updated: AppConfig =
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
        assert!(!updated.desktop_browser_use);
    }

    #[test]
    fn updates_only_selected_program_provider_config() {
        let temporary = tempfile::tempdir().unwrap();
        let config_path = temporary.path().join(CONFIG_FILENAME.get());
        let cert_path = temporary.path().join("ktest-ca.crt");
        let key_path = temporary.path().join("ktest-ca.key");
        let _initial = update_app_provider_config_at(
            &config_path,
            ProviderKind::Claude,
            ProviderCredential {
                base_url: "https://claude.example.test".to_string(),
                api_key: "TEST_ONLY_CLAUDE_KEY".to_string(),
            },
            Some((cert_path.clone(), key_path.clone())),
        )
        .unwrap();
        let updated = update_app_provider_config_at(
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

        let unchanged = update_app_provider_config_at(
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
                "features.respect_system_proxy=false".to_string(),
                "-c".to_string(),
                "otel.metrics_exporter=\"none\"".to_string(),
                "-c".to_string(),
                "features.apps=false".to_string(),
                "-c".to_string(),
                "include_environment_context_time=false".to_string(),
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
                        "-c".to_string(),
                        "include_environment_context_time=false".to_string(),
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
    fn codex_launcher_honors_explicit_time_reporting_override() {
        for args in [
            vec![
                "-c".to_string(),
                "include_environment_context_time=true".to_string(),
            ],
            vec!["--config=include_environment_context_time=true".to_string()],
        ] {
            let launch_args = codex_launcher_args(&args);
            assert!(!launch_args.contains(&"include_environment_context_time=false".to_string()));
            assert!(launch_args.ends_with(&args));
        }

        // A prompt after `--` is positional text, not a caller override.
        let args = vec![
            "exec".to_string(),
            "--".to_string(),
            "--config=include_environment_context_time=true".to_string(),
            "--enable=apps".to_string(),
        ];
        let launch_args = codex_launcher_args(&args);
        assert!(launch_args.contains(&"include_environment_context_time=false".to_string()));
        assert!(launch_args.contains(&"features.apps=false".to_string()));
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
    fn gateway_health_error_keeps_root_cause() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime
            .block_on(check_gateway_health(
                &format!("http://127.0.0.1:{port}"),
                &Egress {
                    installation_ca_pem: Some(String::new()),
                    upstream: upstream_proxy::Snapshot::direct_for_tests(),
                },
            ))
            .unwrap_err();
        let outer = err.to_string();
        let full = format!("{err:#}");
        assert!(outer.starts_with("failed to GET"));
        assert!(full.starts_with(&outer));
        assert!(full.len() > outer.len(), "{full}");
    }

    #[test]
    fn loads_generated_ca_into_rustls_roots() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ktest-ca.crt");
        let (ca_cert_pem, _) = generate_installation_ca().unwrap();
        fs::write(&ca_path, ca_cert_pem).unwrap();
        load_ca_root_store(&ca_path).unwrap();

        let invalid_path = dir.path().join("invalid-ca.crt");
        fs::write(&invalid_path, b"not a pem certificate").unwrap();
        assert!(load_ca_root_store(&invalid_path).is_err());
    }

    #[test]
    fn reports_each_other_program_ca_once() {
        let listing = "AAA CurrentUser current\r\nBBB CurrentUser old\nBBB CurrentUser old\n\nBBB LocalMachine old\nCCC\n";
        assert_eq!(
            stale_app_ca_thumbprints(listing, "current"),
            vec![
                "BBB in CurrentUser\\Root".to_string(),
                "BBB in LocalMachine\\Root".to_string()
            ]
        );
        assert!(stale_app_ca_thumbprints("AAA CurrentUser current\n", "current").is_empty());
    }

    #[test]
    fn keeps_an_existing_ca_with_the_legacy_subject_name() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = (dir.path().join("ca.crt"), dir.path().join("ca.key"));
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "KTEST local installation CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "KTEST");
        let cert_pem = params.self_signed(&key).unwrap().pem();
        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();

        assert!(!ensure_installation_ca(&cert_path, &key_path, "test").unwrap());
        assert_eq!(fs::read_to_string(&cert_path).unwrap(), cert_pem);
    }

    #[test]
    fn regenerated_installation_cas_have_distinct_subject_names() {
        let common_name = |pem: &str| {
            CertificateParams::from_ca_cert_pem(pem)
                .unwrap()
                .distinguished_name
                .get(&DnType::CommonName)
                .cloned()
        };
        let (first, _) = generate_installation_ca().unwrap();
        let (second, _) = generate_installation_ca().unwrap();
        let first = common_name(&first).unwrap();
        assert!(
            format!("{first:?}").contains("KTEST local installation CA "),
            "{first:?}"
        );
        assert_ne!(Some(first), common_name(&second));
    }

    #[test]
    fn migrates_legacy_codex_system_proxy_only_in_this_listeners_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let env = dir.path().join(".env");
        let listen = "127.0.0.1:19908";
        let managed = merge_codex_ide_env("", listen, "/ca.pem");
        let legacy = "model = \"kept\"\n\n[features]\nrespect_system_proxy = true\nother = true\n";
        let migrate = || migrate_legacy_codex_system_proxy(dir.path(), listen, "/ca.pem").unwrap();
        let backups = || {
            fs::read_dir(dir.path())
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with("config.toml.bak-")
                })
                .count()
        };

        fs::write(&config, legacy).unwrap();
        fs::write(&env, merge_codex_ide_env("", "127.0.0.1:20000", "/ca.pem")).unwrap();
        migrate();
        assert_eq!(fs::read_to_string(&config).unwrap(), legacy);

        fs::write(&env, format!("USER_VAR=1\n{managed}")).unwrap();
        migrate();
        let doc = read_str(&config).parse::<DocumentMut>().unwrap();
        assert_eq!(
            doc["features"]["respect_system_proxy"].as_bool(),
            Some(false)
        );
        assert_eq!(doc["features"]["other"].as_bool(), Some(true));
        assert_eq!(doc["model"].as_str(), Some("kept"));
        assert_eq!(backups(), 1);

        migrate();
        assert_eq!(backups(), 1);

        fs::write(&config, "features.respect_system_proxy = true\n").unwrap();
        migrate();
        let doc = read_str(&config).parse::<DocumentMut>().unwrap();
        assert_eq!(
            doc["features"]["respect_system_proxy"].as_bool(),
            Some(false)
        );

        for unchanged in [
            "[features]\nrespect_system_proxy = false\n",
            "model = \"kept\"\n",
            "features = 1\n",
            "not toml [",
        ] {
            fs::write(&config, unchanged).unwrap();
            migrate();
            assert_eq!(fs::read_to_string(&config).unwrap(), unchanged);
        }
    }

    #[test]
    fn migrates_only_the_legacy_no_proxy_this_listener_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let write = |no_proxy: &str, https_proxy: &str| {
            fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "model": "kept",
                    "env": {"no_proxy": no_proxy, "https_proxy": https_proxy}
                }))
                .unwrap(),
            )
            .unwrap();
        };
        let read = || serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap();

        write(LEGACY_DEFAULT_NO_PROXY, "http://127.0.0.1:19908");
        migrate_legacy_claude_no_proxy(&path, "127.0.0.1:19908").unwrap();
        assert_eq!(read()["env"]["no_proxy"], DEFAULT_NO_PROXY);
        assert_eq!(read()["model"], "kept");

        for (no_proxy, https_proxy) in [
            (LEGACY_DEFAULT_NO_PROXY, "http://127.0.0.1:20000"),
            (
                "downloads.claude.ai,corp.internal",
                "http://127.0.0.1:19908",
            ),
        ] {
            write(no_proxy, https_proxy);
            migrate_legacy_claude_no_proxy(&path, "127.0.0.1:19908").unwrap();
            assert_eq!(read()["env"]["no_proxy"], no_proxy);
        }
        fs::remove_file(&path).unwrap();
        migrate_legacy_claude_no_proxy(&path, "127.0.0.1:19908").unwrap();
        assert!(!path.exists());
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
            Path::new("/home/test/.local/bin/ktest"),
            Path::new("/home/test/.ktest"),
            Path::new("/home/test"),
        )
        .unwrap();
        assert!(unit.contains("ExecStart=\"/home/test/.local/bin/ktest\""));
        assert!(unit.contains("Environment=\"KTEST_HOME=/home/test/.ktest\""));
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
        let raw = format!("123 (ktest worker ) name) {}", fields.join(" "));
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
        match parse_command(&[LINUX_BACKGROUND_COMMAND.to_string()]).unwrap() {
            Command::RunLinuxBackgroundProxy => {}
            _ => panic!("expected Linux background proxy worker command"),
        }
        assert!(
            parse_command(&[LINUX_BACKGROUND_COMMAND.to_string(), "extra".to_string(),]).is_err()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parses_private_windows_background_worker_command() {
        match parse_command(&[WINDOWS_BACKGROUND_COMMAND.to_string()]).unwrap() {
            Command::RunWindowsBackgroundProxy => {}
            _ => panic!("expected Windows background proxy worker command"),
        }
        assert!(
            parse_command(&[WINDOWS_BACKGROUND_COMMAND.to_string(), "extra".to_string(),]).is_err()
        );
    }

    #[test]
    fn quotes_windows_package_activation_arguments() {
        assert_eq!(
            windows_quote_activation_arg(r"--user-data-dir=C:\Users\Test User\KTEST"),
            r#""--user-data-dir=C:\Users\Test User\KTEST""#
        );
        assert_eq!(windows_quote_activation_arg("a\"b"), r#""a\"b""#);
        assert_eq!(windows_quote_activation_arg("ends\\"), r#""ends\\""#);
        let args = windows_packaged_desktop_activation_args(
            "http://127.0.0.1:19908",
            "test-pin",
            Some("codex://threads/new?path=C%3A%5Cwork"),
        );
        assert!(args.contains("--proxy-server=http://127.0.0.1:19908"));
        assert!(args.contains("--ignore-certificate-errors-spki-list=test-pin"));
        assert!(args.contains("codex://threads/new?path=C%3A%5Cwork"));
        assert!(!args.contains("--user-data-dir"));
    }

    #[test]
    fn windows_reuse_activation_preserves_transport_without_a_new_thread_target() {
        let arguments =
            windows_packaged_desktop_activation_args("http://127.0.0.1:19908", "test-pin", None);
        assert_eq!(
            arguments,
            "\"--proxy-server=http://127.0.0.1:19908\" \"--ignore-certificate-errors-spki-list=test-pin\""
        );
        assert!(!arguments.contains("codex://"));
        assert!(!arguments.contains("--user-data-dir"));
    }

    #[test]
    fn windows_workspace_target_is_resolved_only_for_guarded_cold_launch() {
        let source = include_str!("lib.rs");
        let branch = source
            .split("let target = if matches!(decision, windows_desktop_runtime::Decision::Cold) {")
            .nth(1)
            .unwrap()
            .split("let before = observer.inspect")
            .next()
            .unwrap();
        assert!(branch.contains("Some(codex_new_thread_url(&workspace))"));
        assert!(branch.contains("} else {\n        None\n    }"));
        assert!(branch.contains("target.as_deref()"));
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
            name: "ktest".to_string(),
        }];
        assert_eq!(format_listen_owners(&owners), "pid 42 (ktest)");
        assert!(owners[0].is_app());
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
        validate_update_asset(&elf_x86, "ktest-linux-x86_64").unwrap();
        assert!(validate_update_asset(&elf_x86, "ktest-linux-aarch64-wrong").is_err());

        let mut macho = vec![0u8; 64];
        macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        validate_update_asset(&macho, "ktest-macos-aarch64").unwrap();
        assert!(validate_update_asset(&macho, "ktest-macos-x86_64").is_err());

        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        validate_update_asset(&pe, "ktest-windows-x86_64.exe").unwrap();
        assert!(validate_update_asset(&pe, "ktest-windows-aarch64.exe").is_err());

        let expected_current_asset = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "ktest-linux-x86_64",
            ("linux", "aarch64") => "ktest-linux-aarch64",
            ("macos", "x86_64") => "ktest-macos-x86_64",
            ("macos", "aarch64") => "ktest-macos-aarch64",
            ("windows", "x86_64") => "ktest-windows-x86_64.exe",
            ("windows", "aarch64") => "ktest-windows-aarch64.exe",
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
            compare_versions("ktest 0.7.0", "0.7").unwrap(),
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
            sha256_hex(b"ktest"),
            "f99508d99958eb7daae533d096bdbc68e428c53032d8a69549951a456f04f7af"
        );
    }

    #[test]
    fn parses_init_named_args() {
        let args = vec![
            "init".to_string(),
            "--base-url".to_string(),
            "https://api.ktest.test".to_string(),
            "--api-key".to_string(),
            "sk-test".to_string(),
        ];
        match parse_command(&args).unwrap() {
            Command::Init(init) => {
                assert_eq!(init.base_url, "https://api.ktest.test");
                assert_eq!(init.api_key, "sk-test");
                assert!(!init.trust_vscode_ca);
                assert!(!init.configure_vscode_editor);
            }
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn editor_setup_is_a_separate_optional_initialization_choice() {
        for verb in ["init", "init-codex"] {
            for requested in [false, true] {
                let mut args = vec![verb, "https://gateway.example", "TEST_ONLY_KEY"];
                if requested {
                    args.push("--configure-vscode-editor");
                }
                let init =
                    match parse_command(&args.into_iter().map(String::from).collect::<Vec<_>>())
                        .unwrap()
                    {
                        Command::Init(init) | Command::InitCodex(init) => init,
                        _ => panic!("expected initialization"),
                    };
                assert_eq!(init.configure_vscode_editor, requested);
                assert!(!init.trust_vscode_ca);
            }
        }
    }

    #[test]
    fn windows_ca_trust_requires_an_explicit_platform_scoped_option() {
        for verb in ["init", "init-codex"] {
            let args = [
                verb,
                "https://gateway.example",
                "TEST_ONLY_KEY",
                "--trust-vscode-ca",
            ]
            .map(String::from);
            if cfg!(windows) {
                let init = match parse_command(&args).unwrap() {
                    Command::Init(init) | Command::InitCodex(init) => init,
                    _ => panic!("expected initialization"),
                };
                assert!(init.trust_vscode_ca);
            } else {
                assert!(parse_command(&args).is_err());
            }
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
            Path::new("/tmp/ktest-ca.crt"),
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
        assert!(!json_str(&env_obj, "no_proxy").contains("downloads.claude.ai"));
        assert_eq!(
            json_str(&env_obj, "NODE_EXTRA_CA_CERTS"),
            "/tmp/ktest-ca.crt"
        );
    }

    fn top_level_fn_bodies<'a>(source: &'a str, signature: &str) -> Vec<&'a str> {
        let needle = format!("\nfn {signature}");
        source
            .match_indices(&needle)
            .map(|(start, _)| {
                let body = &source[start + 1..];
                &body[..body.find("\n}\n").unwrap()]
            })
            .collect()
    }

    #[test]
    fn shared_proxy_and_codex_paths_do_not_emit_claude_only_warnings() {
        let main = include_str!("lib.rs");
        let claude_only = [
            "warn_process_env_conflicts(",
            "warn_claude_settings_overrides(",
            "warn_claude_settings_overrides_for_paths(",
            "warn_systemd_user_env_conflicts(",
        ];
        let start_bodies = top_level_fn_bodies(main, "run_service_start(");
        assert_eq!(start_bodies.len(), 4, "one per platform plus the fallback");
        let mut bodies = start_bodies;
        for signature in [
            "run_local_proxy(",
            "ensure_local_proxy_running(",
            "init_codex(",
            "run_codex(",
            "run_desktop(",
            "run_linux_desktop(",
            "run_macos_desktop(",
            "run_windows_desktop(",
            "run_windows_packaged_desktop(",
        ] {
            let found = top_level_fn_bodies(main, signature);
            assert_eq!(found.len(), 1, "{signature}");
            bodies.extend(found);
        }
        for body in bodies {
            for call in claude_only {
                assert!(!body.contains(call), "{call} in:\n{body}");
            }
        }
        // `ktest init` remains the Claude setup path that reports both kinds.
        let init_claude = top_level_fn_bodies(main, "init_claude(")[0];
        assert!(init_claude.contains("warn_process_env_conflicts();"));
        assert!(init_claude.contains("warn_claude_settings_overrides_for_paths("));
    }

    #[test]
    fn doctor_runs_claude_environment_checks_only_for_claude_targets() {
        let main = include_str!("lib.rs");
        let doctor = top_level_fn_bodies(main, "run_doctor(")[0];
        let first_claude_gate = doctor.find("if check_claude {").unwrap();
        for check in [
            "check_process_env_conflicts(",
            "check_systemd_user_env_conflicts(",
            "check_persistent_env_conflicts(",
            "check_process_proxy_env_conflicts(",
            "check_persistent_proxy_env_conflicts(",
            "check_systemd_user_proxy_env_conflicts(",
        ] {
            assert_eq!(doctor.matches(check).count(), 1, "{check}");
            let position = doctor.find(check).unwrap();
            assert!(
                position > first_claude_gate,
                "{check} runs before the Claude gate"
            );
            let gate = doctor[..position].rfind("if check_claude {").unwrap();
            assert!(
                !doctor[gate..position].contains("\n    }\n"),
                "{check} is outside a Claude-only block"
            );
        }
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
