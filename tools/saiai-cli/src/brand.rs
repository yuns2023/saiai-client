//! Product identity of this client build.
//!
//! Everything a client installation exposes to its users, their files and
//! the Gateway as a *name* lives in one read-only [`Brand`] value: binary and
//! directory names, environment variables, certificate and service identities,
//! update coordinates, ownership markers, placeholder identities and client
//! proof wire names. Core code reads these values only through [`BRAND`]; the
//! concrete values of a distribution live in a separate module.
//!
//! Changing a value strands existing installations of that distribution
//! (orphaned directories, services, certificates, pins or markers), so the
//! SAIAI values are frozen by `brand_contract_tests`.
//!
//! Value constraints (not checked at run time):
//! - file and directory names are single path components without separators;
//! - environment variable names are `[A-Z0-9_]+` (they are also written as an
//!   XML `<key>` in the macOS LaunchAgent and as `NAME=value` in systemd);
//! - HTTP header names are lowercase RFC 9110 tokens;
//! - URL path segments and paths use only unreserved characters and `/`.

// A brand is complete data for every platform; each platform build reads only
// the fields that apply to it.
#![allow(dead_code)]

/// The brand compiled into this binary.
pub(crate) const BRAND: &Brand = &crate::brand_saiai::SAIAI_BRAND;

pub(crate) struct Brand {
    /// Executable name (without `.exe`); also the prefix printed by `--version`,
    /// followed by one space and the version.
    pub binary_name: &'static str,
    /// Per-user data directory below the home directory.
    pub home_dir_name: &'static str,
    /// Windows per-user directory below `%LOCALAPPDATA%` (program, Desktop runtime).
    pub windows_app_dir_name: &'static str,
    pub config: ConfigNames,
    pub env: EnvironmentNames,
    pub certificates: CertificateNames,
    pub service: ServiceNames,
    pub update: UpdateNames,
    pub markers: OwnershipMarkers,
    pub placeholders: PlaceholderIdentities,
    pub client_proof: ClientProofNames,
    pub gateway: GatewayProtocolNames,
    /// WinHTTP session agent used for proxy auto-configuration lookups.
    pub winhttp_agent: &'static str,
    /// `clientInfo.name` of the read-only Codex daemon initialization check.
    pub codex_daemon_client_name: &'static str,
}

impl Brand {
    /// Whether `name` is this brand's executable (`<binary>` or `<binary>.exe`).
    pub fn is_executable_name(&self, name: &str) -> bool {
        name.strip_suffix(".exe").unwrap_or(name) == self.binary_name
    }
}

pub(crate) struct ConfigNames {
    pub filename: &'static str,
    /// Configuration *format* version, not a brand identity; it only lives
    /// here because the format is shared by this distribution's installs.
    pub version: u32,
    /// Infix of atomic-write temporary files (`.<file>.<infix>-<pid>-<id>`).
    pub temp_file_infix: &'static str,
}

/// Environment variables read by the client or passed to its own children.
pub(crate) struct EnvironmentNames {
    pub home: &'static str,
    pub install_dir: &'static str,
    pub skip_start: &'static str,
    pub binary_updated: &'static str,
    pub upstream_proxy: &'static str,
    pub chatgpt_timezone: &'static str,
    pub chatgpt_bin: &'static str,
    pub desktop_bin: &'static str,
    pub chatgpt_chat_passthrough: &'static str,
    pub desktop_browser_use: &'static str,
    pub openai_trace: &'static str,
    pub openai_trace_path: &'static str,
    pub proxy_verbose: &'static str,
    pub claude_desktop_allow_untested: &'static str,
}

pub(crate) struct CertificateNames {
    pub ca_cert_filename: &'static str,
    pub ca_key_filename: &'static str,
    /// Backups starting with this prefix belong to the CA pair and are not
    /// listed as generic Claude settings backups by uninstall.
    pub ca_backup_prefix: &'static str,
    /// Common name prefix; a per-installation key suffix follows a space.
    pub ca_common_name_prefix: &'static str,
    pub ca_organization: &'static str,
    pub nss_nickname: &'static str,
    /// HKDF salt deriving per-host local TLS leaf keys from the CA key.
    pub tls_leaf_salt: &'static [u8],
    /// CONNECT host answering with the managed leaf SPKI pins.
    pub control_host: &'static str,
    pub spki_header: &'static str,
}

pub(crate) struct ServiceNames {
    /// systemd user unit `<prefix><environment suffix>.service`.
    pub systemd_unit_prefix: &'static str,
    /// launchd label `<label><environment suffix>`.
    pub launchd_label: &'static str,
    pub pid_filename: &'static str,
    pub lock_filename: &'static str,
    pub log_filename: &'static str,
}

pub(crate) struct UpdateNames {
    /// Path segment below the Gateway base URL serving manifest and assets.
    pub channel_path: &'static str,
    /// Release asset prefix (`<prefix>linux-x86_64`, …).
    pub asset_prefix: &'static str,
    /// Staged replacement executable (`<prefix><unique>[.exe]`).
    pub candidate_prefix: &'static str,
    /// Previous executable kept after an update (`<prefix><timestamp>[.exe]`).
    pub backup_prefix: &'static str,
    /// Windows update helper result next to the executable.
    pub status_filename: &'static str,
}

pub(crate) struct OwnershipMarkers {
    pub codex_ide_env_begin: &'static str,
    pub codex_ide_env_end: &'static str,
    pub vscode_proxy: &'static str,
}

pub(crate) struct PlaceholderIdentities {
    pub codex_account_id: &'static str,
    /// Unsigned local-only JWT used as Codex id and access token.
    pub codex_token: &'static str,
    /// Placeholder access tokens written by older clients.
    pub legacy_codex_token_prefix: &'static str,
    /// Every synthetic Desktop bearer token starts with this; such tokens
    /// are never forwarded upstream.
    pub desktop_token_prefix: &'static str,
    /// Claude Desktop access tokens; must start with `desktop_token_prefix`.
    pub claude_desktop_token_prefix: &'static str,
    pub claude_desktop_session_prefix: &'static str,
    pub desktop_email: &'static str,
}

/// Names of Gateway endpoints and headers specific to this distribution.
pub(crate) struct GatewayProtocolNames {
    /// Native Chat update channel: a complete path starting with
    /// `/backend-api/` and without the `/chatgpt` prefix (the local proxy
    /// forwards it as `/chatgpt` + this path).
    pub chat_updates_path: &'static str,
    /// Response header marking a restored native Chat preference.
    pub chat_preference_restored_header: &'static str,
}

pub(crate) struct ClientProofNames {
    pub header: &'static str,
    pub message_domain: &'static str,
    pub enroll_path: &'static str,
    pub key_filename: &'static str,
    pub lock_filename: &'static str,
    pub device_filename: &'static str,
    /// Unreadable key kept aside before a new device key is created.
    pub corrupt_key_filename: &'static str,
}
