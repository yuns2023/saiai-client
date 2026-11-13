//! Product identity of this client build.
//!
//! Everything a client installation exposes to its users, their files and
//! the Gateway as a *name* lives in one read-only [`Brand`] value: binary and
//! directory names, environment variables, certificate and service identities,
//! update coordinates, ownership markers, placeholder identities and client
//! proof wire names. Core code reads these values only through [`BRAND`] /
//! [`brand`], i.e. the brand the program's entry point passed to `run`; the
//! concrete values of a distribution live outside the library.
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

use anyhow::{Result, bail};
use std::ffi::OsStr;
use std::fmt;
use std::ops::Deref;
use std::path::Path;
use std::sync::OnceLock;

static INSTALLED: OnceLock<&'static Brand> = OnceLock::new();

/// Installs the distribution's brand once per process; `run` does this
/// before parsing. A later `run` in the same process must pass the same brand.
pub(crate) fn install(brand: &'static Brand) -> Result<()> {
    install_into(&INSTALLED, brand)
}

fn install_into(slot: &OnceLock<&'static Brand>, brand: &'static Brand) -> Result<()> {
    // Reject an unusable brand before it occupies the slot or the program
    // writes anything (a later failure could leave half-finished work).
    validate(brand)?;
    let installed = *slot.get_or_init(|| brand);
    if !std::ptr::eq(installed, brand) {
        bail!(
            "this process already runs as {}; a different brand cannot be installed",
            installed.binary_name
        );
    }
    Ok(())
}

/// Values that are embedded in scripts, service files or environment
/// variable positions must stay inert there.
fn validate(brand: &Brand) -> Result<()> {
    crate::script_brand::validate(brand)?;
    for name in brand.sensitive_inbound_headers {
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid || crate::gateway::is_protected_header(name) {
            bail!("brand sensitive_inbound_headers entry is not a usable header name: {name:?}");
        }
    }
    // Embedded verbatim in JSON answers and messages. A conservative limit
    // because those answers are assembled by hand (`format!`) rather than
    // serialized; a display name could be JSON-escaped instead if a brand
    // ever needs other characters.
    for (field, value, valid) in [
        (
            "binary_name",
            brand.binary_name,
            (|byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                as fn(u8) -> bool,
        ),
        ("product_name", brand.product_name, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'.')
        }),
        (
            "placeholders.synthetic_id_prefix",
            brand.placeholders.synthetic_id_prefix,
            |byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-',
        ),
    ] {
        if value.is_empty() || !value.bytes().all(valid) {
            bail!("brand {field} may only use plain name characters: {value:?}");
        }
    }
    let env = &brand.env;
    for (field, name) in [
        ("env.home", env.home),
        ("env.install_dir", env.install_dir),
        ("env.skip_start", env.skip_start),
        ("env.binary_updated", env.binary_updated),
        ("env.upstream_proxy", env.upstream_proxy),
        ("env.chatgpt_timezone", env.chatgpt_timezone),
        ("env.chatgpt_bin", env.chatgpt_bin),
        ("env.desktop_bin", env.desktop_bin),
        ("env.chatgpt_chat_passthrough", env.chatgpt_chat_passthrough),
        ("env.desktop_browser_use", env.desktop_browser_use),
        ("env.openai_trace", env.openai_trace),
        ("env.openai_trace_path", env.openai_trace_path),
        ("env.proxy_verbose", env.proxy_verbose),
        (
            "env.claude_desktop_allow_untested",
            env.claude_desktop_allow_untested,
        ),
    ] {
        // `[A-Z][A-Z0-9_]*`: also written as a LaunchAgent `<key>` and a
        // systemd `Environment=` name.
        let valid = name.starts_with(|ch: char| ch.is_ascii_uppercase())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
        if !valid {
            bail!("brand {field} is not a portable environment variable name: {name:?}");
        }
    }
    Ok(())
}

/// The brand of the program running this library.
pub(crate) fn brand() -> &'static Brand {
    match INSTALLED.get() {
        Some(brand) => brand,
        None => uninstalled_brand(),
    }
}

#[cfg(not(test))]
fn uninstalled_brand() -> &'static Brand {
    panic!("the brand is installed by run() before any command executes")
}

// Unit tests call library functions without going through `run`; they see
// the SAIAI values, which the golden contract tests expect.
#[cfg(test)]
fn uninstalled_brand() -> &'static Brand {
    &crate::brand_saiai::SAIAI_BRAND
}

/// `BRAND.field` reads the installed brand (see [`brand`]).
pub(crate) const BRAND: ActiveBrand = ActiveBrand;

#[derive(Clone, Copy)]
pub struct ActiveBrand;

impl Deref for ActiveBrand {
    type Target = Brand;

    fn deref(&self) -> &Brand {
        brand()
    }
}

/// A brand field read when used, for names that used to be constants.
pub struct BrandValue<T: 'static>(pub fn(&'static Brand) -> T);

impl<T> Clone for BrandValue<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for BrandValue<T> {}

impl<T> BrandValue<T> {
    pub fn get(&self) -> T {
        (self.0)(brand())
    }
}

impl Deref for BrandValue<&'static str> {
    type Target = str;

    fn deref(&self) -> &str {
        self.get()
    }
}

impl AsRef<str> for BrandValue<&'static str> {
    fn as_ref(&self) -> &str {
        self.get()
    }
}

impl AsRef<Path> for BrandValue<&'static str> {
    fn as_ref(&self) -> &Path {
        Path::new(self.get())
    }
}

impl AsRef<OsStr> for BrandValue<&'static str> {
    fn as_ref(&self) -> &OsStr {
        OsStr::new(self.get())
    }
}

impl fmt::Display for BrandValue<&'static str> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate so width, precision and alignment behave like the string's.
        fmt::Display::fmt(self.get(), formatter)
    }
}

impl<T: fmt::Debug> fmt::Debug for BrandValue<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl<T: PartialEq<U>, U> PartialEq<U> for BrandValue<T> {
    fn eq(&self, other: &U) -> bool {
        self.get() == *other
    }
}

pub struct Brand {
    /// Executable name (without `.exe`); also the prefix printed by `--version`,
    /// followed by one space and the version.
    pub binary_name: &'static str,
    /// Product name in messages and in the local proxy's synthetic Desktop
    /// answers. Letters, digits, spaces, `-` and `.` only.
    pub product_name: &'static str,
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
    pub scripts: ScriptNames,
    /// Inbound request headers only this program may produce; stripped from
    /// every request the proxy rebuilds (case-insensitive), in addition to
    /// the Gateway extension's signature headers. Lowercase.
    pub sensitive_inbound_headers: &'static [&'static str],
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

pub struct ConfigNames {
    pub filename: &'static str,
    /// Configuration *format* version, not a brand identity; it only lives
    /// here because the format is shared by this distribution's installs.
    pub version: u32,
    /// Infix of atomic-write temporary files (`.<file>.<infix>-<pid>-<id>`).
    pub temp_file_infix: &'static str,
}

/// Environment variables read by the client or passed to its own children.
pub struct EnvironmentNames {
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

pub struct CertificateNames {
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

pub struct ServiceNames {
    /// systemd user unit `<prefix><environment suffix>.service`.
    pub systemd_unit_prefix: &'static str,
    /// launchd label `<label><environment suffix>`.
    pub launchd_label: &'static str,
    pub pid_filename: &'static str,
    pub lock_filename: &'static str,
    pub log_filename: &'static str,
}

pub struct UpdateNames {
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

pub struct OwnershipMarkers {
    pub codex_ide_env_begin: &'static str,
    pub codex_ide_env_end: &'static str,
    pub vscode_proxy: &'static str,
}

pub struct PlaceholderIdentities {
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
    /// Prefix of the synthetic local identifiers in Desktop answers: the
    /// MCP server name, Statsig rule ids, user and stable ids, and the
    /// Claude model catalog revision. Lowercase letters, digits and `-`.
    pub synthetic_id_prefix: &'static str,
}

/// Names the program's own helper scripts use (see `script_brand`).
pub struct ScriptNames {
    /// Prefix of environment variables passed to helper scripts and of
    /// internal helper markers; `[A-Z][A-Z0-9_]*_`.
    pub env_prefix: &'static str,
    /// Prefix of .NET types and PowerShell functions the helpers define;
    /// `[A-Z][A-Za-z0-9]*`.
    pub identifier_prefix: &'static str,
}

/// Names of Gateway endpoints and headers specific to this distribution.
pub struct GatewayProtocolNames {
    /// Native Chat update channel: a complete path starting with
    /// `/backend-api/` and without the `/chatgpt` prefix (the local proxy
    /// forwards it as `/chatgpt` + this path).
    pub chat_updates_path: &'static str,
    /// Response header marking a restored native Chat preference.
    pub chat_preference_restored_header: &'static str,
}

pub struct ClientProofNames {
    pub header: &'static str,
    pub message_domain: &'static str,
    pub enroll_path: &'static str,
    pub key_filename: &'static str,
    pub lock_filename: &'static str,
    pub device_filename: &'static str,
    /// Unreadable key kept aside before a new device key is created.
    pub corrupt_key_filename: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A local slot: the process-wide brand is never installed by tests.
    #[test]
    fn install_accepts_the_same_brand_and_rejects_another_without_overwriting() {
        static OTHER: Brand = Brand {
            binary_name: "other",
            ..crate::brand_saiai::SAIAI_VALUES
        };
        let saiai = &crate::brand_saiai::SAIAI_BRAND;
        let slot = OnceLock::new();
        install_into(&slot, saiai).unwrap();
        install_into(&slot, saiai).unwrap();
        let error = install_into(&slot, &OTHER).unwrap_err();
        assert!(error.to_string().contains("saiai"), "{error}");
        assert!(std::ptr::eq(*slot.get().unwrap(), saiai));
    }

    #[test]
    fn an_unsafe_brand_is_rejected_before_it_occupies_the_slot() {
        use crate::brand_saiai::SAIAI_VALUES;
        static BAD_DIRECTORY: Brand = Brand {
            windows_app_dir_name: "SAIAI'; Remove-Item",
            ..SAIAI_VALUES
        };
        static BAD_PREFIX: Brand = Brand {
            scripts: ScriptNames {
                env_prefix: "SA$AI_",
                identifier_prefix: "Saiai",
            },
            ..SAIAI_VALUES
        };
        static BAD_ENV: Brand = Brand {
            env: EnvironmentNames {
                home: "SAIAI HOME",
                ..SAIAI_VALUES.env
            },
            ..SAIAI_VALUES
        };
        // Names embedded verbatim in JSON answers and messages.
        static BAD_PRODUCT: Brand = Brand {
            product_name: "SAIAI\"}",
            ..SAIAI_VALUES
        };
        static BAD_BINARY: Brand = Brand {
            binary_name: "saiai start",
            ..SAIAI_VALUES
        };
        static BAD_SYNTHETIC: Brand = Brand {
            placeholders: PlaceholderIdentities {
                synthetic_id_prefix: "Saiai-local",
                ..SAIAI_VALUES.placeholders
            },
            ..SAIAI_VALUES
        };
        static EMPTY_PRODUCT: Brand = Brand {
            product_name: "",
            ..SAIAI_VALUES
        };
        for brand in [
            &BAD_DIRECTORY,
            &BAD_PREFIX,
            &BAD_ENV,
            &BAD_PRODUCT,
            &BAD_BINARY,
            &BAD_SYNTHETIC,
            &EMPTY_PRODUCT,
        ] {
            let slot = OnceLock::new();
            assert!(install_into(&slot, brand).is_err());
            assert!(slot.get().is_none());
        }
        let slot = OnceLock::new();
        install_into(&slot, &crate::brand_saiai::SAIAI_BRAND).unwrap();
    }
}
