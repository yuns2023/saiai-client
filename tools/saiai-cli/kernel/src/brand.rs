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
//! each distribution freezes its values in its own contract tests.
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
        ("config.type_name", brand.config.type_name, |byte| {
            byte.is_ascii_alphanumeric() || byte == b'_'
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
    // A Rust identifier, as in the type names earlier releases printed.
    if brand
        .config
        .type_name
        .starts_with(|ch: char| ch.is_ascii_digit())
    {
        bail!(
            "brand config.type_name must not start with a digit: {:?}",
            brand.config.type_name
        );
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
    validate_update_source(&brand.update.source)?;
    Ok(())
}

pub(crate) fn validate_update_source(source: &UpdateSource) -> Result<()> {
    match source {
        UpdateSource::GatewayChannel { channel_path } => {
            let valid = !channel_path.is_empty()
                && !channel_path.starts_with('/')
                && !channel_path.ends_with('/')
                && !channel_path.contains("//")
                && channel_path.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/')
                });
            if !valid {
                bail!("brand update channel_path is not a plain URL path: {channel_path:?}");
            }
        }
        UpdateSource::Fixed(fixed) => {
            if fixed.hosts.is_empty()
                || fixed.hosts.iter().any(|host| {
                    host.is_empty()
                        || !host.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'-' | b'.')
                        })
                })
            {
                bail!(
                    "brand update hosts must be lowercase host names: {:?}",
                    fixed.hosts
                );
            }
            let policy = crate::FixedUrlPolicy::https(fixed.hosts);
            policy
                .check(fixed.manifest_url)
                .map_err(|error| anyhow::anyhow!("brand update manifest_url: {error:#}"))?;
            let template = fixed.asset_url_template;
            if template.matches("{version}").count() != 1
                || template.matches("{asset}").count() != 1
            {
                bail!(
                    "brand update asset_url_template needs exactly one {{version}} and one {{asset}}: {template:?}"
                );
            }
            policy
                .check(&crate::fixed_asset_url(
                    template,
                    "1.2.3",
                    "asset-linux-x86_64",
                ))
                .map_err(|error| anyhow::anyhow!("brand update asset_url_template: {error:#}"))?;
        }
    }
    Ok(())
}

/// The installed brand, without the unit-test fallback.
#[cfg(any(test, feature = "contract"))]
pub(crate) fn installed() -> Option<&'static Brand> {
    INSTALLED.get().copied()
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
// the kernel's test brand.
#[cfg(test)]
fn uninstalled_brand() -> &'static Brand {
    &crate::brand_test::KTEST_BRAND
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

/// Program text that names the brand, rendered from the installed brand
/// each time it is printed. A constant of this type works where a `&str`
/// constant did in format arguments (`{USAGE}`) and as an error message.
#[derive(Clone, Copy)]
pub(crate) struct BrandText(pub fn() -> String);

impl fmt::Display for BrandText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&(self.0)(), formatter)
    }
}

impl fmt::Debug for BrandText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&(self.0)(), formatter)
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
    /// Type name in the errors for a config file of the wrong shape
    /// (`expected struct <name>`); earlier releases printed their Rust type
    /// name there. A Rust identifier.
    pub type_name: &'static str,
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
    /// Where the update manifest and release assets are downloaded from.
    pub source: UpdateSource,
    /// Release asset prefix (`<prefix>linux-x86_64`, …).
    pub asset_prefix: &'static str,
    /// Staged replacement executable (`<prefix><unique>[.exe]`).
    pub candidate_prefix: &'static str,
    /// Previous executable kept after an update (`<prefix><timestamp>[.exe]`).
    pub backup_prefix: &'static str,
    /// Windows update helper result next to the executable.
    pub status_filename: &'static str,
    /// PowerShell command that downloads and loads the public setup script,
    /// shown in messages; append a subcommand (`… uninstall`) to run it.
    pub windows_setup_command: &'static str,
}

/// Origin of the update manifest and release assets.
pub enum UpdateSource {
    /// `<configured Gateway base URL>/<channel_path>/manifest.json` and
    /// `/<asset>`. Requires an initialized configuration; a missing manifest
    /// (404) falls back to an unverified asset download, as earlier releases
    /// did. `channel_path`: unreserved URL characters and inner `/`.
    GatewayChannel { channel_path: &'static str },
    /// Fixed HTTPS locations independent of the configured Gateway.
    Fixed(FixedUpdateSource),
}

/// A release channel at fixed HTTPS URLs (for example a GitHub repository's
/// releases). The manifest is required and verified; the asset URL is pinned
/// to the manifest's version, so a release published in between cannot mix
/// one release's manifest with another's asset.
pub struct FixedUpdateSource {
    /// Manifest of the latest release (`{"version": "X.Y.Z", "assets":
    /// {"<asset>": {"sha256": …, "size": …}}}`).
    pub manifest_url: &'static str,
    /// Asset URL with `{version}` (the manifest's `X.Y.Z`) and `{asset}`.
    pub asset_url_template: &'static str,
    /// Hosts every request and redirect target must name exactly (HTTPS,
    /// port 443, no user information). Lowercase.
    pub hosts: &'static [&'static str],
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `BrandText` constant prints exactly like the `&str` constant it
    /// replaced: plain, padded, debug-quoted and as an error message.
    #[test]
    fn brand_text_prints_like_the_string_it_renders() {
        const TEXT: BrandText = BrandText(|| "KTEST \"local\" proxy".to_string());
        let text = "KTEST \"local\" proxy";
        assert_eq!(format!("{TEXT}"), format!("{text}"));
        assert_eq!(format!("[{TEXT:>30}]"), format!("[{text:>30}]"));
        assert_eq!(format!("{TEXT:?}"), format!("{text:?}"));
        assert_eq!(anyhow::anyhow!(TEXT).to_string(), text);
        assert_eq!(format!("{:#}", anyhow::anyhow!(TEXT)), text);
    }

    // A local slot: these tests never touch the process-wide brand, which
    // other tests in this process may read.
    #[test]
    fn install_accepts_the_same_brand_and_rejects_another_without_overwriting() {
        static OTHER: Brand = Brand {
            binary_name: "other",
            ..crate::brand_test::KTEST_VALUES
        };
        let ktest = &crate::brand_test::KTEST_BRAND;
        let slot = OnceLock::new();
        install_into(&slot, ktest).unwrap();
        install_into(&slot, ktest).unwrap();
        let error = install_into(&slot, &OTHER).unwrap_err();
        assert!(error.to_string().contains("ktest"), "{error}");
        assert!(std::ptr::eq(*slot.get().unwrap(), ktest));
    }

    #[test]
    fn an_unsafe_brand_is_rejected_before_it_occupies_the_slot() {
        use crate::brand_test::KTEST_VALUES;
        static BAD_DIRECTORY: Brand = Brand {
            windows_app_dir_name: "KTEST'; Remove-Item",
            ..KTEST_VALUES
        };
        static BAD_PREFIX: Brand = Brand {
            scripts: ScriptNames {
                env_prefix: "SA$AI_",
                identifier_prefix: "Ktest",
            },
            ..KTEST_VALUES
        };
        static BAD_ENV: Brand = Brand {
            env: EnvironmentNames {
                home: "KTEST HOME",
                ..KTEST_VALUES.env
            },
            ..KTEST_VALUES
        };
        // Names embedded verbatim in JSON answers and messages.
        static BAD_PRODUCT: Brand = Brand {
            product_name: "KTEST\"}",
            ..KTEST_VALUES
        };
        static BAD_BINARY: Brand = Brand {
            binary_name: "ktest start",
            ..KTEST_VALUES
        };
        static DIGIT_TYPE_NAME: Brand = Brand {
            config: ConfigNames {
                type_name: "1Config",
                ..KTEST_VALUES.config
            },
            ..KTEST_VALUES
        };
        static BAD_SYNTHETIC: Brand = Brand {
            placeholders: PlaceholderIdentities {
                synthetic_id_prefix: "Ktest-local",
                ..KTEST_VALUES.placeholders
            },
            ..KTEST_VALUES
        };
        static EMPTY_PRODUCT: Brand = Brand {
            product_name: "",
            ..KTEST_VALUES
        };
        for brand in [
            &BAD_DIRECTORY,
            &BAD_PREFIX,
            &BAD_ENV,
            &BAD_PRODUCT,
            &BAD_BINARY,
            &BAD_SYNTHETIC,
            &EMPTY_PRODUCT,
            &DIGIT_TYPE_NAME,
        ] {
            let slot = OnceLock::new();
            assert!(install_into(&slot, brand).is_err());
            assert!(slot.get().is_none());
        }
        let slot = OnceLock::new();
        install_into(&slot, &crate::brand_test::KTEST_BRAND).unwrap();
    }
}
