//! Test entry points for a distribution's own contract tests (cargo feature
//! `contract`; the library's unit tests compile them too).
//!
//! Each entry calls the code the program runs, unchanged: nothing here adds
//! behavior and the program never calls it. Entries whose result depends on
//! the installed brand take that brand explicitly and fail unless it is the
//! installed one; [`install`] installs a brand and runtime context exactly as
//! `run` does (once per process; installing the same again is fine, another
//! one is refused, and nothing resets it).

use crate::brand::Brand;
use crate::runtime::RuntimeContext;
use anyhow::{Result, bail};

/// Installs `brand` and `context` as `run` does before any command.
pub fn install(brand: &'static Brand, context: RuntimeContext) -> Result<()> {
    crate::brand::install(brand)?;
    crate::runtime::install(context)
}

/// Fails unless `brand` is the installed brand (the same instance); the
/// unit-test fallback brand does not count as installed.
fn installed(brand: &'static Brand) -> Result<()> {
    check_installed(crate::brand::installed(), brand)
}

fn check_installed(installed: Option<&'static Brand>, brand: &'static Brand) -> Result<()> {
    match installed {
        None => bail!("contract entry called before a brand was installed"),
        Some(installed) if !std::ptr::eq(installed, brand) => {
            bail!("contract entry called with a brand other than the installed one")
        }
        Some(_) => Ok(()),
    }
}

/// Service files the program installs for its background proxy.
pub mod service {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::path::Path;

    /// The systemd user unit for `exe` serving the environment `app_home`.
    #[cfg(target_os = "linux")]
    pub fn systemd_unit(
        brand: &'static Brand,
        exe: &Path,
        app_home: &Path,
        working_dir: &Path,
    ) -> Result<String> {
        installed(brand)?;
        crate::render_user_service(exe, app_home, working_dir)
    }

    /// The LaunchAgent property list for `exe` serving `app_home`.
    #[cfg(target_os = "macos")]
    pub fn launchd_plist(
        brand: &'static Brand,
        exe: &Path,
        app_home: &Path,
        working_dir: &Path,
        log: &Path,
    ) -> Result<String> {
        installed(brand)?;
        crate::render_launchd_plist(exe, app_home, working_dir, log)
    }
}

/// The configuration file (`config.json`).
pub mod config {
    use super::*;

    /// Reads config file text with the program's own decoder and writes the
    /// result back as compact JSON: the written text, or the decoder's error
    /// text (with serde_json's line and column).
    pub fn decode(
        brand: &'static Brand,
        json: &str,
    ) -> Result<std::result::Result<String, String>> {
        installed(brand)?;
        Ok(serde_json::from_str::<crate::AppConfig>(json)
            .map(|config| serde_json::to_string(&config).expect("a config always serializes"))
            .map_err(|error| error.to_string()))
    }
}

/// The program's helper script templates and their rendering.
pub mod scripts {
    use super::*;

    /// The VSCode certificate trust helper template (Windows).
    pub const VSCODE_TRUST_WINDOWS: &str = include_str!("vscode_trust_windows.ps1");
    /// The Windows Desktop inspection helper template.
    pub const WINDOWS_DESKTOP_INSPECT: &str = include_str!("windows_desktop_inspect.ps1");

    /// A helper script template rendered for the installed brand.
    pub fn render(brand: &'static Brand, template: &str) -> Result<String> {
        installed(brand)?;
        Ok(crate::script_brand::render(template))
    }

    /// The Windows self-update helper script.
    #[cfg(target_os = "windows")]
    #[allow(clippy::too_many_arguments)]
    pub fn windows_update(
        brand: &'static Brand,
        pid: u32,
        current_exe: &std::path::Path,
        candidate_path: &std::path::Path,
        script_path: &std::path::Path,
        status_path: &std::path::Path,
        restart_service: bool,
        expected_sha256: &str,
    ) -> Result<String> {
        installed(brand)?;
        crate::render_windows_update_script(
            pid,
            current_exe,
            candidate_path,
            script_path,
            status_path,
            restart_service,
            expected_sha256,
        )
    }
}

/// The local TLS leaf certificates the proxy presents.
pub mod certificates {
    use super::*;

    /// The leaf certificate for `host` (DER) and its public key (DER),
    /// derived from the installation CA as the proxy derives it.
    pub fn leaf(
        brand: &'static Brand,
        host: &str,
        ca_cert_pem: &str,
        ca_key_pem: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        installed(brand)?;
        let (der, key) = crate::local_proxy::sign_leaf_certificate(host, ca_cert_pem, ca_key_pem)?;
        Ok((der, key.public_key_der()))
    }
}

/// The self-update channel and file names.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod update {
    use super::*;

    /// Update coordinates for a Gateway base URL and a release asset.
    #[derive(Debug, PartialEq)]
    pub struct Names {
        pub manifest_url: String,
        pub asset_url: String,
        /// This platform's release asset.
        pub current_asset: String,
        /// The staged replacement for `unique`.
        pub candidate: String,
        /// A previous executable kept now (timestamped).
        pub backup: String,
    }

    pub fn names(
        brand: &'static Brand,
        base_url: &str,
        asset: &str,
        unique: &str,
    ) -> Result<Names> {
        installed(brand)?;
        let (manifest_url, asset_url) = crate::update_urls(base_url, asset);
        Ok(Names {
            manifest_url,
            asset_url,
            current_asset: crate::current_platform_asset_name()?,
            candidate: crate::update_candidate_name(unique),
            backup: crate::update_backup_name(),
        })
    }

    /// Whether `bytes` would be accepted as the release asset `asset`.
    pub fn validate_asset(brand: &'static Brand, bytes: &[u8], asset: &str) -> Result<()> {
        installed(brand)?;
        crate::validate_update_asset(bytes, asset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_needs_the_installed_brand_itself() {
        static OTHER: Brand = Brand {
            binary_name: "other",
            ..crate::brand_saiai::SAIAI_VALUES
        };
        let saiai = &crate::brand_saiai::SAIAI_BRAND;
        assert!(check_installed(None, saiai).is_err());
        assert!(check_installed(Some(&OTHER), saiai).is_err());
        assert!(check_installed(Some(saiai), &OTHER).is_err());
        check_installed(Some(saiai), saiai).unwrap();
    }
}

/// The local answers of the Codex / ChatGPT Desktop sidecar.
pub mod desktop {
    use super::*;
    use crate::local_proxy::{DesktopFeatures, IncomingRequest};

    /// A request as the Desktop sends it to the local proxy.
    pub struct Request<'a> {
        pub method: &'a str,
        pub target: &'a str,
        pub headers: &'a [(&'a str, &'a str)],
        pub body: &'a [u8],
    }

    /// A local answer: status, content type (sidecar answers only), body,
    /// diagnostic reason and extra headers.
    #[derive(Debug, PartialEq)]
    pub struct Answer {
        pub status: u16,
        pub content_type: Option<&'static str>,
        pub body: Vec<u8>,
        pub reason: &'static str,
        pub headers: Vec<(&'static str, &'static str)>,
    }

    fn incoming(request: &Request<'_>) -> IncomingRequest {
        IncomingRequest {
            method: request.method.to_string(),
            target: request.target.to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: request
                .headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            body: request.body.to_vec(),
        }
    }

    /// The sidecar's fixed answers (Statsig bootstrap, telemetry no-ops,
    /// refusals of unsupported Desktop controls).
    pub fn sidecar(
        brand: &'static Brand,
        request: &Request<'_>,
        browser_use: bool,
    ) -> Result<Option<Answer>> {
        installed(brand)?;
        let features = DesktopFeatures { browser_use };
        Ok(
            crate::local_proxy::chatgpt_sidecar_response_with(&incoming(request), features).map(
                |response| Answer {
                    status: response.status.as_u16(),
                    content_type: Some(response.content_type),
                    body: response.body.to_vec(),
                    reason: response.reason,
                    headers: Vec::new(),
                },
            ),
        )
    }

    /// The sidecar's local identity answers (accounts, profile, MCP,
    /// identity-preserving Statsig evaluation).
    pub fn account_sidecar(
        brand: &'static Brand,
        request: &Request<'_>,
        browser_use: bool,
    ) -> Result<Option<Answer>> {
        installed(brand)?;
        let features = DesktopFeatures { browser_use };
        Ok(
            crate::local_proxy::chatgpt_account_sidecar_response_with(&incoming(request), features)
                .map(|(status, body, reason, headers)| Answer {
                    status: status.as_u16(),
                    content_type: None,
                    body,
                    reason,
                    headers: headers.to_vec(),
                }),
        )
    }

    /// The local Statsig bootstrap for `brand`.
    pub fn statsig_local_payload(brand: &Brand) -> String {
        crate::local_proxy::desktop_statsig_local_payload(brand)
    }

    /// The Statsig bootstrap with the browser-control gates, as JSON text.
    pub fn statsig_base(brand: &Brand, browser_use: bool) -> String {
        crate::local_proxy::desktop_statsig_base(brand, DesktopFeatures { browser_use }).to_string()
    }

    /// The synthetic user id used when a request carries no identity.
    pub fn synthetic_user_id(brand: &Brand) -> String {
        crate::local_proxy::synthetic_user_id(brand)
    }

    /// The refusal message for an unsupported Desktop control endpoint.
    pub fn control_unsupported_message(brand: &Brand) -> String {
        crate::local_proxy::desktop_control_unsupported_message(brand)
    }
}

/// The Claude Desktop control-plane fixtures.
pub mod claude_desktop {
    use super::*;
    use serde_json::Value;

    pub use crate::claude_desktop::Identity;

    /// The local account, as JSON text.
    pub fn account(brand: &'static Brand, id: &Identity) -> Result<String> {
        installed(brand)?;
        Ok(crate::claude_desktop_fixtures::account(id).to_string())
    }

    /// The local organization, as JSON text.
    pub fn organization(brand: &'static Brand, id: &Identity) -> Result<String> {
        installed(brand)?;
        Ok(crate::claude_desktop_fixtures::organization(id).to_string())
    }

    /// The model selector configuration, as JSON text.
    pub fn selectors(brand: &'static Brand, models: &[Value], selection: &Value) -> Result<String> {
        installed(brand)?;
        Ok(crate::claude_desktop_fixtures::selectors(models, selection).to_string())
    }

    /// A local control-plane answer (status and JSON text), if any.
    pub fn local(
        brand: &'static Brand,
        method: &str,
        path: &str,
        id: &Identity,
    ) -> Result<Option<(u16, String)>> {
        installed(brand)?;
        Ok(crate::claude_desktop_fixtures::local(method, path, id)
            .map(|(status, value)| (status, value.to_string())))
    }

    /// The local account and organization display name for `brand`.
    pub fn local_code_name(brand: &Brand) -> String {
        crate::claude_desktop_fixtures::local_code_name(brand)
    }

    /// The command that relaunches the isolated Claude Desktop for `brand`.
    pub fn desktop_claude_command(brand: &Brand) -> String {
        crate::claude_desktop_fixtures::desktop_claude_command(brand)
    }
}
