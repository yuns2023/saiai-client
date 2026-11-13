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

/// Fails unless `brand` is the installed brand (the same instance).
fn installed(brand: &'static Brand) -> Result<()> {
    if !std::ptr::eq(crate::brand::brand(), brand) {
        bail!("contract entry called with a brand other than the installed one");
    }
    Ok(())
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
