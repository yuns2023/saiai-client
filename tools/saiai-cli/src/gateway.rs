//! Gateway-specific behavior behind a replaceable interface.
//!
//! The local proxy is a transparent client for any compatible Gateway. A
//! distribution whose Gateway speaks an additional protocol (for example a
//! device proof on every request) supplies a [`GatewayExtension`] through
//! `RuntimeContext`; [`NoGatewayExtension`] adds nothing.
//!
//! Contract (see the C1 design):
//! - [`GatewayExtension::start`] is called once per local proxy run, returns
//!   at once and does all slow work (loading keys, enrollment) in tasks it
//!   spawns on [`GatewayStart::runtime`].
//! - [`GatewaySession::sign`] is called once per Gateway request attempt,
//!   just before it is sent, with the final method, wire target and the
//!   exact Bearer the Gateway will receive. It must not block, fail or
//!   panic; an empty result sends the request unsigned.
//! - Signatures are written only under the names the extension declared in
//!   [`GatewayExtension::signature_headers`]; transport and credential
//!   headers can never be set this way. Declared names are also stripped from
//!   every inbound request the proxy rebuilds, together with the brand's
//!   `sensitive_inbound_headers`, from the first request on.

use anyhow::Result;
use futures_util::future::BoxFuture;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Gateway behavior of a distribution.
pub trait GatewayExtension: std::any::Any + Send + Sync {
    /// Lowercase names of the request headers this extension adds. Only the
    /// proxy may produce them, so they are removed from inbound requests.
    fn signature_headers(&self) -> &'static [&'static str] {
        &[]
    }

    /// Starts the per-run session. Must return immediately.
    fn start(&self, start: GatewayStart) -> Arc<dyn GatewaySession>;

    /// Whether the Gateway relays the official ChatGPT Desktop's ordinary
    /// Chat (below `/chatgpt/`), and its names for that relay. `None` turns
    /// the relay off: those requests get an explicit "unsupported" response,
    /// while Codex traffic and the local Desktop compatibility layer stay.
    fn native_chat(&self) -> Option<NativeChatProtocol> {
        None
    }
}

/// What a session gets from the local proxy run that starts it.
pub struct GatewayStart {
    /// Directory for the session's persistent state (the selected
    /// environment's directory); `None` disables persistent features.
    pub state_dir: Option<PathBuf>,
    /// Effective Gateway routes of this run (Anthropic, OpenAI), in order.
    pub routes: Vec<ConfiguredRoute>,
    /// HTTP clients that follow the user's upstream proxy settings.
    pub http: Arc<dyn GatewayHttp>,
    /// Runtime for the session's background work.
    pub runtime: tokio::runtime::Handle,
    /// Released program version.
    pub version: &'static str,
}

/// A Gateway's ordinary Chat relay for the official ChatGPT Desktop.
///
/// Data only: the relay itself (path allowlist, device-proof cookie,
/// preference restore, trace redaction) is ChatGPT client protocol handled
/// by the kernel; a Gateway contributes that it serves the relay plus the
/// names that are its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeChatProtocol {
    /// Gateway's Chat updates channel: a complete path starting with
    /// `/backend-api/` (forwarded as `/chatgpt` + this path).
    pub updates_path: &'static str,
    /// Lowercase response header marking a restored Chat preference.
    pub preference_restored_header: &'static str,
    /// `_devicecheck` values that are local placeholders, never forwarded.
    pub rejected_device_proofs: &'static [&'static str],
}

/// One configured Gateway route.
pub struct ConfiguredRoute {
    pub base_url: String,
    pub api_key: Zeroizing<String>,
}

/// Source of Gateway HTTP clients; resolve again for every attempt.
pub trait GatewayHttp: Send + Sync {
    fn client_for<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<reqwest::Client>>;
}

/// The transport of a signed request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Http,
    WebSocket,
}

/// The final shape of one Gateway request attempt.
#[derive(Clone, Copy, Debug)]
pub struct SignInput<'a> {
    pub transport: Transport,
    /// Gateway base URL of the route the request goes to.
    pub gateway: &'a str,
    pub method: &'a str,
    /// Path and raw query as sent.
    pub target: &'a str,
    /// The single Bearer credential the Gateway receives, if determinable.
    pub bearer: Option<&'a str>,
}

/// Per-run Gateway state.
pub trait GatewaySession: Send + Sync {
    /// Header name/value pairs to add to this attempt.
    fn sign(&self, input: &SignInput<'_>) -> Vec<(String, String)>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any;
}

/// A Gateway without extra protocol: nothing is loaded, signed or stored.
pub struct NoGatewayExtension;

impl GatewayExtension for NoGatewayExtension {
    fn start(&self, _start: GatewayStart) -> Arc<dyn GatewaySession> {
        Arc::new(NoGatewaySession)
    }
}

struct NoGatewaySession;

impl GatewaySession for NoGatewaySession {
    fn sign(&self, _input: &SignInput<'_>) -> Vec<(String, String)> {
        Vec::new()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Path and raw query of a request URL as sent on the wire.
pub fn wire_target(url: &url::Url) -> String {
    let mut target = url.path().to_string();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

/// Headers an extension may never set: transport framing, routing and
/// credentials of the request it signs.
const FORBIDDEN_SIGNATURE_HEADERS: &[&str] = &[
    "authorization",
    "host",
    "connection",
    "upgrade",
    "content-length",
    "transfer-encoding",
    "te",
    "trailer",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "cookie",
];

/// Concrete type of an extension, taken by the kernel (not overridable).
pub(crate) fn extension_type(extension: &dyn GatewayExtension) -> std::any::TypeId {
    let any: &dyn std::any::Any = extension;
    any.type_id()
}

/// Header the proxy itself manages on Gateway requests: credentials,
/// framing and the WebSocket handshake. Brand and extension reserved names
/// may never be one of these, so reserving a name can never break the
/// handshake copy or let a signature replace a credential.
pub(crate) fn is_protected_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FORBIDDEN_SIGNATURE_HEADERS.contains(&lower.as_str()) || lower.starts_with("sec-websocket-")
}

/// Checks the names an extension declares: valid lowercase header names
/// that are not protected. Rejected at installation, before any request.
pub(crate) fn validate_extension(extension: &dyn GatewayExtension) -> Result<()> {
    for name in extension.signature_headers() {
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid || is_protected_header(name) {
            anyhow::bail!("Gateway extension declares an unusable signature header {name:?}");
        }
    }
    if let Some(chat) = extension.native_chat() {
        let header = chat.preference_restored_header;
        let valid = !header.is_empty()
            && header
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid || is_protected_header(header) {
            anyhow::bail!("Gateway extension declares an unusable Chat response header {header:?}");
        }
        let path = chat.updates_path;
        if !path.starts_with("/backend-api/")
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
        {
            anyhow::bail!("Gateway extension declares an unusable Chat updates path {path:?}");
        }
    }
    Ok(())
}

/// Inbound header that only this proxy may produce (case-insensitive): the
/// brand's sensitive headers and the running extension's signature headers.
pub(crate) fn is_reserved_inbound_header(extension: &dyn GatewayExtension, name: &str) -> bool {
    crate::brand::BRAND
        .sensitive_inbound_headers
        .iter()
        .chain(extension.signature_headers())
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// Validated signature headers of `session` for one attempt: only names the
/// extension declared (returned as its static spelling), never forbidden
/// ones, only valid values. Anything else is skipped with a diagnostic.
pub(crate) fn signature(
    extension: &dyn GatewayExtension,
    session: &dyn GatewaySession,
    input: &SignInput<'_>,
) -> Vec<(&'static str, String)> {
    let declared = extension.signature_headers();
    let mut accepted: Vec<(&'static str, String)> = Vec::new();
    for (name, value) in session.sign(input) {
        let Some(&name) = declared
            .iter()
            .find(|declared| declared.eq_ignore_ascii_case(&name))
        else {
            eprintln!("gateway extension: skipped undeclared signature header {name}");
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if is_protected_header(name) {
            eprintln!("gateway extension: skipped forbidden signature header {name}");
            continue;
        }
        // Exits insert with `HeaderName::from_static`, which needs a valid
        // lowercase name; anything else would panic there.
        if name != lower || reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
            eprintln!("gateway extension: skipped invalid signature header name {name}");
            continue;
        }
        if reqwest::header::HeaderValue::from_str(&value).is_err() {
            // The value is a credential-like proof: never print it.
            eprintln!("gateway extension: skipped invalid value for signature header {name}");
            continue;
        }
        // Insertion replaces an earlier value of the same header.
        accepted.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        accepted.push((name, value));
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scripted(Vec<(String, String)>);

    impl GatewaySession for Scripted {
        fn sign(&self, _input: &SignInput<'_>) -> Vec<(String, String)> {
            self.0.clone()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct Declares(&'static [&'static str]);

    impl GatewayExtension for Declares {
        fn signature_headers(&self) -> &'static [&'static str] {
            self.0
        }

        fn start(&self, _start: GatewayStart) -> Arc<dyn GatewaySession> {
            unreachable!()
        }
    }

    const INPUT: SignInput<'static> = SignInput {
        transport: Transport::Http,
        gateway: "https://gateway.example",
        method: "POST",
        target: "/v1/messages",
        bearer: Some("TEST_ONLY_KEY"),
    };

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn only_declared_safe_valid_headers_are_written_and_last_value_wins() {
        let extension = Declares(&["x-test-proof", "authorization", "sec-websocket-key"]);
        let session = Scripted(pairs(&[
            ("X-Test-Proof", "first"),
            ("x-undeclared", "value"),
            ("Authorization", "Bearer stolen"),
            ("sec-websocket-key", "forged"),
            ("x-test-proof", "bad\r\nvalue"),
            ("x-test-proof", "second"),
        ]));
        assert_eq!(
            signature(&extension, &session, &INPUT),
            vec![("x-test-proof", "second".to_string())]
        );
    }

    #[test]
    fn a_declared_name_that_is_not_lowercase_is_skipped_not_inserted() {
        let extension = Declares(&["X-Test-Proof", "x test"]);
        let session = Scripted(pairs(&[("x-test-proof", "value"), ("x test", "value")]));
        assert!(signature(&extension, &session, &INPUT).is_empty());
    }

    #[test]
    fn the_extension_without_protocol_signs_nothing() {
        assert!(NoGatewaySession.sign(&INPUT).is_empty());
        assert!(NoGatewayExtension.signature_headers().is_empty());
    }
}
