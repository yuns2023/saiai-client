use anyhow::{Context, Result, bail};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use reqwest::{Client, Method, StatusCode};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::timeout_at;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::Role;
use url::Url;
use zeroize::Zeroizing;

const ANTHROPIC_HOST: &str = "api.anthropic.com";
const OPENAI_HOST: &str = "api.openai.com";
const CHATGPT_HOST: &str = "chatgpt.com";
// Packaged Windows Desktop 26.908.4834.0 also uses this authenticated
// control-plane alias. Treat it exactly like chatgpt.com: falling through to
// a direct CONNECT bypasses the local sidecars and fails on networks which
// require SAIAI routing.
const CHAT_OPENAI_HOST: &str = "chat.openai.com";
// The packaged Desktop currently uses this host for authenticated Web/Wham
// control-plane calls. It must receive the same local MITM/sidecar treatment
// as chatgpt.com; otherwise CONNECT falls through to the real provider with
// the SAIAI placeholder and the app appears logged out.
const CHATGPT_AUX_HOST: &str = "ab.chatgpt.com";
const CERTIFICATE_CONTROL_HOST: &str = "certificate.saiai.local";
const CERTIFICATE_SPKI_HEADER: &str = "x-saiai-leaf-spki-sha256";
const CHATGPT_CHAT_PASSTHROUGH_ENV: &str = "SAIAI_CHATGPT_CHAT_PASSTHROUGH";
const SAIAI_DESKTOP_EMAIL: &str = "saiai-local-proxy@example.invalid";
const DESKTOP_STATSIG_MAX_REQUEST_BYTES: usize = 1024 * 1024;
// Codex Desktop 26.908.4834.0 / Statsig JS 3.33.4 gates bundled locale
// messages behind layer 72216192. Keep this local bootstrap deliberately
// narrow: it enables only i18n and does not opt the synthetic SAIAI identity
// into unrelated hosted experiments or send it to the Statsig control plane.
const DESKTOP_STATSIG_I18N_PAYLOAD: &str = r#"{"feature_gates":{},"dynamic_configs":{},"layer_configs":{"72216192":{"name":"72216192","value":{"enable_i18n":true},"rule_id":"saiai-local-i18n","secondary_exposures":[],"is_user_in_experiment":false,"is_experiment_active":false,"allocated_experiment_name":"","explicit_parameters":["enable_i18n"],"undelegated_secondary_exposures":[]}},"has_updates":true,"time":0,"user":{"userID":"saiai-local-proxy-user","customIDs":{"stableID":"saiai-local-proxy"}}}"#;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HEADER_LINE: usize = 32 * 1024;
const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_CHAT_INIT_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_DESKTOP_STATE_BYTES: u64 = 2 * 1024 * 1024;

// Service-managed stdout/stderr is the primary diagnostic stream on all
// supported platforms. Keep every proxy line timestamped consistently; this
// is especially important for macOS/Windows file logs, where the service
// manager does not add journal timestamps.
macro_rules! eprintln {
    ($($arg:tt)*) => {
        ::std::eprintln!("[{}] {}", chrono::Utc::now().to_rfc3339(), format_args!($($arg)*));
    };
}

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub base_url: String,
    pub api_key: String,
    pub claude: Option<RouteConfig>,
    pub codex: Option<RouteConfig>,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub verbose: bool,
    pub chatgpt_chat_passthrough: bool,
}

#[derive(Clone)]
pub struct RouteConfig {
    pub base_url: String,
    pub api_key: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("listen", &self.listen)
            .field("base_url", &self.base_url)
            .field("api_key", &"[redacted]")
            .field("claude", &self.claude.as_ref().map(|_| "[configured]"))
            .field("codex", &self.codex.as_ref().map(|_| "[configured]"))
            .field("runtime_ca", &true)
            .field("verbose", &self.verbose)
            .field("chatgpt_chat_passthrough", &self.chatgpt_chat_passthrough)
            .finish()
    }
}

struct State {
    listen: String,
    default_route: UpstreamRoute,
    claude_route: Option<UpstreamRoute>,
    codex_route: Option<UpstreamRoute>,
    ca_cert_pem: String,
    ca_key_pem: Zeroizing<String>,
    verbose: bool,
    chatgpt_chat_passthrough: bool,
    client: Client,
    certs: Mutex<HashMap<String, ManagedCertificate>>,
    openai_trace: Option<Arc<OpenAITrace>>,
}

struct UpstreamRoute {
    base_url: String,
    api_key: Zeroizing<String>,
}

fn validate_route(name: &str, route: RouteConfig) -> Result<UpstreamRoute> {
    let base = route.base_url.trim().trim_end_matches('/').to_string();
    let parsed =
        Url::parse(&base).with_context(|| format!("invalid {name} SAIAI base URL: {base}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => bail!("{name} SAIAI base URL must use http or https, got {scheme}"),
    }
    if parsed.host_str().is_none() {
        bail!("{name} SAIAI base URL host is required");
    }
    if route.api_key.trim().is_empty() {
        bail!("{name} SAIAI API key is required");
    }
    Ok(UpstreamRoute {
        base_url: base,
        api_key: Zeroizing::new(route.api_key),
    })
}

#[derive(Clone)]
struct ManagedCertificate {
    config: Arc<ServerConfig>,
    spki_sha256: String,
}

struct ParsedConnect {
    host: String,
    port: u16,
}

enum InitialProxyRequest {
    Connect(ParsedConnect),
    Http(IncomingRequest),
}

#[derive(Debug, Clone)]
struct IncomingRequest {
    method: String,
    target: String,
    http_version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct OpenAITrace {
    file: Mutex<fs::File>,
}

impl OpenAITrace {
    fn from_env() -> Result<Option<Arc<Self>>> {
        if env::var("SAIAI_OPENAI_TRACE").ok().as_deref() != Some("1") {
            return Ok(None);
        }
        let path = env::var("SAIAI_OPENAI_TRACE_PATH")
            .unwrap_or_else(|_| "/tmp/saiai-openai-trace.jsonl".to_string());
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create OpenAI trace directory {}",
                    parent.display()
                )
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open OpenAI trace {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to protect OpenAI trace {}", path.display()))?;
        }
        eprintln!("OpenAI trace enabled path={}", path.display());
        Ok(Some(Arc::new(Self {
            file: Mutex::new(file),
        })))
    }

    fn write(&self, record: Value) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        let Ok(mut bytes) = serde_json::to_vec(&record) else {
            return;
        };
        bytes.push(b'\n');
        let _ = file.write_all(&bytes);
        let _ = file.flush();
    }
}

struct UpstreamResponseOutcome {
    status: StatusCode,
    response_bytes: u64,
    chunks: u64,
}

struct StaticResponse {
    status: StatusCode,
    content_type: &'static str,
    body: &'static [u8],
    reason: &'static str,
}

type AccountSidecarResponse = (
    StatusCode,
    Vec<u8>,
    &'static str,
    &'static [(&'static str, &'static str)],
);

pub async fn run(cfg: Config) -> Result<()> {
    let state = Arc::new(State::new(cfg)?);
    let listener = TcpListener::bind(&state.listen)
        .await
        .with_context(|| format!("failed to bind local proxy on {}", state.listen))?;

    eprintln!("saiai local proxy listening on http://{}", state.listen);
    eprintln!(
        "forwarding managed Claude/OpenAI traffic to {}",
        state.default_route.base_url
    );
    eprintln!("press Ctrl-C to stop");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted.context("failed to accept local proxy connection")?;
                let state = Arc::clone(&state);
                let verbose = state.verbose;
                tokio::spawn(async move {
                    if let Err(err) = handle_client(state, stream, remote_addr).await
                        && (verbose || !is_benign_client_error(&err))
                    {
                        eprintln!("local proxy client {} error: {err:#}", remote_addr);
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl-C")?;
                eprintln!("saiai local proxy stopped");
                return Ok(());
            }
        }
    }
}

impl State {
    fn new(cfg: Config) -> Result<Self> {
        ensure_rustls_crypto_provider();

        if cfg.listen.trim().is_empty() {
            bail!("local proxy listen address is required");
        }
        let listen_addr = cfg
            .listen
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid local proxy listen address {}", cfg.listen))?;
        if !listen_addr.ip().is_loopback() {
            bail!(
                "local proxy listen address must be loopback-only, got {}",
                cfg.listen
            );
        }
        let default_route = validate_route(
            "default",
            RouteConfig {
                base_url: cfg.base_url,
                api_key: cfg.api_key,
            },
        )?;
        let claude_route = cfg
            .claude
            .map(|route| validate_route("Claude", route))
            .transpose()?;
        let codex_route = cfg
            .codex
            .map(|route| validate_route("Codex", route))
            .transpose()?;

        build_leaf_server_config(ANTHROPIC_HOST, &cfg.ca_cert_pem, &cfg.ca_key_pem)
            .context("failed to validate installation-specific SAIAI CA")?;

        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .context("failed to build upstream HTTP client")?;
        let openai_trace = OpenAITrace::from_env()?;
        let chatgpt_chat_passthrough = match env::var(CHATGPT_CHAT_PASSTHROUGH_ENV).ok().as_deref()
        {
            Some("0") => false,
            Some("1") => true,
            _ => cfg.chatgpt_chat_passthrough,
        };
        // This is an opt-in operator diagnostic for a single inherited service
        // process. It never enables body tracing; verbose records remain
        // limited to request metadata and response outcomes.
        let verbose = cfg.verbose || env::var("SAIAI_PROXY_VERBOSE").ok().as_deref() == Some("1");

        Ok(Self {
            listen: cfg.listen,
            default_route,
            claude_route,
            codex_route,
            ca_cert_pem: cfg.ca_cert_pem,
            ca_key_pem: Zeroizing::new(cfg.ca_key_pem),
            verbose,
            chatgpt_chat_passthrough,
            client,
            certs: Mutex::new(HashMap::new()),
            openai_trace,
        })
    }

    fn tls_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        Ok(Arc::clone(&self.certificate_for_host(host)?.config))
    }

    fn tls_spki_for_host(&self, host: &str) -> Result<String> {
        Ok(self.certificate_for_host(host)?.spki_sha256)
    }

    fn desktop_tls_spki_list(&self) -> Result<String> {
        [
            OPENAI_HOST,
            CHATGPT_HOST,
            CHAT_OPENAI_HOST,
            CHATGPT_AUX_HOST,
        ]
        .into_iter()
        .map(|host| self.tls_spki_for_host(host))
        .collect::<Result<Vec<_>>>()
        .map(|pins| pins.join(","))
    }

    fn certificate_for_host(&self, host: &str) -> Result<ManagedCertificate> {
        let host = canonical_host(host);
        {
            let certs = self.lock_cert_cache();
            if let Some(certificate) = certs.get(&host) {
                return Ok(certificate.clone());
            }
        }

        let certificate = build_leaf_server_config(&host, &self.ca_cert_pem, &self.ca_key_pem)?;
        let mut certs = self.lock_cert_cache();
        Ok(certs.entry(host).or_insert(certificate).clone())
    }

    fn route_for_host(&self, host: &str) -> &UpstreamRoute {
        let host = canonical_host(host);
        match host.as_str() {
            ANTHROPIC_HOST => self.claude_route.as_ref().unwrap_or(&self.default_route),
            OPENAI_HOST | CHATGPT_HOST | CHAT_OPENAI_HOST | CHATGPT_AUX_HOST => {
                self.codex_route.as_ref().unwrap_or(&self.default_route)
            }
            _ => &self.default_route,
        }
    }

    fn upstream_url(&self, target: &str, route: &UpstreamRoute) -> Result<String> {
        let path_query = path_query_from_target(target)?;
        Ok(format!("{}{}", route.base_url, path_query))
    }

    fn websocket_upstream_url(&self, target: &str, route: &UpstreamRoute) -> Result<Url> {
        let mut url = Url::parse(&self.upstream_url(target, route)?)
            .context("failed to parse Gateway WebSocket URL")?;
        let scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            scheme => bail!("unsupported Gateway WebSocket scheme {scheme}"),
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("failed to set Gateway WebSocket scheme"))?;
        Ok(url)
    }

    fn trace_openai_request(&self, event: &str, direction: &str, request: &IncomingRequest) {
        let Some(trace) = &self.openai_trace else {
            return;
        };
        if is_chatgpt_upload_target(&request.target)
            || is_chatgpt_device_cookie_target(&request.target)
        {
            trace.write(json!({
                "event": event, "direction": direction, "method": request.method,
                "path": request.target.split('?').next(),
                "bytes": request.body.len(),
                "sha256": format!("{:x}", Sha256::digest(&request.body)),
            }));
            return;
        }
        let mut headers = Map::new();
        for (name, value) in &request.headers {
            let name = name.to_ascii_lowercase();
            let value = if matches!(
                name.as_str(),
                "authorization" | "proxy-authorization" | "cookie"
            ) {
                "<redacted>".to_string()
            } else {
                value.clone()
            };
            headers.insert(name, Value::String(value));
        }
        trace.write(json!({
            "event": event,
            "direction": direction,
            "method": request.method,
            "path": request.target,
            "headers": headers,
            "body": String::from_utf8_lossy(&request.body),
        }));
    }

    fn trace_openai_frame(&self, direction: &str, message: &Message) {
        let Some(trace) = &self.openai_trace else {
            return;
        };
        let (kind, body) = match message {
            Message::Text(text) => ("text", Value::String(text.to_string())),
            Message::Binary(bytes) => (
                "binary",
                json!({
                    "bytes": bytes.len(),
                    "sha256": format!("{:x}", Sha256::digest(bytes)),
                }),
            ),
            Message::Ping(bytes) => (
                "ping",
                json!({
                    "bytes": bytes.len(),
                    "sha256": format!("{:x}", Sha256::digest(bytes)),
                }),
            ),
            Message::Pong(bytes) => (
                "pong",
                json!({
                    "bytes": bytes.len(),
                    "sha256": format!("{:x}", Sha256::digest(bytes)),
                }),
            ),
            Message::Close(frame) => (
                "close",
                json!(frame.as_ref().map(|value| value.reason.to_string())),
            ),
            Message::Frame(_) => ("frame", Value::Null),
        };
        trace.write(json!({
            "event": "frame",
            "direction": direction,
            "kind": kind,
            "body": body,
        }));
    }

    fn lock_cert_cache(&self) -> MutexGuard<'_, HashMap<String, ManagedCertificate>> {
        match self.certs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("certificate cache lock was poisoned; recovering cached certificates");
                poisoned.into_inner()
            }
        }
    }
}

fn ensure_rustls_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

pub fn validate_tls_config(ca_cert_pem: &str, ca_key_pem: &str) -> Result<()> {
    ensure_rustls_crypto_provider();
    build_leaf_server_config(ANTHROPIC_HOST, ca_cert_pem, ca_key_pem)?;
    Ok(())
}

fn is_benign_client_error(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    is_idle_http_connection_end(err)
        || message.contains("client disconnected while")
        || is_benign_direct_tunnel_close(err)
        || (message.contains("client TLS handshake failed for ") && is_peer_connection_close(err))
}

fn is_idle_http_connection_end(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    message.contains("idle HTTP connection closed before request line")
        || message.contains("idle HTTP connection timed out before request line")
        || (message.contains("idle HTTP connection reset before request line")
            && is_peer_connection_close(err))
}

fn is_peer_connection_close(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
    })
}

fn is_benign_direct_tunnel_close(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    message.contains("direct tunnel copy failed for ")
        && (err.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
        }) || message.contains("Connection reset by peer")
            || message.contains("Broken pipe")
            || message.contains("UnexpectedEof")
            || message.contains("unexpected end of file")
            || message.contains("early eof"))
}

async fn handle_client(
    state: Arc<State>,
    stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<()> {
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| remote_addr.to_string());
    let mut reader = BufReader::new(stream);
    let request = match read_initial_proxy_request(&mut reader).await {
        Ok(request) => request,
        Err(err) => {
            let _ = write_plain_error(reader.get_mut(), StatusCode::BAD_REQUEST).await;
            return Err(err);
        }
    };

    if let InitialProxyRequest::Http(request) = request {
        let stream = reader.into_inner();
        return serve_http_proxy_request(state, stream, request, &peer).await;
    }
    let InitialProxyRequest::Connect(connect) = request else {
        unreachable!("HTTP requests returned above");
    };

    let mut stream = reader.into_inner();
    if connect.host == CERTIFICATE_CONTROL_HOST && connect.port == 443 {
        let spki = state.desktop_tls_spki_list()?;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 Connection Established\r\n{CERTIFICATE_SPKI_HEADER}: {spki}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .context("failed to return managed certificate identity")?;
        stream.flush().await?;
        return Ok(());
    }
    if is_managed_host(&connect.host) && connect.port == 443 {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .context("failed to acknowledge managed CONNECT")?;
        if state.verbose {
            eprintln!(
                "mitm accepted host={}:{} remote={}",
                connect.host, connect.port, peer
            );
        }
        serve_managed_tls(state, stream, &connect.host).await
    } else {
        serve_direct_tunnel(stream, &connect.host, connect.port, &peer, state.verbose).await
    }
}

async fn read_initial_proxy_request<R>(reader: &mut R) -> Result<InitialProxyRequest>
where
    R: AsyncBufRead + Unpin,
{
    let request = read_http_request(reader).await?;
    if request.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&request.target)?;
        return Ok(InitialProxyRequest::Connect(ParsedConnect {
            host: canonical_host(&host),
            port,
        }));
    }
    // Chromium/Electron sends absolute-form requests for ordinary HTTP URLs
    // when a --proxy-server HTTP proxy is configured.  Rejecting those before
    // their startup connectivity check makes Desktop report a generic offline
    // error even though its HTTPS CONNECT path is otherwise healthy.
    parse_http_proxy_target(&request)?;
    Ok(InitialProxyRequest::Http(request))
}

fn parse_http_proxy_target(request: &IncomingRequest) -> Result<Url> {
    if request.method.eq_ignore_ascii_case("CONNECT") {
        bail!("CONNECT is not an HTTP proxy request");
    }
    let target =
        Url::parse(&request.target).context("HTTP proxy target must be an absolute URL")?;
    if target.scheme() != "http" {
        bail!(
            "HTTP proxy request must use the http scheme, got {}",
            target.scheme()
        );
    }
    if target.host_str().is_none() {
        bail!("HTTP proxy target host is required");
    }
    if !target.username().is_empty() || target.password().is_some() {
        bail!("HTTP proxy target must not contain userinfo");
    }
    Ok(target)
}

async fn serve_http_proxy_request(
    state: Arc<State>,
    mut stream: TcpStream,
    request: IncomingRequest,
    peer: &str,
) -> Result<()> {
    let target = match parse_http_proxy_target(&request) {
        Ok(target) => target,
        Err(err) => {
            let _ = write_plain_error(&mut stream, StatusCode::BAD_REQUEST).await;
            return Err(err).context("rejected HTTP proxy request");
        }
    };
    let method = match Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            let _ = write_plain_error(&mut stream, StatusCode::METHOD_NOT_ALLOWED).await;
            return Err(err)
                .with_context(|| format!("unsupported HTTP proxy method {}", request.method));
        }
    };
    let host = canonical_host(target.host_str().unwrap_or_default());
    let port = target.port_or_known_default().unwrap_or(80);
    if state.verbose {
        eprintln!(
            "http proxy accepted method={} scheme=http host={}:{} remote={} bytes={}",
            request.method,
            host,
            port,
            peer,
            request.body.len(),
        );
    }
    let mut builder = state.client.request(method, target);
    for (name, value) in &request.headers {
        if should_forward_http_proxy_header(name) {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    let response = builder.body(request.body).send().await.with_context(|| {
        format!(
            "HTTP proxy request failed method={} host={}:{}",
            request.method, host, port
        )
    });
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            let _ = write_plain_error(&mut stream, StatusCode::BAD_GATEWAY).await;
            return Err(err);
        }
    };
    write_upstream_response(&mut stream, response, true)
        .await
        .with_context(|| {
            format!(
                "HTTP proxy response failed method={} host={}:{}",
                request.method, host, port
            )
        })?;
    Ok(())
}

async fn serve_direct_tunnel(
    mut client: TcpStream,
    host: &str,
    port: u16,
    peer: &str,
    verbose: bool,
) -> Result<()> {
    let mut upstream = match connect_direct_target(host, port).await {
        Ok(upstream) => upstream,
        Err(err) => {
            let _ = write_plain_error(&mut client, StatusCode::BAD_GATEWAY).await;
            return Err(err).with_context(|| {
                format!("failed to open direct tunnel to {host}:{port} for local client {peer}")
            });
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to acknowledge direct CONNECT")?;
    if verbose {
        eprintln!("tunnel accepted host={host}:{port} remote={peer}");
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .with_context(|| format!("direct tunnel copy failed for {host}:{port}"))?;
    Ok(())
}

async fn serve_managed_tls(state: Arc<State>, stream: TcpStream, host: &str) -> Result<()> {
    let tls_config = state.tls_config_for_host(host)?;
    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = acceptor
        .accept(stream)
        .await
        .with_context(|| format!("client TLS handshake failed for {host}"))?;
    // Do not log request contents here.  The Desktop compatibility boundary is
    // negotiated before HTTP begins, so the host and ALPN alone identify a
    // browser transport change without exposing credentials or prompts.
    let alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .unwrap_or_else(|| "none".to_string());
    let mut reader = BufReader::new(tls_stream);
    let mut handled_requests = 0usize;

    loop {
        let mut request = match read_http_request(&mut reader).await {
            Ok(request) => request,
            Err(err) => {
                if is_idle_http_connection_end(&err) {
                    return Ok(());
                }
                let _ = write_static_response(
                    reader.get_mut(),
                    StatusCode::BAD_REQUEST,
                    "text/plain",
                    b"bad request",
                    true,
                )
                .await;
                return Err(err).with_context(|| {
                    format!(
                        "managed TLS stream ended host={host} alpn={alpn} requests_handled={handled_requests}"
                    )
                });
            }
        };
        handled_requests += 1;
        let close_after = request_wants_close(&request);

        if host == ANTHROPIC_HOST {
            if let Some(resp) = local_sidecar_response(&request) {
                if state.verbose {
                    eprintln!(
                        "local sidecar response method={} target={} status={} reason={} close_after={}",
                        request.method, request.target, resp.status, resp.reason, close_after
                    );
                }
                write_static_response(
                    reader.get_mut(),
                    resp.status,
                    resp.content_type,
                    resp.body,
                    close_after,
                )
                .await?;
            } else {
                let path = request_path(&request.target)?;
                if !is_forwarded_anthropic_path(&path) {
                    if state.verbose {
                        eprintln!(
                            "local sidecar fallback method={} target={} status=204 reason=unknown_anthropic_sidecar close_after={}",
                            request.method, request.target, close_after
                        );
                    }
                    write_static_response(
                        reader.get_mut(),
                        StatusCode::NO_CONTENT,
                        "text/plain",
                        b"",
                        close_after,
                    )
                    .await?;
                } else {
                    forward_to_saiai(&state, reader.get_mut(), request, close_after, false).await?;
                }
            }
        } else if host == OPENAI_HOST
            || host == CHATGPT_HOST
            || host == CHAT_OPENAI_HOST
            || host == CHATGPT_AUX_HOST
        {
            state.trace_openai_request(
                if is_websocket_upgrade(&request) {
                    "handshake"
                } else {
                    "request"
                },
                "to_gateway",
                &request,
            );
            let is_chatgpt = matches!(host, CHATGPT_HOST | CHAT_OPENAI_HOST | CHATGPT_AUX_HOST);
            if is_chatgpt {
                match normalize_chatgpt_gateway_target(&request.target) {
                    Ok(target) => request.target = target,
                    Err(_) => {
                        let ordinary_chat_forwarded = state.chatgpt_chat_passthrough
                            && normalize_chatgpt_chat_target(&request.target)
                                .map(|target| {
                                    request.target = target;
                                })
                                .is_ok();
                        if !ordinary_chat_forwarded {
                            if !state.chatgpt_chat_passthrough
                                && let Some(resp) = chatgpt_chat_disabled_response(&request)
                            {
                                write_static_response(
                                    reader.get_mut(),
                                    resp.status,
                                    resp.content_type,
                                    resp.body,
                                    close_after,
                                )
                                .await?;
                                if close_after {
                                    return Ok(());
                                }
                                continue;
                            }
                            if let Some((status, body, reason, headers)) =
                                chatgpt_account_sidecar_response(&request)
                            {
                                if state.verbose {
                                    eprintln!(
                                        "chatgpt account sidecar response method={} target={} status={} reason={} close_after={}",
                                        request.method, request.target, status, reason, close_after
                                    );
                                }
                                write_static_response_with_headers(
                                    reader.get_mut(),
                                    status,
                                    "application/json",
                                    &body,
                                    close_after,
                                    headers,
                                )
                                .await?;
                                if close_after {
                                    return Ok(());
                                }
                                continue;
                            }
                            if let Some(resp) = chatgpt_sidecar_response(&request) {
                                if state.verbose {
                                    eprintln!(
                                        "chatgpt sidecar response method={} target={} status={} reason={} close_after={}",
                                        request.method,
                                        request.target,
                                        resp.status,
                                        resp.reason,
                                        close_after
                                    );
                                }
                                write_static_response(
                                    reader.get_mut(),
                                    resp.status,
                                    resp.content_type,
                                    resp.body,
                                    close_after,
                                )
                                .await?;
                                if close_after {
                                    return Ok(());
                                }
                                continue;
                            }
                            return normalize_chatgpt_gateway_target(&request.target).map(|_| ());
                        }
                    }
                }
            }
            if is_websocket_upgrade(&request) {
                let client_stream = reader.into_inner();
                return serve_openai_websocket(state, client_stream, request).await;
            }
            let path = request_path(&request.target)?;
            if is_forwarded_openai_path(&path) {
                // Codex's OAuth request shape is preserved; only the Gateway
                // credential is substituted at this upstream boundary.
                forward_to_saiai(&state, reader.get_mut(), request, close_after, true).await?;
            } else {
                if state.verbose {
                    eprintln!(
                        "openai sidecar fallback method={} target={} status=204 reason=unknown_openai_path close_after={}",
                        request.method, request.target, close_after
                    );
                }
                write_static_response(
                    reader.get_mut(),
                    StatusCode::NO_CONTENT,
                    "text/plain",
                    b"",
                    close_after,
                )
                .await?;
            }
        }

        if close_after {
            return Ok(());
        }
    }
}

fn build_openai_websocket_request(
    upstream_url: &Url,
    incoming_headers: &[(String, String)],
    gateway_key: &str,
) -> Result<tungstenite::http::Request<()>> {
    let mut upstream_request = upstream_url
        .as_str()
        .into_client_request()
        .context("failed to build Gateway WebSocket request")?;

    // Preserve Codex's WebSocket handshake and client metadata while changing
    // only the destination and the Gateway credential. The generated request
    // key is replaced with Codex's key so the client-facing accept value is
    // derived from the exact incoming handshake.
    let upstream_headers = upstream_request.headers_mut();
    let nominated = connection_nominated_headers(incoming_headers);
    let mut copied_names = std::collections::HashSet::new();
    for (name, value) in incoming_headers {
        if nominated.contains(&name.to_ascii_lowercase()) && !is_websocket_handshake_header(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("sec-websocket-extensions") {
            // The Rust upstream relay does not enable a compression codec.
            // Do not negotiate permessage-deflate on that leg; otherwise the
            // upstream can send RSV1 frames that the relay cannot decode.
            continue;
        }
        if is_websocket_handshake_header(name)
            || (should_forward_request_header_to_gateway(name, true))
        {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid WebSocket header name {name:?}"))?;
            let header_value = HeaderValue::from_str(value)
                .with_context(|| format!("invalid WebSocket header value for {name:?}"))?;
            // Replace a generated handshake default once, then preserve all
            // client values (including duplicate future control headers).
            if copied_names.insert(header_name.clone()) {
                upstream_headers.remove(&header_name);
            }
            upstream_headers.append(header_name, header_value);
        }
    }
    upstream_headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", gateway_key))
            .context("failed to build Gateway WebSocket authorization")?,
    );
    upstream_headers.insert(
        HeaderName::from_static("host"),
        HeaderValue::from_str(upstream_url.authority())
            .context("invalid Gateway WebSocket host")?,
    );

    Ok(upstream_request)
}

async fn serve_openai_websocket(
    state: Arc<State>,
    mut client_stream: TlsStream<TcpStream>,
    request: IncomingRequest,
) -> Result<()> {
    let sec_key = header_value(&request.headers, "sec-websocket-key")
        .context("OpenAI WebSocket request did not include Sec-WebSocket-Key")?;
    let route = state.route_for_host(CHATGPT_HOST);
    let upstream_url = state.websocket_upstream_url(&request.target, route)?;
    let upstream_request =
        build_openai_websocket_request(&upstream_url, &request.headers, &route.api_key)?;

    let (upstream_ws, upstream_response) = match connect_async(upstream_request).await {
        Ok(result) => result,
        Err(error) => {
            let _ = write_plain_error(&mut client_stream, StatusCode::BAD_GATEWAY).await;
            return Err(error).context("failed to establish Gateway WebSocket");
        }
    };
    if upstream_response.status().as_u16() != 101 {
        let _ = write_plain_error(&mut client_stream, StatusCode::BAD_GATEWAY).await;
        bail!(
            "Gateway WebSocket handshake returned {}",
            upstream_response.status()
        );
    }

    let accept_key = tungstenite::handshake::derive_accept_key(sec_key.as_bytes());
    // The client-facing side uses a raw WebSocket stream without an extension
    // codec. Do not accept permessage-deflate back to Codex; otherwise Codex
    // may send frames with RSV1 set and the raw client-side relay rejects them
    // as compressed.
    client_stream
        .write_all(&build_openai_websocket_response(
            &accept_key,
            upstream_response.headers(),
        ))
        .await
        .context("failed to acknowledge Codex WebSocket")?;

    let client_ws = WebSocketStream::from_raw_socket(client_stream, Role::Server, None).await;
    let (mut client_sink, mut client_source) = client_ws.split();
    let (mut upstream_sink, mut upstream_source) = upstream_ws.split();

    loop {
        tokio::select! {
            client_message = client_source.next() => {
                match client_message {
                    Some(Ok(message)) => {
                        let is_close = message.is_close();
                        state.trace_openai_frame("to_gateway", &message);
                        upstream_sink.send(message).await.context("failed to forward Codex WebSocket frame to Gateway")?;
                        if is_close { return Ok(()); }
                    }
                    Some(Err(error)) => return Err(error).context("Codex WebSocket read failed"),
                    None => return Ok(()),
                }
            }
            upstream_message = upstream_source.next() => {
                match upstream_message {
                    Some(Ok(message)) => {
                        let is_close = message.is_close();
                        state.trace_openai_frame("from_gateway", &message);
                        client_sink.send(message).await.context("failed to forward Gateway WebSocket frame to Codex")?;
                        if is_close { return Ok(()); }
                    }
                    Some(Err(error)) => return Err(error).context("Gateway WebSocket read failed"),
                    None => return Ok(()),
                }
            }
        }
    }
}

fn build_openai_websocket_response(
    accept_key: &str,
    upstream_headers: &tungstenite::http::HeaderMap,
) -> Vec<u8> {
    let nominated: std::collections::HashSet<String> = upstream_headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n"
    )
    .into_bytes();
    for (name, value) in upstream_headers {
        let lower = name.as_str();
        if !should_forward_response_header(lower)
            || nominated.contains(lower)
            || matches!(
                lower,
                "authorization" | "cookie" | "set-cookie" | "chatgpt-account-id"
            )
            || (lower.starts_with("sec-websocket-") && lower != "sec-websocket-protocol")
        {
            continue;
        }
        response.extend_from_slice(name.as_str().as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"\r\n");
    response
}

async fn read_http_request<R>(reader: &mut R) -> Result<IncomingRequest>
where
    R: AsyncBufRead + Unpin,
{
    let request_line = read_http_request_line(reader, HEADER_READ_TIMEOUT).await?;
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || !parts[2].starts_with("HTTP/") {
        bail!("invalid HTTP request line");
    }

    let mut headers = Vec::new();
    let mut header_bytes = request_line.len();
    loop {
        let line = read_line_limited(reader).await?;
        header_bytes += line.len();
        if header_bytes > MAX_HEADER_BYTES {
            bail!("HTTP headers are too large");
        }
        if is_blank_line(&line) {
            break;
        }
        let trimmed = trim_crlf(&line);
        let Some((name, value)) = trimmed.split_once(':') else {
            bail!("invalid HTTP header line");
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    let body = read_request_body(reader, &headers).await?;
    Ok(IncomingRequest {
        method: parts[0].to_string(),
        target: parts[1].to_string(),
        http_version: parts[2].to_string(),
        headers,
        body,
    })
}

async fn read_http_request_line<R>(reader: &mut R, wait: Duration) -> Result<String>
where
    R: AsyncBufRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + wait;
    // Chromium opens TLS preconnections before it has an HTTP request. Only
    // zero-byte idle connections are quiet; a partial request remains an error.
    let first = timeout_at(deadline, reader.fill_buf())
        .await
        .context("idle HTTP connection timed out before request line")?
        .map_err(|error| {
            let error = anyhow::Error::from(error);
            if is_peer_connection_close(&error) {
                // No HTTP bytes have been consumed. Chromium may cancel a
                // preconnection or close a reused socket during a cold launch.
                error.context("idle HTTP connection reset before request line")
            } else {
                error
            }
        })
        .context("failed to read HTTP request start")?;
    if first.is_empty() {
        bail!("idle HTTP connection closed before request line");
    }
    timeout_at(deadline, read_line_limited(reader))
        .await
        .context("timed out reading HTTP request line")?
}

async fn read_request_body<R>(reader: &mut R, headers: &[(String, String)]) -> Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    if header_contains(headers, "transfer-encoding", "chunked") {
        return read_chunked_body(reader).await;
    }
    let Some(content_length) = header_value(headers, "content-length") else {
        return Ok(Vec::new());
    };
    let length = content_length
        .parse::<usize>()
        .with_context(|| format!("invalid content-length {content_length:?}"))?;
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .await
        .context("failed to read request body")?;
    Ok(body)
}

async fn read_chunked_body<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let size_line = read_line_limited(reader).await?;
        let size_hex = trim_crlf(&size_line).split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size {size_hex:?}"))?;
        if size == 0 {
            loop {
                let trailer = read_line_limited(reader).await?;
                if is_blank_line(&trailer) {
                    break;
                }
            }
            break;
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .await
            .context("failed to read chunk body")?;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .await
            .context("failed to read chunk terminator")?;
        if crlf != *b"\r\n" {
            bail!("invalid chunk terminator");
        }
    }
    Ok(body)
}

async fn forward_to_saiai<W>(
    state: &State,
    writer: &mut W,
    request: IncomingRequest,
    close_after: bool,
    replace_authorization: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let preferences_path = super::codex_config_dir()
        .ok()
        .map(|home| home.join(".codex-global-state.json"));
    forward_to_saiai_with_preferences_path(
        state,
        writer,
        request,
        close_after,
        replace_authorization,
        preferences_path.as_deref(),
    )
    .await
}

async fn forward_to_saiai_with_preferences_path<W>(
    state: &State,
    writer: &mut W,
    request: IncomingRequest,
    close_after: bool,
    replace_authorization: bool,
    preferences_path: Option<&std::path::Path>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let route = if replace_authorization {
        state.route_for_host(OPENAI_HOST)
    } else {
        state.route_for_host(ANTHROPIC_HOST)
    };
    let upstream_url = state.upstream_url(&request.target, route)?;
    let method = Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("unsupported HTTP method {}", request.method))?;
    let mut builder = state.client.request(method, &upstream_url);

    let mut has_authorization = false;
    let nominated = connection_nominated_headers(&request.headers);
    for (name, value) in &request.headers {
        if nominated.contains(&name.to_ascii_lowercase()) {
            continue;
        }
        if name.eq_ignore_ascii_case("authorization") {
            has_authorization = true;
        }
        if should_forward_request_header_to_gateway(name, replace_authorization) {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    if replace_authorization || !has_authorization {
        builder = builder.bearer_auth(&*route.api_key);
    }

    // Native Mac requires only the provider-issued device proof. The Gateway
    // verifies its scoped digest and original account before forwarding it.
    // Session/auth cookies still never cross this credential substitution.
    if replace_authorization
        && is_chatgpt_device_cookie_target(&request.target)
        && !nominated.contains("cookie")
        && let Some(cookie) = chatgpt_device_cookie(&request.headers)?
    {
        builder = builder.header("Cookie", cookie);
    }

    let request_method = request.method.clone();
    let upload = is_chatgpt_upload_target(&request.target);
    let request_target = if upload {
        request
            .target
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string()
    } else {
        request.target.clone()
    };
    let log_upstream_url = if upload {
        upstream_url.split('?').next().unwrap_or_default()
    } else {
        &upstream_url
    };
    let request_bytes = request.body.len();
    let preserve_chat_preference = state.chatgpt_chat_passthrough
        && replace_authorization
        && is_fresh_chat_init(&request)
        && preferences_path.and_then(saved_chat_model_at).is_some();
    if state.verbose {
        eprintln!(
            "forward request method={} target={} upstream={} bytes={} close_after={}",
            request_method, request_target, log_upstream_url, request_bytes, close_after
        );
    }
    let started = Instant::now();
    let response = builder.body(request.body).send().await.map_err(|error| {
        if upload { error.without_url() } else { error }
    }).with_context(|| {
        format!(
            "request phase failed forwarding {request_method} {request_target} to {log_upstream_url}"
        )
    })?;
    let outcome = if preserve_chat_preference {
        write_chat_init_response(writer, response, close_after).await
    } else {
        write_upstream_response(writer, response, close_after).await
    }
    .with_context(|| {
        format!("response phase failed forwarding {request_method} {request_target}")
    })?;
    if state.verbose {
        eprintln!(
            "forward response method={} target={} status={} elapsed_ms={} response_bytes={} chunks={}",
            request_method,
            request_target,
            outcome.status,
            started.elapsed().as_millis(),
            outcome.response_bytes,
            outcome.chunks
        );
    }
    Ok(())
}

fn is_fresh_chat_init(request: &IncomingRequest) -> bool {
    if !request.method.eq_ignore_ascii_case("POST")
        || request.target.split('?').next() != Some("/chatgpt/backend-api/conversation/init")
    {
        return false;
    }
    let Ok(Value::Object(body)) = serde_json::from_slice(&request.body) else {
        return false;
    };
    // Existing chats, Work/custom GPTs, explicit choices and model envelopes
    // must retain the account's complete initialization response.
    [
        "conversation_id",
        "conversation_origin",
        "gizmo_id",
        "requested_default_model",
        "model",
        "messages",
        "input",
        "prompt",
        "tools",
        "system_hints",
    ]
    .iter()
    .all(|key| body.get(*key).is_none_or(Value::is_null))
}

fn saved_chat_model_at(path: &std::path::Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_DESKTOP_STATE_BYTES + 1),
        &mut data,
    )
    .ok()?;
    if data.len() as u64 > MAX_DESKTOP_STATE_BYTES {
        return None;
    }
    let state: Value = serde_json::from_slice(&data).ok()?;
    let slug = state
        .get("electron-persisted-atom-state")?
        .get("chatgpt-last-selected-model-v1")?
        .get("slug")?
        .as_str()?;
    (slug != "auto"
        && !slug.is_empty()
        && slug.len() <= 128
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
    .then(|| slug.to_owned())
}

fn without_account_chat_defaults(body: &[u8]) -> Option<Vec<u8>> {
    let Value::Object(mut value) = serde_json::from_slice(body).ok()? else {
        return None;
    };
    // A quota-driven model replacement belongs to the selected account.
    if value
        .get("model_limits")
        .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
    {
        return None;
    }
    let mut changed = false;
    for key in ["default_model_slug", "intended_default_model_slug"] {
        if value
            .get(key)
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            return None;
        }
    }
    for key in ["default_model_slug", "intended_default_model_slug"] {
        changed |= value.remove(key).is_some();
    }
    changed.then(|| serde_json::to_vec(&value).ok()).flatten()
}

async fn write_chat_init_response<W>(
    writer: &mut W,
    response: reqwest::Response,
    close_after: bool,
) -> Result<UpstreamResponseOutcome>
where
    W: AsyncWrite + Unpin,
{
    if response.status() != StatusCode::OK
        || !response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
            })
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v != "identity")
    {
        return write_upstream_response(writer, response, close_after).await;
    }
    let status = response.status();
    let mut headers = response.headers().clone();
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading native Chat initialization metadata")?;
        if body.len().saturating_add(chunk.len()) > MAX_CHAT_INIT_RESPONSE_BYTES {
            let prefix = futures_util::stream::iter([
                Ok::<_, reqwest::Error>(body),
                Ok::<_, reqwest::Error>(chunk.to_vec()),
            ]);
            let rest = stream.map(|r| r.map(|b| b.to_vec()));
            let mut original = tungstenite::http::Response::builder()
                .status(status)
                .body(reqwest::Body::wrap_stream(prefix.chain(rest)))?;
            *original.headers_mut() = headers;
            return write_upstream_response(writer, original.into(), close_after).await;
        }
        body.extend_from_slice(&chunk);
    }
    if let Some(adjusted) = without_account_chat_defaults(&body) {
        body = adjusted;
        for key in ["content-length", "etag", "content-md5", "digest"] {
            headers.remove(key);
        }
        headers.insert("x-saiai-chat-preference-restored", "1".parse()?);
    }
    let mut result = tungstenite::http::Response::builder()
        .status(status)
        .body(body)?;
    *result.headers_mut() = headers;
    write_upstream_response(writer, result.into(), close_after).await
}

async fn write_upstream_response<W>(
    writer: &mut W,
    response: reqwest::Response,
    close_after: bool,
) -> Result<UpstreamResponseOutcome>
where
    W: AsyncWrite + Unpin,
{
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("");
    let mut response_bytes = 0u64;
    let mut chunks = 0u64;
    write_client_bytes(
        writer,
        format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes(),
        "writing response headers",
        response_bytes,
        chunks,
    )
    .await?;

    for (name, value) in response.headers() {
        if should_forward_response_header(name.as_str()) {
            write_client_bytes(
                writer,
                name.as_str().as_bytes(),
                "writing response headers",
                response_bytes,
                chunks,
            )
            .await?;
            write_client_bytes(
                writer,
                b": ",
                "writing response headers",
                response_bytes,
                chunks,
            )
            .await?;
            write_client_bytes(
                writer,
                value.as_bytes(),
                "writing response headers",
                response_bytes,
                chunks,
            )
            .await?;
            write_client_bytes(
                writer,
                b"\r\n",
                "writing response headers",
                response_bytes,
                chunks,
            )
            .await?;
        }
    }

    let has_body = status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
        && status.as_u16() >= 200;
    if close_after {
        write_client_bytes(
            writer,
            b"Connection: close\r\n",
            "writing response headers",
            response_bytes,
            chunks,
        )
        .await?;
    } else {
        write_client_bytes(
            writer,
            b"Connection: keep-alive\r\n",
            "writing response headers",
            response_bytes,
            chunks,
        )
        .await?;
    }
    if has_body {
        write_client_bytes(
            writer,
            b"Transfer-Encoding: chunked\r\n",
            "writing response headers",
            response_bytes,
            chunks,
        )
        .await?;
    } else {
        write_client_bytes(
            writer,
            b"Content-Length: 0\r\n",
            "writing response headers",
            response_bytes,
            chunks,
        )
        .await?;
    }
    write_client_bytes(
        writer,
        b"\r\n",
        "writing response headers",
        response_bytes,
        chunks,
    )
    .await?;

    if has_body {
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| {
                format!(
                    "upstream response stream interrupted after {response_bytes} response bytes in {chunks} chunk(s)"
                )
            })?;
            if chunk.is_empty() {
                continue;
            }
            write_client_bytes(
                writer,
                format!("{:X}\r\n", chunk.len()).as_bytes(),
                "streaming upstream response",
                response_bytes,
                chunks,
            )
            .await?;
            write_client_bytes(
                writer,
                &chunk,
                "streaming upstream response",
                response_bytes,
                chunks,
            )
            .await?;
            write_client_bytes(
                writer,
                b"\r\n",
                "streaming upstream response",
                response_bytes,
                chunks,
            )
            .await?;
            response_bytes += chunk.len() as u64;
            chunks += 1;
            writer.flush().await.with_context(|| {
                format!(
                    "client disconnected while flushing upstream response after {response_bytes} response bytes in {chunks} chunk(s)"
                )
            })?;
        }
        write_client_bytes(
            writer,
            b"0\r\n\r\n",
            "finishing upstream response",
            response_bytes,
            chunks,
        )
        .await?;
    }
    writer.flush().await.with_context(|| {
        format!(
            "client disconnected while finishing upstream response after {response_bytes} response bytes in {chunks} chunk(s)"
        )
    })?;
    Ok(UpstreamResponseOutcome {
        status,
        response_bytes,
        chunks,
    })
}

async fn write_client_bytes<W>(
    writer: &mut W,
    bytes: &[u8],
    phase: &str,
    response_bytes: u64,
    chunks: u64,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(bytes).await.with_context(|| {
        format!(
            "client disconnected while {phase} after {response_bytes} response bytes in {chunks} chunk(s)"
        )
    })
}

async fn write_static_response<W>(
    writer: &mut W,
    status: StatusCode,
    content_type: &'static str,
    body: &[u8],
    close_after: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_static_response_with_headers(writer, status, content_type, body, close_after, &[]).await
}

async fn write_static_response_with_headers<W>(
    writer: &mut W,
    status: StatusCode,
    content_type: &'static str,
    body: &[u8],
    close_after: bool,
    headers: &[(&str, &str)],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let reason = status.canonical_reason().unwrap_or("");
    writer
        .write_all(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes())
        .await?;
    if close_after {
        writer.write_all(b"Connection: close\r\n").await?;
    } else {
        writer.write_all(b"Connection: keep-alive\r\n").await?;
    }
    writer
        .write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes())
        .await?;
    if !body.is_empty() {
        writer
            .write_all(format!("Content-Type: {content_type}\r\n").as_bytes())
            .await?;
    }
    for (name, value) in headers {
        writer
            .write_all(format!("{name}: {value}\r\n").as_bytes())
            .await?;
    }
    writer.write_all(b"\r\n").await?;
    if !body.is_empty() {
        writer.write_all(body).await?;
    }
    writer.flush().await?;
    Ok(())
}

async fn write_plain_error<W>(writer: &mut W, status: StatusCode) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let reason = status.canonical_reason().unwrap_or(status.as_str());
    write_static_response(writer, status, "text/plain", reason.as_bytes(), true).await
}

fn local_sidecar_response(request: &IncomingRequest) -> Option<StaticResponse> {
    let Ok(path) = request_path(&request.target) else {
        return Some(StaticResponse {
            status: StatusCode::BAD_REQUEST,
            content_type: "text/plain",
            body: b"bad request",
            reason: "invalid_target",
        });
    };

    match path.as_str() {
        "/api/claude_code/policy_limits" => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{"restrictions":{}}"#,
            reason: "claude_code_policy_limits",
        }),
        "/api/claude_code/settings" => Some(StaticResponse {
            status: StatusCode::NO_CONTENT,
            content_type: "text/plain",
            body: b"",
            reason: "claude_code_settings",
        }),
        _ if path.starts_with("/v1/mcp_servers") => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{"data":[],"has_more":false}"#,
            reason: "mcp_servers_empty",
        }),
        _ if path.starts_with("/api/event_logging/")
            || path.starts_with("/api/eval/")
            || path.starts_with("/api/claude_cli/bootstrap")
            || path.starts_with("/api/claude_code_penguin_mode")
            || path.starts_with("/api/claude_code_grove") =>
        {
            Some(StaticResponse {
                status: StatusCode::NO_CONTENT,
                content_type: "text/plain",
                body: b"",
                reason: "nonessential_sidecar_noop",
            })
        }
        _ if path.starts_with("/api/oauth/") => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{}"#,
            reason: "oauth_sidecar_empty",
        }),
        _ => None,
    }
}

fn is_forwarded_anthropic_path(path: &str) -> bool {
    path == "/v1/messages"
        || path == "/v1/messages/count_tokens"
        || path == "/v1/models"
        || path.starts_with("/v1/models/")
}

fn is_forwarded_openai_path(path: &str) -> bool {
    path == "/v1/responses"
        || path.starts_with("/v1/responses/")
        || path == "/v1/models"
        || path.starts_with("/v1/models/")
        || path == "/v1/codex/images/generations"
        || path == "/v1/codex/images/edits"
        || is_forwarded_chatgpt_path(path)
}

fn is_forwarded_chatgpt_path(path: &str) -> bool {
    path == "/chatgpt/backend-api/models"
        || path == "/chatgpt/backend-api/devicecheck"
        || path == "/chatgpt/backend-api/ios/attestation_challenge"
        || path == "/chatgpt/backend-api/f/conversation"
        || path.starts_with("/chatgpt/backend-api/f/conversation/")
        || path == "/chatgpt/backend-api/conversation/init"
        || path == "/chatgpt/backend-api/sentinel/chat-requirements/prepare"
        || path == "/chatgpt/backend-api/files"
        || path == "/chatgpt/backend-api/files/process_upload_stream"
        || path == "/chatgpt/backend-api/estuary/upload_content_bytes"
        || path == "/chatgpt/api/estuary/upload_content_bytes"
        || path.starts_with("/chatgpt/backend-api/files/download/")
        || path == "/chatgpt/backend-api/estuary/content"
        || path == "/chatgpt/backend-api/celsius/ws/user"
        || path == "/chatgpt/backend-api/saiai/chat-updates"
        || is_chatgpt_owned_conversation_path(path.strip_prefix("/chatgpt").unwrap_or(path))
}

fn is_chatgpt_upload_target(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or_default();
    let path = path.strip_prefix("/chatgpt").unwrap_or(path);
    matches!(
        path,
        "/backend-api/files"
            | "/backend-api/files/process_upload_stream"
            | "/backend-api/estuary/upload_content_bytes"
            | "/api/estuary/upload_content_bytes"
    )
}

fn is_chatgpt_device_cookie_target(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or_default();
    let path = path.strip_prefix("/chatgpt").unwrap_or(path);
    matches!(
        path,
        "/backend-api/devicecheck"
            | "/backend-api/models"
            | "/backend-api/ios/attestation_challenge"
            | "/backend-api/f/conversation"
            | "/backend-api/f/conversation/prepare"
            | "/backend-api/f/conversation/resume"
            | "/backend-api/conversation/init"
            | "/backend-api/sentinel/chat-requirements/prepare"
    )
}

fn chatgpt_device_cookie(headers: &[(String, String)]) -> Result<Option<String>> {
    let mut proof = None;
    let mut seen = false;
    for (_, raw) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
    {
        for part in raw.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name != "_devicecheck" {
                continue;
            }
            if seen
                || value.is_empty()
                || value.len() > 16 * 1024
                || value
                    .bytes()
                    .any(|ch| !(0x21..=0x7e).contains(&ch) || b"\";,\\".contains(&ch))
            {
                bail!("invalid native Chat device proof");
            }
            seen = true;
            // Never replay the historical local bootstrap placeholder as a
            // provider proof. A real registration replaces it on startup.
            if value != "saiai-local-proxy" {
                proof = Some(format!("_devicecheck={value}"));
            }
        }
    }
    Ok(proof)
}

fn is_chatgpt_owned_conversation_path(path: &str) -> bool {
    let Some(tail) = path
        .strip_prefix("/backend-api/conversation/")
        .or_else(|| path.strip_prefix("/backend-api/conversations/"))
    else {
        return false;
    };
    let id = tail.strip_suffix("/messages").unwrap_or(tail);
    !id.is_empty()
        && id.len() <= 512
        && id != "init"
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn normalize_chatgpt_gateway_target(target: &str) -> Result<String> {
    let path = request_path(target)?;
    let normalized = if path == "/backend-api/codex/responses" {
        "/v1/responses"
    } else if path.starts_with("/backend-api/codex/responses/") {
        return Ok(target.replacen("/backend-api/codex/responses", "/v1/responses", 1));
    } else if path == "/backend-api/codex/models" {
        "/v1/models"
    } else if path.starts_with("/backend-api/codex/models/") {
        return Ok(target.replacen("/backend-api/codex/models", "/v1/models", 1));
    } else if path == "/backend-api/codex/images/generations" {
        "/v1/codex/images/generations"
    } else if path == "/backend-api/codex/images/edits" {
        "/v1/codex/images/edits"
    } else {
        bail!("unsupported ChatGPT Codex path: {path}");
    };
    let query = target.split_once('?').map(|(_, value)| value);
    Ok(match query {
        Some(value) if !value.is_empty() => format!("{normalized}?{value}"),
        _ => normalized.to_string(),
    })
}

fn normalize_chatgpt_chat_target(target: &str) -> Result<String> {
    let path = request_path(target)?;
    if path == "/api/estuary/upload_content_bytes" {
        return Ok(format!("/chatgpt{target}"));
    }
    if path == "/celsius/ws/user" {
        return Ok(target.replacen(
            "/celsius/ws/user",
            "/chatgpt/backend-api/celsius/ws/user",
            1,
        ));
    }
    let allowed = path == "/backend-api/models"
        || path == "/backend-api/devicecheck"
        || path == "/backend-api/ios/attestation_challenge"
        || path == "/backend-api/f/conversation"
        || path.starts_with("/backend-api/f/conversation/")
        || path == "/backend-api/conversation/init"
        || path == "/backend-api/sentinel/chat-requirements/prepare"
        || path == "/backend-api/files"
        || path == "/backend-api/files/process_upload_stream"
        || path == "/backend-api/estuary/upload_content_bytes"
        || path.starts_with("/backend-api/files/download/")
        || path == "/backend-api/estuary/content"
        || path == "/backend-api/celsius/ws/user"
        || path == "/backend-api/saiai/chat-updates"
        || is_chatgpt_owned_conversation_path(&path);
    if !allowed {
        bail!("unsupported ChatGPT ordinary Chat path: {path}");
    }
    Ok(target.replacen("/backend-api/", "/chatgpt/backend-api/", 1))
}

fn chatgpt_sidecar_response(request: &IncomingRequest) -> Option<StaticResponse> {
    let path = request_path(&request.target).ok()?;
    if matches!(
        path.as_str(),
        "/backend-api/plugins/featured"
            | "/backend-api/ps/plugins/home"
            | "/ps/plugins/home"
            | "/backend-api/ps/plugins/suggested/codex"
            | "/backend-api/ps/plugins/list"
    ) && !request.method.eq_ignore_ascii_case("GET")
    {
        return Some(desktop_control_unsupported_response());
    }
    match path.as_str() {
        // This bootstraps native conversation notifications and asynchronous
        // task delivery. An empty 200 makes Desktop construct a WebSocket with
        // a missing URL. It is not telemetry, and a shared account's provider
        // subscription must not be exposed without scoped delivery support.
        "/backend-api/celsius/ws/user" | "/celsius/ws/user" => Some(StaticResponse {
            status: StatusCode::NOT_IMPLEMENTED,
            content_type: "application/json",
            body: br#"{"error":{"type":"native_chat_updates_unsupported","message":"Background Chat updates are not supported yet."}}"#,
            reason: "native_chat_updates_unsupported",
        }),
        "/v1/initialize" if !request.method.eq_ignore_ascii_case("POST") => Some(StaticResponse {
            status: StatusCode::METHOD_NOT_ALLOWED,
            content_type: "application/json",
            body: br#"{"error":"method_not_allowed"}"#,
            reason: "desktop_statsig_method_not_allowed",
        }),
        "/v1/initialize" if request.body.len() > DESKTOP_STATSIG_MAX_REQUEST_BYTES => {
            Some(StaticResponse {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                content_type: "application/json",
                body: br#"{"error":"payload_too_large"}"#,
                reason: "desktop_statsig_payload_too_large",
            })
        }
        "/v1/initialize" => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: DESKTOP_STATSIG_I18N_PAYLOAD.as_bytes(),
            reason: "desktop_statsig_i18n_bootstrap",
        }),
        "/ces/statsc/flush" if request.method.eq_ignore_ascii_case("POST") => {
            Some(StaticResponse {
                status: StatusCode::OK,
                content_type: "application/json",
                body: br#"{"success":true}"#,
                reason: "desktop_statsc_noop",
            })
        }
        "/otlp/v1/metrics" if request.method.eq_ignore_ascii_case("POST") => {
            let json = header_value(&request.headers, "content-type")
                .is_some_and(|value| value.starts_with("application/json"));
            Some(StaticResponse {
                status: StatusCode::OK,
                content_type: if json { "application/json" } else { "application/x-protobuf" },
                body: if json { b"{}" } else { b"" },
                reason: "desktop_metrics_noop",
            })
        }
        "/ces/v1/rgstr" | "/ces/v1/telemetry/intake" => Some(StaticResponse {
            status: StatusCode::NO_CONTENT,
            content_type: "text/plain",
            body: b"",
            reason: "desktop_telemetry_noop",
        }),
        "/backend-api/plugins/featured" => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{"plugins":[],"pagination":{"total":0,"limit":200,"offset":0}}"#,
            reason: "desktop_plugins_empty",
        }),
        "/backend-api/ps/plugins/home" | "/ps/plugins/home" => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{"sections":[]}"#,
            reason: "desktop_plugin_home_empty",
        }),
        "/backend-api/ps/plugins/suggested/codex" => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{"plugins":[],"enabled":false}"#,
            reason: "desktop_recommended_plugins_disabled",
        }),
        "/backend-api/ps/plugins/list" => Some(StaticResponse {
            status: StatusCode::OK,
            content_type: "application/json",
            body: br#"{"plugins":[],"pagination":{"total":0,"limit":200,"offset":0}}"#,
            reason: "desktop_plugins_empty",
        }),
        // Desktop 26.924 renders notification settings with `data.settings.map(...)`.
        // A generic 200/{} crashes the renderer, while a 501 keeps the page
        // loading and retrying. The local account has no hosted categories.
        "/backend-api/notifications/settings" | "/notifications/settings"
            if request.method.eq_ignore_ascii_case("GET") =>
        {
            Some(StaticResponse {
                status: StatusCode::OK,
                content_type: "application/json",
                body: br#"{"settings":[]}"#,
                reason: "desktop_notification_settings_empty",
            })
        }
        "/backend-api/notifications/settings" | "/notifications/settings" => Some(StaticResponse {
                status: StatusCode::NOT_IMPLEMENTED,
                content_type: "application/json",
                body: br#"{"error":{"type":"desktop_notification_settings_unsupported","message":"Notification settings are unavailable through SAIAI Desktop."}}"#,
                reason: "desktop_notification_settings_unsupported",
            }),
        _ if path.starts_with("/backend-api/wham/")
            || path.starts_with("/backend-api/")
            || path.starts_with("/wham/")
            || path.starts_with("/accounts/")
            || path == "/me"
            || path.starts_with("/settings/")
            || path.starts_with("/beacons/")
            || path == "/settings/user"
            || path == "/automations" =>
        {
            Some(desktop_control_unsupported_response())
        }
        _ => None,
    }
}

fn desktop_control_unsupported_response() -> StaticResponse {
    StaticResponse {
        status: StatusCode::NOT_IMPLEMENTED,
        content_type: "application/json",
        body: br#"{"error":{"type":"desktop_control_unsupported","message":"This Desktop control endpoint is unavailable through SAIAI."}}"#,
        reason: "desktop_control_unsupported",
    }
}

fn chatgpt_chat_disabled_response(request: &IncomingRequest) -> Option<StaticResponse> {
    normalize_chatgpt_chat_target(&request.target).ok()?;
    Some(StaticResponse {
        status: StatusCode::NOT_IMPLEMENTED,
        content_type: "application/json",
        body: br#"{"error":{"type":"chat_mode_temporarily_disabled","message":"Chat mode is temporarily unsupported; switch to Codex mode."}}"#,
        reason: "chat_mode_temporarily_disabled",
    })
}

fn chatgpt_account_sidecar_response(request: &IncomingRequest) -> Option<AccountSidecarResponse> {
    let path = request_path(&request.target).ok()?;
    // These are local identity reads, not hosted account APIs. A write must
    // never receive a synthetic success or be sent to a pooled account.
    if is_desktop_identity_read_path(&path) && !request.method.eq_ignore_ascii_case("GET") {
        return Some((
            StatusCode::NOT_IMPLEMENTED,
            br#"{"error":{"type":"desktop_identity_write_unsupported","message":"Hosted account changes are unavailable through SAIAI Desktop."}}"#.to_vec(),
            "desktop_identity_write_unsupported",
            &[],
        ));
    }
    let account_id = header_value(&request.headers, "chatgpt-account-id")
        .map(str::to_owned)
        .or_else(|| oauth_claim_account_id(&request.headers))
        .or_else(desktop_account_id_fallback)
        .unwrap_or_else(|| "fixture-chatgpt-account".to_string());
    let user_id = oauth_claim_user_id(&request.headers)
        .unwrap_or_else(|| "saiai-local-proxy-user".to_string());
    if path == "/v1/initialize"
        && request.method.eq_ignore_ascii_case("POST")
        && request.body.len() <= DESKTOP_STATSIG_MAX_REQUEST_BYTES
    {
        // Re-evaluation must retain the identity used by the SDK. Returning a
        // fixed user here makes Desktop's identity check wait indefinitely.
        let body = desktop_statsig_request(request)?;
        let user = desktop_statsig_user(body.get("user")?)?;
        return Some((
            StatusCode::OK,
            serde_json::to_vec(&desktop_statsig_payload(user)?).ok()?,
            "desktop_statsig_identity_bootstrap",
            &[],
        ));
    }
    if matches!(
        path.as_str(),
        "/backend-api/wham/statsig/bootstrap" | "/wham/statsig/bootstrap"
    ) && !matches!(request.method.as_str(), "GET" | "POST")
    {
        return Some((
            StatusCode::NOT_IMPLEMENTED,
            desktop_control_unsupported_response().body.to_vec(),
            "desktop_control_unsupported",
            &[],
        ));
    }
    if path == "/backend-api/ps/mcp" {
        if !request.method.eq_ignore_ascii_case("POST") {
            return Some((
                StatusCode::NOT_IMPLEMENTED,
                desktop_control_unsupported_response().body.to_vec(),
                "desktop_control_unsupported",
                &[],
            ));
        }
        let request_json: Value = serde_json::from_slice(&request.body).ok()?;
        let id = request_json.get("id").cloned().unwrap_or(Value::Null);
        let method = request_json.get("method").and_then(Value::as_str);
        if id.is_null() || method.is_some_and(|value| value.starts_with("notifications/")) {
            return Some((
                StatusCode::ACCEPTED,
                Vec::new(),
                "desktop_mcp_notification",
                &[],
            ));
        }
        let response = match method {
            Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "saiai-local", "version": "1"}
            }}),
            Some("tools/list") => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
            Some("ping") => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
            Some(_) => json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": -32601, "message": "Method not found"
            }}),
            None => json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": -32600, "message": "Invalid Request"
            }}),
        };
        return Some((
            StatusCode::OK,
            serde_json::to_vec(&response).ok()?,
            "desktop_mcp_response",
            &[],
        ));
    }
    let response = match path.as_str() {
        // The Desktop renderer uses the optimized account endpoint for seat
        // access.  It is not the same wire shape as the app-server's
        // `/wham/accounts/check` workspace-discovery endpoint: the renderer
        // dereferences `account_user.seat_type` directly during startup.
        "/backend-api/accounts/optimized/check" | "/accounts/optimized/check" => json!({
            "account": {
                "id": account_id,
                "is_fedramp_compliant_workspace": false
            },
            "account_user": {
                "account_id": account_id,
                "user_id": user_id,
                "seat_type": "default",
                "trial_expires_at": null,
                "pending_seat_upgrade_request": false
            }
        }),
        "/backend-api/wham/accounts/check" | "/wham/accounts/check" => json!({
            "account_ordering": [account_id],
            "default_account_id": account_id,
            "accounts": [{
                "id": account_id,
                "account_user_id": user_id,
                "account_user_role": "standard-user",
                // Codex app-server 0.155+ uses these fields to resolve the
                // selected workspace before `account/read` can report the
                // local ChatGPT identity. `NO_CONSTRAINT` keeps the effective
                // ChatGPT origin and adds no regional routing override.
                "workspace_backend_origin": "NO_CONSTRAINT",
                "account_routing_override": "NO_CONSTRAINT",
                "structure": "personal",
                "plan_type": "plus",
                "is_zdr": false,
                "is_openai_internal": false,
                "can_access_with_session": true,
                "enable_account_switching": false,
                "is_deactivated": false,
                "name": null,
                "profile_picture_url": null
            }]
        }),
        // Codex Desktop 26.917 reads the versioned full-account endpoint in
        // addition to the older wham and optimized endpoints. Its renderer
        // expects an ordered map of account records, not the wham array. A
        // generic `{}` fallback makes `account_ordering.map(...)` throw and
        // displays "ChatGPT hit a snag" despite an HTTP 200 response.
        _ if is_desktop_full_account_path(&path) => desktop_account_catalog(&account_id, &user_id),
        // Codex Desktop's model picker treats this authenticated control-plane
        // response as the source of optional Daybreak access. A null root
        // means no special access program is present; an object such as `{}`
        // can be interpreted as a non-standard access state and hide Astra.
        "/backend-api/accounts/verified_access" | "/accounts/verified_access" => Value::Null,
        "/backend-api/wham/statsig/bootstrap" | "/wham/statsig/bootstrap" => {
            if request.body.len() > DESKTOP_STATSIG_MAX_REQUEST_BYTES {
                return Some((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    br#"{"error":"payload_too_large"}"#.to_vec(),
                    "desktop_statsig_payload_too_large",
                    &[],
                ));
            }
            let mut user = json!({
                "userID": user_id,
                "custom": {"auth_method": "chatgpt"},
                "customIDs": {"account_id": account_id, "workspace_id": account_id}
            });
            if let Ok(body) = serde_json::from_slice::<Value>(&request.body)
                && let Some(stable_id) = body
                    .get("stable_id")
                    .and_then(desktop_statsig_identity_value)
            {
                user["customIDs"]["stableID"] = Value::String(stable_id.to_owned());
            }
            json!({"statsigPayload": serde_json::to_string(&desktop_statsig_payload(user)?).ok()?})
        }
        "/backend-api/conversations" => json!({
            "items": [],
            "total": 0,
            "limit": 100,
            "offset": 0
        }),
        // Desktop 26.1002 iterates this optional tool catalog even on a
        // plain Chat. The neutral local identity must return an array;
        // a generic {} response throws "system_hints is not iterable".
        "/backend-api/system_hints" if request.method.eq_ignore_ascii_case("GET") => {
            json!({"system_hints": []})
        }
        "/backend-api/wham/profiles/me" | "/wham/profiles/me" => json!({
            "profile": {
                "display_name": null,
                "username": null,
                "profile_picture_url": null
            },
            "stats": {
                "daily_usage_buckets": null
            },
            "metadata": {
                "stats_error": null
            }
        }),
        // Desktop 26.1007 reads this identity endpoint during sidebar render.
        // It is distinct from `/wham/profiles/me` (usage), and dereferences
        // `profile_details.profile_picture_url` even when no hosted profile
        // is configured. Keep optional identity fields empty for the local
        // account; a generic `{}` response crashes the entire renderer.
        "/backend-api/profiles/me" | "/profiles/me"
            if request.method.eq_ignore_ascii_case("GET") =>
        {
            json!({
                "profile_details": {
                    "display_name": null,
                    "username": null,
                    "profile_picture_url": null
                }
            })
        }
        "/backend-api/profiles/me" | "/profiles/me" => {
            return Some((
                StatusCode::NOT_IMPLEMENTED,
                br#"{"error":{"type":"desktop_profile_update_unsupported","message":"Profile updates are unavailable through SAIAI Desktop."}}"#.to_vec(),
                "desktop_profile_update_unsupported",
                &[],
            ));
        }
        "/backend-api/me" => json!({
            "id": account_id,
            "account_id": account_id,
            "email": SAIAI_DESKTOP_EMAIL
        }),
        // The Desktop rate-limit/sidebar code dereferences this array even
        // when no checkout flow is enabled. Returning an empty collection is
        // the neutral authenticated shape; `{}` makes the renderer panic on
        // `payment_methods.length`.
        "/backend-api/payments/payment_methods" => json!({
            "payment_methods": []
        }),
        "/settings/user" => json!({}),
        _ if desktop_settings_account_id(&path).is_some() => {
            if desktop_settings_account_id(&path) != Some(account_id.as_str()) {
                return None;
            }
            json!({"account_id": account_id, "settings": {}})
        }
        _ => return None,
    };
    Some((
        StatusCode::OK,
        serde_json::to_vec(&response).ok()?,
        "desktop_account_identity",
        &[],
    ))
}

fn is_desktop_full_account_path(path: &str) -> bool {
    matches!(
        path,
        "/accounts/check/v4-2023-04-27" | "/backend-api/accounts/check/v4-2023-04-27"
    )
}

fn desktop_settings_account_id(path: &str) -> Option<&str> {
    let account_id = path
        .strip_prefix("/backend-api/accounts/")?
        .strip_suffix("/settings")?;
    (!account_id.is_empty() && !account_id.contains('/')).then_some(account_id)
}

fn is_desktop_identity_read_path(path: &str) -> bool {
    matches!(
        path,
        "/backend-api/accounts/optimized/check"
            | "/accounts/optimized/check"
            | "/backend-api/wham/accounts/check"
            | "/wham/accounts/check"
            | "/backend-api/accounts/verified_access"
            | "/accounts/verified_access"
            | "/backend-api/conversations"
            | "/backend-api/system_hints"
            | "/backend-api/wham/profiles/me"
            | "/wham/profiles/me"
            | "/backend-api/me"
            | "/backend-api/payments/payment_methods"
            | "/settings/user"
    ) || is_desktop_full_account_path(path)
        || desktop_settings_account_id(path).is_some()
}

// The synthetic Desktop identity has no hosted subscription. Keep the complete
// account record together: sidebar membership, Chat home, and Work home read
// the same catalog, and subscription observers run even when trial UI is off.
// Desktop 26.1007 mounts a timer that dereferences `entitlement.expires_at`
// before checking whether the account has a trial. An omitted object throws
// inside Jotai's onMount and becomes a renderer-wide AggregateError.
fn desktop_account_catalog(account_id: &str, user_id: &str) -> Value {
    let record = json!({
        "account": {
            "account_id": account_id,
            "account_user_id": user_id,
            "account_user_role": "standard-user",
            "account_owner_id": null,
            "structure": "personal",
            "plan_type": "plus",
            "is_zdr": false,
            "is_openai_internal": false,
            "is_deactivated": false,
            "is_fedramp_compliant_workspace": false,
            "is_hipaa_compliant_workspace": false,
            "ekm_config": null
        },
        "entitlement": {
            "subscription_id": null,
            "subscription_plan": null,
            "expires_at": null,
            "renews_at": null,
            "has_active_subscription": false,
            "is_active_subscription_gratis": false,
            "trial": null
        },
        "last_active_subscription": {
            "subscription_id": null,
            "purchase_origin_platform": null,
            "will_renew": false
        },
        "eligible_offers": [],
        "eligible_promo_campaigns": {},
        "features": [],
        "can_access_with_session": true
    });
    let mut accounts = Map::new();
    accounts.insert(account_id.to_owned(), record);
    json!({"account_ordering": [account_id], "accounts": accounts})
}

fn desktop_statsig_request(request: &IncomingRequest) -> Option<Value> {
    if request.body.len() > DESKTOP_STATSIG_MAX_REQUEST_BYTES {
        return None;
    }
    let url = Url::parse(&format!("http://localhost{}", request.target)).ok()?;
    let encoding: Vec<_> = url.query_pairs().filter(|(key, _)| key == "se").collect();
    if encoding.is_empty() {
        return serde_json::from_slice(&request.body).ok();
    }
    if encoding.len() != 1 || encoding[0].1 != "1" {
        return None;
    }
    // Statsig JS 3.34 sends initialize JSON as reversed base64 when se=1.
    // Decode only this bounded local control request; model traffic is untouched.
    let reversed: Vec<u8> = request.body.iter().rev().copied().collect();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(reversed)
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn desktop_statsig_identity_value(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    (!text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control)).then_some(text)
}

// Only identity fields are projected. Never echo arbitrary request metadata,
// private attributes, credentials or hosted experiment settings.
fn desktop_statsig_user(input: &Value) -> Option<Value> {
    let mut user = json!({"userID": desktop_statsig_identity_value(input.get("userID")?)?});
    let mut ids = Map::new();
    for key in ["account_id", "workspace_id", "stableID"] {
        if let Some(value) = input
            .get("customIDs")
            .and_then(|ids| ids.get(key))
            .and_then(desktop_statsig_identity_value)
        {
            ids.insert(key.to_owned(), Value::String(value.to_owned()));
        }
    }
    user["customIDs"] = Value::Object(ids);
    if input
        .get("custom")
        .and_then(|v| v.get("auth_method"))
        .and_then(Value::as_str)
        == Some("chatgpt")
    {
        user["custom"] = json!({"auth_method": "chatgpt"});
    }
    Some(user)
}

fn desktop_statsig_payload(user: Value) -> Option<Value> {
    let mut payload: Value = serde_json::from_str(DESKTOP_STATSIG_I18N_PAYLOAD).ok()?;
    payload["user"] = user;
    Some(payload)
}

fn oauth_claim_user_id(headers: &[(String, String)]) -> Option<String> {
    let authorization = header_value(headers, "authorization")?;
    let token = authorization.strip_prefix("Bearer ")?.trim();
    if token.len() > 32 * 1024 {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1)?)
        .ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("https://api.openai.com/auth")
        .and_then(|auth| auth.get("chatgpt_user_id"))
        .and_then(desktop_statsig_identity_value)
        .map(str::to_owned)
}

fn oauth_claim_account_id(headers: &[(String, String)]) -> Option<String> {
    let authorization = header_value(headers, "authorization")?;
    let token = authorization.strip_prefix("Bearer ")?.trim();
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("https://api.openai.com/auth")
        .and_then(Value::as_object)
        .and_then(|auth| auth.get("chatgpt_account_id"))
        .and_then(Value::as_str)
        .or_else(|| claims.get("chatgpt_account_id").and_then(Value::as_str))
        .map(str::to_owned)
}

fn desktop_account_id_fallback() -> Option<String> {
    let root = env::var_os("SAIAI_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".saiai"))
        })?;
    let value = fs::read_to_string(root.join("desktop/account-id")).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn is_managed_host(host: &str) -> bool {
    host == ANTHROPIC_HOST
        || host == OPENAI_HOST
        || host == CHATGPT_HOST
        || host == CHAT_OPENAI_HOST
        || host == CHATGPT_AUX_HOST
}

fn is_websocket_upgrade(request: &IncomingRequest) -> bool {
    header_contains(&request.headers, "upgrade", "websocket")
        && header_contains(&request.headers, "connection", "upgrade")
        && header_value(&request.headers, "sec-websocket-key").is_some()
}

fn is_websocket_handshake_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "upgrade"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-extensions"
            | "sec-websocket-protocol"
    )
}

fn should_forward_request_header(name: &str) -> bool {
    !is_hop_by_hop_header(name)
        && !name.eq_ignore_ascii_case("host")
        && !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("transfer-encoding")
        && !name.eq_ignore_ascii_case("proxy-authorization")
        && !name.eq_ignore_ascii_case("proxy-connection")
}

fn connection_nominated_headers(headers: &[(String, String)]) -> std::collections::HashSet<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect()
}

fn should_forward_request_header_to_gateway(name: &str, replace_authorization: bool) -> bool {
    should_forward_request_header(name)
        && !(replace_authorization
            && (name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie")))
}

// Plain HTTP proxy requests are not a credential-bearing transport.  Desktop
// uses them for connectivity/bootstrap checks; never disclose OAuth headers or
// cookies if an unexpected request is made to an arbitrary cleartext origin.
fn should_forward_http_proxy_header(name: &str) -> bool {
    should_forward_request_header(name)
        && !name.eq_ignore_ascii_case("authorization")
        && !name.eq_ignore_ascii_case("cookie")
}

fn should_forward_response_header(name: &str) -> bool {
    !is_hop_by_hop_header(name)
        && !name.eq_ignore_ascii_case("content-length")
        && !name.eq_ignore_ascii_case("transfer-encoding")
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn connect_direct_target(host: &str, port: u16) -> Result<TcpStream> {
    if is_managed_host(host) && port == 443 {
        bail!("managed host must use local MITM route");
    }
    let addrs = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve {host}:{port}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        bail!("no addresses resolved for {host}:{port}");
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    match last_err {
        Some(err) => Err(err).with_context(|| format!("failed to connect to {host}:{port}")),
        None => bail!("no usable addresses resolved for {host}:{port}"),
    }
}

fn build_leaf_server_config(
    host: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<ManagedCertificate> {
    let ca_key = KeyPair::from_pem(ca_key_pem).context("failed to parse SAIAI CA key")?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .context("failed to parse SAIAI CA certificate")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("failed to load SAIAI CA")?;

    let mut params = CertificateParams::new(vec![host.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    params.distinguished_name = dn;
    let leaf_key = desktop_leaf_key(&ca_key, host)?;
    let spki_sha256 =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(leaf_key.public_key_der()));
    let leaf = params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .context("failed to sign leaf certificate")?;
    let cert_der = leaf.der().to_vec();
    let key_der = leaf_key.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("failed to build TLS server config")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(ManagedCertificate {
        config: Arc::new(config),
        spki_sha256,
    })
}

fn desktop_leaf_key(ca_key: &KeyPair, host: &str) -> Result<KeyPair> {
    use p256::pkcs8::EncodePrivateKey;
    // HKDF-SHA256 derives an independent, per-host P-256 key from this
    // installation's private CA key. A service refresh retains the same leaf
    // SPKI; a CA-key rotation changes it. No additional private key is stored.
    // Preserve the existing leaf-only pin boundary instead of pinning a CA
    // certificate anywhere in a Chromium-supplied chain.
    let private_der = Zeroizing::new(ca_key.serialize_der());
    let hkdf = hkdf::Hkdf::<Sha256>::new(Some(b"SAIAI local proxy TLS leaf v1"), &private_der);
    let mut seed = Zeroizing::new([0_u8; 32]);
    for counter in 0_u8..16 {
        let mut info = host.as_bytes().to_vec();
        info.extend_from_slice(&[0, counter]);
        hkdf.expand(&info, seed.as_mut())
            .map_err(|_| anyhow::anyhow!("failed to derive local TLS leaf key"))?;
        // Reject the extremely rare zero/out-of-range scalar. Keep the same
        // ECDSA P-256 algorithm as the previous randomly generated leaves.
        if let Ok(key) = p256::SecretKey::from_slice(seed.as_ref()) {
            let pkcs8 = key
                .to_pkcs8_der()
                .context("failed to encode local TLS leaf key")?;
            return KeyPair::from_pkcs8_der_and_sign_algo(
                &PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
                &rcgen::PKCS_ECDSA_P256_SHA256,
            )
            .context("failed to load local TLS leaf key");
        }
    }
    bail!("failed to derive a valid local TLS leaf key")
}

async fn read_line_limited<R>(reader: &mut R) -> Result<String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .context("failed to read header line")?;
    if read == 0 {
        bail!("connection closed while reading header line");
    }
    if line.len() > MAX_HEADER_LINE {
        bail!("header line is too large");
    }
    Ok(line)
}

fn split_host_port(authority: &str) -> Result<(String, u16)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            bail!("invalid IPv6 authority");
        };
        let host = &rest[..end];
        let port_part = rest[end + 1..].strip_prefix(':').unwrap_or("");
        if port_part.is_empty() {
            bail!("CONNECT authority must include a port");
        }
        let port = port_part
            .parse::<u16>()
            .with_context(|| format!("invalid CONNECT port {port_part:?}"))?;
        return Ok((host.to_string(), port));
    }

    let Some((host, port_part)) = authority.rsplit_once(':') else {
        bail!("CONNECT authority must include host:port");
    };
    if host.is_empty() {
        bail!("CONNECT host is required");
    }
    let port = port_part
        .parse::<u16>()
        .with_context(|| format!("invalid CONNECT port {port_part:?}"))?;
    Ok((host.to_string(), port))
}

fn canonical_host(host: &str) -> String {
    host.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn is_blank_line(line: &str) -> bool {
    line == "\r\n" || line == "\n" || line.trim().is_empty()
}

fn trim_crlf(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn header_contains(headers: &[(String, String)], name: &str, token: &str) -> bool {
    header_value(headers, name)
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
        .unwrap_or(false)
}

fn request_wants_close(request: &IncomingRequest) -> bool {
    if header_contains(&request.headers, "connection", "close") {
        return true;
    }
    if request.http_version.eq_ignore_ascii_case("HTTP/1.0") {
        return !header_contains(&request.headers, "connection", "keep-alive");
    }
    false
}

fn path_query_from_target(target: &str) -> Result<String> {
    if target.starts_with('/') {
        return Ok(target.to_string());
    }
    let parsed =
        Url::parse(target).with_context(|| format!("invalid request target {target:?}"))?;
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let mut result = path.to_string();
    if let Some(query) = parsed.query() {
        result.push('?');
        result.push_str(query);
    }
    Ok(result)
}

fn request_path(target: &str) -> Result<String> {
    let path_query = path_query_from_target(target)?;
    Ok(path_query
        .split('?')
        .next()
        .unwrap_or(path_query.as_str())
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa};
    use tokio::time::timeout;

    #[test]
    fn native_codex_images_keep_their_own_protocol_route() {
        for operation in ["generations", "edits"] {
            let path = format!("/backend-api/codex/images/{operation}");
            let target = format!("{path}?opaque=a%2Fb&opaque=%2B");
            let normalized = normalize_chatgpt_gateway_target(&target).unwrap();
            assert_eq!(
                normalized,
                format!("/v1/codex/images/{operation}?opaque=a%2Fb&opaque=%2B")
            );
            assert!(is_forwarded_openai_path(
                &request_path(&normalized).unwrap()
            ));
            assert!(!is_forwarded_chatgpt_path(
                &request_path(&normalized).unwrap()
            ));
            assert!(normalize_chatgpt_gateway_target(&format!("{path}/unexpected")).is_err());
        }
        assert!(!is_forwarded_openai_path("/v1/codex/images/unknown"));
        assert!(!is_forwarded_openai_path("/v1/images/generations"));
    }

    fn test_ca() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn request_with_version_and_connection(
        http_version: &str,
        connection: Option<&str>,
    ) -> IncomingRequest {
        let mut headers = Vec::new();
        if let Some(connection) = connection {
            headers.push(("Connection".to_string(), connection.to_string()));
        }
        IncomingRequest {
            method: "GET".to_string(),
            target: "/api/claude_code/settings".to_string(),
            http_version: http_version.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn detects_forwarded_anthropic_paths() {
        assert!(is_forwarded_anthropic_path("/v1/messages"));
        assert!(is_forwarded_anthropic_path("/v1/messages/count_tokens"));
        assert!(is_forwarded_anthropic_path("/v1/models"));
        assert!(is_forwarded_anthropic_path("/v1/models/claude-sonnet-4"));
        assert!(!is_forwarded_anthropic_path("/api/oauth/usage"));
    }

    #[test]
    fn detects_forwarded_openai_paths() {
        assert!(is_forwarded_openai_path("/v1/responses"));
        assert!(is_forwarded_openai_path("/v1/responses/compact"));
        assert!(is_forwarded_openai_path("/v1/models"));
        assert!(is_forwarded_openai_path("/v1/models/gpt-5.3-codex"));
        assert!(!is_forwarded_openai_path("/backend-api/codex/models"));
    }

    #[test]
    fn normalizes_chatgpt_codex_targets_for_gateway() {
        assert_eq!(
            normalize_chatgpt_gateway_target("/backend-api/codex/responses?stream=true").unwrap(),
            "/v1/responses?stream=true"
        );
        assert_eq!(
            normalize_chatgpt_gateway_target("/backend-api/codex/models/gpt-5").unwrap(),
            "/v1/models/gpt-5"
        );
        assert!(normalize_chatgpt_gateway_target("/backend-api/conversations").is_err());
        assert!(is_managed_host(CHATGPT_HOST));
        assert!(is_managed_host(CHAT_OPENAI_HOST));
        assert!(is_managed_host(CHATGPT_AUX_HOST));
    }

    #[test]
    fn normalizes_ordinary_chatgpt_targets_only_when_allowlisted() {
        assert_eq!(
            normalize_chatgpt_chat_target("/backend-api/ios/attestation_challenge?x=a%2Fb&x=a+b")
                .unwrap(),
            "/chatgpt/backend-api/ios/attestation_challenge?x=a%2Fb&x=a+b"
        );
        assert!(is_forwarded_openai_path(
            "/chatgpt/backend-api/ios/attestation_challenge"
        ));
        assert!(
            normalize_chatgpt_chat_target("/backend-api/ios/attestation_challenge/future").is_err()
        );
        assert_eq!(
            normalize_chatgpt_chat_target("/backend-api/models?language=zh-CN&x=a%2Bb&x=c")
                .unwrap(),
            "/chatgpt/backend-api/models?language=zh-CN&x=a%2Bb&x=c"
        );
        assert!(is_forwarded_openai_path("/chatgpt/backend-api/models"));
        assert!(normalize_chatgpt_gateway_target("/backend-api/models").is_err());
        assert!(normalize_chatgpt_chat_target("/backend-api/models/future").is_err());
        assert!(normalize_chatgpt_chat_target("/backend-api/models-admin").is_err());
        assert_eq!(
            normalize_chatgpt_chat_target("/backend-api/f/conversation?foo=bar").unwrap(),
            "/chatgpt/backend-api/f/conversation?foo=bar"
        );
        assert_eq!(
            normalize_chatgpt_chat_target("/backend-api/f/conversation/prepare").unwrap(),
            "/chatgpt/backend-api/f/conversation/prepare"
        );
        assert_eq!(
            normalize_chatgpt_chat_target(
                "/backend-api/files/download/file_123?conversation_id=conv-1"
            )
            .unwrap(),
            "/chatgpt/backend-api/files/download/file_123?conversation_id=conv-1"
        );
        assert!(normalize_chatgpt_chat_target("/backend-api/conversations").is_err());
        assert!(is_forwarded_chatgpt_path(
            "/chatgpt/backend-api/f/conversation"
        ));
        assert!(is_forwarded_chatgpt_path(
            "/chatgpt/backend-api/files/download/file_123"
        ));
        assert_eq!(
            normalize_chatgpt_chat_target("/backend-api/estuary/content?id=file_123").unwrap(),
            "/chatgpt/backend-api/estuary/content?id=file_123"
        );
        assert!(!is_forwarded_chatgpt_path("/backend-api/f/conversation"));
        assert!(!should_forward_request_header_to_gateway(
            "Authorization",
            true
        ));
        assert!(!should_forward_request_header_to_gateway("Cookie", true));
        assert!(should_forward_request_header_to_gateway("originator", true));
    }

    #[test]
    fn disables_ordinary_chat_with_explicit_unsupported_response() {
        let request = IncomingRequest {
            method: "POST".to_string(),
            target: "/backend-api/f/conversation".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = chatgpt_chat_disabled_response(&request).unwrap();
        assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(response.reason, "chat_mode_temporarily_disabled");
        assert!(
            !chatgpt_chat_disabled_response(&IncomingRequest {
                target: "/backend-api/codex/models".to_string(),
                ..request
            })
            .is_some()
        );
    }

    #[test]
    fn serves_empty_notification_settings_without_accepting_updates() {
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/notifications/settings".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        for target in [
            "/backend-api/notifications/settings",
            "/notifications/settings",
        ] {
            for method in ["GET", "PATCH"] {
                let response = chatgpt_sidecar_response(&IncomingRequest {
                    method: method.to_string(),
                    target: target.to_string(),
                    ..request.clone()
                })
                .expect("notification settings response");
                let body: Value = serde_json::from_slice(response.body).unwrap();
                if method == "GET" {
                    assert_eq!(response.status, StatusCode::OK);
                    assert_eq!(response.reason, "desktop_notification_settings_empty");
                    assert_eq!(body["settings"], json!([]));
                } else {
                    assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
                    assert_eq!(response.reason, "desktop_notification_settings_unsupported");
                    assert_eq!(
                        body["error"]["type"],
                        "desktop_notification_settings_unsupported"
                    );
                }
            }
        }
    }

    #[test]
    fn native_chat_updates_bootstrap_is_not_an_empty_success_sidecar() {
        for target in [
            "/backend-api/celsius/ws/user",
            "/backend-api/celsius/ws/user?include_external=all",
            "/celsius/ws/user",
        ] {
            let request = IncomingRequest {
                method: "GET".to_string(),
                target: target.to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            };
            let response = chatgpt_sidecar_response(&request)
                .expect("unsupported native conversation updates must fail explicitly");
            assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
            let body: Value = serde_json::from_slice(response.body).unwrap();
            assert_eq!(body["error"]["type"], "native_chat_updates_unsupported");
            assert!(body.get("websocket_url").is_none());
            assert_eq!(response.reason, "native_chat_updates_unsupported");
            let forwarded = normalize_chatgpt_chat_target(target).unwrap();
            assert!(is_forwarded_chatgpt_path(
                &request_path(&forwarded).unwrap()
            ));
        }
    }

    #[test]
    fn native_chat_system_hints_catalog_is_an_array_for_official_renderer() {
        let request = IncomingRequest {
            method: "GET".into(),
            target: "/backend-api/system_hints?mode=plugins&exclude_logo=true".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
        };
        let (status, body, _, _) = chatgpt_account_sidecar_response(&request).unwrap();
        assert_eq!(status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["system_hints"], json!([]));
        assert_eq!(
            chatgpt_account_sidecar_response(&IncomingRequest {
                method: "POST".into(),
                ..request
            })
            .unwrap()
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[test]
    fn native_chat_device_cookie_is_narrow_and_never_a_local_placeholder() {
        let headers = vec![(
            "Cookie".into(),
            "session=MOCK_ONLY_AUTH; _devicecheck=MOCK_ONLY_PROOF; other=MOCK_ONLY_OTHER".into(),
        )];
        assert_eq!(
            chatgpt_device_cookie(&headers).unwrap().as_deref(),
            Some("_devicecheck=MOCK_ONLY_PROOF")
        );
        for invalid in [
            "_devicecheck=",
            "_devicecheck=\"MOCK_ONLY_PROOF\"",
            "_devicecheck=MOCK_ONLY_FIRST; _devicecheck=MOCK_ONLY_SECOND",
        ] {
            assert!(chatgpt_device_cookie(&[("Cookie".into(), invalid.into())]).is_err());
        }
        assert!(
            chatgpt_device_cookie(&[("Cookie".into(), "_devicecheck=saiai-local-proxy".into())])
                .unwrap()
                .is_none()
        );
        assert!(!is_chatgpt_device_cookie_target("/v1/responses"));
        assert!(!is_chatgpt_device_cookie_target(
            "/chatgpt/backend-api/files"
        ));
        for target in [
            "/backend-api/f/conversation/prepare?x=a%2Fb&x=a+b",
            "/chatgpt/backend-api/f/conversation/prepare",
        ] {
            assert!(is_chatgpt_device_cookie_target(target));
        }
        assert!(!is_chatgpt_device_cookie_target(
            "/backend-api/f/conversation/prepare/future"
        ));
        assert!(normalize_chatgpt_chat_target("/backend-api/devicecheck/future").is_err());
        let settings = IncomingRequest {
            method: "POST".into(),
            target: "/settings/user".into(),
            http_version: "HTTP/1.1".into(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(
            chatgpt_account_sidecar_response(&settings)
                .unwrap()
                .3
                .is_empty()
        );
    }

    #[tokio::test]
    async fn native_chat_device_registration_uses_tls_forwarding_and_keeps_proofs_private() {
        ensure_rustls_crypto_provider();
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_cert_pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        for (method, path, body, cookie, expected_cookie) in [
            (
                "POST",
                "/backend-api/devicecheck?x=a%2Fb&x=a+b",
                "{ \"device_token\":\"MOCK_ONLY_APPLE\",\"bundle_id\":\"com.openai.codex\",\"future\":null }",
                "session=MOCK_ONLY_AUTH; _devicecheck=saiai-local-proxy",
                None,
            ),
            (
                "GET",
                "/backend-api/ios/attestation_challenge?x=a%2Fb",
                "",
                "session=MOCK_ONLY_AUTH; _devicecheck=MOCK_ONLY_PROOF",
                Some("_devicecheck=MOCK_ONLY_PROOF"),
            ),
            (
                "POST",
                "/backend-api/f/conversation/prepare?x=a%2Fb&x=a+b",
                "{ \"model\":\"auto\",\"app_attest_challenge\":\"MOCK_ONLY_CHALLENGE\",\"future\":null }",
                "session=MOCK_ONLY_AUTH; _devicecheck=MOCK_ONLY_PROOF",
                Some("_devicecheck=MOCK_ONLY_PROOF"),
            ),
            (
                "POST",
                "/backend-api/f/conversation/prepare",
                "{ \"model\":\"auto\",\"future\":null }",
                "session=MOCK_ONLY_AUTH",
                None,
            ),
            (
                "POST",
                "/backend-api/f/conversation/prepare",
                "{ \"model\":\"auto\",\"future\":null }",
                "session=MOCK_ONLY_AUTH; _devicecheck=saiai-local-proxy",
                None,
            ),
            (
                "POST",
                "/backend-api/f/conversation",
                "{ \"model\":\"auto\",\"app_attest_challenge\":\"MOCK_ONLY_CHALLENGE\",\"future\":null }",
                "session=MOCK_ONLY_AUTH; _devicecheck=MOCK_ONLY_PROOF",
                Some("_devicecheck=MOCK_ONLY_PROOF"),
            ),
        ] {
            let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base_url = format!("http://{}", gateway.local_addr().unwrap());
            let captured = tokio::spawn(async move {
                let (stream, _) = gateway.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let request = read_http_request(&mut reader).await.unwrap();
                reader.get_mut().write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: _devicecheck=MOCK_ONLY_PROOF; Domain=.chatgpt.com; Path=/; Secure; HttpOnly\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
                request
            });
            let trace_dir = tempfile::tempdir().unwrap();
            let trace_path = trace_dir.path().join("trace.jsonl");
            let mut state = State::new(Config {
                listen: "127.0.0.1:0".into(),
                base_url,
                api_key: "MOCK_ONLY_GATEWAY".into(),
                claude: None,
                codex: None,
                ca_cert_pem: ca_cert_pem.clone(),
                ca_key_pem: ca_key_pem.clone(),
                verbose: false,
                chatgpt_chat_passthrough: true,
            })
            .unwrap();
            state.openai_trace = Some(Arc::new(OpenAITrace {
                file: Mutex::new(fs::File::create(&trace_path).unwrap()),
            }));
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = proxy.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (stream, _) = proxy.accept().await.unwrap();
                serve_managed_tls(Arc::new(state), stream, CHATGPT_HOST)
                    .await
                    .unwrap();
            });
            let stream = TcpStream::connect(address).await.unwrap();
            let mut tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("chatgpt.com").unwrap(),
                    stream,
                )
                .await
                .unwrap();
            let wire = format!(
                "{method} {path} HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer MOCK_ONLY_LOCAL\r\nCookie: {cookie}\r\nOAI-DID: MOCK_ONLY_DEVICE\r\nX-Sentinel-DC: MOCK_ONLY_HEADER_PROOF\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(wire.as_bytes()).await.unwrap();
            let mut response_reader = BufReader::new(tls);
            let mut response_headers = String::new();
            loop {
                let mut line = String::new();
                response_reader.read_line(&mut line).await.unwrap();
                assert!(!line.is_empty());
                response_headers.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            assert_eq!(
                read_chunked_body(&mut response_reader).await.unwrap(),
                b"{}"
            );
            task.await.unwrap();
            let request = captured.await.unwrap();
            assert_eq!(request.target, format!("/chatgpt{path}"));
            assert_eq!(request.method, method);
            assert_eq!(request.body, body.as_bytes());
            assert_eq!(header_value(&request.headers, "cookie"), expected_cookie);
            assert_eq!(
                header_value(&request.headers, "authorization"),
                Some("Bearer MOCK_ONLY_GATEWAY")
            );
            assert_eq!(
                header_value(&request.headers, "x-sentinel-dc"),
                Some("MOCK_ONLY_HEADER_PROOF")
            );
            assert!(response_headers.contains("_devicecheck=MOCK_ONLY_PROOF; Domain=.chatgpt.com"));
            let trace = fs::read_to_string(&trace_path).unwrap();
            for secret in [
                "MOCK_ONLY_APPLE",
                "MOCK_ONLY_PROOF",
                "MOCK_ONLY_LOCAL",
                "MOCK_ONLY_AUTH",
                "MOCK_ONLY_CHALLENGE",
                "MOCK_ONLY_HEADER_PROOF",
            ] {
                assert!(!trace.contains(secret));
            }
        }
    }

    #[test]
    fn native_chat_delivery_routes_preserve_queries_and_bound_conversation_paths() {
        for target in [
            "/backend-api/conversation/TEST_ONLY_ID?history_off=true&x=a%2Bb",
            "/backend-api/conversations/TEST_ONLY_ID?num_turns=10",
            "/backend-api/conversations/TEST_ONLY_ID/messages?cursor=TEST_ONLY",
            "/backend-api/saiai/chat-updates",
        ] {
            let forwarded = normalize_chatgpt_chat_target(target).unwrap();
            assert_eq!(forwarded, format!("/chatgpt{target}"));
            assert!(is_forwarded_chatgpt_path(
                &request_path(&forwarded).unwrap()
            ));
        }
        for target in [
            "/backend-api/conversations",
            "/backend-api/conversation/../accounts",
            "/backend-api/conversation/%2Faccounts",
            "/backend-api/conversation/id/unknown",
            "/backend-api/celsius/ws/admin",
            "/backend-api/saiai/chat-updates/admin",
        ] {
            assert!(normalize_chatgpt_chat_target(target).is_err());
        }
    }

    #[test]
    fn desktop_profile_identity_read_has_the_required_nested_shape() {
        for target in [
            "/backend-api/profiles/me",
            "/profiles/me",
            "/backend-api/profiles/me?source=sidebar",
        ] {
            let request = IncomingRequest {
                method: "GET".to_string(),
                target: target.to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![(
                    "ChatGPT-Account-ID".to_string(),
                    "local-account".to_string(),
                )],
                body: Vec::new(),
            };
            let (status, bytes, reason, headers) =
                chatgpt_account_sidecar_response(&request).unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(reason, "desktop_account_identity");
            assert!(headers.is_empty());
            let response: Value = serde_json::from_slice(&bytes).unwrap();
            let profile = response["profile_details"].as_object().unwrap();
            for field in ["display_name", "username", "profile_picture_url"] {
                assert_eq!(profile.get(field), Some(&Value::Null));
            }
            assert_eq!(response.as_object().unwrap().len(), 1);
            assert!(normalize_chatgpt_chat_target(target).is_err());
        }
    }

    #[test]
    fn desktop_profile_identity_does_not_report_success_for_updates() {
        for target in ["/backend-api/profiles/me", "/profiles/me"] {
            for method in ["POST", "PATCH", "PUT", "DELETE"] {
                let request = IncomingRequest {
                    method: method.to_string(),
                    target: target.to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    headers: Vec::new(),
                    body: br#"{"display_name":"fixture"}"#.to_vec(),
                };
                let (status, bytes, reason, headers) =
                    chatgpt_account_sidecar_response(&request).unwrap();
                assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
                assert_eq!(reason, "desktop_profile_update_unsupported");
                assert!(headers.is_empty());
                let response: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    response["error"]["type"],
                    "desktop_profile_update_unsupported"
                );
                assert!(response.get("profile_details").is_none());
            }
        }
    }

    #[test]
    fn serves_desktop_non_model_sidecars_locally() {
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/wham/accounts/check".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = chatgpt_sidecar_response(&request).expect("desktop sidecar response");
        // Account reads are handled by the complete identity response first.
        // Falling through must not manufacture a second, malformed success.
        assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);

        let telemetry = IncomingRequest {
            target: "/ces/v1/rgstr".to_string(),
            ..request
        };
        let response = chatgpt_sidecar_response(&telemetry).expect("telemetry sidecar response");
        assert_eq!(response.status, StatusCode::NO_CONTENT);

        let telemetry_intake = IncomingRequest {
            target: "/ces/v1/telemetry/intake".to_string(),
            ..telemetry
        };
        let response =
            chatgpt_sidecar_response(&telemetry_intake).expect("telemetry intake sidecar response");
        assert_eq!(response.status, StatusCode::NO_CONTENT);

        let recommended_plugins = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/ps/plugins/suggested/codex?scope=GLOBAL".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = chatgpt_sidecar_response(&recommended_plugins).unwrap();
        let body: Value = serde_json::from_slice(response.body).unwrap();
        assert_eq!(body["plugins"], json!([]));
        assert_eq!(body["enabled"], false);
    }

    #[test]
    fn desktop_plugin_home_has_sections_for_renderer_find_without_changing_plugin_lists() {
        for target in [
            "/backend-api/ps/plugins/home",
            "/backend-api/ps/plugins/home?scope=GLOBAL",
            "/ps/plugins/home",
            "/ps/plugins/home?scope=GLOBAL",
        ] {
            let request = IncomingRequest {
                method: "GET".to_string(),
                target: target.to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            };
            let response = chatgpt_sidecar_response(&request).unwrap();
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.reason, "desktop_plugin_home_empty");
            let body: Value = serde_json::from_slice(response.body).unwrap();
            assert_eq!(body, json!({ "sections": [] }));
        }
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/ps/plugins/list".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let response = chatgpt_sidecar_response(&request).unwrap();
        assert_eq!(response.reason, "desktop_plugins_empty");
        let body: Value = serde_json::from_slice(response.body).unwrap();
        assert_eq!(body["plugins"], json!([]));
        assert!(body.get("sections").is_none());
    }

    #[test]
    fn serves_desktop_control_plane_shapes_locally() {
        let conversations = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/conversations?limit=100&offset=0".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("ChatGPT-Account-ID".to_string(), "account-test".to_string())],
            body: Vec::new(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&conversations).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["items"], json!([]));
        assert_eq!(body["total"], 0);

        let me = IncomingRequest {
            target: "/backend-api/me".to_string(),
            ..conversations.clone()
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&me).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["email"], SAIAI_DESKTOP_EMAIL);

        let accounts = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/wham/accounts/check".to_string(),
            headers: vec![("ChatGPT-Account-ID".to_string(), "account-test".to_string())],
            ..conversations.clone()
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&accounts).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["default_account_id"], "account-test");
        assert_eq!(body["accounts"][0]["account_user_role"], "standard-user");
        assert_eq!(
            body["accounts"][0]["workspace_backend_origin"],
            "NO_CONSTRAINT"
        );
        assert_eq!(
            body["accounts"][0]["account_routing_override"],
            "NO_CONSTRAINT"
        );
        assert_eq!(body["accounts"][0]["is_zdr"], false);

        let optimized_accounts = IncomingRequest {
            target: "/backend-api/accounts/optimized/check".to_string(),
            ..accounts
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&optimized_accounts).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["account_user"]["seat_type"], "default");
        assert_eq!(body["account"]["is_fedramp_compliant_workspace"], false);

        let unprefixed_optimized_accounts = IncomingRequest {
            target: "/accounts/optimized/check".to_string(),
            ..optimized_accounts
        };
        let (_, body, _, _) =
            chatgpt_account_sidecar_response(&unprefixed_optimized_accounts).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["account_user"]["account_id"], "account-test");
        assert_eq!(body["account_user"]["seat_type"], "default");

        for target in [
            "/accounts/check/v4-2023-04-27",
            "/backend-api/accounts/check/v4-2023-04-27",
        ] {
            let versioned_accounts = IncomingRequest {
                target: target.to_string(),
                ..conversations.clone()
            };
            let (_, body, _, _) = chatgpt_account_sidecar_response(&versioned_accounts).unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["account_ordering"], json!(["account-test"]));
            assert!(body["accounts"].is_object());
            assert_eq!(
                body["accounts"]["account-test"]["account"]["account_id"],
                "account-test"
            );
            assert_eq!(
                body["accounts"]["account-test"]["can_access_with_session"],
                true
            );
            // Desktop 26.930's membership parser requires all of these
            // fields before it can evaluate Chat access.
            let account = &body["accounts"]["account-test"]["account"];
            for field in [
                "account_id",
                "account_user_id",
                "account_user_role",
                "structure",
                "plan_type",
            ] {
                assert!(
                    account[field]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "missing membership field {field} for {target}"
                );
            }
            assert!(account["is_zdr"].is_boolean());
            assert!(account["is_openai_internal"].is_boolean());
        }

        let verified_access = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/accounts/verified_access".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("ChatGPT-Account-ID".to_string(), "account-test".to_string())],
            body: Vec::new(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&verified_access).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body.is_null());

        let statsig = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/wham/statsig/bootstrap".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("ChatGPT-Account-ID".to_string(), "account-test".to_string())],
            body: Vec::new(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&statsig).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let payload: Value =
            serde_json::from_str(body["statsigPayload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["has_updates"], true);
        assert_eq!(payload["user"]["userID"], "saiai-local-proxy-user");
        assert_eq!(
            payload["layer_configs"]["72216192"]["value"]["enable_i18n"],
            true
        );
        assert_eq!(
            payload["layer_configs"]["72216192"]["explicit_parameters"],
            json!(["enable_i18n"])
        );

        let unprefixed_statsig = IncomingRequest {
            target: "/wham/statsig/bootstrap".to_string(),
            ..statsig
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&unprefixed_statsig).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body["statsigPayload"].is_string());

        let profile = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/wham/profiles/me".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("ChatGPT-Account-ID".to_string(), "account-test".to_string())],
            body: Vec::new(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&profile).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body["profile"].is_object());
        assert!(body["stats"].is_object());
        assert!(body["metadata"].is_object());

        let payment_methods = IncomingRequest {
            method: "GET".to_string(),
            target: "/backend-api/payments/payment_methods".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&payment_methods).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["payment_methods"], json!([]));

        let mcp = IncomingRequest {
            method: "POST".to_string(),
            target: "/backend-api/ps/mcp".to_string(),
            body: br#"{"jsonrpc":"2.0","id":7,"method":"initialize"}"#.to_vec(),
            ..conversations
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&mcp).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["result"]["serverInfo"]["name"], "saiai-local");

        let tools_list = IncomingRequest {
            method: "POST".to_string(),
            target: "/backend-api/ps/mcp".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("ChatGPT-Account-ID".to_string(), "account-test".to_string())],
            body: br#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#.to_vec(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&tools_list).unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["id"], 8);
        assert_eq!(body["result"]["tools"], json!([]));

        let notification = IncomingRequest {
            body: br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
            ..mcp
        };
        let (status, body, _, _) = chatgpt_account_sidecar_response(&notification).unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(body.is_empty());

        let settings = IncomingRequest {
            method: "POST".to_string(),
            target: "/backend-api/devicecheck".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(chatgpt_account_sidecar_response(&settings).is_none());
        assert_eq!(
            chatgpt_sidecar_response(&settings).unwrap().status,
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[test]
    fn unknown_desktop_controls_never_fabricate_success_or_plugin_catalogs() {
        for target in [
            "/backend-api/future/control?extension=TEST_ONLY",
            "/backend-api/wham/future",
            "/backend-api/ps/plugins/future",
            "/accounts/check/v5-future",
            "/backend-api/accounts/check/v5-future",
            "/accounts/future",
            "/settings/future",
            "/wham/future",
            "/automations",
        ] {
            for method in ["GET", "POST", "PATCH", "DELETE"] {
                let request = IncomingRequest {
                    method: method.into(),
                    target: target.into(),
                    http_version: "HTTP/1.1".into(),
                    headers: vec![],
                    body: vec![],
                };
                assert!(chatgpt_account_sidecar_response(&request).is_none());
                let response = chatgpt_sidecar_response(&request).unwrap();
                assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
                let body: Value = serde_json::from_slice(response.body).unwrap();
                assert_eq!(body["error"]["type"], "desktop_control_unsupported");
                assert!(body.get("plugins").is_none());
                assert!(normalize_chatgpt_chat_target(target).is_err());
            }
        }
    }

    #[test]
    fn desktop_identity_and_optional_catalog_writes_cannot_report_success() {
        for target in [
            "/backend-api/me",
            "/backend-api/accounts/optimized/check",
            "/accounts/check/v4-2023-04-27",
            "/backend-api/accounts/check/v4-2023-04-27",
            "/backend-api/wham/profiles/me",
            "/backend-api/payments/payment_methods",
            "/settings/user",
            "/backend-api/ps/plugins/list",
            "/ps/plugins/home",
        ] {
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                let request = IncomingRequest {
                    method: method.into(),
                    target: target.into(),
                    http_version: "HTTP/1.1".into(),
                    headers: vec![],
                    body: br#"{"TEST_ONLY_CHANGE":true}"#.to_vec(),
                };
                let status = if let Some(response) = chatgpt_account_sidecar_response(&request) {
                    response.0
                } else {
                    chatgpt_sidecar_response(&request).unwrap().status
                };
                assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{method} {target}");
                assert!(normalize_chatgpt_chat_target(target).is_err());
            }
        }
    }

    #[test]
    fn desktop_account_catalog_has_no_hosted_subscription_or_trial() {
        let response = desktop_account_catalog("TEST_ONLY_ACCOUNT", "TEST_ONLY_USER");
        let record = &response["accounts"]["TEST_ONLY_ACCOUNT"];
        let entitlement = &record["entitlement"];
        for field in [
            "subscription_id",
            "subscription_plan",
            "expires_at",
            "renews_at",
            "trial",
        ] {
            assert!(entitlement.get(field).unwrap().is_null(), "{field}");
        }
        assert_eq!(entitlement["has_active_subscription"], false);
        assert_eq!(entitlement["is_active_subscription_gratis"], false);
        assert!(record["last_active_subscription"]["subscription_id"].is_null());
        assert_eq!(record["last_active_subscription"]["will_renew"], false);
        assert!(record["account"]["account_owner_id"].is_null());
        assert_eq!(record["eligible_offers"], json!([]));
        assert_eq!(record["eligible_promo_campaigns"], json!({}));
    }

    #[test]
    fn desktop_mcp_unknown_methods_return_protocol_errors_without_fake_results() {
        for (method, expected_code) in [
            (json!("tools/call"), -32601),
            (json!("future/control"), -32601),
            (json!(false), -32600),
        ] {
            let request = IncomingRequest {
                method: "POST".into(),
                target: "/backend-api/ps/mcp".into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![],
                body: serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 17, "method": method}))
                    .unwrap(),
            };
            let (status, body, _, _) = chatgpt_account_sidecar_response(&request).unwrap();
            assert_eq!(status, StatusCode::OK);
            let response: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(response["id"], 17);
            assert_eq!(response["error"]["code"], expected_code);
            assert!(response.get("result").is_none());
            assert_eq!(
                chatgpt_account_sidecar_response(&IncomingRequest {
                    method: "GET".into(),
                    ..request
                })
                .unwrap()
                .0,
                StatusCode::NOT_IMPLEMENTED
            );
        }
    }

    #[test]
    fn desktop_account_settings_match_only_the_current_identity_and_exact_path() {
        let request = IncomingRequest {
            method: "GET".into(),
            target: "/backend-api/accounts/TEST_ONLY_ACCOUNT/settings".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![("chatgpt-account-id".into(), "TEST_ONLY_ACCOUNT".into())],
            body: vec![],
        };
        assert_eq!(
            chatgpt_account_sidecar_response(&request).unwrap().0,
            StatusCode::OK
        );
        for target in [
            "/backend-api/accounts/TEST_ONLY_FOREIGN/settings",
            "/backend-api/accounts/TEST_ONLY_ACCOUNT/future/settings",
            "/backend-api/accounts//settings",
            "/backend-api/accounts/TEST_ONLY_ACCOUNT/settings/future",
        ] {
            let request = IncomingRequest {
                target: target.into(),
                ..request.clone()
            };
            assert!(chatgpt_account_sidecar_response(&request).is_none());
            assert_eq!(
                chatgpt_sidecar_response(&request).unwrap().status,
                StatusCode::NOT_IMPLEMENTED
            );
        }
        for target in [
            "/backend-api/wham/statsig/bootstrap",
            "/wham/statsig/bootstrap",
        ] {
            let request = IncomingRequest {
                method: "PATCH".into(),
                target: target.into(),
                ..request.clone()
            };
            assert_eq!(
                chatgpt_account_sidecar_response(&request).unwrap().0,
                StatusCode::NOT_IMPLEMENTED
            );
        }
    }

    #[test]
    fn desktop_statsig_bootstrap_tracks_authenticated_identity_without_enabling_gates() {
        for (account, user) in [("account-one", "user-one"), ("account-two", "user-two")] {
            let claims = json!({"https://api.openai.com/auth": {
                "chatgpt_account_id": account, "chatgpt_user_id": user
            }});
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap());
            let request = IncomingRequest {
                method: "POST".to_string(),
                target: "/wham/statsig/bootstrap".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![("Authorization".to_string(), format!("Bearer e30.{encoded}.fixture"))],
                body: br#"{"stable_id":"stable-test","token":"must-not-echo","prompt":"must-not-echo"}"#.to_vec(),
            };
            let (status, body, _, _) = chatgpt_account_sidecar_response(&request).unwrap();
            assert_eq!(status, StatusCode::OK);
            let envelope: Value = serde_json::from_slice(&body).unwrap();
            let payload: Value =
                serde_json::from_str(envelope["statsigPayload"].as_str().unwrap()).unwrap();
            assert_eq!(
                payload["user"],
                json!({
                    "userID": user, "custom": {"auth_method": "chatgpt"},
                    "customIDs": {"account_id": account, "workspace_id": account, "stableID": "stable-test"}
                })
            );
            assert_eq!(payload["feature_gates"], json!({}));
            assert_eq!(payload["dynamic_configs"], json!({}));
            assert_eq!(payload["layer_configs"].as_object().unwrap().len(), 1);
            assert!(!String::from_utf8(body).unwrap().contains("must-not-echo"));

            let initialize = IncomingRequest {
                target: "/v1/initialize".to_string(),
                body: serde_json::to_vec(&json!({"user": payload["user"]})).unwrap(),
                ..request
            };
            let (_, body, _, _) = chatgpt_account_sidecar_response(&initialize).unwrap();
            let evaluated: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(evaluated["user"], payload["user"]);
            assert_eq!(evaluated["feature_gates"], json!({}));
        }
    }

    #[test]
    fn desktop_statsig_initialize_projects_only_bounded_identity_fields() {
        let request = IncomingRequest {
            method: "POST".to_string(), target: "/v1/initialize".to_string(),
            http_version: "HTTP/1.1".to_string(), headers: vec![],
            body: serde_json::to_vec(&json!({"user": {
                "userID": "user", "custom": {"auth_method": "chatgpt", "token": "must-not-echo"},
                "customIDs": {"account_id": "account", "workspace_id": "account", "token": "must-not-echo"},
                "privateAttributes": {"secret": "must-not-echo"}
            }})).unwrap(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&request).unwrap();
        assert!(!String::from_utf8(body).unwrap().contains("must-not-echo"));
        let oversized = IncomingRequest {
            body: vec![0; DESKTOP_STATSIG_MAX_REQUEST_BYTES + 1],
            ..request.clone()
        };
        assert!(chatgpt_account_sidecar_response(&oversized).is_none());
        assert_eq!(
            chatgpt_sidecar_response(&oversized).unwrap().status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let get = IncomingRequest {
            method: "GET".to_string(),
            ..request
        };
        assert!(chatgpt_account_sidecar_response(&get).is_none());
        assert_eq!(
            chatgpt_sidecar_response(&get).unwrap().status,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn desktop_statsig_encoded_initialize_retains_the_sdk_identity() {
        let user = json!({"userID": "encoded-user", "custom": {"auth_method": "chatgpt"},
            "customIDs": {"account_id": "encoded-account", "workspace_id": "encoded-account", "stableID": "encoded-stable"}});
        let body = serde_json::to_vec(&json!({"user": user,
            "statsigMetadata": {"private": "must-not-echo"}}))
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        let request = IncomingRequest {
            method: "POST".to_string(),
            target: "/v1/initialize?k=fixture&se=1&sv=3.34.0".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: encoded.bytes().rev().collect(),
        };
        let (_, body, _, _) = chatgpt_account_sidecar_response(&request).unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["user"], user);
        assert_eq!(payload["feature_gates"], json!({}));
        assert!(!String::from_utf8(body).unwrap().contains("must-not-echo"));
        for target in [
            "/v1/initialize?se=2",
            "/v1/initialize?se=1&se=1",
            "/v1/initialize",
        ] {
            let invalid = IncomingRequest {
                target: target.to_string(),
                ..request.clone()
            };
            assert!(desktop_statsig_request(&invalid).is_none());
        }
        let invalid = IncomingRequest {
            body: b"invalid-base64".to_vec(),
            ..request
        };
        assert!(desktop_statsig_request(&invalid).is_none());
    }

    #[test]
    fn serves_only_bounded_post_statsig_initialize_requests_locally() {
        let request = IncomingRequest {
            method: "POST".to_string(),
            target: "/v1/initialize?k=client-test".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer ignored".to_string())],
            body: br#"{"statsigMetadata":{"sdkType":"javascript-client"}}"#.to_vec(),
        };
        let response = chatgpt_sidecar_response(&request).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.reason, "desktop_statsig_i18n_bootstrap");
        let payload: Value = serde_json::from_slice(response.body).unwrap();
        assert_eq!(
            payload["layer_configs"]["72216192"]["value"]["enable_i18n"],
            true
        );

        let get = IncomingRequest {
            method: "GET".to_string(),
            ..request.clone()
        };
        let response = chatgpt_sidecar_response(&get).unwrap();
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);

        let oversized = IncomingRequest {
            body: vec![0; DESKTOP_STATSIG_MAX_REQUEST_BYTES + 1],
            ..request
        };
        let response = chatgpt_sidecar_response(&oversized).unwrap();
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn openai_websocket_preserves_duplicate_headers_and_query_on_wire() {
        struct CaptureHandshake(
            tokio::sync::oneshot::Sender<tungstenite::handshake::server::Request>,
        );

        impl tungstenite::handshake::server::Callback for CaptureHandshake {
            fn on_request(
                self,
                request: &tungstenite::handshake::server::Request,
                response: tungstenite::handshake::server::Response,
            ) -> Result<
                tungstenite::handshake::server::Response,
                tungstenite::handshake::server::ErrorResponse,
            > {
                self.0.send(request.clone()).unwrap();
                Ok(response)
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "ws://{}/v1/responses?future=a%2Fb&future=a+b",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _websocket =
                tokio_tungstenite::accept_hdr_async(stream, CaptureHandshake(captured_tx))
                    .await
                    .unwrap();
        });
        let incoming = vec![
            ("User-Agent".into(), "codex_vscode/0.159.2".into()),
            ("Originator".into(), "codex_vscode".into()),
            ("Version".into(), "0.159.2".into()),
            ("OpenAI-Beta".into(), "responses=mock_native".into()),
            ("X-Codex-Future-Control".into(), "first".into()),
            ("x-codex-future-control".into(), "second".into()),
            ("Cookie".into(), "MOCK_ONLY_PRIVATE_COOKIE".into()),
            ("Authorization".into(), "Bearer MOCK_ONLY_CLIENT".into()),
            ("Connection".into(), "Upgrade, X-Mock-Hop".into()),
            ("X-Mock-Hop".into(), "MOCK_ONLY_HOP".into()),
            (
                "Sec-WebSocket-Extensions".into(),
                "permessage-deflate".into(),
            ),
        ];
        let request = build_openai_websocket_request(&url, &incoming, "MOCK_ONLY_GATEWAY").unwrap();
        let (client, _) = connect_async(request).await.unwrap();
        let outgoing = timeout(Duration::from_secs(3), captured_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outgoing.uri().path_and_query().unwrap().as_str(),
            "/v1/responses?future=a%2Fb&future=a+b"
        );
        let headers = outgoing.headers();
        assert_eq!(
            headers
                .get_all("x-codex-future-control")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        for name in ["User-Agent", "Originator", "Version", "OpenAI-Beta"] {
            assert_eq!(
                headers.get(name).unwrap().to_str().unwrap(),
                header_value(&incoming, name).unwrap()
            );
        }
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer MOCK_ONLY_GATEWAY"
        );
        assert!(headers.get("cookie").is_none());
        assert!(headers.get("sec-websocket-extensions").is_none());
        assert!(headers.get("x-mock-hop").is_none());
        drop(client);
        server.await.unwrap();
    }

    #[test]
    fn detects_openai_websocket_handshake() {
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: "/v1/responses".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Connection".to_string(), "Upgrade".to_string()),
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Sec-WebSocket-Key".to_string(), "key".to_string()),
            ],
            body: Vec::new(),
        };
        assert!(is_websocket_upgrade(&request));
    }

    #[test]
    fn chat_preference_applies_only_to_unconfigured_new_chat_initialization() {
        let request = IncomingRequest {
            method: "POST".into(),
            target: "/chatgpt/backend-api/conversation/init".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            body: br#"{ "requested_default_model":null,"conversation_origin":null }"#.to_vec(),
        };
        assert!(is_fresh_chat_init(&request));
        for body in [
            json!({"conversation_id":"MOCK_EXISTING_CHAT"}),
            json!({"conversation_origin":"tpp"}),
            json!({"conversation_origin":"flora"}),
            json!({"gizmo_id":"MOCK_CUSTOM_GPT"}),
            json!({"requested_default_model":"gpt-6-pro"}),
            json!({"model":"gpt-6-pro"}),
            json!({"messages":[]}),
            json!({"input":"MOCK_MODEL_REQUEST"}),
            json!({"system_hints":["MOCK_MODEL_POLICY"]}),
        ] {
            assert!(!is_fresh_chat_init(&IncomingRequest {
                body: serde_json::to_vec(&body).unwrap(),
                ..request.clone()
            }));
        }
        for target in [
            "/v1/responses",
            "/chatgpt/backend-api/f/conversation",
            "/chatgpt/backend-api/models",
        ] {
            assert!(!is_fresh_chat_init(&IncomingRequest {
                target: target.into(),
                ..request.clone()
            }));
        }
    }

    #[test]
    fn saved_chat_preference_is_bounded_and_never_written() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".codex-global-state.json");
        let body = br#"{"electron-persisted-atom-state":{"chatgpt-last-selected-model-v1":{"slug":"gpt-5-6-thinking","thinkingEffort":"extended","versionId":"MOCK_VERSION"}},"unrelated":"MOCK_KEEP"}"#;
        fs::write(&path, body).unwrap();
        assert_eq!(
            saved_chat_model_at(&path).as_deref(),
            Some("gpt-5-6-thinking")
        );
        assert_eq!(fs::read(&path).unwrap(), body);
        for body in [br#"{"slug":"gpt-6"}"#.as_slice(),b"invalid JSON",br#"{"electron-persisted-atom-state":{"chatgpt-last-selected-model-v1":{"slug":"auto"}}}"#] {
            fs::write(&path,body).unwrap();assert!(saved_chat_model_at(&path).is_none());
        }
        fs::write(&path, vec![b' '; MAX_DESKTOP_STATE_BYTES as usize + 1]).unwrap();
        assert!(saved_chat_model_at(&path).is_none());
    }

    async fn chat_init_wire(
        status: StatusCode,
        content_type: &str,
        encoding: Option<&str>,
        body: Vec<u8>,
    ) -> (String, Vec<u8>) {
        let mut response = tungstenite::http::Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("x-mock-upstream", "keep")
            .header("etag", "MOCK_ORIGINAL");
        if let Some(value) = encoding {
            response = response.header("content-encoding", value);
        }
        let response: reqwest::Response = response.body(body.clone()).unwrap().into();
        let (mut writer, mut reader) = tokio::io::duplex(body.len() + 8192);
        write_chat_init_response(&mut writer, response, true)
            .await
            .unwrap();
        drop(writer);
        let mut raw = Vec::new();
        reader.read_to_end(&mut raw).await.unwrap();
        let split = raw.windows(4).position(|s| s == b"\r\n\r\n").unwrap();
        let headers = String::from_utf8(raw[..split].to_vec()).unwrap();
        let mut chunked = BufReader::new(&raw[split + 4..]);
        let decoded = read_chunked_body(&mut chunked).await.unwrap();
        (headers, decoded)
    }

    #[tokio::test]
    async fn native_chat_initialization_retains_limits_and_only_withholds_account_defaults() {
        let body = json!({"default_model_slug":"gpt-6-pro","intended_default_model_slug":"gpt-6-pro",
            "type":"conversation_detail_metadata","model_limits":[],
            "blocked_features":[{"name":"image_gen","remaining":0}],
            "limits_progress":[{"feature_name":"image_gen","remaining":0}],
            "file_attachment_limits":{"max_count_per_turn":20},"future":"MOCK_KEEP"});
        let (headers, actual) = chat_init_wire(
            StatusCode::OK,
            "application/json",
            None,
            serde_json::to_vec(&body).unwrap(),
        )
        .await;
        let mut expected = body;
        expected
            .as_object_mut()
            .unwrap()
            .remove("default_model_slug");
        expected
            .as_object_mut()
            .unwrap()
            .remove("intended_default_model_slug");
        assert_eq!(serde_json::from_slice::<Value>(&actual).unwrap(), expected);
        assert!(headers.contains("x-saiai-chat-preference-restored: 1"));
        assert!(headers.contains("x-mock-upstream: keep"));
        assert!(!headers.contains("etag:"));
    }

    #[tokio::test]
    async fn native_chat_errors_quota_encoding_unknown_and_oversized_responses_pass_through() {
        for (status,kind,encoding,body) in [
            (StatusCode::FORBIDDEN,"text/html",None,b"MOCK_UPSTREAM_403".to_vec()),
            (StatusCode::OK,"application/json",Some("gzip"),b"MOCK_ENCODED_BYTES".to_vec()),
            (StatusCode::OK,"application/json",None,br#"{ "model_limits":[{"model_slug":"gpt-5-6-thinking","using_default_model_slug":"gpt-6-pro"}],"default_model_slug":"gpt-6-pro" }"#.to_vec()),
            (StatusCode::OK,"application/json",None,b"MOCK_FUTURE_FORMAT".to_vec()),
            (StatusCode::OK,"application/json",None,vec![b' ';MAX_CHAT_INIT_RESPONSE_BYTES+1]),
        ] {
            let (headers,actual)=chat_init_wire(status,kind,encoding,body.clone()).await;
            assert_eq!(actual,body);assert!(!headers.contains("x-saiai-chat-preference-restored"));
            assert!(headers.contains("etag: MOCK_ORIGINAL"));
        }
    }

    #[tokio::test]
    async fn native_chat_preference_keeps_original_initialization_request_on_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let captured = read_http_request(&mut reader).await.unwrap();
            let body=br#"{"default_model_slug":"gpt-6-pro","intended_default_model_slug":"gpt-6-pro","file_attachment_limits":{"max_count_per_turn":20}}"#;
            reader.get_mut().write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
            reader.get_mut().write_all(body).await.unwrap();
            captured
        });
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let state = State::new(Config {
            listen: "127.0.0.1:0".into(),
            base_url,
            api_key: "MOCK_ONLY_GATEWAY".into(),
            claude: None,
            codex: None,
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
            chatgpt_chat_passthrough: true,
        })
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".codex-global-state.json");
        let preferences=br#"{"electron-persisted-atom-state":{"chatgpt-last-selected-model-v1":{"slug":"gpt-5-6-thinking","thinkingEffort":"extended"}}}"#;
        fs::write(&path, preferences).unwrap();
        let body=br#"{ "conversation_origin":null, "requested_default_model":null,"timezone":"MOCK_ZONE","timezone_offset_min":0 }"#.to_vec();
        let target = "/chatgpt/backend-api/conversation/init?future=a%2Fb&future=a+b";
        let request = IncomingRequest {
            method: "POST".into(),
            target: target.into(),
            http_version: "HTTP/1.1".into(),
            body: body.clone(),
            headers: vec![
                ("User-Agent".into(), "MOCK_DESKTOP".into()),
                ("X-Desktop-Future".into(), "first".into()),
                ("x-desktop-future".into(), "second".into()),
                ("Authorization".into(), "Bearer MOCK_CLIENT".into()),
            ],
        };
        let (mut writer, mut output) = tokio::io::duplex(16384);
        forward_to_saiai_with_preferences_path(
            &state,
            &mut writer,
            request,
            true,
            true,
            Some(&path),
        )
        .await
        .unwrap();
        drop(writer);
        let mut response = Vec::new();
        output.read_to_end(&mut response).await.unwrap();
        let captured = server.await.unwrap();
        assert_eq!(captured.body, body);
        assert_eq!(captured.target, target);
        assert_eq!(
            header_value(&captured.headers, "user-agent"),
            Some("MOCK_DESKTOP")
        );
        assert_eq!(
            captured
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("x-desktop-future"))
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            header_value(&captured.headers, "authorization"),
            Some("Bearer MOCK_ONLY_GATEWAY")
        );
        assert_eq!(fs::read(path).unwrap(), preferences);
        let split = response.windows(4).position(|s| s == b"\r\n\r\n").unwrap();
        assert!(
            String::from_utf8_lossy(&response[..split])
                .contains("x-saiai-chat-preference-restored: 1")
        );
        let mut reader = BufReader::new(&response[split + 4..]);
        assert_eq!(
            serde_json::from_slice::<Value>(&read_chunked_body(&mut reader).await.unwrap())
                .unwrap(),
            json!({"file_attachment_limits":{"max_count_per_turn":20}})
        );
    }

    #[tokio::test]
    async fn openai_http_keeps_body_and_application_headers_and_removes_nominated_hops() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let request = read_http_request(&mut reader).await.unwrap();
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
            request
        });
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let state = State::new(Config {
            listen: "127.0.0.1:0".into(),
            base_url,
            api_key: "MOCK_ONLY_GATEWAY".into(),
            claude: None,
            codex: None,
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
            chatgpt_chat_passthrough: false,
        })
        .unwrap();
        let body = b"{ \"model\":\"mock_native\",\"reasoning\":{\"effort\":\"high\"},\"future\":[null,true] }".to_vec();
        let request = IncomingRequest {
            method: "POST".into(),
            target: "/v1/responses?future=a%2Fb&future=a+b".into(),
            http_version: "HTTP/1.1".into(),
            body: body.clone(),
            headers: vec![
                ("User-Agent".into(), "codex_cli_rs/0.159.2".into()),
                ("X-Codex-Future".into(), "first".into()),
                ("x-codex-future".into(), "second".into()),
                ("Connection".into(), "keep-alive, X-Mock-Hop".into()),
                ("connection".into(), "X-Other-Hop".into()),
                ("x-mock-hop".into(), "MOCK_HOP".into()),
                ("X-Other-Hop".into(), "MOCK_OTHER_HOP".into()),
                ("Authorization".into(), "Bearer MOCK_ONLY_CLIENT".into()),
                ("Cookie".into(), "MOCK_PRIVATE_COOKIE".into()),
            ],
        };
        let (mut writer, mut output) = tokio::io::duplex(16_384);
        forward_to_saiai(&state, &mut writer, request, true, true)
            .await
            .unwrap();
        drop(writer);
        let mut response = Vec::new();
        output.read_to_end(&mut response).await.unwrap();
        let captured = server.await.unwrap();
        assert_eq!(captured.body, body);
        assert_eq!(captured.target, "/v1/responses?future=a%2Fb&future=a+b");
        assert_eq!(
            header_value(&captured.headers, "authorization").unwrap(),
            "Bearer MOCK_ONLY_GATEWAY"
        );
        assert_eq!(
            captured
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-codex-future"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        for name in ["cookie", "x-mock-hop", "x-other-hop", "connection"] {
            assert!(
                header_value(&captured.headers, name).is_none(),
                "unexpected hop or credential: {name}"
            );
        }
        assert!(
            String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
    }

    #[tokio::test]
    async fn native_chat_upload_wire_keeps_binary_json_headers_and_queries_without_tracing_capabilities()
     {
        for path in [
            "/backend-api/files",
            "/backend-api/files/process_upload_stream",
            "/backend-api/estuary/upload_content_bytes",
            "/api/estuary/upload_content_bytes",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let request = read_http_request(&mut reader).await.unwrap();
                reader
                    .get_mut()
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .await
                    .unwrap();
                request
            });
            let (ca_cert_pem, ca_key_pem) = test_ca();
            let mut state = State::new(Config {
                listen: "127.0.0.1:0".into(),
                base_url,
                api_key: "MOCK_ONLY_GATEWAY".into(),
                claude: None,
                codex: None,
                ca_cert_pem,
                ca_key_pem,
                verbose: false,
                chatgpt_chat_passthrough: true,
            })
            .unwrap();
            let trace = tempfile::NamedTempFile::new().unwrap();
            state.openai_trace = Some(Arc::new(OpenAITrace {
                file: Mutex::new(trace.reopen().unwrap()),
            }));
            let target = format!("{path}?upload_url=MOCK_ONLY_CAPABILITY&future=a%2Fb&future=a+b");
            let normalized = normalize_chatgpt_chat_target(&target).unwrap();
            assert_eq!(normalized, format!("/chatgpt{target}"));
            assert!(is_forwarded_chatgpt_path(
                &request_path(&normalized).unwrap()
            ));
            let multipart = path.contains("estuary");
            let body = if multipart {
                b"--MOCK_ONLY_BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"MOCK_ONLY.png\"\r\n\r\nPNG\0\xff\r\n--MOCK_ONLY_BOUNDARY--\r\n".to_vec()
            } else {
                b"{ \"file_id\":\"file-MOCK_ONLY\",\"future\":[true,null] }".to_vec()
            };
            let content_type = if multipart {
                "multipart/form-data; boundary=MOCK_ONLY_BOUNDARY"
            } else {
                "application/json"
            };
            let request = IncomingRequest {
                method: "POST".into(),
                target: normalized.clone(),
                http_version: "HTTP/1.1".into(),
                body: body.clone(),
                headers: vec![
                    ("Content-Type".into(), content_type.into()),
                    ("X-Upload-Future".into(), "first".into()),
                    ("x-upload-future".into(), "second".into()),
                    ("Authorization".into(), "Bearer MOCK_ONLY_CLIENT".into()),
                    ("Cookie".into(), "MOCK_ONLY_COOKIE".into()),
                ],
            };
            state.trace_openai_request("request", "to_gateway", &request);
            let (mut writer, mut output) = tokio::io::duplex(16384);
            forward_to_saiai(&state, &mut writer, request, true, true)
                .await
                .unwrap();
            drop(writer);
            let mut response = Vec::new();
            output.read_to_end(&mut response).await.unwrap();
            let captured = server.await.unwrap();
            assert_eq!(captured.method, "POST");
            assert_eq!(captured.target, normalized);
            assert_eq!(captured.body, body);
            assert_eq!(
                header_value(&captured.headers, "content-type"),
                Some(content_type)
            );
            assert_eq!(
                header_value(&captured.headers, "authorization"),
                Some("Bearer MOCK_ONLY_GATEWAY")
            );
            assert!(header_value(&captured.headers, "cookie").is_none());
            assert_eq!(
                captured
                    .headers
                    .iter()
                    .filter(|(n, _)| n.eq_ignore_ascii_case("x-upload-future"))
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>(),
                vec!["first", "second"]
            );
            let evidence = fs::read_to_string(trace.path()).unwrap();
            assert!(!evidence.contains("MOCK_ONLY_CAPABILITY"));
            assert!(!evidence.contains("MOCK_ONLY.png"));
            let evidence: Value = serde_json::from_str(evidence.trim()).unwrap();
            assert_eq!(evidence["bytes"], body.len());
            assert!(evidence.get("body").is_none());
            assert!(evidence.get("headers").is_none());
        }
        for path in [
            "/backend-api/files/admin",
            "/api/estuary/other",
            "/backend-api/files/upload_reservations",
        ] {
            assert!(normalize_chatgpt_chat_target(path).is_err());
        }
    }

    #[tokio::test]
    async fn ordinary_chat_model_catalog_preserves_native_query_and_response_on_wire() {
        for (target, payload) in [
            (
                "/backend-api/models?language=zh-CN&x=a%2Bb&x=c",
                br#"{ "models":[{"slug":"auto","title":"Automatic"}], "future":{"enabled":true} }"#
                    .as_slice(),
            ),
            (
                "/backend-api/ios/attestation_challenge?x=a%2Fb&x=a+b",
                br#"{ "attestation_challenge":"MOCK_ONLY_CHALLENGE", "future":null }"#.as_slice(),
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let catalog = payload;
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let request = read_http_request(&mut reader).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    catalog.len()
                );
                reader
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
                reader.get_mut().write_all(catalog).await.unwrap();
                request
            });
            let (ca_cert_pem, ca_key_pem) = test_ca();
            let state = State::new(Config {
                listen: "127.0.0.1:0".into(),
                base_url,
                api_key: "MOCK_ONLY_GATEWAY".into(),
                claude: None,
                codex: None,
                ca_cert_pem,
                ca_key_pem,
                verbose: false,
                chatgpt_chat_passthrough: true,
            })
            .unwrap();
            let request = IncomingRequest {
                method: "GET".into(),
                target: normalize_chatgpt_chat_target(target).unwrap(),
                http_version: "HTTP/1.1".into(),
                headers: vec![
                    ("Accept".into(), "application/json".into()),
                    ("X-OpenAI-Devicecheck".into(), "MOCK_ONLY_FIRST".into()),
                    ("X-OpenAI-Devicecheck".into(), "MOCK_ONLY_SECOND".into()),
                ],
                body: Vec::new(),
            };
            let (mut writer, mut output) = tokio::io::duplex(16_384);
            forward_to_saiai(&state, &mut writer, request, true, true)
                .await
                .unwrap();
            drop(writer);
            let mut response = Vec::new();
            output.read_to_end(&mut response).await.unwrap();
            let captured = server.await.unwrap();
            assert_eq!(captured.method, "GET");
            assert_eq!(captured.target, format!("/chatgpt{target}"));
            assert_eq!(
                captured
                    .headers
                    .iter()
                    .filter(|(key, _)| key.eq_ignore_ascii_case("X-OpenAI-Devicecheck"))
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>(),
                vec!["MOCK_ONLY_FIRST", "MOCK_ONLY_SECOND"]
            );
            assert!(captured.body.is_empty());
            assert!(
                response
                    .windows(catalog.len())
                    .any(|bytes| bytes == catalog)
            );
        }
    }

    #[test]
    fn openai_websocket_response_keeps_application_headers_and_duplicate_values() {
        let mut headers = tungstenite::http::HeaderMap::new();
        headers.append("x-codex-future", "first".parse().unwrap());
        headers.append("x-codex-future", "second".parse().unwrap());
        headers.insert("x-codex-turn-state", "mock_state".parse().unwrap());
        headers.insert("sec-websocket-protocol", "mock_protocol".parse().unwrap());
        headers.insert("connection", "upgrade, x-mock-hop".parse().unwrap());
        for name in [
            "x-mock-hop",
            "authorization",
            "set-cookie",
            "chatgpt-account-id",
            "content-length",
            "sec-websocket-extensions",
            "sec-websocket-accept",
        ] {
            headers.insert(name, "private_value".parse().unwrap());
        }
        let wire = build_openai_websocket_response("mock_client_accept", &headers);
        let wire = String::from_utf8(wire).unwrap();
        assert!(wire.contains("x-codex-future: first\r\nx-codex-future: second\r\n"));
        assert!(wire.contains("x-codex-turn-state: mock_state\r\n"));
        assert!(wire.contains("sec-websocket-protocol: mock_protocol\r\n"));
        assert!(wire.contains("Sec-WebSocket-Accept: mock_client_accept\r\n"));
        assert!(!wire.contains("private_value"));
    }

    #[tokio::test]
    async fn restarted_proxy_preserves_leaf_pin_and_valid_tls_without_extra_key_files() {
        ensure_rustls_crypto_provider();
        let (ca_pem, key_pem) = test_ca();
        let ca_der = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der.clone()).unwrap();
        let client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client);
        let mut prior_pin = None;
        for _ in 0..2 {
            // A fresh server config represents a restarted service. The
            // launched Desktop pin must still match its domain's leaf key.
            let certificate =
                build_leaf_server_config(CHAT_OPENAI_HOST, &ca_pem, &key_pem).unwrap();
            if let Some(pin) = &prior_pin {
                assert_eq!(pin, &certificate.spki_sha256);
            }
            prior_pin = Some(certificate.spki_sha256);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = TlsAcceptor::from(certificate.config);
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(socket).await.unwrap();
                tls.write_all(b"OK").await.unwrap();
                tls.shutdown().await.unwrap();
            });
            let mut tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from(CHAT_OPENAI_HOST).unwrap(),
                    TcpStream::connect(address).await.unwrap(),
                )
                .await
                .unwrap();
            let chain = tls.get_ref().1.peer_certificates().unwrap();
            assert_eq!(chain.len(), 1, "only the pinned leaf is sent");
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"OK");
            server.await.unwrap();
        }
    }

    #[test]
    fn builds_tls_config_with_explicit_crypto_provider() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let cfg = Config {
            listen: "127.0.0.1:0".to_string(),
            base_url: "https://api.saiai.top".to_string(),
            api_key: "sk-test".to_string(),
            claude: Some(RouteConfig {
                base_url: "https://claude.example.test".to_string(),
                api_key: "claude-key".to_string(),
            }),
            codex: Some(RouteConfig {
                base_url: "https://codex.example.test".to_string(),
                api_key: "codex-key".to_string(),
            }),
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
            chatgpt_chat_passthrough: true,
        };
        let state = State::new(cfg.clone()).unwrap();

        let config = state.tls_config_for_host(ANTHROPIC_HOST).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let first = state.tls_spki_for_host(CHATGPT_HOST).unwrap();
        let second = state.tls_spki_for_host(CHATGPT_HOST).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(first)
                .unwrap()
                .len(),
            32
        );
        let desktop_pins = state.desktop_tls_spki_list().unwrap();
        let decoded_pins = desktop_pins
            .split(',')
            .map(|pin| {
                base64::engine::general_purpose::STANDARD
                    .decode(pin)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(decoded_pins.len(), 4);
        assert!(decoded_pins.iter().all(|pin| pin.len() == 32));
        assert_eq!(
            decoded_pins
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4
        );
        let restarted = State::new(cfg.clone()).unwrap();
        assert_eq!(desktop_pins, restarted.desktop_tls_spki_list().unwrap());
        for host in [
            OPENAI_HOST,
            CHATGPT_HOST,
            CHAT_OPENAI_HOST,
            CHATGPT_AUX_HOST,
        ] {
            assert_eq!(
                state.tls_spki_for_host(host).unwrap(),
                restarted.tls_spki_for_host(host).unwrap()
            );
        }
        let (rotated_cert, rotated_key) = test_ca();
        let rotated = State::new(Config {
            ca_cert_pem: rotated_cert,
            ca_key_pem: rotated_key,
            ..cfg
        })
        .unwrap();
        assert_ne!(desktop_pins, rotated.desktop_tls_spki_list().unwrap());
        assert_eq!(
            state.route_for_host(ANTHROPIC_HOST).base_url,
            "https://claude.example.test"
        );
        assert_eq!(
            state.route_for_host(ANTHROPIC_HOST).api_key.as_str(),
            "claude-key"
        );
        assert_eq!(
            state.route_for_host(OPENAI_HOST).base_url,
            "https://codex.example.test"
        );
        assert_eq!(
            state.route_for_host(CHATGPT_HOST).api_key.as_str(),
            "codex-key"
        );
        assert_eq!(
            state.route_for_host(CHAT_OPENAI_HOST).api_key.as_str(),
            "codex-key"
        );
        assert_eq!(
            state.route_for_host(CHATGPT_AUX_HOST).api_key.as_str(),
            "codex-key"
        );
    }

    #[test]
    fn treats_direct_tunnel_peer_closes_as_benign() {
        let reset = anyhow::anyhow!(
            "direct tunnel copy failed for www.google-analytics.com:443: Connection reset by peer (os error 104)"
        );
        assert!(is_benign_client_error(&reset));

        let broken_pipe = anyhow::anyhow!(
            "direct tunnel copy failed for example.com:443: Broken pipe (os error 32)"
        );
        assert!(is_benign_client_error(&broken_pipe));
    }

    #[test]
    fn treats_client_stream_disconnects_as_benign() {
        let err = anyhow::anyhow!(
            "response phase failed forwarding POST /v1/messages?beta=true: client disconnected while streaming upstream response after 4096 response bytes in 2 chunk(s): Broken pipe"
        );
        assert!(is_benign_client_error(&err));
    }

    #[test]
    fn detects_idle_http_connection_end() {
        let closed = anyhow::anyhow!("idle HTTP connection closed before request line");
        assert!(is_idle_http_connection_end(&closed));

        let timed_out = anyhow::anyhow!(
            "idle HTTP connection timed out before request line: deadline has elapsed"
        );
        assert!(is_idle_http_connection_end(&timed_out));
        let partial = anyhow::anyhow!("timed out reading HTTP request line: deadline has elapsed");
        assert!(!is_idle_http_connection_end(&partial));
        assert!(!is_benign_client_error(&partial));
        let headers = anyhow::anyhow!("connection closed while reading header line");
        assert!(!is_benign_client_error(&headers));
    }

    #[tokio::test]
    async fn distinguishes_empty_preconnections_from_partial_request_uploads() {
        let (mut sender, receiver) = tokio::io::duplex(256);
        let mut reader = BufReader::new(receiver);
        let idle = read_http_request_line(&mut reader, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(is_benign_client_error(&idle));
        sender.write_all(b"POST ").await.unwrap();
        let partial = read_http_request_line(&mut reader, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(!is_benign_client_error(&partial));

        let (sender, receiver) = tokio::io::duplex(256);
        drop(sender);
        let empty_eof = read_http_request(&mut BufReader::new(receiver))
            .await
            .unwrap_err();
        assert!(is_benign_client_error(&empty_eof));
        let mut partial_headers =
            &b"POST /backend-api/f/conversation HTTP/1.1\r\nHost: chatgpt.com\r\n"[..];
        let partial_eof = read_http_request(&mut partial_headers).await.unwrap_err();
        assert!(!is_benign_client_error(&partial_eof));
    }

    #[test]
    fn treats_windows_direct_tunnel_shutdowns_as_benign_by_error_kind() {
        for kind in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
        ] {
            let err = anyhow::Error::from(std::io::Error::new(kind, "localized Windows close"))
                .context("direct tunnel copy failed for example.test:443");
            assert!(is_benign_client_error(&err));
        }
        let active_upload = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "localized Windows close",
        ))
        .context("failed to read request body");
        assert!(!is_benign_client_error(&active_upload));
    }

    #[test]
    fn quiets_only_peer_closed_tls_preconnections_and_keeps_certificate_errors() {
        for kind in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = anyhow::Error::from(std::io::Error::new(kind, "localized peer close"))
                .context("client TLS handshake failed for chatgpt.com");
            assert!(is_benign_client_error(&error));
            for phase in [
                "failed to read request body",
                "failed to read header line",
                "failed to read upstream response",
                "upstream TLS handshake failed",
            ] {
                let error = anyhow::Error::from(std::io::Error::new(kind, "localized peer close"))
                    .context(phase);
                assert!(!is_benign_client_error(&error), "{phase}");
            }
        }
        let certificate = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::CertificateUnknown),
        ))
        .context("client TLS handshake failed for chat.openai.com");
        assert!(!is_benign_client_error(&certificate));
    }

    #[tokio::test]
    async fn quiets_zero_byte_peer_resets_but_reports_partial_http_requests() {
        struct ClosingReader {
            remaining: &'static [u8],
            kind: std::io::ErrorKind,
        }
        impl tokio::io::AsyncRead for ClosingReader {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.remaining.is_empty() {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        self.kind,
                        "localized peer close",
                    )));
                }
                let n = self.remaining.len().min(buffer.remaining());
                buffer.put_slice(&self.remaining[..n]);
                self.remaining = &self.remaining[n..];
                std::task::Poll::Ready(Ok(()))
            }
        }
        for kind in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
        ] {
            for bytes in [
                &b""[..],
                &b"POST "[..],
                &b"POST /backend-api/f/conversation HTTP/1.1\r\nHost: chatgpt.com"[..],
                &b"POST /backend-api/f/conversation HTTP/1.1\r\nContent-Length: 2\r\n\r\nx"[..],
            ] {
                let reader = ClosingReader {
                    remaining: bytes,
                    kind,
                };
                let error = read_http_request(&mut BufReader::new(reader))
                    .await
                    .unwrap_err();
                assert_eq!(is_benign_client_error(&error), bytes.is_empty());
                assert_eq!(is_idle_http_connection_end(&error), bytes.is_empty());
            }
        }
    }

    #[test]
    fn acknowledges_only_exact_background_stats_and_metrics_posts() {
        for path in ["/ces/statsc/flush", "/otlp/v1/metrics"] {
            for content_type in ["application/json", "application/x-protobuf"] {
                let mut request = IncomingRequest {
                    method: "POST".to_string(),
                    target: path.to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    headers: vec![("content-type".to_string(), content_type.to_string())],
                    body: b"TEST_ONLY_BACKGROUND_BYTES".to_vec(),
                };
                let response = chatgpt_sidecar_response(&request).unwrap();
                assert!(response.status.is_success());
                if path == "/ces/statsc/flush" {
                    // Desktop 26.1002 parses the JSON and requires success=true;
                    // an empty 204 increments its lost-metrics/retry counters.
                    assert_eq!(response.status, StatusCode::OK);
                    let body: Value = serde_json::from_slice(response.body).unwrap();
                    assert_eq!(body["success"], true);
                }
                if path == "/otlp/v1/metrics" {
                    assert_eq!(response.content_type, content_type);
                    assert_eq!(
                        response.body,
                        if content_type == "application/json" {
                            &b"{}"[..]
                        } else {
                            &b""[..]
                        }
                    );
                }
                request.method = "GET".to_string();
                assert!(chatgpt_sidecar_response(&request).is_none());
                request.method = "POST".to_string();
                request.target.push_str("/other");
                assert!(chatgpt_sidecar_response(&request).is_none());
            }
        }
    }

    #[test]
    fn keeps_direct_tunnel_setup_failures_visible() {
        let dns = anyhow::anyhow!(
            "failed to open direct tunnel to example.invalid:443 for local client 127.0.0.1:12345: failed to resolve example.invalid:443"
        );
        assert!(!is_benign_client_error(&dns));
    }

    #[test]
    fn splits_connect_authority() {
        assert_eq!(
            split_host_port("api.anthropic.com:443").unwrap(),
            ("api.anthropic.com".to_string(), 443)
        );
        assert_eq!(
            split_host_port("[::1]:443").unwrap(),
            ("::1".to_string(), 443)
        );
        assert_eq!(
            split_host_port("git.example.test:22").unwrap(),
            ("git.example.test".to_string(), 22)
        );
    }

    #[test]
    fn accepts_absolute_form_http_proxy_requests() {
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: "http://connectivity-check.example.test/generate_204?source=desktop"
                .to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let target = parse_http_proxy_target(&request).unwrap();
        assert_eq!(target.scheme(), "http");
        assert_eq!(target.host_str(), Some("connectivity-check.example.test"));
        assert_eq!(target.path(), "/generate_204");
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_http_proxy_targets() {
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: "https://chatgpt.com/backend-api/wham/accounts/check".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(
            parse_http_proxy_target(&request)
                .unwrap_err()
                .to_string()
                .contains("http scheme")
        );

        let relative = IncomingRequest {
            target: "/generate_204".to_string(),
            ..request.clone()
        };
        assert!(parse_http_proxy_target(&relative).is_err());

        let credentialed = IncomingRequest {
            target: "http://user:password@example.test/".to_string(),
            ..request
        };
        assert!(
            parse_http_proxy_target(&credentialed)
                .unwrap_err()
                .to_string()
                .contains("userinfo")
        );
    }

    #[tokio::test]
    async fn forwards_absolute_form_http_proxy_requests() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /generate_204 HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let (ca_cert_pem, ca_key_pem) = test_ca();
        let state = Arc::new(
            State::new(Config {
                listen: "127.0.0.1:0".to_string(),
                base_url: "https://gateway.example.test".to_string(),
                api_key: "test-key".to_string(),
                claude: None,
                codex: None,
                ca_cert_pem,
                ca_key_pem,
                verbose: false,
                chatgpt_chat_passthrough: false,
            })
            .unwrap(),
        );
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = TcpStream::connect(proxy_addr);
        let server = proxy.accept();
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let (server, _) = server.unwrap();
        let request = IncomingRequest {
            method: "GET".to_string(),
            target: format!("http://127.0.0.1:{upstream_port}/generate_204"),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![
                ("Proxy-Connection".to_string(), "keep-alive".to_string()),
                (
                    "Authorization".to_string(),
                    "Bearer must-not-forward".to_string(),
                ),
                ("Cookie".to_string(), "must-not-forward=1".to_string()),
            ],
            body: Vec::new(),
        };
        let proxy_task = tokio::spawn(serve_http_proxy_request(
            state,
            server,
            request,
            "127.0.0.1:test",
        ));
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        proxy_task.await.unwrap().unwrap();
        upstream_task.await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 204"));
    }

    #[test]
    fn canonical_host_strips_case_brackets_and_trailing_dot() {
        assert_eq!(canonical_host("[API.Anthropic.Com.]"), "api.anthropic.com");
    }

    #[tokio::test]
    async fn direct_tunnel_connects_to_any_target_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (connected, accepted) =
            tokio::join!(connect_direct_target("127.0.0.1", port), listener.accept());

        assert!(connected.is_ok());
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn direct_tunnel_cannot_bypass_anthropic_mitm_route() {
        let error = connect_direct_target(ANTHROPIC_HOST, 443)
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("managed host must use local MITM route")
        );
    }

    #[tokio::test]
    async fn direct_tunnel_cannot_bypass_openai_mitm_route() {
        let error = connect_direct_target(OPENAI_HOST, 443).await.err().unwrap();
        assert!(
            error
                .to_string()
                .contains("managed host must use local MITM route")
        );
    }

    #[test]
    fn rejects_non_loopback_proxy_listener() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let error = State::new(Config {
            listen: "0.0.0.0:19908".to_string(),
            base_url: "https://api.saiai.top".to_string(),
            api_key: "sk-test".to_string(),
            claude: None,
            codex: None,
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
            chatgpt_chat_passthrough: true,
        })
        .err()
        .unwrap();

        assert!(error.to_string().contains("must be loopback-only"));
    }

    #[test]
    fn honors_http_connection_close_rules() {
        assert!(!request_wants_close(&request_with_version_and_connection(
            "HTTP/1.1", None
        )));
        assert!(request_wants_close(&request_with_version_and_connection(
            "HTTP/1.1",
            Some("close")
        )));
        assert!(request_wants_close(&request_with_version_and_connection(
            "HTTP/1.0", None
        )));
        assert!(!request_wants_close(&request_with_version_and_connection(
            "HTTP/1.0",
            Some("keep-alive")
        )));
    }
}
