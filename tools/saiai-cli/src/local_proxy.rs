use anyhow::{Context, Result, bail};
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
use tokio::time::timeout;
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
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HEADER_LINE: usize = 32 * 1024;
const MAX_HEADER_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub base_url: String,
    pub api_key: String,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub verbose: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("listen", &self.listen)
            .field("base_url", &self.base_url)
            .field("api_key", &"[redacted]")
            .field("runtime_ca", &true)
            .field("verbose", &self.verbose)
            .finish()
    }
}

struct State {
    listen: String,
    base_url: String,
    api_key: Zeroizing<String>,
    ca_cert_pem: String,
    ca_key_pem: Zeroizing<String>,
    verbose: bool,
    client: Client,
    certs: Mutex<HashMap<String, Arc<ServerConfig>>>,
    openai_trace: Option<Arc<OpenAITrace>>,
}

struct ParsedConnect {
    host: String,
    port: u16,
}

#[derive(Debug)]
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

pub async fn run(cfg: Config) -> Result<()> {
    let state = Arc::new(State::new(cfg)?);
    let listener = TcpListener::bind(&state.listen)
        .await
        .with_context(|| format!("failed to bind local proxy on {}", state.listen))?;

    eprintln!("saiai local proxy listening on http://{}", state.listen);
    eprintln!(
        "forwarding managed Claude/OpenAI traffic to {}",
        state.base_url
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
        let base = cfg.base_url.trim().trim_end_matches('/').to_string();
        let parsed =
            Url::parse(&base).with_context(|| format!("invalid SAIAI base URL: {base}"))?;
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => bail!("SAIAI base URL must use http or https, got {scheme}"),
        }
        if parsed.host_str().is_none() {
            bail!("SAIAI base URL host is required");
        }
        if cfg.api_key.trim().is_empty() {
            bail!("SAIAI API key is required");
        }

        build_leaf_server_config(ANTHROPIC_HOST, &cfg.ca_cert_pem, &cfg.ca_key_pem)
            .context("failed to validate installation-specific SAIAI CA")?;

        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .context("failed to build upstream HTTP client")?;
        let openai_trace = OpenAITrace::from_env()?;

        Ok(Self {
            listen: cfg.listen,
            base_url: base,
            api_key: Zeroizing::new(cfg.api_key),
            ca_cert_pem: cfg.ca_cert_pem,
            ca_key_pem: Zeroizing::new(cfg.ca_key_pem),
            verbose: cfg.verbose,
            client,
            certs: Mutex::new(HashMap::new()),
            openai_trace,
        })
    }

    fn tls_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = canonical_host(host);

        {
            let certs = self.lock_cert_cache();
            if let Some(config) = certs.get(&host) {
                return Ok(Arc::clone(config));
            }
        }

        let config = Arc::new(build_leaf_server_config(
            &host,
            &self.ca_cert_pem,
            &self.ca_key_pem,
        )?);
        let mut certs = self.lock_cert_cache();
        let cached = certs.entry(host).or_insert_with(|| Arc::clone(&config));
        Ok(Arc::clone(cached))
    }

    fn upstream_url(&self, target: &str) -> Result<String> {
        let path_query = path_query_from_target(target)?;
        Ok(format!("{}{}", self.base_url, path_query))
    }

    fn websocket_upstream_url(&self, target: &str) -> Result<Url> {
        let mut url = Url::parse(&self.upstream_url(target)?)
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

    fn lock_cert_cache(&self) -> MutexGuard<'_, HashMap<String, Arc<ServerConfig>>> {
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
    message.contains("connection closed while reading header line")
        || message.contains("client disconnected while")
        || is_benign_direct_tunnel_close(&message)
}

fn is_idle_http_connection_end(err: &anyhow::Error) -> bool {
    let message = format!("{err:#}");
    message.contains("connection closed while reading header line")
        || message.contains("timed out reading HTTP request line")
}

fn is_benign_direct_tunnel_close(message: &str) -> bool {
    message.contains("direct tunnel copy failed for ")
        && (message.contains("Connection reset by peer")
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
    let connect = match read_connect_request(&mut reader).await {
        Ok(connect) => connect,
        Err(err) => {
            let _ = write_plain_error(reader.get_mut(), StatusCode::METHOD_NOT_ALLOWED).await;
            return Err(err);
        }
    };

    let mut stream = reader.into_inner();
    if (connect.host == ANTHROPIC_HOST || connect.host == OPENAI_HOST) && connect.port == 443 {
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

async fn read_connect_request<R>(reader: &mut R) -> Result<ParsedConnect>
where
    R: AsyncBufRead + Unpin,
{
    let request_line = read_line_limited(reader).await?;
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || !parts[2].starts_with("HTTP/") {
        bail!("invalid proxy request line");
    }
    if !parts[0].eq_ignore_ascii_case("CONNECT") {
        bail!("only CONNECT proxy requests are supported");
    }
    let (host, port) = split_host_port(parts[1])?;

    let mut header_bytes = request_line.len();
    loop {
        let line = read_line_limited(reader).await?;
        header_bytes += line.len();
        if header_bytes > MAX_HEADER_BYTES {
            bail!("CONNECT headers are too large");
        }
        if is_blank_line(&line) {
            break;
        }
    }

    Ok(ParsedConnect {
        host: canonical_host(&host),
        port,
    })
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
        .context("client TLS handshake failed")?;
    let mut reader = BufReader::new(tls_stream);
    let mut handled_requests = 0usize;

    loop {
        let request = match read_http_request(&mut reader).await {
            Ok(request) => request,
            Err(err) => {
                if handled_requests > 0 && is_idle_http_connection_end(&err) {
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
                return Err(err);
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
        } else if host == OPENAI_HOST {
            state.trace_openai_request(
                if is_websocket_upgrade(&request) {
                    "handshake"
                } else {
                    "request"
                },
                "to_gateway",
                &request,
            );
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

async fn serve_openai_websocket(
    state: Arc<State>,
    mut client_stream: TlsStream<TcpStream>,
    request: IncomingRequest,
) -> Result<()> {
    let sec_key = header_value(&request.headers, "sec-websocket-key")
        .context("OpenAI WebSocket request did not include Sec-WebSocket-Key")?;
    let upstream_url = state.websocket_upstream_url(&request.target)?;
    let mut upstream_request = upstream_url
        .as_str()
        .into_client_request()
        .context("failed to build Gateway WebSocket request")?;

    // Preserve Codex's WebSocket handshake and client metadata while changing
    // only the destination and the Gateway credential. The generated request
    // key is replaced with Codex's key so the client-facing accept value is
    // derived from the exact incoming handshake.
    let upstream_headers = upstream_request.headers_mut();
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("sec-websocket-extensions") {
            // The Rust upstream relay does not enable a compression codec.
            // Do not negotiate permessage-deflate on that leg; otherwise the
            // upstream can send RSV1 frames that the relay cannot decode.
            continue;
        }
        if is_websocket_handshake_header(name)
            || (should_forward_request_header(name) && !name.eq_ignore_ascii_case("authorization"))
        {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid WebSocket header name {name:?}"))?;
            let header_value = HeaderValue::from_str(value)
                .with_context(|| format!("invalid WebSocket header value for {name:?}"))?;
            upstream_headers.insert(header_name, header_value);
        }
    }
    upstream_headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", *state.api_key))
            .context("failed to build Gateway WebSocket authorization")?,
    );
    upstream_headers.insert(
        HeaderName::from_static("host"),
        HeaderValue::from_str(upstream_url.authority())
            .context("invalid Gateway WebSocket host")?,
    );

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
    let negotiated_headers = ["sec-websocket-protocol"]
        .into_iter()
        .filter_map(|name| {
            upstream_response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|value| format!("Sec-WebSocket-Protocol: {value}\r\n"))
        })
        .collect::<String>();
    client_stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n{negotiated_headers}\r\n"
            )
            .as_bytes(),
        )
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

async fn read_http_request<R>(reader: &mut R) -> Result<IncomingRequest>
where
    R: AsyncBufRead + Unpin,
{
    let request_line = timeout(HEADER_READ_TIMEOUT, read_line_limited(reader))
        .await
        .context("timed out reading HTTP request line")??;
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
    let upstream_url = state.upstream_url(&request.target)?;
    let method = Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("unsupported HTTP method {}", request.method))?;
    let mut builder = state.client.request(method, &upstream_url);

    let mut has_authorization = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("authorization") {
            has_authorization = true;
        }
        if should_forward_request_header(name)
            && !(replace_authorization && name.eq_ignore_ascii_case("authorization"))
        {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    if replace_authorization || !has_authorization {
        builder = builder.bearer_auth(&*state.api_key);
    }

    let request_method = request.method.clone();
    let request_target = request.target.clone();
    let request_bytes = request.body.len();
    if state.verbose {
        eprintln!(
            "forward request method={} target={} upstream={} bytes={} close_after={}",
            request_method, request_target, upstream_url, request_bytes, close_after
        );
    } else {
        eprintln!(
            "forward request method={} target={} bytes={}",
            request_method, request_target, request_bytes
        );
    }
    let started = Instant::now();
    let response = builder.body(request.body).send().await.with_context(|| {
        format!(
            "request phase failed forwarding {request_method} {request_target} to {upstream_url}"
        )
    })?;
    let outcome = write_upstream_response(writer, response, close_after)
        .await
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
    if (host == ANTHROPIC_HOST || host == OPENAI_HOST) && port == 443 {
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
) -> Result<ServerConfig> {
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
    let leaf_key = KeyPair::generate().context("failed to generate leaf key")?;
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
    Ok(config)
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
    fn builds_tls_config_with_explicit_crypto_provider() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let state = State::new(Config {
            listen: "127.0.0.1:0".to_string(),
            base_url: "https://api.saiai.top".to_string(),
            api_key: "sk-test".to_string(),
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
        })
        .unwrap();

        let config = state.tls_config_for_host(ANTHROPIC_HOST).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
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
        let closed = anyhow::anyhow!("connection closed while reading header line");
        assert!(is_idle_http_connection_end(&closed));

        let timed_out =
            anyhow::anyhow!("timed out reading HTTP request line: deadline has elapsed");
        assert!(is_idle_http_connection_end(&timed_out));
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
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
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
