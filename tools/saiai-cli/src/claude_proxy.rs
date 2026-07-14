use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use reqwest::{Client, Method, StatusCode};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use url::Url;
use zeroize::Zeroizing;

const ANTHROPIC_HOST: &str = "api.anthropic.com";
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HEADER_LINE: usize = 32 * 1024;
const MAX_HEADER_BYTES: usize = 256 * 1024;

pub struct Config {
    pub listen: String,
    pub base_url: String,
    pub api_key: String,
    pub verbose: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("listen", &self.listen)
            .field("base_url", &self.base_url)
            .field("api_key", &"[redacted]")
            .field("verbose", &self.verbose)
            .finish()
    }
}

impl Config {
    /// Supplies the installation-specific CA required by this proxy instance.
    /// There is deliberately no default or embedded CA construction path.
    pub fn with_runtime_ca(
        self,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> RuntimeConfig {
        RuntimeConfig {
            config: self,
            ca: CaMaterial {
                cert_pem: cert_pem.into(),
                key_pem: Zeroizing::new(key_pem.into()),
            },
            quiet: false,
        }
    }
}

pub struct RuntimeConfig {
    config: Config,
    ca: CaMaterial,
    quiet: bool,
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeConfig")
            .field("config", &self.config)
            .field("runtime_ca", &true)
            .field("quiet", &self.quiet)
            .finish()
    }
}

impl RuntimeConfig {
    /// Suppresses proxy lifecycle, request, and client-error output.
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }
}

struct CaMaterial {
    cert_pem: String,
    key_pem: Zeroizing<String>,
}

struct State {
    listen: String,
    base_url: String,
    api_key: Zeroizing<String>,
    verbose: bool,
    quiet: bool,
    client: Client,
    ca: CaMaterial,
    certs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

/// A fully initialized proxy listener. Binding is separate from serving so a
/// caller can publish the actual address before launching a child process.
pub struct BoundProxy {
    listener: TcpListener,
    local_addr: SocketAddr,
    state: Arc<State>,
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

/// Binds a proxy listener and returns the actual socket address. In
/// particular, `127.0.0.1:0` is resolved before this function returns.
pub async fn bind(cfg: RuntimeConfig) -> Result<BoundProxy> {
    let state = Arc::new(State::new(cfg)?);
    let listener = TcpListener::bind(&state.listen)
        .await
        .with_context(|| format!("failed to bind local proxy on {}", state.listen))?;
    let local_addr = listener
        .local_addr()
        .context("failed to read local proxy listener address")?;
    Ok(BoundProxy {
        listener,
        local_addr,
        state,
    })
}

impl BoundProxy {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves until the caller-controlled shutdown future completes.
    pub async fn run_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        self.serve_until(async {
            shutdown.await;
            Ok(())
        })
        .await
    }

    async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        tokio::pin!(shutdown);
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, remote_addr) =
                        accepted.context("failed to accept local proxy connection")?;
                    let state = Arc::clone(&self.state);
                    clients.spawn(async move {
                        if let Err(err) = handle_client(Arc::clone(&state), stream, remote_addr).await
                            && !state.quiet
                            && (state.verbose || !is_benign_client_error(&err))
                        {
                            eprintln!("local proxy client {} error: {err:#}", remote_addr);
                        }
                    });
                }
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
                result = &mut shutdown => return result,
            }
        }
    }
}

impl State {
    fn new(runtime: RuntimeConfig) -> Result<Self> {
        ensure_rustls_crypto_provider();
        let RuntimeConfig {
            config: cfg,
            ca,
            quiet,
        } = runtime;

        if cfg.listen.trim().is_empty() {
            bail!("local proxy listen address is required");
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

        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .context("failed to build upstream HTTP client")?;
        let initial_tls_config = Arc::new(build_leaf_server_config(
            ANTHROPIC_HOST,
            &ca.cert_pem,
            &ca.key_pem,
        )?);
        let mut certs = HashMap::new();
        certs.insert(ANTHROPIC_HOST.to_string(), initial_tls_config);

        Ok(Self {
            listen: cfg.listen,
            base_url: base,
            api_key: Zeroizing::new(cfg.api_key),
            verbose: cfg.verbose,
            quiet,
            client,
            ca,
            certs: Mutex::new(certs),
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
            &self.ca.cert_pem,
            &self.ca.key_pem,
        )?);
        let mut certs = self.lock_cert_cache();
        let cached = certs.entry(host).or_insert_with(|| Arc::clone(&config));
        Ok(Arc::clone(cached))
    }

    fn upstream_url(&self, target: &str) -> Result<String> {
        let path_query = path_query_from_target(target)?;
        Ok(format!("{}{}", self.base_url, path_query))
    }

    fn lock_cert_cache(&self) -> MutexGuard<'_, HashMap<String, Arc<ServerConfig>>> {
        match self.certs.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                if !self.quiet {
                    eprintln!(
                        "certificate cache lock was poisoned; recovering cached certificates"
                    );
                }
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

pub fn validate_runtime_tls_config(cert_pem: &str, key_pem: &str) -> Result<()> {
    ensure_rustls_crypto_provider();
    build_leaf_server_config(ANTHROPIC_HOST, cert_pem, key_pem)?;
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
    if connect.host == ANTHROPIC_HOST && connect.port == 443 {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .context("failed to acknowledge Anthropic CONNECT")?;
        if state.verbose && !state.quiet {
            eprintln!(
                "mitm accepted host={}:{} remote={}",
                connect.host, connect.port, peer
            );
        }
        serve_anthropic_tls(state, stream).await
    } else {
        serve_direct_tunnel(
            stream,
            &connect.host,
            connect.port,
            &peer,
            state.verbose && !state.quiet,
        )
        .await
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
    if port != 443 {
        write_plain_error(&mut client, StatusCode::FORBIDDEN).await?;
        bail!("direct tunnel rejected host={host}:{port}: only port 443 is allowed");
    }

    let mut upstream = connect_public(host, port).await.with_context(|| {
        format!("failed to open direct tunnel to {host}:{port} for local client {peer}")
    })?;
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

async fn serve_anthropic_tls(state: Arc<State>, stream: TcpStream) -> Result<()> {
    let tls_config = state.tls_config_for_host(ANTHROPIC_HOST)?;
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

        if let Some(resp) = local_sidecar_response(&request) {
            if state.verbose && !state.quiet {
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
                if state.verbose && !state.quiet {
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
                forward_to_saiai(&state, reader.get_mut(), request, close_after).await?;
            }
        }

        if close_after {
            reader
                .get_mut()
                .shutdown()
                .await
                .context("failed to close client TLS session")?;
            return Ok(());
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
        if should_forward_request_header(name) {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    if !has_authorization {
        builder = builder.bearer_auth(state.api_key.as_str());
    }

    let request_method = request.method.clone();
    let request_target = request.target.clone();
    let request_bytes = request.body.len();
    if !state.quiet {
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
    if state.verbose && !state.quiet {
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

async fn connect_public(host: &str, port: u16) -> Result<TcpStream> {
    if host == ANTHROPIC_HOST {
        bail!("Anthropic host must use local MITM route");
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
        if is_forbidden_addr(addr) {
            continue;
        }
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    match last_err {
        Some(err) => Err(err).with_context(|| format!("failed to connect to {host}:{port}")),
        None => bail!("all resolved addresses for {host}:{port} are private or reserved"),
    }
}

fn is_forbidden_addr(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => is_forbidden_ipv4(ip),
        IpAddr::V6(ip) => is_forbidden_ipv6(ip),
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])
        || ip.octets()[0] == 169 && ip.octets()[1] == 254
        || ip.octets()[0] == 198 && (18..=19).contains(&ip.octets()[1])
        || ip.octets()[0] >= 224
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
        || ip.segments()[0] & 0xffc0 == 0xfe80
        || ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
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

    fn test_config() -> Config {
        Config {
            listen: "127.0.0.1:0".to_string(),
            base_url: "https://api.saiai.top".to_string(),
            api_key: "sk-test".to_string(),
            verbose: false,
        }
    }

    fn generate_test_ca(common_name: &str) -> (String, String) {
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        params.distinguished_name = distinguished_name;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn test_runtime_config() -> RuntimeConfig {
        let (cert_pem, key_pem) = generate_test_ca("SAIAI V2 proxy test CA");
        test_config().with_runtime_ca(cert_pem, key_pem).quiet(true)
    }

    async fn assert_tls_config_trusted(config: Arc<ServerConfig>, ca_cert_pem: &str) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(config).accept(stream).await.unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(ca_cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(certs.len(), 1);
        roots.add(certs.into_iter().next().unwrap()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(address).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from(ANTHROPIC_HOST.to_string()).unwrap();
        let tls_stream = connector.connect(server_name, stream).await.unwrap();
        drop(tls_stream);
        server.await.unwrap();
    }

    async fn read_through_headers<R>(reader: &mut R) -> Vec<u8>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut bytes = Vec::new();
        let mut byte = [0_u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            reader.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 64 * 1024);
        }
        bytes
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
    fn builds_tls_config_with_explicit_crypto_provider() {
        let state = State::new(test_runtime_config()).unwrap();

        let config = state.tls_config_for_host(ANTHROPIC_HOST).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn runtime_ca_signs_a_trusted_server_config() {
        let (cert_pem, key_pem) = generate_test_ca("SAIAI V2 test CA");
        validate_runtime_tls_config(&cert_pem, &key_pem).unwrap();
        let state = State::new(
            test_config()
                .with_runtime_ca(cert_pem.clone(), key_pem)
                .quiet(true),
        )
        .unwrap();

        let config = state.tls_config_for_host(ANTHROPIC_HOST).unwrap();
        assert_tls_config_trusted(config, &cert_pem).await;
    }

    #[tokio::test]
    async fn random_port_is_ready_and_caller_shutdown_stops_proxy() {
        let proxy = bind(test_runtime_config()).await.unwrap();
        let address = proxy.local_addr();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(proxy.run_until(async move {
            let _ = shutdown_rx.await;
        }));
        let stream = TcpStream::connect(address).await.unwrap();
        drop(stream);

        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("proxy did not stop after caller shutdown")
            .expect("proxy task panicked")
            .expect("proxy shutdown failed");
    }

    #[tokio::test]
    async fn runtime_proxy_forwards_anthropic_messages_to_a_local_mock() {
        const BODY: &[u8] = br#"{"model":"mock"}"#;
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let headers = read_through_headers(&mut stream).await;
            let headers = String::from_utf8(headers).unwrap();
            assert!(headers.starts_with("POST /v1/messages?beta=true HTTP/1.1\r\n"));
            assert!(headers.lines().any(|line| {
                line.eq_ignore_ascii_case("authorization: Bearer sk-runtime-mock")
            }));
            assert!(headers.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("content-length: {}", BODY.len()))
            }));
            let mut body = vec![0_u8; BODY.len()];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, BODY);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\nX-Request-ID: req_mock\r\nConnection: close\r\n\r\n{\"ok\":true}\n     ",
                )
                .await
                .unwrap();
        });

        let (cert_pem, key_pem) = generate_test_ca("SAIAI V2 forwarding test CA");
        let proxy = bind(
            Config {
                listen: "127.0.0.1:0".to_owned(),
                base_url: format!("http://{upstream_address}"),
                api_key: "sk-runtime-mock".to_owned(),
                verbose: false,
            }
            .with_runtime_ca(cert_pem.clone(), key_pem)
            .quiet(true),
        )
        .await
        .unwrap();
        let proxy_address = proxy.local_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let proxy_task = tokio::spawn(proxy.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        let mut stream = TcpStream::connect(proxy_address).await.unwrap();
        stream
            .write_all(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n",
            )
            .await
            .unwrap();
        let connect_response = read_through_headers(&mut stream).await;
        assert_eq!(
            connect_response,
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );

        let mut roots = rustls::RootCertStore::empty();
        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        let certificate = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        roots.add(certificate).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name =
            rustls::pki_types::ServerName::try_from(ANTHROPIC_HOST.to_owned()).unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();
        tls.write_all(
            format!(
                "POST /v1/messages?beta=true HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                BODY.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        tls.write_all(BODY).await.unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("x-request-id: req_mock\r\n"));
        assert!(response.contains("{\"ok\":true}"));

        upstream.await.unwrap();
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("runtime proxy did not stop")
            .expect("runtime proxy task panicked")
            .expect("runtime proxy failed");
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

        let rejected =
            anyhow::anyhow!("direct tunnel rejected host=127.0.0.1:80: only port 443 is allowed");
        assert!(!is_benign_client_error(&rejected));
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
    }

    #[test]
    fn canonical_host_strips_case_brackets_and_trailing_dot() {
        assert_eq!(canonical_host("[API.Anthropic.Com.]"), "api.anthropic.com");
    }

    #[test]
    fn rejects_private_direct_targets() {
        assert!(is_forbidden_addr("127.0.0.1:443".parse().unwrap()));
        assert!(is_forbidden_addr("192.168.1.10:443".parse().unwrap()));
        assert!(is_forbidden_addr("[::1]:443".parse().unwrap()));
        assert!(!is_forbidden_addr("93.184.216.34:443".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv4_mapped_and_reserved_ipv6_targets() {
        for address in [
            "[::ffff:127.0.0.1]:443",
            "[::ffff:10.0.0.1]:443",
            "[ff02::1]:443",
            "[2001:db8::1]:443",
        ] {
            let address = address.parse::<SocketAddr>().unwrap();
            assert!(is_forbidden_addr(address), "accepted {address}");
        }
        assert!(!is_forbidden_addr(
            "[2606:4700:4700::1111]:443".parse().unwrap()
        ));
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
