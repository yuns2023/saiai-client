//! Wire-level regressions for shared versus Desktop-only proxy ingress.
use super::tests::{capture_gateway_requests, proof_test_state, test_ca};
use super::*;

fn state(root: Option<&std::path::Path>, upstream: Option<String>) -> Arc<State> {
    let (ca_cert_pem, ca_key_pem) = test_ca();
    Arc::new(
        State::new(Config {
            listen: "127.0.0.1:0".into(),
            base_url: "http://127.0.0.1:1".into(),
            api_key: "MOCK_GATEWAY".into(),
            claude: None,
            codex: None,
            ca_cert_pem,
            ca_key_pem,
            verbose: false,
            chatgpt_chat_passthrough: false,
            desktop_browser_use: true,
            gateway_state_dir: None,
            desktop_config_root: root.map(std::path::Path::to_path_buf),
            upstream_proxy: upstream,
        })
        .unwrap(),
    )
}

async fn connection(
    state: Arc<State>,
    entry: EntryPoint,
) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_client_on(state, stream, peer, entry).await
    });
    (TcpStream::connect(address).await.unwrap(), task)
}

async fn head(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 16384);
    }
    bytes
}

async fn tls_request(state: Arc<State>, entry: EntryPoint, host: &str, request: &[u8]) -> Vec<u8> {
    tls_round_trip(state, entry, host, request, false).await
}

/// Like `tls_request`, but an upgraded (101) or kept-alive answer ends the
/// exchange instead of waiting for the proxy to close the connection.
async fn tls_exchange(state: Arc<State>, entry: EntryPoint, host: &str, request: &[u8]) -> Vec<u8> {
    tls_round_trip(state, entry, host, request, true).await
}

async fn tls_round_trip(
    state: Arc<State>,
    entry: EntryPoint,
    host: &str,
    request: &[u8],
    open_ended: bool,
) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(&state.ca_cert_pem)) {
        roots.add(cert.unwrap()).unwrap();
    }
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let (mut stream, task) = connection(state, entry).await;
    stream
        .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        head(&mut stream).await,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let mut tls = connector.connect(name, stream).await.unwrap();
    tls.write_all(request).await.unwrap();
    let mut response = Vec::new();
    while open_ended && !response.ends_with(b"\r\n\r\n") {
        match timeout(Duration::from_secs(5), tls.read_u8())
            .await
            .unwrap()
        {
            Ok(byte) => response.push(byte),
            Err(_) => break,
        }
    }
    if response.starts_with(b"HTTP/1.1 101") {
        // An upgraded relay stays open; the head is the answer.
        task.abort();
        return response;
    }
    let head_text = String::from_utf8_lossy(&response).to_ascii_lowercase();
    if !head_text.contains("\r\nconnection: close\r\n")
        && let Some(length) = head_text
            .split("\r\n")
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.trim().parse::<usize>().ok())
    {
        // A kept-alive answer ends at its declared length.
        let mut body = vec![0; length];
        timeout(Duration::from_secs(5), tls.read_exact(&mut body))
            .await
            .unwrap()
            .unwrap();
        response.extend(body);
        task.abort();
        return response;
    }
    // The existing server closes the TCP stream without a TLS close_notify.
    let result = timeout(Duration::from_secs(5), tls.read_to_end(&mut response))
        .await
        .unwrap();
    if let Err(error) = result {
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
    task.await.unwrap().unwrap();
    response
}

#[tokio::test]
async fn main_claude_connect_is_a_byte_tunnel_with_or_without_desktop_identity() {
    let root = tempfile::tempdir().unwrap();
    for initialized in [false, true] {
        if initialized {
            crate::claude_desktop::Identity::prepare(root.path()).unwrap();
        }
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let request = read_http_request(&mut reader).await.unwrap();
            assert_eq!(request.method, "CONNECT");
            assert_eq!(request.target, "claude.ai:443");
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut opaque = [0u8; 12];
            reader.read_exact(&mut opaque).await.unwrap();
            assert_eq!(&opaque, b"NOT_TLS_DATA");
            reader.get_mut().write_all(b"UPSTREAM_REPLY").await.unwrap();
        });
        let (mut client, task) = connection(
            state(Some(root.path()), Some(format!("http://{address}"))),
            EntryPoint::Main,
        )
        .await;
        client
            .write_all(b"CONNECT claude.ai:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            head(&mut client).await,
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        client.write_all(b"NOT_TLS_DATA").await.unwrap();
        let mut reply = [0u8; 14];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"UPSTREAM_REPLY");
        drop(client);
        server.await.unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn main_oauth_update_and_profile_keep_the_original_response_bytes() {
    let root = tempfile::tempdir().unwrap();
    crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    // Corrupt Desktop state must also have no effect on main-port CLI clients.
    fs::write(
        root.path().join("desktop/claude/state/identity.json"),
        b"broken",
    )
    .unwrap();
    for path in ["/v1/oauth/token", "/api/desktop/linux/x64/deb/latest"] {
        let raw = format!(
            "POST {path} HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        let response = tls_request(
            state(Some(root.path()), None),
            EntryPoint::Main,
            ANTHROPIC_HOST,
            raw.as_bytes(),
        )
        .await;
        assert_eq!(
            response,
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
    }
    let response = tls_request(
        state(Some(root.path()), None),
        EntryPoint::Main,
        ANTHROPIC_HOST,
        b"GET /api/oauth/profile HTTP/1.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(response, b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}");
}

#[tokio::test]
async fn main_preserves_provider_and_reserved_bearers_and_does_not_inspect_email() {
    let (url, server) = capture_gateway_requests(2, 0).await;
    let (mut state, root) = proof_test_state(&url, &url, None);
    state.gateway_session = std::sync::OnceLock::new();
    crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    fs::write(
        root.path().join("desktop/claude/state/identity.json"),
        b"broken",
    )
    .unwrap();
    let state = Arc::new(state);
    let body = r#"{"system":"The user's email address is fixture@example.invalid"}"#;
    let tokens = ["sk-ant-MOCK_ONLY", "saiai-desktop-claude-FOREIGN"];
    for token in tokens {
        let raw = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer {token}\r\nCookie: original-cookie\r\nx-api-key: original-key\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = tls_request(
            Arc::clone(&state),
            EntryPoint::Main,
            ANTHROPIC_HOST,
            raw.as_bytes(),
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
    }
    let (requests, _) = server.await.unwrap();
    for (request, token) in requests.iter().zip(tokens) {
        assert_eq!(
            header_value(&request.headers, "authorization"),
            Some(format!("Bearer {token}").as_str())
        );
        assert_eq!(
            header_value(&request.headers, "cookie"),
            Some("original-cookie")
        );
        assert_eq!(
            header_value(&request.headers, "x-api-key"),
            Some("original-key")
        );
        assert_eq!(request.body, body.as_bytes());
    }
}

#[tokio::test]
async fn desktop_missing_and_corrupt_identity_are_explicit_http_errors() {
    let root = tempfile::tempdir().unwrap();
    for corrupt in [false, true] {
        if corrupt {
            crate::claude_desktop::Identity::prepare(root.path()).unwrap();
            fs::write(
                root.path().join("desktop/claude/state/identity.json"),
                b"{MOCK_SECRET_BROKEN",
            )
            .unwrap();
        }
        for (host, path) in [
            ("claude.ai", "/api/account"),
            (ANTHROPIC_HOST, "/v1/oauth/token"),
            (ANTHROPIC_HOST, "/v1/messages"),
        ] {
            let response = tls_request(
                state(Some(root.path()), None),
                EntryPoint::ClaudeDesktop,
                host,
                format!("GET {path} HTTP/1.1\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await;
            let text = String::from_utf8(response).unwrap();
            assert!(text.starts_with("HTTP/1.1 503"));
            assert!(text.contains(if corrupt {
                "desktop_identity_invalid"
            } else {
                "desktop_identity_missing"
            }));
            assert!(!text.contains("MOCK_SECRET"));
        }
    }
}

#[tokio::test]
async fn desktop_classification_works_without_client_proof_storage() {
    let root = tempfile::tempdir().unwrap();
    crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    let state = state(Some(root.path()), None);
    assert!(state.gateway_state_dir.is_none());
    for (host, path, code) in [
        ("claude.ai", "/api/account", 200),
        ("claude.ai", "/api/unknown", 501),
        ("claude.ai", "/%61pi/account", 400),
        (ANTHROPIC_HOST, "/v1/oauth/token", 400),
        (ANTHROPIC_HOST, "/api/desktop/linux/x64/deb/latest", 204),
    ] {
        let method = if path == "/v1/oauth/token" {
            "POST"
        } else {
            "GET"
        };
        let response = tls_request(
            Arc::clone(&state),
            EntryPoint::ClaudeDesktop,
            host,
            format!("{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await;
        assert!(
            String::from_utf8(response)
                .unwrap()
                .starts_with(&format!("HTTP/1.1 {code}"))
        );
    }
    for token in ["sk-ant-MOCK_ONLY", "saiai-desktop-claude-FOREIGN"] {
        let response = tls_request(Arc::clone(&state), EntryPoint::ClaudeDesktop, ANTHROPIC_HOST,
            format!("POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes()).await;
        assert!(response.starts_with(b"HTTP/1.1 401"));
    }
}

#[tokio::test]
async fn certificate_control_identifies_the_entry_without_changing_main_bytes() {
    for (entry, count) in [(EntryPoint::Main, 4), (EntryPoint::ClaudeDesktop, 2)] {
        let (mut stream, task) = connection(state(None, None), entry).await;
        stream
            .write_all(b"CONNECT certificate.saiai.local:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let response = String::from_utf8(head(&mut stream).await).unwrap();
        let pins = response
            .lines()
            .find_map(|l| l.strip_prefix("x-saiai-leaf-spki-sha256: "))
            .unwrap();
        assert_eq!(pins.split(',').count(), count);
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn run_without_desktop_identity_keeps_only_main_entry_and_creates_no_desktop_state() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        crate::claude_desktop::bind_if_initialized(Some(root.path()), "127.0.0.1:0")
            .await
            .unwrap()
            .is_none()
    );
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    let (ca_cert_pem, ca_key_pem) = test_ca();
    let cfg = Config {
        listen: address.to_string(),
        base_url: "http://127.0.0.1:1".into(),
        api_key: "MOCK_ONLY".into(),
        claude: None,
        codex: None,
        ca_cert_pem,
        ca_key_pem,
        verbose: false,
        chatgpt_chat_passthrough: false,
        desktop_browser_use: true,
        gateway_state_dir: None,
        desktop_config_root: Some(root.path().to_path_buf()),
        upstream_proxy: Some("direct".into()),
    };
    drop(reservation);
    let task = tokio::spawn(run(cfg));
    let mut stream = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                break stream;
            }
            assert!(
                !task.is_finished(),
                "proxy exited before accepting connections"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stream
        .write_all(b"CONNECT certificate.saiai.local:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    // A control response proves run() has completed listener setup.
    let response = timeout(Duration::from_secs(5), head(&mut stream))
        .await
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(!root.path().join("desktop/claude").exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn main_openai_replace_preserves_x_api_key() {
    let (url, server) = capture_gateway_requests(1, 0).await;
    let (mut state, _root) = proof_test_state(&url, &url, None);
    state.gateway_session = std::sync::OnceLock::new();
    let response = tls_request(
        Arc::new(state),
        EntryPoint::Main,
        OPENAI_HOST,
        b"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer MOCK_PLACEHOLDER\r\nx-api-key: original-key\r\nCookie: original-cookie\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let (requests, _) = server.await.unwrap();
    assert_eq!(
        header_value(&requests[0].headers, "authorization"),
        Some("Bearer MOCK_ONLY_GATEWAY")
    );
    assert_eq!(header_value(&requests[0].headers, "cookie"), None);
    assert_eq!(
        header_value(&requests[0].headers, "x-api-key"),
        Some("original-key")
    );
}

#[tokio::test]
async fn desktop_plaintext_canonical_hosts_are_rejected() {
    for host in ["claude.ai.", "CLAUDE.AI.", "API.ANTHROPIC.COM."] {
        let (mut stream, task) = connection(state(None, None), EntryPoint::ClaudeDesktop).await;
        stream.write_all(format!("GET http://{host}/api/account HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer MOCK_ONLY\r\nCookie: sessionKey=MOCK_ONLY\r\n\r\n").as_bytes()).await.unwrap();
        assert!(head(&mut stream).await.starts_with(b"HTTP/1.1 400"));
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn desktop_settings_put_requires_session_and_fragment_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let id = crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    let state = state(Some(root.path()), None);
    for (cookie, status) in [("", "401"), ("sessionKey=wrong", "401")] {
        let raw = format!(
            "PUT /api/claude_code/organizations/{}/user_settings HTTP/1.1\r\nHost: claude.ai\r\nCookie: {cookie}\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{{}}",
            id.organization
        );
        let response = tls_request(
            Arc::clone(&state),
            EntryPoint::ClaudeDesktop,
            "claude.ai",
            raw.as_bytes(),
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status}")));
        assert!(
            !root
                .path()
                .join("desktop/claude/state/settings.json")
                .exists()
        );
    }
    let raw = format!(
        "PUT /api/claude_code/organizations/{}/user_settings HTTP/1.1\r\nHost: claude.ai\r\nCookie: sessionKey={}\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{{}}",
        id.organization, id.session
    );
    assert!(
        tls_request(
            Arc::clone(&state),
            EntryPoint::ClaudeDesktop,
            "claude.ai",
            raw.as_bytes()
        )
        .await
        .starts_with(b"HTTP/1.1 200")
    );
    for path in [
        "/api#x",
        "/page?query=#x",
        "/api/desktop/linux/x64/deb/latest#x",
    ] {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: claude.ai\r\nConnection: close\r\n\r\n");
        assert!(
            tls_request(
                Arc::clone(&state),
                EntryPoint::ClaudeDesktop,
                "claude.ai",
                raw.as_bytes()
            )
            .await
            .starts_with(b"HTTP/1.1 400")
        );
    }
}

#[tokio::test]
async fn desktop_never_injects_the_route_key_without_its_placeholder() {
    let root = tempfile::tempdir().unwrap();
    crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    let state = state(Some(root.path()), None);
    for headers in [
        "Connection: close\r\n",
        "x-api-key: saiai-desktop-claude-FOREIGN\r\nConnection: close\r\n",
        "x-api-key: MOCK_ONLY\r\nCookie: sessionKey=MOCK_ONLY\r\nConnection: close\r\n",
        "Authorization: Bearer ordinary-saiai-key\r\nConnection: close\r\n",
        "Authorization: Bearer ordinary-saiai-key\r\nConnection: authorization, close\r\n",
    ] {
        for path in ["/v1/messages", "/v1/messages/count_tokens", "/v1/models"] {
            let response = tls_request(
                Arc::clone(&state),
                EntryPoint::ClaudeDesktop,
                ANTHROPIC_HOST,
                format!("POST {path} HTTP/1.1\r\n{headers}Content-Length: 2\r\n\r\n{{}}")
                    .as_bytes(),
            )
            .await;
            let text = String::from_utf8(response).unwrap();
            assert!(
                text.starts_with("HTTP/1.1 401"),
                "{headers:?} {path}: {text}"
            );
            assert!(text.contains("invalid_local_desktop_token"));
        }
    }
}

#[tokio::test]
async fn desktop_listener_does_not_mitm_openai_hosts() {
    for host in [
        OPENAI_HOST,
        CHATGPT_HOST,
        CHAT_OPENAI_HOST,
        CHATGPT_AUX_HOST,
    ] {
        assert!(EntryPoint::Main.manages(host));
        assert!(!EntryPoint::ClaudeDesktop.manages(host));
        let (mut stream, task) = connection(state(None, None), EntryPoint::ClaudeDesktop).await;
        stream
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        assert!(head(&mut stream).await.starts_with(b"HTTP/1.1 502"));
        assert!(task.await.unwrap().is_err());
    }
    for host in ["claude.ai", ANTHROPIC_HOST] {
        assert!(EntryPoint::ClaudeDesktop.manages(host));
    }
    assert!(!EntryPoint::Main.manages("claude.ai"));
}

/// The third signing exit: every page of the Claude Desktop model catalog is
/// signed for its final target (encoded `after_id`) with the route key.
#[tokio::test]
async fn claude_model_catalog_pages_are_each_signed_with_the_route_key() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut captured = Vec::new();
        for body in [
            r#"{"data":[{"id":"m-1"}],"has_more":true,"last_id":"m 1/x"}"#,
            r#"{"data":[{"id":"m-2"}],"has_more":false}"#,
        ] {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let request = read_http_request(&mut reader).await.unwrap();
                if request.target.ends_with("/client/devices/enroll") {
                    reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await
                        .unwrap();
                    continue;
                }
                captured.push(request);
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
        captured
    });
    let (state, root) = proof_test_state(&url, &url, Some("MOCK_ONLY_GATEWAY"));
    let identity = crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    let models = claude_desktop::models(&state, &identity).await.unwrap();
    assert_eq!(
        models
            .iter()
            .map(|model| model["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["m-1", "m-2"]
    );
    let captured = server.await.unwrap();
    let proof = super::tests::saiai_proof(&state);
    let mut nonces = std::collections::HashSet::new();
    for (request, target) in captured
        .iter()
        .zip(["/v1/models", "/v1/models?after_id=m+1%2Fx"])
    {
        assert_eq!(request.target, target);
        assert_eq!(
            header_value(&request.headers, "authorization"),
            Some("Bearer MOCK_ONLY_GATEWAY")
        );
        let header = header_value(&request.headers, "x-saiai-client-proof").expect("signed page");
        super::tests::verify_proof(&proof, header, "GET", target, "MOCK_ONLY_GATEWAY");
        assert!(nonces.insert(header.split('.').nth(3).unwrap().to_string()));
    }
}

/// Without a Gateway extension nothing is loaded, stored or signed, while
/// the brand's sensitive inbound headers are still never relayed.
#[tokio::test]
async fn no_gateway_extension_stores_and_signs_nothing() {
    static NONE: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
    let (url, server) = capture_gateway_requests(1, 0).await;
    let (mut state, root) = proof_test_state(&url, &url, None);
    state.gateway = &NONE;
    state.gateway_session = std::sync::OnceLock::new();
    let state_dir = tempfile::tempdir().unwrap();
    state.gateway_state_dir = Some(state_dir.path().to_path_buf());
    let state = Arc::new(state);
    state.start_gateway_session();
    let response = tls_request(
        Arc::clone(&state),
        EntryPoint::Main,
        ANTHROPIC_HOST,
        b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nx-saiai-client-proof: v1.MOCK_SPOOFED\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let (requests, enrollments) = server.await.unwrap();
    assert!(enrollments.is_empty());
    assert_eq!(
        header_value(&requests[0].headers, "x-saiai-client-proof"),
        None
    );
    assert_eq!(fs::read_dir(state_dir.path()).unwrap().count(), 0);
    drop(root);
}

/// Inbound proofs are stripped from the first request on, whether or not the
/// extension ever loads its key (here the key directory is a file).
#[tokio::test]
async fn reserved_headers_are_stripped_even_when_the_extension_fails_to_load() {
    let (url, server) = capture_gateway_requests(1, 0).await;
    let (mut state, root) = proof_test_state(&url, &url, None);
    state.gateway_session = std::sync::OnceLock::new();
    let blocked = root.path().join("not-a-directory");
    fs::write(&blocked, b"file").unwrap();
    state.gateway_state_dir = Some(blocked);
    let state = Arc::new(state);
    state.start_gateway_session();
    let response = tls_request(
        Arc::clone(&state),
        EntryPoint::Main,
        ANTHROPIC_HOST,
        b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nX-SAIAI-Client-Proof: v1.MOCK_SPOOFED\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let (requests, _) = server.await.unwrap();
    assert_eq!(
        header_value(&requests[0].headers, "x-saiai-client-proof"),
        None
    );
}

/// Signing starts as soon as the key is loaded, while the configured route's
/// enrollment is still in flight, and that configured claim uses none of the
/// on-demand enrollment budget.
#[tokio::test]
async fn signing_does_not_wait_for_enrollment_and_configured_routes_use_no_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (enrolled, mut enrollments) = tokio::sync::mpsc::unbounded_channel::<()>();
    let (forward, mut forwarded) = tokio::sync::mpsc::unbounded_channel::<IncomingRequest>();
    let server = tokio::spawn(async move {
        // Enrollment connections are held open and never answered.
        let mut held = Vec::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let request = read_http_request(&mut reader).await.unwrap();
            if request.target.ends_with("/client/devices/enroll") {
                let _ = enrolled.send(());
                held.push(reader);
                continue;
            }
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
            let _ = forward.send(request);
        }
    });
    let (mut state, _root) = proof_test_state(&url, &url, None);
    state.gateway_session = std::sync::OnceLock::new();
    let state_dir = tempfile::tempdir().unwrap();
    crate::client_proof::ClientProof::load(state_dir.path())
        .unwrap()
        .record_device(&url, "MOCK_ONLY_GATEWAY", "cd_MOCKMOCKMOCKMOCKMOCK00")
        .unwrap();
    state.gateway_state_dir = Some(state_dir.path().to_path_buf());
    let state = Arc::new(state);
    state.start_gateway_session();

    timeout(Duration::from_secs(5), enrollments.recv())
        .await
        .expect("configured route enrollment started")
        .unwrap();
    let session = state.gateway_session.get().unwrap();
    let saiai = session
        .as_any()
        .downcast_ref::<crate::gateway_saiai::SaiaiSession>()
        .unwrap();
    // Publication follows the configured claims without awaiting enrollment.
    timeout(Duration::from_secs(5), async {
        while saiai.proof().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("proof published while enrollment is pending");

    let response = tls_request(
        Arc::clone(&state),
        EntryPoint::Main,
        ANTHROPIC_HOST,
        b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let request = timeout(Duration::from_secs(5), forwarded.recv())
        .await
        .unwrap()
        .unwrap();
    let proof = super::tests::saiai_proof(&state);
    let header = header_value(&request.headers, "x-saiai-client-proof").expect("signed");
    super::tests::verify_proof(&proof, header, "POST", "/v1/messages", "MOCK_ONLY_GATEWAY");
    // The whole on-demand budget (16 extra credentials) is still available.
    for index in 0..16 {
        assert!(proof.claim_enrollment(&url, &format!("TEST_ONLY_EXTRA_{index}"), true));
    }
    assert!(!proof.claim_enrollment(&url, "TEST_ONLY_EXTRA_16", true));
    server.abort();
}

/// A test extension that reserves a header outside the brand's sensitive
/// set and records every signing request.
struct TestProof;
static TEST_PROOF: TestProof = TestProof;
/// (transport, gateway, method, target, bearer) of each signing request.
type SignedRequest = (
    crate::gateway::Transport,
    String,
    String,
    String,
    Option<String>,
);
static SIGNED: std::sync::Mutex<Vec<SignedRequest>> = std::sync::Mutex::new(Vec::new());

struct TestProofSession;

impl crate::gateway::GatewayExtension for TestProof {
    fn signature_headers(&self) -> &'static [&'static str] {
        // `user-agent` is on the Claude public fetch allowlist: reserving it
        // proves that exit consults the extension, not only its allowlist.
        &["x-test-proof", "user-agent"]
    }

    fn start(
        &self,
        _start: crate::gateway::GatewayStart,
    ) -> Arc<dyn crate::gateway::GatewaySession> {
        Arc::new(TestProofSession)
    }
}

impl crate::gateway::GatewaySession for TestProofSession {
    fn sign(&self, input: &crate::gateway::SignInput<'_>) -> Vec<(String, String)> {
        SIGNED.lock().unwrap().push((
            input.transport,
            input.gateway.to_string(),
            input.method.to_string(),
            input.target.to_string(),
            input.bearer.map(str::to_string),
        ));
        vec![(
            "x-test-proof".to_string(),
            format!("signed {} {}", input.method, input.target),
        )]
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn signed_for(gateway: &str) -> Vec<(crate::gateway::Transport, String, String, Option<String>)> {
    SIGNED
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, url, ..)| url == gateway)
        .map(|(transport, _, method, target, bearer)| {
            (*transport, method.clone(), target.clone(), bearer.clone())
        })
        .collect()
}

/// Reserved inbound headers come from the extension the proxy runs with, not
/// only from the brand: before the session starts nothing is signed and the
/// spoofed header is dropped; afterwards the managed TLS exit signs.
#[tokio::test]
async fn extension_reserved_headers_are_stripped_and_signed_on_managed_tls() {
    let (url, server) = capture_gateway_requests(2, 0).await;
    let (mut state, _root) = proof_test_state(&url, &url, None);
    state.gateway = &TEST_PROOF;
    state.gateway_session = std::sync::OnceLock::new();
    let state = Arc::new(state);
    let request = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nX-Test-Proof: spoofed\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}";
    // First request: the session has not started.
    let response = tls_request(
        Arc::clone(&state),
        EntryPoint::Main,
        ANTHROPIC_HOST,
        request,
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    state.start_gateway_session();
    let response = tls_request(
        Arc::clone(&state),
        EntryPoint::Main,
        ANTHROPIC_HOST,
        request,
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let (requests, _) = server.await.unwrap();
    assert_eq!(header_value(&requests[0].headers, "x-test-proof"), None);
    let proofs = requests[1]
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-test-proof"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    assert_eq!(proofs, ["signed POST /v1/messages"]);
    assert_eq!(
        signed_for(&url),
        [(
            crate::gateway::Transport::Http,
            "POST".to_string(),
            "/v1/messages".to_string(),
            Some("MOCK_ONLY_GATEWAY".to_string())
        )]
    );
}

#[tokio::test]
async fn extension_reserved_headers_are_dropped_by_plain_http_proxy_and_claude_public_fetch() {
    let request = super::tests::relay_plain_http_proxy_request_with(
        vec![
            ("X-Test-Proof".to_string(), "spoofed".to_string()),
            ("X-Custom".to_string(), "kept".to_string()),
        ],
        &TEST_PROOF,
    )
    .await
    .to_ascii_lowercase();
    assert!(request.contains("\r\nx-custom: kept\r\n"), "{request}");
    assert!(!request.contains("x-test-proof"), "{request}");
    assert!(!claude_desktop::public_request_header(
        "X-Test-Proof",
        &TEST_PROOF
    ));
    // Allowlisted, yet reserved by this extension: refused.
    assert!(!claude_desktop::public_request_header(
        "User-Agent",
        &TEST_PROOF
    ));
    assert!(claude_desktop::public_request_header(
        "User-Agent",
        crate::runtime::gateway()
    ));
    assert!(claude_desktop::public_request_header("accept", &TEST_PROOF));
}

#[test]
fn extension_reserved_headers_are_not_copied_into_the_websocket_handshake() {
    let url = Url::parse("wss://gateway.ws-test.example/v1/responses?x=1").unwrap();
    let incoming = vec![
        ("X-Test-Proof".to_string(), "spoofed".to_string()),
        (
            "Sec-WebSocket-Key".to_string(),
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        ),
    ];
    let mut signed = None;
    let request = build_openai_websocket_request(
        &url,
        &incoming,
        "MOCK_ONLY_GATEWAY",
        &TEST_PROOF,
        |method, target| {
            signed = Some((method.to_string(), target.to_string()));
            vec![("x-test-proof", "signed handshake".to_string())]
        },
    )
    .unwrap();
    assert_eq!(
        signed,
        Some(("GET".to_string(), "/v1/responses?x=1".to_string()))
    );
    let values = request
        .headers()
        .get_all("x-test-proof")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values, ["signed handshake"]);
    // Unsigned (session not ready): the spoofed value is still not copied.
    let request = build_openai_websocket_request(
        &url,
        &incoming,
        "MOCK_ONLY_GATEWAY",
        &TEST_PROOF,
        |_, _| Vec::new(),
    )
    .unwrap();
    assert!(request.headers().get("x-test-proof").is_none());
}

/// The model catalog exit hands the extension the finished request.
#[tokio::test]
async fn model_catalog_exit_passes_the_finished_request_to_the_extension() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let request = read_http_request(&mut reader).await.unwrap();
        let body = r#"{"data":[{"id":"m-1"}],"has_more":false}"#;
        reader
            .get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        request
    });
    let (mut state, root) = proof_test_state(&url, &url, None);
    // A configured key with surrounding spaces is used verbatim.
    state.default_route.api_key = Zeroizing::new(" MOCK_SPACED_KEY ".to_string());
    state.gateway = &TEST_PROOF;
    state.gateway_session = std::sync::OnceLock::new();
    let state = Arc::new(state);
    state.start_gateway_session();
    let identity = crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    claude_desktop::models(&state, &identity).await.unwrap();
    let request = server.await.unwrap();
    assert_eq!(
        header_value(&request.headers, "x-test-proof"),
        Some("signed GET /v1/models")
    );
    assert_eq!(
        signed_for(&url),
        [(
            crate::gateway::Transport::Http,
            "GET".to_string(),
            "/v1/models".to_string(),
            Some(" MOCK_SPACED_KEY ".to_string())
        )]
    );
}

/// Gateway that accepts requests forever and reports each one.
async fn recording_gateway() -> (
    String,
    tokio::sync::mpsc::UnboundedReceiver<IncomingRequest>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let Ok(request) = read_http_request(&mut reader).await else {
                continue;
            };
            if request.target.ends_with("/client/devices/enroll") {
                let _ = reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                    .await;
                continue;
            }
            let key = header_value(&request.headers, "sec-websocket-key").map(str::to_owned);
            let _ = sender.send(request);
            let Some(key) = key else {
                let _ = reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                    .await;
                continue;
            };
            let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
            let _ = reader
                .get_mut()
                .write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes())
                .await;
            // End the session with a proper closing handshake.
            let mut socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
                reader.into_inner(),
                tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            tokio::spawn(async move {
                let _ = socket.close(None).await;
                while let Some(Ok(_)) = futures_util::StreamExt::next(&mut socket).await {}
            });
        }
    });
    (url, receiver, task)
}

const WS_HEADERS: &str = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n";

/// Native Chat relay matrix: Gateway capability × user switch × HTTP/WS ×
/// chatgpt.com native paths and api.openai.com `/chatgpt/` paths. Codex
/// traffic and the local Desktop compatibility layer are never affected;
/// refused relay requests get the explicit JSON answer and never leave.
#[tokio::test]
async fn native_chat_relay_follows_the_gateway_capability_and_the_user_switch() {
    static NONE: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
    for capability in [true, false] {
        for passthrough in [true, false] {
            let (url, mut forwarded, task) = recording_gateway().await;
            let (mut state, _root) = proof_test_state(&url, &url, None);
            state.gateway_session = std::sync::OnceLock::new();
            state.chatgpt_chat_passthrough = passthrough;
            if !capability {
                state.gateway = &NONE;
            }
            let state = Arc::new(state);
            let relay = capability && passthrough;
            let cases: Vec<(&str, String, Option<&str>)> = vec![
                // (host, request, Gateway target when forwarded)
                (
                    CHATGPT_HOST,
                    "POST /backend-api/f/conversation HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".into(),
                    relay.then_some("/chatgpt/backend-api/f/conversation"),
                ),
                (
                    OPENAI_HOST,
                    "POST /chatgpt/backend-api/f/conversation HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".into(),
                    // An already prefixed path never depended on the user
                    // switch; it follows the Gateway capability only.
                    capability.then_some("/chatgpt/backend-api/f/conversation"),
                ),
                (
                    CHATGPT_HOST,
                    "POST /backend-api/codex/images/generations HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".into(),
                    capability.then_some("/v1/codex/images/generations"),
                ),
                (
                    OPENAI_HOST,
                    "POST /v1/codex/images/generations HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".into(),
                    capability.then_some("/v1/codex/images/generations"),
                ),
                (
                    CHATGPT_HOST,
                    "POST /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".into(),
                    Some("/v1/responses"),
                ),
                (
                    OPENAI_HOST,
                    "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".into(),
                    Some("/v1/responses"),
                ),
                (
                    CHATGPT_HOST,
                    format!("GET /backend-api/celsius/ws/user HTTP/1.1\r\nHost: chatgpt.com\r\n{WS_HEADERS}\r\n"),
                    relay.then_some("/chatgpt/backend-api/celsius/ws/user"),
                ),
                (
                    OPENAI_HOST,
                    format!("GET /chatgpt/backend-api/celsius/ws/user HTTP/1.1\r\nHost: api.openai.com\r\n{WS_HEADERS}\r\n"),
                    capability.then_some("/chatgpt/backend-api/celsius/ws/user"),
                ),
                (
                    OPENAI_HOST,
                    format!("GET /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n{WS_HEADERS}\r\n"),
                    Some("/v1/responses"),
                ),
            ];
            for (host, request, expected) in &cases {
                let label = format!(
                    "capability={capability} passthrough={passthrough} {host} {}",
                    request.lines().next().unwrap()
                );
                let response = tls_exchange(
                    Arc::clone(&state),
                    EntryPoint::Main,
                    host,
                    request.as_bytes(),
                )
                .await;
                match expected {
                    Some(target) => {
                        let seen = timeout(Duration::from_secs(5), forwarded.recv())
                            .await
                            .unwrap_or_else(|_| panic!("not forwarded: {label}"))
                            .unwrap();
                        assert_eq!(seen.target, *target, "{label}");
                        let status = if request.contains("Upgrade: websocket") {
                            "HTTP/1.1 101"
                        } else {
                            "HTTP/1.1 200"
                        };
                        assert!(
                            response.starts_with(status.as_bytes()),
                            "{label}: {}",
                            String::from_utf8_lossy(&response)
                        );
                    }
                    None => {
                        let text = String::from_utf8_lossy(&response);
                        assert!(text.starts_with("HTTP/1.1 501"), "{label}: {text}");
                        assert!(
                            text.contains("chat_mode_temporarily_disabled"),
                            "{label}: {text}"
                        );
                        assert!(forwarded.try_recv().is_err(), "forwarded anyway: {label}");
                    }
                }
            }
            // The local Desktop compatibility layer answers either way.
            let response = tls_exchange(
                Arc::clone(&state),
                EntryPoint::Main,
                CHATGPT_HOST,
                b"GET /backend-api/me HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(
                response.starts_with(b"HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&response)
            );
            assert!(forwarded.try_recv().is_err());
            task.abort();
        }
    }
}

/// Without a Chat relay the forwarder never extracts the device-proof cookie
/// nor rewrites a Chat initialization response, even when a request reaches
/// it directly.
#[tokio::test]
async fn no_chat_relay_means_no_device_cookie_and_no_preference_rewrite() {
    static NONE: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let upstream =
        br#"{"default_model_slug":"gpt-6-pro","intended_default_model_slug":"gpt-6-pro"}"#;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let captured = read_http_request(&mut reader).await.unwrap();
        reader
            .get_mut()
            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", upstream.len()).as_bytes())
            .await
            .unwrap();
        reader.get_mut().write_all(upstream).await.unwrap();
        captured
    });
    let (mut state, root) = proof_test_state(&url, &url, None);
    state.gateway = &NONE;
    state.gateway_session = std::sync::OnceLock::new();
    // The user switch is on: only the missing capability holds both back.
    state.chatgpt_chat_passthrough = true;
    let preferences = root.path().join(".codex-global-state.json");
    fs::write(
        &preferences,
        br#"{"electron-persisted-atom-state":{"chatgpt-last-selected-model-v1":{"slug":"gpt-5-6-thinking"}}}"#,
    )
    .unwrap();
    let request = IncomingRequest {
        method: "POST".into(),
        target: "/chatgpt/backend-api/conversation/init".into(),
        http_version: "HTTP/1.1".into(),
        body: br#"{"conversation_origin":null,"requested_default_model":null}"#.to_vec(),
        headers: vec![(
            "Cookie".into(),
            "session=MOCK_ONLY_AUTH; _devicecheck=MOCK_ONLY_PROOF".into(),
        )],
    };
    let (mut writer, mut output) = tokio::io::duplex(16384);
    forward_to_saiai_with_preferences_path(
        &state,
        &mut writer,
        request,
        true,
        GatewayRoute::OpenAI,
        CredentialPolicy::Replace,
        Some(&preferences),
    )
    .await
    .unwrap();
    drop(writer);
    let mut response = Vec::new();
    output.read_to_end(&mut response).await.unwrap();
    let captured = server.await.unwrap();
    assert_eq!(header_value(&captured.headers, "cookie"), None);
    let text = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(!text.contains("chat-preference-restored"), "{text}");
    // The upstream initialization answer passes through unrewritten.
    assert!(
        String::from_utf8_lossy(&response).contains(std::str::from_utf8(upstream).unwrap()),
        "{text}"
    );
}

/// Without a Chat relay, no spelling of a relay path gets through: dot
/// segments the outgoing URL would resolve, a bare `/chatgpt`, and a
/// `/chatgpt/` path sent to chatgpt.com — over HTTP and WebSocket alike.
#[tokio::test]
async fn no_chat_relay_refuses_every_spelling_of_a_relay_path() {
    static NONE: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
    let (url, mut forwarded, task) = recording_gateway().await;
    let (mut state, _root) = proof_test_state(&url, &url, None);
    state.gateway = &NONE;
    state.gateway_session = std::sync::OnceLock::new();
    state.chatgpt_chat_passthrough = true;
    let state = Arc::new(state);
    let targets = [
        // Case, trailing slash and alias-host spellings.
        (OPENAI_HOST, "/ChatGPT/backend-api/celsius/ws/user"),
        (OPENAI_HOST, "/v1/codex/images/generations/"),
        (OPENAI_HOST, "//chatgpt/backend-api/models"),
        (OPENAI_HOST, "/chatgpt#x"),
        (CHATGPT_HOST, "/backend-api/devicecheck#x"),
        (CHAT_OPENAI_HOST, "/Backend-API/f/conversation"),
        (CHATGPT_AUX_HOST, "/backend-api/codex/images/generations/"),
        (CHATGPT_HOST, "/backend-api/devicecheck/"),
        (
            OPENAI_HOST,
            "/v1/responses/../../chatgpt/backend-api/models",
        ),
        (
            OPENAI_HOST,
            "/v1/responses/%2e%2e/%2E%2E/chatgpt/backend-api/models",
        ),
        (OPENAI_HOST, "/v1/models/../codex/images/generations"),
        // Escapes a Gateway base path such as https://gateway/prefix.
        (
            OPENAI_HOST,
            "/v1/responses/../../../prefix/chatgpt/backend-api/models",
        ),
        (
            OPENAI_HOST,
            "/v1/responses/../../../prefix/v1/codex/images/generations",
        ),
        (OPENAI_HOST, "/v1/responses/.%2E/x"),
        (OPENAI_HOST, "/v1/responses/./compact"),
        (
            OPENAI_HOST,
            "/v1/responses\\..\\..\\chatgpt/backend-api/models",
        ),
        (OPENAI_HOST, "/chatgpt"),
        (OPENAI_HOST, "/chatgpt?x=1"),
        (CHATGPT_HOST, "/chatgpt/backend-api/f/conversation"),
        (
            CHATGPT_HOST,
            "/backend-api/codex/responses/../../../chatgpt/backend-api/f/conversation",
        ),
        (
            CHATGPT_HOST,
            "/backend-api/codex/models/../codex/images/edits",
        ),
    ];
    for (host, target) in targets {
        for websocket in [false, true] {
            let headers = if websocket {
                WS_HEADERS
            } else {
                "Connection: close\r\n"
            };
            let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n");
            let response = tls_exchange(
                Arc::clone(&state),
                EntryPoint::Main,
                host,
                request.as_bytes(),
            )
            .await;
            let text = String::from_utf8_lossy(&response);
            let label = format!("{host} {target} websocket={websocket}");
            assert!(text.starts_with("HTTP/1.1 501"), "{label}: {text}");
            assert!(
                text.contains("chat_mode_temporarily_disabled"),
                "{label}: {text}"
            );
            assert!(forwarded.try_recv().is_err(), "forwarded anyway: {label}");
        }
    }
    task.abort();
}

/// The plain HTTP proxy holds the same Chat relay gate: without the
/// capability, absolute-form requests to relay paths on the OpenAI hosts
/// (any method, any alias host, any spelling) get the explicit 501 and
/// never leave; Codex and other traffic is forwarded as before. With the
/// capability nothing changes.
#[tokio::test]
async fn plain_http_proxy_holds_the_chat_relay_gate() {
    static NONE: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
    let relay = [
        ("POST", "http://chatgpt.com/backend-api/f/conversation"),
        ("POST", "http://CHATGPT.COM./Backend-API/f/conversation"),
        ("GET", "http://chat.openai.com/backend-api/devicecheck/"),
        ("GET", "http://ab.chatgpt.com/celsius/ws/user"),
        (
            "POST",
            "http://api.openai.com/chatgpt/backend-api/f/conversation",
        ),
        ("GET", "http://api.openai.com/ChatGPT/backend-api/models"),
        ("GET", "http://api.openai.com/chatgpt"),
        ("POST", "http://api.openai.com/v1/codex/images/generations/"),
        (
            "POST",
            "http://api.openai.com/v1/responses/../../chatgpt/backend-api/models",
        ),
        ("POST", "http://chatgpt.com/backend-api/codex/images/edits"),
        ("HEAD", "http://api.openai.com/chatgpt/backend-api/models"),
        ("GET", "http://chatgpt.com/backend-api/devicecheck#x"),
        ("GET", "http://api.openai.com/chatgpt#x"),
        ("OPTIONS", "http://chatgpt.com/backend-api/f/conversation"),
    ];
    let open = [
        ("POST", "http://api.openai.com/v1/responses"),
        ("GET", "http://api.openai.com/v1/models"),
        ("POST", "http://chatgpt.com/backend-api/codex/responses"),
        ("GET", "http://example.com/chatgpt/backend-api/models"),
    ];
    for capability in [true, false] {
        let (proxy, mut forwarded, task) = recording_gateway().await;
        // Every forwarded request reaches the recorder as the upstream proxy.
        let mut state = state(None, Some(proxy));
        if !capability {
            Arc::get_mut(&mut state).unwrap().gateway = &NONE;
        }
        for (method, url) in relay.iter().chain(open.iter()) {
            let refused = !capability && relay.contains(&(method, url));
            let (mut stream, client) = connection(Arc::clone(&state), EntryPoint::Main).await;
            let length = if *method == "POST" {
                "Content-Length: 2\r\n\r\n{}"
            } else {
                "\r\n"
            };
            stream
                .write_all(format!("{method} {url} HTTP/1.1\r\nHost: x\r\n{length}").as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            let _ = client.await.unwrap();
            let text = String::from_utf8_lossy(&response);
            let label = format!("capability={capability} {method} {url}");
            if refused {
                assert!(text.starts_with("HTTP/1.1 501"), "{label}: {text}");
                assert!(
                    text.contains("chat_mode_temporarily_disabled"),
                    "{label}: {text}"
                );
                assert!(forwarded.try_recv().is_err(), "forwarded anyway: {label}");
            } else {
                assert!(text.starts_with("HTTP/1.1 200"), "{label}: {text}");
                let seen = timeout(Duration::from_secs(5), forwarded.recv())
                    .await
                    .unwrap_or_else(|_| panic!("not forwarded: {label}"))
                    .unwrap();
                assert_eq!(seen.method, *method, "{label}");
            }
        }
        task.abort();
    }
}

/// Without a Chat relay the forwarder never parses the device-proof cookie
/// (a malformed one raises no error) nor looks at the saved preference file;
/// with the relay both happen, which proves the probes observe them.
#[tokio::test]
async fn no_chat_relay_never_parses_the_device_cookie_nor_reads_preferences() {
    static NONE: crate::gateway::NoGatewayExtension = crate::gateway::NoGatewayExtension;
    for capability in [true, false] {
        let (url, mut forwarded, task) = recording_gateway().await;
        let (mut state, root) = proof_test_state(&url, &url, None);
        state.gateway_session = std::sync::OnceLock::new();
        state.chatgpt_chat_passthrough = true;
        if !capability {
            state.gateway = &NONE;
        }
        let preferences = root.path().join(".codex-global-state.json");
        fs::write(
            &preferences,
            br#"{"electron-persisted-atom-state":{"chatgpt-last-selected-model-v1":{"slug":"gpt-5-6-thinking"}}}"#,
        )
        .unwrap();

        let duplicated = IncomingRequest {
            method: "GET".into(),
            target: "/chatgpt/backend-api/devicecheck".into(),
            http_version: "HTTP/1.1".into(),
            body: Vec::new(),
            headers: vec![(
                "Cookie".into(),
                "_devicecheck=MOCK_ONLY_FIRST; _devicecheck=MOCK_ONLY_SECOND".into(),
            )],
        };
        let result = forward_to_saiai_with_preferences_path(
            &state,
            &mut tokio::io::sink(),
            duplicated,
            true,
            GatewayRoute::OpenAI,
            CredentialPolicy::Replace,
            None,
        )
        .await;
        if capability {
            let error = format!("{:#}", result.unwrap_err());
            assert!(
                error.contains("invalid native Chat device proof"),
                "{error}"
            );
            assert!(forwarded.try_recv().is_err());
        } else {
            result.unwrap();
            let seen = forwarded.recv().await.unwrap();
            assert_eq!(header_value(&seen.headers, "cookie"), None);
        }

        let init = IncomingRequest {
            method: "POST".into(),
            target: "/chatgpt/backend-api/conversation/init".into(),
            http_version: "HTTP/1.1".into(),
            body: br#"{"conversation_origin":null,"requested_default_model":null}"#.to_vec(),
            headers: Vec::new(),
        };
        let before = super::preference_reads();
        forward_to_saiai_with_preferences_path(
            &state,
            &mut tokio::io::sink(),
            init,
            true,
            GatewayRoute::OpenAI,
            CredentialPolicy::Replace,
            Some(&preferences),
        )
        .await
        .unwrap();
        let reads = super::preference_reads() - before;
        assert_eq!(
            reads > 0,
            capability,
            "capability={capability} reads={reads}"
        );
        task.abort();
    }
}

/// Byte goldens of the Claude Desktop listener's own answers (frozen from
/// the SAIAI build before their names moved to `Brand`). The organization
/// id is a random UUID (`Identity::prepare`): only its format is frozen.
#[tokio::test]
async fn claude_desktop_local_answers_are_byte_identical() {
    let root = tempfile::tempdir().unwrap();
    let response = tls_request(
        state(Some(root.path()), None),
        EntryPoint::ClaudeDesktop,
        "claude.ai",
        b"GET /api/account HTTP/1.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 104\r\nContent-Type: application/json\r\n\r\n{\"error\":\"desktop_identity_missing\",\"message\":\"Run saiai desktop claude to initialize this environment\"}"
    );

    let id = crate::claude_desktop::Identity::prepare(root.path()).unwrap();
    let org = &id.organization;
    assert!(
        org.len() == 36
            && org
                .char_indices()
                .all(|(index, ch)| if matches!(index, 8 | 13 | 18 | 23) {
                    ch == '-'
                } else {
                    ch.is_ascii_hexdigit()
                }),
        "{org}"
    );
    let response = tls_request(
        state(Some(root.path()), None),
        EntryPoint::ClaudeDesktop,
        ANTHROPIC_HOST,
        format!(
            "GET /api/oauth/profile HTTP/1.1\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            id.access_token
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(
        String::from_utf8(response)
            .unwrap()
            .replace(org.as_str(), "<ORG-UUID>"),
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 312\r\nContent-Type: application/json\r\n\r\n{\"account\":{\"display_name\":\"SAIAI Local Code\",\"email_address\":\"\"},\"organization\":{\"active_flags\":[],\"capabilities\":[\"chat\",\"claude_pro\",\"claude_code\"],\"created_at\":\"2026-01-01T00:00:00Z\",\"name\":\"SAIAI Local Code\",\"rate_limit_tier\":\"default_claude_ai\",\"settings\":{},\"uuid\":\"<ORG-UUID>\"}}"
    );

    let response = tls_request(
        state(Some(root.path()), None),
        EntryPoint::ClaudeDesktop,
        "claude.ai",
        format!(
            "GET /api/zzz_unknown HTTP/1.1\r\nCookie: sessionKey={}\r\nConnection: close\r\n\r\n",
            id.session
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 120\r\nContent-Type: application/json\r\n\r\n{\"error\":{\"message\":\"This Desktop control endpoint is unavailable through SAIAI.\",\"type\":\"desktop_control_unsupported\"}}"
    );

    fs::write(
        root.path().join("desktop/claude/state/identity.json"),
        b"{MOCK_ONLY_BROKEN",
    )
    .unwrap();
    let response = tls_request(
        state(Some(root.path()), None),
        EntryPoint::ClaudeDesktop,
        "claude.ai",
        b"GET /api/account HTTP/1.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 124\r\nContent-Type: application/json\r\n\r\n{\"error\":\"desktop_identity_invalid\",\"message\":\"Repair the isolated Desktop identity file and relaunch saiai desktop claude\"}"
    );
}
