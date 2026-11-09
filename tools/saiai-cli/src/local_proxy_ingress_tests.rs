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
            client_proof_dir: None,
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
    state.client_proof = std::sync::OnceLock::new();
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
    assert!(state.client_proof_dir.is_none());
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
        client_proof_dir: None,
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
    state.client_proof = std::sync::OnceLock::new();
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
