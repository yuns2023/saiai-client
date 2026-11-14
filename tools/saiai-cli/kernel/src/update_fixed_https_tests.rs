//! The fixed-URL update source over real HTTPS: a local TLS server with a
//! test CA that only the test's own client trusts (`Egress::test_ca_pem`;
//! no system or process-wide trust changes). Covers the host allowlist
//! (including redirects across hosts and certificate names), the redirect
//! limit, and the size and time limits, with the production code paths.

use super::*;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const GITHUB: &str = "github.com";
const ASSETS: &str = "release-assets.githubusercontent.com";
/// Allowed by the policy, but not named by the server's certificate.
const UNCERTIFIED: &str = "objects.githubusercontent.com";
/// Certified and resolved, but not allowed by the policy.
const EVIL: &str = "evil.example";

/// A test CA and a server configuration whose leaf (signed by it) names
/// `hosts`.
struct Pki {
    ca_pem: String,
    server: Arc<rustls::ServerConfig>,
}

fn pki(hosts: &[&str]) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Update HTTPS Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(
        hosts
            .iter()
            .map(|host| host.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .signed_by(&leaf_key, &ca, &ca_key)
    .unwrap();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(leaf.der().to_vec())],
        PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Pki {
        ca_pem: ca.pem(),
        server: Arc::new(server),
    }
}

#[derive(Clone, Default)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Send no Content-Length (the body ends when the connection closes).
    no_length: bool,
    /// Pause before the head.
    head_delay: Duration,
    /// Pause after the head, before the body.
    delay: Duration,
    /// Send the body in pieces of this many bytes (0: at once), flushing
    /// and pausing briefly after each.
    piece: usize,
}

/// One canned response per (Host, path).
type Routes = HashMap<(String, String), Reply>;

struct Server {
    port: u16,
    /// `<host> <path>` of every request that reached HTTP (after TLS).
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Server {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// An HTTPS server on a loopback port, for every host its certificate
/// names; unknown routes answer 404.
async fn serve(pki: &Pki, routes: impl FnOnce(u16) -> Routes) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes = Arc::new(routes(port));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&pki.server));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let routes = Arc::clone(&routes);
            let log = Arc::clone(&log);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let host = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("host").then(|| value.trim())
                    })
                    .unwrap_or_default();
                let host = host.split(':').next().unwrap_or_default().to_string();
                log.lock().unwrap().push(format!("{host} {path}"));
                let reply = routes.get(&(host, path)).cloned().unwrap_or(Reply {
                    status: 404,
                    body: b"missing".to_vec(),
                    ..Reply::default()
                });
                let mut response =
                    format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status).into_bytes();
                if !reply.no_length {
                    response.extend(format!("Content-Length: {}\r\n", reply.body.len()).bytes());
                }
                for (name, value) in reply.headers {
                    response.extend(format!("{name}: {value}\r\n").bytes());
                }
                response.extend(b"\r\n");
                tokio::time::sleep(reply.head_delay).await;
                if stream.write_all(&response).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
                tokio::time::sleep(reply.delay).await;
                let piece = if reply.piece == 0 {
                    reply.body.len().max(1)
                } else {
                    reply.piece
                };
                for chunk in reply.body.chunks(piece) {
                    if stream.write_all(chunk).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                    if reply.piece != 0 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    Server { port, requests }
}

fn route(host: &str, path: &str) -> (String, String) {
    (host.to_string(), path.to_string())
}

fn ok(body: &[u8]) -> Reply {
    Reply {
        status: 200,
        body: body.to_vec(),
        ..Reply::default()
    }
}

fn redirect(status: u16, location: String) -> Reply {
    Reply {
        status,
        headers: vec![("Location".to_string(), location)],
        ..Reply::default()
    }
}

/// The production policy shape (HTTPS, exact hosts), on the server's port
/// instead of 443.
fn policy(port: u16) -> FixedUrlPolicy<'static> {
    FixedUrlPolicy {
        hosts: &[GITHUB, ASSETS, UNCERTIFIED],
        scheme: "https",
        ports: Vec::leak(vec![port]),
    }
}

/// A direct client that resolves every test host to the server and trusts
/// `ca_pem` only (`None`: the real update client's roots).
fn egress(port: u16, ca_pem: Option<&str>) -> Egress {
    Egress {
        installation_ca_pem: None,
        upstream: upstream_proxy::UpstreamProxy::new(Some("direct"), None, Vec::new()).snapshot(),
        resolve: [GITHUB, ASSETS, UNCERTIFIED, EVIL]
            .iter()
            .map(|host| (host.to_string(), SocketAddr::from(([127, 0, 0, 1], port))))
            .collect(),
        test_ca_pem: ca_pem.map(str::to_string),
    }
}

fn url(host: &str, port: u16, path: &str) -> String {
    format!("https://{host}:{port}{path}")
}

async fn get(
    pki: &Pki,
    server: &Server,
    path: &str,
    limit: u64,
    total: Duration,
) -> Result<Option<Vec<u8>>> {
    fixed_get(
        &policy(server.port),
        &url(GITHUB, server.port, path),
        limit,
        total,
        &egress(server.port, Some(&pki.ca_pem)),
    )
    .await
}

const ASSET: &str = "ktest-linux-x86_64";

fn release_bytes() -> Vec<u8> {
    let mut bytes = vec![7_u8; 1024 * 1024 + 11];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes
}

/// A release published like GitHub's: `latest` and the versioned asset on
/// github.com redirect to the asset host.
fn github_release(port: u16, asset: &[u8]) -> Routes {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "version": "9.9.9",
        "assets": { ASSET: { "sha256": sha256_hex(asset), "size": asset.len() } },
    }))
    .unwrap();
    Routes::from([
        (
            route(GITHUB, "/o/r/releases/latest/download/m.json"),
            redirect(302, url(ASSETS, port, "/m.json?sig=1")),
        ),
        (route(ASSETS, "/m.json?sig=1"), ok(&manifest)),
        (
            route(GITHUB, &format!("/o/r/releases/download/v9.9.9/{ASSET}")),
            redirect(302, url(ASSETS, port, "/asset?sig=2")),
        ),
        (route(ASSETS, "/asset?sig=2"), ok(asset)),
    ])
}

async fn fetch_release(server: &Server, ca_pem: Option<&str>) -> Result<FixedUpdate> {
    let port = server.port;
    fetch_fixed_update(
        &policy(port),
        &url(GITHUB, port, "/o/r/releases/latest/download/m.json"),
        &url(GITHUB, port, "/o/r/releases/download/v{version}/{asset}"),
        ASSET,
        "1.0.0",
        "0",
        &egress(port, ca_pem),
    )
    .await
}

#[tokio::test]
async fn an_https_release_downloads_across_allowed_hosts() {
    let pki = pki(&[GITHUB, ASSETS, EVIL]);
    let bytes = release_bytes();
    let server = serve(&pki, |port| github_release(port, &bytes)).await;
    match fetch_release(&server, Some(&pki.ca_pem)).await.unwrap() {
        FixedUpdate::Download {
            bytes: got,
            version,
        } => {
            assert_eq!(version, "9.9.9");
            assert_eq!(got, bytes);
        }
        FixedUpdate::Current(message) => panic!("{message}"),
    }
    assert_eq!(
        server.requests(),
        [
            format!("{GITHUB} /o/r/releases/latest/download/m.json"),
            format!("{ASSETS} /m.json?sig=1"),
            format!("{GITHUB} /o/r/releases/download/v9.9.9/{ASSET}"),
            format!("{ASSETS} /asset?sig=2"),
        ]
    );
}

/// The test CA is trusted by the one client it is given to: the real update
/// client (system and bundled roots), a client given another CA, and the
/// real client again after a trusted download all fail the handshake, before
/// any request.
#[tokio::test]
async fn the_test_ca_is_trusted_only_by_the_client_it_is_given_to() {
    let pki = pki(&[GITHUB, ASSETS]);
    let other = pki_ca_only();
    let bytes = release_bytes();
    let server = serve(&pki, |port| github_release(port, &bytes)).await;
    for (label, ca) in [("system roots", None), ("another CA", Some(other.as_str()))] {
        let error = format!("{:#}", fetch_release(&server, ca).await.err().unwrap());
        assert!(error.contains("certificate"), "{label}: {error}");
    }
    assert!(server.requests().is_empty(), "{:?}", server.requests());
    assert!(matches!(
        fetch_release(&server, Some(&pki.ca_pem)).await.unwrap(),
        FixedUpdate::Download { .. }
    ));
    let requests = server.requests().len();
    let error = format!("{:#}", fetch_release(&server, None).await.err().unwrap());
    assert!(error.contains("certificate"), "{error}");
    assert_eq!(server.requests().len(), requests);
}

/// Just another CA's certificate (PEM).
fn pki_ca_only() -> String {
    pki(&[GITHUB]).ca_pem
}

/// Redirects are checked against the allowlist before they are followed:
/// another host (even one the server is certified for), plain HTTP, another
/// port. An allowed host the certificate does not name fails the handshake.
#[tokio::test]
async fn https_redirects_stay_on_allowed_and_certified_hosts() {
    let pki = pki(&[GITHUB, ASSETS, EVIL]);
    let server = serve(&pki, |port| {
        Routes::from([
            (route(GITHUB, "/evil"), redirect(302, url(EVIL, port, "/x"))),
            (route(EVIL, "/x"), ok(b"evil")),
            (
                route(GITHUB, "/plain"),
                redirect(301, format!("http://{GITHUB}:{port}/x")),
            ),
            (
                route(GITHUB, "/port"),
                redirect(307, url(GITHUB, port.wrapping_add(1).max(1), "/x")),
            ),
            (
                route(GITHUB, "/uncertified"),
                redirect(302, url(UNCERTIFIED, port, "/x")),
            ),
            (
                route(GITHUB, "/userinfo"),
                redirect(302, format!("https://user:secret@{ASSETS}:{port}/x")),
            ),
        ])
    })
    .await;
    for (path, expected) in [
        ("/evil", "not on an allowed update host"),
        ("/plain", "does not use https"),
        ("/port", "names a port that is not allowed"),
        ("/userinfo", "carries user information"),
    ] {
        let error = format!(
            "{:#}",
            get(&pki, &server, path, 1024, Duration::from_secs(10))
                .await
                .unwrap_err()
        );
        assert!(
            error.contains("redirected to a URL that is not allowed") && error.contains(expected),
            "{path}: {error}"
        );
    }
    let error = format!(
        "{:#}",
        get(&pki, &server, "/uncertified", 1024, Duration::from_secs(10))
            .await
            .unwrap_err()
    );
    assert!(error.contains("certificate"), "{error}");
    // Only the first hop of each chain reached the server.
    let requests = server.requests();
    assert_eq!(requests.len(), 5, "{requests:?}");
    assert!(
        requests.iter().all(|request| request.starts_with(GITHUB)),
        "{requests:?}"
    );
    // A URL off the allowlist is refused before any connection.
    let error = fixed_get(
        &policy(server.port),
        &url(EVIL, server.port, "/x"),
        1024,
        Duration::from_secs(10),
        &egress(server.port, Some(&pki.ca_pem)),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("not on an allowed update host"));
    assert_eq!(server.requests().len(), 5);
}

#[tokio::test]
async fn https_redirects_are_limited_to_five() {
    let pki = pki(&[GITHUB, ASSETS]);
    let server = serve(&pki, |port| {
        let mut routes = Routes::new();
        // /hop0 -> /hop1 -> ... -> /hop6, alternating hosts.
        for hop in 0..6 {
            let (host, next) = if hop % 2 == 0 {
                (GITHUB, ASSETS)
            } else {
                (ASSETS, GITHUB)
            };
            routes.insert(
                route(host, &format!("/hop{hop}")),
                redirect(302, url(next, port, &format!("/hop{}", hop + 1))),
            );
        }
        routes.insert(route(GITHUB, "/hop6"), ok(b"six"));
        routes
    })
    .await;
    // Five redirects (from /hop1, ending at /hop6) are followed.
    let five = fixed_get(
        &policy(server.port),
        &url(ASSETS, server.port, "/hop1"),
        1024,
        Duration::from_secs(10),
        &egress(server.port, Some(&pki.ca_pem)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(five, b"six");
    // A sixth (from /hop0) is refused.
    let error = get(&pki, &server, "/hop0", 1024, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("redirected more than 5 times"),
        "{error:#}"
    );
}

#[tokio::test]
async fn https_bodies_are_limited_in_size_and_time() {
    let pki = pki(&[GITHUB]);
    let server = serve(&pki, |_| {
        Routes::from([
            // The declared length alone must stop it: the body would come
            // only after the request's whole budget.
            (
                route(GITHUB, "/declared"),
                Reply {
                    delay: Duration::from_secs(30),
                    ..ok(&[1; 2048])
                },
            ),
            // No length: pieces each below the limit, together above it.
            (
                route(GITHUB, "/streamed"),
                Reply {
                    no_length: true,
                    piece: 300,
                    ..ok(&[1; 2048])
                },
            ),
            (route(GITHUB, "/exact"), ok(&[1; 1024])),
            (
                route(GITHUB, "/slow"),
                Reply {
                    delay: Duration::from_secs(30),
                    ..ok(b"late")
                },
            ),
        ])
    })
    .await;
    for path in ["/declared", "/streamed"] {
        // (`/declared` would otherwise end at the 10 s budget, not on size.)
        let error = get(&pki, &server, path, 1024, Duration::from_secs(10))
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("is larger than 1024 bytes"),
            "{path}: {error:#}"
        );
    }
    let exact = get(&pki, &server, "/exact", 1024, Duration::from_secs(10))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact.len(), 1024);
    let started = std::time::Instant::now();
    let error = get(&pki, &server, "/slow", 1024, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("did not complete within 1s"),
        "{error:#}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// One deadline covers the whole redirect chain: three hops that each
/// answer within the budget, but not all together. The margins (2 s for
/// one hop, 4 s for the chain) lower the chance that a busy machine flips
/// either outcome; a deadline reset per hop lets the chain through.
#[tokio::test]
async fn https_redirect_chains_share_one_deadline() {
    let pki = pki(&[GITHUB, ASSETS]);
    let slow = |reply: Reply| Reply {
        head_delay: Duration::from_secs(3),
        ..reply
    };
    let server = serve(&pki, |port| {
        Routes::from([
            (
                route(GITHUB, "/a"),
                slow(redirect(302, url(ASSETS, port, "/b"))),
            ),
            (
                route(ASSETS, "/b"),
                slow(redirect(302, url(GITHUB, port, "/c"))),
            ),
            (route(GITHUB, "/c"), slow(ok(b"late"))),
        ])
    })
    .await;
    // Each hop alone (3 s) fits in 5 s, with 2 s to spare ...
    let one = get(&pki, &server, "/c", 1024, Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(one, b"late");
    // ... the chain of three (9 s) does not, by 4 s.
    let started = std::time::Instant::now();
    let error = get(&pki, &server, "/a", 1024, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("did not complete within 5s"),
        "{error:#}"
    );
    assert!(started.elapsed() < Duration::from_secs(8));
}
