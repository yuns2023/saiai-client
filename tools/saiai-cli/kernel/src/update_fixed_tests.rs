//! The fixed-URL update source against a local HTTP server: every request
//! and redirect is checked by the same policy code as production, with a
//! plain-HTTP policy for the loopback server (the HTTPS policy itself is
//! checked as a pure function).

use super::*;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// A canned response.
#[derive(Clone, Default)]
struct Reply {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    /// Send no Content-Length (the body ends when the connection closes).
    no_length: bool,
    /// Pause before the head.
    head_delay: Duration,
    /// Pause after the head, before the body.
    delay: Duration,
}

/// One canned response per path (query included).
type Routes = HashMap<String, Reply>;

/// A loopback server: its port and every request target it received (an
/// absolute-form target means the request came through it as a proxy).
struct Server {
    port: u16,
    /// Request heads received, in order.
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Server {
    /// Request targets received, in order.
    fn requested(&self) -> Vec<String> {
        self.heads()
            .iter()
            .map(|head| {
                head.split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    fn heads(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// Serves `routes` on a loopback port until the test ends; unknown paths
/// answer 404. Absolute-form targets (proxy requests) are answered by path.
async fn serve(routes: Routes) -> u16 {
    serve_with(move |_| routes).await.port
}

/// Like `serve`, with routes that may name the server's own port.
async fn serve_with(routes: impl FnOnce(u16) -> Routes) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes = Arc::new(routes(port));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let routes = Arc::clone(&routes);
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head);
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                log.lock().unwrap().push(head.to_string());
                let path = match target.strip_prefix("http://") {
                    Some(rest) => rest
                        .find('/')
                        .map_or("/".to_string(), |at| rest[at..].to_string()),
                    None => target,
                };
                let reply = routes.get(&path).cloned().unwrap_or(Reply {
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
                    response.extend(name.bytes());
                    response.extend(b": ");
                    response.extend(value);
                    response.extend(b"\r\n");
                }
                response.extend(b"\r\n");
                tokio::time::sleep(reply.head_delay).await;
                if stream.write_all(&response).await.is_err() {
                    return;
                }
                tokio::time::sleep(reply.delay).await;
                let _ = stream.write_all(&reply.body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Server { port, requests }
}

fn ok(body: &[u8]) -> Reply {
    Reply {
        status: 200,
        body: body.to_vec(),
        ..Reply::default()
    }
}

fn redirect(status: u16, location: &str) -> Reply {
    Reply {
        status,
        headers: vec![("Location".to_string(), location.as_bytes().to_vec())],
        ..Reply::default()
    }
}

/// The loopback server's policy: plain HTTP, `127.0.0.1` only, its port.
fn loopback(port: u16) -> FixedUrlPolicy<'static> {
    FixedUrlPolicy {
        hosts: &["127.0.0.1"],
        scheme: "http",
        ports: Vec::leak(vec![port]),
    }
}

fn direct() -> Egress {
    Egress {
        installation_ca_pem: None,
        upstream: upstream_proxy::UpstreamProxy::new(Some("direct"), None, Vec::new()).snapshot(),
        resolve: Vec::new(),
    }
}

async fn get(port: u16, path: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    get_within(port, path, limit, Duration::from_secs(10)).await
}

async fn get_within(port: u16, path: &str, limit: u64, total: Duration) -> Result<Option<Vec<u8>>> {
    fixed_get(
        &loopback(port),
        &format!("http://127.0.0.1:{port}{path}"),
        limit,
        total,
        &direct(),
    )
    .await
}

#[test]
fn https_policy_accepts_only_exact_hosts_on_the_default_port() {
    let policy = FixedUrlPolicy::https(&["github.com", "release-assets.githubusercontent.com"]);
    for allowed in [
        "https://github.com/o/r/releases/latest/download/m.json",
        "https://GitHub.com/o/r",
        "https://github.com:443/o/r",
        "https://release-assets.githubusercontent.com/a?sig=x&se=1",
    ] {
        policy
            .check(allowed)
            .unwrap_or_else(|error| panic!("{allowed}: {error:#}"));
    }
    for refused in [
        "http://github.com/o/r",
        "https://github.com:8443/o/r",
        "https://user:secret@github.com/o/r",
        "https://user@github.com/o/r",
        "https://github.com/o/r#fragment",
        "https://evil-github.com/o/r",
        "https://github.com.evil.example/o/r",
        "https://sub.github.com/o/r",
        "https://140.82.112.3/o/r",
        "ftp://github.com/o/r",
        "not a url",
    ] {
        assert!(policy.check(refused).is_err(), "{refused}");
    }
}

#[test]
fn release_versions_are_three_plain_numbers() {
    for version in ["0.1.0", "1.2.3", "10.20.30", "0.0.0"] {
        assert!(is_release_version(version), "{version}");
    }
    for version in [
        "",
        "1.2",
        "1.2.3.4",
        "v1.2.3",
        " 1.2.3",
        "1.2.3 ",
        "1.2.3-rc.1",
        "1.2.3+b",
        "01.2.3",
        "1.02.3",
        "1..3",
        "1.2.x",
        "+1.2.3",
        "1.2.3/..",
        "1234567890.0.0",
    ] {
        assert!(!is_release_version(version), "{version:?}");
    }
}

#[test]
fn asset_urls_substitute_version_and_asset() {
    assert_eq!(
        fixed_asset_url(
            "https://github.com/o/r/releases/download/v{version}/{asset}",
            "1.2.3",
            "x-linux-x86_64"
        ),
        "https://github.com/o/r/releases/download/v1.2.3/x-linux-x86_64"
    );
}

#[test]
fn brand_update_sources_are_validated_at_install() {
    use crate::brand::{FixedUpdateSource, UpdateSource};
    static HOSTS: &[&str] = &["github.com"];
    let fixed = |manifest_url, asset_url_template, hosts| {
        crate::brand::validate_update_source(&UpdateSource::Fixed(FixedUpdateSource {
            manifest_url,
            asset_url_template,
            hosts,
        }))
    };
    fixed(
        "https://github.com/o/r/releases/latest/download/m.json",
        "https://github.com/o/r/releases/download/v{version}/{asset}",
        HOSTS,
    )
    .unwrap();
    for (manifest, template, hosts) in [
        (
            "http://github.com/m.json",
            "https://github.com/v{version}/{asset}",
            HOSTS,
        ),
        (
            "https://example.com/m.json",
            "https://github.com/v{version}/{asset}",
            HOSTS,
        ),
        (
            "https://github.com/m.json",
            "https://github.com/{asset}",
            HOSTS,
        ),
        (
            "https://github.com/m.json",
            "https://github.com/v{version}/{version}/{asset}",
            HOSTS,
        ),
        (
            "https://github.com/m.json",
            "https://example.com/v{version}/{asset}",
            HOSTS,
        ),
        (
            "https://github.com/m.json",
            "https://github.com/v{version}/{asset}",
            &["GitHub.com"],
        ),
        (
            "https://github.com/m.json",
            "https://github.com/v{version}/{asset}",
            &[],
        ),
    ] {
        assert!(
            fixed(manifest, template, hosts).is_err(),
            "{manifest} {template} {hosts:?}"
        );
    }
    let gateway = |channel_path| {
        crate::brand::validate_update_source(&UpdateSource::GatewayChannel { channel_path })
    };
    gateway("ktest-cli").unwrap();
    gateway("a/b.c_d~e").unwrap();
    for channel in ["", "/x", "x/", "a//b", "a b", "a?b", "a%2fb"] {
        assert!(gateway(channel).is_err(), "{channel:?}");
    }
}

#[tokio::test]
async fn redirects_are_followed_within_the_policy() {
    let port = serve_with(|port| {
        Routes::from([
            ("/latest".to_string(), redirect(302, "/hop")),
            (
                "/hop".to_string(),
                redirect(307, &format!("http://127.0.0.1:{port}/final")),
            ),
            ("/final".to_string(), ok(b"body")),
        ])
    })
    .await
    .port;
    assert_eq!(get(port, "/latest", 1024).await.unwrap().unwrap(), b"body");
}

#[tokio::test]
async fn a_relative_redirect_chain_reaches_the_body() {
    let port = serve(Routes::from([
        ("/a".to_string(), redirect(301, "/b")),
        ("/b".to_string(), redirect(303, "c")),
        ("/c".to_string(), redirect(307, "./d")),
        ("/d".to_string(), redirect(308, "/e?x=1&sig=abc")),
        ("/e?x=1&sig=abc".to_string(), ok(b"done")),
    ]))
    .await;
    assert_eq!(get(port, "/a", 1024).await.unwrap().unwrap(), b"done");
}

/// Each redirect changes one thing the policy forbids; the request fails
/// for that reason and the forbidden target is never requested.
#[tokio::test]
async fn redirects_leaving_the_policy_are_refused_before_they_are_followed() {
    let server = serve_with(|port| {
        Routes::from([
            (
                "/host".to_string(),
                redirect(302, &format!("http://localhost:{port}/forbidden")),
            ),
            (
                "/scheme".to_string(),
                redirect(302, &format!("https://127.0.0.1:{port}/forbidden")),
            ),
            (
                "/userinfo".to_string(),
                redirect(302, &format!("http://user@127.0.0.1:{port}/forbidden")),
            ),
            (
                "/port".to_string(),
                redirect(302, &format!("http://127.0.0.1:{}/forbidden", port + 1)),
            ),
            ("/fragment".to_string(), redirect(302, "/forbidden#part")),
            (
                "/no-location".to_string(),
                Reply {
                    status: 302,
                    ..Reply::default()
                },
            ),
            (
                "/binary-location".to_string(),
                Reply {
                    status: 302,
                    headers: vec![("Location".to_string(), b"/forbidden\xff".to_vec())],
                    ..Reply::default()
                },
            ),
            ("/forbidden".to_string(), ok(b"must not be reached")),
        ])
    })
    .await;
    let port = server.port;
    for (path, reason) in [
        ("/host", "is not on an allowed update host"),
        ("/scheme", "does not use http"),
        ("/userinfo", "carries user information"),
        ("/port", "names a port that is not allowed"),
        ("/fragment", "carries a fragment"),
        ("/no-location", "without a Location"),
        ("/binary-location", "Location that is not plain ASCII"),
    ] {
        let error = format!("{:#}", get(port, path, 1024).await.unwrap_err());
        assert!(error.contains(reason), "{path}: {error}");
    }
    assert!(
        !server
            .requested()
            .iter()
            .any(|target| target.contains("forbidden")),
        "{:?}",
        server.requested()
    );
}

#[tokio::test]
async fn five_redirects_are_followed_and_a_sixth_is_refused() {
    let mut routes = Routes::new();
    for hop in 0..6 {
        routes.insert(format!("/r{hop}"), redirect(302, &format!("/r{}", hop + 1)));
    }
    routes.insert("/r6".to_string(), ok(b"six"));
    routes.insert("/s5".to_string(), redirect(302, "/r6"));
    for hop in 0..5 {
        routes.insert(format!("/s{hop}"), redirect(302, &format!("/s{}", hop + 1)));
    }
    let port = serve(routes).await;
    // /s0 -> s1 -> s2 -> s3 -> s4 -> s5 -> r6: six redirects.
    let error = format!("{:#}", get(port, "/s0", 1024).await.unwrap_err());
    assert!(error.contains("redirected more than 5 times"), "{error}");
    // /r1 -> r2 -> r3 -> r4 -> r5 -> r6: five redirects.
    assert_eq!(get(port, "/r1", 1024).await.unwrap().unwrap(), b"six");
}

#[tokio::test]
async fn bodies_without_a_length_are_limited_while_streaming() {
    let port = serve(Routes::from([
        (
            "/unbounded".to_string(),
            Reply {
                no_length: true,
                ..ok(&[b'x'; 4096])
            },
        ),
        (
            "/fits".to_string(),
            Reply {
                no_length: true,
                ..ok(&[b'x'; 1024])
            },
        ),
    ]))
    .await;
    let error = format!("{:#}", get(port, "/unbounded", 1024).await.unwrap_err());
    assert!(error.contains("larger than 1024"), "{error}");
    assert_eq!(get(port, "/fits", 1024).await.unwrap().unwrap().len(), 1024);
}

/// Each hop alone fits in the budget; together they do not.
#[tokio::test]
async fn the_whole_chain_shares_one_deadline() {
    let slow = Duration::from_millis(700);
    let port = serve(Routes::from([
        (
            "/start".to_string(),
            Reply {
                head_delay: slow,
                ..redirect(302, "/slow")
            },
        ),
        (
            "/slow".to_string(),
            Reply {
                head_delay: slow,
                ..ok(b"late")
            },
        ),
    ]))
    .await;
    let budget = Duration::from_secs(1);
    // One slow hop alone completes.
    assert_eq!(
        get_within(port, "/slow", 1024, budget)
            .await
            .unwrap()
            .unwrap(),
        b"late"
    );
    let error = get_within(port, "/start", 1024, budget).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("did not complete within 1s"),
        "{error:#}"
    );
}

/// The command returns when the update future does, even if blocking work
/// it started (route selection) is still running.
#[test]
fn a_timed_out_update_does_not_wait_for_its_blocking_work() {
    let started = std::time::Instant::now();
    let output = block_on_abandoning(async {
        let stuck = tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(5)));
        tokio::time::timeout(Duration::from_millis(100), stuck)
            .await
            .is_err()
    })
    .unwrap();
    assert!(output, "the future timed out");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

/// Loopback targets always go direct, so the first origin is a name only
/// the proxy knows; it redirects to a loopback origin, which the next hop
/// reaches directly: each hop is routed for its own target.
#[tokio::test]
async fn every_hop_is_routed_for_its_own_target() {
    let origin = serve_with(|_| Routes::from([("/c".to_string(), ok(b"direct origin"))])).await;
    let origin_port = origin.port;
    let proxy = serve_with(move |_| {
        Routes::from([
            ("/a".to_string(), redirect(302, "/b")),
            (
                "/b".to_string(),
                redirect(302, &format!("http://127.0.0.1:{origin_port}/c")),
            ),
        ])
    })
    .await;
    let via = |port: u16| Egress {
        installation_ca_pem: None,
        upstream: upstream_proxy::UpstreamProxy::new(
            Some(&format!("http://127.0.0.1:{port}")),
            None,
            Vec::new(),
        )
        .snapshot(),
        resolve: Vec::new(),
    };
    let policy = FixedUrlPolicy {
        hosts: &["updates.invalid", "127.0.0.1"],
        scheme: "http",
        ports: Vec::leak(vec![8080, origin_port]),
    };
    let body = fixed_get(
        &policy,
        "http://updates.invalid:8080/a",
        1024,
        Duration::from_secs(10),
        &via(proxy.port),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(body, b"direct origin");
    assert_eq!(
        proxy.requested(),
        vec![
            "http://updates.invalid:8080/a".to_string(),
            "http://updates.invalid:8080/b".to_string(),
        ]
    );
    assert_eq!(origin.requested(), vec!["/c".to_string()]);
}

/// A proxy that fails (accepts, then closes: deterministic, unlike a freed
/// port another process may take) fails the request, and the origin is
/// never contacted directly: the client resolves the origin's name to an
/// observable local server, which a direct attempt would reach (shown by
/// the direct control).
#[tokio::test]
async fn a_failing_proxy_fails_the_request_without_going_direct() {
    let origin = serve_with(|_| Routes::from([("/a".to_string(), ok(b"origin"))])).await;
    let closing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = closing.local_addr().unwrap().port();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&attempts);
    tokio::spawn(async move {
        while let Ok((socket, _)) = closing.accept().await {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(socket);
        }
    });
    let egress = |setting: &str| Egress {
        installation_ca_pem: None,
        upstream: upstream_proxy::UpstreamProxy::new(Some(setting), None, Vec::new()).snapshot(),
        resolve: vec![(
            "updates.invalid".to_string(),
            SocketAddr::from(([127, 0, 0, 1], origin.port)),
        )],
    };
    let ports = [origin.port];
    let policy = FixedUrlPolicy {
        hosts: &["updates.invalid"],
        scheme: "http",
        ports: &ports,
    };
    let url = format!("http://updates.invalid:{}/a", origin.port);
    // Control: going direct with this resolution reaches the origin.
    let body = fixed_get(
        &policy,
        &url,
        1024,
        Duration::from_secs(10),
        &egress("direct"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(body, b"origin");
    assert_eq!(origin.requested().len(), 1);
    let error = fixed_get(
        &policy,
        &url,
        1024,
        Duration::from_secs(10),
        &egress(&format!("http://127.0.0.1:{proxy_port}")),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{error:#}").contains(&format!("failed to GET {url}")),
        "{error:#}"
    );
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(origin.requested().len(), 1, "{:?}", origin.requested());
}

/// No hop carries credentials: no Authorization or Cookie anywhere, and the
/// proxy's own credentials go only to the proxy, never to the next host.
#[tokio::test]
async fn requests_carry_no_credentials_across_hosts() {
    let origin = serve_with(|_| Routes::from([("/c".to_string(), ok(b"body"))])).await;
    let origin_port = origin.port;
    let proxy = serve_with(move |_| {
        Routes::from([(
            "/a".to_string(),
            redirect(302, &format!("http://127.0.0.1:{origin_port}/c")),
        )])
    })
    .await;
    let egress = Egress {
        installation_ca_pem: None,
        upstream: upstream_proxy::UpstreamProxy::new(
            Some(&format!("http://user:secret@127.0.0.1:{}", proxy.port)),
            None,
            Vec::new(),
        )
        .snapshot(),
        resolve: Vec::new(),
    };
    let policy = FixedUrlPolicy {
        hosts: &["updates.invalid", "127.0.0.1"],
        scheme: "http",
        ports: Vec::leak(vec![8080, origin_port]),
    };
    fixed_get(
        &policy,
        "http://updates.invalid:8080/a",
        1024,
        Duration::from_secs(10),
        &egress,
    )
    .await
    .unwrap()
    .unwrap();
    let lower = |heads: Vec<String>| heads.join("\n").to_ascii_lowercase();
    let (proxy_heads, origin_heads) = (lower(proxy.heads()), lower(origin.heads()));
    assert!(!proxy_heads.is_empty() && !origin_heads.is_empty());
    for head in [&proxy_heads, &origin_heads] {
        assert!(!head.contains("\nauthorization:"), "{head}");
        assert!(!head.contains("\ncookie:"), "{head}");
    }
    assert!(
        proxy_heads.contains("\nproxy-authorization:"),
        "{proxy_heads}"
    );
    assert!(
        !origin_heads.contains("proxy-authorization"),
        "{origin_heads}"
    );
    assert!(!origin_heads.contains("secret"), "{origin_heads}");
}

#[tokio::test]
async fn a_slow_body_runs_out_of_time() {
    let port = serve(Routes::from([(
        "/slow-body".to_string(),
        Reply {
            delay: Duration::from_secs(3),
            ..ok(b"late")
        },
    )]))
    .await;
    let started = std::time::Instant::now();
    let error = get_within(port, "/slow-body", 1024, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("did not complete within 1s"),
        "{error:#}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// The download layer of a fixed-source update (egress setup and fetch, as
/// `update` runs them) without a configuration, i.e. not initialized: it
/// proceeds to a verified download. (The command end to end is covered by
/// the distribution's black-box tests.)
#[test]
fn the_download_layer_needs_no_configuration() {
    let server = tokio::runtime::Runtime::new().unwrap();
    let bytes = release_bytes();
    let sha = sha256_hex(&bytes);
    let port = server.block_on(serve(release(
        manifest("9.9.9", &sha, Some(bytes.len() as u64)),
        bytes.clone(),
    )));
    let policy = loopback(port);
    let result = fixed_download(
        &policy,
        &format!("http://127.0.0.1:{port}/releases/latest/download/manifest.json"),
        &format!("http://127.0.0.1:{port}/releases/download/v{{version}}/{{asset}}"),
        None,
        ASSET,
        "1.0.0",
        "0",
    )
    .unwrap();
    assert!(matches!(result, FixedUpdate::Download { version, .. } if version == "9.9.9"));
}

/// A configuration that exists but cannot be read stops the update; only a
/// missing one means "not initialized".
#[test]
fn only_a_missing_configuration_counts_as_uninitialized() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    assert!(read_app_config_at_if_present(&path).unwrap().is_none());
    fs::write(&path, b"{not json").unwrap();
    let error = read_app_config_at_if_present(&path).err().unwrap();
    assert!(
        format!("{error:#}").contains("failed to parse"),
        "{error:#}"
    );
    fs::write(&path, b"{}").unwrap();
    assert!(read_app_config_at_if_present(&path).is_err());
    #[cfg(unix)]
    {
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(directory.path().join("gone"), &path).unwrap();
        let error = read_app_config_at_if_present(&path).err().unwrap();
        assert!(format!("{error:#}").contains("failed to read"), "{error:#}");
    }
}

#[test]
fn one_update_at_a_time_per_installation_directory() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let held = lock_update_directory(first.path()).unwrap();
    let error = lock_update_directory(first.path()).unwrap_err();
    assert!(
        format!("{error:#}").contains("another ktest update or uninstall is running"),
        "{error:#}"
    );
    let _other = lock_update_directory(second.path()).unwrap();
    drop(held);
    let _again = lock_update_directory(first.path()).unwrap();
    // Unix locks the directory itself: nothing that uninstall could delete.
    #[cfg(unix)]
    assert_eq!(fs::read_dir(first.path()).unwrap().count(), 0);
    #[cfg(windows)]
    assert!(first.path().join(".ktest-update-lock").is_file());
}

/// Windows: a replacement helper holding the helper lock keeps updates and
/// uninstall out after the updater has gone.
#[cfg(windows)]
#[test]
fn a_held_helper_lock_keeps_the_installation_locked() {
    use std::os::windows::fs::OpenOptionsExt;
    let directory = tempfile::tempdir().unwrap();
    let helper = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .share_mode(0)
        .open(directory.path().join(".ktest-update-helper-lock"))
        .unwrap();
    let error = lock_update_directory(directory.path()).unwrap_err();
    assert!(
        format!("{error:#}").contains("a previous ktest update is still being installed"),
        "{error:#}"
    );
    // Refused without keeping the main lock.
    drop(helper);
    let lock = lock_update_directory(directory.path()).unwrap();
    assert!(lock.holds(&directory.path().join(".ktest-update-lock")));
    assert!(lock.holds(&directory.path().join(".ktest-update-helper-lock")));
    assert!(!lock.holds(&directory.path().join(".ktest-update-x")));
}

/// Windows: a helper that never takes the helper lock is reported (the
/// caller stops it), and the lock is not kept open while waiting.
#[cfg(windows)]
#[test]
fn a_helper_that_does_not_take_over_is_reported() {
    let directory = tempfile::tempdir().unwrap();
    let mut lock = lock_update_directory(directory.path()).unwrap();
    let started = std::time::Instant::now();
    let (mut child, handed_over) = lock
        .hand_over_to_helper(Duration::from_secs(1), || {
            Ok(ProcessCommand::new("cmd")
                .args(["/c", "ping -n 30 127.0.0.1 >nul"])
                .spawn()?)
        })
        .unwrap();
    assert!(!handed_over);
    assert!(started.elapsed() < Duration::from_secs(10));
    // The update then stops it and cleans up.
    let dir = directory.path();
    let candidate = dir.join(".ktest-update-1.exe");
    let script = dir.join(".ktest-update-1.ps1");
    let status = dir.join(".ktest-update-status.txt");
    for path in [&candidate, &script, &status] {
        fs::write(path, b"x").unwrap();
    }
    let error = cancel_windows_update_helper(&mut child, &candidate, &script, &status);
    let error = format!("{error:#}");
    assert!(
        error.contains("did not lock the installation directory"),
        "{error}"
    );
    assert!(child.try_wait().unwrap().is_some());
    assert!(!candidate.exists() && !script.exists());
    let report = fs::read_to_string(&status).unwrap();
    assert!(
        report.starts_with("failed: the Windows update helper"),
        "{report}"
    );
}

/// Windows: the real replacement helper takes the helper lock before the
/// updater lets go, and holds it until it has replaced the program; only
/// then can the next update or uninstall lock the directory.
#[cfg(windows)]
#[test]
fn the_windows_replacement_helper_holds_the_installation_until_done() {
    let directory = tempfile::tempdir().unwrap();
    let dir = directory.path();
    // The "installed program": its `stop` waits until the test lets it go.
    let current = dir.join("current.cmd");
    let release = dir.join("release");
    fs::write(
        &current,
        format!(
            "@echo off\r\n:wait\r\nif exist \"{}\" exit /b 0\r\nping -n 2 127.0.0.1 >nul\r\ngoto wait\r\n",
            release.display()
        ),
    )
    .unwrap();
    let new_program = b"@exit /b 0\r\n".to_vec();
    let candidate = dir.join(".ktest-update-1.exe");
    fs::write(&candidate, &new_program).unwrap();
    let script_path = dir.join(".ktest-update-1.ps1");
    let status_path = dir.join(".ktest-update-status.txt");
    fs::write(&status_path, "pending\n").unwrap();
    // The updater the helper waits for: a short-lived process.
    let mut updater = ProcessCommand::new("cmd")
        .args(["/c", "ping -n 2 127.0.0.1 >nul"])
        .spawn()
        .unwrap();
    let mut lock = lock_update_directory(dir).unwrap();
    let helper_lock = dir.join(".ktest-update-helper-lock");
    let script = render_windows_update_script_locked(
        updater.id(),
        &current,
        &candidate,
        &script_path,
        &status_path,
        false,
        &sha256_hex(&new_program),
        Some(&helper_lock),
    )
    .unwrap();
    fs::write(&script_path, script).unwrap();
    let mut helper = None;
    let ((), handed_over) = lock
        .hand_over_to_helper(Duration::from_secs(30), || {
            helper = Some(
                ProcessCommand::new("powershell")
                    .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                    .arg(&script_path)
                    .stdin(Stdio::null())
                    .spawn()?,
            );
            Ok(())
        })
        .unwrap();
    assert!(handed_over);
    drop(lock);
    // The updater has let go; the helper still waits for it and stops the
    // program, holding the installation.
    let error = lock_update_directory(dir).unwrap_err();
    assert!(
        format!("{error:#}").contains("still being installed"),
        "{error:#}"
    );
    fs::write(&release, b"").unwrap();
    let status = helper.unwrap().wait().unwrap();
    let _ = updater.wait();
    let report = fs::read_to_string(&status_path).unwrap();
    assert!(status.success(), "{report}");
    assert!(
        report
            .trim_start_matches('\u{feff}')
            .starts_with("updated:"),
        "{report}"
    );
    assert_eq!(fs::read(&current).unwrap(), new_program);
    let _again = lock_update_directory(dir).unwrap();
}

#[test]
fn candidates_are_written_only_as_new_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(".ktest-update-x");
    write_new_update_candidate(&path, b"first").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"first");
    assert!(write_new_update_candidate(&path, b"second").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"first");
    #[cfg(unix)]
    {
        let target = directory.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = directory.path().join(".ktest-update-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_new_update_candidate(&link, b"replace").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }
}

/// Fake candidates (shell scripts): the probe reads a well-behaved one and
/// stops, reaps and reports the others within its budget.
#[cfg(unix)]
#[test]
fn candidate_probes_are_bounded() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let script = |name: &str, body: &str| {
        let path = directory.path().join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    };
    let budget = Duration::from_secs(1);
    let good = script("good", "echo 'ktest 1.2.3'");
    assert_eq!(
        probe_candidate_version(&good, budget, 4096).unwrap(),
        "ktest 1.2.3\n"
    );
    // Closing its output early and exiting a little later is fine.
    let closes_early = script("closes-early", "echo 'ktest 1.2.3'; exec >&-; sleep 0.3");
    assert_eq!(
        probe_candidate_version(&closes_early, budget, 4096).unwrap(),
        "ktest 1.2.3\n"
    );
    for (name, body, expected) in [
        ("hangs", "exec sleep 30", "did not exit within 1s"),
        ("floods", "exec yes", "printed more than 4096 bytes"),
        ("fails", "echo 'ktest 1.2.3'; exit 3", "exited with"),
        (
            "lingers",
            "echo 'ktest 1.2.3'; exec sleep 30 >&-",
            "did not exit after printing",
        ),
        (
            "succeeds-too-loud",
            "printf '%5000s' x; exit 0",
            "printed more than 4096 bytes",
        ),
        (
            "orphans",
            "echo 'ktest 1.2.3'; sleep 30 & echo $! > \"$0.pid\"; exit 0",
            "left its output open",
        ),
        (
            "orphans-and-hangs",
            "echo 'ktest 1.2.3'; sleep 30 & echo $! > \"$0.pid\"; exec sleep 30 >&-",
            "did not exit within 1s",
        ),
    ] {
        let started = std::time::Instant::now();
        let error = probe_candidate_version(&script(name, body), budget, 4096).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{name}: {error:#}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{name}: {:?}",
            started.elapsed()
        );
    }
    // Whatever the candidates started ended with the probe.
    for name in ["orphans", "orphans-and-hangs"] {
        let orphan = fs::read_to_string(directory.path().join(format!("{name}.pid"))).unwrap();
        assert!(!process_runs(orphan.trim()), "{name}: {orphan}");
    }
    // A candidate that succeeds but leaves something running (its output
    // closed): the version is read and the leftover ended.
    let leaves = script(
        "leaves",
        "echo 'ktest 1.2.3'; (exec >/dev/null 2>&1; sleep 30) & echo $! > \"$0.pid\"",
    );
    assert_eq!(
        probe_candidate_version(&leaves, budget, 4096).unwrap(),
        "ktest 1.2.3\n"
    );
    let leftover = fs::read_to_string(directory.path().join("leaves.pid")).unwrap();
    assert!(!process_runs(leftover.trim()), "{leftover}");
}

/// Whether process `pid` runs (a zombie, ended but not yet reaped by its
/// new parent, does not).
#[cfg(unix)]
fn process_runs(pid: &str) -> bool {
    let until = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let output = ProcessCommand::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let runs = !state.is_empty() && !state.starts_with('Z');
        // A killed process may take a moment to go.
        if !runs || std::time::Instant::now() >= until {
            return runs;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Windows: the probe runs the candidate (here a batch file, run by
/// cmd.exe) in a job: a descendant that keeps the output and the candidate
/// file open ends with the probe, which finishes within its budget, and the
/// candidate can then be removed.
#[cfg(windows)]
#[test]
fn candidate_probes_end_their_descendants_on_windows() {
    let directory = tempfile::tempdir().unwrap();
    let script = |name: &str, body: &str| {
        let path = directory.path().join(format!("{name}.cmd"));
        fs::write(&path, body.replace('\n', "\r\n")).unwrap();
        path
    };
    let budget = Duration::from_secs(30);
    let good = script("good", "@echo ktest 1.2.3\n");
    assert_eq!(
        probe_candidate_version(&good, budget, 4096).unwrap(),
        "ktest 1.2.3\r\n"
    );
    let started = std::time::Instant::now();
    let hangs = script("hangs", "@ping -n 30 127.0.0.1 >nul\n");
    let error = probe_candidate_version(&hangs, Duration::from_secs(2), 4096).unwrap_err();
    assert!(
        format!("{error:#}").contains("did not exit within 2s"),
        "{error:#}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    remove_candidate(&hangs).unwrap();

    // The descendant opens the candidate (no delete sharing), records its
    // process ID, and sleeps holding the output; the candidate waits for
    // that record, prints its version and exits.
    let path = directory.path().join("orphans.cmd");
    let marker = directory.path().join("orphans.pid");
    let held = format!(
        "$f = [IO.File]::Open('{}', 'Open', 'Read', 'Read'); Set-Content -LiteralPath '{}' -Value $PID; Start-Sleep 60",
        path.display(),
        marker.display()
    );
    let orphans = script(
        "orphans",
        &format!(
            "@echo off\nstart \"\" /b powershell -NoProfile -NonInteractive -Command \"{held}\"\n:wait\nif exist \"{}\" goto done\nping -n 2 127.0.0.1 >nul\ngoto wait\n:done\necho ktest 1.2.3\n",
            marker.display()
        ),
    );
    let started = std::time::Instant::now();
    let error = probe_candidate_version(&orphans, budget, 4096).unwrap_err();
    assert!(
        format!("{error:#}").contains("left its output open"),
        "{error:#}"
    );
    assert!(started.elapsed() < budget, "{:?}", started.elapsed());
    let pid = fs::read_to_string(&marker).unwrap();
    let pid = pid.trim_start_matches('\u{feff}').trim();
    let listed = ProcessCommand::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !listed.contains(&format!("\"{pid}\"")),
        "descendant {pid} still runs: {listed}"
    );
    remove_candidate(&orphans).unwrap();
    assert!(!orphans.exists());
}

#[tokio::test]
async fn a_redirect_loop_stops_at_the_limit() {
    let port = serve(Routes::from([(
        "/loop".to_string(),
        redirect(302, "/loop"),
    )]))
    .await;
    let error = format!("{:#}", get(port, "/loop", 1024).await.unwrap_err());
    assert!(error.contains("redirected more than 5 times"), "{error}");
}

#[test]
fn candidates_must_report_exactly_the_release_version() {
    for output in ["ktest 1.2.3", "ktest 1.2.3\n", "ktest 1.2.3\r\n"] {
        assert!(
            reports_exact_version(output, "ktest", "1.2.3"),
            "{output:?}"
        );
    }
    for output in [
        "ktest 1.2.4\n",
        " ktest 1.2.3\n",
        "ktest 1.2.3 \n",
        "ktest  1.2.3\n",
        "ktest 1.2.3\t\n",
        "ktest 1.2.3\n\n",
        "ktest 1.2.3\nextra\n",
        "other 1.2.3\n",
        "ktest v1.2.3\n",
        "",
    ] {
        assert!(
            !reports_exact_version(output, "ktest", "1.2.3"),
            "{output:?}"
        );
    }
}

#[tokio::test]
async fn missing_large_and_failed_responses_are_distinguished() {
    let port = serve(Routes::from([
        ("/large".to_string(), ok(&[b'x'; 2048])),
        (
            "/error".to_string(),
            Reply {
                status: 500,
                body: b"no".to_vec(),
                ..Reply::default()
            },
        ),
        ("/exact".to_string(), ok(&[b'x'; 1024])),
    ]))
    .await;
    assert!(get(port, "/missing", 1024).await.unwrap().is_none());
    let error = get(port, "/large", 1024).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("larger than 1024"),
        "{error:#}"
    );
    let error = get(port, "/error", 1024).await.unwrap_err();
    assert!(format!("{error:#}").contains("500"), "{error:#}");
    assert_eq!(
        get(port, "/exact", 1024).await.unwrap().unwrap().len(),
        1024
    );
}

const ASSET: &str = "ktest-linux-x86_64";

fn manifest(version: &str, sha256: &str, size: Option<u64>) -> Vec<u8> {
    let mut asset = serde_json::json!({ "sha256": sha256 });
    if let Some(size) = size {
        asset["size"] = size.into();
    }
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "assets": { ASSET: asset },
    }))
    .unwrap()
}

fn release_bytes() -> Vec<u8> {
    let mut bytes = vec![0_u8; 1024 * 1024 + 7];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes
}

async fn fetch(port: u16, current_version: &str, current_sha256: &str) -> Result<FixedUpdate> {
    fetch_fixed_update(
        &loopback(port),
        &format!("http://127.0.0.1:{port}/releases/latest/download/manifest.json"),
        &format!("http://127.0.0.1:{port}/releases/download/v{{version}}/{{asset}}"),
        ASSET,
        current_version,
        current_sha256,
        &direct(),
    )
    .await
}

fn release(manifest_body: Vec<u8>, asset: Vec<u8>) -> Routes {
    Routes::from([
        (
            "/releases/latest/download/manifest.json".to_string(),
            redirect(302, "/releases/download/v9.9.9/manifest.json"),
        ),
        (
            "/releases/download/v9.9.9/manifest.json".to_string(),
            ok(&manifest_body),
        ),
        (format!("/releases/download/v9.9.9/{ASSET}"), ok(&asset)),
    ])
}

#[tokio::test]
async fn a_newer_release_downloads_the_verified_asset_of_its_own_version() {
    let bytes = release_bytes();
    let sha = sha256_hex(&bytes);
    let port = serve(release(
        manifest("9.9.9", &sha, Some(bytes.len() as u64)),
        bytes.clone(),
    ))
    .await;
    match fetch(port, "1.0.0", "0").await.unwrap() {
        FixedUpdate::Download {
            bytes: got,
            version,
        } => {
            assert_eq!(version, "9.9.9");
            assert_eq!(got, bytes);
        }
        FixedUpdate::Current(message) => panic!("{message}"),
    }
    // Same version and bytes, or an older remote: nothing to download.
    for (current, current_sha) in [("9.9.9", sha.as_str()), ("10.0.0", "0")] {
        match fetch(port, current, current_sha).await.unwrap() {
            FixedUpdate::Current(message) => assert!(message.starts_with("Already current: ktest")),
            FixedUpdate::Download { .. } => panic!("{current}"),
        }
    }
}

#[tokio::test]
async fn no_published_release_is_a_clear_error_without_a_download() {
    let port = serve(Routes::new()).await;
    let error = fetch(port, "1.0.0", "0").await.err().unwrap();
    let text = format!("{error:#}");
    assert!(
        text.contains("update manifest is unavailable (HTTP 404")
            && text.contains("no release may have been published yet"),
        "{text}"
    );
}

#[tokio::test]
async fn manifests_and_assets_that_do_not_verify_are_refused() {
    let bytes = release_bytes();
    let sha = sha256_hex(&bytes);
    let length = bytes.len() as u64;
    let size = Some(length);
    let cases: Vec<(&str, Vec<u8>, Vec<u8>, &str)> = vec![
        (
            "bad version",
            manifest("latest", &sha, size),
            bytes.clone(),
            "not X.Y.Z",
        ),
        (
            "prefixed version",
            manifest("v9.9.9", &sha, size),
            bytes.clone(),
            "not X.Y.Z",
        ),
        (
            "no size",
            manifest("9.9.9", &sha, None),
            bytes.clone(),
            "has no size",
        ),
        (
            "tiny size",
            manifest("9.9.9", &sha, Some(10)),
            bytes.clone(),
            "has no size",
        ),
        (
            "huge size",
            manifest("9.9.9", &sha, Some(64 * 1024 * 1024 + 1)),
            bytes.clone(),
            "has no size",
        ),
        (
            "bad sha",
            manifest("9.9.9", "abc", size),
            bytes.clone(),
            "invalid sha256",
        ),
        (
            "wrong sha",
            manifest("9.9.9", &"0".repeat(64), size),
            bytes.clone(),
            "sha256 mismatch",
        ),
        (
            "short asset",
            manifest("9.9.9", &sha, Some(length + 1)),
            bytes.clone(),
            "the manifest says",
        ),
        (
            "long asset",
            manifest("9.9.9", &sha, Some(length - 1)),
            bytes.clone(),
            "larger than",
        ),
        (
            "not json",
            b"<html>".to_vec(),
            bytes.clone(),
            "failed to parse",
        ),
        (
            "other asset",
            serde_json::to_vec(&serde_json::json!({"version": "9.9.9", "assets": {}})).unwrap(),
            bytes.clone(),
            "does not include asset",
        ),
    ];
    for (name, manifest_body, asset, expected) in cases {
        let port = serve(release(manifest_body, asset)).await;
        let error = fetch(port, "1.0.0", "0").await.err().unwrap();
        assert!(format!("{error:#}").contains(expected), "{name}: {error:#}");
    }
    // The asset of another version is never used: the manifest names 9.9.9,
    // only 9.9.8's asset exists.
    let port = serve(Routes::from([
        (
            "/releases/latest/download/manifest.json".to_string(),
            ok(&manifest("9.9.9", &sha, size)),
        ),
        (format!("/releases/download/v9.9.8/{ASSET}"), ok(&bytes)),
    ]))
    .await;
    let error = fetch(port, "1.0.0", "0").await.err().unwrap();
    assert!(
        format!("{error:#}").contains("is missing (HTTP 404"),
        "{error:#}"
    );
}
