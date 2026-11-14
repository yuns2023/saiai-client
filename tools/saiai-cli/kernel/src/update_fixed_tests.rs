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
    /// Pause after the head, before the body.
    delay: Duration,
}

/// One canned response per path (query included).
type Routes = HashMap<String, Reply>;

/// A loopback server: its port and every request target it received (an
/// absolute-form target means the request came through it as a proxy).
struct Server {
    port: u16,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Server {
    fn requested(&self) -> Vec<String> {
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
                log.lock().unwrap().push(target.clone());
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
        port: Some(port),
    }
}

fn direct() -> Egress {
    Egress {
        installation_ca_pem: None,
        upstream: upstream_proxy::UpstreamProxy::new(Some("direct"), None, Vec::new()).snapshot(),
    }
}

async fn get(port: u16, path: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    fixed_get(
        &loopback(port),
        &format!("http://127.0.0.1:{port}{path}"),
        limit,
        Duration::from_secs(10),
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

#[tokio::test]
async fn the_whole_chain_shares_one_deadline() {
    let port = serve(Routes::from([
        ("/start".to_string(), redirect(302, "/slow")),
        (
            "/slow".to_string(),
            Reply {
                delay: Duration::from_secs(5),
                ..ok(b"late")
            },
        ),
    ]))
    .await;
    let started = std::time::Instant::now();
    let error = fixed_get(
        &loopback(port),
        &format!("http://127.0.0.1:{port}/start"),
        1024,
        Duration::from_secs(1),
        &direct(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("did not complete within 1s"),
        "{error:#}"
    );
    assert!(started.elapsed() < Duration::from_secs(4));
}

/// Loopback targets always go direct, so the origin here is a name that only
/// the proxy knows: every hop reaches it through the proxy.
#[tokio::test]
async fn every_hop_goes_through_the_configured_proxy() {
    // The proxy itself answers the absolute-form requests it receives.
    let proxy = serve_with(|_| {
        Routes::from([
            ("/a".to_string(), redirect(302, "/b")),
            ("/b".to_string(), ok(b"via proxy")),
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
    };
    let policy = FixedUrlPolicy {
        hosts: &["updates.invalid"],
        scheme: "http",
        port: Some(8080),
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
    assert_eq!(body, b"via proxy");
    assert_eq!(
        proxy.requested(),
        vec![
            "http://updates.invalid:8080/a".to_string(),
            "http://updates.invalid:8080/b".to_string(),
        ]
    );
    // A proxy that cannot be reached fails the request.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let error = fixed_get(
        &policy,
        "http://updates.invalid:8080/a",
        1024,
        Duration::from_secs(10),
        &via(closed_port),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("failed to GET"), "{error:#}");
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
