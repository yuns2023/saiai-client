//! The fixed-URL update source against a local HTTP server: every request
//! and redirect is checked by the same policy code as production, with a
//! plain-HTTP policy for the loopback server (the HTTPS policy itself is
//! checked as a pure function).

use super::*;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// One canned response per path: status line, extra headers, body.
type Routes = HashMap<String, (u16, Vec<(String, String)>, Vec<u8>)>;

/// Serves `routes` on a loopback port until the test ends; returns the
/// port. Unknown paths answer 404.
async fn serve(routes: Routes) -> u16 {
    serve_with(move |_| routes).await
}

/// Like `serve`, with routes that may name the server's own port.
async fn serve_with(routes: impl FnOnce(u16) -> Routes) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes = Arc::new(routes(port));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let routes = Arc::clone(&routes);
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
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, headers, body) =
                    routes
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, Vec::new(), b"missing".to_vec()));
                let mut response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (name, value) in headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str("\r\n");
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    port
}

fn ok(body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    (200, Vec::new(), body.to_vec())
}

fn redirect(status: u16, location: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    (
        status,
        vec![("Location".to_string(), location.to_string())],
        Vec::new(),
    )
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
        installation_ca_pem: String::new(),
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
    .await;
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

#[tokio::test]
async fn redirects_leaving_the_policy_or_looping_are_refused() {
    let port = serve(Routes::from([
        (
            "/other-host".to_string(),
            redirect(302, "http://localhost/x"),
        ),
        ("/https".to_string(), redirect(302, "https://127.0.0.1/x")),
        (
            "/userinfo".to_string(),
            redirect(302, "http://user@127.0.0.1/x"),
        ),
        ("/no-location".to_string(), (302, Vec::new(), Vec::new())),
        ("/loop".to_string(), redirect(302, "/loop")),
    ]))
    .await;
    for path in [
        "/other-host",
        "/https",
        "/userinfo",
        "/no-location",
        "/loop",
    ] {
        let error = get(port, path, 1024).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("not allowed")
                || format!("{error:#}").contains("Location")
                || format!("{error:#}").contains("redirected more than"),
            "{path}: {error:#}"
        );
    }
    let error = get(port, "/loop", 1024).await.unwrap_err();
    assert!(format!("{error:#}").contains("more than 5"), "{error:#}");
}

#[tokio::test]
async fn missing_large_and_failed_responses_are_distinguished() {
    let port = serve(Routes::from([
        ("/large".to_string(), ok(&[b'x'; 2048])),
        ("/error".to_string(), (500, Vec::new(), b"no".to_vec())),
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
