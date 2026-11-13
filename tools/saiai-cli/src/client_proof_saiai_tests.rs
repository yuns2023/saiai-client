//! SAIAI client proof wire contract: frozen golden values, hand-written
//! literals except the release version (read from this package's manifest).
//!
//! SAIAI-side tests declared at the crate root rather than inside
//! `client_proof`, so that a crate including `client_proof.rs` for its own
//! tests does not run them against another package's version.

use crate::client_proof::{
    CORRUPT_KEY_FILENAME, ClientProof, DEVICE_FILENAME, ENROLL_PATH, HEADER_NAME, KEY_FILENAME,
    LOCK_FILENAME, MESSAGE_DOMAIN, proof_message,
};
use serde_json::Value;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Release version as written in this package's manifest.
fn release_version() -> String {
    let manifest = include_str!("../Cargo.toml");
    let package = manifest
        .split("\n[")
        .find(|section| section.starts_with("[package]") || section.starts_with("package]"))
        .expect("Cargo.toml has a [package] section");
    package
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("version = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .expect("Cargo.toml declares package.version")
        .to_string()
}

#[test]
fn client_proof_wire_names_are_frozen() {
    assert_eq!(HEADER_NAME, "x-saiai-client-proof");
    assert_eq!(
        proof_message("post", "/v1/messages", 1, "n", "k"),
        "saiai-client-proof-v1\nPOST\n/v1/messages\n1\nn\n\
         8254c329a92850f6d539dd376f4816ee2764517da5e0235514af433164480d7a"
    );
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("proof");
    crate::installed_saiai();
    ClientProof::load_for_version(&state, "test-version").unwrap();
    let mut names = fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["client-device-key", "client-device.lock"]);
}

#[tokio::test]
async fn client_proof_enrollment_request_is_frozen() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&request).to_string();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text[..split]
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if request.len() >= split + 4 + length {
                    break;
                }
            }
            if read == 0 {
                break;
            }
        }
        let body = r#"{"device_id":"cd_CCCCCCCCCCCCCCCCCCCCCC","status":"active"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8(request).unwrap()
    });
    let directory = tempfile::tempdir().unwrap();
    crate::installed_saiai();
    // The version the program passes: its own package version.
    let proof = Arc::new(
        ClientProof::load_for_version(directory.path(), env!("CARGO_PKG_VERSION")).unwrap(),
    );
    // No retries and no inherited proxy: a broken contract fails fast.
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::timeout(
        Duration::from_secs(20),
        Arc::clone(&proof).enroll(
            client,
            gateway,
            zeroize::Zeroizing::new("TEST_ONLY_PROOF".into()),
            &[],
        ),
    )
    .await
    .expect("enrollment finished in time")
    .expect("enrollment recorded a device");
    let request = tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .expect("mock gateway finished in time")
        .unwrap();
    assert!(
        request.starts_with("POST /api/v1/client/devices/enroll HTTP/1.1\r\n"),
        "{request}"
    );
    let body: Value =
        serde_json::from_str(&request[request.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    // The Gateway sees the shipped release version, not a library version.
    assert_eq!(body["client_version"], release_version().as_str());
    assert_eq!(body["os"], std::env::consts::OS);
    assert_eq!(body["arch"], std::env::consts::ARCH);
    let mut names = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "client-device-key",
            "client-device.json",
            "client-device.lock"
        ]
    );
}

/// The client proof protocol names.
#[test]
fn client_proof_protocol_names_are_frozen() {
    assert_eq!(HEADER_NAME, "x-saiai-client-proof");
    assert_eq!(MESSAGE_DOMAIN, "saiai-client-proof-v1");
    assert_eq!(ENROLL_PATH, "/api/v1/client/devices/enroll");
    assert_eq!(KEY_FILENAME, "client-device-key");
    assert_eq!(LOCK_FILENAME, "client-device.lock");
    assert_eq!(DEVICE_FILENAME, "client-device.json");
    assert_eq!(CORRUPT_KEY_FILENAME, "client-device-key.corrupt");
}
