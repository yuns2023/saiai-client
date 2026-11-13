//! Frozen SAIAI external contract (golden values).
//!
//! Every expected value below is a hand-written literal describing what an
//! installed SAIAI client already relies on: directories, file names,
//! environment variables, service identities, certificate identities, the
//! Codex placeholder login, ownership markers, update coordinates and the
//! client proof wire format. Changing any of them strands existing
//! installations, so a refactor (for example moving brand constants into a
//! `Brand` value) must keep these tests passing unchanged.
//!
//! Rules for editing this file:
//! - Never derive an expected value from the production constant or from a
//!   future `Brand` value; that would only prove the code equals itself.
//! - Prefer asserting rendered output (unit files, plists, auth files, config
//!   JSON) over asserting a constant.
//! - The source inventories at the end are the weakest tier: they only prove a
//!   literal is still used by a named production file. When a refactor
//!   removes such a literal, replace that entry with a behavioral assertion of
//!   the same literal value instead of deleting it.
//!
//! A few expectations are computed at run time because the input itself is
//! not fixed. None of them reads the value under test from production code:
//! - the release version is parsed from this package's `Cargo.toml` (the
//!   version is bumped every release; the contract is "equal to the shipped
//!   version", not a particular number);
//! - the installation CA name suffix is the SHA-256 of the freshly generated
//!   key, recomputed here from the key the code returned;
//! - environment directory digests in the black-box tests hash a temporary
//!   path (the in-process tests use fixed paths and literal digests);
//! - `std::env::consts::OS`/`ARCH` select which literal asset name applies.

use super::*;
#[allow(dead_code)]
#[path = "../tests/support/source_scan.rs"]
mod source_scan;
use source_scan::*;
use std::collections::BTreeSet;

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

// ------------------------------------------------------------ Home layout

#[test]
fn saiai_home_file_names_and_versions() {
    assert_eq!(CONFIG_FILENAME, "config.json");
    assert_eq!(CA_FILENAME, "saiai-ca.crt");
    assert_eq!(CA_KEY_FILENAME, "saiai-ca.key");
    assert_eq!(CONFIG_VERSION, 2);
    assert_eq!(DEFAULT_LOCAL_PROXY_LISTEN, "127.0.0.1:19908");
    assert_eq!(environment_scope::PRODUCT_DIR_FILENAME, "product-dir");
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    assert_eq!(SERVICE_LOG_FILENAME, "saiai.log");
}

// --------------------------------------------------- Environment isolation

// ------------------------------------------------------ Linux background

#[cfg(target_os = "linux")]
#[test]
fn linux_headless_background_state_is_frozen() {
    assert_eq!(LINUX_PID_FILENAME, "saiai.pid");
    assert_eq!(LINUX_LOCK_FILENAME, "saiai.lock");
    assert_eq!(LINUX_BACKGROUND_COMMAND, "__run-background-proxy");
    assert_eq!(LINUX_BACKGROUND_STATE_VERSION, 1);
    assert!(matches!(
        parse_command(&["__run-background-proxy".to_string()]).unwrap(),
        Command::RunLinuxBackgroundProxy
    ));
    let state = LinuxBackgroundState {
        schema_version: 1,
        pid: 42,
        start_time_ticks: 7,
        instance: Some("/home/u/.saiai".into()),
    };
    assert_eq!(
        serde_json::to_value(&state).unwrap(),
        serde_json::json!({
            "schema_version": 1,
            "pid": 42,
            "start_time_ticks": 7,
            "instance": "/home/u/.saiai"
        })
    );
    // Upgrades read state files written before `instance` existed.
    let legacy: LinuxBackgroundState =
        serde_json::from_str(r#"{"schema_version":1,"pid":42,"start_time_ticks":7}"#).unwrap();
    assert_eq!(legacy.instance, None);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_nss_certificate_nickname_is_frozen() {
    assert_eq!(LOCAL_PROXY_NSS_CERT_NICKNAME, "saiai-local-proxy");
}

// ------------------------------------------------------ macOS background

// ---------------------------------------------------- Windows background

#[cfg(target_os = "windows")]
#[test]
fn windows_background_identity_is_frozen() {
    assert_eq!(WINDOWS_PID_FILENAME, "saiai.pid");
    assert_eq!(WINDOWS_BACKGROUND_COMMAND, "__run-background-proxy");
    assert_eq!(
        WINDOWS_PACKAGED_PROXY_LEASE_FILENAME,
        "windows-packaged-proxy-lease.json"
    );
    for args in [
        vec!["__run-background-proxy".to_string()],
        vec![
            "__run-background-proxy".to_string(),
            "--instance-v2".to_string(),
        ],
    ] {
        assert!(matches!(
            parse_command(&args).unwrap(),
            Command::RunWindowsBackgroundProxy
        ));
    }
    let state = WindowsBackgroundState {
        version: 2,
        pid: 42,
        created: 7,
        instance: r"C:\Users\u\.saiai".into(),
    };
    assert_eq!(
        serde_json::to_value(&state).unwrap(),
        serde_json::json!({
            "version": 2,
            "pid": 42,
            "created": 7,
            "instance": r"C:\Users\u\.saiai"
        })
    );
    assert_eq!(
        windows_update_status_path(Path::new(r"C:\Users\u\AppData\Local\SAIAI\bin\saiai.exe"))
            .unwrap(),
        PathBuf::from(r"C:\Users\u\AppData\Local\SAIAI\bin\.saiai-update-status.txt")
    );
}

// ---------------------------------------------------------------- Update

// ------------------------------------------------------------ Certificates

// ---------------------------------------------------- Codex placeholder login

// --------------------------------------------------------- Ownership markers

// ------------------------------------------------------------- Uninstall

/// A listener owned by a process whose name contains the binary name (any
/// case) is treated as this client's own proxy.
#[test]
fn listen_port_owner_recognition_is_frozen() {
    for (name, ours) in [
        ("saiai", true),
        ("SAIAI", true),
        ("saiai.exe", true),
        ("my-saiai-worker", true),
        ("aitp", false),
        ("node", false),
    ] {
        let owner = ListenPortOwner {
            pid: 1,
            name: name.to_string(),
        };
        assert_eq!(owner.is_app(), ours, "{name}");
    }
}

// ------------------------------------------------------------ Client proof

#[test]
fn client_proof_wire_names_are_frozen() {
    assert_eq!(client_proof::HEADER_NAME, "x-saiai-client-proof");
    assert_eq!(
        client_proof::proof_message("post", "/v1/messages", 1, "n", "k"),
        "saiai-client-proof-v1\nPOST\n/v1/messages\n1\nn\n\
         8254c329a92850f6d539dd376f4816ee2764517da5e0235514af433164480d7a"
    );
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("proof");
    client_proof::ClientProof::load(&state).unwrap();
    let mut names = fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["client-device-key", "client-device.lock"]);
}

#[tokio::test]
async fn client_proof_enrollment_request_is_frozen() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let proof = Arc::new(client_proof::ClientProof::load(directory.path()).unwrap());
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
    assert_eq!(body["os"], env::consts::OS);
    assert_eq!(body["arch"], env::consts::ARCH);
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

// ------------------------------------------------- Desktop synthetic identity

#[test]
fn desktop_synthetic_identity_is_frozen() {
    assert_eq!(claude_desktop::TOKEN_PREFIX, "saiai-desktop-claude-");
    // An identity persisted by an earlier client keeps loading from the same
    // place with the same field names.
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("desktop/claude/state");
    fs::create_dir_all(&state).unwrap();
    let identity = serde_json::json!({
        "account": "6f1c1f5e-8f1a-4d9e-9a51-0c2f5b7d1e01",
        "organization": "0b9d6a7c-2e4f-4c1b-8d3a-5f6e7a8b9c02",
        "access_token": "saiai-desktop-claude-0123456789abcdef0123456789abcdef",
        "refresh_token": "saiai-desktop-claude-refresh-0123456789abcdef",
        "session": "saiai-local-0123456789abcdef0123456789abcdef"
    });
    fs::write(state.join("identity.json"), identity.to_string()).unwrap();
    let loaded = claude_desktop::Identity::load(root.path())
        .unwrap()
        .expect("persisted identity is found");
    assert_eq!(serde_json::to_value(&loaded).unwrap(), identity);
}

// ------------------------------------------------------- Source inventories
//
// Source inventories are the weakest tier: they are not behavioral golden
// tests. They pin *where* a literal is used in production code, per file, so
// that a consumer kept on the old value cannot hide another consumer that was
// changed. Comments and `#[cfg(test)]` items are removed before matching.

/// Variables the binary hands to its own PowerShell helpers. Both ends are
/// templates of the same brand prefix: Rust passes `script_brand::env("X")`
/// and the script reads `$env:@@ENV@@X`, from the same production files as
/// before the names became templates; under SAIAI the names are unchanged.
#[test]
fn helper_environment_variables_are_written_and_read() {
    let sources = cli_sources();
    let expected: &[(&str, &[&str])] = &[
        ("SAIAI_CA_FILES", &["uninstall.rs"]),
        ("SAIAI_CA_THUMBPRINT", &["uninstall.rs"]),
        ("SAIAI_CA_THUMBPRINTS", &["uninstall.rs"]),
        ("SAIAI_CHECK_EXE", &["lib.rs"]),
        ("SAIAI_CHECK_PID", &["lib.rs"]),
        ("SAIAI_CLEANUP_DIR", &["uninstall.rs"]),
        ("SAIAI_CLEANUP_DIRS", &["uninstall.rs"]),
        ("SAIAI_CLEANUP_FILES", &["uninstall.rs"]),
        ("SAIAI_DESKTOP_ACTIVATION_ARGS", &["lib.rs"]),
        ("SAIAI_DESKTOP_APP_ID", &["lib.rs"]),
        ("SAIAI_PATH_KIND", &["uninstall.rs"]),
        ("SAIAI_PATH_NEW", &["uninstall.rs"]),
        ("SAIAI_PATH_OLD", &["uninstall.rs"]),
        (
            "SAIAI_RUNTIME_APP_ID",
            &["windows_desktop_inspect.ps1", "windows_desktop_runtime.rs"],
        ),
        ("SAIAI_RUNTIME_DIRECTORY", &["windows_desktop_runtime.rs"]),
        (
            "SAIAI_RUNTIME_PACKAGE_ROOT",
            &["windows_desktop_inspect.ps1", "windows_desktop_runtime.rs"],
        ),
        (
            "SAIAI_RUNTIME_REQUIRE_NO_ACTORS",
            &["windows_desktop_inspect.ps1", "windows_desktop_runtime.rs"],
        ),
        (
            "SAIAI_VSCODE_CA_PATH",
            &["vscode.rs", "vscode_trust_windows.ps1"],
        ),
        (
            "SAIAI_VSCODE_CA_SHA256",
            &["vscode.rs", "vscode_trust_windows.ps1"],
        ),
    ];
    let bounded = |text: &str, needle: &str| {
        text.match_indices(needle).any(|(index, _)| {
            !text[index + needle.len()..]
                .starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_')
        })
    };
    // Exactly these helper variables exist: none may be added unregistered.
    let mut found = BTreeSet::new();
    for text in sources.values() {
        for (marker, terminator) in [("script_brand::env(\"", '"'), ("$env:@@ENV@@", ' ')] {
            for (index, _) in text.match_indices(marker) {
                let rest = &text[index + marker.len()..];
                let suffix = if terminator == '"' {
                    rest.split('"').next().unwrap_or_default().to_string()
                } else {
                    rest.chars()
                        .take_while(|ch| {
                            ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_'
                        })
                        .collect()
                };
                // The failure marker is a line prefix, not a variable.
                if suffix != "DESKTOP_HELPER_FAILURE:" {
                    found.insert(format!("SAIAI_{suffix}"));
                }
            }
        }
    }
    assert_eq!(
        found,
        expected
            .iter()
            .map(|(name, _)| name.to_string())
            .collect::<BTreeSet<_>>()
    );
    for (name, files) in expected {
        let suffix = name.strip_prefix("SAIAI_").unwrap();
        assert_eq!(crate::script_brand::env(suffix), *name);
        let writer = format!("script_brand::env(\"{suffix}\")");
        let reader = format!("$env:@@ENV@@{suffix}");
        assert!(
            sources
                .iter()
                .any(|(file, text)| file.ends_with(".rs") && text.contains(&writer)),
            "the binary no longer passes {name} to its helper"
        );
        assert!(
            sources.values().any(|text| bounded(text, &reader)),
            "no helper script reads {name} any more"
        );
        let users = sources
            .iter()
            .filter(|(_, text)| text.contains(&writer) || bounded(text, &reader))
            .map(|(file, _)| file.as_str())
            .collect::<Vec<_>>();
        assert_eq!(&users, files, "files using {name}");
    }
}

/// Native Chat update channel of the SAIAI Gateway, on both entry spellings.
#[test]
fn native_chat_update_route_is_frozen() {
    assert_eq!(
        local_proxy::normalize_chatgpt_chat_target("/backend-api/saiai/chat-updates?since=1")
            .unwrap(),
        "/chatgpt/backend-api/saiai/chat-updates?since=1"
    );
    assert!(local_proxy::is_forwarded_chatgpt_path(
        "/chatgpt/backend-api/saiai/chat-updates"
    ));
    for rejected in [
        "/backend-api/saiai/chat-updates/admin",
        "/backend-api/aitp/chat-updates",
    ] {
        assert!(
            local_proxy::normalize_chatgpt_chat_target(rejected).is_err(),
            "{rejected}"
        );
    }
    for unforwarded in [
        "/chatgpt/backend-api/saiai/chat-updates/admin",
        "/backend-api/saiai/chat-updates",
        "/chatgpt/backend-api/aitp/chat-updates",
    ] {
        assert!(
            !local_proxy::is_forwarded_chatgpt_path(unforwarded),
            "{unforwarded}"
        );
    }
}

/// Wire names inside helper scripts under SAIAI, written out by hand.
#[test]
fn helper_script_names_are_frozen() {
    use crate::script_brand::{env, identifier_prefix, null_sentinel, render};
    assert_eq!(env("CA_FILES"), "SAIAI_CA_FILES");
    assert_eq!(null_sentinel(), "__SAIAI_NULL__");
    assert_eq!(identifier_prefix(), "Saiai");
    assert_eq!(
        crate::windows_desktop_runtime::helper_failure_prefix(),
        "SAIAI_DESKTOP_HELPER_FAILURE:"
    );
    // Production templates where they are reachable from tests.
    assert!(
        render(crate::STALE_CA_LISTING_SCRIPT)
            .contains("Where-Object { $_.Subject -match '(^|, )O=SAIAI(,|$)' }")
    );
    let activation = render(crate::PACKAGE_ACTIVATION_SCRIPT);
    assert!(activation.contains("public static class SaiaiPackageActivation {"));
    assert!(activation.contains(
        "[SaiaiPackageActivation]::Activate($env:SAIAI_DESKTOP_APP_ID,$env:SAIAI_DESKTOP_ACTIVATION_ARGS)"
    ));
    // The uninstall helpers are local constants of their functions; the
    // namespace token is checked through the renderer.
    assert_eq!(
        render("Add-Type -Namespace @@ID@@Uninstall"),
        "Add-Type -Namespace SaiaiUninstall"
    );
    assert_eq!(
        render("'@@APP_DIR@@\\desktop-runtime'"),
        "'SAIAI\\desktop-runtime'"
    );
}

/// Executes the observer's production expression for the runtime directory.
#[cfg(windows)]
#[test]
fn windows_desktop_runtime_directory_is_frozen() {
    // The observer is a brand template; run what the program runs.
    let observer = crate::script_brand::render(include_str!("windows_desktop_inspect.ps1"));
    let line = observer
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("runtime_directory="))
        .expect("observer reports runtime_directory");
    let script = format!(
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; $base=[Environment]::GetFolderPath('LocalApplicationData'); $value={line}; $base; $value"
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let mut lines = text.lines().map(str::trim);
    let base = lines.next().unwrap().to_string();
    assert_eq!(
        lines.next().unwrap(),
        format!(r"{base}\SAIAI\desktop-runtime")
    );
}

/// The client proof protocol names, constants of the SAIAI extension
/// (they move out of the library with it).
#[test]
fn client_proof_protocol_names_are_frozen() {
    use crate::client_proof as proof;
    assert_eq!(proof::HEADER_NAME, "x-saiai-client-proof");
    assert_eq!(proof::MESSAGE_DOMAIN, "saiai-client-proof-v1");
    assert_eq!(proof::ENROLL_PATH, "/api/v1/client/devices/enroll");
    assert_eq!(proof::KEY_FILENAME, "client-device-key");
    assert_eq!(proof::LOCK_FILENAME, "client-device.lock");
    assert_eq!(proof::DEVICE_FILENAME, "client-device.json");
    assert_eq!(proof::CORRUPT_KEY_FILENAME, "client-device-key.corrupt");
}
