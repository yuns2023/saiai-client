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
//!   literal still exists somewhere in the sources. When a refactor removes
//!   such a literal, replace that entry with a behavioral assertion of the same
//!   literal value instead of deleting it.

use super::*;
use std::collections::BTreeSet;

/// Fixed P-256 installation CA key used only to freeze leaf derivation.
const FIXTURE_CA_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq9CjdR/blyuJLwO9
rRwtbhRu5K6erOiP7uCwzzd9PXShRANCAAR9MvoxxSfya0pWhgD4ODg/zZT8l7j8
lnlBHU8SoMoq33F9ZTGTqCWDaA3J4o7FJHuch2xnehGEi5vTE8+bhki0
-----END PRIVATE KEY-----
";

const PLACEHOLDER_JWT: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InNhaWFpLWxvY2FsLXByb3h5QGludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3VzZXJfaWQiOiJzYWlhaS1sb2NhbC1wcm94eS11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoic2FpYWktbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.c2FpYWktbG9jYWwtcHJveHk";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

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
    assert_eq!(SAIAI_CONFIG_FILENAME, "config.json");
    assert_eq!(SAIAI_CA_FILENAME, "saiai-ca.crt");
    assert_eq!(SAIAI_CA_KEY_FILENAME, "saiai-ca.key");
    assert_eq!(SAIAI_CONFIG_VERSION, 2);
    assert_eq!(DEFAULT_LOCAL_PROXY_LISTEN, "127.0.0.1:19908");
    assert_eq!(environment_scope::PRODUCT_DIR_FILENAME, "product-dir");
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    assert_eq!(SAIAI_SERVICE_LOG_FILENAME, "saiai.log");
}

#[test]
fn saiai_config_json_shape_is_frozen() {
    let config = SaiaiConfig {
        version: 2,
        base_url: "https://gateway.example".into(),
        api_key: "TEST_ONLY_CONTRACT".into(),
        listen: "127.0.0.1:19908".into(),
        ca_cert_path: "/h/.saiai/saiai-ca.crt".into(),
        ca_key_path: "/h/.saiai/saiai-ca.key".into(),
        chatgpt_chat_passthrough: true,
        desktop_browser_use: false,
        upstream_proxy: None,
        providers: ProviderCredentials {
            claude: Some(ProviderCredential {
                base_url: "https://claude.gateway.example".into(),
                api_key: "TEST_ONLY_CLAUDE".into(),
            }),
            codex: None,
        },
    };
    assert_eq!(
        serde_json::to_value(&config).unwrap(),
        serde_json::json!({
            "version": 2,
            "base_url": "https://gateway.example",
            "api_key": "TEST_ONLY_CONTRACT",
            "listen": "127.0.0.1:19908",
            "ca_cert_path": "/h/.saiai/saiai-ca.crt",
            "ca_key_path": "/h/.saiai/saiai-ca.key",
            "chatgpt_chat_passthrough": true,
            "desktop_browser_use": false,
            "providers": {
                "claude": {
                    "base_url": "https://claude.gateway.example",
                    "api_key": "TEST_ONLY_CLAUDE"
                }
            }
        })
    );

    let full = serde_json::json!({
        "version": 2,
        "base_url": "https://gateway.example",
        "api_key": "TEST_ONLY_CONTRACT",
        "listen": "127.0.0.1:41035",
        "ca_cert_path": "/h/.claude/saiai-ca.crt",
        "ca_key_path": "/h/.claude/saiai-ca.key",
        "chatgpt_chat_passthrough": false,
        "desktop_browser_use": true,
        "upstream_proxy": "http://127.0.0.1:7890",
        "providers": {
            "claude": {"base_url": "https://claude.gateway.example", "api_key": "TEST_ONLY_CLAUDE"},
            "codex": {"base_url": "https://codex.gateway.example", "api_key": "TEST_ONLY_CODEX"}
        }
    });
    let parsed: SaiaiConfig = serde_json::from_value(full.clone()).unwrap();
    assert_eq!(
        parsed.upstream_proxy.as_deref(),
        Some("http://127.0.0.1:7890")
    );
    assert_eq!(
        parsed
            .providers
            .codex
            .as_ref()
            .map(|codex| codex.base_url.as_str()),
        Some("https://codex.gateway.example")
    );
    assert_eq!(serde_json::to_value(&parsed).unwrap(), full);

    // Configurations written by older clients keep loading with defaults.
    let legacy: SaiaiConfig = serde_json::from_value(serde_json::json!({
        "version": 2,
        "base_url": "https://gateway.example",
        "api_key": "TEST_ONLY_CONTRACT",
        "listen": "127.0.0.1:19908",
        "ca_cert_path": "/h/.saiai/saiai-ca.crt",
        "upstream_proxy": "direct"
    }))
    .unwrap();
    assert_eq!(legacy.ca_key_path, "");
    assert!(legacy.chatgpt_chat_passthrough);
    assert!(legacy.desktop_browser_use);
    assert_eq!(legacy.upstream_proxy.as_deref(), Some("direct"));
    assert!(legacy.providers.is_empty());
}

// --------------------------------------------------- Environment isolation

#[test]
fn environment_isolation_names_are_frozen() {
    assert_eq!(
        environment_scope::environment_name("codex", Path::new("/work/project/codex")),
        "codex-2da86b69bd2e5ac6a16af476"
    );
    assert_eq!(
        environment_scope::service_suffix_for(
            Path::new("/saiai"),
            Path::new("/saiai/environments/codex-project")
        ),
        "-79ac17449adbff9bab473f32"
    );
    assert_eq!(
        environment_scope::service_suffix_for(Path::new("/saiai"), Path::new("/saiai")),
        ""
    );
    assert_eq!(
        environment_scope::environment_product("claude-2da86b69bd2e5ac6a16af476"),
        Some("claude")
    );
    assert_eq!(
        environment_scope::environment_product("codex-2da86b69bd2e5ac6a16af476"),
        Some("codex")
    );
    assert_eq!(
        environment_scope::environment_product("aitp-2da86b69bd2e5ac6a16af476"),
        None
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_default_service_name_is_frozen() {
    // The test process never resolves an isolated environment.
    assert_eq!(environment_scope::service_name(), "saiai.service");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_default_launchd_label_is_frozen() {
    assert_eq!(environment_scope::launchd_label(), "top.saiai.local-proxy");
}

// ------------------------------------------------------ Linux background

#[cfg(target_os = "linux")]
#[test]
fn linux_systemd_unit_renders_exactly() {
    let unit = render_user_service(
        Path::new("/opt/saiai bin/saiai"),
        Path::new("/home/u/.saiai"),
        Path::new("/home/u"),
    )
    .unwrap();
    assert_eq!(
        unit,
        "[Unit]
Description=SAIAI local Claude Code proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=\"SAIAI_HOME=/home/u/.saiai\"
WorkingDirectory=/home/u
ExecStart=\"/opt/saiai bin/saiai\" --instance-dir \"/home/u/.saiai\"
Restart=on-failure
RestartSec=2s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_headless_background_state_is_frozen() {
    assert_eq!(SAIAI_LINUX_PID_FILENAME, "saiai.pid");
    assert_eq!(SAIAI_LINUX_LOCK_FILENAME, "saiai.lock");
    assert_eq!(SAIAI_LINUX_BACKGROUND_COMMAND, "__run-background-proxy");
    assert_eq!(SAIAI_LINUX_BACKGROUND_STATE_VERSION, 1);
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
    assert_eq!(SAIAI_LOCAL_PROXY_NSS_CERT_NICKNAME, "saiai-local-proxy");
}

// ------------------------------------------------------ macOS background

#[cfg(target_os = "macos")]
#[test]
fn macos_launchd_plist_renders_exactly() {
    // The production template uses `\` line continuations, so the plist has
    // no indentation; existing LaunchAgents were written byte-for-byte so.
    let plist = render_launchd_plist(
        Path::new("/Applications/SAIAI & Co/saiai"),
        Path::new("/Users/u/.saiai"),
        Path::new("/Users/u"),
        Path::new("/Users/u/.saiai/saiai.log"),
    )
    .unwrap();
    assert_eq!(
        plist,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
<key>Label</key>
<string>top.saiai.local-proxy</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/SAIAI &amp; Co/saiai</string>
<string>--instance-dir</string>
<string>/Users/u/.saiai</string>
</array>
<key>EnvironmentVariables</key>
<dict>
<key>SAIAI_HOME</key>
<string>/Users/u/.saiai</string>
</dict>
<key>WorkingDirectory</key>
<string>/Users/u</string>
<key>RunAtLoad</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>StandardOutPath</key>
<string>/Users/u/.saiai/saiai.log</string>
<key>StandardErrorPath</key>
<string>/Users/u/.saiai/saiai.log</string>
</dict>
</plist>
"
    );
}

// ---------------------------------------------------- Windows background

#[cfg(target_os = "windows")]
#[test]
fn windows_background_identity_is_frozen() {
    assert_eq!(SAIAI_WINDOWS_PID_FILENAME, "saiai.pid");
    assert_eq!(SAIAI_WINDOWS_BACKGROUND_COMMAND, "__run-background-proxy");
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn update_assets_and_file_names_are_frozen() {
    let expected = match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => "saiai-linux-x86_64",
        ("linux", "aarch64") => "saiai-linux-aarch64",
        ("macos", "x86_64") => "saiai-macos-x86_64",
        ("macos", "aarch64") => "saiai-macos-aarch64",
        ("windows", "x86_64") => "saiai-windows-x86_64.exe",
        ("windows", "aarch64") => "saiai-windows-aarch64.exe",
        other => panic!("no frozen asset for {other:?}"),
    };
    assert_eq!(current_platform_asset_name().unwrap(), expected);
    for foreign in ["aitp-linux-x86_64", "linux-x86_64", "saiai.exe"] {
        assert!(
            validate_update_asset(b"\x7FELF", foreign).is_err(),
            "{foreign}"
        );
    }
    let (candidate, backup_prefix) = if cfg!(windows) {
        (".saiai-update-1-2.exe", "saiai.bak-")
    } else {
        (".saiai-update-1-2", "saiai.bak-")
    };
    assert_eq!(update_candidate_name("1-2"), candidate);
    let backup = update_backup_name();
    assert!(backup.starts_with(backup_prefix), "{backup}");
    assert_eq!(backup.ends_with(".exe"), cfg!(windows), "{backup}");
}

// ------------------------------------------------------------ Certificates

#[test]
fn installation_ca_subject_is_frozen() {
    let (cert_pem, key_pem) = generate_installation_ca().unwrap();
    let key = KeyPair::from_pem(&key_pem).unwrap();
    let suffix = hex(&Sha256::digest(key.public_key_der())[..4]);
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let certificate = pem.parse_x509().unwrap();
    let subject = certificate.subject();
    let common_names = subject
        .iter_common_name()
        .map(|name| name.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let organizations = subject
        .iter_organization()
        .map(|name| name.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        common_names,
        vec![format!("SAIAI local installation CA {suffix}")]
    );
    assert_eq!(organizations, vec!["SAIAI".to_string()]);
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn certificate_control_protocol_is_frozen() {
    assert_eq!(CODEX_CERTIFICATE_CONTROL_HOST, "certificate.saiai.local");
    assert_eq!(CODEX_CERTIFICATE_SPKI_HEADER, "x-saiai-leaf-spki-sha256");
    assert_eq!(
        local_proxy::CERTIFICATE_CONTROL_HOST,
        "certificate.saiai.local"
    );
    assert_eq!(
        local_proxy::CERTIFICATE_SPKI_HEADER,
        "x-saiai-leaf-spki-sha256"
    );
}

/// Desktop launches pin the leaf SPKI; the leaf key is derived from the
/// installation CA key with a fixed salt. A different salt (or derivation)
/// changes these pins and breaks every installed Desktop pin and NSS trust.
///
/// Expected pins were cross-checked with an independent Python derivation
/// (HKDF-SHA256, salt `SAIAI local proxy TLS leaf v1`, info `host || 0 ||
/// counter`, P-256 scalar) over the fixture key.
#[test]
fn local_tls_leaf_spki_derivation_is_frozen() {
    let ca_key = KeyPair::from_pem(FIXTURE_CA_KEY_PEM).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert_pem = params.self_signed(&ca_key).unwrap().pem();
    for (host, expected) in [
        (
            "chatgpt.com",
            "0KSOSoW1HJ3sKOwX9WVZbe3YxU4dgSgmTTiObJg8k30=",
        ),
        (
            "chat.openai.com",
            "gz3pLSJJX5uH67CNLMIgg9pQwsOUZ+ER+nLd56XRx0o=",
        ),
        (
            "api.anthropic.com",
            "r9tBJxcCJEYQ75Rfsdfv5+UrvcgKHbRUIiMvXZNbXAE=",
        ),
        ("claude.ai", "1+qXNzzUuPkaLTuhugkSlvGwDAC6YZl05DPaDNKn5iQ="),
    ] {
        let (leaf_der, leaf_key) =
            local_proxy::sign_leaf_certificate(host, &ca_cert_pem, FIXTURE_CA_KEY_PEM).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        let pin = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(leaf.tbs_certificate.subject_pki.raw));
        assert_eq!(pin, expected, "{host}");
        // The control header carries the hash of the same SPKI.
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(leaf_key.public_key_der())),
            expected,
            "{host}"
        );
    }
}

// ---------------------------------------------------- Codex placeholder login

#[test]
fn codex_placeholder_login_is_frozen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.json");
    ensure_codex_local_proxy_auth(&path).unwrap();
    let auth: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(auth["auth_mode"], "chatgptAuthTokens");
    assert_eq!(auth["OPENAI_API_KEY"], Value::Null);
    assert_eq!(
        auth["tokens"],
        serde_json::json!({
            "id_token": PLACEHOLDER_JWT,
            "access_token": PLACEHOLDER_JWT,
            "refresh_token": "",
            "account_id": "saiai-local-proxy-account"
        })
    );
    let decode = |part: &str| -> Value {
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .unwrap(),
        )
        .unwrap()
    };
    let parts = PLACEHOLDER_JWT.split('.').collect::<Vec<_>>();
    assert_eq!(
        decode(parts[0]),
        serde_json::json!({"alg": "none", "typ": "JWT"})
    );
    assert_eq!(
        decode(parts[1]),
        serde_json::json!({
            "email": "saiai-local-proxy@invalid",
            "exp": 4_102_444_800_u64,
            "https://api.openai.com/auth": {
                "chatgpt_plan_type": "plus",
                "chatgpt_user_id": "saiai-local-proxy-user",
                "chatgpt_account_id": "saiai-local-proxy-account"
            }
        })
    );
    // Placeholders written by older clients are still recognized as ours.
    assert!(is_codex_placeholder_access_token(PLACEHOLDER_JWT));
    assert!(is_codex_placeholder_access_token(
        "saiai-local-proxy-placeholder-0123"
    ));
    assert!(!is_codex_placeholder_access_token(
        "aitp-local-proxy-placeholder-0123"
    ));
}

// --------------------------------------------------------- Ownership markers

#[test]
fn codex_ide_env_block_renders_exactly() {
    assert_eq!(
        merge_codex_ide_env("KEEP=1\n", "127.0.0.1:19908", "/h/.saiai/saiai-ca.crt"),
        "KEEP=1

# BEGIN SAIAI CODEX IDE (managed)
SSL_CERT_FILE=\"/h/.saiai/saiai-ca.crt\"
HTTP_PROXY=\"http://127.0.0.1:19908\"
HTTPS_PROXY=\"http://127.0.0.1:19908\"
ALL_PROXY=\"http://127.0.0.1:19908\"
NO_PROXY=\"localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local\"
http_proxy=\"http://127.0.0.1:19908\"
https_proxy=\"http://127.0.0.1:19908\"
all_proxy=\"http://127.0.0.1:19908\"
no_proxy=\"localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10,.local\"
# END SAIAI CODEX IDE (managed)
"
    );
}

#[test]
fn vscode_ownership_marker_is_frozen() {
    let merged = vscode::merge_settings("{}\n", "127.0.0.1:19908").unwrap();
    assert!(
        merged.contains("// SAIAI managed VSCode proxy: http://127.0.0.1:19908"),
        "{merged}"
    );
    assert!(vscode::has_managed_proxy(
        "{\n// SAIAI managed VSCode proxy: http://127.0.0.1:19908\n\"http.proxy\": \"http://127.0.0.1:19908\"\n}\n"
    ));
    assert!(!vscode::has_managed_proxy(
        "{\n// AITP managed VSCode proxy: http://127.0.0.1:19908\n}\n"
    ));
}

// ------------------------------------------------------------- Uninstall

#[test]
fn uninstall_recognition_rules_are_frozen() {
    assert_eq!(
        uninstall::SAIAI_HOME_FILES,
        &[
            "config.json",
            "saiai-ca.crt",
            "saiai-ca.key",
            "initialization.lock",
            "saiai.lock",
            "saiai.pid",
            "saiai.log",
            "client-device-key",
            "client-device.json",
            "client-device.lock",
            "client-device-key.corrupt",
            "windows-packaged-proxy-lease.json",
        ]
    );
    assert_eq!(uninstall::SAIAI_HOME_DIRS, &["log-followers", "desktop"]);
    for name in [
        "config.json.bak-20261030-010203",
        ".config.json.saiai-tmp-1-abc",
        "saiai-ca.key.bak-1",
    ] {
        assert!(uninstall::is_saiai_home_file(name), "{name}");
    }
    assert!(!uninstall::is_saiai_home_file(
        ".config.json.aitp-tmp-1-abc"
    ));
    for name in [
        "saiai",
        "saiai.exe",
        "saiai-previous",
        "saiai-previous.exe",
        "saiai.bak-20261030-010203",
        ".saiai-update-1-2.exe",
        ".saiai-update-status.txt",
        ".saiai.install.AbC123",
        ".saiai.replace.0123.bak",
    ] {
        assert!(uninstall::is_program_file(name), "{name}");
    }
    for name in ["aitp", "aitp.exe", "saiai-other", "saiai.bak"] {
        assert!(!uninstall::is_program_file(name), "{name}");
    }
    assert!(uninstall::is_claude_ca_file("saiai-ca.crt"));
    assert!(uninstall::is_claude_ca_file("saiai-ca.key.bak-1"));
    assert!(!uninstall::is_claude_ca_file("aitp-ca.crt"));
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

/// Production sources of the CLI (Rust plus bundled PowerShell/JavaScript),
/// recursively. Test-only files (`*_tests.*`) and inline `#[cfg(test)] mod
/// … {` blocks are dropped so that a name kept alive only by an old test
/// cannot hide a removed production use.
fn cli_sources() -> Vec<(String, String)> {
    fn collect(directory: &Path, sources: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, sources);
                continue;
            }
            let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                continue;
            };
            let stem = path.file_stem().and_then(|value| value.to_str()).unwrap();
            if !matches!(extension, "rs" | "ps1" | "js") || stem.ends_with("_tests") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            sources.push((
                path.display().to_string(),
                production_part(&text).to_string(),
            ));
        }
    }
    let mut sources = Vec::new();
    collect(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources.sort();
    sources
}

/// Text before the first inline test module (`#[cfg(test)]` + `mod x {`).
/// Relies on the repository convention that inline test modules sit at the
/// end of a file; production code after one would not be scanned.
fn production_part(text: &str) -> &str {
    let mut offset = 0;
    while let Some(found) = text[offset..].find("#[cfg(test)]\nmod ") {
        let start = offset + found;
        let line_end = text[start + "#[cfg(test)]\n".len()..]
            .find('\n')
            .map_or(text.len(), |end| start + "#[cfg(test)]\n".len() + end);
        if text[start..line_end].trim_end().ends_with('{') {
            return &text[..start];
        }
        offset = line_end;
    }
    text
}

/// `SAIAI_*` names referenced as environment variables: Rust/JS string
/// literals, PowerShell `$env:`/`${env:}`, POSIX `${…}`/`$…`, and CMD `%…%`.
fn saiai_environment_names(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (index, _) in text.match_indices("SAIAI_") {
        let name = text[index..]
            .chars()
            .take_while(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_')
            .collect::<String>();
        let before = &text[..index];
        let after = &text[index + name.len()..];
        // Names are all-uppercase; `SAIAI_Foo` is not a reference to `SAIAI_F`.
        let complete = !after.starts_with(|ch: char| ch.is_ascii_alphanumeric());
        let referenced = complete
            && ((before.ends_with('"') && after.starts_with('"'))
                || (before.ends_with('\'') && after.starts_with('\''))
                || before.ends_with("$env:")
                || (before.ends_with("${env:") && after.starts_with('}'))
                || (before.ends_with("${") && (after.starts_with('}') || after.starts_with(':')))
                || (before.ends_with('$') && !before.ends_with("\\$"))
                || (before.ends_with('%') && after.starts_with('%')));
        if referenced {
            found.insert(name);
        }
    }
    found
}

#[test]
fn environment_scanner_recognizes_every_reference_style() {
    let sample = r#"env::var("SAIAI_A"); .env('SAIAI_B', x); $env:SAIAI_C; ${env:SAIAI_D};
${SAIAI_E:-x} "$SAIAI_F" %SAIAI_G% const SAIAI_NOT_ENV: &str = "x"; "__SAIAI_NULL__" $SAIAI_Foo"#;
    assert_eq!(
        saiai_environment_names(sample),
        [
            "SAIAI_A", "SAIAI_B", "SAIAI_C", "SAIAI_D", "SAIAI_E", "SAIAI_F", "SAIAI_G"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
    let text = "a\n#[cfg(test)]\nmod brand_contract_tests;\nb\n#[cfg(test)]\nmod tests {\nc";
    assert_eq!(
        production_part(text),
        "a\n#[cfg(test)]\nmod brand_contract_tests;\nb\n"
    );
}

/// Every `SAIAI_*` environment variable the client reads or hands to its own
/// helper processes and scripts. Users, installers, services and older
/// clients set these names; renaming or dropping one is a breaking change,
/// and adding one should be a conscious decision recorded here.
#[test]
fn saiai_environment_variable_inventory_is_frozen() {
    let expected = BTreeSet::from([
        "SAIAI_BINARY_UPDATED",
        "SAIAI_CA_FILES",
        "SAIAI_CA_THUMBPRINT",
        "SAIAI_CA_THUMBPRINTS",
        "SAIAI_CHATGPT_BIN",
        "SAIAI_CHATGPT_CHAT_PASSTHROUGH",
        "SAIAI_CHATGPT_TIMEZONE",
        "SAIAI_CHECK_EXE",
        "SAIAI_CHECK_PID",
        "SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED",
        "SAIAI_CLEANUP_DIR",
        "SAIAI_CLEANUP_DIRS",
        "SAIAI_CLEANUP_FILES",
        "SAIAI_DESKTOP_ACTIVATION_ARGS",
        "SAIAI_DESKTOP_APP_ID",
        "SAIAI_DESKTOP_BIN",
        "SAIAI_DESKTOP_BROWSER_USE",
        "SAIAI_HOME",
        "SAIAI_INSTALL_DIR",
        "SAIAI_OPENAI_TRACE",
        "SAIAI_OPENAI_TRACE_PATH",
        "SAIAI_PATH_KIND",
        "SAIAI_PATH_NEW",
        "SAIAI_PATH_OLD",
        "SAIAI_PROXY_VERBOSE",
        "SAIAI_RUNTIME_APP_ID",
        "SAIAI_RUNTIME_DIRECTORY",
        "SAIAI_RUNTIME_PACKAGE_ROOT",
        "SAIAI_RUNTIME_REQUIRE_NO_ACTORS",
        "SAIAI_SKIP_START",
        "SAIAI_UPSTREAM_PROXY",
        "SAIAI_VSCODE_CA_PATH",
        "SAIAI_VSCODE_CA_SHA256",
    ]);
    let found = cli_sources()
        .iter()
        .flat_map(|(_, text)| saiai_environment_names(text))
        .collect::<BTreeSet<_>>();
    let found = found.iter().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(found, expected);
}

/// Contract literals that are only reachable through inline code today
/// (update URLs, uninstall service patterns, PowerShell filters). Each needle
/// must stay present until a refactor replaces it with a behavioral test.
#[test]
fn inline_contract_literals_are_present() {
    let sources = cli_sources();
    for needle in [
        // Self-update channel below the configured Gateway base URL.
        "/saiai-cli/manifest.json",
        "/saiai-cli/{asset}",
        // Update candidates must identify themselves as SAIAI.
        "starts_with(\"saiai \")",
        // Uninstall discovers every environment's service by name pattern.
        "\"saiai{}.service\"",
        "is_service_file_name(&name, \"saiai\", \".service\")",
        "\"top.saiai.local-proxy{}\"",
        "is_service_file_name(&name, \"top.saiai.local-proxy\", \".plist\")",
        // Windows: stale CAs are recognized by organization, uninstall
        // locates the per-user install and Desktop runtime under SAIAI.
        "O=SAIAI(,|$)",
        ".join(\"SAIAI\").join(\"bin\")",
        ".join(\"SAIAI\").join(\"desktop-runtime\")",
        "AppData/Local/SAIAI/bin",
        // Desktop synthetic identity returned by the local sidecars.
        "saiai-local-proxy@example.invalid",
        "\"userID\":\"saiai-local-proxy-user\"",
        "\"stableID\":\"saiai-local-proxy\"",
        "x-saiai-chat-preference-restored",
        // Atomic temporary files that uninstall recognizes.
        "\".{name}.saiai-tmp-{}-{}\"",
    ] {
        assert!(
            sources.iter().any(|(_, text)| text.contains(needle)),
            "SAIAI contract literal disappeared from tools/saiai-cli/src: {needle}"
        );
    }
}
