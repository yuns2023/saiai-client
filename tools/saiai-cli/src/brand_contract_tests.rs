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
use std::collections::{BTreeMap, BTreeSet};

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
        assert_eq!(owner.is_saiai(), ours, "{name}");
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

/// Production text of every CLI source below `src`, keyed by its path
/// relative to `src` (with `/`). Test-only files (`*_tests.*`) are skipped.
fn cli_sources() -> BTreeMap<String, String> {
    fn collect(root: &Path, directory: &Path, sources: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, sources);
                continue;
            }
            let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                continue;
            };
            let stem = path.file_stem().and_then(|value| value.to_str()).unwrap();
            if !matches!(extension, "rs" | "ps1" | "js") || stem.ends_with("_tests") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|component| component.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/");
            let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
            sources.insert(relative, production_text(&text, extension));
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = BTreeMap::new();
    collect(&root, &root, &mut sources);
    sources
}

/// Source without comments and, for Rust, without `#[cfg(test)]` items.
fn production_text(text: &str, extension: &str) -> String {
    match extension {
        "rs" => remove_rust_test_items(&strip_rust_comments(text)),
        "ps1" => text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Byte ranges of Rust string and char literals (including raw strings).
fn rust_literal_ranges(text: &str) -> Vec<std::ops::Range<usize>> {
    let bytes = text.as_bytes();
    let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index = block_comment_end(text, index);
            continue;
        }
        let raw_start = byte == b'r'
            && (index == 0
                || !is_ident(bytes[index - 1])
                || (bytes[index - 1] == b'b' && (index < 2 || !is_ident(bytes[index - 2]))));
        if raw_start {
            let hashes = bytes[index + 1..]
                .iter()
                .take_while(|byte| **byte == b'#')
                .count();
            if bytes.get(index + 1 + hashes) == Some(&b'"') {
                let terminator = format!("\"{}", "#".repeat(hashes));
                let body = index + 2 + hashes;
                let end = text[body..]
                    .find(&terminator)
                    .map_or(bytes.len(), |end| body + end + terminator.len());
                ranges.push(index..end);
                index = end;
                continue;
            }
        }
        if byte == b'"' {
            let mut end = index + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            ranges.push(index..(end + 1).min(bytes.len()));
            index = end + 1;
            continue;
        }
        if byte == b'\'' {
            // Char literal ('x', '\n', '\u{..}') versus a lifetime ('a).
            let rest = &text[index + 1..];
            let length = if rest.starts_with('\\') {
                rest.find('\'').map(|end| end + 1)
            } else {
                rest.chars()
                    .next()
                    .filter(|ch| rest[ch.len_utf8()..].starts_with('\''))
                    .map(|ch| ch.len_utf8() + 1)
            };
            if let Some(length) = length {
                ranges.push(index..index + 1 + length);
                index += 1 + length;
                continue;
            }
        }
        index += 1;
    }
    ranges
}

/// End of the (possibly nested) block comment starting at `start`.
fn block_comment_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut index = start;
    while index + 1 < bytes.len() {
        match (bytes[index], bytes[index + 1]) {
            (b'/', b'*') => {
                depth += 1;
                index += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                index += 2;
                if depth == 0 {
                    return index;
                }
            }
            _ => index += 1,
        }
    }
    bytes.len()
}

fn literal_mask(text: &str) -> Vec<bool> {
    let mut mask = vec![false; text.len()];
    for range in rust_literal_ranges(text) {
        mask[range].fill(true);
    }
    mask
}

fn strip_rust_comments(text: &str) -> String {
    let mask = literal_mask(text);
    let in_literal = |index: usize| mask[index];
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if !in_literal(index) && text[index..].starts_with("//") {
            index = text[index..]
                .find('\n')
                .map_or(text.len(), |end| index + end);
            continue;
        }
        if !in_literal(index) && text[index..].starts_with("/*") {
            index = block_comment_end(text, index);
            continue;
        }
        let ch = text[index..].chars().next().unwrap();
        output.push(ch);
        index += ch.len_utf8();
    }
    output
}

/// Removes every item annotated exactly `#[cfg(test)]` (module, fn, use, …),
/// matching braces outside literals, and keeps everything after it.
fn remove_rust_test_items(text: &str) -> String {
    let mask = literal_mask(text);
    let in_literal = |index: usize| mask[index];
    let mut output = String::new();
    let mut copied = 0;
    let mut search = 0;
    while let Some(found) = text[search..].find("#[cfg(test)]") {
        let start = search + found;
        if in_literal(start) {
            search = start + 1;
            continue;
        }
        let mut index = start + "#[cfg(test)]".len();
        // Braces end an item body; `;` ends an item only outside any
        // bracket, so `fn f(x: [u8; 1])` is not cut at the array length.
        let (mut braces, mut nested) = (0_usize, 0_usize);
        let mut end = text.len();
        while index < text.len() {
            if !in_literal(index) {
                match text.as_bytes()[index] {
                    b'(' | b'[' => nested += 1,
                    b')' | b']' => nested = nested.saturating_sub(1),
                    b'{' => braces += 1,
                    b'}' => {
                        braces = braces.saturating_sub(1);
                        if braces == 0 && nested == 0 {
                            end = index + 1;
                            break;
                        }
                    }
                    b';' if braces == 0 && nested == 0 => {
                        end = index + 1;
                        break;
                    }
                    _ => {}
                }
            }
            index += 1;
        }
        output.push_str(&text[copied..start]);
        copied = end;
        search = end;
    }
    output.push_str(&text[copied..]);
    output
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Reference {
    /// A string literal naming the variable (Rust `env::var`, `.env`, …).
    Literal,
    /// A script reading it (`$env:`, `${env:}`, `${…}`, `$…`, `%…%`).
    Script,
}

/// `SAIAI_*` environment variable references in production text.
fn saiai_environment_references(text: &str) -> BTreeSet<(String, Reference)> {
    let mut found = BTreeSet::new();
    for (index, _) in text.match_indices("SAIAI_") {
        let name = text[index..]
            .chars()
            .take_while(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_')
            .collect::<String>();
        let before = &text[..index];
        let after = &text[index + name.len()..];
        // Names are all-uppercase; `SAIAI_Foo` is not a reference to `SAIAI_F`.
        if after.starts_with(|ch: char| ch.is_ascii_alphanumeric()) {
            continue;
        }
        let reference = if (before.ends_with('"') && after.starts_with('"'))
            || (before.ends_with('\'') && after.starts_with('\''))
        {
            Reference::Literal
        } else if before.ends_with("$env:")
            || (before.ends_with("${env:") && after.starts_with('}'))
            || (before.ends_with("${") && (after.starts_with('}') || after.starts_with(':')))
            || (before.ends_with('$') && !before.ends_with("\\$"))
            || (before.ends_with('%') && after.starts_with('%'))
        {
            Reference::Script
        } else {
            continue;
        };
        found.insert((name, reference));
    }
    found
}

/// Variable name → production files referencing it.
fn environment_inventory(sources: &BTreeMap<String, String>) -> BTreeMap<String, BTreeSet<String>> {
    let mut inventory = BTreeMap::<String, BTreeSet<String>>::new();
    for (file, text) in sources {
        for (name, _) in saiai_environment_references(text) {
            inventory.entry(name).or_default().insert(file.clone());
        }
    }
    inventory
}

#[test]
fn source_scanner_ignores_comments_and_tests_and_sees_every_consumer() {
    let sample = r#"env::var("SAIAI_A"); .env('SAIAI_B', x); $env:SAIAI_C; ${env:SAIAI_D};
${SAIAI_E:-x} "$SAIAI_F" %SAIAI_G% const SAIAI_NOT_ENV: &str = "x"; "__SAIAI_NULL__" $SAIAI_Foo"#;
    assert_eq!(
        saiai_environment_references(sample)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        [
            "SAIAI_A", "SAIAI_B", "SAIAI_C", "SAIAI_D", "SAIAI_E", "SAIAI_F", "SAIAI_G"
        ]
    );

    // A name kept only in a comment or a test item is not a production use,
    // while production code after a test item is still scanned.
    let rust = "fn a() { let _ = \"// not a comment SAIAI_KEEP\"; }
// env::var(\"SAIAI_COMMENT\")
/* env::var(\"SAIAI_BLOCK\") */
/* outer /* inner */ env::var(\"SAIAI_NESTED\") */
#[cfg(test)]
fn sized(_: [u8; 1]) { env::var(\"SAIAI_TEST_ARRAY\"); }
#[cfg(test)]
fn helper() { env::var(\"SAIAI_TEST_FN\"); }
#[cfg(test)]
mod tests { fn t() { let _ = \"}\"; let _ = '{'; env::var(\"SAIAI_TEST_MOD\"); } }
#[cfg(test)]
mod declared;
fn after<'a>(_: &'a str) { env::var(\"SAIAI_AFTER\"); let _ = r#\"{\"SAIAI_RAW\"}\"#; }
";
    let names = saiai_environment_references(&production_text(rust, "rs"))
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["SAIAI_AFTER", "SAIAI_RAW"]);
    let script = "# $env:SAIAI_COMMENT\n$x = $env:SAIAI_READ\n";
    assert_eq!(
        saiai_environment_references(&production_text(script, "ps1")),
        BTreeSet::from([("SAIAI_READ".to_string(), Reference::Script)])
    );

    // Renaming the variable in one consumer is visible even though another
    // consumer still uses the old name.
    let before = BTreeMap::from([
        ("a.rs".to_string(), "env::var(\"SAIAI_HOME\")".to_string()),
        ("b.rs".to_string(), "env::var(\"SAIAI_HOME\")".to_string()),
    ]);
    let mut after = before.clone();
    after.insert("b.rs".into(), "env::var(\"AITP_HOME\")".into());
    assert_ne!(
        environment_inventory(&before),
        environment_inventory(&after)
    );
    assert_eq!(
        environment_inventory(&after)["SAIAI_HOME"],
        BTreeSet::from(["a.rs".to_string()])
    );
}

/// Every `SAIAI_*` environment variable the client reads or hands to its own
/// helper processes and scripts, with the production files that spell it.
/// Names owned by the brand are spelled only in `brand_saiai.rs`; their
/// users are pinned by `brand_environment_fields_are_used_by_the_same_files`
/// and `brand_environment_call_sites_are_pinned`.
/// Users, installers, services and older clients set these names; renaming
/// or dropping one anywhere is a breaking change, and adding one should be a
/// conscious decision recorded here.
#[test]
fn saiai_environment_variable_inventory_is_frozen() {
    let expected: &[(&str, &[&str])] = &[
        // Prefix of the program's helper script variables (see
        // `helper_environment_variables_are_written_and_read`).
        ("SAIAI_", &["brand_saiai.rs"]),
        ("SAIAI_BINARY_UPDATED", &["brand_saiai.rs"]),
        ("SAIAI_CHATGPT_BIN", &["brand_saiai.rs"]),
        ("SAIAI_CHATGPT_CHAT_PASSTHROUGH", &["brand_saiai.rs"]),
        ("SAIAI_CHATGPT_TIMEZONE", &["brand_saiai.rs"]),
        ("SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED", &["brand_saiai.rs"]),
        ("SAIAI_DESKTOP_BIN", &["brand_saiai.rs"]),
        ("SAIAI_DESKTOP_BROWSER_USE", &["brand_saiai.rs"]),
        ("SAIAI_HOME", &["brand_saiai.rs"]),
        ("SAIAI_INSTALL_DIR", &["brand_saiai.rs"]),
        ("SAIAI_OPENAI_TRACE", &["brand_saiai.rs"]),
        ("SAIAI_OPENAI_TRACE_PATH", &["brand_saiai.rs"]),
        ("SAIAI_PROXY_VERBOSE", &["brand_saiai.rs"]),
        ("SAIAI_SKIP_START", &["brand_saiai.rs"]),
        ("SAIAI_UPSTREAM_PROXY", &["brand_saiai.rs"]),
    ];
    let found = environment_inventory(&cli_sources());
    let found = found
        .iter()
        .map(|(name, files)| {
            (
                name.as_str(),
                files.iter().map(String::as_str).collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected = expected
        .iter()
        .map(|(name, files)| (*name, files.to_vec()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(found, expected);
}

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

/// Contract literals that are only reachable through inline code today,
/// pinned to the production file that uses them. Each entry must stay until
/// a refactor replaces it with a behavioral test of the same value.
#[test]
fn inline_contract_literals_are_present() {
    let sources = cli_sources();
    for (file, needle) in [
        // Self-update channel below the configured Gateway base URL, and the
        // version prefix an update candidate must print.
        ("lib.rs", "let channel = BRAND.update.channel_path;"),
        ("lib.rs", "\"{base}/{channel}/manifest.json\""),
        ("lib.rs", "\"{base}/{channel}/{asset}\""),
        (
            "lib.rs",
            "!candidate_version\n        .trim_start()\n        .strip_prefix(BRAND.binary_name)\n        .is_some_and(|rest| rest.starts_with(' '))",
        ),
        // Service identities: the start side and the uninstall discovery.
        (
            "environment_scope.rs",
            "\"{}{}.service\",\n        BRAND.service.systemd_unit_prefix,",
        ),
        (
            "environment_scope.rs",
            "\"{}{}\",\n        BRAND.service.launchd_label,",
        ),
        (
            "uninstall.rs",
            "\"{}{}.service\",\n                BRAND.service.systemd_unit_prefix,",
        ),
        (
            "uninstall.rs",
            "is_service_file_name(&name, BRAND.service.systemd_unit_prefix, \".service\")",
        ),
        (
            "uninstall.rs",
            "\"{}{}\",\n                BRAND.service.launchd_label,",
        ),
        (
            "uninstall.rs",
            "is_service_file_name(&name, BRAND.service.launchd_label, \".plist\")",
        ),
        // Windows: stale CAs are recognized by organization.
        ("lib.rs", "O=@@CA_ORG@@(,|$)"),
        // Windows per-user install directory known to uninstall.
        (
            "uninstall.rs",
            ".join(BRAND.windows_app_dir_name)\n                    .join(\"bin\")",
        ),
        (
            "uninstall.rs",
            ".join(format!(\"AppData/Local/{}/bin\", BRAND.windows_app_dir_name))",
        ),
        // Windows Desktop runtime directory: produced by the observer script,
        // consumed by the launcher, removed by uninstall.
        (
            "windows_desktop_inspect.ps1",
            "runtime_directory=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) '@@APP_DIR@@\\desktop-runtime'",
        ),
        (
            "windows_desktop_runtime.rs",
            "pub runtime_directory: String,",
        ),
        ("lib.rs", "PathBuf::from(&initial.runtime_directory)"),
        (
            "uninstall.rs",
            ".join(BRAND.windows_app_dir_name)\n            .join(\"desktop-runtime\")",
        ),
        // The installer's "binary replaced" flag is read here.
        (
            "lib.rs",
            "binary_changed_during_initialization(env::var(BRAND.env.binary_updated)",
        ),
        // Desktop synthetic identity returned by the local sidecars: the email
        // and the synthetic ids derived from the brand's prefix.
        (
            "local_proxy.rs",
            "const DESKTOP_EMAIL: crate::brand::BrandValue<&'static str> =\n    crate::brand::BrandValue(|brand| brand.placeholders.desktop_email);",
        ),
        ("local_proxy.rs", "\"userID\":\"@@ID@@-proxy-user\""),
        ("local_proxy.rs", "\"stableID\":\"@@ID@@-proxy\""),
        (
            "local_proxy.rs",
            "DESKTOP_STATSIG_LOCAL_TEMPLATE.replace(\"@@ID@@\", brand.placeholders.synthetic_id_prefix)",
        ),
        // The restored-preference marker: the forwarder writes the header the
        // Native Chat capability names, and SAIAI names its brand header.
        (
            "local_proxy.rs",
            "headers.insert(restored_header, \"1\".parse()?);",
        ),
        (
            "gateway_saiai.rs",
            "preference_restored_header: brand.gateway.chat_preference_restored_header,",
        ),
        (
            "gateway_saiai.rs",
            "updates_path: brand.gateway.chat_updates_path,",
        ),
        (
            "gateway_saiai.rs",
            "rejected_device_proofs: &[\"saiai-local-proxy\"],",
        ),
        // Atomic temporary files that uninstall recognizes.
        (
            "lib.rs",
            "\".{name}.{}-{}-{}\",\n        BRAND.config.temp_file_infix,",
        ),
    ] {
        let text = sources
            .get(file)
            .unwrap_or_else(|| panic!("production source {file} disappeared"));
        assert!(
            text.contains(needle),
            "SAIAI contract literal disappeared from tools/saiai-cli/src/{file}: {needle}"
        );
    }
}

/// File-level check: each brand-owned environment variable field is used by
/// exactly the production files that spelled the name before it moved to the
/// brand. It does not prove every call site; the most error-prone ones are
/// pinned per function in `brand_environment_call_sites_are_pinned`.
#[test]
fn brand_environment_fields_are_used_by_the_same_files() {
    let sources = cli_sources();
    let expected: &[(&str, &[&str])] = &[
        (
            "BRAND.env.home",
            &[
                "environment_scope.rs",
                "lib.rs",
                "local_proxy.rs",
                "uninstall.rs",
            ],
        ),
        ("BRAND.env.install_dir", &["uninstall.rs"]),
        ("BRAND.env.skip_start", &["codex_daemon.rs", "lib.rs"]),
        ("BRAND.env.binary_updated", &["lib.rs"]),
        ("BRAND.env.upstream_proxy", &["upstream_proxy.rs"]),
        ("BRAND.env.chatgpt_timezone", &["lib.rs"]),
        ("BRAND.env.chatgpt_bin", &["lib.rs"]),
        ("BRAND.env.desktop_bin", &["lib.rs"]),
        ("BRAND.env.chatgpt_chat_passthrough", &["local_proxy.rs"]),
        ("BRAND.env.desktop_browser_use", &["local_proxy.rs"]),
        ("BRAND.env.openai_trace", &["local_proxy.rs"]),
        ("BRAND.env.openai_trace_path", &["local_proxy.rs"]),
        ("BRAND.env.proxy_verbose", &["local_proxy.rs"]),
        (
            "BRAND.env.claude_desktop_allow_untested",
            &["claude_desktop.rs"],
        ),
    ];
    for (field, files) in expected {
        // A field is read as `BRAND.env.x` or, in a lazily resolved
        // constant, as `BrandValue(|brand| brand.env.x)`.
        let lazy = field.replacen("BRAND.", "|brand| brand.", 1);
        // `BRAND.env.openai_trace` is a prefix of `…_trace_path`.
        let users = sources
            .iter()
            .filter(|(_, text)| {
                [field, lazy.as_str()].into_iter().any(|needle| {
                    text.match_indices(needle).any(|(index, _)| {
                        !text[index + needle.len()..]
                            .starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_')
                    })
                })
            })
            .map(|(file, _)| file.as_str())
            .collect::<Vec<_>>();
        assert_eq!(&users, files, "consumers of {field}");
    }
}

/// Text of every function named `name` in production text (all `cfg`
/// variants), matched by braces outside literals. Supports the plain
/// `fn name(` signatures pinned here: no generics, no braces inside the
/// signature. Callers accept a needle found in any variant.
fn function_texts<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    let mask = literal_mask(text);
    let signature = format!("fn {name}(");
    let mut found = Vec::new();
    for (start, _) in text.match_indices(&signature) {
        if mask[start] {
            continue;
        }
        let mut depth = 0_usize;
        let mut end = text.len();
        for (index, byte) in text.bytes().enumerate().skip(start) {
            if mask[index] {
                continue;
            }
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = index + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        found.push(&text[start..end]);
    }
    found
}

/// Call sites where the wrong brand field (or none) would silently change
/// which variable a user, installer or child process sees.
#[test]
fn brand_environment_call_sites_are_pinned() {
    let sources = cli_sources();
    for (file, function, needle) in [
        // Desktop executable overrides: `DESKTOP_BIN` wins over `CHATGPT_BIN`
        // on macOS and Windows; Linux only honors `CHATGPT_BIN`.
        (
            "lib.rs",
            "resolve_macos_desktop_override",
            "for variable in [BRAND.env.desktop_bin, BRAND.env.chatgpt_bin] {",
        ),
        (
            "lib.rs",
            "resolve_windows_desktop_override",
            "for variable in [BRAND.env.desktop_bin, BRAND.env.chatgpt_bin] {",
        ),
        (
            "lib.rs",
            "run_linux_desktop",
            "env::var_os(BRAND.env.chatgpt_bin)",
        ),
        // Every service/helper child is pinned to the resolved home.
        (
            "lib.rs",
            "finalize_update",
            ".env(BRAND.env.home, saiai_config_dir()?)",
        ),
        (
            "lib.rs",
            "start_linux_background_proxy",
            ".env(BRAND.env.home, &saiai_home)",
        ),
        (
            "lib.rs",
            "start_windows_background_proxy",
            ".env(BRAND.env.home, &saiai_home)",
        ),
        (
            "lib.rs",
            "saiai_config_dir",
            "env_dir_override(BRAND.env.home)",
        ),
        (
            "environment_scope.rs",
            "layout",
            "override_dir(BRAND.env.home)?",
        ),
        (
            "uninstall.rs",
            "discover_layout",
            "env_dir_override(BRAND.env.home)",
        ),
        (
            "uninstall.rs",
            "discover_layout",
            "env_dir_override(BRAND.env.install_dir)",
        ),
        (
            "local_proxy.rs",
            "desktop_account_id_fallback",
            "env::var_os(BRAND.env.home)",
        ),
        // Timezone opt-in: read once, never leaked to Desktop children.
        (
            "lib.rs",
            "resolve_chatgpt_timezone",
            "env::var_os(SAIAI_CHATGPT_TIMEZONE_ENV.get())",
        ),
        (
            "lib.rs",
            "run_windows_packaged_desktop",
            "env::var_os(SAIAI_CHATGPT_TIMEZONE_ENV.get()).is_some()",
        ),
        (
            "lib.rs",
            "run_linux_desktop",
            "command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV.get());",
        ),
        (
            "lib.rs",
            "run_macos_desktop",
            "command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV.get());",
        ),
        (
            "lib.rs",
            "run_windows_desktop",
            "command.env_remove(SAIAI_CHATGPT_TIMEZONE_ENV.get());",
        ),
        // Installer hand-off and configure-only switch.
        (
            "lib.rs",
            "start_managed_service_after_initialization",
            "env::var(BRAND.env.skip_start)",
        ),
        (
            "lib.rs",
            "start_managed_service_after_initialization",
            "env::var(BRAND.env.binary_updated)",
        ),
        (
            "codex_daemon.rs",
            "after_initialization",
            "BRAND.env.skip_start",
        ),
        // Local proxy switches.
        (
            "local_proxy.rs",
            "new",
            "env::var(CHATGPT_CHAT_PASSTHROUGH_ENV.get())",
        ),
        (
            "local_proxy.rs",
            "new",
            "env::var(DESKTOP_BROWSER_USE_ENV.get())",
        ),
        ("local_proxy.rs", "new", "env::var(BRAND.env.proxy_verbose)"),
        (
            "local_proxy.rs",
            "from_env",
            "env::var(BRAND.env.openai_trace)",
        ),
        (
            "local_proxy.rs",
            "from_env",
            "env::var(BRAND.env.openai_trace_path)",
        ),
        (
            "upstream_proxy.rs",
            "new",
            "std::env::var(UPSTREAM_PROXY_ENV.get())",
        ),
        (
            "claude_desktop.rs",
            "run",
            "BRAND.env.claude_desktop_allow_untested",
        ),
    ] {
        let text = sources
            .get(file)
            .unwrap_or_else(|| panic!("production source {file} disappeared"));
        let functions = function_texts(text, function);
        assert!(
            !functions.is_empty(),
            "fn {function} disappeared from {file}"
        );
        assert!(
            functions.iter().any(|body| body.contains(needle)),
            "fn {function} in {file} no longer contains {needle}"
        );
    }
    // The aliases those call sites use still name the brand fields.
    for (file, needle) in [
        (
            "lib.rs",
            "const SAIAI_CHATGPT_TIMEZONE_ENV: BrandValue<&'static str> =\n    BrandValue(|brand| brand.env.chatgpt_timezone);",
        ),
        (
            "local_proxy.rs",
            "const CHATGPT_CHAT_PASSTHROUGH_ENV: crate::brand::BrandValue<&'static str> =\n    crate::brand::BrandValue(|brand| brand.env.chatgpt_chat_passthrough);",
        ),
        (
            "local_proxy.rs",
            "const DESKTOP_BROWSER_USE_ENV: crate::brand::BrandValue<&'static str> =\n    crate::brand::BrandValue(|brand| brand.env.desktop_browser_use);",
        ),
        (
            "upstream_proxy.rs",
            "pub(crate) const UPSTREAM_PROXY_ENV: crate::brand::BrandValue<&'static str> =\n    crate::brand::BrandValue(|brand| brand.env.upstream_proxy);",
        ),
    ] {
        assert!(sources[file].contains(needle), "{file}: {needle}");
    }
}

/// Update channel URLs below a Gateway base URL, written out in full.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn update_channel_urls_are_frozen() {
    for base in [
        "https://api.saiai.top",
        "https://api.saiai.top/",
        "https://api.saiai.top///",
        "  https://api.saiai.top/  ",
    ] {
        assert_eq!(
            update_urls(base, "saiai-linux-x86_64"),
            (
                "https://api.saiai.top/saiai-cli/manifest.json".to_string(),
                "https://api.saiai.top/saiai-cli/saiai-linux-x86_64".to_string()
            ),
            "{base:?}"
        );
    }
    assert_eq!(
        update_urls(
            "https://gateway.example/prefix/",
            "saiai-windows-x86_64.exe"
        ),
        (
            "https://gateway.example/prefix/saiai-cli/manifest.json".to_string(),
            "https://gateway.example/prefix/saiai-cli/saiai-windows-x86_64.exe".to_string()
        )
    );
    for (asset, url) in [
        (
            "saiai-linux-x86_64",
            "https://api.saiai.top/saiai-cli/saiai-linux-x86_64",
        ),
        (
            "saiai-linux-aarch64",
            "https://api.saiai.top/saiai-cli/saiai-linux-aarch64",
        ),
        (
            "saiai-macos-x86_64",
            "https://api.saiai.top/saiai-cli/saiai-macos-x86_64",
        ),
        (
            "saiai-macos-aarch64",
            "https://api.saiai.top/saiai-cli/saiai-macos-aarch64",
        ),
        (
            "saiai-windows-x86_64.exe",
            "https://api.saiai.top/saiai-cli/saiai-windows-x86_64.exe",
        ),
        (
            "saiai-windows-aarch64.exe",
            "https://api.saiai.top/saiai-cli/saiai-windows-aarch64.exe",
        ),
    ] {
        assert_eq!(update_urls("https://api.saiai.top", asset).1, url);
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

/// The library never reports its own package metadata as the program's: a
/// distribution binary supplies the release facts through `RuntimeContext`.
#[test]
fn library_takes_release_facts_from_the_entry_point() {
    let sources = cli_sources();
    for (file, text) in &sources {
        // `env!`/`option_env!` with an ordinary string literal naming any
        // `CARGO_*` variable, with or without whitespace or line breaks.
        // Raw strings (`env!(r"CARGO_…")`) and `concat!`-built names are
        // not detected.
        let compact = text.split_whitespace().collect::<String>();
        if file != "main.rs" {
            assert!(
                !compact.contains("env!(\"CARGO_"),
                "{file} reads compile-time Cargo metadata"
            );
        }
    }
    let entry = &sources["main.rs"];
    assert!(
        entry.contains(
            "proxy_cli::run(\n        &brand_saiai::SAIAI_BRAND,\n        proxy_cli::RuntimeContext {"
        ),
        "{entry}"
    );
    assert!(
        entry.contains("version: env!(\"CARGO_PKG_VERSION\"),"),
        "{entry}"
    );
}

/// Blocks naming the SAIAI brand directly from library sources: only the
/// program side (`main.rs`) and the SAIAI values themselves spell these
/// names. A textual check, not a proof of the dependency boundary.
#[test]
fn only_the_program_names_the_saiai_brand() {
    let sources = cli_sources();
    for (file, text) in &sources {
        if file == "main.rs" || file == "brand_saiai.rs" {
            continue;
        }
        for name in ["brand_saiai", "SAIAI_BRAND"] {
            assert!(!text.contains(name), "{file} names {name}");
        }
    }
    assert!(sources["main.rs"].contains("mod brand_saiai;"));
}

/// The SAIAI values of every brand field, written out by hand. A refactor
/// may move or rename the fields, never change these values.
#[test]
fn saiai_brand_values_are_frozen() {
    let brand = crate::brand::BRAND;
    assert_eq!(brand.binary_name, "saiai");
    assert_eq!(brand.product_name, "SAIAI");
    assert_eq!(brand.home_dir_name, ".saiai");
    assert_eq!(brand.windows_app_dir_name, "SAIAI");
    assert_eq!(brand.config.filename, "config.json");
    assert_eq!(brand.config.version, 2);
    assert_eq!(brand.config.temp_file_infix, "saiai-tmp");
    let env = &brand.env;
    assert_eq!(
        [
            env.home,
            env.install_dir,
            env.skip_start,
            env.binary_updated,
            env.upstream_proxy,
            env.chatgpt_timezone,
            env.chatgpt_bin,
            env.desktop_bin,
            env.chatgpt_chat_passthrough,
            env.desktop_browser_use,
            env.openai_trace,
            env.openai_trace_path,
            env.proxy_verbose,
            env.claude_desktop_allow_untested,
        ],
        [
            "SAIAI_HOME",
            "SAIAI_INSTALL_DIR",
            "SAIAI_SKIP_START",
            "SAIAI_BINARY_UPDATED",
            "SAIAI_UPSTREAM_PROXY",
            "SAIAI_CHATGPT_TIMEZONE",
            "SAIAI_CHATGPT_BIN",
            "SAIAI_DESKTOP_BIN",
            "SAIAI_CHATGPT_CHAT_PASSTHROUGH",
            "SAIAI_DESKTOP_BROWSER_USE",
            "SAIAI_OPENAI_TRACE",
            "SAIAI_OPENAI_TRACE_PATH",
            "SAIAI_PROXY_VERBOSE",
            "SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED",
        ]
    );
    let certificates = &brand.certificates;
    assert_eq!(certificates.ca_cert_filename, "saiai-ca.crt");
    assert_eq!(certificates.ca_key_filename, "saiai-ca.key");
    assert_eq!(
        certificates.ca_common_name_prefix,
        "SAIAI local installation CA"
    );
    assert_eq!(certificates.ca_organization, "SAIAI");
    assert_eq!(certificates.nss_nickname, "saiai-local-proxy");
    assert_eq!(certificates.tls_leaf_salt, b"SAIAI local proxy TLS leaf v1");
    assert_eq!(certificates.control_host, "certificate.saiai.local");
    assert_eq!(certificates.spki_header, "x-saiai-leaf-spki-sha256");
    let service = &brand.service;
    assert_eq!(service.systemd_unit_prefix, "saiai");
    assert_eq!(service.launchd_label, "top.saiai.local-proxy");
    assert_eq!(service.pid_filename, "saiai.pid");
    assert_eq!(service.lock_filename, "saiai.lock");
    assert_eq!(service.log_filename, "saiai.log");
    let update = &brand.update;
    assert_eq!(update.channel_path, "saiai-cli");
    assert_eq!(update.asset_prefix, "saiai-");
    assert_eq!(update.candidate_prefix, ".saiai-update-");
    assert_eq!(update.backup_prefix, "saiai.bak-");
    assert_eq!(update.status_filename, ".saiai-update-status.txt");
    let markers = &brand.markers;
    assert_eq!(
        markers.codex_ide_env_begin,
        "# BEGIN SAIAI CODEX IDE (managed)"
    );
    assert_eq!(markers.codex_ide_env_end, "# END SAIAI CODEX IDE (managed)");
    assert_eq!(markers.vscode_proxy, "// SAIAI managed VSCode proxy: ");
    let placeholders = &brand.placeholders;
    assert_eq!(placeholders.codex_account_id, "saiai-local-proxy-account");
    assert_eq!(placeholders.codex_token, PLACEHOLDER_JWT);
    assert_eq!(
        placeholders.legacy_codex_token_prefix,
        "saiai-local-proxy-placeholder-"
    );
    assert_eq!(placeholders.desktop_token_prefix, "saiai-desktop-");
    assert_eq!(
        placeholders.claude_desktop_token_prefix,
        "saiai-desktop-claude-"
    );
    assert_eq!(placeholders.claude_desktop_session_prefix, "saiai-local-");
    assert_eq!(
        placeholders.desktop_email,
        "saiai-local-proxy@example.invalid"
    );
    assert_eq!(placeholders.synthetic_id_prefix, "saiai-local");
    let proof = &brand.client_proof;
    assert_eq!(proof.header, "x-saiai-client-proof");
    assert_eq!(proof.message_domain, "saiai-client-proof-v1");
    assert_eq!(proof.enroll_path, "/api/v1/client/devices/enroll");
    assert_eq!(proof.key_filename, "client-device-key");
    assert_eq!(proof.lock_filename, "client-device.lock");
    assert_eq!(proof.device_filename, "client-device.json");
    assert_eq!(proof.corrupt_key_filename, "client-device-key.corrupt");
    assert_eq!(certificates.ca_backup_prefix, "saiai-ca.");
    assert_eq!(
        brand.gateway.chat_updates_path,
        "/backend-api/saiai/chat-updates"
    );
    assert_eq!(
        brand.gateway.chat_preference_restored_header,
        "x-saiai-chat-preference-restored"
    );
    // SAIAI turns the Native Chat relay on with exactly its brand names and
    // the historical placeholder device proof it never forwards.
    assert_eq!(
        crate::GatewayExtension::native_chat(&crate::gateway_saiai::SAIAI_GATEWAY),
        Some(crate::NativeChatProtocol {
            updates_path: "/backend-api/saiai/chat-updates",
            preference_restored_header: "x-saiai-chat-preference-restored",
            rejected_device_proofs: &["saiai-local-proxy"],
        })
    );
    assert_eq!(
        crate::GatewayExtension::native_chat(&crate::gateway::NoGatewayExtension),
        None
    );
    assert_eq!(brand.winhttp_agent, "SAIAI");
    assert_eq!(brand.codex_daemon_client_name, "saiai_daemon_check");
    assert_eq!(brand.scripts.env_prefix, "SAIAI_");
    assert_eq!(brand.scripts.identifier_prefix, "Saiai");
    assert_eq!(brand.sensitive_inbound_headers, ["x-saiai-client-proof"]);
}

/// Identifier (not a field access or field declaration) of the client proof
/// protocol or the SAIAI extension used on `line`, if any.
fn protocol_reference(line: &str) -> Option<&'static str> {
    let ident = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    for name in [
        "client_proof",
        "ClientProof",
        "gateway_saiai",
        "SAIAI_GATEWAY",
    ] {
        for (index, _) in line.match_indices(name) {
            let before = &line[..index];
            let after = &line[index + name.len()..];
            if before.ends_with(ident) || after.starts_with(ident) {
                continue;
            }
            // `brand.client_proof.header` and `client_proof: ClientProofNames`
            // are brand data, not the protocol module.
            if before.ends_with('.') || (after.starts_with(':') && !after.starts_with("::")) {
                continue;
            }
            return Some(name);
        }
    }
    None
}

#[test]
fn protocol_reference_scanner_sees_paths_imports_and_types() {
    for line in [
        "crate::client_proof::wire_target(&url)",
        "use crate::client_proof::{self, ClientProof};",
        "let proof: Arc<ClientProof> = todo!();",
        "&proxy_cli::gateway_saiai::SAIAI_GATEWAY",
        "client_proof::HEADER_NAME.get()",
    ] {
        assert!(protocol_reference(line).is_some(), "{line}");
    }
    for line in [
        "BRAND.client_proof.key_filename,",
        "pub client_proof: ClientProofNames,",
        "client_proof: ClientProofNames {",
        "BrandValue(|brand| brand.client_proof.header)",
    ] {
        assert_eq!(protocol_reference(line), None, "{line}");
    }
}

/// The SAIAI program injects the SAIAI Gateway extension; library sources
/// other than the extension itself never use the client proof protocol.
/// A textual check of direct references, not a dependency-graph proof.
#[test]
fn only_the_extension_side_uses_the_client_proof_protocol() {
    let sources = cli_sources();
    assert!(
        sources["main.rs"].contains("gateway: &proxy_cli::gateway_saiai::SAIAI_GATEWAY,"),
        "the saiai program must inject the SAIAI Gateway extension"
    );
    for (file, text) in &sources {
        if matches!(
            file.as_str(),
            "main.rs" | "gateway_saiai.rs" | "client_proof.rs"
        ) {
            continue;
        }
        for line in text.lines() {
            let trimmed = line.trim();
            // lib.rs declares the modules (and nothing else may name them).
            if file == "lib.rs" && matches!(trimmed, "mod client_proof;" | "pub mod gateway_saiai;")
            {
                continue;
            }
            if let Some(name) = protocol_reference(trimmed) {
                panic!("{file} uses {name}: {trimmed}");
            }
        }
    }
}

/// Helper script templates render to exactly the scripts SAIAI shipped
/// before they became templates (SHA-256 of the previous file contents).
#[test]
fn helper_scripts_render_to_the_shipped_saiai_scripts() {
    use sha2::{Digest, Sha256};
    for (template, expected) in [
        (
            include_str!("vscode_trust_windows.ps1"),
            "92e176ca26965518366f792c9efc02610f439a099a7bfdee75326d3950c118cd",
        ),
        (
            include_str!("windows_desktop_inspect.ps1"),
            "3387f0e3ae941e20177c0ee3a76c3cce40bc395f4a7927ca4e4319f4b5c116f6",
        ),
    ] {
        // `.gitattributes` checks scripts out with CRLF; hash the LF form
        // stored in the repository.
        let rendered = crate::script_brand::render(template).replace("\r\n", "\n");
        assert_eq!(hex(&Sha256::digest(rendered.as_bytes())), expected);
    }
}

/// The update helper is assembled around user paths after the brand name is
/// inserted: tokens inside those paths stay as typed and never fail.
#[cfg(windows)]
#[test]
fn update_helper_keeps_token_like_user_paths_verbatim() {
    let directory = Path::new(r"C:\Users\u\@@ENV@@\@@ID@@\@@OTHER@@");
    let script = render_windows_update_script(
        1,
        &directory.join("saiai.exe"),
        &directory.join(".saiai-update-1.exe"),
        &directory.join(".saiai-update-1.ps1"),
        &directory.join(".saiai-update-status.txt"),
        true,
        &"0".repeat(64),
    )
    .unwrap();
    assert!(
        script.contains(r"C:\Users\u\@@ENV@@\@@ID@@\@@OTHER@@\saiai.exe"),
        "{script}"
    );
    assert!(
        script.contains("function Invoke-SaiaiCommand([string]$verb) {"),
        "{script}"
    );
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

/// Files that may name SAIAI: its brand values, its Gateway extension, the
/// client proof (moves out in C4), and the SAIAI program entry point.
const SAIAI_NAMING_FILES: [&str; 4] = [
    "brand_saiai.rs",
    "gateway_saiai.rs",
    "client_proof.rs",
    "main.rs",
];

/// Production lines elsewhere that still contain `saiai` (any case), one
/// `file<TAB>line` per occurrence, whitespace collapsed. The list may only
/// shrink: names move to `Brand`, they never come back.
const SAIAI_RESIDUE: &str = include_str!("brand_residue.txt");

fn saiai_residue_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for (file, text) in cli_sources() {
        if SAIAI_NAMING_FILES.contains(&file.as_str()) {
            continue;
        }
        for line in text.lines() {
            if line.to_ascii_lowercase().contains("saiai") {
                let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
                lines.push(format!("{file}\t{line}"));
            }
        }
    }
    lines.sort();
    lines
}

#[test]
fn saiai_names_outside_the_brand_only_shrink() {
    let mut expected: Vec<String> = SAIAI_RESIDUE
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    expected.sort();
    let actual = saiai_residue_lines();
    let added: Vec<_> = actual
        .iter()
        .filter(|line| !expected.contains(line))
        .collect();
    let removed: Vec<_> = expected
        .iter()
        .filter(|line| !actual.contains(line))
        .collect();
    assert!(
        added.is_empty() && removed.is_empty() && actual == expected,
        "SAIAI name residue changed.\nNew (read the value from Brand instead):\n{}\nGone (delete from brand_residue.txt):\n{}",
        added
            .iter()
            .map(|line| line.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        removed
            .iter()
            .map(|line| line.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
