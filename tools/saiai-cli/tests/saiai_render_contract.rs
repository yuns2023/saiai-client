//! SAIAI golden outputs that the kernel renders, checked through its
//! `contract` entries from outside the library (feature `contract`; the
//! library is built without cfg(test)). Expected values are unchanged from
//! the in-library tests they replace.

use base64::Engine as _;
#[allow(unused_imports)]
use proxy_cli::contract::{
    certificates, claude_desktop, codex, config, desktop, environment, scripts, service, uninstall,
    update, vscode,
};
use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames, UpdateSource,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

#[path = "../src/brand_saiai.rs"]
mod brand_saiai;
#[allow(dead_code)]
#[path = "support/source_scan.rs"]
mod source_scan;

/// The SAIAI brand and runtime, installed as the program installs them.
fn saiai() -> &'static Brand {
    proxy_cli::contract::install(
        &brand_saiai::SAIAI_BRAND,
        proxy_cli::RuntimeContext {
            version: env!("CARGO_PKG_VERSION"),
            gateway: &saiai::gateway_saiai::SAIAI_GATEWAY,
        },
    )
    .unwrap();
    &brand_saiai::SAIAI_BRAND
}

/// A config file's text through the program's serde decoder and encoder
/// (compact JSON; the program writes the file pretty-printed, and file-read
/// error context is not part of this check), as a JSON value.
fn decoded(json: &str) -> serde_json::Value {
    serde_json::from_str(&config::decode(saiai(), json).unwrap().unwrap()).unwrap()
}

/// Update channel URLs (manifest, asset) as the program builds them.
#[allow(dead_code)]
fn urls(base: &str, asset: &str) -> (String, String) {
    let names = update::names(saiai(), base, asset, "1").unwrap();
    (names.manifest_url, names.asset_url)
}

const FIXTURE_CA_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq9CjdR/blyuJLwO9
rRwtbhRu5K6erOiP7uCwzzd9PXShRANCAAR9MvoxxSfya0pWhgD4ODg/zZT8l7j8
lnlBHU8SoMoq33F9ZTGTqCWDaA3J4o7FJHuch2xnehGEi5vTE8+bhki0
-----END PRIVATE KEY-----
";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_os = "linux")]
#[test]
fn linux_systemd_unit_renders_exactly() {
    let unit = service::systemd_unit(
        saiai(),
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

#[cfg(target_os = "macos")]
#[test]
fn macos_launchd_plist_renders_exactly() {
    // The production template uses `\` line continuations, so the plist has
    // no indentation; existing LaunchAgents were written byte-for-byte so.
    let plist = service::launchd_plist(
        saiai(),
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn update_assets_and_file_names_are_frozen() {
    let names = update::names(saiai(), "https://api.saiai.top", "x", "1-2").unwrap();
    let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "saiai-linux-x86_64",
        ("linux", "aarch64") => "saiai-linux-aarch64",
        ("macos", "x86_64") => "saiai-macos-x86_64",
        ("macos", "aarch64") => "saiai-macos-aarch64",
        ("windows", "x86_64") => "saiai-windows-x86_64.exe",
        ("windows", "aarch64") => "saiai-windows-aarch64.exe",
        other => panic!("no frozen asset for {other:?}"),
    };
    assert_eq!(names.current_asset, expected);
    for foreign in ["aitp-linux-x86_64", "linux-x86_64", "saiai.exe"] {
        assert!(
            update::validate_asset(saiai(), b"\x7FELF", foreign).is_err(),
            "{foreign}"
        );
    }
    let (candidate, backup_prefix) = if cfg!(windows) {
        (".saiai-update-1-2.exe", "saiai.bak-")
    } else {
        (".saiai-update-1-2", "saiai.bak-")
    };
    assert_eq!(names.candidate, candidate);
    let backup = names.backup.clone();
    assert!(backup.starts_with(backup_prefix), "{backup}");
    assert_eq!(backup.ends_with(".exe"), cfg!(windows), "{backup}");
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
            certificates::leaf(saiai(), host, &ca_cert_pem, FIXTURE_CA_KEY_PEM).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        let pin = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(leaf.tbs_certificate.subject_pki.raw));
        assert_eq!(pin, expected, "{host}");
        // The control header carries the hash of the same SPKI.
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&leaf_key)),
            expected,
            "{host}"
        );
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
            urls(base, "saiai-linux-x86_64"),
            (
                "https://api.saiai.top/saiai-cli/manifest.json".to_string(),
                "https://api.saiai.top/saiai-cli/saiai-linux-x86_64".to_string()
            ),
            "{base:?}"
        );
    }
    assert_eq!(
        urls(
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
        assert_eq!(urls("https://api.saiai.top", asset).1, url);
    }
}

/// Helper script templates render to exactly the scripts SAIAI shipped
/// before they became templates (SHA-256 of the previous file contents).
#[test]
fn helper_scripts_render_to_the_shipped_saiai_scripts() {
    use sha2::{Digest, Sha256};
    for (template, expected) in [
        (
            scripts::VSCODE_TRUST_WINDOWS,
            "92e176ca26965518366f792c9efc02610f439a099a7bfdee75326d3950c118cd",
        ),
        (
            scripts::WINDOWS_DESKTOP_INSPECT,
            "3387f0e3ae941e20177c0ee3a76c3cce40bc395f4a7927ca4e4319f4b5c116f6",
        ),
    ] {
        // `.gitattributes` checks scripts out with CRLF; hash the LF form
        // stored in the repository.
        let rendered = scripts::render(saiai(), template)
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(hex(&Sha256::digest(rendered.as_bytes())), expected);
    }
}

/// The update helper is assembled around user paths after the brand name is
/// inserted: tokens inside those paths stay as typed and never fail.
#[cfg(windows)]
#[test]
fn update_helper_keeps_token_like_user_paths_verbatim() {
    let directory = Path::new(r"C:\Users\u\@@ENV@@\@@ID@@\@@OTHER@@");
    let script = scripts::windows_update(
        saiai(),
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

#[test]
fn saiai_config_json_shape_is_frozen() {
    // Written by an install with a Claude route and no upstream proxy.
    let config = decoded(
        r#"{"version":2,"base_url":"https://gateway.example","api_key":"TEST_ONLY_CONTRACT","listen":"127.0.0.1:19908","ca_cert_path":"/h/.saiai/saiai-ca.crt","ca_key_path":"/h/.saiai/saiai-ca.key","chatgpt_chat_passthrough":true,"desktop_browser_use":false,"providers":{"claude":{"base_url":"https://claude.gateway.example","api_key":"TEST_ONLY_CLAUDE"}}}"#,
    );
    assert_eq!(
        config,
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
    let parsed = decoded(&full.to_string());
    assert_eq!(parsed["upstream_proxy"], "http://127.0.0.1:7890");
    assert_eq!(
        parsed["providers"]["codex"]["base_url"],
        "https://codex.gateway.example"
    );
    assert_eq!(parsed, full);

    // Configurations written by older clients keep loading with defaults.
    let legacy = decoded(
        &serde_json::json!({
            "version": 2,
            "base_url": "https://gateway.example",
            "api_key": "TEST_ONLY_CONTRACT",
            "listen": "127.0.0.1:19908",
            "ca_cert_path": "/h/.saiai/saiai-ca.crt",
            "upstream_proxy": "direct"
        })
        .to_string(),
    );
    assert_eq!(legacy["ca_key_path"], "");
    assert_eq!(legacy["chatgpt_chat_passthrough"], true);
    assert_eq!(legacy["desktop_browser_use"], true);
    assert_eq!(legacy["upstream_proxy"], "direct");
    assert_eq!(legacy["providers"], serde_json::json!({}));
}

/// config.json shapes and their exact results, frozen from the release
/// before the configuration type was renamed: every error names the type
/// as earlier releases did, including array-form length errors, with
/// serde_json's line and column.
#[test]
fn config_json_shapes_and_diagnostics_are_frozen() {
    let cases: &[(&str, Result<&str, &str>)] = &[
        (
            r#"1"#,
            Err(r#"invalid type: integer `1`, expected struct SaiaiConfig at line 1 column 1"#),
        ),
        (
            r#""x""#,
            Err(r#"invalid type: string "x", expected struct SaiaiConfig at line 1 column 3"#),
        ),
        (
            r#"true"#,
            Err(r#"invalid type: boolean `true`, expected struct SaiaiConfig at line 1 column 4"#),
        ),
        (
            r#"null"#,
            Err(r#"invalid type: null, expected struct SaiaiConfig at line 1 column 4"#),
        ),
        (
            r#"1.5"#,
            Err(
                r#"invalid type: floating point `1.5`, expected struct SaiaiConfig at line 1 column 3"#,
            ),
        ),
        (
            r#"[]"#,
            Err(
                r#"invalid length 0, expected struct SaiaiConfig with 10 elements at line 1 column 2"#,
            ),
        ),
        (
            r#"[2]"#,
            Err(
                r#"invalid length 1, expected struct SaiaiConfig with 10 elements at line 1 column 3"#,
            ),
        ),
        (
            r#"[2,"u","k"]"#,
            Err(
                r#"invalid length 3, expected struct SaiaiConfig with 10 elements at line 1 column 11"#,
            ),
        ),
        (
            r#"[2,"u","k","l"]"#,
            Err(
                r#"invalid length 4, expected struct SaiaiConfig with 10 elements at line 1 column 15"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c"]"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c","kp",true,false,null,{}]"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"kp","chatgpt_chat_passthrough":true,"desktop_browser_use":false,"providers":{}}"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c","kp",true,false,null,{},1]"#,
            Err(r#"trailing characters at line 1 column 44"#),
        ),
        (
            r#"["2"]"#,
            Err(r#"invalid type: string "2", expected u32 at line 1 column 4"#),
        ),
        (
            r#"{}"#,
            Err(r#"missing field `version` at line 1 column 2"#),
        ),
        (
            r#"{"version":2}"#,
            Err(r#"missing field `base_url` at line 1 column 13"#),
        ),
        (
            r#"{"version":2,"version":3,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}"#,
            Err(r#"duplicate field `version` at line 1 column 22"#),
        ),
        (
            r#"{"version":"2","base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}"#,
            Err(r#"invalid type: string "2", expected u32 at line 1 column 14"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","extra":1}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"

   null"#,
            Err(r#"invalid type: null, expected struct SaiaiConfig at line 3 column 7"#),
        ),
        (
            r#"
  [
 2,
 "u"
 ]"#,
            Err(
                r#"invalid length 2, expected struct SaiaiConfig with 10 elements at line 5 column 2"#,
            ),
        ),
        (
            r#"{
  "version": 2
}"#,
            Err(r#"missing field `base_url` at line 3 column 1"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        // Field-level edge cases, same source release.
        (
            r#"[2,"u","k","l","c","kp"]"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"kp","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c","kp",false]"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"kp","chatgpt_chat_passthrough":false,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c","kp",false,false]"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"kp","chatgpt_chat_passthrough":false,"desktop_browser_use":false,"providers":{}}"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c","kp",false,false,"direct"]"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"kp","chatgpt_chat_passthrough":false,"desktop_browser_use":false,"upstream_proxy":"direct","providers":{}}"#,
            ),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","chatgpt_chat_passthrough":null}"#,
            Err(r#"invalid type: null, expected a boolean at line 1 column 105"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","chatgpt_chat_passthrough":"yes"}"#,
            Err(r#"invalid type: string "yes", expected a boolean at line 1 column 106"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","desktop_browser_use":null}"#,
            Err(r#"invalid type: null, expected a boolean at line 1 column 100"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","desktop_browser_use":"no"}"#,
            Err(r#"invalid type: string "no", expected a boolean at line 1 column 100"#),
        ),
        (
            r#"[2,"u","k","l","c","kp",null]"#,
            Err(r#"invalid type: null, expected a boolean at line 1 column 28"#),
        ),
        (
            r#"[2,"u","k","l","c","kp",true,"x"]"#,
            Err(r#"invalid type: string "x", expected a boolean at line 1 column 32"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":null}"#,
            Err(r#"invalid type: null, expected a string at line 1 column 92"#),
        ),
        (
            r#"[2,"u","k","l","c",null]"#,
            Err(r#"invalid type: null, expected a string at line 1 column 23"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","providers":null}"#,
            Err(r#"invalid type: null, expected struct ProviderCredentials at line 1 column 90"#),
        ),
        (
            r#"[2,"u","k","l","c","kp",true,true,null,null]"#,
            Err(r#"invalid type: null, expected struct ProviderCredentials at line 1 column 43"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","upstream_proxy":null}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","upstream_proxy":"direct"}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"upstream_proxy":"direct","providers":{}}"#,
            ),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","upstream_proxy":5}"#,
            Err(r#"invalid type: integer `5`, expected a string at line 1 column 92"#),
        ),
        (
            r#"[2,"u","k","l","c","kp",true,true,5]"#,
            Err(r#"invalid type: integer `5`, expected a string at line 1 column 35"#),
        ),
        (
            r#"{"version":null,"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}"#,
            Err(r#"invalid type: null, expected u32 at line 1 column 15"#),
        ),
        (
            r#"{"upstream_proxy":null,"upstream_proxy":"direct","version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}"#,
            Err(r#"duplicate field `upstream_proxy` at line 1 column 39"#),
        ),
        (
            r#"{"providers":{},"upstream_proxy":"direct","desktop_browser_use":false,"chatgpt_chat_passthrough":false,"ca_key_path":"kp","ca_cert_path":"c","listen":"l","api_key":"k","base_url":"u","version":2}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"kp","chatgpt_chat_passthrough":false,"desktop_browser_use":false,"upstream_proxy":"direct","providers":{}}"#,
            ),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","extra":{"a":[1,{"b":null}]},"more":[1,[2,{}]]}"#,
            Ok(
                r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c","ca_key_path":"","chatgpt_chat_passthrough":true,"desktop_browser_use":true,"providers":{}}"#,
            ),
        ),
        (
            r#"[2,"u","k","l","c",]"#,
            Err(r#"trailing comma at line 1 column 20"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c",}"#,
            Err(r#"trailing comma at line 1 column 75"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"} {}"#,
            Err(r#"trailing characters at line 1 column 76"#),
        ),
        (
            r#"[2,"u","k","l","c"] 1"#,
            Err(r#"trailing characters at line 1 column 21"#),
        ),
        (
            r#"{"version":2,"base_url":"u","api_key":"k","listen":"l","ca_cert_path":"c"}

  null"#,
            Err(r#"trailing characters at line 3 column 3"#),
        ),
    ];
    for (input, expected) in cases {
        let actual = config::decode(saiai(), input).unwrap();
        assert_eq!(
            actual.as_deref().map_err(String::as_str),
            *expected,
            "{input:?}"
        );
    }
}

/// A config.json whose root is not an object reports the same serde
/// diagnostic as before the configuration type was renamed.
#[test]
fn config_type_diagnostic_is_unchanged() {
    let error = config::decode(saiai(), "null").unwrap().unwrap_err();
    assert_eq!(
        error,
        "invalid type: null, expected struct SaiaiConfig at line 1 column 4"
    );
}

// Thin unwrapping helpers so the assertions read as before.
fn home_file(name: &str) -> bool {
    uninstall::is_home_file(saiai(), name).unwrap()
}
fn program_file(name: &str) -> bool {
    uninstall::is_program_file(saiai(), name).unwrap()
}
fn claude_ca_file(name: &str) -> bool {
    uninstall::is_claude_ca_file(saiai(), name).unwrap()
}
fn product_of(name: &str) -> Option<&'static str> {
    environment::product_of(saiai(), name).unwrap()
}
fn suffix(root: &Path, directory: &Path) -> String {
    environment::service_suffix(saiai(), root, directory).unwrap()
}
fn placeholder_token(token: &str) -> bool {
    codex::is_placeholder_access_token(saiai(), token).unwrap()
}
fn managed(settings: &str) -> bool {
    vscode::has_managed_proxy(saiai(), settings).unwrap()
}

const PLACEHOLDER_JWT: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InNhaWFpLWxvY2FsLXByb3h5QGludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3VzZXJfaWQiOiJzYWlhaS1sb2NhbC1wcm94eS11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoic2FpYWktbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.c2FpYWktbG9jYWwtcHJveHk";

#[test]
fn environment_isolation_names_are_frozen() {
    assert_eq!(
        environment::name(saiai(), "codex", Path::new("/work/project/codex")).unwrap(),
        "codex-2da86b69bd2e5ac6a16af476"
    );
    assert_eq!(
        suffix(
            Path::new("/saiai"),
            Path::new("/saiai/environments/codex-project")
        ),
        "-79ac17449adbff9bab473f32"
    );
    assert_eq!(suffix(Path::new("/saiai"), Path::new("/saiai")), "");
    assert_eq!(
        product_of("claude-2da86b69bd2e5ac6a16af476"),
        Some("claude")
    );
    assert_eq!(product_of("codex-2da86b69bd2e5ac6a16af476"), Some("codex"));
    assert_eq!(product_of("aitp-2da86b69bd2e5ac6a16af476"), None);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_default_service_name_is_frozen() {
    // The test process never resolves an isolated environment.
    assert_eq!(environment::service_name(saiai()).unwrap(), "saiai.service");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_default_launchd_label_is_frozen() {
    assert_eq!(
        environment::launchd_label(saiai()).unwrap(),
        "top.saiai.local-proxy"
    );
}

#[test]
fn codex_placeholder_login_is_frozen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.json");
    codex::placeholder_login(saiai(), &path).unwrap();
    let auth: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
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
    assert!(placeholder_token(PLACEHOLDER_JWT));
    assert!(placeholder_token("saiai-local-proxy-placeholder-0123"));
    assert!(!placeholder_token("aitp-local-proxy-placeholder-0123"));
}

#[test]
fn codex_ide_env_block_renders_exactly() {
    assert_eq!(
        codex::ide_env(saiai(), "KEEP=1\n", "127.0.0.1:19908", "/h/.saiai/saiai-ca.crt").unwrap(),
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
    let merged = vscode::merge_settings(saiai(), "{}\n", "127.0.0.1:19908").unwrap();
    assert!(
        merged.contains("// SAIAI managed VSCode proxy: http://127.0.0.1:19908"),
        "{merged}"
    );
    assert!(managed(
        "{\n// SAIAI managed VSCode proxy: http://127.0.0.1:19908\n\"http.proxy\": \"http://127.0.0.1:19908\"\n}\n"
    ));
    assert!(!managed(
        "{\n// AITP managed VSCode proxy: http://127.0.0.1:19908\n}\n"
    ));
}

#[test]
fn uninstall_recognition_rules_are_frozen() {
    let (home_files, home_dirs) = uninstall::home_layout(saiai()).unwrap();
    assert_eq!(
        home_files,
        &[
            "config.json",
            "saiai-ca.crt",
            "saiai-ca.key",
            "initialization.lock",
            "saiai.lock",
            "saiai.pid",
            "saiai.log",
            "windows-packaged-proxy-lease.json",
        ]
    );
    // The client proof files, declared by the SAIAI extension, are still the
    // program's own, with their backups and atomic-write leftovers.
    for file in [
        "client-device-key",
        "client-device.json",
        "client-device.lock",
        "client-device-key.corrupt",
    ] {
        for name in [
            file.to_string(),
            format!("{file}.bak-20261030-010203"),
            format!(".{file}.saiai-tmp-1-abc"),
        ] {
            assert!(home_file(&name), "{name}");
        }
        assert!(!home_file(&format!(".{file}.aitp-tmp-1-abc")));
        assert!(!home_file(&format!("{file}x")));
    }
    assert_eq!(home_dirs, &["log-followers", "desktop"]);
    for name in [
        "config.json.bak-20261030-010203",
        ".config.json.saiai-tmp-1-abc",
        "saiai-ca.key.bak-1",
    ] {
        assert!(home_file(name), "{name}");
    }
    assert!(!home_file(".config.json.aitp-tmp-1-abc"));
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
        assert!(program_file(name), "{name}");
    }
    for name in ["aitp", "aitp.exe", "saiai-other", "saiai.bak"] {
        assert!(!program_file(name), "{name}");
    }
    assert!(claude_ca_file("saiai-ca.crt"));
    assert!(claude_ca_file("saiai-ca.key.bak-1"));
    assert!(!claude_ca_file("aitp-ca.crt"));
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
        assert_eq!(
            service::owns_listener(saiai(), name).unwrap(),
            ours,
            "{name}"
        );
    }
}

#[test]
fn desktop_synthetic_identity_is_frozen() {
    // An identity persisted by an earlier client keeps loading from the same
    // place with the same field names.
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("desktop/claude/state");
    std::fs::create_dir_all(&state).unwrap();
    let identity = serde_json::json!({
        "account": "6f1c1f5e-8f1a-4d9e-9a51-0c2f5b7d1e01",
        "organization": "0b9d6a7c-2e4f-4c1b-8d3a-5f6e7a8b9c02",
        "access_token": "saiai-desktop-claude-0123456789abcdef0123456789abcdef",
        "refresh_token": "saiai-desktop-claude-refresh-0123456789abcdef",
        "session": "saiai-local-0123456789abcdef0123456789abcdef"
    });
    std::fs::write(state.join("identity.json"), identity.to_string()).unwrap();
    let loaded = claude_desktop::load_identity(saiai(), root.path())
        .unwrap()
        .expect("persisted identity is found");
    assert_eq!(serde_json::to_value(&loaded).unwrap(), identity);
}

/// Variables the binary hands to its own PowerShell helpers. Both ends are
/// templates of the same brand prefix: Rust passes `script_brand::env("X")`
/// and the script reads `$env:@@ENV@@X`, from the same production files as
/// before the names became templates; under SAIAI the names are unchanged.
#[test]
fn helper_environment_variables_are_written_and_read() {
    use source_scan::cli_sources;
    use std::collections::BTreeSet;
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
        assert_eq!(scripts::env(saiai(), suffix).unwrap(), *name);
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
        desktop::chat_relay_target(saiai(), "/backend-api/saiai/chat-updates?since=1")
            .unwrap()
            .unwrap(),
        "/chatgpt/backend-api/saiai/chat-updates?since=1"
    );
    assert!(
        desktop::is_forwarded_chat_path(saiai(), "/chatgpt/backend-api/saiai/chat-updates")
            .unwrap()
    );
    for rejected in [
        "/backend-api/saiai/chat-updates/admin",
        "/backend-api/aitp/chat-updates",
    ] {
        assert!(
            desktop::chat_relay_target(saiai(), rejected)
                .unwrap()
                .is_err(),
            "{rejected}"
        );
    }
    for unforwarded in [
        "/chatgpt/backend-api/saiai/chat-updates/admin",
        "/backend-api/saiai/chat-updates",
        "/chatgpt/backend-api/aitp/chat-updates",
    ] {
        assert!(
            !desktop::is_forwarded_chat_path(saiai(), unforwarded).unwrap(),
            "{unforwarded}"
        );
    }
}

/// Wire names inside helper scripts under SAIAI, written out by hand, in
/// the production templates the program renders.
#[test]
fn helper_script_names_are_frozen() {
    let render = |template: &str| scripts::render(saiai(), template).unwrap();
    assert_eq!(scripts::env(saiai(), "CA_FILES").unwrap(), "SAIAI_CA_FILES");
    assert_eq!(scripts::null_sentinel(saiai()).unwrap(), "__SAIAI_NULL__");
    assert_eq!(scripts::identifier_prefix(saiai()).unwrap(), "Saiai");
    #[cfg(windows)]
    assert_eq!(
        scripts::helper_failure_prefix(saiai()).unwrap(),
        "SAIAI_DESKTOP_HELPER_FAILURE:"
    );
    assert!(
        render(scripts::STALE_CA_LISTING)
            .contains("Where-Object { $_.Subject -match '(^|, )O=SAIAI(,|$)' }")
    );
    let activation = render(scripts::PACKAGE_ACTIVATION);
    assert!(activation.contains("public static class SaiaiPackageActivation {"));
    assert!(activation.contains(
        "[SaiaiPackageActivation]::Activate($env:SAIAI_DESKTOP_APP_ID,$env:SAIAI_DESKTOP_ACTIVATION_ARGS)"
    ));
    assert!(render(scripts::UNINSTALL_USER_PATH).contains("Add-Type -Namespace SaiaiUninstall"));
    assert!(render(scripts::WINDOWS_DESKTOP_INSPECT).contains("'SAIAI\\desktop-runtime'"));
}

/// Executes the observer's production expression for the runtime directory.
#[cfg(windows)]
#[test]
fn windows_desktop_runtime_directory_is_frozen() {
    // The observer is a brand template; run what the program runs.
    let observer = scripts::render(saiai(), scripts::WINDOWS_DESKTOP_INSPECT).unwrap();
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
