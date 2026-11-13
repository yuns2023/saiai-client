//! SAIAI golden outputs that the kernel renders, checked through its
//! `contract` entries from outside the library (feature `contract`; the
//! library is built without cfg(test)). Expected values are unchanged from
//! the in-library tests they replace.

use base64::Engine as _;
#[allow(unused_imports)]
use proxy_cli::contract::{certificates, config, scripts, service, update};
use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use sha2::{Digest, Sha256};
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

#[path = "../src/brand_saiai.rs"]
mod brand_saiai;

/// The SAIAI brand and runtime, installed as the program installs them.
fn saiai() -> &'static Brand {
    proxy_cli::contract::install(
        &brand_saiai::SAIAI_BRAND,
        proxy_cli::RuntimeContext {
            version: env!("CARGO_PKG_VERSION"),
            gateway: &proxy_cli::gateway_saiai::SAIAI_GATEWAY,
        },
    )
    .unwrap();
    &brand_saiai::SAIAI_BRAND
}

/// A config file as the program reads and rewrites it, as JSON.
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
