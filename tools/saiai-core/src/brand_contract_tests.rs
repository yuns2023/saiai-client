//! Frozen SAIAI contract of the V2 runtime core used by SAIAI Desktop.
//!
//! Expected values are hand-written literals (never derived from the
//! production constants or a future `Brand` value). Desktop installations
//! already own these directories, markers, provider names and certificate
//! identities, so a refactor must keep these tests passing unchanged.

use crate::{AppPaths, BootstrapCapabilities, ConfigV2, GatewayUrl, GenerationRef, Product};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn discover(variables: &[(&str, &str)]) -> AppPaths {
    let variables = variables
        .iter()
        .map(|(name, value)| (name.to_string(), OsString::from(value)))
        .collect::<Vec<_>>();
    AppPaths::discover_with(|name| {
        variables
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
    })
    .unwrap()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn dirs(paths: &AppPaths) -> [PathBuf; 3] {
    [
        paths.config_dir().to_path_buf(),
        paths.data_dir().to_path_buf(),
        paths.state_dir().to_path_buf(),
    ]
}

#[cfg(target_os = "linux")]
#[test]
fn linux_application_directories_are_frozen() {
    let paths = discover(&[("HOME", "/home/u")]);
    assert_eq!(
        dirs(&paths),
        [
            PathBuf::from("/home/u/.config/saiai"),
            PathBuf::from("/home/u/.local/share/saiai"),
            PathBuf::from("/home/u/.local/state/saiai"),
        ]
    );
    let paths = discover(&[
        ("HOME", "/home/u"),
        ("XDG_CONFIG_HOME", "/xdg/config"),
        ("XDG_DATA_HOME", "/xdg/data"),
        ("XDG_STATE_HOME", "/xdg/state"),
        // Legacy SAIAI CLI location never moves the V2 runtime.
        ("SAIAI_HOME", "/elsewhere"),
    ]);
    assert_eq!(
        dirs(&paths),
        [
            PathBuf::from("/xdg/config/saiai"),
            PathBuf::from("/xdg/data/saiai"),
            PathBuf::from("/xdg/state/saiai"),
        ]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_application_directories_are_frozen() {
    let paths = discover(&[("HOME", "/Users/u")]);
    assert_eq!(
        dirs(&paths),
        [
            PathBuf::from("/Users/u/Library/Application Support/SAIAI/config"),
            PathBuf::from("/Users/u/Library/Application Support/SAIAI/data"),
            PathBuf::from("/Users/u/Library/Application Support/SAIAI/state"),
        ]
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_application_directories_and_mutex_are_frozen() {
    let paths = discover(&[("LOCALAPPDATA", r"C:\Users\u\AppData\Local")]);
    assert_eq!(
        dirs(&paths),
        [
            PathBuf::from(r"C:\Users\u\AppData\Local\SAIAI\config"),
            PathBuf::from(r"C:\Users\u\AppData\Local\SAIAI\data"),
            PathBuf::from(r"C:\Users\u\AppData\Local\SAIAI\state"),
        ]
    );
    // FNV-1a 64 over the lowercased, backslash-separated directories, each
    // followed by 0xff (precomputed outside the production code).
    assert_eq!(
        crate::setup::transaction_mutex_name(&paths),
        OsString::from(r"Global\SAIAI-V2-Transaction-57b2683c07207112")
    );
}

#[test]
fn managed_client_home_marker_is_frozen() {
    let paths =
        AppPaths::from_app_dirs(absolute("config"), absolute("data"), absolute("state")).unwrap();
    let generation = GenerationRef::new("gen-1").unwrap();
    let marker = paths.generation_product_marker(&generation, Product::Codex);
    assert_eq!(
        marker.file_name().and_then(|name| name.to_str()),
        Some(".saiai-managed-v2")
    );
    assert_eq!(
        marker.parent().unwrap(),
        paths
            .data_dir()
            .join("generations")
            .join("gen-1")
            .join("clients")
            .join("codex")
    );
    assert_eq!(
        crate::setup::PRODUCT_MARKER,
        b"saiai-managed-client-home-v2\n"
    );
    assert_eq!(crate::setup::PRODUCT_MARKER_FILENAME, ".saiai-managed-v2");
    assert_eq!(
        crate::permissions::PRODUCT_MARKER_FILENAME,
        ".saiai-managed-v2"
    );
    assert_eq!(
        paths
            .config_file()
            .file_name()
            .and_then(|name| name.to_str()),
        Some("config.json")
    );
}

fn absolute(name: &str) -> std::path::PathBuf {
    if cfg!(windows) {
        std::path::PathBuf::from(r"C:\saiai-contract").join(name)
    } else {
        std::path::PathBuf::from("/saiai-contract").join(name)
    }
}

#[test]
fn config_and_bootstrap_schema_versions_are_frozen() {
    assert_eq!(crate::CONFIG_SCHEMA_VERSION, 2);
    assert_eq!(crate::BOOTSTRAP_SCHEMA_VERSION, 2);
    assert_eq!(crate::provision::BOOTSTRAP_PATH, "/api/v1/client/bootstrap");
    let config: ConfigV2 = serde_json::from_str(
        r#"{"schema_version":2,"base_url":"https://gateway.example/","products":{"codex":{"credential_ref":"codex-credential","active_generation":"gen-1"}}}"#,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&config).unwrap()["schema_version"],
        serde_json::json!(2)
    );
}

#[test]
fn codex_provider_config_renders_exactly() {
    let gateway = GatewayUrl::parse("https://gateway.example/").unwrap();
    let plain =
        crate::provision::build_codex_config(&gateway, &BootstrapCapabilities::default()).unwrap();
    assert_eq!(
        plain,
        r#"model_provider = "saiai"
disable_response_storage = true

[model_providers]

[model_providers.saiai]
name = "SAIAI"
base_url = "https://gateway.example"
wire_api = "responses"
requires_openai_auth = false
env_key = "SAIAI_CODEX_API_KEY"
"#
    );
    let websockets = crate::provision::build_codex_config(
        &gateway,
        &BootstrapCapabilities {
            codex_websockets: true,
            ..BootstrapCapabilities::default()
        },
    )
    .unwrap();
    assert!(
        websockets.contains("env_key = \"SAIAI_CODEX_API_KEY\"\nsupports_websockets = true\n"),
        "{websockets}"
    );
    assert!(
        websockets.contains("[features]\nresponses_websockets_v2 = true\n"),
        "{websockets}"
    );
}

#[test]
fn installation_ca_identity_is_frozen() {
    assert_eq!(crate::CLAUDE_CA_CERT_FILENAME, "saiai-ca.crt");
    assert_eq!(crate::CLAUDE_CA_KEY_FILENAME, "saiai-ca.key");
    let (cert_pem, _) = crate::provision::generate_installation_ca().unwrap();
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
    assert_eq!(common_names.len(), 1);
    let suffix = common_names[0]
        .strip_prefix("SAIAI local installation CA ")
        .unwrap_or_else(|| panic!("unexpected CA name {:?}", common_names[0]));
    assert_eq!(suffix.len(), 8, "{suffix}");
    assert!(
        suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{suffix}"
    );
    assert_eq!(organizations, vec!["SAIAI".to_string()]);
}
