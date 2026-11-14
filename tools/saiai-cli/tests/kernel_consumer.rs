//! A minimal outside user of the client library: its own distribution
//! (`ktest`, written out below and not derived from the SAIAI values) and no
//! Gateway extension, installed once in this test process before any entry
//! is called. Every expected value is a hand-written literal for this brand,
//! so the library is shown to take each name from the installed brand rather
//! than from SAIAI.

use proxy_cli::contract::desktop::{self, Request};
use proxy_cli::contract::{
    claude_desktop, codex, config, environment, scripts, service, uninstall, update, vscode,
};
use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, NoGatewayExtension, OwnershipMarkers,
    PlaceholderIdentities, RuntimeContext, ScriptNames, ServiceNames, UpdateNames, UpdateSource,
};
use std::path::Path;

/// The single KTEST instance; `KTEST_VALUES` builds look-alikes.
static KTEST: Brand = KTEST_VALUES;

const KTEST_VALUES: Brand = Brand {
    binary_name: "ktest",
    product_name: "KTEST",
    home_dir_name: ".ktest",
    windows_app_dir_name: "KTEST",
    config: ConfigNames {
        filename: "settings.json",
        version: 7,
        temp_file_infix: "ktest-tmp",
        type_name: "KtestConfig",
    },
    env: EnvironmentNames {
        home: "KTEST_HOME",
        install_dir: "KTEST_INSTALL_DIR",
        skip_start: "KTEST_SKIP_START",
        binary_updated: "KTEST_BINARY_UPDATED",
        upstream_proxy: "KTEST_UPSTREAM_PROXY",
        chatgpt_timezone: "KTEST_CHATGPT_TIMEZONE",
        chatgpt_bin: "KTEST_CHATGPT_BIN",
        desktop_bin: "KTEST_DESKTOP_BIN",
        chatgpt_chat_passthrough: "KTEST_CHATGPT_CHAT_PASSTHROUGH",
        desktop_browser_use: "KTEST_DESKTOP_BROWSER_USE",
        openai_trace: "KTEST_OPENAI_TRACE",
        openai_trace_path: "KTEST_OPENAI_TRACE_PATH",
        proxy_verbose: "KTEST_PROXY_VERBOSE",
        claude_desktop_allow_untested: "KTEST_CLAUDE_DESKTOP_ALLOW_UNTESTED",
    },
    certificates: CertificateNames {
        ca_cert_filename: "ktest-ca.crt",
        ca_key_filename: "ktest-ca.key",
        ca_backup_prefix: "ktest-ca.",
        ca_common_name_prefix: "KTEST local CA",
        ca_organization: "KTEST",
        nss_nickname: "ktest-local-proxy",
        tls_leaf_salt: b"KTEST leaf v1",
        control_host: "certificate.ktest.invalid",
        spki_header: "x-ktest-leaf-spki-sha256",
    },
    service: ServiceNames {
        systemd_unit_prefix: "ktest",
        launchd_label: "invalid.ktest.local-proxy",
        pid_filename: "ktest.pid",
        lock_filename: "ktest.lock",
        log_filename: "ktest.log",
    },
    update: UpdateNames {
        source: UpdateSource::GatewayChannel {
            channel_path: "ktest-channel",
        },
        asset_prefix: "ktest-",
        candidate_prefix: ".ktest-update-",
        backup_prefix: "ktest.bak-",
        status_filename: ".ktest-update-status.txt",
        windows_setup_command: Some("ktest-setup"),
        release_page: None,
    },
    markers: OwnershipMarkers {
        codex_ide_env_begin: "# BEGIN KTEST CODEX IDE",
        codex_ide_env_end: "# END KTEST CODEX IDE",
        vscode_proxy: "// KTEST managed VSCode proxy: ",
    },
    placeholders: PlaceholderIdentities {
        codex_account_id: "ktest-account",
        codex_token: "ktest.placeholder.token",
        legacy_codex_token_prefix: "ktest-legacy-",
        desktop_token_prefix: "ktest-desktop-",
        claude_desktop_token_prefix: "ktest-desktop-claude-",
        claude_desktop_session_prefix: "ktest-local-",
        desktop_email: "ktest@example.invalid",
        synthetic_id_prefix: "ktest-local",
    },
    sensitive_inbound_headers: &["x-ktest-proof"],
    scripts: ScriptNames {
        env_prefix: "KTEST_",
        identifier_prefix: "Ktest",
    },
    winhttp_agent: "KTEST",
    codex_daemon_client_name: "ktest_daemon_check",
};

static NONE: NoGatewayExtension = NoGatewayExtension;

/// Installs KTEST (repeatable: the same brand and context again is fine).
fn ktest() -> &'static Brand {
    proxy_cli::contract::install(
        &KTEST,
        RuntimeContext {
            version: "9.8.7",
            gateway: &NONE,
        },
    )
    .unwrap();
    &KTEST
}

/// Equal values, another instance: never the installed brand.
static OTHER: Brand = Brand {
    binary_name: "other",
    ..KTEST_VALUES
};

#[test]
fn entries_refuse_a_brand_that_is_not_installed() {
    ktest();
    let directory = tempfile::tempdir().unwrap();
    let path = Path::new("/p");
    assert!(environment::name(&OTHER, "codex", path).is_err());
    assert!(environment::service_suffix(&OTHER, path, path).is_err());
    assert!(environment::product_of(&OTHER, "codex-x").is_err());
    #[cfg(target_os = "linux")]
    assert!(environment::service_name(&OTHER).is_err());
    #[cfg(target_os = "macos")]
    assert!(environment::launchd_label(&OTHER).is_err());
    let auth = directory.path().join("auth.json");
    assert!(codex::placeholder_login(&OTHER, &auth).is_err());
    assert!(!auth.exists());
    assert!(codex::is_placeholder_access_token(&OTHER, "x").is_err());
    assert!(codex::ide_env(&OTHER, "", "127.0.0.1:1", "/c").is_err());
    assert!(vscode::merge_settings(&OTHER, "{}", "127.0.0.1:1").is_err());
    assert!(vscode::has_managed_proxy(&OTHER, "{}").is_err());
    assert!(uninstall::home_layout(&OTHER).is_err());
    assert!(uninstall::is_home_file(&OTHER, "x").is_err());
    assert!(uninstall::is_program_file(&OTHER, "x").is_err());
    assert!(uninstall::is_claude_ca_file(&OTHER, "x").is_err());
    assert!(service::owns_listener(&OTHER, "x").is_err());
    assert!(scripts::env(&OTHER, "X").is_err());
    assert!(scripts::null_sentinel(&OTHER).is_err());
    assert!(scripts::identifier_prefix(&OTHER).is_err());
    #[cfg(windows)]
    assert!(scripts::helper_failure_prefix(&OTHER).is_err());
    assert!(desktop::chat_relay_target(&OTHER, "/x").is_err());
    assert!(desktop::is_forwarded_chat_path(&OTHER, "/x").is_err());
    assert!(claude_desktop::load_identity(&OTHER, directory.path()).is_err());
}

#[test]
fn listener_and_helper_names_use_the_installed_brand() {
    assert!(service::owns_listener(ktest(), "my-ktest-worker").unwrap());
    assert!(service::owns_listener(ktest(), "KTEST.exe").unwrap());
    assert!(!service::owns_listener(ktest(), "saiai").unwrap());
    assert_eq!(scripts::env(ktest(), "CA_FILES").unwrap(), "KTEST_CA_FILES");
    assert_eq!(scripts::null_sentinel(ktest()).unwrap(), "__KTEST_NULL__");
    assert_eq!(scripts::identifier_prefix(ktest()).unwrap(), "Ktest");
    #[cfg(windows)]
    assert_eq!(
        scripts::helper_failure_prefix(ktest()).unwrap(),
        "KTEST_DESKTOP_HELPER_FAILURE:"
    );
    assert!(
        scripts::render(ktest(), scripts::UNINSTALL_USER_PATH)
            .unwrap()
            .contains("Add-Type -Namespace KtestUninstall")
    );
}

#[test]
fn without_a_chat_relay_nothing_is_relayed() {
    // NoGatewayExtension has no Chat relay.
    assert!(
        desktop::chat_relay_target(ktest(), "/backend-api/saiai/chat-updates")
            .unwrap()
            .is_err()
    );
    assert!(!desktop::is_forwarded_chat_path(ktest(), "/chatgpt/backend-api/models").unwrap());
}

#[test]
fn no_persisted_desktop_identity_loads_as_none() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        claude_desktop::load_identity(ktest(), root.path())
            .unwrap()
            .is_none()
    );
}

#[test]
fn desktop_refusal_names_the_installed_product() {
    let request = Request {
        method: "GET",
        target: "/automations",
        headers: &[],
        body: b"",
    };
    let answer = desktop::sidecar(ktest(), &request, true).unwrap().unwrap();
    assert_eq!(answer.status, 501);
    assert_eq!(
        std::str::from_utf8(&answer.body).unwrap(),
        r#"{"error":{"type":"desktop_control_unsupported","message":"This Desktop control endpoint is unavailable through KTEST."}}"#
    );
}

#[test]
fn config_errors_name_the_installed_type() {
    assert_eq!(
        config::decode(ktest(), "null").unwrap(),
        Err("invalid type: null, expected struct KtestConfig at line 1 column 4".to_string())
    );
}

#[test]
fn helper_scripts_render_with_the_installed_names() {
    assert_eq!(
        scripts::render(
            ktest(),
            "$env:@@ENV@@X; [@@ID@@Y]; @@APP_DIR@@; O=@@CA_ORG@@"
        )
        .unwrap(),
        "$env:KTEST_X; [KtestY]; KTEST; O=KTEST"
    );
}

#[test]
fn environment_and_service_names_use_the_installed_brand() {
    // The digest is of the directory only; the brand names the services.
    assert_eq!(
        environment::name(ktest(), "codex", Path::new("/work/project/codex")).unwrap(),
        "codex-2da86b69bd2e5ac6a16af476"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(environment::service_name(ktest()).unwrap(), "ktest.service");
    #[cfg(target_os = "macos")]
    assert_eq!(
        environment::launchd_label(ktest()).unwrap(),
        "invalid.ktest.local-proxy"
    );
}

#[test]
fn update_names_use_the_installed_channel_and_prefixes() {
    let names = update::names(ktest(), "https://gateway.invalid", "x", "1-2").unwrap();
    assert_eq!(
        names.manifest_url,
        "https://gateway.invalid/ktest-channel/manifest.json"
    );
    assert_eq!(names.asset_url, "https://gateway.invalid/ktest-channel/x");
    assert!(names.current_asset.starts_with("ktest-"), "{names:?}");
    let exe = if cfg!(windows) { ".exe" } else { "" };
    assert_eq!(names.candidate, format!(".ktest-update-1-2{exe}"));
    assert!(names.backup.starts_with("ktest.bak-"), "{names:?}");
}

#[test]
fn managed_markers_use_the_installed_brand() {
    let merged = vscode::merge_settings(ktest(), "{}\n", "127.0.0.1:1").unwrap();
    assert!(
        merged.contains("// KTEST managed VSCode proxy: http://127.0.0.1:1"),
        "{merged}"
    );
    assert!(vscode::has_managed_proxy(ktest(), &merged).unwrap());
    assert!(
        !vscode::has_managed_proxy(
            ktest(),
            "{\n// SAIAI managed VSCode proxy: http://127.0.0.1:1\n}\n"
        )
        .unwrap()
    );

    let env = codex::ide_env(ktest(), "", "127.0.0.1:1", "/k/ca.crt").unwrap();
    assert!(
        env.starts_with("# BEGIN KTEST CODEX IDE\nSSL_CERT_FILE=\"/k/ca.crt\"\n"),
        "{env}"
    );
    assert!(env.ends_with("\n# END KTEST CODEX IDE\n"), "{env}");
}

#[test]
fn codex_placeholder_login_uses_the_installed_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("auth.json");
    codex::placeholder_login(ktest(), &path).unwrap();
    let auth: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        auth["tokens"],
        serde_json::json!({
            "id_token": "ktest.placeholder.token",
            "access_token": "ktest.placeholder.token",
            "refresh_token": "",
            "account_id": "ktest-account"
        })
    );
    assert!(codex::is_placeholder_access_token(ktest(), "ktest-legacy-0").unwrap());
    assert!(
        !codex::is_placeholder_access_token(ktest(), "saiai-local-proxy-placeholder-0").unwrap()
    );
}

#[test]
fn uninstall_recognizes_the_installed_files_only() {
    let (files, _) = uninstall::home_layout(ktest()).unwrap();
    assert_eq!(
        files,
        [
            "settings.json",
            "ktest-ca.crt",
            "ktest-ca.key",
            "initialization.lock",
            "ktest.lock",
            "ktest.pid",
            "ktest.log",
            "windows-packaged-proxy-lease.json",
        ]
    );
    assert!(uninstall::is_home_file(ktest(), "ktest.log").unwrap());
    assert!(!uninstall::is_home_file(ktest(), "saiai.log").unwrap());
    assert!(uninstall::is_claude_ca_file(ktest(), "ktest-ca.crt").unwrap());
    assert!(!uninstall::is_claude_ca_file(ktest(), "saiai-ca.crt").unwrap());
}
