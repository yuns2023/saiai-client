//! The kernel's own test brand: the fallback brand of unit tests, so the
//! kernel is tested without any distribution's names.
//!
//! Its values follow the shape of a real distribution's names (a binary
//! name, an upper-case environment prefix, a dot directory, ...) so path,
//! environment and marker logic run on realistic input; tests spell out the
//! expected values literally.

use crate::brand::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames, UpdateSource,
};

/// The single test brand instance (a `static`, so repeated installation is
/// recognized as the same brand).
pub static KTEST_BRAND: Brand = KTEST_VALUES;

pub const KTEST_VALUES: Brand = Brand {
    binary_name: "ktest",
    product_name: "KTEST",
    home_dir_name: ".ktest",
    windows_app_dir_name: "KTEST",
    config: ConfigNames {
        filename: "config.json",
        version: 2,
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
        ca_common_name_prefix: "KTEST local installation CA",
        ca_organization: "KTEST",
        nss_nickname: "ktest-local-proxy",
        tls_leaf_salt: b"KTEST local proxy TLS leaf v1",
        control_host: "certificate.ktest.local",
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
            channel_path: "ktest-cli",
        },
        asset_prefix: "ktest-",
        candidate_prefix: ".ktest-update-",
        backup_prefix: "ktest.bak-",
        status_filename: ".ktest-update-status.txt",
        windows_setup_command: Some(
            "irm https://ktest.invalid/ktest-cli/setup.ps1 | iex; Invoke-Ktest",
        ),
        release_page: None,
    },
    markers: OwnershipMarkers {
        codex_ide_env_begin: "# BEGIN KTEST CODEX IDE (managed)",
        codex_ide_env_end: "# END KTEST CODEX IDE (managed)",
        vscode_proxy: "// KTEST managed VSCode proxy: ",
    },
    placeholders: PlaceholderIdentities {
        codex_account_id: "ktest-local-proxy-account",
        // Unsigned JWT: claims only, never usable against OpenAI.
        codex_token: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6Imt0ZXN0LWxvY2FsLXByb3h5QGludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3VzZXJfaWQiOiJrdGVzdC1sb2NhbC1wcm94eS11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoia3Rlc3QtbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.a3Rlc3QtbG9jYWwtcHJveHk",
        legacy_codex_token_prefix: "ktest-local-proxy-placeholder-",
        desktop_token_prefix: "ktest-desktop-",
        claude_desktop_token_prefix: "ktest-desktop-claude-",
        claude_desktop_session_prefix: "ktest-local-",
        desktop_email: "ktest-local-proxy@example.invalid",
        synthetic_id_prefix: "ktest-local",
    },
    sensitive_inbound_headers: &["x-ktest-client-proof"],
    scripts: ScriptNames {
        env_prefix: "KTEST_",
        identifier_prefix: "Ktest",
    },
    winhttp_agent: "KTEST",
    codex_daemon_client_name: "ktest_daemon_check",
    refuse_foreign_profiles: true,
};
