//! SAIAI distribution values for [`crate::brand::Brand`].
//!
//! These are the names every installed SAIAI client already uses; see
//! `brand_contract_tests` before changing any of them.

use crate::brand::{
    Brand, CertificateNames, ClientProofNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ServiceNames, UpdateNames,
};

pub(crate) const SAIAI_BRAND: Brand = Brand {
    binary_name: "saiai",
    home_dir_name: ".saiai",
    windows_app_dir_name: "SAIAI",
    config: ConfigNames {
        filename: "config.json",
        version: 2,
        temp_file_infix: "saiai-tmp",
    },
    env: EnvironmentNames {
        home: "SAIAI_HOME",
        install_dir: "SAIAI_INSTALL_DIR",
        skip_start: "SAIAI_SKIP_START",
        binary_updated: "SAIAI_BINARY_UPDATED",
        upstream_proxy: "SAIAI_UPSTREAM_PROXY",
        chatgpt_timezone: "SAIAI_CHATGPT_TIMEZONE",
        chatgpt_bin: "SAIAI_CHATGPT_BIN",
        desktop_bin: "SAIAI_DESKTOP_BIN",
        chatgpt_chat_passthrough: "SAIAI_CHATGPT_CHAT_PASSTHROUGH",
        desktop_browser_use: "SAIAI_DESKTOP_BROWSER_USE",
        openai_trace: "SAIAI_OPENAI_TRACE",
        openai_trace_path: "SAIAI_OPENAI_TRACE_PATH",
        proxy_verbose: "SAIAI_PROXY_VERBOSE",
        claude_desktop_allow_untested: "SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED",
    },
    certificates: CertificateNames {
        ca_cert_filename: "saiai-ca.crt",
        ca_key_filename: "saiai-ca.key",
        ca_common_name_prefix: "SAIAI local installation CA",
        ca_organization: "SAIAI",
        nss_nickname: "saiai-local-proxy",
        tls_leaf_salt: b"SAIAI local proxy TLS leaf v1",
        control_host: "certificate.saiai.local",
        spki_header: "x-saiai-leaf-spki-sha256",
    },
    service: ServiceNames {
        systemd_unit_prefix: "saiai",
        launchd_label: "top.saiai.local-proxy",
        pid_filename: "saiai.pid",
        lock_filename: "saiai.lock",
        log_filename: "saiai.log",
    },
    update: UpdateNames {
        channel_path: "saiai-cli",
        asset_prefix: "saiai-",
        candidate_prefix: ".saiai-update-",
        backup_prefix: "saiai.bak-",
        status_filename: ".saiai-update-status.txt",
    },
    markers: OwnershipMarkers {
        codex_ide_env_begin: "# BEGIN SAIAI CODEX IDE (managed)",
        codex_ide_env_end: "# END SAIAI CODEX IDE (managed)",
        vscode_proxy: "// SAIAI managed VSCode proxy: ",
    },
    placeholders: PlaceholderIdentities {
        codex_account_id: "saiai-local-proxy-account",
        // Structurally valid but unsigned and therefore unusable against
        // OpenAI; claims only let Codex expose an authenticated UI state.
        codex_token: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InNhaWFpLWxvY2FsLXByb3h5QGludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3VzZXJfaWQiOiJzYWlhaS1sb2NhbC1wcm94eS11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoic2FpYWktbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.c2FpYWktbG9jYWwtcHJveHk",
        legacy_codex_token_prefix: "saiai-local-proxy-placeholder-",
        desktop_token_prefix: "saiai-desktop-",
        claude_desktop_token_prefix: "saiai-desktop-claude-",
        claude_desktop_session_prefix: "saiai-local-",
        desktop_email: "saiai-local-proxy@example.invalid",
    },
    client_proof: ClientProofNames {
        header: "x-saiai-client-proof",
        message_domain: "saiai-client-proof-v1",
        enroll_path: "/api/v1/client/devices/enroll",
        key_filename: "client-device-key",
        lock_filename: "client-device.lock",
        device_filename: "client-device.json",
        corrupt_key_filename: "client-device-key.corrupt",
    },
    winhttp_agent: "SAIAI",
    codex_daemon_client_name: "saiai_daemon_check",
};
