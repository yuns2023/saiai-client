//! AITP distribution values for [`Brand`].
//!
//! Installed copies depend on every value here (directories, services,
//! certificates, markers, update coordinates); the tests below freeze them
//! by hand. Change one only with a migration for existing installations.

use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, FixedUpdateSource, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames, UpdateSource,
};

/// The single AITP brand instance.
pub static AITP_BRAND: Brand = Brand {
    binary_name: "aitp",
    product_name: "AITP",
    home_dir_name: ".aitp",
    windows_app_dir_name: "AITP",
    config: ConfigNames {
        filename: "config.json",
        version: 2,
        temp_file_infix: "aitp-tmp",
        type_name: "AitpConfig",
    },
    env: EnvironmentNames {
        home: "AITP_HOME",
        install_dir: "AITP_INSTALL_DIR",
        skip_start: "AITP_SKIP_START",
        binary_updated: "AITP_BINARY_UPDATED",
        upstream_proxy: "AITP_UPSTREAM_PROXY",
        chatgpt_timezone: "AITP_CHATGPT_TIMEZONE",
        chatgpt_bin: "AITP_CHATGPT_BIN",
        desktop_bin: "AITP_DESKTOP_BIN",
        chatgpt_chat_passthrough: "AITP_CHATGPT_CHAT_PASSTHROUGH",
        desktop_browser_use: "AITP_DESKTOP_BROWSER_USE",
        openai_trace: "AITP_OPENAI_TRACE",
        openai_trace_path: "AITP_OPENAI_TRACE_PATH",
        proxy_verbose: "AITP_PROXY_VERBOSE",
        claude_desktop_allow_untested: "AITP_CLAUDE_DESKTOP_ALLOW_UNTESTED",
    },
    certificates: CertificateNames {
        ca_cert_filename: "aitp-ca.crt",
        ca_key_filename: "aitp-ca.key",
        ca_backup_prefix: "aitp-ca.",
        ca_common_name_prefix: "AITP local installation CA",
        ca_organization: "AITP",
        nss_nickname: "aitp-local-proxy",
        tls_leaf_salt: b"AITP local proxy TLS leaf v1",
        control_host: "certificate.aitp.invalid",
        spki_header: "x-aitp-leaf-spki-sha256",
    },
    service: ServiceNames {
        systemd_unit_prefix: "aitp",
        launchd_label: "io.github.2742zdz.aitp.local-proxy",
        pid_filename: "aitp.pid",
        lock_filename: "aitp.lock",
        log_filename: "aitp.log",
    },
    update: UpdateNames {
        source: UpdateSource::Fixed(FixedUpdateSource {
            manifest_url: "https://github.com/2742zdz/AITP/releases/latest/download/aitp-manifest.json",
            asset_url_template: "https://github.com/2742zdz/AITP/releases/download/v{version}/{asset}",
            hosts: &[
                "github.com",
                "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            ],
            distribution: "aitp",
            // PLACEHOLDERS, not keys: their key bytes are no curve point, so
            // nothing verifies with them. The maintainer's real primary and
            // recovery public keys replace them before the first release;
            // `scripts/release_manifest.py` and `scripts/build-release.sh`
            // refuse a release while they are here.
            signing_keys: &[
                "RWQAITPxPRIMARYxPLACEHOLDERxKEYxNOTxFORxRELEASE222222222",
                "RWQAITPxRECOVERYxPLACEHOLDERxKEYxNOTxFORxRELEASEXXXXXXXX",
            ],
        }),
        asset_prefix: "aitp-",
        candidate_prefix: ".aitp-update-",
        backup_prefix: "aitp.bak-",
        status_filename: ".aitp-update-status.txt",
        windows_setup_command: None,
        release_page: Some("https://github.com/2742zdz/AITP/releases/latest"),
    },
    markers: OwnershipMarkers {
        codex_ide_env_begin: "# BEGIN AITP CODEX IDE (managed)",
        codex_ide_env_end: "# END AITP CODEX IDE (managed)",
        vscode_proxy: "// AITP managed VSCode proxy: ",
    },
    placeholders: PlaceholderIdentities {
        codex_account_id: "aitp-local-proxy-account",
        // Unsigned JWT: claims only, never usable against OpenAI.
        codex_token: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImFpdHAtbG9jYWwtcHJveHlAaW52YWxpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS9hdXRoIjp7ImNoYXRncHRfcGxhbl90eXBlIjoicGx1cyIsImNoYXRncHRfdXNlcl9pZCI6ImFpdHAtbG9jYWwtcHJveHktdXNlciIsImNoYXRncHRfYWNjb3VudF9pZCI6ImFpdHAtbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.YWl0cC1sb2NhbC1wcm94eQ",
        legacy_codex_token_prefix: "aitp-local-proxy-placeholder-",
        desktop_token_prefix: "aitp-desktop-",
        claude_desktop_token_prefix: "aitp-desktop-claude-",
        claude_desktop_session_prefix: "aitp-local-",
        desktop_email: "aitp-local-proxy@example.invalid",
        synthetic_id_prefix: "aitp-local",
    },
    sensitive_inbound_headers: &[],
    scripts: ScriptNames {
        env_prefix: "AITP_",
        identifier_prefix: "Aitp",
    },
    winhttp_agent: "AITP",
    codex_daemon_client_name: "aitp_daemon_check",
    refuse_foreign_profiles: true,
};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Every value, written out by hand.
    #[test]
    fn aitp_values_are_frozen() {
        let brand = &AITP_BRAND;
        assert_eq!(brand.binary_name, "aitp");
        assert_eq!(brand.product_name, "AITP");
        assert_eq!(brand.home_dir_name, ".aitp");
        assert_eq!(brand.windows_app_dir_name, "AITP");
        let config = &brand.config;
        assert_eq!(config.filename, "config.json");
        assert_eq!(config.version, 2);
        assert_eq!(config.temp_file_infix, "aitp-tmp");
        assert_eq!(config.type_name, "AitpConfig");
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
                "AITP_HOME",
                "AITP_INSTALL_DIR",
                "AITP_SKIP_START",
                "AITP_BINARY_UPDATED",
                "AITP_UPSTREAM_PROXY",
                "AITP_CHATGPT_TIMEZONE",
                "AITP_CHATGPT_BIN",
                "AITP_DESKTOP_BIN",
                "AITP_CHATGPT_CHAT_PASSTHROUGH",
                "AITP_DESKTOP_BROWSER_USE",
                "AITP_OPENAI_TRACE",
                "AITP_OPENAI_TRACE_PATH",
                "AITP_PROXY_VERBOSE",
                "AITP_CLAUDE_DESKTOP_ALLOW_UNTESTED",
            ]
        );
        let certificates = &brand.certificates;
        assert_eq!(certificates.ca_cert_filename, "aitp-ca.crt");
        assert_eq!(certificates.ca_key_filename, "aitp-ca.key");
        assert_eq!(certificates.ca_backup_prefix, "aitp-ca.");
        assert_eq!(
            certificates.ca_common_name_prefix,
            "AITP local installation CA"
        );
        assert_eq!(certificates.ca_organization, "AITP");
        assert_eq!(certificates.nss_nickname, "aitp-local-proxy");
        assert_eq!(certificates.tls_leaf_salt, b"AITP local proxy TLS leaf v1");
        assert_eq!(certificates.control_host, "certificate.aitp.invalid");
        assert_eq!(certificates.spki_header, "x-aitp-leaf-spki-sha256");
        let service = &brand.service;
        assert_eq!(service.systemd_unit_prefix, "aitp");
        assert_eq!(service.launchd_label, "io.github.2742zdz.aitp.local-proxy");
        assert_eq!(service.pid_filename, "aitp.pid");
        assert_eq!(service.lock_filename, "aitp.lock");
        assert_eq!(service.log_filename, "aitp.log");
        let update = &brand.update;
        let UpdateSource::Fixed(fixed) = &update.source else {
            panic!("AITP updates from fixed URLs");
        };
        assert_eq!(
            fixed.manifest_url,
            "https://github.com/2742zdz/AITP/releases/latest/download/aitp-manifest.json"
        );
        assert_eq!(
            fixed.asset_url_template,
            "https://github.com/2742zdz/AITP/releases/download/v{version}/{asset}"
        );
        assert_eq!(
            fixed.hosts,
            [
                "github.com",
                "release-assets.githubusercontent.com",
                "objects.githubusercontent.com",
            ]
        );
        assert_eq!(fixed.distribution, "aitp");
        assert_eq!(
            fixed.signing_keys,
            [
                "RWQAITPxPRIMARYxPLACEHOLDERxKEYxNOTxFORxRELEASE222222222",
                "RWQAITPxRECOVERYxPLACEHOLDERxKEYxNOTxFORxRELEASEXXXXXXXX",
            ]
        );
        assert_eq!(update.asset_prefix, "aitp-");
        assert_eq!(update.candidate_prefix, ".aitp-update-");
        assert_eq!(update.backup_prefix, "aitp.bak-");
        assert_eq!(update.status_filename, ".aitp-update-status.txt");
        assert_eq!(update.windows_setup_command, None);
        assert_eq!(
            update.release_page,
            Some("https://github.com/2742zdz/AITP/releases/latest")
        );
        let markers = &brand.markers;
        assert_eq!(
            markers.codex_ide_env_begin,
            "# BEGIN AITP CODEX IDE (managed)"
        );
        assert_eq!(markers.codex_ide_env_end, "# END AITP CODEX IDE (managed)");
        assert_eq!(markers.vscode_proxy, "// AITP managed VSCode proxy: ");
        let placeholders = &brand.placeholders;
        assert_eq!(placeholders.codex_account_id, "aitp-local-proxy-account");
        assert_eq!(
            placeholders.codex_token,
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImFpdHAtbG9jYWwtcHJveHlAaW52YWxpZCIsImV4cCI6NDEwMjQ0NDgwMCwiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS9hdXRoIjp7ImNoYXRncHRfcGxhbl90eXBlIjoicGx1cyIsImNoYXRncHRfdXNlcl9pZCI6ImFpdHAtbG9jYWwtcHJveHktdXNlciIsImNoYXRncHRfYWNjb3VudF9pZCI6ImFpdHAtbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.YWl0cC1sb2NhbC1wcm94eQ"
        );
        assert_eq!(
            placeholders.legacy_codex_token_prefix,
            "aitp-local-proxy-placeholder-"
        );
        assert_eq!(placeholders.desktop_token_prefix, "aitp-desktop-");
        assert_eq!(
            placeholders.claude_desktop_token_prefix,
            "aitp-desktop-claude-"
        );
        assert_eq!(placeholders.claude_desktop_session_prefix, "aitp-local-");
        assert_eq!(
            placeholders.desktop_email,
            "aitp-local-proxy@example.invalid"
        );
        assert_eq!(placeholders.synthetic_id_prefix, "aitp-local");
        assert!(brand.sensitive_inbound_headers.is_empty());
        assert_eq!(brand.scripts.env_prefix, "AITP_");
        assert_eq!(brand.scripts.identifier_prefix, "Aitp");
        assert_eq!(brand.winhttp_agent, "AITP");
        assert_eq!(brand.codex_daemon_client_name, "aitp_daemon_check");
        assert!(brand.refuse_foreign_profiles);
    }

    /// The placeholder JWT: an unsigned token whose claims name the AITP
    /// placeholder account, consistent with `codex_account_id`.
    #[test]
    fn the_placeholder_token_carries_the_aitp_claims() {
        let parts: Vec<_> = AITP_BRAND.placeholders.codex_token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let decode = |part: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .unwrap()
        };
        assert_eq!(decode(parts[0]), br#"{"alg":"none","typ":"JWT"}"#);
        let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({
                "email": "aitp-local-proxy@invalid",
                "exp": 4102444800_u64,
                "https://api.openai.com/auth": {
                    "chatgpt_plan_type": "plus",
                    "chatgpt_user_id": "aitp-local-proxy-user",
                    "chatgpt_account_id": AITP_BRAND.placeholders.codex_account_id,
                },
            })
        );
        assert_eq!(decode(parts[2]), b"aitp-local-proxy");
    }

    /// Installs as the program does (all brand checks, update source
    /// included), and the service names follow from it.
    #[cfg(feature = "contract")]
    #[test]
    fn the_brand_installs_and_names_its_services() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        use proxy_cli::contract::environment;
        use proxy_cli::contract::service;
        proxy_cli::contract::install(
            &AITP_BRAND,
            proxy_cli::RuntimeContext {
                version: "0.0.0-test",
                gateway: &proxy_cli::NoGatewayExtension,
            },
        )
        .unwrap();
        assert!(service::owns_listener(&AITP_BRAND, "aitp").unwrap());
        assert!(!service::owns_listener(&AITP_BRAND, "otherproxy").unwrap());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                environment::service_name(&AITP_BRAND).unwrap(),
                "aitp.service"
            );
            let unit = service::systemd_unit(
                &AITP_BRAND,
                std::path::Path::new("/home/u/.local/bin/aitp"),
                std::path::Path::new("/home/u/.aitp"),
                std::path::Path::new("/home/u"),
            )
            .unwrap();
            assert!(
                unit.contains("ExecStart=\"/home/u/.local/bin/aitp\""),
                "{unit}"
            );
            assert!(
                unit.contains("Environment=\"AITP_HOME=/home/u/.aitp\""),
                "{unit}"
            );
            assert!(unit.contains("AITP"), "{unit}");
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                environment::launchd_label(&AITP_BRAND).unwrap(),
                "io.github.2742zdz.aitp.local-proxy"
            );
            let plist = service::launchd_plist(
                &AITP_BRAND,
                std::path::Path::new("/Users/u/.local/bin/aitp"),
                std::path::Path::new("/Users/u/.aitp"),
                std::path::Path::new("/Users/u"),
                std::path::Path::new("/Users/u/.aitp/aitp.log"),
            )
            .unwrap();
            assert!(
                plist.contains("<string>io.github.2742zdz.aitp.local-proxy</string>"),
                "{plist}"
            );
            assert!(plist.contains("<key>AITP_HOME</key>"), "{plist}");
        }
        // The Windows replacement helper of a fixed-source brand takes the
        // installation's helper lock before anything else.
        #[cfg(windows)]
        {
            let directory = std::path::Path::new(r"C:\Users\u\AppData\Local\AITP\bin");
            let script = proxy_cli::contract::scripts::windows_update(
                &AITP_BRAND,
                1,
                &directory.join("aitp.exe"),
                &directory.join(".aitp-update-1.exe"),
                &directory.join(".aitp-update-1.ps1"),
                &directory.join(".aitp-update-status.txt"),
                true,
                &"0".repeat(64),
            )
            .unwrap();
            let lock = script
                .find(r"$helperLockPath = 'C:\Users\u\AppData\Local\AITP\bin\.aitp-update-helper-lock'")
                .unwrap_or_else(|| panic!("{script}"));
            // Before the command function and every `try` block.
            let function = script.find("function Invoke-AitpCommand").unwrap();
            let first_try = script.find("try {").unwrap();
            assert!(lock < function && lock < first_try, "{script}");
            assert!(script.contains("foreach ($attempt in 1..600)"), "{script}");
        }
    }
}
