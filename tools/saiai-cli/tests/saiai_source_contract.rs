//! SAIAI source contract tests that need no access to the client library's
//! internals: source pins and inventories read from the production files,
//! the SAIAI name residue and frozen text, scans of the boundary between
//! the kernel and the SAIAI side, and the SAIAI brand's values through its
//! public fields. They belong to the SAIAI program, not to the kernel.

use proxy_cli::{
    Brand, CertificateNames, ConfigNames, EnvironmentNames, OwnershipMarkers,
    PlaceholderIdentities, ScriptNames, ServiceNames, UpdateNames, UpdateSource,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[path = "../src/brand_saiai.rs"]
mod brand_saiai;
#[allow(dead_code)]
#[path = "support/source_scan.rs"]
mod source_scan;

use brand_saiai::SAIAI_BRAND;
use source_scan::*;

const PLACEHOLDER_JWT: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJlbWFpbCI6InNhaWFpLWxvY2FsLXByb3h5QGludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDAsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBsdXMiLCJjaGF0Z3B0X3VzZXJfaWQiOiJzYWlhaS1sb2NhbC1wcm94eS11c2VyIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoic2FpYWktbG9jYWwtcHJveHktYWNjb3VudCJ9fQ.c2FpYWktbG9jYWwtcHJveHk";

/// The SAIAI values of every brand field, written out by hand. A refactor
/// may move or rename the fields, never change these values.
#[test]
fn saiai_brand_values_are_frozen() {
    let brand = &SAIAI_BRAND;
    assert_eq!(brand.binary_name, "saiai");
    assert_eq!(brand.product_name, "SAIAI");
    assert_eq!(brand.home_dir_name, ".saiai");
    assert_eq!(brand.windows_app_dir_name, "SAIAI");
    assert_eq!(brand.config.filename, "config.json");
    assert_eq!(brand.config.version, 2);
    assert_eq!(brand.config.temp_file_infix, "saiai-tmp");
    assert_eq!(brand.config.type_name, "SaiaiConfig");
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
    assert!(matches!(
        update.source,
        UpdateSource::GatewayChannel {
            channel_path: "saiai-cli"
        }
    ));
    assert_eq!(update.asset_prefix, "saiai-");
    assert_eq!(update.candidate_prefix, ".saiai-update-");
    assert_eq!(update.backup_prefix, "saiai.bak-");
    assert_eq!(update.status_filename, ".saiai-update-status.txt");
    assert_eq!(
        update.windows_setup_command,
        Some("irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai")
    );
    assert_eq!(update.release_page, None);
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
    // The client proof protocol's files and header, as the SAIAI extension
    // declares them (its constants are pinned with the extension).
    {
        let family = |name| proxy_cli::StateFile {
            name,
            backups: true,
            atomic_temporaries: true,
        };
        assert_eq!(
            proxy_cli::GatewayExtension::owned_state_files(&saiai::gateway_saiai::SAIAI_GATEWAY),
            [
                family("client-device-key"),
                family("client-device.json"),
                family("client-device.lock"),
                family("client-device-key.corrupt"),
            ]
        );
        assert_eq!(
            proxy_cli::GatewayExtension::signature_headers(&saiai::gateway_saiai::SAIAI_GATEWAY),
            ["x-saiai-client-proof"]
        );
    }
    assert_eq!(certificates.ca_backup_prefix, "saiai-ca.");
    // SAIAI turns the Native Chat relay on with exactly its brand names and
    // the historical placeholder device proof it never forwards.
    assert_eq!(
        proxy_cli::GatewayExtension::native_chat(&saiai::gateway_saiai::SAIAI_GATEWAY),
        Some(proxy_cli::NativeChatProtocol {
            updates_path: "/backend-api/saiai/chat-updates",
            preference_restored_header: "x-saiai-chat-preference-restored",
            rejected_device_proofs: &["saiai-local-proxy"],
        })
    );
    assert_eq!(
        proxy_cli::GatewayExtension::native_chat(&proxy_cli::NoGatewayExtension),
        None
    );
    assert_eq!(brand.winhttp_agent, "SAIAI");
    assert_eq!(brand.codex_daemon_client_name, "saiai_daemon_check");
    assert!(!brand.refuse_foreign_profiles);
    assert_eq!(brand.scripts.env_prefix, "SAIAI_");
    assert_eq!(brand.scripts.identifier_prefix, "Saiai");
    assert_eq!(brand.sensitive_inbound_headers, ["x-saiai-client-proof"]);
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

/// Contract literals that are only reachable through inline code today,
/// pinned to the production file that uses them. Each entry must stay until
/// a refactor replaces it with a behavioral test of the same value.
#[test]
fn inline_contract_literals_are_present() {
    let sources = cli_sources();
    for (file, needle) in [
        // Self-update channel below the configured Gateway base URL, and the
        // version prefix an update candidate must print.
        (
            "lib.rs",
            "UpdateSource::GatewayChannel { channel_path } => {\n            let cfg = read_app_config()?;\n            let asset = current_platform_asset_name()?;\n            let (manifest_url, url) = gateway_update_urls(channel_path, &cfg.base_url, &asset);",
        ),
        ("lib.rs", "\"{base}/{channel}/manifest.json\""),
        ("lib.rs", "\"{base}/{channel}/{asset}\""),
        (
            "lib.rs",
            "!candidate_version\n        .trim_start()\n        .strip_prefix(BRAND.binary_name)\n        .is_some_and(|rest| rest.starts_with(' '))",
        ),
        // The Windows uninstall retry hint names the brand's setup command.
        (
            "uninstall.rs",
            "match BRAND.update.windows_setup_command {\n            Some(setup) => format!(",
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
            "preference_restored_header: CHAT_PREFERENCE_RESTORED_HEADER,",
        ),
        ("gateway_saiai.rs", "updates_path: CHAT_UPDATES_PATH,"),
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
            ".env(BRAND.env.home, app_config_dir()?)",
        ),
        (
            "lib.rs",
            "start_linux_background_proxy",
            ".env(BRAND.env.home, &app_home)",
        ),
        (
            "lib.rs",
            "start_windows_background_proxy",
            ".env(BRAND.env.home, &app_home)",
        ),
        (
            "lib.rs",
            "app_config_dir",
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
            "env::var_os(CHATGPT_TIMEZONE_ENV.get())",
        ),
        (
            "lib.rs",
            "run_windows_packaged_desktop",
            "env::var_os(CHATGPT_TIMEZONE_ENV.get()).is_some()",
        ),
        (
            "lib.rs",
            "run_linux_desktop",
            "command.env_remove(CHATGPT_TIMEZONE_ENV.get());",
        ),
        (
            "lib.rs",
            "run_macos_desktop",
            "command.env_remove(CHATGPT_TIMEZONE_ENV.get());",
        ),
        (
            "lib.rs",
            "run_windows_desktop",
            "command.env_remove(CHATGPT_TIMEZONE_ENV.get());",
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
            "const CHATGPT_TIMEZONE_ENV: BrandValue<&'static str> =\n    BrandValue(|brand| brand.env.chatgpt_timezone);",
        ),
        // Raised only for a non-UTF-8 environment value; frozen by source.
        (
            "lib.rs",
            ".with_context(|| format!(\"{CHATGPT_TIMEZONE_ENV} must be valid UTF-8\"))?",
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

/// The library never reports its own package metadata as the program's: a
/// distribution binary (the SAIAI `main.rs`, the kernel's AITP entry
/// `bin/aitp/main.rs`) supplies the release facts through `RuntimeContext`.
#[test]
fn library_takes_release_facts_from_the_entry_point() {
    let sources = cli_sources();
    for (file, text) in &sources {
        // `env!`/`option_env!` with an ordinary string literal naming any
        // `CARGO_*` variable, with or without whitespace or line breaks.
        // Raw strings (`env!(r"CARGO_…")`) and `concat!`-built names are
        // not detected.
        let compact = text.split_whitespace().collect::<String>();
        if !matches!(file.as_str(), "main.rs" | "bin/aitp/main.rs") {
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

/// Blocks naming the SAIAI brand directly from kernel sources: only the
/// SAIAI program's own sources spell these names. A textual check; the
/// package boundary itself is enforced by the compiler.
#[test]
fn only_the_program_names_the_saiai_brand() {
    let sources = cli_sources();
    let kernel = kernel_files();
    for (file, text) in &sources {
        if !kernel.contains(file) {
            continue;
        }
        for name in ["brand_saiai", "SAIAI_BRAND"] {
            assert!(!text.contains(name), "{file} names {name}");
        }
    }
    assert!(sources["main.rs"].contains("use saiai::{brand_saiai, gateway_saiai};"));
    assert!(sources["distribution.rs"].contains("pub mod brand_saiai;"));
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
        "client_proof::HEADER_NAME",
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
        sources["main.rs"].contains("gateway: &gateway_saiai::SAIAI_GATEWAY,"),
        "the saiai program must inject the SAIAI Gateway extension"
    );
    let kernel = kernel_files();
    for (file, text) in &sources {
        if !kernel.contains(file) {
            continue;
        }
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(name) = protocol_reference(trimmed) {
                panic!("{file} uses {name}: {trimmed}");
            }
        }
    }
}

/// Every file below `kernel/`, recursively, and every symbolic link found
/// there (not followed). A local build directory `kernel/target` is skipped.
fn kernel_tree() -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    fn walk(
        dir: &Path,
        top: bool,
        files: &mut Vec<std::path::PathBuf>,
        links: &mut Vec<std::path::PathBuf>,
    ) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_symlink() {
                links.push(path);
            } else if kind.is_dir() {
                if !(top && path.file_name().is_some_and(|name| name == "target")) {
                    walk(&path, false, files, links);
                }
            } else {
                files.push(path);
            }
        }
    }
    let (mut files, mut links) = (Vec::new(), Vec::new());
    let kernel = Path::new(env!("CARGO_MANIFEST_DIR")).join("kernel");
    walk(&kernel, true, &mut files, &mut links);
    files.sort();
    (files, links)
}

/// Registered exceptions to the kernel's SAIAI-free rule:
/// `(path below kernel/, whitespace-collapsed line)`, each with its reason.
/// Empty: the kernel is distribution-neutral.
const KERNEL_SAIAI_EXCEPTIONS: &[(&str, &str)] = &[];

/// No file below `kernel/` (code, tests, comments, scripts, manifest) spells
/// `saiai` in any case: the directory can stand alone as a public
/// repository, and every SAIAI value reaches the kernel through the brand
/// and Gateway extension the program passes in.
///
/// Hidden files are scanned like any other: they ship with the directory.
/// If `kernel/` later becomes a git submodule, skip only its git metadata
/// (the `.git` file or directory), never hidden files in general.
#[test]
fn the_kernel_directory_never_names_saiai() {
    let kernel = Path::new(env!("CARGO_MANIFEST_DIR")).join("kernel");
    let (files, _) = kernel_tree();
    assert!(files.iter().any(|file| file.ends_with("Cargo.toml")));
    assert!(files.iter().any(|file| file.ends_with("lib.rs")));
    let mut found = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(&kernel)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(file).unwrap();
        if relative.to_ascii_lowercase().contains("saiai") {
            found.push(format!("{relative}\t(file name)"));
        }
        for line in String::from_utf8_lossy(&bytes).lines() {
            if !line.to_ascii_lowercase().contains("saiai") {
                continue;
            }
            let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
            if !KERNEL_SAIAI_EXCEPTIONS.contains(&(relative.as_str(), line.as_str())) {
                found.push(format!("{relative}\t{line}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "kernel/ names SAIAI (read the value from Brand, use the test brand in tests):\n{}",
        found.join("\n")
    );
}

/// `"name.ext"`: a plain string literal naming a sibling file (letters,
/// digits, `_`, `-`, `.`, not only dots).
fn sibling_name(token: &proc_macro2::TokenTree) -> Option<String> {
    let proc_macro2::TokenTree::Literal(literal) = token else {
        return None;
    };
    let text = literal.to_string();
    let name = text.strip_prefix('"')?.strip_suffix('"')?;
    let plain = !name.is_empty()
        && !name.chars().all(|ch| ch == '.')
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'));
    plain.then(|| name.to_string())
}

/// An identifier's name without a raw `r#` prefix.
fn ident_name(ident: &proc_macro2::Ident) -> String {
    let text = ident.to_string();
    text.strip_prefix("r#").unwrap_or(&text).to_string()
}

fn is_ident(token: Option<&proc_macro2::TokenTree>, name: &str) -> bool {
    matches!(token, Some(proc_macro2::TokenTree::Ident(ident)) if ident_name(ident) == name)
}

fn is_punct(token: Option<&proc_macro2::TokenTree>, ch: char) -> bool {
    matches!(token, Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == ch)
}

fn is_group(token: Option<&proc_macro2::TokenTree>, delimiter: proc_macro2::Delimiter) -> bool {
    matches!(token, Some(proc_macro2::TokenTree::Group(group)) if group.delimiter() == delimiter)
}

/// Whether the item starting at `tokens[at]` (outer attributes skipped) is
/// an inline `mod name { ... }`.
fn is_inline_module(tokens: &[proc_macro2::TokenTree], mut at: usize) -> bool {
    use proc_macro2::Delimiter::{Brace, Bracket, Parenthesis};
    while is_punct(tokens.get(at), '#') && is_group(tokens.get(at + 1), Bracket) {
        at += 2;
    }
    if is_ident(tokens.get(at), "pub") {
        at += 1;
        if is_group(tokens.get(at), Parenthesis) {
            at += 1;
        }
    }
    is_ident(tokens.get(at), "mod") && is_group(tokens.get(at + 2), Brace)
}

/// `path = ...` values inside one attribute body (any depth, so
/// `cfg_attr(..., path = ...)` counts). `inline` is whether the attribute
/// annotates an inline module.
fn attribute_paths(
    body: proc_macro2::TokenStream,
    inline: bool,
    found: &mut Vec<Result<String, String>>,
) {
    let tokens: Vec<_> = body.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        if let proc_macro2::TokenTree::Group(group) = token {
            attribute_paths(group.stream(), inline, found);
        }
        if is_ident(Some(token), "path") && is_punct(tokens.get(index + 1), '=') {
            let value = tokens.get(index + 2);
            let name = value
                .and_then(sibling_name)
                .filter(|name| name.ends_with(".rs") && !inline);
            found.push(name.ok_or_else(|| {
                format!(
                    "path = {}{}",
                    value.map(ToString::to_string).unwrap_or_default(),
                    if inline { " on an inline module" } else { "" }
                )
            }));
        }
    }
}

/// Whether `stream` contains a `$` (a `macro_rules!` metavariable).
fn has_metavariable(stream: proc_macro2::TokenStream) -> bool {
    stream.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Punct(punct) => punct.as_char() == '$',
        proc_macro2::TokenTree::Group(group) => has_metavariable(group.stream()),
        _ => false,
    })
}

/// The kernel's own `macro_rules!` macros, name and exact rules. A macro can
/// take apart the tokens it is given and rebuild them (keep a checked
/// `include_str!` name, swap its argument), which no token scan can follow;
/// a new macro is reviewed and registered here instead.
const KERNEL_MACROS: &[(&str, &str)] = &[(
    "eprintln",
    "{ ($($arg:tt)*) => { ::std::eprintln!(\"[{}] {}\", chrono::Utc::now().to_rfc3339(), format_args!($($arg)*)); }; }",
)];

fn token_references(tokens: &[proc_macro2::TokenTree], found: &mut Vec<Result<String, String>>) {
    use proc_macro2::Delimiter::Bracket;
    for (index, token) in tokens.iter().enumerate() {
        match token {
            proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '#' => {
                let mut at = index + 1;
                if is_punct(tokens.get(at), '!') {
                    at += 1;
                }
                // A `#` that does not start a complete attribute (`# $tokens`,
                // a `#` passed to a macro) or an attribute a macro assembles
                // (`#[$attr]`) could carry a `path` this scan cannot see.
                if !is_group(tokens.get(at), Bracket) {
                    found.push(Err("# without an attribute body".to_string()));
                } else if let Some(proc_macro2::TokenTree::Group(group)) = tokens.get(at)
                    && group.delimiter() == Bracket
                {
                    if has_metavariable(group.stream()) {
                        found.push(Err(format!("#{group} (macro-generated attribute)")));
                    }
                    let inline = is_inline_module(tokens, at + 1);
                    attribute_paths(group.stream(), inline, found);
                }
            }
            proc_macro2::TokenTree::Ident(ident)
                if ident_name(ident) == "macro_rules" && is_punct(tokens.get(index + 1), '!') =>
            {
                let registered = match (tokens.get(index + 2), tokens.get(index + 3)) {
                    (
                        Some(proc_macro2::TokenTree::Ident(name)),
                        Some(proc_macro2::TokenTree::Group(rules)),
                    ) => KERNEL_MACROS.iter().any(|(known, text)| {
                        ident_name(name) == *known
                            && text
                                .parse::<proc_macro2::TokenStream>()
                                .unwrap()
                                .to_string()
                                == proc_macro2::TokenStream::from(proc_macro2::TokenTree::Group(
                                    rules.clone(),
                                ))
                                .to_string()
                    }),
                    _ => false,
                };
                if !registered {
                    found.push(Err(format!(
                        "macro_rules! {} (not registered in KERNEL_MACROS)",
                        tokens
                            .get(index + 2)
                            .map(ToString::to_string)
                            .unwrap_or_default()
                    )));
                }
            }
            // These names may appear only as a direct call (never passed to
            // another macro, aliased or imported, which this scan cannot follow).
            proc_macro2::TokenTree::Ident(ident)
                if ["include", "include_str", "include_bytes"]
                    .contains(&ident_name(ident).as_str()) =>
            {
                let call = is_punct(tokens.get(index + 1), '!');
                let argument = match tokens.get(index + 2) {
                    Some(proc_macro2::TokenTree::Group(group))
                        if call && ident_name(ident) != "include" =>
                    {
                        let inner: Vec<_> = group.stream().into_iter().collect();
                        match inner.as_slice() {
                            [only] => sibling_name(only),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                found.push(argument.ok_or_else(|| {
                    format!(
                        "{ident}!{}",
                        tokens
                            .get(index + 2)
                            .map(ToString::to_string)
                            .unwrap_or_default()
                    )
                }));
            }
            _ => {}
        }
        if let proc_macro2::TokenTree::Group(group) = token {
            // A bracket that is not an attribute body may still become one:
            // a macro can keep a `#` and swap the bracket after it. So its
            // `path = ...` follows the attribute rule, and a macro-built
            // bracket (`[$tokens]`) is refused.
            let before = |back: usize| index.checked_sub(back).and_then(|i| tokens.get(i));
            let attribute_body =
                is_punct(before(1), '#') || (is_punct(before(1), '!') && is_punct(before(2), '#'));
            if group.delimiter() == Bracket && !attribute_body {
                if has_metavariable(group.stream()) {
                    found.push(Err(format!("{group} (macro-generated bracket)")));
                }
                let mut paths = Vec::new();
                attribute_paths(group.stream(), false, &mut paths);
                found.extend(paths);
            }
            // Every group, attribute bodies included: function bodies, macro
            // arguments (`format!(.., include_str!(..))`), `#[doc = include_str!(..)]`.
            token_references(&group.stream().into_iter().collect::<Vec<_>>(), found);
        }
    }
}

/// File references in Rust source `text`, read from its tokens (comments
/// and the contents of string literals are not code): every `include!`,
/// `include_str!` and `include_bytes!` call and every `path = ...` inside an
/// attribute (`#[path]`, `#[cfg_attr(..., path = ...)]`). `Ok(name)` is a
/// sibling file name (a `.rs` file for `path`); `Err(form)` is anything else
/// (another directory, escapes, raw strings, computed paths, `include!`, or
/// a `path` on an inline module), which the kernel does not use. Source that
/// does not lex is one `Err`.
fn file_references(text: &str) -> Vec<Result<String, String>> {
    let mut found = Vec::new();
    match text.parse::<proc_macro2::TokenStream>() {
        Ok(stream) => token_references(&stream.into_iter().collect::<Vec<_>>(), &mut found),
        Err(error) => found.push(Err(format!("does not lex: {error}"))),
    }
    found
}

/// Kernel sources reference only sibling files inside `kernel/` (plain
/// file-name literals, no directories, escapes or computed paths), and
/// `kernel/` holds no symbolic links, so the directory builds and tests on
/// its own.
#[test]
fn kernel_sources_reference_no_file_outside_the_kernel() {
    let (files, links) = kernel_tree();
    assert!(links.is_empty(), "symbolic links in kernel/: {links:?}");
    let mut checked = 0;
    for file in files {
        if file.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let text = fs::read_to_string(&file).unwrap();
        for reference in file_references(&text) {
            checked += 1;
            match reference {
                Ok(name) if file.parent().unwrap().join(&name).is_file() => {}
                Ok(name) => panic!("{} references missing file {name:?}", file.display()),
                Err(form) => panic!(
                    "{} uses a file reference the kernel does not allow (only sibling file-name literals): {form}",
                    file.display()
                ),
            }
        }
    }
    // The kernel embeds its helper scripts with include_str! and its split
    // modules with #[path].
    assert!(checked > 0);
}

#[test]
fn kernel_file_reference_scanner_sees_every_form() {
    let allowed = r##"
#[path = "y.rs"]
mod y;
#[cfg(test)]
#[path="z_tests.rs"] pub(crate) mod z;
const A: &str = include_str!("a.ps1");
const B: &[u8] = include_bytes! ( "b.js" );
fn f() { let _ = format!("{}", include_str!("c.txt")); }
my_include_str!("ignored");
fn g() { let path = "../ignored"; }
// include_str!("../comment") and #[path = "../comment.rs"]
/* #[path = "../block.rs"] */
const EXAMPLE: &str = r#"#[path = "../../example.rs"]"#;
#[doc = "the path = value"]
mod documented;
"##;
    assert_eq!(
        file_references(allowed),
        vec![
            Ok("y.rs".to_string()),
            Ok("z_tests.rs".to_string()),
            Ok("a.ps1".to_string()),
            Ok("b.js".to_string()),
            Ok("c.txt".to_string()),
        ]
    );
    for refused in [
        "#[path = \"../../src/x.rs\"]\nmod x;",
        "#[ path = \"../../outside.rs\"]\nmod x;",
        "#[path/**/= \"../../outside.rs\"]\nmod x;",
        "#[cfg_attr(unix, path = \"../outside.rs\")]\nmod x;",
        "#[cfg_attr(test, doc = r#\"\" ]\"#, path = \"../../outside.rs\")]\nmod x;",
        "#[path = \"fragment.inc\"]\nmod fragment;",
        "#[path = \"x.rs\"]\nmod x { }",
        "#[path = \"x.rs\"]\n#[doc = \"]\"]\nmod x {}",
        "#[path = \"x.rs\"]\npub (crate) mod x {}",
        "#[path = \"..\"]\nmod inner {\n}",
        "const X: &str = include_str ! (\"../../outside.txt\");",
        "const X: &str = include_str/**/!(\"../../outside.txt\");",
        "const X: &str = include_str!(\"..\\x2f..\\x2foutside.txt\");",
        "const X: &str = include_str!(r\"outside.txt\");",
        "const X: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/c\"));",
        "include!(\"fragment.rs\");",
        "const X: &str = include_str!(\"sub/x.txt\");",
        "const X: &str = include_str!(\"..\");",
        "fn f() { g(include_str!(\"../x\")); }",
        "#[doc = include_str!(\"../../outside.md\")]\npub struct Example;",
        "#[cfg_attr(doc, doc = include_str!(\"../outside.md\"))]\npub struct Example;",
        "const X: &str = r#include_str!(\"../../outside.txt\");",
        "#[r#path = \"../outside.rs\"]\nmod x;",
        "macro_rules! load { ($r:ident, $f:literal) => { $r!($f) }; }\nconst X: &str = load!(include_str, \"../../outside.txt\");",
        "use std::include_str as read;\nconst X: &str = read!(\"../x\");",
        "macro_rules! m { ($a:meta) => { #[$a] mod outside; }; }\nm!(path = \"../../outside.rs\");",
        "macro_rules! m { ($($a:tt)*) => { # $($a)* mod outside; }; }\nm!([path = \"../../outside.rs\"]);",
        "macro_rules! m { ($p:literal) => { #[path = $p] mod outside; }; }\nm!(\"../../outside.rs\");",
        "macro_rules! m { ($($t:tt)*) => { $($t)* }; }\nm!(#[path = \"../outside.rs\"] mod outside;);",
        "const X: &[u8] = ::core::include_bytes!(\"../x\");",
        "macro_rules! m { ($h:tt) => { $h [path = \"../../outside.rs\"] mod outside; }; }\nm!(#);",
        "macro_rules! m { ($h:tt $d:tt) => { $h [path = \"../../outside.rs\"] mod outside; }; }\nm!(#[doc = \"placeholder\"]);",
        "macro_rules! m { ($h:tt $d:tt $p:ident) => { $h [$p = \"../../outside.rs\"] mod outside; }; }\nm!(#[doc = \"x\"] path);",
        "macro_rules! m { ($h:tt $d:tt $b:tt) => { $h $b mod outside; }; }\nm!(#[doc = \"x\"] [path = \"../../outside.rs\"]);",
        "macro_rules! load { ($r:ident ! $d:tt) => { $r!(\"../../outside.txt\") }; }\nconst T: &str = load!(include_str!(\"lib.rs\"));",
        "macro_rules! eprintln { ($($arg:tt)*) => { include_str!($($arg)*) }; }",
        "const X: &str = \"unterminated;",
    ] {
        let references = file_references(refused);
        assert!(
            references.iter().any(Result::is_err),
            "{refused}: {references:?}"
        );
    }
}

#[test]
fn production_text_drops_test_items_and_keeps_production_code() {
    let source = r##"fn kept_before() {}
#[test]
fn standalone() { let _ = "SAIAI fixture { }"; }
#[tokio::test]
#[ignore]
async fn standalone_async() { if true { } }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flavored_async() { let _ = ("SAIAI flavored", [1]); }
const MARKER_IN_TEXT: &str = "#[test] fn not_an_item() {}";
#[test_case(1)]
fn parameterized_kept(value: u8) {}
#[cfg(test)]
mod tests { fn inner() {} }
#[cfg(all(test, feature = "contract"))]
mod contract_tests { fn with_entries() {} }
#[cfg(feature = "contract")]
fn feature_kept() {}
fn kept_after() {}
"##;
    let kept = remove_rust_test_items(source);
    for gone in [
        "standalone",
        "SAIAI fixture",
        "standalone_async",
        "flavored_async",
        "SAIAI flavored",
        "mod tests",
        "contract_tests",
    ] {
        assert!(!kept.contains(gone), "{gone} survived:\n{kept}");
    }
    for present in [
        "fn kept_before() {}",
        r##"const MARKER_IN_TEXT: &str = "#[test] fn not_an_item() {}";"##,
        "#[test_case(1)]\nfn parameterized_kept(value: u8) {}",
        "#[cfg(feature = \"contract\")]\nfn feature_kept() {}",
        "fn kept_after() {}",
    ] {
        assert!(kept.contains(present), "{present} lost:\n{kept}");
    }
}

// ------------------------------------------------------- brand-neutral text

/// Brand placeholders in production format strings, the SAIAI text each one
/// stands for, and the named argument that must bind it in the same call.
const BRAND_TEXT_TOKENS: [(&str, &str, &str); 6] = [
    (
        "{brand_product}",
        "SAIAI",
        "brand_product = BRAND.product_name",
    ),
    (
        "{brand_binary}",
        "saiai",
        "brand_binary = BRAND.binary_name",
    ),
    (
        "{brand_skip_start_env}",
        "SAIAI_SKIP_START",
        "brand_skip_start_env = BRAND.env.skip_start",
    ),
    (
        "{brand_desktop_bin_env}",
        "SAIAI_DESKTOP_BIN",
        "brand_desktop_bin_env = BRAND.env.desktop_bin",
    ),
    (
        "{brand_windows_setup}",
        "irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai",
        // Bound to the brand's setup command in `execute_user_path`
        // (pinned in `inline_contract_literals_are_present`).
        "brand_windows_setup = setup",
    ),
    (
        "{brand_allow_untested_env}",
        "SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED",
        "brand_allow_untested_env = BRAND.env.claude_desktop_allow_untested",
    ),
];

/// Every production string literal that renders SAIAI text, as
/// `["file", "literal source"]` JSON lines, frozen before the text moved to
/// `Brand`. This is a source contract: a literal whose brand placeholders are
/// put back to the SAIAI values must reproduce one of these exactly, and each
/// placeholder must be bound to its field in its own call. It does not by
/// itself prove the bytes the program prints at run time (format context,
/// argument values); that equivalence rests on the behavior tests and golden
/// outputs elsewhere.
const BRAND_TEXT_GOLDEN: &str = include_str!("data/brand_text_golden.txt");

/// Text that scripts, tests or tools outside this crate parse; each must stay
/// in the frozen set (the consumer is named for the reviewer).
const BRAND_TEXT_CONTRACTS: [(&str, &str, &str); 11] = [
    (
        "lib.rs",
        "\"SAIAI LaunchAgent started.\"",
        "scripts/saiai-cli/test-macos-service.py",
    ),
    (
        "lib.rs",
        "\"SAIAI background proxy started or refreshed.\"",
        "scripts/saiai-cli/test-linux-service.py",
    ),
    (
        "lib.rs",
        "\"SAIAI background proxy stopped.\"",
        "scripts/saiai-cli/test-linux-service.py",
    ),
    (
        "lib.rs",
        "\"SAIAI configured Codex for local-proxy OAuth mode.\"",
        "scripts/saiai-cli/verify-release.py",
    ),
    (
        "lib.rs",
        "\"SAIAI local proxy start skipped (SAIAI_SKIP_START=1).\"",
        "tools/saiai-cli/tests/saiai_brand_contract.rs",
    ),
    (
        "lib.rs",
        "\"Starting ChatGPT Desktop through the SAIAI local proxy.\"",
        "scripts/saiai-cli/test-macos-service.py",
    ),
    (
        "lib.rs",
        "\"Starting OpenAI Desktop through the SAIAI local proxy.\"",
        "scripts/saiai-cli/test-windows-runtime.ps1",
    ),
    (
        "uninstall.rs",
        "\"SAIAI home: {}\"",
        "scripts/saiai-cli/test-setup-wrappers.sh",
    ),
    (
        "uninstall.rs",
        "\"SAIAI uninstall plan\"",
        "scripts/saiai-cli/setup.sh, setup.ps1",
    ),
    (
        "lib.rs",
        "\"SAIAI Desktop scope: Codex only; the official ChatGPT sidebar, ordinary Chat history, and settings are not supported.\"",
        "scripts/saiai-cli/test-macos-service.py",
    ),
    (
        "lib.rs",
        "\"Trusted the SAIAI CA in the current user's NSS database for direct Linux Desktop (no system trust store or dialog).\"",
        "scripts/saiai-cli/test-initialization-scope.py (must not appear)",
    ),
];

/// Top-level arguments of a call between `from` and `end` (the text after
/// its format literal), each with whitespace collapsed. Not a Rust parser:
/// commas inside generics or closure parameters also split; that is enough
/// to find a standalone `name = BRAND.field` argument, the only use.
fn call_arguments(
    text: &str,
    literals: &[std::ops::Range<usize>],
    from: usize,
    end: usize,
) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut depth = 0_usize;
    let mut index = from;
    while index < end {
        if let Some(range) = literals.iter().find(|range| range.start == index) {
            current.push_str(&text[range.clone()]);
            index = range.end;
            continue;
        }
        let ch = text[index..].chars().next().unwrap();
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                arguments.push(std::mem::take(&mut current));
                index += 1;
                continue;
            }
            _ => {}
        }
        current.push(ch);
        index += ch.len_utf8();
    }
    arguments.push(current);
    arguments
        .iter()
        .map(|argument| argument.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|argument| !argument.is_empty())
        .collect()
}

/// End of the call whose arguments start at `from`: the `)` that closes it.
fn enclosing_call_end(text: &str, literals: &[std::ops::Range<usize>], from: usize) -> usize {
    let mut depth = 0_usize;
    let mut index = from;
    while index < text.len() {
        if let Some(range) = literals.iter().find(|range| range.start == index) {
            index = range.end;
            continue;
        }
        match text.as_bytes()[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return index,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    text.len()
}

/// Production literals that render SAIAI text, with brand placeholders put
/// back to the SAIAI values (source literals, not run-time output); panics
/// if a placeholder is not bound to its `Brand` field in the same call.
fn rendered_brand_text() -> Vec<(String, String)> {
    let mut rendered = Vec::new();
    let kernel = kernel_files();
    for (file, text) in cli_sources() {
        if !kernel.contains(&file) || !file.ends_with(".rs") {
            continue;
        }
        let literals = rust_literal_ranges(&text);
        for range in &literals {
            let literal = &text[range.clone()];
            let mut restored = literal.to_string();
            let mut bound = None;
            for (token, saiai, binding) in BRAND_TEXT_TOKENS {
                if !literal.contains(token) {
                    continue;
                }
                // A top-level argument exactly `name = BRAND.field`: the
                // value printed is the field itself, nothing derived from it.
                let arguments = bound.get_or_insert_with(|| {
                    let end = enclosing_call_end(&text, &literals, range.end);
                    call_arguments(&text, &literals, range.end, end)
                });
                assert!(
                    arguments.iter().any(|argument| argument == binding),
                    "{file}: {token} in {literal} is not bound by exactly `{binding}`"
                );
                restored = restored.replace(token, saiai);
            }
            if restored.to_ascii_lowercase().contains("saiai") {
                rendered.push((file.clone(), restored));
            }
        }
    }
    rendered.sort();
    rendered
}

#[test]
fn brand_text_renders_the_frozen_saiai_bytes() {
    // The placeholders stand for these SAIAI values only if the brand has them.
    let brand = &SAIAI_BRAND;
    for (token, saiai, _) in BRAND_TEXT_TOKENS {
        let value = match token {
            "{brand_product}" => brand.product_name,
            "{brand_binary}" => brand.binary_name,
            "{brand_skip_start_env}" => brand.env.skip_start,
            "{brand_desktop_bin_env}" => brand.env.desktop_bin,
            "{brand_windows_setup}" => brand.update.windows_setup_command.unwrap(),
            "{brand_allow_untested_env}" => brand.env.claude_desktop_allow_untested,
            other => panic!("unknown brand placeholder {other}"),
        };
        assert_eq!(value, saiai, "{token}");
    }
    let mut golden: Vec<(String, String)> = BRAND_TEXT_GOLDEN
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    golden.sort();
    let rendered = rendered_brand_text();
    if rendered != golden {
        let lines: Vec<String> = rendered
            .iter()
            .map(|entry| serde_json::to_string(entry).unwrap())
            .collect();
        panic!(
            "SAIAI text differs from brand_text_golden.txt; rendered now:\n{}",
            lines.join("\n")
        );
    }
    for (file, literal, consumer) in BRAND_TEXT_CONTRACTS {
        assert!(
            golden.contains(&(file.to_string(), literal.to_string())),
            "{file}: {literal} (parsed by {consumer}) is not frozen"
        );
    }
}

#[test]
fn call_arguments_finds_standalone_named_arguments() {
    let text = r#"format!(
        "{brand_product} at {}, {x}",
        f(a, "b, c"),
        brand_product = BRAND.product_name.to_ascii_lowercase(),
        x = [1, 2].len()
    ) + g(brand_binary = BRAND.binary_name)"#;
    let literals = rust_literal_ranges(text);
    let format_literal = literals[0].clone();
    let end = enclosing_call_end(text, &literals, format_literal.end);
    assert_eq!(
        call_arguments(text, &literals, format_literal.end, end),
        [
            r#"f(a, "b, c")"#,
            "brand_product = BRAND.product_name.to_ascii_lowercase()",
            "x = [1, 2].len()",
        ]
    );
}

/// Kernel modules the SAIAI side names through a module path, in `text`
/// (comments and string contents ignored, spacing around `::` allowed):
/// `crate::m`, `super::m`, `$crate::m`, and `m` at the start of an item in a
/// `use crate::{…}` / `use super::{…}` group, for each private module `m`.
fn kernel_module_paths(text: &str, private: &[String]) -> Vec<String> {
    // Blank literals, drop comments, then remove spacing around `::`.
    let mut code = strip_rust_comments(text);
    for range in rust_literal_ranges(&code).into_iter().rev() {
        code.replace_range(range, "\"\"");
    }
    let mut compact = String::new();
    for part in code.split("::") {
        if !compact.is_empty() {
            compact = compact.trim_end().to_string() + "::";
        }
        compact.push_str(if compact.is_empty() {
            part
        } else {
            part.trim_start()
        });
    }
    let ident = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    let mut found = Vec::new();
    for root in ["crate::", "super::"] {
        for (index, _) in compact.match_indices(root) {
            let rest = &compact[index + root.len()..];
            let mut heads = Vec::new();
            if let Some(group) = rest.strip_prefix('{') {
                // Only items directly below the root; a nested item belongs
                // to its parent, which is checked here.
                let mut depth = 0;
                let mut start = true;
                for (offset, ch) in group.char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' if depth == 0 => break,
                        '}' => depth -= 1,
                        ',' if depth == 0 => start = true,
                        ch if start && depth == 0 && ident(ch) => {
                            heads.push(&group[offset..]);
                            start = false;
                        }
                        ch if !ch.is_whitespace() => start = false,
                        _ => {}
                    }
                }
            } else {
                heads.push(rest);
            }
            for head in heads {
                let name: String = head.chars().take_while(|ch| ident(*ch)).collect();
                if private.contains(&name) {
                    found.push(format!("{root}{name}"));
                }
                // An alias of the root would hide later module paths.
                let next: String = head[name.len()..]
                    .trim_start()
                    .chars()
                    .take_while(|ch| ident(*ch))
                    .collect();
                if name == "self" && next == "as" {
                    found.push(format!("{root}{{self as …}}"));
                }
            }
        }
    }
    // Identifier and punctuation tokens, whatever the spacing.
    let mut words = Vec::new();
    let mut rest = compact.as_str();
    while let Some(ch) = rest.chars().next() {
        let length = if ident(ch) {
            rest.find(|ch: char| !ident(ch)).unwrap_or(rest.len())
        } else {
            ch.len_utf8()
        };
        if !ch.is_whitespace() {
            words.push(&rest[..length]);
        }
        rest = &rest[length..];
    }
    for window in words.windows(3) {
        if matches!(window, ["use" | "crate", "crate" | "super" | "self", "as"]) {
            found.push(format!("{} {} as", window[0], window[1]));
        }
    }
    found
}

#[test]
fn kernel_module_path_scanner_sees_aliases_groups_and_spacing() {
    let private = vec!["gateway".to_string(), "brand".to_string()];
    for text in [
        "use crate::gateway as g;",
        "use crate::gateway;",
        "let x = crate :: gateway :: wire_target(url);",
        "use crate::{gateway::GatewayHttp};",
        "use crate::{ Brand, gateway::{GatewayHttp, StateFile} };",
        "use crate::{\n    GatewayHttp,\n    brand,\n};",
        "$crate::gateway::X",
        "use super::brand::BRAND;",
        "use crate as c;\nc::gateway::X",
        "use crate::{self as c};\nc::gateway::X",
        "use super as parent;",
        "extern crate self as root;",
        "use crate::{self as\n    c};\nc::gateway::X",
        "fn f() {};use crate as c;",
        "use\tcrate\tas\tc;",
    ] {
        assert!(!kernel_module_paths(text, &private).is_empty(), "{text}");
    }
    for text in [
        "use crate::{GatewayHttp, StateFile, write_file_atomically};",
        "crate::GatewayHttp::client_for(&**self, url)",
        "use crate::client_proof::{self, ClientProof};",
        "let text = \"crate::gateway::X\"; // crate::gateway::Y",
        "use super::*;",
        "fn gateway() {}",
        "use crate::{client_proof::{brand}};",
        "use crate::client_proof::{self, ClientProof};",
    ] {
        assert_eq!(
            kernel_module_paths(text, &private),
            Vec::<String>::new(),
            "{text}"
        );
    }
}

/// The SAIAI side reaches the kernel only through the crate root's public
/// items (`crate::X`), never a private kernel module (any spelling), so it
/// can move out of the library unchanged. Tests in these files included.
#[test]
fn saiai_side_uses_only_the_public_kernel_root() {
    // The SAIAI modules and SAIAI-side tests that move with them.
    const SAIAI_SIDE: [&str; 5] = [
        "client_proof",
        "client_proof_saiai_tests",
        "gateway_saiai",
        "brand_saiai",
        "contract_desktop_tests",
    ];
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = package.join("src");
    let lib = fs::read_to_string(package.join("kernel/src/lib.rs")).unwrap();
    // Every module lib.rs declares, minus the public ones and the SAIAI side.
    let private: Vec<String> = lib
        .lines()
        .filter_map(|line| line.trim().strip_prefix("mod "))
        .filter_map(|rest| rest.strip_suffix(';'))
        .map(str::to_string)
        .filter(|name| !SAIAI_SIDE.contains(&name.as_str()))
        .collect();
    assert!(private.contains(&"gateway".to_string()), "{private:?}");
    assert!(private.contains(&"local_proxy".to_string()), "{private:?}");
    for module in SAIAI_SIDE {
        let file = format!("{module}.rs");
        let text = fs::read_to_string(root.join(&file)).unwrap();
        let paths = kernel_module_paths(&text, &private);
        assert!(
            paths.is_empty(),
            "{file} reaches into kernel modules: {paths:?}"
        );
    }
}

/// Library constants that carry a brand value read exactly that brand
/// field, on every platform (the SAIAI values of the fields are frozen in
/// `saiai_brand_values_are_frozen`, and the behavior behind several of them
/// by black-box tests that run on one platform only). Includes the client
/// side of the certificate control request, which only the Linux black box
/// reaches.
#[test]
fn brand_value_constants_read_their_brand_field() {
    let sources = cli_sources();
    let bindings: &[(&str, &str, &str, &str)] = &[
        (
            "lib.rs",
            "CONFIG_FILENAME",
            "&'static str",
            "config.filename",
        ),
        ("lib.rs", "CONFIG_VERSION", "u32", "config.version"),
        (
            "lib.rs",
            "CA_FILENAME",
            "&'static str",
            "certificates.ca_cert_filename",
        ),
        (
            "lib.rs",
            "CA_KEY_FILENAME",
            "&'static str",
            "certificates.ca_key_filename",
        ),
        (
            "lib.rs",
            "LOCAL_PROXY_NSS_CERT_NICKNAME",
            "&'static str",
            "certificates.nss_nickname",
        ),
        (
            "lib.rs",
            "CODEX_CERTIFICATE_CONTROL_HOST",
            "&'static str",
            "certificates.control_host",
        ),
        (
            "lib.rs",
            "CODEX_CERTIFICATE_SPKI_HEADER",
            "&'static str",
            "certificates.spki_header",
        ),
        (
            "lib.rs",
            "LINUX_PID_FILENAME",
            "&'static str",
            "service.pid_filename",
        ),
        (
            "lib.rs",
            "LINUX_LOCK_FILENAME",
            "&'static str",
            "service.lock_filename",
        ),
        (
            "lib.rs",
            "WINDOWS_PID_FILENAME",
            "&'static str",
            "service.pid_filename",
        ),
        (
            "lib.rs",
            "SERVICE_LOG_FILENAME",
            "&'static str",
            "service.log_filename",
        ),
        (
            "local_proxy.rs",
            "CERTIFICATE_CONTROL_HOST",
            "&'static str",
            "certificates.control_host",
        ),
        (
            "local_proxy.rs",
            "CERTIFICATE_SPKI_HEADER",
            "&'static str",
            "certificates.spki_header",
        ),
        (
            "claude_desktop.rs",
            "TOKEN_PREFIX",
            "&'static str",
            "placeholders.claude_desktop_token_prefix",
        ),
    ];
    // A textual check of each definition (string contents blanked, so a
    // literal cannot stand in for code); it does not expand macros or
    // resolve names.
    for (file, name, value_type, field) in bindings {
        let mut code = production_text(&sources[*file], "rs");
        for range in rust_literal_ranges(&code).into_iter().rev() {
            code.replace_range(range, "\"\"");
        }
        // Whitespace removed; `crate::brand::` paths and visibility dropped.
        let code = code
            .split_whitespace()
            .collect::<String>()
            .replace("crate::brand::", "")
            .replace("pub(crate)const", "const");
        let compact_type = value_type.split_whitespace().collect::<String>();
        let expected =
            format!("const{name}:BrandValue<{compact_type}>=BrandValue(|brand|brand.{field});");
        assert_eq!(
            code.matches(&format!("const{name}:")).count(),
            1,
            "{file} defines {name} once"
        );
        assert!(
            code.contains(&expected),
            "{file}: {name} must read brand.{field}"
        );
    }
}
