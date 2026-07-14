#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const CLAUDE_KEY: &str = "sk-v2-claude-integration-secret";
const CODEX_KEY: &str = "sk-v2-codex-integration-secret";
const MISMATCH_KEY: &str = "sk-v2-gateway-mismatch-must-not-print";
const PROBE_SECRET: &str = "sk-v2-version-probe-must-not-print";
const MOCK_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const MOCK_IO_TIMEOUT: Duration = Duration::from_secs(2);
const MOCK_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

#[test]
fn v2_setup_launch_doctor_and_revoke_are_isolated_end_to_end() {
    let fixture = Fixture::new();
    let (gateway, server) = bootstrap_server(vec![
        BootstrapExpectation::claude(CLAUDE_KEY),
        BootstrapExpectation::codex(CODEX_KEY),
        BootstrapExpectation::codex(CODEX_KEY),
    ]);

    let setup = fixture.run_with_stdin(
        &["setup", "claude", "--base-url", &gateway, "--api-key-stdin"],
        CLAUDE_KEY,
    );
    assert_success(&setup);
    assert_output_has_no_secret(&setup);
    let setup_text = String::from_utf8_lossy(&setup.stdout);
    assert!(setup_text.contains("Claude V2 setup is ready"));
    assert!(setup_text.contains("Detected claude: claude 1.2.3 integration-test"));

    let config_path = fixture.config_root.join("saiai/config.json");
    let config_text = fs::read_to_string(&config_path).unwrap();
    assert!(!config_text.contains(CLAUDE_KEY));
    assert!(!config_text.contains(CODEX_KEY));
    let config: Value = serde_json::from_str(&config_text).unwrap();
    let normalized_gateway = format!("{gateway}/");
    assert_eq!(config["schema_version"], 2);
    assert_eq!(
        config["base_url"].as_str(),
        Some(normalized_gateway.as_str())
    );
    assert!(config["products"].get("codex").is_none());
    let claude_generation = config["products"]["claude"]["active_generation"]
        .as_str()
        .unwrap()
        .to_string();
    let claude_home = fixture
        .data_root
        .join("saiai/generations")
        .join(&claude_generation)
        .join("clients/claude");
    assert!(claude_home.join("saiai-ca.crt").is_file());
    assert!(claude_home.join("saiai-ca.key").is_file());
    assert!(
        !fs::read_to_string(claude_home.join("settings.json"))
            .unwrap()
            .contains(CLAUDE_KEY)
    );
    let claude_settings: Value =
        serde_json::from_slice(&fs::read(claude_home.join("settings.json")).unwrap()).unwrap();
    assert_eq!(
        claude_settings["env"]["CLAUDE_STREAM_IDLE_TIMEOUT_MS"],
        "600000"
    );

    let doctor_after_claude = fixture.run(&["doctor"]);
    assert_success(&doctor_after_claude);
    assert_output_has_no_secret(&doctor_after_claude);
    let doctor_text = String::from_utf8_lossy(&doctor_after_claude.stdout);
    assert!(doctor_text.contains("Codex: unconfigured"));
    assert!(!doctor_text.contains("[ok] codex:"));
    assert!(doctor_text.contains("0 error(s)"));

    let codex_before_setup = fixture.run(&["codex", "--", "must-not-launch"]);
    assert!(!codex_before_setup.status.success());
    assert_output_has_no_secret(&codex_before_setup);
    assert!(String::from_utf8_lossy(&codex_before_setup.stderr).contains("saiai setup codex"));

    let claude = fixture.run(&["claude", "--", "--print", "hello"]);
    assert_success(&claude);
    assert_output_has_no_secret(&claude);
    assert_eq!(
        fs::read_to_string(fixture.output.join("claude-home")).unwrap(),
        format!("{}\n", claude_home.display())
    );
    assert_eq!(
        fs::read_to_string(fixture.output.join("claude-args")).unwrap(),
        "--print\nhello\n"
    );
    let proxy = fs::read_to_string(fixture.output.join("claude-proxy"))
        .unwrap()
        .trim()
        .strip_prefix("http://")
        .unwrap()
        .to_string();
    assert!(
        TcpStream::connect(proxy).is_err(),
        "session proxy stayed alive"
    );

    let codex_setup = fixture.run_with_stdin(&["setup", "codex", "--api-key-stdin"], CODEX_KEY);
    assert_success(&codex_setup);
    assert_output_has_no_secret(&codex_setup);
    let codex_setup_text = String::from_utf8_lossy(&codex_setup.stdout);
    assert!(codex_setup_text.contains("Codex V2 setup is ready"));
    assert!(codex_setup_text.contains("Detected codex: codex-cli 1.2.3 integration-test"));

    let config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(
        config["base_url"].as_str(),
        Some(normalized_gateway.as_str())
    );
    assert_eq!(
        config["products"]["claude"]["active_generation"].as_str(),
        Some(claude_generation.as_str())
    );
    let codex_generation = config["products"]["codex"]["active_generation"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(codex_generation, claude_generation);
    let codex_home = fixture
        .data_root
        .join("saiai/generations")
        .join(&codex_generation)
        .join("clients/codex");
    assert!(codex_home.join("config.toml").is_file());
    assert!(
        !fs::read_to_string(codex_home.join("config.toml"))
            .unwrap()
            .contains(CODEX_KEY)
    );
    let codex = fixture.run(&["codex", "--", "alpha", "two words"]);
    assert_success(&codex);
    assert_output_has_no_secret(&codex);
    assert_eq!(
        fs::read_to_string(fixture.output.join("codex-home")).unwrap(),
        format!("{}\n", codex_home.display())
    );
    assert_eq!(
        fs::read_to_string(fixture.output.join("codex-args")).unwrap(),
        "alpha\ntwo words\n"
    );

    let doctor = fixture.run(&["doctor"]);
    assert_success(&doctor);
    assert_output_has_no_secret(&doctor);
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("0 error(s)"));

    let codex_config_path = codex_home.join("config.toml");
    let valid_codex_config = fs::read(&codex_config_path).unwrap();
    let corrupt_secret = "sk-never-print-from-corrupt-toml";
    fs::write(
        &codex_config_path,
        format!("invalid = [\"{corrupt_secret}\"\n"),
    )
    .unwrap();
    let corrupt_doctor = fixture.run(&["doctor"]);
    assert!(!corrupt_doctor.status.success());
    let corrupt_output = format!(
        "{}{}",
        String::from_utf8_lossy(&corrupt_doctor.stdout),
        String::from_utf8_lossy(&corrupt_doctor.stderr)
    );
    assert!(!corrupt_output.contains(corrupt_secret));
    fs::write(&codex_config_path, valid_codex_config).unwrap();

    let codex_revoke = fixture.run(&["codex", "revoke"]);
    assert_success(&codex_revoke);
    assert!(!codex_home.exists());
    assert!(claude_home.exists());
    let claude_after_codex_revoke = fixture.run(&["claude", "--", "--print", "still-ready"]);
    assert_success(&claude_after_codex_revoke);
    assert_output_has_no_secret(&claude_after_codex_revoke);
    fixture.assert_legacy_untouched();

    let second_setup = fixture.run_with_stdin(&["setup", "codex", "--api-key-stdin"], CODEX_KEY);
    assert_success(&second_setup);
    assert_output_has_no_secret(&second_setup);
    join_before(server, MOCK_JOIN_TIMEOUT).unwrap();
    let claude_revoke = fixture.run(&["claude", "revoke"]);
    assert_success(&claude_revoke);
    let codex_after_claude_revoke = fixture.run(&["codex", "--", "still-ready"]);
    assert_success(&codex_after_claude_revoke);
    assert_output_has_no_secret(&codex_after_claude_revoke);

    let revoke_all = fixture.run(&["revoke", "--all"]);
    assert_success(&revoke_all);
    assert!(!fixture.config_root.join("saiai").exists());
    assert!(!fixture.data_root.join("saiai").exists());
    assert!(!fixture.state_root.join("saiai").exists());
    fixture.assert_legacy_untouched();
}

#[test]
fn full_revoke_recovers_obsolete_and_corrupt_v2_state_without_migration() {
    let fixture = Fixture::new();
    let app_config = fixture.config_root.join("saiai");
    let app_data = fixture.data_root.join("saiai");
    let app_state = fixture.state_root.join("saiai");
    for path in [&app_config, &app_data, &app_state] {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("sentinel"), "owned-v2-state").unwrap();
    }
    fs::write(
        app_config.join("config.json"),
        r#"{"schema_version":1,"base_url":"https://obsolete.invalid/","credential_ref":"must-not-migrate","active_generation":"old"}"#,
    )
    .unwrap();

    let setup = fixture.run_with_stdin(
        &[
            "setup",
            "claude",
            "--base-url",
            "http://127.0.0.1:9",
            "--api-key-stdin",
        ],
        CLAUDE_KEY,
    );
    assert!(!setup.status.success());
    assert_output_has_no_secret(&setup);
    assert!(String::from_utf8_lossy(&setup.stderr).contains("saiai revoke --all"));
    assert!(app_config.exists());

    let revoke_old = fixture.run(&["revoke", "--all"]);
    assert_success(&revoke_old);
    assert_output_has_no_secret(&revoke_old);
    assert!(!app_config.exists());
    assert!(!app_data.exists());
    assert!(!app_state.exists());
    fixture.assert_legacy_untouched();

    fs::create_dir_all(&app_config).unwrap();
    fs::create_dir_all(&app_data).unwrap();
    fs::create_dir_all(&app_state).unwrap();
    fs::write(
        app_config.join("config.json"),
        br#"{corrupt secret: "sk-corrupt-v2-must-not-print""#,
    )
    .unwrap();
    let revoke_corrupt = fixture.run(&["revoke", "--all"]);
    assert_success(&revoke_corrupt);
    assert!(
        !String::from_utf8_lossy(&revoke_corrupt.stdout).contains("sk-corrupt-v2-must-not-print")
    );
    assert!(
        !String::from_utf8_lossy(&revoke_corrupt.stderr).contains("sk-corrupt-v2-must-not-print")
    );
    assert!(!app_config.exists());
    assert!(!app_data.exists());
    assert!(!app_state.exists());
    fixture.assert_legacy_untouched();
}

#[test]
fn setup_rejects_a_second_products_gateway_before_reading_or_sending_its_key() {
    let fixture = Fixture::new();
    let (gateway, bootstrap) = bootstrap_server(vec![BootstrapExpectation::claude(CLAUDE_KEY)]);
    let setup = fixture.run_with_stdin(
        &["setup", "claude", "--base-url", &gateway, "--api-key-stdin"],
        CLAUDE_KEY,
    );
    assert_success(&setup);
    join_before(bootstrap, MOCK_JOIN_TIMEOUT).unwrap();

    let (other_gateway, unexpected_request) = unexpected_request_server();
    let mismatched_gateway = format!("{other_gateway}/{MISMATCH_KEY}");
    let mismatch = fixture.run_with_stdin(
        &[
            "setup",
            "codex",
            "--base-url",
            &mismatched_gateway,
            "--api-key-stdin",
        ],
        MISMATCH_KEY,
    );
    assert!(!mismatch.status.success());
    assert_output_has_no_secret(&mismatch);
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("shared Gateway"));
    assert!(
        !join_before(unexpected_request, MOCK_JOIN_TIMEOUT).unwrap(),
        "the rejected Gateway received a bootstrap request"
    );

    let config = fs::read_to_string(fixture.config_root.join("saiai/config.json")).unwrap();
    assert!(!config.contains(MISMATCH_KEY));
    assert!(config.contains(&format!("{gateway}/")));
}

#[test]
fn non_interactive_setup_without_key_stdin_fails_with_actionable_guidance() {
    let fixture = Fixture::new();
    let setup = fixture.run(&["setup", "claude", "--base-url", "http://127.0.0.1:9"]);
    assert!(!setup.status.success());
    assert_output_has_no_secret(&setup);
    assert!(String::from_utf8_lossy(&setup.stderr).contains("--api-key-stdin"));

    for product in ["claude", "codex"] {
        let first_launch = fixture
            .command()
            .arg(product)
            .env("PATH", &fixture.output)
            .output()
            .unwrap();
        assert!(!first_launch.status.success());
        assert_output_has_no_secret(&first_launch);
        let first_launch_error = String::from_utf8_lossy(&first_launch.stderr);
        assert!(first_launch_error.contains("standard input and standard error"));
        assert!(first_launch_error.contains("--api-key-stdin"));
        assert!(
            !first_launch_error.contains("could not resolve"),
            "{product} client resolution ran before first-launch initialization"
        );
    }
}

#[test]
fn product_revoke_waits_for_the_launched_clients_generation_lease() {
    let fixture = Fixture::new();
    let (gateway, server) = bootstrap_server(vec![BootstrapExpectation::codex(CODEX_KEY)]);
    let setup = fixture.run_with_stdin(
        &["setup", "codex", "--base-url", &gateway, "--api-key-stdin"],
        CODEX_KEY,
    );
    assert_success(&setup);
    join_before(server, MOCK_JOIN_TIMEOUT).unwrap();

    let config_path = fixture.config_root.join("saiai/config.json");
    let config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    let generation = config["products"]["codex"]["active_generation"]
        .as_str()
        .unwrap();
    let home = fixture
        .data_root
        .join("saiai/generations")
        .join(generation)
        .join("clients/codex");

    let block_dir = fixture.output.join("block-codex");
    fs::create_dir(&block_dir).unwrap();
    let running = fixture
        .command()
        .args(["codex", "--", "hold-generation"])
        .env("SAIAI_TEST_BLOCK_DIR", &block_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let running = BlockingChild::new(running, block_dir.join("release"));
    wait_for_path(&block_dir.join("ready"), Duration::from_secs(5));

    let busy_revoke = fixture.run(&["codex", "revoke"]);
    assert!(!busy_revoke.status.success());
    assert_output_has_no_secret(&busy_revoke);
    assert!(String::from_utf8_lossy(&busy_revoke.stderr).contains("currently running"));
    assert!(
        config_path.is_file(),
        "busy revoke removed the committed config"
    );
    assert!(home.is_dir(), "busy revoke removed the running client home");

    let launched = running.release_and_wait();
    assert_success(&launched);
    assert_output_has_no_secret(&launched);

    let revoke = fixture.run(&["codex", "revoke"]);
    assert_success(&revoke);
    assert!(!home.exists());
    fixture.assert_legacy_untouched();
}

struct Fixture {
    _temp: TempDir,
    home: PathBuf,
    config_root: PathBuf,
    data_root: PathBuf,
    state_root: PathBuf,
    fake_bin: PathBuf,
    output: PathBuf,
    legacy: Vec<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home");
        let config_root = temp.path().join("xdg-config");
        let data_root = temp.path().join("xdg-data");
        let state_root = temp.path().join("xdg-state");
        let fake_bin = temp.path().join("bin");
        let output = temp.path().join("output");
        for path in [
            &home,
            &config_root,
            &data_root,
            &state_root,
            &fake_bin,
            &output,
        ] {
            fs::create_dir_all(path).unwrap();
        }

        let mut legacy = [".saiai", ".claude", ".codex"]
            .into_iter()
            .map(|name| {
                let sentinel = home.join(name).join("sentinel");
                fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
                fs::write(&sentinel, format!("legacy-{name}")).unwrap();
                sentinel
            })
            .collect::<Vec<_>>();
        let claude_state = home.join(".claude.json");
        fs::write(&claude_state, "legacy-home").unwrap();
        legacy.push(claude_state);
        let claude_credentials = home.join(".claude/.credentials.json");
        fs::write(&claude_credentials, "legacy-.claude").unwrap();
        legacy.push(claude_credentials);

        write_executable(
            &fake_bin.join("codex"),
            r#"#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  case "${HOME:-}" in
    */saiai-version-probe-*/home) ;;
    *) exit 70 ;;
  esac
  [ "${CODEX_HOME:-}" = "$HOME/codex" ]
  [ -z "${SAIAI_TEST_OUTPUT+x}" ]
  [ -z "${SAIAI_TEST_SECRET+x}" ]
  printf '%s\n' 'codex-cli 1.2.3 integration-test'
  exit 0
fi
[ "${SAIAI_CODEX_API_KEY:-}" = "sk-v2-codex-integration-secret" ]
[ -n "${CODEX_HOME:-}" ]
[ -z "${OPENAI_API_KEY+x}" ]
[ -z "${OPENAI_BASE_URL+x}" ]
[ -z "${HTTP_PROXY+x}" ]
[ -z "${HTTPS_PROXY+x}" ]
[ -z "${ALL_PROXY+x}" ]
[ -z "${NO_PROXY+x}" ]
[ -z "${http_proxy+x}" ]
[ -z "${https_proxy+x}" ]
[ -z "${all_proxy+x}" ]
[ -z "${no_proxy+x}" ]
if [ -n "${SAIAI_TEST_BLOCK_DIR:-}" ]; then
  : > "$SAIAI_TEST_BLOCK_DIR/ready"
  while [ ! -f "$SAIAI_TEST_BLOCK_DIR/release" ]; do
    sleep 0.01
  done
fi
printf '%s\n' "$CODEX_HOME" > "$SAIAI_TEST_OUTPUT/codex-home"
printf '%s\n' "$@" > "$SAIAI_TEST_OUTPUT/codex-args"
"#,
        );
        write_executable(
            &fake_bin.join("claude"),
            r#"#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  case "${HOME:-}" in
    */saiai-version-probe-*/home) ;;
    *) exit 70 ;;
  esac
  [ "${CLAUDE_CONFIG_DIR:-}" = "$HOME/claude" ]
  [ -z "${SAIAI_TEST_OUTPUT+x}" ]
  [ -z "${SAIAI_TEST_SECRET+x}" ]
  printf '%s\n' 'claude 1.2.3 integration-test'
  exit 0
fi
[ "${CLAUDE_CODE_OAUTH_TOKEN:-}" = "sk-v2-claude-integration-secret" ]
[ "${CLAUDE_STREAM_IDLE_TIMEOUT_MS:-}" = "600000" ]
[ -n "${CLAUDE_CONFIG_DIR:-}" ]
[ -n "${HTTP_PROXY:-}" ]
[ "$HTTP_PROXY" = "$HTTPS_PROXY" ]
[ "$HTTP_PROXY" = "$ALL_PROXY" ]
[ -f "${NODE_EXTRA_CA_CERTS:-missing}" ]
[ -z "${ANTHROPIC_BASE_URL+x}" ]
[ -z "${ANTHROPIC_AUTH_TOKEN+x}" ]
[ -z "${ANTHROPIC_API_KEY+x}" ]
[ -z "${CLAUDE_CODE_USE_BEDROCK+x}" ]
[ -z "${CLAUDE_CODE_USE_VERTEX+x}" ]
[ -z "${CLAUDE_CODE_USE_FOUNDRY+x}" ]
[ -z "${CLAUDE_CODE_SKIP_BEDROCK_AUTH+x}" ]
[ -z "${ANTHROPIC_BEDROCK_BASE_URL+x}" ]
[ -z "${CLAUDE_CODE_SKIP_VERTEX_AUTH+x}" ]
[ -z "${ANTHROPIC_VERTEX_BASE_URL+x}" ]
[ -z "${ANTHROPIC_VERTEX_PROJECT_ID+x}" ]
[ -z "${CLOUD_ML_REGION+x}" ]
[ -z "${CLAUDE_CODE_SKIP_FOUNDRY_AUTH+x}" ]
[ -z "${ANTHROPIC_FOUNDRY_BASE_URL+x}" ]
[ -z "${ANTHROPIC_FOUNDRY_RESOURCE+x}" ]
[ -z "${ANTHROPIC_MODEL+x}" ]
[ -z "${ANTHROPIC_DEFAULT_OPUS_MODEL+x}" ]
[ -z "${ANTHROPIC_DEFAULT_SONNET_MODEL+x}" ]
[ -z "${ANTHROPIC_DEFAULT_HAIKU_MODEL+x}" ]
[ -z "${ANTHROPIC_SMALL_FAST_MODEL+x}" ]
[ -z "${CLAUDE_CODE_SUBAGENT_MODEL+x}" ]
[ -z "${CLAUDE_CODE_EFFORT_LEVEL+x}" ]
[ -z "${CLAUDE_CODE_ENTRYPOINT+x}" ]
[ -z "${CLAUDE_CODE_ATTRIBUTION_HEADER+x}" ]
printf '%s\n' "$CLAUDE_CONFIG_DIR" > "$SAIAI_TEST_OUTPUT/claude-home"
printf '%s\n' "$HTTP_PROXY" > "$SAIAI_TEST_OUTPUT/claude-proxy"
printf '%s\n' "$@" > "$SAIAI_TEST_OUTPUT/claude-args"
"#,
        );

        Self {
            _temp: temp,
            home,
            config_root,
            data_root,
            state_root,
            fake_bin,
            output,
            legacy,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_saiai"));
        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        command
            .stdin(Stdio::null())
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_root)
            .env("XDG_DATA_HOME", &self.data_root)
            .env("XDG_STATE_HOME", &self.state_root)
            .env("SAIAI_HOME", self.home.join(".saiai"))
            .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
            .env("CODEX_HOME", self.home.join(".codex"))
            .env("ANTHROPIC_BASE_URL", "https://legacy.invalid")
            .env("ANTHROPIC_AUTH_TOKEN", "legacy-auth-token")
            .env("ANTHROPIC_API_KEY", "legacy-api-key")
            .env("CLAUDE_CODE_USE_BEDROCK", "1")
            .env("CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1")
            .env("ANTHROPIC_BEDROCK_BASE_URL", "https://bedrock.invalid")
            .env("CLAUDE_CODE_USE_VERTEX", "1")
            .env("CLAUDE_CODE_SKIP_VERTEX_AUTH", "1")
            .env("ANTHROPIC_VERTEX_BASE_URL", "https://vertex.invalid")
            .env("ANTHROPIC_VERTEX_PROJECT_ID", "legacy-project")
            .env("CLOUD_ML_REGION", "legacy-region")
            .env("CLAUDE_CODE_USE_FOUNDRY", "1")
            .env("CLAUDE_CODE_SKIP_FOUNDRY_AUTH", "1")
            .env("ANTHROPIC_FOUNDRY_BASE_URL", "https://foundry.invalid")
            .env("ANTHROPIC_FOUNDRY_RESOURCE", "legacy-resource")
            .env("ANTHROPIC_MODEL", "legacy-model")
            .env("ANTHROPIC_DEFAULT_OPUS_MODEL", "legacy-opus")
            .env("ANTHROPIC_DEFAULT_SONNET_MODEL", "legacy-sonnet")
            .env("ANTHROPIC_DEFAULT_HAIKU_MODEL", "legacy-haiku")
            .env("ANTHROPIC_SMALL_FAST_MODEL", "legacy-fast")
            .env("CLAUDE_CODE_SUBAGENT_MODEL", "legacy-subagent")
            .env("CLAUDE_CODE_EFFORT_LEVEL", "max")
            .env("CLAUDE_CODE_ENTRYPOINT", "legacy-entrypoint")
            .env("CLAUDE_CODE_ATTRIBUTION_HEADER", "legacy-attribution")
            .env("CLAUDE_STREAM_IDLE_TIMEOUT_MS", "12345")
            .env("OPENAI_API_KEY", "legacy-openai-key")
            .env("OPENAI_BASE_URL", "https://legacy-openai.invalid")
            .env("HTTP_PROXY", "http://legacy-proxy.invalid:8080")
            .env("HTTPS_PROXY", "http://legacy-proxy.invalid:8080")
            .env("ALL_PROXY", "http://legacy-proxy.invalid:8080")
            .env("NO_PROXY", "legacy.invalid")
            .env("http_proxy", "http://legacy-lower-proxy.invalid:8080")
            .env("https_proxy", "http://legacy-lower-proxy.invalid:8080")
            .env("all_proxy", "http://legacy-lower-proxy.invalid:8080")
            .env("no_proxy", "legacy-lower.invalid")
            .env("SAIAI_TEST_SECRET", PROBE_SECRET)
            .env("SAIAI_TEST_OUTPUT", &self.output)
            .env(
                "PATH",
                std::env::join_paths(
                    std::iter::once(self.fake_bin.clone())
                        .chain(std::env::split_paths(&inherited_path)),
                )
                .unwrap(),
            );
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .command()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child_stdin = child.stdin.take().unwrap();
        if let Err(error) = child_stdin.write_all(stdin.as_bytes()) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe,
                "failed to write test stdin: {error}"
            );
        }
        drop(child_stdin);
        child.wait_with_output().unwrap()
    }

    fn assert_legacy_untouched(&self) {
        for sentinel in &self.legacy {
            let name = sentinel.parent().unwrap().file_name().unwrap();
            assert_eq!(
                fs::read_to_string(sentinel).unwrap(),
                format!("legacy-{}", name.to_string_lossy())
            );
        }
    }
}

#[derive(Clone, Copy)]
struct BootstrapExpectation {
    expected_key: &'static str,
    claude: bool,
    codex: bool,
}

impl BootstrapExpectation {
    fn claude(expected_key: &'static str) -> Self {
        Self {
            expected_key,
            claude: true,
            codex: false,
        }
    }

    fn codex(expected_key: &'static str) -> Self {
        Self {
            expected_key,
            claude: false,
            codex: true,
        }
    }
}

fn bootstrap_server(expectations: Vec<BootstrapExpectation>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for expectation in expectations {
            let mut stream = accept_before(&listener, Instant::now() + MOCK_ACCEPT_TIMEOUT);
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(MOCK_IO_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(MOCK_IO_TIMEOUT)).unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 64 * 1024);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /api/v1/client/bootstrap HTTP/1.1\r\n"));
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case(&format!(
                        "authorization: Bearer {}",
                        expectation.expected_key
                    )))
            );
            let body = format!(
                r#"{{"code":0,"message":"success","data":{{"schema_version":2,"gateway_version":"integration-gateway","capabilities":{{"claude":{},"codex":{},"codex_responses":{},"codex_websockets":false,"openai_messages_dispatch":false}}}}}}"#,
                expectation.claude, expectation.codex, expectation.codex
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        }
    });
    (format!("http://{address}"), server)
}

fn unexpected_request_server() -> (String, thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    drop(stream);
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("unexpected-request listener failed: {error}"),
            }
        }
    });
    (format!("http://{address}"), server)
}

fn accept_before(listener: &TcpListener, deadline: Instant) -> TcpStream {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for a bootstrap request"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("bootstrap listener failed: {error}"),
        }
    }
}

fn join_before<T>(handle: thread::JoinHandle<T>, timeout: Duration) -> thread::Result<T> {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a mock server thread"
        );
        thread::sleep(Duration::from_millis(5));
    }
    handle.join()
}

fn wait_for_path(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

struct BlockingChild {
    child: Option<Child>,
    release_path: PathBuf,
}

impl BlockingChild {
    fn new(child: Child, release_path: PathBuf) -> Self {
        Self {
            child: Some(child),
            release_path,
        }
    }

    fn release_and_wait(mut self) -> Output {
        fs::write(&self.release_path, b"release\n").unwrap();
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for BlockingChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = fs::write(&self.release_path, b"release\n");
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_output_has_no_secret(output: &Output) {
    for secret in [CLAUDE_KEY, CODEX_KEY, MISMATCH_KEY, PROBE_SECRET] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}
