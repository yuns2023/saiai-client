//! Black-box SAIAI contract: run the built `saiai` binary in a throwaway home
//! and freeze what existing installations depend on (binary name, version
//! output, `~/.saiai` layout, config JSON, CA identity, Codex files,
//! environment isolation). Expected values are hand-written literals, except
//! the release version (read from Cargo.toml), the CA suffix (hash of the
//! generated key) and environment digests of temporary paths; see
//! `src/brand_contract_tests.rs` for the in-process half of the contract.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Compile-time proof that Cargo still builds a binary target named `saiai`.
const BINARY: &str = env!("CARGO_BIN_EXE_saiai");

fn release_version() -> String {
    let manifest = include_str!("../Cargo.toml");
    let package = manifest
        .split("\n[")
        .next()
        .expect("Cargo.toml starts with [package]");
    assert!(package.starts_with("[package]"));
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

struct Sandbox {
    _temporary: tempfile::TempDir,
    home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        // Resolve symlinked temp roots (macOS /var -> /private/var) and
        // Windows 8.3 short names so paths compare equal to what the client
        // records after its own normalization.
        let home = canonical(temporary.path()).join("home");
        std::fs::create_dir(&home).unwrap();
        Self {
            _temporary: temporary,
            home,
        }
    }

    /// The binary with an isolated profile. No SAIAI/Claude/Codex location
    /// variables are inherited, so defaults below `home` are exercised.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(BINARY);
        command
            .args(args)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("SAIAI_SKIP_START", "1")
            .env_remove("SAIAI_HOME")
            .env_remove("SAIAI_INSTALL_DIR")
            .env_remove("SAIAI_UPSTREAM_PROXY")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CODEX_HOME")
            .stdin(Stdio::null());
        command
    }

    /// Runs to completion within a bounded time; output goes to files so a
    /// chatty child can never block on a full pipe.
    fn run(&self, command: &mut Command) -> String {
        let log = self
            .home
            .with_file_name(format!("run-{}.log", uuid::Uuid::new_v4().simple()));
        let file = std::fs::File::create(&log).unwrap();
        let mut child = command
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{command:?} did not finish within 120 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let text = String::from_utf8_lossy(&std::fs::read(&log).unwrap()).into_owned();
        assert!(status.success(), "{command:?} failed:\n{text}");
        text
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    let raw = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_slice(&raw).unwrap()
}

/// Ordinary (non-verbatim on Windows) canonical spelling, like the client's.
fn canonical(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        dunce::canonicalize(path).unwrap()
    }
    #[cfg(not(windows))]
    {
        std::fs::canonicalize(path).unwrap()
    }
}

fn same_path(left: &str, right: &Path) -> bool {
    canonical(Path::new(left)) == canonical(right)
}

fn assert_installation_ca(cert: &Path, key: &Path) {
    let cert_pem = std::fs::read_to_string(cert).unwrap();
    let key_pem = std::fs::read_to_string(key).unwrap();
    let key = rcgen::KeyPair::from_pem(&key_pem).unwrap();
    let suffix = Sha256::digest(key.public_key_der())[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let certificate = pem.parse_x509().unwrap();
    let subject = certificate.subject();
    let cn = subject
        .iter_common_name()
        .map(|name| name.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let o = subject
        .iter_organization()
        .map(|name| name.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(cn, vec![format!("SAIAI local installation CA {suffix}")]);
    assert_eq!(o, vec!["SAIAI".to_string()]);
}

#[test]
fn binary_name_and_version_output_are_frozen() {
    let file_name = Path::new(BINARY).file_name().unwrap().to_str().unwrap();
    assert_eq!(file_name, if cfg!(windows) { "saiai.exe" } else { "saiai" });
    let sandbox = Sandbox::new();
    let output = sandbox.run(&mut sandbox.command(&["--version"]));
    // `saiai update` accepts a candidate only when it prints this prefix.
    assert_eq!(output.trim(), format!("saiai {}", release_version()));
}

fn sorted_keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

const CONFIG_KEYS: [&str; 9] = [
    "api_key",
    "base_url",
    "ca_cert_path",
    "ca_key_path",
    "chatgpt_chat_passthrough",
    "desktop_browser_use",
    "listen",
    "providers",
    "version",
];

#[test]
fn claude_first_installation_layout_is_frozen() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_CLAUDE",
    ]));
    // Installers and CI rely on SAIAI_SKIP_START=1 to configure only.
    assert!(
        output.contains("SAIAI local proxy start skipped (SAIAI_SKIP_START=1)."),
        "{output}"
    );
    let root = sandbox.home.join(".saiai");
    let config = read_json(&root.join("config.json"));
    assert_eq!(sorted_keys(&config), CONFIG_KEYS);
    assert_eq!(config["version"], 2);
    assert_eq!(config["chatgpt_chat_passthrough"], true);
    assert_eq!(config["desktop_browser_use"], true);
    assert!(config["listen"].as_str().unwrap().starts_with("127.0.0.1:"));
    assert_eq!(
        config["providers"]["claude"]["api_key"],
        "TEST_ONLY_CONTRACT_CLAUDE"
    );
    // The default Claude installation keeps its CA next to Claude's settings
    // (`NODE_EXTRA_CA_CERTS`), not in ~/.saiai.
    let claude = sandbox.home.join(".claude");
    assert!(same_path(
        config["ca_cert_path"].as_str().unwrap(),
        &claude.join("saiai-ca.crt")
    ));
    assert!(same_path(
        config["ca_key_path"].as_str().unwrap(),
        &claude.join("saiai-ca.key")
    ));
    assert_installation_ca(&claude.join("saiai-ca.crt"), &claude.join("saiai-ca.key"));
    let settings = read_json(&claude.join("settings.json"));
    assert!(same_path(
        settings["env"]["NODE_EXTRA_CA_CERTS"].as_str().unwrap(),
        &claude.join("saiai-ca.crt")
    ));

    // Codex joins the same installation and receives the managed IDE block
    // and the local placeholder login.
    sandbox.run(&mut sandbox.command(&[
        "init-codex",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_CODEX",
    ]));
    let config = read_json(&root.join("config.json"));
    assert_eq!(
        config["providers"]["codex"]["api_key"],
        "TEST_ONLY_CONTRACT_CODEX"
    );
    let codex = sandbox.home.join(".codex");
    let env = std::fs::read_to_string(codex.join(".env")).unwrap();
    assert!(env.contains("# BEGIN SAIAI CODEX IDE (managed)\n"), "{env}");
    assert!(env.contains("\n# END SAIAI CODEX IDE (managed)"), "{env}");
    let auth = read_json(&codex.join("auth.json"));
    assert_eq!(auth["tokens"]["account_id"], "saiai-local-proxy-account");
}

#[test]
fn codex_first_installation_layout_is_frozen() {
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init-codex",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_CODEX",
    ]));
    let root = sandbox.home.join(".saiai");
    let config = read_json(&root.join("config.json"));
    assert_eq!(sorted_keys(&config), CONFIG_KEYS);
    assert_eq!(config["version"], 2);
    assert!(same_path(
        config["ca_cert_path"].as_str().unwrap(),
        &root.join("saiai-ca.crt")
    ));
    assert!(same_path(
        config["ca_key_path"].as_str().unwrap(),
        &root.join("saiai-ca.key")
    ));
    assert_installation_ca(&root.join("saiai-ca.crt"), &root.join("saiai-ca.key"));
}

#[test]
fn saiai_home_override_and_environment_isolation_are_frozen() {
    let sandbox = Sandbox::new();
    let custom_root = sandbox.home.join("custom-saiai");
    let project = sandbox.home.join("project").join("claude");
    std::fs::create_dir_all(&project).unwrap();
    sandbox.run(
        sandbox
            .command(&[
                "init",
                "--base-url",
                "http://127.0.0.1:9",
                "--api-key",
                "TEST_ONLY_CONTRACT_PROJECT",
            ])
            .env("SAIAI_HOME", &custom_root)
            .env("CLAUDE_CONFIG_DIR", &project),
    );
    assert!(!sandbox.home.join(".saiai").exists());
    // Isolated environments live at <root>/environments/<product>-<first 24
    // hex digits of SHA-256 over the normalized product directory>.
    let digest = Sha256::digest(project.as_os_str().as_encoded_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let environment = custom_root
        .join("environments")
        .join(format!("claude-{}", &digest[..24]));
    let config = read_json(&environment.join("config.json"));
    assert_eq!(config["version"], 2);
    assert!(same_path(
        config["ca_cert_path"].as_str().unwrap(),
        &environment.join("saiai-ca.crt")
    ));
    assert_eq!(
        std::fs::read_to_string(environment.join("product-dir")).unwrap(),
        project.to_str().unwrap()
    );
    assert!(!custom_root.join("config.json").exists());
}

/// `SAIAI_UPSTREAM_PROXY` overrides the configured egress for the process it
/// is set on (only the child here; the test process environment is untouched).
#[test]
fn saiai_upstream_proxy_variable_is_honored() {
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init-codex",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_CODEX",
    ]));
    let direct = sandbox.run(
        sandbox
            .command(&["upstream-proxy"])
            .env("SAIAI_UPSTREAM_PROXY", "direct"),
    );
    assert!(
        direct.contains("this shell resolves it to: direct (configured)"),
        "{direct}"
    );
    let invalid = sandbox.run(
        sandbox
            .command(&["upstream-proxy"])
            .env("SAIAI_UPSTREAM_PROXY", "ftp://proxy.invalid"),
    );
    assert!(
        invalid.contains(
            "this shell resolves it to: SAIAI_UPSTREAM_PROXY is not an http:// proxy URL"
        ),
        "{invalid}"
    );
}
