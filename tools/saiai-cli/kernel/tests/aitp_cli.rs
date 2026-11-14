//! The real `aitp` program in a throwaway home: it reports, writes and
//! names only AITP, and it updates from its own release channel without a
//! Gateway or an initialized configuration. No network access: the update
//! goes through a local proxy that refuses the tunnel.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_aitp");
const MANIFEST_URL: &str =
    "https://github.com/2742zdz/AITP/releases/latest/download/aitp-manifest.json";

/// The other distribution's name, assembled so this file never spells it.
fn other_brand() -> String {
    ["s", "a", "i", "a", "i"].concat()
}

/// Environment variables of any distribution or client location that a
/// developer or CI shell may carry; none reaches the program.
fn foreign_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("AITP_")
        || upper.starts_with(&format!("{}_", other_brand().to_ascii_uppercase()))
        || [
            "CLAUDE_CONFIG_DIR",
            // Claude settings a shell may export; status warns about them.
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_ATTRIBUTION_HEADER",
            "CODEX_HOME",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
        ]
        .contains(&upper.as_str())
}

struct Sandbox {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    /// The program, copied here so nothing it writes or prints carries the
    /// build directory's path.
    program: PathBuf,
    /// Everything the program printed, for the name check.
    printed: Mutex<Vec<String>>,
}

impl Sandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = canonical(temporary.path());
        let home = root.join("home");
        let bin = root.join("bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let program = bin.join(Path::new(BINARY).file_name().unwrap());
        std::fs::copy(BINARY, &program).unwrap();
        Self {
            _temporary: temporary,
            root,
            home,
            program,
            printed: Mutex::new(Vec::new()),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.program);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(foreign_variable) {
                command.env_remove(&name);
            }
        }
        command
            .args(args)
            .current_dir(&self.root)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("AITP_SKIP_START", "1")
            .stdin(Stdio::null());
        command
    }

    /// Runs to completion (bounded); output goes to a file so a chatty
    /// child cannot block on a full pipe.
    fn output(&self, command: &mut Command) -> (bool, String) {
        let log = self.root.join(format!("run-{}.log", std::process::id()));
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
        std::fs::remove_file(&log).unwrap();
        self.printed.lock().unwrap().push(text.clone());
        (status.success(), text)
    }

    fn run(&self, args: &[&str]) -> String {
        let (success, text) = self.output(&mut self.command(args));
        assert!(success, "aitp {args:?} failed:\n{text}");
        text
    }

    /// Neither the files the program wrote anywhere in the sandbox (names
    /// and contents; links are reported, not followed) nor any output names
    /// the other distribution. The copied program itself is checked
    /// separately (`the_program_carries_no_other_distribution_name`).
    fn assert_only_aitp_names(&self) {
        let other = other_brand();
        for text in self.printed.lock().unwrap().iter() {
            assert!(!text.to_ascii_lowercase().contains(&other), "{text}");
        }
        let mut pending = vec![self.root.clone()];
        let mut files = 0;
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                assert!(
                    !path.to_string_lossy().to_ascii_lowercase().contains(&other),
                    "{}",
                    path.display()
                );
                let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                if path == self.program {
                    continue;
                }
                if kind.is_symlink() {
                    let target = std::fs::read_link(&path).unwrap();
                    assert!(
                        !target
                            .to_string_lossy()
                            .to_ascii_lowercase()
                            .contains(&other),
                        "{} -> {}",
                        path.display(),
                        target.display()
                    );
                } else if kind.is_dir() {
                    pending.push(path);
                } else if kind.is_file() {
                    files += 1;
                    let bytes = std::fs::read(&path).unwrap();
                    assert!(
                        !String::from_utf8_lossy(&bytes)
                            .to_ascii_lowercase()
                            .contains(&other),
                        "{} names the other distribution",
                        path.display()
                    );
                }
            }
        }
        assert!(files > 0, "the program wrote nothing to check");
    }
}

fn canonical(path: &Path) -> PathBuf {
    let path = std::fs::canonicalize(path).unwrap();
    #[cfg(windows)]
    {
        // The plain spelling, as the program records paths.
        let text = path.to_string_lossy();
        if let Some(plain) = text.strip_prefix(r"\\?\") {
            return PathBuf::from(plain);
        }
    }
    path
}

fn read_json(path: &Path) -> serde_json::Value {
    let raw = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_slice(&raw).unwrap()
}

/// The DER bytes of the first certificate in a PEM file.
fn certificate_der(path: &Path) -> Vec<u8> {
    use base64::Engine;
    let pem = std::fs::read_to_string(path).unwrap();
    let body: String = pem
        .lines()
        .skip_while(|line| !line.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

/// The string value of the first X.501 attribute with object identifier
/// `oid` (DER: `06 03 <oid>` then a string of one length byte).
fn attribute(der: &[u8], oid: &[u8; 3]) -> Option<String> {
    let mut pattern = vec![0x06, 0x03];
    pattern.extend_from_slice(oid);
    let at = der
        .windows(pattern.len())
        .position(|window| window == pattern)?
        + pattern.len();
    let (tag, length) = (*der.get(at)?, usize::from(*der.get(at + 1)?));
    if !matches!(tag, 0x0c | 0x13) || length >= 0x80 {
        return None;
    }
    String::from_utf8(der.get(at + 2..at + 2 + length)?.to_vec()).ok()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A local "proxy" that records each request head and refuses it, so the
/// program's update request is observed and never leaves the machine.
fn refusing_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read_exact(&mut byte).is_ok() {
                head.push(byte[0]);
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (port, seen)
}

#[test]
fn version_names_aitp_and_this_package() {
    let sandbox = Sandbox::new();
    assert_eq!(
        sandbox.run(&["--version"]),
        format!("aitp {}\n", env!("CARGO_PKG_VERSION"))
    );
    let help = sandbox.run(&["--help"]);
    assert!(help.contains("aitp init"), "{help}");
}

/// init and init-codex write the AITP configuration, CA and client
/// settings for a relay Gateway the user names; status reports AITP; and
/// nothing anywhere names the other distribution.
#[test]
fn initialization_writes_only_aitp_names() {
    let sandbox = Sandbox::new();
    let gateway = "http://127.0.0.1:9";
    sandbox.run(&[
        "init",
        "--base-url",
        gateway,
        "--api-key",
        "TEST_ONLY_AITP_CLAUDE_KEY",
    ]);
    let config = read_json(&sandbox.home.join(".aitp/config.json"));
    assert_eq!(config["base_url"], gateway, "{config}");
    // The default environment keeps its CA with the Claude settings.
    let ca = PathBuf::from(config["ca_cert_path"].as_str().unwrap());
    assert_eq!(ca, sandbox.home.join(".claude/aitp-ca.crt"));
    let der = certificate_der(&ca);
    // Subject (and issuer: self-signed) common name and organization.
    let common_name = attribute(&der, &[0x55, 0x04, 0x03]).unwrap();
    assert!(
        common_name.starts_with("AITP local installation CA "),
        "{common_name}"
    );
    assert_eq!(
        attribute(&der, &[0x55, 0x04, 0x0a]).as_deref(),
        Some("AITP")
    );
    let settings = read_json(&sandbox.home.join(".claude/settings.json"));
    let env = &settings["env"];
    assert_eq!(
        env["NODE_EXTRA_CA_CERTS"].as_str().map(PathBuf::from),
        Some(ca.clone()),
        "{settings}"
    );
    let listen = config["listen"].as_str().unwrap();
    assert_eq!(env["https_proxy"], format!("http://{listen}"), "{settings}");

    sandbox.run(&[
        "init-codex",
        "--base-url",
        gateway,
        "--api-key",
        "TEST_ONLY_AITP_CODEX_KEY",
    ]);
    let auth = read_json(&sandbox.home.join(".codex/auth.json"));
    let auth_text = auth.to_string();
    assert!(auth_text.contains("aitp-local-proxy-account"), "{auth}");
    let codex_config = std::fs::read_to_string(sandbox.home.join(".codex/config.toml")).unwrap();
    assert!(!codex_config.is_empty());

    // Not started (AITP_SKIP_START): status reads the configuration and
    // succeeds.
    let status = sandbox.run(&["status"]);
    let lines: Vec<&str> = status.lines().collect();
    assert!(lines.len() >= 3, "{status}");
    assert_eq!(
        lines[0],
        format!("aitp {}", env!("CARGO_PKG_VERSION")),
        "{status}"
    );
    // The same file, however the platform spells the path.
    let reported = lines[1].strip_prefix("config: ").expect(&status);
    assert_eq!(
        std::fs::canonicalize(reported).unwrap(),
        std::fs::canonicalize(sandbox.home.join(".aitp").join("config.json")).unwrap(),
        "{status}"
    );
    assert_eq!(lines[2], format!("base_url: {gateway}"), "{status}");
    sandbox.assert_only_aitp_names();
}

/// `update` needs no initialization: it asks the AITP release channel
/// (through the configured upstream proxy, which refuses here), and fails
/// without downloading or naming anything else.
#[test]
fn update_asks_the_release_channel_without_initialization() {
    let sandbox = Sandbox::new();
    let (port, seen) = refusing_proxy();
    let (success, text) = sandbox.output(
        sandbox
            .command(&["update"])
            .env("AITP_UPSTREAM_PROXY", format!("http://127.0.0.1:{port}")),
    );
    assert!(!success, "{text}");
    assert!(
        text.contains(&format!("Checking: {MANIFEST_URL}")),
        "{text}"
    );
    assert!(!text.contains("Downloading:"), "{text}");
    let heads = seen.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(heads[0].starts_with("CONNECT github.com:443 "), "{heads:?}");
    // Nothing was staged next to the program.
    let staged: Vec<_> = std::fs::read_dir(sandbox.program.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".aitp-update-"))
        .filter(|name| name.to_string_lossy() != ".aitp-update-lock")
        .collect();
    assert!(staged.is_empty(), "{staged:?}");
    let other = other_brand();
    assert!(!text.to_ascii_lowercase().contains(&other), "{text}");
}

/// A configuration that exists but cannot be read stops `update` before
/// any request.
#[test]
fn update_refuses_an_unreadable_configuration() {
    let sandbox = Sandbox::new();
    std::fs::create_dir_all(sandbox.home.join(".aitp")).unwrap();
    std::fs::write(sandbox.home.join(".aitp/config.json"), b"{not json").unwrap();
    let (port, seen) = refusing_proxy();
    let (success, text) = sandbox.output(
        sandbox
            .command(&["update"])
            .env("AITP_UPSTREAM_PROXY", format!("http://127.0.0.1:{port}")),
    );
    assert!(!success, "{text}");
    assert!(text.contains("failed to parse"), "{text}");
    assert!(text.contains("config.json"), "{text}");
    assert!(seen.lock().unwrap().is_empty());
}

/// The program itself carries no other distribution's name. Only checked
/// when the kernel is built outside such a directory (its build path ends
/// up in debug information), as in the stand-alone kernel CI.
#[test]
fn the_program_carries_no_other_distribution_name() {
    let other = other_brand();
    if env!("CARGO_MANIFEST_DIR")
        .to_ascii_lowercase()
        .contains(&other)
    {
        eprintln!("skipped: built below a directory with the other name");
        return;
    }
    let bytes = std::fs::read(BINARY).unwrap();
    let lower: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    assert!(!contains(&lower, other.as_bytes()));
    assert!(contains(&bytes, b"AITP local installation CA"));
}
