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
        command.stdout(file.try_clone().unwrap()).stderr(file);
        // A test running in parallel may fork while another sandbox's copy
        // of the program is still open for writing ("text file busy").
        let mut attempts = 0;
        let mut child = loop {
            match command.spawn() {
                Ok(child) => break child,
                Err(error)
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 =>
                {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("{command:?}: {error}"),
            }
        };
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
        // The installation-directory lock files (Windows) stay.
        .filter(|name| {
            ![".aitp-update-lock", ".aitp-update-helper-lock"]
                .contains(&name.to_string_lossy().as_ref())
        })
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

/// `bytes` lower-cased with both path separators as `/`, so a path matches
/// in any case and with either separator.
fn path_view(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|byte| match byte {
            b'\\' => b'/',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

/// The absolute build paths that spell `name` and that this build may embed
/// in the program (debug information, build script outputs, crate sources):
/// each ancestor of the package directory, of the program (its target
/// directory) and of the Cargo, rustup and user homes, also canonicalized,
/// in `path_view` form. A path that does not spell the name is not listed.
fn build_paths_naming(name: &str) -> Vec<Vec<u8>> {
    let mut roots = vec![
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        PathBuf::from(BINARY),
    ];
    for variable in ["CARGO_HOME", "RUSTUP_HOME", "HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(variable) {
            roots.push(PathBuf::from(value));
        }
    }
    let mut paths: Vec<Vec<u8>> = Vec::new();
    for root in roots {
        let resolved = std::fs::canonicalize(&root).ok();
        for form in std::iter::once(root).chain(resolved) {
            for ancestor in form.ancestors().filter(|path| path.is_absolute()) {
                let text = ancestor.to_string_lossy();
                let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
                let path = path_view(text.as_bytes());
                if contains(&path, name.as_bytes()) && !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
    }
    paths
}

/// Offsets of each occurrence of `name` in `view` that no occurrence of one
/// of `paths` covers: the name as the program spells it, not as part of a
/// build path.
fn unexplained_occurrences(view: &[u8], name: &[u8], paths: &[Vec<u8>]) -> Vec<usize> {
    let covered = |at: usize| {
        paths.iter().any(|path| {
            path.windows(name.len())
                .enumerate()
                .filter(|(_, window)| *window == name)
                .any(|(offset, _)| {
                    at >= offset
                        && view
                            .get(at - offset..at - offset + path.len())
                            .is_some_and(|found| found == path.as_slice())
                })
        })
    };
    view.windows(name.len())
        .enumerate()
        .filter(|(at, window)| *window == name && !covered(*at))
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn only_the_known_build_paths_explain_the_name() {
    let name = b"other";
    let paths = vec![path_view(br"C:\Work\Other-Client\tools")];
    let view = path_view(
        br"x C:\work\other-client\tools\k.rs y c:/WORK/OTHER-CLIENT/TOOLS/t \\?\C:\Work\Other-Client\tools z",
    );
    assert!(unexplained_occurrences(&view, name, &paths).is_empty());
    // The bare name, a different directory, or a shorter prefix of the path
    // are the program's own text.
    for text in [
        &b"an Other name"[..],
        b"C:/work/other-clients/tools",
        b"C:/work/other-client/",
        b"/work/other-client/tools other",
    ] {
        assert!(
            !unexplained_occurrences(&path_view(text), name, &paths).is_empty(),
            "{}",
            String::from_utf8_lossy(text)
        );
    }
}

/// The program itself carries no other distribution's name, wherever it is
/// built. A build below a directory that spells the name (as the workspace's
/// CI checkout does) embeds that directory in debug information, so exactly
/// those build paths are set aside; every other occurrence, in any case,
/// fails the test.
#[test]
fn the_program_carries_no_other_distribution_name() {
    let other = other_brand();
    let bytes = std::fs::read(BINARY).unwrap();
    assert!(contains(&bytes, b"AITP local installation CA"));
    let view = path_view(&bytes);
    let paths = build_paths_naming(&other);
    let unexplained = unexplained_occurrences(&view, other.as_bytes(), &paths);
    let context: Vec<String> = unexplained
        .iter()
        .take(5)
        .map(|&at| {
            let around = &bytes[at.saturating_sub(60)..(at + 60).min(bytes.len())];
            String::from_utf8_lossy(around).escape_debug().to_string()
        })
        .collect();
    assert!(
        unexplained.is_empty(),
        "{} occurrence(s) outside the build paths {:?}: {context:#?}",
        unexplained.len(),
        paths
            .iter()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>()
    );
}

/// An installation CA of another program built on this kernel ("OTHER"),
/// with its key when `key` is given.
fn other_installation_ca_with_key(path: &Path, key_path: Option<&Path>) {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "OTHER local installation CA 0123abcd");
    name.push(DnType::OrganizationName, "OTHER");
    params.distinguished_name = name;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, params.self_signed(&key).unwrap().pem()).unwrap();
    if let Some(key_path) = key_path {
        std::fs::write(key_path, key.serialize_pem()).unwrap();
    }
}

fn other_installation_ca(path: &Path) {
    other_installation_ca_with_key(path, None);
}

/// The placeholder login of another program built on this kernel.
fn other_placeholder_login() -> String {
    use base64::Engine;
    let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
    format!(
        "{}.{}.{}",
        encode(r#"{"alg":"none","typ":"JWT"}"#),
        encode(
            r#"{"email":"other-local-proxy@invalid","https://api.openai.com/auth":{"chatgpt_account_id":"other-local-proxy-account"}}"#
        ),
        encode("other-local-proxy")
    )
}

fn snapshot(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

/// aitp refuses to take over a configuration another local proxy program
/// manages, before it writes anything, and says how to proceed.
#[test]
fn aitp_does_not_take_over_another_programs_configuration() {
    let gateway = "http://127.0.0.1:9";
    let refused = |sandbox: &Sandbox, args: &[&str]| {
        let (success, text) = sandbox.output(&mut sandbox.command(args));
        assert!(!success, "aitp {args:?} succeeded:\n{text}");
        assert!(
            text.contains("is managed by another local proxy program")
                || text.contains("another local proxy program; AITP does not use it"),
            "{text}"
        );
        assert!(
            text.contains("CLAUDE_CONFIG_DIR or CODEX_HOME") || text.contains("separate AITP home"),
            "{text}"
        );
        assert!(!sandbox.home.join(".aitp").join("config.json").exists());
        text
    };

    // Claude: a local proxy with another program's installation CA.
    let sandbox = Sandbox::new();
    let ca = sandbox.home.join("other/other-ca.crt");
    other_installation_ca(&ca);
    let settings = sandbox.home.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(
        &settings,
        serde_json::to_vec(&serde_json::json!({"env": {
            "https_proxy": "http://127.0.0.1:4000",
            "NODE_EXTRA_CA_CERTS": ca,
        }}))
        .unwrap(),
    )
    .unwrap();
    let before = snapshot(&settings);
    refused(
        &sandbox,
        &["init", "--base-url", gateway, "--api-key", "TEST_ONLY_AITP"],
    );
    assert_eq!(snapshot(&settings), before);

    // Codex: another program's managed block.
    let sandbox = Sandbox::new();
    let env = sandbox.home.join(".codex").join(".env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(
        &env,
        "# BEGIN OTHER CODEX IDE (managed)\nHTTPS_PROXY=\"http://127.0.0.1:4000\"\nhttps_proxy=\"http://127.0.0.1:4000\"\n# END OTHER CODEX IDE (managed)\n",
    )
    .unwrap();
    let before = snapshot(&env);
    refused(
        &sandbox,
        &[
            "init-codex",
            "--base-url",
            gateway,
            "--api-key",
            "TEST_ONLY_AITP",
        ],
    );
    assert_eq!(snapshot(&env), before);
    assert!(!sandbox.home.join(".codex/auth.json").exists());

    // Codex: signed in with another program's placeholder.
    let sandbox = Sandbox::new();
    let auth = sandbox.home.join(".codex").join("auth.json");
    std::fs::create_dir_all(auth.parent().unwrap()).unwrap();
    let token = other_placeholder_login();
    std::fs::write(
        &auth,
        serde_json::to_vec(&serde_json::json!({"auth_mode": "chatgpt", "tokens": {"access_token": token, "id_token": token}}))
            .unwrap(),
    )
    .unwrap();
    let before = snapshot(&auth);
    refused(
        &sandbox,
        &[
            "init-codex",
            "--base-url",
            gateway,
            "--api-key",
            "TEST_ONLY_AITP",
        ],
    );
    assert_eq!(snapshot(&auth), before);

    // The editor: another program's live proxy marker.
    let sandbox = Sandbox::new();
    let editor = sandbox.root.join("vscode/user-data/User/settings.json");
    std::fs::create_dir_all(editor.parent().unwrap()).unwrap();
    std::fs::write(
        &editor,
        "{\n // OTHER managed VSCode proxy: http://127.0.0.1:4000\n \"http.proxy\": \"http://127.0.0.1:4000\"\n}\n",
    )
    .unwrap();
    let before = snapshot(&editor);
    let (success, text) = sandbox.output(
        sandbox
            .command(&["vscode"])
            .env("VSCODE_PORTABLE", sandbox.root.join("vscode")),
    );
    assert!(!success, "{text}");
    assert!(
        text.contains("is managed by another local proxy program"),
        "{text}"
    );
    assert_eq!(snapshot(&editor), before);
}

/// aitp does not use another program's installation CA as its own, even
/// when its configuration names it.
#[test]
fn aitp_does_not_use_another_programs_ca() {
    let sandbox = Sandbox::new();
    let gateway = "http://127.0.0.1:9";
    sandbox.run(&["init", "--base-url", gateway, "--api-key", "TEST_ONLY_AITP"]);
    let config = read_json(&sandbox.home.join(".aitp/config.json"));
    let ca = PathBuf::from(config["ca_cert_path"].as_str().unwrap());
    let key = PathBuf::from(config["ca_key_path"].as_str().unwrap());
    other_installation_ca_with_key(&ca, Some(&key));
    let (success, text) = sandbox.output(&mut sandbox.command(&[
        "init",
        "--base-url",
        gateway,
        "--api-key",
        "TEST_ONLY_AITP",
    ]));
    assert!(!success, "{text}");
    assert!(
        text.contains("is the installation CA of \"OTHER\""),
        "{text}"
    );
    // The proxy itself (it reads the CA when it starts) refuses too.
    let (success, text) = sandbox.output(&mut sandbox.command(&[]));
    assert!(!success, "{text}");
    assert!(
        text.contains("is the installation CA of \"OTHER\""),
        "{text}"
    );
}

/// Without any other program's remains, initialization works as before.
#[test]
fn aitp_initializes_over_its_own_and_unrelated_settings() {
    let sandbox = Sandbox::new();
    let settings = sandbox.home.join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    // A corporate proxy and CA that are not an installation of this kernel.
    std::fs::write(
        &settings,
        r#"{"env": {"https_proxy": "http://10.0.0.1:3128", "NODE_EXTRA_CA_CERTS": "/etc/ssl/corporate.pem"}}"#,
    )
    .unwrap();
    let args = [
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_AITP",
    ];
    sandbox.run(&args);
    sandbox.run(&args);
}

/// Holds the installation-directory lock of `bin` the way an update does
/// (Unix: the directory; Windows: its lock file, or the helper lock).
fn hold_installation_lock(bin: &Path, file: &str) -> std::fs::File {
    #[cfg(unix)]
    {
        let _ = file;
        let directory = std::fs::File::open(bin).unwrap();
        directory.try_lock().unwrap();
        directory
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .share_mode(0)
            .open(bin.join(file))
            .unwrap()
    }
}

/// While an update (or, on Windows, its replacement helper) holds the
/// installation directory, neither another update nor `uninstall` starts:
/// both fail before any request or change.
#[test]
fn update_and_uninstall_wait_for_a_held_installation() {
    let sandbox = Sandbox::new();
    sandbox.run(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_AITP",
    ]);
    let bin = sandbox.program.parent().unwrap().to_path_buf();
    let config = sandbox.home.join(".aitp").join("config.json");
    let config_before = snapshot(&config);
    let program_before = snapshot(&sandbox.program);
    let mut held = vec![(
        ".aitp-update-lock",
        "another aitp update or uninstall is running",
    )];
    if cfg!(windows) {
        held.push((
            ".aitp-update-helper-lock",
            "a previous aitp update is still being installed",
        ));
    }
    for (file, expected) in held {
        let lock = hold_installation_lock(&bin, file);
        let (port, seen) = refusing_proxy();
        let (success, text) = sandbox.output(
            sandbox
                .command(&["update"])
                .env("AITP_UPSTREAM_PROXY", format!("http://127.0.0.1:{port}")),
        );
        assert!(!success, "{text}");
        assert!(text.contains(expected), "{file}: {text}");
        assert!(seen.lock().unwrap().is_empty(), "{file}: {text}");

        let (success, text) = sandbox.output(&mut sandbox.command(&["uninstall", "--yes"]));
        assert!(!success, "{text}");
        assert!(text.contains(expected), "{file}: {text}");
        assert!(
            text.contains(
                "uninstall stopped before changing any configuration, service or program file"
            ),
            "{text}"
        );
        assert_eq!(snapshot(&config), config_before, "{file}");
        assert_eq!(snapshot(&sandbox.program), program_before, "{file}");
        drop(lock);
    }
    // Released: uninstall removes the program and (Windows) the lock files
    // it held meanwhile.
    let text = sandbox.run(&["uninstall", "--yes"]);
    let left: Vec<_> = std::fs::read_dir(&bin)
        .map(|entries| entries.map(|entry| entry.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "{left:?}\n{text}");
    assert!(!config.exists(), "{text}");
    sandbox.assert_only_aitp_names();
}

// ------------------------------------------------- Full update, no GitHub

/// A test CA (PEM) and a TLS server configuration for the release hosts,
/// signed by it. Only the program under test is told to trust the CA
/// (`SSL_CERT_FILE` in its own environment).
fn release_pki() -> (String, std::sync::Arc<rustls::ServerConfig>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Release Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![
        "github.com".to_string(),
        "release-assets.githubusercontent.com".to_string(),
    ])
    .unwrap()
    .signed_by(&leaf_key, &ca, &ca_key)
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(leaf.der().to_vec())],
        rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (ca.pem(), std::sync::Arc::new(config))
}

/// The program's upstream proxy: it accepts each CONNECT, plays the release
/// host itself (TLS with the test CA) and answers from `routes` (path ->
/// status, Location, body). Records `CONNECT <target>` and `<path>` lines.
fn release_proxy(
    config: std::sync::Arc<rustls::ServerConfig>,
    routes: std::collections::HashMap<String, (u16, String, Vec<u8>)>,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let routes = Arc::new(routes);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let config = Arc::clone(&config);
            let routes = Arc::clone(&routes);
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let read_head = |stream: &mut dyn Read| {
                    let mut head = Vec::new();
                    let mut byte = [0_u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && stream.read_exact(&mut byte).is_ok() {
                        head.push(byte[0]);
                    }
                    String::from_utf8_lossy(&head).into_owned()
                };
                let connect = read_head(&mut stream);
                let target = connect.split_whitespace().nth(1).unwrap_or_default();
                log.lock().unwrap().push(format!("CONNECT {target}"));
                if !connect.starts_with("CONNECT ") || !target.ends_with(":443") {
                    let _ =
                        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
                    return;
                }
                if stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                let Ok(connection) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let request = read_head(&mut tls);
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                log.lock().unwrap().push(path.clone());
                let (status, location, body) =
                    routes
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, String::new(), b"missing".to_vec()));
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {}\r\n",
                    body.len()
                );
                if !location.is_empty() {
                    head.push_str(&format!("Location: {location}\r\n"));
                }
                head.push_str("\r\n");
                let _ = tls.write_all(head.as_bytes());
                let _ = tls.write_all(&body);
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    (port, seen)
}

/// This platform's release asset name.
fn asset_name() -> String {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-aarch64",
        ("windows", "x86_64") => "windows-x86_64.exe",
        ("windows", "aarch64") => "windows-aarch64.exe",
        (os, arch) => panic!("no release asset for {os} {arch}"),
    };
    format!("aitp-{platform}")
}

/// A minimal static Linux program that prints `message` and exits 0,
/// padded past the 1 MiB release minimum. (The debug build of the real
/// program is larger than the 64 MiB release maximum.)
#[cfg(target_os = "linux")]
fn tiny_linux_program(message: &str) -> Vec<u8> {
    let message = message.as_bytes();
    let length = u32::try_from(message.len()).unwrap();
    let (machine, code): (u16, Vec<u8>) = match std::env::consts::ARCH {
        "x86_64" => {
            let mut code = vec![0xb8, 1, 0, 0, 0]; // mov eax, 1 (write)
            code.extend([0xbf, 1, 0, 0, 0]); // mov edi, 1
            code.extend([0x48, 0x8d, 0x35, 16, 0, 0, 0]); // lea rsi, [rip + 16]
            code.push(0xba); // mov edx, length
            code.extend(length.to_le_bytes());
            code.extend([0x0f, 0x05]); // syscall
            code.extend([0xb8, 60, 0, 0, 0]); // mov eax, 60 (exit)
            code.extend([0x31, 0xff]); // xor edi, edi
            code.extend([0x0f, 0x05]); // syscall
            assert_eq!(code.len(), 33);
            (62, code)
        }
        "aarch64" => {
            let words: [u32; 8] = [
                0xd280_0020,                 // mov x0, #1
                0x1000_00e1,                 // adr x1, .+28 (the message)
                0xd280_0002 | (length << 5), // mov x2, #length
                0xd280_0808,                 // mov x8, #64 (write)
                0xd400_0001,                 // svc #0
                0xd280_0000,                 // mov x0, #0
                0xd280_0ba8,                 // mov x8, #93 (exit)
                0xd400_0001,                 // svc #0
            ];
            (
                183,
                words.iter().flat_map(|word| word.to_le_bytes()).collect(),
            )
        }
        arch => panic!("no test program for {arch}"),
    };
    const BASE: u64 = 0x40_0000;
    const CODE: u64 = 64 + 56;
    let end = CODE + (code.len() + message.len()) as u64;
    let mut program = Vec::new();
    program.extend(b"\x7fELF\x02\x01\x01\x00");
    program.extend([0; 8]);
    program.extend(2_u16.to_le_bytes()); // executable
    program.extend(machine.to_le_bytes());
    program.extend(1_u32.to_le_bytes());
    program.extend((BASE + CODE).to_le_bytes()); // entry
    program.extend(64_u64.to_le_bytes()); // program headers
    program.extend(0_u64.to_le_bytes()); // no section headers
    program.extend(0_u32.to_le_bytes());
    for value in [64_u16, 56, 1, 64, 0, 0] {
        program.extend(value.to_le_bytes());
    }
    program.extend(1_u32.to_le_bytes()); // PT_LOAD
    program.extend(5_u32.to_le_bytes()); // read + execute
    for value in [0, BASE, BASE, end, end, 0x1_0000] {
        program.extend(value.to_le_bytes());
    }
    assert_eq!(program.len() as u64, CODE);
    program.extend(code);
    program.extend(message);
    program.resize(1024 * 1024 + 4096, 0);
    program
}

/// A program for this platform that reports `aitp <this version>`: on
/// Linux a minimal one, elsewhere the real program with trailing padding
/// (so its hash differs from the installed copy).
fn candidate_program(sandbox: &Sandbox) -> Vec<u8> {
    #[cfg(target_os = "linux")]
    {
        let _ = sandbox;
        tiny_linux_program(&format!("aitp {}\n", env!("CARGO_PKG_VERSION")))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut program = std::fs::read(&sandbox.program).unwrap();
        program.extend([0_u8; 4096]);
        assert!(
            program.len() <= 64 * 1024 * 1024,
            "the test program ({} bytes) exceeds the 64 MiB release limit",
            program.len()
        );
        program
    }
}

/// The release of `version` with `asset` for this platform, published like
/// GitHub's: the versioned asset redirects to the asset host.
fn release_routes(
    version: &str,
    asset: &[u8],
) -> std::collections::HashMap<String, (u16, String, Vec<u8>)> {
    use sha2::Digest;
    let sha256: String = sha2::Sha256::digest(asset)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let name = asset_name();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "version": version,
        "assets": { &name: { "sha256": sha256, "size": asset.len() } },
    }))
    .unwrap();
    std::collections::HashMap::from([
        (
            "/2742zdz/AITP/releases/latest/download/aitp-manifest.json".to_string(),
            (200, String::new(), manifest),
        ),
        (
            format!("/2742zdz/AITP/releases/download/v{version}/{name}"),
            (
                302,
                "https://release-assets.githubusercontent.com/asset?sig=1".to_string(),
                Vec::new(),
            ),
        ),
        (
            "/asset?sig=1".to_string(),
            (200, String::new(), asset.to_vec()),
        ),
    ])
}

/// Runs `aitp update` against `routes` (no GitHub: the proxy plays it).
fn update_from(
    sandbox: &Sandbox,
    routes: std::collections::HashMap<String, (u16, String, Vec<u8>)>,
) -> (bool, String, Vec<String>) {
    let (ca_pem, config) = release_pki();
    let ca = sandbox.root.join("release-test-ca.pem");
    std::fs::write(&ca, ca_pem).unwrap();
    let (port, seen) = release_proxy(config, routes);
    let (success, text) = sandbox.output(
        sandbox
            .command(&["update"])
            .env("AITP_UPSTREAM_PROXY", format!("http://127.0.0.1:{port}"))
            .env("SSL_CERT_FILE", &ca),
    );
    let requests = seen.lock().unwrap().clone();
    (success, text, requests)
}

/// An installation-directory lock file (Windows), which stays.
fn is_lock_file(name: &str) -> bool {
    name.starts_with(".aitp-update-") && name.ends_with("lock")
}

/// Files the update left next to the program, other than the program.
fn left_beside(sandbox: &Sandbox) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(sandbox.program.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| Path::new(name) != sandbox.program.file_name().unwrap())
        .collect();
    names.sort();
    names
}

/// The whole `aitp update` over HTTPS: manifest, redirected asset, sha256
/// and size checks, candidate probe, and replacement (on Windows by the
/// replacement helper, which reports through its status file).
#[test]
fn update_downloads_probes_and_replaces_the_program() {
    let sandbox = Sandbox::new();
    let before = snapshot(&sandbox.program);
    let candidate = candidate_program(&sandbox);
    let version = env!("CARGO_PKG_VERSION");
    let (success, text, requests) = update_from(&sandbox, release_routes(version, &candidate));
    assert!(success, "{text}\n{requests:?}");
    assert_eq!(
        requests,
        [
            "CONNECT github.com:443".to_string(),
            "/2742zdz/AITP/releases/latest/download/aitp-manifest.json".to_string(),
            "CONNECT github.com:443".to_string(),
            format!(
                "/2742zdz/AITP/releases/download/v{version}/{}",
                asset_name()
            ),
            "CONNECT release-assets.githubusercontent.com:443".to_string(),
            "/asset?sig=1".to_string(),
        ],
        "{text}"
    );
    assert!(
        text.contains("Same version but local binary hash differs"),
        "{text}"
    );
    #[cfg(not(windows))]
    {
        assert!(text.contains(&format!("Updated: aitp {version}")), "{text}");
        assert_eq!(snapshot(&sandbox.program), candidate);
    }
    #[cfg(windows)]
    {
        assert!(text.contains("Update staged"), "{text}");
        let status = sandbox
            .program
            .parent()
            .unwrap()
            .join(".aitp-update-status.txt");
        let deadline = Instant::now() + Duration::from_secs(120);
        let report = loop {
            let report = std::fs::read_to_string(&status).unwrap_or_default();
            let report = report.trim_start_matches('\u{feff}').trim().to_string();
            if report.starts_with("updated:") || report.starts_with("failed:") {
                break report;
            }
            assert!(Instant::now() < deadline, "helper still {report:?}");
            std::thread::sleep(Duration::from_millis(200));
        };
        assert!(report.starts_with("updated:"), "{report}");
        // The helper removes its script last; give it a moment.
        let deadline = Instant::now() + Duration::from_secs(30);
        while left_beside(&sandbox)
            .iter()
            .any(|name| name.ends_with(".ps1"))
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(200));
        }
        assert_eq!(snapshot(&sandbox.program), candidate);
    }
    // The previous program is kept as a backup; no candidate is left.
    let left = left_beside(&sandbox);
    let backups: Vec<_> = left
        .iter()
        .filter(|name| name.starts_with("aitp.bak-"))
        .collect();
    assert_eq!(backups.len(), 1, "{left:?}");
    let backup = sandbox.program.parent().unwrap().join(backups[0]);
    assert_eq!(snapshot(&backup), before);
    assert!(
        left.iter().all(|name| name.starts_with("aitp.bak-")
            || is_lock_file(name)
            || name == ".aitp-update-status.txt"),
        "{left:?}"
    );
    // (The backup is a copy of the test build, which may carry its build
    // path; only the output is checked here.)
    let other = other_brand();
    assert!(!text.to_ascii_lowercase().contains(&other), "{text}");
}

/// A release whose program reports another version than its manifest is
/// not installed: the program is unchanged and the candidate removed.
#[test]
fn update_refuses_a_program_that_reports_another_version() {
    let sandbox = Sandbox::new();
    let before = snapshot(&sandbox.program);
    // The candidate reports this version; the manifest names the next.
    let candidate = candidate_program(&sandbox);
    let mut parts: Vec<u64> = env!("CARGO_PKG_VERSION")
        .split('.')
        .map(|part| part.parse().unwrap())
        .collect();
    parts[2] += 1;
    let next = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    let (success, text, requests) = update_from(&sandbox, release_routes(&next, &candidate));
    assert!(!success, "{text}");
    assert!(
        text.contains(&format!(
            "Downloading: https://github.com/2742zdz/AITP/releases/download/v{next}/"
        )),
        "{text}\n{requests:?}"
    );
    assert!(
        text.contains("downloaded binary did not report a AITP version"),
        "{text}"
    );
    assert_eq!(snapshot(&sandbox.program), before);
    let left = left_beside(&sandbox);
    assert!(left.iter().all(|name| is_lock_file(name)), "{left:?}");
    sandbox.assert_only_aitp_names();
}
