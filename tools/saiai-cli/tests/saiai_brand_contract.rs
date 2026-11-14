//! Black-box SAIAI contract: run the built `saiai` binary in a throwaway home
//! and freeze what existing installations depend on (binary name, version
//! output, `~/.saiai` layout, config JSON, CA identity, Codex files,
//! environment isolation). Expected values are hand-written literals, except
//! the release version (read from Cargo.toml), the CA suffix (hash of the
//! generated key) and environment digests of temporary paths; see
//! `tests/saiai_render_contract.rs`, `tests/saiai_source_contract.rs` and the
//! client proof module's tests for the in-process half of the contract.

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

/// The running proxy enrolls its client proof device with the configured
/// Gateway and reports the released program version (supplied by the
/// binary's entry point, not the library's package metadata).
#[test]
fn client_proof_enrollment_reports_the_release_version() {
    use std::io::{Read, Write};
    let sandbox = Sandbox::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    // Bounded mock Gateway: answers until it has seen one enrollment or the
    // deadline passes, so the thread always ends and can be joined.
    listener.set_nonblocking(true).unwrap();
    let gateway_thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(_) => continue,
            };
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let length = text[..split]
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&request).to_string();
            let enrollment = text.starts_with("POST /api/v1/client/devices/enroll ");
            let (status, body) = if enrollment {
                (
                    "200 OK",
                    r#"{"device_id":"cd_DDDDDDDDDDDDDDDDDDDDDD","status":"active"}"#,
                )
            } else {
                ("404 Not Found", "{}")
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            if enrollment {
                let _ = sender.send(text);
                return;
            }
        }
    });
    sandbox.run(&mut sandbox.command(&[
        "init-codex",
        "--base-url",
        &gateway,
        "--api-key",
        "TEST_ONLY_CONTRACT_PROOF",
    ]));
    let log = sandbox.home.with_file_name("proxy.log");
    let file = std::fs::File::create(&log).unwrap();
    let mut proxy = sandbox
        .command(&[])
        .env("SAIAI_UPSTREAM_PROXY", "direct")
        .stdout(file.try_clone().unwrap())
        .stderr(file)
        .spawn()
        .unwrap();
    let request = receiver.recv_timeout(Duration::from_secs(60));
    let _ = proxy.kill();
    let _ = proxy.wait();
    let _ = gateway_thread.join();
    let request = request.unwrap_or_else(|_| {
        panic!(
            "no enrollment within 60 s; proxy log:\n{}",
            String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default())
        )
    });
    let body: serde_json::Value =
        serde_json::from_str(&request[request.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(body["client_version"], release_version().as_str());
}

/// The running SAIAI proxy signs Gateway requests with its device proof and
/// never relays a proof header a client sent.
#[test]
fn proxy_signs_gateway_requests_and_strips_inbound_proofs() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let sandbox = Sandbox::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_gateway = Arc::clone(&stop);
    let gateway_thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline && !stop_gateway.load(Ordering::SeqCst) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(_) => continue,
            };
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let length = text[..split]
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&request).to_string();
            let body = if text.starts_with("POST /api/v1/client/devices/enroll ") {
                r#"{"device_id":"cd_EEEEEEEEEEEEEEEEEEEEEE","status":"active"}"#
            } else {
                "{}"
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            if sender.send(text).is_err() {
                return;
            }
        }
    });
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        &gateway,
        "--api-key",
        "TEST_ONLY_CONTRACT_SIGNED",
    ]));
    let config = read_json(&sandbox.home.join(".saiai/config.json"));
    let listen = config["listen"].as_str().unwrap().to_string();
    let ca = std::fs::read(config["ca_cert_path"].as_str().unwrap()).unwrap();
    let log = sandbox.home.with_file_name("signing-proxy.log");
    let file = std::fs::File::create(&log).unwrap();
    let mut proxy = sandbox
        .command(&[])
        .env("SAIAI_UPSTREAM_PROXY", "direct")
        .stdout(file.try_clone().unwrap())
        .stderr(file)
        .spawn()
        .unwrap();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(&ca)) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let send = || -> Option<()> {
        let mut tcp = std::net::TcpStream::connect(&listen).ok()?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
        tcp.write_all(
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n",
        )
        .ok()?;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).ok()?;
            head.push(byte[0]);
        }
        let connection = rustls::ClientConnection::new(
            Arc::clone(&tls),
            "api.anthropic.com".try_into().unwrap(),
        )
        .ok()?;
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        stream
            .write_all(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nX-Saiai-Client-Proof: v1.MOCK_SPOOFED\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}")
            .ok()?;
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        Some(())
    };

    // Enrollment first, then requests until the device record is in use.
    let mut forwarded = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline && forwarded.is_none() {
        let _ = send();
        while let Ok(request) = receiver.recv_timeout(Duration::from_millis(500)) {
            if request.starts_with("POST /v1/messages ")
                && request
                    .to_ascii_lowercase()
                    .contains("x-saiai-client-proof: v1.cd_eeee")
            {
                forwarded = Some(request);
            }
        }
    }
    let _ = proxy.kill();
    let _ = proxy.wait();
    stop.store(true, Ordering::SeqCst);
    drop(receiver);
    let _ = gateway_thread.join();
    let request = forwarded.unwrap_or_else(|| {
        panic!(
            "no signed Gateway request within 60 s; proxy log:\n{}",
            String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default())
        )
    });
    let proofs = request
        .lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .starts_with("x-saiai-client-proof:")
        })
        .collect::<Vec<_>>();
    assert_eq!(proofs.len(), 1, "{request}");
    assert!(!proofs[0].contains("MOCK_SPOOFED"), "{request}");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer test_only_contract_signed"),
        "{request}"
    );
}

/// Kills a spawned proxy however the test ends.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The running proxy answers the certificate control request that
/// `saiai desktop` sends: a fixed host, a fixed status line and header name,
/// and one base64 SHA-256 SPKI pin per managed Desktop host, the first being
/// the leaf actually served for `api.openai.com`. On Linux the client side is
/// exercised too: `saiai desktop` reads the pins over the same request and
/// passes them to the Desktop executable.
#[test]
fn certificate_control_endpoint_is_frozen() {
    use base64::Engine as _;
    use std::io::{Read, Write};
    use std::sync::Arc;
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_CONTROL",
    ]));
    let config = read_json(&sandbox.home.join(".saiai/config.json"));
    let listen = config["listen"].as_str().unwrap().to_string();
    let ca = std::fs::read(config["ca_cert_path"].as_str().unwrap()).unwrap();
    let log = sandbox.home.with_file_name("control-proxy.log");
    let file = std::fs::File::create(&log).unwrap();
    let proxy = KillOnDrop(
        sandbox
            .command(&[])
            .env("SAIAI_UPSTREAM_PROXY", "direct")
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap(),
    );

    let connect = |host: &str| -> Option<(std::net::TcpStream, String)> {
        let mut tcp = std::net::TcpStream::connect(&listen).ok()?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
        tcp.set_write_timeout(Some(Duration::from_secs(10))).ok()?;
        tcp.write_all(
            format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
        )
        .ok()?;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 4096 {
            tcp.read_exact(&mut byte).ok()?;
            head.push(byte[0]);
        }
        Some((tcp, String::from_utf8(head).ok()?))
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let control = loop {
        if let Some((_, head)) = connect("certificate.saiai.local") {
            break Some(head);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let served = control.as_ref().and_then(|_| {
        let (tcp, _) = connect("api.openai.com")?;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(&ca)) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let tls = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connection =
            rustls::ClientConnection::new(tls, "api.openai.com".try_into().unwrap()).ok()?;
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).ok()?;
        }
        let leaf = stream.conn.peer_certificates()?.first()?.as_ref().to_vec();
        let (_, certificate) = x509_parser::parse_x509_certificate(&leaf).ok()?;
        Some(
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(certificate.public_key().raw)),
        )
    });
    // The Linux launcher with a stand-in Desktop executable that records
    // its arguments.
    #[cfg(target_os = "linux")]
    let launched = control.as_ref().map(|_| {
        use std::os::unix::fs::PermissionsExt;
        let recorder = sandbox.home.with_file_name("desktop-recorder.sh");
        let recorded = sandbox.home.with_file_name("desktop-args.txt");
        std::fs::write(
            &recorder,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CONTRACT_DESKTOP_ARGS\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&recorder, std::fs::Permissions::from_mode(0o755)).unwrap();
        sandbox.run(
            sandbox
                .command(&["desktop"])
                .env("SAIAI_CHATGPT_BIN", &recorder)
                .env("CONTRACT_DESKTOP_ARGS", &recorded)
                .env_remove("SAIAI_CHATGPT_TIMEZONE"),
        );
        std::fs::read_to_string(&recorded).unwrap()
    });
    drop(proxy);
    let head = control.unwrap_or_else(|| {
        panic!(
            "no control response within 60 s; proxy log:\n{}",
            String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default())
        )
    });
    let pins = head
        .strip_prefix("HTTP/1.1 200 Connection Established\r\nx-saiai-leaf-spki-sha256: ")
        .and_then(|rest| rest.strip_suffix("\r\nConnection: close\r\n\r\n"))
        .unwrap_or_else(|| panic!("{head:?}"))
        .split(',')
        .collect::<Vec<_>>();
    assert_eq!(pins.len(), 4, "{head:?}");
    for pin in &pins {
        let digest = base64::engine::general_purpose::STANDARD
            .decode(pin)
            .unwrap_or_else(|error| panic!("{pin}: {error}"));
        assert_eq!(digest.len(), 32, "{pin}");
    }
    assert_eq!(served.as_deref(), Some(pins[0]), "{head:?}");
    #[cfg(target_os = "linux")]
    {
        let launched = launched.unwrap();
        let expected = format!("--ignore-certificate-errors-spki-list={}", pins.join(","));
        assert!(launched.lines().any(|line| line == expected), "{launched}");
    }
}

/// `saiai uninstall --dry-run --yes` prints the plan under the SAIAI heading
/// and changes nothing. The full uninstall lifecycle (refusals, `--yes`,
/// unknown environments, legacy layouts) runs against the real binary in
/// `scripts/saiai-cli/test-uninstall.py` on Linux CI.
#[test]
fn uninstall_dry_run_plan_is_frozen() {
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_UNINSTALL",
    ]));
    let root = sandbox.home.join(".saiai");
    let before = std::fs::read(root.join("config.json")).unwrap();
    let output = sandbox.run(&mut sandbox.command(&["uninstall", "--dry-run", "--yes"]));
    let rest = output
        .strip_prefix("SAIAI uninstall plan\nSAIAI home: ")
        .unwrap_or_else(|| panic!("{output}"));
    let (home, _) = rest.split_once('\n').unwrap();
    assert!(same_path(home, &root), "{output}");
    assert!(
        output.ends_with("\nDry run: nothing was changed.\n"),
        "{output}"
    );
    assert_eq!(std::fs::read(root.join("config.json")).unwrap(), before);
    assert!(
        sandbox.home.join(".claude/saiai-ca.crt").exists(),
        "{output}"
    );
}

/// Byte goldens of the running program's Claude Desktop listener (Linux):
/// status line, header order, Content-Length, CRLF and body of its own
/// answers with the SAIAI names, written by the production HTTP path. The
/// organization id is random, so it is compared as `<ORG-UUID>`.
#[cfg(target_os = "linux")]
#[test]
fn claude_desktop_listener_answers_are_byte_identical() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:1",
        "--api-key",
        "TEST_ONLY_CONTRACT_DESKTOP",
    ]));
    let root = sandbox.home.join(".saiai");
    let config = read_json(&root.join("config.json"));
    let ca = std::fs::read(config["ca_cert_path"].as_str().unwrap()).unwrap();
    let state = root.join("desktop/claude/state");
    std::fs::create_dir_all(&state).unwrap();
    let hex = || uuid::Uuid::new_v4().simple().to_string();
    let org = uuid::Uuid::new_v4().to_string();
    let access = format!("saiai-desktop-claude-{}{}", hex(), hex());
    let session = format!("saiai-local-{}{}", hex(), hex());
    let identity = serde_json::json!({
        "account": uuid::Uuid::new_v4().to_string(),
        "organization": org,
        "access_token": access,
        "refresh_token": format!("saiai-desktop-claude-refresh-{}", hex()),
        "session": session,
    });
    std::fs::write(
        state.join("identity.json"),
        serde_json::to_vec(&identity).unwrap(),
    )
    .unwrap();

    let log = sandbox.home.with_file_name("desktop-proxy.log");
    let file = std::fs::File::create(&log).unwrap();
    let mut proxy = KillOnDrop(
        sandbox
            .command(&[])
            .env("SAIAI_UPSTREAM_PROXY", "direct")
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap(),
    );
    // The listener writes its receipt after binding.
    let receipt = state.join("proxy.json");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !receipt.is_file() {
        let exited = proxy.0.try_wait().unwrap();
        if exited.is_some() || Instant::now() >= deadline {
            panic!(
                "no Claude Desktop listener receipt (proxy exit: {exited:?}); proxy log:\n{}",
                String::from_utf8_lossy(&std::fs::read(&log).unwrap_or_default())
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let listen = read_json(&receipt)["listen"].as_str().unwrap().to_string();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(&ca)) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let request = |host: &str, request: &str| -> String {
        let mut tcp = std::net::TcpStream::connect(&listen).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        assert_eq!(head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let connection =
            rustls::ClientConnection::new(Arc::clone(&tls), host.to_string().try_into().unwrap())
                .unwrap();
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        // The proxy closes the connection after its answer; a TLS close
        // without close_notify is tolerated, a timeout or other error is not.
        match stream.read_to_end(&mut response) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Err(error) => panic!("reading the {host} answer failed: {error}"),
        }
        String::from_utf8(response).unwrap()
    };

    assert_eq!(
        request(
            "api.anthropic.com",
            &format!(
                "GET /api/oauth/profile HTTP/1.1\r\nAuthorization: Bearer {access}\r\nConnection: close\r\n\r\n"
            ),
        )
        .replace(org.as_str(), "<ORG-UUID>"),
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 312\r\nContent-Type: application/json\r\n\r\n{\"account\":{\"display_name\":\"SAIAI Local Code\",\"email_address\":\"\"},\"organization\":{\"active_flags\":[],\"capabilities\":[\"chat\",\"claude_pro\",\"claude_code\"],\"created_at\":\"2026-01-01T00:00:00Z\",\"name\":\"SAIAI Local Code\",\"rate_limit_tier\":\"default_claude_ai\",\"settings\":{},\"uuid\":\"<ORG-UUID>\"}}"
    );
    assert_eq!(
        request(
            "claude.ai",
            &format!(
                "GET /api/zzz_unknown HTTP/1.1\r\nCookie: sessionKey={session}\r\nConnection: close\r\n\r\n"
            ),
        ),
        "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 120\r\nContent-Type: application/json\r\n\r\n{\"error\":{\"message\":\"This Desktop control endpoint is unavailable through SAIAI.\",\"type\":\"desktop_control_unsupported\"}}"
    );
    std::fs::write(state.join("identity.json"), b"{MOCK_ONLY_BROKEN").unwrap();
    assert_eq!(
        request(
            "claude.ai",
            "GET /api/account HTTP/1.1\r\nConnection: close\r\n\r\n"
        ),
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 124\r\nContent-Type: application/json\r\n\r\n{\"error\":\"desktop_identity_invalid\",\"message\":\"Repair the isolated Desktop identity file and relaunch saiai desktop claude\"}"
    );
    std::fs::remove_file(state.join("identity.json")).unwrap();
    assert_eq!(
        request(
            "claude.ai",
            "GET /api/account HTTP/1.1\r\nConnection: close\r\n\r\n"
        ),
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 104\r\nContent-Type: application/json\r\n\r\n{\"error\":\"desktop_identity_missing\",\"message\":\"Run saiai desktop claude to initialize this environment\"}"
    );
}

/// A self-signed installation CA (CA certificate and key PEM) with this
/// subject.
fn installation_ca(common_name: &str, organization: &str) -> (String, String) {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name.push(DnType::OrganizationName, organization);
    params.distinguished_name = name;
    (params.self_signed(&key).unwrap().pem(), key.serialize_pem())
}

/// Claude settings another program on this kernel (AITP) manages: its local
/// proxy and its installation CA.
fn aitp_managed_claude_settings(sandbox: &Sandbox) -> PathBuf {
    let ca = sandbox.home.join(".claude").join("aitp-ca.crt");
    std::fs::create_dir_all(ca.parent().unwrap()).unwrap();
    std::fs::write(
        &ca,
        installation_ca("AITP local installation CA 0123abcd", "AITP").0,
    )
    .unwrap();
    let settings = sandbox.home.join(".claude").join("settings.json");
    std::fs::write(
        &settings,
        serde_json::to_vec_pretty(&serde_json::json!({"env": {
            "https_proxy": "http://127.0.0.1:4000",
            "http_proxy": "http://127.0.0.1:4000",
            "no_proxy": "localhost,127.0.0.1",
            "CLAUDE_CODE_OAUTH_TOKEN": "TEST_ONLY_SHARED_KEY",
            "NODE_EXTRA_CA_CERTS": ca,
        }}))
        .unwrap(),
    )
    .unwrap();
    settings
}

/// SAIAI keeps its behavior with another program's remains (no refusal:
/// its brand leaves `refuse_foreign_profiles` off), but its uninstall does
/// not edit settings that program manages.
#[test]
fn saiai_keeps_initializing_and_uninstall_leaves_another_programs_settings() {
    let sandbox = Sandbox::new();
    let settings = aitp_managed_claude_settings(&sandbox);
    let before = std::fs::read(&settings).unwrap();
    let plan = sandbox.run(&mut sandbox.command(&["uninstall", "--dry-run"]));
    assert!(
        plan.contains("managed by another local proxy program"),
        "{plan}"
    );
    assert_eq!(std::fs::read(&settings).unwrap(), before);

    // Initialization takes the settings over, as before.
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_KEY",
    ]));
    let after = read_json(&settings);
    assert_eq!(
        after["env"]["NODE_EXTRA_CA_CERTS"],
        sandbox
            .home
            .join(".claude")
            .join("saiai-ca.crt")
            .to_string_lossy()
            .as_ref()
    );
    // Codex too: another program's managed block does not stop init-codex.
    let env = sandbox.home.join(".codex").join(".env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    std::fs::write(
        &env,
        "# BEGIN AITP CODEX IDE (managed)\nHTTPS_PROXY=\"http://127.0.0.1:4000\"\nhttps_proxy=\"http://127.0.0.1:4000\"\n# END AITP CODEX IDE (managed)\n",
    )
    .unwrap();
    sandbox.run(&mut sandbox.command(&[
        "init-codex",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_KEY",
    ]));
}

/// An existing SAIAI installation (no ownership record) is never taken for
/// another program's, including one still on a CA from before the common
/// name carried a suffix: re-initialization works and uninstall plans to
/// remove SAIAI's own settings.
#[test]
fn existing_saiai_state_is_never_another_programs() {
    let sandbox = Sandbox::new();
    let init = |sandbox: &Sandbox| {
        sandbox.run(&mut sandbox.command(&[
            "init",
            "--base-url",
            "http://127.0.0.1:9",
            "--api-key",
            "TEST_ONLY_CONTRACT_KEY",
        ]))
    };
    init(&sandbox);
    let config = read_json(&sandbox.home.join(".saiai/config.json"));
    let (cert, key) = installation_ca("SAIAI local installation CA", "SAIAI");
    std::fs::write(config["ca_cert_path"].as_str().unwrap(), cert).unwrap();
    std::fs::write(config["ca_key_path"].as_str().unwrap(), key).unwrap();
    init(&sandbox);
    let plan = sandbox.run(&mut sandbox.command(&["uninstall", "--dry-run"]));
    assert!(
        !plan.contains("managed by another local proxy program"),
        "{plan}"
    );
    assert!(plan.contains("env.https_proxy"), "{plan}");
}

/// SAIAI's `vscode` keeps its behavior with another program's editor proxy
/// (no new refusal): it stops at the different explicit proxy, as before.
#[test]
fn saiai_vscode_keeps_its_behavior_with_another_programs_editor_proxy() {
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_KEY",
    ]));
    let portable = sandbox.home.with_file_name("vscode-portable");
    let editor = portable.join("user-data/User/settings.json");
    std::fs::create_dir_all(editor.parent().unwrap()).unwrap();
    std::fs::write(
        &editor,
        "{\n // AITP managed VSCode proxy: http://127.0.0.1:4000\n \"http.proxy\": \"http://127.0.0.1:4000\"\n}\n",
    )
    .unwrap();
    let before = std::fs::read(&editor).unwrap();
    let output = sandbox
        .command(&["vscode"])
        .env("VSCODE_PORTABLE", &portable)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("different explicit http.proxy"), "{text}");
    assert!(
        !text.contains("managed by another local proxy program"),
        "{text}"
    );
    assert_eq!(std::fs::read(&editor).unwrap(), before);
}

/// Mixed settings (SAIAI's key and proxy, another program's CA): uninstall
/// leaves the whole file and tells the user to check for SAIAI's values.
#[test]
fn uninstall_leaves_mixed_settings_and_says_what_to_check() {
    let sandbox = Sandbox::new();
    sandbox.run(&mut sandbox.command(&[
        "init",
        "--base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "TEST_ONLY_CONTRACT_KEY",
    ]));
    let settings = sandbox.home.join(".claude").join("settings.json");
    let mut value = read_json(&settings);
    let ca = sandbox.home.join("other").join("aitp-ca.crt");
    std::fs::create_dir_all(ca.parent().unwrap()).unwrap();
    std::fs::write(
        &ca,
        installation_ca("AITP local installation CA 0123abcd", "AITP").0,
    )
    .unwrap();
    value["env"]["NODE_EXTRA_CA_CERTS"] = serde_json::json!(ca);
    std::fs::write(&settings, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let before = std::fs::read(&settings).unwrap();
    let plan = sandbox.run(&mut sandbox.command(&["uninstall", "--dry-run"]));
    assert!(
        plan.contains("managed by another local proxy program"),
        "{plan}"
    );
    assert!(
        plan.contains("If SAIAI settings are also in this file"),
        "{plan}"
    );
    assert!(!plan.contains("env.https_proxy"), "{plan}");
    assert_eq!(std::fs::read(&settings).unwrap(), before);
}
