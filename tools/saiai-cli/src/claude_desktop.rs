//! Linux Claude Desktop's isolated local login. Gateway credentials never enter this profile.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(any(target_os = "linux", test))]
pub(crate) const VERSION: &str = "4.23118.0";
pub(crate) const TOKEN_PREFIX: crate::brand::BrandValue<&'static str> =
    crate::brand::BrandValue(|brand| brand.placeholders.claude_desktop_token_prefix);
#[cfg(target_os = "linux")]
pub(crate) const SCOPE: &str = "Claude Desktop: Code only; Chat and Cowork are not supported.";

/// Uninitialized environments and unsupported platforms must have no Desktop side effects.
pub(crate) async fn bind_if_initialized(
    root: Option<&Path>,
    main_listen: &str,
) -> Result<Option<tokio::net::TcpListener>> {
    #[cfg(target_os = "linux")]
    {
        // Check existence, not validity: corrupt identities get explicit HTTP diagnostics.
        if let Some(root) = root
            && root.join("desktop/claude/state/identity.json").is_file()
        {
            return bind_listener(root, main_listen).await.map(Some);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (root, main_listen);
    Ok(None)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Serialize, Deserialize)]
struct ProxyEndpoint {
    main_listen: String,
    listen: std::net::SocketAddr,
}

/// The running proxy owns both listeners. The receipt is a preferred address,
/// not evidence that an old process is still alive; launch verifies TLS and role.
#[cfg(any(target_os = "linux", test))]
async fn bind_listener(root: &Path, main_listen: &str) -> Result<tokio::net::TcpListener> {
    let preferred = read_endpoint(root, main_listen).ok();
    let listener = if let Some(address) = preferred {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => listener,
            Err(_) => tokio::net::TcpListener::bind("127.0.0.1:0").await?,
        }
    } else {
        tokio::net::TcpListener::bind("127.0.0.1:0").await?
    };
    let endpoint = ProxyEndpoint {
        main_listen: main_listen.into(),
        listen: listener.local_addr()?,
    };
    private_write(
        &root.join("desktop/claude/state/proxy.json"),
        &serde_json::to_vec(&endpoint)?,
    )?;
    Ok(listener)
}

#[cfg(any(target_os = "linux", test))]
fn read_endpoint(root: &Path, main_listen: &str) -> Result<std::net::SocketAddr> {
    let endpoint: ProxyEndpoint = serde_json::from_slice(
        &fs::read(root.join("desktop/claude/state/proxy.json"))
            .context("Claude Desktop listener is unavailable; run `saiai restart` in this environment, then retry `saiai desktop claude`")?,
    )?;
    if endpoint.main_listen != main_listen
        || !endpoint.listen.ip().is_loopback()
        || endpoint.listen.port() == 0
        || endpoint.listen.to_string() == main_listen
    {
        bail!(
            "invalid or stale Claude Desktop listener receipt; run `saiai restart` in this environment, then retry `saiai desktop claude`"
        );
    }
    Ok(endpoint.listen)
}

#[cfg(target_os = "linux")]
fn verified_endpoint(root: &Path, cfg: &crate::SaiaiConfig) -> Result<(String, String)> {
    let listen = read_endpoint(root, &cfg.listen)?.to_string();
    let mut desktop_cfg = cfg.clone();
    desktop_cfg.listen = listen.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::connect_local_proxy_tls(&desktop_cfg))
        .context("Claude Desktop listener does not authenticate with this environment's CA; run `saiai restart` in this environment, then retry `saiai desktop claude`")?;
    let pins = crate::local_proxy_chatgpt_spki(&listen)?;
    if pins.split(',').count() != 2 {
        bail!(
            "listener is not the dedicated Claude Desktop entry; run `saiai restart` in this environment, then retry `saiai desktop claude`"
        );
    }
    Ok((listen, pins))
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub account: String,
    pub organization: String,
    pub access_token: String,
    pub refresh_token: String,
    pub session: String,
}

impl Identity {
    #[cfg(any(target_os = "linux", test))]
    fn new() -> Self {
        Self {
            account: uuid::Uuid::new_v4().to_string(),
            organization: uuid::Uuid::new_v4().to_string(),
            access_token: format!(
                "{TOKEN_PREFIX}{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            refresh_token: format!("{TOKEN_PREFIX}refresh-{}", uuid::Uuid::new_v4().simple()),
            session: format!(
                "{}{}{}",
                crate::brand::BRAND
                    .placeholders
                    .claude_desktop_session_prefix,
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
        }
    }

    pub fn load(root: &Path) -> Result<Option<Self>> {
        let path = root.join("desktop/claude/state/identity.json");
        match fs::read(&path) {
            Ok(bytes) => {
                let identity: Self =
                    serde_json::from_slice(&bytes).context("invalid Claude Desktop identity")?;
                if !identity.access_token.starts_with(TOKEN_PREFIX.get())
                    || identity.access_token.len() < 32
                    || [
                        &identity.session,
                        &identity.access_token,
                        &identity.refresh_token,
                    ]
                    .iter()
                    .any(|s| !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                    || identity.session.len() < 32
                    || identity.refresh_token.len() < 32
                    || identity.account == identity.organization
                    || uuid::Uuid::parse_str(&identity.account).is_err()
                    || uuid::Uuid::parse_str(&identity.organization).is_err()
                {
                    bail!(
                        "invalid Claude Desktop identity; remove the isolated identity and relaunch"
                    );
                }
                Ok(Some(identity))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("cannot read Claude Desktop identity"),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn prepare(root: &Path) -> Result<Self> {
        if let Some(identity) = Self::load(root)? {
            return Ok(identity);
        }
        let identity = Self::new();
        private_write(
            &root.join("desktop/claude/state/identity.json"),
            &serde_json::to_vec(&identity)?,
        )?;
        Ok(identity)
    }
}

pub(crate) fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("missing parent directory")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let temp = parent.join(format!(
        ".{}-{}.tmp",
        crate::brand::BRAND.binary_name,
        uuid::Uuid::new_v4()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn check_version(version: &str, allow_untested: bool) -> Result<()> {
    if version.trim() != VERSION && !allow_untested {
        bail!(
            "Claude Desktop {} is untested (supported: {VERSION}); set SAIAI_CLAUDE_DESKTOP_ALLOW_UNTESTED=1 to override",
            version.trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn installed_version() -> Result<String> {
    let output = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "claude-desktop"])
        .output()
        .context("cannot query the installed claude-desktop apt package")?;
    if !output.status.success() {
        bail!("claude-desktop apt package is not installed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

#[cfg(any(target_os = "linux", test))]
fn launch_arguments(profile: &Path, proxy: &str) -> [String; 4] {
    [
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server={proxy}"),
        "--disable-quic".into(),
        "claude://code/new?source=desktop_action".into(),
    ]
}

#[cfg(any(target_os = "linux", test))]
fn apply_environment(
    command: &mut std::process::Command,
    root: &Path,
    proxy: &str,
    ca: &str,
    bundle: &Path,
) {
    for key in crate::CLAUDE_MANAGED_ROUTING_ENV
        .iter()
        .chain(crate::claude_launcher::CONFLICTING_ENV)
        .chain(crate::CODEX_MANAGED_ENV)
    {
        command.env_remove(key);
    }
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("VERTEX_REGION_CLAUDE_")
        {
            command.env_remove(key);
        }
    }
    command.env_remove("NODE_OPTIONS");
    command.env_remove("ELECTRON_RUN_AS_NODE");
    command.env_remove("CLAUDE_CODE_USER_EMAIL");
    command.env_remove("CLAUDE_CODE_ACCOUNT_UUID");
    command.env_remove("CLAUDE_CODE_ORGANIZATION_UUID");
    let home = root.join("home");
    command
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
        .env("NODE_EXTRA_CA_CERTS", ca)
        .env("SSL_CERT_FILE", bundle)
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("NSS_DEFAULT_DB_TYPE", "sql");
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(key, proxy);
    }
    for key in ["NO_PROXY", "no_proxy"] {
        command.env(key, "localhost,127.0.0.1,::1");
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("saiai desktop claude supports Linux only; macOS and Windows are not supported");
    }
    #[cfg(target_os = "linux")]
    {
        if !args.is_empty() {
            bail!("Claude Desktop MVP does not accept extra arguments");
        }
        println!("{SCOPE}");
        let version = installed_version()?;
        check_version(
            &version,
            std::env::var(crate::brand::BRAND.env.claude_desktop_allow_untested).as_deref()
                == Ok("1"),
        )?;
        let executable = Path::new("/usr/bin/claude-desktop");
        if !executable.is_file() {
            bail!("/usr/bin/claude-desktop was not found");
        }
        let config_root = crate::saiai_config_dir()?;
        let root = config_root.join("desktop/claude");
        for relative in [
            "desktop",
            "desktop/claude",
            "desktop/claude/home",
            "desktop/claude/home/.claude",
            "desktop/claude/home/.config",
            "desktop/claude/home/.cache",
            "desktop/claude/home/.local",
            "desktop/claude/home/.local/share",
            "desktop/claude/home/.claude.json",
            "desktop/claude/home/.claude/.claude.json",
            "desktop/claude/user-data",
            "desktop/claude/state",
            "desktop/claude/state/identity.json",
        ] {
            if fs::symlink_metadata(config_root.join(relative))
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                bail!("isolated Claude Desktop path must not be a symlink: {relative}");
            }
        }
        let profile = root.join("user-data");
        fs::create_dir_all(root.join("state"))?;
        // Hold a launcher lock until the child exits; Chromium owns SingletonLock.
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("state/launcher.lock"))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
            || fs::symlink_metadata(profile.join("SingletonLock")).is_ok()
        {
            bail!(
                "isolated Claude Desktop is already running or has a SingletonLock; close it before relaunching (no process was killed)"
            );
        }
        let cfg = crate::read_saiai_config()?;
        if !cfg.providers.is_empty() && cfg.providers.claude.is_none() {
            bail!("SAIAI Claude route is not configured; run the SAIAI Claude setup first");
        }
        crate::read_runtime_ca(&cfg)?;
        Identity::prepare(&config_root)?;
        for path in [&profile, &root.join("home")] {
            fs::create_dir_all(path)?;
        }
        use std::os::unix::fs::PermissionsExt;
        for path in [&root, &profile, &root.join("home")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        for path in [
            root.join("home/.claude.json"),
            root.join("home/.claude/.claude.json"),
        ] {
            if path.exists() {
                let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                let object = value
                    .as_object_mut()
                    .context("isolated .claude.json must be an object")?;
                object.remove("oauthAccount");
                private_write(&path, &serde_json::to_vec_pretty(&value)?)?;
            }
        }
        let system = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .context("system CA bundle not found")?;
        let mut bundle = fs::read(system)?;
        bundle.push(b'\n');
        bundle.extend(fs::read(&cfg.ca_cert_path)?);
        let bundle_path = root.join("state/ca-bundle.pem");
        private_write(&bundle_path, &bundle)?;
        if !crate::ensure_nss_ca(&root.join("home"), Path::new(&cfg.ca_cert_path))? {
            bail!(
                "Claude Desktop requires certutil for isolated NSS trust; run: sudo apt install libnss3-tools"
            );
        }
        crate::ensure_local_proxy_running(&cfg.listen)?;
        crate::verify_selected_proxy_identity(&cfg.listen)?;
        let (desktop_listen, _) = verified_endpoint(&config_root, &cfg)?;
        let proxy = format!("http://{desktop_listen}");
        let mut command = std::process::Command::new(executable);
        apply_environment(&mut command, &root, &proxy, &cfg.ca_cert_path, &bundle_path);
        if std::env::var_os("XAUTHORITY").is_none()
            && let Some(path) = crate::fallback_linux_xauthority(
                crate::home_dir().as_deref(),
                std::env::var_os("DISPLAY").is_some(),
            )
        {
            command.env("XAUTHORITY", path);
        }
        command
            .args(launch_arguments(&profile, &proxy))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        println!(
            "Starting Claude Desktop {version}; profile={} proxy={proxy}",
            profile.display()
        );
        let status = command.status().context("failed to start Claude Desktop")?;
        if !status.success() {
            bail!("Claude Desktop exited with {status}");
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn doctor() -> Result<()> {
    bail!("Claude Desktop supports Linux only; macOS and Windows are not supported")
}

#[cfg(target_os = "linux")]
pub(crate) fn doctor() -> Result<()> {
    println!("{SCOPE}");
    println!("platform={} (Linux only)", std::env::consts::OS);
    let version = installed_version();
    println!(
        "version={} supported={VERSION}",
        version.as_deref().unwrap_or("unavailable")
    );
    let root = crate::saiai_config_dir()?;
    println!(
        "executable=/usr/bin/claude-desktop profile={}",
        root.join("desktop/claude/user-data").display()
    );
    println!(
        "local placeholder present={}",
        Identity::load(&root)?.is_some()
    );
    let cfg = crate::read_saiai_config()?;
    println!("main proxy={} CA={}", cfg.listen, cfg.ca_cert_path);
    crate::read_runtime_ca(&cfg)?;
    crate::verify_selected_proxy_identity(&cfg.listen)?;
    let (desktop_listen, _) = verified_endpoint(&root, &cfg)?;
    println!(
        "Claude Desktop proxy={desktop_listen}; certificate identity and dedicated entry: verified"
    );
    println!(
        "Gateway policy: if the group uses observe/enforce, an administrator must add claude-desktop to that group's allowlist"
    );
    check_version(&version?, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dedicated_listener_reuses_port_and_recovers_from_foreign_occupancy() {
        let root = tempfile::tempdir().unwrap();
        let first = bind_listener(root.path(), "127.0.0.1:19908").await.unwrap();
        let address = first.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        assert_eq!(
            read_endpoint(root.path(), "127.0.0.1:19908").unwrap(),
            address
        );
        assert!(read_endpoint(root.path(), "127.0.0.1:19909").is_err());
        drop(first);
        let second = bind_listener(root.path(), "127.0.0.1:19908").await.unwrap();
        // Another parallel test may claim the released ephemeral port.
        let address = second.local_addr().unwrap();
        assert_eq!(
            read_endpoint(root.path(), "127.0.0.1:19908").unwrap(),
            address
        );
        // The occupied listener is never killed or adopted.
        let third = bind_listener(root.path(), "127.0.0.1:19908").await.unwrap();
        assert_ne!(third.local_addr().unwrap(), address);
        assert_eq!(
            read_endpoint(root.path(), "127.0.0.1:19908").unwrap(),
            third.local_addr().unwrap()
        );
        assert!(Identity::load(root.path()).unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn initialized_environment_enables_listener_even_with_corrupt_identity() {
        let root = tempfile::tempdir().unwrap();
        Identity::prepare(root.path()).unwrap();
        for corrupt in [false, true] {
            if corrupt {
                fs::write(
                    root.path().join("desktop/claude/state/identity.json"),
                    b"broken",
                )
                .unwrap();
            }
            let listener = bind_if_initialized(Some(root.path()), "127.0.0.1:19908")
                .await
                .unwrap()
                .unwrap();
            assert!(listener.local_addr().unwrap().ip().is_loopback());
        }
    }

    #[test]
    fn dedicated_listener_receipt_rejects_nonloopback_and_main_port() {
        let root = tempfile::tempdir().unwrap();
        for listen in ["0.0.0.0:19910", "127.0.0.1:0", "127.0.0.1:19908"] {
            private_write(
                &root.path().join("desktop/claude/state/proxy.json"),
                &serde_json::to_vec(&ProxyEndpoint {
                    main_listen: "127.0.0.1:19908".into(),
                    listen: listen.parse().unwrap(),
                })
                .unwrap(),
            )
            .unwrap();
            assert!(read_endpoint(root.path(), "127.0.0.1:19908").is_err());
        }
    }

    #[test]
    fn identity_is_persistent_and_environment_scoped() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let first = Identity::prepare(a.path()).unwrap();
        assert_eq!(
            first.access_token,
            Identity::prepare(a.path()).unwrap().access_token
        );
        assert_ne!(
            first.access_token,
            Identity::prepare(b.path()).unwrap().access_token
        );
        assert_ne!(first.account, first.organization);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(a.path().join("desktop/claude/state/identity.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn version_gate_requires_explicit_override() {
        assert!(check_version(VERSION, false).is_ok());
        assert!(check_version("4.99999.0", false).is_err());
        assert!(check_version("4.99999.0", true).is_ok());
    }
    #[test]
    fn launch_has_only_supported_switches() {
        let args = launch_arguments(Path::new("/profile"), "http://127.0.0.1:1234");
        assert_eq!(
            args,
            [
                "--user-data-dir=/profile",
                "--proxy-server=http://127.0.0.1:1234",
                "--disable-quic",
                "claude://code/new?source=desktop_action",
            ]
        );
        assert!(args.iter().all(|arg| !arg.contains("ignore-certificate")
            && !arg.contains("remote-debugging")
            && !arg.contains("--inspect")));
    }

    #[test]
    fn desktop_environment_contains_no_real_token() {
        let mut command = std::process::Command::new("unused");
        apply_environment(
            &mut command,
            Path::new("/isolated"),
            "http://127.0.0.1:19908",
            "/ca",
            Path::new("/bundle"),
        );
        let vars: std::collections::HashMap<_, _> = command.get_envs().collect();
        for key in [
            "CLAUDE_CODE_OAUTH_TOKEN",
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_USER_EMAIL",
            "NODE_TLS_REJECT_UNAUTHORIZED",
            "CLAUDE_CODE_ENTRYPOINT",
            "OPENAI_API_KEY",
            "CODEX_ACCESS_TOKEN",
            "NODE_OPTIONS",
            "ELECTRON_RUN_AS_NODE",
        ] {
            assert_eq!(vars.get(std::ffi::OsStr::new(key)), Some(&None), "{key}");
        }
        assert_eq!(
            vars[std::ffi::OsStr::new("SSL_CERT_FILE")],
            Some(std::ffi::OsStr::new("/bundle"))
        );
    }
}
