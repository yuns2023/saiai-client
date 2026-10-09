use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MARKER: &str = "// SAIAI managed VSCode proxy: ";

pub fn certificate_trust(home: &Path, ca_cert: &Path) -> Result<bool> {
    let (program, app) = certificate_loader_program(home).context(
        "could not locate VSCode's certificate loader; editor settings were not changed",
    )?;
    inspect_certificate_trust(&program, &app, ca_cert)
}

#[cfg(windows)]
pub fn trust_windows_current_user_ca(ca_cert: &Path) -> Result<()> {
    use sha2::{Digest, Sha256};
    let raw = fs::read(ca_cert).context("could not read the public installation CA")?;
    let certificates = rustls_pemfile::certs(&mut std::io::Cursor::new(&raw))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("could not parse the public installation CA")?;
    if certificates.len() != 1 {
        bail!("expected exactly one public installation CA");
    }
    let hash = format!("{:x}", Sha256::digest(certificates[0].as_ref()));
    let program =
        PathBuf::from(env::var_os("SystemRoot").context("Windows SystemRoot is missing")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    eprintln!(
        "Windows may show a Security Warning for the existing SAIAI CA (SHA-256: {hash}). Confirm that certificate within 90 seconds to finish VSCode setup."
    );
    let mut child = Command::new(program)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("vscode_trust_windows.ps1"),
        ])
        .env("SAIAI_VSCODE_CA_PATH", ca_cert)
        .env("SAIAI_VSCODE_CA_SHA256", hash)
        .env_remove("PSModulePath")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not start Windows current-user CA trust setup")?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "Windows CA trust confirmation did not complete within 90 seconds; editor settings were preserved"
                );
            }
        }
    }
    let result = child.wait_with_output()?;
    let value: Value = serde_json::from_slice(&result.stdout)
        .context("Windows CA trust setup returned an invalid result")?;
    if value.get("error").and_then(Value::as_str) == Some("interactive_session_required") {
        bail!(
            "Windows CA trust needs an interactive Windows desktop; run initialization in a Windows terminal and confirm the Security Warning; editor settings were preserved"
        );
    }
    if !result.status.success()
        || value.get("current_user_only").and_then(Value::as_bool) != Some(true)
        || value.get("imported").and_then(Value::as_bool).is_none()
    {
        bail!(
            "Windows current-user CA trust could not be established; editor settings were preserved"
        );
    }
    Ok(())
}

fn inspect_certificate_trust(program: &Path, app: &Path, ca_cert: &Path) -> Result<bool> {
    let mut child = Command::new(program)
        .args(["-"])
        .arg(ca_cert)
        .arg(app)
        .env("ELECTRON_RUN_AS_NODE", "1")
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_PATH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not inspect VSCode's certificate loader")?;
    let input = (|| -> Result<()> {
        use std::io::Write;
        child
            .stdin
            .take()
            .context("certificate loader has no input")?
            .write_all(include_bytes!("vscode_certificates.js"))?;
        Ok(())
    })();
    if input.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        bail!("could not initialize VSCode's certificate inspection");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while match child.try_wait() {
        Ok(status) => status.is_none(),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("could not wait for VSCode's certificate inspection");
        }
    } {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("VSCode's certificate inspection timed out");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let output = child.wait_with_output()?;
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        anyhow::anyhow!("VSCode's certificate inspection returned an invalid result")
    })?;
    if !output.status.success() {
        bail!("VSCode's certificate loader could not verify the SAIAI CA");
    }
    value
        .get("trusted")
        .and_then(Value::as_bool)
        .context("VSCode's certificate inspection returned no trust result")
}

fn certificate_loader_program(home: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut candidates = Vec::new();
    #[cfg(target_os = "macos")]
    for app in [
        PathBuf::from("/Applications/Visual Studio Code.app"),
        home.join("Applications/Visual Studio Code.app"),
    ] {
        candidates.push((
            app.join("Contents/MacOS/Code"),
            app.join("Contents/Resources/app"),
        ));
    }
    #[cfg(target_os = "windows")]
    {
        let mut roots = vec![
            env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData/Local"))
                .join("Programs/Microsoft VS Code"),
        ];
        for variable in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(root) = env::var_os(variable) {
                roots.push(PathBuf::from(root).join("Microsoft VS Code"));
            }
        }
        if let Some(portable) = env::var_os("VSCODE_PORTABLE") {
            let portable = PathBuf::from(portable);
            if portable.is_absolute()
                && let Some(root) = portable.parent()
            {
                roots.insert(0, root.to_path_buf());
            }
        }
        if let Some(search_path) = env::var_os("PATH") {
            for directory in env::split_paths(&search_path) {
                if directory.is_absolute()
                    && directory.join("code.cmd").is_file()
                    && let Some(root) = directory.parent()
                {
                    roots.push(root.to_path_buf());
                }
            }
        }
        for root in roots {
            if let Some(candidate) = windows_certificate_loader(&root) {
                candidates.push(candidate);
            }
        }
    }
    #[cfg(target_os = "linux")]
    for root in [
        "/usr/share/code",
        "/usr/lib/code",
        "/opt/visual-studio-code",
    ] {
        candidates.push((
            PathBuf::from(root).join("code"),
            PathBuf::from(root).join("resources/app"),
        ));
    }
    let agent = env::var_os("VSCODE_AGENT_FOLDER")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".vscode-server"));
    for (directory, suffix) in [
        (agent.join("cli/servers"), "server"),
        (agent.join("bin"), ""),
    ] {
        if let Ok(entries) = fs::read_dir(directory) {
            let mut roots: Vec<_> = entries
                .flatten()
                .map(|entry| entry.path().join(suffix))
                .collect();
            roots.sort();
            for root in roots.into_iter().rev() {
                candidates.push((
                    root.join(if cfg!(windows) { "node.exe" } else { "node" }),
                    root,
                ));
            }
        }
    }
    candidates
        .into_iter()
        .find(|(program, app)| program.is_file() && app.is_dir())
}

#[cfg(any(windows, test))]
fn windows_certificate_loader(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let program = root.join("Code.exe");
    if !program.is_file() {
        return None;
    }
    if let Ok(command) = fs::read_to_string(root.join("bin/code.cmd")) {
        let references: Vec<_> = command
            .split(r#""%~dp0..\"#)
            .skip(1)
            .filter_map(|part| part.split_once('"').map(|(reference, _)| reference))
            .filter(|reference| {
                *reference == r"resources\app\out\cli.js"
                    || reference.ends_with(r"\resources\app\out\cli.js")
            })
            .collect();
        if references.len() != 1 {
            return None;
        }
        let app = if references[0] == r"resources\app\out\cli.js" {
            root.join("resources/app")
        } else {
            let version = references[0].strip_suffix(r"\resources\app\out\cli.js")?;
            if !(10..=40).contains(&version.len())
                || !version
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
            {
                return None;
            }
            root.join(version).join("resources/app")
        };
        return app.join("out/cli.js").is_file().then_some((program, app));
    }
    let app = root.join("resources/app");
    app.is_dir().then_some((program, app))
}

struct Document {
    tokens: Vec<Range<usize>>,
    comments: Vec<Range<usize>>,
    values: HashMap<String, Range<usize>>,
    parsed: Value,
}

pub fn settings_paths(home: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(portable) = env::var_os("VSCODE_PORTABLE") {
        roots.push(PathBuf::from(portable).join("user-data/User"));
    } else {
        #[cfg(target_os = "macos")]
        roots.push(home.join("Library/Application Support/Code/User"));
        #[cfg(target_os = "windows")]
        roots.push(
            env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData/Roaming"))
                .join("Code/User"),
        );
        #[cfg(target_os = "linux")]
        roots.push(
            env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join(".config"))
                .join("Code/User"),
        );
    }
    roots.push(
        env::var_os("VSCODE_AGENT_FOLDER")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".vscode-server"))
            .join("data/Machine"),
    );
    let mut paths = Vec::new();
    for root in roots.into_iter().filter(|root| root.is_dir()) {
        paths.push(root.join("settings.json"));
        if let Ok(profiles) = fs::read_dir(root.join("profiles")) {
            for profile in profiles.flatten() {
                let path = profile.path().join("settings.json");
                if path.is_file() {
                    paths.push(path);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

pub fn configure(home: &Path, listen: &str) -> Result<Vec<PathBuf>> {
    configure_paths(&settings_paths(home), listen)
}

pub fn preflight(home: &Path, listen: &str) -> Result<()> {
    for path in settings_paths(home) {
        merge_settings(&read_settings(&path)?, listen)?;
    }
    Ok(())
}

fn configure_paths(paths: &[PathBuf], listen: &str) -> Result<Vec<PathBuf>> {
    let mut updates = Vec::new();
    for path in paths {
        let raw = read_settings(path)?;
        let merged = merge_settings(&raw, listen).with_context(|| {
            format!("could not configure VSCode settings at {}", path.display())
        })?;
        if raw != merged {
            updates.push((path.clone(), raw, merged));
        }
    }
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S%.9f").to_string();
    let mut changed = Vec::new();
    for (path, original, merged) in updates {
        if read_settings(&path)? != original {
            bail!("VSCode settings changed during initialization; no overwrite was attempted");
        }
        super::backup_if_exists(&path, &timestamp)?;
        super::write_bytes_atomic(&path, merged.as_bytes(), 0o600)?;
        changed.push(path);
    }
    Ok(changed)
}

fn read_settings(path: &Path) -> Result<String> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!("VSCode settings are a symbolic link; no replacement was attempted");
    }
    match fs::read_to_string(path) {
        Ok(raw) => Ok(raw),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("{}\n".into()),
        Err(error) => Err(error).context("could not read VSCode settings"),
    }
}

fn managed_settings(proxy: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("http.proxy", json!(proxy)),
        ("http.proxySupport", json!("override")),
        ("http.proxyStrictSSL", json!(true)),
        ("http.fetchAdditionalSupport", json!(true)),
        ("http.systemCertificates", json!(true)),
        ("http.systemCertificatesNode", json!(false)),
    ]
}

pub fn validate_settings(raw: &str, listen: &str) -> Result<()> {
    let document = parse_document(raw)?;
    let proxy = proxy_url(listen)?;
    for (key, expected) in managed_settings(&proxy) {
        if document.parsed.get(key) != Some(&expected) {
            bail!("VSCode's {key} is not configured for the current SAIAI proxy");
        }
    }
    if document
        .parsed
        .get("http.noProxy")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        bail!("VSCode needs a nonempty http.noProxy setting to avoid inherited proxy exclusions");
    }
    validate_no_proxy(&document.parsed)
}

pub fn has_managed_proxy(raw: &str) -> bool {
    match parse_document(raw) {
        Ok(document) => document
            .comments
            .iter()
            .any(|span| raw[span.clone()].starts_with(MARKER)),
        // Keep diagnosing broken settings previously written by this tool.
        Err(_) => raw
            .lines()
            .any(|line| line.trim_start().starts_with(MARKER)),
    }
}

fn proxy_url(listen: &str) -> Result<String> {
    let address: SocketAddr = listen.parse().context("invalid VSCode proxy address")?;
    if !address.ip().is_loopback() || address.port() == 0 {
        bail!("VSCode's managed proxy must use a nonzero loopback port");
    }
    Ok(format!("http://{address}"))
}

fn validate_no_proxy(parsed: &Value) -> Result<()> {
    let Some(value) = parsed.get("http.noProxy") else {
        return Ok(());
    };
    let entries = value
        .as_array()
        .context("VSCode's http.noProxy must be an array of strings")?;
    if entries.iter().any(|entry| !entry.is_string()) {
        bail!("VSCode's http.noProxy must be an array of strings");
    }
    if entries.iter().filter_map(Value::as_str).any(|entry| {
        let normalized = entry.trim().to_ascii_lowercase();
        let mut parts = normalized.splitn(2, ':');
        let name = parts.next().unwrap_or_default();
        let port = parts.next().unwrap_or_default();
        let domain = if name.starts_with('.') {
            name.to_owned()
        } else {
            format!(".{name}")
        };
        normalized == "*"
            || (!name.is_empty()
                && (port.is_empty() || port == "443")
                && [".chatgpt.com", ".chat.openai.com"]
                    .iter()
                    .any(|host| host.ends_with(&domain)))
    }) {
        bail!(
            "VSCode's http.noProxy excludes Codex control requests; existing settings were preserved"
        );
    }
    Ok(())
}

pub fn merge_settings(raw: &str, listen: &str) -> Result<String> {
    let document = parse_document(raw)?;
    let proxy = proxy_url(listen)?;
    let markers: Vec<_> = document
        .comments
        .iter()
        .filter(|span| raw[(*span).clone()].starts_with(MARKER))
        .collect();
    if markers.len() > 1 {
        bail!("VSCode settings contain multiple SAIAI ownership markers");
    }
    if document.parsed.get("http.proxyStrictSSL") == Some(&json!(false)) {
        bail!("VSCode's http.proxyStrictSSL must remain enabled; existing settings were preserved");
    }
    validate_no_proxy(&document.parsed)?;
    if let Some(current) = document.parsed.get("http.proxy") {
        let current = current
            .as_str()
            .context("VSCode's http.proxy must be a string; existing settings were preserved")?;
        let owned = markers.first().is_some_and(|span| {
            raw[(span.start + MARKER.len())..span.end].trim() == current
                && current
                    .strip_prefix("http://")
                    .and_then(|address| address.parse::<SocketAddr>().ok())
                    .is_some_and(|address| address.ip().is_loopback() && address.port() != 0)
        });
        if !current.is_empty() && current != proxy && !owned {
            bail!(
                "VSCode already has a different explicit http.proxy; existing settings were preserved"
            );
        }
    }
    let mut replacements = Vec::new();
    let mut missing = Vec::new();
    let mut settings = managed_settings(&proxy);
    if document
        .parsed
        .get("http.noProxy")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        settings.push(("http.noProxy", json!(["localhost", "127.0.0.1", ".local"])));
    }
    for (key, value) in settings {
        let serialized = serde_json::to_string(&value)?;
        if let Some(span) = document.values.get(key) {
            if document.parsed.get(key) != Some(&value) {
                replacements.push((span.clone(), serialized));
            }
        } else {
            missing.push(format!("  \"{key}\": {serialized}"));
        }
    }
    let marker = format!("{MARKER}{proxy}");
    if let Some(span) = markers.first() {
        if raw[(**span).clone()] != marker {
            replacements.push(((**span).clone(), marker));
        }
    } else {
        let start = document.tokens[0].end;
        replacements.push((start..start, format!("\n  {marker}\n")));
    }
    if !missing.is_empty() {
        let closing = document.tokens.last().unwrap().start;
        let previous = &document.tokens[document.tokens.len() - 2];
        replacements.push((closing..closing, format!("\n{}\n", missing.join(",\n"))));
        if &raw[previous.clone()] != "{" && &raw[previous.clone()] != "," {
            replacements.push((previous.end..previous.end, ",".into()));
        }
    }
    replacements.sort_by_key(|replacement| std::cmp::Reverse(replacement.0.start));
    let mut merged = raw.to_owned();
    for (span, value) in replacements {
        merged.replace_range(span, &value);
    }
    validate_settings(&merged, listen)?;
    Ok(merged)
}

fn parse_document(raw: &str) -> Result<Document> {
    let bytes = raw.as_bytes();
    let mut tokens = Vec::new();
    let mut comments = Vec::new();
    let mut cursor = usize::from(raw.starts_with('\u{feff}')) * 3;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        let start = cursor;
        if bytes[cursor..].starts_with(b"//") {
            cursor += 2;
            while cursor < bytes.len() && !matches!(bytes[cursor], b'\r' | b'\n') {
                cursor += 1;
            }
            comments.push(start..cursor);
            continue;
        }
        if bytes[cursor..].starts_with(b"/*") {
            let end = raw[(cursor + 2)..]
                .find("*/")
                .context("VSCode settings contain an unterminated comment")?;
            cursor += end + 4;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor += 1;
            let mut closed = false;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'\\' => cursor += 2,
                    b'"' => {
                        cursor += 1;
                        closed = true;
                        break;
                    }
                    _ => cursor += 1,
                }
            }
            if !closed {
                bail!("VSCode settings contain an unterminated string");
            }
        } else if b"{}[],:".contains(&bytes[cursor]) {
            cursor += 1;
        } else {
            while cursor < bytes.len()
                && !bytes[cursor].is_ascii_whitespace()
                && !b"{}[],:/\"".contains(&bytes[cursor])
            {
                cursor += 1;
            }
            if cursor == start {
                bail!("VSCode settings contain invalid JSONC");
            }
        }
        tokens.push(start..cursor);
    }
    for (index, span) in tokens.iter().enumerate() {
        if &raw[span.clone()] == ","
            && tokens
                .get(index + 1)
                .is_some_and(|next| matches!(&raw[next.clone()], "}" | "]"))
            && index.checked_sub(1).is_none_or(|previous| {
                matches!(&raw[tokens[previous].clone()], "{" | "[" | ":" | ",")
            })
        {
            bail!("VSCode settings contain invalid JSONC");
        }
    }
    let normalized: String = tokens
        .iter()
        .enumerate()
        .filter(|(index, span)| {
            &raw[(*span).clone()] != ","
                || !tokens
                    .get(index + 1)
                    .is_some_and(|next| matches!(&raw[next.clone()], "}" | "]"))
        })
        .map(|(_, span)| &raw[span.clone()])
        .collect::<Vec<_>>()
        .join(" ");
    let parsed: Value = serde_json::from_str(&normalized)
        .map_err(|_| anyhow::anyhow!("VSCode settings contain invalid JSONC"))?;
    if !parsed.is_object() {
        bail!("VSCode settings must contain a JSONC object");
    }
    let mut values = HashMap::new();
    let mut seen = HashSet::new();
    let mut index = 1;
    while index < tokens.len() - 1 {
        let key: String = serde_json::from_str(&raw[tokens[index].clone()])?;
        if !seen.insert(key.clone()) {
            bail!("VSCode settings contain duplicate top-level keys");
        }
        index += 2;
        let start = tokens[index].start;
        let mut depth = 0_usize;
        loop {
            match &raw[tokens[index].clone()] {
                "{" | "[" => depth += 1,
                "}" | "]" if depth > 0 => depth -= 1,
                _ => {}
            }
            index += 1;
            if depth == 0 && matches!(&raw[tokens[index].clone()], "," | "}") {
                break;
            }
        }
        values.insert(key, start..tokens[index - 1].end);
        if &raw[tokens[index].clone()] == "," {
            index += 1;
        }
    }
    Ok(Document {
        tokens,
        comments,
        values,
        parsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTEN: &str = "127.0.0.1:53940";

    fn windows_loader_fixture(root: &Path, command: &str, apps: &[&str]) {
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("Code.exe"), "TEST_ONLY_RUNTIME").unwrap();
        fs::write(root.join("bin/code.cmd"), command).unwrap();
        for app in apps {
            let directory = root.join(app).join("resources/app/out");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("cli.js"), "TEST_ONLY_CLI").unwrap();
        }
    }

    #[test]
    fn vscode_windows_loader_supports_the_classic_installation() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        windows_loader_fixture(
            root,
            r#""%~dp0..\Code.exe" "%~dp0..\resources\app\out\cli.js" %*"#,
            &[""],
        );
        assert_eq!(
            windows_certificate_loader(root),
            Some((root.join("Code.exe"), root.join("resources/app")))
        );
    }

    #[test]
    fn vscode_windows_loader_uses_the_launchers_current_version_only() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        windows_loader_fixture(
            root,
            r#""%~dp0..\Code.exe" "%~dp0..\8761a5560c\resources\app\out\cli.js" %*"#,
            &["", "8761a5560c", "0000000000"],
        );
        assert_eq!(
            windows_certificate_loader(root),
            Some((root.join("Code.exe"), root.join("8761a5560c/resources/app")))
        );
    }

    #[test]
    fn vscode_windows_loader_does_not_use_a_stale_application_directory() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        windows_loader_fixture(
            root,
            r#""%~dp0..\Code.exe" "%~dp0..\8761a5560c\resources\app\out\cli.js" %*"#,
            &[""],
        );
        assert!(windows_certificate_loader(root).is_none());
    }

    #[test]
    fn vscode_windows_loader_rejects_ambiguous_or_escaping_versions() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        for command in [
            r#""%~dp0..\8761a5560c\resources\app\out\cli.js" "%~dp0..\0000000000\resources\app\out\cli.js""#,
            r#""%~dp0..\..\resources\app\out\cli.js""#,
        ] {
            windows_loader_fixture(root, command, &["", "8761a5560c", "0000000000"]);
            assert!(windows_certificate_loader(root).is_none());
        }
        fs::remove_file(root.join("Code.exe")).unwrap();
        assert!(windows_certificate_loader(root).is_none());
    }

    #[test]
    fn vscode_proxy_adds_default_routing_without_changing_other_settings() {
        let raw = "{\n // 保留用户设置\n \"editor.fontSize\": 16,\n \"nested\": {\"url\": \"https://example.test//path\",},\n}\n";
        let merged = merge_settings(raw, LISTEN).unwrap();
        assert!(merged.contains("// 保留用户设置"));
        assert!(merged.contains("\"nested\": {\"url\": \"https://example.test//path\",}"));
        validate_settings(&merged, LISTEN).unwrap();
        assert_eq!(merged, merge_settings(&merged, LISTEN).unwrap());
    }

    #[test]
    fn vscode_proxy_handles_empty_objects_bom_comments_and_escaped_strings() {
        for raw in [
            "{}",
            "{ /* user */ }",
            "\u{feff}{\r\n// comment\r\n}",
            r#"{"value": "quote: \" and slash: \\"}"#,
            "{\"nested\": [{\"values\": [1, 2,],},],}",
            "{\"value\": true // preserve trailing comment\n}",
        ] {
            let merged = merge_settings(raw, LISTEN).unwrap();
            validate_settings(&merged, LISTEN).unwrap();
            assert_eq!(merged, merge_settings(&merged, LISTEN).unwrap());
        }
    }

    #[test]
    fn vscode_proxy_refreshes_only_owned_proxy_values() {
        let first = merge_settings("{}", LISTEN).unwrap();
        let refreshed = merge_settings(&first, "[::1]:12345").unwrap();
        validate_settings(&refreshed, "[::1]:12345").unwrap();
        assert!(!refreshed.contains(LISTEN));
        let edited = first.replace("\"http://127.0.0.1:53940\"", "\"http://127.0.0.1:7890\"");
        assert!(merge_settings(&edited, "127.0.0.1:12345").is_err());
    }

    #[test]
    fn vscode_proxy_preserves_explicit_conflicts_and_does_not_echo_secrets() {
        let raw = r#"{"http.proxy": "http://secret:password@127.0.0.1:7890"}"#;
        let error = merge_settings(raw, LISTEN).unwrap_err().to_string();
        assert!(!error.contains("secret"));
        assert!(!error.contains("password"));
        for raw in [
            r#"{"http.proxyStrictSSL": false}"#,
            r#"{"http.noProxy": ["*"]}"#,
            r#"{"http.noProxy": [".chatgpt.com"]}"#,
            r#"{"http.noProxy": ["com:443"]}"#,
            r#"{"http.noProxy": [".openai.com"]}"#,
            r#"{"http.noProxy": "*"}"#,
            r#"{"http.noProxy": [123]}"#,
            r#"{"http.proxy": null}"#,
        ] {
            assert!(merge_settings(raw, LISTEN).is_err());
        }
    }

    #[test]
    fn vscode_proxy_rejects_malformed_documents_and_nonlocal_listeners() {
        for raw in [
            "[]",
            "",
            "{",
            "{\"value\":1,\"value\":2}",
            "{/*",
            "{\"value\":\"x}",
            "{,}",
            "{\"value\":[,]}",
        ] {
            assert!(merge_settings(raw, LISTEN).is_err());
        }
        for listen in [
            "0.0.0.0:1234",
            "192.168.1.8:1234",
            "127.0.0.1:0",
            "localhost:1234",
        ] {
            assert!(merge_settings("{}", listen).is_err());
        }
    }

    #[test]
    fn vscode_proxy_file_update_is_backed_up_and_repeat_is_a_noop() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(".vscode-server/data/Machine");
        fs::create_dir_all(&root).unwrap();
        let settings = root.join("settings.json");
        let original = "{ // user\n \"editor.fontSize\": 16\n}\n";
        fs::write(&settings, original).unwrap();
        assert_eq!(
            configure_paths(std::slice::from_ref(&settings), LISTEN).unwrap(),
            vec![settings.clone()]
        );
        assert!(
            configure_paths(std::slice::from_ref(&settings), LISTEN)
                .unwrap()
                .is_empty()
        );
        let backups: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name() != "settings.json")
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read_to_string(backups[0].path()).unwrap(), original);
        validate_settings(&fs::read_to_string(settings).unwrap(), LISTEN).unwrap();
    }

    #[test]
    fn vscode_proxy_preflights_all_settings_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("valid.json");
        let conflict = directory.path().join("conflict.json");
        fs::write(&valid, "{}").unwrap();
        fs::write(&conflict, "{\"http.proxy\":\"http://127.0.0.1:7890\"}").unwrap();
        assert!(configure_paths(&[valid.clone(), conflict], LISTEN).is_err());
        assert_eq!(fs::read_to_string(valid).unwrap(), "{}");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn vscode_proxy_does_not_replace_symlinked_settings() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original.json");
        let link = directory.path().join("settings.json");
        fs::write(&original, "{}").unwrap();
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(configure_paths(std::slice::from_ref(&link), LISTEN).is_err());
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_to_string(original).unwrap(), "{}");
    }

    #[test]
    fn vscode_proxy_sets_local_exclusions_and_preserves_safe_custom_entries() {
        for raw in ["{}", "{\"http.noProxy\": []}"] {
            let merged = merge_settings(raw, LISTEN).unwrap();
            assert_eq!(
                parse_document(&merged).unwrap().parsed["http.noProxy"],
                json!(["localhost", "127.0.0.1", ".local"])
            );
        }
        let raw = "{\"http.noProxy\": [\"example.test\", \".com:80\"]}";
        let merged = merge_settings(raw, LISTEN).unwrap();
        assert!(merged.contains("\"http.noProxy\": [\"example.test\", \".com:80\"]"));
        validate_settings(&merged, LISTEN).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_trust_rejects_leaf_and_expired_ca_without_store_changes() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        fn roots() -> Value {
            let script = r#"
                $ErrorActionPreference = 'Stop'
                $result = @{}
                foreach ($location in @('CurrentUser', 'LocalMachine')) {
                    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', $location)
                    try {
                        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                        $hash = [Security.Cryptography.SHA256]::Create()
                        try {
                            $result[$location] = @($store.Certificates | ForEach-Object {
                                [BitConverter]::ToString($hash.ComputeHash($_.RawData))
                            } | Sort-Object)
                        } finally { $hash.Dispose() }
                    } finally { $store.Close(); $store.Dispose() }
                }
                $result | ConvertTo-Json -Compress
            "#;
            let output = Command::new(
                PathBuf::from(env::var_os("SystemRoot").unwrap())
                    .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
            )
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .env_remove("PSModulePath")
            .output()
            .unwrap();
            assert!(output.status.success());
            serde_json::from_slice(&output.stdout).unwrap()
        }

        let before = roots();
        let directory = tempfile::tempdir().unwrap();
        for expired_ca in [false, true] {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            if expired_ca {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.not_before = rcgen::date_time_ymd(1990, 1, 1);
                params.not_after = rcgen::date_time_ymd(2000, 1, 1);
            }
            let key = KeyPair::generate().unwrap();
            let certificate = params.self_signed(&key).unwrap();
            // Only public certificates are written; these rejected inputs must
            // never reach Windows' protected-root confirmation or store write.
            let path = directory.path().join("rejected-public-certificate.crt");
            fs::write(&path, certificate.pem()).unwrap();
            assert!(trust_windows_current_user_ca(&path).is_err());
            assert_eq!(roots(), before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn vscode_certificate_inspection_preserves_negative_and_unknown_results() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("certificate-loader");
        for (response, status, expected) in [
            ("{\"trusted\":true}", 0, Some(true)),
            ("{\"trusted\":false}", 0, Some(false)),
            ("{\"trusted\":null}", 0, None),
            ("{\"trusted\":true}", 1, None),
            ("invalid result", 0, None),
        ] {
            let script =
                format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{response}'\nexit {status}\n");
            fs::write(&program, script).unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
            let result = inspect_certificate_trust(
                &program,
                directory.path(),
                &directory.path().join("unused.crt"),
            );
            assert_eq!(result.as_ref().ok().copied(), expected, "{result:?}");
        }
    }
}
#[test]
fn editor_diagnostics_require_an_actual_managed_proxy_marker() {
    assert!(!has_managed_proxy(
        r#"{"http.proxy": "http://127.0.0.1:19908"}"#
    ));
    assert!(!has_managed_proxy(
        r#"{"description": "// SAIAI managed VSCode proxy: http://127.0.0.1:19908"}"#
    ));
    assert!(has_managed_proxy(
        "{\n // SAIAI managed VSCode proxy: http://127.0.0.1:19908\n}\n"
    ));
    assert!(has_managed_proxy(
        "{\n // SAIAI managed VSCode proxy: http://127.0.0.1:19908\n broken json\n"
    ));
}
