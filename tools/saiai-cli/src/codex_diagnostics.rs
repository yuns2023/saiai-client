use crate::{DoctorReport, codex_config_dir, codex_process_command};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};
use toml_edit::{DocumentMut, Item};

// This is a configured CLI check, not a Desktop catalog or model-request probe.
// It neither refreshes the catalog nor changes a saved model/effort/profile.
pub(crate) fn check(report: &mut DoctorReport) {
    let mut command = match codex_process_command() {
        Ok(command) => command,
        Err(_) => {
            report.warn(
                "Codex CLI",
                "executable not found; install the official CLI and open a new terminal",
            );
            return;
        }
    };
    let path = command
        .get_args()
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(command.get_program()));
    report.ok("Codex CLI path", path.display().to_string());
    let paths: Vec<PathBuf> = env::var_os("PATH")
        .map(|value| env::split_paths(&value).collect())
        .unwrap_or_default();
    let candidates = installations(&paths, cfg!(windows));
    if candidates.len() > 1 {
        report.warn("Codex CLI installations", format!("{} PATH installations found; updating a shadowed installation does not update the invoked CLI", candidates.len()));
    }
    let Some(version) = cli_version(&mut command) else {
        report.warn("Codex CLI version", "could not obtain an official codex-cli version with --version; raw command output withheld");
        return;
    };
    report.ok(
        "Codex CLI version",
        format!("{version}; independent of SAIAI and Desktop app-server versions"),
    );
    let Ok(home) = codex_config_dir() else { return };
    let Some(config) = fs::read_to_string(home.join("config.toml"))
        .ok()
        .and_then(|raw| raw.parse::<DocumentMut>().ok())
    else {
        return;
    };
    let Some(model) = configured_model(&config) else {
        report.ok(
            "Codex model metadata",
            "no explicit OpenAI default model for this catalog check; command-line overrides are not inspected",
        );
        return;
    };
    let raw = fs::read_to_string(home.join("models_cache.json")).ok();
    match cached_model(raw.as_deref(), &version, model, Utc::now()) {
        CacheStatus::Present => report.ok("Codex model metadata", format!("configured model {model} is in the fresh catalog for CLI {version}; upstream eligibility is still provider-controlled")),
        CacheStatus::Missing => report.warn("Codex model metadata", format!("configured model {model} is absent from the fresh catalog for CLI {version}; fallback metadata may cause compatibility issues. Update the actual CLI installation or explicitly select an advertised model with /model; no saved preference was changed")),
        CacheStatus::Unavailable => report.warn("Codex model metadata", "cache absent or invalid; model support cannot be established offline"),
        CacheStatus::VersionMismatch => report.warn("Codex model metadata", "cache belongs to a different CLI version; do not infer support from this cache"),
        CacheStatus::Stale => report.warn("Codex model metadata", "cache timestamp is stale or invalid; model support cannot be established offline"),
    }
}

fn cli_version(command: &mut std::process::Command) -> Option<String> {
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) if start.elapsed() < Duration::from_secs(3) => {
                thread::sleep(Duration::from_millis(25))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let output = child.wait_with_output().ok()?;
    let output = std::str::from_utf8(&output.stdout).ok()?.trim();
    let version = output.strip_prefix("codex-cli ")?;
    if version.len() > 64
        || !version
            .bytes()
            .all(|char| char.is_ascii_alphanumeric() || b".-+".contains(&char))
    {
        return None;
    }
    Some(version.to_string())
}

fn installations(paths: &[PathBuf], windows: bool) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let names: &[&str] = if windows {
        &[
            "codex.exe",
            "codex.com",
            "codex.cmd",
            "codex.bat",
            "codex.ps1",
        ]
    } else {
        &["codex"]
    };
    for directory in paths {
        if let Some(path) = names
            .iter()
            .map(|name| directory.join(name))
            .find(|path| path.is_file())
        {
            let canonical = fs::canonicalize(&path).unwrap_or(path);
            if !result.contains(&canonical) {
                result.push(canonical);
            }
        }
    }
    result
}

fn configured_model(document: &DocumentMut) -> Option<&str> {
    let profile = document
        .get("profile")
        .and_then(Item::as_str)
        .and_then(|name| document.get("profiles")?.get(name));
    let provider = profile
        .and_then(|profile| profile.get("model_provider"))
        .or_else(|| document.get("model_provider"))
        .and_then(Item::as_str);
    if provider.is_some_and(|provider| provider != "openai") {
        return None;
    }
    profile
        .and_then(|profile| profile.get("model"))
        .or_else(|| document.get("model"))
        .and_then(Item::as_str)
        .filter(|model| !model.is_empty())
}

#[derive(Debug, PartialEq)]
enum CacheStatus {
    Present,
    Missing,
    Unavailable,
    VersionMismatch,
    Stale,
}

fn cached_model(raw: Option<&str>, version: &str, model: &str, now: DateTime<Utc>) -> CacheStatus {
    let Some(cache) = raw.and_then(|raw| serde_json::from_str::<Value>(raw).ok()) else {
        return CacheStatus::Unavailable;
    };
    if cache.get("client_version").and_then(Value::as_str) != Some(version) {
        return CacheStatus::VersionMismatch;
    }
    let Some(fetched) = cache
        .get("fetched_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
    else {
        return CacheStatus::Stale;
    };
    let age = now.signed_duration_since(fetched);
    if age.num_seconds() < -300 || age.num_seconds() > 3600 {
        return CacheStatus::Stale;
    }
    let Some(models) = cache.get("models").and_then(Value::as_array) else {
        return CacheStatus::Unavailable;
    };
    if models.is_empty()
        || models
            .iter()
            .any(|entry| entry.get("slug").and_then(Value::as_str).is_none())
    {
        return CacheStatus::Unavailable;
    }
    if models
        .iter()
        .any(|entry| entry.get("slug").and_then(Value::as_str) == Some(model))
    {
        CacheStatus::Present
    } else {
        CacheStatus::Missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_only_warns_missing_for_fresh_matching_cli() {
        let now = "2026-10-08T17:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let raw = json!({"client_version":"0.161.0","fetched_at":"2026-10-08T16:59:00Z","models":[{"slug":"available"}]}).to_string();
        assert_eq!(
            cached_model(Some(&raw), "0.161.0", "available", now),
            CacheStatus::Present
        );
        assert_eq!(
            cached_model(Some(&raw), "0.161.0", "missing", now),
            CacheStatus::Missing
        );
        assert_eq!(
            cached_model(Some(&raw), "0.154.0", "missing", now),
            CacheStatus::VersionMismatch
        );
        assert_eq!(
            cached_model(
                Some(&raw),
                "0.161.0",
                "missing",
                now + chrono::Duration::hours(2)
            ),
            CacheStatus::Stale
        );
        assert_eq!(
            cached_model(
                Some(&raw),
                "0.161.0",
                "missing",
                now - chrono::Duration::hours(2)
            ),
            CacheStatus::Stale
        );
        assert_eq!(
            cached_model(Some("{}"), "0.161.0", "missing", now),
            CacheStatus::VersionMismatch
        );
        assert_eq!(
            cached_model(None, "0.161.0", "missing", now),
            CacheStatus::Unavailable
        );
        assert_eq!(
            cached_model(Some("bad-json"), "0.161.0", "missing", now),
            CacheStatus::Unavailable
        );
    }

    #[test]
    fn active_profile_model_overrides_default_without_mutation() {
        let raw = "model = 'root'\nprofile = 'work'\n[profiles.work]\nmodel = 'profile'\nmodel_reasoning_effort = 'low'\n";
        let document = raw.parse::<DocumentMut>().unwrap();
        assert_eq!(configured_model(&document), Some("profile"));
        assert_eq!(document.to_string(), raw);
    }

    #[test]
    fn windows_shims_count_once_per_installation_and_keep_path_order() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let shadowed = dir.path().join("shadowed");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&shadowed).unwrap();
        fs::write(first.join("codex.cmd"), "").unwrap();
        fs::write(first.join("codex.ps1"), "").unwrap();
        fs::write(shadowed.join("codex.cmd"), "").unwrap();
        let paths = installations(&[first.clone(), first.clone(), shadowed], true);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], fs::canonicalize(first.join("codex.cmd")).unwrap());
    }
}
