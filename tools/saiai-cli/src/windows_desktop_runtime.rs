use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const RECEIPT_LIMIT: u64 = 16384;

#[cfg(any(windows, test))]
const HELPER_FAILURE_PREFIX: &str = "SAIAI_DESKTOP_HELPER_FAILURE:";

#[cfg(any(windows, test))]
const HELPER_FAILURE_REASONS: &[&str] = &[
    "interactive_session_required",
    "single_official_package_required",
    "official_package_identity_required",
    "official_package_app_id_required",
    "official_package_publisher_required",
    "official_package_store_signature_required",
    "official_package_not_ready",
    "official_package_root_changed",
    "package_refresh_requires_no_actors",
    "signed_entrypoint_required",
    "bounded_actor_inventory_required",
    "unknown_or_foreign_actor",
    "live_actor_inspection_required",
    "bounded_actor_command_line_required",
    "actor_inventory_did_not_settle",
    "same_user_actor_required",
    "bounded_command_arguments_required",
    "actor_changed_during_inspection",
    "runtime_reparse_point_refused",
    "foreign_runtime_owner",
    "unclassified_powershell_failure",
];

#[cfg(any(windows, test))]
const HELPER_FAILURE_CATEGORIES: &[&str] = &[
    "NotSpecified",
    "ObjectNotFound",
    "InvalidOperation",
    "PermissionDenied",
    "ParserError",
    "ResourceUnavailable",
    "InvalidArgument",
    "SecurityError",
    "OperationStopped",
    "OpenError",
    "ReadError",
    "WriteError",
];

#[cfg(any(windows, test))]
fn helper_script(script: &str) -> String {
    let reasons = HELPER_FAILURE_REASONS
        .iter()
        .map(|reason| format!("'{reason}'"))
        .collect::<Vec<_>>()
        .join(",");
    let categories = HELPER_FAILURE_CATEGORIES
        .iter()
        .map(|category| format!("'{category}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "try {{\n& {{\n{script}\n}}\n}} catch {{\n\
         $reason='unclassified_powershell_failure';\n\
         if($_.Exception.Message -cin @({reasons})){{$reason=$_.Exception.Message}};\n\
         $category=[string]$_.CategoryInfo.Category;\n\
         if($category -cnotin @({categories})){{$category='NotSpecified'}};\n\
         [Console]::Out.WriteLine('{HELPER_FAILURE_PREFIX}'+(@{{reason=$reason;category=$category}}|ConvertTo-Json -Compress));\n\
         exit 1\n}}"
    )
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperFailure {
    reason: String,
    category: String,
}

impl std::fmt::Display for HelperFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Windows Desktop helper diagnostic: reason={}, category={}",
            self.reason, self.category
        )
    }
}

impl std::error::Error for HelperFailure {}

#[cfg(any(windows, test))]
fn helper_failure_diagnostic(output: &[u8]) -> Option<HelperFailure> {
    if output.len() as u64 > RECEIPT_LIMIT {
        return None;
    }
    let encoded = std::str::from_utf8(output)
        .ok()?
        .trim()
        .strip_prefix(HELPER_FAILURE_PREFIX)?;
    let failure: HelperFailure = serde_json::from_str(encoded).ok()?;
    if !HELPER_FAILURE_REASONS.contains(&failure.reason.as_str())
        || !HELPER_FAILURE_CATEGORIES.contains(&failure.category.as_str())
    {
        return None;
    }
    Some(failure)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Package {
    pub app_id: String,
    pub install_location: PathBuf,
    pub package_version: String,
}

fn package_version(value: &str) -> Option<[u16; 4]> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut version = [0; 4];
    for (index, part) in parts.into_iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        version[index] = part.parse().ok()?;
    }
    Some(version)
}

fn parse_package(output: &str) -> Result<Option<Package>> {
    let invalid =
        || anyhow::anyhow!("Windows Desktop resolver returned an invalid package identity");
    if output.len() as u64 > RECEIPT_LIMIT {
        return Err(invalid());
    }
    let package: Option<Package> = serde_json::from_str(output.trim()).map_err(|_| invalid())?;
    if let Some(package) = &package
        && (!package.app_id.starts_with("OpenAI.Codex_")
            || !package.app_id.ends_with("!App")
            || package.app_id.len() > 256
            || package.install_location.as_os_str().is_empty()
            || package.install_location.as_os_str().len() > 4096
            || package_version(&package.package_version).is_none())
    {
        return Err(invalid());
    }
    Ok(package)
}

fn package_update_refused() -> anyhow::Error {
    anyhow::anyhow!(
        "Official Codex package changed or is not ready. Wait for its update to finish, then retry `saiai desktop codex`; if Desktop is open, use normal File > Quit first. No Desktop process was stopped or adopted."
    )
}

pub(crate) struct PackageObserver {
    package: Package,
    binding: Option<Snapshot>,
    actors_observed: bool,
    refresh_used: bool,
}

impl PackageObserver {
    pub(crate) fn new(package: Package) -> Self {
        Self {
            package,
            binding: None,
            actors_observed: false,
            refresh_used: false,
        }
    }

    pub(crate) fn identity(&self) -> Result<&Identity> {
        self.binding
            .as_ref()
            .map(|snapshot| &snapshot.identity)
            .context("Windows Desktop package identity has not been observed")
    }

    fn observe_with(
        &mut self,
        mut reader: impl FnMut(&Package, bool) -> Result<Snapshot>,
        mut resolver: impl FnMut() -> Result<Option<Package>>,
    ) -> Result<Snapshot> {
        let snapshot = match reader(&self.package, false) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let reason = error
                    .downcast_ref::<HelperFailure>()
                    .map(|failure| failure.reason.as_str());
                if reason != Some("official_package_root_changed") {
                    return Err(if reason == Some("official_package_not_ready") {
                        error.context(package_update_refused())
                    } else {
                        error
                    });
                }
                if self.refresh_used || self.actors_observed {
                    return Err(error.context(package_update_refused()));
                }
                self.refresh_used = true;
                let package = resolver()?.ok_or_else(package_update_refused)?;
                if package.app_id != self.package.app_id
                    || package.install_location == self.package.install_location
                    || package_version(&package.package_version).is_none()
                    || package_version(&self.package.package_version).is_none()
                    || package_version(&package.package_version)
                        <= package_version(&self.package.package_version)
                {
                    return Err(package_update_refused());
                }
                let current = reader(&package, true)?;
                if current.actor_count != 0
                    || !current.windows.is_empty()
                    || current.identity.app_id != package.app_id
                    || current.identity.package_version != package.package_version
                    || !valid_hash(&current.identity.entrypoint_sha256)
                    || current.identity.session_id == 0
                    || !current.identity.owner_sid.starts_with("S-")
                    || current.identity.owner_sid.len() > 256
                    || self.binding.as_ref().is_some_and(|prior| {
                        prior.identity.app_id != current.identity.app_id
                            || prior.identity.session_id != current.identity.session_id
                            || prior.identity.owner_sid != current.identity.owner_sid
                            || prior.codex_home != current.codex_home
                            || prior.runtime_directory != current.runtime_directory
                    })
                {
                    return Err(package_update_refused());
                }
                self.package = package;
                self.binding = Some(current.clone());
                current
            }
        };
        if snapshot.identity.app_id != self.package.app_id
            || snapshot.identity.package_version != self.package.package_version
            || self.binding.as_ref().is_some_and(|prior| {
                prior.identity != snapshot.identity
                    || prior.codex_home != snapshot.codex_home
                    || prior.runtime_directory != snapshot.runtime_directory
            })
        {
            return Err(refuse());
        }
        self.actors_observed |= snapshot.actor_count != 0;
        if self.binding.is_none() {
            self.binding = Some(snapshot.clone());
        }
        Ok(snapshot)
    }

    #[cfg(windows)]
    pub(crate) fn inspect(&mut self) -> Result<Snapshot> {
        self.observe_with(inspect_package, resolve_package)
    }
}

#[cfg(windows)]
pub(crate) fn resolve_package() -> Result<Option<Package>> {
    parse_package(&powershell(
        include_str!("windows_desktop_resolve.ps1"),
        &[],
    )?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub app_id: String,
    pub package_version: String,
    pub entrypoint_sha256: String,
    pub session_id: u32,
    pub owner_sid: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Window {
    pub process_id: u32,
    pub started_filetime: String,
    pub native_window: bool,
    pub proxy: Option<String>,
    pub spki: Option<String>,
    pub unsafe_overrides: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub identity: Identity,
    pub codex_home: String,
    pub runtime_directory: String,
    pub actor_count: usize,
    pub windows: Vec<Window>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub codex_home: String,
    pub proxy: String,
    pub ca_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub schema_version: u32,
    pub identity: Identity,
    pub profile: Profile,
    pub window: Window,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    Cold,
    Reuse(Box<Receipt>),
}

fn refuse() -> anyhow::Error {
    anyhow::anyhow!(
        "Cannot safely reuse the running OpenAI Desktop. Use its normal File > Quit, then retry `saiai desktop codex`. No Desktop process was stopped."
    )
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_pins(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.split(',').all(|pin| {
            base64::engine::general_purpose::STANDARD
                .decode(pin)
                .is_ok_and(|bytes| bytes.len() == 32)
        })
}

fn validate(snapshot: &Snapshot, profile: &Profile) -> Result<()> {
    let identity = &snapshot.identity;
    let proxy = url::Url::parse(&profile.proxy)?;
    if identity.session_id == 0
        || !identity.owner_sid.starts_with("S-")
        || identity.owner_sid.len() > 256
        || !identity.app_id.starts_with("OpenAI.Codex_")
        || !identity.app_id.ends_with("!App")
        || identity.package_version.is_empty()
        || !valid_hash(&identity.entrypoint_sha256)
        || !valid_hash(&profile.ca_sha256)
        || profile.codex_home.is_empty()
        || proxy.scheme() != "http"
        || !proxy.username().is_empty()
        || proxy.password().is_some()
        || proxy.query().is_some()
        || proxy.fragment().is_some()
        || proxy.path() != "/"
        || proxy.port().is_none_or(|port| port == 0)
        || !(matches!(proxy.host(), Some(url::Host::Ipv4(address)) if address.is_loopback())
            || matches!(proxy.host(), Some(url::Host::Ipv6(address)) if address.is_loopback()))
        || snapshot.codex_home != profile.codex_home
        || snapshot.runtime_directory.is_empty()
        || snapshot.actor_count > 64
        || snapshot.windows.len() > snapshot.actor_count
    {
        return Err(refuse());
    }
    Ok(())
}

fn matches_window(window: &Window, profile: &Profile, spki: &str) -> bool {
    window.process_id != 0
        && window
            .started_filetime
            .parse::<u64>()
            .is_ok_and(|started| started > 0)
        && window.native_window
        && !window.unsafe_overrides
        && window.proxy.as_deref() == Some(profile.proxy.as_str())
        && window.spki.as_deref() == Some(spki)
        && valid_pins(spki)
}

pub(crate) fn decide(
    snapshot: &Snapshot,
    profile: &Profile,
    receipt: Option<&Receipt>,
) -> Result<Decision> {
    validate(snapshot, profile)?;
    if snapshot.actor_count == 0 && snapshot.windows.is_empty() {
        return Ok(Decision::Cold);
    }
    let receipt = receipt.ok_or_else(refuse)?;
    if snapshot.windows.len() != 1
        || receipt.schema_version != 1
        || receipt.identity != snapshot.identity
        || receipt.profile != *profile
        || receipt.window != snapshot.windows[0]
        || !matches_window(
            &receipt.window,
            profile,
            receipt.window.spki.as_deref().unwrap_or_default(),
        )
    {
        return Err(refuse());
    }
    Ok(Decision::Reuse(Box::new(receipt.clone())))
}

pub(crate) fn accept_window(
    snapshot: &Snapshot,
    identity: &Identity,
    profile: &Profile,
    spki: &str,
    decision: &Decision,
    not_before_filetime: u64,
) -> Result<Option<Receipt>> {
    validate(snapshot, profile)?;
    if snapshot.identity != *identity || !valid_pins(spki) || snapshot.windows.len() > 1 {
        return Err(refuse());
    }
    let Some(window) = snapshot.windows.first() else {
        if matches!(decision, Decision::Reuse(_)) {
            return Err(refuse());
        }
        return Ok(None);
    };
    if matches!(decision, Decision::Reuse(prior) if prior.window != *window) {
        return Err(refuse());
    }
    if matches!(decision, Decision::Cold)
        && window.started_filetime.parse::<u64>().unwrap_or_default() < not_before_filetime
    {
        return Err(refuse());
    }
    if !window.native_window && matches!(decision, Decision::Cold) {
        return Ok(None);
    }
    if !matches_window(window, profile, spki) {
        return Err(refuse());
    }
    Ok(Some(Receipt {
        schema_version: 1,
        identity: identity.clone(),
        profile: profile.clone(),
        window: window.clone(),
    }))
}

fn reject_link(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("Desktop runtime link refused");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    bail!("Desktop runtime reparse point refused");
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn read_receipt(path: &Path) -> Result<Option<Receipt>> {
    reject_link(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refuse()),
    };
    let mut bytes = Vec::new();
    file.take(RECEIPT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > RECEIPT_LIMIT {
        return Err(refuse());
    }
    let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    if receipt.schema_version != 1 {
        return Err(refuse());
    }
    Ok(Some(receipt))
}

pub(crate) fn lock(directory: &Path) -> Result<File> {
    reject_link(directory)?;
    let path = directory.join("launch.lock");
    reject_link(&path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.try_lock()
        .context("Another SAIAI Desktop launch is in progress; retry after it finishes")?;
    Ok(file)
}

pub(crate) fn write_receipt(directory: &Path, receipt: &Receipt) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(receipt)?;
    if bytes.len() as u64 > RECEIPT_LIMIT {
        bail!("Desktop instance record exceeds its limit");
    }
    reject_link(directory)?;
    let destination = directory.join("instance.json");
    reject_link(&destination)?;
    let temporary = directory.join(format!("instance-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(windows)]
pub(crate) fn powershell(script: &str, variables: &[(&str, &std::ffi::OsStr)]) -> Result<String> {
    powershell_with_failure(script, variables, helper_failure)
}

#[cfg(windows)]
fn helper_failure() -> anyhow::Error {
    anyhow::anyhow!("Windows Desktop helper failed. No Desktop process was stopped.")
}

#[cfg(windows)]
fn runtime_directory_failure() -> anyhow::Error {
    anyhow::anyhow!(
        "Could not apply private Windows Desktop runtime directory permissions. No Desktop process was stopped."
    )
}

#[cfg(windows)]
fn powershell_with_failure(
    script: &str,
    variables: &[(&str, &std::ffi::OsStr)],
    failure: fn() -> anyhow::Error,
) -> Result<String> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let script = helper_script(script);
    let mut command = Command::new("powershell");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .envs(variables.iter().copied())
        .env_remove("PSModulePath")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("Could not inspect or activate Windows Desktop")?;
    let stdout = child
        .stdout
        .take()
        .context("Desktop observer output unavailable")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(RECEIPT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut status = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        if let Some(status) = status {
            if let Ok(result) = receiver.try_recv() {
                let bytes = result?;
                if !status.success() {
                    let error = failure();
                    return Err(match helper_failure_diagnostic(&bytes) {
                        Some(diagnostic) => error.context(diagnostic),
                        None => error,
                    });
                }
                if bytes.len() as u64 > RECEIPT_LIMIT {
                    bail!("Desktop observer output exceeded its limit");
                }
                return String::from_utf8(bytes).context("Desktop observer output is not UTF-8");
            }
        }
        if Instant::now() >= deadline {
            if status.is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
            bail!("Desktop observer/activation timed out; no Desktop process was stopped");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
pub(crate) fn protect_directory(directory: &Path) -> Result<()> {
    reject_link(directory)?;
    powershell_with_failure(
        r#"$ErrorActionPreference='Stop';$path=$env:SAIAI_RUNTIME_DIRECTORY;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$private=[Security.AccessControl.DirectorySecurity]::new();$private.SetOwner($sid);$private.SetAccessRuleProtection($true,$false);$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$private.AddAccessRule($rule);[IO.Directory]::CreateDirectory($path,$private)|Out-Null;$item=Get-Item -LiteralPath $path;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'runtime_reparse_point_refused'};$acl=Get-Acl -LiteralPath $path;if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'foreign_runtime_owner'};[IO.Directory]::SetAccessControl($path,$private);'ok'"#,
        &[("SAIAI_RUNTIME_DIRECTORY", directory.as_os_str())],
        runtime_directory_failure,
    )
    .context("Could not initialize the private Windows Desktop runtime directory")?;
    Ok(())
}

#[cfg(windows)]
fn inspect_package(package: &Package, require_no_actors: bool) -> Result<Snapshot> {
    let output = powershell(
        include_str!("windows_desktop_inspect.ps1"),
        &[
            (
                "SAIAI_RUNTIME_APP_ID",
                std::ffi::OsStr::new(&package.app_id),
            ),
            (
                "SAIAI_RUNTIME_PACKAGE_ROOT",
                package.install_location.as_os_str(),
            ),
            (
                "SAIAI_RUNTIME_REQUIRE_NO_ACTORS",
                std::ffi::OsStr::new(if require_no_actors { "1" } else { "0" }),
            ),
        ],
    )?;
    let mut snapshot: Snapshot = serde_json::from_str(output.trim()).map_err(|_| {
        anyhow::anyhow!(
            "Windows Desktop observer returned an invalid snapshot. No Desktop process was stopped."
        )
    })?;
    snapshot.codex_home = Path::new(&snapshot.codex_home)
        .canonicalize()?
        .to_str()
        .context("Windows Codex home is not valid Unicode")?
        .to_string();
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_diagnostics_accept_only_bounded_known_fields() {
        for reason in HELPER_FAILURE_REASONS {
            let encoded = format!(
                "{HELPER_FAILURE_PREFIX}{{\"reason\":\"{reason}\",\"category\":\"ObjectNotFound\"}}"
            );
            let diagnostic = helper_failure_diagnostic(encoded.as_bytes())
                .unwrap()
                .to_string();
            assert!(diagnostic.contains(reason));
            assert!(diagnostic.contains("ObjectNotFound"));
        }
        for encoded in [
            "TEST_ONLY_PRIVATE_STDOUT",
            "{\"reason\":\"live_actor_inspection_required\",\"category\":\"ObjectNotFound\"}",
            "SAIAI_DESKTOP_HELPER_FAILURE:{\"reason\":\"TEST_ONLY_PRIVATE\",\"category\":\"ObjectNotFound\"}",
            "SAIAI_DESKTOP_HELPER_FAILURE:{\"reason\":\"live_actor_inspection_required\",\"category\":\"TEST_ONLY_PRIVATE\"}",
            "SAIAI_DESKTOP_HELPER_FAILURE:{\"reason\":\"live_actor_inspection_required\",\"category\":\"ObjectNotFound\",\"secret\":\"TEST_ONLY_PRIVATE\"}",
            "SAIAI_DESKTOP_HELPER_FAILURE:{\"reason\":\"live_actor_inspection_required\"}",
            "SAIAI_DESKTOP_HELPER_FAILURE:not-json",
            "SAIAI_DESKTOP_HELPER_FAILURE:{\"reason\":\"live_actor_inspection_required\",\"category\":\"ObjectNotFound\"}\nTEST_ONLY_PRIVATE_STDOUT",
        ] {
            assert!(helper_failure_diagnostic(encoded.as_bytes()).is_none());
        }
        assert!(helper_failure_diagnostic(&vec![b' '; RECEIPT_LIMIT as usize + 1]).is_none());
        assert!(helper_failure_diagnostic(&[0xff]).is_none());
    }

    #[test]
    fn helper_script_preserves_source_and_does_not_print_raw_exceptions() {
        let source = include_str!("windows_desktop_inspect.ps1");
        let script = helper_script(source);
        assert!(script.contains(source));
        assert!(script.contains("[Console]::Out.WriteLine('SAIAI_DESKTOP_HELPER_FAILURE:'"));
        assert!(script.contains("exit 1"));
        for forbidden in ["Write-Error", "$_ |", "$_.ToString()", "Stop-Process"] {
            assert!(!script.contains(forbidden));
        }
    }

    fn fixture() -> (Snapshot, Profile, Receipt) {
        let profile = Profile {
            codex_home: "standard-user-codex-home".into(),
            proxy: "http://127.0.0.1:19908".into(),
            ca_sha256: "a".repeat(64),
        };
        let snapshot = Snapshot {
            identity: Identity {
                app_id: "OpenAI.Codex_fixture!App".into(),
                package_version: "26.928.2636.0".into(),
                entrypoint_sha256: "b".repeat(64),
                session_id: 2,
                owner_sid: "S-1-5-21-fixture".into(),
            },
            codex_home: profile.codex_home.clone(),
            runtime_directory: "same-user-local-appdata-runtime".into(),
            actor_count: 8,
            windows: vec![Window {
                process_id: 1560,
                started_filetime: "134353986364721150".into(),
                native_window: true,
                proxy: Some(profile.proxy.clone()),
                spki: Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32])),
                unsafe_overrides: false,
            }],
        };
        let receipt = Receipt {
            schema_version: 1,
            identity: snapshot.identity.clone(),
            profile: profile.clone(),
            window: snapshot.windows[0].clone(),
        };
        (snapshot, profile, receipt)
    }

    fn package_fixture() -> (Package, Snapshot, Package, Snapshot) {
        let (mut initial, _, _) = fixture();
        initial.actor_count = 0;
        initial.windows.clear();
        let previous = Package {
            app_id: initial.identity.app_id.clone(),
            install_location: PathBuf::from("C:/TEST_ONLY/previous"),
            package_version: initial.identity.package_version.clone(),
        };
        let next = Package {
            install_location: PathBuf::from("C:/TEST_ONLY/next"),
            package_version: "26.930.4958.0".into(),
            ..previous.clone()
        };
        let mut current = initial.clone();
        current.identity.package_version = next.package_version.clone();
        current.identity.entrypoint_sha256 = "c".repeat(64);
        (previous, initial, next, current)
    }

    fn package_failure(reason: &str) -> anyhow::Error {
        anyhow::anyhow!("Windows Desktop helper failed").context(HelperFailure {
            reason: reason.into(),
            category: "OperationStopped".into(),
        })
    }

    #[test]
    fn package_resolution_is_bounded_and_rejects_untrusted_shapes_without_raw_output() {
        assert!(parse_package("null").unwrap().is_none());
        let (package, _, _, _) = package_fixture();
        let encoded = serde_json::json!({
            "app_id":package.app_id,"install_location":package.install_location,
            "package_version":package.package_version,
        });
        assert_eq!(parse_package(&encoded.to_string()).unwrap(), Some(package));
        for (field, value) in [
            ("app_id", "TEST_ONLY_PRIVATE"),
            ("package_version", "26.930"),
            ("package_version", "26.930.4958.65536"),
            ("package_version", "26.930.-1.0"),
            ("install_location", ""),
            ("private", "TEST_ONLY_PRIVATE"),
        ] {
            let mut invalid = encoded.clone();
            invalid[field] = value.into();
            let error = parse_package(&invalid.to_string()).unwrap_err();
            assert!(!format!("{error:#}").contains("TEST_ONLY_PRIVATE"));
        }
        assert!(parse_package(&"x".repeat(RECEIPT_LIMIT as usize + 1)).is_err());
        assert!(parse_package("TEST_ONLY_PRIVATE").is_err());
    }

    #[test]
    fn package_observer_refreshes_one_empty_context_and_preserves_window_guards() {
        for has_initial_snapshot in [false, true] {
            let (previous, initial, next, current) = package_fixture();
            let mut observer = PackageObserver::new(previous.clone());
            if has_initial_snapshot {
                observer
                    .observe_with(
                        |_, strict| {
                            assert!(!strict);
                            Ok(initial.clone())
                        },
                        || panic!("unexpected resolution"),
                    )
                    .unwrap();
            }
            let mut reads = 0;
            let result = observer
                .observe_with(
                    |package, strict| {
                        reads += 1;
                        if package == &previous {
                            assert!(!strict);
                            return Err(package_failure("official_package_root_changed"));
                        }
                        assert_eq!(package, &next);
                        assert!(strict);
                        Ok(current.clone())
                    },
                    || Ok(Some(next.clone())),
                )
                .unwrap();
            assert_eq!(reads, 2);
            assert_eq!(observer.identity().unwrap(), &current.identity);
            assert_eq!(result.actor_count, 0);
            assert!(observer.refresh_used);

            let (_, profile, receipt) = fixture();
            let mut launched = current.clone();
            launched.actor_count = 1;
            launched.windows = vec![receipt.window.clone()];
            let observed = observer
                .observe_with(
                    |package, strict| {
                        assert_eq!(package, &next);
                        assert!(!strict);
                        Ok(launched.clone())
                    },
                    || panic!("unexpected resolution"),
                )
                .unwrap();
            let pins = receipt.window.spki.as_deref().unwrap();
            assert!(
                accept_window(
                    &observed,
                    observer.identity().unwrap(),
                    &profile,
                    pins,
                    &Decision::Cold,
                    1
                )
                .unwrap()
                .is_some()
            );
            for field in ["proxy", "spki", "started_filetime", "unsafe_overrides"] {
                let mut invalid = launched.clone();
                match field {
                    "proxy" => invalid.windows[0].proxy = Some("http://127.0.0.1:1".into()),
                    "spki" => invalid.windows[0].spki = Some("bad-pin".into()),
                    "started_filetime" => invalid.windows[0].started_filetime = "0".into(),
                    _ => invalid.windows[0].unsafe_overrides = true,
                }
                assert!(
                    accept_window(
                        &invalid,
                        observer.identity().unwrap(),
                        &profile,
                        pins,
                        &Decision::Cold,
                        1
                    )
                    .is_err()
                );
            }
            assert!(
                observer
                    .observe_with(
                        |_, _| Err(package_failure("official_package_root_changed")),
                        || panic!("second refresh")
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn package_observer_never_retries_other_failures_or_forged_reason_text() {
        for reason in HELPER_FAILURE_REASONS {
            if *reason == "official_package_root_changed" {
                continue;
            }
            let (previous, _, _, _) = package_fixture();
            let mut observer = PackageObserver::new(previous);
            let error = observer
                .observe_with(
                    |_, _| Err(package_failure(reason)),
                    || panic!("unexpected resolution"),
                )
                .unwrap_err();
            assert!(format!("{error:#}").contains(reason));
            assert!(!observer.refresh_used);
        }
        let (previous, _, _, _) = package_fixture();
        let mut observer = PackageObserver::new(previous);
        assert!(
            observer
                .observe_with(
                    |_, _| Err(anyhow::anyhow!("official_package_root_changed")),
                    || panic!("forged reason accepted")
                )
                .is_err()
        );
    }

    #[test]
    fn package_observer_refuses_refresh_after_any_actor_even_if_it_later_exits() {
        let (previous, mut initial, _, _) = package_fixture();
        initial.actor_count = 1;
        let mut observer = PackageObserver::new(previous);
        observer
            .observe_with(
                |_, _| Ok(initial.clone()),
                || panic!("unexpected resolution"),
            )
            .unwrap();
        initial.actor_count = 0;
        observer
            .observe_with(
                |_, _| Ok(initial.clone()),
                || panic!("unexpected resolution"),
            )
            .unwrap();
        assert!(
            observer
                .observe_with(
                    |_, _| Err(package_failure("official_package_root_changed")),
                    || panic!("live context refreshed")
                )
                .is_err()
        );
    }

    #[test]
    fn package_observer_refresh_requires_same_identity_newer_version_and_zero_actors() {
        for field in [
            "actor_count",
            "windows",
            "app_id",
            "session_id",
            "owner_sid",
            "codex_home",
            "runtime_directory",
            "package_version",
            "entrypoint_sha256",
        ] {
            let (previous, initial, next, mut current) = package_fixture();
            let (_, _, receipt) = fixture();
            match field {
                "actor_count" => current.actor_count = 1,
                "windows" => current.windows = vec![receipt.window],
                "app_id" => current.identity.app_id = "OpenAI.Codex_other!App".into(),
                "session_id" => current.identity.session_id += 1,
                "owner_sid" => current.identity.owner_sid = "S-1-5-9999".into(),
                "codex_home" => current.codex_home = "other-home".into(),
                "runtime_directory" => current.runtime_directory = "other-runtime".into(),
                "package_version" => {
                    current.identity.package_version = initial.identity.package_version.clone()
                }
                _ => current.identity.entrypoint_sha256 = "invalid".into(),
            }
            let mut observer = PackageObserver::new(previous.clone());
            observer
                .observe_with(
                    |_, _| Ok(initial.clone()),
                    || panic!("unexpected resolution"),
                )
                .unwrap();
            assert!(
                observer
                    .observe_with(
                        |package, _| {
                            if package == &previous {
                                Err(package_failure("official_package_root_changed"))
                            } else {
                                Ok(current.clone())
                            }
                        },
                        || Ok(Some(next.clone()))
                    )
                    .is_err(),
                "accepted {field}"
            );
            assert_eq!(observer.identity().unwrap(), &initial.identity);
            assert_eq!(observer.package, previous);
        }
        for field in [
            "same_path",
            "same_version",
            "downgrade",
            "invalid_version",
            "different_app",
        ] {
            let (previous, _, mut next, _) = package_fixture();
            match field {
                "same_path" => next.install_location = previous.install_location.clone(),
                "same_version" => next.package_version = previous.package_version.clone(),
                "downgrade" => next.package_version = "1.0.0.0".into(),
                "invalid_version" => next.package_version = "invalid".into(),
                _ => next.app_id = "OpenAI.Codex_other!App".into(),
            }
            let mut observer = PackageObserver::new(previous.clone());
            assert!(
                observer
                    .observe_with(
                        |package, _| {
                            assert_eq!(package, &previous);
                            Err(package_failure("official_package_root_changed"))
                        },
                        || Ok(Some(next.clone()))
                    )
                    .is_err(),
                "accepted {field}"
            );
        }
    }

    #[test]
    fn package_observer_discards_failed_refresh_and_refuses_unannounced_identity_changes() {
        let (previous, initial, next, current) = package_fixture();
        let mut observer = PackageObserver::new(previous.clone());
        observer
            .observe_with(
                |_, _| Ok(initial.clone()),
                || panic!("unexpected resolution"),
            )
            .unwrap();
        assert!(
            observer
                .observe_with(
                    |_, _| Ok(current.clone()),
                    || panic!("unexpected resolution")
                )
                .is_err()
        );
        assert_eq!(observer.identity().unwrap(), &initial.identity);
        let error = observer
            .observe_with(
                |package, strict| {
                    if package == &previous {
                        return Err(package_failure("official_package_root_changed"));
                    }
                    assert!(strict);
                    Err(package_failure("signed_entrypoint_required"))
                },
                || Ok(Some(next.clone())),
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("signed_entrypoint_required"));
        assert_eq!(observer.package, previous);
        assert_eq!(observer.identity().unwrap(), &initial.identity);
        assert!(
            observer
                .observe_with(
                    |_, _| Err(package_failure("official_package_root_changed")),
                    || panic!("failed refresh retried")
                )
                .is_err()
        );
    }

    #[test]
    fn package_resolution_and_observation_do_not_activate_or_mutate_desktop() {
        let resolver = include_str!("windows_desktop_resolve.ps1");
        assert_eq!(resolver.matches("Get-AppxPackage").count(), 1);
        assert!(!resolver.contains("Get-StartApps"));
        for source in [resolver, include_str!("windows_desktop_inspect.ps1")] {
            for forbidden in [
                "Stop-Process",
                "Start-Process",
                "ActivateApplication",
                "Set-ItemProperty",
                "Remove-AppxPackage",
                "Add-AppxPackage",
            ] {
                assert!(!source.contains(forbidden));
            }
        }
        let main = include_str!("main.rs");
        let launcher = main
            .split("fn run_windows_packaged_desktop(")
            .nth(1)
            .unwrap()
            .split("fn windows_packaged_profile(")
            .next()
            .unwrap();
        assert_eq!(
            launcher
                .matches("activate_windows_packaged_desktop(")
                .count(),
            1
        );
        assert_eq!(launcher.matches("observer.identity()?").count(), 2);
    }

    #[test]
    fn cold_requires_no_actors_and_does_not_adopt_stale_receipts() {
        let (mut snapshot, profile, mut receipt) = fixture();
        snapshot.actor_count = 0;
        snapshot.windows.clear();
        receipt.schema_version = 99;
        assert_eq!(
            decide(&snapshot, &profile, Some(&receipt)).unwrap(),
            Decision::Cold
        );
        snapshot.actor_count = 1;
        assert!(decide(&snapshot, &profile, Some(&receipt)).is_err());
    }

    #[test]
    fn decision_layout_stays_small_without_changing_receipt_serialization() {
        assert!(std::mem::size_of::<Decision>() <= 2 * std::mem::size_of::<usize>());
        let (snapshot, profile, receipt) = fixture();
        let serialized = serde_json::to_vec(&receipt).unwrap();
        let Decision::Reuse(owned) = decide(&snapshot, &profile, Some(&receipt)).unwrap() else {
            panic!("compatible fixture must reuse");
        };
        assert_eq!(*owned, receipt);
        assert_eq!(serde_json::to_vec(owned.as_ref()).unwrap(), serialized);
    }

    #[test]
    fn compatible_record_reuses_without_requiring_broker_pid() {
        let (snapshot, profile, receipt) = fixture();
        let decision = decide(&snapshot, &profile, Some(&receipt)).unwrap();
        assert_eq!(decision, Decision::Reuse(Box::new(receipt.clone())));
        assert_eq!(
            accept_window(
                &snapshot,
                &snapshot.identity,
                &profile,
                receipt.window.spki.as_deref().unwrap(),
                &decision,
                u64::MAX
            )
            .unwrap(),
            Some(receipt)
        );
    }

    #[test]
    fn unknown_hidden_and_multiple_instances_refuse() {
        let (mut snapshot, profile, receipt) = fixture();
        assert!(decide(&snapshot, &profile, None).is_err());
        snapshot.windows[0].native_window = false;
        assert!(decide(&snapshot, &profile, Some(&receipt)).is_err());
        snapshot.windows = vec![receipt.window.clone(), receipt.window.clone()];
        assert!(decide(&snapshot, &profile, Some(&receipt)).is_err());
    }

    #[test]
    fn each_stale_identity_profile_and_window_field_refuses() {
        let (snapshot, profile, receipt) = fixture();
        let mut cases = Vec::new();
        for field in [
            "app_id",
            "package_version",
            "entrypoint_sha256",
            "owner_sid",
        ] {
            let mut changed = serde_json::to_value(&receipt).unwrap();
            changed["identity"][field] = "synthetic-changed".into();
            cases.push(serde_json::from_value::<Receipt>(changed).unwrap());
        }
        for field in ["codex_home", "proxy", "ca_sha256"] {
            let mut changed = serde_json::to_value(&receipt).unwrap();
            changed["profile"][field] = "synthetic-changed".into();
            cases.push(serde_json::from_value::<Receipt>(changed).unwrap());
        }
        let mut changed = receipt.clone();
        changed.schema_version = 2;
        cases.push(changed);
        let mut changed = receipt.clone();
        changed.identity.session_id += 1;
        cases.push(changed);
        let mut changed = receipt.clone();
        changed.window.process_id += 1;
        cases.push(changed);
        let mut changed = receipt.clone();
        changed.window.started_filetime = "134353986364721151".into();
        cases.push(changed);
        for case in cases {
            assert!(decide(&snapshot, &profile, Some(&case)).is_err());
        }
    }

    #[test]
    fn matching_but_unsafe_startup_arguments_are_never_accepted() {
        let (snapshot, profile, receipt) = fixture();
        for missing in [false, true] {
            let mut altered = snapshot.clone();
            altered.windows[0].spki = if missing {
                None
            } else {
                Some("invalid-pin".into())
            };
            let mut record = receipt.clone();
            record.window = altered.windows[0].clone();
            assert!(decide(&altered, &profile, Some(&record)).is_err());
        }
        let mut altered = snapshot.clone();
        altered.windows[0].unsafe_overrides = true;
        let mut record = receipt.clone();
        record.window = altered.windows[0].clone();
        assert!(decide(&altered, &profile, Some(&record)).is_err());
    }

    #[test]
    fn foreign_session_profile_and_nonloopback_proxy_refuse() {
        let (snapshot, profile, receipt) = fixture();
        for session in [0, 3] {
            let mut altered = snapshot.clone();
            altered.identity.session_id = session;
            assert!(decide(&altered, &profile, Some(&receipt)).is_err());
        }
        let mut altered = snapshot.clone();
        altered.codex_home = "inherited-but-not-native-profile".into();
        assert!(decide(&altered, &profile, Some(&receipt)).is_err());
        for address in [
            "http://192.168.1.1:19908",
            "http://localhost:19908",
            "http://user:secret@127.0.0.1:19908",
            "http://127.0.0.1:19908/path",
            "https://127.0.0.1:19908",
        ] {
            let mut altered = profile.clone();
            altered.proxy = address.into();
            assert!(decide(&snapshot, &altered, Some(&receipt)).is_err());
        }
    }

    #[test]
    fn cold_observation_refuses_old_epoch_and_mismatched_binding() {
        let (snapshot, profile, receipt) = fixture();
        let pins = receipt.window.spki.as_deref().unwrap();
        let started = receipt.window.started_filetime.parse::<u64>().unwrap();
        assert!(
            accept_window(
                &snapshot,
                &snapshot.identity,
                &profile,
                pins,
                &Decision::Cold,
                started + 1
            )
            .is_err()
        );
        assert!(
            accept_window(
                &snapshot,
                &snapshot.identity,
                &profile,
                "bad-pin",
                &Decision::Cold,
                started
            )
            .is_err()
        );
        assert!(
            accept_window(
                &snapshot,
                &snapshot.identity,
                &profile,
                pins,
                &Decision::Cold,
                started
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn reuse_never_adopts_restarted_or_missing_window() {
        let (mut snapshot, profile, receipt) = fixture();
        let pins = receipt.window.spki.as_deref().unwrap();
        let decision = Decision::Reuse(Box::new(receipt.clone()));
        snapshot.windows[0].process_id += 1;
        assert!(
            accept_window(&snapshot, &snapshot.identity, &profile, pins, &decision, 0).is_err()
        );
        snapshot.windows.clear();
        assert!(
            accept_window(&snapshot, &snapshot.identity, &profile, pins, &decision, 0).is_err()
        );
        assert!(
            accept_window(
                &snapshot,
                &snapshot.identity,
                &profile,
                pins,
                &Decision::Cold,
                0
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn records_are_bounded_strict_and_redact_invalid_input() {
        let (_, _, receipt) = fixture();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("instance.json");
        assert!(read_receipt(&path).unwrap().is_none());
        for bytes in [
            b"private-secret-not-json".to_vec(),
            vec![b'x'; RECEIPT_LIMIT as usize + 1],
            Vec::new(),
        ] {
            fs::write(&path, bytes).unwrap();
            let error = read_receipt(&path).unwrap_err().to_string();
            assert!(!error.contains("private-secret"));
        }
        let mut changed = serde_json::to_value(&receipt).unwrap();
        changed["unknown"] = "private-secret".into();
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(read_receipt(&path).is_err());
        changed.as_object_mut().unwrap().remove("unknown");
        changed["schema_version"] = 2.into();
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(read_receipt(&path).is_err());
        changed.as_object_mut().unwrap().remove("schema_version");
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(read_receipt(&path).is_err());
    }

    #[test]
    fn atomic_receipt_replacement_preserves_only_nonsecret_identity() {
        let (_, _, mut receipt) = fixture();
        let directory = tempfile::tempdir().unwrap();
        write_receipt(directory.path(), &receipt).unwrap();
        receipt.window.process_id += 1;
        write_receipt(directory.path(), &receipt).unwrap();
        assert_eq!(
            read_receipt(&directory.path().join("instance.json")).unwrap(),
            Some(receipt)
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.path().join("instance.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn lock_serializes_launchers_without_deleting_the_lockfile() {
        let directory = tempfile::tempdir().unwrap();
        let first = lock(directory.path()).unwrap();
        assert!(lock(directory.path()).is_err());
        drop(first);
        assert!(lock(directory.path()).is_ok());
        assert!(directory.path().join("launch.lock").exists());
    }

    #[test]
    fn runtime_creation_assigns_private_owner_before_checking_existing_ownership() {
        let source = include_str!("windows_desktop_runtime.rs");
        let initialization = source
            .split("pub(crate) fn protect_directory(")
            .nth(1)
            .unwrap()
            .split("fn inspect_package(")
            .next()
            .unwrap();
        assert!(!initialization.contains("fs::create_dir_all"));
        assert!(
            initialization.find("SetOwner($sid)").unwrap()
                < initialization
                    .find("CreateDirectory($path,$private)")
                    .unwrap()
        );
        assert!(
            initialization.find("foreign_runtime_owner").unwrap()
                < initialization
                    .find("SetAccessControl($path,$private)")
                    .unwrap()
        );
        assert!(!initialization.contains("Set-Acl"));
        assert!(initialization.contains("runtime_reparse_point_refused"));
        assert!(initialization.contains("powershell_with_failure("));
        assert!(initialization.contains("runtime_directory_failure"));
    }

    #[cfg(windows)]
    fn assert_native_private_runtime(directory: &Path) {
        let verified = powershell(
            r#"$ErrorActionPreference='Stop';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$acl=Get-Acl -LiteralPath $env:SAIAI_RUNTIME_DIRECTORY;$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or -not $acl.AreAccessRulesProtected -or $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or [string]$rules[0].AccessControlType -ne 'Allow' -or [string]$rules[0].FileSystemRights -ne 'FullControl'){throw 'private_current_user_runtime_required'};'verified'"#,
            &[("SAIAI_RUNTIME_DIRECTORY", directory.as_os_str())],
        )
        .unwrap();
        assert_eq!(verified.trim(), "verified");
    }

    #[cfg(windows)]
    #[test]
    fn native_runtime_creation_has_private_current_user_owner_and_preserves_files() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("private-runtime");
        assert!(!directory.exists());
        protect_directory(&directory).unwrap();
        let marker = directory.join("unchanged-fixture");
        fs::write(&marker, b"owned-runtime-fixture").unwrap();
        protect_directory(&directory).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), b"owned-runtime-fixture");
        assert_native_private_runtime(&directory);
    }

    #[cfg(windows)]
    #[test]
    fn native_runtime_protection_removes_inherited_access_without_changing_files() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("inherited-runtime");
        let created = powershell(
            r#"$ErrorActionPreference='Stop';try{$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$security=[Security.AccessControl.DirectorySecurity]::new();$security.SetOwner($sid);$security.SetAccessRuleProtection($false,$true);$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));[IO.Directory]::CreateDirectory($env:SAIAI_RUNTIME_DIRECTORY,$security)|Out-Null;[IO.Directory]::SetAccessControl($env:SAIAI_RUNTIME_DIRECTORY,$security);$acl=Get-Acl -LiteralPath $env:SAIAI_RUNTIME_DIRECTORY;if($acl.AreAccessRulesProtected){throw 'inherited_fixture_required'};'created'}catch{'fixture_failed:'+ $_.FullyQualifiedErrorId}"#,
            &[("SAIAI_RUNTIME_DIRECTORY", directory.as_os_str())],
        )
        .unwrap();
        assert_eq!(created.trim(), "created");
        let marker = directory.join("unchanged-fixture");
        fs::write(&marker, b"owned-inherited-runtime-fixture").unwrap();
        protect_directory(&directory).unwrap();
        assert_native_private_runtime(&directory);
        assert_eq!(
            fs::read(&marker).unwrap(),
            b"owned-inherited-runtime-fixture"
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_powershell_uses_its_own_module_path() {
        let output = powershell(
            "$ErrorActionPreference='Stop';if($env:PSModulePath -like '*TEST_ONLY_INVALID_MODULE_PATH*'){throw 'foreign_module_path_inherited'};Get-Command Get-Acl -ErrorAction Stop|Out-Null;'verified'",
            &[("PSModulePath", std::ffi::OsStr::new("TEST_ONLY_INVALID_MODULE_PATH"))],
        )
        .unwrap();
        assert_eq!(output.trim(), "verified");
    }

    #[cfg(windows)]
    #[test]
    fn runtime_permission_failure_is_not_a_desktop_reuse_error_or_raw_output() {
        let error = powershell_with_failure(
            "'TEST_ONLY_PRIVATE_STDOUT'; [Console]::Error.WriteLine('TEST_ONLY_PRIVATE_STDERR'); exit 7",
            &[],
            runtime_directory_failure,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("runtime directory permissions"));
        for forbidden in ["Cannot safely reuse", "File > Quit", "TEST_ONLY_PRIVATE"] {
            assert!(!error.contains(forbidden));
        }
        assert!(
            powershell("exit 7", &[])
                .unwrap_err()
                .to_string()
                .contains("Windows Desktop helper failed")
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_helper_failures_report_only_safe_reason_and_category() {
        let known = powershell("throw 'live_actor_inspection_required'", &[]).unwrap_err();
        let known_chain = format!("{known:#}");
        assert!(known_chain.contains("reason=live_actor_inspection_required"));
        assert!(!known_chain.contains("Cannot safely reuse"));
        assert!(!known_chain.contains("File > Quit"));
        let unknown = powershell("throw 'TEST_ONLY_PRIVATE_EXCEPTION'", &[]).unwrap_err();
        let unknown_chain = format!("{unknown:#}");
        assert!(unknown_chain.contains("reason=unclassified_powershell_failure"));
        assert!(!unknown_chain.contains("TEST_ONLY_PRIVATE"));
        assert_eq!(
            powershell("'unchanged-success'", &[]).unwrap().trim(),
            "unchanged-success"
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_observer_rebuilds_only_after_confirmed_actor_exit() {
        let script = include_str!("windows_desktop_inspect_tests.ps1").replace(
            "__OBSERVER_SOURCE__",
            &base64::engine::general_purpose::STANDARD
                .encode(include_str!("windows_desktop_inspect.ps1")),
        );
        let output = powershell(&script, &[]).unwrap();
        let cases: Vec<serde_json::Value> = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(cases.len(), 40);
        for case in cases {
            assert_eq!(case["passed"], true, "observer fixture: {}", case["name"]);
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_resolver_reads_one_trusted_package_without_separate_start_app_lookup() {
        let script = include_str!("windows_desktop_resolve_tests.ps1").replace(
            "__RESOLVER_SOURCE__",
            &base64::engine::general_purpose::STANDARD
                .encode(include_str!("windows_desktop_resolve.ps1")),
        );
        let output = powershell(&script, &[]).unwrap();
        let cases: Vec<serde_json::Value> = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(cases.len(), 7);
        for case in cases {
            assert_eq!(case["passed"], true, "resolver fixture: {}", case["name"]);
        }
    }

    #[cfg(unix)]
    #[test]
    fn linked_runtime_paths_are_rejected_without_modifying_targets() {
        use std::os::unix::fs::symlink;
        let (_, _, receipt) = fixture();
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("fixture-secret");
        fs::write(&secret, b"unchanged-private-fixture").unwrap();
        symlink(&secret, directory.path().join("instance.json")).unwrap();
        assert!(read_receipt(&directory.path().join("instance.json")).is_err());
        assert!(write_receipt(directory.path(), &receipt).is_err());
        assert_eq!(fs::read(&secret).unwrap(), b"unchanged-private-fixture");
    }

    #[test]
    fn actor_observer_is_read_only_and_never_exports_command_lines() {
        let source = include_str!("windows_desktop_inspect.ps1");
        for forbidden in [
            "Stop-Process",
            "Set-ItemProperty",
            "SetEnvironmentVariable",
            "raw_command",
            "command_line=",
        ] {
            assert!(!source.contains(forbidden));
        }
        for required in [
            "GetOwnerSid",
            "Get-AuthenticodeSignature",
            "SignatureKind",
            "CommandLineToArgvW",
            "OperationTimeoutSec 3",
            "LocalApplicationData",
            "GetFolderPath('UserProfile')",
            "Substring('--ignore-certificate-errors-spki-list='.Length)",
            "$_ -like '--disable-web-security*'",
        ] {
            assert!(source.contains(required));
        }
    }

    #[test]
    fn actor_observer_retry_is_bounded_and_discards_partial_snapshots() {
        let source = include_str!("windows_desktop_inspect.ps1").replace("\r\n", "\n");
        for required in [
            "function Read-ActorIdentity($process)",
            "function Read-ActorSnapshot",
            "if ($process.HasExited) { return $null }",
            "$identity = Read-ActorIdentity $process",
            "if ($null -eq $identity) { return $null }",
            "$relevant += @{process=$process;identity=$identity}",
            "throw 'live_actor_inspection_required'",
            "throw 'bounded_actor_command_line_required'",
            "$attempt -lt 3",
            "$snapshot = Read-ActorSnapshot",
            "Start-Sleep -Milliseconds 100",
            "throw 'actor_inventory_did_not_settle'",
            "actor_count=$snapshot.actor_count",
            "windows=@($snapshot.windows)",
        ] {
            assert!(
                source.contains(required),
                "missing observer guard: {required}"
            );
        }
        let snapshot = source
            .split("function Read-ActorSnapshot {")
            .nth(1)
            .unwrap();
        assert!(
            snapshot.find("$relevant = @()").unwrap()
                < snapshot
                    .find("$identity = Read-ActorIdentity $process")
                    .unwrap()
        );
        assert!(
            snapshot
                .find("if ($null -eq $identity) { return $null }")
                .unwrap()
                < snapshot.find("throw 'unknown_or_foreign_actor'").unwrap()
        );
        assert!(
            snapshot.find("$windows = @()").unwrap() < snapshot.find("$process.HasExited").unwrap()
        );
        let identity = source
            .split("function Read-ActorIdentity($process) {")
            .nth(1)
            .unwrap()
            .split("function Read-ActorSnapshot {")
            .next()
            .unwrap();
        let (before, after) = identity.split_once("$identity = @{").unwrap();
        assert!(before.contains("if ($process.HasExited) { return $null }"));
        assert!(after.contains("if ($process.HasExited) { return $null }"));
        assert!(
            after.contains(
                "catch {\n        if ($process.HasExited) { return $null }\n        throw"
            )
        );
    }

    #[test]
    fn packaged_dispatch_guards_before_proxy_mutation_and_ignores_broker_liveness() {
        let main = include_str!("main.rs");
        let dispatch = main
            .split("fn run_windows_desktop(")
            .nth(1)
            .unwrap()
            .split("fn run_windows_packaged_desktop(")
            .next()
            .unwrap();
        assert!(
            dispatch
                .find("return run_windows_packaged_desktop")
                .unwrap()
                < dispatch.find("ensure_local_proxy_running").unwrap()
        );
        let launch = main
            .split("fn run_windows_packaged_desktop(")
            .nth(1)
            .unwrap()
            .split("fn windows_packaged_profile(")
            .next()
            .unwrap();
        assert!(
            launch.find("windows_desktop_runtime::decide").unwrap()
                < launch.find("ensure_local_proxy_running").unwrap()
        );
        assert!(launch.contains("let _broker_pid = activate_windows_packaged_desktop"));
        assert!(launch.contains("let pid = observed.window.process_id"));
        assert!(!launch.contains("windows_pid_is_running"));
        assert!(!main.contains("fn stop_windows_packaged_desktop("));
    }
}
