use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;
use zeroize::Zeroize;

use crate::fsutil::{
    atomic_write_private, ensure_no_managed_symlinks, ensure_private_dir, open_private_lock_file,
    path_present_no_follow, promote_new_directory, reject_symlink_if_present, remove_dir_if_exists,
};
use crate::lease::{ExclusiveGenerationLease, ExclusiveLeaseProbe, GenerationLease};
use crate::{
    AppPaths, CLAUDE_CA_CERT_FILENAME, CLAUDE_CA_KEY_FILENAME, CLAUDE_SETTINGS_FILENAME,
    CLAUDE_STATE_FILENAME, CODEX_CONFIG_FILENAME, ClaudeSetupArtifacts, CodexSetupArtifacts,
    CommittedProduct, ConfigV2, CredentialRef, CredentialStore, Error, FileCredentialStore,
    GatewayUrl, GenerationRef, Product, ProductConfig, ProductSetupArtifacts, ProductSetupState,
    ProductSetupStatus, Result, RevokeReport, RevokeTarget, SecretString, SetupIssue,
    SetupIssueCode, SetupState, SetupStatus,
};

const PRODUCT_MARKER_FILENAME: &str = ".saiai-managed-v2";
const PRODUCT_MARKER: &[u8] = b"saiai-managed-client-home-v2\n";
const UNSAFE_GATEWAY_CREDENTIAL_MESSAGE: &str =
    "the Gateway URL contains a stored API key; run `saiai revoke --all` to reset this V2 state";

/// Validated non-artifact input for one product setup transaction.
#[derive(Debug)]
pub struct SetupRequest {
    base_url: GatewayUrl,
    credential: SecretString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneratedEntryKind {
    GenerationDirectory,
    LeaseFile,
}

struct ProductResources {
    generations: Vec<GenerationRef>,
    removal_paths: Vec<PathBuf>,
    previous_quarantines: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
struct ManagedRootPresence {
    config: bool,
    data: bool,
    state: bool,
}

impl ManagedRootPresence {
    fn inspect(paths: &AppPaths) -> Result<Self> {
        Ok(Self {
            config: path_present_no_follow(paths.config_dir())?,
            data: path_present_no_follow(paths.data_dir())?,
            state: path_present_no_follow(paths.state_dir())?,
        })
    }

    const fn any(self) -> bool {
        self.config || self.data || self.state
    }
}

struct FailedSetupRootCleanup {
    paths: AppPaths,
    before: ManagedRootPresence,
    armed: bool,
}

impl FailedSetupRootCleanup {
    fn new(paths: &AppPaths, before: ManagedRootPresence) -> Self {
        Self {
            paths: paths.clone(),
            before,
            armed: true,
        }
    }

    fn commit(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailedSetupRootCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for (existed, path) in [
            (self.before.config, self.paths.config_dir()),
            (self.before.data, self.paths.data_dir()),
            (self.before.state, self.paths.state_dir()),
        ] {
            if !existed {
                let _ = remove_dir_if_exists(path);
            }
        }
    }
}

fn missing_config_requires_full_revoke() -> Error {
    Error::InvalidConfig(
        "V2-owned roots already exist without config.json; run `saiai revoke --all` before setup"
            .into(),
    )
}

fn roots_are_clean_for_first_setup(paths: &AppPaths) -> Result<bool> {
    if path_present_no_follow(paths.config_dir())? || path_present_no_follow(paths.data_dir())? {
        return Ok(false);
    }
    transaction_state_root_contains_only_lock(paths)
}

fn transaction_state_root_contains_only_lock(paths: &AppPaths) -> Result<bool> {
    let metadata = match fs::symlink_metadata(paths.state_dir()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(Error::io(
                "inspect transaction state root",
                paths.state_dir(),
                error,
            ));
        }
    };
    if crate::fsutil::is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
        return Ok(false);
    }
    let entries = fs::read_dir(paths.state_dir())
        .map_err(|error| Error::io("list transaction state root", paths.state_dir(), error))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| Error::io("list transaction state root", paths.state_dir(), error))?;
        if entry.file_name() != std::ffi::OsStr::new("transaction.lock") {
            return Ok(false);
        }
    }
    Ok(true)
}

fn cleanup_new_transaction_state_root_best_effort(paths: &AppPaths, before: ManagedRootPresence) {
    if !before.state && transaction_state_root_contains_only_lock(paths).unwrap_or(false) {
        let _ = remove_dir_if_exists(paths.state_dir());
    }
}

fn list_managed_directory(
    managed_root: &Path,
    directory: &Path,
    operation: &'static str,
) -> Result<Vec<PathBuf>> {
    ensure_no_managed_symlinks(managed_root, directory)?;
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::io(operation, directory, error)),
    };
    let mut paths = entries
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| Error::io(operation, directory, error))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

fn generated_identifier_suffix(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn generated_credential_reference(product: Product, filename: &str) -> Option<CredentialRef> {
    let reference = filename.strip_suffix(".key")?;
    let prefix = format!("{}-", product.directory_name());
    generated_identifier_suffix(reference, &prefix)
        .then(|| CredentialRef::new(reference.to_owned()).ok())
        .flatten()
}

fn generated_generation_reference(
    product: Product,
    filename: &str,
    kind: GeneratedEntryKind,
) -> Option<GenerationRef> {
    let reference = match kind {
        GeneratedEntryKind::GenerationDirectory => filename,
        GeneratedEntryKind::LeaseFile => filename.strip_suffix(".lock")?,
    };
    let prefix = format!("gen-{}-", product.directory_name());
    generated_identifier_suffix(reference, &prefix)
        .then(|| GenerationRef::new(reference.to_owned()).ok())
        .flatten()
}

fn generated_revoke_quarantine_name(product: Product, filename: &str) -> bool {
    generated_identifier_suffix(
        filename,
        &format!(".saiai-revoke-{}-", product.directory_name()),
    )
}

fn product_for_lease_path(config: Option<&ConfigV2>, path: &Path) -> Option<Product> {
    let filename = path.file_name()?.to_str()?;
    let generation = filename.strip_suffix(".lock")?;
    if let Some(config) = config {
        for product in Product::ALL {
            if config
                .product(product)
                .is_some_and(|entry| entry.active_generation().as_str() == generation)
            {
                return Some(product);
            }
        }
    }
    Product::ALL.into_iter().find(|product| {
        generated_identifier_suffix(generation, &format!("gen-{}-", product.directory_name()))
    })
}

struct QuarantinedPath {
    original: PathBuf,
    quarantined: PathBuf,
}

struct RevokeQuarantine {
    product: Product,
    identifier: String,
    entries: Vec<QuarantinedPath>,
    roots: BTreeSet<PathBuf>,
    rollback_armed: bool,
}

impl RevokeQuarantine {
    fn new(product: Product) -> Self {
        Self {
            product,
            identifier: Uuid::new_v4().simple().to_string(),
            entries: Vec::new(),
            roots: BTreeSet::new(),
            rollback_armed: true,
        }
    }

    fn move_path(&mut self, original: &Path) -> Result<bool> {
        if !path_present_no_follow(original)? {
            return Ok(false);
        }
        let parent = original.parent().ok_or_else(|| Error::InvalidAppPath {
            field: "revoke path",
            path: original.to_path_buf(),
            reason: "path has no parent directory",
        })?;
        let quarantine_root = parent.join(format!(
            ".saiai-revoke-{}-{}",
            self.product.directory_name(),
            self.identifier
        ));
        ensure_private_dir(&quarantine_root)?;
        self.roots.insert(quarantine_root.clone());
        let destination =
            quarantine_root.join(original.file_name().ok_or_else(|| Error::InvalidAppPath {
                field: "revoke path",
                path: original.to_path_buf(),
                reason: "path has no file name",
            })?);
        if path_present_no_follow(&destination)? {
            self.rollback()?;
            return Err(Error::io(
                "quarantine revoked path",
                destination,
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "revoke quarantine destination already exists",
                ),
            ));
        }
        if let Err(error) = fs::rename(original, &destination) {
            let original_error = Error::io("quarantine revoked path", original, error);
            self.rollback()?;
            return Err(original_error);
        }
        self.entries.push(QuarantinedPath {
            original: original.to_path_buf(),
            quarantined: destination,
        });
        Ok(true)
    }

    fn rollback(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        let mut failed_entries = Vec::new();
        for entry in std::mem::take(&mut self.entries).into_iter().rev() {
            let quarantined_present = match path_present_no_follow(&entry.quarantined) {
                Ok(present) => present,
                Err(error) => {
                    failures.push(format!(
                        "could not inspect {}: {error}",
                        entry.quarantined.display()
                    ));
                    failed_entries.push(entry);
                    continue;
                }
            };
            let original_present = match path_present_no_follow(&entry.original) {
                Ok(present) => present,
                Err(error) => {
                    failures.push(format!(
                        "could not inspect {}: {error}",
                        entry.original.display()
                    ));
                    if quarantined_present {
                        failed_entries.push(entry);
                    }
                    continue;
                }
            };

            if !quarantined_present {
                if !original_present {
                    failures.push(format!(
                        "both rollback paths are missing for {}",
                        entry.original.display()
                    ));
                }
                continue;
            }
            if original_present {
                failures.push(format!(
                    "{} was recreated during rollback",
                    entry.original.display()
                ));
                failed_entries.push(entry);
                continue;
            }
            if let Err(error) = fs::rename(&entry.quarantined, &entry.original) {
                failures.push(format!(
                    "could not restore {}: {error}",
                    entry.original.display()
                ));
                failed_entries.push(entry);
            }
        }
        failed_entries.reverse();
        self.entries = failed_entries;
        self.roots.retain(|root| {
            if root
                .read_dir()
                .is_ok_and(|mut entries| entries.next().is_none())
                && fs::remove_dir(root).is_ok()
            {
                return false;
            }
            true
        });

        if failures.is_empty() {
            Ok(())
        } else {
            let path = self
                .entries
                .first()
                .map(|entry| entry.original.clone())
                .unwrap_or_else(|| PathBuf::from("revoke quarantine"));
            Err(Error::io(
                "restore revoked paths",
                path,
                std::io::Error::other(failures.join("; ")),
            ))
        }
    }

    fn commit_and_purge_best_effort(mut self, leave_for_retry: bool) {
        self.rollback_armed = false;
        if !leave_for_retry {
            for root in &self.roots {
                let _ = remove_dir_if_exists(root);
            }
        }
    }
}

impl Drop for RevokeQuarantine {
    fn drop(&mut self) {
        if self.rollback_armed {
            let _ = self.rollback();
        }
    }
}

impl SetupRequest {
    pub fn new(base_url: &str, credential: impl Into<String>) -> Result<Self> {
        let credential = SecretString::new(credential)?;
        Self::from_validated(GatewayUrl::parse(base_url)?, credential)
    }

    pub fn from_validated(base_url: GatewayUrl, credential: SecretString) -> Result<Self> {
        base_url.reject_credential_url_component(&credential)?;
        Ok(Self {
            base_url,
            credential,
        })
    }

    pub fn base_url(&self) -> &GatewayUrl {
        &self.base_url
    }
}

/// Filesystem implementation shared by the greenfield CLI and Tauri frontend.
#[derive(Clone, Debug)]
pub struct SaiaiCore {
    paths: AppPaths,
}

impl SaiaiCore {
    pub fn discover() -> Result<Self> {
        Ok(Self::new(AppPaths::discover()?))
    }

    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// Load and strictly validate the currently committed schema-v2 config,
    /// including its separation from stored credentials. Schema-v1 state is
    /// deliberately not migrated.
    pub fn load_config(&self) -> Result<ConfigV2> {
        let bytes = self.read_config_optional()?.ok_or_else(|| {
            Error::InvalidConfig("setup is not complete because config.json is missing".into())
        })?;
        let config = parse_config(&bytes)?;
        self.reject_gateway_credential_overlap(&config)?;
        Ok(config)
    }

    /// Return only the credential belonging to `product`. The preceding global
    /// config-integrity check may transiently inspect every configured
    /// credential to prevent a Gateway/key overlap.
    pub fn load_credential(&self, product: Product) -> Result<SecretString> {
        let config = self.load_config()?;
        let product_config = configured_product(&config, product)?;
        self.load_configured_credential(product_config)
    }

    /// Read one launch-safe product snapshot under the same transaction lock.
    /// This prevents a concurrent setup from pairing an old Gateway/home with
    /// a credential loaded from a newer product generation.
    pub fn load_committed_product(&self, product: Product) -> Result<CommittedProduct> {
        let _lock = TransactionLock::acquire(&self.paths)?;
        let config = self.load_config()?;
        let product_config = configured_product(&config, product)?;
        let lease = GenerationLease::acquire(&self.paths, product_config.active_generation())?;
        let generation = self
            .paths
            .generation_dir(product_config.active_generation());
        let home = self
            .paths
            .generation_client_home(product_config.active_generation(), product);
        ensure_no_managed_symlinks(self.paths.data_dir(), &generation)?;
        ensure_no_managed_symlinks(self.paths.data_dir(), &home)?;
        validate_product_home(&home, product)?;
        let credential = self.load_configured_credential(product_config)?;
        Ok(CommittedProduct::new(
            product,
            config.base_url().clone(),
            home,
            credential,
            lease,
        ))
    }

    /// Resolve a product home only through that product's committed entry.
    pub fn client_home(&self, product: Product) -> Result<PathBuf> {
        let config = self.load_config()?;
        let product_config = configured_product(&config, product)?;
        Ok(self
            .paths
            .generation_client_home(product_config.active_generation(), product))
    }

    pub fn product_runtime_dir(&self, product: Product) -> Result<PathBuf> {
        let config = self.load_config()?;
        let product_config = configured_product(&config, product)?;
        Ok(self
            .paths
            .generation_product_runtime_dir(product_config.active_generation(), product))
    }

    pub fn product_logs_dir(&self, product: Product) -> Result<PathBuf> {
        let config = self.load_config()?;
        let product_config = configured_product(&config, product)?;
        Ok(self
            .paths
            .generation_product_logs_dir(product_config.active_generation(), product))
    }

    /// Atomically replace one product while preserving the other product's
    /// committed generation and credential. The returned status is a
    /// deterministic commit receipt; call [`Self::setup_status`] separately
    /// for a new live filesystem diagnosis.
    pub fn setup_product_with_artifacts(
        &self,
        request: SetupRequest,
        artifacts: ProductSetupArtifacts,
    ) -> Result<SetupStatus> {
        self.setup_product_with_fault(request, artifacts, SetupFault::None)
    }

    /// Verify that provisioning `product` cannot change the gateway used by a
    /// separately configured product. The transaction repeats this check while
    /// holding its lock; this early check avoids sending a credential to the
    /// wrong gateway in the common mismatch case.
    pub(crate) fn validate_shared_base_url(
        &self,
        product: Product,
        base_url: &GatewayUrl,
    ) -> Result<()> {
        if !ManagedRootPresence::inspect(&self.paths)?.any() {
            return Ok(());
        }
        let _lock = TransactionReadLock::acquire(&self.paths)?;
        self.validate_shared_base_url_locked(product, base_url)
    }

    fn validate_shared_base_url_locked(
        &self,
        product: Product,
        base_url: &GatewayUrl,
    ) -> Result<()> {
        let Some(config) = self.load_config_optional_strict()? else {
            if ManagedRootPresence::inspect(&self.paths)?.any() {
                return Err(missing_config_requires_full_revoke());
            }
            return Ok(());
        };
        validate_shared_base_url(&config, product, base_url)
    }

    /// Inspect setup without creating directories or exposing secrets.
    pub fn setup_status(&self) -> Result<SetupStatus> {
        if !ManagedRootPresence::inspect(&self.paths)?.any() {
            return Ok(uninitialized_status());
        }
        let _lock = TransactionReadLock::acquire(&self.paths)?;
        self.setup_status_locked()
    }

    fn setup_status_locked(&self) -> Result<SetupStatus> {
        let any_state = path_present_no_follow(self.paths.config_dir())?
            || path_present_no_follow(self.paths.data_dir())?
            || path_present_no_follow(self.paths.state_dir())?;
        let config_bytes = self.read_config_optional()?;

        let config = match config_bytes {
            None => {
                if !any_state {
                    return Ok(uninitialized_status());
                }
                let issue = SetupIssue {
                    code: SetupIssueCode::ConfigMissing,
                    message: "V2-owned files exist, but config.json is missing; run `saiai revoke --all` to reset them".into(),
                };
                return Ok(unreadable_config_status(issue));
            }
            Some(bytes) => match parse_config(&bytes) {
                Ok(config) => config,
                Err(_) => {
                    let issue = SetupIssue {
                        code: SetupIssueCode::ConfigInvalid,
                        message: "config.json is invalid or uses an unsupported schema; older V2 state is not migrated, so run `saiai revoke --all` to reset it".into(),
                    };
                    return Ok(unreadable_config_status(issue));
                }
            },
        };

        if self.reject_gateway_credential_overlap(&config).is_err() {
            let issue = SetupIssue {
                code: SetupIssueCode::ConfigInvalid,
                message: UNSAFE_GATEWAY_CREDENTIAL_MESSAGE.into(),
            };
            return Ok(unreadable_config_status(issue));
        }

        let products = self.diagnose_configured_products(&config);
        Ok(status_from_committed_config(config, products))
    }

    fn diagnose_configured_products(&self, config: &ConfigV2) -> Vec<ProductSetupStatus> {
        Product::ALL
            .into_iter()
            .map(|product| self.diagnose_product(config, product))
            .collect()
    }

    fn diagnose_product(&self, config: &ConfigV2, product: Product) -> ProductSetupStatus {
        let Some(product_config) = config.product(product) else {
            return unconfigured_product_status(product);
        };
        let home = self
            .paths
            .generation_client_home(product_config.active_generation(), product);
        let mut issues = Vec::new();

        match self.load_configured_credential(product_config) {
            Ok(_) => {}
            Err(error) if error.is_not_found() => issues.push(SetupIssue {
                code: SetupIssueCode::CredentialMissing,
                message: format!("the {product} credential referenced by config.json is missing"),
            }),
            Err(_) => issues.push(SetupIssue {
                code: SetupIssueCode::CredentialInvalid,
                message: format!("the stored {product} credential is invalid"),
            }),
        }
        let credential_present = !issues.iter().any(|issue| {
            matches!(
                issue.code,
                SetupIssueCode::CredentialMissing | SetupIssueCode::CredentialInvalid
            )
        });

        let generation = self
            .paths
            .generation_dir(product_config.active_generation());
        match ensure_no_managed_symlinks(self.paths.data_dir(), &generation) {
            Err(_) => issues.push(SetupIssue {
                code: SetupIssueCode::UnsafeManagedPath,
                message: format!("the {product} generation uses an unsafe V2-owned path"),
            }),
            Ok(()) if !generation.is_dir() => issues.push(SetupIssue {
                code: SetupIssueCode::GenerationMissing,
                message: format!("the configured {product} generation is missing"),
            }),
            Ok(()) => {
                if ensure_no_managed_symlinks(self.paths.data_dir(), &home)
                    .and_then(|()| validate_product_home(&home, product))
                    .is_err()
                {
                    issues.push(SetupIssue {
                        code: SetupIssueCode::ProductInvalid,
                        message: format!("the configured {product} client state is invalid"),
                    });
                }
            }
        }

        let state = if issues.is_empty() {
            ProductSetupState::Ready
        } else {
            ProductSetupState::Broken
        };
        ProductSetupStatus {
            product,
            state,
            home: Some(home),
            credential_present,
            issues,
        }
    }

    /// Remove one product's independent state or all V2 application roots.
    /// A product report contains the deterministic commit receipt; live
    /// diagnostics remain a separate [`Self::setup_status`] operation.
    /// Full revoke does not depend on successfully parsing config.json, so it
    /// recovers schema-v1 and otherwise invalid state.
    pub fn revoke(&self, target: RevokeTarget) -> Result<RevokeReport> {
        if target == RevokeTarget::All {
            return self.revoke_all(target);
        }

        let RevokeTarget::Product(product) = target else {
            unreachable!();
        };
        self.revoke_product_with_fault(product, RevokeFault::None)
    }

    fn revoke_product_with_fault(
        &self,
        product: Product,
        fault: RevokeFault,
    ) -> Result<RevokeReport> {
        let target = RevokeTarget::Product(product);
        if !ManagedRootPresence::inspect(&self.paths)?.any() {
            return Ok(RevokeReport {
                target,
                removed_paths: Vec::new(),
                status: uninitialized_status(),
            });
        }

        let transaction_lock = TransactionLock::acquire(&self.paths)?;
        let mut config = self.load_config_optional_strict()?;
        let diagnosed_before = config
            .as_ref()
            .map(|config| self.diagnose_configured_products(config))
            .unwrap_or_else(|| {
                Product::ALL
                    .into_iter()
                    .map(unconfigured_product_status)
                    .collect()
            });
        let product_config = config
            .as_ref()
            .and_then(|config| config.product(product).cloned());

        let removed_product = config
            .as_mut()
            .is_some_and(|config| config.remove_product(product).is_some());
        let config_commit = if removed_product {
            let config = config
                .as_ref()
                .expect("removed_product requires a loaded config");
            if config.products().is_empty() {
                ProductConfigCommit::RemoveLast
            } else {
                ProductConfigCommit::Replace(serialize_config(config)?)
            }
        } else {
            ProductConfigCommit::None
        };
        let committed_config = match &config_commit {
            ProductConfigCommit::RemoveLast => None,
            ProductConfigCommit::None | ProductConfigCommit::Replace(_) => config.clone(),
        };
        let committed_status =
            committed_status_after_product_revoke(committed_config, diagnosed_before);

        let resources =
            self.discover_product_resources(product, product_config.as_ref(), config.as_ref())?;
        let mut leases = Vec::new();
        for generation in &resources.generations {
            match ExclusiveGenerationLease::try_acquire_existing(&self.paths, generation)? {
                ExclusiveLeaseProbe::Acquired(lease) => leases.push(lease),
                ExclusiveLeaseProbe::Missing => {}
                ExclusiveLeaseProbe::Busy => return Err(Error::ProductBusy(product)),
            }
        }

        if fault == RevokeFault::BeforeCleanup {
            return Err(injected_revoke_failure(product, "before cleanup"));
        }

        let mut removed_paths = Vec::new();
        for quarantine in &resources.previous_quarantines {
            if remove_dir_if_exists(quarantine)? {
                removed_paths.push(quarantine.clone());
            }
        }

        let mut quarantine = RevokeQuarantine::new(product);
        let mut quarantined_count = 0_usize;
        for path in &resources.removal_paths {
            if quarantine.move_path(path)? {
                quarantined_count += 1;
                removed_paths.push(path.clone());
                if quarantined_count == 1 && fault == RevokeFault::AfterFirstQuarantine {
                    quarantine.rollback()?;
                    return Err(injected_revoke_failure(product, "after first quarantine"));
                }
            }
        }

        if fault == RevokeFault::BeforeConfigCommit {
            quarantine.rollback()?;
            return Err(injected_revoke_failure(product, "before config commit"));
        }
        let config_path = self.paths.config_file();
        let removed_config = match config_commit {
            ProductConfigCommit::None => false,
            ProductConfigCommit::Replace(config_bytes) => {
                if let Err(error) = atomic_write_private(&config_path, &config_bytes) {
                    quarantine.rollback()?;
                    return Err(error);
                }
                false
            }
            ProductConfigCommit::RemoveLast => {
                match remove_config_file_for_product_commit(&config_path) {
                    Ok(removed) => removed,
                    Err(error) => {
                        quarantine.rollback()?;
                        return Err(error);
                    }
                }
            }
        };
        if removed_config {
            removed_paths.push(config_path);
        }

        // The config commit (when one was needed) is now definitive. Physical
        // deletion and stale lease-file removal are cleanup-only; reporting a
        // new error here would falsely imply that callers can roll back.
        quarantine.commit_and_purge_best_effort(fault == RevokeFault::LeaveQuarantineAfterCommit);
        for lease in leases {
            let lease_path = lease.path().to_path_buf();
            if lease.release_and_remove().unwrap_or(false) {
                removed_paths.push(lease_path);
            }
        }
        self.prune_empty_shared_dirs_best_effort(&mut removed_paths);
        drop(transaction_lock);

        Ok(RevokeReport {
            target,
            removed_paths,
            status: committed_status,
        })
    }

    fn discover_product_resources(
        &self,
        product: Product,
        selected: Option<&ProductConfig>,
        remaining_config: Option<&ConfigV2>,
    ) -> Result<ProductResources> {
        let protected_credential = remaining_config.and_then(|config| {
            Product::ALL
                .into_iter()
                .find(|other| *other != product)
                .and_then(|other| config.product(other))
                .map(|config| config.credential_ref().as_str().to_owned())
        });
        let protected_generation = remaining_config.and_then(|config| {
            Product::ALL
                .into_iter()
                .find(|other| *other != product)
                .and_then(|other| config.product(other))
                .map(|config| config.active_generation().as_str().to_owned())
        });

        let mut credentials = BTreeMap::<String, CredentialRef>::new();
        let mut generations = BTreeMap::<String, GenerationRef>::new();
        if let Some(selected) = selected {
            credentials.insert(
                selected.credential_ref().as_str().to_ascii_lowercase(),
                selected.credential_ref().clone(),
            );
            generations.insert(
                selected.active_generation().as_str().to_ascii_lowercase(),
                selected.active_generation().clone(),
            );
        }

        for path in list_managed_directory(
            self.paths.data_dir(),
            &self.paths.credentials_dir(),
            "list stored credentials",
        )? {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(reference) = generated_credential_reference(product, name) else {
                continue;
            };
            if !protected_credential
                .as_deref()
                .is_some_and(|protected| protected.eq_ignore_ascii_case(reference.as_str()))
            {
                credentials.insert(reference.as_str().to_ascii_lowercase(), reference);
            }
        }

        for (root, directory, kind) in [
            (
                self.paths.data_dir(),
                self.paths.generations_dir(),
                GeneratedEntryKind::GenerationDirectory,
            ),
            (
                self.paths.state_dir(),
                self.paths.runtime_dir(),
                GeneratedEntryKind::GenerationDirectory,
            ),
            (
                self.paths.state_dir(),
                self.paths.logs_dir(),
                GeneratedEntryKind::GenerationDirectory,
            ),
            (
                self.paths.state_dir(),
                self.paths.leases_dir(),
                GeneratedEntryKind::LeaseFile,
            ),
        ] {
            for path in list_managed_directory(root, &directory, "list product generations")? {
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Some(reference) = generated_generation_reference(product, name, kind) else {
                    continue;
                };
                if !protected_generation
                    .as_deref()
                    .is_some_and(|protected| protected.eq_ignore_ascii_case(reference.as_str()))
                {
                    generations.insert(reference.as_str().to_ascii_lowercase(), reference);
                }
            }
        }

        let mut previous_quarantines = BTreeSet::new();
        for (root, directory) in [
            (self.paths.data_dir(), self.paths.credentials_dir()),
            (self.paths.data_dir(), self.paths.generations_dir()),
            (self.paths.state_dir(), self.paths.runtime_dir()),
            (self.paths.state_dir(), self.paths.logs_dir()),
        ] {
            for path in list_managed_directory(root, &directory, "list revoke quarantine")? {
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if generated_revoke_quarantine_name(product, name) {
                    previous_quarantines.insert(path);
                }
            }
        }

        let mut removal_paths = BTreeSet::new();
        let store = self.credential_store();
        for reference in credentials.values() {
            let path = store.credential_path(reference);
            ensure_no_managed_symlinks(
                self.paths.data_dir(),
                path.parent().expect("credential path has a parent"),
            )?;
            removal_paths.insert(path);
        }
        for reference in generations.values() {
            for (root, path) in self.generation_paths(reference) {
                ensure_no_managed_symlinks(
                    root,
                    path.parent().expect("generation path has a parent"),
                )?;
                removal_paths.insert(path);
            }
        }

        Ok(ProductResources {
            generations: generations.into_values().collect(),
            removal_paths: removal_paths.into_iter().collect(),
            previous_quarantines: previous_quarantines.into_iter().collect(),
        })
    }

    fn setup_product_with_fault(
        &self,
        request: SetupRequest,
        artifacts: ProductSetupArtifacts,
        fault: SetupFault,
    ) -> Result<SetupStatus> {
        self.setup_product_with_fault_after_root_inspect(request, artifacts, fault, || {})
    }

    fn setup_product_with_fault_after_root_inspect(
        &self,
        request: SetupRequest,
        artifacts: ProductSetupArtifacts,
        fault: SetupFault,
        after_root_inspect: impl FnOnce(),
    ) -> Result<SetupStatus> {
        artifacts.validate()?;
        let product = artifacts.product();
        let roots_before = ManagedRootPresence::inspect(&self.paths)?;
        after_root_inspect();
        let _lock = TransactionLock::acquire(&self.paths)?;
        let previous_config = self.load_config_optional_strict()?;
        let mut setup_cleanup = if previous_config.is_some() {
            None
        } else if roots_before.any() || !roots_are_clean_for_first_setup(&self.paths)? {
            cleanup_new_transaction_state_root_best_effort(&self.paths, roots_before);
            return Err(missing_config_requires_full_revoke());
        } else {
            Some(FailedSetupRootCleanup::new(&self.paths, roots_before))
        };
        if let Some(config) = &previous_config {
            validate_shared_base_url(config, product, &request.base_url)?;
        }
        let diagnosed_before = previous_config
            .as_ref()
            .map(|config| self.diagnose_configured_products(config))
            .unwrap_or_else(|| {
                Product::ALL
                    .into_iter()
                    .map(unconfigured_product_status)
                    .collect()
            });

        let identifier = Uuid::new_v4().simple().to_string();
        let generation_ref =
            GenerationRef::new(format!("gen-{}-{identifier}", product.directory_name()))?;
        let credential_ref =
            CredentialRef::new(format!("{}-{identifier}", product.directory_name()))?;
        let product_config = ProductConfig::new(credential_ref.clone(), generation_ref.clone());
        let config = match previous_config.clone() {
            Some(mut config) => {
                config.replace_base_url(request.base_url.clone());
                config.insert_product(product, product_config.clone());
                config
            }
            None => ConfigV2::new(request.base_url.clone(), product, product_config.clone()),
        };
        let config_bytes = serialize_config(&config)?;
        let committed_status = committed_status_after_product_setup(
            &self.paths,
            config.clone(),
            product,
            diagnosed_before,
        );

        for root in [
            self.paths.config_dir(),
            self.paths.data_dir(),
            self.paths.state_dir(),
        ] {
            ensure_private_dir(root)?;
        }

        let mut stage = SetupStage::create(&self.paths)?;
        ensure_private_dir(&stage.path().join("clients"))?;
        write_product_home(&generation_client_home(stage.path(), product), &artifacts)?;
        if fault == SetupFault::CorruptStagedProduct {
            let (filename, contents): (&str, &[u8]) = match product {
                Product::Claude => (CLAUDE_SETTINGS_FILENAME, b"[]"),
                Product::Codex => (CODEX_CONFIG_FILENAME, b"invalid = [toml"),
            };
            atomic_write_private(
                &generation_client_home(stage.path(), product).join(filename),
                contents,
            )?;
        }
        validate_product_home(&generation_client_home(stage.path(), product), product)?;

        let final_generation = self.paths.generation_dir(&generation_ref);
        stage.promote(&final_generation)?;
        let mut pending_generation = PendingGeneration::new(final_generation);
        if fault == SetupFault::AfterGenerationPromotion {
            return Err(injected_failure(product, "after generation promotion"));
        }

        let store = self.credential_store();
        store.save(&credential_ref, &request.credential)?;
        if fault == SetupFault::AfterCredentialSave {
            let _ = store.delete(&credential_ref);
            return Err(injected_failure(product, "after credential save"));
        }
        if fault == SetupFault::BeforeConfigCommit {
            let _ = store.delete(&credential_ref);
            return Err(injected_failure(product, "before config commit"));
        }

        if let Err(error) = atomic_write_private(&self.paths.config_file(), &config_bytes) {
            let _ = store.delete(&credential_ref);
            return Err(error);
        }
        pending_generation.commit();
        if let Some(cleanup) = &mut setup_cleanup {
            cleanup.commit();
        }

        if let Some(previous) = previous_config.and_then(|config| config.product(product).cloned())
        {
            if previous.credential_ref() != &credential_ref {
                let _ = store.delete(previous.credential_ref());
            }
            if previous.active_generation() != &generation_ref {
                self.cleanup_generation_best_effort(previous.active_generation());
            }
        }
        self.cleanup_staging_best_effort();
        // This is the deterministic receipt for the config commit above. A
        // separate setup_status() call performs live filesystem diagnostics;
        // re-reading here could turn a successful commit into a false error or
        // race the caller's next operation.
        Ok(committed_status)
    }

    fn revoke_all(&self, target: RevokeTarget) -> Result<RevokeReport> {
        if !path_present_no_follow(self.paths.config_dir())?
            && !path_present_no_follow(self.paths.data_dir())?
            && !path_present_no_follow(self.paths.state_dir())?
        {
            return Ok(RevokeReport {
                target,
                removed_paths: Vec::new(),
                status: uninitialized_status(),
            });
        }
        let transaction_lock = TransactionLock::acquire(&self.paths)?;
        self.remove_all_roots_with_lock(target, transaction_lock)
    }

    fn remove_all_roots_with_lock(
        &self,
        target: RevokeTarget,
        _transaction_lock: TransactionLock,
    ) -> Result<RevokeReport> {
        let config = self.load_config_optional_strict().ok().flatten();
        let leases = self.acquire_all_existing_generation_leases(config.as_ref())?;
        let mut removed_paths = Vec::new();
        for path in [
            self.paths.config_dir().to_path_buf(),
            self.paths.data_dir().to_path_buf(),
        ] {
            if remove_dir_if_exists(&path)? {
                removed_paths.push(path);
            }
        }

        // No shared generation lease existed at the preflight point. Release
        // our exclusive lease handles while the transaction lock is still held
        // so Windows can remove their files and no launcher can race into the
        // state tree between the check and deletion.
        drop(leases);
        let state_dir = self.paths.state_dir().to_path_buf();
        if remove_dir_if_exists(&state_dir)? {
            removed_paths.push(state_dir);
        }

        Ok(RevokeReport {
            target,
            removed_paths,
            status: uninitialized_status(),
        })
    }

    fn acquire_all_existing_generation_leases(
        &self,
        config: Option<&ConfigV2>,
    ) -> Result<Vec<ExclusiveGenerationLease>> {
        let leases_dir = self.paths.leases_dir();
        for path in [self.paths.state_dir(), leases_dir.as_path()] {
            match fs::symlink_metadata(path) {
                Ok(metadata)
                    if crate::fsutil::is_symlink_or_reparse(&metadata) || !metadata.is_dir() =>
                {
                    // A core-created lease can never live through a symlink or
                    // non-directory root. Full revoke may safely unlink this
                    // corrupt root without opening or following it.
                    return Ok(Vec::new());
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Vec::new());
                }
                Err(error) => return Err(Error::io("inspect generation leases", path, error)),
            }
        }
        ensure_no_managed_symlinks(self.paths.state_dir(), &leases_dir)?;
        let entries = match fs::read_dir(&leases_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(Error::io("list generation leases", leases_dir, error)),
        };
        let mut paths = entries
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| Error::io("list generation lease", &leases_dir, error))
            })
            .collect::<Result<Vec<_>>>()?;
        paths.sort();

        let mut leases = Vec::new();
        for path in paths {
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(Error::io("inspect generation lease", &path, error)),
            };
            if !metadata.is_file() || crate::fsutil::is_symlink_or_reparse(&metadata) {
                continue;
            }
            match ExclusiveGenerationLease::try_acquire_existing_path(&self.paths, &path)? {
                ExclusiveLeaseProbe::Acquired(lease) => leases.push(lease),
                ExclusiveLeaseProbe::Missing => {}
                ExclusiveLeaseProbe::Busy => {
                    return Err(match product_for_lease_path(config, &path) {
                        Some(product) => Error::ProductBusy(product),
                        None => Error::InstallationBusy,
                    });
                }
            }
        }
        Ok(leases)
    }

    fn cleanup_generation_best_effort(&self, generation: &GenerationRef) {
        let lease = match ExclusiveGenerationLease::try_acquire_existing(&self.paths, generation) {
            Ok(ExclusiveLeaseProbe::Acquired(lease)) => Some(lease),
            Ok(ExclusiveLeaseProbe::Missing) => None,
            Ok(ExclusiveLeaseProbe::Busy) | Err(_) => {
                // A launched child still owns this generation, or the lease
                // could not be inspected safely. Leave it as a product-prefixed
                // orphan; a later product revoke will retry it.
                return;
            }
        };
        for (root, path) in self.generation_paths(generation) {
            if ensure_no_managed_symlinks(root, &path).is_ok() {
                let _ = remove_dir_if_exists(&path);
            }
        }
        if let Some(lease) = lease {
            let _ = lease.release_and_remove();
        }
    }

    fn generation_paths(&self, generation: &GenerationRef) -> [(&Path, PathBuf); 3] {
        [
            (self.paths.data_dir(), self.paths.generation_dir(generation)),
            (
                self.paths.state_dir(),
                self.paths.generation_runtime_dir(generation),
            ),
            (
                self.paths.state_dir(),
                self.paths.generation_logs_dir(generation),
            ),
        ]
    }

    fn cleanup_staging_best_effort(&self) {
        let staging = self.paths.generation_staging_dir();
        if staging
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_none())
        {
            let _ = fs::remove_dir(staging);
        }
    }

    fn prune_empty_shared_dirs_best_effort(&self, removed_paths: &mut Vec<PathBuf>) {
        for path in [
            self.paths.generation_staging_dir(),
            self.paths.credentials_dir(),
            self.paths.generations_dir(),
            self.paths.runtime_dir(),
            self.paths.logs_dir(),
            self.paths.leases_dir(),
        ] {
            if remove_empty_real_directory_best_effort(&path) {
                removed_paths.push(path);
            }
        }

        // On Unix the stable-parent flock remains held while the current lock
        // inode is unlinked. On Windows the cross-session named mutex is the
        // transaction primitive. Removing this exact file is therefore safe,
        // and lets a clean final product revoke prune an otherwise-empty root.
        #[cfg(any(unix, windows))]
        if transaction_state_root_contains_only_lock(&self.paths).unwrap_or(false) {
            let transaction_lock = self.paths.transaction_lock_file();
            if remove_regular_file_best_effort(&transaction_lock) {
                removed_paths.push(transaction_lock);
            }
        }
        for path in [
            self.paths.config_dir().to_path_buf(),
            self.paths.data_dir().to_path_buf(),
            self.paths.state_dir().to_path_buf(),
        ] {
            if remove_empty_real_directory_best_effort(&path) {
                removed_paths.push(path);
            }
        }
    }

    fn credential_store(&self) -> FileCredentialStore {
        FileCredentialStore::new(self.paths.credentials_dir())
    }

    fn load_config_optional_strict(&self) -> Result<Option<ConfigV2>> {
        let Some(bytes) = self.read_config_optional()? else {
            return Ok(None);
        };
        let config = parse_config(&bytes)?;
        self.reject_gateway_credential_overlap(&config)?;
        Ok(Some(config))
    }

    fn read_config_optional(&self) -> Result<Option<Vec<u8>>> {
        let path = self.paths.config_file();
        ensure_no_managed_symlinks(self.paths.config_dir(), &path)?;
        read_optional(&path)
    }

    fn load_configured_credential(&self, config: &ProductConfig) -> Result<SecretString> {
        let store = self.credential_store();
        let path = store.credential_path(config.credential_ref());
        ensure_no_managed_symlinks(self.paths.data_dir(), &path)?;
        store.load(config.credential_ref())
    }

    fn reject_gateway_credential_overlap(&self, config: &ConfigV2) -> Result<()> {
        for product in Product::ALL {
            let Some(product_config) = config.product(product) else {
                continue;
            };
            let Ok(credential) = self.load_configured_credential(product_config) else {
                continue;
            };
            if config
                .base_url()
                .reject_credential_url_component(&credential)
                .is_err()
            {
                return Err(Error::InvalidConfig(
                    UNSAFE_GATEWAY_CREDENTIAL_MESSAGE.into(),
                ));
            }
        }
        Ok(())
    }
}

fn parse_config(bytes: &[u8]) -> Result<ConfigV2> {
    serde_json::from_slice(bytes).map_err(|error| Error::InvalidConfig(error.to_string()))
}

fn serialize_config(config: &ConfigV2) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(config).map_err(|error| Error::InvalidConfig(error.to_string()))
}

fn configured_product(config: &ConfigV2, product: Product) -> Result<&ProductConfig> {
    config
        .product(product)
        .ok_or(Error::ProductNotConfigured(product))
}

fn validate_shared_base_url(
    config: &ConfigV2,
    product: Product,
    base_url: &GatewayUrl,
) -> Result<()> {
    for other in Product::ALL.into_iter().filter(|other| *other != product) {
        if config.product(other).is_some() && config.base_url() != base_url {
            return Err(Error::SharedGatewayMismatch { product, other });
        }
    }
    Ok(())
}

fn unconfigured_product_status(product: Product) -> ProductSetupStatus {
    ProductSetupStatus {
        product,
        state: ProductSetupState::Unconfigured,
        home: None,
        credential_present: false,
        issues: Vec::new(),
    }
}

fn ready_product_status(
    paths: &AppPaths,
    config: &ConfigV2,
    product: Product,
) -> ProductSetupStatus {
    let product_config = config
        .product(product)
        .expect("a committed setup receipt requires the selected product");
    ProductSetupStatus {
        product,
        state: ProductSetupState::Ready,
        home: Some(paths.generation_client_home(product_config.active_generation(), product)),
        credential_present: true,
        issues: Vec::new(),
    }
}

fn preserved_product_status(
    config: &ConfigV2,
    product: Product,
    diagnosed_before: &[ProductSetupStatus],
) -> ProductSetupStatus {
    if config.product(product).is_none() {
        return unconfigured_product_status(product);
    }
    diagnosed_before
        .iter()
        .find(|status| status.product == product)
        .cloned()
        .unwrap_or_else(|| ProductSetupStatus {
            product,
            state: ProductSetupState::Broken,
            home: None,
            credential_present: false,
            issues: vec![SetupIssue {
                code: SetupIssueCode::ConfigInvalid,
                message: format!(
                    "the committed {product} status could not preserve its pre-transaction diagnostics"
                ),
            }],
        })
}

fn committed_status_after_product_setup(
    paths: &AppPaths,
    config: ConfigV2,
    selected: Product,
    diagnosed_before: Vec<ProductSetupStatus>,
) -> SetupStatus {
    let products = Product::ALL
        .into_iter()
        .map(|product| {
            if product == selected {
                ready_product_status(paths, &config, product)
            } else {
                preserved_product_status(&config, product, &diagnosed_before)
            }
        })
        .collect();
    status_from_committed_config(config, products)
}

fn committed_status_after_product_revoke(
    config: Option<ConfigV2>,
    diagnosed_before: Vec<ProductSetupStatus>,
) -> SetupStatus {
    let Some(config) = config else {
        return uninitialized_status();
    };
    let products = Product::ALL
        .into_iter()
        .map(|product| preserved_product_status(&config, product, &diagnosed_before))
        .collect();
    status_from_committed_config(config, products)
}

fn status_from_committed_config(
    config: ConfigV2,
    products: Vec<ProductSetupStatus>,
) -> SetupStatus {
    let issues = products
        .iter()
        .flat_map(|product| product.issues.iter().cloned())
        .collect::<Vec<_>>();
    let state = if products
        .iter()
        .any(|product| product.state == ProductSetupState::Broken)
    {
        SetupState::Broken
    } else {
        SetupState::Ready
    };
    SetupStatus {
        state,
        config: Some(config),
        products,
        issues,
    }
}

fn uninitialized_status() -> SetupStatus {
    SetupStatus {
        state: SetupState::Uninitialized,
        config: None,
        products: Product::ALL
            .into_iter()
            .map(unconfigured_product_status)
            .collect(),
        issues: Vec::new(),
    }
}

fn unreadable_config_status(issue: SetupIssue) -> SetupStatus {
    SetupStatus {
        state: SetupState::Broken,
        config: None,
        products: Product::ALL
            .into_iter()
            .map(|product| ProductSetupStatus {
                product,
                state: ProductSetupState::Broken,
                home: None,
                credential_present: false,
                issues: vec![issue.clone()],
            })
            .collect(),
        issues: vec![issue],
    }
}

fn remove_config_file_for_product_commit(path: &Path) -> Result<bool> {
    reject_symlink_if_present(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::io("remove final product config", path, error)),
    }
}

fn remove_regular_file_best_effort(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || crate::fsutil::is_symlink_or_reparse(&metadata) {
        return false;
    }
    fs::remove_file(path).is_ok()
}

fn remove_empty_real_directory_best_effort(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_dir() || crate::fsutil::is_symlink_or_reparse(&metadata) {
        return false;
    }
    let Ok(mut entries) = fs::read_dir(path) else {
        return false;
    };
    if entries.next().is_some() {
        return false;
    }
    fs::remove_dir(path).is_ok()
}

fn write_product_home(root: &Path, artifacts: &ProductSetupArtifacts) -> Result<()> {
    match artifacts {
        ProductSetupArtifacts::Claude(claude) => write_claude_home(root, claude),
        ProductSetupArtifacts::Codex(codex) => write_codex_home(root, codex),
    }
}

fn write_claude_home(root: &Path, artifacts: &ClaudeSetupArtifacts) -> Result<()> {
    ensure_private_dir(root)?;
    for (filename, contents) in artifacts.files() {
        atomic_write_private(&root.join(filename), contents)?;
    }
    atomic_write_private(&root.join(PRODUCT_MARKER_FILENAME), PRODUCT_MARKER)
}

fn write_codex_home(root: &Path, artifacts: &CodexSetupArtifacts) -> Result<()> {
    ensure_private_dir(root)?;
    for (filename, contents) in artifacts.files() {
        atomic_write_private(&root.join(filename), contents)?;
    }
    atomic_write_private(&root.join(PRODUCT_MARKER_FILENAME), PRODUCT_MARKER)
}

fn validate_product_home(home: &Path, product: Product) -> Result<()> {
    reject_symlink_if_present(home)?;
    let marker = read(&home.join(PRODUCT_MARKER_FILENAME))?;
    if marker != PRODUCT_MARKER {
        return Err(Error::InvalidArtifact {
            artifact: PRODUCT_MARKER_FILENAME,
            reason: "managed marker is missing or invalid".into(),
        });
    }
    match product {
        Product::Claude => {
            ClaudeSetupArtifacts::new(
                read(&home.join(CLAUDE_SETTINGS_FILENAME))?,
                read(&home.join(CLAUDE_STATE_FILENAME))?,
                read_utf8(&home.join(CLAUDE_CA_CERT_FILENAME))?,
                read_utf8(&home.join(CLAUDE_CA_KEY_FILENAME))?,
            )?;
        }
        Product::Codex => {
            CodexSetupArtifacts::new(read_utf8(&home.join(CODEX_CONFIG_FILENAME))?)?;
        }
    }
    Ok(())
}

fn generation_client_home(root: &Path, product: Product) -> PathBuf {
    root.join("clients").join(product.directory_name())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    reject_symlink_if_present(path)?;
    fs::read(path).map_err(|error| Error::io("read file", path, error))
}

fn read_utf8(path: &Path) -> Result<String> {
    String::from_utf8(read(path)?).map_err(|error| {
        let mut bytes = error.into_bytes();
        bytes.zeroize();
        Error::InvalidArtifact {
            artifact: "managed client file",
            reason: format!("{} is not UTF-8", path.display()),
        }
    })
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    reject_symlink_if_present(path)?;
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::io("read file", path, error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupFault {
    None,
    CorruptStagedProduct,
    AfterGenerationPromotion,
    AfterCredentialSave,
    BeforeConfigCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevokeFault {
    None,
    BeforeCleanup,
    AfterFirstQuarantine,
    BeforeConfigCommit,
    LeaveQuarantineAfterCommit,
}

enum ProductConfigCommit {
    None,
    Replace(Vec<u8>),
    RemoveLast,
}

fn injected_failure(product: Product, point: &'static str) -> Error {
    Error::InvalidConfig(format!("injected {product} setup failure {point}"))
}

fn injected_revoke_failure(product: Product, point: &'static str) -> Error {
    Error::InvalidConfig(format!("injected {product} revoke failure {point}"))
}

struct SetupStage {
    root: PathBuf,
    promoted: bool,
}

impl SetupStage {
    fn create(paths: &AppPaths) -> Result<Self> {
        ensure_private_dir(&paths.generations_dir())?;
        let staging = paths.generation_staging_dir();
        ensure_private_dir(&staging)?;
        let root = staging.join(Uuid::new_v4().simple().to_string());
        ensure_private_dir(&root)?;
        Ok(Self {
            root,
            promoted: false,
        })
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn promote(&mut self, destination: &Path) -> Result<()> {
        promote_new_directory(&self.root, destination)?;
        self.promoted = true;
        Ok(())
    }
}

impl Drop for SetupStage {
    fn drop(&mut self) {
        if !self.promoted {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct PendingGeneration {
    root: PathBuf,
    committed: bool,
}

impl PendingGeneration {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingGeneration {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct TransactionLock {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(not(windows))]
    file: fs::File,
    #[cfg(unix)]
    stable_parent: fs::File,
}

/// A mutation-free diagnostic guard. Writers on Unix already serialize on the
/// stable state-parent directory before touching the deletable state root; on
/// Windows they use the cross-session named mutex. A missing Unix parent is a
/// valid linearization point before any writer could have entered.
struct TransactionReadLock {
    #[cfg(windows)]
    _transaction: TransactionLock,
    #[cfg(unix)]
    stable_parent: Option<fs::File>,
    #[cfg(not(any(unix, windows)))]
    _private: (),
}

impl TransactionReadLock {
    #[cfg(windows)]
    fn acquire(paths: &AppPaths) -> Result<Self> {
        Ok(Self {
            _transaction: TransactionLock::acquire(paths)?,
        })
    }

    #[cfg(unix)]
    fn acquire(paths: &AppPaths) -> Result<Self> {
        let stable_parent_path =
            paths
                .state_dir()
                .parent()
                .ok_or_else(|| Error::InvalidAppPath {
                    field: "state_dir",
                    path: paths.state_dir().to_path_buf(),
                    reason: "path has no parent directory",
                })?;
        let stable_parent = match fs::File::open(stable_parent_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    stable_parent: None,
                });
            }
            Err(error) => {
                return Err(Error::io(
                    "open setup diagnostic lock parent",
                    stable_parent_path,
                    error,
                ));
            }
        };
        fs2::FileExt::lock_exclusive(&stable_parent).map_err(|error| {
            Error::io("lock setup diagnostic parent", stable_parent_path, error)
        })?;
        Ok(Self {
            stable_parent: Some(stable_parent),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn acquire(_paths: &AppPaths) -> Result<Self> {
        Ok(Self { _private: () })
    }
}

impl Drop for TransactionReadLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(stable_parent) = &self.stable_parent {
            let _ = fs2::FileExt::unlock(stable_parent);
        }
    }
}

impl TransactionLock {
    #[cfg(windows)]
    fn acquire(paths: &AppPaths) -> Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{CreateMutexW, INFINITE, WaitForSingleObject};

        let name = transaction_mutex_name(paths)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: the optional security attributes are null and the mutex name
        // is NUL-terminated for the duration of the call.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(Error::io(
                "create setup transaction mutex",
                paths.state_dir(),
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: CreateMutexW returned a live handle owned by this function.
        let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            let error = std::io::Error::last_os_error();
            // SAFETY: the handle is live and has not been transferred.
            let _ = unsafe { CloseHandle(handle) };
            return Err(Error::io(
                "lock setup transaction mutex",
                paths.state_dir(),
                error,
            ));
        }
        Ok(Self { handle })
    }

    #[cfg(unix)]
    fn acquire(paths: &AppPaths) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let stable_parent_path =
            paths
                .state_dir()
                .parent()
                .ok_or_else(|| Error::InvalidAppPath {
                    field: "state_dir",
                    path: paths.state_dir().to_path_buf(),
                    reason: "path has no parent directory",
                })?;
        fs::create_dir_all(stable_parent_path).map_err(|error| {
            Error::io(
                "create setup transaction lock parent",
                stable_parent_path,
                error,
            )
        })?;
        let stable_parent = fs::File::open(stable_parent_path).map_err(|error| {
            Error::io(
                "open setup transaction lock parent",
                stable_parent_path,
                error,
            )
        })?;
        fs2::FileExt::lock_exclusive(&stable_parent).map_err(|error| {
            Error::io("lock setup transaction parent", stable_parent_path, error)
        })?;

        let path = paths.transaction_lock_file();
        loop {
            let file = open_private_lock_file(&path)?;
            fs2::FileExt::lock_exclusive(&file)
                .map_err(|error| Error::io("lock setup transaction", &path, error))?;

            let opened = file
                .metadata()
                .map_err(|error| Error::io("inspect setup transaction lock", &path, error))?;
            match fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.is_file()
                        && !metadata.file_type().is_symlink()
                        && metadata.dev() == opened.dev()
                        && metadata.ino() == opened.ino() =>
                {
                    return Ok(Self {
                        file,
                        stable_parent,
                    });
                }
                Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                    let _ = fs2::FileExt::unlock(&file);
                    return Err(Error::io(
                        "inspect current setup transaction lock",
                        &path,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "transaction lock path is not a regular file",
                        ),
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    let _ = fs2::FileExt::unlock(&file);
                    return Err(Error::io(
                        "inspect current setup transaction lock",
                        &path,
                        error,
                    ));
                }
            }

            // A full revoke unlinked the lock while this waiter was blocked.
            // Retry against the newly current inode before entering a critical
            // section, preventing split-lock races after held-lock deletion.
            let _ = fs2::FileExt::unlock(&file);
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn acquire(paths: &AppPaths) -> Result<Self> {
        let path = paths.transaction_lock_file();
        let file = open_private_lock_file(&path)?;
        fs2::FileExt::lock_exclusive(&file)
            .map_err(|error| Error::io("lock setup transaction", path, error))?;
        Ok(Self { file })
    }
}

impl Drop for TransactionLock {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::ReleaseMutex;

            // SAFETY: acquire owns the live mutex handle until this drop.
            let _ = unsafe { ReleaseMutex(self.handle) };
            // SAFETY: the mutex has been released and the handle is still live.
            let _ = unsafe { CloseHandle(self.handle) };
        }
        #[cfg(not(windows))]
        {
            let _ = fs2::FileExt::unlock(&self.file);
        }
        #[cfg(unix)]
        {
            let _ = fs2::FileExt::unlock(&self.stable_parent);
        }
    }
}

#[cfg(windows)]
fn transaction_mutex_name(paths: &AppPaths) -> std::ffi::OsString {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for path in [paths.config_dir(), paths.data_dir(), paths.state_dir()] {
        let normalized = path.to_string_lossy().replace('/', "\\").to_lowercase();
        for byte in normalized.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Global\ is shared across console, RDP, and service sessions. The mutex
    // inherits the process token's default DACL, so access remains limited by
    // Windows object security while the same user gets one cross-session lock.
    format!(r"Global\SAIAI-V2-Transaction-{hash:016x}").into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    struct Fixture {
        _temp: tempfile::TempDir,
        core: SaiaiCore,
        legacy_sentinels: Vec<PathBuf>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            let paths = AppPaths::from_app_dirs(
                root.join("xdg-config/saiai"),
                root.join("xdg-data/saiai"),
                root.join("xdg-state/saiai"),
            )
            .unwrap();
            let legacy_sentinels = [".saiai", ".claude", ".codex"]
                .into_iter()
                .map(|directory| {
                    let path = root.join("home").join(directory).join("sentinel");
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::write(&path, format!("legacy-{directory}")).unwrap();
                    path
                })
                .collect();
            Self {
                _temp: temp,
                core: SaiaiCore::new(paths),
                legacy_sentinels,
            }
        }

        fn assert_legacy_untouched(&self) {
            for sentinel in &self.legacy_sentinels {
                let directory = sentinel.parent().unwrap().file_name().unwrap();
                assert_eq!(
                    fs::read_to_string(sentinel).unwrap(),
                    format!("legacy-{}", directory.to_string_lossy())
                );
            }
        }
    }

    fn request(base_url: &str, key: &str) -> SetupRequest {
        SetupRequest::new(base_url, key).unwrap()
    }

    fn ca_pair() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "SAIAI setup transaction test CA");
        params.distinguished_name = name;
        let certificate = params.self_signed(&key).unwrap();
        (certificate.pem(), key.serialize_pem())
    }

    fn claude_artifacts(tag: &str) -> ProductSetupArtifacts {
        let (certificate, key) = ca_pair();
        ProductSetupArtifacts::Claude(
            ClaudeSetupArtifacts::new(
                format!(r#"{{"env":{{"SAIAI_TEST":"{tag}"}}}}"#).into_bytes(),
                br#"{"hasCompletedOnboarding":true}"#.to_vec(),
                certificate,
                key,
            )
            .unwrap(),
        )
    }

    fn codex_artifacts(tag: &str) -> ProductSetupArtifacts {
        ProductSetupArtifacts::Codex(
            CodexSetupArtifacts::new(format!(
                "model_provider = 'saiai'\n[model_providers.saiai]\nname = '{tag}'\n"
            ))
            .unwrap(),
        )
    }

    fn product_status(status: &SetupStatus, product: Product) -> &ProductSetupStatus {
        status
            .products
            .iter()
            .find(|candidate| candidate.product == product)
            .unwrap()
    }

    #[test]
    fn quarantine_rollback_restores_every_non_conflicting_entry() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("credentials");
        fs::create_dir(&parent).unwrap();
        let first = parent.join("claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.key");
        let conflicting = parent.join("claude-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.key");
        fs::write(&first, b"first-original").unwrap();
        fs::write(&conflicting, b"second-original").unwrap();

        let mut quarantine = RevokeQuarantine::new(Product::Claude);
        assert!(quarantine.move_path(&first).unwrap());
        assert!(quarantine.move_path(&conflicting).unwrap());
        let preserved_quarantine = quarantine
            .entries
            .iter()
            .find(|entry| entry.original == conflicting)
            .unwrap()
            .quarantined
            .clone();
        fs::write(&conflicting, b"concurrent-recreation").unwrap();

        assert!(quarantine.rollback().is_err());
        assert_eq!(fs::read(&first).unwrap(), b"first-original");
        assert_eq!(fs::read(&conflicting).unwrap(), b"concurrent-recreation");
        assert_eq!(fs::read(&preserved_quarantine).unwrap(), b"second-original");
        assert_eq!(quarantine.entries.len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn transaction_mutex_is_cross_session_and_path_alias_stable() {
        let first = AppPaths::from_app_dirs(
            r"C:\Users\Tester\SAIAI\config",
            r"C:\Users\Tester\SAIAI\data",
            r"C:\Users\Tester\SAIAI\state",
        )
        .unwrap();
        let second = AppPaths::from_app_dirs(
            r"c:/users/tester/saiai/CONFIG",
            r"c:/users/tester/saiai/DATA",
            r"c:/users/tester/saiai/STATE",
        )
        .unwrap();
        let first_name = transaction_mutex_name(&first);
        assert_eq!(first_name, transaction_mutex_name(&second));
        assert!(first_name.to_string_lossy().starts_with(r"Global\"));
    }

    #[test]
    fn one_product_is_ready_while_the_other_is_unconfigured() {
        let fixture = Fixture::new();
        let status = fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-only"),
                claude_artifacts("first"),
            )
            .unwrap();

        assert_eq!(status.state, SetupState::Ready);
        assert_eq!(
            product_status(&status, Product::Claude).state,
            ProductSetupState::Ready
        );
        assert_eq!(
            product_status(&status, Product::Codex).state,
            ProductSetupState::Unconfigured
        );
        assert_eq!(
            fixture
                .core
                .load_credential(Product::Claude)
                .unwrap()
                .expose_secret(),
            "sk-claude-only"
        );
        assert!(matches!(
            fixture.core.load_credential(Product::Codex),
            Err(Error::ProductNotConfigured(Product::Codex))
        ));
        let config_text = fs::read_to_string(fixture.core.paths().config_file()).unwrap();
        assert!(config_text.contains("\"schema_version\": 2"));
        assert!(!config_text.contains("sk-claude-only"));
        fixture.assert_legacy_untouched();
    }

    #[test]
    fn committed_product_snapshot_keeps_one_generation_and_redacts_its_credential() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://first.example.test", "sk-first-snapshot"),
                claude_artifacts("first"),
            )
            .unwrap();
        let snapshot = fixture
            .core
            .load_committed_product(Product::Claude)
            .unwrap();
        let old_home = snapshot.home().to_path_buf();
        assert_eq!(snapshot.base_url().as_str(), "https://first.example.test/");
        assert_eq!(snapshot.credential().expose_secret(), "sk-first-snapshot");
        assert!(!format!("{snapshot:?}").contains("sk-first-snapshot"));

        fixture
            .core
            .setup_product_with_artifacts(
                request("https://second.example.test", "sk-second-snapshot"),
                claude_artifacts("second"),
            )
            .unwrap();

        assert_eq!(snapshot.base_url().as_str(), "https://first.example.test/");
        assert_eq!(snapshot.credential().expose_secret(), "sk-first-snapshot");
        assert_eq!(snapshot.home(), old_home.as_path());
        assert!(
            old_home.exists(),
            "the live snapshot must lease its old home"
        );
        let current = fixture
            .core
            .load_committed_product(Product::Claude)
            .unwrap();
        assert_eq!(current.base_url().as_str(), "https://second.example.test/");
        assert_eq!(current.credential().expose_secret(), "sk-second-snapshot");
        drop(current);
        drop(snapshot);

        fixture
            .core
            .revoke(RevokeTarget::Product(Product::Claude))
            .unwrap();
        assert!(!old_home.exists());
    }

    #[test]
    fn adding_and_replacing_a_product_preserves_the_other_product() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-first"),
                claude_artifacts("first"),
            )
            .unwrap();
        let claude_home = fixture.core.client_home(Product::Claude).unwrap();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test/", "sk-codex"),
                codex_artifacts("codex"),
            )
            .unwrap();
        let codex_home = fixture.core.client_home(Product::Codex).unwrap();
        assert_eq!(
            fixture.core.client_home(Product::Claude).unwrap(),
            claude_home
        );

        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-second"),
                claude_artifacts("second"),
            )
            .unwrap();
        assert_eq!(
            fixture.core.client_home(Product::Codex).unwrap(),
            codex_home
        );
        assert_ne!(
            fixture.core.client_home(Product::Claude).unwrap(),
            claude_home
        );
        assert!(!claude_home.exists());
        assert_eq!(
            fixture
                .core
                .load_credential(Product::Codex)
                .unwrap()
                .expose_secret(),
            "sk-codex"
        );
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Ready
        );
        fixture.assert_legacy_untouched();
    }

    #[test]
    fn a_second_product_cannot_silently_change_the_shared_gateway() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://first.example.test", "sk-claude"),
                claude_artifacts("first"),
            )
            .unwrap();
        let error = fixture
            .core
            .setup_product_with_artifacts(
                request("https://second.example.test", "sk-codex"),
                codex_artifacts("second"),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            Error::SharedGatewayMismatch {
                product: Product::Codex,
                other: Product::Claude
            }
        ));
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Ready
        );
        assert!(matches!(
            fixture.core.client_home(Product::Codex),
            Err(Error::ProductNotConfigured(Product::Codex))
        ));
    }

    #[test]
    fn each_precommit_failure_preserves_both_committed_products() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-stable-claude"),
                claude_artifacts("stable"),
            )
            .unwrap();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-stable-codex"),
                codex_artifacts("stable"),
            )
            .unwrap();
        let original_config = fs::read(fixture.core.paths().config_file()).unwrap();
        let original_claude_home = fixture.core.client_home(Product::Claude).unwrap();
        let original_codex_home = fixture.core.client_home(Product::Codex).unwrap();

        for (index, fault) in [
            SetupFault::CorruptStagedProduct,
            SetupFault::AfterGenerationPromotion,
            SetupFault::AfterCredentialSave,
            SetupFault::BeforeConfigCommit,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                fixture
                    .core
                    .setup_product_with_fault(
                        request("https://api.example.test", &format!("sk-failed-{index}")),
                        claude_artifacts("failed"),
                        fault,
                    )
                    .is_err()
            );
            assert_eq!(
                fs::read(fixture.core.paths().config_file()).unwrap(),
                original_config
            );
            assert_eq!(
                fixture.core.client_home(Product::Claude).unwrap(),
                original_claude_home
            );
            assert_eq!(
                fixture.core.client_home(Product::Codex).unwrap(),
                original_codex_home
            );
            assert_eq!(
                fixture
                    .core
                    .load_credential(Product::Claude)
                    .unwrap()
                    .expose_secret(),
                "sk-stable-claude"
            );
        }
        fixture.assert_legacy_untouched();
    }

    #[test]
    fn each_first_setup_failure_removes_only_new_v2_roots() {
        for fault in [
            SetupFault::CorruptStagedProduct,
            SetupFault::AfterGenerationPromotion,
            SetupFault::AfterCredentialSave,
            SetupFault::BeforeConfigCommit,
        ] {
            let fixture = Fixture::new();
            assert!(
                fixture
                    .core
                    .setup_product_with_fault(
                        request("https://api.example.test", "sk-first-failure"),
                        claude_artifacts("failed"),
                        fault,
                    )
                    .is_err()
            );
            assert_eq!(
                fixture.core.setup_status().unwrap().state,
                SetupState::Uninitialized
            );
            assert!(!fixture.core.paths().config_dir().exists());
            assert!(!fixture.core.paths().data_dir().exists());
            assert!(!fixture.core.paths().state_dir().exists());
            fixture.assert_legacy_untouched();
        }
    }

    #[test]
    fn a_waiting_failed_setup_never_removes_a_concurrently_committed_first_setup() {
        let fixture = Fixture::new();
        let waiting_core = fixture.core.clone();
        let (inspected_tx, inspected_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();

        let waiting = std::thread::spawn(move || {
            waiting_core.setup_product_with_fault_after_root_inspect(
                request("https://api.example.test", "sk-waiting-failure"),
                claude_artifacts("waiting"),
                SetupFault::AfterGenerationPromotion,
                || {
                    inspected_tx.send(()).unwrap();
                    continue_rx.recv().unwrap();
                },
            )
        });
        inspected_rx.recv().unwrap();

        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-concurrent-winner"),
                claude_artifacts("winner"),
            )
            .unwrap();
        continue_tx.send(()).unwrap();
        assert!(waiting.join().unwrap().is_err());

        assert_eq!(
            fixture
                .core
                .load_credential(Product::Claude)
                .unwrap()
                .expose_secret(),
            "sk-concurrent-winner"
        );
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Ready
        );
        assert!(fixture.core.client_home(Product::Claude).unwrap().is_dir());
    }

    #[test]
    fn setup_fails_closed_when_roots_exist_without_config() {
        let fixture = Fixture::new();
        let sentinel = fixture.core.paths().data_dir().join("preexisting-sentinel");
        fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        fs::write(&sentinel, b"preserve").unwrap();

        let gateway = GatewayUrl::parse("https://api.example.test").unwrap();
        let error = fixture
            .core
            .validate_shared_base_url(Product::Claude, &gateway)
            .unwrap_err();
        assert!(format!("{error}").contains("revoke --all"));
        assert!(
            fixture
                .core
                .setup_product_with_artifacts(
                    request("https://api.example.test", "sk-dirty-root"),
                    claude_artifacts("dirty"),
                )
                .is_err()
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
        assert!(!fixture.core.paths().config_file().exists());
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Broken
        );
    }

    #[test]
    fn diagnostics_locking_does_not_create_missing_v2_state() {
        let fixture = Fixture::new();
        let sentinel = fixture.core.paths().data_dir().join("orphan");
        fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        fs::write(&sentinel, b"preserve").unwrap();
        assert!(!fixture.core.paths().state_dir().exists());

        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Broken
        );
        assert!(!fixture.core.paths().state_dir().exists());
        let gateway = GatewayUrl::parse("https://api.example.test").unwrap();
        assert!(
            fixture
                .core
                .validate_shared_base_url(Product::Claude, &gateway)
                .is_err()
        );
        assert!(!fixture.core.paths().state_dir().exists());
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
    }

    #[test]
    fn product_revoke_faults_restore_a_complete_retryable_product() {
        for fault in [
            RevokeFault::BeforeCleanup,
            RevokeFault::AfterFirstQuarantine,
            RevokeFault::BeforeConfigCommit,
        ] {
            let fixture = Fixture::new();
            fixture
                .core
                .setup_product_with_artifacts(
                    request("https://api.example.test", "sk-claude-retry"),
                    claude_artifacts("claude"),
                )
                .unwrap();
            fixture
                .core
                .setup_product_with_artifacts(
                    request("https://api.example.test", "sk-codex-stable"),
                    codex_artifacts("codex"),
                )
                .unwrap();
            let config_before = fs::read(fixture.core.paths().config_file()).unwrap();
            let home_before = fixture.core.client_home(Product::Claude).unwrap();

            assert!(
                fixture
                    .core
                    .revoke_product_with_fault(Product::Claude, fault)
                    .is_err()
            );
            assert_eq!(
                fs::read(fixture.core.paths().config_file()).unwrap(),
                config_before
            );
            assert!(home_before.is_dir());
            assert_eq!(
                fixture
                    .core
                    .load_credential(Product::Claude)
                    .unwrap()
                    .expose_secret(),
                "sk-claude-retry"
            );
            assert_eq!(
                fixture.core.setup_status().unwrap().state,
                SetupState::Ready
            );

            let retry = fixture
                .core
                .revoke(RevokeTarget::Product(Product::Claude))
                .unwrap();
            assert_eq!(
                product_status(&retry.status, Product::Claude).state,
                ProductSetupState::Unconfigured
            );
            assert_eq!(
                product_status(&retry.status, Product::Codex).state,
                ProductSetupState::Ready
            );
        }
    }

    #[test]
    fn final_product_revoke_faults_restore_config_home_and_credential() {
        for fault in [
            RevokeFault::BeforeCleanup,
            RevokeFault::AfterFirstQuarantine,
            RevokeFault::BeforeConfigCommit,
        ] {
            let fixture = Fixture::new();
            fixture
                .core
                .setup_product_with_artifacts(
                    request("https://api.example.test", "sk-last-retry"),
                    claude_artifacts("last"),
                )
                .unwrap();
            let config_before = fs::read(fixture.core.paths().config_file()).unwrap();
            let home_before = fixture.core.client_home(Product::Claude).unwrap();

            assert!(
                fixture
                    .core
                    .revoke_product_with_fault(Product::Claude, fault)
                    .is_err()
            );
            assert_eq!(
                fs::read(fixture.core.paths().config_file()).unwrap(),
                config_before
            );
            assert!(home_before.is_dir());
            assert_eq!(
                fixture
                    .core
                    .load_credential(Product::Claude)
                    .unwrap()
                    .expose_secret(),
                "sk-last-retry"
            );
            assert_eq!(
                fixture.core.setup_status().unwrap().state,
                SetupState::Ready
            );

            let retry = fixture
                .core
                .revoke(RevokeTarget::Product(Product::Claude))
                .unwrap();
            assert_eq!(retry.status.state, SetupState::Uninitialized);
            assert!(!fixture.core.paths().config_dir().exists());
            assert!(!fixture.core.paths().data_dir().exists());
            assert!(!fixture.core.paths().state_dir().exists());
        }
    }

    #[test]
    fn setup_receipt_preserves_other_product_diagnostics_without_postcommit_reread() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-codex-broken"),
                codex_artifacts("broken"),
            )
            .unwrap();
        let config = fixture.core.load_config().unwrap();
        let codex_credential = fixture
            .core
            .credential_store()
            .credential_path(config.product(Product::Codex).unwrap().credential_ref());
        fs::remove_file(codex_credential).unwrap();

        let receipt = fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-ready"),
                claude_artifacts("ready"),
            )
            .unwrap();
        assert_eq!(receipt.state, SetupState::Broken);
        assert_eq!(
            product_status(&receipt, Product::Claude).state,
            ProductSetupState::Ready
        );
        assert_eq!(
            product_status(&receipt, Product::Codex).state,
            ProductSetupState::Broken
        );
        assert!(
            product_status(&receipt, Product::Codex)
                .issues
                .iter()
                .any(|issue| issue.code == SetupIssueCode::CredentialMissing)
        );
    }

    #[test]
    fn busy_preflight_drops_acquired_leases_without_unlinking_them() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-busy-preflight"),
                claude_artifacts("busy"),
            )
            .unwrap();
        let config_before = fs::read(fixture.core.paths().config_file()).unwrap();
        let home_before = fixture.core.client_home(Product::Claude).unwrap();
        let committed = fixture
            .core
            .load_committed_product(Product::Claude)
            .unwrap();
        let orphan =
            GenerationRef::new("gen-claude-00000000000000000000000000000000".to_owned()).unwrap();
        let orphan_lease = fixture.core.paths().generation_lease_file(&orphan);
        fs::write(&orphan_lease, b"keep-unlocked-lease").unwrap();

        assert!(matches!(
            fixture.core.revoke(RevokeTarget::Product(Product::Claude)),
            Err(Error::ProductBusy(Product::Claude))
        ));
        assert_eq!(fs::read(&orphan_lease).unwrap(), b"keep-unlocked-lease");
        assert_eq!(
            fs::read(fixture.core.paths().config_file()).unwrap(),
            config_before
        );
        assert!(home_before.is_dir());

        drop(committed);
        fixture.core.revoke(RevokeTarget::All).unwrap();
    }

    #[test]
    fn a_live_generation_blocks_product_and_full_revoke_without_mutation() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-busy"),
                claude_artifacts("busy"),
            )
            .unwrap();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-codex-busy"),
                codex_artifacts("busy"),
            )
            .unwrap();
        let config_before = fs::read(fixture.core.paths().config_file()).unwrap();
        let committed = fixture
            .core
            .load_committed_product(Product::Claude)
            .unwrap();

        assert!(matches!(
            fixture.core.revoke(RevokeTarget::Product(Product::Claude)),
            Err(Error::ProductBusy(Product::Claude))
        ));
        assert!(matches!(
            fixture.core.revoke(RevokeTarget::All),
            Err(Error::ProductBusy(Product::Claude))
        ));
        assert_eq!(
            fs::read(fixture.core.paths().config_file()).unwrap(),
            config_before
        );
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Ready
        );

        drop(committed);
        fixture.core.revoke(RevokeTarget::All).unwrap();
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Uninitialized
        );
    }

    #[test]
    fn reconfigured_leased_generation_is_collected_by_later_product_revoke() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-old"),
                claude_artifacts("old"),
            )
            .unwrap();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-codex-stable"),
                codex_artifacts("stable"),
            )
            .unwrap();
        let old = fixture
            .core
            .load_committed_product(Product::Claude)
            .unwrap();
        let old_home = old.home().to_path_buf();

        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-new"),
                claude_artifacts("new"),
            )
            .unwrap();
        let new_home = fixture.core.client_home(Product::Claude).unwrap();
        assert!(old_home.exists());
        assert!(new_home.exists());
        assert!(matches!(
            fixture.core.revoke(RevokeTarget::Product(Product::Claude)),
            Err(Error::ProductBusy(Product::Claude))
        ));

        drop(old);
        fixture
            .core
            .revoke(RevokeTarget::Product(Product::Claude))
            .unwrap();
        assert!(!old_home.exists());
        assert!(!new_home.exists());
        assert_eq!(
            fixture
                .core
                .load_credential(Product::Codex)
                .unwrap()
                .expose_secret(),
            "sk-codex-stable"
        );
    }

    #[test]
    fn product_revoke_without_an_entry_collects_generated_orphans_and_quarantine() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-once"),
                claude_artifacts("once"),
            )
            .unwrap();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-codex-stable"),
                codex_artifacts("stable"),
            )
            .unwrap();
        fixture
            .core
            .revoke_product_with_fault(Product::Claude, RevokeFault::LeaveQuarantineAfterCommit)
            .unwrap();

        let identifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let credential = fixture
            .core
            .paths()
            .credentials_dir()
            .join(format!("claude-{identifier}.key"));
        fs::create_dir_all(credential.parent().unwrap()).unwrap();
        fs::write(&credential, b"orphan-secret").unwrap();
        let generation = GenerationRef::new(format!("gen-claude-{identifier}")).unwrap();
        for (_, path) in fixture.core.generation_paths(&generation) {
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("orphan"), b"orphan").unwrap();
        }

        let report = fixture
            .core
            .revoke(RevokeTarget::Product(Product::Claude))
            .unwrap();
        assert!(!credential.exists());
        for (_, path) in fixture.core.generation_paths(&generation) {
            assert!(!path.exists());
        }
        assert!(report.removed_paths.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".saiai-revoke-claude-"))
        }));
        assert_eq!(
            product_status(&report.status, Product::Codex).state,
            ProductSetupState::Ready
        );
    }

    #[test]
    fn product_revoke_keeps_the_other_ready_and_last_revoke_is_clean() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude"),
                claude_artifacts("claude"),
            )
            .unwrap();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-codex"),
                codex_artifacts("codex"),
            )
            .unwrap();
        let claude_home = fixture.core.client_home(Product::Claude).unwrap();

        let first = fixture
            .core
            .revoke(RevokeTarget::Product(Product::Claude))
            .unwrap();
        assert_eq!(first.status.state, SetupState::Ready);
        assert_eq!(
            product_status(&first.status, Product::Claude).state,
            ProductSetupState::Unconfigured
        );
        assert_eq!(
            product_status(&first.status, Product::Codex).state,
            ProductSetupState::Ready
        );
        assert!(!claude_home.exists());
        assert!(fixture.core.client_home(Product::Codex).unwrap().is_dir());

        let last = fixture
            .core
            .revoke(RevokeTarget::Product(Product::Codex))
            .unwrap();
        assert_eq!(last.status.state, SetupState::Uninitialized);
        assert!(!fixture.core.paths().config_dir().exists());
        assert!(!fixture.core.paths().data_dir().exists());
        assert!(!fixture.core.paths().state_dir().exists());
        fixture.assert_legacy_untouched();
    }

    #[test]
    fn final_product_revoke_keeps_other_prefixes_and_unknown_files_for_full_revoke() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude-only"),
                claude_artifacts("only"),
            )
            .unwrap();
        let claude_home = fixture.core.client_home(Product::Claude).unwrap();

        let identifier = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let codex_credential = fixture
            .core
            .paths()
            .credentials_dir()
            .join(format!("codex-{identifier}.key"));
        fs::create_dir_all(codex_credential.parent().unwrap()).unwrap();
        fs::write(&codex_credential, b"unconfigured-codex-orphan").unwrap();
        let codex_generation = GenerationRef::new(format!("gen-codex-{identifier}")).unwrap();
        for (_, path) in fixture.core.generation_paths(&codex_generation) {
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("keep"), b"unconfigured-codex-orphan").unwrap();
        }
        let codex_lease = fixture
            .core
            .paths()
            .generation_lease_file(&codex_generation);
        fs::create_dir_all(codex_lease.parent().unwrap()).unwrap();
        fs::write(&codex_lease, b"unconfigured-codex-orphan").unwrap();
        let unknown = fixture.core.paths().config_dir().join("keep-unknown");
        fs::write(&unknown, b"unknown").unwrap();

        let report = fixture
            .core
            .revoke(RevokeTarget::Product(Product::Claude))
            .unwrap();
        assert_eq!(report.status.state, SetupState::Uninitialized);
        assert!(report.status.config.is_none());
        assert!(!fixture.core.paths().config_file().exists());
        assert!(!claude_home.exists());
        assert_eq!(
            fs::read(&codex_credential).unwrap(),
            b"unconfigured-codex-orphan"
        );
        assert_eq!(
            fs::read(&codex_lease).unwrap(),
            b"unconfigured-codex-orphan"
        );
        for (_, path) in fixture.core.generation_paths(&codex_generation) {
            assert!(path.join("keep").is_file());
        }
        assert_eq!(fs::read(&unknown).unwrap(), b"unknown");

        // The operation receipt reflects the committed removal. Live
        // diagnostics are intentionally separate and flag the preserved
        // unowned roots until an explicit full revoke.
        assert_eq!(
            fixture.core.setup_status().unwrap().state,
            SetupState::Broken
        );
        fixture.core.revoke(RevokeTarget::All).unwrap();
        assert!(!fixture.core.paths().config_dir().exists());
        assert!(!fixture.core.paths().data_dir().exists());
        assert!(!fixture.core.paths().state_dir().exists());
    }

    #[test]
    fn existing_gateway_credential_overlap_is_hidden_and_requires_full_revoke() {
        let fixture = Fixture::new();
        let secret = "sk-existing-config-must-never-render";
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", secret),
                claude_artifacts("claude"),
            )
            .unwrap();

        let config_path = fixture.core.paths().config_file();
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config["base_url"] =
            serde_json::Value::String(format!("https://api.example.test/{secret}"));
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

        let status = fixture.core.setup_status().unwrap();
        assert_eq!(status.state, SetupState::Broken);
        assert!(status.config.is_none());
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.code == SetupIssueCode::ConfigInvalid)
        );
        let rendered = format!("{status:?}\n{}", serde_json::to_string(&status).unwrap());
        assert!(!rendered.contains(secret));

        let error = fixture.core.load_config().unwrap_err();
        assert!(!format!("{error}\n{error:?}").contains(secret));
        let error = match fixture.core.load_committed_product(Product::Claude) {
            Ok(_) => panic!("unsafe committed product was loaded"),
            Err(error) => error,
        };
        assert!(!format!("{error}\n{error:?}").contains(secret));

        let config_before = fs::read(&config_path).unwrap();
        let error = fixture
            .core
            .revoke(RevokeTarget::Product(Product::Claude))
            .unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(rendered.contains("revoke --all"));
        assert!(!rendered.contains(secret));
        assert_eq!(fs::read(&config_path).unwrap(), config_before);

        let error = fixture
            .core
            .setup_product_with_artifacts(
                request(
                    &format!("https://api.example.test/{secret}"),
                    "sk-replacement-must-not-commit",
                ),
                claude_artifacts("replacement"),
            )
            .unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        assert!(rendered.contains("revoke --all"));
        assert!(!rendered.contains(secret));
        assert_eq!(fs::read(&config_path).unwrap(), config_before);

        fixture.core.revoke(RevokeTarget::All).unwrap();
        assert!(!fixture.core.paths().config_dir().exists());
        assert!(!fixture.core.paths().data_dir().exists());
        assert!(!fixture.core.paths().state_dir().exists());
        fixture.assert_legacy_untouched();
    }

    #[test]
    fn full_revoke_recovers_old_schema_and_invalid_config_without_parsing() {
        for contents in [
            br#"{"schema_version":1,"base_url":"https://old.invalid"}"#.as_slice(),
            b"not-json".as_slice(),
        ] {
            let fixture = Fixture::new();
            fs::create_dir_all(fixture.core.paths().config_dir()).unwrap();
            fs::create_dir_all(fixture.core.paths().data_dir()).unwrap();
            fs::create_dir_all(fixture.core.paths().state_dir()).unwrap();
            fs::write(fixture.core.paths().config_file(), contents).unwrap();
            fs::write(fixture.core.paths().data_dir().join("orphan"), b"old").unwrap();

            assert_eq!(
                fixture.core.setup_status().unwrap().state,
                SetupState::Broken
            );
            let report = fixture.core.revoke(RevokeTarget::All).unwrap();
            assert_eq!(report.status.state, SetupState::Uninitialized);
            assert!(!fixture.core.paths().config_dir().exists());
            assert!(!fixture.core.paths().data_dir().exists());
            assert!(!fixture.core.paths().state_dir().exists());
            fixture.assert_legacy_untouched();
        }
    }

    #[test]
    fn only_a_configured_product_can_be_broken() {
        let fixture = Fixture::new();
        fixture
            .core
            .setup_product_with_artifacts(
                request("https://api.example.test", "sk-claude"),
                claude_artifacts("claude"),
            )
            .unwrap();
        let config = fixture.core.load_config().unwrap();
        let credential = fixture
            .core
            .credential_store()
            .credential_path(config.product(Product::Claude).unwrap().credential_ref());
        fs::remove_file(credential).unwrap();

        let status = fixture.core.setup_status().unwrap();
        assert_eq!(status.state, SetupState::Broken);
        assert_eq!(
            product_status(&status, Product::Claude).state,
            ProductSetupState::Broken
        );
        assert_eq!(
            product_status(&status, Product::Codex).state,
            ProductSetupState::Unconfigured
        );
        assert!(product_status(&status, Product::Codex).issues.is_empty());
    }
}
