use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::fsutil::is_symlink_or_reparse;
use crate::{
    CLAUDE_CA_CERT_FILENAME, CLAUDE_CA_KEY_FILENAME, CLAUDE_SETTINGS_FILENAME,
    CLAUDE_STATE_FILENAME, CODEX_CONFIG_FILENAME, FileCredentialStore, PrivatePermissionIssue,
    PrivatePermissionIssueCode, PrivatePermissionsAudit, Product, SaiaiCore,
};

const PRODUCT_MARKER_FILENAME: &str = ".saiai-managed-v2";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ManagedObjectKind {
    Directory,
    File,
}

impl ManagedObjectKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }
}

impl SaiaiCore {
    /// Audit permissions on explicit V2-owned paths without reading secrets.
    ///
    /// Windows requires the current user to own each object and a protected
    /// DACL containing exactly current-user, SYSTEM, and Administrators
    /// full-control entries. Unix requires ownership by the effective user and
    /// no group/other permission bits.
    /// Missing setup files remain the responsibility of [`Self::setup_status`]
    /// and are not duplicated as permission findings.
    pub fn audit_private_permissions(&self) -> PrivatePermissionsAudit {
        let mut targets = managed_targets(self).into_iter().collect::<Vec<_>>();
        targets.sort_by(|left, right| {
            left.0
                .components()
                .count()
                .cmp(&right.0.components().count())
                .then_with(|| left.cmp(right))
        });
        let mut audit = PrivatePermissionsAudit {
            supported: cfg!(any(unix, windows)),
            checked_paths: 0,
            issues: Vec::new(),
        };

        if !audit.supported {
            return audit;
        }

        let mut blocked_directories = Vec::<PathBuf>::new();
        for (path, kind) in targets {
            if blocked_directories
                .iter()
                .any(|ancestor| path != *ancestor && path.starts_with(ancestor))
            {
                // Never inspect through a V2-owned directory already proven
                // to be a symlink, non-directory, or unreadable.
                continue;
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    if kind == ManagedObjectKind::Directory {
                        blocked_directories.push(path.clone());
                    }
                    audit.issues.push(issue(
                        PrivatePermissionIssueCode::InspectFailed,
                        path,
                        format!("could not inspect V2-owned path: {error}"),
                    ));
                    continue;
                }
            };

            if is_symlink_or_reparse(&metadata) {
                if kind == ManagedObjectKind::Directory {
                    blocked_directories.push(path.clone());
                }
                audit.issues.push(issue(
                    PrivatePermissionIssueCode::SymbolicLink,
                    path,
                    format!(
                        "expected a managed {}, but found a symbolic link",
                        kind.name()
                    ),
                ));
                continue;
            }

            let expected_type = match kind {
                ManagedObjectKind::Directory => metadata.is_dir(),
                ManagedObjectKind::File => metadata.is_file(),
            };
            if !expected_type {
                if kind == ManagedObjectKind::Directory {
                    blocked_directories.push(path.clone());
                }
                audit.issues.push(issue(
                    PrivatePermissionIssueCode::UnexpectedObjectType,
                    path,
                    format!("expected a managed {}", kind.name()),
                ));
                continue;
            }

            audit.checked_paths += 1;
            if let Err(error) = audit_platform_permissions(&path, kind) {
                audit.issues.push(issue(
                    PrivatePermissionIssueCode::InsecurePermissions,
                    path,
                    error.to_string(),
                ));
            }
        }

        audit
    }
}

fn managed_targets(core: &SaiaiCore) -> BTreeSet<(PathBuf, ManagedObjectKind)> {
    let paths = core.paths();
    let mut targets = BTreeSet::new();
    for path in [
        paths.config_dir().to_path_buf(),
        paths.data_dir().to_path_buf(),
        paths.state_dir().to_path_buf(),
        paths.credentials_dir(),
        paths.generations_dir(),
        paths.generation_staging_dir(),
        paths.runtime_dir(),
        paths.logs_dir(),
        paths.leases_dir(),
    ] {
        targets.insert((path, ManagedObjectKind::Directory));
    }
    for path in [paths.config_file(), paths.transaction_lock_file()] {
        targets.insert((path, ManagedObjectKind::File));
    }

    let Ok(config) = core.load_config() else {
        return targets;
    };
    for product in config.products().configured_products() {
        let product_config = config
            .product(product)
            .expect("configured_products only returns present entries");
        targets.insert((
            FileCredentialStore::new(paths.credentials_dir())
                .credential_path(product_config.credential_ref()),
            ManagedObjectKind::File,
        ));

        let generation = product_config.active_generation();
        for path in [
            paths.generation_dir(generation),
            paths.generation_clients_dir(generation),
            paths.generation_runtime_dir(generation),
            paths.generation_logs_dir(generation),
        ] {
            targets.insert((path, ManagedObjectKind::Directory));
        }
        targets.insert((
            paths.generation_lease_file(generation),
            ManagedObjectKind::File,
        ));

        let home = paths.generation_client_home(generation, product);
        targets.insert((home.clone(), ManagedObjectKind::Directory));
        targets.insert((home.join(PRODUCT_MARKER_FILENAME), ManagedObjectKind::File));
        for path in [
            paths.generation_product_runtime_dir(generation, product),
            paths.generation_product_logs_dir(generation, product),
        ] {
            targets.insert((path, ManagedObjectKind::Directory));
        }
        let filenames: &[&str] = match product {
            Product::Claude => &[
                CLAUDE_SETTINGS_FILENAME,
                CLAUDE_STATE_FILENAME,
                CLAUDE_CA_CERT_FILENAME,
                CLAUDE_CA_KEY_FILENAME,
            ],
            Product::Codex => &[CODEX_CONFIG_FILENAME],
        };
        for filename in filenames {
            targets.insert((home.join(filename), ManagedObjectKind::File));
        }
    }

    targets
}

fn issue(
    code: PrivatePermissionIssueCode,
    path: PathBuf,
    message: String,
) -> PrivatePermissionIssue {
    PrivatePermissionIssue {
        code,
        path,
        message,
    }
}

#[cfg(unix)]
fn audit_platform_permissions(path: &Path, _kind: ManagedObjectKind) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::metadata(path)?;
    // SAFETY: geteuid takes no pointers and has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    validate_unix_private_metadata(metadata.uid(), effective_uid, metadata.permissions().mode())
}

#[cfg(unix)]
fn validate_unix_private_metadata(
    owner_uid: u32,
    effective_uid: u32,
    mode: u32,
) -> std::io::Result<()> {
    if owner_uid != effective_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("owner UID is {owner_uid}; expected current effective UID {effective_uid}"),
        ));
    }
    let mode = mode & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("permissions are {mode:03o}; expected user-only access"),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn audit_platform_permissions(path: &Path, kind: ManagedObjectKind) -> std::io::Result<()> {
    let kind = match kind {
        ManagedObjectKind::Directory => crate::windows_acl::PrivateObjectKind::Directory,
        ManagedObjectKind::File => crate::windows_acl::PrivateObjectKind::File,
    };
    crate::windows_acl::audit_private_permissions(path, kind)
}

#[cfg(not(any(unix, windows)))]
fn audit_platform_permissions(_path: &Path, _kind: ManagedObjectKind) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppPaths, ClaudeSetupArtifacts, ProductSetupArtifacts, SetupRequest};
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use tempfile::TempDir;

    fn fixture() -> (TempDir, SaiaiCore) {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_app_dirs(
            temp.path().join("config/saiai"),
            temp.path().join("data/saiai"),
            temp.path().join("state/saiai"),
        )
        .unwrap();
        (temp, SaiaiCore::new(paths))
    }

    fn artifacts() -> ProductSetupArtifacts {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "SAIAI permission audit test CA");
        params.distinguished_name = name;
        let certificate = params.self_signed(&key).unwrap();
        ProductSetupArtifacts::Claude(
            ClaudeSetupArtifacts::new(
                b"{}".to_vec(),
                b"{}".to_vec(),
                certificate.pem(),
                key.serialize_pem(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn audit_is_non_secret_and_accepts_fresh_setup() {
        let (_temp, core) = fixture();
        core.setup_product_with_artifacts(
            SetupRequest::new("https://gateway.example.test", "never-print-this-secret").unwrap(),
            artifacts(),
        )
        .unwrap();

        let audit = core.audit_private_permissions();
        assert!(audit.supported);
        assert!(audit.checked_paths >= 10);
        assert!(audit.issues.is_empty(), "{:#?}", audit.issues);
        let serialized = serde_json::to_string(&audit).unwrap();
        assert!(!serialized.contains("never-print-this-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_reports_relaxed_secret_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp, core) = fixture();
        core.setup_product_with_artifacts(
            SetupRequest::new("https://gateway.example.test", "secret").unwrap(),
            artifacts(),
        )
        .unwrap();
        let key = core
            .client_home(Product::Claude)
            .unwrap()
            .join(CLAUDE_CA_KEY_FILENAME);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

        let audit = core.audit_private_permissions();
        assert!(!audit.is_secure());
        assert!(audit.issues.iter().any(|issue| {
            issue.code == PrivatePermissionIssueCode::InsecurePermissions && issue.path == key
        }));
    }

    #[cfg(unix)]
    #[test]
    fn unix_permission_validator_rejects_a_different_owner() {
        assert!(validate_unix_private_metadata(1000, 1000, 0o600).is_ok());
        let error = validate_unix_private_metadata(1001, 1000, 0o600).unwrap_err();
        assert!(error.to_string().contains("expected current effective UID"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_rejects_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let (temp, core) = fixture();
        core.setup_product_with_artifacts(
            SetupRequest::new("https://gateway.example.test", "secret").unwrap(),
            artifacts(),
        )
        .unwrap();
        let config = core.load_config().unwrap();
        let claude = config.product(Product::Claude).unwrap();
        let credential = FileCredentialStore::new(core.paths().credentials_dir())
            .credential_path(claude.credential_ref());
        let outside = temp.path().join("outside-secret");
        fs::write(&outside, b"outside").unwrap();
        fs::remove_file(&credential).unwrap();
        symlink(&outside, &credential).unwrap();

        let audit = core.audit_private_permissions();
        assert!(audit.issues.iter().any(|issue| {
            issue.code == PrivatePermissionIssueCode::SymbolicLink && issue.path == credential
        }));
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
    }
}
