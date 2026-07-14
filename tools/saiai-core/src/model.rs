use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{ConfigV2, GatewayUrl, GenerationLease, SecretString};

/// A client product whose V2-owned local state can be prepared or revoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    Claude,
    Codex,
}

impl Product {
    pub const ALL: [Self; 2] = [Self::Claude, Self::Codex];

    pub const fn directory_name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

impl std::fmt::Display for Product {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.directory_name())
    }
}

/// One product's base URL, home, and credential read under the setup
/// transaction lock from the same committed configuration generation.
///
/// Callers should use this snapshot instead of combining separate config and
/// credential reads, which could straddle a concurrent setup transaction.
pub struct CommittedProduct {
    product: Product,
    base_url: GatewayUrl,
    home: PathBuf,
    credential: SecretString,
    lease: GenerationLease,
}

impl CommittedProduct {
    pub(crate) fn new(
        product: Product,
        base_url: GatewayUrl,
        home: PathBuf,
        credential: SecretString,
        lease: GenerationLease,
    ) -> Self {
        Self {
            product,
            base_url,
            home,
            credential,
            lease,
        }
    }

    pub const fn product(&self) -> Product {
        self.product
    }

    pub fn base_url(&self) -> &GatewayUrl {
        &self.base_url
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn credential(&self) -> &SecretString {
        &self.credential
    }

    /// Split the launch snapshot while preserving its lifetime lease.
    ///
    /// The returned lease must remain alive until the launched child process
    /// has fully exited.
    pub fn into_parts(self) -> (Product, GatewayUrl, PathBuf, SecretString, GenerationLease) {
        (
            self.product,
            self.base_url,
            self.home,
            self.credential,
            self.lease,
        )
    }
}

impl std::fmt::Debug for CommittedProduct {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommittedProduct")
            .field("product", &self.product)
            .field("base_url", &self.base_url)
            .field("home", &self.home)
            .field("credential", &"[REDACTED]")
            .field("lease", &"[HELD]")
            .finish()
    }
}

/// High-level initialization state safe to expose to CLI and Tauri callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    Uninitialized,
    Ready,
    Broken,
}

/// Setup state for one independently optional product.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductSetupState {
    Unconfigured,
    Ready,
    Broken,
}

/// Machine-readable setup problem categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupIssueCode {
    ConfigMissing,
    ConfigInvalid,
    CredentialMissing,
    CredentialInvalid,
    GenerationMissing,
    UnsafeManagedPath,
    ProductInvalid,
}

/// A non-secret diagnostic suitable for the CLI or UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SetupIssue {
    pub code: SetupIssueCode,
    pub message: String,
}

/// Setup state for one isolated client home.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProductSetupStatus {
    pub product: Product,
    pub state: ProductSetupState,
    pub home: Option<PathBuf>,
    pub credential_present: bool,
    pub issues: Vec<SetupIssue>,
}

/// Complete setup status. It never contains credential contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SetupStatus {
    pub state: SetupState,
    pub config: Option<ConfigV2>,
    pub products: Vec<ProductSetupStatus>,
    pub issues: Vec<SetupIssue>,
}

/// Broad categories for a private-permission audit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivatePermissionIssueCode {
    InspectFailed,
    SymbolicLink,
    UnexpectedObjectType,
    InsecurePermissions,
}

/// A non-secret private-permission finding for one V2-owned path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivatePermissionIssue {
    pub code: PrivatePermissionIssueCode,
    pub path: PathBuf,
    pub message: String,
}

/// Result of auditing the explicit V2-owned paths for user-private access.
///
/// The report contains paths and diagnostic text only. It never reads or
/// returns credential contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivatePermissionsAudit {
    pub supported: bool,
    pub checked_paths: usize,
    pub issues: Vec<PrivatePermissionIssue>,
}

impl PrivatePermissionsAudit {
    pub fn is_secure(&self) -> bool {
        self.supported && self.issues.is_empty()
    }
}

/// Scope of a revoke operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeTarget {
    Product(Product),
    All,
}

/// Result of a revoke operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevokeReport {
    pub target: RevokeTarget,
    pub removed_paths: Vec<PathBuf>,
    pub status: SetupStatus,
}
