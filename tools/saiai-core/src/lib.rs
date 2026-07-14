//! Filesystem-backed foundations shared by the greenfield SAIAI CLI and UI.
//!
//! This crate deliberately has no knowledge of the legacy SAIAI, Claude, or
//! Codex configuration directories. Callers either use platform-standard
//! [`AppPaths::discover`] paths or inject explicit application directories for
//! tests.

mod artifacts;
mod client_program;
mod config;
mod credentials;
mod error;
mod fsutil;
mod lease;
mod model;
mod paths;
mod permissions;
mod provision;
mod setup;
#[cfg(windows)]
mod windows_acl;

/// Claude Code environment variable controlling its stream-idle threshold.
pub const CLAUDE_STREAM_IDLE_TIMEOUT_ENV: &str = "CLAUDE_STREAM_IDLE_TIMEOUT_MS";
/// Ten-minute value used for the managed Claude Code stream-idle threshold.
pub const CLAUDE_STREAM_IDLE_TIMEOUT_VALUE: &str = "600000";

pub use artifacts::{
    CLAUDE_CA_CERT_FILENAME, CLAUDE_CA_KEY_FILENAME, CLAUDE_SETTINGS_FILENAME,
    CLAUDE_STATE_FILENAME, CODEX_CONFIG_FILENAME, ClaudeSetupArtifacts, CodexSetupArtifacts,
    ProductSetupArtifacts,
};
pub use client_program::{
    ClientProgramResolveError, ClientProgramSource, ResolvedClientProgram,
    UnsupportedNpmShimReason, resolve_client_program,
};
pub use config::{
    CONFIG_SCHEMA_VERSION, ConfigV2, GatewayUrl, GenerationRef, MAX_GATEWAY_URL_BYTES,
    ProductConfig, ProductEntries,
};
pub use credentials::{CredentialRef, CredentialStore, FileCredentialStore, SecretString};
pub use error::{Error, Result};
pub use lease::GenerationLease;
pub use model::{
    CommittedProduct, PrivatePermissionIssue, PrivatePermissionIssueCode, PrivatePermissionsAudit,
    Product, ProductSetupState, ProductSetupStatus, RevokeReport, RevokeTarget, SetupIssue,
    SetupIssueCode, SetupState, SetupStatus,
};
pub use paths::AppPaths;
pub use provision::{
    BOOTSTRAP_SCHEMA_VERSION, BootstrapCapabilities, BootstrapData, ProvisionReport,
    ProvisionRequest,
};
pub use setup::{SaiaiCore, SetupRequest};
