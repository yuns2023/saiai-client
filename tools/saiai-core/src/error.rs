use std::io;
use std::path::PathBuf;

use crate::Product;

/// Errors returned by the filesystem-backed SAIAI core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not discover {0}")]
    PathDiscovery(&'static str),

    #[error("invalid application path for {field}: {path}: {reason}")]
    InvalidAppPath {
        field: &'static str,
        path: PathBuf,
        reason: &'static str,
    },

    #[error("invalid gateway URL: {0}")]
    InvalidGatewayUrl(String),

    #[error("invalid credential reference: {0}")]
    InvalidCredentialRef(String),

    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    #[error("invalid SAIAI configuration: {0}")]
    InvalidConfig(String),

    #[error("{0} is not configured; run `saiai setup {0}` first")]
    ProductNotConfigured(Product),

    #[error(
        "cannot provision {product}: its gateway URL differs from the shared gateway used by {other}; revoke the existing product first to change gateways"
    )]
    SharedGatewayMismatch { product: Product, other: Product },

    #[error("{0} is currently running; stop it before changing or revoking its V2 state")]
    ProductBusy(Product),

    #[error("SAIAI V2 client state is currently in use; stop running clients before revoking it")]
    InstallationBusy,

    #[error("invalid setup artifact {artifact}: {reason}")]
    InvalidArtifact {
        artifact: &'static str,
        reason: String,
    },

    #[error("could not create the SAIAI bootstrap HTTP client")]
    BootstrapClient,

    #[error("could not reach the SAIAI bootstrap endpoint")]
    BootstrapTransport,

    #[error("SAIAI bootstrap was rejected ({category}, HTTP {status})")]
    BootstrapHttp { status: u16, category: &'static str },

    #[error("the SAIAI bootstrap response exceeds the 1 MiB limit")]
    BootstrapResponseTooLarge,

    #[error("the SAIAI bootstrap response is invalid: {0}")]
    InvalidBootstrapResponse(&'static str),

    #[error("the SAIAI gateway is incompatible with V2 setup: {0}")]
    IncompatibleGateway(&'static str),

    #[error("could not {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl Error {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Io { source, .. } if source.kind() == io::ErrorKind::NotFound
        )
    }
}

/// Result type used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;
