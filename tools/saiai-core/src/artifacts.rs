use std::fmt;

use rcgen::{CertificateParams, IsCa, KeyPair};
use serde_json::Value;
use toml_edit::DocumentMut;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroize;

use crate::{Error, Product, Result};

pub const CLAUDE_SETTINGS_FILENAME: &str = "settings.json";
pub const CLAUDE_STATE_FILENAME: &str = ".claude.json";
pub const CLAUDE_CA_CERT_FILENAME: &str = "saiai-ca.crt";
pub const CLAUDE_CA_KEY_FILENAME: &str = "saiai-ca.key";
pub const CODEX_CONFIG_FILENAME: &str = "config.toml";

/// The complete, fixed-shape Claude client state managed by SAIAI.
///
/// The private key is deliberately private and its `Debug` representation is
/// redacted. This type chooses all destination filenames; callers cannot use it
/// as a general-purpose filesystem writer.
pub struct ClaudeSetupArtifacts {
    settings_json: Vec<u8>,
    state_json: Vec<u8>,
    ca_certificate_pem: String,
    ca_private_key_pem: String,
}

impl ClaudeSetupArtifacts {
    pub fn new(
        settings_json: impl Into<Vec<u8>>,
        state_json: impl Into<Vec<u8>>,
        ca_certificate_pem: impl Into<String>,
        ca_private_key_pem: impl Into<String>,
    ) -> Result<Self> {
        let artifacts = Self {
            settings_json: settings_json.into(),
            state_json: state_json.into(),
            ca_certificate_pem: ca_certificate_pem.into(),
            ca_private_key_pem: ca_private_key_pem.into(),
        };
        artifacts.validate()?;
        Ok(artifacts)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_json_object(CLAUDE_SETTINGS_FILENAME, &self.settings_json)?;
        validate_json_object(CLAUDE_STATE_FILENAME, &self.state_json)?;
        validate_ca_pair(&self.ca_certificate_pem, &self.ca_private_key_pem)
    }

    pub(crate) fn files(&self) -> [(&'static str, &[u8]); 4] {
        [
            (CLAUDE_SETTINGS_FILENAME, &self.settings_json),
            (CLAUDE_STATE_FILENAME, &self.state_json),
            (CLAUDE_CA_CERT_FILENAME, self.ca_certificate_pem.as_bytes()),
            (CLAUDE_CA_KEY_FILENAME, self.ca_private_key_pem.as_bytes()),
        ]
    }
}

impl fmt::Debug for ClaudeSetupArtifacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeSetupArtifacts")
            .field("settings_json_bytes", &self.settings_json.len())
            .field("state_json_bytes", &self.state_json.len())
            .field("ca_certificate_pem_bytes", &self.ca_certificate_pem.len())
            .field("ca_private_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ClaudeSetupArtifacts {
    fn drop(&mut self) {
        self.ca_private_key_pem.zeroize();
    }
}

/// The complete, fixed-shape Codex client state managed by SAIAI.
pub struct CodexSetupArtifacts {
    config_toml: String,
}

impl CodexSetupArtifacts {
    pub fn new(config_toml: impl Into<String>) -> Result<Self> {
        let artifacts = Self {
            config_toml: config_toml.into(),
        };
        artifacts.validate()?;
        Ok(artifacts)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.config_toml.trim().is_empty() {
            return Err(invalid_artifact(CODEX_CONFIG_FILENAME, "document is empty"));
        }
        self.config_toml
            .parse::<DocumentMut>()
            .map(|_| ())
            .map_err(|error| invalid_artifact(CODEX_CONFIG_FILENAME, error.to_string()))
    }

    pub(crate) fn files(&self) -> [(&'static str, &[u8]); 1] {
        [(CODEX_CONFIG_FILENAME, self.config_toml.as_bytes())]
    }
}

impl fmt::Debug for CodexSetupArtifacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexSetupArtifacts")
            .field("config_toml_bytes", &self.config_toml.len())
            .finish()
    }
}

/// Typed state accepted by an independent product setup transaction.
#[derive(Debug)]
pub enum ProductSetupArtifacts {
    Claude(ClaudeSetupArtifacts),
    Codex(CodexSetupArtifacts),
}

impl ProductSetupArtifacts {
    pub const fn product(&self) -> Product {
        match self {
            Self::Claude(_) => Product::Claude,
            Self::Codex(_) => Product::Codex,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Claude(artifacts) => artifacts.validate(),
            Self::Codex(artifacts) => artifacts.validate(),
        }
    }
}

fn validate_json_object(name: &'static str, contents: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(contents)
        .map_err(|error| invalid_artifact(name, error.to_string()))?;
    if !value.is_object() {
        return Err(invalid_artifact(name, "top-level value must be an object"));
    }
    Ok(())
}

fn validate_ca_pair(certificate_pem: &str, private_key_pem: &str) -> Result<()> {
    let ca_params = CertificateParams::from_ca_cert_pem(certificate_pem)
        .map_err(|error| invalid_artifact(CLAUDE_CA_CERT_FILENAME, error.to_string()))?;
    if !matches!(ca_params.is_ca, IsCa::Ca(_)) {
        return Err(invalid_artifact(
            CLAUDE_CA_CERT_FILENAME,
            "certificate is not a CA",
        ));
    }

    let private_key = KeyPair::from_pem(private_key_pem)
        .map_err(|error| invalid_artifact(CLAUDE_CA_KEY_FILENAME, error.to_string()))?;
    let (remainder, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|error| invalid_artifact(CLAUDE_CA_CERT_FILENAME, error.to_string()))?;
    if !remainder.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        return Err(invalid_artifact(
            CLAUDE_CA_CERT_FILENAME,
            "expected exactly one CERTIFICATE PEM block",
        ));
    }
    let parsed = pem
        .parse_x509()
        .map_err(|error| invalid_artifact(CLAUDE_CA_CERT_FILENAME, error.to_string()))?;
    if parsed.subject() != parsed.issuer() {
        return Err(invalid_artifact(
            CLAUDE_CA_CERT_FILENAME,
            "installation CA must be self-issued",
        ));
    }
    if !parsed.validity().is_valid() {
        return Err(invalid_artifact(
            CLAUDE_CA_CERT_FILENAME,
            "certificate is not currently valid",
        ));
    }
    parsed
        .verify_signature(None)
        .map_err(|error| invalid_artifact(CLAUDE_CA_CERT_FILENAME, error.to_string()))?;
    if parsed.public_key().raw != private_key.public_key_der() {
        return Err(invalid_artifact(
            CLAUDE_CA_KEY_FILENAME,
            "private key does not match the CA certificate",
        ));
    }

    // Reconstruct an issuer with the exact verified public/private key and
    // prove that it can issue a leaf. No generated leaf bytes are persisted.
    let issuer = ca_params
        .self_signed(&private_key)
        .map_err(|error| invalid_artifact(CLAUDE_CA_KEY_FILENAME, error.to_string()))?;
    let leaf_key = KeyPair::generate()
        .map_err(|error| invalid_artifact(CLAUDE_CA_KEY_FILENAME, error.to_string()))?;
    let leaf_params = CertificateParams::new(vec!["saiai-validation.invalid".to_owned()])
        .map_err(|error| invalid_artifact(CLAUDE_CA_CERT_FILENAME, error.to_string()))?;
    leaf_params
        .signed_by(&leaf_key, &issuer, &private_key)
        .map(|_| ())
        .map_err(|error| invalid_artifact(CLAUDE_CA_KEY_FILENAME, error.to_string()))
}

fn invalid_artifact(artifact: &'static str, reason: impl Into<String>) -> Error {
    Error::InvalidArtifact {
        artifact,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, DistinguishedName, DnType};

    fn ca_pair() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "SAIAI artifact test CA");
        params.distinguished_name = name;
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn artifact_shapes_are_validated() {
        let (cert, key) = ca_pair();
        assert!(ClaudeSetupArtifacts::new(b"{}".to_vec(), b"{}".to_vec(), cert, key).is_ok());
        assert!(ClaudeSetupArtifacts::new(b"[]".to_vec(), b"{}".to_vec(), "x", "y").is_err());
        assert!(CodexSetupArtifacts::new("model_provider = 'saiai'\n").is_ok());
        assert!(CodexSetupArtifacts::new("not = [valid").is_err());
    }

    #[test]
    fn ca_certificate_and_key_must_match() {
        let (cert, _) = ca_pair();
        let (_, other_key) = ca_pair();
        let error =
            ClaudeSetupArtifacts::new(b"{}".to_vec(), b"{}".to_vec(), cert, other_key).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn private_key_is_redacted_from_debug() {
        let (cert, key) = ca_pair();
        let artifacts =
            ClaudeSetupArtifacts::new(b"{}".to_vec(), b"{}".to_vec(), cert, key.clone()).unwrap();
        let debug = format!("{artifacts:?}");
        assert!(!debug.contains(&key));
        assert!(debug.contains("REDACTED"));
    }
}
