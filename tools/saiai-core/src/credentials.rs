use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::fsutil::{
    atomic_write_private, ensure_private_dir, is_portable_reference_component,
    reject_symlink_if_present,
};
use crate::{Error, Result};

const MAX_SECRET_BYTES: usize = 16 * 1024;

/// Opaque, path-safe reference to a credential stored outside `config.json`.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid_length = !value.is_empty() && value.len() <= 64;
        let mut chars = value.chars();
        let valid_start = chars
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric());
        let valid_rest = chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        });

        if !valid_length || !valid_start || !valid_rest || !is_portable_reference_component(&value)
        {
            return Err(Error::InvalidCredentialRef(
                "use 1-64 portable ASCII letters, digits, dots, dashes, or underscores, starting with a letter or digit"
                    .into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CredentialRef")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for CredentialRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// API credential wrapper whose `Debug` implementation never exposes its value.
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let mut value = value.into();
        if value.is_empty() {
            return Err(Error::InvalidCredential("credential is empty".into()));
        }
        if value.len() > MAX_SECRET_BYTES {
            value.zeroize();
            return Err(Error::InvalidCredential(format!(
                "credential exceeds the {MAX_SECRET_BYTES}-byte limit"
            )));
        }
        if value.trim() != value {
            value.zeroize();
            return Err(Error::InvalidCredential(
                "leading or trailing whitespace is not allowed".into(),
            ));
        }
        if value.chars().any(char::is_control) {
            value.zeroize();
            return Err(Error::InvalidCredential(
                "control characters are not allowed".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Expose the secret only at the point where authentication requires it.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Abstract credential storage so a system keyring can replace files later.
pub trait CredentialStore {
    fn save(&self, credential_ref: &CredentialRef, secret: &SecretString) -> Result<()>;
    fn load(&self, credential_ref: &CredentialRef) -> Result<SecretString>;
    fn delete(&self, credential_ref: &CredentialRef) -> Result<()>;
}

/// User-private, filesystem-backed credential store.
#[derive(Clone, Debug)]
pub struct FileCredentialStore {
    root: PathBuf,
}

impl FileCredentialStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn credential_path(&self, credential_ref: &CredentialRef) -> PathBuf {
        self.root.join(format!("{}.key", credential_ref.as_str()))
    }
}

impl CredentialStore for FileCredentialStore {
    fn save(&self, credential_ref: &CredentialRef, secret: &SecretString) -> Result<()> {
        ensure_private_dir(&self.root)?;
        atomic_write_private(
            &self.credential_path(credential_ref),
            secret.expose_secret().as_bytes(),
        )
    }

    fn load(&self, credential_ref: &CredentialRef) -> Result<SecretString> {
        let path = self.credential_path(credential_ref);
        reject_symlink_if_present(&self.root)?;
        reject_symlink_if_present(&path)?;
        let bytes = fs::read(&path).map_err(|error| Error::io("read credential", &path, error))?;
        let value = String::from_utf8(bytes).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Error::InvalidCredential("credential file is not UTF-8".into())
        })?;
        SecretString::new(value)
    }

    fn delete(&self, credential_ref: &CredentialRef) -> Result<()> {
        let path = self.credential_path(credential_ref);
        reject_symlink_if_present(&self.root)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::io("delete credential", path, error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_references_cannot_escape_the_store() {
        for invalid in [
            "",
            ".",
            "..",
            "../secret",
            "/absolute",
            "has space",
            "credential.",
            "CON",
            "aux.txt",
            "LPT9.key",
        ] {
            assert!(CredentialRef::new(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn secrets_are_redacted_from_debug_output() {
        let secret = SecretString::new("sk-secret-value").unwrap();
        let output = format!("{secret:?}");
        assert!(!output.contains("sk-secret-value"));
        assert!(output.contains("REDACTED"));
    }

    #[test]
    fn credentials_have_a_bounded_size() {
        assert!(SecretString::new("x".repeat(MAX_SECRET_BYTES)).is_ok());
        assert!(SecretString::new("x".repeat(MAX_SECRET_BYTES + 1)).is_err());
    }
}
