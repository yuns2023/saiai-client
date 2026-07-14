use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::OsString;
#[cfg(windows)]
use std::path::Prefix;
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
use crate::fsutil::is_portable_reference_component;
use crate::{Error, GenerationRef, Product, Result};

/// All paths owned by the greenfield SAIAI runtime.
///
/// These are application directories, not their platform-wide parent roots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppPaths {
    config_dir: PathBuf,
    data_dir: PathBuf,
    state_dir: PathBuf,
}

impl AppPaths {
    /// Discover platform-standard application directories.
    ///
    /// This intentionally ignores `SAIAI_HOME`, `CLAUDE_CONFIG_DIR`,
    /// `CODEX_HOME`, and every legacy dot-directory.
    pub fn discover() -> Result<Self> {
        Self::discover_with(|name| env::var_os(name))
    }

    /// Construct explicit application directories, primarily for embedding and
    /// isolated tests. Paths are normalized lexically without consulting the
    /// filesystem. Each path must be an absolute, non-root application
    /// directory, and no directory may contain another one. Callers supplying
    /// explicit Windows paths must use their ordinary lexical spelling rather
    /// than 8.3 or reparse-point aliases; discovery produces ordinary paths and
    /// this constructor deliberately does not inspect filesystem ancestors.
    pub fn from_app_dirs(
        config_dir: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let paths = Self {
            config_dir: normalize_app_dir("config_dir", config_dir.into())?,
            data_dir: normalize_app_dir("data_dir", data_dir.into())?,
            state_dir: normalize_app_dir("state_dir", state_dir.into())?,
        };
        let app_dirs = [
            ("config_dir", &paths.config_dir),
            ("data_dir", &paths.data_dir),
            ("state_dir", &paths.state_dir),
        ];
        for index in 0..app_dirs.len() {
            let (field, path) = app_dirs[index];
            for &(_, other) in &app_dirs[index + 1..] {
                if app_dirs_overlap(path, other) {
                    return Err(Error::InvalidAppPath {
                        field,
                        path: path.to_path_buf(),
                        reason: "config, data, and state paths must not be equal or nested",
                    });
                }
            }
        }
        Ok(paths)
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.json")
    }

    pub fn credentials_dir(&self) -> PathBuf {
        self.data_dir.join("credentials")
    }

    pub fn generations_dir(&self) -> PathBuf {
        self.data_dir.join("generations")
    }

    pub fn generation_dir(&self, generation: &GenerationRef) -> PathBuf {
        self.generations_dir().join(generation.as_str())
    }

    pub fn generation_clients_dir(&self, generation: &GenerationRef) -> PathBuf {
        self.generation_dir(generation).join("clients")
    }

    pub fn generation_client_home(&self, generation: &GenerationRef, product: Product) -> PathBuf {
        self.generation_clients_dir(generation)
            .join(product.directory_name())
    }

    pub fn generation_product_marker(
        &self,
        generation: &GenerationRef,
        product: Product,
    ) -> PathBuf {
        self.generation_client_home(generation, product)
            .join(".saiai-managed-v2")
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.state_dir.join("runtime")
    }

    pub fn generation_runtime_dir(&self, generation: &GenerationRef) -> PathBuf {
        self.runtime_dir().join(generation.as_str())
    }

    pub fn generation_product_runtime_dir(
        &self,
        generation: &GenerationRef,
        product: Product,
    ) -> PathBuf {
        self.generation_runtime_dir(generation)
            .join(product.directory_name())
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.state_dir.join("logs")
    }

    pub fn leases_dir(&self) -> PathBuf {
        self.state_dir.join("leases")
    }

    pub fn generation_lease_file(&self, generation: &GenerationRef) -> PathBuf {
        self.leases_dir()
            .join(format!("{}.lock", generation.as_str()))
    }

    pub fn generation_logs_dir(&self, generation: &GenerationRef) -> PathBuf {
        self.logs_dir().join(generation.as_str())
    }

    pub fn generation_product_logs_dir(
        &self,
        generation: &GenerationRef,
        product: Product,
    ) -> PathBuf {
        self.generation_logs_dir(generation)
            .join(product.directory_name())
    }

    pub fn generation_staging_dir(&self) -> PathBuf {
        self.generations_dir().join(".staging")
    }

    pub fn transaction_lock_file(&self) -> PathBuf {
        self.state_dir.join("transaction.lock")
    }

    fn discover_with(get: impl Fn(&str) -> Option<OsString>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let home = absolute_env_path(&get, "HOME").ok_or(Error::PathDiscovery(
                "HOME for SAIAI application directories",
            ))?;
            let config_root =
                absolute_env_path(&get, "XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
            let data_root = absolute_env_path(&get, "XDG_DATA_HOME")
                .unwrap_or_else(|| home.join(".local/share"));
            let state_root = absolute_env_path(&get, "XDG_STATE_HOME")
                .unwrap_or_else(|| home.join(".local/state"));
            Self::from_app_dirs(
                config_root.join("saiai"),
                data_root.join("saiai"),
                state_root.join("saiai"),
            )
        }

        #[cfg(target_os = "macos")]
        {
            let home = absolute_env_path(&get, "HOME").ok_or(Error::PathDiscovery(
                "HOME for SAIAI application directories",
            ))?;
            let root = home.join("Library/Application Support/SAIAI");
            Self::from_app_dirs(root.join("config"), root.join("data"), root.join("state"))
        }

        #[cfg(target_os = "windows")]
        {
            let root = absolute_env_path(&get, "LOCALAPPDATA")
                .ok_or(Error::PathDiscovery(
                    "LOCALAPPDATA for SAIAI application directories",
                ))?
                .join("SAIAI");
            Self::from_app_dirs(root.join("config"), root.join("data"), root.join("state"))
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let home = absolute_env_path(&get, "HOME").ok_or(Error::PathDiscovery(
                "HOME for SAIAI application directories",
            ))?;
            Self::from_app_dirs(
                home.join(".config/saiai"),
                home.join(".local/share/saiai"),
                home.join(".local/state/saiai"),
            )
        }
    }
}

fn normalize_app_dir(field: &'static str, path: PathBuf) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Error::InvalidAppPath {
            field,
            path,
            reason: "path must be absolute",
        });
    }

    let original = path.clone();
    let mut normalized = PathBuf::new();
    let mut has_application_component = false;
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(Error::InvalidAppPath {
                    field,
                    path: original,
                    reason: "path must not contain parent-directory components",
                });
            }
            Component::CurDir => {}
            Component::Normal(value) => {
                #[cfg(windows)]
                {
                    let Some(value) = value.to_str() else {
                        return Err(Error::InvalidAppPath {
                            field,
                            path: original,
                            reason: "Windows path components must be valid Unicode",
                        });
                    };
                    if !is_portable_reference_component(value) {
                        return Err(Error::InvalidAppPath {
                            field,
                            path: original,
                            reason: "path contains a Windows-reserved or aliased component",
                        });
                    }
                    if value.chars().any(|character| {
                        character.is_control()
                            || matches!(
                                character,
                                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                            )
                    }) {
                        return Err(Error::InvalidAppPath {
                            field,
                            path: original,
                            reason: "path contains a character forbidden in Windows file names",
                        });
                    }
                }
                has_application_component = true;
                normalized.push(value);
            }
            Component::Prefix(_prefix) => {
                #[cfg(windows)]
                if matches!(
                    _prefix.kind(),
                    Prefix::Verbatim(_)
                        | Prefix::VerbatimUNC(_, _)
                        | Prefix::VerbatimDisk(_)
                        | Prefix::DeviceNS(_)
                ) {
                    return Err(Error::InvalidAppPath {
                        field,
                        path: original,
                        reason: "verbatim and device-namespace paths are not supported",
                    });
                }
                normalized.push(component.as_os_str());
            }
            Component::RootDir => {
                normalized.push(component.as_os_str());
            }
        }
    }
    if !has_application_component {
        return Err(Error::InvalidAppPath {
            field,
            path: original,
            reason: "path must not be a filesystem root",
        });
    }
    Ok(normalized)
}

#[cfg(windows)]
fn app_dirs_overlap(left: &Path, right: &Path) -> bool {
    fn key(path: &Path) -> Vec<String> {
        path.components()
            .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    }

    let left = key(left);
    let right = key(right);
    left.starts_with(&right) || right.starts_with(&left)
}

#[cfg(not(windows))]
fn app_dirs_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppPathsWire {
    config_dir: PathBuf,
    data_dir: PathBuf,
    state_dir: PathBuf,
}

impl<'de> Deserialize<'de> for AppPaths {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AppPathsWire::deserialize(deserializer)?;
        Self::from_app_dirs(wire.config_dir, wire.data_dir, wire.state_dir)
            .map_err(serde::de::Error::custom)
    }
}

fn absolute_env_path(get: &impl Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    get(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::collections::HashMap;

    #[test]
    fn explicit_paths_must_be_absolute_non_root_and_disjoint() {
        let root = std::env::temp_dir().join("saiai-app-path-validation");
        assert!(
            AppPaths::from_app_dirs("relative", root.join("data"), root.join("state")).is_err()
        );
        assert!(
            AppPaths::from_app_dirs(root.join("same"), root.join("same"), root.join("state"))
                .is_err()
        );
        assert!(
            AppPaths::from_app_dirs(
                root.join("config"),
                root.join("config/children/data"),
                root.join("state"),
            )
            .is_err()
        );
        assert!(
            AppPaths::from_app_dirs(
                root.join("config/children"),
                root.join("config"),
                root.join("state"),
            )
            .is_err()
        );
        assert!(
            AppPaths::from_app_dirs(
                root.join("config/../data"),
                root.join("data"),
                root.join("state"),
            )
            .is_err()
        );
    }

    #[test]
    fn deserialization_revalidates_paths_instead_of_bypassing_the_constructor() {
        let root = std::env::temp_dir().join("saiai-app-path-serde");
        let paths =
            AppPaths::from_app_dirs(root.join("config"), root.join("data"), root.join("state"))
                .unwrap();
        let encoded = serde_json::to_vec(&paths).unwrap();
        assert_eq!(serde_json::from_slice::<AppPaths>(&encoded).unwrap(), paths);

        let overlapping = serde_json::json!({
            "config_dir": root.join("same"),
            "data_dir": root.join("same/child"),
            "state_dir": root.join("state"),
        });
        assert!(serde_json::from_value::<AppPaths>(overlapping).is_err());

        let parent_alias = serde_json::json!({
            "config_dir": root.join("config/../data"),
            "data_dir": root.join("data"),
            "state_dir": root.join("state"),
        });
        assert!(serde_json::from_value::<AppPaths>(parent_alias).is_err());

        #[cfg(unix)]
        {
            let filesystem_root = serde_json::json!({
                "config_dir": "/",
                "data_dir": root.join("data"),
                "state_dir": root.join("state"),
            });
            assert!(serde_json::from_value::<AppPaths>(filesystem_root).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_filesystem_root_is_not_an_application_directory() {
        assert!(AppPaths::from_app_dirs("/", "/tmp/saiai-data", "/tmp/saiai-state").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_paths_keep_valid_non_utf8_and_windows_reserved_components() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::env::temp_dir().join("saiai-unix-app-paths");
        let non_utf8 = OsString::from_vec(vec![b'c', b'f', b'g', 0xff]);
        let paths =
            AppPaths::from_app_dirs(root.join(non_utf8), root.join("CON"), root.join("state. "))
                .unwrap();
        assert!(paths.data_dir().ends_with("CON"));
        assert!(paths.state_dir().ends_with("state. "));
    }

    #[cfg(windows)]
    #[test]
    fn windows_roots_case_and_separator_aliases_are_rejected() {
        assert!(
            AppPaths::from_app_dirs(
                r"C:\",
                r"C:\Users\tester\SAIAI\data",
                r"C:\Users\tester\SAIAI\state",
            )
            .is_err()
        );
        let serialized_root = serde_json::json!({
            "config_dir": r"C:\",
            "data_dir": r"C:\Users\tester\SAIAI\data",
            "state_dir": r"C:\Users\tester\SAIAI\state",
        });
        assert!(serde_json::from_value::<AppPaths>(serialized_root).is_err());
        assert!(
            AppPaths::from_app_dirs(
                r"C:\Users\tester\SAIAI\config",
                r"c:/users/TESTER/saiai/CONFIG/child",
                r"C:\Users\tester\SAIAI\state",
            )
            .is_err()
        );
        for unsafe_component in ["config.", "config ", "CON", "nul.txt", "config:stream"] {
            assert!(
                AppPaths::from_app_dirs(
                    Path::new(r"C:\Users\tester\SAIAI").join(unsafe_component),
                    r"C:\Users\tester\SAIAI\data",
                    r"C:\Users\tester\SAIAI\state",
                )
                .is_err(),
                "unsafe Windows component should be rejected: {unsafe_component:?}"
            );
        }
        for unsupported_prefix in [
            r"\\?\C:\Users\tester\SAIAI\config",
            r"\\?\UNC\server\share\SAIAI\config",
            r"\\.\PIPE\SAIAI\config",
        ] {
            assert!(
                AppPaths::from_app_dirs(
                    unsupported_prefix,
                    r"C:\Users\tester\SAIAI\data",
                    r"C:\Users\tester\SAIAI\state",
                )
                .is_err(),
                "unsupported Windows prefix should be rejected: {unsupported_prefix:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn discovery_ignores_legacy_and_product_environment_overrides() {
        let values = HashMap::from([
            ("HOME", OsString::from("/home/tester")),
            ("XDG_CONFIG_HOME", OsString::from("/xdg/config")),
            ("XDG_DATA_HOME", OsString::from("/xdg/data")),
            ("XDG_STATE_HOME", OsString::from("/xdg/state")),
            ("SAIAI_HOME", OsString::from("/legacy/saiai")),
            ("CLAUDE_CONFIG_DIR", OsString::from("/legacy/claude")),
            ("CODEX_HOME", OsString::from("/legacy/codex")),
        ]);
        let paths = AppPaths::discover_with(|name| values.get(name).cloned()).unwrap();
        assert_eq!(paths.config_dir(), Path::new("/xdg/config/saiai"));
        assert_eq!(paths.data_dir(), Path::new("/xdg/data/saiai"));
        assert_eq!(paths.state_dir(), Path::new("/xdg/state/saiai"));
        assert!(!paths.config_dir().starts_with("/legacy"));
        assert!(!paths.data_dir().starts_with("/legacy"));
        assert!(!paths.state_dir().starts_with("/legacy"));
    }
}
