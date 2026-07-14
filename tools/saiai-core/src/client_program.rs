use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::Product;

/// How a product client will be started after resolving it from `PATH`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientProgramSource {
    /// A native executable found directly in a `PATH` directory.
    NativeExecutable,
    /// A standard global npm shim whose fixed package entry is run by Node.
    NpmGlobalShim,
    /// A standard `node_modules/.bin` shim whose fixed package entry is run by Node.
    NpmLocalShim,
}

/// Why an npm command marker could not be converted into a shell-free launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedNpmShimReason {
    /// The product's fixed, known JavaScript package entry does not exist.
    PackageEntryMissing,
    /// No native `node.exe` is available beside the shim or on `PATH`.
    NodeExecutableMissing,
}

impl fmt::Display for UnsupportedNpmShimReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PackageEntryMissing => "the standard npm package entry is missing",
            Self::NodeExecutableMissing => "a native node.exe is missing",
        })
    }
}

/// A machine-readable failure to resolve a supported product client.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClientProgramResolveError {
    /// No supported client candidate was present in an absolute `PATH` directory.
    #[error("{product} was not found in an absolute PATH directory")]
    NotFound { product: Product },

    /// A `.cmd` marker was found, but its standard npm installation was incomplete.
    #[error("found an unsupported {product} npm shim at {shim:?}: {reason}")]
    UnsupportedNpmShim {
        product: Product,
        shim: PathBuf,
        reason: UnsupportedNpmShimReason,
    },
}

impl ClientProgramResolveError {
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::UnsupportedNpmShim { .. })
    }
}

/// A shell-free executable plus fixed arguments used to launch one client.
///
/// On Windows, an npm installation is represented as an absolute `node.exe`
/// followed by one fixed JavaScript entry path. Callers must append user
/// arguments as individual arguments after [`Self::prefix_args`]; they must
/// never join arguments into a command line or pass them through `cmd.exe`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedClientProgram {
    executable: PathBuf,
    prefix_args: Vec<OsString>,
    source: ClientProgramSource,
}

impl ResolvedClientProgram {
    fn native(executable: PathBuf) -> Self {
        Self {
            executable,
            prefix_args: Vec::new(),
            source: ClientProgramSource::NativeExecutable,
        }
    }

    #[cfg(windows)]
    fn npm(node: PathBuf, package_entry: PathBuf, source: ClientProgramSource) -> Self {
        Self {
            executable: node,
            prefix_args: vec![package_entry.into_os_string()],
            source,
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn prefix_args(&self) -> &[OsString] {
        &self.prefix_args
    }

    pub const fn source(&self) -> ClientProgramSource {
        self.source
    }

    pub fn into_parts(self) -> (PathBuf, Vec<OsString>, ClientProgramSource) {
        (self.executable, self.prefix_args, self.source)
    }
}

/// Resolve a Claude or Codex client without invoking a shell.
///
/// Only absolute directories explicitly listed in `PATH` are searched. The
/// current directory, platform fallback directories, `PATHEXT`, and registry
/// application aliases are never consulted implicitly.
pub fn resolve_client_program(
    product: Product,
) -> Result<ResolvedClientProgram, ClientProgramResolveError> {
    let path = env::var_os("PATH");
    resolve_client_program_from_path(product, path.as_deref())
}

fn resolve_client_program_from_path(
    product: Product,
    path: Option<&OsStr>,
) -> Result<ResolvedClientProgram, ClientProgramResolveError> {
    let directories = absolute_path_directories(path);

    #[cfg(windows)]
    {
        resolve_windows(product, &directories)
    }

    #[cfg(unix)]
    {
        resolve_unix(product, &directories)
    }

    #[cfg(not(any(unix, windows)))]
    {
        resolve_portable(product, &directories)
    }
}

fn absolute_path_directories(path: Option<&OsStr>) -> Vec<PathBuf> {
    path.into_iter()
        .flat_map(env::split_paths)
        .filter(|directory| directory.is_absolute())
        .collect()
}

#[cfg(unix)]
fn resolve_unix(
    product: Product,
    directories: &[PathBuf],
) -> Result<ResolvedClientProgram, ClientProgramResolveError> {
    use std::os::unix::fs::PermissionsExt;

    for directory in directories {
        let candidate = directory.join(product.directory_name());
        let Ok(metadata) = candidate.metadata() else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Ok(ResolvedClientProgram::native(candidate));
        }
    }
    Err(ClientProgramResolveError::NotFound { product })
}

#[cfg(windows)]
fn resolve_windows(
    product: Product,
    directories: &[PathBuf],
) -> Result<ResolvedClientProgram, ClientProgramResolveError> {
    let native_node = directories
        .iter()
        .map(|directory| directory.join("node.exe"))
        .find(|candidate| is_regular_file(candidate));
    let mut unsupported = None;

    for directory in directories {
        let program = product.directory_name();
        let native = directory.join(format!("{program}.exe"));
        if is_regular_file(&native) {
            return Ok(ResolvedClientProgram::native(native));
        }

        let shim = directory.join(format!("{program}.cmd"));
        if !is_regular_file(&shim) {
            continue;
        }

        let (package_entry, source) = npm_package_entry(product, directory);
        if !is_regular_file(&package_entry) {
            remember_unsupported(
                &mut unsupported,
                shim,
                UnsupportedNpmShimReason::PackageEntryMissing,
            );
            continue;
        }

        let sibling_node = directory.join("node.exe");
        let node = is_regular_file(&sibling_node)
            .then_some(sibling_node)
            .or_else(|| native_node.clone());
        let Some(node) = node else {
            remember_unsupported(
                &mut unsupported,
                shim,
                UnsupportedNpmShimReason::NodeExecutableMissing,
            );
            continue;
        };

        return Ok(ResolvedClientProgram::npm(node, package_entry, source));
    }

    match unsupported {
        Some((shim, reason)) => Err(ClientProgramResolveError::UnsupportedNpmShim {
            product,
            shim,
            reason,
        }),
        None => Err(ClientProgramResolveError::NotFound { product }),
    }
}

#[cfg(windows)]
fn remember_unsupported(
    current: &mut Option<(PathBuf, UnsupportedNpmShimReason)>,
    shim: PathBuf,
    reason: UnsupportedNpmShimReason,
) {
    if current.is_none()
        || (matches!(reason, UnsupportedNpmShimReason::NodeExecutableMissing)
            && matches!(
                current,
                Some((_, UnsupportedNpmShimReason::PackageEntryMissing))
            ))
    {
        *current = Some((shim, reason));
    }
}

#[cfg(windows)]
fn npm_package_entry(product: Product, shim_directory: &Path) -> (PathBuf, ClientProgramSource) {
    let local_node_modules = if is_local_npm_bin(shim_directory) {
        shim_directory.parent()
    } else {
        None
    };
    let (node_modules, source) = match local_node_modules {
        Some(node_modules) => (
            node_modules.to_path_buf(),
            ClientProgramSource::NpmLocalShim,
        ),
        None => (
            shim_directory.join("node_modules"),
            ClientProgramSource::NpmGlobalShim,
        ),
    };
    let entry = match product {
        Product::Claude => node_modules
            .join("@anthropic-ai")
            .join("claude-code")
            .join("cli.js"),
        Product::Codex => node_modules
            .join("@openai")
            .join("codex")
            .join("bin")
            .join("codex.js"),
    };
    (entry, source)
}

#[cfg(windows)]
fn is_local_npm_bin(directory: &Path) -> bool {
    path_file_name_eq(directory, ".bin")
        && directory
            .parent()
            .is_some_and(|parent| path_file_name_eq(parent, "node_modules"))
}

#[cfg(windows)]
fn path_file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

#[cfg(any(windows, not(any(unix, windows))))]
fn is_regular_file(path: &Path) -> bool {
    path.metadata().is_ok_and(|metadata| metadata.is_file())
}

#[cfg(not(any(unix, windows)))]
fn resolve_portable(
    product: Product,
    directories: &[PathBuf],
) -> Result<ResolvedClientProgram, ClientProgramResolveError> {
    for directory in directories {
        let candidate = directory.join(product.directory_name());
        if is_regular_file(&candidate) {
            return Ok(ResolvedClientProgram::native(candidate));
        }
    }
    Err(ClientProgramResolveError::NotFound { product })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn joined_path(directories: &[&Path]) -> OsString {
        env::join_paths(directories).unwrap()
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn write_program(path: &Path, executable: bool) {
            fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
            let mode = if executable { 0o700 } else { 0o600 };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        #[test]
        fn resolves_first_regular_executable_from_absolute_path_directories() {
            let temporary = tempfile::tempdir().unwrap();
            let first = temporary.path().join("first");
            let second = temporary.path().join("second");
            fs::create_dir(&first).unwrap();
            fs::create_dir(&second).unwrap();
            write_program(&first.join("codex"), false);
            write_program(&second.join("codex"), true);

            let path = joined_path(&[&first, &second]);
            let resolved =
                resolve_client_program_from_path(Product::Codex, Some(path.as_os_str())).unwrap();
            assert_eq!(resolved.executable(), second.join("codex"));
            assert!(resolved.prefix_args().is_empty());
            assert_eq!(resolved.source(), ClientProgramSource::NativeExecutable);
        }

        #[test]
        fn ignores_relative_path_entries_and_non_files() {
            let temporary = tempfile::tempdir().unwrap();
            let absolute = temporary.path().join("absolute");
            fs::create_dir(&absolute).unwrap();
            fs::create_dir(absolute.join("claude")).unwrap();
            let relative = Path::new("relative-client-bin");
            let path = joined_path(&[relative, &absolute]);

            let error = resolve_client_program_from_path(Product::Claude, Some(path.as_os_str()))
                .unwrap_err();
            assert!(error.is_not_found());
            assert!(!error.is_unsupported());
        }
    }

    #[cfg(windows)]
    mod windows {
        use super::*;

        fn touch(path: &Path, contents: &[u8]) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        fn global_entry(directory: &Path, product: Product) -> PathBuf {
            npm_package_entry(product, directory).0
        }

        #[test]
        fn native_executable_wins_over_cmd_in_the_same_path_directory() {
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("bin");
            fs::create_dir(&directory).unwrap();
            touch(&directory.join("claude.exe"), b"native");
            touch(&directory.join("claude.cmd"), b"exit /b 99\r\n");
            touch(&global_entry(&directory, Product::Claude), b"js");
            touch(&directory.join("node.exe"), b"node");

            let path = joined_path(&[&directory]);
            let resolved =
                resolve_client_program_from_path(Product::Claude, Some(path.as_os_str())).unwrap();
            assert_eq!(resolved.executable(), directory.join("claude.exe"));
            assert!(resolved.prefix_args().is_empty());
            assert_eq!(resolved.source(), ClientProgramSource::NativeExecutable);
        }

        #[test]
        fn malicious_global_cmd_contents_are_never_used_as_a_command() {
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("npm & malicious");
            fs::create_dir(&directory).unwrap();
            let shim = directory.join("codex.cmd");
            touch(
                &shim,
                b"@echo pwned>must-not-exist & powershell -Command whoami\r\n",
            );
            let entry = global_entry(&directory, Product::Codex);
            touch(&entry, b"console.log('safe');\n");
            touch(&directory.join("node.exe"), b"node");

            let path = joined_path(&[&directory]);
            let resolved =
                resolve_client_program_from_path(Product::Codex, Some(path.as_os_str())).unwrap();
            assert_eq!(resolved.executable(), directory.join("node.exe"));
            assert_eq!(resolved.prefix_args(), &[entry.into_os_string()]);
            assert_eq!(resolved.source(), ClientProgramSource::NpmGlobalShim);
        }

        #[test]
        fn resolves_local_npm_bin_with_path_node_fallback() {
            let temporary = tempfile::tempdir().unwrap();
            let project = temporary.path().join("project");
            let shim_directory = project.join("node_modules/.bin");
            let node_directory = temporary.path().join("node-bin");
            fs::create_dir_all(&shim_directory).unwrap();
            fs::create_dir(&node_directory).unwrap();
            touch(&shim_directory.join("claude.cmd"), b"ignored\r\n");
            let (entry, source) = npm_package_entry(Product::Claude, &shim_directory);
            touch(&entry, b"js");
            touch(&node_directory.join("node.exe"), b"node");

            let path = joined_path(&[&shim_directory, &node_directory]);
            let resolved =
                resolve_client_program_from_path(Product::Claude, Some(path.as_os_str())).unwrap();
            assert_eq!(resolved.executable(), node_directory.join("node.exe"));
            assert_eq!(resolved.prefix_args(), &[entry.into_os_string()]);
            assert_eq!(source, ClientProgramSource::NpmLocalShim);
            assert_eq!(resolved.source(), ClientProgramSource::NpmLocalShim);
        }

        #[test]
        fn unsupported_cmd_does_not_hide_a_later_native_executable() {
            let temporary = tempfile::tempdir().unwrap();
            let first = temporary.path().join("first");
            let second = temporary.path().join("second");
            fs::create_dir(&first).unwrap();
            fs::create_dir(&second).unwrap();
            touch(&first.join("codex.cmd"), b"unsupported\r\n");
            touch(&second.join("codex.exe"), b"native");

            let path = joined_path(&[&first, &second]);
            let resolved =
                resolve_client_program_from_path(Product::Codex, Some(path.as_os_str())).unwrap();
            assert_eq!(resolved.executable(), second.join("codex.exe"));
            assert_eq!(resolved.source(), ClientProgramSource::NativeExecutable);
        }

        #[test]
        fn valid_npm_install_preserves_path_directory_precedence() {
            let temporary = tempfile::tempdir().unwrap();
            let first = temporary.path().join("first");
            let second = temporary.path().join("second");
            fs::create_dir(&first).unwrap();
            fs::create_dir(&second).unwrap();
            touch(&first.join("codex.cmd"), b"ignored\r\n");
            let entry = global_entry(&first, Product::Codex);
            touch(&entry, b"js");
            touch(&first.join("node.exe"), b"node");
            touch(&second.join("codex.exe"), b"native");

            let path = joined_path(&[&first, &second]);
            let resolved =
                resolve_client_program_from_path(Product::Codex, Some(path.as_os_str())).unwrap();
            assert_eq!(resolved.executable(), first.join("node.exe"));
            assert_eq!(resolved.prefix_args(), &[entry.into_os_string()]);
            assert_eq!(resolved.source(), ClientProgramSource::NpmGlobalShim);
        }

        #[test]
        fn distinguishes_missing_client_from_unsupported_npm_layout() {
            let temporary = tempfile::tempdir().unwrap();
            let empty = temporary.path().join("empty");
            let npm = temporary.path().join("npm");
            fs::create_dir(&empty).unwrap();
            fs::create_dir(&npm).unwrap();

            let empty_path = joined_path(&[&empty]);
            let missing =
                resolve_client_program_from_path(Product::Codex, Some(empty_path.as_os_str()))
                    .unwrap_err();
            assert!(matches!(
                missing,
                ClientProgramResolveError::NotFound {
                    product: Product::Codex
                }
            ));

            let shim = npm.join("codex.cmd");
            touch(&shim, b"ignored\r\n");
            let npm_path = joined_path(&[&npm]);
            let unsupported =
                resolve_client_program_from_path(Product::Codex, Some(npm_path.as_os_str()))
                    .unwrap_err();
            assert!(unsupported.is_unsupported());
            assert!(matches!(
                unsupported,
                ClientProgramResolveError::UnsupportedNpmShim {
                    product: Product::Codex,
                    reason: UnsupportedNpmShimReason::PackageEntryMissing,
                    ..
                }
            ));
        }

        #[test]
        fn node_cmd_and_other_script_extensions_are_not_executables() {
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("bin");
            fs::create_dir(&directory).unwrap();
            touch(&directory.join("claude.cmd"), b"ignored\r\n");
            touch(&global_entry(&directory, Product::Claude), b"js");
            touch(&directory.join("node.cmd"), b"ignored\r\n");
            touch(&directory.join("claude.bat"), b"ignored\r\n");
            touch(&directory.join("claude.ps1"), b"ignored\r\n");

            let path = joined_path(&[&directory]);
            let error = resolve_client_program_from_path(Product::Claude, Some(path.as_os_str()))
                .unwrap_err();
            assert!(matches!(
                error,
                ClientProgramResolveError::UnsupportedNpmShim {
                    reason: UnsupportedNpmShimReason::NodeExecutableMissing,
                    ..
                }
            ));
        }
    }
}
