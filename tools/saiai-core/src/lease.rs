use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::fsutil::{
    ensure_no_managed_symlinks, harden_lock_open_options, is_symlink_or_reparse,
    open_private_lock_file, validate_opened_lock_file,
};
use crate::{AppPaths, Error, GenerationRef, Result};

/// A shared lifetime lease for one committed client generation.
///
/// The lease is intentionally opaque and non-cloneable. Launchers keep it
/// alive until the corresponding child process has fully exited, preventing
/// setup or revoke from deleting that process's managed home underneath it.
#[must_use = "dropping the generation lease allows its managed home to be removed"]
pub struct GenerationLease {
    file: File,
}

impl GenerationLease {
    pub(crate) fn acquire(paths: &AppPaths, generation: &GenerationRef) -> Result<Self> {
        let path = paths.generation_lease_file(generation);
        ensure_no_managed_symlinks(paths.state_dir(), &path)?;
        let file = open_private_lock_file(&path)?;
        fs2::FileExt::lock_shared(&file)
            .map_err(|error| Error::io("acquire generation lease", &path, error))?;
        validate_opened_lock_file(&file, &path)?;
        Ok(Self { file })
    }
}

impl std::fmt::Debug for GenerationLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GenerationLease([HELD])")
    }
}

impl Drop for GenerationLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub(crate) struct ExclusiveGenerationLease {
    file: File,
    path: PathBuf,
}

pub(crate) enum ExclusiveLeaseProbe {
    Acquired(ExclusiveGenerationLease),
    Missing,
    Busy,
}

impl ExclusiveGenerationLease {
    /// Probe an already-existing generation lease without creating directories,
    /// files, or changing permissions. Callers use this for mutation-free busy
    /// preflight while holding the installation transaction lock.
    pub(crate) fn try_acquire_existing(
        paths: &AppPaths,
        generation: &GenerationRef,
    ) -> Result<ExclusiveLeaseProbe> {
        let path = paths.generation_lease_file(generation);
        Self::try_acquire_existing_path(paths, &path)
    }

    pub(crate) fn try_acquire_existing_path(
        paths: &AppPaths,
        path: &Path,
    ) -> Result<ExclusiveLeaseProbe> {
        ensure_no_managed_symlinks(paths.state_dir(), path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        harden_lock_open_options(&mut options);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ExclusiveLeaseProbe::Missing);
            }
            Err(error) => {
                return Err(Error::io(
                    "open existing generation lease",
                    path.to_path_buf(),
                    error,
                ));
            }
        };
        validate_opened_lock_file(&file, path)?;
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => {
                validate_opened_lock_file(&file, path)?;
                Ok(ExclusiveLeaseProbe::Acquired(Self {
                    file,
                    path: path.to_path_buf(),
                }))
            }
            Err(error) if lock_is_contended(&error) => Ok(ExclusiveLeaseProbe::Busy),
            Err(error) => Err(Error::io(
                "inspect generation lease",
                path.to_path_buf(),
                error,
            )),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Release the OS lock before unlinking its file. The caller must continue
    /// holding the transaction lock across this operation so a new launcher
    /// cannot acquire a replacement lease in between.
    pub(crate) fn release_and_remove(self) -> Result<bool> {
        let path = self.path.clone();
        drop(self);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !is_symlink_or_reparse(&metadata) => {
                std::fs::remove_file(&path)
                    .map_err(|error| Error::io("remove generation lease", &path, error))?;
                Ok(true)
            }
            Ok(_) => Err(Error::io(
                "remove generation lease",
                &path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "generation lease path is not a regular file",
                ),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(Error::io("inspect generation lease", &path, error)),
        }
    }
}

impl Drop for ExclusiveGenerationLease {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn lock_is_contended(error: &std::io::Error) -> bool {
    let platform = fs2::lock_contended_error();
    error.kind() == std::io::ErrorKind::WouldBlock
        || platform
            .raw_os_error()
            .is_some_and(|code| error.raw_os_error() == Some(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, AppPaths, GenerationRef) {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_app_dirs(
            temp.path().join("config/saiai"),
            temp.path().join("data/saiai"),
            temp.path().join("state/saiai"),
        )
        .unwrap();
        let generation =
            GenerationRef::new("gen-claude-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()).unwrap();
        (temp, paths, generation)
    }

    #[test]
    fn existing_probe_does_not_create_a_missing_lease_or_parent() {
        let (_temp, paths, generation) = fixture();
        assert!(matches!(
            ExclusiveGenerationLease::try_acquire_existing(&paths, &generation).unwrap(),
            ExclusiveLeaseProbe::Missing
        ));
        assert!(!paths.state_dir().exists());
    }

    #[test]
    fn shared_and_exclusive_locks_are_reported_as_contention() {
        let (_temp, paths, generation) = fixture();
        let shared = GenerationLease::acquire(&paths, &generation).unwrap();
        assert!(matches!(
            ExclusiveGenerationLease::try_acquire_existing(&paths, &generation).unwrap(),
            ExclusiveLeaseProbe::Busy
        ));
        drop(shared);

        let exclusive =
            match ExclusiveGenerationLease::try_acquire_existing(&paths, &generation).unwrap() {
                ExclusiveLeaseProbe::Acquired(lease) => lease,
                ExclusiveLeaseProbe::Missing | ExclusiveLeaseProbe::Busy => {
                    panic!("the existing lease should be exclusively lockable")
                }
            };
        assert!(matches!(
            ExclusiveGenerationLease::try_acquire_existing(&paths, &generation).unwrap(),
            ExclusiveLeaseProbe::Busy
        ));
        assert!(exclusive.release_and_remove().unwrap());
    }

    #[test]
    fn fs2_platform_contention_error_is_recognized() {
        assert!(lock_is_contended(&fs2::lock_contended_error()));
    }
}
