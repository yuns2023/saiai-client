use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::{Error, Result};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

/// Keep serialized path references valid on every supported platform. Windows
/// aliases reserved device basenames even when an extension is present and
/// silently trims terminal dots, so accepting either shape would make two
/// distinct config references resolve to the same filesystem object.
pub(crate) fn is_portable_reference_component(value: &str) -> bool {
    if value.ends_with('.') || value.ends_with(' ') {
        return false;
    }
    let basename = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    !matches!(
        basename.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    validate_directory_if_present(path)?;
    fs::create_dir_all(path).map_err(|error| Error::io("create directory", path, error))?;
    validate_directory_if_present(path)?;
    set_private_dir_permissions(path)
}

/// Reject symlinks in the V2-owned portion of a path without canonicalizing or
/// inspecting platform/home ancestors above `managed_root`.
pub(crate) fn ensure_no_managed_symlinks(managed_root: &Path, target: &Path) -> Result<()> {
    let relative = target
        .strip_prefix(managed_root)
        .map_err(|_| Error::InvalidAppPath {
            field: "managed path",
            path: target.to_path_buf(),
            reason: "path is outside its V2-owned root",
        })?;
    let mut current = managed_root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();

    inspect_managed_component(&current, !components.is_empty())?;
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let has_children = index + 1 < components.len();
        if !inspect_managed_component(&current, has_children)? {
            // Once a component does not exist, no deeper component can be an
            // existing symlink without first creating this one.
            break;
        }
    }
    Ok(())
}

pub(crate) fn reject_symlink_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_symlink_or_reparse(&metadata) => Err(symlink_error(path)),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::io("inspect managed path", path, error)),
    }
}

pub(crate) fn path_present_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::io("inspect managed path presence", path, error)),
    }
}

fn validate_directory_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_symlink_or_reparse(&metadata) => Err(symlink_error(path)),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(Error::io(
            "validate managed directory",
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "V2-owned directory path is not a directory",
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::io("inspect managed directory", path, error)),
    }
}

fn inspect_managed_component(path: &Path, must_be_directory: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_symlink_or_reparse(&metadata) => Err(symlink_error(path)),
        Ok(metadata) if must_be_directory && !metadata.is_dir() => Err(Error::io(
            "validate managed path",
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "V2-owned path component is not a directory",
            ),
        )),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::io("inspect managed path", path, error)),
    }
}

fn symlink_error(path: &Path) -> Error {
    Error::io(
        "validate managed path",
        path,
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "symbolic links are not allowed in V2-owned paths",
        ),
    )
}

pub(crate) fn is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    platform_is_reparse(metadata)
}

#[cfg(windows)]
fn platform_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn platform_is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemovalKind {
    FileOrFileLink,
    DirectoryLink,
    DirectoryTree,
}

fn removal_kind(is_link_or_reparse: bool, is_directory: bool) -> RemovalKind {
    match (is_link_or_reparse, is_directory) {
        (true, true) => RemovalKind::DirectoryLink,
        (true, false) | (false, false) => RemovalKind::FileOrFileLink,
        (false, true) => RemovalKind::DirectoryTree,
    }
}

#[cfg(windows)]
fn link_is_directory(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::FileTypeExt;

    metadata.is_dir() || metadata.file_type().is_symlink_dir()
}

#[cfg(not(windows))]
fn link_is_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
}

pub(crate) fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    atomic_write_private_with_directory_sync(path, contents, sync_directory)
}

fn atomic_write_private_with_directory_sync(
    path: &Path,
    contents: &[u8],
    sync_parent: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| Error::InvalidAppPath {
        field: "file",
        path: path.to_path_buf(),
        reason: "path has no parent directory",
    })?;
    ensure_private_dir(parent)?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let temporary = parent.join(format!(".{file_name}.tmp-{}", Uuid::new_v4().simple()));
    let mut cleanup = TemporaryFile::new(temporary.clone());

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(&temporary)
        .map_err(|error| Error::io("create temporary file", &temporary, error))?;
    file.write_all(contents)
        .map_err(|error| Error::io("write temporary file", &temporary, error))?;
    file.sync_all()
        .map_err(|error| Error::io("sync temporary file", &temporary, error))?;
    drop(file);
    // The replacement inherits this already-private file's metadata. Keep every
    // permission operation before the commit point so a successful replacement
    // can never be reported as a rollback-safe error.
    set_private_file_permissions(&temporary)?;

    replace_file(&temporary, path)?;
    cleanup.disarm();
    // Directory durability is useful but cannot be reported as a transaction
    // failure after the destination has already been atomically replaced.
    let _ = sync_parent(parent);
    Ok(())
}

pub(crate) fn open_private_lock_file(path: &Path) -> Result<File> {
    let parent = path.parent().ok_or_else(|| Error::InvalidAppPath {
        field: "lock file",
        path: path.to_path_buf(),
        reason: "path has no parent directory",
    })?;
    ensure_private_dir(parent)?;
    reject_symlink_if_present(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    harden_lock_open_options(&mut options);
    let file = options
        .open(path)
        .map_err(|error| Error::io("open transaction lock", path, error))?;
    validate_opened_lock_file(&file, path)?;
    set_private_lock_permissions(&file, path)?;
    validate_opened_lock_file(&file, path)?;
    Ok(file)
}

pub(crate) fn harden_lock_open_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = options;
    }
}

pub(crate) fn validate_opened_lock_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| Error::io("inspect opened lock", path, error))?;
    if !metadata.is_file() || is_symlink_or_reparse(&metadata) {
        return Err(invalid_opened_lock(path));
    }
    if !opened_lock_is_current(file, path)? {
        return Err(invalid_opened_lock(path));
    }
    Ok(())
}

fn invalid_opened_lock(path: &Path) -> Error {
    Error::io(
        "inspect opened lock",
        path,
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "lock path is not the current regular filesystem object",
        ),
    )
}

#[cfg(unix)]
fn opened_lock_is_current(file: &File, path: &Path) -> Result<bool> {
    let opened = file
        .metadata()
        .map_err(|error| Error::io("inspect opened lock", path, error))?;
    match fs::symlink_metadata(path) {
        Ok(current) => Ok(current.is_file()
            && !current.file_type().is_symlink()
            && current.dev() == opened.dev()
            && current.ino() == opened.ino()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::io("inspect current lock path", path, error)),
    }
}

#[cfg(windows)]
fn opened_lock_is_current(file: &File, path: &Path) -> Result<bool> {
    let opened_identity = windows_file_identity(file, path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    harden_lock_open_options(&mut options);
    let current = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(Error::io("open current lock path", path, error)),
    };
    let metadata = current
        .metadata()
        .map_err(|error| Error::io("inspect current lock path", path, error))?;
    if !metadata.is_file() || is_symlink_or_reparse(&metadata) {
        return Ok(false);
    }
    Ok(opened_identity == windows_file_identity(&current, path)?)
}

#[cfg(windows)]
fn windows_file_identity(file: &File, path: &Path) -> Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    // SAFETY: the structure is an output-only plain-old-data buffer.
    let mut information = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: `file` owns a live handle and `information` is writable for the
    // duration of the call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut information) } == 0 {
        return Err(Error::io(
            "identify opened lock",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, index))
}

#[cfg(not(any(unix, windows)))]
fn opened_lock_is_current(_file: &File, path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !is_symlink_or_reparse(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::io("inspect current lock path", path, error)),
    }
}

#[cfg(unix)]
fn set_private_lock_permissions(file: &File, path: &Path) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| Error::io("set lock permissions", path, error))
}

#[cfg(windows)]
fn set_private_lock_permissions(_file: &File, path: &Path) -> Result<()> {
    set_private_file_permissions(path)
}

#[cfg(not(any(unix, windows)))]
fn set_private_lock_permissions(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn remove_dir_if_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let is_link = is_symlink_or_reparse(&metadata);
            let is_directory = if is_link {
                link_is_directory(&metadata)
            } else {
                metadata.is_dir()
            };
            match removal_kind(is_link, is_directory) {
                RemovalKind::FileOrFileLink => {
                    fs::remove_file(path).map_err(|error| Error::io("remove path", path, error))?
                }
                RemovalKind::DirectoryLink => fs::remove_dir(path)
                    .map_err(|error| Error::io("remove directory link", path, error))?,
                RemovalKind::DirectoryTree => fs::remove_dir_all(path)
                    .map_err(|error| Error::io("remove directory", path, error))?,
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::io("inspect path", path, error)),
    }
}

pub(crate) fn promote_new_directory(source: &Path, destination: &Path) -> Result<()> {
    promote_new_directory_with_directory_sync(source, destination, sync_directory)
}

fn promote_new_directory_with_directory_sync(
    source: &Path,
    destination: &Path,
    sync_parent: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if path_present_no_follow(destination)? {
        return Err(Error::io(
            "promote staged directory",
            destination,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination generation already exists",
            ),
        ));
    }
    let parent = destination.parent().ok_or_else(|| Error::InvalidAppPath {
        field: "directory",
        path: destination.to_path_buf(),
        reason: "path has no parent directory",
    })?;
    ensure_private_dir(parent)?;
    fs::rename(source, destination)
        .map_err(|error| Error::io("promote staged directory", destination, error))?;
    // As with file replacement, rename is the commit point. A directory fsync
    // failure after it must not make the caller believe promotion did not occur.
    let _ = sync_parent(parent);
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| Error::io("set directory permissions", path, error))
}

#[cfg(windows)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    crate::windows_acl::set_private_permissions(
        path,
        crate::windows_acl::PrivateObjectKind::Directory,
    )
    .map_err(|error| Error::io("set directory permissions", path, error))
}

#[cfg(not(any(unix, windows)))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| Error::io("set file permissions", path, error))
}

#[cfg(windows)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    crate::windows_acl::set_private_permissions(path, crate::windows_acl::PrivateObjectKind::File)
        .map_err(|error| Error::io("set file permissions", path, error))
}

#[cfg(not(any(unix, windows)))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)
        .map_err(|error| Error::io("atomically replace file", destination, error))
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both path buffers are NUL-terminated and remain alive for the call.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(Error::io(
            "atomically replace file",
            PathBuf::from(String::from_utf16_lossy(
                &destination[..destination.len() - 1],
            )),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)
        .map_err(|error| Error::io("atomically replace file", destination, error))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| Error::io("sync directory", path, error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

struct TemporaryFile {
    path: PathBuf,
    armed: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reparse_removal_policy_never_recurses() {
        assert_eq!(removal_kind(true, true), RemovalKind::DirectoryLink);
        assert_eq!(removal_kind(true, false), RemovalKind::FileOrFileLink);
        assert_eq!(removal_kind(false, false), RemovalKind::FileOrFileLink);
        assert_eq!(removal_kind(false, true), RemovalKind::DirectoryTree);
    }

    #[test]
    fn atomic_replace_does_not_report_a_post_commit_directory_sync_failure() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("config.json");
        fs::write(&destination, b"old").unwrap();

        let result = atomic_write_private_with_directory_sync(&destination, b"new", |path| {
            Err(Error::io(
                "injected directory sync failure",
                path,
                std::io::Error::other("after commit"),
            ))
        });

        assert!(result.is_ok());
        assert_eq!(fs::read(destination).unwrap(), b"new");
    }

    #[test]
    fn directory_promotion_does_not_report_a_post_commit_sync_failure() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("staged");
        let destination = temp.path().join("committed");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("artifact"), b"ready").unwrap();

        let result = promote_new_directory_with_directory_sync(&source, &destination, |path| {
            Err(Error::io(
                "injected directory sync failure",
                path,
                std::io::Error::other("after commit"),
            ))
        });

        assert!(result.is_ok());
        assert!(!source.exists());
        assert_eq!(fs::read(destination.join("artifact")).unwrap(), b"ready");
    }
}
