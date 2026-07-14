use std::ffi::c_void;
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_FLAGS, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE, IsValidSid, NO_INHERITANCE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_MAX_SID_SIZE, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivateObjectKind {
    Directory,
    File,
}

impl PrivateObjectKind {
    fn inheritance(self) -> ACE_FLAGS {
        match self {
            Self::Directory => SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Self::File => NO_INHERITANCE,
        }
    }
}

/// Replace a filesystem object's inherited DACL with a protected, explicit
/// user-private DACL. SYSTEM and the built-in Administrators group retain full
/// access for Windows servicing and account recovery.
pub(crate) fn set_private_permissions(path: &Path, kind: PrivateObjectKind) -> io::Result<()> {
    let wide_path = path_to_wide(path)?;
    let current_user = CurrentUserSid::query()?;
    let system = WellKnownSid::new(WinLocalSystemSid)?;
    let administrators = WellKnownSid::new(WinBuiltinAdministratorsSid)?;

    let user_sid = current_user.sid()?;
    let system_sid = system.sid()?;
    let administrators_sid = administrators.sid()?;
    let owner_is_current_user = object_owner_matches(&wide_path, user_sid)?;

    let inheritance = kind.inheritance();
    let entries = [
        explicit_access(user_sid, TRUSTEE_IS_USER, inheritance),
        explicit_access(system_sid, TRUSTEE_IS_USER, inheritance),
        explicit_access(administrators_sid, TRUSTEE_IS_WELL_KNOWN_GROUP, inheritance),
    ];

    let mut acl = null_mut();
    // SAFETY: every EXPLICIT_ACCESS_W contains a valid SID pointer. The SID
    // backing buffers and entries remain alive until after this call.
    let status =
        unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), null(), &mut acl) };
    let acl_allocation = LocalAllocation::from_maybe_null(acl.cast());
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    let acl_allocation = acl_allocation.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SetEntriesInAclW returned a null ACL",
        )
    })?;

    let mut security_information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let owner = if owner_is_current_user {
        null_mut()
    } else {
        security_information |= OWNER_SECURITY_INFORMATION;
        user_sid
    };

    // SAFETY: the path is NUL-terminated; owner is either null (when the owner
    // flag is absent) or a valid current-user SID; the ACL allocation remains
    // alive throughout the call. Group and SACL are intentionally preserved.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            security_information,
            owner,
            null_mut(),
            acl_allocation.as_ptr().cast(),
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }

    Ok(())
}

/// Verify the exact private ACL written by [`set_private_permissions`].
///
/// A permissive or inherited DACL must fail closed: the object must be owned
/// by the current user and contain exactly three explicit full-control ACEs,
/// for the current user, LocalSystem, and built-in Administrators.
pub(crate) fn audit_private_permissions(path: &Path, kind: PrivateObjectKind) -> io::Result<()> {
    let wide_path = path_to_wide(path)?;
    let current_user = CurrentUserSid::query()?;
    let system = WellKnownSid::new(WinLocalSystemSid)?;
    let administrators = WellKnownSid::new(WinBuiltinAdministratorsSid)?;
    let expected = [current_user.sid()?, system.sid()?, administrators.sid()?];

    let mut owner = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the path is NUL-terminated and every out-pointer is valid. On
    // success, owner and acl point inside the retained security descriptor.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    let descriptor = LocalAllocation::from_maybe_null(descriptor);
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    let descriptor = descriptor.ok_or_else(|| invalid_acl("security descriptor is null"))?;
    validate_sid(owner, "filesystem owner")?;
    // SAFETY: both SIDs are valid and their allocations remain alive.
    if unsafe { EqualSid(owner, expected[0]) } == 0 {
        return Err(invalid_acl("owner is not the current user"));
    }
    if acl.is_null() {
        return Err(invalid_acl("DACL is null (unrestricted access)"));
    }

    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor is the valid security descriptor retained above and
    // both scalar out-pointers are initialized writable storage.
    if unsafe {
        GetSecurityDescriptorControl(descriptor.as_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(invalid_acl("DACL is not protected from inheritance"));
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: acl is retained by descriptor and the output has the exact type
    // and size requested by AclSizeInformation.
    if unsafe {
        GetAclInformation(
            acl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if information.AceCount != expected.len() as u32 {
        return Err(invalid_acl(format!(
            "DACL has {} entries; expected exactly {}",
            information.AceCount,
            expected.len()
        )));
    }

    let mut found = [false; 3];
    for index in 0..information.AceCount {
        let mut raw_ace = null_mut();
        // SAFETY: the index is bounded by the ACE count returned for this ACL.
        if unsafe { GetAce(acl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if raw_ace.is_null() {
            return Err(invalid_acl("DACL contains a null ACE"));
        }
        // SAFETY: GetAce returned a valid ACE pointer owned by the retained ACL.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE {
            return Err(invalid_acl("DACL contains a non-allow ACE"));
        }
        if ace.Mask != FILE_ALL_ACCESS {
            return Err(invalid_acl("DACL entry does not grant exact full control"));
        }
        if ace.Header.AceFlags as u32 & INHERITED_ACE != 0 {
            return Err(invalid_acl("DACL contains an inherited ACE"));
        }
        if ace.Header.AceFlags as u32 != kind.inheritance() {
            return Err(invalid_acl("DACL entry has unexpected inheritance flags"));
        }

        let sid: PSID = (&ace.SidStart as *const u32).cast_mut().cast();
        validate_sid(sid, "DACL trustee")?;
        let mut matched = false;
        for (slot, expected_sid) in found.iter_mut().zip(expected) {
            // SAFETY: both trustee SIDs are valid and retained for this call.
            if unsafe { EqualSid(sid, expected_sid) } != 0 {
                if *slot {
                    return Err(invalid_acl("DACL contains a duplicate trustee"));
                }
                *slot = true;
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(invalid_acl("DACL contains an unexpected trustee"));
        }
    }
    if !found.into_iter().all(|present| present) {
        return Err(invalid_acl("DACL is missing an expected trustee"));
    }

    Ok(())
}

fn explicit_access(sid: PSID, trustee_type: i32, inheritance: ACE_FLAGS) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: trustee_type,
            // With TRUSTEE_IS_SID, this field is a PSID despite its PWSTR type.
            ptstrName: sid.cast(),
        },
    }
}

fn object_owner_matches(path: &[u16], expected_owner: PSID) -> io::Result<bool> {
    let mut owner = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: path is NUL-terminated. On success, owner points inside the
    // LocalAlloc-backed security descriptor returned through descriptor.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    let descriptor = LocalAllocation::from_maybe_null(descriptor);
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    let _descriptor = descriptor.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "GetNamedSecurityInfoW returned a null security descriptor",
        )
    })?;
    validate_sid(owner, "filesystem owner")?;

    // SAFETY: both SID pointers were validated and remain alive for the call.
    Ok(unsafe { EqualSid(owner, expected_owner) != 0 })
}

fn path_to_wide(path: &Path) -> io::Result<Vec<u16>> {
    nul_terminate(path.as_os_str().encode_wide().collect())
}

fn nul_terminate(mut units: Vec<u16>) -> io::Result<Vec<u16>> {
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an embedded NUL",
        ));
    }
    units.push(0);
    Ok(units)
}

fn validate_sid(sid: PSID, label: &str) -> io::Result<()> {
    if sid.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} SID is null"),
        ));
    }
    // SAFETY: the pointer comes from a Windows token/security API and its
    // backing allocation is still alive at each call site.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} SID is invalid"),
        ));
    }
    Ok(())
}

fn win32_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn invalid_acl(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

struct CurrentUserSid {
    token_user: AlignedBuffer,
}

impl CurrentUserSid {
    fn query() -> io::Result<Self> {
        let token = ProcessToken::open()?;
        let mut required = 0;
        // SAFETY: the null buffer/zero-length call is the documented size
        // query. `required` is a valid output pointer and token is open.
        let queried =
            unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
        if queried == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(error);
            }
        }
        if required < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GetTokenInformation returned an undersized TOKEN_USER buffer",
            ));
        }

        let mut token_user = AlignedBuffer::new(required)?;
        let mut written = required;
        // SAFETY: token_user is suitably aligned and has at least `required`
        // writable bytes. token remains open for the duration of the call.
        let queried = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                token_user.as_mut_ptr(),
                required,
                &mut written,
            )
        };
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        if written < size_of::<TOKEN_USER>() as u32 || written > token_user.capacity_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GetTokenInformation returned an invalid TOKEN_USER size",
            ));
        }

        let current = Self { token_user };
        current.sid()?;
        Ok(current)
    }

    fn sid(&self) -> io::Result<PSID> {
        // SAFETY: query() only constructs this value after Windows populated a
        // complete, aligned TOKEN_USER in the retained backing buffer.
        let token_user = unsafe { &*self.token_user.as_ptr().cast::<TOKEN_USER>() };
        let sid = token_user.User.Sid;
        validate_sid(sid, "current user")?;
        Ok(sid)
    }
}

struct WellKnownSid {
    storage: AlignedBuffer,
}

impl WellKnownSid {
    fn new(kind: i32) -> io::Result<Self> {
        let mut size = SECURITY_MAX_SID_SIZE;
        let mut storage = AlignedBuffer::new(size)?;
        // SAFETY: storage is aligned and has `size` writable bytes. Passing a
        // null domain SID requests the well-known local/system SID.
        let created =
            unsafe { CreateWellKnownSid(kind, null_mut(), storage.as_mut_ptr(), &mut size) };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 || size > storage.capacity_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CreateWellKnownSid returned an invalid SID size",
            ));
        }
        let sid = Self { storage };
        sid.sid()?;
        Ok(sid)
    }

    fn sid(&self) -> io::Result<PSID> {
        let sid = self.storage.as_ptr().cast_mut();
        validate_sid(sid, "well-known")?;
        Ok(sid)
    }
}

struct AlignedBuffer(Vec<usize>);

impl AlignedBuffer {
    fn new(byte_len: u32) -> io::Result<Self> {
        let byte_len = usize::try_from(byte_len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Windows buffer size overflow")
        })?;
        let words = byte_len
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Windows buffer size overflow")
            })?
            / size_of::<usize>();
        Ok(Self(vec![0; words.max(1)]))
    }

    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }

    fn capacity_bytes(&self) -> u32 {
        u32::try_from(size_of_val(self.0.as_slice())).unwrap_or(u32::MAX)
    }
}

struct ProcessToken(HANDLE);

impl ProcessToken {
    fn open() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: GetCurrentProcess returns a process pseudo-handle and token is
        // a valid output pointer.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        if token.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OpenProcessToken returned a null handle",
            ));
        }
        Ok(Self(token))
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        // SAFETY: this is the owned token handle returned by OpenProcessToken.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn from_maybe_null(pointer: *mut c_void) -> Option<Self> {
        (!pointer.is_null()).then_some(Self(pointer))
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: SetEntriesInAclW and GetNamedSecurityInfoW return allocations
        // that their contracts require callers to release with LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn inheritance_policy_only_flows_from_private_directories() {
        assert_eq!(
            PrivateObjectKind::Directory.inheritance(),
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        );
        assert_eq!(PrivateObjectKind::File.inheritance(), NO_INHERITANCE);
    }

    #[test]
    fn wide_paths_are_nul_terminated_without_loss() {
        let units = vec![
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            0x79c1,
            0xd83d,
            0xdd12,
        ];
        let wide = nul_terminate(units.clone()).unwrap();
        assert_eq!(&wide[..wide.len() - 1], units);
        assert_eq!(wide.last(), Some(&0));
        assert!(nul_terminate(vec![b'C' as u16, 0, b'x' as u16]).is_err());
    }

    #[test]
    fn runtime_acl_is_protected_and_has_only_expected_trustees() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("saiai-权限-🔒");
        fs::create_dir(&directory).unwrap();
        set_private_permissions(&directory, PrivateObjectKind::Directory).unwrap();

        let file = directory.join("credential-密钥.key");
        fs::write(&file, b"not-a-real-key").unwrap();
        set_private_permissions(&file, PrivateObjectKind::File).unwrap();

        assert_private_acl(&directory, PrivateObjectKind::Directory);
        assert_private_acl(&file, PrivateObjectKind::File);
    }

    fn assert_private_acl(path: &Path, kind: PrivateObjectKind) {
        audit_private_permissions(path, kind).unwrap();

        let path = path_to_wide(path).unwrap();
        let current_user = CurrentUserSid::query().unwrap();
        let system = WellKnownSid::new(WinLocalSystemSid).unwrap();
        let administrators = WellKnownSid::new(WinBuiltinAdministratorsSid).unwrap();
        let expected = [
            current_user.sid().unwrap(),
            system.sid().unwrap(),
            administrators.sid().unwrap(),
        ];

        let mut owner = null_mut();
        let mut acl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: path is NUL-terminated and all out-pointers are valid.
        let status = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        let _descriptor = LocalAllocation::from_maybe_null(descriptor).unwrap();
        assert!(!acl.is_null());
        // SAFETY: owner and expected SIDs remain valid while their backing
        // allocations are retained.
        assert!(unsafe { EqualSid(owner, expected[0]) } != 0);

        let mut control = 0;
        let mut revision = 0;
        // SAFETY: descriptor is a valid security descriptor for the test path.
        assert!(
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);

        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: acl is owned by the retained security descriptor and the
        // output buffer has the exact ACL_SIZE_INFORMATION size.
        assert!(
            unsafe {
                GetAclInformation(
                    acl,
                    (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            } != 0
        );
        assert_eq!(information.AceCount, expected.len() as u32);

        let mut found = [false; 3];
        for index in 0..information.AceCount {
            let mut raw_ace = null_mut();
            // SAFETY: index is bounded by the ACE count returned for this ACL.
            assert!(unsafe { GetAce(acl, index, &mut raw_ace) } != 0);
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            assert_eq!(ace.Header.AceType as u32, ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!(ace.Mask, FILE_ALL_ACCESS);
            assert_eq!(ace.Header.AceFlags as u32 & INHERITED_ACE, 0);
            assert_eq!(
                ace.Header.AceFlags as u32,
                kind.inheritance(),
                "unexpected inheritance flags"
            );
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            for (slot, expected_sid) in found.iter_mut().zip(expected) {
                // SAFETY: each ACE SID is part of the valid retained ACL.
                if unsafe { EqualSid(sid, expected_sid) } != 0 {
                    assert!(!*slot, "duplicate ACL trustee");
                    *slot = true;
                }
            }
        }
        assert!(found.into_iter().all(|present| present));
    }
}
