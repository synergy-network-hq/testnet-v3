//! Read-only Windows managed-root boundary. This grants no release or network
//! authority. Native Windows qualification is required independently of a build.
use super::BundleError;
use std::{
    ffi::{c_void, OsStr},
    fs::File,
    io::Read,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};

type Handle = *mut c_void;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: Handle,
    name: *mut UnicodeString,
    attributes: u32,
    descriptor: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}
#[repr(C)]
struct DeviceInformation {
    device_type: u32,
    characteristics: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct FileInformation {
    attributes: u32,
    creation: [u32; 2],
    access: [u32; 2],
    write: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[repr(C)]
struct Acl {
    revision: u8,
    reserved: u8,
    size: u16,
    count: u16,
    reserved2: u16,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryVolumeInformationFile(
        handle: Handle,
        status: *mut IoStatus,
        information: *mut DeviceInformation,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtCreateFile(
        handle: *mut Handle,
        access: u32,
        attributes: *mut ObjectAttributes,
        status: *mut IoStatus,
        allocation: *const i64,
        file_attributes: u32,
        sharing: u32,
        disposition: u32,
        options: u32,
        ea: *const c_void,
        ea_size: u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileType(handle: Handle) -> u32;
    fn GetFileInformationByHandle(handle: Handle, info: *mut FileInformation) -> i32;
    fn GetVolumeInformationByHandleW(
        handle: Handle,
        name: *mut u16,
        name_size: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_size: u32,
    ) -> i32;
    fn GetCurrentProcess() -> Handle;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn LocalFree(memory: Handle) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        handle: Handle,
        kind: u32,
        selection: u32,
        owner: *mut Handle,
        group: *mut Handle,
        dacl: *mut *mut Acl,
        sacl: *mut Handle,
        descriptor: *mut Handle,
    ) -> u32;
    fn IsValidSecurityDescriptor(descriptor: Handle) -> i32;
    fn IsValidAcl(acl: *const Acl) -> i32;
    fn IsValidSid(sid: Handle) -> i32;
    fn GetLengthSid(sid: Handle) -> u32;
    fn EqualSid(a: Handle, b: Handle) -> i32;
    fn GetAce(acl: *const Acl, index: u32, ace: *mut Handle) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        data: Handle,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn CreateWellKnownSid(kind: u32, domain: Handle, sid: Handle, size: *mut u32) -> i32;
}

struct SecurityDescriptor(Handle);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Token(Handle);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Every ancestor remains open without write/delete sharing, so the selected
/// directory cannot be renamed/replaced while descendant handles are resolved.
pub(super) struct ProtectedRoot {
    ancestors: Vec<File>,
    trusted: TrustedSids,
}

impl ProtectedRoot {
    pub(super) fn open(path: &Path) -> Result<Self, BundleError> {
        let (drive, parts) = root_parts(path)?;
        let drive_root = format!("{drive}:\\\0").encode_utf16().collect::<Vec<_>>();
        if unsafe { GetDriveTypeW(drive_root.as_ptr()) } != 3 {
            return Err(BundleError::Protection);
        }
        let trusted = TrustedSids::current()?;
        let mut ancestors = vec![open_at(
            null_mut(),
            OsStr::new(&format!("\\??\\{drive}:\\")),
        )?];
        inspect(&ancestors[0], true)?;
        for part in parts {
            let parent = ancestors.last().ok_or(BundleError::Path)?;
            let child = open_at(parent.as_raw_handle(), OsStr::new(part))?;
            inspect(&child, true)?;
            ancestors.push(child);
        }
        let root = ancestors.last().ok_or(BundleError::Path)?;
        protected(root, &trusted)?;
        Ok(Self { ancestors, trusted })
    }

    pub(super) fn read(&self, relative: &Path, max: u64) -> Result<Vec<u8>, BundleError> {
        if max == 0 || max > 64 * 1024 * 1024 {
            return Err(BundleError::Bounds);
        }
        // Preserve the parent's portable spelling policy, then reject Windows
        // aliases (ADS, reserved devices, trailing dots/spaces) before any open.
        super::normal_components(relative)?;
        let spelling = relative.to_str().ok_or(BundleError::Path)?;
        let parts = spelling
            .split('/')
            .map(component)
            .collect::<Result<Vec<_>, _>>()?;
        let root = self.ancestors.last().ok_or(BundleError::Path)?;
        protected(root, &self.trusted)?;
        let mut held = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let parent = held.last().unwrap_or(root);
            let child = open_at(parent.as_raw_handle(), OsStr::new(part))?;
            inspect(&child, i + 1 < parts.len())?;
            protected(&child, &self.trusted)?;
            held.push(child);
        }
        let file = held.last().ok_or(BundleError::Path)?;
        let before = inspect(file, false)?;
        let length = (u64::from(before.size_high) << 32) | u64::from(before.size_low);
        if length == 0 || length > max {
            return Err(BundleError::Bounds);
        }
        let mut bytes = Vec::new();
        file.take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| BundleError::Read)?;
        let after = inspect(file, false)?;
        protected(file, &self.trusted)?;
        if bytes.len() as u64 != length
            || before.size_high != after.size_high
            || before.size_low != after.size_low
            || before.write != after.write
            || before.volume != after.volume
            || before.index_high != after.index_high
            || before.index_low != after.index_low
        {
            return Err(BundleError::Read);
        }
        Ok(bytes)
    }
}

fn component(value: &str) -> Result<&str, BundleError> {
    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.starts_with("._")
        || value.ends_with(['.', ' '])
        || value
            .chars()
            .any(|c| c.is_control() || "\\/:<>\"|?*".contains(c))
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|n| {
                matches!(
                    n,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
    {
        return Err(BundleError::Path);
    }
    Ok(value)
}

fn root_parts(path: &Path) -> Result<(char, Vec<&str>), BundleError> {
    let text = path.to_str().ok_or(BundleError::Path)?;
    let bytes = text.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
    {
        return Err(BundleError::Path);
    }
    let parts = text[3..]
        .split(['\\', '/'])
        .map(component)
        .collect::<Result<Vec<_>, _>>()?;
    if parts.len() > 64 {
        return Err(BundleError::Bounds);
    }
    Ok((char::from(bytes[0]), parts))
}

fn open_at(parent: Handle, name: &OsStr) -> Result<File, BundleError> {
    let mut wide = name.encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) || wide.len() > 32766 {
        return Err(BundleError::Path);
    }
    let mut string = UnicodeString {
        length: (wide.len() * 2) as u16,
        maximum_length: (wide.len() * 2) as u16,
        buffer: wide.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: parent,
        name: &mut string,
        attributes: 0x40,
        descriptor: null_mut(),
        qos: null_mut(),
    };
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let mut handle = null_mut();
    // SAFETY: exact counted UTF-16 name, borrowed parent and writable out fields.
    // FILE_OPEN only; no creation, delete or write access. OPEN_REPARSE_POINT
    // opens the link itself; inspect rejects it before descent or data reads.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            0x0012_0089,
            &mut attributes,
            &mut status,
            null(),
            0,
            1,
            1,
            0x0020_0020,
            null(),
            0,
        )
    };
    if result != 0 || handle.is_null() || handle as isize == -1 {
        if !handle.is_null() && handle as isize != -1 {
            unsafe {
                CloseHandle(handle);
            }
        }
        return Err(BundleError::Path);
    }
    // SAFETY: unique successful native handle ownership transfers exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn inspect(file: &File, directory: bool) -> Result<FileInformation, BundleError> {
    let handle = file.as_raw_handle();
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let mut device = DeviceInformation {
        device_type: 0,
        characteristics: 0,
    };
    // Locality belongs to this exact handle, not a drive-letter lookup that
    // could select a different mapping before the native open.
    if unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &mut status,
            &mut device,
            size_of::<DeviceInformation>() as u32,
            4,
        )
    } != 0
        || status.information != size_of::<DeviceInformation>()
        || device.device_type != 7
        || device.characteristics & 0x10 != 0
    {
        return Err(BundleError::Protection);
    }
    let mut information: FileInformation = unsafe { zeroed() };
    if unsafe { GetFileType(handle) } != 1
        || unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
        || information.attributes & 0x400 != 0
        || (information.attributes & 0x10 != 0) != directory
        || (!directory && information.links != 1)
    {
        return Err(BundleError::Protection);
    }
    Ok(information)
}

struct TrustedSids {
    user: Vec<usize>,
    system: [u32; 17],
    admins: [u32; 17],
}
impl TrustedSids {
    fn current() -> Result<Self, BundleError> {
        let mut raw = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) } == 0 {
            return Err(BundleError::Protection);
        }
        let token = Token(raw);
        let mut needed = 0;
        unsafe {
            GetTokenInformation(token.0, 1, null_mut(), 0, &mut needed);
        }
        if !(size_of::<usize>() as u32..=4096).contains(&needed) {
            return Err(BundleError::Protection);
        }
        // usize backing preserves the native TOKEN_USER pointer alignment.
        let mut user = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        if unsafe { GetTokenInformation(token.0, 1, user.as_mut_ptr().cast(), needed, &mut needed) }
            == 0
        {
            return Err(BundleError::Protection);
        }
        let mut result = Self {
            user,
            system: [0; 17],
            admins: [0; 17],
        };
        for (kind, bytes) in [(22, &mut result.system), (26, &mut result.admins)] {
            let mut length = 68;
            if unsafe {
                CreateWellKnownSid(kind, null_mut(), bytes.as_mut_ptr().cast(), &mut length)
            } == 0
            {
                return Err(BundleError::Protection);
            }
        }
        Ok(result)
    }
    fn contains(&self, sid: Handle) -> bool {
        // TOKEN_USER begins with SID_AND_ATTRIBUTES, whose first field is PSID.
        let user = self.user[0] as Handle;
        !sid.is_null()
            && unsafe { IsValidSid(sid) } != 0
            && [
                user,
                self.system.as_ptr().cast_mut().cast(),
                self.admins.as_ptr().cast_mut().cast(),
            ]
            .iter()
            .any(|trusted| unsafe { EqualSid(sid, *trusted) } != 0)
    }
}

fn protected(file: &File, trusted: &TrustedSids) -> Result<(), BundleError> {
    let handle = file.as_raw_handle();
    let mut flags = 0;
    if unsafe {
        GetVolumeInformationByHandleW(
            handle,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    } == 0
        || flags & 8 == 0
    {
        return Err(BundleError::Protection);
    }
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            handle,
            1,
            5,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(BundleError::Protection);
    }
    let descriptor = SecurityDescriptor(descriptor);
    if descriptor.0.is_null()
        || unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0
        || !trusted.contains(owner)
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(BundleError::Protection);
    }
    let count = unsafe { (*dacl).count };
    let start = dacl as usize;
    let end = start
        .checked_add(unsafe { (*dacl).size } as usize)
        .ok_or(BundleError::Protection)?;
    for i in 0..count {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, u32::from(i), &mut ace) } == 0 || ace.is_null() {
            return Err(BundleError::Protection);
        }
        let pointer = ace as usize;
        if pointer < start + size_of::<Acl>() || pointer.checked_add(4).is_none_or(|v| v > end) {
            return Err(BundleError::Protection);
        }
        // SAFETY: GetAce + validated ACL/extent bounds the header and ACE bytes.
        let header = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), 4) };
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < 4 || pointer.checked_add(length).is_none_or(|v| v > end) {
            return Err(BundleError::Protection);
        }
        if header[1] & 8 != 0 {
            continue;
        } // Inherit-only does not grant this object access.
        if header[0] == 1 {
            continue;
        } // A deny ACE cannot grant write authority.
        if header[0] != 0 || length < 16 {
            return Err(BundleError::Protection);
        }
        let bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), length) };
        let mask = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        // Validate SID extent before asking Windows to inspect its subauthorities.
        if 8 + 8 + usize::from(bytes[9]) * 4 > length {
            return Err(BundleError::Protection);
        }
        let sid = unsafe { ace.cast::<u8>().add(8).cast::<c_void>() };
        if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize + 8 > length {
            return Err(BundleError::Protection);
        }
        // Data/append/EA/attribute/delete-child, DELETE, WRITE_DAC, WRITE_OWNER,
        // GENERIC_WRITE and GENERIC_ALL. Read/list/execute grants are harmless.
        if mask & 0x500d_0156 != 0 && !trusted.contains(sid) {
            return Err(BundleError::Protection);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut Handle,
            size: *mut u32,
        ) -> i32;
        fn SetFileSecurityW(path: *const u16, information: u32, descriptor: Handle) -> i32;
    }
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "synergy-reader-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            let result = Self(path);
            set_acl(&result.0, false);
            result
        }
        fn file(&self) -> PathBuf {
            let path = self.0.join("public.bin");
            std::fs::write(&path, b"synthetic public fixture").unwrap();
            set_acl(&path, false);
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn set_acl(path: &Path, untrusted_write: bool) {
        let trusted = TrustedSids::current().unwrap();
        let mut sid_text = null_mut();
        assert_ne!(
            unsafe { ConvertSidToStringSidW(trusted.user[0] as Handle, &mut sid_text) },
            0
        );
        let allocated = SecurityDescriptor(sid_text.cast());
        let mut len = 0;
        while unsafe { *sid_text.add(len) } != 0 {
            len += 1;
            assert!(len < 256);
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, len) }).unwrap();
        drop(allocated);
        let extra = if untrusted_write { "(A;;GW;;;WD)" } else { "" };
        let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid}){extra}\0")
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let descriptor = SecurityDescriptor(descriptor);
        let path = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        assert_ne!(
            unsafe { SetFileSecurityW(path.as_ptr(), 0x8000_0004, descriptor.0) },
            0
        );
    }

    #[test]
    fn rejects_windows_aliases_before_open() {
        for name in [
            "",
            ".",
            "..",
            "data.",
            "data ",
            "a:b",
            "CON",
            "nul.json",
            "COM1",
            "LPT².txt",
            "a\\b",
            "a/b",
            "a?b",
            "._data",
            "a\0b",
        ] {
            assert_eq!(component(name), Err(BundleError::Path), "{name:?}");
        }
    }
    #[test]
    fn rejects_nonlocal_or_normalized_root_spellings() {
        for path in [
            "C:relative",
            "C:\\",
            "\\\\server\\share\\root",
            "\\\\?\\C:\\root",
            "C:\\root\\..\\other",
            "C:\\root\\.\\other",
            "C:\\root\\",
            "C:\\root:stream",
        ] {
            assert!(root_parts(Path::new(path)).is_err(), "{path:?}");
        }
        assert_eq!(
            root_parts(Path::new("C:\\ProgramData\\Synergy")).unwrap().1,
            ["ProgramData", "Synergy"]
        );
    }
    #[test]
    fn accepts_ordinary_case_preserving_components() {
        for name in [
            "received-Genesis.bin",
            "profiles_R1.json",
            "com10.txt",
            "native",
        ] {
            assert_eq!(component(name), Ok(name));
        }
    }

    #[test]
    fn native_protected_read_and_size_bound() {
        let fixture = Fixture::new();
        fixture.file();
        let root = ProtectedRoot::open(&fixture.0).unwrap();
        assert_eq!(
            root.read(Path::new("public.bin"), 1024).unwrap(),
            b"synthetic public fixture"
        );
        assert_eq!(
            root.read(Path::new("public.bin"), 2),
            Err(BundleError::Bounds)
        );
    }

    #[test]
    fn native_rejects_untrusted_root_and_file_acl() {
        let fixture = Fixture::new();
        let file = fixture.file();
        set_acl(&file, true);
        let root = ProtectedRoot::open(&fixture.0).unwrap();
        assert_eq!(
            root.read(Path::new("public.bin"), 1024),
            Err(BundleError::Protection)
        );
        drop(root);
        set_acl(&fixture.0, true);
        assert!(matches!(
            ProtectedRoot::open(&fixture.0),
            Err(BundleError::Protection)
        ));
    }

    #[test]
    fn native_rejects_hard_links_and_holds_root_against_rename() {
        let fixture = Fixture::new();
        let file = fixture.file();
        std::fs::hard_link(file, fixture.0.join("alias.bin")).unwrap();
        let root = ProtectedRoot::open(&fixture.0).unwrap();
        assert_eq!(
            root.read(Path::new("public.bin"), 1024),
            Err(BundleError::Protection)
        );
        let renamed = fixture.0.with_extension("renamed");
        assert!(std::fs::rename(&fixture.0, &renamed).is_err());
        drop(root);
        assert!(!renamed.exists());
    }

    #[test]
    fn native_rejects_empty_file_and_directory_as_file() {
        let fixture = Fixture::new();
        let file = fixture.file();
        std::fs::write(&file, []).unwrap();
        std::fs::create_dir(fixture.0.join("directory")).unwrap();
        set_acl(&fixture.0.join("directory"), false);
        let root = ProtectedRoot::open(&fixture.0).unwrap();
        assert_eq!(
            root.read(Path::new("public.bin"), 1024),
            Err(BundleError::Bounds)
        );
        assert_eq!(
            root.read(Path::new("directory"), 1024),
            Err(BundleError::Protection)
        );
    }

    #[test]
    fn native_rejects_directory_reparse_root_and_descent() {
        let fixture = Fixture::new();
        let outside = Fixture::new();
        outside.file();
        let link = fixture.0.join("link");
        // This native security test requires Windows symlink test privileges;
        // inability to create the attack fixture is a failure, never a skip.
        std::os::windows::fs::symlink_dir(&outside.0, &link).unwrap();
        assert!(matches!(
            ProtectedRoot::open(&link),
            Err(BundleError::Protection)
        ));
        let root = ProtectedRoot::open(&fixture.0).unwrap();
        assert_eq!(
            root.read(Path::new("link/public.bin"), 1024),
            Err(BundleError::Protection)
        );
    }

    #[test]
    fn native_rejects_file_with_existing_writer() {
        let fixture = Fixture::new();
        let path = fixture.file();
        let writer = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let root = ProtectedRoot::open(&fixture.0).unwrap();
        assert!(root.read(Path::new("public.bin"), 1024).is_err());
        drop(writer);
        assert_eq!(
            root.read(Path::new("public.bin"), 1024).unwrap(),
            b"synthetic public fixture"
        );
    }
}
