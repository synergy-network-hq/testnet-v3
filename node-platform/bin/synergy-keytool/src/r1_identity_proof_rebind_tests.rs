//! Fixed public synthetic parser/refusal tests only. No authorization token is
//! constructed, no actual credential is loaded, and no signing/RNG is invoked.
use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn path() -> Self {
        Self(std::env::temp_dir().join(format!(
            "PUBLIC-SYNTHETIC-keytool-proof-rebind-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        )))
    }
    fn create() -> Self {
        let t = Self::path();
        std::fs::create_dir(&t.0).unwrap();
        t
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

#[test]
fn missing_native_receipt_never_creates_custody_or_loads_a_provider() {
    let temp = Temp::path();
    assert!(!temp.0.exists());
    let missing = temp.0.join("receipt.json");
    assert!(prove(&temp.0, &missing, &"01".repeat(32)).is_err());
    assert!(rebind(&temp.0, &missing, &"01".repeat(32)).is_err());
    assert!(!temp.0.exists());
}
#[test]
fn malformed_original_request_refuses_before_any_receipt_or_custody_access() {
    let temp = Temp::path();
    for request in [
        "01".repeat(31),
        "AA".repeat(32),
        format!("{}\n", "01".repeat(32)),
        "PUBLIC-TEST-NOT-A-DIGEST".into(),
    ] {
        assert!(prove(&temp.0, &temp.0.join("receipt"), &request).is_err());
        assert!(rebind(&temp.0, &temp.0.join("receipt"), &request).is_err());
    }
    assert!(!temp.0.exists());
}
#[test]
fn caller_json_is_never_a_protected_native_grant_and_never_creates_journal_state() {
    let temp = Temp::create();
    let path = temp.0.join("receipt.json");
    let public=br#"{"purpose":"PUBLIC_SYNTHETIC_INVALID_GRANT_ONLY","approved":true,"ceremony_authorized":true,"production":false,"request":{"operation":"r1_identity_prove"}}"#;
    std::fs::write(&path, public).unwrap();
    assert!(prove(&temp.0, &path, &"01".repeat(32)).is_err());
    assert!(rebind(&temp.0, &path, &"01".repeat(32)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), public);
    assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 1);
}
#[cfg(unix)]
#[test]
fn symlink_receipt_is_rejected_without_reading_or_mutating_its_public_target() {
    let temp = Temp::create();
    let target = temp.0.join("PUBLIC-SYNTHETIC-target.json");
    std::fs::write(&target, b"PUBLIC-SYNTHETIC-NOT-A-GRANT").unwrap();
    let link = temp.0.join("receipt.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(prove(&temp.0, &link, &"01".repeat(32)).is_err());
    assert!(rebind(&temp.0, &link, &"01".repeat(32)).is_err());
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"PUBLIC-SYNTHETIC-NOT-A-GRANT"
    );
    assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 2);
}
#[cfg(unix)]
#[test]
fn fixed_public_factor_parser_is_exact_bounded_and_never_a_capability() {
    let valid = b"0123456789abcdef".repeat(4);
    let factor = read_factor_bytes(&mut std::io::Cursor::new(valid.clone())).unwrap();
    assert_eq!(factor.as_bytes(), valid);
    for bad in [
        vec![],
        vec![b'0'; 63],
        vec![b'0'; 65],
        vec![b'G'; 64],
        vec![b'0'; 64].into_iter().chain([b'\n']).collect(),
    ] {
        assert!(read_factor_bytes(&mut std::io::Cursor::new(bad)).is_err());
    }
    let mut cursor = std::io::Cursor::new(vec![b'0'; 10000]);
    assert!(read_factor_bytes(&mut cursor).is_err());
    assert_eq!(cursor.position(), 65);
}
#[cfg(unix)]
#[test]
fn partial_factor_read_failure_returns_no_material_and_missing_scope_creates_nothing() {
    struct Broken(bool);
    impl std::io::Read for Broken {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.0 {
                return Err(std::io::Error::other("PUBLIC-SYNTHETIC-READ-FAULT"));
            }
            self.0 = true;
            buffer[..8].fill(b'0');
            Ok(8)
        }
    }
    assert!(read_factor_bytes(&mut Broken(false)).is_err());
    let temp = Temp::path();
    assert!(unlock_factor(&temp.0, &[0; 64], 1).is_err());
    assert!(unlock_factor(&temp.0, &[1; 64], 0).is_err());
    assert!(!temp.0.exists());
}

#[test]
fn exact_cli_arity_and_unrecognized_commands_never_load_provider_or_claim_completion() {
    for command in [PROVE_COMMAND, REBIND_COMMAND] {
        for args in [
            vec![command.to_owned()],
            vec![
                command.to_owned(),
                "root".into(),
                "receipt".into(),
                "01".repeat(32),
                "--approved".into(),
            ],
        ] {
            assert!(dispatch(&args).is_err());
        }
    }
    assert!(dispatch(&["generate-other-unowned-command".into()])
        .unwrap()
        .is_none());
}

#[cfg(unix)]
#[test]
fn untrusted_fifo_receipt_cannot_block_before_native_preflight() {
    use std::os::unix::ffi::OsStrExt;
    let temp = Temp::create();
    let path = temp.0.join("PUBLIC-SYNTHETIC-receipt-fifo");
    let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
    for rebind_operation in [false, true] {
        let (sender, receiver) = std::sync::mpsc::channel();
        let root = temp.0.clone();
        let path = path.clone();
        let worker = std::thread::spawn(move || {
            let refused = if rebind_operation {
                rebind(&root, &path, &"01".repeat(32)).is_err()
            } else {
                prove(&root, &path, &"01".repeat(32)).is_err()
            };
            sender.send(refused).unwrap();
        });
        assert!(receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("untrusted FIFO must not block native preflight"));
        worker.join().unwrap();
    }
    assert_eq!(std::fs::read_dir(&temp.0).unwrap().count(), 1);
}
