//! Shared explicit native-provider loader for node and offline tooling.
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use synergy_address_engine::apqe::crypto_engine::CryptoEngine;

fn trusted_file(path: &Path, maximum: u64) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err("APQE native input must be a bounded absolute regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("APQE native input must not be writable by group or others".into());
        }
        let parent = path.parent().ok_or("APQE input directory absent")?;
        let directory = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.permissions().mode() & 0o022 != 0
        {
            return Err(
                "APQE native input directory must be a protected non-symlink directory".into(),
            );
        }
    }
    Ok(())
}
/// Loads only an explicitly authenticated native report and its pinned artifacts.
/// The operator must keep files, containing directories and loader dependencies
/// immutable throughout engine lifetime. The supplied digest is a trust input,
/// not something this function discovers or authenticates on the operator's behalf.
pub fn load_authenticated_native_engine(
    report_path: &Path,
    authenticated_report_sha256: &str,
) -> Result<Arc<Mutex<CryptoEngine>>, String> {
    load_selected_engine(report_path, authenticated_report_sha256, false)
}
/// Current R1 public verification needs exactly ML-DSA-65/87 and ML-KEM-1024.
/// Historical algorithms are not silently required, enabled or substituted.
/// The same independent authentication and immutable native-code contract as
/// load_authenticated_native_engine applies. Loading conveys no signing,
/// creation, current membership, execution or commissioning authority.
pub fn load_authenticated_r1_verification_engine(
    report_path: &Path,
    authenticated_report_sha256: &str,
) -> Result<Arc<Mutex<CryptoEngine>>, String> {
    #[cfg(not(unix))]
    {
        let _ = (report_path, authenticated_report_sha256);
        return Err(
            "current R1 protected native loading requires a qualified platform file/ACL bridge"
                .into(),
        );
    }
    #[cfg(unix)]
    load_selected_engine(report_path, authenticated_report_sha256, true)
}
fn load_selected_engine(
    report_path: &Path,
    authenticated_report_sha256: &str,
    current_r1: bool,
) -> Result<Arc<Mutex<CryptoEngine>>, String> {
    let digest = authenticated_report_sha256;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("APQE report digest requires exactly 32 bytes of lowercase hex".into());
    }
    trusted_file(report_path, 1024 * 1024)?;
    let mut hash = [0; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b =
            u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).map_err(|_| "invalid APQE digest")?;
    }
    // Canonical local artifact names are enforced independently by the APQE report loader.
    let directory = report_path.parent().ok_or("APQE directory absent")?;
    let variants: &[&str] = if current_r1 {
        &["mldsa65", "mldsa87", "mlkem1024"]
    } else {
        &["mldsa65", "mldsa87", "fndsa1024", "mlkem768", "mlkem1024"]
    };
    for variant in variants {
        trusted_file(
            &directory.join(format!(
                "libaegis{variant}.{}",
                std::env::consts::DLL_EXTENSION
            )),
            64 * 1024 * 1024,
        )?;
    }
    // SAFETY: explicit operator-authenticated report digest pins native bytes; the
    // protected local files/directories above must be held immutable by the operator
    // for node lifetime, including their OS-loader dependencies. No discovered code.
    let engine = unsafe {
        if current_r1 {
            synergy_address_engine::apqe::native_manifest::received_r1_verification_engine(
                report_path,
                hash,
            )
        } else {
            synergy_address_engine::apqe::native_manifest::validator_engine(report_path, hash)
        }
    }?;
    Ok(Arc::new(Mutex::new(engine)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_r1_loader_rejects_unpinned_code_before_access() {
        for bad in ["", "01", &"F".repeat(64), &"0".repeat(65)] {
            assert!(load_authenticated_r1_verification_engine(
                Path::new("relative-must-not-open"),
                bad
            )
            .is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn writable_and_symlink_reports_reject_before_loading_native_code() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let p = std::env::temp_dir().join(format!(
            "synergy-native-r1-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        let temp = Temp(p);
        std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let report = temp.0.join("report.json");
        std::fs::write(&report, b"{}").unwrap();
        std::fs::set_permissions(&report, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            load_authenticated_r1_verification_engine(&report, &"0".repeat(64))
                .err().unwrap()
                .contains("writable")
        );
        std::fs::set_permissions(&report, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.0.join("link.json");
        symlink(&report, &link).unwrap();
        assert!(load_authenticated_r1_verification_engine(&link, &"0".repeat(64)).is_err());
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    #[ignore = "requires exact canonical Darwin public native validation artifacts"]
    fn current_three_provider_report_verifies_actual_public_signature() {
        let report=Path::new("/Volumes/PortableSSD/02-Synergy-Network/24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation/build-report.json");
        let pin = "1c7851d11260c880aced3fbad8aadc7b68e1f02a379d8efc8846d65a7c89af9c";
        let engine = load_authenticated_r1_verification_engine(report, pin).unwrap();
        let path=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_ordinary_transaction_public.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(v["production_import_permitted"], false);
        assert_eq!(v["chain_id"].as_u64(), Some(u64::MAX - 1));
        let decode = |v: &serde_json::Value| {
            v.as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let key = decode(&v["controller_public_keys_hex"][0]);
        let message = decode(&v["exact_message_hex"]);
        let signature = decode(&v["proofs"][0]["signature_hex"]);
        assert!(engine
            .lock()
            .unwrap()
            .verify(
                synergy_address_engine::types::Algorithm::MlDsa87,
                &key,
                &message,
                &signature,
                synergy_address_engine::apqe::provider::SignOptions::Pure {
                    context: b"QACE/TRANSACTION/R1"
                }
            )
            .unwrap());
        assert!(load_authenticated_r1_verification_engine(report, &"0".repeat(64)).is_err());
        // Exact historical wrapper still requires its historical complete set.
        assert!(load_authenticated_native_engine(report, pin).is_err());
    }
}
