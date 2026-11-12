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
    for variant in ["mldsa65", "mldsa87", "fndsa1024", "mlkem768", "mlkem1024"] {
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
        synergy_address_engine::apqe::native_manifest::validator_engine(report_path, hash)
    }?;
    Ok(Arc::new(Mutex::new(engine)))
}
