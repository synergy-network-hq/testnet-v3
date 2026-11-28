//! Existing native controller → protected receipt → durable R1 custody owner.
//! No renderer secrets, direct CLI approval boolean or independent issuer.
#[cfg(unix)]
pub fn create(
    root: &std::path::Path,
    receipt: &std::path::Path,
    request_sha256: &str,
) -> Result<serde_json::Value, String> {
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        os::unix::fs::OpenOptionsExt,
    };
    use synergy_address::r1_custody::{CustodyReservationResult, NativeCustodyJournal};
    use synergy_address_engine::apqe::{
        managed_creation::VerifiedManagedCreationAuthorization, Primitives, SecretBytes,
    };
    let receipt_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(receipt)
        .map_err(|_| "Protected native receipt unavailable")?;
    let cap =
        VerifiedManagedCreationAuthorization::from_controller_receipt(root, receipt, receipt_fd)
            .map_err(|_| "Native R1 creation authorization refused")?;
    if hex(&cap.native_request_digest()) != request_sha256 {
        return Err("Original native request differs".into());
    }
    let mut journal = NativeCustodyJournal::from_managed_creation(&cap)
        .map_err(|_| "Native R1 custody journal unavailable")?;
    let slot = cap.slot_ref().to_owned();
    let generation = cap.key_generation();
    let pending = match journal
        .reserve_managed(&cap)
        .map_err(|_| "Native R1 generation conflict; reconcile before retrying")?
    {
        CustodyReservationResult::AlreadySealed(pending) => pending,
        CustodyReservationResult::Reserved(reservation) => {
            let lease = journal
                .begin_generation(&reservation)
                .map_err(|_| "Native generation already dispatched or ambiguous")?;
            let (record_path, record_fd) = journal
                .managed_generation_record(&lease)
                .map_err(|_| "Durable native generation lease unavailable")?;
            let report = root.join("lib/apqe/build-report.json");
            let report_pin = cap.provider_report_sha256();
            // SAFETY: private cap independently authenticated installed manifest,
            // protected native report pin and exact immutable package inventory.
            let engine = unsafe {
                synergy_address_engine::apqe::native_manifest::managed_creation_engine(
                    &report, report_pin,
                )
            }
            .map_err(|_| "Qualified current R1 native provider unavailable")?;
            // Existing private native custody owns this factor. It never leaves
            // the platform root and cannot confer activation/current authority.
            let directory = root.join("keys/apqe/r1/unlock");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .or_else(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .map_err(|_| "Native unlock directory unavailable")?;
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            let m = std::fs::symlink_metadata(&directory)
                .map_err(|_| "Native unlock directory unavailable")?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
                return Err("Native unlock protection differs".into());
            }
            let path = directory.join(format!("{}-{}.factor", hex(slot.as_bytes()), generation));
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| "Prior native factor requires reconciliation")?;
            // First entropy occurs only after consumed native grant+durable CAS.
            let mut entropy = [0u8; 32];
            Primitives
                .random_bytes(&mut entropy)
                .map_err(|_| "Native secure randomness unavailable")?;
            let factor = SecretBytes::from_bytes(hex(&entropy).into_bytes());
            // Wipe the stack seed as soon as its zeroizing representation exists.
            entropy.fill(0);
            output
                .write_all(factor.as_bytes())
                .and_then(|_| output.sync_all())
                .map_err(|_| "Native factor persistence failed")?;
            File::open(&directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| "Native factor directory persistence failed")?;
            let pass = std::str::from_utf8(factor.as_bytes())
                .map_err(|_| "Native factor encoding failed")?;
            let material = cap
                .generate_and_seal(&engine, &record_path, record_fd, pass)
                .map_err(|_| "Authorized native creation failed; generation remains fenced")?;
            journal
                .seal_managed_generated(&lease, material)
                .map_err(|_| {
                    "Native sealed generation CAS failed; reconcile without regeneration"
                })?
        }
    };
    let key = pending.public_key_record();
    Ok(
        serde_json::json!({"schema":"synergy-r1-managed-sealed-key-v1","stage":"sealed_pending","request_sha256":request_sha256,"slot_ref":slot,"key_generation":generation.to_string(),"public_key_record":{"role":key.role,"algorithm":key.algorithm,"key_generation":key.key_generation.to_string(),"full_public_key_hex":hex(key.full_public_key)},"envelope_commitment_hex":hex(&pending.envelope_commitment()),"runtime_authority_granted":false}),
    )
}
#[cfg(not(unix))]
pub fn create(
    _: &std::path::Path,
    _: &std::path::Path,
    _: &str,
) -> Result<serde_json::Value, String> {
    Err("Native R1 platform protection is not qualified".into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn public_status_of_absent_root_cannot_generate_or_create_state() {
        let root=std::env::temp_dir().join(format!("synergy-no-r1-status-root-{}",std::process::id()));
        assert!(!root.exists());
        let result=super::inspect(&root,"PUBLIC-ROOT-SLOT-1",&"01".repeat(32)).unwrap();
        assert_eq!(result["stage"],"absent");assert_eq!(result["runtime_authority_granted"],false);
        assert!(!root.exists());
    }
    #[test]
    fn missing_native_receipt_fails_without_loading_provider_or_creating_root() {
        let root =
            std::env::temp_dir().join(format!("synergy-no-native-grant-{}", std::process::id()));
        assert!(!root.exists());
        assert!(super::create(&root, &root.join("receipt.json"), &"00".repeat(32)).is_err());
        assert!(!root.exists());
    }
}

pub fn inspect(
    root: &std::path::Path,
    slot: &str,
    request_sha256: &str,
) -> Result<serde_json::Value, String> {
    if request_sha256.len() != 64
        || !request_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Exact original native request SHA256 required".into());
    }
    let mut request = [0u8; 32];
    for (i, b) in request.iter_mut().enumerate() {
        *b = u8::from_str_radix(&request_sha256[2 * i..2 * i + 2], 16)
            .map_err(|_| "Request digest differs")?;
    }
    use synergy_address::r1_custody::{CustodyJournalError, NativeCustodyJournal};
    let mut out = serde_json::json!({"schema":"synergy-r1-managed-key-status-v1","slot_ref":slot,"original_request_sha256":request_sha256,"runtime_authority_granted":false});
    match NativeCustodyJournal::inspect_managed_pending(root, slot, &request) {
        Ok(None) => out["stage"] = "absent".into(),
        Err(CustodyJournalError::AmbiguousGeneration) => {
            out["stage"] = "generating_requires_reconciliation".into()
        }
        Err(_) => {
            return Err(
                "Native R1 public custody observation refused; reconcile protected state".into(),
            )
        }
        Ok(Some(pending)) => {
            let key = pending.public_key_record();
            out["stage"] = "sealed_pending".into();
            out["key_generation"] = pending.key_generation().to_string().into();
            out["public_key_record"] = serde_json::json!({"role":key.role,"algorithm":key.algorithm,"key_generation":key.key_generation.to_string(),"full_public_key_hex":hex(key.full_public_key)});
            out["envelope_commitment_hex"] = hex(&pending.envelope_commitment()).into();
        }
    }
    Ok(out)
}
