//! Existing native controller → protected receipt → durable R1 custody owner.
//! No renderer secrets, direct CLI approval boolean or independent issuer.
#[path="r1_identity_proof_rebind.rs"]
pub(crate) mod proof_rebind;
/// Public semantic inspection only. This command cannot open a platform root,
/// consume a grant, load a provider or reserve a generation.
pub fn inspect_parameters(parameters: &str) -> Result<serde_json::Value, String> {
    if parameters.is_empty() || parameters.len() > 16 * 1024 {
        return Err("Bounded current R1 creation parameters required".into());
    }
    use synergy_address_engine::apqe::managed_creation::{
        inspect_creation_parameters, ManagedCreationParameters,
    };
    let parameters: ManagedCreationParameters = serde_json::from_str(parameters)
        .map_err(|_| "Exact current R1 creation parameters required")?;
    if parameters.creation_scope_frame_hex.len() > 8192 {
        return Err("Bounded current R1 creation scope required".into());
    }
    let inspection = inspect_creation_parameters(&parameters)
        .map_err(|_| "Canonical current R1 creation scope differs")?;
    Ok(serde_json::json!({
        "schema":"synergy-r1-managed-creation-preview-v1",
        "inspection":inspection,
        "runtime_authority_granted":false
    }))
}

#[cfg(unix)]
pub fn create(
    root: &std::path::Path,
    receipt: &std::path::Path,
    request_sha256: &str,
) -> Result<serde_json::Value, String> {
    use std::{
        fs::{File, OpenOptions},
        io::{Seek, Write},
        os::unix::fs::OpenOptionsExt,
    };
    use synergy_address::r1_custody::{CustodyReservationResult, NativeCustodyJournal};
    use synergy_address_engine::apqe::{
        managed_creation::VerifiedManagedCreationAuthorization, Primitives, SecretBytes,
    };
    let expected_request = original_request_digest(request_sha256)?;
    let mut receipt_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(receipt)
        .map_err(|_| "Protected native receipt unavailable")?;
    synergy_address_engine::apqe::managed_creation::preflight_controller_receipt(
        root,
        receipt,
        receipt_fd
            .try_clone()
            .map_err(|_| "Protected native receipt unavailable")?,
        expected_request,
    )
    .map_err(|_| "Native R1 receipt preflight refused")?;
    // APQE owns the receipt parser. Its by-value cloned descriptor shares this
    // open-file offset; restore it before final independent recheck/consumption.
    receipt_fd
        .rewind()
        .map_err(|_| "Native receipt offset unavailable")?;
    use crate::r1_identity_context::NativeContext;
    let context = crate::r1_identity_context::load(root)?;
    let cap = match &context {
        NativeContext::Runtime(genesis) => {
            VerifiedManagedCreationAuthorization::from_controller_receipt_for_runtime(
                root,
                receipt,
                receipt_fd,
                genesis.nic_approvals(),
                genesis.genesis_approvals(),
            )
        }
        NativeContext::Initial(nic) => {
            VerifiedManagedCreationAuthorization::from_controller_receipt_for_initial(
                root,
                receipt,
                receipt_fd,
                nic.approvals(),
            )
        }
        NativeContext::Formation(nic) => {
            VerifiedManagedCreationAuthorization::from_controller_receipt_for_formation(
                root,
                receipt,
                receipt_fd,
                nic.approvals(),
            )
        }
        NativeContext::Bootstrap => {
            VerifiedManagedCreationAuthorization::from_controller_receipt(root, receipt, receipt_fd)
        }
    }
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
            cap.ensure_current()
                .map_err(|_| "Native creation expired; generation remains fenced")?;
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
            // The full APQE scope binds the incarnation and avoids both slot
            // aliases across networks and NAME_MAX overflow for 120-byte slots.
            let path = directory.join(format!(
                "{}-{}.factor",
                hex(&cap.creation_scope_commitment()),
                generation
            ));
            cap.ensure_current()
                .map_err(|_| "Native creation expired; generation remains fenced")?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| "Prior native factor requires reconciliation")?;
            // First entropy occurs only after consumed native grant+durable CAS.
            let mut entropy = vec![0u8; 32];
            cap.ensure_current()
                .map_err(|_| "Native creation expired; generation remains fenced")?;
            let random = Primitives.random_bytes(&mut entropy);
            // Transfer ownership before checking the RNG result, so even a
            // partially filled failure buffer is wiped by the secret owner.
            let entropy = SecretBytes::from_bytes(entropy);
            random.map_err(|_| "Native secure randomness unavailable")?;
            cap.ensure_current()
                .map_err(|_| "Native creation expired; generation remains fenced")?;
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let factor = SecretBytes::from_bytes(
                entropy
                    .as_bytes()
                    .iter()
                    .flat_map(|byte| [HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])
                    .collect(),
            );
            cap.ensure_current()
                .map_err(|_| "Native creation expired; generation remains fenced")?;
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
pub(crate) fn original_request_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Exact original native request SHA256 required".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| "Request digest differs")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn semantic_preview_uses_apqe_decoder_and_never_grants_authority() {
        use synergy_address_engine::apqe::{
            custody_binding_r1::{
                CustodyCreationBinding, CustodyScope, RuntimeIdentityCreationPurpose,
            },
            network_birth_r1::ProfileRef,
            r1_framing::NetworkRef,
        };
        let binding = CustodyCreationBinding {
            scope: CustodyScope::RuntimeIdentityCreation {
                network: NetworkRef {
                    chain_id: synergy_address_engine::apqe::preparation::SYNTHETIC_CHAIN,
                    nic: [1; 64],
                },
                genesis_profile: ProfileRef {
                    name: "SYNERGY-GENESIS-R1",
                    revision: 1,
                },
                genesis_digest48: &[2; 48],
                activated_profile_set_commitment: &[3; 64],
                target_namespace: "synw",
                purpose: RuntimeIdentityCreationPurpose::AccountEnrollment,
                custody_object_ref: "PUBLIC-FRESH-ACCOUNT-OPERATION-1",
            },
            role: "D",
            algorithm: "ML-DSA-87",
            key_generation: 1,
            trust_domain: "PUBLIC-SYNTHETIC-ONLY",
        };
        let mut p = serde_json::json!({
            "release_id":"PUBLIC-TEST", "manifest_sha256":"01".repeat(32),
            "slot_ref":"PUBLIC-SLOT-1", "role":"D", "algorithm":"ML-DSA-87",
            "key_generation":"1", "operation_nonce_hex":"02".repeat(32),
            "creation_scope_frame_hex":super::hex(&binding.canonical_frame().unwrap()),
            "creation_scope_commitment_hex":super::hex(&binding.commitment().unwrap()),
            "provider_report_sha256":"04".repeat(32),
            "profile_catalog_commitment_hex":"03".repeat(64)
        });
        let preview = super::inspect_parameters(&p.to_string()).unwrap();
        assert_eq!(preview["runtime_authority_granted"], false);
        assert_eq!(preview["inspection"]["authority_granted"], false);
        assert_eq!(
            preview["inspection"]["scope"]["scope_kind"],
            "runtime_identity_creation"
        );
        assert_eq!(preview["inspection"]["scope"]["target_namespace"], "synw");
        assert_eq!(
            preview["inspection"]["scope"]["owner_raw48_hex"],
            serde_json::Value::Null
        );
        p["authorized"] = true.into();
        assert!(super::inspect_parameters(&p.to_string()).is_err());
        p.as_object_mut().unwrap().remove("authorized");
        p["creation_scope_commitment_hex"] = "ff".repeat(64).into();
        assert!(super::inspect_parameters(&p.to_string()).is_err());
        assert!(super::inspect_parameters(&" ".repeat(16 * 1024 + 1)).is_err());
    }
    #[test]
    fn public_status_of_absent_root_cannot_generate_or_create_state() {
        let root =
            std::env::temp_dir().join(format!("synergy-no-r1-status-root-{}", std::process::id()));
        assert!(!root.exists());
        let result = super::inspect(&root, "PUBLIC-ROOT-SLOT-1", &"01".repeat(32)).unwrap();
        assert_eq!(result["stage"], "absent");
        assert_eq!(result["runtime_authority_granted"], false);
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
    let request = original_request_digest(request_sha256)?;
    use synergy_address::r1_custody::{CustodyJournalError, NativeCustodyJournal};
    let mut out = serde_json::json!({"schema":"synergy-r1-managed-key-status-v1","slot_ref":slot,"original_request_sha256":request_sha256,"runtime_authority_granted":false});
    // A selected runtime is never searched through the bootstrap namespace.
    // A missing platform root has no selected context and cannot contain state.
    let context = match std::fs::symlink_metadata(root) {
        Ok(_) => crate::r1_identity_context::load(root)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            crate::r1_identity_context::NativeContext::Bootstrap
        }
        Err(_) => return Err("Protected native status context unavailable".into()),
    };
    let network = context.network();
    match NativeCustodyJournal::inspect_managed_pending_in_network(root, slot, &request, network) {
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
