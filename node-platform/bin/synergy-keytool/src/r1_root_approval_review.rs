//! Pure calculation over the exact staged public inputs. No grant, signature,
//! custody open, journal mutation or activation authority is returned.
use serde::Deserialize;
use std::path::{Path, PathBuf};
use synergy_address_engine::apqe::{
    managed_creation::root_approval_use::{self as approval, RootApprovalStage},
    HashAlgorithm, Primitives,
};
use synergy_genesis::r1::{
    formation::{FormationRegistration, Population},
    policy::{IndexedProof, KeyRecord, NodeRecord},
    received_bundle, stage_review,
};
use synergy_protocol_types::c14n02::Decoder;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    chain_id: String,
    nic_selection: synergy_config::R1NicSelection,
    root_index: u32,
    stage: RootApprovalStage,
    source: Option<Source>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    node_record_c14n02_hex: String,
    formation_key_c14n02_hex: String,
    registration_nonce_hex: String,
    key_possession_hex: String,
    controller_approvals: Vec<Proof>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    index: u32,
    signature_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FormationSource {
    population: String,
    registrations: Vec<Registration>,
}
fn bytes(s: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if s.len() > 2 * maximum
        || s.is_empty()
        || !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Bounded canonical public bytes required".into());
    }
    hex::decode(s).map_err(|_| "Canonical public bytes required".into())
}
fn hash(raw: &[u8]) -> Result<String, String> {
    Primitives
        .hash(HashAlgorithm::Sha256, raw)
        .map(hex::encode)
        .map_err(|_| "Public input digest unavailable".into())
}
fn read(root: &Path, path: &Path, max: u64) -> Result<Vec<u8>, String> {
    received_bundle::read_protected_managed_file(root, path, max)
        .map_err(|_| "Protected public review input unavailable".into())
}
#[cfg(unix)]
fn engine(
    root: &Path,
) -> Result<
    std::sync::Arc<std::sync::Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
    String,
> {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::geteuid() } != 0
        || !root.is_absolute()
        || root.canonicalize().ok().as_deref() != Some(root)
    {
        return Err("Protected native review root required".into());
    }
    for p in root.ancestors() {
        let m = std::fs::symlink_metadata(p).map_err(|_| "Native root unavailable")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("Native root protection differs".into());
        }
    }
    let package_bytes = read(root, Path::new("package.json"), 2 * 1024 * 1024)?;
    let package: serde_json::Value =
        serde_json::from_slice(&package_bytes).map_err(|_| "Native package differs")?;
    let install: serde_json::Value = serde_json::from_slice(&read(
        root,
        Path::new("installation.json"),
        2 * 1024 * 1024,
    )?)
    .map_err(|_| "Native installation differs")?;
    let policy: serde_json::Value = serde_json::from_slice(&read(
        root,
        Path::new("tmp/controller/policy.json"),
        2 * 1024 * 1024,
    )?)
    .map_err(|_| "Native policy differs")?;
    let release = package["release_id"]
        .as_str()
        .ok_or("Native release absent")?;
    let digest = hash(&package_bytes)?;
    if policy["root"] != root.to_string_lossy().as_ref()
        || policy["format"] != "synergy-nodenetwork-host-policy-v1"
        || policy["community_enrollment"] != false
        || install["root"] != policy["root"]
        || install["package_sha256"] != digest
        || install["package_files"] != package["files"]
        || policy["releases"][release]["manifest_sha256"] != digest
        || policy["releases"][release]["inventory_authenticated"] != true
    {
        return Err("Authenticated native review release unavailable".into());
    }
    let report = "lib/apqe/build-report.json";
    let report_pin = package["files"][report]
        .as_str()
        .ok_or("Native provider absent")?;
    if hash(&read(root, Path::new(report), 1024 * 1024)?)? != report_pin {
        return Err("Native provider pin differs".into());
    }
    for variant in ["mldsa65", "mldsa87", "mlkem1024"] {
        let name = format!(
            "lib/apqe/libaegis{variant}.{}",
            std::env::consts::DLL_EXTENSION
        );
        if package["files"][&name] != hash(&read(root, Path::new(&name), 64 * 1024 * 1024)?)? {
            return Err("Native provider inventory differs".into());
        }
    }
    synergy_aegis::load_authenticated_r1_verification_engine(&root.join(report), report_pin)
}
#[cfg(not(unix))]
fn engine(
    _: &Path,
) -> Result<
    std::sync::Arc<std::sync::Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
    String,
> {
    Err("Native root review platform unqualified".into())
}
pub(crate) fn review(root: &Path, parameters: &str) -> Result<serde_json::Value, String> {
    if parameters.is_empty() || parameters.len() > 65536 {
        return Err("Bounded exact root review required".into());
    }
    let request: Request =
        serde_json::from_str(parameters).map_err(|_| "Closed root review request required")?;
    let chain = request
        .chain_id
        .parse::<u64>()
        .map_err(|_| "Canonical review chain required")?;
    if chain == 0
        || chain.to_string() != request.chain_id
        || request.nic_selection.managed_root != root
    {
        return Err("Root review scope differs".into());
    }
    let (authority, catalog) =
        received_bundle::load_received_pinned_authority(&request.nic_selection, chain)
            .map_err(|_| "Prospective pinned birth unavailable")?;
    let plan = approval::inspect_approval_plan(&authority, request.root_index, &request.stage)
        .map_err(|_| "Actual root approval plan invalid")?;
    let n = authority.network();
    let profiles = authority.activated_profile_set_commitment();
    let source = match &request.source {
        Some(s) => {
            let b = read(root, &s.path, 4 * 1024 * 1024)?;
            if s.sha256.len() != 64 || hash(&b)? != s.sha256 {
                return Err("Exact staged source digest differs".into());
            }
            Some(b)
        }
        None => None,
    };
    let stage_source = match &request.stage {
        RootApprovalStage::Nic {} => {
            if source.is_some() {
                return Err("NIC review has no dependent stage source".into());
            }
            serde_json::json!({"kind":"PROSPECTIVE_PINNED_BIRTH","nic_hex":hex::encode(n.nic),"profile_catalog_commitment_hex":hex::encode(profiles)})
        }
        RootApprovalStage::Formation {
            registry_commitment_hex,
            input_commitment_hex,
        } => {
            let source: FormationSource = serde_json::from_slice(
                source
                    .as_deref()
                    .ok_or("Actual formation registrations required")?,
            )
            .map_err(|_| "Closed formation input required")?;
            let population = match source.population.as_str() {
                "conditional_five" => Population::ConditionalFive,
                "reference_seven" => Population::ReferenceSeven,
                _ => return Err("Exact formation population required".into()),
            };
            if source.registrations.len() > 7 {
                return Err("Formation population exceeds bound".into());
            }
            let provider = engine(root)?;
            let provider = provider
                .lock()
                .map_err(|_| "Native verification unavailable")?;
            catalog
                .validate_provider(&provider)
                .map_err(|_| "Native catalog/provider differs")?;
            let nic =
                received_bundle::load_received_nic_bundle(&request.nic_selection, chain, &provider)
                    .map_err(|_| "Genuine NIC required before formation review")?;
            let mut registrations = Vec::new();
            for r in source.registrations {
                let node_bytes = bytes(&r.node_record_c14n02_hex, 1024 * 1024)?;
                let mut d =
                    Decoder::new(&node_bytes, 1024 * 1024).map_err(|_| "Node input bounds")?;
                let node =
                    NodeRecord::decode_from(&mut d, n).map_err(|_| "Actual NodeRecord invalid")?;
                d.finish().map_err(|_| "Trailing NodeRecord input")?;
                let key_bytes = bytes(&r.formation_key_c14n02_hex, 16384)?;
                let mut d = Decoder::new(&key_bytes, 16384).map_err(|_| "Formation key bounds")?;
                let formation_key =
                    KeyRecord::decode_from(&mut d).map_err(|_| "Actual formation key invalid")?;
                d.finish().map_err(|_| "Trailing formation key")?;
                let registration_nonce = bytes(&r.registration_nonce_hex, 32)?
                    .try_into()
                    .map_err(|_| "Exact registration nonce required")?;
                if r.controller_approvals.len() > 32 {
                    return Err("Controller proof bound exceeded".into());
                }
                let controller_approvals = r
                    .controller_approvals
                    .into_iter()
                    .map(|p| {
                        Ok(IndexedProof {
                            index: p.index,
                            signature: bytes(&p.signature_hex, 4627)?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                registrations.push(FormationRegistration {
                    node,
                    formation_key,
                    registration_nonce,
                    key_possession: bytes(&r.key_possession_hex, 4627)?,
                    controller_approvals,
                });
            }
            let reviewed = stage_review::review_formation(
                nic.approvals(),
                &catalog,
                population,
                registrations,
                &provider,
            )
            .map_err(|_| "Actual formation review failed")?;
            if hex::encode(reviewed.registry_commitment()) != *registry_commitment_hex
                || hex::encode(reviewed.preseed_commitment()) != *input_commitment_hex
            {
                return Err("Reviewed formation differs from approval subject".into());
            }
            serde_json::json!({"kind":"VERIFIED_FORMATION_CANDIDATE","registry_commitment_hex":registry_commitment_hex,"input_commitment_hex":input_commitment_hex})
        }
        RootApprovalStage::Genesis { genesis_digest_hex } => {
            let provider = engine(root)?;
            let provider = provider
                .lock()
                .map_err(|_| "Native verification unavailable")?;
            catalog
                .validate_provider(&provider)
                .map_err(|_| "Native catalog/provider differs")?;
            let nic =
                received_bundle::load_received_nic_bundle(&request.nic_selection, chain, &provider)
                    .map_err(|_| "Genuine NIC required before Genesis review")?;
            let reviewed = stage_review::review_complete_genesis(
                source
                    .as_deref()
                    .ok_or("Actual complete Genesis required")?,
                &catalog,
                &authority,
                nic.approvals(),
                &provider,
            )
            .map_err(|_| "Actual complete Genesis review failed")?;
            if hex::encode(reviewed.coordinate().genesis.digest) != *genesis_digest_hex {
                return Err("Reviewed Genesis differs from approval subject".into());
            }
            serde_json::json!({"kind":"INDEPENDENT_COMPLETE_GENESIS","genesis_digest_hex":genesis_digest_hex,"profile_catalog_commitment_hex":hex::encode(profiles)})
        }
    };
    let key = authority
        .root_key_record(request.root_index)
        .map_err(|_| "Selected bootstrap root absent")?;
    Ok(
        serde_json::json!({"schema":"synergy-r1-root-approval-context-review-v1","authority_granted":false,"chain_id":request.chain_id,"nic_hex":hex::encode(n.nic),"pinned_birth_frame_hex":hex::encode(authority.canonical_birth_frame()),"pinned_root_threshold":authority.threshold(),"profile_catalog_commitment_hex":hex::encode(profiles),"root_index":request.root_index,"public_key":{"role":key.role,"algorithm":key.algorithm,"key_generation":key.key_generation,"full_public_key_hex":hex::encode(key.full_public_key)},"stage":request.stage,"stage_source":stage_source,"approval_plan_commitment_hex":hex::encode(plan.approval_plan_commitment)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r1_review_rejects_unbounded_noncanonical_public_carriers() {
        assert_eq!(bytes("00af19", 3).unwrap(), [0, 175, 25]);
        for (input, limit) in [
            ("", 32),
            ("a", 32),
            ("AA", 32),
            ("0x00", 32),
            ("00 0", 32),
            ("0000", 1),
        ] {
            assert!(bytes(input, limit).is_err());
        }
        let root = Path::new("/nonexistent-public-review-fixture");
        assert!(review(root, "").is_err());
        assert!(review(root, &" ".repeat(65537)).is_err());
        assert!(review(root, r#"{"chain_id":"9969","injected_authority":true}"#).is_err());
        assert!(!root.exists());
    }
    #[test]
    fn r1_review_closed_formation_source_rejects_authority_injection() {
        assert!(serde_json::from_str::<FormationSource>(
            r#"{"population":"conditional_five","registrations":[],"verified":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Source>(
            r#"{"path":"public.json","sha256":"00","grant":true}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Proof>(r#"{"index":0,"signature_hex":"00","valid":true}"#)
                .is_err()
        );
        let n = serde_json::json!({
            "managed_root":"/nonexistent-public-review-fixture",
            "pinned_bootstrap_input_path":"public/birth.json", "pinned_bootstrap_input_sha256":"00",
            "profile_catalog_path":"public/catalog.json", "profile_catalog_sha256":"00",
            "approvals_path":"public/nic.json", "expected_nic_hex":"00"
        });
        for chain in ["0", "09969", "+9969", " 9969", "18446744073709551616"] {
            let request = serde_json::json!({"chain_id":chain,"nic_selection":n,"root_index":0,"stage":{"kind":"NIC"},"source":null});
            assert!(review(
                Path::new("/nonexistent-public-review-fixture"),
                &request.to_string()
            )
            .is_err());
        }
    }
}
