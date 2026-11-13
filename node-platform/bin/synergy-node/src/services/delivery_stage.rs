//! Read-only check for an interrupted atomic write containing one extra peer
//! ECHO for an already finalized round-zero candidate. Never changes journals.
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::Path;

use serde::Deserialize;
use synergy_posy::{
    CertifiedCandidateSubject, FinalizedBlockRecord, ProposalDeliveryPhase,
    ProposalDeliveryStatement, SimplifiedQuorumCertificate, ThreeQcFinality,
};
use synergy_storage::NodeStorageLayout;

use super::{apqe_transport, authority, identity};

const MAX_RECORD: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryRecord {
    slot: (u64, u64),
    statements: Vec<ProposalDeliveryStatement>,
    delivered: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalityWitness {
    finalized: FinalizedBlockRecord,
    certificates: [SimplifiedQuorumCertificate; 3],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRecord {
    slot: synergy_posy::persistence::SigningSlot,
    subject: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningJournal {
    format: String,
    finalized_floor: u64,
    records: Vec<SigningRecord>,
}

fn exact_input(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    let bytes = apqe_transport::read(path, MAX_RECORD, true)?;
    if apqe_transport::sha256(&bytes) != expected {
        return Err("delivery recovery input differs from the independent digest".into());
    }
    Ok(bytes)
}

fn verify_supplement(
    committed: &DeliveryRecord,
    staging: &DeliveryRecord,
    candidate: &CertifiedCandidateSubject,
    local: &str,
) -> Result<(), String> {
    if committed.slot != staging.slot
        || staging.slot != (candidate.context.height, 0)
        || committed.delivered.is_some()
        || staging.delivered.is_some()
        || committed.statements.is_empty()
        || staging.statements.len() != committed.statements.len() + 1
        || !staging.statements.starts_with(&committed.statements)
    {
        return Err("stage is not a one-statement undelivered supplement".into());
    }
    let mut signers = BTreeSet::new();
    for statement in &staging.statements {
        if statement.phase != ProposalDeliveryPhase::Echo
            || statement.context != candidate.context
            || &statement.candidate != candidate
            || statement.validator_id == local
            || !signers.insert(statement.validator_id.as_str())
        {
            return Err("stage is not a distinct peer ECHO for the finalized slot".into());
        }
    }
    Ok(())
}

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args = args.take(6).collect::<Vec<_>>();
    let [config, stage_name, committed_sha256, stage_sha256, signer_sha256] = args.as_slice()
    else {
        return Err("usage: verify-delivery-stage CONFIG STAGE_NAME COMMITTED_SHA256 STAGE_SHA256 SIGNER_SHA256 < WITNESS".into());
    };
    let config = Path::new(config);
    let stage_numbers = stage_name
        .strip_prefix("delivery.tmp-")
        .and_then(|suffix| suffix.split_once('-'));
    if !config.is_absolute()
        || !stage_numbers.is_some_and(|(pid, sequence)| {
            pid.parse::<u32>()
                .is_ok_and(|v| v > 1 && v.to_string() == pid)
                && sequence
                    .parse::<u64>()
                    .is_ok_and(|v| v.to_string() == sequence)
        })
    {
        return Err("invalid delivery-stage verification coordinates".into());
    }
    let configuration = synergy_config::load(config).map_err(|error| error.to_string())?;
    if configuration.role != synergy_protocol_types::NodeRole::Validator {
        return Err("delivery recovery requires a registered validator configuration".into());
    }
    let genesis = crate::commands::selected_network::verify(&configuration)?;
    let selected = authority::load(&configuration)?.ok_or("signed PoSy authority is required")?;
    let owner =
        identity::load_public_identity(&configuration.public_identity_path, configuration.role)?;
    selected
        .registry
        .active_validator(owner.node_address.as_str())
        .map_err(|error| error.to_string())?;
    let root = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| error.to_string())?
        .consensus()
        .join("posy");
    let committed: DeliveryRecord =
        serde_json::from_slice(&exact_input(&root.join("delivery.json"), committed_sha256)?)
            .map_err(|error| format!("decode committed delivery record: {error}"))?;
    let stage: DeliveryRecord =
        serde_json::from_slice(&exact_input(&root.join(stage_name), stage_sha256)?)
            .map_err(|error| format!("decode staged delivery record: {error}"))?;
    let signing: SigningJournal =
        serde_json::from_slice(&exact_input(&root.join("sign-once.json"), signer_sha256)?)
            .map_err(|error| format!("decode signing journal: {error}"))?;
    if signing.format != "synergy-posy-sign-once-v1"
        || signing.finalized_floor > stage.slot.0
        || signing
            .records
            .iter()
            .any(|record| record.slot.height == stage.slot.0 || record.subject.is_empty())
    {
        return Err("signing journal has a reservation or incompatible floor for the stage".into());
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read finality witness: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
        return Err("missing or oversized delivery-stage finality witness".into());
    }
    let witness: FinalityWitness = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode delivery-stage finality witness: {error}"))?;
    let candidate = witness.certificates[0]
        .subject()
        .map_err(|error| error.to_string())?;
    verify_supplement(&committed, &stage, &candidate, owner.node_address.as_str())?;
    let mut finality = ThreeQcFinality::default();
    for certificate in witness.certificates {
        // Takeover histories require a separate verified timeout closure.
        if certificate.context.round != 0 || certificate.takeover_tc_id.is_some() {
            return Err("delivery-stage retirement requires round-zero finality".into());
        }
        certificate
            .verify(&selected.epoch, &selected.registry, selected.as_ref())
            .map_err(|error| format!("verify delivery-stage QC: {error}"))?;
        finality
            .accept(certificate)
            .map_err(|error| format!("verify delivery-stage QC ancestry: {error}"))?;
    }
    if finality.last_finalized() != Some(&witness.finalized)
        || witness.finalized.height != stage.slot.0
    {
        return Err("delivery-stage finality witness differs from the exact stage slot".into());
    }
    for statement in &stage.statements {
        statement
            .verify(&selected.epoch, &selected.registry, selected.as_ref())
            .map_err(|error| format!("verify delivery-stage peer ECHO: {error}"))?;
    }
    println!(
        "{}",
        serde_json::json!({
            "genesis_hash":genesis,
            "stage":stage_name,
            "committed_sha256":committed_sha256,
            "stage_sha256":stage_sha256,
            "signer_sha256":signer_sha256,
            "witness_sha256":apqe_transport::sha256(&bytes),
            "finalized":witness.finalized,
            "verified":true,
        })
    );
    Ok(())
}
