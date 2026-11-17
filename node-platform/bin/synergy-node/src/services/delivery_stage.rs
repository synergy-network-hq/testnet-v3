//! Read-only authentication of narrowly discardable interrupted delivery writes.
//! Never changes committed delivery or signing journals.
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRecord {
    slot: synergy_posy::persistence::SigningSlot,
    subject: String,
}

#[derive(Clone, Deserialize)]
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
    peer_supplement: bool,
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
    if peer_supplement
        && staging
            .statements
            .last()
            .is_some_and(|s| s.validator_id == local)
    {
        return Err("uncommitted supplement must not add local signing evidence".into());
    }
    let mut signers = BTreeSet::new();
    for statement in &staging.statements {
        if (!peer_supplement && statement.phase != ProposalDeliveryPhase::Echo)
            || statement.context != candidate.context
            || &statement.candidate != candidate
            || (!peer_supplement && statement.validator_id == local)
            || !signers.insert((statement.phase, statement.validator_id.as_str()))
        {
            return Err("stage is not distinct same-candidate peer delivery evidence".into());
        }
    }
    Ok(())
}

fn verify_peer_supplement(
    committed: &DeliveryRecord,
    staging: &DeliveryRecord,
    signing: &SigningJournal,
    local: &str,
    selected: &authority::VerifiedAuthority,
) -> Result<CertifiedCandidateSubject, String> {
    let candidate = committed
        .statements
        .first()
        .ok_or("committed delivery has no candidate")?
        .candidate
        .clone();
    verify_signing_journal(signing, staging.slot.0, Some(&candidate))?;
    verify_supplement(committed, staging, &candidate, local, true)?;
    if staging.statements.len() > selected.registry.active_count() * 2 {
        return Err("delivery supplement exceeds frozen participant bound".into());
    }
    selected
        .registry
        .active_validator(local)
        .map_err(|e| e.to_string())?;
    for statement in &staging.statements {
        statement
            .verify(&selected.epoch, &selected.registry, selected)
            .map_err(|e| format!("verify uncommitted peer delivery supplement: {e}"))?;
    }
    Ok(candidate)
}

fn verify_signing_journal(
    signing: &SigningJournal,
    height: u64,
    candidate: Option<&CertifiedCandidateSubject>,
) -> Result<(), String> {
    let subject = candidate
        .map(CertifiedCandidateSubject::id)
        .transpose()
        .map_err(|e| e.to_string())?;
    let mut slots = BTreeSet::new();
    if signing.format != "synergy-posy-sign-once-v1"
        || signing.finalized_floor > height
        || signing.records.iter().any(|record| {
            (record.slot.height == height
                && !(record.slot.round == 0
                    && matches!(
                        record.slot.domain.as_str(),
                        "proposal" | "proposal-echo" | "proposal-ready"
                    )
                    && subject.as_ref() == Some(&record.subject)))
                || record.slot.height <= signing.finalized_floor
                || record.slot.domain.trim().is_empty()
                || record.subject.trim().is_empty()
                || !slots.insert(record.slot.clone())
        })
    {
        return Err("signing journal has a reservation or incompatible floor for the stage".into());
    }
    Ok(())
}

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args = args.take(7).collect::<Vec<_>>();
    let (coordinates, peer_supplement) = match args.as_slice() {
        [_, _, _, _, _] => (&args[..], false),
        [_, _, _, _, _, mode] if mode == "peer-supplement" => (&args[..5], true),
        _ => return Err("usage: verify-delivery-stage CONFIG STAGE_NAME COMMITTED_SHA256 STAGE_SHA256 SIGNER_SHA256 [peer-supplement] < WITNESS".into()),
    };
    let [config, stage_name, committed_sha256, stage_sha256, signer_sha256] = coordinates else {
        unreachable!();
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
    if !peer_supplement {
        verify_signing_journal(&signing, stage.slot.0, None)?;
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read finality witness: {error}"))?;
    if peer_supplement {
        if !bytes.is_empty() {
            return Err("peer-supplement mode accepts no finality witness".into());
        }
        let candidate = verify_peer_supplement(
            &committed,
            &stage,
            &signing,
            owner.node_address.as_str(),
            selected.as_ref(),
        )?;
        println!(
            "{}",
            serde_json::json!({
                "genesis_hash":genesis, "stage":stage_name,
                "committed_sha256":committed_sha256, "stage_sha256":stage_sha256,
                "signer_sha256":signer_sha256, "witness_sha256":apqe_transport::sha256(&bytes),
                "recovery_mode":"peer-supplement", "epoch":selected.epoch.epoch,
                "candidate":candidate, "finalized":null, "verified":true,
            })
        );
        return Ok(());
    }
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD {
        return Err("missing or oversized delivery-stage finality witness".into());
    }
    let witness: FinalityWitness = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode delivery-stage finality witness: {error}"))?;
    let candidate = witness.certificates[0]
        .subject()
        .map_err(|error| error.to_string())?;
    verify_supplement(
        &committed,
        &stage,
        &candidate,
        owner.node_address.as_str(),
        false,
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    use synergy_posy::{ConsensusObjectContext, ValidatorRecord, ValidatorStatus};

    #[test]
    #[ignore = "requires explicitly authenticated native APQE artifacts"]
    fn native_uncommitted_peer_supplement_preserves_exact_local_reservations() {
        let provider = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = crate::services::apqe_provider::load_selected(&provider).unwrap();
        let keys = (0..5)
            .map(|_| {
                engine
                    .lock()
                    .unwrap()
                    .generate_keypair(Algorithm::MlDsa65)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let entries = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                (
                    ValidatorRecord {
                        validator_id: format!("delivery-validator-{i}"),
                        consensus_key_id: format!("delivery-key-{i}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    key.public_key.clone(),
                )
            })
            .collect();
        let selected =
            authority::qualification_authority_with_provider(entries, Some(Arc::clone(&engine)));
        let local = "delivery-validator-0";
        let candidate = CertifiedCandidateSubject::new(
            ConsensusObjectContext::for_height(&selected.epoch, 8, 0).unwrap(),
            "a".repeat(64),
            "b".repeat(64),
            synergy_posy::SimplifiedFinalityParent::QuorumCertificate {
                height: 7,
                block_id: "b".repeat(64),
                qc_id: "c".repeat(64),
            },
            "d".repeat(64),
        )
        .unwrap();
        let statement = |i: usize, phase| {
            let mut value = ProposalDeliveryStatement {
                context: candidate.context.clone(),
                phase,
                candidate: candidate.clone(),
                validator_id: format!("delivery-validator-{i}"),
                key_id: format!("delivery-key-{i}"),
                signature: Vec::new(),
            };
            value.signature = engine
                .lock()
                .unwrap()
                .sign(
                    Algorithm::MlDsa65,
                    keys[i].private_key.as_bytes(),
                    &value.signing_bytes().unwrap(),
                    SignOptions::default(),
                )
                .unwrap();
            value
        };
        let mut base = DeliveryRecord {
            slot: (8, 0),
            delivered: None,
            statements: (0..4)
                .map(|i| statement(i, ProposalDeliveryPhase::Echo))
                .collect(),
        };
        base.statements
            .push(statement(0, ProposalDeliveryPhase::Ready));
        base.statements
            .push(statement(1, ProposalDeliveryPhase::Ready));
        let mut stage = base.clone();
        stage
            .statements
            .push(statement(2, ProposalDeliveryPhase::Ready));
        let signing = SigningJournal {
            format: "synergy-posy-sign-once-v1".into(),
            finalized_floor: 5,
            records: ["proposal", "proposal-echo", "proposal-ready"]
                .into_iter()
                .map(|domain| SigningRecord {
                    slot: synergy_posy::persistence::SigningSlot {
                        height: 8,
                        round: 0,
                        domain: domain.into(),
                    },
                    subject: candidate.id().unwrap(),
                })
                .collect(),
        };
        let verify = |base: &DeliveryRecord, stage: &DeliveryRecord, signing: &SigningJournal| {
            verify_peer_supplement(base, stage, signing, local, &selected)
        };
        assert_eq!(verify(&base, &stage, &signing).unwrap(), candidate);
        let mut echo_base = base.clone();
        echo_base.statements.pop();
        let mut echo_stage = echo_base.clone();
        echo_stage
            .statements
            .push(statement(4, ProposalDeliveryPhase::Echo));
        assert!(verify(&echo_base, &echo_stage, &signing).is_ok());

        let rejected_stage = |change: &dyn Fn(&mut DeliveryRecord)| {
            let mut altered = stage.clone();
            change(&mut altered);
            assert!(verify(&base, &altered, &signing).is_err());
        };
        rejected_stage(&|s| s.statements.last_mut().unwrap().signature[0] ^= 1);
        rejected_stage(&|s| s.statements[0].signature[0] ^= 1);
        rejected_stage(&|s| s.statements.last_mut().unwrap().candidate.block_id = "e".repeat(64));
        rejected_stage(&|s| s.slot.1 = 1);
        rejected_stage(&|s| s.delivered = Some(candidate.id().unwrap()));
        rejected_stage(&|s| {
            *s.statements.last_mut().unwrap() = statement(0, ProposalDeliveryPhase::Ready)
        });
        rejected_stage(&|s| {
            *s.statements.last_mut().unwrap() = statement(1, ProposalDeliveryPhase::Ready)
        });
        rejected_stage(&|s| s.statements.last_mut().unwrap().key_id = "foreign-key".into());
        let mut delivered = base.clone();
        delivered.delivered = Some(candidate.id().unwrap());
        assert!(verify(&delivered, &stage, &signing).is_err());
        for domain in ["block-vote", "timeout-vote", "unrecognized"] {
            let mut changed = signing.clone();
            changed.records[0].slot.domain = domain.into();
            assert!(verify(&base, &stage, &changed).is_err());
        }
        let mut changed = signing.clone();
        changed.records[0].subject = "e".repeat(64);
        assert!(verify(&base, &stage, &changed).is_err());
        changed = signing.clone();
        changed.records[0].slot.round = 1;
        assert!(verify(&base, &stage, &changed).is_err());
        changed = signing.clone();
        changed.records.push(changed.records[0].clone());
        assert!(verify(&base, &stage, &changed).is_err());
        changed = signing.clone();
        changed.finalized_floor = 9;
        assert!(verify(&base, &stage, &changed).is_err());
        assert!(verify_signing_journal(&signing, 8, None).is_err());
        // The verifier is read-only and cannot discard or re-sign reservations.
        assert_eq!(signing.records.len(), 3);
        assert!(signing
            .records
            .iter()
            .all(|r| r.subject == candidate.id().unwrap()));
    }
}
