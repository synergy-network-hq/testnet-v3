//! Paid candidate enrollment outcomes, committed atomically with fee/business diffs.
//! No authority, public action assignment, inclusion or non-consumption is inferred.
use super::*;
use super::settlement::EngineeringEtdagOpening;
use serde_json::{json, Value};

const SPONSOR_PREFIX: &str = "apqe-protected-account-candidate/v1/sponsored-enrollment/";
const MAX_STORED_RECEIPT_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum SponsoredOutcome {
    CommitApplied,
    DuplicatePaidCommit,
    RevealApplied,
    RevealRevertedCommitUsed,
}
impl SponsoredOutcome {
    fn action(self) -> u16 {
        use super::super::protected_action_wire::{ENROLL_COMMIT, ENROLL_REVEAL};
        match self {
            Self::CommitApplied | Self::DuplicatePaidCommit => ENROLL_COMMIT,
            Self::RevealApplied | Self::RevealRevertedCommitUsed => ENROLL_REVEAL,
        }
    }
    fn status(self) -> &'static str {
        match self {
            Self::CommitApplied => "commit_applied_candidate",
            Self::DuplicatePaidCommit => "duplicate_paid_commit_candidate",
            Self::RevealApplied => "reveal_applied_candidate",
            Self::RevealRevertedCommitUsed => "reveal_reverted_commit_used_candidate",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SponsorSettlement {
    version: u8,
    network: Network,
    payer: String,
    signed_sponsor_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engineering_etdag_opening: Option<EngineeringEtdagOpening>,
    commitment: [u8; 32],
    action: u16,
    outcome: SponsoredOutcome,
    source_finalized_height: u64,
    source_finalized_time: u64,
    included_height: u64,
    consensus_time: u64,
    gas_used: u64,
    fee_nwei: u128,
    nonce_before: u64,
    nonce_after: u64,
}

pub(super) fn owns_key(key: &str) -> bool {
    key.starts_with(SPONSOR_PREFIX)
}

fn canonical_payer(payer: &str) -> Result<(), String> {
    if payer.len() > 128 {
        return Err("invalid candidate sponsor payer".into());
    }
    // decode_address enforces lowercase, checksum variant, namespace and exact
    // data/text lengths. The ordinary syna namespace has no 20-byte SYNW ID.
    let decoded = synergy_address::decode_address(payer)?;
    if decoded.hrp != "syna" || decoded.account_identifier.is_some() {
        return Err("candidate sponsor must be a canonical ordinary syna account".into());
    }
    Ok(())
}
fn canonical_digest(digest: &str) -> Result<(), String> {
    if digest.len() != 128
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("candidate sponsor digest must be exact lower-hex SHA3-512".into());
    }
    Ok(())
}
pub(super) fn receipt_key(payer: &str, nonce_before: u64) -> String {
    format!("{SPONSOR_PREFIX}{payer}/{nonce_before}")
}
fn validate(record: &SponsorSettlement) -> Result<(), String> {
    canonical_payer(&record.payer)?;
    canonical_digest(&record.signed_sponsor_digest)?;
    if let Some(opening) = &record.engineering_etdag_opening {
        opening.validate()?;
        if opening.authorization_height <= record.source_finalized_height {
            return Err("candidate sponsor opening must follow its finalized source".into());
        }
    }
    if record.version != 1
        || record.action != record.outcome.action()
        || record.commitment == [0; 32]
        || record.source_finalized_height == 0
        || record.source_finalized_height >= record.included_height
        || record.source_finalized_time == 0
        || record.source_finalized_time > record.consensus_time
        || record.gas_used == 0
        || record.fee_nwei == 0
        || record.nonce_before.checked_add(1) != Some(record.nonce_after)
    {
        return Err("invalid candidate sponsored enrollment settlement".into());
    }
    Ok(())
}

/// Called only after root's exact sponsor signature/binding/fee verification.
/// The result must join the same atomic StateDiff as the fee/business outcome.
/// It does not apply anything or grant sponsor authority over the new account.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_sponsor_settlement(
    finalized: &FinalizedSnapshot<'_>,
    world: &WorldState,
    payer: &str,
    signed_digest: &str,
    commitment: [u8; 32],
    outcome: SponsoredOutcome,
    gas_used: u64,
    fee_nwei: u128,
    nonce_before: u64,
    inclusion: Position,
    opening: Option<&EngineeringEtdagOpening>,
) -> Result<ProtocolChange, String> {
    canonical_payer(payer)?;
    canonical_digest(signed_digest)?;
    if inclusion.height <= finalized.position.height
        || inclusion.consensus_time < finalized.position.consensus_time
        || !world.accounts.get(payer).is_some_and(|a| {
            a.code_hash.is_none() && a.nonce == nonce_before && a.balance_nwei >= fee_nwei
        })
    {
        return Err(
            "candidate sponsor settlement differs from execution position or payer state".into(),
        );
    }
    let key = receipt_key(payer, nonce_before);
    if finalized.world.protocol.contains_key(&key) || world.protocol.contains_key(&key) {
        return Err(
            "sponsor nonce already has a candidate settlement; reconcile original outcome".into(),
        );
    }
    let record = SponsorSettlement {
        version: 1,
        network: finalized.registry.network,
        payer: payer.into(),
        signed_sponsor_digest: signed_digest.into(),
        engineering_etdag_opening: opening.cloned(),
        commitment,
        action: outcome.action(),
        outcome,
        source_finalized_height: finalized.position.height,
        source_finalized_time: finalized.position.consensus_time,
        included_height: inclusion.height,
        consensus_time: inclusion.consensus_time,
        gas_used,
        fee_nwei,
        nonce_before,
        nonce_after: nonce_before
            .checked_add(1)
            .ok_or("sponsor nonce exhausted")?,
    };
    validate(&record)?;
    let bytes = encode(&record)?;
    if bytes.len() > MAX_STORED_RECEIPT_BYTES {
        return Err("candidate sponsor settlement exceeds storage bound".into());
    }
    Ok(ProtocolChange {
        key,
        expected_value: None,
        value: Some(bytes),
    })
}

pub(super) fn inspect_sponsor_settlement(
    snapshot: &FinalizedSnapshot<'_>,
    payer: &str,
    nonce_before: u64,
    signed_digest: &str,
    expected_opening: Option<&EngineeringEtdagOpening>,
) -> Result<Value, String> {
    canonical_payer(payer)?;
    canonical_digest(signed_digest)?;
    if let Some(opening) = expected_opening {
        opening.validate()?;
    }
    let Some(bytes) = snapshot
        .world
        .protocol
        .get(&receipt_key(payer, nonce_before))
    else {
        // A different ordinary action may have consumed this nonce. No record
        // is evidence only about this snapshot's settlement namespace.
        return Ok(
            json!({"payer":payer,"nonce_before":nonce_before,"status":"no_settlement_in_snapshot"}),
        );
    };
    let record: SponsorSettlement = decode(bytes, MAX_STORED_RECEIPT_BYTES)?;
    validate(&record)?;
    if encode(&record)? != *bytes
        || record.network != snapshot.registry.network
        || record.payer != payer
        || record.nonce_before != nonce_before
        || record.signed_sponsor_digest != signed_digest
        || expected_opening.is_some_and(|expected| record.engineering_etdag_opening.as_ref() != Some(expected))
        || record.included_height > snapshot.position.height
        || record.consensus_time > snapshot.position.consensus_time
    {
        return Err("candidate sponsor settlement conflicts with exact request or snapshot".into());
    }
    let mut result = json!({
        "payer":record.payer,"signed_sponsor_digest":record.signed_sponsor_digest,
        "commitment":inspection::hex_bytes(&record.commitment),"action":record.action,"status":record.outcome.status(),
        "source_finalized_height":record.source_finalized_height,"source_finalized_time":record.source_finalized_time,
        "included_height":record.included_height,"inclusion_consensus_timestamp_unix":record.consensus_time,
        "gas_used":record.gas_used,"fee_nwei":record.fee_nwei.to_string(),
        "nonce_before":record.nonce_before,"nonce_after":record.nonce_after,
    });
    if let Some(opening) = record.engineering_etdag_opening {
        result["engineering_etdag_opening"] = json!(opening);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_state::AccountState;

    fn registry(wire: &UnactivatedWireProfile) -> CandidateProtectedAccounts<'_> {
        CandidateProtectedAccounts::new(
            ChainId::from_u64(99999),
            ExternalChainPolicy::new(ChainId::from_u64(1), NativeGenesisHash::from_bytes([5; 32]))
                .unwrap(),
            wire,
            UnactivatedCommitmentProfile::candidate_concat_v1(),
            vec![[6; 32]],
        )
        .unwrap()
    }
    fn payer() -> String {
        synergy_address::derive_standard_account_address(&[7; 1793]).unwrap()
    }
    fn world(payer: &str) -> WorldState {
        let mut world = WorldState::default();
        world.accounts.insert(
            payer.into(),
            AccountState {
                balance_nwei: 1000,
                nonce: 7,
                ..Default::default()
            },
        );
        world
    }
    fn snapshot<'a>(
        registry: &'a CandidateProtectedAccounts<'a>,
        world: &'a WorldState,
        height: u64,
        time: u64,
    ) -> FinalizedSnapshot<'a> {
        let (pointer, proof) = super::super::tests::finalized(height, world);
        registry.finalized_snapshot(world, &pointer, &proof, time).unwrap()
    }
    fn staged(
        snapshot: &FinalizedSnapshot<'_>,
        world: &WorldState,
        payer: &str,
        outcome: SponsoredOutcome,
    ) -> ProtocolChange {
        prepare_sponsor_settlement(
            snapshot,
            world,
            payer,
            &"ab".repeat(64),
            [9; 32],
            outcome,
            5,
            25,
            7,
            Position {
                height: 4,
                consensus_time: 1001,
            },
            None,
        )
        .unwrap()
    }
    #[test]
    fn sponsor_settlement_paid_outcomes_are_exact_and_stage_atomically() {
        let wire = inspection::candidate_wire_profile().unwrap();
        let registry = registry(&wire);
        let payer = payer();
        let base = world(&payer);
        let parent = snapshot(&registry, &base, 3, 1000);
        for (outcome, status) in [
            (SponsoredOutcome::CommitApplied, "commit_applied_candidate"),
            (
                SponsoredOutcome::DuplicatePaidCommit,
                "duplicate_paid_commit_candidate",
            ),
            (SponsoredOutcome::RevealApplied, "reveal_applied_candidate"),
            (
                SponsoredOutcome::RevealRevertedCommitUsed,
                "reveal_reverted_commit_used_candidate",
            ),
        ] {
            let change = staged(&parent, &base, &payer, outcome);
            assert!(owns_key(&change.key));
            assert!(!owns_key("unrelated"));
            assert_eq!(base, world(&payer));
            let mut working = base.clone();
            StateDiff {
                changes: vec![
                    AccountChange {
                        account: payer.clone(),
                        debit_nwei: 25,
                        credit_nwei: 0,
                        expected_nonce: Some(7),
                        code_hash: None,
                    },
                    AccountChange {
                        account: "fixture-fee-collector".into(),
                        debit_nwei: 0,
                        credit_nwei: 25,
                        expected_nonce: None,
                        code_hash: None,
                    },
                ],
                protocol_changes: vec![change],
            }
            .apply(&mut working)
            .unwrap();
            let finalized = snapshot(&registry, &working, 4, 1001);
            let result =
                inspect_sponsor_settlement(&finalized, &payer, 7, &"ab".repeat(64), None).unwrap();
            assert_eq!(result["status"], status);
            assert_eq!(result["action"], outcome.action());
            assert_eq!(result["fee_nwei"], "25");
            assert_eq!(result["gas_used"], 5);
            assert_eq!(result["nonce_before"], 7);
            assert_eq!(result["nonce_after"], 8);
            assert!(result.get("engineering_etdag_opening").is_none());
            assert_eq!(working.accounts[&payer].nonce, 8);
            assert_eq!(working.accounts[&payer].balance_nwei, 975);
            assert_eq!(working.accounts["fixture-fee-collector"].balance_nwei, 25);
            let bytes = working.protocol[&receipt_key(&payer, 7)].clone();
            assert_eq!(
                encode(&decode::<SponsorSettlement>(&bytes, MAX_STORED_RECEIPT_BYTES).unwrap())
                    .unwrap(),
                bytes
            );
            assert!(inspect_sponsor_settlement(&finalized, &payer, 7, &"cd".repeat(64), None).is_err());
            // A conflicting same-payer nonce cannot be staged under a new digest.
            assert!(prepare_sponsor_settlement(
                &parent,
                &working,
                &payer,
                &"cd".repeat(64),
                [9; 32],
                outcome,
                5,
                25,
                7,
                Position {
                    height: 5,
                    consensus_time: 1002
                },
                None,
            )
            .is_err());
        }
    }
    #[test]
    fn sponsor_settlement_receipt_conflicts_and_fee_failure_preserve_state() {
        let wire = inspection::candidate_wire_profile().unwrap();
        let registry = registry(&wire);
        let payer = payer();
        let base = world(&payer);
        let parent = snapshot(&registry, &base, 3, 1000);
        let change = staged(&parent, &base, &payer, SponsoredOutcome::CommitApplied);
        let mut working = base.clone();
        let invalid_fee = StateDiff {
            changes: vec![AccountChange {
                account: payer.clone(),
                debit_nwei: 2000,
                credit_nwei: 0,
                expected_nonce: Some(7),
                code_hash: None,
            }],
            protocol_changes: vec![change],
        };
        assert!(invalid_fee.apply(&mut working).is_err());
        assert_eq!(working, base);
        let change = staged(&parent, &base, &payer, SponsoredOutcome::CommitApplied);
        working.protocol.insert(change.key, change.value.unwrap());
        let with_record = snapshot(&registry, &working, 4, 1001);
        // Lost local copies never make a finalized sponsor nonce available again.
        assert!(prepare_sponsor_settlement(
            &with_record,
            &base,
            &payer,
            &"cd".repeat(64),
            [9; 32],
            SponsoredOutcome::RevealApplied,
            5,
            25,
            7,
            Position {
                height: 5,
                consensus_time: 1002
            },
            None,
        )
        .is_err());
        assert!(prepare_sponsor_settlement(
            &parent,
            &working,
            &payer,
            &"ab".repeat(64),
            [9; 32],
            SponsoredOutcome::CommitApplied,
            5,
            25,
            7,
            Position {
                height: 4,
                consensus_time: 1001
            },
            None,
        )
        .is_err());
    }
    #[test]
    fn sponsor_settlement_codec_refuses_corrupt_foreign_and_noncanonical_records() {
        let wire = inspection::candidate_wire_profile().unwrap();
        let registry = registry(&wire);
        let payer = payer();
        let base = world(&payer);
        let parent = snapshot(&registry, &base, 3, 1000);
        let change = staged(&parent, &base, &payer, SponsoredOutcome::CommitApplied);
        let bytes = change.value.unwrap();
        for kind in 0..17 {
            let mut record: SponsorSettlement = decode(&bytes, MAX_STORED_RECEIPT_BYTES).unwrap();
            match kind {
                0 => record.version = 2,
                1 => record.network.genesis = [8; 32],
                2 => record.signed_sponsor_digest = "cd".repeat(64),
                3 => record.signed_sponsor_digest = "AB".repeat(64),
                4 => record.commitment = [0; 32],
                5 => record.action = 0,
                6 => record.outcome = SponsoredOutcome::RevealApplied,
                7 => record.source_finalized_height = 0,
                8 => record.source_finalized_height = 4,
                9 => record.included_height = 5,
                10 => record.consensus_time = 1002,
                11 => record.source_finalized_time = 1002,
                12 => record.gas_used = 0,
                13 => record.fee_nwei = 0,
                14 => record.nonce_after = 9,
                15 => record.payer = payer.to_uppercase(),
                _ => record.nonce_before = u64::MAX,
            }
            let mut bad = base.clone();
            bad.protocol
                .insert(change.key.clone(), encode(&record).unwrap());
            assert!(
                inspect_sponsor_settlement(
                    &snapshot(&registry, &bad, 4, 1001),
                    &payer,
                    7,
                    &"ab".repeat(64),
                    None,
                )
                .is_err(),
                "mutation {kind}"
            );
        }
        let mut alternatives = vec![vec![b' '; MAX_STORED_RECEIPT_BYTES + 1]];
        let mut trailing = bytes.clone();
        trailing.push(b'\n');
        alternatives.push(trailing);
        let mut unknown = bytes.clone();
        unknown.pop();
        unknown.extend_from_slice(b",\"unknown\":true}");
        alternatives.push(unknown);
        let mut duplicate = bytes.clone();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"version\":1}");
        alternatives.push(duplicate);
        for bad_bytes in alternatives {
            let mut bad = base.clone();
            bad.protocol.insert(change.key.clone(), bad_bytes);
            assert!(inspect_sponsor_settlement(
                &snapshot(&registry, &bad, 4, 1001),
                &payer,
                7,
                &"ab".repeat(64),
                None,
            )
            .is_err());
        }
    }
    #[test]
    fn sponsor_settlement_missing_is_not_evidence_of_unspent_nonce() {
        let wire = inspection::candidate_wire_profile().unwrap();
        let registry = registry(&wire);
        let payer = payer();
        let mut base = world(&payer);
        base.accounts.get_mut(&payer).unwrap().nonce = 8; // An ordinary action already used nonce7.
        let snapshot = snapshot(&registry, &base, 4, 1001);
        let result = inspect_sponsor_settlement(&snapshot, &payer, 7, &"ab".repeat(64), None).unwrap();
        assert_eq!(result["status"], "no_settlement_in_snapshot");
        assert!(result.get("nonce_unused").is_none());
        for digest in ["ab".repeat(63), "AB".repeat(64), "x".repeat(128)] {
            assert!(inspect_sponsor_settlement(&snapshot, &payer, 7, &digest, None).is_err())
        }
        assert!(
            inspect_sponsor_settlement(&snapshot, &payer.to_uppercase(), 7, &"ab".repeat(64), None)
                .is_err()
        );
        let nonpayer = AccountIdentifier::from_bytes([33; 20])
            .to_native(&Primitives)
            .unwrap();
        assert!(inspect_sponsor_settlement(&snapshot, &nonpayer, 7, &"ab".repeat(64), None).is_err());
    }
}
