//! Read-only inspection of a verified World under the frozen PW13 candidate.
//! The caller authenticates Genesis, PoSy finality and the block preimage.
use super::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use synergy_address_engine::apqe::{
    address::parse_address, enrollment::UnactivatedWireAssignments,
};

const MAX_SELECTORS: usize = 8;
const MAX_PROVIDER_PINS: usize = 4;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateReadQuery {
    pub(crate) height: u64,
    pub(crate) block_id: String,
    pub(crate) state_root: String,
    ownership_chain_id: String,
    provider_manifests: Vec<String>,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    commitments: Vec<String>,
    #[serde(default)]
    settlements: Vec<SettlementQuery>,
    #[serde(default)]
    sponsorships: Vec<SponsorshipQuery>,
    #[serde(default)]
    transition_settlements: Vec<TransitionSettlementQuery>,
    #[serde(default)]
    dispositions: Vec<processing_disposition::DispositionQuery>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementQuery {
    sender: String,
    intent_id: String,
    signed_intent_digest: String,
    #[serde(default)]
    engineering_etdag_opening: Option<settlement::EngineeringEtdagOpening>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SponsorshipQuery {
    payer: String,
    nonce_before: u64,
    signed_sponsor_digest: String,
    #[serde(default)]
    engineering_etdag_opening: Option<settlement::EngineeringEtdagOpening>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionSettlementQuery {
    address: String,
    pending_reference: String,
    #[serde(default)]
    signed_intent_digest: Option<String>,
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("write to String");
    }
    text
}

fn digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected a 32-byte lowercase hexadecimal value".into());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(display)?;
    }
    Ok(bytes)
}

pub(in crate::services) fn candidate_wire_profile() -> Result<UnactivatedWireProfile, String> {
    UnactivatedWireProfile::new(UnactivatedWireAssignments {
        ordinary_roles_key: 0,
        recovery_pairs_key: 1,
        recovery_only_key: 2,
        initial_status: 0,
        initial_epoch: 0,
        mldsa87_algorithm_id: 1,
        dkg_commitment_bytes: 32,
        recovery_ack_domain: b"AEGIS/RECOVERY-ENROLL/v1",
        recovery_ack_context: b"AEGIS.RECOVERY.ENROLL.V1",
    })
    .map_err(display)
}

/// Returns observations from one exact finalized snapshot. A missing ledger
/// paired with a policy (or the converse) is inconsistent and fails closed.
pub(crate) fn inspect(
    world: &WorldState,
    finality: &FinalizedBlockRecord,
    authenticated_root: &str,
    consensus_time: u64,
    chain_id: u64,
    genesis_hash: &str,
    query: CandidateReadQuery,
) -> Result<Value, String> {
    if query.height != finality.height
        || query.block_id != finality.block_id
        || query.state_root != authenticated_root
    {
        return Err("verified World differs from the selected finalized snapshot".into());
    }
    let selectors = query.addresses.len()
        + query.commitments.len()
        + query.settlements.len()
        + query.sponsorships.len()
        + query.transition_settlements.len()
        + query.dispositions.len();
    if !(1..=MAX_SELECTORS).contains(&selectors)
        || query.provider_manifests.is_empty()
        || query.provider_manifests.len() > MAX_PROVIDER_PINS
    {
        return Err("candidate query exceeds selector or provider bounds".into());
    }
    let providers = query
        .provider_manifests
        .iter()
        .map(|pin| digest(pin))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if providers.contains(&[0; 32]) || providers.len() != query.provider_manifests.len() {
        return Err("candidate query requires distinct nonzero provider pins".into());
    }
    let ownership = ExternalChainPolicy::new(
        ChainId::from_be_bytes(digest(&query.ownership_chain_id)?),
        NativeGenesisHash::from_bytes(digest(genesis_hash)?),
    )
    .map_err(display)?;
    let wire = candidate_wire_profile()?;
    let registry = CandidateProtectedAccounts::new(
        ChainId::from_u64(chain_id),
        ownership,
        &wire,
        UnactivatedCommitmentProfile::candidate_concat_v1(),
        providers.iter().copied().collect(),
    )?;
    let pointer = FinalizedState {
        finalized_height: finality.height,
        finalized_block_id: finality.block_id.clone(),
        state_root: authenticated_root.into(),
    };
    let snapshot = registry.finalized_snapshot(world, &pointer, finality, consensus_time)?;
    let mut addresses = BTreeSet::new();
    let accounts = query
        .addresses
        .into_iter()
        .map(|address| {
            let account = parse_address(&Primitives, &address).map_err(display)?;
            account.validate_spending_destination().map_err(display)?;
            if !addresses.insert(account.lowercase_hex()) {
                return Err("duplicate candidate account selector".into());
            }
            inspect_account(&snapshot, &address, account, &providers)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen_sponsors = BTreeSet::new();
    let sponsorships = query
        .sponsorships
        .into_iter()
        .map(|query| {
            if !seen_sponsors.insert((query.payer.clone(), query.nonce_before)) {
                return Err("duplicate candidate sponsorship selector".into());
            }
            sponsor_settlement::inspect_sponsor_settlement(
                &snapshot,
                &query.payer,
                query.nonce_before,
                &query.signed_sponsor_digest,
                query.engineering_etdag_opening.as_ref(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen_intents = BTreeSet::new();
    let settlements = query
        .settlements
        .into_iter()
        .map(|query| {
            let sender = parse_address(&Primitives, &query.sender).map_err(display)?;
            sender.validate_spending_destination().map_err(display)?;
            let id = digest(&query.intent_id)?;
            if id == [0; 32]
                || !seen_intents.insert((*sender.as_bytes(), id))
                || query.signed_intent_digest.len() != 128
                || !query
                    .signed_intent_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid or duplicate candidate intent selector".into());
            }
            settlement::inspect_transfer_settlement(
                &snapshot,
                sender,
                id,
                &query.signed_intent_digest,
                query.engineering_etdag_opening.as_ref(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut commitments = BTreeSet::new();
    let commitment_records = query
        .commitments
        .into_iter()
        .map(|text| {
            let hash = digest(&text)?;
            if hash == [0; 32] || !commitments.insert(hash) {
                return Err("invalid or duplicate candidate commitment selector".into());
            }
            inspect_commitment(&snapshot, hash)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen_transitions = BTreeSet::new();
    let transition_settlements = query
        .transition_settlements
        .into_iter()
        .map(|query| {
            let account = parse_address(&Primitives, &query.address).map_err(display)?;
            account.validate_spending_destination().map_err(display)?;
            let reference = digest(&query.pending_reference)?;
            if reference == [0; 32] || !seen_transitions.insert((*account.as_bytes(), reference)) {
                return Err("invalid or duplicate candidate transition selector".into());
            }
            transition_settlement::inspect_transition_settlement(
                &snapshot,
                account,
                reference,
                query.signed_intent_digest.as_deref(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut result = json!({
        "status": "unactivated_candidate",
        "address_profile": "SYNW_HEX_EIP55_V1",
        "wire_profile_sha3_256": hex_bytes(&wire.profile_fingerprint().map_err(display)?),
        "ownership_chain_id": query.ownership_chain_id,
        "accounts": accounts,
        "commitments": commitment_records,
        "settlements": settlements,
        "sponsorships": sponsorships,
    });
    if !transition_settlements.is_empty() {
        result["transition_settlements"] = json!(transition_settlements);
    }
    if !query.dispositions.is_empty() {
        let mut envelopes = BTreeSet::new();
        let dispositions = query
            .dispositions
            .iter()
            .map(|query| {
                if !envelopes.insert(&query.opening.envelope_id) {
                    return Err("duplicate protected disposition selector".into());
                }
                processing_disposition::inspect(&snapshot, query)
            })
            .collect::<Result<Vec<_>, String>>()?;
        result["dispositions"] = json!(dispositions);
    }
    Ok(result)
}

/// The proof caller authenticates both headers and their direct relationship.
/// The reader checks each World against its certified root.
pub(crate) struct CandidateWorld<'a> {
    pub(crate) world: &'a WorldState,
    pub(crate) finality: &'a FinalizedBlockRecord,
    pub(crate) state_root: &'a str,
    pub(crate) consensus_time: u64,
}

impl CandidateWorld<'_> {
    fn project(
        &self,
        chain_id: u64,
        genesis: &str,
        query: CandidateReadQuery,
    ) -> Result<Value, String> {
        inspect(
            self.world,
            self.finality,
            self.state_root,
            self.consensus_time,
            chain_id,
            genesis,
            query,
        )
    }
}

/// Prove introduction of the exact encrypted settlement at its included height.
/// Ledger observations are at block boundaries and may reflect other actions.
pub(crate) fn inspect_settlement_inclusion(
    predecessor: CandidateWorld<'_>,
    inclusion: CandidateWorld<'_>,
    chain_id: u64,
    genesis: &str,
    query: CandidateReadQuery,
) -> Result<Value, String> {
    if !query.addresses.is_empty()
        || !query.commitments.is_empty()
        || !query.transition_settlements.is_empty()
        || query
            .settlements
            .iter()
            .any(|record| record.engineering_etdag_opening.is_none())
        || query
            .sponsorships
            .iter()
            .any(|record| record.engineering_etdag_opening.is_none())
    {
        return Err("inclusion proof requires exact encrypted settlement selectors".into());
    }
    if predecessor.finality.height.checked_add(1) != Some(inclusion.finality.height)
        || predecessor.consensus_time > inclusion.consensus_time
    {
        return Err("inclusion requires adjacent, ordered finalized Worlds".into());
    }
    let previous = predecessor.project(
        chain_id,
        genesis,
        CandidateReadQuery {
            height: predecessor.finality.height,
            block_id: predecessor.finality.block_id.clone(),
            state_root: predecessor.state_root.into(),
            ..query.clone()
        },
    )?;
    let dispositions = query.dispositions.clone();
    let mut applied = inclusion.project(chain_id, genesis, query)?;
    let mut touched = BTreeSet::new();
    for (section, payer) in [("settlements", "sender"), ("sponsorships", "payer")] {
        let previous_receipts = previous[section]
            .as_array()
            .ok_or("predecessor receipts missing")?;
        let receipts = applied[section]
            .as_array()
            .ok_or("inclusion receipts missing")?;
        if previous_receipts.len() != receipts.len() {
            return Err("settlement projection count differs at inclusion".into());
        }
        for (earlier, receipt) in previous_receipts.iter().zip(receipts) {
            if earlier["status"] != "no_settlement_in_snapshot"
                || receipt["included_height"].as_u64() != Some(inclusion.finality.height)
                || receipt["inclusion_consensus_timestamp_unix"].as_u64()
                    != Some(inclusion.consensus_time)
            {
                return Err(
                    "settlement was not introduced at the verified inclusion height and time"
                        .into(),
                );
            }
            let payer = receipt[payer].as_str().ok_or("settlement payer missing")?;
            let before = settlement_ledger(predecessor.world, payer)?;
            let after = settlement_ledger(inclusion.world, payer)?;
            let nonce_before = receipt["nonce_before"]
                .as_u64()
                .ok_or("settlement nonce missing")?;
            let nonce_after = receipt["nonce_after"]
                .as_u64()
                .ok_or("settlement nonce missing")?;
            if before.nonce > nonce_before || after.nonce < nonce_after {
                return Err("certified ledger nonce does not cover the settlement charge".into());
            }
            touched.insert(payer.to_owned());
            if let Some(recipient) = receipt["recipient"].as_str() {
                touched.insert(recipient.to_owned());
            }
        }
    }
    for (index, query) in dispositions.iter().enumerate() {
        let receipt = &applied["dispositions"][index];
        if previous["dispositions"][index]["status"] != "no_disposition_in_snapshot"
            || receipt["included_height"].as_u64() != Some(inclusion.finality.height)
            || receipt["inclusion_consensus_timestamp_unix"].as_u64()
                != Some(inclusion.consensus_time)
        {
            return Err("disposition was not introduced at the verified inclusion slot".into());
        }
        let payer = receipt["payer"]
            .as_str()
            .ok_or("disposition payer missing")?;
        let nonce = receipt["request_nonce"]
            .as_u64()
            .ok_or("disposition nonce missing")?;
        let original = synergy_execution::processing_member_claim(predecessor.world, payer, nonce)
            .map_err(debug)?;
        let remaining =
            synergy_execution::processing_member_claim_optional(inclusion.world, payer, nonce)
                .map_err(debug)?;
        if original.member.envelope.tx_commitment != query.opening.envelope_id
            || original.member.authorization_root != query.authorization_root
            || original.member.processing_context_root != query.opening.processing_context_root
            || remaining.is_some_and(|claim| {
                claim.member.envelope.tx_commitment == query.opening.envelope_id
            })
        {
            return Err("disposition does not consume the exact original ordered member".into());
        }
        touched.insert(payer.to_owned());
    }
    applied["ledger"] = json!(touched.into_iter().map(|address| {
        let before = settlement_ledger(predecessor.world, &address)?;
        let after = settlement_ledger(inclusion.world, &address)?;
        Ok(json!({
            "address": address,
            "predecessor": {"balance_nwei": before.balance_nwei.to_string(), "next_nonce": before.nonce},
            "inclusion": {"balance_nwei": after.balance_nwei.to_string(), "next_nonce": after.nonce},
        }))
    }).collect::<Result<Vec<_>, String>>()?);
    applied["predecessor"] = json!({
        "height": predecessor.finality.height,
        "block_id": predecessor.finality.block_id,
        "state_root": predecessor.state_root,
        "consensus_timestamp_unix": predecessor.consensus_time,
        "finality_certificate_id": predecessor.finality.finality_certificate_id,
    });
    Ok(applied)
}

fn settlement_ledger<'a>(
    world: &'a WorldState,
    address: &str,
) -> Result<&'a synergy_state::AccountState, String> {
    world
        .accounts
        .get(address)
        .filter(|account| account.code_hash.is_none())
        .ok_or_else(|| "settlement ledger account missing or inconsistent".into())
}

fn inspect_account(
    snapshot: &FinalizedSnapshot<'_>,
    address: &str,
    account: AccountIdentifier,
    providers: &BTreeSet<[u8; 32]>,
) -> Result<Value, String> {
    let ledger = snapshot.world.accounts.get(address);
    let has_policy = snapshot.world.protocol.contains_key(&account_key(account));
    if !has_policy && ledger.is_none() {
        if snapshot
            .world
            .protocol
            .contains_key(&transition_key(account))
        {
            return Err("absent protected account has pending transition state".into());
        }
        return Ok(json!({
            "address": address, "account_id": account.lowercase_hex(), "status": "absent",
        }));
    }
    let ledger = ledger
        .filter(|entry| entry.code_hash.is_none())
        .ok_or("registered protected account has missing or executable ledger state")?;
    let registry = snapshot.registry;
    let record = registry.read_policy(snapshot.world, account)?;
    if record.registered_height > snapshot.position.height {
        return Err("candidate registration height exceeds selected finality".into());
    }
    let policy = registry.current_policy(&record)?;
    let public = policy.terms();
    if !providers.contains(&public.provider_manifest_hash) {
        return Err("candidate current policy provider is not selected".into());
    }
    // Pending state is interpreted only by the canonical transition owner;
    // malformed or unsupported retained state must not become apparent absence.
    let pending_transition = inspect_pending_transition(snapshot, account)?;
    let roles = public.roles.iter().map(|role| {
        json!({
            "role_id": role.role_id,
            "participant_id": hex_bytes(&role.participant_id),
            "key_version": role.key_version,
            "auth_algorithm": role.auth_algorithm,
            "auth_public_key_base64": BASE64.encode(role.auth_public_key),
        })
    }).collect::<Vec<_>>();
    Ok(json!({
        "address": address,
        "account_id": account.lowercase_hex(),
        "status": "enrolled",
        "account_class": "protected_unified_v1",
        "registered_height": record.registered_height,
        "aggregate_public_point_sec1_hex": hex_bytes(public.evm_public_key),
        "policy_epoch": record.policy_epoch,
        "policy_hash": hex_bytes(&record.policy_hash),
        "policy_cbor_base64": BASE64.encode(policy.encoded()),
        "roles": roles,
        "balance_nwei": ledger.balance_nwei.to_string(),
        "next_nonce": ledger.nonce,
        "pending_transition": pending_transition,
    }))
}

fn inspect_commitment(snapshot: &FinalizedSnapshot<'_>, hash: [u8; 32]) -> Result<Value, String> {
    let key = commit_key(EnrollmentCommitment::from_bytes(hash));
    let Some(bytes) = snapshot.world.protocol.get(&key) else {
        return Ok(json!({ "commitment": hex_bytes(&hash), "status": "absent" }));
    };
    let record: CommitRecord = decode(bytes, MAX_STORED_COMMIT_BYTES)?;
    if encode(&record)? != *bytes
        || record.network != snapshot.registry.network
        || record.commitment != hash
        || !(1..=snapshot.position.height).contains(&record.included_height)
        || !(1..=snapshot.position.consensus_time).contains(&record.consensus_time)
    {
        return Err("candidate commitment conflicts with verified scope".into());
    }
    Ok(json!({
        "commitment": hex_bytes(&hash),
        "status": if record.consumed { "consumed" } else { "unconsumed" },
        "included_height": record.included_height,
        "included_consensus_timestamp_unix": record.consensus_time,
    }))
}
