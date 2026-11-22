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

#[derive(Deserialize)]
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettlementQuery {
    sender: String,
    intent_id: String,
    signed_intent_digest: String,
    #[serde(default)]
    engineering_etdag_opening: Option<settlement::EngineeringEtdagOpening>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SponsorshipQuery {
    payer: String,
    nonce_before: u64,
    signed_sponsor_digest: String,
    #[serde(default)]
    engineering_etdag_opening: Option<settlement::EngineeringEtdagOpening>,
}

#[derive(Deserialize)]
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

pub(super) fn candidate_wire_profile() -> Result<UnactivatedWireProfile, String> {
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
        + query.transition_settlements.len();
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
    Ok(result)
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
    let enrollment =
        CanonicalEnrollment::decode(&record.enrollment, registry.wire).map_err(display)?;
    let policy = registry.canonical_policy(&record, &enrollment)?;
    let public = policy.policy();
    if !providers.contains(&public.provider_manifest_hash) {
        return Err("candidate current policy provider is not selected".into());
    }
    // Pending state is interpreted only by the canonical transition owner;
    // malformed or unsupported retained state must not become apparent absence.
    let pending_transition = inspect_pending_transition(snapshot, account)?;
    let roles = public.roles.map(|role| {
        json!({
            "role_id": role.role_id,
            "participant_id": hex_bytes(&role.participant_id),
            "key_version": role.key_version,
            "auth_algorithm": role.auth_algorithm,
            "auth_public_key_base64": BASE64.encode(role.auth_public_key),
        })
    });
    Ok(json!({
        "address": address,
        "account_id": account.lowercase_hex(),
        "status": "enrolled",
        "account_class": "protected_unified_v1",
        "registered_height": record.registered_height,
        "aggregate_public_point_sec1_hex": hex_bytes(&public.evm_public_key),
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
