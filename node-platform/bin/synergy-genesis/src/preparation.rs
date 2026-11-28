//! Non-executing adapter for staged commissioning inputs, not runtime Genesis.
//!
//! Reads public preparation inputs only. No provider, RNG, hashing, signing,
//! file writes, network, clock or process invocation exists in this module.
//! Identity R1 pp265–271; PoSy R1 pp260–267; QACE R1 pp272–279;
//! Economics v3.2 pp47–50,103–104; owner pre-ceremony directive 2026-11-27.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Component, Path};

pub const TARGET_CHAIN_ID: u64 = 9969;
pub const CEREMONY_REQUIRED: &str = "CEREMONY_AUTHORIZATION_REQUIRED: Testnet 9969 preparation only; actual Genesis bytes/hash, authority signing, release signing and execution are disabled. No authorization verifier is implemented; flags, environment values and staging records cannot grant ceremony authority.";

/// There is intentionally no bool, environment variable or token-string bypass.
/// A future approved ceremony verifier must be implemented and qualified first.
pub fn require_ceremony_for_chain(chain_id: u64) -> Result<(), String> {
    if chain_id == TARGET_CHAIN_ID {
        return Err(CEREMONY_REQUIRED.into());
    }
    Ok(())
}

macro_rules! public_struct {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}

// Unit fields require literal JSON null; fabricated live values cannot deserialize.
public_struct!(StagedGenesis {
    chain_id: u64,
    environment: String,
    package_schema: String,
    status: String,
    artifact_type: String,
    activation_allowed: bool,
    network_file: String,
    initial_height: u64,
    initial_epoch_candidate: u64,
    genesis_time: (),
    network_incarnation_commitment: (),
    validator_roster_file: String,
    monetary_allocation_file: String,
    protocol_configuration_file: String,
    system_registry_file: String,
    address_registry_file: String,
    formation_registry_file: String,
    formation_result_file: String,
    release_bindings_file: String,
    initial_state: StagedState,
    system_contracts: StagedContracts,
    integrity: StagedIntegrity
});
public_struct!(StagedState {
    balances:(), bond_positions:(), registry_state:(), native_asset:StagedNativeAsset,
    transactions:Vec<()>, receipts:Vec<()>, historical_state_import:bool,
    execution_state_root:(), aivm_state_root:(), receipt_root:(), allocation_commitment:(),
    validator_set_commitment:(), system_registry_commitment:(), profile_set_commitment:()
});
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedNativeAsset {
    pub token_address: (),
    pub decimals: u8,
    pub issued_nwei: String,
    /// Public metadata revision; absent in historical preparation inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}
public_struct!(StagedContracts { required_deployments:(), deployment_receipts:Vec<()>, no_automatic_historical_redeploy:bool });
public_struct!(StagedIntegrity {
    genesis_commitment:(), root_approvals:Vec<()>, genesis_schema_profile:(),
    canonicalization_profile:(), formation_authority_closure_evidence:()
});
public_struct!(StagedRoster {
    chain_id:u64, environment:String, package_schema:String, status:String,
    requested_host_count:usize, reference_fleet_count:usize, conditional_alternative_count:usize,
    selected_count_for_preparation:usize, six_member_activation_approved:bool,
    initial_equal_weight_candidate:EqualWeightCandidate, members:Vec<StagedValidator>,
    future_identity_generation:String, separate_hosts_required:bool
});
public_struct!(EqualWeightCandidate {
    count: usize,
    total_weight_units: u64,
    minimum_signers: usize,
    minimum_weight_units: u64,
    maximum_byzantine_count_strictly_below_one_third: usize,
    maximum_unavailable_at_equal_weights: usize
});
public_struct!(StagedValidator {
    slot: String,
    host_inventory_label: String,
    host_identity_evidence: (),
    namespace: String,
    node_class: u8,
    desired_genesis_member: bool,
    activated: bool,
    bond_nwei: String,
    candidate_equal_weight_units: u64,
    node_id: (),
    node_birth_nonce_hex: (),
    node_birth_root: (),
    birth_authority_policy: (),
    role_keys: (),
    proofs_of_possession: (),
    peer_identity: (),
    vpn_private_locator: (),
    package_qualification: (),
    bond_owner_binding: (),
    reward_beneficiary_binding: ()
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuorumPlan {
    pub count: usize,
    pub weight: u128,
    pub minimum_signers: usize,
    pub minimum_weight: u128,
}

/// Same actual signer set must satisfy both strict inequalities. These are
/// hypothetical prepared weights, never an authenticated electorate or seal.
pub fn quorum_plan(weights: &[u64]) -> Result<QuorumPlan, String> {
    if weights.is_empty() || weights.len() > 4096 || weights.contains(&0) {
        return Err("invalid bounded positive weight set".into());
    }
    let total = weights
        .iter()
        .try_fold(0_u128, |a, w| a.checked_add(u128::from(*w)))
        .ok_or("weight overflow")?;
    Ok(QuorumPlan {
        count: weights.len(),
        weight: total,
        minimum_signers: 2 * weights.len() / 3 + 1,
        minimum_weight: 2 * total / 3 + 1,
    })
}
pub fn has_dual_quorum(weights: &[u64], signers: &[usize]) -> Result<bool, String> {
    let plan = quorum_plan(weights)?;
    let mut seen = BTreeSet::new();
    let mut weight = 0_u128;
    for &index in signers {
        if index >= weights.len() || !seen.insert(index) {
            return Err("duplicate or out-of-range signer".into());
        }
        weight = weight
            .checked_add(u128::from(weights[index]))
            .ok_or("weight overflow")?;
    }
    Ok(seen.len() >= plan.minimum_signers && weight >= plan.minimum_weight)
}

#[derive(Debug, Clone, Serialize)]
pub struct Dependency {
    pub id: String,
    pub value: (),
    pub reason: String,
    pub required_before: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Stage {
    pub id: String,
    pub requires: Vec<String>,
    pub status: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct PreparationPlan {
    pub schema: String,
    pub phase: String,
    pub target_chain_id: u64,
    pub runtime_compatible: bool,
    pub actual_generation_authorized: bool,
    pub runtime_outputs: (),
    pub quorum_candidate: QuorumPlan,
    pub stages: Vec<Stage>,
    pub dependencies: Vec<Dependency>,
    pub runtime_adapter_gaps: Vec<String>,
    pub validator_slots: Vec<String>,
    pub input_references: Vec<String>,
}

fn common(
    chain: u64,
    environment: &str,
    schema: &str,
    status: &str,
    expected: u64,
) -> Result<(), String> {
    if chain != expected
        || environment != "testnet"
        || schema != "synergy.commissioning-inputs/1"
        || status != "staged_not_runtime_genesis"
    {
        return Err("input is not the selected preparation-only commissioning contract".into());
    }
    Ok(())
}
fn public_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.is_ascii() && !value.contains(char::is_control)
}
fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains(char::is_control)
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

pub fn plan(genesis: &[u8], roster: &[u8]) -> Result<PreparationPlan, String> {
    plan_for_chain(genesis, roster, TARGET_CHAIN_ID)
}
fn plan_for_chain(genesis: &[u8], roster: &[u8], expected: u64) -> Result<PreparationPlan, String> {
    if genesis.len() > 16 * 1024 * 1024 || roster.len() > 1024 * 1024 {
        return Err("preparation input exceeds bound".into());
    }
    // Deserialize errors can quote rejected scalar values. Never echo input
    // contents, including accidental credentials, into public plan diagnostics.
    let g: StagedGenesis = serde_json::from_slice(genesis).map_err(|e| {
        format!(
            "invalid staged Genesis input at line {} column {}",
            e.line(),
            e.column()
        )
    })?;
    let r: StagedRoster = serde_json::from_slice(roster).map_err(|e| {
        format!(
            "invalid staged roster input at line {} column {}",
            e.line(),
            e.column()
        )
    })?;
    common(
        g.chain_id,
        &g.environment,
        &g.package_schema,
        &g.status,
        expected,
    )?;
    common(
        r.chain_id,
        &r.environment,
        &r.package_schema,
        &r.status,
        expected,
    )?;
    let refs = vec![
        g.network_file,
        g.validator_roster_file,
        g.monetary_allocation_file,
        g.protocol_configuration_file,
        g.system_registry_file,
        g.address_registry_file,
        g.formation_registry_file,
        g.formation_result_file,
        g.release_bindings_file,
    ];
    if refs.iter().any(|p| !safe_relative(p)) {
        return Err("unsafe or unbounded package-relative reference".into());
    }
    if g.artifact_type != "commissioning_source_not_node_loadable_genesis"
        || g.activation_allowed
        || g.initial_height != 0
        || g.initial_epoch_candidate != 0
        || g.initial_state.historical_state_import
        || !g.initial_state.transactions.is_empty()
        || !g.initial_state.receipts.is_empty()
        || !g.system_contracts.deployment_receipts.is_empty()
        || !g.system_contracts.no_automatic_historical_redeploy
        || !g.integrity.root_approvals.is_empty()
        || g.initial_state
            .native_asset
            .name
            .as_deref()
            .is_some_and(|n| n != "Testnet Synergy Coin")
        || g.initial_state
            .native_asset
            .symbol
            .as_deref()
            .is_some_and(|s| s != "tSNRG")
        || g.initial_state.native_asset.decimals != 9
        || g.initial_state.native_asset.issued_nwei != "202000000000000000"
    {
        return Err("preparation must contain no activated/imported/executed state and exact staged native units".into());
    }
    if r.members.len() != 6
        || r.requested_host_count != r.members.len()
        || r.selected_count_for_preparation != r.members.len()
        || r.reference_fleet_count != 7
        || r.conditional_alternative_count != 5
        || r.six_member_activation_approved
        || !r.separate_hosts_required
        || r.future_identity_generation != "on governed enrollment; no pre-generated future keys"
    {
        return Err("six preparation slots are not an approved or sealed electorate".into());
    }
    let mut slots = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    for (index, m) in r.members.iter().enumerate() {
        if !public_label(&m.slot)
            || !public_label(&m.host_inventory_label)
            || m.slot != format!("validator-{:02}", index + 1)
            || m.host_inventory_label != format!("Val{}", index + 1)
            || !slots.insert(m.slot.clone())
            || !hosts.insert(m.host_inventory_label.clone())
            || m.namespace != "synv1"
            || m.node_class != 1
            || m.activated
            || !m.desired_genesis_member
            || m.bond_nwei != "50000000000000"
            || m.candidate_equal_weight_units != 1
        {
            return Err(
                "invalid, duplicated, activated or unbacked validator preparation slot".into(),
            );
        }
    }
    let weights = r
        .members
        .iter()
        .map(|m| m.candidate_equal_weight_units)
        .collect::<Vec<_>>();
    let quorum = quorum_plan(&weights)?;
    let q = &r.initial_equal_weight_candidate;
    if q.count != quorum.count
        || u128::from(q.total_weight_units) != quorum.weight
        || q.minimum_signers != quorum.minimum_signers
        || u128::from(q.minimum_weight_units) != quorum.minimum_weight
        || q.maximum_byzantine_count_strictly_below_one_third != (quorum.count - 1) / 3
        || q.maximum_unavailable_at_equal_weights != quorum.count - quorum.minimum_signers
    {
        return Err("staged quorum arithmetic does not match the actual prepared set".into());
    }
    let stages = formation_stages();
    validate_stage_order(&stages)?;
    let mut dependencies = Vec::new();
    let mut pending = |id: String, reason: &str, stage: &str| {
        dependencies.push(Dependency {
            id,
            value: (),
            reason: reason.into(),
            required_before: stage.into(),
        })
    };
    for (id,reason,stage) in [
        ("ceremony_authorization","Separate approved ceremony authorization and qualified verifier absent; no flags/environment bypass","authenticate_roots_profiles"),
        ("fleet_resolution","Six prepared hosts versus seven reference/five conditional requires owner resolution before sealing","freeze_registry"),
        ("bootstrap_roots","Fresh independently controlled PQ roots and exact threshold/custody/approval profile unset","network_birth_nic"),
        ("executable_profiles","Exact schema/provider/build/ABI digests and formal executable codec approval unset","network_birth_nic"),
        ("formation_session","PQ-FORMATION-SESSION/1 exact authenticated NIC-only message/key/fence profile not qualified","nic_root_approvals"),
        ("fresh_ceremony_nonce","No fresh nonce is generated; staged metadata nonce is not ceremony evidence","network_birth_nic"),
        ("randomness","Qualified collective seed construction/participants/evidence unavailable; no local fallback","randomness_assignments"),
        ("native_transaction_contract","Exact native QACE transaction/receipt/replay preimages and full-width identifier consumers unresolved","execute_genesis"),
        ("fee_profile_atomicity","Cumulative allocator exists but actual restricted state/receipt/replay integration remains open","execute_genesis"),
        ("supply_and_funding_approval","Staged202m is not authenticated funding or approval; later issuance/rewards/source restrictions require reconciliation","execute_genesis"),
        ("independent_hosts","Actual independent host/trust/power/operator evidence and uniform authenticated platform release NOT RUN","activate_close_formation"),
        ("closure_and_runtime","One-way formation closure and runtime NIC+finalGenesis/profile verification require implementation qualification","activate_close_formation")
    ] { pending(id.into(),reason,stage); }
    for m in &r.members {
        for (suffix,reason) in [
            ("birth_root","Fresh full ML-DSA-87 root; source role is not provider qualification"),
            ("consensus","Fresh ML-DSA-65 consensus key, scoped delegation and durable signing/fence state"),
            ("transport","Fresh separate ML-DSA-65 transport-authentication key; no consensus reuse"),
            ("formation","Dedicated fresh formation-only key/profile/custody and irreversible closure binding"),
            ("possession_policy","Complete birth/current authority policy, independent PoP, generations and recovery/fencing"),
            ("bond_and_beneficiary","Fresh bond-owner and reward-beneficiary bindings distinct from node identity; no historical funds/import"),
            ("session_kem","Ephemeral ML-KEM-1024 candidate session operations with authenticated transcript/KDF/AEAD; not counted as persistent keys")
        ] { pending(format!("{}.{}",m.slot,suffix),reason,"initial_identities_formation_keys"); }
    }
    for kind in [
        "general_treasury",
        "treasury_recovery",
        "security_forfeiture",
        "fee_rounding_escrow",
    ] {
        pending(format!("economic_record.{kind}"),"Distinct opaque Protocol Registry record, actual canonical state binding, source lots, receive/spend/replay policy and backing unset; no new SRPA or ordinary private-key wallet","execute_genesis");
    }
    Ok(PreparationPlan {schema:"synergy.genesis-preparation-plan/1".into(),phase:"pre_ceremony".into(),
        target_chain_id:expected,runtime_compatible:false,actual_generation_authorized:false,runtime_outputs:(),
        quorum_candidate:quorum,stages,dependencies,validator_slots:r.members.iter().map(|m|m.slot.clone()).collect(),input_references:refs,
        runtime_adapter_gaps:vec![
            "UnsignedGenesis expects format_version/network/validators/ETDAG/state_root/trust_key_id, not commissioning references or nulls".into(),
            "GenesisNetwork.network_id is String and lacks typed authenticated NIC plus finalGenesis/profile coordinate".into(),
            "Historical Genesis canonical_bytes is JSON and genesis_hash is domain-framed SHA3-256; no approved R1 Genesis commitment inferred".into(),
            "GenesisValidator stores one ML-DSA-65 public key, not fresh root/consensus/transport/formation roles and complete policy/PoP".into(),
            "AuthorityPayload uses one trust signer and historical hash fields; indexed bootstrap approvals/full-width identity consumers not integrated".into(),
            "NodeConfiguration expects runtime identity/key/provider/manifest/custody paths; preparation nulls are intentionally not node-loadable".into()
        ]})
}

pub fn formation_stages() -> Vec<Stage> {
    let mut result = Vec::new();
    let mut previous: Option<&str> = None;
    for id in [
        "authenticate_roots_profiles",
        "network_birth_nic",
        "nic_root_approvals",
        "initial_identities_formation_keys",
        "freeze_registry",
        "authenticated_pre_seed",
        "randomness_assignments",
        "execute_genesis",
        "final_genesis_commitment",
        "genesis_root_approvals",
        "activate_close_formation",
    ] {
        result.push(Stage {
            id: id.into(),
            requires: previous.into_iter().map(str::to_owned).collect(),
            status: "NOT_RUN_CEREMONY_REQUIRED".into(),
        });
        previous = Some(id);
    }
    result
}
pub fn validate_stage_order(stages: &[Stage]) -> Result<(), String> {
    let expected = formation_stages();
    if stages.len() != expected.len()
        || stages
            .iter()
            .zip(&expected)
            .any(|(a, b)| a.id != b.id || a.requires != b.requires)
    {
        return Err(
            "formation stage graph differs from the complete acyclic preparation contract".into(),
        );
    }
    let mut prior = BTreeSet::new();
    for stage in stages {
        if !public_label(&stage.id)
            || stage.requires.iter().any(|d| !prior.contains(d))
            || !prior.insert(stage.id.clone())
        {
            return Err("duplicate, circular or out-of-order formation dependency".into());
        }
    }
    Ok(())
}

/// Exact preparation schemas are constructed from the adapter's fixed template.
/// No schema here is an approved runtime, cryptographic or signing codec.
pub fn input_schemas() -> Value {
    let mut genesis = schema_for(&genesis_template(TARGET_CHAIN_ID));
    // Metadata was added by the supplied revision. The parser and schema both
    // accept the older preparation shape while enforcing the exact name if set.
    genesis["properties"]["initial_state"]["properties"]["native_asset"]["required"]
        .as_array_mut()
        .unwrap()
        .retain(|field| field != "name" && field != "symbol");
    json!({"schema":"synergy.genesis-preparation-schemas/1","runtime_compatible":false,
        "genesis":genesis,"roster":schema_for(&roster_template(TARGET_CHAIN_ID))})
}
fn schema_for(value: &Value) -> Value {
    match value {
        Value::Null => json!({"type":"null"}),
        Value::Array(values) if values.is_empty() => json!({"type":"array","maxItems":0}),
        Value::Array(values) => {
            json!({"type":"array","minItems":6,"maxItems":6,"items":schema_for(&values[0])})
        }
        Value::Object(map) => {
            let properties = map
                .iter()
                .map(|(k, v)| {
                    let schema = if v.is_string()
                        && !(k.ends_with("_file")
                            || matches!(k.as_str(), "slot" | "host_inventory_label"))
                    {
                        json!({"type":"string","const":v})
                    } else {
                        schema_for(v)
                    };
                    (k.clone(), schema)
                })
                .collect::<serde_json::Map<_, _>>();
            json!({"type":"object","additionalProperties":false,"properties":properties,"required":map.keys().collect::<Vec<_>>()})
        }
        Value::String(_) => json!({"type":"string","maxLength":512}),
        Value::Bool(_) => json!({"const":value}),
        Value::Number(_) => json!({"type":"integer","const":value}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SYNTHETIC_CHAIN: u64 = u64::MAX - 1;
    fn encoded(g: &Value, r: &Value) -> (Vec<u8>, Vec<u8>) {
        (
            serde_json::to_vec(g).unwrap(),
            serde_json::to_vec(r).unwrap(),
        )
    }
    fn fixture() -> (Value, Value) {
        (
            genesis_template(SYNTHETIC_CHAIN),
            roster_template(SYNTHETIC_CHAIN),
        )
    }
    fn synthetic_plan(g: &Value, r: &Value) -> Result<PreparationPlan, String> {
        let (g, r) = encoded(g, r);
        plan_for_chain(&g, &r, SYNTHETIC_CHAIN)
    }

    #[test]
    fn native_asset_name_accepts_exact_metadata_revision_and_old_preparation_shape() {
        let (mut g, r) = fixture();
        assert!(synthetic_plan(&g, &r).is_ok());
        g["initial_state"]["native_asset"]
            .as_object_mut()
            .unwrap()
            .remove("name");
        g["initial_state"]["native_asset"]
            .as_object_mut()
            .unwrap()
            .remove("symbol");
        assert!(synthetic_plan(&g, &r).is_ok());
        g["initial_state"]["native_asset"]["symbol"] = json!("unapproved symbol");
        assert!(synthetic_plan(&g, &r).is_err());
        g["initial_state"]["native_asset"]
            .as_object_mut()
            .unwrap()
            .remove("symbol");
        g["initial_state"]["native_asset"]["name"] = json!("unapproved metadata revision");
        assert!(synthetic_plan(&g, &r).is_err());
    }
    #[test]
    fn typed_public_preparation_returns_no_runtime_or_ceremony_output() {
        let (g, r) = fixture();
        let before = encoded(&g, &r);
        let plan = synthetic_plan(&g, &r).unwrap();
        assert_eq!(before, encoded(&g, &r));
        assert!(!plan.runtime_compatible && !plan.actual_generation_authorized);
        assert_eq!(
            plan.quorum_candidate,
            QuorumPlan {
                count: 6,
                weight: 6,
                minimum_signers: 5,
                minimum_weight: 5
            }
        );
        assert_eq!(plan.stages.len(), 11);
        assert!(plan
            .stages
            .iter()
            .all(|s| s.status == "NOT_RUN_CEREMONY_REQUIRED"));
        assert_eq!(
            plan.dependencies
                .iter()
                .filter(|d| d.id.starts_with("economic_record."))
                .count(),
            4
        );
        let value = serde_json::to_value(plan).unwrap();
        assert!(value["runtime_outputs"].is_null());
        assert!(value["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["value"].is_null()));
    }
    #[test]
    fn fabricated_live_results_and_unknown_or_duplicate_fields_fail_closed() {
        let (g, r) = fixture();
        for pointer in [
            "/genesis_time",
            "/network_incarnation_commitment",
            "/initial_state/balances",
            "/initial_state/bond_positions",
            "/initial_state/registry_state",
            "/initial_state/native_asset/token_address",
            "/initial_state/execution_state_root",
            "/integrity/genesis_commitment",
            "/integrity/genesis_schema_profile",
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("fixture-output-must-not-enter-live-field");
            assert!(synthetic_plan(&bad, &r).is_err(), "accepted {pointer}");
        }
        for key in [
            "node_id",
            "node_birth_nonce_hex",
            "node_birth_root",
            "birth_authority_policy",
            "role_keys",
            "proofs_of_possession",
            "peer_identity",
            "vpn_private_locator",
            "bond_owner_binding",
            "reward_beneficiary_binding",
        ] {
            let mut bad = r.clone();
            bad["members"][0][key] = json!({"unapproved":"fixture"});
            assert!(synthetic_plan(&g, &bad).is_err(), "accepted {key}");
        }
        let mut bad = g.clone();
        bad["ceremony_authorized"] = json!(true);
        assert!(synthetic_plan(&bad, &r).is_err());
        let (mut gb, rb) = encoded(&g, &r);
        let original = String::from_utf8(gb).unwrap();
        gb = original.replacen('{', "{\"chain_id\":1,", 1).into_bytes();
        assert!(plan_for_chain(&gb, &rb, SYNTHETIC_CHAIN).is_err());
    }
    #[test]
    fn activation_history_wrong_units_and_path_escape_cannot_be_planned() {
        let (g, r) = fixture();
        for (pointer, value) in [
            ("/activation_allowed", json!(true)),
            ("/initial_state/historical_state_import", json!(true)),
            ("/initial_state/transactions", json!([null])),
            ("/integrity/root_approvals", json!([null])),
            (
                "/initial_state/native_asset/issued_nwei",
                json!("0202000000000000000"),
            ),
            ("/network_file", json!("../outside.json")),
            ("/network_file", json!("/absolute.json")),
            ("/network_file", json!("..\\outside.json")),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(synthetic_plan(&bad, &r).is_err(), "accepted {pointer}");
        }
        let mut bad = r.clone();
        bad["six_member_activation_approved"] = json!(true);
        assert!(synthetic_plan(&g, &bad).is_err());
        bad = r.clone();
        bad["members"][1]["host_inventory_label"] =
            bad["members"][0]["host_inventory_label"].clone();
        assert!(synthetic_plan(&g, &bad).is_err());
        bad = r.clone();
        bad["initial_equal_weight_candidate"]["minimum_signers"] = json!(4);
        assert!(synthetic_plan(&g, &bad).is_err());
        let (gb, rb) = encoded(&g, &r);
        assert!(plan(&gb, &rb).is_err()); // synthetic inputs cannot become target records
    }
    #[test]
    fn strict_quorum_uses_same_unique_signer_set_and_actual_denominators() {
        assert_eq!(quorum_plan(&[1; 6]).unwrap().minimum_signers, 5);
        assert!(!has_dual_quorum(&[1; 6], &[0, 1, 2, 3]).unwrap());
        assert!(has_dual_quorum(&[1; 6], &[0, 1, 2, 3, 4]).unwrap());
        assert!(!has_dual_quorum(&[100, 1, 1, 1, 1, 1], &[1, 2, 3, 4, 5]).unwrap());
        assert!(!has_dual_quorum(&[100, 1, 1, 1, 1, 1], &[0]).unwrap());
        assert!(has_dual_quorum(&[1; 6], &[0, 0, 1, 2, 3, 4]).is_err());
        assert!(has_dual_quorum(&[1; 6], &[6]).is_err());
        assert_eq!(quorum_plan(&[1; 7]).unwrap().minimum_signers, 5);
        assert_eq!(quorum_plan(&[1; 5]).unwrap().minimum_signers, 4);
        assert!(quorum_plan(&[1, 0]).is_err());
    }
    #[test]
    fn acyclic_formation_requires_complete_graph_and_no_recursive_genesis() {
        let stages = formation_stages();
        validate_stage_order(&stages).unwrap();
        let mut bad = stages.clone();
        bad[1].requires.push("final_genesis_commitment".into());
        assert!(validate_stage_order(&bad).is_err());
        bad = stages.clone();
        bad.swap(1, 8);
        assert!(validate_stage_order(&bad).is_err());
        assert!(validate_stage_order(&stages[..10]).is_err());
        assert!(
            stages
                .iter()
                .position(|s| s.id == "network_birth_nic")
                .unwrap()
                < stages
                    .iter()
                    .position(|s| s.id == "execute_genesis")
                    .unwrap()
        );
    }
    #[test]
    fn preparation_is_not_runtime_genesis_and_ceremony_guard_is_not_a_flag() {
        let (g, _) = fixture();
        assert!(serde_json::from_value::<crate::builder::UnsignedGenesis>(g.clone()).is_err());
        assert!(serde_json::from_value::<synergy_config::NodeConfiguration>(g).is_err());
        assert_eq!(
            require_ceremony_for_chain(TARGET_CHAIN_ID).unwrap_err(),
            CEREMONY_REQUIRED
        );
        assert!(require_ceremony_for_chain(SYNTHETIC_CHAIN).is_ok());
        let input = crate::builder::UnsignedGenesis {
            format_version: 2,
            network: crate::network::GenesisNetwork {
                chain_id: TARGET_CHAIN_ID,
                network_id: String::new(),
                protocol_version: String::new(),
                activation_unix: 0,
                autonomous_epoch_protocol: None,
                ethereum_compatibility: None,
            },
            validators: vec![],
            etdag: crate::etdag::GenesisEtdag {
                parameters: Default::default(),
                cryptographic_profile_root: String::new(),
                ingress_kem_registry_root: synergy_etdag::EtdagDigest(String::new()),
            },
            initial_state_root: String::new(),
            authority_trust_key_id: String::new(),
        };
        // Target integer only: no identity/key/nonce/commitment or live bytes.
        assert_eq!(input.canonical_bytes().unwrap_err(), CEREMONY_REQUIRED);
        assert_eq!(input.genesis_hash().unwrap_err(), CEREMONY_REQUIRED);
        struct RejectAllSigner;
        impl synergy_aegis::AegisSigner for RejectAllSigner {
            fn sign(
                &self,
                _: &synergy_aegis::KeyId,
                _: &synergy_aegis::SigningContext,
                _: &[u8],
            ) -> Result<synergy_aegis::Signature, synergy_aegis::SigningError> {
                panic!("ceremony rejection must precede signer/provider/RNG work")
            }
        }
        assert_eq!(
            crate::signing::sign(
                input,
                &RejectAllSigner,
                synergy_aegis::KeyId::new("test-only-unset-authority").unwrap()
            )
            .unwrap_err(),
            CEREMONY_REQUIRED
        );
    }
    #[test]
    fn historical_runtime_parser_is_not_silently_broadened_by_candidate_preparation() {
        // Fixed presentation-shaped synthetic input, no derivation or keypair.
        for class in 1..=5 {
            let presentation = format!("synv{class}.2.{}", "A".repeat(64));
            assert_eq!(presentation.len(), 72);
            assert!(synergy_protocol_types::NodeAddress::parse(presentation).is_err());
        }
    }
    #[test]
    fn rejected_scalar_contents_never_enter_public_diagnostics() {
        let (mut g, r) = fixture();
        g["genesis_time"] = json!("DO_NOT_LOG_SYNTHETIC_PRIVATE_VALUE");
        let error = synthetic_plan(&g, &r).unwrap_err();
        assert!(!error.contains("DO_NOT_LOG"));
        let (g, mut r) = fixture();
        r["members"][0]["role_keys"] = json!("DO_NOT_LOG_SYNTHETIC_PRIVATE_VALUE");
        let error = synthetic_plan(&g, &r).unwrap_err();
        assert!(!error.contains("DO_NOT_LOG"));
    }
}
// Public-only adapter templates contain no keys, addresses, nonce, commitment or
// credential, and cannot deserialize as runtime UnsignedGenesis.
pub fn genesis_template(chain_id: u64) -> Value {
    json!({"chain_id":chain_id,"environment":"testnet","package_schema":"synergy.commissioning-inputs/1","status":"staged_not_runtime_genesis",
        "artifact_type":"commissioning_source_not_node_loadable_genesis","activation_allowed":false,"network_file":"config/network.json",
        "initial_height":0,"initial_epoch_candidate":0,"genesis_time":null,"network_incarnation_commitment":null,
        "validator_roster_file":"config/roster.json","monetary_allocation_file":"config/monetary.json","protocol_configuration_file":"config/protocol.json",
        "system_registry_file":"config/system.json","address_registry_file":"config/address.json","formation_registry_file":"formation/registry.json",
        "formation_result_file":"formation/result.json","release_bindings_file":"formation/release.json",
        "initial_state":{"balances":null,"bond_positions":null,"registry_state":null,"native_asset":{"name":"Testnet Synergy Coin","symbol":"tSNRG","token_address":null,"decimals":9,"issued_nwei":"202000000000000000"},
            "transactions":[],"receipts":[],"historical_state_import":false,"execution_state_root":null,"aivm_state_root":null,"receipt_root":null,"allocation_commitment":null,
            "validator_set_commitment":null,"system_registry_commitment":null,"profile_set_commitment":null},
        "system_contracts":{"required_deployments":null,"deployment_receipts":[],"no_automatic_historical_redeploy":true},
        "integrity":{"genesis_commitment":null,"root_approvals":[],"genesis_schema_profile":null,"canonicalization_profile":null,"formation_authority_closure_evidence":null}})
}
pub fn roster_template(chain_id: u64) -> Value {
    json!({"chain_id":chain_id,"environment":"testnet","package_schema":"synergy.commissioning-inputs/1","status":"staged_not_runtime_genesis",
        "requested_host_count":6,"reference_fleet_count":7,"conditional_alternative_count":5,"selected_count_for_preparation":6,
        "six_member_activation_approved":false,"initial_equal_weight_candidate":{"count":6,"total_weight_units":6,"minimum_signers":5,"minimum_weight_units":5,
            "maximum_byzantine_count_strictly_below_one_third":1,"maximum_unavailable_at_equal_weights":1},
        "members":(1..=6).map(|n|json!({"slot":format!("validator-{n:02}"),"host_inventory_label":format!("Val{n}"),"host_identity_evidence":null,
            "namespace":"synv1","node_class":1,"desired_genesis_member":true,"activated":false,"bond_nwei":"50000000000000","candidate_equal_weight_units":1,
            "node_id":null,"node_birth_nonce_hex":null,"node_birth_root":null,"birth_authority_policy":null,"role_keys":null,"proofs_of_possession":null,
            "peer_identity":null,"vpn_private_locator":null,"package_qualification":null,"bond_owner_binding":null,"reward_beneficiary_binding":null})).collect::<Vec<_>>(),
        "future_identity_generation":"on governed enrollment; no pre-generated future keys","separate_hosts_required":true})
}
