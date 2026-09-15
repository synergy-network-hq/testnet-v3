//! Proves the canonical governance-authorization envelope actually binds.
//!
//! The scheme it replaces verified a caller-supplied `message: Bytes` against
//! the governance key and nothing else, so a single signature authorized any
//! governed setter on any contract, for any arguments, forever. Every test
//! below is a specific way that used to succeed and must now fail.

use aivm_core::execution::{ContractArtifact, ContractFormat, ExecutionContext, ExecutionStatus};
use aivm_core::state::ContractState;
use aivm_core::stateful_synq::{governance_action_signing_payload, governance_key_fingerprint};
use aivm_core::synq_runtime::{call_synq_contract, deploy_synq_contract, synq_execution_request};
use pqsynq::traits::{DetachedSignature, DigitalSignature};
use pqsynq::Sign;
use std::path::PathBuf;

const CHAIN_ID: u64 = 1266;
const NETWORK_ID: &str = "synergy-testnet";

fn staged(name: &str) -> ContractArtifact {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join("genesis-contracts/staged-governance-v1");
    let read = |ext: &str| {
        std::fs::read(root.join(format!("{name}.{ext}")))
            .unwrap_or_else(|e| panic!("read staged {name}.{ext}: {e}"))
    };
    ContractArtifact {
        format: ContractFormat::SynqBytecodeV1,
        bytes: read("compiled.synq"),
        abi_json: Some(String::from_utf8(read("abi.json")).unwrap()),
        manifest_json: Some(String::from_utf8(read("manifest.json")).unwrap()),
        metadata_json: None,
        compiler_version: None,
        source_hash: None,
    }
}

fn calldata(artifact: &ContractArtifact, method: &str, args: &serde_json::Value) -> Vec<u8> {
    let abi: serde_json::Value =
        serde_json::from_str(artifact.abi_json.as_deref().unwrap()).unwrap();
    let raw = abi["methods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == method)
        .unwrap_or_else(|| panic!("method {method} not in ABI"))["selector"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x")
        .to_string();
    let mut bytes: Vec<u8> = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect();
    bytes.extend_from_slice(&serde_json::to_vec(args).unwrap());
    bytes
}

/// Mirrors the host's `encode_governance_arguments` for the value shapes these
/// tests use. Deliberately re-implemented rather than exported: if the host
/// encoding ever silently changes, these tests break, which is the point.
fn encode_args(values: &[serde_json::Value]) -> Vec<u8> {
    fn push_bytes(out: &mut Vec<u8>, v: &[u8]) {
        out.extend_from_slice(&(v.len() as u64).to_be_bytes());
        out.extend_from_slice(v);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for v in values {
        match v {
            serde_json::Value::Bool(b) => {
                out.push(0x03);
                out.push(u8::from(*b));
            }
            // Address-typed parameters decode to SynQValue::Address (tag 0x06).
            serde_json::Value::String(s) => {
                out.push(0x06);
                push_bytes(&mut out, s.as_bytes());
            }
            other => panic!("unsupported test argument {other}"),
        }
    }
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

struct Governance {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl Governance {
    fn new() -> Self {
        let (public_key, private_key) = Sign::mldsa87().keygen().expect("ML-DSA-87 keygen");
        Self {
            public_key,
            private_key,
        }
    }

    /// Signs exactly what the host will reconstruct.
    #[allow(clippy::too_many_arguments)]
    fn authorize(
        &self,
        contract_id: &str,
        function_id: &str,
        action_args: &[serde_json::Value],
        nonce: u128,
        valid_until_block: u128,
        chain_id: u64,
        network_id: &str,
    ) -> String {
        let payload = governance_action_signing_payload(
            chain_id,
            network_id,
            contract_id.as_bytes(),
            function_id,
            &sha256(&encode_args(action_args)),
            nonce,
            valid_until_block,
            &governance_key_fingerprint(&self.public_key),
        );
        let sig = Sign::mldsa87()
            .detached_sign(&payload, &self.private_key)
            .expect("ML-DSA-87 sign");
        format!("0x{}", hex::encode(sig))
    }

    fn hex_public_key(&self) -> String {
        format!("0x{}", hex::encode(&self.public_key))
    }
}

fn deploy_pair(gov: &Governance) -> (ContractState, ContractArtifact, ContractArtifact) {
    let slashing = staged("Slashing");
    let rewards = staged("RewardDistributor");
    let mut state = ContractState::default();

    let mut deploy =
        |state: &mut ContractState, id: &str, art: &ContractArtifact, args: serde_json::Value| {
            let mut context = ExecutionContext::testnet_1266_for_contract(id, 5_000_000);
            context.caller = b"genesis-deployer".to_vec();
            let receipt = deploy_synq_contract(
                &synq_execution_request(
                    id.to_string(),
                    art.clone(),
                    context,
                    serde_json::to_vec(&args).unwrap(),
                ),
                state,
            );
            assert_eq!(
                receipt.status,
                ExecutionStatus::Succeeded,
                "{id}: {receipt:?}"
            );
        };

    deploy(
        &mut state,
        "slashing",
        &slashing,
        serde_json::json!([
            gov.hex_public_key(),
            "registry",
            "staking",
            "slasher",
            "500",
            "100",
            "500",
            "10",
            "20"
        ]),
    );
    deploy(
        &mut state,
        "rewards",
        &rewards,
        serde_json::json!([gov.hex_public_key(), "distributor"]),
    );
    (state, slashing, rewards)
}

#[allow(clippy::too_many_arguments)]
fn call(
    state: &mut ContractState,
    id: &str,
    artifact: &ContractArtifact,
    method: &str,
    args: serde_json::Value,
    block_height: u64,
    chain_id: u64,
    network_id: &str,
) -> ExecutionStatus {
    let mut context = ExecutionContext::testnet_1266_for_contract(id, 5_000_000);
    context.caller = b"anyone".to_vec();
    context.block_height = block_height;
    context.chain_id = chain_id;
    context.network_id = network_id.to_string();
    let request = synq_execution_request(
        id.to_string(),
        artifact.clone(),
        context,
        calldata(artifact, method, &args),
    );
    call_synq_contract(&request, state).status
}

fn set_authority(
    state: &mut ContractState,
    artifact: &ContractArtifact,
    new_authority: &str,
    nonce: u128,
    valid_until: u128,
    signature: &str,
    block_height: u64,
) -> ExecutionStatus {
    call(
        state,
        "slashing",
        artifact,
        "setSlashingAuthority",
        serde_json::json!([
            new_authority,
            nonce.to_string(),
            valid_until.to_string(),
            signature
        ]),
        block_height,
        CHAIN_ID,
        NETWORK_ID,
    )
}

#[test]
fn valid_governance_authorization_succeeds_exactly_once() {
    let gov = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);
    let args = vec![serde_json::json!("new-authority")];
    let sig = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );

    assert_eq!(
        set_authority(&mut state, &slashing, "new-authority", 0, 0, &sig, 1),
        ExecutionStatus::Succeeded,
        "first valid authorization must succeed"
    );
    assert_ne!(
        set_authority(&mut state, &slashing, "new-authority", 0, 0, &sig, 1),
        ExecutionStatus::Succeeded,
        "replaying the identical authorization must fail"
    );
}

#[test]
fn authorization_does_not_transfer_across_functions() {
    let gov = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);
    let sig = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &[serde_json::json!("new-authority")],
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        call(
            &mut state,
            "slashing",
            &slashing,
            "setPaused",
            serde_json::json!([true, "0", "0", sig]),
            1,
            CHAIN_ID,
            NETWORK_ID
        ),
        ExecutionStatus::Succeeded,
        "a setSlashingAuthority signature must not authorize setPaused"
    );
}

#[test]
fn authorization_does_not_transfer_across_contracts() {
    let gov = Governance::new();
    let (mut state, _, rewards) = deploy_pair(&gov);
    // setPaused(Bool) exists on both contracts with identical argument types.
    let sig = gov.authorize(
        "slashing",
        "setPaused",
        &[serde_json::json!(true)],
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        call(
            &mut state,
            "rewards",
            &rewards,
            "setPaused",
            serde_json::json!([true, "0", "0", sig]),
            1,
            CHAIN_ID,
            NETWORK_ID
        ),
        ExecutionStatus::Succeeded,
        "a signature bound to `slashing` must not authorize the same function on `rewards`"
    );
}

#[test]
fn mutating_an_argument_invalidates_the_authorization() {
    let gov = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);
    let sig = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &[serde_json::json!("intended-authority")],
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        set_authority(&mut state, &slashing, "attacker-authority", 0, 0, &sig, 1),
        ExecutionStatus::Succeeded,
        "substituting the authority argument must invalidate the signature"
    );
    assert_eq!(
        set_authority(&mut state, &slashing, "intended-authority", 0, 0, &sig, 1),
        ExecutionStatus::Succeeded,
        "the same signature is still good for the arguments it actually signed"
    );
}

#[test]
fn authorization_is_bound_to_chain_and_network() {
    let gov = Governance::new();
    let args = vec![serde_json::json!("new-authority")];
    let (mut state, slashing, _) = deploy_pair(&gov);

    let wrong_chain = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        0,
        9999,
        NETWORK_ID,
    );
    assert_ne!(
        set_authority(
            &mut state,
            &slashing,
            "new-authority",
            0,
            0,
            &wrong_chain,
            1
        ),
        ExecutionStatus::Succeeded,
        "a signature for another chain must not verify"
    );

    let wrong_network = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        0,
        CHAIN_ID,
        "synergy-mainnet",
    );
    assert_ne!(
        set_authority(
            &mut state,
            &slashing,
            "new-authority",
            0,
            0,
            &wrong_network,
            1
        ),
        ExecutionStatus::Succeeded,
        "a signature for another network must not verify"
    );
}

#[test]
fn nonce_must_match_exactly_and_advances_only_on_success() {
    let gov = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);
    let args = vec![serde_json::json!("a1")];

    let future = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        7,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        set_authority(&mut state, &slashing, "a1", 7, 0, &future, 1),
        ExecutionStatus::Succeeded,
        "a skipped nonce must fail"
    );

    let good = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_eq!(
        set_authority(&mut state, &slashing, "a1", 0, 0, &good, 1),
        ExecutionStatus::Succeeded,
        "a rejected attempt must not have consumed nonce 0"
    );

    let args2 = vec![serde_json::json!("a2")];
    let stale = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args2,
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        set_authority(&mut state, &slashing, "a2", 0, 0, &stale, 1),
        ExecutionStatus::Succeeded,
        "nonce 0 must not be reusable"
    );
    let next = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args2,
        1,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_eq!(
        set_authority(&mut state, &slashing, "a2", 1, 0, &next, 1),
        ExecutionStatus::Succeeded,
        "nonce advanced by exactly one"
    );
}

#[test]
fn failed_action_validation_does_not_consume_the_nonce() {
    let gov = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);

    // Address(0) is rejected by the contract's own require, *after* the
    // authorization verifies. The nonce increment must roll back with it.
    let zero = vec![serde_json::json!("")];
    let sig_zero = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &zero,
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        set_authority(&mut state, &slashing, "", 0, 0, &sig_zero, 1),
        ExecutionStatus::Succeeded,
        "invalid authority must be rejected by the contract"
    );

    let args = vec![serde_json::json!("valid-authority")];
    let sig = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_eq!(
        set_authority(&mut state, &slashing, "valid-authority", 0, 0, &sig, 1),
        ExecutionStatus::Succeeded,
        "nonce 0 must still be available after a failed action"
    );
}

#[test]
fn expiration_is_enforced_at_a_deterministic_boundary() {
    let gov = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);
    let args = vec![serde_json::json!("a1")];
    let sig = gov.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        100,
        CHAIN_ID,
        NETWORK_ID,
    );

    assert_ne!(
        set_authority(&mut state, &slashing, "a1", 0, 100, &sig, 101),
        ExecutionStatus::Succeeded,
        "an expired authorization must fail"
    );
    assert_eq!(
        set_authority(&mut state, &slashing, "a1", 0, 100, &sig, 100),
        ExecutionStatus::Succeeded,
        "valid_until_block is inclusive"
    );
}

#[test]
fn a_different_governance_key_cannot_authorize() {
    let gov = Governance::new();
    let attacker = Governance::new();
    let (mut state, slashing, _) = deploy_pair(&gov);
    let args = vec![serde_json::json!("a1")];
    let sig = attacker.authorize(
        "slashing",
        "setSlashingAuthority",
        &args,
        0,
        0,
        CHAIN_ID,
        NETWORK_ID,
    );
    assert_ne!(
        set_authority(&mut state, &slashing, "a1", 0, 0, &sig, 1),
        ExecutionStatus::Succeeded,
        "only the contract's governance key may authorize"
    );
}
