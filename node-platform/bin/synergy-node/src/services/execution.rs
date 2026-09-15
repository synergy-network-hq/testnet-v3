use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use synergy_aegis::{
    AegisPolicy, AegisVerifier, KeyId, PqSynqVerifier, PqvmVerifier, Signature, SignatureAlgorithm,
    SigningContext, VerifiedPqSynqOperation,
};
use synergy_aivm::CanonicalAivmSynqVm;
use synergy_block::{hash_block_bytes, BlockBody};
use synergy_config::{NodeConfiguration, StorageConfiguration};
use synergy_etdag::execution::PreparedProtectedBatch;
use synergy_execution::{
    BlockExecutionOutcome, BlockExecutionScheduler, CanonicalTransactionDispatcher,
    ExecutionCandidate, FeeSchedule, GovernanceDispatcher, GovernanceOperation, NativeDispatcher,
    NativeOperation, SxcpDispatcher, SxcpExecutor, SynqDispatcher, SynqRuntime, SystemDispatcher,
    SystemOperation, TransactionDispatch, TransactionExecutionContext,
};
use synergy_governance::GovernanceExecution;
use synergy_naming::{
    NamingAuthorization, NamingAuthorizationVerifier, NamingEngine, NamingRegistrySnapshot, NodeId,
    RegistrationRequest, RenameRequest, PROTOCOL_STATE_KEY as NAMING_STATE_KEY,
};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_node_ownership::{
    OwnershipAuthorizationVerifier, OwnershipClaimRequest, OwnershipEngine,
    OwnershipRegistrySnapshot, OwnershipTransferRequest, PROTOCOL_STATE_KEY as OWNERSHIP_STATE_KEY,
};
use synergy_posy::{
    FinalitySyncWitness, VerifiedQuorumCertificateStore, VerifiedTimeoutCertificateStore,
};
use synergy_rewards::{
    RewardAuthorizationVerifier, RewardEngine, RewardLedgerSnapshot, RewardWithdrawalRequest,
    PROTOCOL_STATE_KEY as REWARD_STATE_KEY,
};
use synergy_state::{AccountChange, FinalizedStateStore, ProtocolChange, StateDiff, WorldState};
use synergy_storage::{AtomicStore, NodeStorageLayout};
use synergy_sxcp::{FinalizedSxcpRelayIntent, SxcpRelayExecution, SynergyFinalityAnchor};
use synergy_sync::{FinalizedCandidateResponse, SyncWireMessage};
use synergy_synq::{DeterministicContext, SynqArtifact, SynqExecutor, SynqHost};
use synergy_transaction::{
    AegisTransactionVerifier, NetworkBinding, SignedTransaction, TransactionAction,
};

use super::authority::VerifiedAuthority;
use super::ingress::{
    AuthenticatedIngress, OutboundFrame, SnapshotPublication, SnapshotRestoreReceipt,
};
use synergy_protocol_types::ProtocolKind;

const MAX_BATCHES_PER_POLL: usize = 16;
const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const TESTNET_V3_BASE_FEE_NWEI: u64 = 40;
const TESTNET_V3_FEE_COLLECTOR: &str = "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l";

/// Canonical SynQ caller: Aegis verifies the PQSynQ account-domain envelope,
/// AIVM executes the established deterministic QVM bytecode, and execution
/// returns only a scheduler-applied account-state diff.
#[derive(Debug, Clone)]
struct CanonicalSynqRuntime {
    verifier: PqSynqVerifier,
    vm: CanonicalAivmSynqVm,
}

impl CanonicalSynqRuntime {
    fn new() -> Self {
        Self {
            verifier: PqSynqVerifier::testnet_1266(),
            vm: CanonicalAivmSynqVm,
        }
    }
}

#[derive(Debug, Default)]
struct BoundedSynqHost;

impl SynqHost for BoundedSynqHost {
    fn read(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, synergy_synq::SynqError> {
        Ok(None)
    }

    fn write(&mut self, _key: Vec<u8>, _value: Vec<u8>) -> Result<(), synergy_synq::SynqError> {
        Err(synergy_synq::SynqError::Host(
            "this QVM profile has no persistent host-write opcode".into(),
        ))
    }

    fn emit(&mut self, _topic: Vec<u8>, _data: Vec<u8>) -> Result<(), synergy_synq::SynqError> {
        Err(synergy_synq::SynqError::Host(
            "this QVM profile has no host-event opcode".into(),
        ))
    }
}

impl SynqRuntime for CanonicalSynqRuntime {
    type Error = String;

    fn execute_synq(
        &self,
        artifact: &[u8],
        encoded_authorization: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        let authorization = self
            .verifier
            .verify_execution(
                artifact,
                encoded_authorization,
                context.network.chain_id,
                &context.network.network_id,
                transaction.unsigned.timestamp_unix,
                &transaction.signer_public_key,
            )
            .map_err(|error| error.to_string())?;
        let artifact = SynqArtifact::new(artifact.to_vec()).map_err(|error| error.to_string())?;
        let state_diff = match authorization.operation {
            VerifiedPqSynqOperation::Deploy { .. } => {
                if state
                    .accounts
                    .get(&transaction.unsigned.receiver)
                    .and_then(|account| account.code_hash.as_ref())
                    .is_some()
                {
                    return Err("SynQ deployment target already has code".into());
                }
                StateDiff {
                    changes: vec![AccountChange {
                        account: transaction.unsigned.receiver.clone(),
                        debit_nwei: 0,
                        credit_nwei: 0,
                        expected_nonce: None,
                        code_hash: Some(Some(artifact.code_hash.clone())),
                    }],
                    protocol_changes: Vec::new(),
                }
            }
            VerifiedPqSynqOperation::Call {
                contract_address_preimage,
                ..
            } => {
                let bound_contract =
                    synergy_address::derive_object_address("synq", &contract_address_preimage)?;
                if bound_contract != transaction.unsigned.receiver {
                    return Err(
                        "PQSynQ call contract does not match the transaction receiver".into(),
                    );
                }
                let installed_hash = state
                    .accounts
                    .get(&transaction.unsigned.receiver)
                    .and_then(|account| account.code_hash.as_deref())
                    .ok_or("SynQ call target has no deployed code")?;
                if installed_hash != artifact.code_hash {
                    return Err("SynQ call artifact does not match deployed code".into());
                }
                StateDiff::default()
            }
        };
        let mut host = BoundedSynqHost;
        let receipt = SynqExecutor::execute(
            &artifact,
            transaction.id().map_err(|error| error.to_string())?,
            DeterministicContext {
                block_height: context.block_height,
                transaction_index: context.transaction_index,
            },
            &authorization.invocation_input,
            transaction.unsigned.fee_limit.gas_limit,
            &self.vm,
            &mut host,
        )
        .map_err(|error| error.to_string())?;
        state_diff
            .validate()
            .map_err(|error| format!("{error:?}"))?;
        Ok(TransactionDispatch {
            state_diff,
            gas_used: receipt.gas_used,
        })
    }
}

#[derive(Debug, Clone)]
struct CanonicalSxcpExecutor {
    authority: Arc<VerifiedAuthority>,
}

impl SxcpExecutor for CanonicalSxcpExecutor {
    type Error = String;

    fn execute_sxcp(
        &self,
        destination: &str,
        message: &[u8],
        transaction: &SignedTransaction,
        _context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        if transaction.unsigned.amount_nwei != 0 {
            return Err("SXCP authorization transaction cannot transfer value".into());
        }
        let execution: SxcpRelayExecution = serde_json::from_slice(message)
            .map_err(|error| format!("decode SXCP relay execution: {error}"))?;
        let verified = execution.verify(self.authority.as_ref(), destination)?;
        let key = format!("sxcp/pending/{}", verified.transfer.transfer_id);
        if state.protocol.contains_key(&key) {
            return Err("SXCP relay transfer is already recorded".into());
        }
        let value = serde_json::to_vec(&(execution, verified))
            .map_err(|error| format!("encode SXCP relay state: {error}"))?;
        let gas_used = 100_000u64
            .checked_add(u64::try_from(value.len()).map_err(|_| "SXCP relay value too large")?)
            .ok_or("SXCP gas overflow")?;
        Ok(TransactionDispatch {
            state_diff: StateDiff {
                changes: Vec::new(),
                protocol_changes: vec![ProtocolChange {
                    key,
                    expected_value: None,
                    value: Some(value),
                }],
            },
            gas_used,
        })
    }
}

#[derive(Debug, Clone)]
struct CanonicalGovernanceOperation {
    authority: Arc<VerifiedAuthority>,
}

impl CanonicalGovernanceOperation {
    fn execute(
        &self,
        authorization_id: &str,
        operation: &[u8],
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, String> {
        let execution: GovernanceExecution = serde_json::from_slice(operation)
            .map_err(|error| format!("decode governance execution: {error}"))?;
        let key = execution.verify(
            self.authority.as_ref(),
            authorization_id,
            context.block_height,
        )?;
        if state.protocol.get(&key) != execution.mutation.expected_value.as_ref() {
            return Err("governance mutation expected value differs from speculative state".into());
        }
        let operation_bytes = operation.len();
        let gas_used = 75_000u64
            .checked_add(u64::try_from(operation_bytes).map_err(|_| "governance value too large")?)
            .ok_or("governance gas overflow")?;
        Ok(TransactionDispatch {
            state_diff: StateDiff {
                changes: Vec::new(),
                protocol_changes: vec![ProtocolChange {
                    key,
                    expected_value: execution.mutation.expected_value,
                    value: Some(execution.mutation.value),
                }],
            },
            gas_used,
        })
    }
}

impl GovernanceOperation for CanonicalGovernanceOperation {
    type Error = String;

    fn execute_governance(
        &self,
        authorization_id: &str,
        operation: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        if transaction.unsigned.amount_nwei != 0 {
            return Err("governance transaction cannot transfer value".into());
        }
        self.execute(authorization_id, operation, context, state)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "kind", content = "operation", rename_all = "snake_case")]
enum CanonicalSystemAction {
    Governance(GovernanceExecution),
}

#[derive(Debug, Clone)]
struct CanonicalSystemOperation {
    governance: CanonicalGovernanceOperation,
}

impl SystemOperation for CanonicalSystemOperation {
    type Error = String;

    fn execute_system(
        &self,
        authorization_id: &str,
        operation: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        if transaction.unsigned.amount_nwei != 0 {
            return Err("system transaction cannot transfer value".into());
        }
        match serde_json::from_slice::<CanonicalSystemAction>(operation)
            .map_err(|error| format!("decode canonical system action: {error}"))?
        {
            CanonicalSystemAction::Governance(execution) => self.governance.execute(
                authorization_id,
                &serde_json::to_vec(&execution)
                    .map_err(|error| format!("encode delegated governance action: {error}"))?,
                context,
                state,
            ),
        }
    }
}

const VERIFIED_TRANSACTION_PROOF: &[u8] = b"verified-transaction-sender-v1";
const NATIVE_STATE_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachedAuthorizationProof {
    public_key: Vec<u8>,
    signature: Vec<u8>,
    signature_algorithm: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipClaimInput {
    node_address: synergy_protocol_types::NodeAddress,
    nonce: u64,
    node_possession_proof: Vec<u8>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipTransferInput {
    node_address: synergy_protocol_types::NodeAddress,
    new_owner_wallet: String,
    nonce: u64,
    new_owner_acceptance_proof: Vec<u8>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamingRegistrationInput {
    node_id: NodeId,
    node_address: synergy_protocol_types::NodeAddress,
    nonce: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamingRenameInput {
    current_node_id: NodeId,
    replacement_node_id: NodeId,
    node_address: synergy_protocol_types::NodeAddress,
    nonce: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardWithdrawalInput {
    withdrawal_id: String,
    node_address: synergy_protocol_types::NodeAddress,
    destination_wallet: String,
    amount_nwei: u128,
    nonce: u64,
}

#[derive(Debug, Clone)]
struct CanonicalNativeOperation {
    verifier: PqvmVerifier,
    chain_id: u64,
}

struct NativeAuthorizationVerifier<'a> {
    verifier: &'a PqvmVerifier,
    chain_id: u64,
    sender: &'a str,
    signer_public_key: &'a [u8],
}

impl NativeAuthorizationVerifier<'_> {
    fn verify_wallet(&self, wallet: &str, payload: &[u8], proof: &[u8]) -> Result<(), String> {
        if proof == VERIFIED_TRANSACTION_PROOF {
            if wallet != self.sender
                || !synergy_address::address_matches_public_key(wallet, self.signer_public_key)
            {
                return Err("verified transaction signer is not the claimed wallet".into());
            }
            return Ok(());
        }
        self.verify_detached(wallet, payload, proof, false)
    }

    fn verify_detached(
        &self,
        subject: &str,
        payload: &[u8],
        proof: &[u8],
        node_subject: bool,
    ) -> Result<(), String> {
        let proof: DetachedAuthorizationProof = serde_json::from_slice(proof)
            .map_err(|error| format!("decode detached Aegis authorization proof: {error}"))?;
        if !synergy_address::address_matches_public_key(subject, &proof.public_key) {
            return Err("authorization public key does not control the claimed address".into());
        }
        let algorithm = match proof.signature_algorithm.as_str() {
            "ML-DSA-65" | "ml_dsa_65" => SignatureAlgorithm::MlDsa65,
            "ML-DSA-87" | "ml_dsa_87" => SignatureAlgorithm::MlDsa87,
            _ => return Err("unsupported Aegis authorization signature algorithm".into()),
        };
        let domain = if node_subject {
            "SYNERGY-NODE-OWNERSHIP-POSSESSION-V1"
        } else {
            "SYNERGY-WALLET-AUTHORIZATION-V1"
        };
        self.verifier
            .verify(
                &SigningContext {
                    domain: domain.into(),
                    chain_id: self.chain_id,
                    epoch: None,
                    height: None,
                },
                payload,
                &Signature {
                    algorithm,
                    key_id: KeyId::new("presented-native-authorization-key")
                        .map_err(|error| error.to_string())?,
                    bytes: proof.signature,
                },
                &proof.public_key,
            )
            .map_err(|error| error.to_string())
    }
}

impl OwnershipAuthorizationVerifier for NativeAuthorizationVerifier<'_> {
    fn verify_wallet_proof(
        &self,
        wallet: &str,
        payload: &[u8],
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_wallet(wallet, payload, proof)
    }

    fn verify_node_possession(
        &self,
        node_address: &synergy_protocol_types::NodeAddress,
        payload: &[u8],
        proof: &[u8],
    ) -> Result<(), String> {
        self.verify_detached(node_address.as_str(), payload, proof, true)
    }
}

impl NamingAuthorizationVerifier for NativeAuthorizationVerifier<'_> {
    fn verify(
        &self,
        action: &synergy_naming::NamingAction,
        authorization: &NamingAuthorization,
    ) -> Result<(), String> {
        self.verify_wallet(
            action.owner_wallet(),
            &action
                .signing_payload()
                .map_err(|error| error.to_string())?,
            &authorization.proof,
        )
    }
}

impl RewardAuthorizationVerifier for NativeAuthorizationVerifier<'_> {
    fn verify_owner_proof(&self, wallet: &str, payload: &[u8], proof: &[u8]) -> Result<(), String> {
        self.verify_wallet(wallet, payload, proof)
    }
}

fn decode_protocol_state<T: serde::de::DeserializeOwned + Default>(
    state: &WorldState,
    key: &str,
) -> Result<T, String> {
    state.protocol.get(key).map_or_else(
        || Ok(T::default()),
        |bytes| serde_json::from_slice(bytes).map_err(|error| format!("decode {key}: {error}")),
    )
}

fn protocol_state_dispatch<T: serde::Serialize>(
    state: &WorldState,
    key: &str,
    replacement: &T,
) -> Result<TransactionDispatch, String> {
    let value =
        serde_json::to_vec(replacement).map_err(|error| format!("encode {key}: {error}"))?;
    if value.is_empty() || value.len() > NATIVE_STATE_MAX_BYTES {
        return Err(format!("{key} exceeds canonical protocol-state bound"));
    }
    let gas_used = 50_000u64
        .checked_add(u64::try_from(value.len()).map_err(|_| "native state is too large")?)
        .ok_or("native operation gas overflow")?;
    Ok(TransactionDispatch {
        state_diff: StateDiff {
            changes: Vec::new(),
            protocol_changes: vec![ProtocolChange {
                key: key.into(),
                expected_value: state.protocol.get(key).cloned(),
                value: Some(value),
            }],
        },
        gas_used,
    })
}

impl NativeOperation for CanonicalNativeOperation {
    type Error = String;

    fn execute_native(
        &self,
        module: &str,
        method: &str,
        input: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        if transaction.unsigned.amount_nwei != 0 {
            return Err("native protocol operation cannot transfer value".into());
        }
        let authorization = NativeAuthorizationVerifier {
            verifier: &self.verifier,
            chain_id: self.chain_id,
            sender: &transaction.unsigned.sender,
            signer_public_key: &transaction.signer_public_key,
        };
        match (module, method) {
            ("node_ownership", "claim") => {
                let input: OwnershipClaimInput = serde_json::from_slice(input)
                    .map_err(|error| format!("decode ownership claim: {error}"))?;
                let mut ownership: OwnershipRegistrySnapshot =
                    decode_protocol_state(state, OWNERSHIP_STATE_KEY)?;
                let transition = OwnershipEngine::new(authorization)
                    .prepare_claim(
                        &ownership,
                        OwnershipClaimRequest {
                            node_address: input.node_address,
                            owner_wallet: transaction.unsigned.sender.clone(),
                            nonce: input.nonce,
                            wallet_proof: VERIFIED_TRANSACTION_PROOF.to_vec(),
                            node_possession_proof: input.node_possession_proof,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                ownership
                    .apply_at_height(context.block_height, transition)
                    .map_err(|error| error.to_string())?;
                protocol_state_dispatch(state, OWNERSHIP_STATE_KEY, &ownership)
            }
            ("node_ownership", "transfer") => {
                let input: OwnershipTransferInput = serde_json::from_slice(input)
                    .map_err(|error| format!("decode ownership transfer: {error}"))?;
                let mut ownership: OwnershipRegistrySnapshot =
                    decode_protocol_state(state, OWNERSHIP_STATE_KEY)?;
                let transition = OwnershipEngine::new(authorization)
                    .prepare_transfer(
                        &ownership,
                        OwnershipTransferRequest {
                            node_address: input.node_address,
                            current_owner_wallet: transaction.unsigned.sender.clone(),
                            new_owner_wallet: input.new_owner_wallet,
                            nonce: input.nonce,
                            current_owner_proof: VERIFIED_TRANSACTION_PROOF.to_vec(),
                            new_owner_acceptance_proof: input.new_owner_acceptance_proof,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                ownership
                    .apply_at_height(context.block_height, transition)
                    .map_err(|error| error.to_string())?;
                protocol_state_dispatch(state, OWNERSHIP_STATE_KEY, &ownership)
            }
            ("naming", "register") => {
                let input: NamingRegistrationInput = serde_json::from_slice(input)
                    .map_err(|error| format!("decode naming registration: {error}"))?;
                let ownership: OwnershipRegistrySnapshot =
                    decode_protocol_state(state, OWNERSHIP_STATE_KEY)?;
                let mut naming: NamingRegistrySnapshot =
                    decode_protocol_state(state, NAMING_STATE_KEY)?;
                let transition = NamingEngine::new(ownership, authorization)
                    .prepare_registration(
                        &naming,
                        RegistrationRequest {
                            node_id: input.node_id,
                            node_address: input.node_address,
                            authorization: NamingAuthorization {
                                owner_wallet: transaction.unsigned.sender.clone(),
                                nonce: input.nonce,
                                proof: VERIFIED_TRANSACTION_PROOF.to_vec(),
                            },
                        },
                    )
                    .map_err(|error| error.to_string())?;
                naming
                    .apply_at_height(context.block_height, transition)
                    .map_err(|error| error.to_string())?;
                protocol_state_dispatch(state, NAMING_STATE_KEY, &naming)
            }
            ("naming", "rename") => {
                let input: NamingRenameInput = serde_json::from_slice(input)
                    .map_err(|error| format!("decode naming rename: {error}"))?;
                let ownership: OwnershipRegistrySnapshot =
                    decode_protocol_state(state, OWNERSHIP_STATE_KEY)?;
                let mut naming: NamingRegistrySnapshot =
                    decode_protocol_state(state, NAMING_STATE_KEY)?;
                let transition = NamingEngine::new(ownership, authorization)
                    .prepare_rename(
                        &naming,
                        RenameRequest {
                            current_node_id: input.current_node_id,
                            replacement_node_id: input.replacement_node_id,
                            node_address: input.node_address,
                            authorization: NamingAuthorization {
                                owner_wallet: transaction.unsigned.sender.clone(),
                                nonce: input.nonce,
                                proof: VERIFIED_TRANSACTION_PROOF.to_vec(),
                            },
                        },
                    )
                    .map_err(|error| error.to_string())?;
                naming
                    .apply_at_height(context.block_height, transition)
                    .map_err(|error| error.to_string())?;
                protocol_state_dispatch(state, NAMING_STATE_KEY, &naming)
            }
            ("rewards", "withdraw") => {
                let input: RewardWithdrawalInput = serde_json::from_slice(input)
                    .map_err(|error| format!("decode reward withdrawal: {error}"))?;
                let ownership: OwnershipRegistrySnapshot =
                    decode_protocol_state(state, OWNERSHIP_STATE_KEY)?;
                let mut rewards: RewardLedgerSnapshot =
                    decode_protocol_state(state, REWARD_STATE_KEY)?;
                let transition = RewardEngine::new(ownership, authorization)
                    .prepare_withdrawal(
                        &rewards,
                        RewardWithdrawalRequest {
                            withdrawal_id: input.withdrawal_id,
                            node_address: input.node_address,
                            owner_wallet: transaction.unsigned.sender.clone(),
                            destination_wallet: input.destination_wallet,
                            amount_nwei: input.amount_nwei,
                            nonce: input.nonce,
                            owner_proof: VERIFIED_TRANSACTION_PROOF.to_vec(),
                        },
                    )
                    .map_err(|error| error.to_string())?;
                rewards
                    .apply_at_height(context.block_height, transition)
                    .map_err(|error| error.to_string())?;
                protocol_state_dispatch(state, REWARD_STATE_KEY, &rewards)
            }
            _ => Err(format!("unsupported native operation {module}.{method}")),
        }
    }
}

type CanonicalExecutionDispatcher = CanonicalTransactionDispatcher<
    NativeDispatcher<CanonicalNativeOperation>,
    SynqDispatcher<CanonicalSynqRuntime>,
    SxcpDispatcher<CanonicalSxcpExecutor>,
    GovernanceDispatcher<CanonicalGovernanceOperation>,
    SystemDispatcher<CanonicalSystemOperation>,
>;

#[derive(Debug, Clone)]
struct TransactionPqvmVerifier {
    verifier: PqvmVerifier,
    chain_id: u64,
}

impl TransactionPqvmVerifier {
    fn new(chain_id: u64) -> Result<Self, String> {
        let verifier = PqvmVerifier::new(AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
            maximum_message_bytes: MAX_TRANSACTION_BYTES,
            maximum_signature_bytes: 16 * 1024,
        })
        .map_err(|error| format!("construct transaction PQVM verifier: {error}"))?;
        Ok(Self { verifier, chain_id })
    }
}

impl AegisTransactionVerifier for TransactionPqvmVerifier {
    type Error = String;

    fn verify_transaction(
        &self,
        signing_bytes: &[u8],
        signer_public_key: &[u8],
        signature: &[u8],
        signature_algorithm: &str,
    ) -> Result<bool, Self::Error> {
        if signature_algorithm != "ML-DSA-87" && signature_algorithm != "ml_dsa_87" {
            return Ok(false);
        }
        let key_id = KeyId::new("transaction-presented-key").map_err(|error| error.to_string())?;
        let result = self.verifier.verify(
            &SigningContext {
                domain: "SYNERGY-TRANSACTION-SIGNING-V1".into(),
                chain_id: self.chain_id,
                epoch: None,
                height: None,
            },
            signing_bytes,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa87,
                key_id,
                bytes: signature.to_vec(),
            },
            signer_public_key,
        );
        Ok(result.is_ok())
    }
}

/// Durable speculative execution material is advisory until PoSy's frozen
/// authority verifies its QC. Persisting before publication lets a restart
/// reconstruct every certified-but-not-finalized account transition.
struct CandidateStore {
    store: AtomicStore,
}

impl CandidateStore {
    fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            store: AtomicStore::new(root.as_ref(), 64 * 1024 * 1024)
                .map_err(|error| format!("open execution candidate store: {error}"))?,
        })
    }

    fn get(&self, height: u64) -> Result<Option<ExecutionCandidate>, String> {
        let path = format!("candidate/{height:020}.json");
        if !self
            .store
            .exists(&path)
            .map_err(|error| error.to_string())?
        {
            return Ok(None);
        }
        let bytes = self
            .store
            .read_bounded(&path)
            .map_err(|error| format!("read execution candidate H{height}: {error}"))?;
        let candidate: ExecutionCandidate = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode execution candidate H{height}: {error}"))?;
        if candidate.height != height {
            return Err(format!(
                "execution candidate record height mismatch at H{height}"
            ));
        }
        candidate.validate()?;
        Ok(Some(candidate))
    }

    fn put_once(&self, candidate: &ExecutionCandidate) -> Result<(), String> {
        candidate.validate()?;
        let path = format!("candidate/{:020}.json", candidate.height);
        if let Some(existing) = self.get(candidate.height)? {
            if existing == *candidate {
                return Ok(());
            }
            return Err(format!(
                "conflicting durable execution candidate at H{}",
                candidate.height
            ));
        }
        let bytes = serde_json::to_vec(candidate)
            .map_err(|error| format!("encode execution candidate: {error}"))?;
        self.store
            .write_atomic(path, &bytes)
            .map_err(|error| format!("persist execution candidate: {error}"))
    }
}

struct SxcpRelayOutbox {
    store: AtomicStore,
}

impl SxcpRelayOutbox {
    fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        Ok(Self {
            store: AtomicStore::new(root.as_ref(), 8 * 1024 * 1024)
                .map_err(|error| format!("open SXCP relay outbox: {error}"))?,
        })
    }

    fn put_once(&self, intent: &FinalizedSxcpRelayIntent) -> Result<(), String> {
        intent.validate_shape()?;
        let path = format!("pending/{}.json", intent.transaction_id);
        let bytes = serde_json::to_vec(intent)
            .map_err(|error| format!("encode finalized SXCP relay intent: {error}"))?;
        if self
            .store
            .exists(&path)
            .map_err(|error| error.to_string())?
        {
            let existing = self
                .store
                .read_bounded(&path)
                .map_err(|error| format!("read finalized SXCP relay intent: {error}"))?;
            return if existing == bytes {
                Ok(())
            } else {
                Err("conflicting finalized SXCP relay intent".into())
            };
        }
        self.store
            .write_atomic(path, &bytes)
            .map_err(|error| format!("persist finalized SXCP relay intent: {error}"))
    }
}

/// Owns the ETDAG-to-execution boundary and commits state only after an exact
/// PoSy finality record. Candidate execution never grants finality authority.
pub fn registration(
    configuration: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let StorageConfiguration { data_directory, .. } = &configuration.storage;
    let layout = NodeStorageLayout::new(data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let state_store = FinalizedStateStore::load(layout.state().join("execution"))
        .map_err(|error| format!("open canonical finalized state: {error:?}"))?;
    let network = NetworkBinding {
        chain_id: configuration.chain_id,
        network_id: configuration.network_id.clone(),
    };
    network
        .validate()
        .map_err(|error| format!("validate execution network binding: {error:?}"))?;
    let governance = CanonicalGovernanceOperation {
        authority: Arc::clone(&authority),
    };
    let scheduler = BlockExecutionScheduler::new(
        CanonicalTransactionDispatcher {
            native: NativeDispatcher::new(CanonicalNativeOperation {
                verifier: PqvmVerifier::new(AegisPolicy {
                    allowed_algorithms: vec![
                        SignatureAlgorithm::MlDsa65,
                        SignatureAlgorithm::MlDsa87,
                    ],
                    maximum_message_bytes: 64 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                })
                .map_err(|error| format!("construct native authorization verifier: {error}"))?,
                chain_id: configuration.chain_id,
            }),
            synq: SynqDispatcher::new(CanonicalSynqRuntime::new()),
            sxcp: SxcpDispatcher::new(CanonicalSxcpExecutor {
                authority: Arc::clone(&authority),
            }),
            governance: GovernanceDispatcher::new(governance.clone()),
            system: SystemDispatcher::new(CanonicalSystemOperation { governance }),
        },
        TransactionPqvmVerifier::new(configuration.chain_id)?,
        FeeSchedule {
            base_fee_per_gas_nwei: TESTNET_V3_BASE_FEE_NWEI,
            collector: TESTNET_V3_FEE_COLLECTOR.into(),
        },
    )
    .map_err(|error| format!("construct deterministic execution scheduler: {error:?}"))?;
    let finalized_height = state_store
        .current()
        .map(|state| state.finalized_height)
        .unwrap_or_else(|| authority.anchor_parent.height());
    let state = match (
        state_store.current(),
        state_store
            .current_world_state()
            .map_err(|error| format!("load verified finalized account state: {error:?}"))?,
    ) {
        (Some(_), Some(world)) => world,
        (Some(_), None) => {
            return Err("finalized execution commitment lacks durable account state".into());
        }
        (None, _) => WorldState::default(),
    };
    let candidate_store = CandidateStore::new(layout.blocks().join("execution-candidates"))?;
    let sxcp_outbox = SxcpRelayOutbox::open(layout.state().join("sxcp-relay-outbox"))?;
    let qc_store = VerifiedQuorumCertificateStore::new(layout.consensus().join("posy"))
        .map_err(|error| format!("open certified execution replay authority: {error}"))?;
    let timeout_store = VerifiedTimeoutCertificateStore::new(layout.consensus().join("posy"))
        .map_err(|error| format!("open Sync timeout witness store: {error}"))?;
    let mut candidates = BTreeMap::new();
    let mut execution_height = finalized_height;
    let mut recovered_state = state;
    let mut expected_parent = state_store
        .current()
        .map(|record| record.finalized_block_id.clone())
        .unwrap_or_else(|| authority.anchor_parent.block_id().to_string());
    loop {
        let next_height = execution_height
            .checked_add(1)
            .ok_or("execution recovery height overflow")?;
        if !authority.epoch.contains_height(next_height) {
            break;
        }
        let Some(qc) = qc_store
            .get_verified(
                next_height,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .map_err(|error| {
                format!("verify certified execution replay H{next_height}: {error}")
            })?
        else {
            break;
        };
        let candidate = candidate_store
            .get(next_height)?
            .ok_or_else(|| format!("certified H{next_height} lacks durable executed candidate"))?;
        if candidate.block_id != qc.block_id
            || candidate.parent_block_id != expected_parent
            || candidate.parent_block_id != qc.parent_block_id
            || candidate.protected_execution_root != qc.protected_execution_root
        {
            return Err(format!(
                "certified execution candidate conflicts with PoSy QC at H{next_height}"
            ));
        }
        let outcome = scheduler
            .execute(
                &BlockBody {
                    transactions: candidate.transactions.clone(),
                },
                &network,
                next_height,
                &recovered_state,
            )
            .map_err(|error| format!("re-execute certified candidate H{next_height}: {error:?}"))?;
        if outcome.state != candidate.state
            || outcome.state_root != candidate.state_root
            || outcome.receipts != candidate.receipts
        {
            return Err(format!(
                "certified candidate H{next_height} fails deterministic replay"
            ));
        }
        expected_parent = candidate.block_id.clone();
        recovered_state = candidate.state.clone();
        execution_height = next_height;
        ingress.submit_execution_candidate(candidate.clone())?;
        candidates.insert(next_height, candidate);
    }
    Ok((
        ServiceSpec {
            id: ServiceId::new("execution")?,
            dependencies: vec![ServiceId::new("etdag")?, ServiceId::new("storage")?],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(ExecutionService {
            scheduler,
            state_store: Some(state_store),
            ingress,
            network,
            authority,
            finalized_height,
            execution_height,
            state: recovered_state,
            candidate_store,
            sxcp_outbox,
            qc_store,
            timeout_store,
            retention_blocks: configuration.storage.prune_finalized_history_after_blocks,
            batches: BTreeMap::new(),
            candidates,
            started: false,
            failure: None,
        }),
    ))
}

struct ExecutionService {
    scheduler: BlockExecutionScheduler<CanonicalExecutionDispatcher, TransactionPqvmVerifier>,
    state_store: Option<FinalizedStateStore>,
    ingress: AuthenticatedIngress,
    network: NetworkBinding,
    authority: Arc<VerifiedAuthority>,
    finalized_height: u64,
    execution_height: u64,
    state: WorldState,
    candidate_store: CandidateStore,
    sxcp_outbox: SxcpRelayOutbox,
    qc_store: VerifiedQuorumCertificateStore,
    timeout_store: VerifiedTimeoutCertificateStore,
    retention_blocks: Option<u64>,
    batches: BTreeMap<u64, PreparedProtectedBatch>,
    candidates: BTreeMap<u64, ExecutionCandidate>,
    started: bool,
    failure: Option<String>,
}

impl ExecutionService {
    fn accept_batch(&mut self, batch: PreparedProtectedBatch) -> Result<(), String> {
        batch
            .validate()
            .map_err(|error| format!("validate execution protected batch: {error:?}"))?;
        if batch
            .context
            .root()
            .map_err(|error| format!("derive execution context root: {error:?}"))?
            != batch.context_root
            || batch.context.target_height != batch.target_height
            || batch.context.chain_id != self.network.chain_id
            || batch.context.network_id != self.network.network_id
            || batch.context.epoch != self.authority.epoch.epoch
        {
            return Err("execution batch is not bound to the active authority context".into());
        }
        match self.batches.get(&batch.target_height) {
            Some(current) if current == &batch => return Ok(()),
            Some(_) => return Err("conflicting ETDAG batch for one target height".into()),
            None => {}
        }
        self.batches.insert(batch.target_height, batch);
        Ok(())
    }

    fn execute_next_ready(&mut self) -> Result<bool, String> {
        let next_height = self
            .execution_height
            .checked_add(1)
            .ok_or("execution height overflow")?;
        if self.candidates.contains_key(&next_height) {
            self.execution_height = next_height;
            return Ok(true);
        }
        let batch = self.batches.get(&next_height).cloned();
        if batch.is_none() && next_height >= self.finalized_height.saturating_add(5) {
            return Ok(false);
        }
        let transactions = match &batch {
            Some(batch) => batch
                .transactions
                .iter()
                .map(|prepared| {
                    if prepared.plaintext.len() > MAX_TRANSACTION_BYTES {
                        return Err("prepared transaction exceeds execution bound".into());
                    }
                    let transaction: SignedTransaction =
                        serde_json::from_slice(&prepared.plaintext).map_err(|error| {
                            format!("decode ETDAG-authorized transaction: {error}")
                        })?;
                    transaction.validate_structure().map_err(|error| {
                        format!("validate ETDAG-authorized transaction: {error:?}")
                    })?;
                    Ok(transaction)
                })
                .collect::<Result<Vec<_>, String>>()?,
            None => Vec::new(),
        };
        let body = BlockBody {
            transactions: transactions.clone(),
        };
        let outcome: BlockExecutionOutcome = self
            .scheduler
            .execute(&body, &self.network, next_height, &self.state)
            .map_err(|error| format!("execute deterministic protected batch: {error:?}"))?;
        if self.scheduler.may_determine_finality() || outcome.may_determine_finality() {
            return Err("execution candidate illegally claims finality authority".into());
        }
        let parent_block_id = self
            .candidates
            .get(&self.execution_height)
            .map(|candidate| candidate.block_id.clone())
            .or_else(|| {
                self.ingress
                    .latest_finality()
                    .ok()
                    .flatten()
                    .filter(|record| record.height == self.execution_height)
                    .map(|record| record.block_id)
            })
            .unwrap_or_else(|| self.authority.anchor_parent.block_id().to_string());
        let protected_execution_root = match &batch {
            Some(batch) => hash_block_bytes(batch.protected_batch_root.0.as_bytes()),
            None => hash_block_bytes(
                format!("SYNERGY_EMPTY_PROTECTED_BATCH_V1:{next_height}").as_bytes(),
            ),
        };
        let candidate_bytes = serde_json::to_vec(&(
            next_height,
            &parent_block_id,
            &protected_execution_root,
            &outcome.state_root,
            &transactions,
            &outcome.receipts,
        ))
        .map_err(|error| format!("encode execution candidate commitment: {error}"))?;
        let candidate = ExecutionCandidate {
            height: next_height,
            block_id: hash_block_bytes(&candidate_bytes),
            parent_block_id,
            protected_execution_root,
            state_root: outcome.state_root,
            transactions,
            receipts: outcome.receipts,
            state: outcome.state,
        };
        self.candidate_store.put_once(&candidate)?;
        self.ingress.submit_execution_candidate(candidate.clone())?;
        self.state = candidate.state.clone();
        self.execution_height = next_height;
        self.candidates.insert(next_height, candidate);
        Ok(true)
    }

    fn serve_sync_requests(&mut self) -> Result<(), String> {
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some((peer, request)) = self.ingress.take_sync_candidate_request()? else {
                break;
            };
            if request.height > self.finalized_height {
                continue;
            }
            let candidate = self.candidate_store.get(request.height)?.ok_or_else(|| {
                format!(
                    "finalized execution candidate H{} is unavailable",
                    request.height
                )
            })?;
            if candidate.parent_block_id != request.expected_parent_id {
                continue;
            }
            let middle = request
                .height
                .checked_add(1)
                .ok_or("Sync witness height overflow")?;
            let newest = request
                .height
                .checked_add(2)
                .ok_or("Sync witness height overflow")?;
            let certificates = [
                self.qc_store
                    .get_verified(
                        request.height,
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|error| format!("load Sync QC witness: {error}"))?
                    .ok_or("finalized candidate lacks oldest QC witness")?,
                self.qc_store
                    .get_verified(
                        middle,
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|error| format!("load Sync QC witness: {error}"))?
                    .ok_or("finalized candidate lacks middle QC witness")?,
                self.qc_store
                    .get_verified(
                        newest,
                        &self.authority.epoch,
                        &self.authority.registry,
                        self.authority.as_ref(),
                    )
                    .map_err(|error| format!("load Sync QC witness: {error}"))?
                    .ok_or("finalized candidate lacks newest QC witness")?,
            ];
            let mut timeout_certificates = Vec::new();
            for certificate in &certificates {
                for round in 0..certificate.context.round {
                    let timeout = self
                        .timeout_store
                        .get_verified(
                            certificate.context.height,
                            round,
                            &self.authority.epoch,
                            &self.authority.registry,
                            self.authority.as_ref(),
                        )
                        .map_err(|error| format!("load Sync timeout witness: {error}"))?
                        .ok_or("finalized candidate lacks required timeout witness")?;
                    timeout_certificates.push(timeout);
                }
            }
            let witness = FinalitySyncWitness {
                quorum_certificates: certificates,
                timeout_certificates,
            };
            let finality_witness = serde_json::to_vec(&witness)
                .map_err(|error| format!("encode Sync candidate witness: {error}"))?;
            if finality_witness.len() > 1024 * 1024 {
                return Err("Sync candidate witness exceeds protocol bound".into());
            }
            let response = FinalizedCandidateResponse {
                request,
                candidate,
                finality_witness,
            };
            self.ingress.publish_outbound(OutboundFrame {
                peer_id: peer.node_address.to_string(),
                protocol: ProtocolKind::Sync,
                payload: serde_json::to_vec(&SyncWireMessage::FinalizedCandidateResponse(response))
                    .map_err(|error| format!("encode Sync candidate response: {error}"))?,
            })?;
        }
        Ok(())
    }

    fn accept_verified_sync_candidates(&mut self) -> Result<(), String> {
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some((candidate, record)) = self.ingress.take_verified_sync_candidate()? else {
                break;
            };
            let expected_height = self
                .finalized_height
                .checked_add(1)
                .ok_or("Sync import height overflow")?;
            let expected_parent = self
                .state_store
                .as_ref()
                .and_then(FinalizedStateStore::current)
                .map(|state| state.finalized_block_id.clone())
                .unwrap_or_else(|| self.authority.anchor_parent.block_id().to_string());
            if candidate.height != expected_height
                || candidate.parent_block_id != expected_parent
                || candidate.block_id != record.block_id
                || candidate.protected_execution_root != record.protected_execution_root
            {
                return Err(
                    "PoSy-verified Sync candidate is not the next finalized transition".into(),
                );
            }
            let outcome = self
                .scheduler
                .execute(
                    &BlockBody {
                        transactions: candidate.transactions.clone(),
                    },
                    &self.network,
                    candidate.height,
                    &self.state,
                )
                .map_err(|error| format!("re-execute Sync candidate: {error:?}"))?;
            if outcome.state != candidate.state
                || outcome.state_root != candidate.state_root
                || outcome.receipts != candidate.receipts
            {
                return Err("PoSy-verified Sync candidate fails deterministic execution".into());
            }
            self.candidate_store.put_once(&candidate)?;
            self.state = candidate.state.clone();
            self.execution_height = candidate.height;
            self.candidates.insert(candidate.height, candidate.clone());
            self.ingress.submit_execution_candidate(candidate)?;
        }
        Ok(())
    }

    fn apply_snapshot_restore_handoffs(&mut self) -> Result<(), String> {
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some(handoff) = self.ingress.take_snapshot_restore_handoff()? else {
                break;
            };
            if handoff.epoch != self.authority.epoch.epoch
                || handoff.finalized_height < self.finalized_height
                || handoff.finalized_height > self.authority.epoch.epoch_end_height
                || synergy_state::state_root(&handoff.state)
                    .map_err(|error| format!("root snapshot restore state: {error:?}"))?
                    != handoff.application_state_root
            {
                return Err(
                    "snapshot restore handoff is not bound to current authority/state".into(),
                );
            }
            if handoff.finalized_height == self.finalized_height {
                let current = self
                    .state_store
                    .as_ref()
                    .and_then(FinalizedStateStore::current)
                    .ok_or("snapshot replay lacks current finalized commitment")?;
                if current.finalized_block_id != handoff.finalized_block_id
                    || current.state_root != handoff.application_state_root
                {
                    return Err("snapshot replay conflicts with current finalized state".into());
                }
                self.ingress
                    .submit_snapshot_restore_receipt(SnapshotRestoreReceipt {
                        finalized_height: handoff.finalized_height,
                        finalized_block_id: handoff.finalized_block_id,
                        application_state_root: handoff.application_state_root,
                    })?;
                continue;
            }
            let finalized = synergy_state::FinalizedState {
                finalized_height: handoff.finalized_height,
                finalized_block_id: handoff.finalized_block_id.clone(),
                state_root: handoff.application_state_root.clone(),
            };
            self.state_store
                .as_mut()
                .ok_or("execution finalized-state store unavailable")?
                .commit_verified_snapshot(finalized, &handoff.state)
                .map_err(|error| format!("commit restored finalized snapshot: {error:?}"))?;
            self.state = handoff.state;
            self.finalized_height = handoff.finalized_height;
            self.execution_height = handoff.finalized_height;
            self.batches.clear();
            self.candidates.clear();
            self.ingress
                .submit_snapshot_restore_receipt(SnapshotRestoreReceipt {
                    finalized_height: handoff.finalized_height,
                    finalized_block_id: handoff.finalized_block_id,
                    application_state_root: handoff.application_state_root,
                })?;
        }
        Ok(())
    }

    fn persist_finalized_sxcp_relays(
        &self,
        candidate: &ExecutionCandidate,
        record: &synergy_posy::FinalizedBlockRecord,
    ) -> Result<(), String> {
        for transaction in &candidate.transactions {
            let TransactionAction::Sxcp {
                destination,
                message,
            } = transaction
                .unsigned
                .action()
                .map_err(|error| format!("decode finalized SXCP action: {error:?}"))?
            else {
                continue;
            };
            let execution: SxcpRelayExecution = serde_json::from_slice(&message)
                .map_err(|error| format!("decode finalized SXCP execution: {error}"))?;
            if destination != execution.transfer.destination {
                return Err("finalized SXCP destination binding changed after execution".into());
            }
            let intent = FinalizedSxcpRelayIntent {
                transaction_id: transaction.id().map_err(|error| error.to_string())?.0,
                execution,
                synergy_finality: SynergyFinalityAnchor {
                    chain_id: self.network.chain_id,
                    finalized_height: record.height,
                    finalized_block_id: record.block_id.clone(),
                    finality_certificate_id: record.finality_certificate_id.clone(),
                },
            };
            self.sxcp_outbox.put_once(&intent)?;
        }
        Ok(())
    }

    fn apply_finality(&mut self) -> Result<(), String> {
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some(record) = self.ingress.take_finality()? else {
                break;
            };
            if record.height <= self.finalized_height {
                continue;
            }
            if record.height != self.finalized_height.saturating_add(1) {
                return Err("execution received non-contiguous PoSy finality".into());
            }
            let candidate = self
                .candidates
                .get(&record.height)
                .ok_or("PoSy finalized a block without local executed candidate state")?;
            if candidate.block_id != record.block_id
                || candidate.protected_execution_root != record.protected_execution_root
            {
                return Err("PoSy finality conflicts with local execution candidate".into());
            }
            self.persist_finalized_sxcp_relays(candidate, &record)?;
            let finalized = synergy_state::FinalizedState {
                finalized_height: record.height,
                finalized_block_id: record.block_id.clone(),
                state_root: candidate.state_root.clone(),
            };
            let state_store = self
                .state_store
                .as_mut()
                .ok_or("execution finalized-state store unavailable")?;
            state_store
                .commit_verified_world_state(finalized, &candidate.state)
                .map_err(|error| format!("commit PoSy-verified state: {error:?}"))?;
            if let Some(retain_blocks) = self.retention_blocks {
                state_store
                    .prune_finalized_history(record.height, retain_blocks)
                    .map_err(|error| format!("prune finalized execution history: {error:?}"))?;
            }
            self.finalized_height = record.height;
            self.ingress
                .submit_snapshot_publication(SnapshotPublication {
                    epoch: self.authority.epoch.epoch,
                    finality: record.clone(),
                    application_state_root: candidate.state_root.clone(),
                    state: candidate.state.clone(),
                })?;
            self.batches.remove(&record.height);
            self.candidates.retain(|height, _| *height >= record.height);
        }
        Ok(())
    }
}

impl ManagedService for ExecutionService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("execution service start was cancelled".into());
        }
        if self.state_store.is_none() {
            return Err("execution finalized-state store is unavailable".into());
        }
        self.started = true;
        self.failure = None;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("execution service is not started".into());
        }
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some(batch) = self.ingress.take_protected_batch()? else {
                break;
            };
            self.accept_batch(batch)?;
        }
        self.serve_sync_requests()?;
        self.apply_snapshot_restore_handoffs()?;
        self.accept_verified_sync_candidates()?;
        self.apply_finality()?;
        for _ in 0..MAX_BATCHES_PER_POLL {
            if !self.execute_next_ready()? {
                break;
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.started = false;
        self.batches.clear();
        self.candidates.clear();
        self.state_store = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if !self.started || self.state_store.is_none() {
            return ServiceHealth::Unhealthy {
                reason: "execution runtime is stopped".into(),
            };
        }
        if let Some(reason) = &self.failure {
            return ServiceHealth::Unhealthy {
                reason: reason.clone(),
            };
        }
        ServiceHealth::Healthy
    }

    fn readiness(&self) -> ServiceReadiness {
        if self.started && self.state_store.is_some() {
            ServiceReadiness::Ready
        } else {
            ServiceReadiness::Blocked {
                reason: "execution owners are not ready".into(),
            }
        }
    }
}
