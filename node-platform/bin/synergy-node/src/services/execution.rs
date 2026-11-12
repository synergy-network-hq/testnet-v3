#[path = "execution_processing.rs"]
mod processing;
#[path = "execution_processing_retirement.rs"]
mod processing_retirement;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use synergy_protocol_types::AuthenticatedPeer;
use synergy_sync::{
    candidate_response_digest, CandidateResponseChunk, CANDIDATE_CHUNK_BYTES,
    MAX_CANDIDATE_RESPONSE_BYTES, MAX_CANDIDATE_WITNESS_BYTES,
};

use synergy_aegis::{
    AegisPolicy, AegisVerifier, KeyId, PqSynqVerifier, PqvmVerifier, Signature, SignatureAlgorithm,
    SigningContext, VerifiedPqSynqOperation,
};
use synergy_aivm::CanonicalAivmSynqVm;
use synergy_block::{hash_block_bytes, BlockBody};
use synergy_config::{NodeConfiguration, StorageConfiguration};
use synergy_etdag::execution::{PreparedProtectedBatch, ProtectedProposalMaterial};
use synergy_etdag::EtdagDigest;
use synergy_execution::{
    BlockExecutionOutcome, BlockExecutionScheduler,
    BudgetedExecutionCandidate as ExecutionCandidate, CanonicalTransactionDispatcher, FeeSchedule,
    GovernanceDispatcher, GovernanceOperation, NativeDispatcher, NativeOperation, SxcpDispatcher,
    SxcpExecutor, SynqDispatcher, SynqRuntime, SystemDispatcher, SystemOperation,
    TransactionDispatch, TransactionExecutionContext,
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
use synergy_sync::{
    BudgetedFinalizedCandidateResponse as FinalizedCandidateResponse,
    BudgetedSyncWireMessage as SyncWireMessage,
};
use synergy_synq::{DeterministicContext, SynqArtifact, SynqExecutor, SynqHost};
use synergy_transaction::{
    AegisTransactionVerifier, NetworkBinding, SignedTransaction, TransactionAction,
};

use super::authority::VerifiedAuthority;
use super::ingress::{
    AuthenticatedIngress, FinalizedExecutionCommit, OutboundFrame, SnapshotRestoreHandoff,
    SnapshotRestoreReceipt,
};
use synergy_protocol_types::ProtocolKind;

const MAX_BATCHES_PER_POLL: usize = 16;
const MAX_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
pub(super) const TESTNET_V3_BASE_FEE_NWEI: u64 = 40;
const TESTNET_V3_FEE_COLLECTOR: &str = "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l";

#[cfg(test)]
thread_local! {
    static HISTORICAL_FINALITY_LOADS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn historical_finality_loads() -> usize {
    HISTORICAL_FINALITY_LOADS.with(std::cell::Cell::get)
}

/// Canonical SynQ caller: Aegis verifies the PQSynQ account-domain envelope,
/// AIVM executes the established deterministic QVM bytecode, and execution
/// returns only a scheduler-applied account-state diff.
#[derive(Debug, Clone)]
struct CanonicalSynqRuntime {
    verifier: PqSynqVerifier,
    vm: CanonicalAivmSynqVm,
}

impl CanonicalSynqRuntime {
    fn new(configuration: &NodeConfiguration) -> Result<Self, String> {
        Ok(Self {
            verifier: {
                #[cfg(test)]
                let legacy_fixture = configuration.aegis_provider.is_none();
                #[cfg(not(test))]
                let legacy_fixture = false;
                if legacy_fixture {
                    PqSynqVerifier::for_network(configuration.chain_id, &configuration.network_id)
                } else {
                    PqSynqVerifier::with_apqe(
                        configuration.chain_id,
                        &configuration.network_id,
                        super::apqe_provider::load(configuration)?,
                    )
                }
                .map_err(|e| format!("configured SynQ policy: {e:?}"))?
            },
            vm: CanonicalAivmSynqVm,
        })
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
    authority: Arc<VerifiedAuthority>,
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
            ("identity", "register_authorization") => {
                if input.len() > synergy_identity::registration::MAX_AUTHORIZATION_TABLE_BYTES {
                    return Err("identity registration exceeds the byte limit".into());
                }
                let carrier = serde_json::from_slice(input)
                    .map_err(|error| format!("decode identity registration: {error}"))?;
                let key =
                    synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY;
                let value = synergy_identity::registration::register_authorization_with_verifier(
                    &state.protocol,
                    &transaction.unsigned.sender,
                    &carrier,
                    context.network.chain_id,
                    &context.network.network_id,
                    self.authority
                        .consensus_timestamp_unix(context.block_height)?,
                    self.authority.identity_verifier(),
                )?;
                let gas_used = 50_000u64
                    .checked_add(value.len() as u64)
                    .ok_or("identity registration gas overflow")?;
                let changed = state.protocol.get(key) != Some(&value);
                let mut protocol_changes = vec![ProtocolChange {
                    key: key.into(),
                    expected_value: state.protocol.get(key).cloned(),
                    value: Some(value),
                }];
                if changed {
                    let marker =
                        synergy_identity::registration::AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY;
                    protocol_changes.push(ProtocolChange {
                        key: marker.into(),
                        expected_value: state.protocol.get(marker).cloned(),
                        value: Some(
                            serde_json::to_vec(&context.block_height).map_err(|e| e.to_string())?,
                        ),
                    });
                }
                Ok(TransactionDispatch {
                    state_diff: StateDiff {
                        changes: vec![synergy_state::AccountChange {
                            account: transaction.unsigned.sender.clone(),
                            debit_nwei: 0,
                            credit_nwei: 0,
                            expected_nonce: Some(transaction.unsigned.nonce),
                            code_hash: None,
                        }],
                        protocol_changes,
                    },
                    gas_used,
                })
            }
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
            ("naming", "register_wallet") => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct WalletNamingInput {
                    syn_id: String,
                }
                let input: WalletNamingInput = serde_json::from_slice(input)
                    .map_err(|error| format!("decode wallet naming registration: {error}"))?;
                let key = synergy_naming::WALLET_PROTOCOL_STATE_KEY;
                let mut naming = synergy_naming::WalletSynIdRegistry::decode(
                    state.protocol.get(key).map(Vec::as_slice),
                )?;
                naming.register_authenticated(
                    &input.syn_id,
                    &transaction.unsigned.sender,
                    context.block_height,
                )?;
                // Use the existing protocol-state dispatcher, fee accounting and
                // atomic native execution; no independent registry writes.
                let _ = naming.encode()?;
                protocol_state_dispatch(state, key, &naming)
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
pub(super) struct TransactionPqvmVerifier {
    verifier: PqvmVerifier,
    identity_verifier: Option<synergy_aegis::ApqeIdentityVerifier>,
    chain_id: u64,
}

impl TransactionPqvmVerifier {
    pub(super) fn from_authority(authority: &VerifiedAuthority, chain_id: u64) -> Self {
        Self {
            verifier: authority.wallet_verifier().clone(),
            identity_verifier: authority.apqe_identity_verifier(),
            chain_id,
        }
    }
    pub(super) fn from_configuration(configuration: &NodeConfiguration) -> Result<Self, String> {
        let verifier = super::apqe_provider::verifier(
            configuration,
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
                maximum_message_bytes: MAX_TRANSACTION_BYTES,
                maximum_signature_bytes: 16 * 1024,
            },
        )?;
        Ok(Self {
            verifier,
            identity_verifier: super::apqe_provider::identity_verifier(configuration)?,
            chain_id: configuration.chain_id,
        })
    }
}

impl AegisTransactionVerifier for TransactionPqvmVerifier {
    fn authorization_verifier(
        &self,
    ) -> Option<&dyn synergy_identity::authorization::AuthorizationSignatureVerifier> {
        self.identity_verifier
            .as_ref()
            .map(|v| v as &dyn synergy_identity::authorization::AuthorizationSignatureVerifier)
    }
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
        match result {
            Ok(()) => Ok(true),
            Err(
                synergy_aegis::VerificationError::InvalidSignature
                | synergy_aegis::VerificationError::InvalidPublicKey,
            ) => Ok(false),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod transaction_provider_error_tests {
    use super::*;

    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_transaction_invalid_proof_is_distinct_from_unavailable_provider() {
        use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
        let selected = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = super::super::apqe_provider::load_selected(&selected).unwrap();
        let message = b"canonical transaction verifier error-boundary fixture";
        let (public, signature) = {
            let engine = engine.lock().unwrap();
            let pair = engine.generate_keypair(Algorithm::MlDsa87).unwrap();
            let signature = engine
                .sign(
                    Algorithm::MlDsa87,
                    pair.private_key.as_bytes(),
                    message,
                    SignOptions::default(),
                )
                .unwrap();
            (pair.public_key, signature)
        };
        let verifier = TransactionPqvmVerifier {
            verifier: PqvmVerifier::with_apqe(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
                    maximum_message_bytes: MAX_TRANSACTION_BYTES,
                    maximum_signature_bytes: 16 * 1024,
                },
                engine.clone(),
            )
            .unwrap(),
            identity_verifier: None,
            chain_id: 1266,
        };
        assert!(verifier
            .verify_transaction(message, &public, &signature, "ML-DSA-87")
            .unwrap());
        assert!(!verifier
            .verify_transaction(b"changed preimage", &public, &signature, "ML-DSA-87")
            .unwrap());
        let held = engine.lock().unwrap();
        let error = verifier
            .verify_transaction(message, &public, &signature, "ML-DSA-87")
            .unwrap_err();
        assert!(error.contains("provider") && error.contains("busy"));
        drop(held);
        assert!(verifier
            .verify_transaction(message, &public, &signature, "ML-DSA-87")
            .unwrap());
    }
}

use synergy_execution::BudgetedCandidateStore as CandidateStore;
use synergy_state::world_resources::BudgetedWorld;

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
    let authority = VerifiedAuthority::owner_context(&authority)?;
    let StorageConfiguration { data_directory, .. } = &configuration.storage;
    let layout = NodeStorageLayout::new(data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let mut state_store = FinalizedStateStore::load_budgeted(
        layout.state().join("execution"),
        Arc::clone(ingress.world_budget()),
    )
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
                authority: Arc::clone(&authority),
                verifier: super::apqe_provider::verifier(
                    configuration,
                    AegisPolicy {
                        allowed_algorithms: vec![
                            SignatureAlgorithm::MlDsa65,
                            SignatureAlgorithm::MlDsa87,
                        ],
                        maximum_message_bytes: 64 * 1024,
                        maximum_signature_bytes: 16 * 1024,
                    },
                )
                .map_err(|error| format!("construct native authorization verifier: {error}"))?,
                chain_id: configuration.chain_id,
            }),
            synq: SynqDispatcher::new(CanonicalSynqRuntime::new(configuration)?),
            sxcp: SxcpDispatcher::new(CanonicalSxcpExecutor {
                authority: Arc::clone(&authority),
            }),
            governance: GovernanceDispatcher::new(governance.clone()),
            system: SystemDispatcher::new(CanonicalSystemOperation { governance }),
        },
        TransactionPqvmVerifier::from_configuration(configuration)?,
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
            .current_world_state_budgeted(ingress.world_budget())
            .map_err(|error| format!("load verified finalized account state: {error:?}"))?,
    ) {
        (Some(_), Some(world)) => world,
        (Some(_), None) => {
            return Err("finalized execution commitment lacks durable account state".into());
        }
        (None, _) => authority.initial_world_state_budgeted(ingress.world_budget())?,
    };
    let candidate_store = CandidateStore::new_budgeted(
        layout.blocks().join("execution-candidates"),
        Arc::clone(ingress.world_budget()),
    )?;
    if authority.processing_profile_enabled() {
        // Complete the crash boundary between an execution commit and its
        // sparse proof pin before any owner can prune or recover terminal work.
        for pin in candidate_store
            .pinned_descriptors()
            .iter()
            .filter(|pin| pin.height <= finalized_height)
        {
            if state_store
                .history_at(pin.height)
                .map_err(|error| format!("recover processing commitment pin: {error:?}"))?
                .is_some()
            {
                state_store
                    .pin_processing_history(pin.height)
                    .map_err(|error| format!("restore processing commitment pin: {error:?}"))?;
            }
        }
    }
    let transition = super::authority::load_transition_context(configuration, authority.as_ref())?;
    let previous_processing = if authority.processing_profile_enabled() {
        transition
            .as_ref()
            .map(|transition| {
                let previous = VerifiedAuthority::owner_context(transition.previous_authority())?;
                let namespace = super::processing_pipeline::processing_namespace(
                    &previous,
                    ingress.world_budget(),
                )?;
                let store = super::processing_proposals::ProcessingProposalStore::open(
                    &super::processing_proposals::epoch_store_path(
                        &layout.blocks(),
                        previous.epoch.epoch,
                    ),
                    namespace,
                    ingress.world_budget(),
                    Arc::clone(&previous),
                )?;
                Ok::<_, String>(processing::PreviousProcessingState {
                    authority: previous,
                    store: Arc::new(std::sync::Mutex::new(store)),
                    transition: transition.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };
    let processing = if authority.processing_profile_enabled() {
        let namespace =
            super::processing_pipeline::processing_namespace(&authority, ingress.world_budget())?;
        // PoSy and ETDAG also verify through this mutex-owned store. Keep its
        // provider separate from Execution's QC reads outside the store lock.
        let store_authority = VerifiedAuthority::owner_context(&authority)?;
        let store = Arc::new(std::sync::Mutex::new(
            super::processing_proposals::ProcessingProposalStore::open(
                &super::processing_proposals::epoch_store_path(
                    &layout.blocks(),
                    authority.epoch.epoch,
                ),
                namespace,
                ingress.world_budget(),
                store_authority,
            )?,
        ));
        ingress.install_processing_proposal_store(Arc::clone(&store))?;
        Some(processing::ProcessingExecutionState::new(store))
    } else {
        None
    };
    let sxcp_outbox = SxcpRelayOutbox::open(layout.state().join("sxcp-relay-outbox"))?;
    let qc_store = VerifiedQuorumCertificateStore::new(layout.consensus().join("posy"))
        .map_err(|error| format!("open certified execution replay authority: {error}"))?;
    if let Some(owner) = &processing {
        owner
            .store
            .lock()
            .map_err(|_| "processing proposal journal lock poisoned")?
            .recover_certified_stages(&qc_store)?;
    }
    let timeout_store = VerifiedTimeoutCertificateStore::new(layout.consensus().join("posy"))
        .map_err(|error| format!("open Sync timeout witness store: {error}"))?;
    ingress.install_finality_history_with_transition(
        layout.consensus().join("posy"),
        Arc::clone(&authority),
        transition.clone(),
    )?;
    let mut candidates = BTreeMap::new();
    let mut execution_height = finalized_height;
    let finalized_authorization_state = Arc::new(state);
    let mut recovered_state = Arc::clone(&finalized_authorization_state);
    let mut expected_parent = state_store
        .current()
        .map(|record| record.finalized_block_id.clone())
        .unwrap_or_else(|| authority.anchor_parent.block_id().to_string());
    if processing.is_some() && finalized_height > 0 {
        let historical = previous_processing.as_ref().filter(|previous| {
            previous.authority.epoch.contains_height(finalized_height)
                && finalized_height >= previous.transition.finalized().height
        });
        let candidate_authority =
            historical.map_or(authority.as_ref(), |previous| previous.authority.as_ref());
        let record = ingress
            .finalized_record(finalized_height)?
            .ok_or("processing finalized state lacks native three-QC history")?;
        let mut candidate = candidate_store
            .get_budgeted(finalized_height)
            .map_err(|error| error.to_string())?
            .ok_or("processing finalized state lacks durable candidate")?;
        candidate.validate()?;
        if record.block_id != candidate.block_id
            || record.protected_execution_root != candidate.protected_execution_root
            || candidate.state.as_ref().as_ref() != recovered_state.as_ref().as_ref()
            || candidate.state_root
                != state_store
                    .current()
                    .expect("finalized state exists")
                    .state_root
            || !matches!(&candidate.protected_material,
                synergy_etdag::execution::CandidateProtectedMaterial::Processing(material)
                if material.namespace_root == super::processing_pipeline::processing_namespace(candidate_authority, ingress.world_budget())?)
        {
            return Err("processing finalized recovery conflicts with durable PoSy state".into());
        }
        candidate.state = Arc::clone(&recovered_state);
        candidates.insert(finalized_height, Arc::new(candidate));
    }
    if processing.is_some() {
        ingress.publish_processing_finalized_world(
            finalized_height,
            Arc::clone(&finalized_authorization_state),
        )?;
    }
    loop {
        // Versioned replay requires original native processing capabilities.
        // The live owner resumes it after ETDAG restores its prepaid workers.
        if processing.is_some() {
            break;
        }
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
        let Some(candidate) = candidate_store.get(next_height)? else {
            // Authenticated Sync can commit consensus proof before the matching
            // execution payload arrives. Preserve that proof and wait at the
            // exact execution gap; never infer state from a QC alone.
            break;
        };
        let candidate = Arc::new(candidate);
        if candidate.block_id != qc.block_id
            || candidate.parent_block_id != expected_parent
            || candidate.parent_block_id != qc.parent_block_id
            || candidate.protected_execution_root != qc.protected_execution_root
        {
            return Err(format!(
                "certified execution candidate conflicts with PoSy QC at H{next_height}"
            ));
        }
        verify_governed_candidate_material(&candidate, authority.as_ref(), &ingress)?;
        let outcome = scheduler
            .execute_at_budgeted(
                &BlockBody {
                    transactions: candidate.transactions.clone(),
                },
                &network,
                next_height,
                authority.consensus_timestamp_unix(next_height)?,
                &recovered_state,
                &finalized_authorization_state,
            )
            .map_err(|error| format!("re-execute certified candidate H{next_height}: {error:?}"))?;
        if outcome.state != *candidate.state
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
        ingress.submit_protected_material(
            candidate
                .protected_material
                .as_legacy()
                .ok_or("processing profile has no governed native replay path yet")?
                .clone(),
        )?;
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
        super::owned_service::production(
            Box::new(ExecutionService {
                scheduler,
                processing,
                previous_processing,
                state_store: Some(state_store),
                ingress,
                network,
                authority,
                finalized_height,
                execution_height,
                state: recovered_state,
                finalized_state: finalized_authorization_state,
                candidate_store,
                sxcp_outbox,
                qc_store,
                timeout_store,
                retention_blocks: configuration.storage.prune_finalized_history_after_blocks,
                batches: BTreeMap::new(),
                candidates,
                outgoing_candidate: None,
                pending_snapshot_restore: None,
                sync_diagnostic_requests: BTreeMap::new(),
                sync_diagnostic_at: Instant::now(),
                started: false,
                failure: None,
            }),
            "execution",
        ),
    ))
}

fn bounded_response_bytes(response: &FinalizedCandidateResponse) -> Result<Vec<u8>, String> {
    struct BoundedBytes(Vec<u8>);
    impl std::io::Write for BoundedBytes {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_CANDIDATE_RESPONSE_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(
                    "candidate response exceeds transport bound",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut output, response).map_err(|e| e.to_string())?;
    Ok(output.0)
}

struct OutgoingCandidate {
    peer: AuthenticatedPeer,
    request: synergy_sync::FinalizedCandidateRequest,
    bytes: Vec<u8>,
    digest: [u8; 32],
    offset: usize,
    started: Instant,
}

struct ExecutionService {
    processing: Option<processing::ProcessingExecutionState>,
    previous_processing: Option<processing::PreviousProcessingState>,
    scheduler: BlockExecutionScheduler<CanonicalExecutionDispatcher, TransactionPqvmVerifier>,
    state_store: Option<FinalizedStateStore>,
    ingress: AuthenticatedIngress,
    network: NetworkBinding,
    authority: Arc<VerifiedAuthority>,
    finalized_height: u64,
    execution_height: u64,
    state: Arc<BudgetedWorld>,
    finalized_state: Arc<BudgetedWorld>,
    candidate_store: CandidateStore,
    sxcp_outbox: SxcpRelayOutbox,
    qc_store: VerifiedQuorumCertificateStore,
    timeout_store: VerifiedTimeoutCertificateStore,
    retention_blocks: Option<u64>,
    batches: BTreeMap<u64, PreparedProtectedBatch>,
    candidates: BTreeMap<u64, Arc<ExecutionCandidate>>,
    outgoing_candidate: Option<OutgoingCandidate>,
    pending_snapshot_restore: Option<SnapshotRestoreHandoff>,
    // Bounded, non-authoritative observations for stalled requests only.
    sync_diagnostic_requests: BTreeMap<(String, u64), Instant>,
    sync_diagnostic_at: Instant,
    started: bool,
    failure: Option<String>,
}

fn verify_committed_sync_replay(
    candidate: &ExecutionCandidate,
    committed: &synergy_state::FinalizedState,
) -> Result<(), String> {
    candidate.validate()?;
    if candidate.height != committed.finalized_height
        || candidate.block_id != committed.finalized_block_id
        || candidate.state_root != committed.state_root
    {
        return Err("historical Sync candidate conflicts with durable finalized state".into());
    }
    Ok(())
}

/// H1/H2 are the only Genesis bootstrap heights. Every normal height must
/// wait for ETDAG-verified material, even when that material contains no user
/// transactions. Advancing finality never authorizes an uncertified empty cut.
fn transactions_for_candidate(
    height: u64,
    batch: Option<&PreparedProtectedBatch>,
) -> Result<Option<Vec<SignedTransaction>>, String> {
    if height == 0 {
        return Err("Genesis is not an execution candidate".into());
    }
    let Some(batch) = batch else {
        return Ok(if height <= 2 { Some(Vec::new()) } else { None });
    };
    batch
        .validate()
        .map_err(|error| format!("validate candidate batch: {error:?}"))?;
    if batch.target_height != height {
        return Err("protected batch belongs to a different candidate height".into());
    }
    batch
        .transactions
        .iter()
        .map(|prepared| {
            if prepared.plaintext.len() > MAX_TRANSACTION_BYTES {
                return Err("prepared transaction exceeds execution bound".into());
            }
            let transaction: SignedTransaction = serde_json::from_slice(&prepared.plaintext)
                .map_err(|error| format!("decode ETDAG-authorized transaction: {error}"))?;
            transaction
                .validate_structure()
                .map_err(|error| format!("validate ETDAG-authorized transaction: {error:?}"))?;
            Ok(transaction)
        })
        .collect::<Result<Vec<_>, String>>()
        .map(Some)
}

/// Assembles only independently governed execution and ETDAG-certified next-cut
/// commitments; absence is readiness, never authority to create an empty cut.
fn assemble_protected_material<S>(
    authority: &VerifiedAuthority,
    ingress: &AuthenticatedIngress,
    height: u64,
    batch: Option<&PreparedProtectedBatch>,
    outcome: &BlockExecutionOutcome<S>,
    transactions: &[SignedTransaction],
) -> Result<Option<ProtectedProposalMaterial>, String> {
    if outcome.block_height != height {
        return Err("protected execution outcome height mismatch".into());
    }
    let next = height
        .checked_add(1)
        .ok_or("next protected height overflow")?;
    let next_batch_root = if next == 2 {
        authority.protected_bootstrap_next_batch(next)?
    } else {
        let Some((next_batch, _)) = ingress.protected_commitments(next)? else {
            return Ok(None);
        };
        let source_height = authority.protected_source_height(next)?;
        let source = if source_height == 0 {
            None
        } else {
            let Some(source) = ingress.finalized_record(source_height)? else {
                return Ok(None);
            };
            Some(source)
        };
        let (_, expected_context) = authority.protected_target(source.as_ref(), next)?;
        if next_batch.context_root != expected_context {
            return Err("next protected batch differs from governed target context".into());
        }
        next_batch.protected_batch_root
    };
    let target = height.checked_add(2).ok_or("boundary target overflow")?;
    let source_height = authority.protected_source_height(target)?;
    let source = if source_height == 0 {
        None
    } else {
        let Some(source) = ingress.finalized_record(source_height)? else {
            return Ok(None);
        };
        Some(source)
    };
    let cutoff_boundary_root = authority.protected_cutoff_boundary(source.as_ref(), height)?;
    let execution_authority = match batch {
        Some(batch) => EtdagDigest::from_canonical(
            "SYNERGY_POSY_EXECUTED_BATCH_AUTHORITY_V1",
            &(
                &batch.context_root,
                batch.target_height,
                &batch.protected_batch_root,
                // The authorization binds the stable parent candidate/VC identity.
                // Exact verified share bundles remain audit/recovery evidence;
                // valid threshold subsets cannot change a PoSy candidate.
                &batch.reveal_authorization,
            ),
        )
        .map_err(|e| format!("executed protected authority: {e:?}"))?,
        None => authority.protected_bootstrap_execution(height)?,
    };
    let execution_root = EtdagDigest::from_canonical(
        "SYNERGY_POSY_EXECUTION_RESULT_V1",
        &(
            execution_authority,
            height,
            &outcome.state_root,
            transactions,
            &outcome.receipts,
        ),
    )
    .map_err(|e| format!("executed protected result: {e:?}"))?;
    let material = ProtectedProposalMaterial {
        material_version: 2,
        height,
        execution_root,
        next_batch_root,
        cutoff_boundary_root,
    };
    material
        .validate()
        .map_err(|e| format!("validate assembled protected material: {e:?}"))?;
    Ok(Some(material))
}

/// Historical material is admitted only alongside verified PoSy QC/finality
/// authority and deterministic execution replay. Disk or Sync cannot choose
/// the governed future boundary or substitute bootstrap commitments.
fn verify_governed_candidate_material(
    candidate: &ExecutionCandidate,
    authority: &VerifiedAuthority,
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    candidate.validate()?;
    let material = candidate.protected_material.as_legacy().ok_or(
        "processing candidate requires explicit governed activation and native verification",
    )?;
    let target = candidate
        .height
        .checked_add(2)
        .ok_or("candidate boundary overflow")?;
    let source_height = authority.protected_source_height(target)?;
    let source = if source_height == 0 {
        None
    } else {
        Some(
            ingress
                .finalized_record(source_height)?
                .ok_or("historical protected boundary lacks verified finalized source")?,
        )
    };
    if material.cutoff_boundary_root
        != authority.protected_cutoff_boundary(source.as_ref(), candidate.height)?
    {
        return Err("candidate protected boundary differs from signed governance".into());
    }
    if candidate.height <= 2 {
        if !candidate.transactions.is_empty() || !candidate.receipts.is_empty() {
            return Err("Genesis bootstrap candidate contains normal transactions".into());
        }
        let root = EtdagDigest::from_canonical(
            "SYNERGY_POSY_EXECUTION_RESULT_V1",
            &(
                authority.protected_bootstrap_execution(candidate.height)?,
                candidate.height,
                &candidate.state_root,
                &candidate.transactions,
                &candidate.receipts,
            ),
        )
        .map_err(|e| format!("verify bootstrap execution result: {e:?}"))?;
        if material.execution_root != root {
            return Err("bootstrap execution differs from signed Genesis authority".into());
        }
        if candidate.height == 1
            && material.next_batch_root != authority.protected_bootstrap_next_batch(2)?
        {
            return Err("bootstrap next-batch differs from signed Genesis authority".into());
        }
    }
    Ok(())
}

/// A remote reveal proof cannot advance execution ahead of the parent that
/// the local PoSy owner has accepted and durably verified.
pub(super) fn protected_parent_ready(
    batch: &PreparedProtectedBatch,
    local_parent: Option<&synergy_posy::ProposalValidationCertificate>,
) -> Result<bool, String> {
    let Some(local_parent) = local_parent else {
        return Ok(false);
    };
    let reveal_parent: synergy_posy::ProposalValidationCertificate =
        serde_json::from_slice(&batch.parent_evidence.validation_proof)
            .map_err(|error| format!("decode protected parent proof: {error}"))?;
    if local_parent.context != reveal_parent.context
        || local_parent.candidate != reveal_parent.candidate
        || local_parent.context.height.checked_add(1) != Some(batch.target_height)
    {
        return Err("protected reveal proof conflicts with locally accepted PoSy parent".into());
    }
    Ok(true)
}

fn execution_resource_pressure(error: &synergy_execution::BlockExecutionError) -> bool {
    matches!(
        error,
        synergy_execution::BlockExecutionError::StateRoot(
            synergy_state::StateError::ResourcePressure { .. }
        ) | synergy_execution::BlockExecutionError::State {
            source: synergy_state::StateError::ResourcePressure { .. },
            ..
        }
    )
}
fn candidate_resource_pressure(error: &synergy_execution::CandidateResourceError) -> bool {
    matches!(
        error,
        synergy_execution::CandidateResourceError::Resource(
            synergy_state::world_resources::WorldResourceError::Capacity { .. }
        )
    )
}

/// Read the durable Sync proof using the execution consumer's independent
/// APQE provider, rather than the shared PoSy authority engine.
pub(super) fn load_sync_witness(
    authority: &Arc<VerifiedAuthority>,
    qc_store: &VerifiedQuorumCertificateStore,
    timeout_store: &VerifiedTimeoutCertificateStore,
    height: u64,
) -> Result<FinalitySyncWitness, String> {
    let authority = VerifiedAuthority::worker_context(authority)?;
    let middle = height
        .checked_add(1)
        .ok_or("Sync witness height overflow")?;
    let newest = height
        .checked_add(2)
        .ok_or("Sync witness height overflow")?;
    let qc = |height, missing| {
        qc_store
            .get_verified(
                height,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .map_err(|error| format!("load Sync QC witness: {error}"))?
            .ok_or_else(|| String::from(missing))
    };
    let certificates = [
        qc(height, "finalized candidate lacks oldest QC witness")?,
        qc(middle, "finalized candidate lacks middle QC witness")?,
        qc(newest, "finalized candidate lacks newest QC witness")?,
    ];
    FinalitySyncWitness::from_verified_certificates(
        certificates,
        timeout_store,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .map_err(|error| format!("assemble Sync lease timeout witness: {error}"))
}

impl ExecutionService {
    fn accept_batch(&mut self, batch: PreparedProtectedBatch) -> Result<(), String> {
        batch
            .validate()
            .map_err(|error| format!("validate execution protected batch: {error:?}"))?;
        synergy_etdag::reveal::VerifiedRevealAuthorization::verify(
            batch.reveal_authorization.clone(),
            &batch.parent_evidence,
            self.authority.as_ref(),
        )
        .map_err(|error| format!("verify exact PoSy parent before execution: {error:?}"))?;
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
        let source_height = self
            .authority
            .protected_source_height(batch.target_height)?;
        let source = if source_height == 0 {
            None
        } else {
            Some(
                self.ingress
                    .finalized_record(source_height)?
                    .ok_or("execution batch lacks verified governed source finality")?,
            )
        };
        let (expected_context, _) = self
            .authority
            .protected_target(source.as_ref(), batch.target_height)?;
        if batch.context != expected_context {
            return Err(
                "execution batch differs from independently governed target context".into(),
            );
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
        let batch = self.batches.get(&next_height);
        if let Some(batch) = &batch {
            let parent = self.ingress.proposal_validation(next_height - 1)?;
            if !protected_parent_ready(batch, parent.as_ref())? {
                return Ok(false);
            }
        }
        let metadata_permit = match synergy_execution::reserve_execution_metadata(
            batch.into_iter().flat_map(|batch| {
                batch
                    .transactions
                    .iter()
                    .map(|prepared| prepared.plaintext.as_slice())
            }),
            self.ingress.world_budget(),
        ) {
            Ok(permit) => permit,
            Err(error) if candidate_resource_pressure(&error) => return Ok(false),
            Err(error) => return Err(error.to_string()),
        };
        let Some(transactions) = transactions_for_candidate(next_height, batch)? else {
            return Ok(false);
        };
        let body = BlockBody {
            transactions: transactions.clone(),
        };
        let finalized_authorization_state = Arc::clone(&self.finalized_state);
        let outcome = match self.scheduler.execute_at_budgeted(
            &body,
            &self.network,
            next_height,
            self.authority.consensus_timestamp_unix(next_height)?,
            &self.state,
            &finalized_authorization_state,
        ) {
            Ok(outcome) => outcome,
            Err(error) if execution_resource_pressure(&error) => return Ok(false),
            Err(error) => return Err(format!("execute deterministic protected batch: {error:?}")),
        };
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
        let Some(protected_material) =
            self.proposal_material(next_height, batch, &outcome, &transactions)?
        else {
            return Ok(false);
        };
        let protected_execution_root = hash_block_bytes(
            &protected_material
                .commitment_bytes()
                .map_err(|e| format!("commit complete protected material: {e:?}"))?,
        );
        let candidate_bytes = serde_json::to_vec(&(
            next_height,
            &parent_block_id,
            &protected_execution_root,
            &outcome.state_root,
            &transactions,
            &outcome.receipts,
        ))
        .map_err(|error| format!("encode execution candidate commitment: {error}"))?;
        #[cfg(test)]
        if next_height == 3 && !transactions.is_empty() {
            eprintln!(
                "protected execution: H3 state={} material={} transcript={}",
                outcome.state_root,
                protected_execution_root,
                batch
                    .as_ref()
                    .map(|b| b.reveal_transcript_root.0.as_str())
                    .unwrap_or("absent")
            );
        }
        let candidate = ExecutionCandidate {
            resource_permit: Some(Arc::new(metadata_permit)),
            height: next_height,
            block_id: hash_block_bytes(&candidate_bytes),
            parent_block_id,
            protected_execution_root,
            protected_material: protected_material.clone().into(),
            state_root: outcome.state_root,
            transactions,
            receipts: outcome.receipts,
            state: Arc::new(outcome.state),
        };
        if let Some(qc) = self
            .qc_store
            .get_verified(
                next_height,
                &self.authority.epoch,
                &self.authority.registry,
                self.authority.as_ref(),
            )
            .map_err(|error| format!("verify recovered candidate QC: {error}"))?
        {
            if candidate.block_id != qc.block_id
                || candidate.parent_block_id != qc.parent_block_id
                || candidate.protected_execution_root != qc.protected_execution_root
            {
                return Err("recovered execution candidate conflicts with retained PoSy QC".into());
            }
        }
        match self.candidate_store.put_budgeted(&candidate, &self.state) {
            Ok(()) => {}
            Err(error) if candidate_resource_pressure(&error) => return Ok(false),
            Err(error) => return Err(error.to_string()),
        }
        let candidate = Arc::new(candidate);
        self.ingress.submit_protected_material(protected_material)?;
        self.ingress.submit_execution_candidate(candidate.clone())?;
        self.state = candidate.state.clone();
        self.execution_height = next_height;
        self.candidates.insert(next_height, candidate);
        Ok(true)
    }

    fn proposal_material<S>(
        &self,
        height: u64,
        batch: Option<&PreparedProtectedBatch>,
        outcome: &BlockExecutionOutcome<S>,
        transactions: &[SignedTransaction],
    ) -> Result<Option<ProtectedProposalMaterial>, String> {
        assemble_protected_material(
            self.authority.as_ref(),
            &self.ingress,
            height,
            batch,
            outcome,
            transactions,
        )
    }

    fn report_sync_candidate(
        &mut self,
        peer: &AuthenticatedPeer,
        request: &synergy_sync::FinalizedCandidateRequest,
        code: &'static str,
        bytes: usize,
    ) {
        let key = (peer.node_address.to_string(), request.height);
        // A request for a newer height is the receiver's observable progress.
        // Retire its older diagnostic entries without changing serving state.
        self.sync_diagnostic_requests
            .retain(|(peer_id, height), _| peer_id != &key.0 || *height >= request.height);
        if !self.sync_diagnostic_requests.contains_key(&key)
            && self.sync_diagnostic_requests.len() >= 16
        {
            if let Some(oldest) = self
                .sync_diagnostic_requests
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(key, _)| key.clone())
            {
                self.sync_diagnostic_requests.remove(&oldest);
            }
        }
        let age = self
            .sync_diagnostic_requests
            .entry(key)
            .or_insert_with(Instant::now)
            .elapsed();
        if age < Duration::from_secs(10)
            || self.sync_diagnostic_at.elapsed() < Duration::from_secs(10)
        {
            return;
        }
        self.sync_diagnostic_at = Instant::now();
        eprintln!(
            "SYNC_CANDIDATE_PROVIDER network={} height={} peer={} rx_session={:?} age_ms={} code={} bytes={} execution_finalized={} execution_height={}",
            self.authority.epoch.network_id, request.height, peer.node_address, peer.session_id,
            age.as_millis(), code, bytes, self.finalized_height, self.execution_height,
        );
    }

    fn flush_candidate_chunks(&mut self) -> Result<(), String> {
        let Some(stream) = self.outgoing_candidate.as_ref() else {
            return Ok(());
        };
        if stream.started.elapsed() >= Duration::from_secs(120)
            || !self.ingress.is_current_session(&stream.peer)?
        {
            let peer = stream.peer.clone();
            let request = stream.request.clone();
            self.report_sync_candidate(&peer, &request, "stream-age-or-session-expired", 0);
            self.outgoing_candidate = None;
            return Ok(());
        }
        for _ in 0..4 {
            let stream = self
                .outgoing_candidate
                .as_mut()
                .ok_or("candidate stream disappeared")?;
            let end = (stream.offset + CANDIDATE_CHUNK_BYTES).min(stream.bytes.len());
            let chunk = CandidateResponseChunk {
                request: stream.request.clone(),
                total_bytes: stream.bytes.len(),
                digest: stream.digest,
                offset: stream.offset,
                bytes: stream.bytes[stream.offset..end].to_vec(),
            };
            let payload = serde_json::to_vec(&SyncWireMessage::FinalizedCandidateChunk(chunk))
                .map_err(|e| format!("encode candidate chunk: {e}"))?;
            if payload.len() > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
                let peer = stream.peer.clone();
                let request = stream.request.clone();
                let bytes = payload.len();
                self.report_sync_candidate(&peer, &request, "chunk-frame-oversized", bytes);
                self.outgoing_candidate = None;
                return Ok(());
            }
            if !self.ingress.try_publish_outbound(OutboundFrame {
                peer_id: stream.peer.node_address.to_string(),
                protocol: ProtocolKind::Sync,
                payload,
            })? {
                let peer = stream.peer.clone();
                let request = stream.request.clone();
                let remaining = stream.bytes.len().saturating_sub(stream.offset);
                self.report_sync_candidate(
                    &peer,
                    &request,
                    "chunk-outbound-backpressure",
                    remaining,
                );
                break;
            }
            stream.offset = end;
            if end == stream.bytes.len() {
                let peer = stream.peer.clone();
                let request = stream.request.clone();
                let bytes = stream.bytes.len();
                self.outgoing_candidate = None;
                self.report_sync_candidate(&peer, &request, "chunks-queued", bytes);
                break;
            }
        }
        Ok(())
    }

    fn serve_sync_requests(&mut self) -> Result<(), String> {
        if self.outgoing_candidate.is_some() {
            self.flush_candidate_chunks()?;
            return Ok(());
        }
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some((peer, request, chunks)) = self.ingress.take_sync_candidate_request()? else {
                break;
            };
            if !self.ingress.is_current_session(&peer)? {
                self.report_sync_candidate(&peer, &request, "request-stale-session", 0);
                continue;
            }
            if request.height > self.finalized_height {
                self.report_sync_candidate(
                    &peer,
                    &request,
                    "request-ahead-of-execution-finality",
                    0,
                );
                continue;
            }
            let candidate = match self.candidate_store.get_budgeted(request.height) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => {
                    // A peer can legitimately lag beyond our retained candidate
                    // horizon. Absence is not corruption or a local execution
                    // failure; never let a remote read stop the provider.
                    self.report_sync_candidate(&peer, &request, "candidate-unavailable", 0);
                    continue;
                }
                Err(error) if candidate_resource_pressure(&error) => {
                    self.ingress
                        .submit_sync_candidate_request_version(peer, request, chunks)?;
                    break;
                }
                Err(error) => return Err(error.to_string()),
            };
            if candidate.parent_block_id != request.expected_parent_id {
                self.report_sync_candidate(&peer, &request, "request-parent-mismatch", 0);
                continue;
            }
            let witness = load_sync_witness(
                &self.authority,
                &self.qc_store,
                &self.timeout_store,
                request.height,
            )?;
            let finality_witness = serde_json::to_vec(&witness)
                .map_err(|error| format!("encode Sync candidate witness: {error}"))?;
            let witness_limit = if chunks {
                MAX_CANDIDATE_WITNESS_BYTES
            } else {
                1024 * 1024
            };
            if finality_witness.len() > witness_limit {
                // An unservable historical request is not a local execution
                // failure. Keep consensus alive and let the bounded requester
                // retry; never truncate proof or emit an oversized frame.
                self.report_sync_candidate(
                    &peer,
                    &request,
                    "witness-oversized",
                    finality_witness.len(),
                );
                continue;
            }
            let processing_replay = if let Some(owner) = &self.processing {
                Some(
                    owner
                        .store
                        .lock()
                        .map_err(|_| "processing proposal journal lock poisoned")?
                        .export_sync(&candidate.block_id)?,
                )
            } else {
                None
            };
            let (processing_replay, _processing_replay_permit) = match processing_replay {
                Some((bytes, permit)) => (Some(bytes), Some(permit)),
                None => (None, None),
            };
            let response = FinalizedCandidateResponse {
                request: request.clone(),
                candidate,
                finality_witness,
                processing_replay,
            };
            if chunks {
                let bytes = match bounded_response_bytes(&response) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.report_sync_candidate(&peer, &request, "response-oversized", 0);
                        continue;
                    }
                };
                self.report_sync_candidate(&peer, &request, "response-stream-queued", bytes.len());
                let digest = candidate_response_digest(&bytes);
                self.outgoing_candidate = Some(OutgoingCandidate {
                    peer,
                    request,
                    bytes,
                    digest,
                    offset: 0,
                    started: Instant::now(),
                });
                self.flush_candidate_chunks()?;
                break;
            }
            let payload =
                serde_json::to_vec(&SyncWireMessage::FinalizedCandidateResponse(response))
                    .map_err(|error| format!("encode Sync candidate response: {error}"))?;
            if payload.len() > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
                self.report_sync_candidate(
                    &peer,
                    &request,
                    "legacy-response-frame-oversized",
                    payload.len(),
                );
                continue;
            }
            let response_bytes = payload.len();
            if !self.ingress.try_publish_outbound(OutboundFrame {
                peer_id: peer.node_address.to_string(),
                protocol: ProtocolKind::Sync,
                payload,
            })? {
                // Retain the authenticated request. The finalized candidate and
                // witness are durable, so the exact response can be retried.
                self.report_sync_candidate(
                    &peer,
                    &request,
                    "legacy-response-outbound-backpressure",
                    response_bytes,
                );
                self.ingress.submit_sync_candidate_request(peer, request)?;
                break;
            }
            self.report_sync_candidate(&peer, &request, "legacy-response-queued", response_bytes);
        }
        Ok(())
    }

    fn accept_verified_sync_candidates(&mut self) -> Result<(), String> {
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some((candidate, record)) = self.ingress.take_verified_sync_candidate()? else {
                break;
            };
            candidate.validate()?;
            if candidate.height != record.height
                || candidate.block_id != record.block_id
                || candidate.protected_execution_root != record.protected_execution_root
            {
                return Err("Sync candidate conflicts with verified PoSy finality".into());
            }
            if candidate.height <= self.finalized_height {
                let store = self
                    .state_store
                    .as_ref()
                    .ok_or("Sync replay lacks finalized-state store")?;
                let committed = store
                    .history_at(candidate.height)
                    .map_err(|error| format!("load historical Sync commitment: {error:?}"))?
                    .or_else(|| {
                        store
                            .current()
                            .filter(|state| state.finalized_height == candidate.height)
                            .cloned()
                    })
                    .ok_or("Sync replay lacks exact durable finalized commitment")?;
                verify_committed_sync_replay(&candidate, &committed)?;
                if self.processing.is_some() {
                    // Restart can leave Sync awaiting an already durable
                    // transition. Re-acknowledge its verified exact commitment
                    // without executing it or advancing any safety floor.
                    if !self.ingress.finalized_execution_commit_has_capacity()? {
                        self.ingress
                            .submit_verified_sync_candidate(candidate, record)?;
                        break;
                    }
                    self.ingress.execution_committed(candidate.height)?;
                    self.ingress
                        .submit_finalized_execution_commit(FinalizedExecutionCommit {
                            epoch: self.authority.epoch.epoch,
                            finality: record,
                            application_state_root: committed.state_root,
                        })?;
                }
                continue;
            }
            let expected_height = self
                .finalized_height
                .checked_add(1)
                .ok_or("Sync import height overflow")?;
            if candidate.height > expected_height {
                // Retain authenticated future material until preceding state
                // transitions commit. A queued response never grants a skip.
                self.ingress
                    .submit_verified_sync_candidate(candidate, record)?;
                continue;
            }
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
            if matches!(
                candidate.protected_material,
                synergy_etdag::execution::CandidateProtectedMaterial::Processing(_)
            ) {
                if self.processing.is_none() || !self.authority.processing_profile_enabled() {
                    return Err("processing Sync requires governed activation".into());
                }
                if let Some(existing) = self.candidates.get(&candidate.height) {
                    if existing.as_ref() != candidate.as_ref() {
                        return Err("processing Sync differs from native replayed candidate".into());
                    }
                    self.apply_finality()?;
                } else {
                    // PoSy has persisted the exact certified replay inputs and
                    // VC. The existing execution owner restores each native
                    // transition in sequence; absence of native material is
                    // backpressure, never permission to trust an incoming World.
                    self.ingress
                        .submit_verified_sync_candidate(candidate, record)?;
                    break;
                }
                continue;
            }
            verify_governed_candidate_material(&candidate, self.authority.as_ref(), &self.ingress)?;
            if let Some(existing) = self.candidates.get(&candidate.height) {
                if existing.block_id != candidate.block_id
                    || existing.protected_execution_root != candidate.protected_execution_root
                    || existing.state_root != candidate.state_root
                {
                    return Err("Sync candidate conflicts with pending execution transition".into());
                }
                self.apply_finality()?;
                continue;
            }
            let finalized_authorization_state = Arc::clone(&self.finalized_state);
            let outcome = match self.scheduler.execute_at_budgeted(
                &BlockBody {
                    transactions: candidate.transactions.clone(),
                },
                &self.network,
                candidate.height,
                self.authority.consensus_timestamp_unix(candidate.height)?,
                &finalized_authorization_state,
                &finalized_authorization_state,
            ) {
                Ok(outcome) => outcome,
                Err(error) if execution_resource_pressure(&error) => {
                    self.ingress
                        .submit_verified_sync_candidate(candidate, record)?;
                    break;
                }
                Err(error) => return Err(format!("re-execute Sync candidate: {error:?}")),
            };
            if outcome.state != *candidate.state
                || outcome.state_root != candidate.state_root
                || outcome.receipts != candidate.receipts
            {
                return Err("PoSy-verified Sync candidate fails deterministic execution".into());
            }
            drop(outcome);
            match self
                .candidate_store
                .put_budgeted(&candidate, &finalized_authorization_state)
            {
                Ok(()) => {}
                Err(error) if candidate_resource_pressure(&error) => {
                    self.ingress
                        .submit_verified_sync_candidate(candidate, record)?;
                    break;
                }
                Err(error) => return Err(error.to_string()),
            }
            self.state = candidate.state.clone();
            self.execution_height = candidate.height;
            self.candidates.insert(candidate.height, candidate.clone());
            self.ingress.submit_protected_material(
                candidate
                    .protected_material
                    .as_legacy()
                    .ok_or("processing profile has no governed native replay path yet")?
                    .clone(),
            )?;
            self.ingress.submit_execution_candidate(candidate)?;
            self.apply_finality()?;
        }
        Ok(())
    }

    fn apply_snapshot_restore_handoffs(&mut self) -> Result<(), String> {
        for _ in 0..MAX_BATCHES_PER_POLL {
            let handoff = match self.pending_snapshot_restore.take() {
                Some(handoff) => Some(handoff),
                None => self.ingress.take_snapshot_restore_handoff()?,
            };
            let Some(handoff) = handoff else {
                break;
            };
            if handoff.epoch != self.authority.epoch.epoch
                || handoff.finalized_height > self.authority.epoch.epoch_end_height
                || synergy_state::state_root(&handoff.state)
                    .map_err(|error| format!("root snapshot restore state: {error:?}"))?
                    != handoff.application_state_root
            {
                return Err(
                    "snapshot restore handoff is not bound to current authority/state".into(),
                );
            }
            if handoff.finalized_height <= self.finalized_height {
                let current = self
                    .state_store
                    .as_ref()
                    .ok_or("snapshot replay lacks finalized-state store")?
                    .history_at(handoff.finalized_height)
                    .map_err(|error| format!("verify historical snapshot replay: {error:?}"))?
                    .ok_or("snapshot replay lacks exact finalized commitment")?;
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
            match self
                .state_store
                .as_mut()
                .ok_or("execution finalized-state store unavailable")?
                .commit_verified_snapshot(finalized, &handoff.state)
            {
                Ok(_) => {}
                Err(synergy_state::StateError::ResourcePressure { .. }) => {
                    self.pending_snapshot_restore = Some(handoff);
                    break;
                }
                Err(error) => return Err(format!("commit restored finalized snapshot: {error:?}")),
            }
            self.state = handoff.state;
            self.finalized_state = Arc::clone(&self.state);
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
            let Some(queued) = self.ingress.pending_finality()? else {
                break;
            };
            if queued.height <= self.finalized_height {
                self.ingress.take_finality()?;
                continue;
            }
            // Preserve the finality front while Sync is backpressured. Do not
            // commit state and then fail to publish its compact acknowledgement.
            if !self.ingress.finalized_execution_commit_has_capacity()? {
                break;
            }
            let next = self
                .finalized_height
                .checked_add(1)
                .ok_or("execution finality height overflow")?;
            let record = if queued.height == next {
                queued.clone()
            } else {
                // Catchup can retain a certified tip while the next execution
                // payload is still in flight. Do not repeatedly load its
                // historical three-QC proof until there is work to commit.
                if !self.candidates.contains_key(&next) {
                    break;
                }
                // Restart may publish the latest verified consensus tip while
                // execution still imports its earlier candidates. Historical
                // authority independently verifies the exact three-QC chain.
                #[cfg(test)]
                HISTORICAL_FINALITY_LOADS.with(|loads| loads.set(loads.get() + 1));
                let Some(record) = self.ingress.finalized_record(next)? else {
                    break;
                };
                record
            };
            let Some(candidate) = self.candidates.get(&record.height) else {
                // Valid future QCs may establish finality before this node has
                // imported the matching execution transition. Retain the exact
                // verified front; Sync must still fetch/re-execute every height
                // in order, and finality cannot skip or invent candidate state.
                break;
            };
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
            match state_store.commit_verified_world_transition(
                finalized,
                &self.finalized_state,
                &candidate.state,
            ) {
                Ok(_) => {}
                Err(synergy_state::StateError::ResourcePressure { .. }) => break,
                Err(error) => return Err(format!("commit PoSy-verified state: {error:?}")),
            }
            if self.processing.is_some()
                && self
                    .candidate_store
                    .pinned_descriptors()
                    .iter()
                    .any(|pin| pin.height == record.height)
            {
                state_store
                    .pin_processing_history(record.height)
                    .map_err(|error| format!("pin processing execution commitment: {error:?}"))?;
            }
            if let Some(retain_blocks) = self.retention_blocks {
                state_store
                    .prune_finalized_history(record.height, retain_blocks)
                    .map_err(|error| format!("prune finalized execution history: {error:?}"))?;
                self.candidate_store
                    .prune_finalized_history(record.height, retain_blocks)?;
            }
            self.finalized_state = Arc::clone(&candidate.state);
            self.finalized_height = record.height;
            if self.processing.is_some() {
                self.ingress.publish_processing_finalized_world(
                    record.height,
                    Arc::clone(&candidate.state),
                )?;
            }
            self.ingress.execution_committed(record.height)?;
            self.ingress.record_execution_observation(
                record.height,
                candidate.receipts.len(),
                true,
            )?;
            self.ingress
                .submit_finalized_execution_commit(FinalizedExecutionCommit {
                    epoch: self.authority.epoch.epoch,
                    finality: record.clone(),
                    application_state_root: candidate.state_root.clone(),
                })?;
            if record.height == queued.height {
                let consumed = self
                    .ingress
                    .take_finality()?
                    .ok_or("verified finality disappeared during execution commit")?;
                if consumed != record {
                    return Err("verified finality front changed during execution commit".into());
                }
            }
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
        #[cfg(any(test, feature = "qualification-timing"))]
        let mut operation_trace = super::owner_poll_diagnostic::PollTrace::new("execution");
        for _ in 0..MAX_BATCHES_PER_POLL {
            let Some(batch) = self.ingress.take_protected_batch()? else {
                break;
            };
            self.accept_batch(batch)?;
        }
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("batch-intake");
        self.serve_sync_requests()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("serve-sync-requests");
        self.apply_snapshot_restore_handoffs()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("snapshot-restore");
        self.accept_verified_sync_candidates()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("verified-sync-candidates");
        self.apply_finality()?;
        #[cfg(any(test, feature = "qualification-timing"))]
        operation_trace.completed("apply-finality");
        if self.processing.is_some() {
            self.poll_processing_execution()?;
            #[cfg(any(test, feature = "qualification-timing"))]
            operation_trace.completed("processing-execution");
            self.apply_finality()?;
            #[cfg(any(test, feature = "qualification-timing"))]
            operation_trace.completed("processing-finality");
            self.cleanup_processing_proofs()?;
            #[cfg(any(test, feature = "qualification-timing"))]
            operation_trace.completed("cleanup-proofs");
            return Ok(());
        }
        for _ in 0..MAX_BATCHES_PER_POLL {
            if !self.execute_next_ready()? {
                break;
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.started = false;
        if self.processing.take().is_some() {
            self.ingress.detach_processing_execution()?;
        }
        self.batches.clear();
        self.candidates.clear();
        self.outgoing_candidate = None;
        self.pending_snapshot_restore = None;
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

#[cfg(test)]
pub(super) fn wallet_naming_execution_fixture(
    authority: Arc<VerifiedAuthority>,
    transaction: &SignedTransaction,
    input: &[u8],
    state: &WorldState,
) -> Result<TransactionDispatch, String> {
    CanonicalNativeOperation {
        authority,
        verifier: PqvmVerifier::new(AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
            maximum_message_bytes: 64 * 1024,
            maximum_signature_bytes: 16 * 1024,
        })
        .unwrap(),
        chain_id: transaction.unsigned.network.chain_id,
    }
    .execute_native(
        "naming",
        "register_wallet",
        input,
        transaction,
        TransactionExecutionContext {
            network: &transaction.unsigned.network,
            block_height: 1,
            transaction_index: 0,
        },
        state,
    )
}

#[cfg(test)]
mod bootstrap_tests {
    use super::transactions_for_candidate;

    #[test]
    fn processing_material_cannot_activate_through_legacy_candidate_recovery() {
        use super::super::posy::qualification::Fleet;
        use super::*;
        use synergy_etdag::execution::{ProcessingProposalMaterial, ProcessingReadyView};
        let fleet = Fleet::new();
        let ingress = fleet.qualification_ingress();
        let root = EtdagDigest::from_domain_bytes("processing-gate-fixture", b"namespace");
        let material = ProcessingProposalMaterial {
            material_version: 1,
            profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
            height: 1,
            namespace_root: root.clone(),
            selection: ProcessingReadyView {
                namespace_root: root.clone(),
                items: vec![],
            }
            .select(30_000_000, 8 * 1024 * 1024)
            .unwrap(),
            transition_root: root,
            ordered_group: None,
        };
        let state =
            BudgetedWorld::try_clone_world(&WorldState::default(), ingress.world_budget()).unwrap();
        let mut candidate = ExecutionCandidate {
            resource_permit: None,
            height: 1,
            block_id: String::new(),
            parent_block_id: fleet.authority.anchor_parent.block_id().into(),
            protected_execution_root: hash_block_bytes(&material.commitment_bytes().unwrap()),
            protected_material: material.into(),
            state_root: synergy_state::state_root(state.as_ref()).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: Arc::new(state),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate.validate().unwrap(); // Structure/persistence is not authority.
        let error =
            verify_governed_candidate_material(&candidate, &fleet.authority, &ingress).unwrap_err();
        assert!(error.contains("explicit governed activation"));
        assert!(ingress.take_execution_candidate().unwrap().is_none());
    }

    #[test]
    fn approved_material_h1_through_h6_has_no_future_cutoff_cycle() {
        use super::super::posy::qualification::Fleet;
        use super::*;
        use aegis_pqvm::pqc::kem::mlkem::mlkem1024;
        use pqrust_traits::kem::PublicKey as _;
        use synergy_aegis::{AegisSigner, PqvmSigner};
        use synergy_etdag::{
            ordering::ProtectedCutMarker, persistence::ProtectedPipeline, EtdagGraph,
            IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey,
        };
        let mut fleet = Fleet::new();
        let records = (0..5)
            .map(|i| {
                let (public, _) = mlkem1024::keypair();
                IngressKemKeyRecord {
                    key_id: format!("ingress-{i}"),
                    validator_id: format!("qualification-{i}"),
                    public_key: IngressKemPublicKey {
                        algorithm: "ML-KEM-1024".into(),
                        public_key: public.as_bytes().to_vec(),
                    },
                    activation_height: 1,
                    retirement_height: None,
                }
            })
            .collect();
        let authority = fleet
            .authority
            .qualification_with_ingress(IngressKemKeyRegistry {
                context_root: EtdagDigest::from_domain_bytes("test-governed-registry", b"causal"),
                records,
            });
        let ingress = fleet.qualification_ingress();
        let members = (0..5)
            .map(|i| (format!("qualification-{i}"), (format!("key-{i}"), 1)))
            .collect::<synergy_etdag::ordering::CutoffMembers>();
        let mut pipelines = BTreeMap::<u64, ProtectedPipeline>::new();
        assert!(authority.protected_cutoff_boundary(None, 4).is_err());
        assert!(authority.protected_bootstrap_execution(3).is_err());
        for height in 1..=6 {
            let prepared = if height >= 3 {
                let (authorization, evidence) =
                    ingress.accepted_protected_parent(height).unwrap().unwrap();
                let pipeline = pipelines.get_mut(&height).unwrap();
                pipeline
                    .prepare_empty(authorization, evidence, &authority)
                    .unwrap();
                Some(pipeline.prepared().unwrap().clone())
            } else {
                None
            };
            let state = synergy_state::WorldState::default();
            let outcome = BlockExecutionOutcome {
                block_height: height,
                state_root: synergy_state::state_root(&state).unwrap(),
                state,
                receipts: Vec::new(),
                total_gas_used: 0,
                total_fees_nwei: 0,
            };
            // Production assembly can proceed before VC(H) exists; it names a
            // boundary and requires only the previously certified next batch.
            assert!(ingress
                .protected_cutoff_authority(height + 2)
                .unwrap()
                .is_none());
            let material = assemble_protected_material(
                &authority,
                &ingress,
                height,
                prepared.as_ref(),
                &outcome,
                &[],
            )
            .unwrap()
            .unwrap();
            if height == 1 {
                let mut replay = ExecutionCandidate {
                    resource_permit: None,
                    height,
                    block_id: String::new(),
                    parent_block_id: authority.anchor_parent.block_id().into(),
                    protected_execution_root: hash_block_bytes(
                        &material.commitment_bytes().unwrap(),
                    ),
                    protected_material: material.clone().into(),
                    state_root: outcome.state_root.clone(),
                    transactions: Vec::new(),
                    receipts: Vec::new(),
                    state: Arc::new(
                        BudgetedWorld::try_clone_world(&outcome.state, ingress.world_budget())
                            .unwrap(),
                    ),
                };
                replay.block_id = replay.commitment_id().unwrap();
                let committed = synergy_state::FinalizedState {
                    finalized_height: height,
                    finalized_block_id: replay.block_id.clone(),
                    state_root: replay.state_root.clone(),
                };
                // A delayed already committed Sync response is idempotent,
                // while a different durable block/root or forged payload fails.
                verify_committed_sync_replay(&replay, &committed).unwrap();
                let mut wrong_root = committed.clone();
                wrong_root.state_root = "0".repeat(64);
                assert!(verify_committed_sync_replay(&replay, &wrong_root).is_err());
                let mut wrong_block = committed.clone();
                wrong_block.finalized_block_id = "0".repeat(64);
                assert!(verify_committed_sync_replay(&replay, &wrong_block).is_err());
                let mut wrong_height = committed.clone();
                wrong_height.finalized_height += 1;
                assert!(verify_committed_sync_replay(&replay, &wrong_height).is_err());
                replay.state_root = "0".repeat(64);
                assert!(verify_committed_sync_replay(&replay, &committed).is_err());
            }
            let target = height + 2;
            let source = if target <= 5 {
                None
            } else {
                Some(ingress.finalized_record(target - 5).unwrap().unwrap())
            };
            assert_eq!(
                material.cutoff_boundary_root,
                authority
                    .protected_cutoff_boundary(source.as_ref(), height)
                    .unwrap()
            );
            if height > 1 {
                assert_ne!(
                    material.cutoff_boundary_root,
                    authority.protected_cutoff_boundary(None, 1).unwrap()
                );
            }
            if let Some(prepared) = &prepared {
                // Share proof variants must not alter the execution subject.
                // Authentication/recovery verification remains a separate gate.
                let mut proof_variant = prepared.clone();
                proof_variant.reveal_transcript_root = EtdagDigest::from_domain_bytes(
                    "qualified-valid-share-proof-variant",
                    b"different-subset",
                );
                let same = assemble_protected_material(
                    &authority,
                    &ingress,
                    height,
                    Some(&proof_variant),
                    &outcome,
                    &[],
                )
                .unwrap()
                .unwrap();
                assert_eq!(same, material);
                let mut wrong_parent = prepared.clone();
                wrong_parent.reveal_authorization.finality_reference =
                    EtdagDigest::from_domain_bytes("wrong-parent-reveal-reference", b"tampered");
                assert!(synergy_etdag::reveal::VerifiedRevealAuthorization::verify(
                    wrong_parent.reveal_authorization.clone(),
                    &wrong_parent.parent_evidence,
                    &authority
                )
                .is_err());
            }
            ingress.submit_protected_material(material.clone()).unwrap();
            let certificate = fleet.validate_protected_parent(&material);
            assert_eq!(
                certificate.candidate.protected_execution_root,
                hash_block_bytes(&material.commitment_bytes().unwrap())
            );
            // VC(H), not the descriptor, now creates close authority for H+2.
            let cutoff = ingress.protected_cutoff_authority(target).unwrap().unwrap();
            let mut next_outcome = outcome.clone();
            next_outcome.block_height = height + 1;
            assert!(
                assemble_protected_material(
                    &authority,
                    &ingress,
                    height + 1,
                    None,
                    &next_outcome,
                    &[]
                )
                .unwrap()
                .is_none(),
                "a VC boundary alone must not fabricate the next cut"
            );
            let source = if target <= 5 {
                None
            } else {
                Some(ingress.finalized_record(target - 5).unwrap().unwrap())
            };
            let (context, root) = authority.protected_target(source.as_ref(), target).unwrap();
            let mut pipeline = ProtectedPipeline::open(
                fleet.root.join(format!("causal-target-{target}")),
                context.clone(),
                authority.protected_parameters().unwrap(),
                cutoff.clone(),
                "qualification-0".into(),
                &members,
                &authority,
            )
            .unwrap();
            let markers = (0..4)
                .map(|i| {
                    let key = KeyId::new(format!("key-{i}")).unwrap();
                    let signer = PqvmSigner::from_secret_key_bytes(
                        AegisPolicy {
                            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                            maximum_message_bytes: 1024 * 1024,
                            maximum_signature_bytes: 16 * 1024,
                        },
                        key.clone(),
                        fleet.secrets[i].clone(),
                    )
                    .unwrap();
                    let mut marker = ProtectedCutMarker {
                        marker_version: 1,
                        context_root: root.clone(),
                        target_height: target,
                        cutoff_context_root: cutoff.clone(),
                        frontier: Vec::new(),
                        validator_id: format!("qualification-{i}"),
                        key_id: key.as_str().into(),
                        signature: Vec::new(),
                    };
                    marker.signature = signer
                        .sign(
                            &key,
                            &SigningContext {
                                domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                                chain_id: 1266,
                                epoch: Some(1),
                                height: None,
                            },
                            &marker.signing_bytes().unwrap(),
                        )
                        .unwrap()
                        .bytes;
                    marker
                })
                .collect::<Vec<_>>();
            let graph = EtdagGraph::new(root, target).unwrap();
            pipeline
                .accept_cut(&markers, &graph, &BTreeMap::new(), &members, &authority)
                .unwrap();
            ingress
                .submit_protected_commitments(target, pipeline.batch().unwrap().clone(), cutoff)
                .unwrap();
            pipelines.insert(target, pipeline);
        }
        assert!(ingress.latest_finality().unwrap().unwrap().height >= 4);
    }

    #[test]
    fn only_h1_h2_can_execute_without_protected_material() {
        assert!(transactions_for_candidate(0, None).is_err());
        for height in [1, 2] {
            assert!(transactions_for_candidate(height, None)
                .unwrap()
                .unwrap()
                .is_empty());
        }
        for height in [3, 4, 5, 6, 100, u64::MAX] {
            assert!(transactions_for_candidate(height, None).unwrap().is_none());
        }
    }
}
