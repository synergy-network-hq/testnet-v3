use crate::gas::GasSchedule;
use crate::sts::{CredentialRecord, CredentialStatus, StsState};
use crate::synergy_types::{Hash, Transaction, TxId};
use crate::synq_admission::{
    decode_synq_admission_carrier, SynQAdmissionEnvelope, SynQAdmissionKind,
    SynQVerificationSummary,
};
use aivm_core::execution::{
    AivmSecurityPolicyRef, ContractArtifact, ContractFormat, ExecutionContext, ExecutionRequest,
    ExecutionStatus, StsHostContext, StsHostCredential, StsHostFungibleToken, StsHostNft,
};
use aivm_core::state::ContractState;
use aivm_core::stateful_synq::SynQNativeTransfer;
use aivm_core::synq_runtime::{
    call_synq_contract, deploy_synq_contract, synq_execution_request, SynQRuntimeOperation,
    SynQRuntimeReceipt,
};
use pqsynq::{
    ContractCallEnvelope, ContractDeployEnvelope, DomainTag, SignaturePurpose, SynQAddress,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SYNQ_CONTRACT_ADDRESS_DERIVATION_DOMAIN: &str = "SYNERGY_SYNQ_CONTRACT_ADDRESS_V1";
pub const SYNERGY_CUSTOM_CONTRACT_ADDRESS_PREFIX: &str = "sync";
const SYNQ_CONTRACT_ADDRESS_VERSION: u8 = 1;
const SYNQ_CONTRACT_ADDRESS_CLASS: u16 = 0xC001;
const SYNQ_ADDRESS_LEN: usize = 41;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SynQArtifactKey {
    pub bytecode_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub abi_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQContractArtifact {
    pub bytecode: Vec<u8>,
    pub abi_json: String,
    pub manifest_json: String,
    #[serde(default)]
    pub metadata_json: Option<String>,
}

impl SynQContractArtifact {
    pub fn new(bytecode: Vec<u8>, abi_json: String, manifest_json: String) -> Self {
        Self {
            bytecode,
            abi_json,
            manifest_json,
            metadata_json: None,
        }
    }

    pub fn with_metadata_json(mut self, metadata_json: Option<String>) -> Self {
        self.metadata_json = metadata_json;
        self
    }

    pub fn key(&self) -> SynQArtifactKey {
        SynQArtifactKey {
            bytecode_hash: sha256_array(&self.bytecode),
            manifest_hash: sha256_array(self.manifest_json.as_bytes()),
            abi_hash: sha256_array(self.abi_json.as_bytes()),
        }
    }

    pub fn to_aivm_artifact(&self) -> ContractArtifact {
        ContractArtifact {
            format: ContractFormat::SynqBytecodeV1,
            bytes: self.bytecode.clone(),
            abi_json: Some(self.abi_json.clone()),
            manifest_json: Some(self.manifest_json.clone()),
            metadata_json: self.metadata_json.clone(),
            compiler_version: None,
            source_hash: None,
        }
    }

    fn manifest_contract_name(&self) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(&self.manifest_json)
            .ok()
            .and_then(|manifest| {
                manifest
                    .get("contract_name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQExecutionContext {
    pub runtime_block_height: u64,
    #[serde(default)]
    pub runtime_block_timestamp_unix: u64,
    #[serde(default)]
    pub sts_host: Option<StsHostContext>,
    /// The protocol-authoritative fee market applicable to the block being
    /// built/executed, if the fee market is active at this height. `None`
    /// means either the fee market has not activated yet (legacy blocks)
    /// or this execution context is being used for a purpose that
    /// intentionally has no live pricing (e.g. isolated unit tests). When
    /// `None`, transaction charging falls back byte-for-byte to the
    /// pre-fee-market behavior (sender-declared `max_fee_nwei` charged in
    /// full) so existing behavior and tests are unaffected.
    #[serde(default)]
    pub applied_fee_market: Option<crate::gas::fee_market::AppliedFeeMarket>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQDeploymentRecord {
    pub contract_address: String,
    pub deployer: String,
    pub artifact_key: SynQArtifactKey,
    pub deploy_tx_id: TxId,
    pub deploy_receipt_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAivmReceiptSummary {
    pub operation: String,
    pub contract_address: String,
    pub status: String,
    pub gas_used: u64,
    pub pqc_gas_used: u64,
    pub return_data_hex: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub receipt_hash: String,
    pub logs: Vec<String>,
    #[serde(default)]
    pub native_transfers: Vec<SynQNativeTransfer>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

pub fn register_synq_artifact(
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    artifact: SynQContractArtifact,
) -> Result<SynQArtifactKey, String> {
    let key = artifact.key();
    validate_artifact_hashes(&artifact, &key)?;
    artifacts.insert(key.clone(), artifact);
    Ok(key)
}

pub fn execute_synq_transaction(
    tx_id: &TxId,
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    aivm_state: &mut ContractState,
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &mut BTreeMap<String, SynQDeploymentRecord>,
) -> Result<Option<SynQAivmReceiptSummary>, String> {
    execute_synq_transaction_at(
        tx_id,
        tx,
        verification,
        aivm_state,
        artifacts,
        deployments,
        SynQExecutionContext::default(),
    )
}

pub fn sts_host_context_from_sts_state(
    sts_state: &StsState,
    runtime_timestamp_unix: u64,
) -> StsHostContext {
    let mut host = StsHostContext::default();

    for (token_id, token) in &sts_state.token_registry {
        host.object_classes
            .insert(token_id.clone(), token.class.discriminant());
        host.fungible_tokens.insert(
            token_id.clone(),
            StsHostFungibleToken {
                class: token.class.discriminant(),
                total_supply: token.total_supply,
            },
        );
    }
    for balance in sts_state.fungible_balances.values() {
        host.fungible_balances.insert(
            StsHostContext::fungible_balance_key(&balance.token_id, &balance.owner),
            balance.balance,
        );
    }
    for (collection_id, collection) in &sts_state.nft_collections {
        host.object_classes
            .insert(collection_id.clone(), collection.class.discriminant());
    }
    for (nft_id, nft) in &sts_state.nft_instances {
        host.object_classes
            .insert(nft_id.clone(), nft.class.discriminant());
        host.nfts.insert(
            nft_id.clone(),
            StsHostNft {
                class: nft.class.discriminant(),
                owner: nft.owner.clone(),
                burned: nft.burned,
                revoked: nft.revoked,
            },
        );
    }
    for collection_id in sts_state.multi_asset_collections.keys() {
        host.object_classes.insert(
            collection_id.clone(),
            crate::sts::TokenClass::MAMultiAsset.discriminant(),
        );
    }
    for balance in sts_state.multi_asset_balances.values() {
        host.multi_asset_balances.insert(
            StsHostContext::multi_asset_balance_key(
                &balance.collection_id,
                balance.item_id,
                &balance.owner,
            ),
            balance.amount,
        );
    }
    for (credential_id, credential) in &sts_state.credential_records {
        host.object_classes.insert(
            credential_id.clone(),
            crate::sts::TokenClass::IDCredential.discriminant(),
        );
        let status = effective_credential_status(credential, runtime_timestamp_unix);
        host.credentials.insert(
            credential_id.clone(),
            StsHostCredential {
                status: status as u8,
                issuer: credential.issuer.clone(),
                subject: credential.subject.clone(),
                subject_commitment: credential.subject_commitment.clone(),
                schema_id: credential.schema_id.clone(),
                expires_at: credential.expires_at,
            },
        );
        if let Some(subject) = credential.subject.as_deref() {
            host.credential_lookup.insert(
                StsHostContext::credential_lookup_key(
                    subject,
                    &credential.schema_id,
                    &credential.issuer,
                ),
                credential_id.clone(),
            );
        }
        host.credential_lookup.insert(
            StsHostContext::credential_lookup_key(
                &credential.subject_commitment,
                &credential.schema_id,
                &credential.issuer,
            ),
            credential_id.clone(),
        );
    }

    host
}

fn effective_credential_status(
    credential: &CredentialRecord,
    runtime_timestamp_unix: u64,
) -> CredentialStatus {
    if credential.status == CredentialStatus::Active {
        if let Some(expires_at) = credential.expires_at {
            if runtime_timestamp_unix > 0 && expires_at <= runtime_timestamp_unix {
                return CredentialStatus::Expired;
            }
        }
    }
    credential.status
}

pub fn execute_synq_transaction_at(
    tx_id: &TxId,
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    aivm_state: &mut ContractState,
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &mut BTreeMap<String, SynQDeploymentRecord>,
    execution_context: SynQExecutionContext,
) -> Result<Option<SynQAivmReceiptSummary>, String> {
    let Some(envelope) = decode_synq_admission_carrier(&tx.payload)
        .map_err(|error| format!("SynQ carrier decode failed [{}]: {error}", error.code()))?
    else {
        return Ok(None);
    };

    match envelope.kind {
        SynQAdmissionKind::Deploy => execute_deploy(
            tx_id,
            tx,
            verification,
            &envelope,
            aivm_state,
            artifacts,
            deployments,
            execution_context,
        )
        .map(Some),
        SynQAdmissionKind::Call => execute_call(
            tx,
            verification,
            &envelope,
            aivm_state,
            artifacts,
            deployments,
            execution_context,
        )
        .map(Some),
    }
}

/// Execute a verified public `view` method against an immutable snapshot of
/// finalized SynQ state.  JSON-RPC reads must never create an admission
/// artifact, mutate consensus state, or make a private method reachable.
///
/// This is intentionally separate from `execute_synq_transaction_at`: writes
/// still require a chain-admitted, PQ-signed transaction and can only mutate
/// state through finalized block execution.
pub fn execute_synq_static_call(
    contract_address: &str,
    caller: &str,
    calldata: &[u8],
    aivm_state: &ContractState,
    artifacts: &BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &BTreeMap<String, SynQDeploymentRecord>,
    execution_context: SynQExecutionContext,
) -> Result<SynQAivmReceiptSummary, String> {
    if calldata.len() < 4 {
        return Err("SynQ static call requires a four-byte ABI selector".to_string());
    }
    let deployment = deployments.get(contract_address).ok_or_else(|| {
        "SynQ static call target is not deployed in finalized execution state".to_string()
    })?;
    let artifact = artifacts.get(&deployment.artifact_key).ok_or_else(|| {
        "SynQ static call target artifact is missing from finalized execution state".to_string()
    })?;
    let abi: serde_json::Value = serde_json::from_str(&artifact.abi_json)
        .map_err(|error| format!("parse verified SynQ ABI for static call: {error}"))?;
    let selector = format!("0x{}", hex::encode(&calldata[..4]));
    let method = abi
        .get("methods")
        .and_then(serde_json::Value::as_array)
        .and_then(|methods| {
            methods.iter().find(|method| {
                method.get("selector").and_then(serde_json::Value::as_str)
                    == Some(selector.as_str())
            })
        })
        .ok_or_else(|| {
            format!("SynQ static call selector {selector} is not in the verified ABI")
        })?;
    if method.get("visibility").and_then(serde_json::Value::as_str) != Some("public") {
        return Err("SynQ static calls may invoke only public ABI methods".to_string());
    }
    if method.get("mutability").and_then(serde_json::Value::as_str) != Some("view") {
        return Err("SynQ static calls may invoke only view ABI methods".to_string());
    }

    let mut context = ExecutionContext::testnet_1266_for_contract(contract_address, 1_000_000);
    context.runtime_block_height = execution_context.runtime_block_height;
    context.block_height = execution_context.runtime_block_height;
    context.block_timestamp_unix = execution_context.runtime_block_timestamp_unix;
    context.caller = caller.as_bytes().to_vec();
    context.contract_address = contract_address.as_bytes().to_vec();
    context.tx_hash = Hash::from_domain_bytes(
        "SYNERGY_SYNQ_STATIC_CALL_V1",
        &[contract_address.as_bytes(), caller.as_bytes(), calldata].concat(),
    )
    .0;
    context.sts_host = execution_context.sts_host;
    context.resolved_synq_contracts = resolved_synq_contracts(artifacts, deployments);

    let request = synq_execution_request(
        contract_address.to_string(),
        artifact.to_aivm_artifact(),
        context,
        calldata.to_vec(),
    );
    let mut snapshot = aivm_state.clone();
    let receipt = call_synq_contract(&request, &mut snapshot);
    if receipt.status == ExecutionStatus::Succeeded
        && snapshot.state_root() != aivm_state.state_root()
    {
        return Err(
            "SynQ view call attempted to mutate state; static execution rejected it".to_string(),
        );
    }
    Ok(summary_from_aivm_receipt(contract_address, &receipt))
}

fn execute_deploy(
    tx_id: &TxId,
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    envelope: &SynQAdmissionEnvelope,
    aivm_state: &mut ContractState,
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &mut BTreeMap<String, SynQDeploymentRecord>,
    execution_context: SynQExecutionContext,
) -> Result<SynQAivmReceiptSummary, String> {
    let deploy = deploy_envelope_from_carrier(envelope)?;
    let contract_address = derive_synergy_contract_address_from_deploy_with_identity_address(
        &deploy,
        &verification.signer,
    )?;
    let artifact = match artifact_from_envelope(envelope) {
        Ok(artifact) => artifact,
        Err(message) => {
            return Ok(pre_aivm_failed_summary(
                SynQRuntimeOperation::Deploy,
                &contract_address,
                "SYNQ-AIVM-ARTIFACT",
                &message,
                aivm_state,
            ));
        }
    };
    let artifact_key = artifact.key();
    if let Err(message) = validate_artifact_hashes(&artifact, &artifact_key) {
        return Ok(pre_aivm_failed_summary(
            SynQRuntimeOperation::Deploy,
            &contract_address,
            "SYNQ-AIVM-ARTIFACT",
            &message,
            aivm_state,
        ));
    }

    let request = synq_execution_request(
        contract_address.clone(),
        artifact.to_aivm_artifact(),
        aivm_context(
            tx,
            verification,
            &contract_address,
            execution_context,
            resolved_synq_contracts(artifacts, deployments),
        )?,
        envelope.constructor_args.clone().unwrap_or_default(),
    );
    let receipt = deploy_synq_contract(&request, aivm_state);
    let summary = summary_from_aivm_receipt(&contract_address, &receipt);
    if receipt.status == ExecutionStatus::Succeeded {
        artifacts.insert(artifact_key.clone(), artifact);
        deployments.insert(
            contract_address.clone(),
            SynQDeploymentRecord {
                contract_address,
                deployer: verification.signer.clone(),
                artifact_key,
                deploy_tx_id: tx_id.clone(),
                deploy_receipt_hash: summary.receipt_hash.clone(),
            },
        );
    }
    Ok(summary)
}

pub fn derive_synq_contract_address_from_deploy(
    deploy: &ContractDeployEnvelope,
) -> Result<SynQAddress, String> {
    Err(format!(
        "SynQ contract address derivation for key {} requires a verified FN-DSA-rooted identity address",
        hex::encode(Sha256::digest(&deploy.public_key.bytes))
    ))
}

pub fn derive_synq_contract_address_from_deploy_with_identity_address(
    deploy: &ContractDeployEnvelope,
    identity_address: &str,
) -> Result<SynQAddress, String> {
    if deploy.signing_payload.domain_tag != DomainTag::SynqContractDeployV1
        || deploy.signing_payload.signature_purpose != SignaturePurpose::ContractDeploy
    {
        return Err(
            "SynQ contract address derivation requires a deploy signing payload".to_string(),
        );
    }
    let network_id = deploy
        .signing_payload
        .network_id
        .numeric_id()
        .map_err(|error| format!("SynQ contract address network derivation failed: {error}"))?;
    let chain_id = deploy.signing_payload.chain_id.0;
    if chain_id > u16::MAX as u64 {
        return Err(format!(
            "SynQ contract address derivation requires u16 chain id, found {chain_id}"
        ));
    }

    let mut material = Vec::new();
    push_u64(&mut material, chain_id);
    push_string(&mut material, deploy.signing_payload.network_id.as_str());
    push_u16(&mut material, deploy.signing_payload.protocol_version);
    push_u16(&mut material, deploy.signing_payload.algorithm_id.code());
    push_u64(&mut material, deploy.signing_payload.nonce);
    let decoded_identity = crate::address::decode_address(identity_address)?;
    if decoded_identity.classification
        != crate::snts_registry::IdentifierClass::KeyControlledAddress
    {
        return Err("SynQ deployer identity address must be key-controlled".to_string());
    }
    push_string(&mut material, identity_address);
    push_bytes(&mut material, &deploy.signing_payload.payload_hash);
    push_bytes(&mut material, &deploy.bytecode_hash);
    push_bytes(&mut material, &deploy.manifest_hash);
    push_bytes(&mut material, &deploy.abi_hash);
    push_bytes(&mut material, &deploy.constructor_args_hash);

    let digest = Hash::from_domain_bytes(SYNQ_CONTRACT_ADDRESS_DERIVATION_DOMAIN, &material);
    let mut bytes = [0_u8; SYNQ_ADDRESS_LEN];
    bytes[0] = SYNQ_CONTRACT_ADDRESS_VERSION;
    bytes[1..3].copy_from_slice(&network_id.to_be_bytes());
    bytes[3..5].copy_from_slice(&SYNQ_CONTRACT_ADDRESS_CLASS.to_be_bytes());
    bytes[5..37].copy_from_slice(&digest.0);
    let checksum = Sha256::digest(&bytes[..37]);
    bytes[37..41].copy_from_slice(&checksum[..4]);

    Ok(SynQAddress::from_bytes(bytes))
}

pub fn derive_synergy_contract_address_from_deploy(
    deploy: &ContractDeployEnvelope,
) -> Result<String, String> {
    let synq_address = derive_synq_contract_address_from_deploy(deploy)?;
    synergy_contract_address_from_pqsynq_address(&synq_address)
}

pub fn derive_synergy_contract_address_from_deploy_with_identity_address(
    deploy: &ContractDeployEnvelope,
    identity_address: &str,
) -> Result<String, String> {
    let synq_address =
        derive_synq_contract_address_from_deploy_with_identity_address(deploy, identity_address)?;
    synergy_contract_address_from_pqsynq_address(&synq_address)
}

pub fn synergy_contract_address_from_pqsynq_address(
    address: &SynQAddress,
) -> Result<String, String> {
    crate::address::generate_generic_address(
        SYNERGY_CUSTOM_CONTRACT_ADDRESS_PREFIX,
        &hex::encode(address.as_bytes()),
    )
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn execute_call(
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    envelope: &SynQAdmissionEnvelope,
    aivm_state: &mut ContractState,
    artifacts: &BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &BTreeMap<String, SynQDeploymentRecord>,
    execution_context: SynQExecutionContext,
) -> Result<SynQAivmReceiptSummary, String> {
    let call: ContractCallEnvelope = serde_json::from_slice(&envelope.encoded_pqsynq_envelope)
        .map_err(|error| format!("SynQ call envelope decode failed after admission: {error}"))?;
    let contract_address = synergy_contract_address_from_pqsynq_address(&call.contract_address)?;
    let Some(deployment) = deployments.get(&contract_address) else {
        return Ok(pre_aivm_failed_summary(
            SynQRuntimeOperation::Call,
            &contract_address,
            "SYNQ-AIVM-STATE",
            "SynQ call precondition failed: contract has not been deployed in execution state",
            aivm_state,
        ));
    };
    let Some(artifact) = artifacts.get(&deployment.artifact_key) else {
        return Ok(pre_aivm_failed_summary(
            SynQRuntimeOperation::Call,
            &contract_address,
            "SYNQ-AIVM-ARTIFACT",
            "SynQ call precondition failed: deployed contract artifact is missing from execution state",
            aivm_state,
        ));
    };

    let mut calldata = call.method_selector.to_vec();
    if let Some(encoded_args) = envelope.encoded_args.as_deref() {
        calldata.extend_from_slice(encoded_args);
    }

    let request = synq_execution_request(
        contract_address.clone(),
        artifact.to_aivm_artifact(),
        aivm_context(
            tx,
            verification,
            &contract_address,
            execution_context,
            resolved_synq_contracts(artifacts, deployments),
        )?,
        calldata,
    );
    let receipt = call_synq_contract(&request, aivm_state);
    Ok(summary_from_aivm_receipt(&contract_address, &receipt))
}

fn artifact_from_envelope(
    envelope: &SynQAdmissionEnvelope,
) -> Result<SynQContractArtifact, String> {
    let bytecode = envelope
        .bytecode
        .clone()
        .ok_or_else(|| "SynQ deploy carrier is missing bytecode bytes".to_string())?;
    let abi_json = envelope
        .abi_json
        .clone()
        .ok_or_else(|| "SynQ deploy carrier is missing ABI JSON".to_string())?;
    let manifest_json = envelope
        .manifest_json
        .clone()
        .ok_or_else(|| "SynQ deploy carrier is missing manifest JSON".to_string())?;
    let artifact = SynQContractArtifact::new(bytecode, abi_json, manifest_json)
        .with_metadata_json(envelope.sts9_verification_json.clone());
    let actual = artifact.key();
    if envelope.bytecode_hash != Some(actual.bytecode_hash)
        || envelope.manifest_hash != Some(actual.manifest_hash)
        || envelope.abi_hash != Some(actual.abi_hash)
    {
        return Err(
            "SynQ deploy artifact bytes do not match admitted bytecode/manifest/ABI hashes"
                .to_string(),
        );
    }
    Ok(artifact)
}

fn validate_artifact_hashes(
    artifact: &SynQContractArtifact,
    key: &SynQArtifactKey,
) -> Result<(), String> {
    let contract_id = artifact
        .manifest_contract_name()
        .unwrap_or_else(|| "Counter".to_string());
    let request = ExecutionRequest {
        contract_id: contract_id.clone(),
        artifact: artifact.to_aivm_artifact(),
        calldata: Vec::new(),
        context: ExecutionContext::testnet_1266_for_contract(&contract_id, 150_000),
    };
    aivm_core::execution::validate_synq_artifact(&request)
        .map_err(|error| format!("AIVM artifact validation failed: {error}"))?;
    if artifact.key() != *key {
        return Err("SynQ artifact key does not match artifact bytes".to_string());
    }
    Ok(())
}

fn aivm_context(
    tx: &Transaction,
    _verification: &SynQVerificationSummary,
    contract_address: &str,
    execution_context: SynQExecutionContext,
    resolved_synq_contracts: BTreeMap<String, ContractArtifact>,
) -> Result<ExecutionContext, String> {
    Ok(ExecutionContext {
        admission_pq_gas_used: GasSchedule::default().pqc_signature_verify_gas,
        runtime_block_height: execution_context.runtime_block_height,
        chain_id: tx.chain_id.0,
        network_id: tx.network_id.0.clone(),
        block_height: execution_context.runtime_block_height,
        block_timestamp_unix: execution_context.runtime_block_timestamp_unix,
        tx_hash: tx.canonical_tx_bytes_hash()?.0,
        caller: tx.sender_uma_or_account.as_bytes().to_vec(),
        contract_address: contract_address.as_bytes().to_vec(),
        call_value: tx.amount_nwei,
        gas_limit: tx.gas_limit,
        pq_gas_limit: 300_000,
        security_policy: AivmSecurityPolicyRef {
            policy_id: "synq-testnet-1266-v1".to_string(),
            required_signature_policy: aivm_core::execution::SYNQ_ACCOUNT_DOMAIN_SIGNATURE_POLICY
                .to_string(),
        },
        sts_host: execution_context.sts_host.clone(),
        resolved_synq_contracts,
    })
}

fn resolved_synq_contracts(
    artifacts: &BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &BTreeMap<String, SynQDeploymentRecord>,
) -> BTreeMap<String, ContractArtifact> {
    deployments
        .iter()
        .filter_map(|(address, deployment)| {
            artifacts
                .get(&deployment.artifact_key)
                .map(|artifact| (address.clone(), artifact.to_aivm_artifact()))
        })
        .collect()
}

fn summary_from_aivm_receipt(
    contract_address: &str,
    receipt: &SynQRuntimeReceipt,
) -> SynQAivmReceiptSummary {
    SynQAivmReceiptSummary {
        operation: operation_name(receipt.operation).to_string(),
        contract_address: contract_address.to_string(),
        status: execution_status_name(&receipt.status).to_string(),
        gas_used: receipt.gas_used,
        pqc_gas_used: receipt.pqc_gas_used,
        return_data_hex: hex::encode(&receipt.return_data),
        pre_state_root: hex::encode(receipt.pre_state_root),
        post_state_root: hex::encode(receipt.post_state_root),
        receipt_hash: hex::encode(receipt.canonical_hash()),
        logs: receipt.logs.clone(),
        native_transfers: receipt.native_transfers.clone(),
        error_code: receipt.error_code.map(|code| format!("{code:?}")),
        error_message: receipt.error.clone(),
    }
}

fn pre_aivm_failed_summary(
    operation: SynQRuntimeOperation,
    contract_address: &str,
    code: &str,
    message: &str,
    state: &ContractState,
) -> SynQAivmReceiptSummary {
    let state_root = hex::encode(state.state_root());
    let mut summary = SynQAivmReceiptSummary {
        operation: operation_name(operation).to_string(),
        contract_address: contract_address.to_string(),
        status: "failed".to_string(),
        gas_used: 0,
        pqc_gas_used: GasSchedule::default().pqc_signature_verify_gas,
        return_data_hex: String::new(),
        pre_state_root: state_root.clone(),
        post_state_root: state_root,
        receipt_hash: String::new(),
        logs: Vec::new(),
        native_transfers: Vec::new(),
        error_code: Some(code.to_string()),
        error_message: Some(message.to_string()),
    };
    summary.receipt_hash = Hash::from_domain_bytes(
        "SYNERGY_SYNQ_AIVM_PRE_EXECUTION_RECEIPT_V1",
        &serde_json::to_vec(&summary).unwrap_or_default(),
    )
    .to_hex();
    summary
}

fn operation_name(operation: SynQRuntimeOperation) -> &'static str {
    match operation {
        SynQRuntimeOperation::Deploy => "deploy",
        SynQRuntimeOperation::Call => "call",
    }
}

fn execution_status_name(status: &ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Succeeded => "succeeded",
        ExecutionStatus::Reverted => "reverted",
        ExecutionStatus::Failed => "failed",
    }
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn deploy_envelope_from_carrier(
    envelope: &SynQAdmissionEnvelope,
) -> Result<ContractDeployEnvelope, String> {
    serde_json::from_slice(&envelope.encoded_pqsynq_envelope)
        .map_err(|error| format!("SynQ deploy envelope decode failed after admission: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sts::{CreateFungibleParams, FungibleControlFlags, FungiblePolicy, TokenClass};

    #[test]
    fn sts_host_context_exports_native_fungible_balances() {
        let creator = "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war";
        let mut state = StsState::new();
        let token_id = state
            .create_fungible(CreateFungibleParams {
                class: TokenClass::B1BasicFungible,
                creator: creator.to_string(),
                creator_nonce: 7,
                name: "Host Token".to_string(),
                symbol: "HOST".to_string(),
                decimals: 9,
                initial_supply: 42_000,
                max_supply: Some(42_000),
                mint_authority: None,
                metadata_authority: None,
                metadata_uri: None,
                metadata_hash: None,
                metadata_mutable: false,
                image_uri: None,
                image_hash: None,
                flags: FungibleControlFlags::default(),
                policies: Vec::<FungiblePolicy>::new(),
                created_at: 1_783_200_000,
            })
            .expect("create native STS token");

        let host = sts_host_context_from_sts_state(&state, 1_783_200_000);
        assert_eq!(
            host.object_classes.get(&token_id),
            Some(&(TokenClass::B1BasicFungible.discriminant()))
        );
        assert_eq!(
            host.fungible_tokens
                .get(&token_id)
                .map(|token| token.total_supply),
            Some(42_000)
        );
        assert_eq!(
            host.fungible_balances
                .get(&StsHostContext::fungible_balance_key(&token_id, creator))
                .copied(),
            Some(42_000)
        );
    }
}
