use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AivmError, AivmErrorCode};
use crate::execution::{
    execute_contract, push_receipt_context, validate_synq_artifact, ContractArtifact,
    ExecutionContext, ExecutionReceipt, ExecutionReceiptContext, ExecutionRequest, ExecutionStatus,
    StsHostContext, SynQManifestArtifact,
};
use crate::metering::AivmGasMeter;
use crate::state::{ContractState, CounterStateMachine, StateKey, StateOverlay};
use crate::stateful_synq::{
    call_stateful_synq, deploy_stateful_synq, StatefulSynQFailure, SynQNativeTransfer,
};

pub const COUNTER_INCREMENT_SELECTOR: [u8; 4] = [0x58, 0x42, 0xf1, 0xbe];
pub const COUNTER_GET_SELECTOR: [u8; 4] = [0x75, 0xb7, 0x04, 0x57];
pub const STS9_TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0xe3, 0xd6, 0x1a, 0x97];
pub const STS9_BALANCE_OF_SELECTOR: [u8; 4] = [0xc0, 0xbb, 0x20, 0xc3];
pub const STS9_TRANSFER_SELECTOR: [u8; 4] = [0x63, 0x25, 0x2e, 0x1a];
pub const STS_BALANCE_SELECTOR: [u8; 4] = [0xac, 0x11, 0xea, 0x15];
pub const STS_TOKEN_EXISTS_SELECTOR: [u8; 4] = [0x81, 0xa1, 0xd6, 0x95];
pub const STS_TOKEN_CLASS_SELECTOR: [u8; 4] = [0x9e, 0xc0, 0xa8, 0x93];
pub const STS_TOTAL_SUPPLY_SELECTOR: [u8; 4] = [0x58, 0xf2, 0x77, 0xb9];
pub const STS_OWNER_OF_SELECTOR: [u8; 4] = [0xcb, 0xc6, 0xfd, 0x12];
pub const STS_NFT_EXISTS_SELECTOR: [u8; 4] = [0x25, 0x79, 0x95, 0xde];
pub const STS_MULTI_ASSET_BALANCE_SELECTOR: [u8; 4] = [0xa6, 0x4d, 0x45, 0xe6];
pub const STS_CREDENTIAL_STATUS_SELECTOR: [u8; 4] = [0x96, 0x4b, 0x2c, 0x9e];
pub const STS_VERIFY_CREDENTIAL_SELECTOR: [u8; 4] = [0x46, 0xf0, 0xcc, 0xc1];
pub const STS_TRANSFER_SELECTOR: [u8; 4] = [0xd7, 0x58, 0x22, 0xc4];
pub const STS_MINT_SELECTOR: [u8; 4] = [0x0a, 0x7a, 0xb2, 0xcf];
pub const STS_BURN_SELECTOR: [u8; 4] = [0x35, 0x7f, 0x9a, 0x06];
pub const GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT: u64 = 466_626;

const ABI_DECODE_GAS: u64 = 10;
const DEPLOY_BASE_GAS: u64 = 75;
const CALL_BASE_GAS: u64 = 40;
const STATE_READ_GAS: u64 = 15;
const STATE_WRITE_GAS: u64 = 35;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SynQRuntimeOperation {
    Deploy,
    Call,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQRuntimeReceipt {
    pub contract_id: String,
    pub context: ExecutionReceiptContext,
    pub operation: SynQRuntimeOperation,
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub pqc_gas_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<String>,
    pub native_transfers: Vec<SynQNativeTransfer>,
    pub error_code: Option<AivmErrorCode>,
    pub error: Option<String>,
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
}

impl SynQRuntimeReceipt {
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut out = Vec::new();
        out.extend_from_slice(b"AIVM-SYNQ-STATEFUL-RECEIPT-V1");
        push_bytes(&mut out, self.contract_id.as_bytes());
        push_receipt_context(&mut out, &self.context);
        push_u16(&mut out, operation_code(self.operation));
        push_u16(&mut out, execution_status_code(&self.status));
        push_u64(&mut out, self.gas_used);
        push_u64(&mut out, self.pqc_gas_used);
        push_bytes(&mut out, &self.return_data);
        push_u64(&mut out, self.logs.len() as u64);
        for log in &self.logs {
            push_bytes(&mut out, log.as_bytes());
        }
        push_u64(&mut out, self.native_transfers.len() as u64);
        for transfer in &self.native_transfers {
            push_bytes(&mut out, transfer.from.as_bytes());
            push_bytes(&mut out, transfer.to.as_bytes());
            out.extend_from_slice(&transfer.amount_nwei.to_be_bytes());
        }
        match self.error_code {
            Some(code) => push_u16(&mut out, aivm_error_code_value(code)),
            None => push_u16(&mut out, 0),
        }
        match &self.error {
            Some(error) => push_bytes(&mut out, error.as_bytes()),
            None => push_bytes(&mut out, &[]),
        }
        out.extend_from_slice(&self.pre_state_root);
        out.extend_from_slice(&self.post_state_root);

        let digest = Sha256::digest(&out);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }

    pub fn execution_receipt(&self) -> ExecutionReceipt {
        ExecutionReceipt {
            contract_id: self.contract_id.clone(),
            context: self.context.clone(),
            status: self.status.clone(),
            gas_used: self.gas_used,
            pqc_gas_used: self.pqc_gas_used,
            return_data: self.return_data.clone(),
            logs: self.logs.clone(),
            error_code: self.error_code,
            error: self.error.clone(),
        }
    }
}

pub fn deploy_synq_contract(
    request: &ExecutionRequest,
    state: &mut ContractState,
) -> SynQRuntimeReceipt {
    let pre_state_root = state.state_root();
    let mut meter = AivmGasMeter::new(request.context.gas_limit, request.context.pq_gas_limit);
    if let Err(error) = meter.charge_pq_gas(request.context.admission_pq_gas_used) {
        return failed(
            request,
            SynQRuntimeOperation::Deploy,
            pre_state_root,
            &meter,
            error,
        );
    }
    let profile = match validate_runtime_artifact(request) {
        Ok(profile) => profile,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Deploy,
                pre_state_root,
                &meter,
                error,
            )
        }
    };
    if !matches!(profile, SynQRuntimeProfile::Stateful { .. }) && !request.calldata.is_empty() {
        return failed(
            request,
            SynQRuntimeOperation::Deploy,
            pre_state_root,
            &meter,
            AivmError::new(
                AivmErrorCode::Abi,
                "SynQ deploy precondition failed: deploy calldata must be empty",
            ),
        );
    }
    if let Err(error) = meter.charge_gas(DEPLOY_BASE_GAS) {
        return failed(
            request,
            SynQRuntimeOperation::Deploy,
            pre_state_root,
            &meter,
            error,
        );
    }

    if let SynQRuntimeProfile::Stateful { contract_name } = &profile {
        return deploy_stateful_contract(request, state, pre_state_root, &mut meter, contract_name);
    }

    let mut overlay = StateOverlay::default();
    if let Err(error) =
        initialize_contract_state(request, state, &mut overlay, &profile, &mut meter)
    {
        overlay.rollback();
        return failed(
            request,
            SynQRuntimeOperation::Deploy,
            pre_state_root,
            &meter,
            error,
        );
    }
    overlay.commit(state);
    let post_state_root = state.state_root();

    let mut logs = vec![
        format!("synq.deploy.contract={}", profile.contract_name()),
        format!("synq.deploy.runtime={}", profile.runtime_name()),
        format!("synq.state.pre={}", hex(&pre_state_root)),
        format!("synq.state.post={}", hex(&post_state_root)),
    ];
    logs.extend(profile.deploy_logs());

    succeeded(
        request,
        SynQRuntimeOperation::Deploy,
        &meter,
        encode_u256(0),
        logs,
        pre_state_root,
        post_state_root,
    )
}

pub fn call_synq_contract(
    request: &ExecutionRequest,
    state: &mut ContractState,
) -> SynQRuntimeReceipt {
    let pre_state_root = state.state_root();
    let mut meter = AivmGasMeter::new(request.context.gas_limit, request.context.pq_gas_limit);
    if let Err(error) = meter.charge_pq_gas(request.context.admission_pq_gas_used) {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            &meter,
            error,
        );
    }
    let profile = match validate_runtime_artifact(request) {
        Ok(profile) => profile,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                &meter,
                error,
            )
        }
    };
    if let SynQRuntimeProfile::Stateful { contract_name } = &profile {
        return call_stateful_contract(request, state, pre_state_root, &mut meter, contract_name);
    }
    if let SynQRuntimeProfile::Generic {
        contract_name,
        token,
    } = &profile
    {
        return call_generic_synq_contract(
            request,
            state,
            pre_state_root,
            &mut meter,
            contract_name,
            token,
        );
    }

    let method = match decode_counter_method(&request.calldata, &mut meter) {
        Ok(method) => method,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                &meter,
                error,
            )
        }
    };

    let counter = CounterStateMachine::new(request.contract_id.as_bytes().to_vec());
    if !counter.is_deployed(state, &StateOverlay::default()) {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            &meter,
            AivmError::new(
                AivmErrorCode::State,
                "SynQ call precondition failed: contract has not been deployed",
            ),
        );
    }

    if let Err(error) = meter.charge_gas(CALL_BASE_GAS) {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            &meter,
            error,
        );
    }

    match method {
        CounterMethod::Increment => {
            let mut overlay = StateOverlay::default();
            if let Err(error) = meter.charge_gas(STATE_READ_GAS) {
                overlay.rollback();
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    &meter,
                    error,
                );
            }
            if let Err(error) = meter.charge_gas(STATE_WRITE_GAS) {
                overlay.rollback();
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    &meter,
                    error,
                );
            }
            let next = counter.increment(state, &mut overlay);
            overlay.commit(state);
            let post_state_root = state.state_root();
            succeeded(
                request,
                SynQRuntimeOperation::Call,
                &meter,
                encode_u256(next),
                vec![
                    "synq.call.method=increment".to_string(),
                    format!("synq.counter.value={next}"),
                    format!("synq.state.pre={}", hex(&pre_state_root)),
                    format!("synq.state.post={}", hex(&post_state_root)),
                ],
                pre_state_root,
                post_state_root,
            )
        }
        CounterMethod::Get => {
            if let Err(error) = meter.charge_gas(STATE_READ_GAS) {
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    &meter,
                    error,
                );
            }
            let value = counter.get(state, &StateOverlay::default());
            succeeded(
                request,
                SynQRuntimeOperation::Call,
                &meter,
                encode_u256(value),
                vec![
                    "synq.call.method=get".to_string(),
                    format!("synq.counter.value={value}"),
                    format!("synq.state.pre={}", hex(&pre_state_root)),
                    format!("synq.state.post={}", hex(&pre_state_root)),
                ],
                pre_state_root,
                pre_state_root,
            )
        }
    }
}

pub fn synq_execution_request(
    contract_id: impl Into<String>,
    artifact: ContractArtifact,
    context: ExecutionContext,
    calldata: Vec<u8>,
) -> ExecutionRequest {
    ExecutionRequest {
        contract_id: contract_id.into(),
        artifact,
        calldata,
        context,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterMethod {
    Increment,
    Get,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SynQRuntimeProfile {
    Counter,
    Stateful {
        contract_name: String,
    },
    Generic {
        contract_name: String,
        token: Option<SynQTokenMetadata>,
    },
}

impl SynQRuntimeProfile {
    fn contract_name(&self) -> &str {
        match self {
            Self::Counter => "Counter",
            Self::Stateful { contract_name } => contract_name,
            Self::Generic { contract_name, .. } => contract_name,
        }
    }

    fn runtime_name(&self) -> &'static str {
        match self {
            Self::Counter => "counter-state-machine",
            Self::Stateful { .. } => "stateful-synq-ir-v2",
            Self::Generic { .. } => "generic-synq-bytecode",
        }
    }

    fn deploy_logs(&self) -> Vec<String> {
        match self {
            Self::Counter | Self::Stateful { .. } => Vec::new(),
            Self::Generic { token, .. } => token
                .as_ref()
                .map(|token| {
                    vec![
                        format!("synq.token.standard={}", token.standard_id),
                        format!("synq.token.symbol={}", token.symbol),
                        format!("synq.token.initial_holder={}", token.initial_holder),
                        format!("synq.token.initial_supply={}", token.initial_supply),
                    ]
                })
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SynQTokenMetadata {
    contract_name: String,
    standard_id: String,
    name: String,
    symbol: String,
    decimals: u8,
    initial_supply: u128,
    max_supply: u128,
    initial_holder: String,
    issuer: String,
    verification_status: String,
    metadata_uri: String,
    metadata_hash: String,
}

#[derive(Debug, Deserialize)]
struct SynQAbiArtifact {
    contract: String,
    #[serde(default)]
    methods: Vec<SynQAbiMethod>,
}

#[derive(Debug, Clone, Deserialize)]
struct SynQAbiMethod {
    name: String,
    mutability: String,
    selector: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawSynQTokenMetadata {
    #[serde(default)]
    contract_name: Option<String>,
    #[serde(default)]
    standard_id: Option<String>,
    #[serde(default)]
    token_name: Option<String>,
    #[serde(default)]
    token_symbol: Option<String>,
    #[serde(default)]
    chain_id: Option<u64>,
    #[serde(default)]
    network_id: Option<String>,
    #[serde(default)]
    decimals: Option<u8>,
    #[serde(default)]
    initial_supply_base_units: Option<String>,
    #[serde(default)]
    max_supply_base_units: Option<String>,
    #[serde(default)]
    issuer_address: Option<String>,
    #[serde(default)]
    genesis_recipient: Option<String>,
    #[serde(default)]
    initial_holder: Option<String>,
    #[serde(default)]
    contract_address: Option<String>,
    #[serde(default)]
    verification_status: Option<String>,
    #[serde(default)]
    metadata_uri: Option<String>,
    #[serde(default)]
    metadata_hash: Option<String>,
}

fn validate_runtime_artifact(request: &ExecutionRequest) -> Result<SynQRuntimeProfile, AivmError> {
    validate_synq_artifact(request)?;

    let manifest = decode_manifest_artifact(request)?;
    let abi = decode_abi_artifact(request, "SynQ execution requires an ABI artifact")?;
    if abi.contract != manifest.contract_name {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!(
                "SynQ ABI contract mismatch: manifest {} ABI {}",
                manifest.contract_name, abi.contract
            ),
        ));
    }

    if manifest.artifact_format == "synq-stateful-ir-v2" && manifest.bytecode_version == 2 {
        return Ok(SynQRuntimeProfile::Stateful {
            contract_name: manifest.contract_name,
        });
    }

    if manifest.contract_name == "Counter" {
        validate_counter_abi(&abi)?;
        return Ok(SynQRuntimeProfile::Counter);
    }

    if request.context.runtime_block_height < GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "unsupported SynQ contract {}; only Counter is enabled in this AIVM path",
                manifest.contract_name
            ),
        ));
    }

    let token = parse_token_metadata(request, &manifest)?;
    Ok(SynQRuntimeProfile::Generic {
        contract_name: manifest.contract_name,
        token,
    })
}

fn decode_manifest_artifact(request: &ExecutionRequest) -> Result<SynQManifestArtifact, AivmError> {
    let manifest_json = request.artifact.manifest_json.as_deref().ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Manifest,
            "SynQ execution requires a manifest artifact",
        )
    })?;
    serde_json::from_str(manifest_json).map_err(|error| {
        AivmError::new(
            AivmErrorCode::Manifest,
            format!("failed to decode SynQ manifest artifact: {error}"),
        )
    })
}

fn decode_abi_artifact(
    request: &ExecutionRequest,
    missing_message: &'static str,
) -> Result<SynQAbiArtifact, AivmError> {
    let abi_json = request
        .artifact
        .abi_json
        .as_deref()
        .ok_or_else(|| AivmError::new(AivmErrorCode::Abi, missing_message))?;
    serde_json::from_str(abi_json).map_err(|error| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("failed to decode SynQ ABI artifact: {error}"),
        )
    })
}

fn validate_counter_abi(abi: &SynQAbiArtifact) -> Result<(), AivmError> {
    let has_increment = abi.methods.iter().any(|method| {
        method.name == "increment"
            && method.mutability == "write"
            && method.selector == "0x5842f1be"
    });
    let has_get = abi.methods.iter().any(|method| {
        method.name == "get" && method.mutability == "view" && method.selector == "0x75b70457"
    });
    if !has_increment || !has_get {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            "SynQ Counter ABI must expose increment/write and get/view selectors",
        ));
    }

    Ok(())
}

fn parse_token_metadata(
    request: &ExecutionRequest,
    manifest: &SynQManifestArtifact,
) -> Result<Option<SynQTokenMetadata>, AivmError> {
    let Some(metadata_json) = request.artifact.metadata_json.as_deref() else {
        return Ok(None);
    };
    let raw: RawSynQTokenMetadata = serde_json::from_str(metadata_json).map_err(|error| {
        AivmError::new(
            AivmErrorCode::Manifest,
            format!("failed to decode SynQ token metadata: {error}"),
        )
    })?;

    let has_token_metadata = raw.standard_id.as_deref() == Some("STS-9")
        || raw.token_name.is_some()
        || raw.token_symbol.is_some()
        || raw.initial_supply_base_units.is_some()
        || raw.max_supply_base_units.is_some();
    if !has_token_metadata {
        return Ok(None);
    }

    let contract_name = required_metadata_string(&raw.contract_name, "contract_name")?;
    if contract_name != manifest.contract_name {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "SynQ token metadata contract mismatch: manifest {} metadata {}",
                manifest.contract_name, contract_name
            ),
        ));
    }
    if let Some(chain_id) = raw.chain_id {
        if chain_id != request.context.chain_id {
            return Err(AivmError::new(
                AivmErrorCode::Manifest,
                format!(
                    "SynQ token metadata chain mismatch: metadata {} context {}",
                    chain_id, request.context.chain_id
                ),
            ));
        }
    }
    if let Some(network_id) = raw.network_id.as_deref() {
        if normalize_testnet_network(network_id)
            != normalize_testnet_network(&request.context.network_id)
        {
            return Err(AivmError::new(
                AivmErrorCode::Manifest,
                format!(
                    "SynQ token metadata network mismatch: metadata {} context {}",
                    network_id, request.context.network_id
                ),
            ));
        }
    }
    if let Some(contract_address) = raw.contract_address.as_deref() {
        if contract_address != request.contract_id {
            return Err(AivmError::new(
                AivmErrorCode::Manifest,
                format!(
                    "SynQ token metadata address mismatch: metadata {} request {}",
                    contract_address, request.contract_id
                ),
            ));
        }
    }

    let initial_supply = parse_u128_decimal(
        "initial_supply_base_units",
        &required_metadata_string(&raw.initial_supply_base_units, "initial_supply_base_units")?,
    )?;
    let max_supply = parse_u128_decimal(
        "max_supply_base_units",
        &required_metadata_string(&raw.max_supply_base_units, "max_supply_base_units")?,
    )?;
    if initial_supply > max_supply {
        return Err(AivmError::new(
            AivmErrorCode::Manifest,
            format!(
                "SynQ token metadata supply mismatch: initial {} exceeds max {}",
                initial_supply, max_supply
            ),
        ));
    }

    let initial_holder = raw
        .initial_holder
        .clone()
        .or_else(|| raw.genesis_recipient.clone())
        .ok_or_else(|| {
            AivmError::new(
                AivmErrorCode::Manifest,
                "SynQ token metadata requires initial_holder or genesis_recipient",
            )
        })?;

    Ok(Some(SynQTokenMetadata {
        contract_name,
        standard_id: required_metadata_string(&raw.standard_id, "standard_id")?,
        name: required_metadata_string(&raw.token_name, "token_name")?,
        symbol: required_metadata_string(&raw.token_symbol, "token_symbol")?,
        decimals: raw.decimals.ok_or_else(|| {
            AivmError::new(
                AivmErrorCode::Manifest,
                "SynQ token metadata requires decimals",
            )
        })?,
        initial_supply,
        max_supply,
        initial_holder,
        issuer: required_metadata_string(&raw.issuer_address, "issuer_address")?,
        verification_status: raw
            .verification_status
            .unwrap_or_else(|| "unverified".to_string()),
        metadata_uri: raw.metadata_uri.unwrap_or_default(),
        metadata_hash: raw.metadata_hash.unwrap_or_default(),
    }))
}

fn required_metadata_string(
    value: &Option<String>,
    field: &'static str,
) -> Result<String, AivmError> {
    value
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| {
            AivmError::new(
                AivmErrorCode::Manifest,
                format!("SynQ token metadata requires {field}"),
            )
        })
}

fn normalize_testnet_network(network_id: &str) -> Option<&'static str> {
    match network_id {
        "synergy-testnet" | "synergy-testnet-v3" => Some("synergy-testnet"),
        _ => None,
    }
}

fn initialize_contract_state(
    request: &ExecutionRequest,
    state: &ContractState,
    overlay: &mut StateOverlay,
    profile: &SynQRuntimeProfile,
    meter: &mut AivmGasMeter,
) -> Result<(), AivmError> {
    match profile {
        SynQRuntimeProfile::Counter => {
            let counter = CounterStateMachine::new(request.contract_id.as_bytes().to_vec());
            if !counter.initialize(state, overlay) {
                return Err(AivmError::new(
                    AivmErrorCode::State,
                    "SynQ deploy precondition failed: contract is already deployed",
                ));
            }
            Ok(())
        }
        SynQRuntimeProfile::Stateful { .. } => Err(AivmError::new(
            AivmErrorCode::InternalInvariant,
            "stateful SynQ deploy reached the legacy initializer",
        )),
        SynQRuntimeProfile::Generic {
            contract_name,
            token,
        } => {
            initialize_generic_contract_state(request, state, overlay, contract_name, token, meter)
        }
    }
}

fn deploy_stateful_contract(
    request: &ExecutionRequest,
    state: &mut ContractState,
    pre_state_root: [u8; 32],
    meter: &mut AivmGasMeter,
    contract_name: &str,
) -> SynQRuntimeReceipt {
    let manifest = match decode_manifest_artifact(request) {
        Ok(manifest) => manifest,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Deploy,
                pre_state_root,
                meter,
                error,
            )
        }
    };
    let executable = match synq_compiler::StatefulSynQExecutable::decode(&request.artifact.bytes) {
        Ok(executable) => executable,
        Err(message) => {
            return failed(
                request,
                SynQRuntimeOperation::Deploy,
                pre_state_root,
                meter,
                AivmError::bytecode(message),
            )
        }
    };
    let mut overlay = StateOverlay::default();
    match deploy_stateful_synq(
        &executable,
        &manifest,
        &request.calldata,
        &request.context,
        &request.contract_id,
        state,
        &mut overlay,
        meter,
    ) {
        Ok(outcome) => {
            overlay.commit(state);
            let post_state_root = state.state_root();
            let mut logs = vec![
                format!("synq.deploy.contract={contract_name}"),
                "synq.deploy.runtime=stateful-synq-ir-v2".to_string(),
                format!("synq.state.pre={}", hex(&pre_state_root)),
                format!("synq.state.post={}", hex(&post_state_root)),
            ];
            logs.extend(outcome.logs);
            succeeded_with_transfers(
                request,
                SynQRuntimeOperation::Deploy,
                meter,
                outcome.return_data,
                logs,
                outcome.native_transfers,
                pre_state_root,
                post_state_root,
            )
        }
        Err(failure) => {
            overlay.rollback();
            failed_stateful(
                request,
                SynQRuntimeOperation::Deploy,
                pre_state_root,
                meter,
                failure,
            )
        }
    }
}

fn call_stateful_contract(
    request: &ExecutionRequest,
    state: &mut ContractState,
    pre_state_root: [u8; 32],
    meter: &mut AivmGasMeter,
    contract_name: &str,
) -> SynQRuntimeReceipt {
    if let Err(error) = meter.charge_gas(CALL_BASE_GAS) {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            meter,
            error,
        );
    }
    let manifest = match decode_manifest_artifact(request) {
        Ok(manifest) => manifest,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                error,
            )
        }
    };
    let abi = match decode_abi_artifact(request, "stateful SynQ execution requires an ABI") {
        Ok(abi) => abi,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                error,
            )
        }
    };
    let (method_name, encoded_args) = match decode_stateful_method(&abi, &request.calldata) {
        Ok(decoded) => decoded,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                error,
            )
        }
    };
    let executable = match synq_compiler::StatefulSynQExecutable::decode(&request.artifact.bytes) {
        Ok(executable) => executable,
        Err(message) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                AivmError::bytecode(message),
            )
        }
    };
    let mut overlay = StateOverlay::default();
    match call_stateful_synq(
        &executable,
        &manifest,
        method_name,
        encoded_args,
        &request.context,
        &request.contract_id,
        state,
        &mut overlay,
        meter,
    ) {
        Ok(outcome) => {
            overlay.commit(state);
            let post_state_root = state.state_root();
            let mut logs = vec![
                format!("synq.call.contract={contract_name}"),
                "synq.call.runtime=stateful-synq-ir-v2".to_string(),
                format!("synq.call.method={method_name}"),
                format!("synq.state.pre={}", hex(&pre_state_root)),
                format!("synq.state.post={}", hex(&post_state_root)),
            ];
            logs.extend(outcome.logs);
            succeeded_with_transfers(
                request,
                SynQRuntimeOperation::Call,
                meter,
                outcome.return_data,
                logs,
                outcome.native_transfers,
                pre_state_root,
                post_state_root,
            )
        }
        Err(failure) => {
            overlay.rollback();
            failed_stateful(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                failure,
            )
        }
    }
}

fn decode_stateful_method<'a>(
    abi: &'a SynQAbiArtifact,
    calldata: &'a [u8],
) -> Result<(&'a str, &'a [u8]), AivmError> {
    if calldata.len() < 4 {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!(
                "stateful SynQ calldata requires a 4-byte selector; got {} bytes",
                calldata.len()
            ),
        ));
    }
    let selector = format!("0x{}", hex(&calldata[..4]));
    let method = abi
        .methods
        .iter()
        .find(|method| method.selector == selector)
        .ok_or_else(|| {
            AivmError::new(
                AivmErrorCode::Abi,
                format!("unsupported stateful SynQ selector {selector}"),
            )
        })?;
    Ok((&method.name, &calldata[4..]))
}

fn initialize_generic_contract_state(
    request: &ExecutionRequest,
    state: &ContractState,
    overlay: &mut StateOverlay,
    contract_name: &str,
    token: &Option<SynQTokenMetadata>,
    meter: &mut AivmGasMeter,
) -> Result<(), AivmError> {
    let namespace = request.contract_id.as_bytes().to_vec();
    if is_deployed(state, overlay, &namespace) {
        return Err(AivmError::new(
            AivmErrorCode::State,
            "SynQ deploy precondition failed: contract is already deployed",
        ));
    }

    write_state(overlay, meter, &namespace, "__deployed", vec![1])?;
    write_state(
        overlay,
        meter,
        &namespace,
        "contract_name",
        contract_name.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        &namespace,
        "runtime",
        b"generic-synq-bytecode".to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        &namespace,
        "artifact_bytecode_hash",
        sha256_hex(&request.artifact.bytes).into_bytes(),
    )?;
    if let Some(manifest_json) = request.artifact.manifest_json.as_deref() {
        write_state(
            overlay,
            meter,
            &namespace,
            "artifact_manifest_hash",
            sha256_hex(manifest_json.as_bytes()).into_bytes(),
        )?;
    }
    if let Some(abi_json) = request.artifact.abi_json.as_deref() {
        write_state(
            overlay,
            meter,
            &namespace,
            "artifact_abi_hash",
            sha256_hex(abi_json.as_bytes()).into_bytes(),
        )?;
    }

    if let Some(token) = token {
        initialize_token_state(overlay, meter, &namespace, token)?;
    }
    Ok(())
}

fn initialize_token_state(
    overlay: &mut StateOverlay,
    meter: &mut AivmGasMeter,
    namespace: &[u8],
    token: &SynQTokenMetadata,
) -> Result<(), AivmError> {
    write_state(
        overlay,
        meter,
        namespace,
        "token_standard",
        token.standard_id.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "token_name",
        token.name.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "token_symbol",
        token.symbol.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "token_decimals",
        encode_u256_u128(token.decimals as u128),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "token_max_supply",
        encode_u256_u128(token.max_supply),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "token_total_supply",
        encode_u256_u128(token.initial_supply),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "token_circulating_supply",
        encode_u256_u128(token.initial_supply),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "issuer",
        token.issuer.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "verification",
        token.verification_status.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "metadata_uri",
        token.metadata_uri.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        "metadata_hash",
        token.metadata_hash.as_bytes().to_vec(),
    )?;
    write_state(
        overlay,
        meter,
        namespace,
        &format!("balance:{}", token.initial_holder),
        encode_u256_u128(token.initial_supply),
    )?;
    Ok(())
}

fn call_generic_synq_contract(
    request: &ExecutionRequest,
    state: &mut ContractState,
    pre_state_root: [u8; 32],
    meter: &mut AivmGasMeter,
    contract_name: &str,
    token: &Option<SynQTokenMetadata>,
) -> SynQRuntimeReceipt {
    let namespace = request.contract_id.as_bytes().to_vec();
    if !is_deployed(state, &StateOverlay::default(), &namespace) {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            meter,
            AivmError::new(
                AivmErrorCode::State,
                "SynQ call precondition failed: contract has not been deployed",
            ),
        );
    }
    if let Err(error) = meter.charge_gas(CALL_BASE_GAS) {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            meter,
            error,
        );
    }
    if is_sts_host_selector(&request.calldata) {
        return call_sts_host(request, state, pre_state_root, meter, contract_name);
    }
    if token.is_some() {
        return call_sts9_token_contract(request, state, pre_state_root, meter, contract_name);
    }

    let mut vm_request = request.clone();
    vm_request.context.admission_pq_gas_used = 0;
    vm_request.context.gas_limit = meter.remaining_gas();
    vm_request.context.pq_gas_limit = meter.remaining_pq_gas();
    let vm_receipt = execute_contract(&vm_request);
    let post_state_root = state.state_root();
    let mut logs = vec![
        format!("synq.call.contract={contract_name}"),
        "synq.call.runtime=generic-synq-bytecode".to_string(),
        format!("synq.state.pre={}", hex(&pre_state_root)),
        format!("synq.state.post={}", hex(&post_state_root)),
    ];
    logs.extend(vm_receipt.logs);

    SynQRuntimeReceipt {
        contract_id: request.contract_id.clone(),
        context: ExecutionReceiptContext::from_request(request),
        operation: SynQRuntimeOperation::Call,
        status: vm_receipt.status,
        gas_used: meter.gas_used().saturating_add(vm_receipt.gas_used),
        pqc_gas_used: meter.pq_gas_used().saturating_add(vm_receipt.pqc_gas_used),
        return_data: vm_receipt.return_data,
        logs,
        native_transfers: Vec::new(),
        error_code: vm_receipt.error_code,
        error: vm_receipt.error,
        pre_state_root,
        post_state_root,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StsHostMethod {
    Balance {
        token_id: String,
        owner: String,
    },
    TokenExists {
        object_id: String,
    },
    TokenClass {
        object_id: String,
    },
    TotalSupply {
        token_id: String,
    },
    OwnerOf {
        nft_id: String,
    },
    NftExists {
        nft_id: String,
    },
    MultiAssetBalance {
        collection_id: String,
        item_id: u64,
        owner: String,
    },
    CredentialStatus {
        credential_id: String,
    },
    VerifyCredential {
        subject: String,
        schema_id: String,
        issuer: String,
    },
    WriteRejected {
        function_name: &'static str,
    },
}

fn is_sts_host_selector(calldata: &[u8]) -> bool {
    calldata
        .get(0..4)
        .and_then(|selector| selector.try_into().ok())
        .is_some_and(|selector: [u8; 4]| {
            matches!(
                selector,
                STS_BALANCE_SELECTOR
                    | STS_TOKEN_EXISTS_SELECTOR
                    | STS_TOKEN_CLASS_SELECTOR
                    | STS_TOTAL_SUPPLY_SELECTOR
                    | STS_OWNER_OF_SELECTOR
                    | STS_NFT_EXISTS_SELECTOR
                    | STS_MULTI_ASSET_BALANCE_SELECTOR
                    | STS_CREDENTIAL_STATUS_SELECTOR
                    | STS_VERIFY_CREDENTIAL_SELECTOR
                    | STS_TRANSFER_SELECTOR
                    | STS_MINT_SELECTOR
                    | STS_BURN_SELECTOR
            )
        })
}

fn call_sts_host(
    request: &ExecutionRequest,
    state: &ContractState,
    pre_state_root: [u8; 32],
    meter: &mut AivmGasMeter,
    contract_name: &str,
) -> SynQRuntimeReceipt {
    let method = match decode_sts_host_method(&request.calldata, meter) {
        Ok(method) => method,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                error,
            )
        }
    };
    let Some(sts_host) = request.context.sts_host.as_ref() else {
        return failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            meter,
            AivmError::new(
                AivmErrorCode::HostFunction,
                "STS host context is unavailable for this SynQ execution",
            ),
        );
    };
    let result = execute_sts_host_method(sts_host, method, meter);
    let post_state_root = state.state_root();
    match result {
        Ok((return_data, mut logs)) => {
            logs.insert(0, "synq.call.runtime=sts-host-v1".to_string());
            logs.insert(0, format!("synq.call.contract={contract_name}"));
            logs.push(format!("synq.state.pre={}", hex(&pre_state_root)));
            logs.push(format!("synq.state.post={}", hex(&post_state_root)));
            succeeded(
                request,
                SynQRuntimeOperation::Call,
                meter,
                return_data,
                logs,
                pre_state_root,
                post_state_root,
            )
        }
        Err(error) => failed(
            request,
            SynQRuntimeOperation::Call,
            pre_state_root,
            meter,
            error,
        ),
    }
}

fn decode_sts_host_method(
    calldata: &[u8],
    meter: &mut AivmGasMeter,
) -> Result<StsHostMethod, AivmError> {
    meter.charge_gas(ABI_DECODE_GAS)?;
    if calldata.len() < 4 {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!(
                "STS host call calldata must include 4 selector bytes; got {}",
                calldata.len()
            ),
        ));
    }
    let selector: [u8; 4] = calldata[0..4].try_into().map_err(|_| {
        AivmError::new(
            AivmErrorCode::Abi,
            "STS host call selector could not be decoded",
        )
    })?;
    let args = decode_json_args(&calldata[4..], "STS host")?;
    match selector {
        STS_BALANCE_SELECTOR => Ok(StsHostMethod::Balance {
            token_id: string_arg(&args, 0, "token_id", "STS host")?,
            owner: string_arg(&args, 1, "owner", "STS host")?,
        }),
        STS_TOKEN_EXISTS_SELECTOR => Ok(StsHostMethod::TokenExists {
            object_id: string_arg(&args, 0, "object_id", "STS host")?,
        }),
        STS_TOKEN_CLASS_SELECTOR => Ok(StsHostMethod::TokenClass {
            object_id: string_arg(&args, 0, "object_id", "STS host")?,
        }),
        STS_TOTAL_SUPPLY_SELECTOR => Ok(StsHostMethod::TotalSupply {
            token_id: string_arg(&args, 0, "token_id", "STS host")?,
        }),
        STS_OWNER_OF_SELECTOR => Ok(StsHostMethod::OwnerOf {
            nft_id: string_arg(&args, 0, "nft_id", "STS host")?,
        }),
        STS_NFT_EXISTS_SELECTOR => Ok(StsHostMethod::NftExists {
            nft_id: string_arg(&args, 0, "nft_id", "STS host")?,
        }),
        STS_MULTI_ASSET_BALANCE_SELECTOR => Ok(StsHostMethod::MultiAssetBalance {
            collection_id: string_arg(&args, 0, "collection_id", "STS host")?,
            item_id: u64_arg(&args, 1, "item_id", "STS host")?,
            owner: string_arg(&args, 2, "owner", "STS host")?,
        }),
        STS_CREDENTIAL_STATUS_SELECTOR => Ok(StsHostMethod::CredentialStatus {
            credential_id: string_arg(&args, 0, "credential_id", "STS host")?,
        }),
        STS_VERIFY_CREDENTIAL_SELECTOR => Ok(StsHostMethod::VerifyCredential {
            subject: string_arg(&args, 0, "subject", "STS host")?,
            schema_id: string_arg(&args, 1, "schema_id", "STS host")?,
            issuer: string_arg(&args, 2, "issuer", "STS host")?,
        }),
        STS_TRANSFER_SELECTOR => Ok(StsHostMethod::WriteRejected {
            function_name: "sts_transfer",
        }),
        STS_MINT_SELECTOR => Ok(StsHostMethod::WriteRejected {
            function_name: "sts_mint",
        }),
        STS_BURN_SELECTOR => Ok(StsHostMethod::WriteRejected {
            function_name: "sts_burn",
        }),
        _ => Err(AivmError::new(
            AivmErrorCode::Abi,
            format!("unsupported STS host selector 0x{}", hex(&selector)),
        )),
    }
}

fn execute_sts_host_method(
    sts_host: &StsHostContext,
    method: StsHostMethod,
    meter: &mut AivmGasMeter,
) -> Result<(Vec<u8>, Vec<String>), AivmError> {
    meter.charge_gas(STATE_READ_GAS)?;
    match method {
        StsHostMethod::Balance { token_id, owner } => {
            let balance = sts_host
                .fungible_balances
                .get(&StsHostContext::fungible_balance_key(&token_id, &owner))
                .copied()
                .unwrap_or(0);
            Ok((
                encode_u256_u128(balance),
                vec![
                    "sts.host.call=sts_balance".to_string(),
                    format!("sts.host.token_id={token_id}"),
                    format!("sts.host.owner={owner}"),
                ],
            ))
        }
        StsHostMethod::TokenExists { object_id } => {
            let exists = sts_host.object_classes.contains_key(&object_id);
            Ok((
                encode_bool(exists),
                vec![
                    "sts.host.call=sts_token_exists".to_string(),
                    format!("sts.host.object_id={object_id}"),
                ],
            ))
        }
        StsHostMethod::TokenClass { object_id } => {
            let class = sts_host.object_classes.get(&object_id).copied().unwrap_or(0);
            Ok((
                encode_u256(class as u64),
                vec![
                    "sts.host.call=sts_token_class".to_string(),
                    format!("sts.host.object_id={object_id}"),
                ],
            ))
        }
        StsHostMethod::TotalSupply { token_id } => {
            let total_supply = sts_host
                .fungible_tokens
                .get(&token_id)
                .map(|token| token.total_supply)
                .unwrap_or(0);
            Ok((
                encode_u256_u128(total_supply),
                vec![
                    "sts.host.call=sts_total_supply".to_string(),
                    format!("sts.host.token_id={token_id}"),
                ],
            ))
        }
        StsHostMethod::OwnerOf { nft_id } => {
            let Some(nft) = sts_host.nfts.get(&nft_id) else {
                return Err(AivmError::new(
                    AivmErrorCode::State,
                    format!("STS host owner lookup failed: NFT {nft_id} does not exist"),
                ));
            };
            if nft.burned || nft.revoked {
                return Err(AivmError::new(
                    AivmErrorCode::State,
                    format!("STS host owner lookup failed: NFT {nft_id} is not active"),
                ));
            }
            Ok((
                nft.owner.as_bytes().to_vec(),
                vec![
                    "sts.host.call=sts_owner_of".to_string(),
                    format!("sts.host.nft_id={nft_id}"),
                    format!("sts.host.owner={}", nft.owner),
                ],
            ))
        }
        StsHostMethod::NftExists { nft_id } => {
            let exists = sts_host
                .nfts
                .get(&nft_id)
                .is_some_and(|nft| !nft.burned && !nft.revoked);
            Ok((
                encode_bool(exists),
                vec![
                    "sts.host.call=sts_nft_exists".to_string(),
                    format!("sts.host.nft_id={nft_id}"),
                ],
            ))
        }
        StsHostMethod::MultiAssetBalance {
            collection_id,
            item_id,
            owner,
        } => {
            let balance = sts_host
                .multi_asset_balances
                .get(&StsHostContext::multi_asset_balance_key(
                    &collection_id,
                    item_id,
                    &owner,
                ))
                .copied()
                .unwrap_or(0);
            Ok((
                encode_u256_u128(balance),
                vec![
                    "sts.host.call=sts_multi_asset_balance".to_string(),
                    format!("sts.host.collection_id={collection_id}"),
                    format!("sts.host.item_id={item_id}"),
                    format!("sts.host.owner={owner}"),
                ],
            ))
        }
        StsHostMethod::CredentialStatus { credential_id } => {
            let status = sts_host
                .credentials
                .get(&credential_id)
                .map(|credential| credential.status)
                .unwrap_or(0);
            Ok((
                encode_u256(status as u64),
                vec![
                    "sts.host.call=sts_credential_status".to_string(),
                    format!("sts.host.credential_id={credential_id}"),
                    format!("sts.host.status={status}"),
                ],
            ))
        }
        StsHostMethod::VerifyCredential {
            subject,
            schema_id,
            issuer,
        } => {
            let key = StsHostContext::credential_lookup_key(&subject, &schema_id, &issuer);
            let verified = sts_host
                .credential_lookup
                .get(&key)
                .and_then(|credential_id| sts_host.credentials.get(credential_id))
                .is_some_and(|credential| credential.status == 1);
            Ok((
                encode_bool(verified),
                vec![
                    "sts.host.call=sts_verify_credential".to_string(),
                    format!("sts.host.subject={subject}"),
                    format!("sts.host.schema_id={schema_id}"),
                    format!("sts.host.issuer={issuer}"),
                    format!("sts.host.verified={verified}"),
                ],
            ))
        }
        StsHostMethod::WriteRejected { function_name } => Err(AivmError::new(
            AivmErrorCode::HostFunction,
            format!(
                "{function_name} is not enabled in the deterministic read-only STS host surface; use native STS transactions for state mutation"
            ),
        )),
    }
}

fn call_sts9_token_contract(
    request: &ExecutionRequest,
    state: &mut ContractState,
    pre_state_root: [u8; 32],
    meter: &mut AivmGasMeter,
    contract_name: &str,
) -> SynQRuntimeReceipt {
    let namespace = request.contract_id.as_bytes().to_vec();
    let call = match decode_sts9_method(&request.calldata, meter) {
        Ok(call) => call,
        Err(error) => {
            return failed(
                request,
                SynQRuntimeOperation::Call,
                pre_state_root,
                meter,
                error,
            )
        }
    };

    match call {
        Sts9Method::TotalSupply => {
            match read_u256_u128_state(
                state,
                &StateOverlay::default(),
                meter,
                &namespace,
                "token_total_supply",
            ) {
                Ok(total_supply) => {
                    let post_state_root = state.state_root();
                    succeeded(
                        request,
                        SynQRuntimeOperation::Call,
                        meter,
                        encode_u256_u128(total_supply),
                        sts9_logs(
                            contract_name,
                            &pre_state_root,
                            &post_state_root,
                            vec!["synq.token.call=total_supply".to_string()],
                        ),
                        pre_state_root,
                        post_state_root,
                    )
                }
                Err(error) => failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    meter,
                    error,
                ),
            }
        }
        Sts9Method::BalanceOf { owner } => {
            let key = format!("balance:{owner}");
            match read_u256_u128_state(state, &StateOverlay::default(), meter, &namespace, &key) {
                Ok(balance) => {
                    let post_state_root = state.state_root();
                    succeeded(
                        request,
                        SynQRuntimeOperation::Call,
                        meter,
                        encode_u256_u128(balance),
                        sts9_logs(
                            contract_name,
                            &pre_state_root,
                            &post_state_root,
                            vec![
                                "synq.token.call=balance_of".to_string(),
                                format!("synq.token.owner={owner}"),
                            ],
                        ),
                        pre_state_root,
                        post_state_root,
                    )
                }
                Err(error) => failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    meter,
                    error,
                ),
            }
        }
        Sts9Method::Transfer { to, amount } => {
            let from = match caller_address(request) {
                Ok(from) => from,
                Err(error) => {
                    return failed(
                        request,
                        SynQRuntimeOperation::Call,
                        pre_state_root,
                        meter,
                        error,
                    )
                }
            };
            let mut overlay = StateOverlay::default();
            let from_key = format!("balance:{from}");
            let to_key = format!("balance:{to}");
            let from_balance =
                match read_u256_u128_state(state, &overlay, meter, &namespace, &from_key) {
                    Ok(balance) => balance,
                    Err(error) => {
                        overlay.rollback();
                        return failed(
                            request,
                            SynQRuntimeOperation::Call,
                            pre_state_root,
                            meter,
                            error,
                        );
                    }
                };
            if from_balance < amount {
                overlay.rollback();
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    meter,
                    AivmError::new(
                        AivmErrorCode::State,
                        format!(
                            "STS-9 transfer failed: insufficient balance for {from}; have {from_balance}, need {amount}"
                        ),
                    ),
                );
            }
            let to_balance = match read_u256_u128_state(state, &overlay, meter, &namespace, &to_key)
            {
                Ok(balance) => balance,
                Err(error) => {
                    overlay.rollback();
                    return failed(
                        request,
                        SynQRuntimeOperation::Call,
                        pre_state_root,
                        meter,
                        error,
                    );
                }
            };
            let Some(next_to_balance) = to_balance.checked_add(amount) else {
                overlay.rollback();
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    meter,
                    AivmError::new(
                        AivmErrorCode::State,
                        "STS-9 transfer failed: recipient balance overflow",
                    ),
                );
            };
            if let Err(error) = write_state(
                &mut overlay,
                meter,
                &namespace,
                &from_key,
                encode_u256_u128(from_balance - amount),
            ) {
                overlay.rollback();
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    meter,
                    error,
                );
            }
            if let Err(error) = write_state(
                &mut overlay,
                meter,
                &namespace,
                &to_key,
                encode_u256_u128(next_to_balance),
            ) {
                overlay.rollback();
                return failed(
                    request,
                    SynQRuntimeOperation::Call,
                    pre_state_root,
                    meter,
                    error,
                );
            }
            overlay.commit(state);
            let post_state_root = state.state_root();
            succeeded(
                request,
                SynQRuntimeOperation::Call,
                meter,
                encode_u256(1),
                sts9_logs(
                    contract_name,
                    &pre_state_root,
                    &post_state_root,
                    vec![
                        "synq.token.call=transfer".to_string(),
                        format!("synq.token.from={from}"),
                        format!("synq.token.to={to}"),
                        format!("synq.token.amount={amount}"),
                    ],
                ),
                pre_state_root,
                post_state_root,
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sts9Method {
    TotalSupply,
    BalanceOf { owner: String },
    Transfer { to: String, amount: u128 },
}

fn decode_sts9_method(calldata: &[u8], meter: &mut AivmGasMeter) -> Result<Sts9Method, AivmError> {
    meter.charge_gas(ABI_DECODE_GAS)?;
    if calldata.len() < 4 {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!(
                "STS-9 call calldata must include 4 selector bytes; got {}",
                calldata.len()
            ),
        ));
    }
    let selector: [u8; 4] = calldata[0..4].try_into().map_err(|_| {
        AivmError::new(
            AivmErrorCode::Abi,
            "STS-9 call selector could not be decoded",
        )
    })?;
    match selector {
        STS9_TOTAL_SUPPLY_SELECTOR => {
            if calldata.len() != 4 {
                return Err(AivmError::new(
                    AivmErrorCode::Abi,
                    "STS-9 total_supply expects no encoded args",
                ));
            }
            Ok(Sts9Method::TotalSupply)
        }
        STS9_BALANCE_OF_SELECTOR => {
            let args = decode_json_args(&calldata[4..], "STS-9")?;
            Ok(Sts9Method::BalanceOf {
                owner: sts9_address_arg(&args, 0, "owner")?,
            })
        }
        STS9_TRANSFER_SELECTOR => {
            let args = decode_json_args(&calldata[4..], "STS-9")?;
            Ok(Sts9Method::Transfer {
                to: sts9_address_arg(&args, 0, "to")?,
                amount: sts9_amount_arg(&args, 1, "amount")?,
            })
        }
        _ => Err(AivmError::new(
            AivmErrorCode::Abi,
            format!("unsupported STS-9 selector 0x{}", hex(&selector)),
        )),
    }
}

fn decode_json_args(bytes: &[u8], label: &str) -> Result<Vec<serde_json::Value>, AivmError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("{label} encoded args must be JSON bytes: {error}"),
        )
    })?;
    if let Some(values) = value.as_array() {
        return Ok(values.clone());
    }
    if let Some(object) = value.as_object() {
        let values = [
            "token_id",
            "object_id",
            "nft_id",
            "collection_id",
            "item_id",
            "credential_id",
            "subject",
            "schema_id",
            "issuer",
            "owner",
            "account",
            "to",
            "amount",
            "from",
        ]
        .iter()
        .filter_map(|key| object.get(*key).cloned())
        .collect();
        return Ok(values);
    }
    Err(AivmError::new(
        AivmErrorCode::Abi,
        format!("{label} encoded args must be a JSON array or object"),
    ))
}

fn string_arg(
    args: &[serde_json::Value],
    index: usize,
    field: &'static str,
    label: &str,
) -> Result<String, AivmError> {
    let value = args.get(index).ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("{label} {field} argument is required"),
        )
    })?;
    let text = value.as_str().map(str::trim).ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("{label} {field} argument must be a string"),
        )
    })?;
    if text.is_empty() {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!("{label} {field} argument must not be empty"),
        ));
    }
    Ok(text.to_string())
}

fn u64_arg(
    args: &[serde_json::Value],
    index: usize,
    field: &'static str,
    label: &str,
) -> Result<u64, AivmError> {
    let value = args.get(index).ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("{label} {field} argument is required"),
        )
    })?;
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .ok_or_else(|| {
            AivmError::new(
                AivmErrorCode::Abi,
                format!("{label} {field} argument must be a u64 or decimal string"),
            )
        })?
        .trim()
        .parse::<u64>()
        .map_err(|error| {
            AivmError::new(
                AivmErrorCode::Abi,
                format!("{label} {field} argument is invalid: {error}"),
            )
        })
}

fn sts9_address_arg(
    args: &[serde_json::Value],
    index: usize,
    field: &'static str,
) -> Result<String, AivmError> {
    let value = args.get(index).ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("STS-9 {field} argument is required"),
        )
    })?;
    let address = value.as_str().map(str::trim).ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("STS-9 {field} argument must be a string address"),
        )
    })?;
    if !is_synergy_address_shape(address) {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!("STS-9 {field} argument is not a valid Synergy address"),
        ));
    }
    Ok(address.to_string())
}

fn sts9_amount_arg(
    args: &[serde_json::Value],
    index: usize,
    field: &'static str,
) -> Result<u128, AivmError> {
    let value = args.get(index).ok_or_else(|| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("STS-9 {field} argument is required"),
        )
    })?;
    let amount = (if let Some(text) = value.as_str() {
        text.trim()
            .parse::<u128>()
            .map_err(|error| error.to_string())
    } else if let Some(number) = value.as_u64() {
        Ok(number as u128)
    } else {
        Err("amount must be a decimal string or unsigned integer".to_string())
    })
    .map_err(|error| {
        AivmError::new(
            AivmErrorCode::Abi,
            format!("STS-9 {field} argument is invalid: {error}"),
        )
    })?;
    if amount == 0 {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            "STS-9 transfer amount must be greater than zero",
        ));
    }
    Ok(amount)
}

fn caller_address(request: &ExecutionRequest) -> Result<String, AivmError> {
    let caller = std::str::from_utf8(&request.context.caller)
        .map(str::trim)
        .map_err(|error| {
            AivmError::new(
                AivmErrorCode::Abi,
                format!("STS-9 caller address is not UTF-8: {error}"),
            )
        })?;
    if !is_synergy_address_shape(caller) {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            "STS-9 caller is not a valid Synergy address",
        ));
    }
    Ok(caller.to_string())
}

fn is_synergy_address_shape(value: &str) -> bool {
    value.len() == 41
        && value.starts_with("syn")
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn read_u256_u128_state(
    base: &ContractState,
    overlay: &StateOverlay,
    meter: &mut AivmGasMeter,
    namespace: &[u8],
    key: &str,
) -> Result<u128, AivmError> {
    meter.charge_gas(STATE_READ_GAS)?;
    let Some(value) = overlay.read(
        base,
        &StateKey::new(namespace.to_vec(), key.as_bytes().to_vec()),
    ) else {
        return Ok(0);
    };
    if value.len() != 32 {
        return Err(AivmError::new(
            AivmErrorCode::State,
            format!("STS-9 state value {key} is not a UInt256"),
        ));
    }
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&value[16..32]);
    Ok(u128::from_be_bytes(raw))
}

fn sts9_logs(
    contract_name: &str,
    pre_state_root: &[u8; 32],
    post_state_root: &[u8; 32],
    mut extra: Vec<String>,
) -> Vec<String> {
    let mut logs = vec![
        format!("synq.call.contract={contract_name}"),
        "synq.call.runtime=sts9-token".to_string(),
        format!("synq.state.pre={}", hex(pre_state_root)),
        format!("synq.state.post={}", hex(post_state_root)),
    ];
    logs.append(&mut extra);
    logs
}

fn decode_counter_method(
    calldata: &[u8],
    meter: &mut AivmGasMeter,
) -> Result<CounterMethod, AivmError> {
    meter.charge_gas(ABI_DECODE_GAS)?;
    if calldata.len() != 4 {
        return Err(AivmError::new(
            AivmErrorCode::Abi,
            format!(
                "SynQ call calldata must be exactly 4 selector bytes; got {}",
                calldata.len()
            ),
        ));
    }
    if calldata == COUNTER_INCREMENT_SELECTOR {
        Ok(CounterMethod::Increment)
    } else if calldata == COUNTER_GET_SELECTOR {
        Ok(CounterMethod::Get)
    } else {
        Err(AivmError::new(
            AivmErrorCode::Abi,
            format!("unsupported SynQ Counter selector 0x{}", hex(calldata)),
        ))
    }
}

fn failed(
    request: &ExecutionRequest,
    operation: SynQRuntimeOperation,
    state_root: [u8; 32],
    meter: &AivmGasMeter,
    error: AivmError,
) -> SynQRuntimeReceipt {
    SynQRuntimeReceipt {
        contract_id: request.contract_id.clone(),
        context: ExecutionReceiptContext::from_request(request),
        operation,
        status: ExecutionStatus::Failed,
        gas_used: meter.gas_used(),
        pqc_gas_used: meter.pq_gas_used(),
        return_data: Vec::new(),
        logs: Vec::new(),
        native_transfers: Vec::new(),
        error_code: Some(error.code),
        error: Some(error.message),
        pre_state_root: state_root,
        post_state_root: state_root,
    }
}

fn succeeded(
    request: &ExecutionRequest,
    operation: SynQRuntimeOperation,
    meter: &AivmGasMeter,
    return_data: Vec<u8>,
    logs: Vec<String>,
    pre_state_root: [u8; 32],
    post_state_root: [u8; 32],
) -> SynQRuntimeReceipt {
    succeeded_with_transfers(
        request,
        operation,
        meter,
        return_data,
        logs,
        Vec::new(),
        pre_state_root,
        post_state_root,
    )
}

fn succeeded_with_transfers(
    request: &ExecutionRequest,
    operation: SynQRuntimeOperation,
    meter: &AivmGasMeter,
    return_data: Vec<u8>,
    logs: Vec<String>,
    native_transfers: Vec<SynQNativeTransfer>,
    pre_state_root: [u8; 32],
    post_state_root: [u8; 32],
) -> SynQRuntimeReceipt {
    SynQRuntimeReceipt {
        contract_id: request.contract_id.clone(),
        context: ExecutionReceiptContext::from_request(request),
        operation,
        status: ExecutionStatus::Succeeded,
        gas_used: meter.gas_used(),
        pqc_gas_used: meter.pq_gas_used(),
        return_data,
        logs,
        native_transfers,
        error_code: None,
        error: None,
        pre_state_root,
        post_state_root,
    }
}

fn failed_stateful(
    request: &ExecutionRequest,
    operation: SynQRuntimeOperation,
    state_root: [u8; 32],
    meter: &AivmGasMeter,
    failure: StatefulSynQFailure,
) -> SynQRuntimeReceipt {
    SynQRuntimeReceipt {
        contract_id: request.contract_id.clone(),
        context: ExecutionReceiptContext::from_request(request),
        operation,
        status: if failure.reverted {
            ExecutionStatus::Reverted
        } else {
            ExecutionStatus::Failed
        },
        gas_used: meter.gas_used(),
        pqc_gas_used: meter.pq_gas_used(),
        return_data: Vec::new(),
        logs: Vec::new(),
        native_transfers: Vec::new(),
        error_code: Some(failure.error.code),
        error: Some(failure.error.message),
        pre_state_root: state_root,
        post_state_root: state_root,
    }
}

fn encode_u256(value: u64) -> Vec<u8> {
    encode_u256_u128(value as u128)
}

fn encode_bool(value: bool) -> Vec<u8> {
    encode_u256(if value { 1 } else { 0 })
}

fn encode_u256_u128(value: u128) -> Vec<u8> {
    let mut out = vec![0_u8; 32];
    out[16..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn parse_u128_decimal(field: &'static str, value: &str) -> Result<u128, AivmError> {
    value.parse::<u128>().map_err(|error| {
        AivmError::new(
            AivmErrorCode::Manifest,
            format!("SynQ token metadata {field} is not a valid u128 decimal: {error}"),
        )
    })
}

fn is_deployed(base: &ContractState, overlay: &StateOverlay, namespace: &[u8]) -> bool {
    overlay.read(base, &deployed_key(namespace)).is_some()
}

fn deployed_key(namespace: &[u8]) -> StateKey {
    StateKey::new(namespace.to_vec(), b"__deployed".to_vec())
}

fn write_state(
    overlay: &mut StateOverlay,
    meter: &mut AivmGasMeter,
    namespace: &[u8],
    key: &str,
    value: Vec<u8>,
) -> Result<(), AivmError> {
    meter.charge_gas(STATE_WRITE_GAS)?;
    overlay.write(
        StateKey::new(namespace.to_vec(), key.as_bytes().to_vec()),
        value,
    );
    Ok(())
}

fn operation_code(operation: SynQRuntimeOperation) -> u16 {
    match operation {
        SynQRuntimeOperation::Deploy => 1,
        SynQRuntimeOperation::Call => 2,
    }
}

fn execution_status_code(status: &ExecutionStatus) -> u16 {
    match status {
        ExecutionStatus::Succeeded => 1,
        ExecutionStatus::Reverted => 2,
        ExecutionStatus::Failed => 3,
    }
}

fn aivm_error_code_value(code: AivmErrorCode) -> u16 {
    match code {
        AivmErrorCode::Bytecode => 1,
        AivmErrorCode::Manifest => 2,
        AivmErrorCode::Abi => 3,
        AivmErrorCode::Verification => 4,
        AivmErrorCode::Gas => 5,
        AivmErrorCode::PqGas => 6,
        AivmErrorCode::RuntimeTrap => 7,
        AivmErrorCode::State => 8,
        AivmErrorCode::HostFunction => 9,
        AivmErrorCode::Receipt => 10,
        AivmErrorCode::InternalInvariant => 11,
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn checked_in_counter_deploy_increment_get_replay_is_deterministic() {
        let mut first_state = ContractState::default();
        let first_deploy = deploy_synq_contract(
            &checked_in_counter_request(Vec::new(), 20_000),
            &mut first_state,
        );
        let first_increment = call_synq_contract(
            &checked_in_counter_request(COUNTER_INCREMENT_SELECTOR.to_vec(), 20_000),
            &mut first_state,
        );
        let first_get = call_synq_contract(
            &checked_in_counter_request(COUNTER_GET_SELECTOR.to_vec(), 20_000),
            &mut first_state,
        );

        assert_eq!(first_deploy.status, ExecutionStatus::Succeeded);
        assert_eq!(first_increment.status, ExecutionStatus::Succeeded);
        assert_eq!(first_get.status, ExecutionStatus::Succeeded);
        assert_eq!(decode_u256(&first_increment.return_data), 1);
        assert_eq!(decode_u256(&first_get.return_data), 1);

        let mut replay_state = ContractState::default();
        let replay_deploy = deploy_synq_contract(
            &checked_in_counter_request(Vec::new(), 20_000),
            &mut replay_state,
        );
        let replay_increment = call_synq_contract(
            &checked_in_counter_request(COUNTER_INCREMENT_SELECTOR.to_vec(), 20_000),
            &mut replay_state,
        );
        let replay_get = call_synq_contract(
            &checked_in_counter_request(COUNTER_GET_SELECTOR.to_vec(), 20_000),
            &mut replay_state,
        );

        assert_eq!(first_state.state_root(), replay_state.state_root());
        assert_eq!(first_deploy, replay_deploy);
        assert_eq!(first_increment, replay_increment);
        assert_eq!(first_get, replay_get);
        assert_eq!(
            first_deploy.canonical_hash(),
            replay_deploy.canonical_hash()
        );
        assert_eq!(
            first_increment.canonical_hash(),
            replay_increment.canonical_hash()
        );
        assert_eq!(first_get.canonical_hash(), replay_get.canonical_hash());
    }

    #[test]
    fn call_before_deploy_fails_without_state_change() {
        let mut state = ContractState::default();
        let root_before = state.state_root();
        let receipt = call_synq_contract(
            &checked_in_counter_request(COUNTER_INCREMENT_SELECTOR.to_vec(), 20_000),
            &mut state,
        );

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::State));
        assert_eq!(receipt.pre_state_root, root_before);
        assert_eq!(receipt.post_state_root, root_before);
        assert_eq!(state.state_root(), root_before);
    }

    #[test]
    fn unsupported_selector_rolls_back_state() {
        let mut state = ContractState::default();
        let deploy =
            deploy_synq_contract(&checked_in_counter_request(Vec::new(), 20_000), &mut state);
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);
        let root_before = state.state_root();

        let receipt = call_synq_contract(
            &checked_in_counter_request(vec![0, 0, 0, 0], 20_000),
            &mut state,
        );

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Abi));
        assert_eq!(receipt.pre_state_root, root_before);
        assert_eq!(receipt.post_state_root, root_before);
        assert_eq!(state.state_root(), root_before);
    }

    #[test]
    fn gas_exhaustion_rolls_back_increment() {
        let mut state = ContractState::default();
        let deploy =
            deploy_synq_contract(&checked_in_counter_request(Vec::new(), 20_000), &mut state);
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);
        let root_before = state.state_root();

        let receipt = call_synq_contract(
            &checked_in_counter_request(COUNTER_INCREMENT_SELECTOR.to_vec(), 60),
            &mut state,
        );

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Gas));
        assert_eq!(receipt.pre_state_root, root_before);
        assert_eq!(receipt.post_state_root, root_before);
        assert_eq!(state.state_root(), root_before);
    }

    #[test]
    fn duplicate_deploy_fails_without_reinitializing_counter() {
        let mut state = ContractState::default();
        let deploy =
            deploy_synq_contract(&checked_in_counter_request(Vec::new(), 20_000), &mut state);
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);
        let increment = call_synq_contract(
            &checked_in_counter_request(COUNTER_INCREMENT_SELECTOR.to_vec(), 20_000),
            &mut state,
        );
        assert_eq!(decode_u256(&increment.return_data), 1);
        let root_before = state.state_root();

        let duplicate =
            deploy_synq_contract(&checked_in_counter_request(Vec::new(), 20_000), &mut state);

        assert_eq!(duplicate.status, ExecutionStatus::Failed);
        assert_eq!(duplicate.error_code, Some(AivmErrorCode::State));
        assert_eq!(state.state_root(), root_before);
        let get = call_synq_contract(
            &checked_in_counter_request(COUNTER_GET_SELECTOR.to_vec(), 20_000),
            &mut state,
        );
        assert_eq!(decode_u256(&get.return_data), 1);
    }

    #[test]
    fn admission_pq_gas_is_preserved_in_stateful_receipts() {
        let mut state = ContractState::default();
        let mut request = checked_in_counter_request(Vec::new(), 20_000);
        request.context.admission_pq_gas_used = 42;

        let receipt = deploy_synq_contract(&request, &mut state);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(receipt.pqc_gas_used, 42);
        assert_eq!(receipt.execution_receipt().pqc_gas_used, 42);
    }

    #[test]
    fn non_counter_deploy_before_activation_preserves_counter_only_failure() {
        let mut state = ContractState::default();
        let root_before = state.state_root();
        let request = generic_token_request(466_625);

        let receipt = deploy_synq_contract(&request, &mut state);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::Manifest));
        assert!(receipt
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("only Counter is enabled in this AIVM path"));
        assert_eq!(state.state_root(), root_before);
    }

    #[test]
    fn non_counter_deploy_after_activation_initializes_token_state() {
        let mut state = ContractState::default();
        let request = generic_token_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT);
        let namespace = request.contract_id.as_bytes().to_vec();

        let receipt = deploy_synq_contract(&request, &mut state);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert!(receipt
            .logs
            .contains(&"synq.deploy.contract=STS9HorizonToken".to_string()));
        assert!(receipt.logs.contains(&"synq.token.symbol=HRZN".to_string()));
        let encoded_supply = encode_u256_u128(1_000_000_000_000_000_000);
        assert_eq!(
            state.get(&StateKey::new(
                namespace.clone(),
                b"token_total_supply".to_vec()
            )),
            Some(encoded_supply.as_slice())
        );
        assert_eq!(
            state.get(&StateKey::new(
                namespace,
                b"balance:synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war".to_vec()
            )),
            Some(encoded_supply.as_slice())
        );
    }

    #[test]
    fn sts9_token_balance_of_reads_initialized_holder_balance() {
        let mut state = ContractState::default();
        let deploy = deploy_synq_contract(
            &generic_token_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT),
            &mut state,
        );
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);

        let calldata = sts9_calldata(
            STS9_BALANCE_OF_SELECTOR,
            serde_json::json!(["synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war"]),
        );
        let receipt = call_synq_contract(
            &generic_token_call_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT, calldata),
            &mut state,
        );

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(
            decode_u256_u128(&receipt.return_data),
            1_000_000_000_000_000_000
        );
        assert!(receipt
            .logs
            .contains(&"synq.token.call=balance_of".to_string()));
    }

    #[test]
    fn sts9_token_transfer_moves_balances_between_synergy_addresses() {
        let mut state = ContractState::default();
        let deploy = deploy_synq_contract(
            &generic_token_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT),
            &mut state,
        );
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);
        let root_before = state.state_root();
        let recipient = "synw1recipient000000000000000000000000000";
        let amount = 1_500_000_000_u128;

        let calldata = sts9_calldata(
            STS9_TRANSFER_SELECTOR,
            serde_json::json!([recipient, amount.to_string()]),
        );
        let receipt = call_synq_contract(
            &generic_token_call_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT, calldata),
            &mut state,
        );

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(decode_u256(&receipt.return_data), 1);
        assert_ne!(state.state_root(), root_before);
        let namespace = "sync1jehgp37lhxfh3gkp7nepcfxe908kl4kelacw"
            .as_bytes()
            .to_vec();
        let expected_sender_balance = encode_u256_u128(1_000_000_000_000_000_000 - amount);
        let expected_recipient_balance = encode_u256_u128(amount);
        assert_eq!(
            state.get(&StateKey::new(
                namespace.clone(),
                b"balance:synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war".to_vec()
            )),
            Some(expected_sender_balance.as_slice())
        );
        assert_eq!(
            state.get(&StateKey::new(
                namespace,
                format!("balance:{recipient}").into_bytes()
            )),
            Some(expected_recipient_balance.as_slice())
        );
    }

    #[test]
    fn sts_host_balance_reads_supplied_native_snapshot() {
        let mut state = ContractState::default();
        let deploy = deploy_synq_contract(
            &generic_token_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT),
            &mut state,
        );
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);

        let token_id = "synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd";
        let owner = "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war";
        let mut host = StsHostContext::default();
        host.object_classes.insert(token_id.to_string(), 1);
        host.fungible_tokens.insert(
            token_id.to_string(),
            crate::execution::StsHostFungibleToken {
                class: 1,
                total_supply: 9_000,
            },
        );
        host.fungible_balances
            .insert(StsHostContext::fungible_balance_key(token_id, owner), 7_500);

        let mut request = generic_token_call_request(
            GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT,
            sts_host_calldata(STS_BALANCE_SELECTOR, serde_json::json!([token_id, owner])),
        );
        request.context.sts_host = Some(host);
        let receipt = call_synq_contract(&request, &mut state);

        assert_eq!(receipt.status, ExecutionStatus::Succeeded);
        assert_eq!(decode_u256_u128(&receipt.return_data), 7_500);
        assert!(receipt
            .logs
            .iter()
            .any(|log| log == "sts.host.call=sts_balance"));
    }

    #[test]
    fn sts_host_write_selectors_fail_closed() {
        let mut state = ContractState::default();
        let deploy = deploy_synq_contract(
            &generic_token_request(GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT),
            &mut state,
        );
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);

        let mut request = generic_token_call_request(
            GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT,
            sts_host_calldata(
                STS_MINT_SELECTOR,
                serde_json::json!([
                    "synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd",
                    "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war",
                    "1"
                ]),
            ),
        );
        request.context.sts_host = Some(StsHostContext::default());
        let receipt = call_synq_contract(&request, &mut state);

        assert_eq!(receipt.status, ExecutionStatus::Failed);
        assert_eq!(receipt.error_code, Some(AivmErrorCode::HostFunction));
        assert!(receipt
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("read-only STS host surface"));
    }

    fn checked_in_counter_request(calldata: Vec<u8>, gas_limit: u64) -> ExecutionRequest {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../synq-language/contracts");
        let bytecode = fs::read(root.join("Counter.compiled.synq")).expect("Counter bytecode");
        let abi_json = fs::read_to_string(root.join("Counter.abi.json")).expect("Counter ABI");
        let manifest_json =
            fs::read_to_string(root.join("Counter.manifest.json")).expect("Counter manifest");
        let artifact = ContractArtifact {
            format: crate::execution::ContractFormat::SynqBytecodeV1,
            bytes: bytecode,
            abi_json: Some(abi_json),
            manifest_json: Some(manifest_json),
            metadata_json: None,
            compiler_version: None,
            source_hash: None,
        };
        synq_execution_request(
            "Counter",
            artifact,
            ExecutionContext::testnet_1266_for_contract("Counter", gas_limit),
            calldata,
        )
    }

    fn generic_token_request(runtime_block_height: u64) -> ExecutionRequest {
        generic_token_request_with_calldata(runtime_block_height, Vec::new())
    }

    fn generic_token_call_request(
        runtime_block_height: u64,
        calldata: Vec<u8>,
    ) -> ExecutionRequest {
        generic_token_request_with_calldata(runtime_block_height, calldata)
    }

    fn generic_token_request_with_calldata(
        runtime_block_height: u64,
        calldata: Vec<u8>,
    ) -> ExecutionRequest {
        let contract_id = "sync1jehgp37lhxfh3gkp7nepcfxe908kl4kelacw";
        let bytecode = b"generic-token-bytecode".to_vec();
        let abi_json = serde_json::json!({
            "abi_version": "0.1",
            "contract": "STS9HorizonToken",
            "methods": [
                {"name": "total_supply", "mutability": "view", "selector": "0xe3d61a97"},
                {"name": "balance_of", "mutability": "view", "selector": "0xc0bb20c3"},
                {"name": "transfer", "mutability": "write", "selector": "0x63252e1a"}
            ]
        })
        .to_string();
        let manifest_json = serde_json::json!({
            "abi_hash": sha256_hex(abi_json.as_bytes()),
            "artifact_format": "synq-bytecode-v1",
            "bytecode_hash": sha256_hex(&bytecode),
            "bytecode_version": 1,
            "compiler_version": "0.1.0",
            "contract_name": "STS9HorizonToken",
            "host_functions": [],
            "manifest_version": "0.1",
            "permissions": [],
            "required_aivm_version": "0.1",
            "required_chain_id": 1266,
            "required_network_id": "synergy-testnet",
            "required_signature_algorithm": "ML-DSA-87",
            "security_policy": "synq-testnet-1266-v1",
            "source_hash": "test-source",
            "storage_schema_hash": "test-storage"
        })
        .to_string();
        let metadata_json = serde_json::json!({
            "contract_name": "STS9HorizonToken",
            "standard_id": "STS-9",
            "token_name": "Horizon Token",
            "token_symbol": "HRZN",
            "chain_id": 1266,
            "network_id": "synergy-testnet",
            "decimals": 9,
            "initial_supply_base_units": "1000000000000000000",
            "max_supply_base_units": "1000000000000000000",
            "issuer_address": "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war",
            "genesis_recipient": "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war",
            "initial_holder": "synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war",
            "contract_address": contract_id,
            "verification_status": "verified"
        })
        .to_string();
        let artifact = ContractArtifact {
            format: crate::execution::ContractFormat::SynqBytecodeV1,
            bytes: bytecode,
            abi_json: Some(abi_json),
            manifest_json: Some(manifest_json),
            metadata_json: Some(metadata_json),
            compiler_version: None,
            source_hash: None,
        };
        let mut context = ExecutionContext::testnet_1266_for_contract(contract_id, 20_000);
        context.runtime_block_height = runtime_block_height;
        context.caller = b"synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war".to_vec();
        synq_execution_request(contract_id, artifact, context, calldata)
    }

    fn decode_u256(data: &[u8]) -> u64 {
        if data.len() == 32 {
            return u64::from_be_bytes(data[24..32].try_into().expect("u64 tail"));
        }
        match serde_json::from_slice::<crate::stateful_synq::SynQValue>(data)
            .expect("stateful SynQ return value")
        {
            crate::stateful_synq::SynQValue::Uint(value) => {
                u64::try_from(value).expect("u64 stateful value")
            }
            value => panic!("expected stateful uint, found {value:?}"),
        }
    }

    fn decode_u256_u128(data: &[u8]) -> u128 {
        assert_eq!(data.len(), 32);
        u128::from_be_bytes(data[16..32].try_into().expect("u128 tail"))
    }

    fn sts9_calldata(selector: [u8; 4], args: serde_json::Value) -> Vec<u8> {
        let mut calldata = selector.to_vec();
        calldata.extend_from_slice(&serde_json::to_vec(&args).expect("json args"));
        calldata
    }

    fn sts_host_calldata(selector: [u8; 4], args: serde_json::Value) -> Vec<u8> {
        sts9_calldata(selector, args)
    }
}
