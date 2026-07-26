use crate::error::{AivmError, AivmErrorCode};
use crate::execution::{ContractArtifact, ExecutionContext, SynQManifestArtifact};
use crate::metering::AivmGasMeter;
use crate::state::{ContractState, StateKey, StateOverlay};
use pqsynq::{signature::verify_signature, AlgorithmId, SynQPublicKey, SynQSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use synq_compiler::ast::{
    BinaryOp, Block, ConstructorDefinition, ContractDefinition, ContractPart, Expression,
    FunctionDefinition, Literal, Parameter, SourceUnit, Statement, Type, UnaryOp,
};
use synq_compiler::StatefulSynQExecutable;

const STATEMENT_GAS: u64 = 8;
const EXPRESSION_GAS: u64 = 3;
const STATE_READ_GAS: u64 = 15;
const STATE_WRITE_GAS: u64 = 35;
const HOST_CALL_GAS: u64 = 40;
const MLDSA_VERIFY_PQ_GAS: u64 = 35_000;
const MAX_CALL_DEPTH: usize = 32;
const MAX_LOOP_ITERATIONS: u128 = 10_000;
const STATE_PREFIX: &str = "synq-v2:";
const DEPLOYED_KEY: &str = "__deployed";
const NATIVE_NAMESPACE: &[u8] = b"__synergy_native_balances_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SynQValue {
    Uint(u128),
    Int(i128),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    Address(String),
    Array(Vec<SynQValue>),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQNativeTransfer {
    pub from: String,
    pub to: String,
    pub amount_nwei: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatefulSynQOutcome {
    pub return_data: Vec<u8>,
    pub logs: Vec<String>,
    pub native_transfers: Vec<SynQNativeTransfer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatefulSynQFailure {
    pub error: AivmError,
    pub reverted: bool,
}

impl StatefulSynQFailure {
    fn failed(code: AivmErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: AivmError::new(code, message),
            reverted: false,
        }
    }

    fn reverted(message: impl Into<String>) -> Self {
        Self {
            error: AivmError::new(AivmErrorCode::RuntimeTrap, message),
            reverted: true,
        }
    }
}

type RuntimeResult<T> = Result<T, StatefulSynQFailure>;

#[derive(Debug)]
enum ControlFlow {
    Continue,
    Return(SynQValue),
}

pub fn decode_stateful_contract(
    executable: &StatefulSynQExecutable,
) -> RuntimeResult<ContractDefinition> {
    let mut contracts = executable
        .source_units
        .iter()
        .filter_map(|unit| match unit {
            SourceUnit::Contract(contract) => Some(contract.clone()),
            _ => None,
        });
    let contract = contracts.next().ok_or_else(|| {
        StatefulSynQFailure::failed(
            AivmErrorCode::Bytecode,
            "stateful SynQ executable has no contract definition",
        )
    })?;
    if contracts.next().is_some() {
        return Err(StatefulSynQFailure::failed(
            AivmErrorCode::Bytecode,
            "stateful SynQ executable must contain exactly one contract",
        ));
    }
    Ok(contract)
}

pub fn deploy_stateful_synq(
    executable: &StatefulSynQExecutable,
    manifest: &SynQManifestArtifact,
    calldata: &[u8],
    context: &ExecutionContext,
    contract_id: &str,
    state: &ContractState,
    overlay: &mut StateOverlay,
    meter: &mut AivmGasMeter,
) -> RuntimeResult<StatefulSynQOutcome> {
    let contract = decode_stateful_contract(executable)?;
    ensure_manifest_contract(manifest, &contract)?;
    let mut interpreter = Interpreter::new(
        contract,
        manifest,
        context,
        contract_id,
        state,
        overlay,
        meter,
    );
    interpreter.deploy(calldata)
}

pub fn call_stateful_synq(
    executable: &StatefulSynQExecutable,
    manifest: &SynQManifestArtifact,
    method_name: &str,
    encoded_args: &[u8],
    context: &ExecutionContext,
    contract_id: &str,
    state: &ContractState,
    overlay: &mut StateOverlay,
    meter: &mut AivmGasMeter,
) -> RuntimeResult<StatefulSynQOutcome> {
    let contract = decode_stateful_contract(executable)?;
    ensure_manifest_contract(manifest, &contract)?;
    let mut interpreter = Interpreter::new(
        contract,
        manifest,
        context,
        contract_id,
        state,
        overlay,
        meter,
    );
    interpreter.call(method_name, encoded_args)
}

fn ensure_manifest_contract(
    manifest: &SynQManifestArtifact,
    contract: &ContractDefinition,
) -> RuntimeResult<()> {
    if manifest.contract_name != contract.name {
        return Err(StatefulSynQFailure::failed(
            AivmErrorCode::Manifest,
            format!(
                "stateful SynQ executable contract {} does not match manifest {}",
                contract.name, manifest.contract_name
            ),
        ));
    }
    Ok(())
}

struct Interpreter<'a> {
    contract: ContractDefinition,
    allowed_host_functions: BTreeSet<String>,
    context: &'a ExecutionContext,
    contract_id: &'a str,
    state: &'a ContractState,
    overlay: &'a mut StateOverlay,
    meter: &'a mut AivmGasMeter,
    frames: Vec<BTreeMap<String, SynQValue>>,
    logs: Vec<String>,
    native_transfers: Vec<SynQNativeTransfer>,
    call_depth: usize,
}

impl<'a> Interpreter<'a> {
    fn new(
        contract: ContractDefinition,
        manifest: &SynQManifestArtifact,
        context: &'a ExecutionContext,
        contract_id: &'a str,
        state: &'a ContractState,
        overlay: &'a mut StateOverlay,
        meter: &'a mut AivmGasMeter,
    ) -> Self {
        Self {
            contract,
            allowed_host_functions: manifest.host_functions.iter().cloned().collect(),
            context,
            contract_id,
            state,
            overlay,
            meter,
            frames: Vec::new(),
            logs: Vec::new(),
            native_transfers: Vec::new(),
            call_depth: 0,
        }
    }

    fn deploy(&mut self, calldata: &[u8]) -> RuntimeResult<StatefulSynQOutcome> {
        if self.is_deployed(self.contract_id) {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::State,
                "SynQ deploy precondition failed: contract is already deployed",
            ));
        }
        self.credit_call_value()?;
        self.initialize_state_variables()?;
        let constructor = self.contract.parts.iter().find_map(|part| match part {
            ContractPart::Constructor(constructor) => Some(constructor.clone()),
            _ => None,
        });
        match constructor {
            Some(constructor) => {
                let args = decode_arguments(calldata, &constructor.params)?;
                self.invoke_constructor(&constructor, args)?;
            }
            None if !calldata.is_empty() && calldata != b"[]" => {
                return Err(StatefulSynQFailure::failed(
                    AivmErrorCode::Abi,
                    "constructor arguments supplied to contract without constructor",
                ))
            }
            None => {}
        }
        self.write_raw(self.contract_id, DEPLOYED_KEY, vec![1])?;
        Ok(self.outcome(SynQValue::Null)?)
    }

    fn call(
        &mut self,
        method_name: &str,
        encoded_args: &[u8],
    ) -> RuntimeResult<StatefulSynQOutcome> {
        if !self.is_deployed(self.contract_id) {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::State,
                "SynQ call precondition failed: contract has not been deployed",
            ));
        }
        let function = self.function(method_name).ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                format!("SynQ method {method_name} is not present in executable"),
            )
        })?;
        if !function.is_public {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                format!("SynQ method {method_name} is not public"),
            ));
        }
        self.credit_call_value()?;
        let args = decode_arguments(encoded_args, &function.params)?;
        let value = self.invoke_function(&function, args)?;
        self.outcome(value)
    }

    fn outcome(&self, value: SynQValue) -> RuntimeResult<StatefulSynQOutcome> {
        let return_data = serde_json::to_vec(&value).map_err(|error| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Receipt,
                format!("encode SynQ return value: {error}"),
            )
        })?;
        Ok(StatefulSynQOutcome {
            return_data,
            logs: self.logs.clone(),
            native_transfers: self.native_transfers.clone(),
        })
    }

    fn initialize_state_variables(&mut self) -> RuntimeResult<()> {
        let declarations: Vec<_> = self
            .contract
            .parts
            .iter()
            .filter_map(|part| match part {
                ContractPart::StateVariable(variable) => Some(variable.clone()),
                _ => None,
            })
            .collect();
        for variable in declarations {
            if !matches!(variable.ty, Type::Mapping(_, _)) {
                self.write_state_value(
                    self.contract_id,
                    &variable.name,
                    &[],
                    default_value(&variable.ty),
                )?;
            }
        }
        Ok(())
    }

    fn invoke_constructor(
        &mut self,
        constructor: &ConstructorDefinition,
        args: Vec<SynQValue>,
    ) -> RuntimeResult<()> {
        self.push_frame(&constructor.params, args)?;
        let result = self.execute_block(&constructor.body);
        self.frames.pop();
        match result? {
            ControlFlow::Continue | ControlFlow::Return(SynQValue::Null) => Ok(()),
            ControlFlow::Return(_) => Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                "constructor cannot return a value",
            )),
        }
    }

    fn invoke_function(
        &mut self,
        function: &FunctionDefinition,
        args: Vec<SynQValue>,
    ) -> RuntimeResult<SynQValue> {
        if self.call_depth >= MAX_CALL_DEPTH {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                "maximum SynQ call depth exceeded",
            ));
        }
        self.call_depth += 1;
        self.push_frame(&function.params, args)?;
        let result = self.execute_block(&function.body);
        self.frames.pop();
        self.call_depth -= 1;
        match result? {
            ControlFlow::Return(value) => Ok(value),
            ControlFlow::Continue if function.returns.is_none() => Ok(SynQValue::Null),
            ControlFlow::Continue => Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                format!(
                    "function {} completed without a return value",
                    function.name
                ),
            )),
        }
    }

    fn push_frame(&mut self, params: &[Parameter], args: Vec<SynQValue>) -> RuntimeResult<()> {
        if params.len() != args.len() {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                format!(
                    "SynQ argument count mismatch: expected {}, found {}",
                    params.len(),
                    args.len()
                ),
            ));
        }
        let frame = params
            .iter()
            .zip(args)
            .map(|(param, value)| (param.name.clone(), value))
            .collect();
        self.frames.push(frame);
        Ok(())
    }

    fn execute_block(&mut self, block: &Block) -> RuntimeResult<ControlFlow> {
        for statement in &block.statements {
            self.meter
                .charge_gas(STATEMENT_GAS)
                .map_err(runtime_failure)?;
            match self.execute_statement(statement)? {
                ControlFlow::Continue => {}
                returned => return Ok(returned),
            }
        }
        Ok(ControlFlow::Continue)
    }

    fn execute_statement(&mut self, statement: &Statement) -> RuntimeResult<ControlFlow> {
        match statement {
            Statement::Expression(expression) => {
                self.evaluate(expression)?;
                Ok(ControlFlow::Continue)
            }
            Statement::VariableDeclaration(name, ty, initializer) => {
                let value = match initializer {
                    Some(expression) => self.evaluate(expression)?,
                    None => default_value(ty),
                };
                let frame = self.frames.last_mut().ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::InternalInvariant,
                        "SynQ local declaration without a frame",
                    )
                })?;
                frame.insert(name.clone(), value);
                Ok(ControlFlow::Continue)
            }
            Statement::Assignment(target, expression) => {
                let value = self.evaluate(expression)?;
                self.assign(target, value)?;
                Ok(ControlFlow::Continue)
            }
            Statement::Return(expression) => Ok(ControlFlow::Return(match expression {
                Some(expression) => self.evaluate(expression)?,
                None => SynQValue::Null,
            })),
            Statement::Require(condition, message) => {
                if !self.evaluate(condition)?.as_bool()? {
                    return Err(StatefulSynQFailure::reverted(format!(
                        "require failed: {message}"
                    )));
                }
                Ok(ControlFlow::Continue)
            }
            Statement::Revert(message) => Err(StatefulSynQFailure::reverted(message.clone())),
            Statement::If(condition, then_block, else_block) => {
                if self.evaluate(condition)?.as_bool()? {
                    self.execute_block(then_block)
                } else if let Some(else_block) = else_block {
                    self.execute_block(else_block)
                } else {
                    Ok(ControlFlow::Continue)
                }
            }
            Statement::For(iterator, start, end, body) => {
                let start = self.evaluate(start)?.as_uint()?;
                let end = self.evaluate(end)?.as_uint()?;
                let iterations = end.saturating_sub(start);
                if iterations > MAX_LOOP_ITERATIONS {
                    return Err(StatefulSynQFailure::failed(
                        AivmErrorCode::Gas,
                        format!("SynQ loop exceeds {MAX_LOOP_ITERATIONS} iterations"),
                    ));
                }
                for value in start..end {
                    self.set_local(iterator, SynQValue::Uint(value))?;
                    match self.execute_block(body)? {
                        ControlFlow::Continue => {}
                        returned => return Ok(returned),
                    }
                }
                Ok(ControlFlow::Continue)
            }
            Statement::Emit(name, args) => {
                let values = args
                    .iter()
                    .map(|arg| self.evaluate(arg))
                    .collect::<RuntimeResult<Vec<_>>>()?;
                let encoded = serde_json::to_string(&values).map_err(|error| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::Receipt,
                        format!("encode SynQ event: {error}"),
                    )
                })?;
                self.logs.push(format!("synq.event.{name}={encoded}"));
                Ok(ControlFlow::Continue)
            }
            Statement::RequirePqc(block, fallback) => {
                let overlay_before = self.overlay.clone();
                let frames_before = self.frames.clone();
                match self.execute_block(block) {
                    Ok(ControlFlow::Continue) => Ok(ControlFlow::Continue),
                    Ok(returned) => Ok(returned),
                    Err(_) => {
                        *self.overlay = overlay_before;
                        self.frames = frames_before;
                        match fallback {
                            Some(statement) => self.execute_statement(statement),
                            None => Err(StatefulSynQFailure::reverted("PQC verification failed")),
                        }
                    }
                }
            }
        }
    }

    fn evaluate(&mut self, expression: &Expression) -> RuntimeResult<SynQValue> {
        self.meter
            .charge_gas(EXPRESSION_GAS)
            .map_err(runtime_failure)?;
        match expression {
            Expression::Literal(literal) => Ok(value_from_literal(literal)),
            Expression::Identifier(name) => self.lookup(name),
            Expression::MemberAccess(object, member) => self.evaluate_member(object, member),
            Expression::IndexAccess(_, _) => self.evaluate_index(expression),
            Expression::Call(name, args) => self.evaluate_call(name, args),
            Expression::Binary(op, left, right) => {
                let left = self.evaluate(left)?;
                if *op == BinaryOp::And && !left.as_bool()? {
                    return Ok(SynQValue::Bool(false));
                }
                if *op == BinaryOp::Or && left.as_bool()? {
                    return Ok(SynQValue::Bool(true));
                }
                let right = self.evaluate(right)?;
                evaluate_binary(op, left, right)
            }
            Expression::Unary(op, expression) => {
                let value = self.evaluate(expression)?;
                match op {
                    UnaryOp::Not => Ok(SynQValue::Bool(!value.as_bool()?)),
                    UnaryOp::Neg => Ok(SynQValue::Int(
                        value
                            .as_uint()?
                            .try_into()
                            .map(|value: i128| -value)
                            .map_err(|_| {
                                StatefulSynQFailure::failed(
                                    AivmErrorCode::RuntimeTrap,
                                    "SynQ integer negation overflow",
                                )
                            })?,
                    )),
                    UnaryOp::Inc | UnaryOp::Dec => Err(StatefulSynQFailure::failed(
                        AivmErrorCode::RuntimeTrap,
                        "increment/decrement expressions are unsupported outside normalized loops",
                    )),
                }
            }
            Expression::Ternary(condition, then_expression, else_expression) => {
                if self.evaluate(condition)?.as_bool()? {
                    self.evaluate(then_expression)
                } else {
                    self.evaluate(else_expression)
                }
            }
        }
    }

    fn evaluate_member(&mut self, object: &Expression, member: &str) -> RuntimeResult<SynQValue> {
        if matches!(object, Expression::Identifier(name) if name == "msg") {
            return match member {
                "sender" => Ok(SynQValue::Address(caller_string(self.context))),
                "value" => Ok(SynQValue::Uint(self.context.call_value)),
                _ => Err(unknown_member("msg", member)),
            };
        }
        if matches!(object, Expression::Identifier(name) if name == "block") {
            return match member {
                "number" => Ok(SynQValue::Uint(self.context.block_height as u128)),
                "timestamp" => Ok(SynQValue::Uint(self.context.block_timestamp_unix as u128)),
                _ => Err(unknown_member("block", member)),
            };
        }
        let value = self.evaluate(object)?;
        match (value, member) {
            (SynQValue::Array(values), "length") => Ok(SynQValue::Uint(values.len() as u128)),
            (SynQValue::Bytes(values), "length") => Ok(SynQValue::Uint(values.len() as u128)),
            (SynQValue::String(value), "length") => {
                Ok(SynQValue::Uint(value.chars().count() as u128))
            }
            _ => Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                format!("unsupported SynQ member access .{member}"),
            )),
        }
    }

    fn evaluate_index(&mut self, expression: &Expression) -> RuntimeResult<SynQValue> {
        if let Some((root, indices)) = decompose_index_access(expression) {
            if let Some(ty) = self.state_variable_type(root) {
                let keys = indices
                    .iter()
                    .map(|index| self.evaluate(index))
                    .collect::<RuntimeResult<Vec<_>>>()?;
                return self.read_state_value(self.contract_id, root, &keys, &ty);
            }
        }
        let Expression::IndexAccess(object, index) = expression else {
            unreachable!()
        };
        let object = self.evaluate(object)?;
        let index = self.evaluate(index)?.as_uint()?;
        match object {
            SynQValue::Array(values) => values.get(index as usize).cloned().ok_or_else(|| {
                StatefulSynQFailure::reverted(format!("array index {index} out of bounds"))
            }),
            SynQValue::Bytes(values) => values
                .get(index as usize)
                .copied()
                .map(|value| SynQValue::Uint(value as u128))
                .ok_or_else(|| {
                    StatefulSynQFailure::reverted(format!("byte index {index} out of bounds"))
                }),
            _ => Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                "index access requires an array, bytes, or mapping",
            )),
        }
    }

    fn evaluate_call(&mut self, name: &str, args: &[Expression]) -> RuntimeResult<SynQValue> {
        let values = args
            .iter()
            .map(|arg| self.evaluate(arg))
            .collect::<RuntimeResult<Vec<_>>>()?;
        match name {
            "Address" => Ok(SynQValue::Address(
                values
                    .first()
                    .map(address_string)
                    .transpose()?
                    .unwrap_or_default(),
            )),
            "Bytes" => Ok(SynQValue::Bytes(
                values
                    .first()
                    .map(value_bytes)
                    .transpose()?
                    .unwrap_or_default(),
            )),
            "String" => Ok(SynQValue::String(
                values
                    .first()
                    .map(value_string)
                    .transpose()?
                    .unwrap_or_default(),
            )),
            "verifyMLDSASignature" => self.verify_mldsa(&values),
            "sendNative" => self.send_native(&values),
            "synidNormalize" => self.synid_normalize(&values),
            "synidNameHash" => self.synid_name_hash(&values),
            "registryIsKnownValidator"
            | "registryIsActiveValidator"
            | "registryValidatorSelfStake"
            | "registryReduceSelfStake"
            | "registryJailValidator"
            | "registryTombstoneValidator"
            | "stakingSlashSelfStake"
            | "stakingVotingPower"
            | "stakingTotalVotingPower" => self.registry_or_staking_host(name, &values),
            "callContract" => self.call_contract(&values),
            qualified if qualified.ends_with(".push") => {
                let root = qualified.trim_end_matches(".push");
                let value = values.first().cloned().ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::Abi,
                        "array push requires one argument",
                    )
                })?;
                self.push_array(root, value)?;
                Ok(SynQValue::Null)
            }
            function_name => {
                let function = self.function(function_name).ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::HostFunction,
                        format!("unknown SynQ function {function_name}"),
                    )
                })?;
                self.invoke_function(&function, values)
            }
        }
    }

    fn assign(&mut self, target: &Expression, value: SynQValue) -> RuntimeResult<()> {
        match target {
            Expression::Identifier(name) if self.has_local(name) => self.set_local(name, value),
            Expression::Identifier(name) if self.state_variable_type(name).is_some() => {
                self.write_state_value(self.contract_id, name, &[], value)
            }
            Expression::IndexAccess(_, _) => {
                let (root, index_expressions) =
                    decompose_index_access(target).ok_or_else(|| {
                        StatefulSynQFailure::failed(
                            AivmErrorCode::RuntimeTrap,
                            "invalid indexed assignment target",
                        )
                    })?;
                if self.state_variable_type(root).is_none() {
                    return Err(StatefulSynQFailure::failed(
                        AivmErrorCode::RuntimeTrap,
                        "indexed local assignment is not supported",
                    ));
                }
                let indices = index_expressions
                    .iter()
                    .map(|index| self.evaluate(index))
                    .collect::<RuntimeResult<Vec<_>>>()?;
                self.write_state_value(self.contract_id, root, &indices, value)
            }
            _ => Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                "invalid SynQ assignment target",
            )),
        }
    }

    fn lookup(&mut self, name: &str) -> RuntimeResult<SynQValue> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(name) {
                return Ok(value.clone());
            }
        }
        let ty = self.state_variable_type(name).ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                format!("undefined SynQ symbol {name}"),
            )
        })?;
        self.read_state_value(self.contract_id, name, &[], &ty)
    }

    fn has_local(&self, name: &str) -> bool {
        self.frames
            .iter()
            .rev()
            .any(|frame| frame.contains_key(name))
    }

    fn set_local(&mut self, name: &str, value: SynQValue) -> RuntimeResult<()> {
        if let Some(frame) = self
            .frames
            .iter_mut()
            .rev()
            .find(|frame| frame.contains_key(name))
        {
            frame.insert(name.to_string(), value);
            return Ok(());
        }
        let frame = self.frames.last_mut().ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::InternalInvariant,
                "SynQ local assignment without a frame",
            )
        })?;
        frame.insert(name.to_string(), value);
        Ok(())
    }

    fn function(&self, name: &str) -> Option<FunctionDefinition> {
        self.contract.parts.iter().find_map(|part| match part {
            ContractPart::Function(function) if function.name == name => Some(function.clone()),
            _ => None,
        })
    }

    fn state_variable_type(&self, name: &str) -> Option<Type> {
        self.contract.parts.iter().find_map(|part| match part {
            ContractPart::StateVariable(variable) if variable.name == name => {
                Some(variable.ty.clone())
            }
            _ => None,
        })
    }

    fn read_state_value(
        &mut self,
        namespace: &str,
        root: &str,
        indices: &[SynQValue],
        ty: &Type,
    ) -> RuntimeResult<SynQValue> {
        self.meter
            .charge_gas(STATE_READ_GAS)
            .map_err(runtime_failure)?;
        let key = StateKey::new(
            namespace.as_bytes().to_vec(),
            storage_key(root, indices).into_bytes(),
        );
        match self.overlay.read(self.state, &key) {
            Some(bytes) => serde_json::from_slice(bytes).map_err(|error| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::State,
                    format!("decode SynQ state {root}: {error}"),
                )
            }),
            None => Ok(default_value(&indexed_value_type(ty, indices.len()))),
        }
    }

    fn write_state_value(
        &mut self,
        namespace: &str,
        root: &str,
        indices: &[SynQValue],
        value: SynQValue,
    ) -> RuntimeResult<()> {
        let bytes = serde_json::to_vec(&value).map_err(|error| {
            StatefulSynQFailure::failed(
                AivmErrorCode::State,
                format!("encode SynQ state {root}: {error}"),
            )
        })?;
        self.write_raw(namespace, &storage_key(root, indices), bytes)
    }

    fn write_raw(&mut self, namespace: &str, key: &str, value: Vec<u8>) -> RuntimeResult<()> {
        self.meter
            .charge_gas(STATE_WRITE_GAS)
            .map_err(runtime_failure)?;
        self.overlay.write(
            StateKey::new(namespace.as_bytes().to_vec(), key.as_bytes().to_vec()),
            value,
        );
        Ok(())
    }

    fn is_deployed(&self, namespace: &str) -> bool {
        self.overlay
            .read(
                self.state,
                &StateKey::new(
                    namespace.as_bytes().to_vec(),
                    DEPLOYED_KEY.as_bytes().to_vec(),
                ),
            )
            .is_some()
    }

    fn push_array(&mut self, root: &str, value: SynQValue) -> RuntimeResult<()> {
        let ty = self.state_variable_type(root).ok_or_else(|| {
            StatefulSynQFailure::failed(AivmErrorCode::RuntimeTrap, format!("unknown array {root}"))
        })?;
        if !matches!(ty, Type::Array(_, _)) {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                format!("{root} is not an array"),
            ));
        }
        let mut array = match self.read_state_value(self.contract_id, root, &[], &ty)? {
            SynQValue::Array(values) => values,
            _ => Vec::new(),
        };
        array.push(value);
        self.write_state_value(self.contract_id, root, &[], SynQValue::Array(array))
    }

    fn require_host(&self, name: &str) -> RuntimeResult<()> {
        if self.allowed_host_functions.contains(name) {
            Ok(())
        } else {
            Err(StatefulSynQFailure::failed(
                AivmErrorCode::HostFunction,
                format!("SynQ manifest does not authorize host function {name}"),
            ))
        }
    }

    fn verify_mldsa(&mut self, values: &[SynQValue]) -> RuntimeResult<SynQValue> {
        self.require_host("verifyMLDSASignature")?;
        if values.len() != 3 {
            return Err(argument_error("verifyMLDSASignature", 3, values.len()));
        }
        self.meter
            .charge_pq_gas(MLDSA_VERIFY_PQ_GAS)
            .map_err(runtime_failure)?;
        let public_key = SynQPublicKey::new(value_bytes(&values[0])?);
        let message = value_bytes(&values[1])?;
        let signature = SynQSignature::new(value_bytes(&values[2])?);
        Ok(SynQValue::Bool(
            verify_signature(AlgorithmId::MlDsa65, &message, &signature, &public_key).is_ok(),
        ))
    }

    fn send_native(&mut self, values: &[SynQValue]) -> RuntimeResult<SynQValue> {
        self.require_host("sendNative")?;
        if values.len() != 2 {
            return Err(argument_error("sendNative", 2, values.len()));
        }
        self.meter
            .charge_gas(HOST_CALL_GAS)
            .map_err(runtime_failure)?;
        let to = address_string(&values[0])?;
        let amount = values[1].as_uint()?;
        let from = self.contract_id.to_string();
        let current = self.native_balance(&from)?;
        if current < amount {
            return Err(StatefulSynQFailure::reverted(
                "contract native balance is insufficient",
            ));
        }
        let recipient = self.native_balance(&to)?;
        self.write_native_balance(&from, current - amount)?;
        self.write_native_balance(
            &to,
            recipient.checked_add(amount).ok_or_else(|| {
                StatefulSynQFailure::failed(AivmErrorCode::State, "native balance overflow")
            })?,
        )?;
        self.native_transfers.push(SynQNativeTransfer {
            from,
            to,
            amount_nwei: amount,
        });
        Ok(SynQValue::Null)
    }

    fn call_contract(&mut self, values: &[SynQValue]) -> RuntimeResult<SynQValue> {
        self.require_host("callContract")?;
        if values.len() != 3 {
            return Err(argument_error("callContract", 3, values.len()));
        }
        self.meter
            .charge_gas(HOST_CALL_GAS)
            .map_err(runtime_failure)?;
        let target = address_string(&values[0])?;
        let call_value = values[1].as_uint()?;
        let calldata = value_bytes(&values[2])?;
        let artifact = self
            .context
            .resolved_synq_contracts
            .get(&target)
            .cloned()
            .ok_or_else(|| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::HostFunction,
                    format!("callContract target {target} is not a deployed SynQ contract"),
                )
            })?;
        let (executable, manifest, method_name, encoded_args) =
            resolve_nested_call(&artifact, &calldata)?;

        if call_value > 0 {
            let source_balance = self.native_balance(self.contract_id)?;
            if source_balance < call_value {
                return Err(StatefulSynQFailure::reverted(
                    "contract call value exceeds native balance",
                ));
            }
            self.write_native_balance(self.contract_id, source_balance - call_value)?;
            self.native_transfers.push(SynQNativeTransfer {
                from: self.contract_id.to_string(),
                to: target.clone(),
                amount_nwei: call_value,
            });
        }

        let mut child_context = self.context.clone();
        child_context.caller = self.contract_id.as_bytes().to_vec();
        child_context.contract_address = target.as_bytes().to_vec();
        child_context.call_value = call_value;
        let child_contract = decode_stateful_contract(&executable)?;
        ensure_manifest_contract(&manifest, &child_contract)?;
        let mut child = Interpreter::new(
            child_contract,
            &manifest,
            &child_context,
            &target,
            self.state,
            self.overlay,
            self.meter,
        );
        child.call_depth = self.call_depth;
        let outcome = child.call(&method_name, &encoded_args)?;
        drop(child);
        self.logs.extend(outcome.logs);
        self.native_transfers.extend(outcome.native_transfers);
        serde_json::from_slice(&outcome.return_data).map_err(|error| {
            StatefulSynQFailure::failed(
                AivmErrorCode::RuntimeTrap,
                format!("decode nested SynQ return value: {error}"),
            )
        })
    }

    fn native_balance(&mut self, address: &str) -> RuntimeResult<u128> {
        self.meter
            .charge_gas(STATE_READ_GAS)
            .map_err(runtime_failure)?;
        let key = StateKey::new(NATIVE_NAMESPACE.to_vec(), address.as_bytes().to_vec());
        Ok(self
            .overlay
            .read(self.state, &key)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u128::from_be_bytes)
            .unwrap_or(0))
    }

    fn credit_call_value(&mut self) -> RuntimeResult<()> {
        if self.context.call_value == 0 {
            return Ok(());
        }
        let current = self.native_balance(self.contract_id)?;
        self.write_native_balance(
            self.contract_id,
            current
                .checked_add(self.context.call_value)
                .ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::State,
                        "contract native balance overflow",
                    )
                })?,
        )
    }

    fn write_native_balance(&mut self, address: &str, balance: u128) -> RuntimeResult<()> {
        self.meter
            .charge_gas(STATE_WRITE_GAS)
            .map_err(runtime_failure)?;
        self.overlay.write(
            StateKey::new(NATIVE_NAMESPACE.to_vec(), address.as_bytes().to_vec()),
            balance.to_be_bytes().to_vec(),
        );
        Ok(())
    }

    fn synid_normalize(&mut self, values: &[SynQValue]) -> RuntimeResult<SynQValue> {
        self.require_host("synidNormalize")?;
        let value = value_string(
            values
                .first()
                .ok_or_else(|| argument_error("synidNormalize", 1, 0))?,
        )?;
        let normalized = value.trim().to_lowercase();
        if normalized.is_empty()
            || normalized.len() > 64
            || !normalized
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(StatefulSynQFailure::reverted("invalid SynID name"));
        }
        Ok(SynQValue::String(normalized))
    }

    fn synid_name_hash(&mut self, values: &[SynQValue]) -> RuntimeResult<SynQValue> {
        self.require_host("synidNameHash")?;
        let SynQValue::String(normalized) = self.synid_normalize(values)? else {
            unreachable!()
        };
        let mut hasher = Sha256::new();
        hasher.update(b"SYNERGY_SYNID_NAME_V1");
        hasher.update(normalized.as_bytes());
        Ok(SynQValue::Bytes(hasher.finalize().to_vec()))
    }

    fn registry_or_staking_host(
        &mut self,
        name: &str,
        values: &[SynQValue],
    ) -> RuntimeResult<SynQValue> {
        self.require_host(name)?;
        self.meter
            .charge_gas(HOST_CALL_GAS)
            .map_err(runtime_failure)?;
        let target = values
            .first()
            .map(address_string)
            .transpose()?
            .ok_or_else(|| argument_error(name, 1, 0))?;
        if !self.is_deployed(&target) {
            return Err(StatefulSynQFailure::failed(
                AivmErrorCode::HostFunction,
                format!("{name} target {target} is not a deployed SynQ contract"),
            ));
        }
        match name {
            "registryIsKnownValidator" | "registryIsActiveValidator" => {
                let validator = address_string(
                    values
                        .get(1)
                        .ok_or_else(|| argument_error(name, 2, values.len()))?,
                )?;
                let status = self
                    .read_state_value(
                        &target,
                        "validatorStatus",
                        &[SynQValue::Address(validator)],
                        &Type::Mapping(Box::new(Type::Address), Box::new(Type::UInt8)),
                    )?
                    .as_uint()?;
                Ok(SynQValue::Bool(if name == "registryIsActiveValidator" {
                    status == 2
                } else {
                    status != 0
                }))
            }
            "registryValidatorSelfStake" => {
                let validator = address_string(
                    values
                        .get(1)
                        .ok_or_else(|| argument_error(name, 2, values.len()))?,
                )?;
                self.read_state_value(
                    &target,
                    "validatorSelfStake",
                    &[SynQValue::Address(validator)],
                    &Type::Mapping(Box::new(Type::Address), Box::new(Type::UInt256)),
                )
            }
            "registryReduceSelfStake" => {
                let validator = address_string(
                    values
                        .get(1)
                        .ok_or_else(|| argument_error(name, 3, values.len()))?,
                )?;
                let amount = values
                    .get(2)
                    .ok_or_else(|| argument_error(name, 3, values.len()))?
                    .as_uint()?;
                let ty = Type::Mapping(Box::new(Type::Address), Box::new(Type::UInt256));
                let key = SynQValue::Address(validator);
                let old = self
                    .read_state_value(&target, "validatorSelfStake", &[key.clone()], &ty)?
                    .as_uint()?;
                let actual = old.min(amount);
                self.write_state_value(
                    &target,
                    "validatorSelfStake",
                    &[key],
                    SynQValue::Uint(old - actual),
                )?;
                Ok(SynQValue::Uint(actual))
            }
            "registryJailValidator" | "registryTombstoneValidator" => {
                let validator = address_string(
                    values
                        .get(1)
                        .ok_or_else(|| argument_error(name, 2, values.len()))?,
                )?;
                let key = SynQValue::Address(validator.clone());
                self.write_state_value(
                    &target,
                    "validatorStatus",
                    &[key.clone()],
                    SynQValue::Uint(if name == "registryJailValidator" {
                        3
                    } else {
                        5
                    }),
                )?;
                if name == "registryJailValidator" {
                    let until = values
                        .get(2)
                        .ok_or_else(|| argument_error(name, 3, values.len()))?
                        .as_uint()?;
                    self.write_state_value(
                        &target,
                        "validatorJailedUntil",
                        &[key],
                        SynQValue::Uint(until),
                    )?;
                }
                Ok(SynQValue::Null)
            }
            "stakingSlashSelfStake" => {
                let validator = address_string(
                    values
                        .get(1)
                        .ok_or_else(|| argument_error(name, 3, values.len()))?,
                )?;
                let requested = values
                    .get(2)
                    .ok_or_else(|| argument_error(name, 3, values.len()))?
                    .as_uint()?;
                let mapping_ty = Type::Mapping(Box::new(Type::Address), Box::new(Type::UInt256));
                let key = SynQValue::Address(validator);
                let available = self
                    .read_state_value(&target, "selfStakeOf", &[key.clone()], &mapping_ty)?
                    .as_uint()?;
                let actual = available.min(requested);
                self.write_state_value(
                    &target,
                    "selfStakeOf",
                    &[key],
                    SynQValue::Uint(available - actual),
                )?;
                let total = self
                    .read_state_value(&target, "totalSelfStake", &[], &Type::UInt256)?
                    .as_uint()?;
                self.write_state_value(
                    &target,
                    "totalSelfStake",
                    &[],
                    SynQValue::Uint(total.checked_sub(actual).ok_or_else(|| {
                        StatefulSynQFailure::failed(
                            AivmErrorCode::State,
                            "staking total self stake underflow",
                        )
                    })?),
                )?;
                Ok(SynQValue::Uint(actual))
            }
            "stakingVotingPower" => {
                let account = SynQValue::Address(address_string(
                    values
                        .get(1)
                        .ok_or_else(|| argument_error(name, 2, values.len()))?,
                )?);
                let mapping_ty = Type::Mapping(Box::new(Type::Address), Box::new(Type::UInt256));
                let self_stake = self
                    .read_state_value(&target, "selfStakeOf", &[account.clone()], &mapping_ty)?
                    .as_uint()?;
                let delegated = self
                    .read_state_value(&target, "delegatedStakeOf", &[account], &mapping_ty)?
                    .as_uint()?;
                Ok(SynQValue::Uint(
                    self_stake.checked_add(delegated).ok_or_else(|| {
                        StatefulSynQFailure::failed(
                            AivmErrorCode::State,
                            "staking voting power overflow",
                        )
                    })?,
                ))
            }
            "stakingTotalVotingPower" => {
                let self_stake = self
                    .read_state_value(&target, "totalSelfStake", &[], &Type::UInt256)?
                    .as_uint()?;
                let delegated = self
                    .read_state_value(&target, "totalDelegatedStake", &[], &Type::UInt256)?
                    .as_uint()?;
                Ok(SynQValue::Uint(
                    self_stake.checked_add(delegated).ok_or_else(|| {
                        StatefulSynQFailure::failed(
                            AivmErrorCode::State,
                            "staking total voting power overflow",
                        )
                    })?,
                ))
            }
            _ => unreachable!(),
        }
    }
}

impl SynQValue {
    fn as_uint(&self) -> RuntimeResult<u128> {
        match self {
            Self::Uint(value) => Ok(*value),
            Self::Int(value) if *value >= 0 => Ok(*value as u128),
            _ => Err(type_error("unsigned integer", self)),
        }
    }

    fn as_bool(&self) -> RuntimeResult<bool> {
        match self {
            Self::Bool(value) => Ok(*value),
            _ => Err(type_error("boolean", self)),
        }
    }
}

fn decode_arguments(bytes: &[u8], params: &[Parameter]) -> RuntimeResult<Vec<SynQValue>> {
    let raw = if bytes.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice::<Vec<serde_json::Value>>(bytes).map_err(|error| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                format!("decode SynQ JSON arguments: {error}"),
            )
        })?
    };
    if raw.len() != params.len() {
        return Err(StatefulSynQFailure::failed(
            AivmErrorCode::Abi,
            format!(
                "SynQ argument count mismatch: expected {}, found {}",
                params.len(),
                raw.len()
            ),
        ));
    }
    raw.iter()
        .zip(params)
        .map(|(value, param)| value_from_json(value, &param.ty))
        .collect()
}

#[derive(Debug, Deserialize)]
struct NestedSynQAbi {
    methods: Vec<NestedSynQAbiMethod>,
}

#[derive(Debug, Deserialize)]
struct NestedSynQAbiMethod {
    name: String,
    selector: String,
}

fn resolve_nested_call(
    artifact: &ContractArtifact,
    calldata: &[u8],
) -> RuntimeResult<(
    StatefulSynQExecutable,
    SynQManifestArtifact,
    String,
    Vec<u8>,
)> {
    if calldata.len() < 4 {
        return Err(StatefulSynQFailure::failed(
            AivmErrorCode::Abi,
            "nested SynQ call requires a 4-byte selector",
        ));
    }
    let executable = StatefulSynQExecutable::decode(&artifact.bytes)
        .map_err(|message| StatefulSynQFailure::failed(AivmErrorCode::Bytecode, message))?;
    let manifest = artifact
        .manifest_json
        .as_deref()
        .ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Manifest,
                "nested SynQ artifact is missing its manifest",
            )
        })
        .and_then(|json| {
            serde_json::from_str(json).map_err(|error| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::Manifest,
                    format!("decode nested SynQ manifest: {error}"),
                )
            })
        })?;
    let abi: NestedSynQAbi = artifact
        .abi_json
        .as_deref()
        .ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                "nested SynQ artifact is missing its ABI",
            )
        })
        .and_then(|json| {
            serde_json::from_str(json).map_err(|error| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::Abi,
                    format!("decode nested SynQ ABI: {error}"),
                )
            })
        })?;
    let selector = format!("0x{}", hex(&calldata[..4]));
    let method_name = abi
        .methods
        .into_iter()
        .find(|method| method.selector == selector)
        .map(|method| method.name)
        .ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                format!("nested SynQ selector {selector} is not in target ABI"),
            )
        })?;
    Ok((executable, manifest, method_name, calldata[4..].to_vec()))
}

fn value_from_json(value: &serde_json::Value, ty: &Type) -> RuntimeResult<SynQValue> {
    match ty {
        Type::UInt256 | Type::UInt128 | Type::UInt64 | Type::UInt32 | Type::UInt8 => {
            let value = value
                .as_u64()
                .map(u128::from)
                .or_else(|| value.as_str()?.parse::<u128>().ok())
                .ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::Abi,
                        "SynQ unsigned argument must be a JSON number or decimal string",
                    )
                })?;
            Ok(SynQValue::Uint(value))
        }
        Type::Int256 | Type::Int128 | Type::Int64 | Type::Int32 | Type::Int8 => {
            let value = value
                .as_i64()
                .map(i128::from)
                .or_else(|| value.as_str()?.parse::<i128>().ok())
                .ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::Abi,
                        "SynQ signed argument must be a JSON number or decimal string",
                    )
                })?;
            Ok(SynQValue::Int(value))
        }
        Type::Bool => value.as_bool().map(SynQValue::Bool).ok_or_else(|| {
            StatefulSynQFailure::failed(AivmErrorCode::Abi, "SynQ Bool argument must be boolean")
        }),
        Type::String => value
            .as_str()
            .map(|value| SynQValue::String(value.to_string()))
            .ok_or_else(|| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::Abi,
                    "SynQ String argument must be a string",
                )
            }),
        Type::Address => value
            .as_str()
            .map(|value| SynQValue::Address(value.to_string()))
            .ok_or_else(|| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::Abi,
                    "SynQ Address argument must be a string",
                )
            }),
        Type::Bytes
        | Type::MLDSAPublicKey
        | Type::MLDSAKeyPair
        | Type::MLDSASignature
        | Type::FNDSAPublicKey
        | Type::FNDSAKeyPair
        | Type::FNDSASignature
        | Type::MLKEMPublicKey
        | Type::MLKEMKeyPair
        | Type::MLKEMCiphertext
        | Type::SLHDSAPublicKey
        | Type::SLHDSAKeyPair
        | Type::SLHDSASignature => Ok(SynQValue::Bytes(decode_json_bytes(value)?)),
        Type::Array(element, _) => {
            let values = value.as_array().ok_or_else(|| {
                StatefulSynQFailure::failed(
                    AivmErrorCode::Abi,
                    "SynQ array argument must be a JSON array",
                )
            })?;
            Ok(SynQValue::Array(
                values
                    .iter()
                    .map(|value| value_from_json(value, element))
                    .collect::<RuntimeResult<Vec<_>>>()?,
            ))
        }
        Type::Mapping(_, _) | Type::Struct(_) | Type::Generic(_, _) => Err(
            StatefulSynQFailure::failed(AivmErrorCode::Abi, "unsupported SynQ ABI argument type"),
        ),
    }
}

fn decode_json_bytes(value: &serde_json::Value) -> RuntimeResult<Vec<u8>> {
    if let Some(text) = value.as_str() {
        let hex = text.strip_prefix("0x").unwrap_or(text);
        if hex.len() % 2 == 0 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return (0..hex.len())
                .step_by(2)
                .map(|index| {
                    u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| {
                        StatefulSynQFailure::failed(
                            AivmErrorCode::Abi,
                            "invalid SynQ hex bytes argument",
                        )
                    })
                })
                .collect();
        }
        return Ok(text.as_bytes().to_vec());
    }
    value
        .as_array()
        .ok_or_else(|| {
            StatefulSynQFailure::failed(
                AivmErrorCode::Abi,
                "SynQ bytes argument must be a hex string or byte array",
            )
        })?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| {
                    StatefulSynQFailure::failed(
                        AivmErrorCode::Abi,
                        "SynQ byte array contains an invalid byte",
                    )
                })
        })
        .collect()
}

fn value_from_literal(literal: &Literal) -> SynQValue {
    match literal {
        Literal::String(value) => SynQValue::String(value.clone()),
        Literal::Number(value) => SynQValue::Uint(*value as u128),
        Literal::Bool(value) => SynQValue::Bool(*value),
        Literal::Address(value) => SynQValue::Address(value.clone()),
        Literal::Bytes(value) => SynQValue::Bytes(value.clone()),
    }
}

fn default_value(ty: &Type) -> SynQValue {
    match ty {
        Type::Address => SynQValue::Address(String::new()),
        Type::UInt256 | Type::UInt128 | Type::UInt64 | Type::UInt32 | Type::UInt8 => {
            SynQValue::Uint(0)
        }
        Type::Int256 | Type::Int128 | Type::Int64 | Type::Int32 | Type::Int8 => SynQValue::Int(0),
        Type::Bool => SynQValue::Bool(false),
        Type::String => SynQValue::String(String::new()),
        Type::Array(_, _) => SynQValue::Array(Vec::new()),
        Type::Bytes
        | Type::MLDSAPublicKey
        | Type::MLDSAKeyPair
        | Type::MLDSASignature
        | Type::FNDSAPublicKey
        | Type::FNDSAKeyPair
        | Type::FNDSASignature
        | Type::MLKEMPublicKey
        | Type::MLKEMKeyPair
        | Type::MLKEMCiphertext
        | Type::SLHDSAPublicKey
        | Type::SLHDSAKeyPair
        | Type::SLHDSASignature => SynQValue::Bytes(Vec::new()),
        Type::Mapping(_, _) | Type::Struct(_) | Type::Generic(_, _) => SynQValue::Null,
    }
}

fn indexed_value_type(ty: &Type, depth: usize) -> Type {
    let mut current = ty;
    for _ in 0..depth {
        current = match current {
            Type::Mapping(_, value) | Type::Array(value, _) => value,
            other => return other.clone(),
        };
    }
    current.clone()
}

fn decompose_index_access(expression: &Expression) -> Option<(&str, Vec<&Expression>)> {
    fn walk<'a>(expression: &'a Expression, indices: &mut Vec<&'a Expression>) -> Option<&'a str> {
        match expression {
            Expression::Identifier(name) => Some(name),
            Expression::IndexAccess(object, index) => {
                let root = walk(object, indices)?;
                indices.push(index);
                Some(root)
            }
            _ => None,
        }
    }
    let mut indices = Vec::new();
    let root = walk(expression, &mut indices)?;
    Some((root, indices))
}

fn storage_key(root: &str, indices: &[SynQValue]) -> String {
    let mut key = format!("{STATE_PREFIX}{root}");
    for index in indices {
        let bytes = serde_json::to_vec(index).expect("SynQValue serialization is infallible");
        key.push(':');
        key.push_str(&hex(&Sha256::digest(bytes)));
    }
    key
}

fn evaluate_binary(op: &BinaryOp, left: SynQValue, right: SynQValue) -> RuntimeResult<SynQValue> {
    match op {
        BinaryOp::Eq => Ok(SynQValue::Bool(left == right)),
        BinaryOp::Ne => Ok(SynQValue::Bool(left != right)),
        BinaryOp::And => Ok(SynQValue::Bool(left.as_bool()? && right.as_bool()?)),
        BinaryOp::Or => Ok(SynQValue::Bool(left.as_bool()? || right.as_bool()?)),
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            let left = left.as_uint()?;
            let right = right.as_uint()?;
            Ok(SynQValue::Bool(match op {
                BinaryOp::Lt => left < right,
                BinaryOp::Le => left <= right,
                BinaryOp::Gt => left > right,
                BinaryOp::Ge => left >= right,
                _ => unreachable!(),
            }))
        }
        BinaryOp::Add
        | BinaryOp::Sub
        | BinaryOp::Mul
        | BinaryOp::Div
        | BinaryOp::Mod
        | BinaryOp::Shl
        | BinaryOp::Shr => {
            let left = left.as_uint()?;
            let right = right.as_uint()?;
            let value = match op {
                BinaryOp::Add => left.checked_add(right),
                BinaryOp::Sub => left.checked_sub(right),
                BinaryOp::Mul => left.checked_mul(right),
                BinaryOp::Div => (right != 0).then(|| left / right),
                BinaryOp::Mod => (right != 0).then(|| left % right),
                BinaryOp::Shl => u32::try_from(right)
                    .ok()
                    .and_then(|shift| left.checked_shl(shift)),
                BinaryOp::Shr => u32::try_from(right)
                    .ok()
                    .and_then(|shift| left.checked_shr(shift)),
                _ => unreachable!(),
            }
            .ok_or_else(|| {
                StatefulSynQFailure::reverted(
                    "SynQ arithmetic overflow, underflow, or division by zero",
                )
            })?;
            Ok(SynQValue::Uint(value))
        }
    }
}

fn address_string(value: &SynQValue) -> RuntimeResult<String> {
    match value {
        SynQValue::Address(value) | SynQValue::String(value) => Ok(value.clone()),
        SynQValue::Uint(0) => Ok(String::new()),
        _ => Err(type_error("address", value)),
    }
}

fn value_string(value: &SynQValue) -> RuntimeResult<String> {
    match value {
        SynQValue::String(value) | SynQValue::Address(value) => Ok(value.clone()),
        _ => Err(type_error("string", value)),
    }
}

fn value_bytes(value: &SynQValue) -> RuntimeResult<Vec<u8>> {
    match value {
        SynQValue::Bytes(value) => Ok(value.clone()),
        SynQValue::String(value) | SynQValue::Address(value) => Ok(value.as_bytes().to_vec()),
        _ => Err(type_error("bytes", value)),
    }
}

fn caller_string(context: &ExecutionContext) -> String {
    String::from_utf8(context.caller.clone()).unwrap_or_else(|_| hex(&context.caller))
}

fn runtime_failure(error: AivmError) -> StatefulSynQFailure {
    StatefulSynQFailure {
        error,
        reverted: false,
    }
}

fn type_error(expected: &str, found: &SynQValue) -> StatefulSynQFailure {
    StatefulSynQFailure::failed(
        AivmErrorCode::RuntimeTrap,
        format!("SynQ expected {expected}, found {found:?}"),
    )
}

fn unknown_member(object: &str, member: &str) -> StatefulSynQFailure {
    StatefulSynQFailure::failed(
        AivmErrorCode::RuntimeTrap,
        format!("unknown SynQ member {object}.{member}"),
    )
}

fn argument_error(name: &str, expected: usize, found: usize) -> StatefulSynQFailure {
    StatefulSynQFailure::failed(
        AivmErrorCode::Abi,
        format!("{name} expects {expected} arguments, found {found}"),
    )
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{
        ContractArtifact, ContractFormat, ExecutionContext, ExecutionRequest, ExecutionStatus,
    };
    use crate::synq_runtime::{call_synq_contract, deploy_synq_contract};
    use synq_compiler::{analyze, parse, ArtifactBundle, CodeGenerator};

    fn artifact(source: &str) -> (ContractArtifact, ArtifactBundle) {
        let (_, ast) = parse(source).unwrap();
        analyze(&ast).unwrap();
        let bytecode = CodeGenerator::new().generate_stateful(&ast).unwrap();
        let bundle = ArtifactBundle::generate(source, &ast, bytecode).unwrap();
        (
            ContractArtifact {
                format: ContractFormat::SynqBytecodeV1,
                bytes: bundle.bytecode.clone(),
                abi_json: Some(String::from_utf8(bundle.abi_json().unwrap()).unwrap()),
                manifest_json: Some(String::from_utf8(bundle.manifest_json().unwrap()).unwrap()),
                metadata_json: None,
                compiler_version: None,
                source_hash: None,
            },
            bundle,
        )
    }

    fn request(
        artifact: &ContractArtifact,
        calldata: Vec<u8>,
        caller: &str,
        value: u128,
    ) -> ExecutionRequest {
        request_for("contract-1", artifact, calldata, caller, value)
    }

    fn request_for(
        contract_id: &str,
        artifact: &ContractArtifact,
        calldata: Vec<u8>,
        caller: &str,
        value: u128,
    ) -> ExecutionRequest {
        let mut context = ExecutionContext::testnet_1266_for_contract(contract_id, 1_000_000);
        context.runtime_block_height = 1;
        context.block_height = 10;
        context.caller = caller.as_bytes().to_vec();
        context.call_value = value;
        ExecutionRequest {
            contract_id: contract_id.to_string(),
            artifact: artifact.clone(),
            calldata,
            context,
        }
    }

    fn call_data(bundle: &ArtifactBundle, method: &str, args: serde_json::Value) -> Vec<u8> {
        let selector = bundle
            .abi
            .methods
            .iter()
            .find(|candidate| candidate.name == method)
            .unwrap()
            .selector
            .trim_start_matches("0x");
        let mut bytes = (0..selector.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&selector[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.extend_from_slice(&serde_json::to_vec(&args).unwrap());
        bytes
    }

    #[test]
    fn stateful_mapping_write_read_and_revert_are_atomic() {
        let source = r#"
contract Stateful {
    owner: Address public;
    values: mapping(Address => UInt256) public;
    constructor(initialOwner: Address) {
        require(initialOwner != Address(0), "owner required");
        owner = initialOwner;
    }
    @public function set(account: Address, value: UInt256) {
        require(msg.sender == owner, "unauthorized");
        values[account] = value;
    }
    @public function get(account: Address) -> UInt256 {
        return values[account];
    }
}
"#;
        let (artifact, bundle) = artifact(source);
        let mut state = ContractState::default();
        let deploy = deploy_synq_contract(
            &request(&artifact, br#"["alice"]"#.to_vec(), "alice", 0),
            &mut state,
        );
        assert_eq!(deploy.status, ExecutionStatus::Succeeded);

        let set = call_synq_contract(
            &request(
                &artifact,
                call_data(&bundle, "set", serde_json::json!(["bob", "42"])),
                "alice",
                0,
            ),
            &mut state,
        );
        assert_eq!(set.status, ExecutionStatus::Succeeded);
        let committed_root = state.state_root();

        let rejected = call_synq_contract(
            &request(
                &artifact,
                call_data(&bundle, "set", serde_json::json!(["bob", "99"])),
                "mallory",
                0,
            ),
            &mut state,
        );
        assert_eq!(rejected.status, ExecutionStatus::Reverted);
        assert_eq!(state.state_root(), committed_root);

        let get = call_synq_contract(
            &request(
                &artifact,
                call_data(&bundle, "get", serde_json::json!(["bob"])),
                "bob",
                0,
            ),
            &mut state,
        );
        assert_eq!(get.status, ExecutionStatus::Succeeded);
        assert_eq!(
            serde_json::from_slice::<SynQValue>(&get.return_data).unwrap(),
            SynQValue::Uint(42)
        );
    }

    #[test]
    fn stateful_send_native_emits_a_consensus_bound_transfer() {
        let source = r#"
contract Payer {
    @public function pay(recipient: Address, amount: UInt256) {
        sendNative(recipient, amount);
    }
}
"#;
        let (artifact, bundle) = artifact(source);
        let mut state = ContractState::default();
        assert_eq!(
            deploy_synq_contract(&request(&artifact, Vec::new(), "alice", 0), &mut state).status,
            ExecutionStatus::Succeeded
        );
        let pay = call_synq_contract(
            &request(
                &artifact,
                call_data(&bundle, "pay", serde_json::json!(["bob", "7"])),
                "alice",
                10,
            ),
            &mut state,
        );
        assert_eq!(pay.status, ExecutionStatus::Succeeded);
        assert_eq!(
            pay.native_transfers,
            vec![SynQNativeTransfer {
                from: "contract-1".to_string(),
                to: "bob".to_string(),
                amount_nwei: 7,
            }]
        );
    }

    #[test]
    fn stateful_call_contract_uses_only_transaction_resolved_artifacts() {
        let target_source = r#"
contract Target {
    value: UInt256 public;
    @public function set(next: UInt256) {
        value = next;
    }
    @public function get() -> UInt256 {
        return value;
    }
}
"#;
        let caller_source = r#"
contract Caller {
    @public function relay(target: Address, data: Bytes) {
        callContract(target, 0, data);
    }
}
"#;
        let (target_artifact, target_bundle) = artifact(target_source);
        let (caller_artifact, caller_bundle) = artifact(caller_source);
        let mut state = ContractState::default();
        assert_eq!(
            deploy_synq_contract(
                &request_for("target", &target_artifact, Vec::new(), "alice", 0),
                &mut state,
            )
            .status,
            ExecutionStatus::Succeeded
        );
        assert_eq!(
            deploy_synq_contract(
                &request_for("caller", &caller_artifact, Vec::new(), "alice", 0),
                &mut state,
            )
            .status,
            ExecutionStatus::Succeeded
        );

        let nested = call_data(&target_bundle, "set", serde_json::json!(["77"]));
        let mut relay = request_for(
            "caller",
            &caller_artifact,
            call_data(
                &caller_bundle,
                "relay",
                serde_json::json!(["target", format!("0x{}", hex(&nested))]),
            ),
            "alice",
            0,
        );
        relay
            .context
            .resolved_synq_contracts
            .insert("target".to_string(), target_artifact.clone());
        assert_eq!(
            call_synq_contract(&relay, &mut state).status,
            ExecutionStatus::Succeeded
        );

        let get = call_synq_contract(
            &request_for(
                "target",
                &target_artifact,
                call_data(&target_bundle, "get", serde_json::json!([])),
                "alice",
                0,
            ),
            &mut state,
        );
        assert_eq!(
            serde_json::from_slice::<SynQValue>(&get.return_data).unwrap(),
            SynQValue::Uint(77)
        );
    }

    fn checked_in_genesis_artifact(name: &str) -> ContractArtifact {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../genesis-contracts/contracts");
        ContractArtifact {
            format: ContractFormat::SynqBytecodeV1,
            bytes: std::fs::read(root.join(format!("{name}.compiled.synq"))).unwrap(),
            abi_json: Some(std::fs::read_to_string(root.join(format!("{name}.abi.json"))).unwrap()),
            manifest_json: Some(
                std::fs::read_to_string(root.join(format!("{name}.manifest.json"))).unwrap(),
            ),
            metadata_json: None,
            compiler_version: None,
            source_hash: None,
        }
    }

    fn artifact_call_data(
        artifact: &ContractArtifact,
        method: &str,
        args: serde_json::Value,
    ) -> Vec<u8> {
        let abi: serde_json::Value =
            serde_json::from_str(artifact.abi_json.as_deref().unwrap()).unwrap();
        let selector = abi["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["name"] == method)
            .unwrap()["selector"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x");
        let mut bytes = (0..selector.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&selector[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.extend_from_slice(&serde_json::to_vec(&args).unwrap());
        bytes
    }

    fn run_checked_in_genesis_suite() -> (ContractState, Vec<[u8; 32]>) {
        let names = [
            "ValidatorRegistry",
            "Staking",
            "RewardDistributor",
            "Governance",
            "Treasury",
            "SynergyOracle",
            "Identity",
            "Slashing",
        ];
        let artifacts: BTreeMap<String, ContractArtifact> = names
            .iter()
            .map(|name| (name.to_string(), checked_in_genesis_artifact(name)))
            .collect();
        let ids = [
            ("ValidatorRegistry", "registry"),
            ("Staking", "staking"),
            ("RewardDistributor", "rewards"),
            ("Governance", "governance"),
            ("Treasury", "treasury"),
            ("SynergyOracle", "oracle"),
            ("Identity", "identity"),
            ("Slashing", "slashing"),
        ];
        let constructors = [
            serde_json::json!(["00", "authority", "100", "6", "1"]),
            serde_json::json!(["00", "registry", "1", "1000000", "1", "1000000", "10"]),
            serde_json::json!(["00", "distributor"]),
            serde_json::json!(["00", "staking", "2000", "5001", "3300", "1", "10", "5"]),
            serde_json::json!(["00", "governance", "1"]),
            serde_json::json!(["00", "1", true]),
            serde_json::json!(["00", "fee-collector", "1"]),
            serde_json::json!([
                "00", "registry", "staking", "slasher", "500", "100", "500", "10", "20"
            ]),
        ];
        let mut state = ContractState::default();
        let mut receipt_hashes = Vec::new();
        for ((name, id), args) in ids.iter().zip(constructors) {
            let receipt = deploy_synq_contract(
                &request_for(
                    id,
                    artifacts.get(*name).unwrap(),
                    serde_json::to_vec(&args).unwrap(),
                    "genesis-deployer",
                    0,
                ),
                &mut state,
            );
            assert_eq!(
                receipt.status,
                ExecutionStatus::Succeeded,
                "{name}: {receipt:?}"
            );
            receipt_hashes.push(receipt.canonical_hash());
        }

        let resolved: BTreeMap<String, ContractArtifact> = ids
            .iter()
            .map(|(name, id)| (id.to_string(), artifacts.get(*name).unwrap().clone()))
            .collect();
        let mut execute = |name: &str,
                           id: &str,
                           method: &str,
                           args: serde_json::Value,
                           caller: &str,
                           value: u128| {
            let artifact = artifacts.get(name).unwrap();
            let mut request = request_for(
                id,
                artifact,
                artifact_call_data(artifact, method, args),
                caller,
                value,
            );
            request.context.resolved_synq_contracts = resolved.clone();
            let receipt = call_synq_contract(&request, &mut state);
            assert_eq!(
                receipt.status,
                ExecutionStatus::Succeeded,
                "{name}.{method}: {receipt:?}"
            );
            receipt_hashes.push(receipt.canonical_hash());
            receipt
        };

        execute(
            "ValidatorRegistry",
            "registry",
            "registerValidator",
            serde_json::json!(["01", "validator-1", "reward-1", "1", "10000", "02", "03"]),
            "authority",
            0,
        );
        execute(
            "ValidatorRegistry",
            "registry",
            "activateValidator",
            serde_json::json!(["validator-1", "1"]),
            "authority",
            0,
        );
        execute(
            "Staking",
            "staking",
            "selfStake",
            serde_json::json!([]),
            "validator-1",
            10000,
        );
        execute(
            "RewardDistributor",
            "rewards",
            "distribute",
            serde_json::json!(["reward-1", "10"]),
            "distributor",
            10,
        );
        execute(
            "Governance",
            "governance",
            "propose",
            serde_json::json!(["treasury", "0", "0x", "04"]),
            "proposer",
            1,
        );
        execute(
            "Treasury",
            "treasury",
            "queueGovernanceTransaction",
            serde_json::json!(["identity", "0", "0x", "05"]),
            "governance",
            0,
        );
        execute(
            "SynergyOracle",
            "oracle",
            "isFinalized",
            serde_json::json!(["06"]),
            "reader",
            0,
        );
        let mut hasher = Sha256::new();
        hasher.update(b"SYNERGY_SYNID_NAME_V1");
        hasher.update(b"alice");
        execute(
            "Identity",
            "identity",
            "register",
            serde_json::json!(["Alice", format!("0x{}", hex(&hasher.finalize()))]),
            "alice",
            1,
        );
        execute(
            "Slashing",
            "slashing",
            "slashForDoubleSign",
            serde_json::json!(["validator-1"]),
            "slasher",
            0,
        );

        (state, receipt_hashes)
    }

    #[test]
    fn all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically() {
        let (first_state, first_receipts) = run_checked_in_genesis_suite();
        let encoded = serde_json::to_vec(&first_state).unwrap();
        let restarted: ContractState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restarted.state_root(), first_state.state_root());

        let (replay_state, replay_receipts) = run_checked_in_genesis_suite();
        assert_eq!(replay_state.state_root(), first_state.state_root());
        assert_eq!(replay_receipts, first_receipts);
    }
}
