# SynQ AIVM Execution Spec

Spec version: 0.1

## Execution Context

```rust
pub struct ExecutionContext {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub block_height: u64,
    pub block_timestamp: u64,
    pub tx_hash: Hash32,
    pub caller: SynQAddress,
    pub contract_address: SynQAddress,
    pub gas_limit: u64,
    pub pq_gas_limit: u64,
    pub security_policy: SynQSecurityPolicy,
}
```

## Determinism Rules

Contract execution MUST NOT access:

- wall-clock time
- nondeterministic randomness
- network I/O
- filesystem I/O
- host-machine identifiers
- locale-sensitive formatting

Consensus context values come only from `ExecutionContext`.

## Deployment Flow

1. Decode artifact envelope.
2. Validate bytecode header and section table.
3. Validate ABI hash and manifest hash.
4. Validate manifest security requirements.
5. Call `aegis-pqsynq.verify_contract_deploy`.
6. Create state overlay.
7. Run init/constructor if present.
8. Commit overlay on success, rollback on trap/failure.
9. Emit deterministic receipt.

## Call Flow

1. Load deployed contract artifact.
2. Decode call envelope and ABI method selector.
3. Call `aegis-pqsynq.verify_contract_call`.
4. Validate visibility and argument encoding.
5. Create state overlay.
6. Execute method.
7. Commit overlay on success, rollback on trap/failure.
8. Emit deterministic receipt.

## Error Families

- `BytecodeError`
- `ManifestError`
- `AbiError`
- `VerificationError`
- `GasError`
- `PqGasError`
- `RuntimeTrap`
- `StateError`
- `HostFunctionError`
- `ReceiptError`
- `InternalInvariantError`
