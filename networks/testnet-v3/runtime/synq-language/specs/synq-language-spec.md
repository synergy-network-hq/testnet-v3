# SynQ Language Spec

Spec version: 0.1
Target network profile: `synergy-testnet`, chain `1264`

## File And Module Rules

- Source files use the `.synq` extension.
- Source text MUST be UTF-8.
- A file contains zero or one `module` declaration, zero or more `import`
  declarations, and one or more `contract` declarations.
- Imports are disabled for chain-1264 deployment until deterministic import
  resolution is implemented. A compiler MAY parse imports but MUST reject deploy
  artifacts that depend on unresolved imports.

## Contract Form

```synq
contract Counter {
    state count: u64;

    pub fn increment() {
        self.count = self.count + 1;
    }

    pub fn get() -> u64 {
        return self.count;
    }
}
```

## Declarations

| Declaration | Required fields | Notes |
|---|---|---|
| `contract` | name, body | Contract name MUST be unique in a source file. |
| `state` | name, type | State names MUST be unique per contract. |
| `fn` | name, params, return type, body | Function names MUST be unique per contract for v0.1. |
| `event` | name, fields | Event names MUST be unique per contract. |
| `error` | name, fields | Error names MUST be unique per contract. |
| `security` | key/value entries | Compiles into manifest, not runtime code. |

## Visibility And Mutability

- `pub fn` is externally callable.
- `priv fn` is internal only.
- Missing visibility defaults to `priv`.
- `view fn` MAY read state but MUST NOT write state.

## Types

Supported v0.1 types:

- `bool`
- `u8`, `u16`, `u32`, `u64`, `u128`
- `i32`, `i64`
- `bytes`, `bytes32`
- `address`
- `string`
- `array<T>`

Floats are forbidden. Maps are deferred until the storage-key encoding is frozen.

## Security Block

```synq
security {
    signature = "ML-DSA-65";
    chain_bound = true;
    domain = "SYNQ_CONTRACT_DEPLOY_V1";
}
```

The security block MUST compile into the manifest fields:

- `required_signature_algorithm`
- `required_chain_id`
- `required_network_id`
- `required_domain_tags`
- `chain_bound`
- `domain_separation`

## Execution Semantics

- Arithmetic on unsigned integers traps on overflow, underflow, and division by
  zero.
- State writes are staged in AIVM overlay storage and commit only after
  successful execution.
- `trap` aborts execution, rolls back state writes, and emits a deterministic
  receipt with status `reverted`.

## Host Functions

Contracts may access host behavior only through manifest-declared host functions.
The v0.1 host ABI names are:

- `state.read`
- `state.write`
- `event.emit`
- `context.chain_id`
- `context.network_id`
- `context.caller`
- `context.contract_address`

## Diagnostics

Diagnostics MUST include:

- stable error code
- source file
- line and column
- span start/end byte offsets
- message
- optional help text
