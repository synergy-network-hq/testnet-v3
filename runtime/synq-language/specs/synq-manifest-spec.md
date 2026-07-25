# SynQ Manifest Spec

Spec version: 0.1

## Canonical Form

The manifest is canonical JSON encoded as UTF-8 with sorted object keys and no
insignificant whitespace. The manifest hash is
`SHA-256(canonical_manifest_json_bytes)`.

## Required Fields

| Field | Type | Notes |
|---|---|---|
| `manifest_version` | string | fixed `0.1` |
| `contract_name` | string | source contract name |
| `compiler_version` | string | semantic version or build SHA |
| `bytecode_hash` | hex32 | SHA-256 of bytecode |
| `abi_hash` | hex32 | SHA-256 of canonical ABI |
| `security_policy` | object | see security policy spec |
| `required_signature_algorithm` | string | launch default `ML-DSA-65` |
| `required_chain_id` | integer | `1264` for testnet |
| `required_network_id` | string | `synergy-testnet`; local chain-1264 node admission may also accept the `synergy-testnet-v3` alias after explicit normalization |
| `required_aivm_version` | string | `0.1` |
| `permissions` | array | sorted permission names |
| `host_functions` | array | sorted host ABI names |
| `storage_schema_hash` | hex32 | SHA-256 of canonical storage schema |

## Rejection Rules

AIVM MUST reject deployment if:

- manifest hash does not match bytecode header
- chain ID is not `1264` for the testnet profile
- network ID is neither `synergy-testnet` nor an explicitly normalized
  chain-1264 alias such as `synergy-testnet-v3`
- required signature algorithm is not allowed by `aegis-pqsynq`
- manifest declares host functions not supported by AIVM
- storage schema hash is missing or malformed

## Project Configuration

The CLI consumes `synq.toml` when present beside or above a source file. The
current production-bound profile validates package/compiler/network/security
sections before artifact generation and rejects unsupported chain IDs, network
IDs, address HRPs, bytecode versions, language versions, domain tags, and
signature algorithms. Validated fields flow into the manifest instead of being
ignored by the CLI.
