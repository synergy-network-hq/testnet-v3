# Validator Operations API v1

The status schema is a read-only operations adapter. Its separately authorized
lifecycle and diagnostic endpoints use only the local agent's fixed allowlist.
It is not part of PoSy, block
validation, VC/QC, or ProtectedPipeline progression. A validator does not call
it and continues operating if the agent or Node Control Panel is unavailable.

## Runtime contract

The validator runtime writes one atomic, public-data-only observation to:

`data/operations/validator-operations-v1.json`

The observation uses schema version `synergy.validator-operations.v1` and the
Rust types in `src/validator_operations.rs`. The management agent reads only
that file. It does not grep logs, inspect consensus stores, infer service names,
or guess release identity. Missing, oversized, wrong-version, identity-mismatched,
or unknown-field snapshots fail closed with HTTP 503. Unknown fields are rejected
so accidental secret-bearing additions cannot pass through the API.

The runtime must publish snapshots with an atomic replace. The file must never
contain private keys, seed material, passphrases, signing credentials, sensitive
environment values, or raw custody material. Public key fingerprints and public
addresses are allowed.

## Endpoints

- `GET /v1/validator-operations/cluster/status`
- `GET /v1/validator-operations/nodes/{validator_id}/status`
- `GET /v1/validator-operations/nodes/{validator_id}/diagnose-liveness`
- `GET /v1/validator-operations/nodes/{validator_id}/preflight`
- `GET /v1/validator-operations/nodes/{validator_id}/logs?limit=200`
- `POST /v1/validator-operations/nodes/{validator_id}/control`
- `POST /v1/validator-operations/nodes/{validator_id}/diagnostic-snapshots`

Every endpoint requires:

- loopback, or an explicitly allowlisted private/VPN source address;
- `Authorization: Bearer <SYNERGY_TESTNET_AGENT_TOKEN>`;
- `X-Synergy-Operator-Id: <stable operator identity>`;
- `X-Synergy-Operator-Scopes: validator.operations.read` for reads,
  `validator.operations.control` for lifecycle changes, or
  `validator.operations.snapshot` for snapshot capture.

Lifecycle input is a closed `START | STOP | RESTART` enum and a mandatory audit
reason. Start and restart require every defined host preflight check and release
consistency to pass. The handler maps those values to the existing local
`nodectl` allowlist and cannot accept arbitrary commands. Diagnostic snapshots
contain the typed status, preflight result, and bounded structured logs. A
conservative marker filter replaces an entire sensitive log line; neither the
API nor the UI returns raw custody material.

Requests and outcomes are appended to
`audit/validator-operations-api.jsonl`. Audit records contain operator identity,
remote address, action, validator ID, and outcome only. Tokens and response
payloads are never recorded. Mutations require a durable authorization audit
record before execution and a second outcome record afterward.

The current HTTP transport is acceptable only on loopback or through the
encrypted validator VPN. The endpoint must not be bound to a public interface.

## Deterministic evaluation

The agent computes health and the first missing transition from the supplied
observation without wall-clock reads or log heuristics. The runtime supplies
explicit progress state and elapsed-finality time. Health classes are:

`HEALTHY`, `SYNCING`, `DEGRADED`, `STALLED`, `OFFLINE`, `MISCONFIGURED`, and
`RELEASE_MISMATCH`.

Protected batch source values align with the runtime contract exactly:
`GENESIS_BOOTSTRAP`, `NORMAL_ETDAG`, and `NORMAL_ETDAG_STEADY_STATE`. Both normal
ETDAG variants follow the same fail-closed evidence and reveal diagnostics.

Cluster release consistency compares release ID/tag, binary SHA-256, Core/SynQ/
Aegis revisions, Genesis hash, protocol version, ProtectedPipeline version, and
validator configuration version. Any discovered divergence raises
`RELEASE_MISMATCH` for the cluster view.

`diagnose_liveness` walks the stable transition order across service, P2P,
ProtectedPipeline, PoSy proposal/VC, reveal/execution, QC, and finalization and
returns the first unsatisfied edge with its observed/required counts.

## Integration boundary

This slice deliberately does not make the Node Control Panel consensus-critical.
The ProtectedPipeline field names are an abstract operations contract; the
consensus integration owner still needs to emit the corresponding snapshot from
the authoritative runtime state. Until that producer exists, the API returns 503
instead of fabricating state from journals or filesystem artifacts.
