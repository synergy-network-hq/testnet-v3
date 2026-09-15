# SynQ Counter AMA Demo

Status date: 2026-06-01

This is a local proof-backed vertical slice for the June 6, 2026 AMA. It is
not a live TESTNET deployment claim.

## Purpose

Show a real SynQ smart contract moving through the current production-shaped
path:

```text
source -> artifacts -> pqsynq deploy/call verification -> pqvm admission
-> local AIVM Counter execution -> gas/PQ-Gas -> deterministic receipt
```

The goal is to make the demo clear for the community while preserving the
engineering boundary: SynQ owns artifacts, `aegis-pqsynq` owns inner SynQ
authorization, `aegis-pqvm` owns outer blockchain admission, and AIVM owns
execution/receipts.

## Prerequisites

- Local SynQ workspace:
  `/Volumes/xcode/Synergy-Network-Projects/synq-language`
- Local Testnet-Beta workspace:
  `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet`
- Local AIVM core crate:
  `/Volumes/xcode/Synergy-Network-Projects/synergy-aivm/runtime/aivm-core`
- Rust/Cargo installed.
- Build cache must stay off `/Volumes/xcode`:

```sh
export CARGO_TARGET_DIR=/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/target
export CARGO_BUILD_JOBS=2
```

## Commands

Environment check only:

```sh
cd /Volumes/xcode/Synergy-Network-Projects/synq-language
./scripts/ama_demo_synq_counter.sh --check
```

Run the screen-share demo:

```sh
cd /Volumes/xcode/Synergy-Network-Projects/synq-language
./scripts/ama_demo_synq_counter.sh
```

Verbose engineering run:

```sh
./scripts/ama_demo_synq_counter.sh --verbose
```

The script writes a self-contained visual board:

```text
/Volumes/xcode/Synergy-Network-Projects/synq-language/docs/demo/SynQ-Counter-AMA-Demo-Visual.html
```

Open that HTML file during the AMA to show the pipeline, hashes, verification
results, Counter state transition, gas lanes, state root, and receipt hash.

## Expected Output

The sanitized expected-output snapshot is:

```text
/Volumes/xcode/Synergy-Network-Projects/synq-language/docs/demo/SynQ-Counter-AMA-Expected-Output-2026-06-06.txt
```

Key values from the current proof run:

```text
bytecode_hash=6b8b2d0d1433c0c4941bfc41054a58a004e9cc46e475926f0f70d3d309e92533
abi_hash=ea9c1f48cad5f0d39d299d854ba578f6909a8475093aa8c616b1ee186c599b26
manifest_hash=6334f5a98926f3c5eeb4f9337a9602841e5cc9b77b59f0e648203a296d290332
chain_id=1264
network_id=synergy-testnet
signature_algorithm=ML-DSA-65
deploy_verification=PASS
call_verification=PASS
cli_keygen=PASS
cli_deploy_envelope_verified=PASS
cli_increment_call_envelope_verified=PASS
cli_get_call_envelope_verified=PASS
aegis_pqvm_outer_admission=PASS
counter_before=0
counter_increment_return=1
counter_get_return=1
ordinary_gas_used=31
pq_gas_used=50000
state_root=1bd01d6d3270341d2f6613b4de853e840575be6b82d71fccd8dd7da751fa344c
receipt_hash=f5b8e3bde36244ea08aea937abca982db2b78d48ab3ad7162a503686202cb39c
```

## What Each Step Proves

1. `synq_build`: `contracts/Counter.synq` builds deterministic bytecode, ABI,
   manifest, and labeled Solidity compatibility output.
2. `compiler_artifact_tests`: checked-in Counter fixtures match regenerated
   artifacts and stable hashes.
3. `pqsynq_verifier_tests`: real ML-DSA-65 `aegis-pqsynq` deploy and call
   authorization paths pass.
4. `synq_cli_*`: the CLI creates a temporary local ML-DSA-65 testnet identity,
   signs and verifies deploy plus `increment()` and `get()` call envelopes
   through `aegis-pqsynq`, and deletes the temporary key directory afterward.
5. `synq_admission_positive_and_negative_tests`: wrong chain, wrong domain,
   invalid signature, and malformed carrier preserve structured error codes.
6. `counter_artifact_linked_pqsynq_then_pqvm`: generated Counter hashes pass
   pqsynq verification before the existing pqvm outer admission path.
7. `receipt_preserves_synq_verification_summary`: internal receipts preserve
   SynQ verification summaries.
8. `counter_state_demo`: local AIVM overlay executes the Counter state
   transition and prints ordinary gas, PQ-Gas, state root, and receipt hash.
9. Visual board generation: presenter has an accurate screen-share artifact.

## Local-Only Boundary

Working and source-backed:

- Counter source, bytecode, ABI, manifest, and stable hashes.
- Local CLI `keygen`, `sign-deploy`, `verify-deploy`, `sign-call`, and
  `verify-call` flows backed by `aegis-pqsynq`.
- Real `aegis-pqsynq` ML-DSA-65 verification.
- Existing `aegis-pqvm` outer admission preserved.
- Local AIVM manifest validation, state overlay, and deterministic receipt
  hash.

Not claimed:

- Public RPC listener.
- Live TESTNET deployment.
- Persisted chain storage for Counter.
- Public AIVM RPC deploy/execute handlers.
- Explorer/indexer display of SynQ receipt summary fields.
- Production audit readiness.

## Troubleshooting

- If Cargo tries to build under `/Volumes/xcode`, export the approved
  `CARGO_TARGET_DIR` shown above.
- If `--check` fails, fix the missing path before running the full demo.
- If the visual board does not refresh, rerun the script and reopen the HTML
  file.
- If Testnet-Beta warnings appear in verbose mode, confirm the final PASS lines.
  The default mode suppresses raw build logs unless a command fails.

## Community Wording

Safe 60-second version:

> This is the SynQ smart contract alpha path. We start with real `Counter.synq`
> source, build deterministic bytecode, ABI, and manifest artifacts, verify
> SynQ deploy and call authorization with ML-DSA-65 through `aegis-pqsynq`, keep
> the existing `aegis-pqvm` admission layer, and run a local AIVM Counter state
> transition with separate gas and PQ-Gas plus a deterministic receipt hash.

Safe 3-minute version:

> The important part is the boundary. SynQ produces developer artifacts.
> `aegis-pqsynq` owns the SynQ-specific cryptographic policy: deploy/call
> domains, chain-1264 binding, ML-DSA-65, payload hashes, and structured
> errors. The Testnet-Beta path still uses `aegis-pqvm` for the outer
> blockchain admission layer. The local AIVM demo shows deterministic Counter
> state and receipt behavior. This is local proof, not a public deploy claim.

Technical deep-dive version:

> The artifact fixture tests rebuild `Counter.synq` and compare bytecode, ABI,
> manifest, and hashes against checked-in fixtures. The admission test reads
> those generated hashes, builds a pqsynq deploy envelope, verifies it with the
> real ML-DSA-65 path, wraps it in the `synq-admission-v1` carrier, and then
> confirms the existing pqvm admission path still accepts the outer
> transaction. Negative tests preserve `AEGIS-CHAIN`, `AEGIS-DOMAIN`,
> `AEGIS-SIG`, and `AEGIS-CANON`.

Unsafe claims to avoid:

- "This deployed live on public TESTNET."
- "Public AIVM RPC is enabled."
- "Counter state is persisted on chain."
- "This is production audited."
- "The VM/runtime is complete."
- "Live SynQ deploy/call CLI submission is finished."

## Production Readiness Delta After AMA Demo Slice

What the AMA slice proves:

- Artifact generation is deterministic and fixture-backed.
- The local CLI can generate and verify pqsynq-backed deploy and no-arg call
  envelopes for the current Counter subset.
- The Model B pqsynq-then-pqvm boundary is regression-tested.
- AIVM has a local deterministic Counter overlay, separate gas lanes, and
  receipt hashes.
- The demo is repeatable from one command and has a visual artifact.

What production systems can build upon:

- Canonical artifact schema constants and fixtures.
- CLI `check`, `build`, `abi`, `manifest`, `simulate`, and `init` foundations.
- Structured negative-path tests in the admission boundary.
- Local AIVM state/meter/receipt primitives.

Still prototype/demo-only:

- Direct Counter execution uses the local AIVM overlay helper; the raw compiler
  bytecode still does not execute stateful Counter behavior in QuantumVM.
- Public AIVM RPC remains disabled.
- Live deploy/call flow remains pending.

Next three production milestones:

1. Connect `validate_synq_artifact` to the node deploy/call execution handoff
   once public AIVM RPC remains gated.
2. Implement real Counter state load/store bytecode semantics or native AIVM
   Counter execution through the artifact envelope.
3. Add guarded local RPC after the direct runtime handoff is complete.

Risk list:

- Raw QuantumVM Counter bytecode currently fails on state access.
- Node-side PQ-Gas pricing for pqsynq verification is not finalized.
- Public receipt/indexer exposure for SynQ summaries remains pending.

Recommended next engineering prompt:

> Wire `validate_synq_artifact` and `SynQVerificationSummary` into the direct
> AIVM deploy/call handoff. Add tests for missing verification summary,
> manifest/signature mismatch, successful Counter initialization, rollback
> after trapped call, and receipt hash changes across state transitions. Keep
> public RPC disabled until the direct runtime handoff is complete.
