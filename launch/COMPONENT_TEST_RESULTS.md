# Testnet-v3 component test results

Date: 2026-07-25

## Confirmed

- Component packaging and wiring audit: 18 of 18 component groups passed.
- Repository structure validation passed.
- AIVM and SynQ are vendored as normal repository content; no nested `.git`
  pointers remain.
- All eight genesis contracts are native `.synq` sources.
- All eight pass SynQ parsing, semantic analysis, bytecode generation, ABI
  generation, and manifest generation.
- Deterministic verification confirmed that every `.compiled.synq` artifact
  exactly matches its source.
- Every manifest is bound to chain `1264`, network `synergy-testnet-v3`, and
  `ML-DSA-65`; source, bytecode, and ABI hashes match their artifacts.
- No Solidity source or compatibility preview is included in Testnet-v3.

Focused behavior suites:

| Suite | Result |
| --- | ---: |
| Synergy Token System | 18 passed |
| Transaction execution, fee collector, burn, and SynQ/AIVM path | 12 passed |
| Native token, fee distribution, and reward lifecycle | 17 passed |
| Reward allocation, settlement, reliability, and invariants | 21 passed |
| SynQ admission and PQ envelope verification | 11 passed |
| AIVM core, deterministic state, SynQ runtime, and STS host calls | 38 passed |
| Gas and network fee model | 14 passed |
| Wallet fee reserve, SNRG/custom-token transfer, and staking | 10 passed |
| Validator lifecycle and stake gates | 26 passed |
| Reward, STS, SynQ/AIVM receipt, and burn RPCs | 8 passed |

Total focused capability tests: 175 passed.

These 175 inherited runtime tests validate token, fee, rewards, admission,
receipt, and limited AIVM/STS behavior. They do not prove general stateful
execution of the new SynQ genesis contracts.

## Genesis-dependent integration status

The active Testnet-v3 genesis files are still prelaunch placeholders. A broad
RPC test run therefore reported 46 passes and 10 failures; every observed
failure terminated while loading the placeholder with:

```text
missing path header.timestamp
```

The reward audit and invariant RPCs, STS payload/materialization RPCs,
SynQ/AIVM receipt and replay RPCs, and burn-ledger RPC were also rerun
individually: all eight passed. The remaining broad-suite tests cannot be used
as launch evidence until a complete Testnet-v3 genesis document built from new
public identities is installed.

## AIVM/SynQ deployment status

The inherited AIVM currently deploys generic contracts as metadata and does not
execute their constructors. Generic bytecode calls do not receive the complete
contract host context or mutate persistent contract state. Consequently the
eight native SynQ contracts are compiled but not deployable as functioning
stateful contracts on the current runtime.

This is a hard functional-parity blocker because Testnet-v3 needs these
contracts to deploy and execute, not merely compile.

## Remaining binding work

`runtime/src/token.rs` still contains the concrete system-wallet addresses
inherited with the Testnet-v2 implementation. The routing logic is present and
tested, but those values are not approved Testnet-v3 identities. Bind the final
new fee collector, validator reward pool, DAO treasury, treasury recovery, and
reliability pool addresses before launch, then rerun the focused and broad
integration suites.

Inherited Testnet-v2 validator/node identities and addresses also remain in
configuration files, public allocation and validator manifests, templates, and
the node-control-panel's embedded genesis. They are reference inputs only and
must be replaced—not carried forward—when the new Testnet-v3 identities and
final genesis configuration are produced.
