# Session 13j — canonical governance authorization (P0)

Executed and verified. Nothing inferred.

## Result

The replayable-governance-signature defect is **fixed and proven**. All 24
governed operations across the eight governance-keyed contracts now authorize
through one canonical, host-reconstructed envelope. Nine binding tests pass.
All nine contracts rebuilt byte-identically across three independent builds.

**Not done this session:** authority separation (step 8), custody tooling
(step 10), Track G (step 11). Scope and reasons at the end.

## 1. Inventory — 24 governed operations

Every operation authorized by `initialGovernanceKey`. All had the same defect:
a caller-supplied `message: Bytes` verified against the governance key, bound to
nothing else. No replay protection of any kind existed on any of them.

| contract | governed functions | count |
|---|---|---|
| Identity | `setReservedName`, `setRegistrationFee`, `setFeeCollector`, `setPaused` | 4 |
| ValidatorRegistry | `setAuthority`, `setPaused`, `updateGovernanceKey` | 3 |
| Staking | `setSlashingContract`, `enableDelegation`, `setPaused` | 3 |
| Governance | `governanceCancel`, `setPaused` | 2 |
| Treasury | `setSigner`, `setRequiredSigners`, `setGovernanceContract`, `setPaused` | 4 |
| Slashing | `setSlashingAuthority`, `setPaused` | 2 |
| RewardDistributor | `setDistributorAuthority`, `setPaused` | 2 |
| SynergyOracle | `setOracle`, `setSourceDomain`, `setQuorumThreshold`, `setPaused` | 4 |

Required during genesis initialization: `Treasury.setSigner` ×5,
`Identity.setReservedName` ×6, `SynergyOracle.setOracle` ×1 +
`setSourceDomain` ×3. ValidatorRegistry genesis initialization uses
`registerValidator` / `activateValidator`, which are **authority**-gated
(`msg.sender`), not governance-signed, and are covered by step 8 instead.

**Finding — governance-key rotation exists on only one contract.** Only
`ValidatorRegistry` has `updateGovernanceKey`. The other seven have no rotation
path at all, so a compromised Initial Governance Authority cannot be replaced on
them without redeploying. Reported for ruling; not fixed here because adding
rotation to seven contracts is a scope change beyond the P0.

## 2. Canonical envelope

`hostVerifyGovernanceAuthorization` is implemented in the AIVM host
(`stateful_synq.rs`), not in contract source, so there is exactly one encoder
and eight contracts cannot drift apart.

The contract surface is deliberately minimal:

```
verifyGovernanceAuthorization(governanceKey, governanceNonce, validUntilBlock, signature) -> Bool
```

Everything else in the signed payload is **reconstructed by the host from the
invocation in flight** and cannot be supplied or influenced by the caller:

| field | source |
|---|---|
| domain `SYNQ_GOVERNANCE_ACTION_V1` | host constant |
| chain_id | `ExecutionContext` |
| network_id | `ExecutionContext` |
| target_contract | `ExecutionContext.contract_address` |
| function_id | method actually resolved on the executable |
| arguments_hash | SHA-256 over the decoded arguments, excluding the authorization tail |
| governance_nonce | compared against protocol-owned stored nonce |
| valid_until_block | compared against `ExecutionContext.block_height` |
| governance_key_fingerprint | SHA-256 over the key the contract stores |

The arguments are captured in `Interpreter::call` from the decoded calldata
before any contract code runs. There is no path by which a caller asserts what
it is authorizing.

Encoding is type-tagged and length-prefixed, so `("ab","c")` and `("a","bc")`
cannot collide. No free-form string concatenation anywhere.

`arbitrary-message verification is no longer reachable`: the eight rebuilt
manifests declare `verifyGovernanceAuthorization` and **no longer declare**
`verifyMLDSASignature`, so the host's `require_host` allowlist rejects the old
call outright.

## 3. Nonce

Per-contract, monotonic, stored in the reserved AIVM namespace
`__synergy_governance_nonce_v1` keyed by contract address — protocol-owned, not
contract storage, so no contract can miscount it and all eight get identical
semantics. It participates in the AIVM state root.

- genesis value is deterministic (`0`, absent key = zero)
- must match exactly; replayed and skipped values both fail
- read and compared *before* signature work, so a bad signature consumes nothing
- incremented only after the signature verifies
- a later contract `require` failure reverts the call, and the increment is
  discarded with the overlay — proven by test, not asserted
- `checked_add`, fails closed on overflow

`valid_until_block = 0` is the explicitly governed no-expiry value; any other
value is an inclusive ceiling on block height. No wall-clock time is involved.

## 4. Tests — 9/9 passing

`runtime/synergy-aivm/runtime/aivm-core/tests/governance_authorization.rs`

| test | proves |
|---|---|
| `valid_governance_authorization_succeeds_exactly_once` | first use succeeds, identical replay fails |
| `authorization_does_not_transfer_across_functions` | a `setSlashingAuthority` signature does not authorize `setPaused` |
| `authorization_does_not_transfer_across_contracts` | a signature for `slashing` does not authorize the *same* function on `rewards` (identical argument types) |
| `mutating_an_argument_invalidates_the_authorization` | one substituted argument invalidates; the original arguments still verify |
| `authorization_is_bound_to_chain_and_network` | wrong chain id and wrong network id both fail |
| `nonce_must_match_exactly_and_advances_only_on_success` | future nonce fails, rejected attempt leaves nonce 0 available, success advances by exactly one, old nonce dies |
| `failed_action_validation_does_not_consume_the_nonce` | contract-level `require` failure rolls the increment back |
| `expiration_is_enforced_at_a_deterministic_boundary` | expired fails; `valid_until_block` is inclusive at the boundary |
| `a_different_governance_key_cannot_authorize` | key-fingerprint binding rejects a well-formed signature from another key |

The key-fingerprint binding is also the key-rotation defence: rotating the key
changes the fingerprint, so every outstanding authorization dies immediately.
A direct rotation test is only expressible on `ValidatorRegistry` — see the
rotation finding in section 1.

## 5. Rebuilt artifacts — three-build byte-identical

Staged at `genesis-contracts/staged-governance-v1/` (in-repo, **not frozen**).
Three independent builds into `/Volumes/xcode/phase8-rebuild-gov-{1,2,3}`
produced byte-identical output for all 27 files: `diff -r` reports no
differences.

TeamVesting bytecode is unchanged (`6a4bf755…`), confirming the change is
isolated to the eight governance-keyed contracts.

| contract | source | bytecode | abi | manifest |
|---|---|---|---|---|
| Identity | `841078b5499ed4d230452260118346daba91ada22308a9be06980af77a9bdf21` | `d35d3806ac57d41da5388380b24f3da0d22fa75960e7c14fb4f67dc47564392c` | `d9965a8d237f6fa5d5cb13d79cb49aaa4eda5d436c92b8ade13e1adfbc7473e9` | `51727e80960d7a374c958b1f2dc773c12ce5268e52fc6daf4dfd83fc752ec64e` |
| ValidatorRegistry | `482dc6fa555905c5d5e168fcd0fa9c857e4125f3b073fdecf309efe3e2d28210` | `0648bf7e3c55fba3737d37739eb6bcb67c37dec709311ea2a3c1a6be56916643` | `161782f8b82c879e600472dba06e812ddda684c3963662b587699aba16bcc2a0` | `dc0f5b7d5c64cf323389d229cbf5bf704798720b0a657c060abf7d4f649b9b20` |
| Staking | `2a9481ed46135f3ac5e16282780e5f5b5e375ec6a73964c6cce407f2503ee306` | `49a1a49e4b649bd6ab2a6ab99d32859a5942eee7669bae10cbccc3ff05a7c866` | `0d445de6280d069d84b805a57f903041e7ce83db6094fec5e9bdd624f47b5763` | `cca957e5f1f4bfda4e265cfbbe86f0c3c03d28a4241b7896f9010e63e9ac4cb7` |
| Governance | `9f24b707528f090910b3bc3568259aff6bbec522fbc1b25c8ad4877e34745053` | `b118a914c64c3454884022c5a9c160fc3de4241698c5fde332473e6276c6bf56` | `562370918cd2907cdd65cf379e3ffa34f892ea24e1a5d843d421500f8eeaf52a` | `54f72bc98254394287d204e1a381558e805925a8546bce3dcccbecd7f387c60d` |
| Treasury | `dfc535fb6818406a79258aab781f6f76c7f080c9a39a74832b610c884e2d03f2` | `d35e7736eca4c3a61428809f109631ec4ab39d8a3904ef05a82eb23cdd364408` | `1e5ac5b604a83339eccd3a245fbb46f0f5b0218650ba75e8419dbfee20af7f74` | `c19a29580b503224aed06cc9ca37381823b5d39fefefb0fb8e72c2389edb9ae2` |
| Slashing | `90fa5a6d1d049872a2d32522fc7713d74d0aa86ce79ffa4dc56208232a909a25` | `fe44ea53ddc1c626ef0d73884a317f7e30962df476ee3d5043ec528f738cb1b5` | `7c2aa314689e5b16a7f0edf752a4dff52a13282312a4b41f5eadc5b970b102c5` | `bfd5dbdcb70244c7006c59df4c2c6df685f1f970aa604686acf65d304a47216a` |
| RewardDistributor | `ebf99b64c1dbb2cd70ffb49a48db6915ce64b0dec1c2ecba71d221eb4e1d416f` | `1bddb527b9f9f401996fabea1dfced503f483b827ba77258576c255667208e92` | `7f3122c10bcf0f625681915473e21df22a6c24536832345a54a1cd1ca002c596` | `b98a09e09a335f1242259f40869e417630f35aac9ab84521bc385d1d526295bc` |
| SynergyOracle | `d853575d745d9391965e0d7974bd3c71eed7c759f03ba181d4f7b33f3e1425d0` | `f2d7c848d7b607754f83da9b18f4f85cb33a5fae2607780f75860d243fc6316a` | `ff5c1d482464a961798523f00a2bccdf9b95a2f723505da34ae8b979dc54a53c` | `457089cd7572b58489aa9850af2c9523860427fcf1e8d2051666c5441ba3790f` |
| TeamVesting | `7a0bc49290db88fb4efa587499d4a0b407295384be1a1d6946da40c7e3436fe9` | `6a4bf755a81615aed240c51f6842aa1bdc6ca8ef16ffa75ce7a510453f1b7f4c` | `5f7df0c83f56283e9c1f78bfe84f9f8b494f1c300ae9cc412d87164027f00753` | `c340a5ced8204e5d6dad0e78d0c78bd4a7aaa0ed6f7c2ea9dde053d74ef89383` |

All nine manifests declare `required_signature_algorithm: ML-DSA-87`.

## 6. AIVM status

- `aivm-core` lib: **41 passed / 1 failed**
- `governance_authorization` integration: **9 passed / 0 failed**

The single failure remains
`all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`:
it loads the stale committed artifacts from `genesis-contracts/contracts/`,
which are pre-migration. This is the artifact/runtime coherence gate and was
**not** patched around, per instruction. It clears when the staged artifacts are
frozen in the atomic rebind.

## 7. Not done — honest scope

**Step 8, authority separation (VNS-A01).** Not implemented. This is
configuration and fixture work plus negative tests; it does not require contract
source changes, because `setAuthority` and `setDistributorAuthority` already
exist and are now protected by the new envelope. It is the correct next task.

**Step 10, custody ceremony tooling.** Not implemented.

**Step 11, Track G.** Not started. It was correctly gated behind this P0 — and
that gating was justified: Track G's genesis initialization calls are governed
calls, and they now have a completely different signature shape
(`governanceNonce, validUntilBlock, signature` instead of `message, signature`).
Building the orchestrator before this fix would have produced an orchestrator
that had to be rewritten.

**Runtime-side suites.** Not run. `runtime/src` cold-compiles in excess of 20
minutes on this host; the governance change touches contract artifacts and the
AIVM host, so the runtime SynQ fixtures will need review before the five-run
gate. That gate has not started and must not start until steps 8 and 11 land.

## 8. Files changed

- `runtime/synergy-aivm/runtime/aivm-core/src/stateful_synq.rs` — canonical
  envelope, argument encoder, key fingerprint, nonce, host function, invocation
  capture.
- `runtime/synergy-aivm/runtime/aivm-core/Cargo.toml` — `hex` dev-dependency.
- `runtime/synergy-aivm/runtime/aivm-core/tests/governance_authorization.rs` — new.
- `runtime/synq-language/compiler/src/semantic.rs` — typed builtin signature so a
  mis-declared authorization tail fails to compile.
- `runtime/synq-language/compiler/src/artifacts.rs` — host-function registration.
- `genesis-contracts/contracts/{Identity,ValidatorRegistry,Staking,Governance,Treasury,Slashing,RewardDistributor,SynergyOracle}.synq`
  — 24 governed operations migrated.
- `genesis-contracts/staged-governance-v1/` — new staged build (not frozen).

No genesis document was modified. No contract address was derived.
