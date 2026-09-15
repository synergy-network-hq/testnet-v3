# Phase 8 — corrected plan (nine contracts, deployment-derived addresses)

Supersedes the acceptance criteria in `launch/LAUNCH_CHECKLIST.md` and the
ruling in `PHASE_8_DEPLOYMENT_FINDINGS.md` §5. Operator rulings 2026-07-27.

## Governing model

FN-DSA-derived Synergy addresses are contract **identity / custody** records.
Deployed SynQ contract **instances** take addresses from the canonical
deterministic deployment derivation. The two are separate fields and are never
conflated.

Roles kept distinct: genesis deployer (derives addresses, authorizes genesis
installation) · treasury wallet (funds and holds assets) · contract identity
(administrative/custody identity) · contract instance address (derived) ·
contract administrator (governance/multisig, assigned per contract after
deployment).

## Scope: nine contracts, not ten

SaleClaim is **removed from Testnet-v3**. Claims cannot begin until Mainnet-beta
and Testnet-v3 tokens have no redemption value, so its redemption architecture
must not be frozen under launch pressure. Source and research preserved and
marked `DEFERRED_TO_MAINNET_BETA — NOT ACTIVE OR DEPLOYED ON TESTNET-V3`.

On Testnet-v3: no claim endpoint, no claim UI, no voucher redemption, no
Base-token migration, no issuance from presale evidence, no placeholder attestor
set, no placeholder constructor inputs, **no reserved nonce**.

Testnet-v3 launch is blocked on the nine-contract deployment only.

## Deployment order and nonces

The dependency graph was checked, not assumed: **no contract's `init_params`
references another contract's address**, so there are no genesis-time ordering
constraints. Cross-contract access is runtime host-capability/registry based.
The canonical order below is therefore free to adopt and is fixed for
determinism.

| nonce | contract |
|---|---|
| 0 | Identity |
| 1 | ValidatorRegistry |
| 2 | Treasury |
| 3 | Governance |
| 4 | Staking |
| 5 | Slashing |
| 6 | RewardDistributor |
| 7 | SynergyOracle |
| 8 | TeamVesting |

Nonce 9 is **not** reserved. Nonces are fixed in the deployment manifest and may
not depend on execution timing, machine state, filesystem order, hash-map order,
or prior failed attempts.

## Genesis Deployment Authority

One new dedicated account, e.g. *Testnet-v3 Genesis Deployer*. Governed
account/deployment signing profile — **not** a validator consensus key, node
key, WireGuard key, or contract identity key. Not the treasury, Foundation
operating wallet, a developer wallet, or any individual's everyday wallet.

- single deployer for all nine contracts, nonces 0–8;
- deployer address, order, nonces, constructor hashes and artifact hashes bound
  into the signed deployment manifest;
- no treasury allocation beyond the runtime minimum — ideally zero if
  genesis-system deployment charges no real fees;
- deployment authority permanently revoked once final genesis is signed; it must
  not remain a general-purpose hot deployer.

Custody: preferred a dedicated threshold-controlled authority (e.g. 3-of-5,
shares held separately). Acceptable for testnet: a dedicated encrypted deployer
key in the existing custody system with the deployment manifest approved by
multiple operators before signing.

**This account does not exist yet and is the gating input** — every one of the
nine addresses derives from its address, and `verifier.rs::expect_address`
requires that address to be derivable from the deployer's public key under the
SynQ address scheme.

## Derivation inputs (all required, none omitted)

Chain ID `1266` · network ID `synergy-testnet-v3` · protocol version ·
address-derivation version · algorithm identifier · deployer address · nonce ·
payload hash · bytecode hash · ABI hash · manifest hash · constructor-arguments
hash.

Verified from the code: `payload_hash = hash_contract_deploy_body(bytecode_hash,
manifest_hash, abi_hash, signer_address, constructor_args_hash)` — no
timestamps, so `not_before_unix` / `expiration_unix` cannot leak into an address.
There is **no salt field** in `SynQSigningPayload`; nonce is the sole
disambiguator. Deriving an address needs only public inputs — custody is
required to *execute* a signed deploy, not to derive.

No manual address selection. No derivation from contract names. No derivation
from FN-DSA public keys.

## BLOCKER FOUND — the deploy verifier rejects ML-DSA-87 today

Traced as instructed rather than assumed. The policy the runtime actually uses
for SynQ admission is `SynQSecurityPolicy::testnet_1266_policy()`
(`runtime/src/synq_admission.rs:1394`), and it reads:

```rust
let mut tx = BTreeSet::new();
tx.insert(AlgorithmId::MlDsa65);
let deploy = tx.clone();
let call = tx.clone();
```

`verifier.rs::validate_algorithm_policy` checks
`allowed_deploy_signature_algorithms.contains(&algorithm)` and returns
`UnsupportedAlgorithm` otherwise. **An ML-DSA-87 deploy envelope is rejected
today.** `AlgorithmId::MlDsa87` exists (code `0x0103`) and clears
`min_signature_security_level: Level3`, so the only obstacle is the allow-list.

This is a domain conflation, not just a missing entry. Session-6 moved
user/account transactions to **ML-DSA-87** and kept consensus on **ML-DSA-65**,
but the SynQ admission policy still names ML-DSA-65 as the transaction, deploy
**and** call algorithm — i.e. it is using the *consensus* algorithm for the
*account* domain, which `CRYPTOGRAPHIC_IDENTITY_PROFILE.md` forbids. The same
policy would reject ML-DSA-87 user contract calls, so this is a latent runtime
defect independent of the deployer question.

**This must be fixed before the deployer identity is generated**, because the
deployer's algorithm is an input to its address and therefore to all nine
contract addresses. Do not substitute FN-DSA or ML-DSA-65 to work around it.

Proposed fix, pending operator confirmation because it changes a PQ security
policy: set `allowed_tx_signature_algorithms`, `allowed_deploy_signature_algorithms`
and `allowed_call_signature_algorithms` to the governed **account** domain
(ML-DSA-87), with ML-DSA-65 retained on the deploy/call paths only for as long
as existing fixtures need it, then removed. Blast radius: every existing SynQ
test signs with ML-DSA-65, so the fixtures migrate with the policy.

### What was actually wrong — two layers, not one

The allow-list was only the first layer. `signature.rs::verify_signature`
implemented **ML-DSA-65 alone**; every other algorithm hit
`_ => Err(UnsupportedAlgorithm)`. The `MlDsa87` enum variant existed with a code
and a security level but had **no verification arm at all**, so ML-DSA-87
envelopes could never have verified no matter what the policy said.

Applied per the operator ruling (ML-DSA-87 only, migrate fixtures):

1. `policy.rs::testnet_1266_policy()` — tx/deploy/call set to `MlDsa87`.
2. `signature.rs::verify_signature` — ML-DSA-87 arm added; both arms refactored
   through a `verify_with` helper so the public-key and signature length checks
   run for every algorithm rather than only ML-DSA-65.
3. Runtime SynQ fixtures in `synq_admission.rs`, `execution.rs` and
   `rpc_server.rs` migrated to `Sign::mldsa87()` / `AlgorithmId::MlDsa87`.

`derive_synq_address` needed no change — it embeds `algorithm.code()` and is
algorithm-agnostic.

Result: SynQ-path failures went **12 → 4**. Deploy and call envelopes now verify
under ML-DSA-87.

### STILL OPEN — contract manifests still require ML-DSA-65

The last 4 failures are not fixture noise. `synq_admission.rs:1087` enforces:

```rust
if algorithm != "ML-DSA-65" {
    return Err(invalid_sts9("manifest required_signature_algorithm must be ML-DSA-65"));
}
```

That reads `required_signature_algorithm` out of each **compiled contract
manifest**, and all nine manifests declare `ML-DSA-65`. So the contract
manifests must move to ML-DSA-87 as well — which means changing what the SynQ
compiler emits, which changes every manifest hash, every artifact binding and
therefore every derived address.

That is acceptable because all nine are being regenerated anyway, but it is a
**compiler change, not a fixture edit**, and it must land before artifacts are
frozen (sequence step 2). Do not paper over it by relaxing the check to accept
either algorithm — that would reintroduce the cross-domain conflation this whole
correction exists to remove.

Until it lands, these 4 tests are expected red and are tracked deliberately:
`synq_admission::synq_deploy_carrier_verifies_through_pqsynq`,
`synq_admission::synq_call_carrier_verifies_through_pqsynq`,
`execution::synq_deploy_carrier_reaches_receipt_through_node_admission`,
`aegis_tx_tool::real_aegis_transaction_preserves_synq_admission_summary`.

## Sequence

1. Create the Genesis Deployment Authority through the custody workflow.
2. Freeze all nine artifacts and constructor inputs (source, bytecode, ABI,
   manifest and their hashes; constructor schema and arguments; host
   capabilities; derivation version).
3. Separate `contract_identity` and `deployment` blocks in the genesis schema;
   add a structural checker that fails when an identity-derived address appears
   in a deployed-contract field.
4. Build the genesis system-deployment mechanism — none exists today; it must
   execute the same canonical address derivation and AIVM initialisation as
   governed SynQ deployment, superseding direct artifact-to-identity binding.
5. Derive the nine addresses; publish deterministic test vectors.
6. Execute the deployment three times — clean current environment, fresh state
   database, clean checkout/build — requiring byte-identical addresses,
   receipts, events, storage roots, aggregate roots and post-deployment AIVM
   state root.
7. Bind all nine **atomically**, then recompute in dependency order: contract
   records → state root → data root → contract hash/root → header → genesis hash
   → network magic → release integrity manifest.
8. Migrate every reference workspace-wide with an explicit old→new map, leaving
   identity/custody records alone.
9. Rebuild fixtures against the final nine-contract genesis. Do not patch tests
   around an eight- or nine-contract mixed state.
10. Only then regenerate ceremony challenges and perform custody signing.

## Current state

Reverted to the pre-TeamVesting baseline: genesis hash `ac5186cb…008407`,
network magic `845e8eca`, eight artifacts bound, diagnostics 3/3 green. Both
values remain **candidates** and will change after the nine-contract deployment.
Nothing has been bound under the corrected model yet.
