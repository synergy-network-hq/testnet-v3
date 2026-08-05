# rebind-testnet-v3-single-authority — derived specification

Status: **specification complete, implementation not started.**
Derived 2026-08-05 from the launch worktree at HEAD `5815dd8`
(branch `release/chain1266-single-authority`, clean, all 11 required commits ancestors).

## Input document

    launch/production-node-configs/canonical-genesis/genesis.json

* file sha256 `2e60911ceea6fe73dfe95a2b2a1b74770043d154b5c5c8c359084e70a44431fe`
  (sidecar `genesis.json.sha256` agrees)
* **owner-supplied `d79053eb9225…6902042` is NOT the file hash** — it is the
  internal field `.integrity.genesis_hash`. The tool's step-2 input check must
  assert against that field, not against a sha256 of the file.
* Identical content also at `genesis.testnet-v3.identity-assigned.json` and
  `launch/production-genesis-ceremony/genesis.testnet-v3.final-candidate.json`.
  `runtime/config/genesis.testnet-v3.test-fixture.json` differs (`4453ecf9…`).

## Canonicalization contract (from `.canonicalization`)

    hash_algorithm : blake3-256          <-- NOT sha256
    json_profile   : deterministic_sorted_keys_no_insignificant_whitespace

`genesis_hash_inputs` (25 sections, in order): header, network, token,
accounts, allocations, balances, address_assignment_register, validators,
node_identities, contract_identities, consensus, execution, crypto, contracts,
modules, governance, security, synergy_state, system_reserved_addresses,
vesting, custody_controls, upgrade, consensus_parameters, genesis_deployment,
contract_address_migration.

`excluded_from_genesis_hash`: `integrity.genesis_hash`, `integrity.signed_by`,
`network_magic_bytes`.

Note the active validator set lives in the **top-level `validators`** section;
`.consensus.validators` is empty in this document.

## Roots and digests to recompute (`.integrity`, 15 keys)

allocation_hash, consensus_parameter_decision_id,
consensus_parameter_manifest_sha256, consensus_parameter_root_sha3_512,
contract_hash, deployment_manifest_hash, genesis_hash,
post_deployment_aivm_state_root, post_deployment_execution_state_root,
receipt_root, signed_by, state_root, status, validator_hash,
validator_set_hash.

Also `.execution`: genesis_aivm_state_root, genesis_execution_state_root,
genesis_receipt_root, genesis_deployment_manifest_hash.

## Required output bindings

    chain_id                    1266
    chain_incarnation           5
    network_id                  synergy-testnet-v3
    consensus_protocol          single_authority_v1
    release_id                  chain1266-incarnation-5-single-authority-rc1
    authority_id                authority-node-01
    identity catalog ID         NODE-AUTHORITY-01
    authority address           synv11n57gc4h9tnt3c78crncx46hnlg9vz8eu4lu
    authority peer ID           ca2903a8cc1f2db03a5b9a7c18a82d268598c23529e85371c647902df5d19fd9
    target_block_time_ms        1000
    first_authority_height      1
    pending_consensus_transition null
    bootstrap fingerprint       sha256:c39e17970a711cadbbb6e43f49f322b14bb1710a2fb6c90822b081fe7f5ce5b4

Current `.consensus` is `algorithm=ProofOfSynergy`, `model=cluster_dag_hybrid`
— to be replaced wholesale by the `single_authority_v1` profile.
`.integrity.consensus_parameter_decision_id` is currently
`TV3-POSY-PARAMS-2026-07-28-01` and **must not remain** the active consensus
authorization.

Public bundle to bind (all from `authority-node-01.pub.json`, host synergy-val):
FN-DSA-1024 identity, ML-DSA-87 account, ML-DSA-65 consensus, ML-KEM-768
entropy, Ed25519 peer, synv1 address, peer ID, key-bundle hash.
pub.json sha256 `57a7e20d9ca11b167180b5a39df5563dbf9a5142cf8ff694e3dca0bfb2759b09`.

Preserve unchanged: allocations, supply, balances, contract addresses, contract
state, execution snapshot, historical identity records. Old validator stake
accounts remain as execution accounts only — not producers, voters, quorum
members or signing authorities.

## Existing tooling — reuse, do not rewrite

* `runtime/src/bin/chain1266-single-authority-bootstrap.rs` — **already
  implements DesiredStateV2** for this exact incarnation. Constants already
  match: CHAIN_ID 1266, CHAIN_INCARNATION 5, NETWORK_ID synergy-testnet-v3,
  AUTHORITY_ID authority-node-01, TARGET_BLOCK_TIME_MS 1000, ROLE_ID
  `SNRG-TESTNET-V3-SINGLE-AUTHORITY-BOOTSTRAP`. Subcommands:
  generate-bootstrap-identity / build / sign / verify. Signing domain
  `SYNERGY_CHAIN1266_START_CONSENSUS_V2`. Explicitly does not touch Genesis.
  → Owner steps 8.3 and 8.4 need **no new tool**.
* `runtime/src/bin/bind-testnet-v3-consensus-genesis.rs` — closest analogue for
  the Genesis consensus binding; model the new tool on it.
* `runtime/src/bin/advance-testnet-v3-chain-incarnation.rs` — precedent for a
  deterministic one-shot Genesis mutation (used by c712e91).
* `runtime/src/bin/build-chain1266-consensus-activation.rs`,
  `sign-chain1266-consensus-activation.rs` — activation path.

## Runtime key configuration

    SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE=/var/lib/synergy/keys/mldsa65-consensus/private.key

Installed on synergy-val: 0600 synergy:synergy, sha256
`b5a6e5e7c91ec7c01c2ade65569f8704cb129bf08f43df3b26977054f4b0bf3b`,
decoded length 4032 bytes (FIPS 204 ML-DSA-65 secret key). Do not rely on the
default provisioner path
(`/var/lib/synergy/validator/config/validator/mldsa65-consensus.private.key`).

## Output layout

New candidate directory (do not overwrite RC30 or earlier). Signed
`release_id` must be `chain1266-incarnation-5-single-authority-rc1` regardless
of the directory label. Write to a temporary candidate dir, validate, then
promote atomically.


---

# Round 2 findings — these change the tool's design

Derived from `runtime/src` at HEAD `5815dd8`.

## The consensus protocol does NOT live in Genesis

`single_authority_v1` appears in `desired_state_v2.rs`, `config/mod.rs`,
`role_runtime.rs` and `consensus/single_authority_*` — **and nowhere in
`genesis.rs`**. `role_runtime.rs:1210`: *"single_authority_v1 requires a
verified ML-DSA-87 signed DesiredStateV2 activation"*.

So the owner-listed fields `consensus_protocol`, `release_id`,
`target_block_time_ms`, `first_authority_height`,
`pending_consensus_transition` and the bootstrap fingerprint are
**DesiredStateV2 fields**, not Genesis fields. Their schema
(`desired_state_v2.rs`, `consensus_binding`) is:

    protocol, authority_id, authority_public_key_fingerprint,
    target_block_time_ms, authority_start_height, authority_end_height,
    pending_consensus_transition

plus top level: schema_version 2, chain_id, chain_incarnation, network_id,
directory_namespace, release_id, genesis_hash,
authority_public_key_fingerprint, execution_configuration_fingerprint.

`chain1266-single-authority-bootstrap.rs` already emits exactly this. **Do not
add these fields to Genesis.**

## What Genesis is actually required to carry

The only path permitted to select the driver is
`consensus::single_authority_startup::resolve_verified_consensus_startup`
(`config/mod.rs:749` doc comment). Its `StartupExpectation` reads five Genesis
values and `verify_genesis_identity` (line 258) checks:

    genesis_chain_id            == 1266   (LAUNCH_CHAIN_ID)
    genesis_chain_incarnation   == 5      (LAUNCH_CHAIN_INCARNATION)
    genesis_network_id          == synergy-testnet-v3
    genesis_directory_namespace == chain-1266/incarnation-5
    genesis_hash                   non-empty

Launch constants at `single_authority_startup.rs:37-41` already equal the
targets, including `LAUNCH_TARGET_BLOCK_TIME_MS = 1_000` and
`LAUNCH_AUTHORITY_ID = "authority-node-01"`.

**`verify_genesis_identity` does not inspect the Genesis validator set.** The
6→1 strip is therefore a defence-in-depth policy requirement, not a driver
precondition — it should still be done, but it cannot be justified by "the
runtime needs it", and it must not be allowed to break the preservation list.

## Unresolved tension — needs an owner decision before implementation

`recompute_testnet_v3_candidate_integrity` (`genesis.rs:940`) derives:

    integrity.validator_hash      <- hash_json(validators)
    integrity.validator_set_hash  <- hash_json(contracts.validator_registry
                                                .init_params.validators)
    integrity.contract_hash       <- hash_json(contracts)
    integrity.state_root          <- includes contracts + validators + consensus

It also *writes back*
`contracts.validator_registry.init_params.validator_set_hash`.

So removing the six validators from
`contracts.validator_registry.init_params.validators` **is a modification of
contract state**, which the owner's preservation list forbids
("do not delete ... contract addresses, contract state").

Two coherent readings:

* **(a) recommended** — strip the six only from the top-level `validators`
  section (the active consensus / validator-runtime set) and leave the
  ValidatorRegistry contract's `init_params.validators` intact. Preserves
  contract state and the historical registry; consistent with "old validator
  stake accounts may remain as execution accounts, but must not be active
  producers, voters, quorum members or signing authorities".
* **(b)** — strip from both, which rewrites deployed contract state and
  contradicts the preservation list.

These produce different `genesis_hash` values, so the choice must be made
before the candidate is generated, not after.

## Revised tool scope

Much smaller than first assumed:

1. Load canonical Genesis; assert `.integrity.genesis_hash == d79053eb…`.
2. Snapshot allocations / token supply / balances / contracts / execution.
3. Set chain identity fields (chain_id, chain_incarnation, network_id,
   directory_namespace) — verify they already equal the targets from c712e91.
4. Replace the active `validators` set per decision (a) or (b).
5. Replace the `consensus` profile (currently `algorithm=ProofOfSynergy`,
   `model=cluster_dag_hybrid`) and clear the PoSy activation binding so
   `TV3-POSY-PARAMS-2026-07-28-01` is no longer the active authorization.
6. Call `recompute_testnet_v3_candidate_integrity(&mut value)` — this performs
   the owner's entire step 10 (header roots, allocation/validator/validator_set/
   contract hashes, state_root, data_root, receipts_root, genesis_hash,
   network_magic_bytes) and self-validates via
   `validate_testnet_v3_candidate_integrity_hashes`.
7. Diff against the step-2 snapshot; abort on any unexpected change.
8. Write candidate + `.sha256` sidecar to a new temp dir; validate; promote
   atomically.

Then DesiredStateV2 via the existing bootstrap tool (`build`, `sign`,
`verify`), binding the Genesis hash produced in step 8.


## OWNER DECISION (resolved) — strip scope = TOP-LEVEL VALIDATORS ONLY

* Replace the top-level active validator set with only NODE-AUTHORITY-01.
* Do **not** modify `contracts.validator_registry.init_params`.
* Do **not** insert NODE-AUTHORITY-01 into the contract registry.
* Do **not** remove the existing validators from the contract registry.
* Preserve exactly: validator count, validator-set hash, entries, contract
  storage, deployment receipts, execution snapshot, resulting state root.

Rationale of record: under `single_authority_v1` the preserved
validator-registry contract state is **not a consensus-input surface**. It is
legacy execution state carried forward for continuity.

Required protocol-aware validations to add:

1. The top-level active consensus set contains exactly NODE-AUTHORITY-01.
2. The single-authority driver never reads the validator-registry contract to
   select producers, voters, quorum members or signing authorities.
3. The preserved registry validators cannot produce, vote or affect finality.
4. The validator-registry subtree digest is identical before and after rebind.
5. The contract execution-state root is unchanged by the 6→1 consensus rebind.
6. Any code path attempting to derive single-authority membership from the
   contract registry fails closed.

The future PoSy activation performs a separate, explicitly authorized
contract-registry transition at its activation height. That migration must
**not** happen inside the initial single-authority Genesis.

Implementation note: `integrity.state_root` and `header.state_root` necessarily
change, because `validators` and `consensus` are inputs to both. That is
expected and is not a violation of the preservation list. The invariants
asserted are subtree equality of `contracts`, `genesis_deployment`,
`execution`, `allocations`, `balances`, `accounts`, `token`, plus
`integrity.contract_hash`, `integrity.validator_set_hash`,
`integrity.allocation_hash` and the two execution roots.


---

# Round 3 findings — implement in Python, not Rust

## The canonical Genesis tool is `runtime/scripts/testnet/genesis_tool.py`

`key_bundle_hash`, `validator_id_hash` and `metadata_hash` are **never derived
anywhere in Rust** — `runtime/src` and the address engine only ever *read*
them. They are produced by `genesis_tool.py` (line ~206). The rebind therefore
belongs as a subcommand of that tool, which already owns validator-entry
construction and the `hash_json` canonicalisation. A new Rust bin would have to
re-derive three digests it does not own.

## Exact digest derivations (genesis_tool.py:205-225)

    key_bundle_hash = hash_json({
        account_public_key, consensus_public_key, identity_public_key,
        node_identity_public_key, peer_id })

    metadata_hash   = hash_json({
        address, address_type, algorithm, created_at, validator_id })

    validator_id_hash = hash_json({ "validator_id": validator_id })

**Quirk that must be replicated exactly:** in `genesis_tool.py` the field
`identity_public_key` is populated from the **entropy** key
(`entropy.get("public_key")`), not from the FN-DSA-1024 identity key — see the
`public_bundle` literal. Every existing genesis validator entry was built this
way, so the authority entry must be built the same way or its
`key_bundle_hash` will not be comparable with the other six.

Note also `genesis_tool.py` defaults `consensus_key_type` to `FN-DSA-1024` when
absent; the real bundle supplies `ML-DSA-65`, which is what the existing
entries carry.

## TRAP — do not replace the `consensus` block wholesale

`consensus.state_directory_namespace = "chain-1266/incarnation-5"` is the
source of `StartupExpectation.genesis_directory_namespace`
(`role_runtime.rs:1296` builds it; `verify_genesis_identity` at
`single_authority_startup.rs:274` requires it to equal
`chain-1266/incarnation-5`).

Replacing the whole `consensus` object would drop this key and make the node
fail startup verification with a namespace mismatch. Preserve
`state_directory_namespace` (and audit the rest of the block for other
identity-bearing keys) when swapping the PoSy profile out.

## Top-level validator entry schema (28 fields, from entry 0)

    account_key_type ML-DSA-87        account_public_key <b64>
    activation_height 0               address_type synv1
    allocation_account_id VNS-A02     commission_rate_bps 500
    consensus_key_type ML-DSA-65      consensus_public_key <b64>
    deactivation_height null          entropy_contribution_key <b64>
    entropy_key_type ML-KEM-768       identity validator-1
    identity_key_type FN-DSA-1024     identity_public_key <b64>
    key_bundle_hash <hex>             metadata_hash <hex>
    moniker "Synergy Validator 1"     node_identity_key <b64>
    node_identity_key_type Ed25519    operator_address synv11yc4cje…
    peer_id aa4ce949…                 reward_address synv11yc4cje…
    slashing_status none              stake_nwei 50000000000000
    status active_at_genesis          validator_id validator-1
    validator_id_hash <hex>           voting_power 100

Entry 0 is `allocation_account_id VNS-A02`, `operator_address
synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t` — i.e. the six genesis validators
include Val1/VNS-A02, the prior identity of the same physical host now
carrying NODE-AUTHORITY-01.

## Remaining open item

`hash_json` in `genesis_tool.py` must be confirmed byte-identical to the Rust
`hash_json` (`genesis.rs:1409` → `blake3` over `canonical_json`) before the
candidate is generated, otherwise the Python-written digests will not validate
under `recompute_testnet_v3_candidate_integrity`.


---

# Round 4 — cross-language hash gate RESULT

Gate script: `runtime/scripts/testnet/hash_equivalence_gate.py` (re-runnable).

## Canonicalization: PASS — Python ≡ Rust

Python `genesis_tool.canonical_json` + blake3 reproduces digests that the Rust
`recompute_testnet_v3_candidate_integrity` path wrote into the canonical
Genesis:

    integrity.allocation_hash      MATCH
    integrity.validator_hash       MATCH
    integrity.contract_hash        MATCH
    integrity.validator_set_hash   MATCH
    integrity.genesis_hash         MATCH   <- d79053eb…6902042, whole document

Reproducing `integrity.genesis_hash` over the entire document — including the
`genesis_hash_inputs` selection and both exclusion lists — is conclusive. No
alignment work is needed; the two serializations are byte-identical for all
types present. Golden vector (unicode, floats, ints, escapes, empty
containers, key ordering), 244 utf-8 bytes:

    blake3 = 012673694dbbe9e6742893dbedf0b1035912fb081029e26f7c84c2e087165578

## BLOCKER — the per-validator digest convention is not `hash_json`

The three per-validator digests were **not** produced by
`genesis_tool.py::build_public_bundle`. That function's
`for preserved_field in [...]` loop (line 239) copies them straight from its
input payload when present, so genesis_tool only ever carried upstream values
through. The real conventions:

    validator_id_hash = blake3(validator_id raw utf-8)     RECOVERED
                        verified against all six entries (v0-v5 OK)
                        NOT hash_json({"validator_id": ...})

    key_bundle_hash   = UNRECOVERED
                        pinned v0 = 1af3868b5a3378e25b9f23f048296b377392d7a
                                    50dab26abb177c1f9b3e71e0a
                        hash_json formula gives 670a0bfd3dd3946e…  (differs)
                        16 raw-concatenation permutations tried
                        (5 key fields x 4 separators x orderings) — no match

    metadata_hash     = UNRECOVERED
                        pinned v0 = 1bb581193619b980f57e8d182c5576c710e1fcdd
                                    ad4fb583aee9ad4b6a13234c
                        hash_json formula gives 5322ea59be1e4896…  (differs)
                        12 candidates tried — no match

The minting tool is in neither `runtime/` nor the address engine. It predates
both and produced the values fed into the c712e91 ceremony.

## Consequence for NODE-AUTHORITY-01

The instruction "derive the three through the existing Python-owned
`hash_json` functions" is implementable, but it would give the authority entry
a **different digest convention from the six preserved entries in the same
document** — `hash_json`-based rather than the historical raw-blake3 /
unknown-preimage convention.

Nothing in the Rust recompute or `verify_genesis_identity` reads these three
fields, so it does not break startup. It is a provenance inconsistency inside
one Genesis, not a functional failure. Options:

* **(a)** `validator_id_hash = blake3("authority-node-01")` (matches the
  recovered historical convention exactly), and `key_bundle_hash` /
  `metadata_hash` via `hash_json` with the field set documented above — a
  documented, reproducible convention for the new entry, noted as differing
  from the unrecoverable historical one.
* **(b)** locate the original minting tool and reproduce all three.
* **(c)** all three via `hash_json` as literally instructed, accepting that
  `validator_id_hash` then also diverges from the six.

This is the one exact mismatch to report; candidate generation is otherwise
unblocked.
