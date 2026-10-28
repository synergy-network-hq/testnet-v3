# Fresh P3 executed-deployment evidence contract

The custody ceremony must execute
`fresh-p3-genesis-predeployment-public-input.json` from an empty execution
state initialized only with that file's 36 balances. It must use the fresh
authority record and the nine canonical contract artifact quadruples in
`genesis-contracts/contracts` (`.synq`, `.compiled.synq`, `.abi.json`, and
`.manifest.json`).

## Exact ceremony boundary

This is a new block-zero deployment, not a continuation of any earlier chain.
The execution driver is the release-built `synergy-genesis-ceremony` binary.
It consumes the canonical public freeze
`fresh-genesis-authority-freeze.json` (not the V4 release-approval authority
view), the P3 predeployment input, the resolved 36-account allocation input,
the 21-validator source input, and the nine canonical contract artifacts.

Before execution, an authorized higher-memory builder must have produced the
release binaries from the CI-verified revision, and the Address Engine binary
must be pinned by its SHA-256.  The ceremony output directories must be new
and empty.  Passphrases are prompted for interactively by the existing
ceremony binary; they must never be passed in a command, environment variable,
or file.

```bash
REPO=/absolute/path/to/testnet-v3
RELEASE=/absolute/path/to/new-ci-verified-p3-release
INPUT="$REPO/launch/posy-v3-genesis-inputs"
ENGINE=/absolute/path/to/synergy-address-engine
ENGINE_SHA256=<sha256-of-that-exact-engine-binary>
IDENTITY_ROOT=/absolute/path/to/testnet-v3-identity-files

"$RELEASE/bin/synergy-genesis-ceremony" \
  --dry-run \
  --authorities-file "$INPUT/fresh-genesis-authority-freeze.json" \
  --allocation-manifest "$REPO/runtime/testnet-allocation-manifest.json" \
  --resolved-allocations "$INPUT/fresh-resolved-allocation-inputs.json" \
  --validator-inputs "$INPUT/fresh-validator-genesis-source-inputs.json" \
  --contracts-dir "$REPO/genesis-contracts/contracts" \
  --source-genesis "$INPUT/fresh-p3-genesis-predeployment-public-input.json" \
  --identity-root "$IDENTITY_ROOT" \
  --address-engine-binary "$ENGINE" \
  --address-engine-sha256 "$ENGINE_SHA256" \
  --output-dir "$RELEASE/fresh-p3-ceremony-dry-run"
```

Only after that status is `DRY_RUN_PASSED`, the same exact inputs and engine
hash may be used with a separate empty execution directory and the dry-run
status path:

```bash
"$RELEASE/bin/synergy-genesis-ceremony" \
  --execute \
  --prior-dry-run-status "$RELEASE/fresh-p3-ceremony-dry-run/dry-run-status.json" \
  --authorities-file "$INPUT/fresh-genesis-authority-freeze.json" \
  --allocation-manifest "$REPO/runtime/testnet-allocation-manifest.json" \
  --resolved-allocations "$INPUT/fresh-resolved-allocation-inputs.json" \
  --validator-inputs "$INPUT/fresh-validator-genesis-source-inputs.json" \
  --contracts-dir "$REPO/genesis-contracts/contracts" \
  --source-genesis "$INPUT/fresh-p3-genesis-predeployment-public-input.json" \
  --identity-root "$IDENTITY_ROOT" \
  --address-engine-binary "$ENGINE" \
  --address-engine-sha256 "$ENGINE_SHA256" \
  --output-dir "$RELEASE/fresh-p3-ceremony-executed"
```

The second command creates the four evidence files named below. It does not
write a canonical Genesis, sign a release, or mutate any node.

The ceremony writes four public files into a new empty directory:

- `execution-status.json`
- `deployment-receipts.json`
- `initialization-receipts.json`
- `execution-state.json`

`execution-status.json` has this exact top-level contract:

```json
{
  "schema_version": 1,
  "artifact_type": "fresh-p3-executed-deployment-evidence",
  "status": "EXECUTION_PASSED",
  "mode": "execute",
  "chain_id": 1266,
  "network_id": "testnet",
  "release_id": "testnet-v3",
  "protocol_version": "posy/3.0",
  "candidate_input_id": "<64 lowercase hex>",
  "inputs": {
    "source_genesis_sha256": "<64 lowercase hex>",
    "allocation_manifest_sha256": "<64 lowercase hex>",
    "resolved_allocations_sha256": "<64 lowercase hex>",
    "validator_inputs_sha256": "<64 lowercase hex>",
    "authority_record_sha256": "<64 lowercase hex>",
    "contract_artifact_set_sha256": "<64 lowercase hex>"
  },
  "contract_artifacts": [
    {"file": "Governance.abi.json", "sha256": "<64 lowercase hex>"}
  ],
  "evidence_files": {
    "deployment_receipts_sha256": "<64 lowercase hex>",
    "initialization_receipts_sha256": "<64 lowercase hex>",
    "execution_state_sha256": "<64 lowercase hex>",
    "execution_state_canonical_sha256": "<64 lowercase hex>"
  },
  "contract_addresses": {
    "Identity": "<fresh derived synq address>",
    "ValidatorRegistry": "<fresh derived synq address>",
    "Staking": "<fresh derived synq address>",
    "Governance": "<fresh derived synq address>",
    "Treasury": "<fresh derived synq address>",
    "Slashing": "<fresh derived synq address>",
    "RewardDistributor": "<fresh derived synq address>",
    "TeamVesting": "<fresh derived synq address>",
    "SynergyOracle": "<fresh derived synq address>"
  },
  "receipt_root": "<64 lowercase hex>",
  "post_deployment_execution_state_root": "<64 lowercase hex>",
  "post_deployment_aivm_state_root": "<64 lowercase hex>",
  "deployment_manifest_hash": "<64 lowercase hex>"
}
```

`contract_artifacts` contains all 36 artifact entries in canonical contract
order and suffix order; it is not a one-entry example in the real output. The
composer recomputes this inventory and its set SHA-256 directly from disk.
`candidate_input_id` is SHA-256 over the sorted, compact JSON encoding of the
exact six-field `inputs` object; the composer rederives it independently.

The receipt files contain exactly nine deployment receipts and 27
initialization receipts. Their AIVM state transitions must be continuous, all
must be successful, and the last initialization state root must equal the
snapshot AIVM root. `execution-state.json` is the runtime's public
`GenesisExecutionSnapshot` for chain 1266/network `testnet`, containing 36
balances, nine deployed contracts, and nine artifacts.

After the runtime ceremony writes these files, run
`scripts/compose-fresh-posy-v3-executed-genesis.py` with the exact inputs. The
composer independently recomputes the combined receipt root and all Genesis
integrity roots, refuses retired identifiers, and writes only a new output
path. The canonical output path is:

`launch/posy-v3-genesis-inputs/fresh-p3-genesis-with-executed-deployment.json`

The composer takes both authority records intentionally. The ceremony freeze
is the record whose digest is included in the executed evidence; the separate
V4 authority view is the record whose digest must occupy
`/genesis_deployment/authority_record_sha256` for the later release-approval
verifier. The composer rejects mismatched entries rather than treating either
record as interchangeable.

```bash
python3 "$REPO/scripts/compose-fresh-posy-v3-executed-genesis.py" \
  --source-genesis "$INPUT/fresh-p3-genesis-predeployment-public-input.json" \
  --allocation-manifest "$REPO/runtime/testnet-allocation-manifest.json" \
  --resolved-allocations "$INPUT/fresh-resolved-allocation-inputs.json" \
  --validator-inputs "$INPUT/fresh-validator-genesis-source-inputs.json" \
  --authority-record "$INPUT/fresh-genesis-authority-freeze.json" \
  --release-authority-record "$INPUT/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json" \
  --contracts-dir "$REPO/genesis-contracts/contracts" \
  --execution-status "$RELEASE/fresh-p3-ceremony-executed/execution-status.json" \
  --deployment-receipts "$RELEASE/fresh-p3-ceremony-executed/deployment-receipts.json" \
  --initialization-receipts "$RELEASE/fresh-p3-ceremony-executed/initialization-receipts.json" \
  --execution-state "$RELEASE/fresh-p3-ceremony-executed/execution-state.json" \
  --output "$RELEASE/fresh-p3-genesis-with-executed-deployment.json"
```

That source then goes to `prepare-fresh-posy-v3-genesis`, which atomically
binds the finalized P3 consensus decision, exact five-validator activation,
and governed ETDAG parameter/fee artifacts into the new pre-anchor output
`fresh-p3-genesis-authorities-bound-pre-anchor.json`.

The existing `testnet-v3-etdag-governed-artifacts` command then derives the
membership anchor from that candidate and attaches it to another new output:
`fresh-p3-genesis-final-authority-bound.json`. The canonical membership trust
anchor is the top-level `/etdag_membership_anchor` object. Renderers and release
gates must reject the predeployment, executed-only, and pre-anchor files.
