# Fresh P3 executed-deployment evidence contract

The custody ceremony must execute
`fresh-p3-genesis-predeployment-public-input.json` from an empty execution
state initialized only with that file's 36 balances. It must use the fresh
authority record and the nine canonical contract artifact quadruples in
`genesis-contracts/contracts` (`.synq`, `.compiled.synq`, `.abi.json`, and
`.manifest.json`).

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

That source then goes to `prepare-fresh-posy-v3-genesis`, which atomically
binds the finalized P3 consensus decision, exact five-validator activation,
and governed ETDAG parameter/fee artifacts into the new pre-anchor output
`fresh-p3-genesis-authorities-bound-pre-anchor.json`.

The existing `testnet-v3-etdag-governed-artifacts` command then derives the
membership anchor from that candidate and attaches it to another new output:
`fresh-p3-genesis-final-authority-bound.json`. The canonical membership trust
anchor is the top-level `/etdag_membership_anchor` object. Renderers and release
gates must reject the predeployment, executed-only, and pre-anchor files.
