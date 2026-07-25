# Synergy Testnet Validator Onboarding Process (Jarvis-Driven, v2)

This runbook covers the full path from a fresh machine to an active Testnet validator using the Node Control Panel `Testnet` onboarding flow in `node-control-panel`.  
It is a sequential operator playbook; all state-changing steps are performed by Jarvis with explicit gate checks.

## Scope and constants

- Network: `chain_id=1264`, `network_id=synergy-testnet-v3`
- Required stake: `50,000 SNRG` (`50_000_000_000_000 nWei`)
- Validator role only (role class 1)
- Maximum post-snapshot catch-up gap: `10,000` blocks
- Maximum head sync gap for activation: `2` blocks
- Validator address prefix: `synv1` (canonical validator identity)
- Dashboard handoff is blocked until activation confirmation evidence is recorded and valid.

## 0) First launch: Jarvis checks for an existing setup

On startup, Jarvis scans local testnet setup state for an existing validator workspace.

- If validator files are found:
  - Jarvis message:  
    - `I found validator setup files on this machine at <workspace> for <address>.`  
    - `Do you want me to continue setting up that validator, or start over fresh with a new validator?`
  - Operator choices:
    - **Continue Existing Setup**
    - **Start Over**
- If no setup is detected, Jarvis proceeds into new setup prompts:
  - `I am Jarvis, your setup assistant.`
  - `I will be assisting you in setting up a new Synergy Network validator node.`
  - `I will create the validator appliance root, generate the node address and signing keys, write the runtime configuration, and prepare the required stake.`

## 1) Continue Existing Setup vs Start Over

### Continue Existing Setup

Only choose this when the same machine/workspace is being reused to finish a previously interrupted setup.

Jarvis behavior:
- Validates the existing local node record is present.
- If resumable:
  - `I will continue setup with the existing validator <address>.`
- If not resumable (stale or missing setup record):
  - `I found validator files at <workspace>, but I do not see a local setup record that I can safely resume. Choose Start Over and I will erase the stale local validator files before provisioning a fresh validator.`
- If activation confirmation already exists:
  - `This validator already has activation confirmation evidence. I am opening the dashboard now.`

### Start Over

From the choice screen, selecting Start Over triggers local setup state cleanup and restarts a fresh flow:

- `I erased the existing local validator files. I will continue with a fresh validator onboarding flow.`

Use this path if:
- The previous setup was interrupted before identity/signing files were fully written.
- You need to switch public host, appliance path, or operator passphrase.
- You must clear stale, half-built setup artifacts.

## 2) Provisioning a new validator appliance

Jarvis creates and/or validates the validator root layout before first runtime start.

### What gets built

When reviewing directory choice, Jarvis states:

`It will use the current appliance layout with identity, config, state, evidence, logs, runtime, and rollback directories.`

At minimum, this includes:

- `identity/`
- `config/`
- `state/`
- `evidence/`
- `logs/`
- `runtime/`
- `rollback/`

From architecture docs, the canonical layout also uses:
- `state/store/consensus.db`
- `state/derived/`
- `state/checkpoints/`
- `state/snapshots/`
- `state/quarantine/`

### Linux default path

- Linux validator path: `/var/lib/synergy/validator`
- Cross-platform desktop defaults are resolved under home directories, then normalized by Jarvis.

### Provision step details

When provisioning:

1. Confirm role = `validator`.
2. Confirm public host/IP/DNS.
3. Confirm appliance root and proceed.
4. Set identity passphrase (minimum 8 characters; enforced by backend).
5. Jarvis writes key material to `identity/`, plus workspace config in `config/`.

Critical backend preconditions for provisioning:
- Role class must be validator.
- Public host must be routable when public validators are used.
- Identity passphrase must be present and meet minimum length.
- Role-specific config and identity files are generated in one workspace initialization path.

## 3) Generated validator identity (`synv1...`) and validation

Jarvis generates a class-1 validator identity during workspace provision:

- Validator identity files: `identity/public.key`, `identity/private.key`, `identity/address.txt`, `identity/identity.json`
- Address is displayed to the operator before funding:
  - `Your new validator address is <synv1...>.`

## 4) Archive snapshot restore (required before funded onboarding)

For validator onboarding, control flow requires restoring an archive-produced validator-pruned snapshot first.

Jarvis messages:
- `The validator workspace is provisioned. I am now going to grab the latest validator-pruned chain snapshot from the archive validator and apply it to this validator.`
- Terminal/Status: `Downloading the latest validator-pruned snapshot from the archive validator...`
- `Applying verified snapshot state to the validator appliance...`
- `Snapshot applied to the validator state.`
- `The snapshot is applied. I am starting the validator runtime now so it can catch up from the restored state.`

Backend snapshot evidence names used by onboarding:
- `logs/evidence/validator-pruned-snapshot-restore.json`
- `logs/evidence/validator-pruned-snapshot-sync-complete.json`

### Post-snapshot catch-up requirement

Jarvis waits for two thresholds:

1. Snapshot catch-up must be reduced to `<= 10,000` blocks from snapshot height to head.
2. Final head sync must be reduced to `<= 2` blocks before onboarding funds.

Jarvis explicit blocker text when catch-up requirement is not met:

- `The archive validator's latest snapshot is <N> blocks behind the verified chain head. Jarvis will not continue because new validators must start within 10,000 blocks after snapshot restore. The archive validator needs to publish a newer validator-pruned snapshot.`

If successful:
- `The validator is now catching up from the restored snapshot. I am going to wait here until it is synced to the chain head before asking for funding.`  
  and then  
  `The validator is synced to the chain head and ready for funding.`

The catch-up gates are backed by `validator-pruned-snapshot-restore.json` + `validator-pruned-snapshot-sync-complete.json` verification checks.

## 5) Funding phase (request + tx-hash capture)

After head sync:
- Jarvis prints funding instruction with exact amount and validator address.
- Example:
  - `Your new validator address is <synv1...>. Please request 50,000 SNRG from the project team for that synv1 validator address.`
  - `I'll wait here while you do that. Just let me know once the team has sent it so we can continue with onboarding.`

Operator action:
- Respond with **“The team sent the SNRG”**.

Jarvis then asks for tx hash:
- `Great. Please paste the transaction hash the project team provided for the 50,000 SNRG transfer.`

Acceptance conditions:
- Tx hash is recorded in evidence (`validator-funding-operator-report-...json`) by `testnet_record_validator_funding`.
- Live preflight sees liquid balance or staked balance >= required minimum.

If not ready yet:
- `The transaction hash is recorded, but the validator wallet balance is not visible yet. I will wait here; click The team sent the SNRG again once the transaction is final.`

If user hasn’t clicked:
- `I am waiting here. Click The team sent the SNRG once the project team has sent the validator funding.`

## 6) Staking 50,000 SNRG

Once funding is visible:
- `Funding is visible. I am staking 50,000 SNRG to the validator now.`

Staking checks (must pass before stake tx can submit):
- `validator-role`
- `canonical-validator-address`
- `canonical-workspace-genesis`
- `canonical-chain-state`
- `post-fork-fndsa-metadata`
- `fndsa-consensus-key`
- `local-rpc`
- `liquid-balance`
- `local-signing-key`
- `runtime-wallet-loaded`

Failure clues:
- If funding is visible but preflight blocks:
  - `Funding is visible, but staking is still blocked by: <failed checks>. I will keep this setup session open so we can retry.`
- If runtime wallet or signing key is missing:
  - `Local signing key` suggestion: re-run setup / generate or import identity.
  - `Runtime wallet loaded` suggestion: restart or resume chain sync after runtime imports key material.
- If address/type mismatch:
  - Preflight will not allow staking for non-canonical addresses.

## 7) Evidence and activation gates

After stake is confirmed, Jarvis runs onboarding evidence checks repeatedly:

- `The required stake is bonded. I am running the remaining onboarding evidence checks now.`

The activation policy requires all of these gates to pass:

1. **Source-majority proof**
   - `source-majority-proof.json`
   - Requires a trusted head match from at least 3 sources.
   - Must not be public-RPC-only.
2. **Shadow epoch proof**
   - `validator-onboarding-shadow-epoch-1.json` (or compatible proof path)
   - One full shadow epoch: `1000` required blocks, `mismatches=0`, `missed=0`
   - The observed counter can remain `0/1000` until the next complete epoch boundary begins; Jarvis keeps the setup chat open during this wait.
3. **Duty-gate proof**
   - `duty-gate-proof-before.json` / equivalent
   - Required closed flags:
     - `can_vote=false`
     - `can_propose=false`
     - `can_aggregate_qc=false`
     - `can_count_toward_quorum=false`
     - `can_enter_proposer_schedule=false`
     - `can_serve_as_canonical_source=false`
     - `shadow_signs_real_votes=false`
4. **Activation confirmation evidence**
   - `logs/evidence/activation-confirmation.json`
   - `canonical_status` must be active/pass for this validator.

If these are incomplete:
- `Validator is activation-eligible. I am still waiting for remaining source-majority, shadow, or duty-gate evidence to pass.` (or equivalent blocked text from `run_validator_onboarding`)

## 8) Activation submission and pending confirmation

When all preflight+policy gates pass:
- Jarvis: `The validator is ready to be activated. I am submitting activation now.`
- Activation tx submitted message:
  - `Validator activation was submitted. I am waiting for canonical activation confirmation before I open the dashboard.`

If submitted and not yet confirmed:
- `Activation is still pending confirmation in the canonical validator registry. I am staying in setup and will keep checking.`
- If submit happened earlier and phase is looping:
  - `Activation was already submitted. I am waiting for canonical activation confirmation before opening the dashboard.`

If activation confirmation never arrives while in submission loop:
- `Activation transaction was submitted, but activation confirmation is still pending in the canonical validator registry. Jarvis will stay in setup until confirmation is visible.`

## 9) Canonical activation confirmation and dashboard handoff rule

Jarvis will refuse dashboard handoff until activation confirmation evidence proves canonical active status:

- Internal check text: `Jarvis cannot open the dashboard until canonical activation confirmation is visible.`
- In general operational terms:
  - Required before handoff: `activation-confirmation.json` exists and is `pass` for the same validator address, and is fresh.
- Dashboard attempts during incomplete state are blocked with:
  - `I cannot open the dashboard yet. This validator still needs Jarvis to finish snapshot-backed onboarding, funding, staking, activation, and activation confirmation.`

On success:
- activation status confirms in consensus-aware state and setup completes with dashboard handoff.

## Verification checkpoints and expected operator signals

### Step-by-step checkpoints

1. **Existing setup detection**
   - Expected: setup reuse prompt or fresh setup sequence.
   - Gate: operator chooses Continue Existing Setup or Start Over intentionally.
2. **Provision complete**
   - Expected: pass through passphrase + directory + identity generation flow.
   - Files present under `identity/`, `config/`, `state/`.
3. **Snapshot restore**
   - Expected:
     - Snapshot download/apply messages
     - `validator-pruned-snapshot-restore.json` exists and is verified
   - Gate: post-restore catch-up begins.
4. **Post-snapshot catch-up**
   - Expected: move from 10000-block backlog to <=10000.
   - Gate: `mark_setup_sync_complete` is allowed.
5. **Head sync**
   - Expected: down to <=2 block gap before fund/activate.
   - Gate: funding prompt displayed.
6. **Funding capture**
   - Expected: tx hash recorded message, balance visibility check.
   - Gate: `Wallet funding` preflight eventually passes.
7. **Stake**
   - Expected: stake submission message; if already bonded, skip path triggers bonded message.
   - Gate: `Bonded stake` check passes.
8. **Evidence gates**
   - Expected: source-majority, shadow epoch, duty gates all pass.
   - Gate: `ACTIVATION_ELIGIBLE` then activation submit.
9. **Activation confirmation**
   - Expected: transition from submitted/pending to consensus-active confirmation.
   - Gate: `activation-confirmation.json` pass, then handoff.

## Troubleshooting

### Snapshot restore failures

- Archive snapshot restore fails or returns stale evidence:
  - Open Archive Manager and verify state is canonical.
  - Check snapshot class (`validator-pruned`) and matching chain/network metadata.
  - Re-run setup only after snapshot source is healthy.
- Restore succeeds but post-snapshot catch-up gap remains too high:
  - Error text shows archive snapshot lag; wait for a newer archive snapshot and retry restore.

### Sync blockers

- Runtime not reporting progress:
  - Start the runtime and wait for local RPC readiness.
  - Verify node startup, ports, and that peer discovery is active.
- Persistent gap >2 blocks before fund/activation:
  - Confirm node is connected to relayers and local live height is moving.
  - Verify seed registration and public endpoint visibility where required.

### Funding issues

- Sent to wrong address (`synw...` instead of `synv1...`):
  - This is a non-staking wallet address and will never satisfy validator funding checks.
- Tx hash not accepted:
  - Keep to non-spaced hashes and re-enter.
- Funding tx posted but balance invisible:
  - Re-enter via `The team sent the SNRG` after block finality and let preflight refresh.

### Staking / private key / wallet import issues

- `local-signing-key` fails:
  - Re-run provisioning with the correct validator identity or import valid validator identity material (FN-DSA-1024) for `validator` role.
- `runtime-wallet-loaded` fails:
  - Restart runtime after any identity/wallet import or after app update.
  - Ensure the runtime can query wallet readiness from the local RPC.
- `local-rpc` fails:
  - Start validator process, wait for RPC bind, and re-run.

### Activation pending blockers

- `source-majority` blocked:
  - Retry source-majority proof with enough trusted non-public-RPC sources.
- `shadow epoch` blocked:
  - Continue shadow observation until full epoch completes with zero misses/mismatches.
- `duty-gates` blocked:
  - Keep validator shadowing; duty flags must remain closed.
- Activation confirmed as submitted but never accepted:
  - Keep setup open and monitor for canonical activation evidence refresh.
  - Re-check seed connectivity, RPC, and sync peers.

## Completion criteria

The validator is operator-complete when all of these are true:

- Archive snapshot restore evidence and catch-up evidence are recorded.
- Wallet has received and/or staked at least `50,000 SNRG`.
- Source-majority, shadow, and duty gates pass.
- Activation is submitted and canonical activation confirmation evidence is valid for the validator address.
- Jarvis exits setup and opens dashboard.

At that point the validator should transition to consensus participation according to epoch scheduling after activation inclusion and registration state propagation.
