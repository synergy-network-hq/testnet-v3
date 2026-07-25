# Node Terminal Command Catalog

This catalog covers the Synergy Testnet v3 node architecture in this branch.
It is grounded in `src/bin/synergy-node.rs`, `src/Cargo.toml`, `scripts/testnet`,
and the existing runbooks under `docs/runbooks`.

## Safety Boundary

- Use workbook-backed `ssh synergy-*` aliases only for live hosts.
- Stop validators before any offline migration, recovery, or replay gate.
- Never hand-edit consensus JSON/JSONL files:
  `chain.json`, `canonical_locks.json`, `committed_qcs.jsonl`,
  `state_checkpoint.json`, or derived index files.
- Never copy source identity/key material between hosts.
- The legacy validator workspace
  `/home/node/.synergy/testnet/nodes/validator-workspace` must be archived or
  made inert, and must never be symlinked to `/var/lib/synergy/validator`.
- Live `--apply` / `--force` commands below require an explicit recovery window,
  a stopped target, and operator review of the generated report.

## New Validator Layout

Canonical appliance layout for the validator branch:

```text
/var/lib/synergy/validator
/etc/synergy/validator
/var/log/synergy/validator
/etc/systemd/system/synergy-validator.service
```

The appliance root should contain validator identity, config, state, derived
index, checkpoint, snapshot, quarantine, evidence, log, and runtime
subdirectories.

Read-only closeout gate:

```bash
python3 scripts/testnet/verify-validator-appliance-layout.py
```

Common operator gate before any validator restart:

```bash
synergy-node validator verify-state --state-root <state-root> --allow-testnet-recovery-checkpoint --chain-id 1264 --network-id synergy-testnet-v3
```

## `synergy-node validator`

Core validator commands:

```bash
synergy-node validator inspect-state --state-root <state-root> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator verify-state --state-root <state-root> [--allow-testnet-recovery-checkpoint] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator adopt-compacted-checkpoint --state-root <state-root> --source-validator <node> --source-bundle-path <bundle.tar.gz> --source-bundle-sha256 <sha256> --source-state-dir <state-root> --operator-approval-id <id> --recovery-reason <text> --dry-run|--apply --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator migrate-state --state-root <state-root> --dry-run|--force [--allow-testnet-recovery-checkpoint] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator rebuild-derived-indexes --state-root <state-root> [--dry-run] [--allow-testnet-recovery-checkpoint] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator export-compat-json --state-root <state-root> [--output <state.json>] --chain-id 1264 --network-id synergy-testnet-v3
```

State-sync and offline repair:

```bash
synergy-node validator state-sync-plan --request <request.json> --source-proof <proof.json> --transfer-proof <transfer.json> [--state-root <state-root>] [--output <plan.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1264 --network-id synergy-testnet-v3
```

Generic validator appliance recovery helper:

```bash
scripts/testnet/validator-appliance-recovery.sh quorum-proof --nodes Val1,Val2,Val3,Val4 --heights 651000,650900
scripts/testnet/validator-appliance-recovery.sh status --target Val5
scripts/testnet/validator-appliance-recovery.sh start --target Val5 --execute
scripts/testnet/validator-appliance-recovery.sh quarantine --target Val5 --quorum-height <height> --quorum-hash <hash> --stop-target --execute
scripts/testnet/validator-appliance-recovery.sh transient-lock-recovery --target Val6 --finalized-height <height> [--min-age-secs <seconds>] [--execute]
scripts/testnet/validator-appliance-recovery.sh install-runtime --target Val6 --runtime <local-linux-elf> --runtime-sha <sha256> [--execute]
scripts/testnet/validator-appliance-recovery.sh rollback-runtime --target Val6 [--backup-dir <remote-backup-dir>] [--execute]
scripts/testnet/validator-appliance-recovery.sh repair-permissions --target Val6 [--restart-target] [--execute]
scripts/testnet/validator-appliance-recovery.sh snapshot-repair --target Val5 --manifest <remote-manifest> [--snapshot-root <remote-root>] --execute
```

The helper is node-agnostic. It uses the node credential workbook through
`scripts/testnet/spreadsheet_host_access.py`, invokes supported runtime
commands, and refuses mutation phases unless `--execute` is present. It must
not be used to copy validator state between nodes or manually edit consensus
JSON/JSONL files. Runtime installs reject non-ELF artifacts before upload and
again on the target before replacing `/opt/synergy/bin/synergy-node`.

Supervisor state machine:

```bash
synergy-node validator classify-supervisor-state --evidence <evidence.json> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator supervisor-transition --evidence <evidence.json> [--previous-state <state.json>] [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator supervisor-write --transition <transition.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1264 --network-id synergy-testnet-v3
```

Onboarding, package, identity, cluster, and activation gates:

```bash
synergy-node validator onboarding-preflight --input <candidate.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator onboarding-bundle --input <bundle-input.json> [--output <manifest.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator onboarding-dry-run-join --input <join-input.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator enrollment-token verify --input <token.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator package verify --manifest <package.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator identity-bundle verify --input <identity.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator cluster-assignment preview --input <assignment.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node validator activation-eligibility --input <activation.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
```

Risk notes:

- `adopt-compacted-checkpoint` is for the guarded compacted recovery checkpoint
  path only.
- `--allow-testnet-recovery-checkpoint` is an explicit compact-state gate for
  `verify-state`, `migrate-state`, and `rebuild-derived-indexes`. All three
  commands remain strict by default.
- `migrate-state --force`, `state-sync repair --apply`, and
  `supervisor-write --apply` are live-mutation commands only after the target is
  stopped and a rollback/report is reviewed.

## `synergy-node recovery`

Recovery planning and apply flow:

```bash
synergy-node recovery status --chain-id 1264 --network-id synergy-testnet-v3
synergy-node recovery inspect-divergence --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node recovery build-plan --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --source-node <validator-id>... --evidence-path <dir> --rollback-path <dir> --output <plan.json> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node recovery verify-plan --plan <plan.json> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node recovery apply-plan --plan <plan.json> --confirm-target-stopped --chain-id 1264 --network-id synergy-testnet-v3
```

## `synergy-node archive`

Archive validator and reseed gates:

```bash
synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive verify-canonical --manifest <signed-manifest.json> --snapshot-root <dir> --expected-height <height> --expected-block-hash <hash> --expected-snapshot-class <class> --source-canonical [--allow-validator-pruned-support-snapshot] [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive reseed-plan --manifest <signed-manifest.json> --snapshot-root <dir> --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed [--current-finalized-height <height>] [--output <plan.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive reseed --dry-run --plan <plan.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive publish-snapshot --dry-run --manifest <signed-manifest.json> --snapshot-root <dir> --snapshot-api-disabled --snapshot-worker-disabled --source-canonical [--unsafe-snapshot] [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive list-unsafe-snapshots [--inventory <inventory.json>] [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive mark-unsafe-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive quarantine-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
```

The separate `synergy-archive` binary also exposes:

```bash
synergy-archive init
synergy-archive start
synergy-archive stop
synergy-archive status
synergy-archive verify-chain
synergy-archive create-snapshot --height <height>|--latest-eligible
synergy-archive verify-snapshot --snapshot <path>
synergy-archive list-snapshots
synergy-archive publish-catalog
synergy-archive serve
synergy-archive inspect-manifest --height <height>
synergy-archive inspect-catalog
synergy-archive repair-indexes
synergy-archive collect-diagnostics
synergy-archive print-aegis-identity
synergy-archive verify-aegis-identity
```

`synergy-archive-validator-node` is a shared lifecycle wrapper for the archive
validator role.

## `synergy-node fleet`

```bash
synergy-node fleet status --snapshot <fleet-status.json> [--strict] --chain-id 1264 --network-id synergy-testnet-v3
```

Use this with `docs/runbooks/strict-fleet-status.md` and
`docs/runbooks/public-rpc-atlas-backend-safety.md` for offline fleet evidence.

## Shared Diagnostics and Snapshot Gating

```bash
synergy-node chaos run --input <scenario.json> [--output <report.json>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node diagnose-sync-target --rpc-url <url> [--expected-genesis-hash <hash>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node diagnose-consensus-stall --chain-id 1264 --network-id synergy-testnet-v3
synergy-node diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 [--finalized-height <height>]
synergy-node divergence-status --chain-id 1264 --network-id synergy-testnet-v3
synergy-node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3
synergy-node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3
synergy-node self-heal --chain-id 1264 --network-id synergy-testnet-v3
synergy-node recover-transient-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 [--finalized-height <height>] [--min-age-secs <seconds>]
synergy_recoverTransientVoteLocks qRPC method with params {"finalized_height": <height>, "min_age_secs": <seconds>, "reason": "<operator-reason>"}
synergy-node sync-from-canonical-peer --chain-id 1264 --network-id synergy-testnet-v3 --canonical-height <height> --canonical-hash <hash> --source-qc-aegis-pqc-verified --parent-continuity-verified --state-root-matches --source-peer-not-quarantined [--source-peer <id>]
synergy-node create-snapshot --chain-id 1264 --network-id synergy-testnet-v3 --source-node-majority-branch-proven [--source-role VALIDATOR] [--snapshot-class validator-pruned|support-relayer|support-rpc|support-observer|indexer-replay|indexer-full|archive-full|archive-bootstrap] [--allowed-role <role> ...] [--conflict-height-hash <hash>]
synergy-node list-snapshots --chain-id 1264 --network-id synergy-testnet-v3
synergy-node verify-snapshot --manifest <path> [--snapshot-root <dir>] [--snapshot-class <class>] [--target-role <role>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node self-heal-from-snapshot --manifest <path> [--snapshot-root <dir>] --chain-id 1264 --network-id synergy-testnet-v3
synergy-node quarantine-stopped-validator --chain-id 1264 --network-id synergy-testnet-v3 --target-stopped --operator-approved-containment --quorum-majority-height <height> --quorum-majority-hash <hash> [--local-conflicting-height <height>] [--local-conflicting-hash <hash>]
synergy-node start-shadow-observe --chain-id 1264 --network-id synergy-testnet-v3 [--required-blocks <blocks>]
synergy-node shadow-status --chain-id 1264 --network-id synergy-testnet-v3
synergy-node rejoin-eligibility --chain-id 1264 --network-id synergy-testnet-v3
synergy-node request-rejoin --chain-id 1264 --network-id synergy-testnet-v3 --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation [--operator-approved-emergency-leader-stall-recovery]
synergy-node promote-vote-only-to-active --chain-id 1264 --network-id synergy-testnet-v3
synergy-node sync-from-archive --archive-url <url> --expected-genesis-hash <hash> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node self-heal-from-archive --archive-url <url> --divergence-height <height> --expected-genesis-hash <hash> --chain-id 1264 --network-id synergy-testnet-v3
```

`sync-from-archive` and `self-heal-from-archive` are present but currently fail
closed rather than mutating local chain data.

Generic appliance recovery wrapper commands:

```bash
scripts/testnet/validator-appliance-recovery.sh status --target <validator-name-from-workbook>
scripts/testnet/validator-appliance-recovery.sh request-rejoin --target <validator-name-from-workbook> --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation --operator-approved-rejoin --execute
scripts/testnet/validator-appliance-recovery.sh promote-vote-only-to-active --target <validator-name-from-workbook> --execute
scripts/testnet/validator-appliance-recovery.sh wait-promote-vote-only-to-active --target <validator-name-from-workbook> --rejoin-height <height> --probation-blocks <blocks> --public-rpc https://testnet-core-rpc.synergy-network.io --workbook /Users/devpup/Desktop/node-machine-credentials.xlsx --execute
```

## Other Built Binaries

Role-runtime wrappers discovered in this repo:

```bash
synergy-testnet
synergy-validator-node
synergy-relayer-node
synergy-rpc-gateway-node
synergy-indexer-and-explorer-node
synergy-archive-validator-node
synergy-aegis-cryptography-node
synergy-synq-execution-node
synergy-analytics-and-simulation-node
synergy-audit-validator-node
synergy-committee-node
synergy-cross-chain-verifier-node
synergy-data-availability-node
synergy-governance-auditor-node
synergy-observer-light-node
synergy-oracle-node
synergy-security-council-node
synergy-treasury-controller-node
synergy-uma-coordinator-node
synergy-witness-node
```

These use the shared role runtime lifecycle commands:

```bash
<binary> start --config <config.toml>
<binary> stop
<binary> restart
<binary> status
<binary> logs
```

Other operational binaries:

```bash
aegis-pqvm smoke-test
aegis-pqvm init-archive-identity --output <identity.json> --uma-id <id>
aegis-pqvm sign-json --identity <identity.json> --domain <domain> --input <json> --output <sig.json>
aegis-pqvm verify-json --domain <domain> --input <json> --signature <sig.json> [--expected-signer-sha256 <sha256>]
aegis-pqvm test-only-create-snapshot-fixture --output <directory> --snapshot-class <validator-pruned|support-relayer|support-rpc|support-observer|indexer-replay|indexer-full|archive-full|archive-bootstrap>

wallet-pqc-cli gen-keypair [--algo fndsa]
wallet-pqc-cli passcode --passcode <secret> --mnemonic <bip39 words>
wallet-pqc-cli sign-tx --private-key <hex> --tx '<json>' [--algo fndsa]
wallet-pqc-cli sign-message --private-key-b64 <base64> --message <text> [--algo fndsa]

generate-node-keys
```

## Testnet Helper Scripts

Workbook-backed host access:

```bash
python3 scripts/testnet/spreadsheet_host_access.py inventory [--workbook <node-machine-credentials.xlsx>] [--nodes <node> ...]
python3 scripts/testnet/spreadsheet_host_access.py run <node> <remote_command> [--timeout <secs>] [--remote-env NAME=VALUE ...] [--password-auth]
python3 scripts/testnet/spreadsheet_host_access.py run-file <node> <script_path> [--timeout <secs>] [--remote-env NAME=VALUE ...] [--password-auth]
python3 scripts/testnet/spreadsheet_host_access.py download <node> <remote_path> <local_path> [--timeout <secs>] [--password-auth]
python3 scripts/testnet/spreadsheet_host_access.py upload <node> <local_path> <remote_path> [--timeout <secs>] [--password-auth]
```

Validator appliance migration:

```bash
python3 scripts/testnet/validator_appliance_migration.py --dry-run --validator-name <node> --source-workspace /home/node/.synergy/testnet/nodes/validator-workspace --target-root /var/lib/synergy/validator --config-root /etc/synergy/validator --log-root /var/log/synergy/validator --service-path /etc/systemd/system/synergy-validator.service --archive-root /var/backups/synergy/validator-workspace-archives --rollback-root /opt/synergy/backups
python3 scripts/testnet/validator_appliance_migration.py --apply --validator-name <node> --source-workspace /home/node/.synergy/testnet/nodes/validator-workspace --target-root /var/lib/synergy/validator --config-root /etc/synergy/validator --log-root /var/log/synergy/validator --service-path /etc/systemd/system/synergy-validator.service --archive-root /var/backups/synergy/validator-workspace-archives --rollback-root /opt/synergy/backups
```

Val2 cold canonical restore:

```bash
python3 scripts/testnet/val2_cold_canonical_snapshot_restore.py --dry-run --source-state-dir <state-root> --target-root /var/lib/synergy/validator --config-root /etc/synergy/validator --old-workspace /home/node/.synergy/testnet/nodes/validator-workspace --archive-root /var/backups/synergy --staging-root /var/lib/synergy [--allow-testnet-recovery-checkpoint] [--no-systemd] [--skip-helper-verify] [--skip-chown]
python3 scripts/testnet/val2_cold_canonical_snapshot_restore.py --apply --source-state-dir <state-root> --target-root /var/lib/synergy/validator --config-root /etc/synergy/validator --old-workspace /home/node/.synergy/testnet/nodes/validator-workspace --archive-root /var/backups/synergy --staging-root /var/lib/synergy [--allow-testnet-recovery-checkpoint] [--no-systemd] [--skip-helper-verify] [--skip-chown]
```

Snapshot helper scripts:

```bash
bash scripts/testnet/apply-majority-state-and-runtime.sh
bash scripts/testnet/apply-verified-support-snapshot.sh --distribution-manifest <distribution-manifest.json> --snapshot-root <extracted-snapshot-root> --snapshot-class <support-relayer|support-rpc|support-observer|indexer-replay|indexer-full> --target-role <relayer|rpc|observer|indexer> --target-data-dir <data-dir> --evidence-path <dir> --rollback-path <dir> --confirm-target-stopped
bash scripts/testnet/create-compact-state-snapshot.sh
bash scripts/testnet/manual-snapshot-publisher.sh --snapshot-root <dir> --snapshot-manifest <manifest.json> --snapshot-class <validator-pruned|support-relayer|support-rpc|support-observer|indexer-full|indexer-replay|archive-full|archive-bootstrap> --allowed-role <role> --out <dir> --source-node <node-id> --runtime <synergy-testnet-linux-amd64> --runtime-sha <sha256> [--source-workspace <node-workspace>] [--source-config <node-config.toml>]
bash scripts/testnet/manual-snapshot-receiver.sh --input <distribution-dir> --snapshot-class <class> --target-role <role> --extract-root <dir> --runtime <synergy-testnet-linux-amd64> --source-workspace <node-workspace> [--source-config <node-config.toml>]
bash scripts/testnet/support-node-snapshot-reseed-remote.sh
```

Recovery and evidence helpers:

```bash
bash scripts/testnet/preserve-live-consensus-evidence.sh
bash scripts/testnet/remote-state-recovery-freeze.sh
bash scripts/testnet/validator-appliance-recovery.sh transient-lock-recovery --target <validator> --finalized-height <height> [--min-age-secs <seconds>] [--execute]
bash scripts/testnet/remote-storage-cleanup-stale-artifacts.sh
bash scripts/testnet/remote-storage-audit.sh
bash scripts/testnet/remote-node-orchestrator.sh <machine-id> <operation>
bash scripts/testnet/run-node.sh <start|stop|restart|status|logs> <machine-id> [--follow]
bash scripts/testnet/deploy_validator_runtime_hotfix.sh
bash scripts/testnet/install-runtime-only.sh
```

The remote node orchestrator operations discovered in this branch are:

```bash
install_node
setup_node
bootstrap_node
reset_chain
start
stop
restart
status
logs
export_logs
view_chain_data
export_chain_data
info
```

Layout verification and cleanup helpers:

```bash
python3 scripts/testnet/verify-validator-appliance-layout.py
```

`scripts/testnet/recover-transient-vote-locks-live.sh` is retired and fails
closed. It previously edited old workspace consensus files directly; use the
generic appliance helper above so recovery runs through the supported runtime
command or qRPC method and records evidence.

## Live Command Notes

- `synergy-node validator adopt-compacted-checkpoint` is the guarded compacted
  recovery checkpoint adoption path for validators that must accept the testnet
  recovery checkpoint.
- `synergy-node validator verify-state`, `migrate-state`, and
  `rebuild-derived-indexes` accept `--allow-testnet-recovery-checkpoint` only as
  the branch-specific verification exception for compacted state. Without the
  flag they remain strict.
- `synergy-node validator migrate-state --force`, `state-sync repair --apply`,
  `supervisor-write --apply`, `recovery apply-plan`, and the live recovery
  helpers under `scripts/testnet` should only run after the target validator is
  stopped and the generated report is reviewed.
- `synergy-node archive status` and the archive reseed commands are only valid
  while archive services, snapshot API, snapshot worker, and publication are
  disabled.
- `synergy-node fleet status --strict` is offline evidence only; it does not
  change quorum or routing.

## Node Control Panel

The control panel is the desktop operator console for this repo. It ships the
app shell, the local Rust `control-service`, bundled testnet agents, installer
bundles, release packaging, and the remote-node orchestration helpers.

### Local Development

```bash
cd node-control-panel
npm install
npm run dev
npm run dev:desktop
npm run dev:electron
npm run dev:renderer
npm run build
npm run build:control-service
npm run build:electron
npm run build:sidecars
npm run build:bundle-prep
npm run preview
npm run test:uiux-revamp
```

`npm run dev:desktop` starts the Vite renderer and Electron shell, building the
Rust control-service first. `npm run dev:electron` uses the renderer port set by
`SYNERGY_RENDERER_PORT`. `npm run dev` is renderer-only.

### Build, Package, and Release

```bash
cd node-control-panel
npm run dist:electron
bash scripts/release.sh <version>
bash scripts/release/preflight.sh
bash scripts/release/build-bundle-prep.sh
bash scripts/release/generate-latest-json.sh <assets-dir> <version-tag> [releases-repo]
bash scripts/release/generate-workspace-manifest.sh
bash scripts/release/validate-bundled-assets.sh
python3 scripts/release/repair-electron-update-metadata.py
bash scripts/build-sidecars.sh [--all|--linux|--windows]
cargo check --manifest-path control-service/Cargo.toml --bin control-service --no-default-features
```

The release flow bumps `package.json` and `control-service/Cargo.toml`, stages
the Electron runtime, refreshes bundled binaries, and publishes installer
artifacts. `scripts/build-sidecars.sh` builds the bundled testnet agent binary
used by the control panel updater.

`scripts/release/preflight.sh` is the local release gate. It runs the frontend
build, control-service checks, bundle validation, and version alignment checks
before release tagging.

### Runtime, Service, and Health

```bash
control-service --port <port> --token <token>
synergy-control diagnose-onboarding-sync [--node-id <node-id>]
synergy-control prove-onboarding --node-id <node-id>
curl -sS http://127.0.0.1:47891/health
curl -sS "http://127.0.0.1:47891/validator/live-status?node_id=<node-id>"
curl -sS -H "Authorization: Bearer <token>" "http://127.0.0.1:47891/v1/validator/live-status?node_id=<node-id>"
curl -sS -H "Authorization: Bearer <token>" "http://127.0.0.1:47891/v1/events/stream?token=<token>"
curl -sS http://127.0.0.1:47990/health
```

`control-service` is the local HTTP server embedded by the Electron app. It
uses `/health` for readiness and the panel uses the testnet-agent on port
`47990` for local machine control. `synergy-control` is the tiny CLI wrapper
for onboarding diagnostics and proof generation.

The control-service also exposes a v2 invoke API for the panel's operator
workflows:

```bash
curl -sS \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"command":"validator.package.verify","args":{"node_id":"<node>","package_manifest":{"package_version":"<version>"}}}' \
  http://127.0.0.1:47891/v1/invoke
```

Supported `v1/invoke` command names in this branch:

```text
validator.machine.preflight
validator.package.verify
validator.identity.create
validator.identity.backup.verify
validator.cluster.previewAssignment
validator.cluster.assign
validator.config.render
validator.state.inspect
validator.state.verify
validator.stateSync.plan
validator.stateSync.dryRun
validator.stateSync.repair
validator.recovery.plan
validator.recovery.quarantineStopped
validator.recovery.snapshotRepair
validator.recovery.transientVoteLockRecover
validator.onboarding.verify
validator.onboarding.run
validator.lifecycle.status
validator.lifecycle.requestVoteOnly
validator.lifecycle.promoteProbation
validator.stake.preflight
validator.stake.submit
validator.activation.preflight
validator.activation.submit
validator.doctor.run
fleet.status.strict
archive.status
archive.verifyCanonical
archive.reseed.plan
archive.snapshot.listUnsafe
archive.snapshot.quarantine
```

The testnet agent API used by the control panel is:

```bash
curl -sS http://127.0.0.1:47990/health
curl -sS \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"node_slot_id":"<node-slot-id>","action":"status"}' \
  http://127.0.0.1:47990/v1/control
curl -sS \
  -H "Authorization: Bearer <token>" \
  "http://127.0.0.1:47990/v1/control/jobs/<job-id>"
```

Supported agent actions:

```text
start
stop
restart
status
setup
setup_node
install_node
bootstrap_node
reset_chain
explorer_reset
node_logs
logs
sync_node
```

### Runtime Paths, Config, and Env

```text
~/.synergy-node-control-panel/monitor-workspace
~/.synergy-testnet-control-panel/monitor-workspace
~/.synergy-node-monitor/monitor-workspace
testnet/runtime/node-inventory.csv
testnet/runtime/hosts.env
testnet/runtime/installers/<node-slot-id>/
```

Important environment variables:

```text
SYNERGY_RESOURCE_ROOT
SYNERGY_APP_DATA_DIR
SYNERGY_MONITOR_INVENTORY
SYNERGY_MONITOR_HOSTS_ENV
SYNERGY_RENDERER_PORT
SYNERGY_TESTNET_SSH_USER
SYNERGY_TESTNET_SSH_PORT
SYNERGY_TESTNET_SSH_KEY
```

`generate-monitor-hosts-env.sh` writes the machine alias table and the
precomputed `*_START_CMD`, `*_STOP_CMD`, `*_RESTART_CMD`, `*_STATUS_CMD`, and
other launcher variables into `testnet/runtime/hosts.env`.

### Logs and Cleanup

```bash
bash uninstall.sh [--yes|-y]
bash scripts/cleanup/clean-slate-linux.sh
bash scripts/cleanup/clean-slate-macos.sh
powershell -File scripts/cleanup/clean-slate-windows.ps1
bash scripts/uninstall/clean-uninstall-linux.sh [--yes|-y]
bash scripts/uninstall/clean-uninstall-macos.sh [--yes|-y]
powershell -File scripts/uninstall/clean-uninstall-windows.ps1 -Force
```

Linux cleanup removes the user workspace under `~/.synergy-node-control-panel`
and the user `synergy-testnet-agent.service`. macOS cleanup removes the Launch
Agent `io.synergy.testnet.agent`. Windows cleanup removes the startup shortcut,
service registration, and app data roots. The uninstall scripts are the
destructive versions of the same cleanup flow.

### Installer and Update Helpers

```bash
bash scripts/reset-testnet.sh
bash scripts/testnet/run-node.sh <start|stop|restart|status|logs> <node-slot-id> [--follow]
bash scripts/testnet/remote-node-orchestrator.sh <node-slot-id> <operation>
bash scripts/testnet/generate-monitor-hosts-env.sh
bash scripts/testnet/render-configs.sh
bash scripts/testnet/generate-testnet-genesis.sh
bash scripts/testnet/generate-node-keys.sh
bash scripts/testnet/fund-validator-stake.sh <validator_address> [amount_snrg]
bash scripts/testnet/sync-legacy-setup-packages.sh
bash scripts/testnet/verify-node-installers.sh
bash scripts/testnet/validate-testnet.sh
bash scripts/testnet/bootstrap-sxcp-testnet.sh
bash scripts/testnet/check-determinism.sh
bash scripts/testnet/check-sxcp-external-infra.sh
bash scripts/testnet/sxcp-smoke-test.sh
bash scripts/testnet/sxcp-test-phases.sh
bash scripts/testnet/start-observability.sh
bash scripts/testnet/stop-observability.sh
```

`remote-node-orchestrator.sh` is the app-facing fleet command dispatcher. It
drives `start`, `stop`, `restart`, `status`, `logs`, `export_logs`,
`view_chain_data`, `export_chain_data`, `reset_chain`, `install_node`,
`setup_node`, `bootstrap_node`, `deploy_agent`, and the node-role-specific
operations documented in `node-control-panel/docs/reference/COMMANDS.md`.

`sync-legacy-setup-packages.sh` copies generated `setup-package.json` files for
the early validator nodes into the legacy desktop staging locations used by the
control-panel installer workflows.

`generate-node-keys.sh` is the repo-local identity/package generator for node
slot bootstrap material. `fund-validator-stake.sh` funds and optionally stakes a
validator address from the repo helper flow. `render-configs.sh` and
`generate-testnet-genesis.sh` are the config/genesis helpers that the desktop
control panel and its installer bundles rely on when preparing a testnet
layout.

### Operational Capabilities

The control panel exposes the normal operator workflow for:

- onboarding and validator activation;
- validator detail, logs, health, rewards, and connections;
- cluster assignment and node inventory management;
- state sync repair, proof-only onboarding, and incident evidence;
- archive safety, snapshot safety, and local agent updates;
- remote machine control through the bundled testnet agent.

The bundled agent on each remote machine exposes the actions:

```text
start
stop
restart
status
setup
setup_node
install_node
bootstrap_node
reset_chain
explorer_reset
node_logs
logs
sync_node
```

On Linux the agent service is `synergy-testnet-agent.service`. The macOS launch
agent is `io.synergy.testnet.agent`.

The control-panel v2 UI surfaces the operator pages and routes for Dashboard,
Onboarding, My Node, Clusters, State Sync, Archive, Connections, Rewards,
Activity, Settings, and Help, with advanced/developer views for diagnostics and
maintenance.
