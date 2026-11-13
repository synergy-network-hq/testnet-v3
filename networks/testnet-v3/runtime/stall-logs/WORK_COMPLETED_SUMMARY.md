# Work Completed Summary

## 2026-04-28

### 0. Block `21200` fork and stall recovery
- Diagnosed the current validator stall to a two-part failure:
  - an unsafe local-vote optimization produced a same-height fork at block `21200`
  - the wrong-parent `21201` vote-request refusal path then triggered unnecessary 514-block sync requests, blocking P2P/status progress on healthy validators
- Repaired `GenVal-05` from the minority block `21200` fork back onto the majority `21200` hash.
- Patched P2P vote-request recovery so only real height gaps request sync; `local_tip + 1` wrong-parent proposals are now refused without bulk catch-up.
- Built and deployed Linux runtime checksum:
  - `cd6757c717cf6811398913438dec38f44ebe013e522be4a19753cc12a75b8003`
- Source release:
  - `synergy-testnet`: commit `967a611`, tag `v9.0.13`
  - `synergy-testnet/node-control-panel`: commit `902044c`, tag `v9.0.13`
- Restarted all five genesis validators through their control-panel-managed workspaces.
- Rolled the same runtime to `Node-RPC`, `Node-EXP`, `Relayer-1`, and `Relayer-2`.
- Started `Node-EXP`, which was stopped at stale height `10304`; it caught up to height `21250`.
- Verified public RPC and Atlas are on the live chain again:
  - public RPC advanced past `21350`
  - Atlas API reported `latestBlock: 21329` and `activeValidators: 5`
- Rechecked `GenVal-03` and `GenVal-05` through their control-panel-managed workspaces; both reported local RPC height `21342` and recent received/proposed block activity above `21347`.
- Re-ran the community validator setup tests on the `v9.0.13` control-panel source:
  - `setup_node` tests: `6 passed`
  - `setup_assigns_unique_port_slots_and_config_ports`: `1 passed`
  - coverage includes non-genesis validator public endpoint rejection for private/reserved/malformed hosts, node address override handling, bootstrap input generation, and unique port slot assignment
- Added regression guards after release publication:
  - runtime cluster registry now has an explicit test that `10` active validators split into two clusters of `5`
  - control-service setup now asserts generated non-genesis validator configs carry `validator_cluster_size = 5`
- Updated `CHAIN_STALL_INCIDENT_LOG.md` with Incident 4 root cause, recovery actions, rollout scope, and verification evidence.
- Node Control Panel `v9.0.13` release workflow completed successfully:
  - run: `https://github.com/synergy-network-hq/synergy-node-control-panel/actions/runs/25084136059`
  - release: `https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/tag/v9.0.13`
  - verified assets include Windows installer, macOS DMG/ZIP, Linux `.deb`/AppImage, and update metadata.

### 1. GenVal-03 / GenVal-05 recovery
- Diagnosed the validator stall around block `10300-10309`.
- Confirmed `GenVal-03` was stopped with a zero-byte `data/chain.json`.
- Confirmed `GenVal-03` then failed recovery startup because the historical launch block-1 envelope was stale and failed normal transaction timestamp validation.
- Confirmed `GenVal-05` was stopped in the same window after losing `GenVal-03` as a consensus peer.

### 2. Runtime fixes
- Patched `BlockChain::save_to_file` so chain state is now written atomically instead of truncating `data/chain.json` in place.
- Patched launch block-1 preload handling:
  - live fallback RPC / `node.env` fallback URL is checked first
  - historical launch envelopes are skipped when the network is already past genesis
  - stale or malformed launch envelopes still fail before genesis launch
- Added launch-block1 unit coverage for:
  - recovery after network launch
  - stale envelope before launch
  - malformed envelope hard failure
  - post-genesis skip behavior

### 3. Launch artifact cleanup
- Removed stale committed `launch-block1-transaction.json` files from validator installer bundles.
- Added a `.gitignore` rule so generated launch envelopes remain launch artifacts.
- Updated launch helpers so default block-1 transaction outputs target only the initial quorum validators (`GenVal-01`, `GenVal-02`, `GenVal-04`).
- Updated `clean-launch-testnet.sh launch-quorum` so it regenerates and redeploys the fresh block-1 transaction immediately before quorum launch.

### 4. Validator rollout
- Built and bundled Linux runtime checksum:
  - `6f971ce5525cbc5f422630fda5083d6f0b2f8b649979f038b92742cb38478a22`
- Deployed through control-panel-managed validator workspaces.
- Verified all five genesis validators now report the fixed checksum.
- Verified `GenVal-03` and `GenVal-05` are running, seeing `visible_validators: 5`, applying blocks, and sending/serving consensus traffic.

### 5. Remaining stabilization work
- The validator startup/catch-up stall is fixed.
- Block cadence still needs the separate missed-leader/proposal-timeout fix; verification samples still showed about `20-30s` for a few block advances after recovery.
- Next priority is the Node Control Panel community validator setup path before returning to the RPC/dApp checklist.

## 2026-04-26 / 2026-04-27

### 0. Public RPC outage recovery and documentation correction
- Re-verified the live public RPC edge on `2026-04-27` and found the previous tracker state was stale:
  - `https://testnet-core-rpc.synergy-network.io` was returning `502 Bad Gateway`
  - Atlas API remained live and current on the new chain, reporting:
    - `latestBlock = 10412`
    - `avgBlockTimeSeconds = 8.458333333333334`
- Diagnosed the public outage to the managed `Node-RPC` runtime itself being stopped on the host, not an Atlas/indexer regression and not an Nginx process failure.
- Verified on the RPC host:
  - `nginx` was running
  - `Node-RPC` was stopped
  - local backend port `5646` was not listening
- Restarted the managed `Node-RPC` workspace in `/opt/synergy/Node-RPC` and re-verified:
  - localhost JSON-RPC on `5646` returned `synergy_getChainId = 0x52acf`
  - public HTTPS RPC returned successfully again
  - public WSS accepted `synergy_subscribe("newHeads")` and returned subscription id `0x0000000000000001`
  - `synergy_getNodeStatus` on the public edge resumed returning live node status

### 0.1 Readiness tracker and RPC manual corrections
- Updated:
  - `/Users/devpup/Desktop/Testnet/dApp_Connection_Missing_Features_Checklist.md`
  - `/Users/devpup/Desktop/Synergy Docs Formatting/new docs/Synergy_Network_RPC_Specification_Part_1_Core_and_Security_Controlled_Interfaces.docx`
  - `/Users/devpup/Desktop/Synergy Docs Formatting/new docs/Synergy_Network_RPC_Specification_Part_2_Runtime_Governance_Cross_Chain_and_Operations.docx`
- Corrected the readiness tracker so it no longer falsely marks the sustained sub-`5s` block-time goal as complete.
- Added fresh live evidence to the tracker:
  - direct public RPC sample: `10412 -> 10414` over `20s` (`~10s/block`)
  - Atlas API sample: `avgBlockTimeSeconds = 8.458333333333334`
- Updated the RPC spec manuals to reflect the current transport and exposure model:
  - public TLS ingress on `443`
  - HTTPS RPC endpoint `https://testnet-core-rpc.synergy-network.io`
  - WSS endpoint `wss://testnet-core-ws.synergy-network.io`
  - node-local backend ports `5646` / `5666` on `Node-RPC`
- Added or corrected method coverage in the manuals for:
  - `synergy_getAccountAuthNonce`
  - `synergy_reverseResolveSynID`
  - `synergy_resetChainHead`
- Corrected the `synergy_getChainId` manual entry to the canonical hex return form:
  - `0x52acf` on Testnet
- Rebuilt the Linux runtime after the final P2P genesis-gating patch and resynced the bundled control-panel assets:
  - runtime checksum: `6bb16da4798cf6b09038badf9d398fe9dc8b3c9d68ac15f9ef0f1b2b942bc2e0`
- Committed and pushed both repos cleanly on `main`:
  - `testnet`: `07914be`
  - `synergy-node-control-panel`: `885038c`

### 1. Chain stall incident recovery and genesis reset
- Created the authoritative incident log:
  - `/Users/devpup/Desktop/Testnet/CHAIN_STALL_INCIDENT_LOG.md`
- Confirmed the stall shape before reset:
  - public/service plane pinned at block `15282`
  - validator-side consensus continued briefly into the `15316-15322` range
  - validators were repeatedly hitting leader-timeout, insufficient-vote, and peer-dial failure paths
  - relayer/service nodes were serving `0 validators`

### 2. Launch block-1 transaction root-cause fix
- Diagnosed the failed first reset attempt as a source-of-truth split in the launch-transaction path:
  - the required block-1 transaction had been signed from the local generated network-profile treasury wallet
  - that wallet was not funded by the canonical bundled genesis
  - validators aborted during startup before consensus with:
    - `Failed to preload deterministic launch block-1 transaction ... has insufficient SNRG balance`
- Patched:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/scripts/testnet/send-launch-block1-transaction.sh`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/scripts/testnet/generate-testnet-genesis.sh`
- The launch-transaction path now:
  - signs with the shipped `GenVal-01` runtime identity key
  - derives the default recipient from canonical genesis (`Faucet`)
  - validates signer balance directly against canonical genesis before writing any envelope file

### 3. Canonical genesis correction for the block-1 sponsor
- Updated canonical genesis owner:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/config/genesis.json`
- Funded the shipped `GenVal-01` validator address:
  - `synv114cvu472rkdgpmzvkj70zk9tu8cqqlu4x9ra`
  - amount: `2000000000` nWei
- Deducted the same amount from the unlocked faucet allocation to preserve total supply discipline.
- Recomputed the canonical integrity fields and new genesis hash:
  - `f838a1ff39d9dcac47c3b22492f1636d88cc9238f9034706db3f5144d3cd96c9`

### 4. Canonical genesis propagation fix
- Expanded `generate-testnet-genesis.sh` so canonical genesis is propagated to:
  - runtime genesis copy
  - installer `config/genesis.json` copies
  - bootstrap-bundle `config/genesis.json` copies
  - validator `keys/setup-package.json` `artifacts.genesis` payloads
- This removes the previous drift path where canonical genesis could change without all bundled artifacts changing with it.

### 5. Required block-1 transaction verification
- Generated the required launch transaction envelopes in:
  - `testnet/runtime/installers/GenVal-01/config/launch-block1-transaction.json`
  - `testnet/runtime/installers/GenVal-02/config/launch-block1-transaction.json`
  - `testnet/runtime/installers/GenVal-03/config/launch-block1-transaction.json`
  - `testnet/runtime/installers/GenVal-04/config/launch-block1-transaction.json`
  - `testnet/runtime/installers/GenVal-05/config/launch-block1-transaction.json`
- Live verified after restart:
  - block `1` exists
  - block `1` transaction count is `1`
  - transaction hash:
    - `syntxn-46fa7f453bd6ba150a62ac10070269ec5aec3761979ba89e082fefab95bde984`
  - sender:
    - `synv114cvu472rkdgpmzvkj70zk9tu8cqqlu4x9ra`
  - receiver:
    - `synw1y9vkp3pfdq88vs32v5378dvq23py2k9kkavm`
  - memo:
    - `launch-block-1`

### 6. Fleet reset and restart on one genesis hash
- Reset and redeployed:
  - `Node-0A`
  - `Node-0B`
  - `Node-0C`
  - `GenVal-01`
  - `GenVal-02`
  - `GenVal-03`
  - `GenVal-04`
  - `GenVal-05`
  - `Node-RPC`
  - `Node-EXP`
  - `relayer1`
  - `relayer2`
  - `observer`
- Verified running genesis hash across the live fleet:
  - `f838a1ff39d9dcac47c3b22492f1636d88cc9238f9034706db3f5144d3cd96c9`

### 7. Node-EXP post-reset outlier fix
- The first post-reset verification pass found `Node-EXP` still on the old `ce86...` genesis.
- Root cause:
  - stale `data/chain.json` remained in `/opt/synergy/Node-EXP`
  - after the bundle redeploy, the runtime correctly refused to start against the new canonical genesis because that stale chain-state file still referenced the old genesis hash
- Fixed by:
  - removing stale runtime data from `/opt/synergy/Node-EXP/data/`
  - restarting `Node-EXP`
  - re-verifying the live config hash and running state

### 8. Post-recovery public verification
- Public HTTPS RPC after recovery:
  - `synergy_getBlockNumber => 159`
  - `synergy_getNodeStatus.last_block => 159`
  - `synergy_getNodeStatus.average_block_time => 1.8235294117647058`
  - `synergy_getNodeStatus.sync_status => synced`

## 2026-04-25 / 2026-04-26

### 1. Live consensus root cause
- Confirmed the minute-scale block stalls were coming from validator self-conflict handling in dual-quorum consensus.
- The live validators were repeatedly hitting:
  - `QC error - block proposal failed`
  - `attempted conflicting votes at height ...`
  - `Leader proposal timeout — following shared leader rotation`
- The original live failure mode was:
  1. a validator voted for a remote leader's proposal
  2. the leader window timed out
  3. the same validator became leader for the same height
  4. the local proposal path re-used a round the validator had already voted in
  5. that created a false self-conflict and burned another leader window

### 2. Consensus fixes implemented
- Patched `/Users/devpup/Desktop/Testnet/synergy-testnet/src/consensus/dual_quorum.rs`.
- Restored proper equivocation detection semantics:
  - exact replay of the same vote is idempotent
  - same validator + same height + same round + different block hash is treated as a conflict
  - later rounds for the same height remain valid
- Added a second round-allocation fix:
  - when a validator has already cast a local vote for a given height/epoch, any later local proposal for that same height must advance to the next unused round
  - this removes the remaining self-conflict path that was still present after the first rollout

### 3. Consensus verification
- Ran:
  - `cargo test -p synergy-testnet consensus::dual_quorum -- --nocapture`
- Result after the final patch:
  - `10 passed`
  - `0 failed`

### 4. Final release artifact
- Built the final Linux runtime with:
  - `cargo zigbuild --release -p synergy-testnet --target x86_64-unknown-linux-gnu`
- Final checksum:
  - `96ee5e06e0efda835a1eec5110089b1cca1be2f9410cb4e759f9a11a0d59468b`

### 5. Validator fleet rollout through control-panel workspaces
- Rolled the final runtime through the control-panel-managed validator workspaces, not ad hoc standalone nodes.
- Updated and restarted:
  - `GenVal-01`
  - `GenVal-02`
  - `GenVal-03`
  - `GenVal-04`
  - `GenVal-05`
- Verified the validator workspace binary checksum on the successfully restarted nodes matched:
  - `96ee5e06e0efda835a1eec5110089b1cca1be2f9410cb4e759f9a11a0d59468b`

### 6. Public RPC / WebSocket implementation and rollout
- Patched `/Users/devpup/Desktop/Testnet/synergy-testnet/src/rpc/rpc_server.rs` and `/Users/devpup/Desktop/Testnet/synergy-testnet/src/role_runtime.rs`.
- Implemented and verified:
  - `synergy_simulateTransaction`
  - `synergy_subscribe` / `synergy_unsubscribe`
  - `synergy_getAccountNonce`
  - `synergy_getAccountAuthNonce`
  - spec-style transaction envelope normalization for `synergy_sendTransaction`
  - structured `synergy_estimateGas`
  - hex `synergy_getChainId`
  - JSON-RPC batch handling
  - `Content-Type: application/json` enforcement
- Fixed the WS bind bug where the WS thread was incorrectly binding the HTTP port instead of the configured WS port.
- Rolled the final checksum to:
  - `/opt/synergy/Node-RPC`
  - `/opt/synergy/Node-EXP`

### 7. Public ingress verification
- Verified local listeners on the RPC host:
  - HTTP: `5646`, `5647`
  - WS: `5666`, `5667`
- Verified public production ingress over TLS:
  - HTTPS RPC: `https://testnet-core-rpc.synergy-network.io`
  - WSS: `wss://testnet-core-ws.synergy-network.io`
- Verified live subscribe/unsubscribe over WSS.
- Confirmed raw custom ports on the VPS are still filtered upstream of the host, even though the node listeners and UFW rules are correct.
- Current browser-safe integration path is therefore the Nginx/TLS ingress on `443`, not the raw high ports.

### 8. Control-panel bundle sync
- Updated the nested control-panel bundled Linux runtime:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/binaries/synergy-testnet-linux-amd64`
- Regenerated and revalidated bundled metadata:
  - `testnet/runtime/workspace-manifest.json`
  - `binaries/synergy-testnet-linux-amd64.sha256`
- Synced the same final runtime into the local monitor workspace:
  - `/Users/devpup/.synergy-node-control-panel/monitor-workspace`

### 9. Current chain status
- After the final consensus fix and mesh recovery, the recent steady-state block deltas on a healthy validator were:
  - `13s, 12s, 10s, 3s, 15s, 11s, 4s, 4s, 13s, 16s`
- There are no new `attempted conflicting votes` lines in the fresh validator log window after the final rollout.
- The large `average_block_time` values still visible in `synergy_getNodeStatus` are contaminated by the long restart/rejoin stall window and not representative of the current steady-state cadence.

### 10. Validator catch-up and divergent-tip recovery
- Diagnosed the live `GenVal-02` failure as a divergent local chain at height `9608`, not a simple behind-tip delay.
- Confirmed the local hash at height `9608` did not match the healthy validator chain.
- Patched:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/consensus/consensus_algorithm.rs`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/sync/manager.rs`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/p2p/networking.rs`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/block.rs`
- The catch-up fix included:
  - wiring `SyncManager` into the normal validator behind-tip path
  - dropping chain/pool guards before sleep paths so block application is not blocked by a sleeping validator thread
  - requesting overlapping sync windows so divergent peers can reconcile
  - rolling back to the highest common ancestor before replaying forward
- Added a regression test for rollback/replay in:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/p2p/networking.rs`
- Built the follow-on Linux runtime with checksum:
  - `238c7cb79ba021ca75d0529f7a8dab98832d83346fcafd2b8aecf12c95810f59`
- Verified the new runtime could sync `GenVal-02` from the divergent state back to live tip, then restarted it through the control-panel-managed workspace and confirmed it rejoined the network.

### 11. Fleet rollout to the catch-up runtime
- Rolled `238c7cb79ba021ca75d0529f7a8dab98832d83346fcafd2b8aecf12c95810f59` through the live control-panel-managed validator workspaces:
  - `GenVal-01`
  - `GenVal-02`
  - `GenVal-03`
  - `GenVal-04`
  - `GenVal-05`
- Restarted each validator through `nodectl.sh`.
- Verified each validator reported:
  - checksum `238c7cb79ba021ca75d0529f7a8dab98832d83346fcafd2b8aecf12c95810f59`
  - `status: running`
  - `sync_status: synced`
- Rolled the same checksum to:
  - `/opt/synergy/Node-RPC`
  - `/opt/synergy/Node-EXP`
- Verified both public service nodes restarted cleanly on the same checksum.

### 12. Control-panel bundle and local monitor alignment
- Updated the nested control-panel bundled Linux runtime to:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/binaries/synergy-testnet-linux-amd64`
- Updated the bundled installer copies and `BINARY_STATUS.txt` files under:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/testnet/runtime/installers`
- Regenerated and revalidated:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/testnet/runtime/workspace-manifest.json`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/binaries/synergy-testnet-linux-amd64.sha256`
- Synced the same bundle state into the local monitor workspace:
  - `/Users/devpup/.synergy-node-control-panel/monitor-workspace`

### 13. Control-panel settings page fix
- Fixed the blank `/settings` route in the nested control-panel app.
- Root cause:
  - `ControlPanelOperationsPage.jsx` rendered `error` but did not destructure it from `useControlPanel()`
  - that caused a renderer-side `ReferenceError`, which blanked both:
    - the settings button
    - the sidebar link directly above the first node slot
- Patched:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel/src/components/control-panel/ControlPanelOperationsPage.jsx`
- Rebuilt the nested control-panel frontend successfully with `npm run build`.

### 14. Post-rollout public verification
- Re-verified public HTTPS RPC after the service-node restart:
  - `https://testnet-core-rpc.synergy-network.io`
- Re-verified public WSS subscription acceptance after the service-node restart:
  - `wss://testnet-core-ws.synergy-network.io`
- Example post-rollout public tip:
  - block height `10103+`

### 15. Tracking artifacts updated
- Updated:
  - `/Users/devpup/Desktop/Testnet/dApp_Connection_Missing_Features_Checklist.md`
  - `/Users/devpup/Desktop/Testnet/WORK_COMPLETED_SUMMARY.md`

### 16. Observer / Grafana audit findings
- Confirmed the observer host is running:
  - `prometheus.service`
  - `grafana-server.service`
  - `node_exporter.service`
- Confirmed Prometheus is successfully scraping live `synergy_*` metrics from:
  - validators `Val1` through `Val5`
  - `Relayer-1`
  - `Relayer-2`
- Confirmed the current Grafana dashboards still contain stale PromQL references that leave panels blank:
  - `synergy_mempool_pending`
  - `synergy_mempool_queued`
  - `synergy_gas_price_wei`
  - `synergy_syncing`
  - `synergy_rpc_errors_total`
  - `synergy_peers_connected`
  - `synergy_cluster_quorum_ready`
  - `synergy_cluster_member`
- Confirmed Prometheus still shows down scrape targets for:
  - bootnodes
  - seed nodes
  - Explorer
  - RPC Gateway
  - placeholder validators `Val6` / `Val7`
- This means the current Grafana problems are split across two separate causes:
  1. stale dashboard queries against renamed metrics
  2. real scrape-target coverage gaps in Prometheus

### 17. Catch-up transport and retry-path hardening
- Patched:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/p2p/networking.rs`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/sync/manager.rs`
- Removed the remaining validator catch-up request storm and queue contention by:
  - routing sync-critical `Block`, `Blocks`, and `GetBlocks` traffic around the shared background queue
  - pausing the bootstrap loop's missing-block requests while `SyncManager` is actively catching up
  - retrying the same overlapping sync window instead of falling back to a genesis-wide request
  - treating forward sync progress as progress instead of an immediate failure
- Added regression coverage in `p2p::networking` for:
  - direct bypass of sync-critical messages
  - suppression of background block-request storms during active sync
  - sync poll interval behavior while `SyncManager` is active
- Verified with:
  - `cargo test --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/src/Cargo.toml -p synergy-testnet p2p::networking -- --nocapture`
- Result:
  - `41 passed`
  - `0 failed`

### 18. Final validator-runtime rollout and live block-speed verification
- Built the current Linux runtime with:
  - `cargo zigbuild --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/src/Cargo.toml --release -p synergy-testnet --target x86_64-unknown-linux-gnu`
- Final checksum:
  - `7c80a5df14072732a7d9ec8ca771ab96478a5183e3bd628a520df28e87f0e808`
- Rolled that runtime sequentially through the live control-panel-managed validator workspaces:
  - `GenVal-01`
  - `GenVal-02`
  - `GenVal-03`
  - `GenVal-04`
  - `GenVal-05`
- Verified the same checksum on the validator workspaces and on the shared service roles.
- Fresh live verification after the rollout:
  - `GenVal-01` reported `sync_status: synced`, `peer_count: 6`, and `average_block_time: 4.105263157894737`
  - a fresh public RPC sample advanced from block `12775` to `12781` over about `21s`, which is about `3.5s/block`
- This restored the chain to the requested sustained sub-`5s` range.

### 19. Observer, Prometheus, and Grafana rebuild
- Added canonical source-of-truth ops files in:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/ops/README.md`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/ops/observability/prometheus.observer.yml`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/ops/nginx/testnet-core-rpc.synergy-network.io.conf`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/ops/nginx/testnet-explorer.conf`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/ops/observability/grafana/public-edge-and-bootstrap.json`
- Updated the shared public service host nginx config so the observer can scrape:
  - `https://testnet-core-rpc.synergy-network.io/metrics/node-rpc`
  - `https://testnet-core-rpc.synergy-network.io/metrics/node-exporter`
  - `https://testnet-explorer.synergy-network.io/metrics/node-exp`
- Restricted those metrics paths to the observer IP `209.145.50.9`.
- Rebuilt the observer Prometheus topology so that:
  - stale validator placeholders `Val6` / `Val7` were removed
  - the invalid raw `synergy-seeds` metrics job was removed
  - RPC / explorer / shared-host metrics moved to the new HTTPS metrics paths on `443`
  - bootnode and seed visibility moved to explicit blackbox TCP probes on their real public bootstrap ports
  - public HTTPS endpoint health is now probed explicitly
- Installed and enabled `prometheus-blackbox-exporter` on the observer host.
- Corrected an observer packaging issue first:
  - the host already had a non-system `prometheus` user at UID/GID `1000`
  - converted that account into a proper system-range service account at UID/GID `987`
  - re-owned the Prometheus data tree and restarted Prometheus cleanly before the blackbox exporter install
- Prometheus validation:
  - `/opt/prometheus/promtool check config /opt/prometheus/config/prometheus.yml`
  - result: valid
- Current observer state:
  - `prometheus.service` active
  - `prometheus-blackbox-exporter.service` active
  - Prometheus target health count:
    - `0` down targets

### 20. Public RPC/WSS exposure-policy enforcement
- Patched:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/rpc/rpc_server.rs`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/src/role_runtime.rs`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/ops/nginx/testnet-core-rpc.synergy-network.io.conf`
- Implemented method-tier enforcement so the public edge now behaves correctly by role and transport:
  - public read methods remain available
  - canonical client pipeline methods such as `synergy_estimateGas`, `synergy_simulateTransaction`, and `synergy_sendTransaction` remain available on the RPC gateway
  - authority-plane methods such as `synergy_createWallet` / `synergy_resolveSynID` are denied on public ingress
  - non-public write methods such as `synergy_sendTokens` are denied on public ingress
  - local loopback access still retains node-local administrative methods for operator workflows
- Added RPC tests covering:
  - proxy forwarded IP handling
  - Cloudflare `CF-Connecting-IP` handling
  - denial of authority-plane methods on public ingress
  - allowance of canonical client methods on the service-access gateway
  - allowance of non-public methods on loopback-only access
- Verified with:
  - `cargo test --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/src/Cargo.toml -p synergy-testnet rpc::rpc_server -- --nocapture`
- Result:
  - `9 passed`
  - `0 failed`

### 21. Cloudflare/WebSocket trust-chain fix and final fleet rollout
- Diagnosed a live gap where public HTTPS RPC enforcement worked but public WSS still allowed `synergy_createWallet`.
- Root cause:
  - the WebSocket RPC surface enforced exposure correctly when it received a forwarded client IP, but the public trust chain needed explicit handling for Cloudflare-style client IP headers and explicit forwarding through nginx.
- Fixed by:
  - teaching the RPC request context to honor `CF-Connecting-IP` and `True-Client-IP`
  - updating the canonical RPC nginx config to forward those headers on both HTTP and WSS
  - deploying the updated nginx config to both:
    - `/etc/nginx/sites-enabled/testnet-core-rpc.synergy-network.io`
    - `/etc/nginx/sites-available/testnet-core-rpc.synergy-network.io`
  - reloading nginx after a successful `nginx -t`
- Built the final Linux runtime with checksum:
  - `858c5aa89696f4e6fb3483edd024eec3cdad8f097d326470eeeb424a6fd2d37c`
- Rolled that runtime through the live control-panel-managed validator workspaces:
  - `GenVal-01`
  - `GenVal-02`
  - `GenVal-03`
  - `GenVal-04`
  - `GenVal-05`
- Rolled the same checksum to:
  - `/opt/synergy/Node-RPC`
  - `/opt/synergy/Node-EXP`
- Updated the nested control-panel bundle and local monitor workspace to the same checksum and regenerated:
  - `binaries/synergy-testnet-linux-amd64.sha256`
  - `testnet/runtime/workspace-manifest.json`
- Live verification after the final rollout:
  - validators `1-5`, `Node-RPC`, and `Node-EXP` all read back checksum `858c5aa89696f4e6fb3483edd024eec3cdad8f097d326470eeeb424a6fd2d37c`
  - public HTTPS RPC still allows canonical client methods and denies non-public writes
  - public WSS now denies `synergy_createWallet` with `-32003`
  - public WSS `synergy_subscribe("newHeads")` still succeeds and emits live block notifications
  - all five validators report `sync_status: synced`
  - a fresh public sample advanced from block `13484` to `13497` over about `57s`, which is about `4.4s/block`
- Added a dedicated Grafana dashboard at:
  - `/var/lib/grafana/dashboards/synergy/public-edge-and-bootstrap.json`
- This dashboard makes the public-role coverage explicit instead of burying it in validator-centric charts:
  - public HTTPS endpoint health
  - bootnode P2P TCP reachability
  - seed TCP reachability
  - public probe duration

### 22. GenVal-03 / GenVal-05 recovery and Node Control Panel v9.0.11
- Diagnosed and documented the 2026-04-28 validator stall in:
  - `/Users/devpup/Desktop/Testnet/CHAIN_STALL_INCIDENT_LOG.md`
- Root cause:
  - `GenVal-03` had a zero-byte `data/chain.json` caused by non-atomic chain-state writes
  - after fallback to genesis-only local state, the normal runtime still treated the old launch block-1 transaction envelope as mandatory even though the live chain was already past genesis
  - that stale envelope failed startup with `Transaction timestamp is too old`
  - `GenVal-05` was caught in the same stall window and lost `GenVal-03` as a consensus peer
- Fixed the validator runtime in `/Users/devpup/Desktop/Testnet/synergy-testnet`:
  - chain-state persistence now writes to a temporary file, syncs, and atomically renames over `data/chain.json`
  - launch block-1 preload now skips a historical launch envelope when fallback RPC shows the live network is already past genesis
  - malformed or stale launch envelopes still fail hard before network launch
  - fresh launch envelopes are regenerated immediately before quorum launch instead of being committed into normal validator installer bundles
- Rolled the fixed runtime through all five control-panel-managed genesis validators.
- Current fixed runtime checksum:
  - `6f971ce5525cbc5f422630fda5083d6f0b2f8b649979f038b92742cb38478a22`
- Source release:
  - `synergy-testnet`: commit `e8eb659`, tag `v9.0.11`
  - `synergy-testnet/node-control-panel`: commit `5ccb4bc`, tag `v9.0.11`
- Fixed the Node Control Panel setup path for community non-genesis validators:
  - standard setup now includes validators in the public-endpoint review flow
  - setup chat now shows actionable choice controls for role selection, device review, endpoint review, folder review, package import, and final provisioning
  - non-genesis validators require a publicly routable IP address or DNS name before provisioning
  - private, loopback, link-local, carrier-grade NAT, documentation, malformed, and local-only endpoints are rejected before any workspace is written
  - genesis validators stay on the private VPN / ceremony setup flow
  - setup no longer auto-provisions immediately after role selection; it waits for explicit `Provision Node`
- Fixed the settings blank page in the control panel by routing `/settings` to the actual settings component.
- Removed stale `launch-block1-transaction.json` files from bundled validator installer assets and ignored future generated launch envelopes.
- Verified locally before pushing:
  - `npm run build`
  - `cargo test --manifest-path control-service/Cargo.toml setup_node -- --test-threads=1 --nocapture`
  - `cargo test --manifest-path control-service/Cargo.toml setup_assigns_unique_port_slots_and_config_ports -- --nocapture`
  - `git diff --check`
  - `./scripts/release/preflight.sh`
- Release publishing:
  - pushed `main` and tag `v9.0.11` to `synergy-network-hq/synergy-node-control-panel`
  - GitHub Actions release run: `25078227601`
  - GitHub Actions result: `completed / success`
  - verified published release:
    - `https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/tag/v9.0.11`
  - verified release assets include:
    - `Synergy.Node.Control.Panel.Setup.9.0.11.exe`
    - `Synergy.Node.Control.Panel-9.0.11-arm64.dmg`
    - `Synergy.Node.Control.Panel-9.0.11-arm64.zip`
    - `synergy-node-control-panel_9.0.11_amd64.deb`
    - `Synergy.Node.Control.Panel-9.0.11.AppImage`
    - `latest.yml`
    - `latest-mac.yml`
    - `latest-linux.yml`
- Remaining sequence after release publication:
  - continue the missed-leader / proposal-timeout work needed for consistently sub-`5s` block cadence
  - resume the RPC / wallet / developer onboarding checklist only after the validator setup path is fully published and verified

### 23. Service-plane catch-up deadlock fix and v9.0.12 rollout
- Diagnosed a new service-plane stall where public RPC and `Node-RPC` were pinned at block `20657` while the validator mesh continued advancing.
- Root cause:
  - service-plane nodes requested catch-up from `local_tip + 1`
  - when the service-plane tip had diverged, the returned batch did not include a common ancestor
  - `apply_block_batch` could not roll back/replay without that ancestor, so the node repeated ineffective `GetBlocks` requests forever
  - `Relayer-2` was also stopped, reducing redundancy in the public path
- Fixed `/Users/devpup/Desktop/Testnet/synergy-testnet/src/p2p/networking.rs`:
  - added a 512-block reconciliation lookback for block-sync requests
  - status-driven catch-up now requests an overlapping range
  - background bootstrap catch-up now requests the same overlapping range
  - added regression coverage for the service-plane stuck height case
- Verified locally:
  - `cargo fmt --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/src/Cargo.toml --all`
  - `cargo test --manifest-path /Users/devpup/Desktop/Testnet/synergy-testnet/src/Cargo.toml -p synergy-testnet p2p::networking::tests -- --nocapture`
  - result: `44 passed`, `0 failed`
  - `git diff --check`
- Built and deployed Linux runtime checksum:
  - `efbe76acb9fc24273c2b08778196321563d05000714994d5e141308bf33cc5b2`
- Live rollout:
  - `Node-RPC`
  - `Relayer-1`
  - `Relayer-2`
  - `GenVal-01`
  - `GenVal-02`
  - `GenVal-03`
  - `GenVal-04`
  - `GenVal-05`
- Validators were restarted one at a time through the control-panel-managed validator workspaces.
- Live verification:
  - public RPC recovered from the pinned height and advanced `20657 -> 20739 -> 20742`
  - later public samples advanced `20752 -> 20764`
  - all five validators reported checksum `efbe76acb9fc24273c2b08778196321563d05000714994d5e141308bf33cc5b2`
  - all five validators reported `synergy_best_peer_height_delta 0`, `synergy_live_validators 5`, and `synergy_status_ready_validators 5`
  - both relayers reported the fixed checksum, `peer_count: 6`, and `sync_status: synced`
- Source release:
  - `synergy-testnet`: commit `6b62af1`, tag `v9.0.12`
- Remaining sequence:
  - update and publish the Node Control Panel bundle with the `v9.0.12` runtime so new community validator installs inherit the service-plane catch-up fix
  - continue the missed-leader / proposal-timeout work needed for sustained sub-`5s` block cadence
  - then continue the RPC / wallet / developer onboarding checklist

### 24. Deterministic leader retry fix, fresh genesis reset, and Atlas chain-data reset
- Diagnosed the new fresh-chain stall at height `773`.
- Root cause:
  - the same-height anti-equivocation vote lock was correct, but leader retries were rebuilding a new block proposal for the same height, parent hash, and leader
  - each retry could produce a different proposal hash because the block timestamp and transaction snapshot were regenerated
  - after the validator had already locked a local vote for one height-`773` hash, later retry hashes were correctly refused as self-conflicts
- Fixed `/Users/devpup/Desktop/Testnet/synergy-testnet/src/consensus/consensus_algorithm.rs`:
  - added a persistent local proposal cache under `data/consensus_proposals`
  - reused the exact same signed block proposal when the same leader retries the same height on the same parent
  - validated cached proposals by recalculating block hash and transaction root before reuse
  - wrote proposal cache files atomically with owner-only permissions
  - pruned cached proposal files after the corresponding height is committed
  - added regression coverage for same-height leader retry reuse
- Verified locally:
  - `cargo test --manifest-path src/Cargo.toml -p synergy-testnet leader_reuses_cached_proposal_for_same_height_retry -- --nocapture`
  - `cargo test --manifest-path src/Cargo.toml -p synergy-testnet dual_quorum::tests:: -- --nocapture`
  - `cargo test --manifest-path src/Cargo.toml -p synergy-testnet consensus::consensus_algorithm::tests:: -- --nocapture`
  - `git diff --check`
- Built and deployed Linux runtime checksum:
  - `f516ed8348e09d63306ca14ee3e8c448fd2138f99de7c4d7b142c3b1e76dfe40`
- Live reset / rollout:
  - cleared active chain data and consensus lock/proposal state from all five control-panel-managed genesis validator workspaces
  - restarted bootnodes and seed services on the same fresh genesis
  - restarted all five genesis validators through their control-panel-managed workspaces
  - restarted `Relayer-1`, `Relayer-2`, `Node-RPC`, `Node-EXP`, and the observer from clean chain state
  - cleared the old Atlas/explorer chain tables before starting the indexer against the new chain
- Live verification so far:
  - all five validators agreed on fresh block `1` hash `5050e23ccfc170493452651071675106f6685cc04230e180d1bbbbeb4a06b8cd`
  - all five validators agreed on block `50` hash `2a6c4e35aecb2f194fcffdd07eeda1503f969a2128e8b2a8882a5d950c29f2a9`
  - block `1` contains the required single launch transaction with memo `launch-block-1`
  - public RPC is serving the fresh chain and reported height above `400`
  - `Node-EXP` is serving the fresh chain and reported height above `450`
  - Atlas API is no longer serving the old chain and reported fresh-chain height around `450` with total transactions `1`
- Final stabilization verification:
  - public RPC advanced past the prior height-`773` failure point to `801`, then later to `1364`
  - all five genesis validators returned the same block `773` hash:
    - `37dd91ab8ecf6c731870ddcda06baa24e94f77b8b2ed6ddf997df64667ab07b6`
  - Atlas API reported fresh-chain latest block `1364`, total transactions `1`, and active validators `5`
- Source release:
  - `synergy-testnet`: commit `657f459`, tag `v9.0.15`
- Control Panel update prepared:
  - bumped Synergy Node Control Panel to `9.0.15`
  - non-genesis public-IP validator setup now keeps bootnodes, seed services, and dnsaddr bootstrap enabled while also pinning `relay1.synergy-network.io:5622` and `relay2.synergy-network.io:5622` as persistent upstreams
  - existing genesis validator setup still uses the private WireGuard validator mesh
  - setup refresh logic now preserves public validator relayer upstreams when rebuilding `peers.toml`
  - verified with:
    - `cargo test --manifest-path control-service/Cargo.toml setup_node -- --test-threads=1 --nocapture`
    - `npm run build`
    - `./scripts/release/preflight.sh`
- Remaining sequence:
  - tag and publish the Node Control Panel `v9.0.15` release
  - continue any remaining public-IP validator join validation before resuming the remaining RPC and developer onboarding checklist items

### 25. Public validator join hardening and Node Control Panel v9.0.16 release
- Cancelled the in-flight `v9.0.15` control-panel release before publication because one runtime contract was still incomplete.
- Fixed `/Users/devpup/Desktop/Testnet/synergy-testnet/src/config/mod.rs` and `/Users/devpup/Desktop/Testnet/synergy-testnet/src/role_runtime.rs`:
  - parsed the `[validator] state_sync_before_join` control-panel setting in the runtime config
  - enforced state sync before self-registration and consensus for public, auto-registering validators
  - kept static genesis validators out of that public-join gate so the private genesis mesh does not deadlock during normal restarts
  - retrying sync now delays registration/consensus instead of allowing an unsynced public validator to join
- Verified runtime changes with:
  - `cargo test --manifest-path src/Cargo.toml -p synergy-testnet parses_validator_state_sync_before_join -- --nocapture`
  - `cargo test --manifest-path src/Cargo.toml -p synergy-testnet state_sync -- --nocapture`
  - `cargo test --manifest-path src/Cargo.toml -p synergy-testnet static_genesis_validator_does_not_block_on_public_join_sync_gate -- --nocapture`
  - `git diff --check`
- Source release:
  - `synergy-testnet`: commit `bc1bb3d` (`Enforce validator sync before public join`), tag `v9.0.16`
- Published Synergy Node Control Panel `v9.0.16`:
  - `synergy-testnet/node-control-panel`: commit `0b20408` (`Release control panel v9.0.16`), tag `v9.0.16`
  - GitHub Actions release run: `https://github.com/synergy-network-hq/synergy-node-control-panel/actions/runs/25088451551`
  - verified release: `https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases/tag/v9.0.16`
  - verified release assets:
    - `Synergy.Node.Control.Panel.Setup.9.0.16.exe`
    - `Synergy.Node.Control.Panel-9.0.16-arm64.dmg`
    - `Synergy.Node.Control.Panel-9.0.16-arm64.zip`
    - `synergy-node-control-panel_9.0.16_amd64.deb`
    - `Synergy.Node.Control.Panel-9.0.16.AppImage`
    - `latest.yml`
    - `latest-mac.yml`
    - `latest-linux.yml`
- Added a signed transaction runner for manual test transactions:
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/scripts/testnet/run-signed-load.sh`
  - `/Users/devpup/Desktop/Testnet/synergy-testnet/scripts/testnet/signed-transaction-runner.py`
  - the runner requires an explicit sender and private-key file; no validator private-key path is hardcoded
  - verified with `bash -n`, `python3 -m py_compile`, help output, and `git diff --check`
  - committed as `0723218` (`Add signed transaction runner`)
- Fresh-chain verification after release:
  - public RPC height: `2860`
  - Atlas latest block: `2860`
  - Atlas average block time window: `1.625s`
  - Atlas total transactions: `1`
  - Atlas active validators: `5`
  - Atlas source RPC: `https://testnet-core-rpc.synergy-network.io`
- Remaining sequence:
  - install/verify the `v9.0.16` control-panel update on any target GUI hosts that should immediately use the new public-validator setup path
  - run an end-to-end public-IP community validator setup test from a non-genesis machine
  - after public validator onboarding is proven live, continue the remaining RPC, wallet, metrics, and developer-onboarding checklist items
