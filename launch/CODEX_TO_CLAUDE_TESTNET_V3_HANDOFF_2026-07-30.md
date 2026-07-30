# Testnet-v3 launch handoff: Codex to Claude

Last verified: **2026-07-30 11:53 UTC**

This document supersedes the launch-status portions of the older
`launch/CODEX_HANDOFF.md`. That older document is still useful as historical
background for the genesis and contract-deployment work, but its “immediate
next action” is obsolete.

## 1. Executive status

Testnet-v3 validator consensus is now **live and advancing**, but the public
network is **not launch-complete** because finalized records are not propagating
through the relayer observer path.

The canonical genesis, governance approval, six validator identities, VPN
generation, node configs, and corrected v20.0.0 validator runtime are active.
The coordinated six-validator recovery completed successfully. All six
validators now use finality-store version 3 and advance on one common chain:

| Node set | Current state |
|---|---|
| Validators 1–6 | active; corrected validator SHA; version-3 stores; common advancing chain at heights 58–59 in the 11:53 UTC sample |
| Relayers 1–3 | active; corrected v20 runtime deployed; rejecting round-1 finalized records |
| RPC gateway | active; corrected v20 runtime deployed; public height 0 |
| Explorer index node | active; corrected v20 runtime deployed; height 0 |
| Atlas | HTTP 200; six validators displayed; latest block 0 |

The obsolete version-2 validator finality/signing state was preserved in
timestamped backup directories and removed from the live data paths. The
corrected validator binary was staged on all six machines while the services
were inactive, all launch invariants passed, and the services were then started
through one coordinated barrier. The six validators have since finalized more
than 50 version-3 blocks without a fork.

The direct release blocker is now narrower and is reproduced identically on all
three relayers:

```text
Rejected typed finality observer message
round 1 is not authorized; valid TC is required to advance from round 0
```

The relayers therefore do not create an observer finality store and remain at
height 0. The public RPC and Atlas correctly remain at height 0 downstream.
A secondary repeated authorization error must be resolved in the same pass:

```text
typed finality observer request to relayer is not from a configured public service role
```

The next operator must diagnose the complete durable-finality observer contract,
fix both validation and service-role authorization together, add round-greater-
than-zero recovery tests, build one immutable corrected v20.0.0 artifact, deploy
it to the affected roles, and prove validator-to-Atlas propagation. Do not
restart or alter the healthy validator set while diagnosing this observer path.

Do not regenerate genesis, validator identities, validator consensus keys,
ETDAG keys, contract addresses, or VPN identities.

## 2. Credentials and access rules

The credentials workbook is the access source of truth:

`/Volumes/xcode/Synergy-Network-Projects/node-machine-credentials.xlsx`

No passwords, passphrases, private keys, or tokens are included in this
handoff. The user will provide the workbook separately.

Mandatory access rules:

- Use only workbook-backed aliases of the form `ssh synergy-*`.
- Use one persistent SSH control connection per node.
- Do not use raw IP addresses, ad-hoc jump hosts, or repeated one-off SSH
  probes.
- Use `ssh synergy-index` for the explorer indexer. `synergy-vps` is retired.
- Use `sudo -n` after confirming the workbook-backed host configuration.
- Do not print private-key material.

The options used for the current launch work were:

```bash
-o BatchMode=yes \
-o ConnectTimeout=8 \
-o ControlMaster=auto \
-o ControlPersist=900 \
-o ControlPath=/tmp/synergy-tv3-status-%C
```

Relevant aliases:

```text
synergy-val1
synergy-val2
synergy-val3
synergy-val4
synergy-val5
synergy-val6
synergy-relayer1
synergy-relayer2
synergy-relayer3
synergy-rpc
synergy-index
synergy-main
```

The validator VPN coordinator is on `synergy-main`. It already published the
corrected signed generation 22. Do not replace it or generate another
validator set during this recovery.

## 3. Frozen network identity and launch invariants

| Item | Canonical value |
|---|---|
| Network | `synergy-testnet-v3` |
| Chain ID | `1266` |
| Runtime / Control Panel version | `20.0.0` |
| Canonical genesis file SHA-256 | `ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf` |
| Canonical genesis hash | `c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d` |
| Candidate input ID | `6226cbebc7b4d7589f4a12c2b42fd052d7844194b1b0f1fd38e41d81b1f690bc` |
| Consensus decision ID | `TV3-POSY-PARAMS-2026-07-28-01` |
| Consensus parameter manifest SHA-256 | `5451f7084bfd97d136a1ab035d70b09ddc3262e6cc4e142b90091bac3a3ea854` |
| Consensus parameter SHA3-512 root | `2e6760bed60c8f8e44b3b693254367f0da9a8aa9efae46c517856fb78be7402cf232c064083116b805278e95a952660f7a92e16ca9cd9349aa74467d577127cd` |

Canonical launch consensus values:

```text
epoch_length_slots      = 1000
target_block_time_ms    = 2000
proposal_timeout_ms     = 1500
prevote_timeout_ms      = 1500
precommit_timeout_ms    = 1500
max_round_timeout_ms    = 10000
```

Healthy-network performance targets are not consensus timeouts:

```text
healthy_proposal_target_ms = 450
healthy_qc_target_ms       = 1850
healthy_commit_target_ms   = 2250
finality_p95_target_ms     = 2500
finality_p99_target_ms     = 3000
```

Deferred:

- `epoch_length_slots = 3600`
- `max_round_timeout_ms = 30000`
- ETDAG activation at genesis

The chain must launch with the current six-validator baseline. Do not expand it
to validators 7–21 during initial recovery.

## 4. Canonical local directories and artifacts

### 4.1 Main repositories

| Purpose | Local path |
|---|---|
| Testnet-v3 source | `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3` |
| Canonical SynQ language source | `/Volumes/xcode/Synergy-Network-Projects/network-components/synq-language` |
| Address Engine | `/Volumes/xcode/Synergy-Network-Projects/protocol-components/synergy-address-engine` |
| Control Panel working clone | `/Users/devpup/Documents/Codex/2026-07-28/we/synergy-node-control-panel` |
| Current work/evidence directory | `/Users/devpup/Documents/Codex/2026-07-28/we/work` |
| Credentials workbook | `/Volumes/xcode/Synergy-Network-Projects/node-machine-credentials.xlsx` |

Do not treat duplicated SynQ source under a runtime checkout as canonical. The
canonical repository is the `network-components/synq-language` path above.

### 4.2 Genesis and launch records

All paths below are relative to the Testnet-v3 repository unless absolute:

| Artifact | Path |
|---|---|
| Canonical applied genesis | `genesis.testnet-v3.identity-assigned.json` |
| Test-fixture genesis | `genesis.testnet-v3.test-fixture.json` |
| Production authorities | `launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json` |
| Production contract addresses | `launch/TESTNET_V3_PRODUCTION_CONTRACT_ADDRESSES.json` |
| Ceremony evidence directory | `launch/production-genesis-ceremony` |
| Signed release approval | `launch/production-genesis-ceremony/testnet-v3-genesis-release-approval.json` |
| Phase 7/8 apply journal | `launch/production-genesis-ceremony/phase7-apply-journal.json` |
| Phase 7 integrity record | `launch/production-genesis-ceremony/phase7-release-integrity.json` |
| Canonical generated node configs | `launch/production-node-configs` |
| Consensus parameter manifest | `launch/TESTNET_V3_CONSENSUS_PARAMETERS.json` |
| Runtime binding | `launch/TESTNET_V3_RUNTIME_BINDING.json` |
| Validator identity root | `testnet-v3-identity-files` |
| ETDAG ingress records | `launch/TESTNET_V3_ETDAG_INGRESS_KEY_RECORDS.json` |
| ETDAG admission request | `launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_REQUEST.json` |
| ETDAG admission votes | `launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_VOTES.json` |
| VPN public registry | `launch/validator-vpn-public-registry.json` |
| VPN checksums | `launch/validator-vpn-checksums.json` |

The final genesis deployment and release approval are complete:

- Ceremony execution succeeded for nine deployments and 27 initialization
  calls.
- Governance signed the exact release-approval request with ML-DSA-87.
- `phase7-apply-journal.json` reports `APPLIED`.
- `phase7-release-integrity.json` reports
  `PHASE_7_8_APPLIED_PENDING_RELEASE_GATES` and Track H `APPLIED`.

### 4.3 Corrected runtime artifact

Local downloaded artifact directory:

`/Users/devpup/Documents/Codex/2026-07-28/we/work/testnet-v3-v20-runtime-hotfix-30536627486`

Files:

```text
SHA256SUMS
TESTNET_SOURCE_REVISION
release-config-manifest.json
synergy-node-linux-amd64
synergy-relayer-node-linux-amd64
synergy-validator-node-linux-amd64
```

The artifact was built from immutable Testnet source:

`791a61e146fd55e44f0460c9ec8e00bdcb31d13f`

Verified artifact SHA-256 values:

| File | SHA-256 |
|---|---|
| `synergy-node-linux-amd64` | `dc5eea12132e1f5445e3cf061e930d84ddf4bd5f3a4de2ed88ced57cb3f203b4` |
| `synergy-relayer-node-linux-amd64` | `6b7d5cdb065e7c9a1e76b37d7df461c2fc7ec0e22891040d7d941c1140eaafc4` |
| `synergy-validator-node-linux-amd64` | `0a1b295a38171a5657974172d3044af2f8e7f0ca072569ce7cc10bca4e069823` |
| `release-config-manifest.json` | `1480ba65e166dde69e899831d9986f0f6512d413314df54111efa6cab409b703` |
| `TESTNET_SOURCE_REVISION` | `01d6f62758397bb2e18a1a4a3e647a9fea091e2f5577001bf6ee914cedc0131e` |

Verification already completed:

- All five entries pass `sha256sum -c SHA256SUMS`.
- Source revision matches `791a61e...`.
- The artifact release-config manifest is byte-identical to the canonical
  source file.
- All three binaries are Linux x86-64 ELF executables.
- The GitHub job executed all three binaries and verified
  `Synergy Testnet Node v20.0.0` before artifact upload.

Do not rebuild this artifact merely to continue the launch.

## 5. GitHub repositories, PRs, workflows, and artifacts

### 5.1 Testnet-v3 repository

GitHub repository:

`https://github.com/synergy-network-hq/testnet-v3`

Current remote `main` when this document was written:

`ed9e671892243a98b0c70bac52cc0703652f8008`

Important merged PRs:

| PR | Purpose | Merge commit |
|---|---|---|
| [#3](https://github.com/synergy-network-hq/testnet-v3/pull/3) | Typed finality recovery and service observers | `791a61e146fd55e44f0460c9ec8e00bdcb31d13f` |
| [#4](https://github.com/synergy-network-hq/testnet-v3/pull/4) | Recoverable v20 runtime switch and v2-state quarantine scripts | `ed9e671892243a98b0c70bac52cc0703652f8008` |

Current local operational branch:

`agent/control-panel-v20-testnet-v3-release`

Branch commit before this live-status update:

`081db33797288c21cf344968c37736ef84b45747`

Open handoff PR:

`https://github.com/synergy-network-hq/testnet-v3/pull/5`

The branch also contains commit `98a709886fb48c27643e85d709b6af63f9e307dd`,
which fixes a runtime-switch verifier race by waiting for the
`synergy-release-guard` shell to `exec` the actual runtime. Neither the
operational-script commit nor this handoff PR was merged into `main` at the
11:53 UTC verification point.

Operational scripts:

```text
scripts/stage-testnet-v3-v20-runtime-hotfix.sh
scripts/testnet-v3-v20-runtime-hotfix-remote.sh
scripts/quarantine-testnet-v3-v2-validator-state.sh
scripts/testnet-v3-v2-validator-state-remote-quarantine.sh
```

### 5.2 Node Control Panel repository

GitHub repository:

`https://github.com/synergy-network-hq/synergy-node-control-panel`

Current remote `main`:

`d17bb0913bdeddc71b5dd2f3d65c72379e09ae3d`

Important merged PRs:

| PR | Purpose | Merge commit |
|---|---|---|
| [#38](https://github.com/synergy-network-hq/synergy-node-control-panel/pull/38) | V20 Testnet-v3 launch contracts and early runtime hotfix | `5b9ce83ddd65f879c93a923b58d563da3efd65aa` |
| [#39](https://github.com/synergy-network-hq/synergy-node-control-panel/pull/39) | Preserve immutable Testnet source binding after compile | `d17bb0913bdeddc71b5dd2f3d65c72379e09ae3d` |

Canonical workflow:

`/Users/devpup/Documents/Codex/2026-07-28/we/synergy-node-control-panel/.github/workflows/release.yml`

The hotfix job in that workflow is:

`build-linux-runtime-hotfix`

It builds:

```text
synergy-testnet
synergy-validator-node
synergy-relayer-node
```

from immutable Testnet-v3 and SynQ revisions.

Corrected hotfix workflow run:

`https://github.com/synergy-network-hq/synergy-node-control-panel/actions/runs/30536627486`

- Head: `d17bb0913bdeddc71b5dd2f3d65c72379e09ae3d`
- Hotfix job conclusion: success
- Runtime artifact ID: `8757259227`
- Runtime artifact name: `testnet-v3-linux-runtime-hotfix`
- The overall run was deliberately canceled after the hotfix artifact
  succeeded, to avoid duplicating the already-running full installer build.

Full installer workflow run:

`https://github.com/synergy-network-hq/synergy-node-control-panel/actions/runs/30535584586`

- Head: `5b9ce83ddd65f879c93a923b58d563da3efd65aa`
- Linux installer job succeeded.
- Artifact ID: `8757257127`
- Artifact name: `installer-linux`
- Artifact size at handoff: 684,661,112 bytes.
- The overall run was still active for remaining non-Linux work when last
  checked.

## 6. Live node layout and current deployed state

### 6.1 Validators

All six validator services are active:

`synergy-validator.service`

Current validator runtime on every validator:

```text
/opt/synergy/bin/synergy-validator
SHA-256 0a1b295a38171a5657974172d3044af2f8e7f0ca072569ce7cc10bca4e069823
Version output: Synergy Testnet Node v20.0.0
```

This is the corrected validator artifact. It was verified against the live
process image on all six machines at 11:53 UTC.

Canonical remote paths:

```text
Service unit:
  /etc/systemd/system/synergy-validator.service

Runtime:
  /opt/synergy/bin/synergy-validator

Canonical systemd config:
  /etc/synergy/validator/config.toml

Control Panel config workspace:
  /var/lib/synergy/validator/config/node.toml

Canonical genesis:
  /etc/synergy/testnet-v3/genesis.json

ML-DSA-65 consensus key:
  /var/lib/synergy/validator/config/validator/mldsa65-consensus.private.key

Validator data:
  /var/lib/synergy/validator/data

Current finality store:
  /var/lib/synergy/validator/data/typed-posy-finality.json

Current signing journal:
  /var/lib/synergy/validator/data/consensus_signing_authorizations.json

Recoverable backups:
  /var/backups/synergy-testnet-v3
```

Correction to earlier handoff text: no validator has
`/var/lib/synergy/validator/config/operational-manifest.json`, and the active
service does not directly load one. Do **not** copy the similarly named Control
Panel source artifact to the hosts: the only such source file found is a stale
Testnet-v2/chain-1264 manifest. The live validator services have explicit
Testnet-v3 validator addresses, canonical configs, canonical genesis, and
VPN transports. The optional manifest lookup in the runtime is used only for a
legacy local-slot/self-alias derivation path and is not a launch requirement for
these explicitly bound V3 services.

The consensus key exists on all six machines and was previously verified as
mode `0600`, owned by the node service account, with a 5,377-byte protected
key file. Never print it.

The obsolete version-2 state was quarantined before the corrected runtime was
started. Backup directories:

| Alias | Version-2 quarantine | Runtime-switch backup |
|---|---|---|
| `synergy-val1` | `prelaunch-v2-validator-state-20260730T114436Z` | `runtime-hotfix-validator-20260730T114539Z` |
| `synergy-val2` | `prelaunch-v2-validator-state-20260730T114437Z` | `runtime-hotfix-validator-20260730T114538Z` |
| `synergy-val3` | `prelaunch-v2-validator-state-20260730T114437Z` | `runtime-hotfix-validator-20260730T114540Z` |
| `synergy-val4` | `prelaunch-v2-validator-state-20260730T114437Z` | `runtime-hotfix-validator-20260730T114545Z` |
| `synergy-val5` | `prelaunch-v2-validator-state-20260730T114438Z` | `runtime-hotfix-validator-20260730T114553Z` |
| `synergy-val6` | `prelaunch-v2-validator-state-20260730T114437Z` | `runtime-hotfix-validator-20260730T114537Z` |

Current finality state at the 11:53 UTC sample:

| Alias | Store version | Height | Block ID |
|---|---:|---:|---|
| `synergy-val1` | 3 | 58 | `61ec76a7f63d4a1ebe0d1ecc34da0f375e433bbdc96cfa44d900fa975c6e8b38` |
| `synergy-val2` | 3 | 59 | `7e42b52b9e5da259c54f3b08f30de05c54e1daab1a8ff055e4dd9d6908793704` |
| `synergy-val3` | 3 | 58 | `61ec76a7f63d4a1ebe0d1ecc34da0f375e433bbdc96cfa44d900fa975c6e8b38` |
| `synergy-val4` | 3 | 58 | `61ec76a7f63d4a1ebe0d1ecc34da0f375e433bbdc96cfa44d900fa975c6e8b38` |
| `synergy-val5` | 3 | 58 | `61ec76a7f63d4a1ebe0d1ecc34da0f375e433bbdc96cfa44d900fa975c6e8b38` |
| `synergy-val6` | 3 | 58 | `61ec76a7f63d4a1ebe0d1ecc34da0f375e433bbdc96cfa44d900fa975c6e8b38` |

Validator 2 was one block ahead in this instantaneous sample. Earlier samples
showed all six at height 10 on one block ID, then normal one-block propagation
lag at heights 13–14 and 16–17. No divergent same-height block ID was observed.

Canonical validator addresses and config hashes:

| Validator | Address | VPN listen | Config SHA-256 |
|---|---|---|---|
| 1 | `synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t` | `10.70.10.1:5622` | `d2b57d938158864ca23c6f1344cd96f57305d44c7c3c736bc6f0a168cb70c8bc` |
| 2 | `synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk` | `10.70.10.2:5622` | `9f7748287ef49b71fab865d6f0d90e238c405e9eeb4ba9a7b53f3e788ad67499` |
| 3 | `synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj` | `10.70.10.3:5622` | `6ff5dc65c745d98d53d5a80580c8f9e9c117c8aa5dd7b9ef7dc4b7f3852cd645` |
| 4 | `synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg` | `10.70.10.4:5622` | `17b7a353da956e82a07e255404f54d48da803d9898ccfaf4af16dffd9451002a` |
| 5 | `synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu` | `10.70.10.5:5622` | `5e68133d4d5560a99882015748fe0f979ce13030b9ee63f03a96250213904fa3` |
| 6 | `synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc` | `10.70.10.6:5622` | `eccf76d5002d03df305dfe8d7fea4c236ba6363961f7977e442e76e6cad21c8d` |

The six live validator config files and genesis files were checked against
these canonical values before the current handoff.

### 6.2 Relayers

Service on each:

`synergy-testnet-v3-relayer.service`

Corrected runtime currently executing on all three:

```text
/opt/synergy/testnet-v3/relayer/synergy-relayer-node-v20.0.0-6b7d5cdb065e7c9a1e76b37d7df461c2fc7ec0e22891040d7d941c1140eaafc4
```

Runtime SHA-256:

`6b7d5cdb065e7c9a1e76b37d7df461c2fc7ec0e22891040d7d941c1140eaafc4`

Other paths:

```text
Release guard:
  /opt/synergy/testnet-v3/relayer/synergy-release-guard

Configs:
  /etc/synergy/testnet-v3/relay1.toml
  /etc/synergy/testnet-v3/relay2.toml
  /etc/synergy/testnet-v3/relay3.toml

Working directories:
  /var/lib/synergy/testnet-v3/relay1
  /var/lib/synergy/testnet-v3/relay2
  /var/lib/synergy/testnet-v3/relay3

Backups:
  /var/backups/synergy-testnet-v3
```

The three relayer processes are active, but none has created a
`typed-posy-finality.json` observer store. Their role data directories contain
`chain.json`, `dag_state.json`, `role-runtime.json`, and the validator transport
registry only. All three repeatedly reject validator records with:

```text
round 1 is not authorized; valid TC is required to advance from round 0
```

All three also log:

```text
typed finality observer request to relayer is not from a configured public service role
```

These were still occurring at 11:53 UTC. Fix and test both conditions before
the next deployment; do not assume the first error is the only blocker.

Do not touch the retired masked unit:

`synergy-testnet-relayer.service`

### 6.3 RPC gateway

Alias:

`synergy-rpc`

Service:

`synergy-testnet-v3-rpc-gateway.service`

Corrected runtime currently executing:

```text
/opt/synergy/testnet-v3/bin/synergy-node-v20.0.0-dc5eea12132e1f5445e3cf061e930d84ddf4bd5f3a4de2ed88ced57cb3f203b4
```

Runtime SHA-256:

`dc5eea12132e1f5445e3cf061e930d84ddf4bd5f3a4de2ed88ced57cb3f203b4`

Paths:

```text
Config:
  /etc/synergy/testnet-v3/rpc-gateway/node.toml

Runtime environment:
  /etc/synergy/testnet-v3/rpc-gateway/runtime.env

Release guard:
  /opt/synergy/testnet-v3/bin/synergy-release-guard

Backups:
  /var/backups/synergy-testnet-v3
```

Public endpoint:

`https://testnet-core-rpc.synergy-network.io`

`/healthz` currently returns HTTP 200 and `ok`. A live JSON-RPC query at
11:53 UTC returned `synergy_blockNumber = 0` because the relayer finality
observers reject the validators' finalized records. The validators themselves
are already finalizing post-genesis blocks.

### 6.4 Explorer index node and Atlas

Alias:

`synergy-index`

Explorer runtime service:

`synergy-testnet-v3-explorer-indexer.service`

Corrected runtime currently executing:

```text
/opt/synergy/testnet-v3/bin/synergy-node-v20.0.0-dc5eea12132e1f5445e3cf061e930d84ddf4bd5f3a4de2ed88ced57cb3f203b4
```

Paths:

```text
Config:
  /etc/synergy/testnet-v3/explorer-indexer/node.toml

Runtime environment:
  /etc/synergy/testnet-v3/explorer-indexer/runtime.env

Atlas releases:
  /opt/synergy/testnet-v3/atlas/releases

Current Atlas backend release:
  /opt/synergy/testnet-v3/atlas/releases/v20.0.0-atlas-v3-hotfix-c78c9574406d
```

Atlas services:

```text
synergy-testnet-v3-atlas-api.service
synergy-testnet-v3-atlas-indexer.service
synergy-testnet-v3-explorer-indexer.service
```

Current public sites:

```text
https://testnet-atlas.synergy-network.io
https://testnet-explorer.synergy-network.io
```

At handoff, both canonical sites returned HTTP 200 and their network summary
reported:

```text
chainId          = 1266
latestBlock      = 0
activeValidators = 6
totalValidators  = 6
peerCount        = 3
```

The earlier Cloudflare 526 failure is no longer active, but Atlas is **not yet
verified stable**. A follow-up endpoint audit on 2026-07-30 found all of the
following:

- The API and indexer services are active, and the current valid read contracts
  return the expected JSON when requests reach the backend.
- A 240-request soak through both
  `testnet-atlas-api.synergy-network.io` and the Pages proxy completed with
  240 HTTP 200 responses at the end of the audit.
- Nginx access logs nevertheless contain 460 real browser-origin HTTP 400
  responses across the ten Atlas snapshot paths: 46 failures apiece for
  blocks, transactions, validators, tokens, contracts, accounts, network
  summary, DAG status, DAG frontier, and DAG topology.
- The origin requires a Cloudflare client certificate:

  ```text
  /etc/nginx/snippets/synergy-cloudflare-aop.conf
  ssl_verify_client on;
  ```

  but Cloudflare zone-level Authenticated Origin Pulls currently reports
  `enabled: false`, with no hostname-level associations. Earlier failing
  responses contained `No required SSL certificate was sent`. This mismatch is
  the recurrence risk behind the intermittent HTTP 400 bursts and must be
  corrected before Atlas is called stable.

The backend currently defines 34 read-only GET routes including health and
version routes. Thirty-three were exercised; the only route not invoked was a
wallet-pairing session lookup because producing a valid session would require a
state-changing session-creation request.

Several visible Atlas messages describe genuine backend gaps rather than
frontend transport failures. These routes currently return HTTP 404:

```text
/api/v1/clusters
/api/v1/clusters/:id
/api/v1/clusters/:id/history
/api/v1/epochs
/api/v1/epochs/:number
/api/v1/epochs/:number/history
/api/v1/metrics/network-activity
/api/v1/metrics/blocks
/api/v1/metrics/throughput
/api/v1/metrics/indexer-lag
/api/v1/status/components
/api/v1/status/incidents
/api/v1/search
/api/v1/openapi.json
```

Accordingly, `Backend blocked`, `REQUIRED CONTRACT GET /clusters`, and many
`Historical endpoint required` surfaces are deliberate unavailable states for
contracts that do not exist yet. They are not evidence that the corresponding
backend work was completed.

The denomination converter and gas tools exist only in the dirty local Atlas
checkout:

```text
/Volumes/xcode/Synergy-Network-Projects/network-websites/atlas-v3
```

They are not in Git commit `6edcd85fe8063b2f5db88b713ac3ed03a67c18c4`,
which is the commit associated with the current production Pages deployment.
The local tool work passes 66 tests, lint, and a production build, but it has
not been committed, pushed, or deployed. The live `/converter` and `/gas`
routes therefore still render the temporary Testnet-v3 activation landing
page.

Atlas is also showing zero blocks because its source RPC is at height zero.
The current API summary reports chain ID 1266, six active validators, indexed
height zero, and zero transactions. The green readiness response only proves
that the indexer and RPC agree at height zero; it does not prove that the chain
is advancing.

At 11:53 UTC the public summary still returned:

```text
chainId=1266 latestBlock=0 activeValidators=6 totalValidators=6 peerCount=3
```

`atlas-api.synergy-network.io` did not resolve when checked. It is not the
canonical public URL used for the current launch verification.

## 7. What has already been attempted and resolved

### 7.1 Genesis ceremony

The first dry-run ceremony panicked while serializing a map with non-string
keys. That was fixed. A later dry run completed, then the execute ceremony
completed:

- Nine contract addresses matched the frozen derivation record.
- Nine deployments completed.
- Twenty-seven initialization calls completed.
- Post-deployment execution root:
  `2902ef7dc3f6d49d30ced4b03274c4f5708b84c88bf368fd051ebee11ffb0c39`
- Post-deployment AIVM state root:
  `6bb65e453b33a5a9bdbcf6446fc1bf5ad6bec487375def6e8cf74c3b2f0dc452`
- Deployment receipt root:
  `1ddd5472813884fe71456bd3df736848820db8fb55a3f307792b2796027e828a`
- Genesis deployer was permanently retired.

The governance authority then signed the exact generated release request. The
approval SHA-256 is:

`b55629e894a25032d4bb96ae3274ec1a39b5ea8de5d68adc84bd1d5f89d6c5a3`

The guarded finalizer was applied and wrote the Phase 7/8 integrity evidence.

### 7.2 VPN and validator identities

- The VPN coordinator published generation 21 for the six validators.
- A canonical-address correction published generation 22.
- Generation-22 public snapshot SHA-256:
  `747fa7ba11905476431308f75cd12ec96a1d0cb01073a08801984d341cdfc141`
- All six validator machines and three relayers were observed as VPN peers.
- Validator 5’s innernet-managed interface issue was resolved. Do not enable
  `wg-quick@sy-vpn`; the installed transport is managed by
  `synergy-innernet.service`.
- Validator 5’s ML-DSA-65 consensus key was successfully provisioned at the
  canonical path.

### 7.3 ETDAG

- Six ETDAG ingress keypairs were generated and verified.
- Five validator admission votes were signed with ML-DSA-65.
- Five votes were intentional quorum admission; validator 6 was not required
  for that artifact.
- ETDAG activation at genesis was later deferred. These artifacts remain valid
  preparation for later activation but are not a current chain-launch blocker.

### 7.4 Runtime and release recovery

- Source and Control Panel versions were aligned to v20.0.0.
- Testnet PR #3 added version-3 finality recovery plus non-signing typed
  finality observers for relayer/RPC/index roles.
- Testnet PR #4 added recoverable deployment and exact v2-state quarantine
  scripts.
- Control Panel PRs #38 and #39 corrected the v20 release workflow and
  immutable Testnet source binding.
- A first runtime-hotfix run compiled successfully but failed after compilation
  because `TESTNET_SOURCE_REV` was out of shell scope.
- PR #39 fixed the environment scope, Rust cache, and checksum paths.
- The corrected run built and uploaded the verified artifact.
- Relayers 1–3, RPC, and explorer indexer were switched to the corrected
  binaries with timestamped backups.
- The RPC switch initially emitted:
  `live process is not using the staged runtime`.
  This was a false negative caused by checking the guard shell before it had
  executed the runtime. The RPC process was verified to be running the correct
  hash. Commit `98a7098...` changes the verifier to wait up to 30 seconds. The
  indexer then switched cleanly with that fix.

### 7.5 Coordinated validator version-3 recovery

The six-validator cutover described in the earlier version of this handoff is
complete:

1. The corrected artifact, immutable Testnet source revision, and release
   config manifest were reverified.
2. All six validator services were stopped through one barrier and verified
   inactive.
3. The exact version-2 finality/signing state was moved—not deleted—into the
   timestamped backup directories listed in section 6.1.
4. The corrected validator binary was staged on all six machines while the
   services remained inactive.
5. Pre-start checks passed for the binary, canonical genesis, per-validator
   config, ML-DSA-65 key, absence of live version-2 journals, VPN peer set, and
   lack of detached validator processes.
6. All six validators were started through one barrier.
7. All six created version-3 stores and converged on a common advancing chain.

The initial startup warning that the typed coordinator was not running occurred
before the coordinator was installed during service initialization. Each
validator subsequently logged the `posy/2.2` coordinator starting and produced
finalized records.

Observed advancement samples:

```text
11:49:54 UTC  all six at height 10, common block ID
11:50:05 UTC  validators at heights 13–14
11:50:17 UTC  validators at heights 16–17
11:53 UTC     validators at heights 58–59
```

This proves validator consensus and persistence recovery. It does not prove
public launch readiness because the relayer observer defect described below
still blocks downstream propagation.

## 8. Current blockers and incomplete work

### Blocker 1: relayer observer rejects valid round-1 finality

This is the direct reason the public chain remains at height 0.

- Validator consensus is healthy and advancing with version-3 stores.
- Each relayer receives finalized records but rejects them with
  `round 1 is not authorized; valid TC is required to advance from round 0`.
- No relayer creates a typed finality observer store.
- RPC, indexer, and Atlas consequently remain at height 0.

The relevant source areas are:

```text
runtime/src/consensus/typed_finality_observer.rs
runtime/src/consensus/posy.rs
runtime/src/p2p/messages.rs
runtime/src/p2p/networking.rs
runtime/src/role_runtime.rs
```

The exact invariant must be resolved from code and tests. Do not bypass or
weaken consensus verification. Determine whether:

1. the finalized record must durably carry the TC/QC evidence that authorized
   round 1 and the serving validator currently omits it; or
2. the observer is applying a live round-transition check to a durable
   finalized record whose QC already cryptographically authorizes its round and
   should use the dedicated finalized-record recovery verification path.

Add tests for valid round-greater-than-zero recovery, missing/invalid evidence,
gap rejection, and fork rejection before building another runtime artifact.

### Blocker 2: relayer service-role authorization mismatch

All three relayers also reject a typed-finality observer request because its
peer is not classified as a configured public service role. Audit the RPC and
index role allowlists, the signed role identities, and the P2P authorization
branch that handles observer requests. Resolve this in the same source/build/
deployment pass as Blocker 1 so another long release is not spent discovering
the second known failure afterward.

### Incomplete 3: public propagation is blocked, not merely unproven

After the two observer defects are fixed, verify:

- all three relayer observer stores are created and advance;
- RPC `synergy_blockNumber` advances;
- the explorer index node follows the same head;
- Atlas `latestBlock` advances above zero across multiple samples;
- relayers no longer log either known observer rejection.

### Incomplete 4: runtime release manifest is stale

`launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json` still contains older validator
and relayer hashes and a retired relayer service path. Update it after the
successful cutover with:

```text
generic   dc5eea12132e1f5445e3cf061e930d84ddf4bd5f3a4de2ed88ced57cb3f203b4
relayer   6b7d5cdb065e7c9a1e76b37d7df461c2fc7ec0e22891040d7d941c1140eaafc4
validator 0a1b295a38171a5657974172d3044af2f8e7f0ca072569ce7cc10bca4e069823
source    791a61e146fd55e44f0460c9ec8e00bdcb31d13f
workflow  30536627486
artifact  8757259227
```

### Incomplete 5: operational/handoff PR not merged

PR #5 is open and cleanly mergeable at commit
`081db33797288c21cf344968c37736ef84b45747`. It contains the switch-verifier
fix and this handoff. Merge it after review; do not confuse merging operational
documentation with fixing the runtime observer defect.

### Incomplete 6: Atlas endpoint and transport completion

The endpoint contract and 400-response audit described in section 6.4 must be
finished after this handoff update. Known issues before the final audit:

- Cloudflare AOP is disabled while Nginx requires a client certificate;
- browser-origin 400 bursts have been observed on all ten snapshot routes;
- clusters, history, metrics, status, search, and OpenAPI routes are missing;
- the denomination converter and gas tools exist only in a dirty local checkout
  and are not deployed.

### Incomplete 7: boot persistence

The current launch services were observed as active but some are static or
disabled. After the chain is demonstrably healthy, install or enable the
intended boot target so an ordinary host reboot restores the full Testnet-v3
stack. Do not change boot behavior during the coordinated consensus cutover.

## 9. Current continuation and completed operator record

### 9.1 Exact current continuation

Do not repeat the validator quarantine/cutover procedure in section 9.2. It is
retained only as an audit record of the completed recovery.

1. Keep the six validators running. Capture multi-sample finality heights while
   diagnosing, but do not restart them or alter their version-3 state.
2. Inspect the complete finalized-record production, persistence,
   serialization, serving, transport, and observer-validation path. Start with:

   ```text
   runtime/src/consensus/typed_finality_observer.rs
   runtime/src/consensus/posy.rs
   runtime/src/p2p/messages.rs
   runtime/src/p2p/networking.rs
   runtime/src/role_runtime.rs
   ```

3. Reproduce the round-1 rejection in a test using a real finalized record
   shape. Prove the exact missing or misapplied evidence rather than relaxing
   `validate_round_change`.
4. In parallel within the same source audit, trace the known service-role
   rejection from the configured RPC/index identity through relayer
   authorization. Correct the allowlist/identity contract without broadening it
   to arbitrary peers.
5. Add round-greater-than-zero recovery, evidence-failure, gap, fork, and
   unauthorized-role tests. Run the focused consensus/P2P/role suites before
   any new release.
6. Commit and merge the source fix, update the Control Panel workflow's
   immutable `TESTNET_SOURCE_REV`, and build one new v20.0.0 Linux runtime
   artifact in GitHub Actions. Do not use a locally compiled Mac artifact on
   Linux nodes.
7. Verify source revision, `SHA256SUMS`, release-config manifest, ELF
   architecture, and embedded version. Stage roles while preserving current
   binaries and data in timestamped backups.
8. Deploy the corrected observer-capable artifact to relayers first. If the
   durable record format or serving behavior changed, deploy validators only
   through a coordinated no-data-loss barrier; otherwise leave the healthy
   validators untouched. Then deploy RPC and index roles if their code changed.
9. Require all of the following before declaring launch:

   ```text
   relayer observer stores created and advancing
   no round-1/TC rejection
   no public-service-role rejection
   public RPC height advancing above zero
   explorer index height following RPC
   Atlas latestBlock and block list advancing across multiple samples
   ```

10. Update `launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json`, append final node
    hashes/heights/backups/workflow provenance to launch evidence, and only then
    address boot-persistence testing.

### 9.2 Completed validator recovery record — do not rerun

Run from:

```bash
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3
```

Artifact directory:

```bash
artifact_dir=/Users/devpup/Documents/Codex/2026-07-28/we/work/testnet-v3-v20-runtime-hotfix-30536627486
```

### Completed step 1: re-verify the artifact

```bash
(
  cd "$artifact_dir"
  sha256sum -c SHA256SUMS
)

test "$(tr -d '\r\n' < "$artifact_dir/TESTNET_SOURCE_REVISION")" \
  = 791a61e146fd55e44f0460c9ec8e00bdcb31d13f

cmp -s \
  "$artifact_dir/release-config-manifest.json" \
  launch/production-node-configs/release-config-manifest.json
```

### Completed step 2: verify support services on corrected binaries

For each of `synergy-relayer1`, `synergy-relayer2`, `synergy-relayer3`,
`synergy-rpc`, and `synergy-index`, inspect the active unit’s MainPID,
`/proc/<pid>/exe`, and SHA-256. Expected hashes:

```text
relayers: 6b7d5cdb065e7c9a1e76b37d7df461c2fc7ec0e22891040d7d941c1140eaafc4
RPC/index: dc5eea12132e1f5445e3cf061e930d84ddf4bd5f3a4de2ed88ced57cb3f203b4
```

Do not redeploy them if they already match.

### Completed step 3: stop all six validators before changing state

Use a coordinated barrier:

```bash
for host_alias in \
  synergy-val1 synergy-val2 synergy-val3 \
  synergy-val4 synergy-val5 synergy-val6
do
  ssh \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    -o ControlMaster=auto \
    -o ControlPersist=900 \
    -o ControlPath=/tmp/synergy-tv3-status-%C \
    "$host_alias" \
    'sudo -n systemctl stop synergy-validator.service' &
done
wait
```

Then verify all six are inactive before proceeding.

### Completed step 4: quarantine only obsolete version-2 finality state

Validator 1:

```bash
scripts/quarantine-testnet-v3-v2-validator-state.sh \
  --host synergy-val1 \
  --expected-height 18 \
  --expected-block-id 5bf3448cbae973b7f68798242e3a5d1a388dd28b9cb15742f203663467d2812b \
  --apply
```

Validators 2–6 were actually at height 29 in the final pre-cutover sample:

```bash
for host_alias in \
  synergy-val2 synergy-val3 synergy-val4 synergy-val5 synergy-val6
do
  scripts/quarantine-testnet-v3-v2-validator-state.sh \
    --host "$host_alias" \
    --expected-height 29 \
    --expected-block-id 1098966c08ea29e2f870f7027f868b7b30acb5821da5f1fb7db5ac5669727b73 \
    --apply
done
```

The script fails closed if the height, block ID, store version, service state,
genesis, or journal format differs. If it fails, inspect the discrepancy. Do
not manually delete files.

Expected files moved into each timestamped backup:

```text
typed-posy-finality.json
consensus_signing_authorizations.json
consensus_vote_locks.json          if present
consensus_proposals/               if present
```

Do not move or delete `chain.json`, genesis, identity files, validator keys,
node configs, DAG state, or unrelated data.

### Completed step 5: stage corrected binary while services remained inactive

```bash
for host_alias in \
  synergy-val1 synergy-val2 synergy-val3 \
  synergy-val4 synergy-val5 synergy-val6
do
  scripts/stage-testnet-v3-v20-runtime-hotfix.sh \
    --artifact-dir "$artifact_dir" \
    --role validator \
    --host "$host_alias" \
    --leave-inactive \
    --apply
done
```

Expected live validator binary SHA-256:

`0a1b295a38171a5657974172d3044af2f8e7f0ca072569ce7cc10bca4e069823`

Before starting any validator, verify on all six:

- service is inactive;
- binary hash matches;
- genesis SHA matches;
- per-validator config SHA matches the table above;
- ML-DSA-65 consensus key exists with protected permissions;
- version-2 store and signing journal are absent from the live data directory;
- timestamped quarantine evidence exists;
- VPN interface and peer set are healthy;
- no detached validator process is running.

### Completed step 6: start all six through one barrier

```bash
for host_alias in \
  synergy-val1 synergy-val2 synergy-val3 \
  synergy-val4 synergy-val5 synergy-val6
do
  ssh \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    -o ControlMaster=auto \
    -o ControlPersist=900 \
    -o ControlPath=/tmp/synergy-tv3-status-%C \
    "$host_alias" \
    'sudo -n systemctl start synergy-validator.service' &
done
wait
```

### Completed step 7: verify consensus, not merely process liveness

Poll all six version-3 finality stores. Success requires:

- all services remain active;
- all six stores report `store_version = 3`;
- all six reach a common height and block ID;
- the common height advances over multiple samples;
- no validator remains at a lower fixed height;
- logs contain no repeated finality, signature, genesis, parameter-root, peer
  authorization, or store-recovery errors.

Use the persisted finality record as the authoritative per-validator check:

```bash
sudo -n jq -r \
  '[.store_version, (.records | length), .records[-1].height, .records[-1].block_id] | @tsv' \
  /var/lib/synergy/validator/data/typed-posy-finality.json
```

Do not declare success from `systemctl is-active` alone.

### Pending downstream step 8: verify public propagation after observer repair

Public RPC:

```bash
curl -fsS \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_chainId","params":[]}' \
  https://testnet-core-rpc.synergy-network.io

curl -fsS \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}' \
  https://testnet-core-rpc.synergy-network.io
```

Atlas:

```bash
curl -fsS \
  -A 'SynergyLaunchVerifier/20.0.0' \
  'https://testnet-atlas.synergy-network.io/api/v1/network/summary'

curl -fsS \
  -A 'SynergyLaunchVerifier/20.0.0' \
  'https://testnet-atlas.synergy-network.io/api/v1/blocks?limit=5'
```

Success requires an advancing nonzero public RPC height and Atlas
`latestBlock`, not a single nonzero sample.

### Pending final step 9: write final evidence and update release records

After stable multi-sample advancement:

1. Update `launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json`.
2. Record each node’s binary/config/genesis hash.
3. Record common validator heights and block IDs at multiple timestamps.
4. Record relayer observer, RPC, indexer, and Atlas heights.
5. Record backup directories created during the version-2 quarantine.
6. Merge commit `98a7098...` to Testnet `main`.
7. Enable the intended boot target and perform a controlled restart test only
   after the healthy chain evidence is preserved.

## 10. Things not to do

- Do not regenerate any identity or custody bundle.
- Do not run the genesis ceremony again.
- Do not apply another genesis finalizer.
- Do not publish a new VPN generation merely to fix consensus.
- Do not start only one corrected validator against five version-2 stores.
- Do not delete validator data or backups.
- Do not delete `chain.json`.
- Do not activate ETDAG as part of this recovery.
- Do not use stale standalone installer configs containing chain 1264,
  public-IP P2P binds, or FN-DSA key paths.
- Do not use the retired `synergy-testnet-relayer.service`.
- Do not use `wg-quick@sy-vpn`; the validator transport is innernet-managed.
- Do not treat active systemd services as proof of chain health.
- Do not claim Atlas is fixed until its height advances with the public RPC.

## 11. Historical conversations and terminal captures

Original pasted Claude conversation exports:

```text
/Users/devpup/.codex/attachments/85972f75-90e6-48fb-9ab6-047183194d49/pasted-text-1.txt
/Users/devpup/.codex/attachments/85972f75-90e6-48fb-9ab6-047183194d49/pasted-text-2.txt
```

Earlier terminal output capture:

```text
/Users/devpup/.codex/attachments/e1b22913-f779-4c2b-bf50-f5845ac52910/pasted-text.txt
```

Validator-5 innernet diagnostics:

```text
/Users/devpup/.codex/attachments/0a1cda70-0974-4e8f-bea5-d84b69ef07ea/pasted-text.txt
/Users/devpup/.codex/attachments/8e77e6d7-24b4-41d8-819a-51d3e970f7d7/pasted-text.txt
```

Control Panel security-alert capture:

```text
/Users/devpup/.codex/attachments/bb82edc0-4436-4958-b3c4-b2ea7a3348f0/pasted-text.txt
```

Other useful launch reports:

```text
launch/TRACK_G_COMPLETE.md
launch/SESSION_13K_TRACK_G_STATE.md
launch/SESSION_13J_GOVERNANCE_AUTHORIZATION.md
launch/SESSION_13I_ACCOUNT_DOMAIN_VM_FINDINGS.md
launch/BATCH_LAUNCH_BLOCKER_PASS.md
launch/CONSTRUCTOR_RESOLUTION_FINDINGS.md
launch/CONSTRUCTOR_READINESS.md
launch/CONSTRUCTOR_DEPENDENCY_GRAPH.md
launch/SYNQ_MLDSA87_MANIFEST_MIGRATION_REPORT.md
launch/PHASE_8_CORRECTED_PLAN.md
launch/PHASE_8_DEPLOYMENT_FINDINGS.md
launch/BASELINE_VALIDATOR_COUNT_RESOLUTION.md
launch/CRYPTOGRAPHIC_IDENTITY_PROFILE.md
launch/CRYPTOGRAPHIC_PROFILE_RESOLUTION.md
launch/VALIDATOR_VPN_SECURITY_REPORT.md
launch/VALIDATOR_VPN_ARCHITECTURE.md
launch/VALIDATOR_VPN_ASSIGNMENT_REPORT.md
launch/DEFERRED_NONBLOCKING_FINDINGS.md
```

Some older reports contain now-superseded status statements. Treat current
source, applied genesis evidence, live node state, and this handoff’s
timestamped hashes as authoritative.

## 12. Definition of launch complete

Testnet-v3 is complete only when all of the following are simultaneously true:

- six corrected validator binaries run the expected hash;
- all six use canonical configs, genesis, identities, keys, and VPN transport;
- all six version-3 finality stores agree;
- the common finalized height advances across multiple samples;
- relayers ingest and serve the same finalized chain;
- public RPC reports an advancing nonzero height;
- explorer indexer follows the public chain;
- Atlas reports the advancing height and live blocks;
- no validator or support service is crash-looping or repeatedly logging
  consensus/recovery errors;
- final hashes, heights, backups, and workflow provenance are written to launch
  evidence;
- services have a tested boot-persistence path.

Until those conditions are proven, the chain is not live and healthy.
