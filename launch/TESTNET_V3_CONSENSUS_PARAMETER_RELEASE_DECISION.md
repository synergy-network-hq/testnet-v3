# Testnet-v3 consensus parameter release decision

Date: 2026-07-28  
Decision class: Testnet release engineering decision  
Scope: Synergy Testnet-v3 only  
Status: APPROVED FOR CANONICAL MANIFEST EMISSION
Decision ID: `TV3-POSY-PARAMS-2026-07-28-01`

## Authority and boundary

The active Testnet-v3 launch instruction requires unresolved engineering
parameters to be inventoried, benchmarked or simulated where useful, and
selected as the safest internally consistent Testnet release values. It also
states that this is not a Mainnet governance ratification and prohibits
fabricating a governance vote or approval signature.

On 2026-07-28, the Testnet-v3 operator explicitly approved the canonical
launch values in this record and assigned Decision ID
`TV3-POSY-PARAMS-2026-07-28-01`. This record therefore authorizes
deterministic Testnet-v3 manifest emission. It is not a cryptographic
governance vote, third-party review, Mainnet policy, or permission to weaken
any launch gate.

The machine manifest carries the exact Decision ID. Finalized Genesis
separately binds the SHA-256 digest of this exact decision record, the
canonical manifest SHA-256 digest, and the manifest SHA3-512 parameter root.

## Source precedence

1. Security Specification v7 for security-domain requirements.
2. PoSy v2.2 and the corrected workbook controls for consensus semantics.
3. Explicit Testnet-v3 operator rulings already recorded in `launch/`.
4. Current typed PoSy/ETDAG implementation and focused conformance tests.
5. Candidate Genesis and inherited configuration only when they do not
   conflict with the sources above.

## Selected values

| Parameter | Value | Rationale |
|---|---:|---|
| Chain ID | `1266` | Existing canonical Testnet-v3 identity |
| Network ID | `synergy-testnet-v3` | Existing canonical Testnet-v3 identity |
| Protocol | `posy/2.2` | Typed coordinator protocol |
| Epoch length | `1000` slots | Currently exercised production-path profile; 3600 is deferred pending epoch-transition and production-path soak testing; supersedes the competing test-only 7200 |
| Healthy block target | `2000` ms | Genesis, configs, and workbook agree |
| Count quorum | strict `3*s > 2*n` | Safety requirement; 5 of 6 |
| Weight quorum | strict `3*w_s > 2*w_total` | Independent safety requirement |
| Cluster schedule | `dynamic-v3-floor7` | Corrected dynamic topology |
| Consensus signature | `mldsa65` | Security v7 and recorded crypto-domain ruling; workbook ML-DSA-87 entry is superseded |
| ETDAG ingress KEM | `mlkem1024` | ETDAG v2.2 requirement |
| ETDAG payload AEAD | `aes256gcm` | ETDAG v2.2 requirement |
| ETDAG target offset | `3` | H+3 admission profile |
| Initial validators / quorum / reveal threshold | `6 / 5 / 2` | Tested launch topology |
| Shadow epochs | `1` | Existing typed protocol release default |
| Activation delay | `1` epoch | Existing typed protocol release default |
| Minimum shadow blocks | `100` | Existing typed protocol release default |
| Maximum finalized lag | `2` blocks | Existing typed protocol release default |
| Required vote match rate | `995000` ppm | Existing typed protocol release default |
| Required validator stake | `50000000000000` nwei | Genesis and recorded Testnet ruling |
| Over-staking | allowed | Existing Testnet policy |
| Anti-divergence / reconciliation / self-quarantine / invalid-peer quarantine | enabled | Fail-closed release posture |
| Reconciliation peer quorum | required | Fail-closed release posture |
| Minimum canonical sync peers | `4` | Five-of-six quorum leaves one unavailable validator |
| Maximum automatic rejoin lag | `0` | Exact finalized boundary required |
| Rejoin boundary | round boundary only | Prevents mid-round authority changes |
| Quorum reduction | forbidden | Safety requirement |
| Proposal timeout | `1500` ms | Conservative current typed default; workbook 450 ms remains a healthy-path performance target, not a differently scoped hard timeout |
| Prevote timeout | `1500` ms | Conservative current typed default pending production soak |
| Precommit timeout | `1500` ms | Conservative current typed default pending production soak |
| Maximum round timeout | `10000` ms | Currently exercised typed runtime cap; 30000 ms is deferred pending partition, recovery, and prolonged-fault testing |

## Healthy-network performance targets

These are observability and release-gate targets. They are not consensus
timeouts and must never be used to expire or invalidate safety state.

| Target | Value |
|---|---:|
| Healthy proposal | `450` ms |
| Healthy QC | `1850` ms |
| Healthy commit | `2250` ms |
| Finality p95 | `2500` ms |
| Finality p99 | `3000` ms |

## Deferred values

- `epoch_length_slots = 3600` is deferred until epoch-transition and
  production-path soak testing demonstrates that the two-hour epoch profile is
  preferable to the currently exercised 1,000-slot profile.
- `max_round_timeout_ms = 30000` is deferred until partition, recovery, and
  prolonged-fault testing justifies increasing the current 10-second cap.
- A deferred value may be activated only through a new finalized manifest at
  Genesis or a declared epoch boundary.

## Required implementation consequences

- The canonical JSON manifest is the only production parameter source.
- The manifest uses exact canonical serialization and rejects unknown fields.
- Its SHA3-512 root is embedded in finalized Genesis and every height context.
- Validator startup must load the Genesis-bound manifest before installing any
  consensus ingress or signing authority.
- Environment variables, TOML, CLI defaults, tests, or inherited constants may
  not override the bound manifest.
- Competing epoch and timeout values remain launch blockers until removed from
  every active production path or proven unreachable.
- Healthy-network performance targets remain separately named release targets;
  they are not proposal, prevote, precommit, or maximum-round timeouts.
- Parameter activation is permitted only from Genesis or a declared epoch
  boundary.
- The 10,000-block performance gate may require a later governed manifest
  revision; it may not silently mutate this one.
