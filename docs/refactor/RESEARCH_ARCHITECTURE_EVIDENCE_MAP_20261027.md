# Research architecture decision and evidence map

The user supplied `/Volumes/PortableSSD/deep-research-report.md` (65,116 bytes,
755 lines, SHA256 `7c373f96497f0f08d7b4faf588e19288dd6a72814c06ec653634c4d01aa7678f`).
It was read completely, including its final SQLite reference. It is engineering
evidence, not authority to adopt its example schemas, change PoSy, or delete
unique records. The active operator objective controls execution.

Evidence root: `node-platform/target/controlled-network-recovery-20261027T110225Z`.
The report does not contain the requested Narwhal/Bullshark, Mysticeti, Aptos or
Agave comparisons. The explicitly marked supplements below close that source
gap; they are not findings attributed to the supplied report.

## Decision

Implement a hybrid: existing synchronous signing-safety state and bounded hot
consensus metadata, with immutable size-rolled binary segments for unique
historical facts and a rebuildable SQLite locator index. Retain exact legacy
bytes and original files. Do not import another consensus algorithm, safety
state fields, certificate, round, owner, or cryptographic aggregation scheme.

| Alternative | Defensible benefit | Limitation / decision |
|---|---|---|
| Deduplicated SQLite only | Smallest incremental change; transactional CAS and indexed reads | Historical payloads remain in mutable B-tree pages. Existing 8,192-height synthetic test proves fewer files, not enough physical-byte/IO improvement. Keep as measured comparison baseline. |
| Append segments only | Sequential immutable history; simple checksummed framing | Mutable sign reservations and stale-owner CAS still need a crash-atomic owner. Reimplementing that owner increases risk. |
| Hybrid | Retains existing safety/CAS; separates cold proof bytes and bounded operational metadata; raw signature encoding removes measured decimal-array expansion | Selected for implementation and measurement. Additive schema and crash ordering require migration/recovery tests; not yet qualified for deployment. |

## Recommendation to implementation

| Recommendation / primary source | Exact Synergy boundary | Safety / compatibility condition | Measurement and status |
|---|---|---|---|
| Proof-bound retirement: [PBFT algorithm](https://www.usenix.org/legacy/publications/library/proceedings/osdi99/full_papers/castro/castro_html/node4.html) uses stable checkpoints for log retirement | `crates/synergy-posy/src/persistence/safety_journal.rs`, `delivery.rs`; narrow existing finalized-floor maintenance in `bin/synergy-node/src/services/posy.rs` | Derive local retirement from existing verified three-QC finality. No PBFT checkpoint messages. New READY retirement must also exclude startup's recent-eight horizon and preserve all actual readers. | Bound operational rows independently of total height; below-floor signing and restart tests. Reader audit supports implementation; retirement regression still required. |
| Compact independent durable safety: [Aptos SafetyData](https://raw.githubusercontent.com/aptos-labs/aptos-core/main/consensus/consensus-types/src/safety_data.rs) and [persistent safety storage](https://raw.githubusercontent.com/aptos-labs/aptos-core/main/consensus/safety-rules/src/persistent_safety_storage.rs) **supplement** | `persistence/safety_journal.rs`, `persistence/signing_authority.rs` | Keep PoSy's actual phase/round reservations, finalized floor and reserve-before-sign order; do not copy Aptos's fields or reinitialization behavior. | Crash/equivocation/floor tests and actual stopped-state replay. Existing all-five replay passes; new archive integration rerun pending. |
| Separate ordinary proof from misconduct: [CometBFT evidence specification](https://raw.githubusercontent.com/cometbft/cometbft/main/spec/consensus/evidence.md) | `delivery.rs`, `persistence/certificate_store.rs`, `persistence/timeout_store.rs`, `persistence/evidence_store.rs` | No imported evidence expiry. Preserve exact conflicting facts and unique VC/ECHO custody/validity signatures; block QC does not imply them. | Exact reconstructed bytes and conflict/CAS negatives; signatures physically deduplicated only. PoSy-specific distinction verified in current recovery consumers. |
| Indexed immutable cold history: [Geth databases](https://geth.ethereum.org/docs/fundamentals/databases) | New `persistence/archive_segments.rs` and existing `persistence/evidence_store.rs` | Durable complete frame before index commit/ack. Normal startup bounded to active tail; full reindex explicit offline. Legacy data stays intact; no automatic old-binary rollback after new-format writes. | Logical/allocated bytes, fsyncs, writes, reads, inode slope, early/late lookup and recovery at 10k/100k+. Selected, implementation in progress; improvement unmeasured. |
| Preserve strong SQLite durability: [SQLite PRAGMA reference](https://www.sqlite.org/pragma.html) | Existing DELETE + EXTRA, fullfsync, mmap disabled and bounded cache in `persistence/evidence_store.rs` | Report's WAL suggestion is optional. DELETE+EXTRA already adds rollback-journal directory durability; do not replace it with weaker synchronization. | Crash before/after segment sync and index commit; hot-journal recovery. Retain current mode unless measured evidence justifies a change. |
| Separate dissemination from ordering: [Narwhal/Tusk](https://arxiv.org/abs/2105.11827); [Bullshark](https://arxiv.org/abs/2201.05677) **supplement** | Existing ETDAG admission/material lifecycle, PoSy proposal/QC/finality, Execution proof pins | These papers describe distinct DAG ordering designs. Apply only the ownership/lifecycle comparison; PoSy remains the only consensus owner and existing custody proof remains required. | Track admission, ETDAG queues, ordered/executed/finalized/effects separately. No imported TPS result or claim of Synergy equivalence. |
| Reduce redundant certificate work only when protocol proves it: [Mysticeti](https://arxiv.org/abs/2310.14821) **supplement** | `delivery.rs`, `cut_recovery` consumers, `persistence/evidence_store.rs` | Mysticeti's uncertified-DAG commit rule is a different protocol. It does not justify deleting Synergy ECHO/VC evidence or changing three-QC finality. | Deduplicate representation without changing authenticated messages; no Mysticeti protocol transplant. |
| Separate persistent payload from indexes: [Agave AccountsDb source](https://raw.githubusercontent.com/anza-xyz/agave/master/accounts-db/src/accounts_db.rs) **supplement** | `crates/synergy-state` and candidate/processing retention; new consensus archive | Agave's account/slot/mmap design is not PoSy evidence semantics. Use as comparison, not a new state backend or mmap/cgroup assumption. | Existing touched-state retention plus 100k-height fixture, bursts/drains and early/late memory windows. Synthetic state fixture remains distinct from encrypted ingress. |
| Attribute cgroup memory correctly: [kernel cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html) and [proc accounting](https://www.kernel.org/doc/html/latest/filesystems/proc.html) | `tools/validator/soak-resource-observer.py` | Preserve 1GiB/swap0. Page cache is not anonymous heap; smaps availability and measurement timestamps explicit. Do not clear live caches. | 5s memory/native, 30s bounded smaps, 60s FD cache, local/hierarchical OOM, PSI, dirty/writeback; 21 observer tests pass, Linux payload budget still to verify. |
| Authorized transactions and reproducible deployment | Existing encrypted processing/identity registration, Linux lifecycle and conformance owners | Authenticated selected network, finalized binding, ordinary sponsor nonce/fees; no bypass. Verify all-five backups/migration before mutation. | Corrected five-socket fixture passes 84.48s total, all four phases <=30s, retained-source restart237ms <=5s. Actual live effects and new release deployment remain pending. |

## Measured starting point and proof gates

Original Val2 H10167 QC: four 3,309-byte signatures = 13,236 raw signature
bytes. Signature JSON arrays alone occupy47,140 of49,016 serialized bytes;
allocated size49,152. Finality row416 serialized/4,096 allocated. This exact
record establishes encoding overhead, not an all-history minimum or average.
VC/ECHO contains separate unique signatures and must be included in the budget.

Full public PoSy histories on all five remain unchanged after prior disposable
replay:71,606–73,258 records,2.25–2.29GB per host. That replay verifies the actual
startup tail and signing floor twice; it is not a complete historical signature
sweep or full execution boot. New-format copy migration must add exact100%
mapping, idempotence, interrupted-write recovery and historical proof checks.

Deployment remains gated on new architecture safety/scale results, actual-state
copy migration/recovery, recoverable verified backups of every stopped host,
one frozen package, all-five conformance, and the original readiness/finality
limits. An old binary must not be assumed safe after schema2 writes. Live
authorization/effects gates precede a fresh actual24h soak and measured executed
and finalized TPS. No projected storage gain, fixture result or paper TPS
satisfies those live requirements.
