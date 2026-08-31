# Requested quantities not measured

`NOT_MEASURED` is an evidence classification, not a zero.

| Quantity | Why it was not measured | What would be required |
|---|---|---|
| Live block intervals, TPS, finality, block/transaction distributions | The authorized RPC-gateway service was inactive and no Synergy process or listener was present | Observe an active, commit-identified testnet during a defined UTC window |
| Live Aegis CPU, memory, cache, queue, and network counters | No active process exported them during the passive snapshot | Authorized telemetry from active nodes |
| Submit-to-inclusion latency | No active, safely authorized submission endpoint was available | Low-impact signed test transactions on an active testnet with inclusion evidence |
| Isolated node TPS and finality | No disposable topology equivalent to the six-validator configuration was available | Instantiate the same binary, Genesis, validator identities, and network limits in disposable infrastructure |
| Multi-node CPU, memory, storage, and bandwidth under load | The local crypto-pool harness is not a node network | Disposable multi-node deployment plus synchronized host/network telemetry |
| Fault, timeout, retry, catch-up, and partition behavior | Unsafe on the shared testnet and unavailable locally | Disposable topology and an explicit fault matrix |
| Current vote, QC, VC, and TC costs | `coordinated_round_robin_v1` has no such objects | Benchmark a separately identified release where typed PoSy is enabled; never merge with current-mode results |
| Modified-vote negative path | The current coordinated release has no validator vote object | Test only in a separately identified vote-enabled mode |
| Full validator registration/readiness startup latency | Requires Genesis identity loading, service startup, P2P connectivity, and finalized-set checks | Disposable node process with authorized generated identities |
| Node startup cost attributable to Aegis | Fresh-process signer/verifier initialization was measured, but a faithful node process was not started | Instrument a disposable current node startup and separate Aegis spans from other initialization |
| x86-64/AVX2 performance | Only the Apple M2 host was available | Replicate on validator-class x86-64 hardware with exact feature selection recorded |
| Optional AArch64/NEON implementation | The production dependency did not enable Aegis `neon` | Separate optimized build and result set; do not relabel as baseline |
| Classical production baseline | No equivalent current classical transaction/consensus authentication path was established | Add a clearly synthetic, separately labeled baseline or identify a real legacy production path |
| Energy and joules/operation | No calibrated authorized counter | Calibrated external meter or documented platform energy counter |
| CPU frequency, thermals, PMU counters | No stable non-privileged interface was used | Authorized hardware-counter collection and temperature/frequency telemetry |
| Network bandwidth versus committed throughput | Neither committed throughput nor live network byte counters were measured | Synchronized transaction, finality, and interface telemetry |

No plot or table converts these missing values to zero, and no local verification rate is labeled network TPS.
