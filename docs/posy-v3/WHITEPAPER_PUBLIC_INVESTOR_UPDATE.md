# Public and investor whitepaper update proposal

Publication target: the current public/investor whitepaper consensus section. This text is intentionally explanatory and does not claim live deployment.

## Predictable leadership with automatic quorum-certified recovery

The proposed fresh Testnet-v3 PoSy consensus profile uses deterministic scheduled leadership. At Genesis and at the start of each later epoch, the active validators compute the same fixed leadership order from finalized network data. Leaders receive ten-block turns, which reduces coordination churn while keeping every block independently subject to validator approval.

If a leader becomes unavailable, no individual machine elects a replacement. The remaining validators sign timeout votes, and only a valid quorum-certified timeout passes the rest of that leader's current turn to the next scheduled validator. The normal schedule resumes at the next turn boundary. This creates automatic recovery without relying on a central operator, a hidden availability list, or manual leader forcing.

Finality is based on chained certificates. Validators cast one ordinary vote per consensus round, and a block that receives the required Quorum Certificate becomes part of the certified chain. A conservative three-certificate chain commits the oldest block in that chain. Certificates remain protected by post-quantum ML-DSA-65 signatures, durable anti-double-signing records, strict validator-count and frozen-weight thresholds, and fail-closed behavior when quorum is unavailable.

The proposed first Testnet-v3 epoch uses the five active validators for which hardware is currently available and requires four distinct signatures plus strictly more than two-thirds of frozen voting weight. Five is not a permanent network limit. Additional approved validators can join at a later certified epoch boundary, when every node adopts the same new frozen membership, weight set, quorum threshold, and leader ring. Infrastructure services such as seed nodes, relays, RPC gateways, explorers, and archives do not gain voting power merely by operating network services.

This architecture remains prelaunch until the fresh Genesis, governed ETDAG artifacts, governance release signature, and qualification evidence are complete. Implementation and local testing alone do not mean the five-validator network is live.
