# PoSy v3 simplified consensus architecture

Status: proposed, not active.

## State machine

```mermaid
stateDiagram-v2
    [*] --> AwaitProposal
    AwaitProposal --> VerifyProposal: PROPOSAL from authorized lease owner
    VerifyProposal --> SafetyHalt: conflicting valid QC evidence
    VerifyProposal --> AwaitProposal: invalid context, parent, lock, ETDAG, or proposer
    VerifyProposal --> VoteJournal: proposal extends lock or higher verified QC unlocks
    VoteJournal --> BroadcastVote: durable compare-and-set then ML-DSA-65 VOTE
    BroadcastVote --> AwaitQC
    AwaitQC --> Certified: QC has dynamic strict count and frozen-weight quorum
    Certified --> CommitAncestor: consecutive B0 <- B1 <- B2 exists
    Certified --> AwaitProposal: fewer than three certified blocks
    CommitAncestor --> AwaitProposal: atomically finalize B0
    AwaitProposal --> TimeoutJournal: local timer permits TIMEOUT_VOTE only
    AwaitQC --> TimeoutJournal: local timer permits TIMEOUT_VOTE only
    TimeoutJournal --> AwaitTC
    AwaitTC --> AwaitProposal: valid sequential TC increments lease takeover offset
    AwaitTC --> AwaitTC: stale, skipped, wrong-context, or nonquorate TC
    SafetyHalt --> SafetyHalt
```

## Lease and takeover

```mermaid
flowchart LR
    A0["A scheduled: 1000-1009"] --> A1["A certifies 1000-1002"]
    A1 --> TCA["QC-authority timeout votes form TC(A, round 0)"]
    TCA --> B1["B inherits 1003-1009"]
    B1 --> Boundary["Predetermined lease boundary at 1010"]
    Boundary --> B2["B scheduled: 1010-1019"]
    B2 --> Result["B may certify 17 consecutive blocks; every block still needs its own QC"]
```

If B also fails before the boundary, a sequential `TC(B, round 1, previous=TC(A))` authorizes C for the remaining lease. Local peer health and wall clock never appear in the authority calculation.

## Boundaries

```mermaid
flowchart TB
    Epoch["Finalized epoch transition"] --> Context["Frozen epoch validator context and leader-ring root"]
    Context --> Proposal["PoSy PROPOSAL / VOTE / QC / TC"]
    ETDAG["ETDAG VAC/DCC/BVC/BOC/BTC and reveal"] --> Protected["Protected execution commitment"]
    Protected --> Proposal
    Proposal --> Chain["Three-QC certified chain"]
    Chain --> Finality["Canonical finalized state"]
    External["SXCP, relays, explorer, archive, RPC"] -. asynchronous and non-voting .-> Finality
```
