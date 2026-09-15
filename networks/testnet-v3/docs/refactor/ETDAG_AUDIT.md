# ETDAG audit

`runtime/src/etdag.rs` implements target admission contexts, encrypted
submission envelopes, certification, protected input coordination, safety
journaling, and finalization pruning. It binds admission to source finality and
target H+3 context, so ETDAG remains an input subsystem rather than a finality
substitute.

The authority-semantics gate recorded in `CONSENSUS_AUDIT.md` establishes that
`frozen_bonded_weight_root` and `assigned_cluster_total_voting_weight` currently
commit approved frozen validator weights used with an independent strict
validator-count quorum. They are not automatically stake-derived merely because
of their historical names. `TargetAdmissionContext::derive` computes both from
the finalized active set in `runtime/src/etdag.rs:348-356`; validation
recomputes them in `:497-532`, and certification checks the context total in
`:1942` and `:4040`.

Accordingly, this refactor must preserve those commitments until a versioned,
end-to-end semantic migration proves an actual economic-stake dependency. A
wire-compatible rename alone would be unsafe and misleading. ETDAG extraction
will instead isolate admission, DAG, certificates, ordering, reveal, and
persistence while retaining finality-context verification.

Protected flow retained: client target context -> ingress KEM -> encrypted
envelope -> admission -> DAG/certification -> deterministic order -> authorized
reveal -> verified decrypt shares -> execution input -> PoSy finality -> durable
state.
