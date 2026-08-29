# PoSy v3 control-panel status contract

The control panel must label this profile `PROPOSED / NOT ACTIVATED` until the runtime reports a finalized schema-4 manifest and matching epoch transition. It must not infer activation from compiled code or a local config flag.

When integration is authorized, display read-only:

- protocol version, activation epoch/height, epoch-context and parameter roots;
- current frozen-epoch validator count plus active-set/key/weight/leader-ring
  roots and local equality status; the initial activation profile expects five,
  but later finalized epochs may contain a different dynamically frozen count;
- scheduled owner, lease range, takeover offset, verified current TC ID, and authorized proposer;
- highest QC, locked QC, finalized head, and three-chain depth;
- signer-journal readiness and SafetyHalt state without secrets or raw private material;
- `posy_v3_proposal_latency_us`, `posy_v3_vote_propagation_us`, `posy_v3_qc_formation_latency_us`, `posy_v3_chained_finality_latency_us`, `posy_v3_tc_recovery_latency_us`, `posy_v3_leader_takeover_latency_us`, `posy_v3_pqc_verification_us`, `posy_v3_certificate_size_bytes`, and `posy_v3_restart_rejoin_time_us`.

The panel provides no force-leader, clear-lock, delete-journal, edit-height, quorum override, or local activation control. A missing/mismatched root, invalid TC chain, state-record error, or SafetyHalt is a blocking red state, not a repair button.
