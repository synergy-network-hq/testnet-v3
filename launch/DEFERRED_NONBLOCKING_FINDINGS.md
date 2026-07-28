# Deferred non-blocking findings

Recorded per the scope freeze. None blocks Testnet-v3 launch.

1. **Governance-key rotation exists only on ValidatorRegistry.** The other seven
   governed contracts have no rotation path. Mitigated by the ruling that
   `SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY` is permanent for Testnet-v3.
   Post-launch hardening item.

2. **`build_call_admission_envelope_from_pqsynq_bytes_with_args` verifies before
   attaching arguments.** Its first verification pass hashes an empty argument
   list, so the helper cannot admit a call that has arguments. Worked around in
   `genesis_deployment.rs` by constructing the envelope directly and verifying
   once. The helper itself is still wrong for any caller with arguments.

3. **SynQ admission requires a non-zero envelope nonce.** Deployment ordinals
   stay 0..=8; the envelope nonce is ordinal + 1. Documented in code.

4. **`SynergyOracle` quorum threshold is 1**, so a single publisher both proposes
   and finalizes a checkpoint in one call.

5. **VNS-A01 role separation** is configuration only and is handled by the
   production ceremony identities, not by contract changes.
