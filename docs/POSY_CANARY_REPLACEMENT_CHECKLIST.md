# PoSy Canary readiness checklist

Complete these checks on Canary chain 99999 to qualify the architecture for a fresh PoSy Testnet on chain 1266. Check off each item when its full acceptance criteria are verified.

- [ ] Commission the public gateway on `synergy-devrpc` through NodeNetwork with a reusable, authenticated network profile and a gateway-only VPN policy. Verify HTTPS, Genesis, epoch and finality proofs, balances and receipts after restart and reboot.
- [ ] Qualify one uniform, signed master on Val2, Val3, Val4 and Val6. Prove sustained matching finality across consecutive autonomous epochs, including restart, rejoin and safe recovery at an epoch boundary.
- [ ] Qualify self-service validator enrollment and rotation. Verify APQE custody, VPN enrollment, sync, the 50,000 SNRG bond, dynamic quorum and the approved cluster splits at 10 and 21 validators.
- [ ] Qualify ETDAG end to end. Prove encrypted submissions execute exactly once, with correct fees, nonces, balances and durable finalized receipts through the public gateway, including across restarts and epoch changes.
- [ ] Verify APQE and operational security. Check authenticated provider provenance, key custody and rotation, peer admission, malformed requests, replay rejection, and signed install, update and recovery through NodeNetwork.
- [ ] Pass a sustained multi-host load and recovery test. Measure finalized throughput, finality latency, backlog recovery, resource growth and behavior when a validator drops out. Verify monitoring and alerts against authenticated data.
- [ ] Validate the replacement formation. Prepare a fresh signed PoSy Genesis for chain 1266 with Val1 as the fifth validator, settle the initial allocation and entitlement rules, and verify that Portal and Wallet distinguish the fresh network by Genesis. Any protected Wallet features in launch scope need their ratified Core contract and end-to-end verification.

## Latest verification

On 2026-11-21 at 05:09 UTC, the public Canary `/network-profile` endpoint passed TLS verification and returned HTTP 502. Gateway commissioning and public proof, balance, and receipt verification remain open.
