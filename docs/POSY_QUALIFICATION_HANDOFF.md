# PoSy qualification handoff

## Ownership and source

PoSy owns distributed consensus and general ETDAG qualification, the user-operated node lifecycle, internal infrastructure qualification, Atlas observations and replacement formation. The Wallet workstream owns protected accounts, PW13, APQE integration, Wallet applications and the current Canary deployment window.

PoSy qualification baseline is Core `2c9139799a376e6de234af319239768f1125388d`. Work is isolated on `codex/posy-qualification-20261123` in `/Volumes/SynergyBuilds/Source/posy-qualification-20261123`. This branch owns the general validator qualification tooling under `node-platform/tools/validator`. The local Python checks use no build output. Reserve a separate external Cargo target if a PoSy build becomes necessary. Use the [existing readiness checklist](POSY_CANARY_REPLACEMENT_CHECKLIST.md) for acceptance status.

## Legacy single-authority retirement

| Evidence | Verified value |
| --- | --- |
| Chain and incarnation | 1266, incarnation 5 |
| Genesis | `2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74` |
| Authority host and unit | Val1, `synergy-chain1266-authority.service` |
| Inactive entered after authorized stop | 2026-11-22 23:15:00 UTC, read from systemd before reboot |
| Post-reboot boot ID | `0cb1e139-24fc-47c3-aeee-65b64ddaf555` |
| Post-reboot and current service state | Disabled, inactive, MainPID 0 |
| Finalized height and block | 6,004,855, `e7af71b5eb4a59214fae69f32897ac7aa80b7a1461b275189373354ad49b9179` |
| Finality head SHA-256 | `8b9076fd0427ab03e9702c774550d0a099c3b006e99928fbc21531fb7600d8de` |
| Retained journal | `data/consensus/chain-1266-incarnation-5/single-authority-finality.log` under `/var/lib/synergy/node`, 33,101,394,974 bytes, matching the finality-head offset |
| Legacy public JSON-RPC | HTTP 502 on a chain-ID request after shutdown and during the 2026-11-23 recheck |

The finality-head digest and retained journal size match the shutdown checkpoint. The legacy root, executable and disabled service registration remain present. This records the preserved finality checkpoint and does not certify every historical file. Val1 is reachable and runs Ubuntu 26.04 LTS on x86-64, with 8 logical CPUs, roughly 24 GiB of RAM, and 202 GiB free on the root filesystem at inspection. Package compatibility, new custody and VPN admission require verification before commissioning.

## Canary qualification

On 2026-11-23, public chain status returned HTTP 200 and reported active and ready for 99999, `synergy-posy-canary-20261117`, Genesis `ed0d27c89c691dd4d611d107dcd791a8348af94cf22a31e223bfd4e74b51f641`. The public signed-profile route returned HTTP 503. Identity reported in the status response is observation only pending successful retrieval and verification of the signed origin. No Canary services or workload were changed.

The asynchronous workload harness reports throughput from matching observer RPC records. The independently verified TPS field remains null until original three-QC evidence is verified. The current counter remains useful for comparing observed load steps. The 0.5–1.5 second target remains an observation, with no pass/fail threshold inferred from it.

`node-platform/tools/validator/verify-finalized-observations.py` requests original finality and block pages for one explicit height. Run it with one `--observer HTTPS_RPC_URL` per independently selected observer, `--node` pointing to the qualified native verifier, `--config` to the independently authenticated trust configuration, and `--chain`, `--network`, `--genesis` and `--height` set to the expected subject. It verifies each proof with the existing native three-QC verifier and requires matching block, state and protected execution commitments. Distinct URLs do not establish independent backends by themselves. Transport tests cover discontinuous pages, changing digests and mismatched network or height. Live distributed qualification still requires the approved trust configuration and independently attributed observer routes.

NodeNetwork at Hub baseline `b14ef0d` retained previous VPN observations during retirement. A fresh host inspection could then satisfy the commission gate using those cached observations. Candidate `9cc8b34a5568ce97c039ba885ba88cf82e8a2e62` clears VPN status and diagnostics when retirement, revocation or unused-key cancellation starts, so an uncertain result cannot leave that evidence available for commissioning. The focused suite passed 17 tests including the new invalidation regression. The candidate is in `/Volumes/SynergyBuilds/Source/posy-nodenetwork-20261123` on `codex/posy-nodenetwork-20261123`. Native Portal acceptance and integration into the active dApp branch remain open.

After the live window is released, qualify the same signed release across the assigned hosts, compare finalized block and state commitments with verified three-QC evidence, then qualify epoch-boundary rejoin, Sentry failover and multi-host workload. Replacement formation requires explicitly governed Genesis inputs and the retained Val1 installation must stay inactive during preparation.

## Replacement formation input review

The existing historical stability recipe hardcodes Val2–Val6, copies an old endpoint scheme, assumes 32 funded wallets and uses a million-block first epoch. Use the native Portal and NodeNetwork formation workflow for replacement commissioning.

Run `python3 node-platform/tools/validator/review-replacement-formation.py PUBLIC_INPUT_DIRECTORY EXPECTATIONS.json` before dispatching native formation. The public directory must contain `formation.json`, `recipe.json` and the five APQE registration exports named `val1.json`, `val2.json`, `val3.json`, `val4.json`, and `val6.json`. The independently reviewed expectations supply `chain_id`, `network_id`, `formation_sha256`, `recipe_sha256` and a `registrations` object mapping each host to its export SHA-256. The recipe pin covers allocation and policy bytes. Host attribution must come from the authenticated export workflow. This review checks the pinned inputs, first epoch H1–H1,000, asynchronous ETDAG profile and exact registered-address roster. Native formation must still verify the APQE proofs, validate the recipe, and produce signed Genesis and authority artifacts. No allocations, registrations or credentials were generated.

## Atlas telemetry

Atlas candidate `5bc8b04173670f901551fffb333676dcb7ec5b7a` is published on `codex/posy-atlas-20261123` in `/Volumes/SynergyBuilds/Source/posy-atlas-20261123`. The staff view starts a new chart history when the chain ID, network ID or Genesis changes and rejects observations with an incomplete identity or an older timestamp. The frontend and backend passed 152 Vitest checks, the link previews passed three Node tests, and the production build succeeded. Live anonymous checks returned 200 for the staff page shell and 401 for its telemetry endpoint. Staff-authenticated readings and deployment of the candidate remain unverified.
