# Source-integrity recovery — 2026-08-29

## Canonical source roots

- Testnet-v3: `/Volumes/xcode/Synergy-Network/01-Core-Protocol/testnet-v3`
- Node Control Panel: `/Volumes/xcode/Synergy-Network/07-Node-Control-Panel`
- Aegis: `/Volumes/xcode/Synergy-Network/02-Aegis-Cryptography/aegis-pqc`
- SynQ: `/Volumes/xcode/Synergy-Network/04-SynQ/synq-language`
- Aegis Post-Quantum Cryptography Engine: `/Volumes/xcode/Synergy-Network/21-Address-Engine/synergy-address-engine`

No alternate Testnet-v3 or Node Control Panel source checkout remains in the
Synergy workspace. Temporary copies were removed only after their dirty state
was pinned under `refs/recovery/source-integrity-20260829/`.

## Testnet-v3 worktree disposition

| Worktree group | Dirty state | Disposition |
| --- | --- | --- |
| PoSy reconciliation, RC33, ProtectedPipeline, and simplified-consensus | Preserved in named recovery refs | Current SGEN/ProtectedPipeline implementation integrated semantically; obsolete alternate source bodies removed. |
| R11 protocol, pipeline, PoSy, genesis, ETDAG, P2P, runtime, and NCP agents | Preserved in named recovery refs | Current behavior integrated or superseded by the canonical R11/SGEN implementation; physical worktrees removed. |
| `Synergy-Chain-Work/testnet-v3-r11` | Ceremony evidence archived under `.git/recovery/` | Its committed SGEN source was already an ancestor of canonical Testnet-v3; duplicate checkout removed. |

## Verification at recovery completion

- One registered Testnet-v3 worktree.
- Zero tracked Testnet-v2 filenames or active Testnet-v2 source directories.
- Zero embedded Node Control Panel files in Testnet-v3.
- Clean canonical Testnet-v3, NCP, Aegis, and Address Engine worktrees.
- `cargo check -p synergy-testnet --bin synergy-validator-node` passed.
- SGEN unit tests: 5 passed.
- ProtectedPipeline tests: 23 passed.
- Canonical NCP production build passed.

## Future rule

All future work must be promoted to the canonical source root before a task is
considered complete. Do not create nested clones or leave long-lived worktrees.
