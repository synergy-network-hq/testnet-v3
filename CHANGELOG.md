# Changelog

## 3.0.0-prelaunch.2 - 2026-07-25

- Replaced the invalid Solidity genesis-contract package with eight native SynQ
  contracts and compiler-produced SynQ bytecode, ABI, and manifest artifacts.
- Bound every contract manifest to chain `1264`, network
  `synergy-testnet-v3`, and `ML-DSA-65`.
- Added placeholder-only deployment inputs for new Testnet-v3 identities and
  system addresses.
- Added deterministic source-to-bytecode and artifact-integrity validation.
- Marked general stateful AIVM execution and genesis-contract deployment as
  hard operational blockers rather than claiming capability from file presence.

## 3.0.0-prelaunch.1 - 2026-07-24

- Created the dedicated Testnet-v3 workspace from the current Testnet runtime hotfix source.
- Preserved chain ID and numeric network ID `1264`.
- Changed the runtime isolation ID to `synergy-testnet-v3`.
- Renamed Testnet-v2 runtime constants, commands, tests, and package labels for Testnet-v3.
- Added Testnet-v3 topology metadata and generated-config runtime network IDs.
- Removed active Testnet-v2 genesis and bootstrap bundles from top-level
  deployable paths; inherited runtime identity bindings remain blocked
  migration inputs and are not approved for Testnet-v3.
- Retained retired Testnet-v2 launch material only as explicitly blocked reference input.
- Added fail-closed structural and full launch-readiness validation.
- Excluded nested Git histories, build caches, generated binaries, release archives, `.env` files, and live chain data.
