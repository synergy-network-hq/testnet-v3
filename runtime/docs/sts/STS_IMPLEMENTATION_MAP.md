# STS Implementation Map

## Scope

STS is the native Synergy Token System for testnet. It is implemented as runtime state and transaction execution logic, not as a SynQ template, wallet-only ledger, or RPC-only side table.

The active integration target is the Chain 1266 Testnet-v3 single-authority
release branch.

## Current Runtime Slice

- `src/sts.rs` defines the native STS wire payload, class discriminants, deterministic object ID derivation, fungible token registry, NFT state, multi-asset state, credential state, balances, snapshots, events, and policy checks.
- `src/sts.rs` exposes registry, balance, NFT, multi-asset, credential, and event query helpers so RPC/SDK/explorer callers resolve STS assets without duplicating state rules.
- On Chain 1266, finalized STS state is part of `ExecutionState`, its deterministic state root, and the durable single-authority execution replay. The older `data/sts_state.json` path is retained only for legacy non-single-authority runtimes and cannot shadow Chain 1266 state.
- `src/lib.rs` exposes `pub mod sts`.
- `src/execution.rs` stores `StsState` inside `ExecutionState`, includes it in the deterministic state root, decodes STS payloads after Aegis authorization, charges native SNRG fees, and applies STS mutations atomically.
- Native SNRG is represented as the gas asset with `token_address = null`; the 41-zero string `00000000000000000000000000000000000000000` is reserved only as a compatibility placeholder for string-only surfaces.
- Non-native STS assets expose `token_address` equal to their deterministic Bech32m object ID, so every user-created fungible token has a non-empty `synb1`, `synb2`, or `synb3` token address.
- `src/sts.rs` enforces protocol-level unsafe-token protections: no native SNRG/Synergy impersonation, bounded uppercase symbols, immutable metadata in this slice, no unenforced allowlist/denylist/transfer-approval flags, bounded mint supply when mint authority exists, duplicate-symbol rejection, and a 1000 bps transfer-fee cap.
- `src/sts.rs` supports token image metadata at creation and `set_fungible_image`, which only the creator can execute and which locks the image after the first set.
- `src/bin/synergy-sts.rs` provides a dedicated `synergy-sts` CLI for building native STS payloads for fungible create/mint/transfer/burn/control/image, NFT create/mint/transfer/burn/control/metadata/verify, multi-asset collection/item/batch, credential schema/issue/status, and native-info workflows.
- The CLI emits `payload_hex` and payload JSON for signed transaction wrapping; it does not mutate chain state directly or call legacy token-manager RPC write methods.
- Single-authority execution applies finalized `synergy-sts-v1:` payloads from verified Aegis envelopes, charges native SNRG network fees once, and commits the resulting STS state and receipts with the block.
- `src/rpc/rpc_server.rs` exposes read-only STS RPC methods under both `sts_*` and `synergy_sts*` names. Chain 1266 reads use only the finalized consensus execution snapshot and fail closed while that snapshot is unavailable; legacy runtimes retain the standalone-snapshot/full-chain-replay fallback.
- `docs/sts/STS_RPC_API.md` documents the read methods and response fields for native SNRG, fungible tokens, NFTs, multi-assets, credentials, and events.
- `.github/workflows/release-synergy-sts-cli.yml` publishes standalone macOS and Linux CLI binaries to `synergy-network-hq/synergy-sts-cli-releases`.
- `scripts/install-synergy-sts.sh` installs the released CLI on macOS and Linux, verifies release checksums by default, supports pinned versions, and can also install from a local source checkout or an existing binary.
- The Chain 1266 CLI signs typed Aegis transaction envelopes with ML-DSA-87, verifies the envelope locally, and submits it through `synergy_submitAegisTransaction`.
- Atlas indexing support is implemented in `synergy-atlas`: the indexer decodes `synergy-sts-v1:` payloads, derives non-native `synb*` token addresses, materializes STS token definitions/events/balances/images, and the `/tokens` API merges STS assets into the token registry.
- Atlas exposes a wallet-authenticated `POST /tokens/:tokenAddress/image` fallback for the creator wallet to set an omitted image exactly once from the token detail view.
- Atlas materializes finalized STS payloads into its token registry. Live deployment and first-token visibility must be verified separately from runtime activation.

## Implemented Classes

- `synb1` / class `1`: basic fungible tokens.
- `synb2` / class `2`: managed fungible tokens with freeze, pause, and clawback flags.
- `synb3` / class `3`: policy fungible tokens with transfer fee, snapshot, vesting metadata validation, and max-wallet policies.
- `synn1` / class `11`: standard NFT collections and instances with native ownership, transfer, burn, metadata, and collection verification.
- `synn2` / class `12`: controlled NFT collections and instances with issuer approval, expiry, freeze/thaw, revoke, and use state.
- `synj` / class `21`: native multi-asset collections, items, balances, transfer policies, and atomic batch mint/transfer/burn.
- `synk` / class `31`: non-transferable credential schemas and records with active, suspended, revoked, and expired status handling.

## Chain Identity

- STS uses exactly Chain 1266 and network ID `synergy-testnet-v3`; legacy chain
  1264 and the generic network name `testnet` are rejected rather than
  reinterpreted.
- The wider runtime exposes `SYNERGY_TESTNET_V3_CHAIN_ID = 1266` and `SYNERGY_TESTNET_V3_NETWORK_ID = "synergy-testnet-v3"` in `src/synergy_types.rs`.
- `synergy-sts` fails closed for non-testnet payload construction and emits `chain_id = 1266` in every payload artifact.

## Legacy Paths

- `src/token.rs` remains the legacy in-memory token manager and is not the canonical STS ledger.
- Legacy token registry responses now normalize identity metadata: `SNRG` has no token address, while non-native legacy tokens receive a deterministic `synb1` compatibility address until callers migrate to signed STS transactions.
- Existing token RPC write methods that mutate `TOKEN_MANAGER` directly are not canonical STS write paths.
- STS read RPC methods are canonical for the current fungible STS slice; legacy `synergy_getTokens` and `synergy_getTokenBalance` still read the old token manager.
- `src/address.rs` currently treats several `syn*` prefixes as protocol-controlled addresses; STS token IDs need a separate object-ID validation path before wallet/RPC/Atlas presentation is finalized.

## Follow-Up Integration

- Add SDK builders for `StsSignedPayload` and payload encoding.
- Add SynQ/AIVM host functions only after native STS execution is stable.
- Expand Atlas/indexer UI beyond fungible STS tokens to first-class NFT, multi-asset, and credential views.

## Verification Notes

- Baseline `cargo test -p synergy-testnet` failed before STS implementation with one consensus test failure and five SynQ fixture failures caused by missing `Counter.compiled.synq`.
- `cargo check -p synergy-testnet --bin synergy-sts` passes after this slice.
- `cargo test -p synergy-testnet sts::tests:: --lib` passes with 18 focused STS tests.
- `cargo test --locked -p synergy-testnet --lib rpc::rpc_server::tests::sts_` passes with 4 focused STS RPC tests.
- `cargo test --locked -p synergy-testnet --bin synergy-sts` passes with 6 focused CLI tests.
