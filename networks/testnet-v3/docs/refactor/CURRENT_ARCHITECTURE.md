# Current architecture inventory

This inventory is based on traced implementations in the Desktop canonical checkout, not filenames alone.

- `runtime/src/role_runtime.rs` owns startup, role normalization, Genesis loading, custody unlock, P2P/RPC/sync start order, consensus worker selection, telemetry, and shutdown. Its `run` entry point begins near line 4669.
- `runtime/src/config/mod.rs` loads `NodeConfig`, applies environment overrides, and rejects non-Chain-1266/non-`posy_simplified_v3` production configuration. It has no first-class local Admin API configuration yet.
- `runtime/src/p2p/networking.rs` is an approximately 800 KB monolith. It owns sockets, handshakes, peer lifecycle, discovery, validator-VPN route qualification, message routing, finality adapters, and portions of sync source selection. `p2p/mod.rs` also exposes process-global `GLOBAL_P2P_NETWORK`.
- `runtime/src/sync/{manager,state_sync,fast_sync,full_sync}.rs` contains sync algorithms, while P2P still makes routing/source decisions.
- `runtime/src/consensus/{typed_coordinator,simplified_posy,typed_finality_store}.rs` contains the current PoSy finality/recovery path. Legacy and coordinated engines remain present and must stay isolated from fresh Chain 1266 activation.
- `runtime/src/etdag.rs` contains admission context, encrypted envelopes, availability certificates, protected-input coordination, pruning, and safety journal in one module.
- `runtime/src/{transaction,execution,synq*,crypto/aegis_pqvm}.rs` form the deterministic execution/protected workload path.
- `runtime/src/rpc/rpc_server.rs` is a separate monolith from P2P and is the public node RPC/WS surface.
- `/Users/jhutzler/Desktop/Synergy-Network/07-Node-Control-Panel/control-service` has separate Node Control Panel/NetBird control code. It is not yet a consumer of the runtime management contract.

The first implemented boundary is `runtime/crates/synergy-node-core` plus `runtime/crates/synergy-admin-api`, with runtime dispatch in `runtime/src/node_management.rs` and local Unix-socket startup from `role_runtime.rs`.
