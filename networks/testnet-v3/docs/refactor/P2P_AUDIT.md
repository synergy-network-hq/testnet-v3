# P2P audit

`runtime/src/p2p/networking.rs` still combines authenticated handshakes, peer storage, discovery/bootstrap, message routing, typed PoSy requests, ETDAG messages, sync source choice, and validator VPN route policy. `p2p/mod.rs` adds global lifecycle state. Canonical endpoint parsing has now moved to `runtime/src/p2p/transport.rs`; the networking callers consume that module rather than owning normalization themselves.

`runtime/src/p2p/peer_lifecycle.rs` is now the owner of peer connection-admission state: inbound/outbound classification, connecting/connected/disconnected states, duplicate suppression, configured connection limits, deterministic reconnect backoff/jitter, authenticated state, quarantine, bans, and stale-peer classification. `P2PNetwork` consumes it before direct and discovery dials, at inbound acceptance, and after signed handshake verification. The existing socket/cache structures remain in the monolith while the lifecycle snapshot and disconnection policy are migrated; that work is explicitly incomplete.

The first safe extraction order is: protocol framing/versioning, transport, handshake identity proof, peer lifecycle, discovery, router/backpressure, then narrow PoSy/ETDAG/sync adapters. Existing callers must move with their behavior and tests; no renamed forwarding module is considered complete.
