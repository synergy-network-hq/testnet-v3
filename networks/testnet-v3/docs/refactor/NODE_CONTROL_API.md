# Node Control API

Schema version 1 lives in `runtime/crates/synergy-admin-api`.

| Operation | Current implementation |
| --- | --- |
| `node_status` | Runtime config/role/lifecycle report |
| `health` | Structural health checks |
| `readiness` | Blocking-check report |
| `diagnostics` | `synergy-node doctor` report |
| `configuration_validation` | Fail-closed configuration validation |
| `role_inspection` | Canonical role profile surface |
| `capability_discovery` | Implemented management operations |

The runtime binds a local Unix-domain socket with permission mode 0600 at `<data-dir>/synergy-node-admin.sock`. `synergy-node <command> --admin-socket <path>` uses that typed API; without a socket it uses the same runtime dispatcher for offline validation. This is intentionally local-only and separate from public RPC/WS.

Mutating operations are not advertised yet. Start/stop/restart, identity, validator onboarding, VPN enrollment, snapshots, upgrades, and safe remediation will be added only with typed input, authorization, idempotency, event streaming, audit records, and recovery semantics.
