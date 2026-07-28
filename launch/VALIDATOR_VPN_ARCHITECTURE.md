# Testnet-v3 Validator VPN Architecture

## Addressing plan (governed, unchanged)

Source: `runtime/node-control-panel/docs/control-panel/validator-vpn-coordinator.md`

    supernet     10.70.0.0/16
    coordinator  10.70.0.1:51820
    validators   10.70.10.1 .. 10.70.10.21
    relayers     10.70.20.1 .. 10.70.20.3

No subnet was invented and no existing assignment was changed. Public IPs and
SSH access are retained exactly as recorded in the node credentials workbook.

## Topology

Coordinator-assisted enrollment with **full-mesh data plane**. Every one of the
24 participants carries a peer entry for all 23 others plus the coordinator.
This satisfies PoSy's requirement that active validators reach every other
active validator and all three relayers, and it means validators 7–21 can be
activated later without touching deployed configs.

## Four identity layers — never conflated

| Layer | Value | Role | May change? |
|---|---|---|---|
| Infrastructure route | public IP, VPN IP, port | reach the machine | yes, freely |
| Tunnel identity | WireGuard public key | authenticate the VPN tunnel | on rotation |
| **Synergy node identity** | **`synv…` + proof of possession** | **identify the peer** | no |
| Consensus identity | validator address, consensus key, active set, cluster, weight | authorize consensus | per governance |

## Connection sequence

1. IP/port establishes the transport route.
2. WireGuard authenticates and encrypts the tunnel.
3. Synergy P2P handshake presents the node's `synv…` address.
4. Peer proves possession of the key bound to that `synv…`.
5. Receiver validates `synv…` against the authorized topology registry.
6. If a validator, consensus identity is validated **separately** against the
   active set and height context.
7. The session is indexed by the authenticated `synv…` address.
8. IP and port remain connection metadata only.

Correct IP + wrong `synv…` → reject. Unknown IP + valid identity → handled by
endpoint-update policy, never trusted automatically.

## Firewall posture

- `51820/udp` open only as required for WireGuard.
- Consensus/P2P (`5622`) reachable over the VPN; not publicly exposed.
- SSH remains governed by the existing operational security model.
- Source IP is never treated as authorization.
- Coordinator compromise does not grant consensus signing authority.
