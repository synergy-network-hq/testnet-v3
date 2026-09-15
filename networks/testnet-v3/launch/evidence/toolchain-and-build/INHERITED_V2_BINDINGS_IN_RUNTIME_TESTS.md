# Inherited-binding analysis — CORRECTED 2026-07-27

## Retraction

An earlier revision of this file classified `73.79.66.255` and
`194.163.183.166` as "inherited Testnet-v2 bindings" that had to be removed.
**That classification was wrong and is retracted.**

The reasoning error: the addresses were found under
`launch/reference/testnet-v2/` and absent from the v3 genesis, and I concluded
they were stale. Both premises were true; the conclusion did not follow. The
same physical machines are intentionally retained for Testnet-v3, and the v3
genesis schema does not carry operational routing data — so absence from
genesis proves nothing about validity.

## Evidence: the addresses are current and correctly assigned

Source: `documentation/unorganized-files/node-machine-credentials.xlsx`
(current node credentials workbook; credentials themselves not reproduced here).

| Node | Public IP | VPN IP | LAN IP | Ports (P2P/qRPC/WS/Disc/Metrics) |
|---|---|---|---|---|
| Val1 | 62.146.182.207 | 10.69.0.1 | — | 5622/5640/5660/5680/6030 |
| Val2 | 62.146.182.208 | 10.69.0.2 | — | 5622/5640/5660/5680/6030 |
| Val3 | 62.146.182.209 | 10.69.0.3 | — | 5622/5640/5660/5680/6030 |
| **Val4** | **73.79.66.255** | 10.69.0.4 | 192.168.11.229 | 5622/5640/5660/5680/6030 |
| **Val5** | **194.163.183.166** | 10.69.0.5 | — | 5622/5640/5660/5680/6030 |
| Val6 | 157.173.192.45 | *(none assigned)* | — | 5622/5640/5660/5680/6030 |
| Archive Validator | **73.79.66.255** | 10.69.0.220 | 192.168.11.140 | 5622/5640/5660/5680/6030 |
| Relayer-1 | 195.26.241.95 | 10.69.0.201 | — | 5622/… |
| Relayer-2 | 94.72.117.108 | 10.69.0.202 | — | 5622/… |
| Observer | 209.145.50.9 | 10.69.0.250 | — | 5622/… |

Both addresses are **live, correctly assigned Testnet-v3 infrastructure
routes**. Nothing about them is stale.

## The real defect these tests exposed

`Val4` and `Archive Validator` are **two different machines sharing one public
IP** (`73.79.66.255`, distinguished only by LAN IPs `.229` / `.140`), and both
serve P2P on port `5622`. Therefore `73.79.66.255:5622` is **ambiguous by
construction** — it cannot identify a Synergy node.

`networking.rs` keys its peer/vote-target map by `ip:port`. The failing
assertion `!active_subset_address_map.contains_key("73.79.66.255:5622")` is the
runtime telling the truth: an endpoint-keyed map cannot represent this
topology. The defect is **IP-as-identity in the peer layer**, not a stale IP.

Correct model (four separate layers, not to be conflated):

| Layer | Value | Purpose |
|---|---|---|
| Infrastructure route | public IP, VPN IP, port | reach the machine; may change freely |
| WireGuard tunnel identity | WG public key | authenticate a VPN participant |
| **Synergy node identity** | **`synv…` address + proof of possession** | **identify the peer** |
| Consensus identity | validator address, consensus key, active-set/cluster/weight | authorize consensus |

## Genuinely stale (unchanged from prior analysis)

`rpc_server.rs:10913` asserts genesis hash
`f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789`. That value
appears only under `launch/reference/testnet-v2/`; it is the **Testnet-v2
genesis hash** and is a chain-identity value that must not be reused. The v3
candidate is `ac5186cb4a95130d22986c73c20d0eedd73821a735d944184c94691860008407`.

This one is a real inherited chain binding. It should not be replaced with the
candidate production hash in a broad unit test either — it belongs in a
deterministic test-only v3 fixture.

## Gate impact

- IP retention is **not** a launch blocker and must not be counted as one.
- `inherited_identity_bindings_removed` remains `false` for one reason only:
  the **v2 genesis hash** in `rpc_server.rs`, plus peer identity still being
  endpoint-keyed rather than `synv…`-keyed.
