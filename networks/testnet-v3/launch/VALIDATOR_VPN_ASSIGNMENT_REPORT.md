# Testnet-v3 Validator VPN Assignment Report

Generated: 2026-07-27T08:51:20.984575+00:00  |  config version: `tnv3-vpn-1`
Registry SHA-256: `13d7ba7f8a8dd9a552cf0ed798c4ab80084d49b5fe552afcf1295dc2e013a285`

Chain binding: `synergy-testnet-v3` / chain_id `1266`  |  supernet `10.70.0.0/16`
Coordinator: `10.70.0.1:51820`
Coordinator WG public key: `PHGmRUyONycEToSu/3Hls6phFcXixO5HpxAn886lUl0=`

**Identity model.** The `synv…` address is the node identity and the primary key
of this table. Public IP and VPN IP are **routes**. The WireGuard public key
authenticates the **tunnel**. Consensus authority is separate and governed by the
validator active set — VPN membership never implies consensus authorization.

## Reconciliation

| Role | Node name | synv… address (identity) | Public IP (route) | VPN IP (route) | WireGuard public key (tunnel) | Status |
|---|---|---|---|---|---|---|
| validator 1 | Val1 | `synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t` | 62.146.182.207:51820 | 10.70.10.1 | `XfNTXSEctRiorOsvdAcFkZgkrmjQySB5IBKpEPtKSE0=` | active |
| validator 2 | Val2 | `synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk` | 62.146.182.208:51820 | 10.70.10.2 | `gC3WlV1+/LU5V7EVJteIcmkSgJ2aAzUdNWbCt8Y0XCY=` | active |
| validator 3 | Val3 | `synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj` | 62.146.182.209:51820 | 10.70.10.3 | `6J1TeYXUrC/8XyNrTew2yiyzKHWi6Fpgq2gUNm9ueQo=` | active |
| validator 4 | Val4 | `synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg` | 73.79.66.255:51820 | 10.70.10.4 | `uSHJvz5TqBfMYFtKI8jsEKGNaEVAEqtuIL6GTWP1CBM=` | active |
| validator 5 | Val5 | `synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu` | 194.163.183.166:51820 | 10.70.10.5 | `G5ZD+A3r+wJfyq8WDKVhU5VxAuEpie1QHCtvDhx/aRc=` | active |
| validator 6 | Val6 | `synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc` | 157.173.192.45:51820 | 10.70.10.6 | `NTg9xr4DjNf6iSpaF2fYRSvVp0/xHe4dpMkzgmMG5Fk=` | active |
| validator 7 | (unassigned machine) | `synv11lgxgqj3juusy9rdfc6r0z4p0sf2ext4f48g` | — | 10.70.10.7 | `XSIPbi3b6wYdE0cKGeOYQVvnmbpQ+OvNBKmfvcu4+SA=` | provisioned-inactive |
| validator 8 | (unassigned machine) | `synv11nqlh9w5nrqsg0y0lq6lljtgxnm0d5ep30l5` | — | 10.70.10.8 | `PcW0G6RMYlnGkWTMGiy0p4aHHBqv3RMmwakiBgJo8Cc=` | provisioned-inactive |
| validator 9 | (unassigned machine) | `synv11tcpv98np8eexpua5fq5wc4kvj4ul7e5x3k7` | — | 10.70.10.9 | `7HjXnEVhVKoaklTTTMF6tbgcU5cLYD0KunQnjG+rES0=` | provisioned-inactive |
| validator 10 | (unassigned machine) | `synv11dm930g9e0l96rxfg65fn8z4y2vm7qz3yfn3` | — | 10.70.10.10 | `SkT96BXy4s57twrM+30Obcp83HhoLzfUCIVjnC7lkGY=` | provisioned-inactive |
| validator 11 | (unassigned machine) | `synv112ggx4l8st0uq3gvy6hqvaa4d90w5uanaqjz` | — | 10.70.10.11 | `Mj52nJXmajn53jQBCF00sltujUaXOEFqb4XAYfRiJGo=` | provisioned-inactive |
| validator 12 | (unassigned machine) | `synv11tf8hc6fsrdg0jpcqy8xay0awack2k69a36l` | — | 10.70.10.12 | `pAkmlLck8UUsIZcaZEN5CZhbrNX7AtPoytg7KVX6UAw=` | provisioned-inactive |
| validator 13 | (unassigned machine) | `synv11p8ej4mxf3uuepqxvnlnus67aut8vtman47g` | — | 10.70.10.13 | `32DHzXMmBZzhgZIZeUgYAsW1Z9KE5/InWorIkukmhC0=` | provisioned-inactive |
| validator 14 | (unassigned machine) | `synv11sadw92489zclv0v0p56fmjhwqze56ud0wm2` | — | 10.70.10.14 | `yzMsLLupHPKILY8O0n2Rf6gnCGhg09Zu5/hPxArlvy4=` | provisioned-inactive |
| validator 15 | (unassigned machine) | `synv11t2u2xh3elek5q682lqprclauyatn5xjq4pq` | — | 10.70.10.15 | `B+eJr8s36yAVtTeyG2vw7iQ7hMfKDd6y8ait0tkLdhs=` | provisioned-inactive |
| validator 16 | (unassigned machine) | `synv11t4hhy3k4dh9xlnn5fus82e3t70d3q8ur8fa` | — | 10.70.10.16 | `L0a4SxLAndSDdJTw4CmOm7y3mFxNboNGK82E4AJXkAs=` | provisioned-inactive |
| validator 17 | (unassigned machine) | `synv11x3pzwp2xvd4jxs6fq5hvahrrglcytahtz7w` | — | 10.70.10.17 | `6enAs7XdvdIJGdlla669SEMO8Bq+idTq0JkMd/vlvFM=` | provisioned-inactive |
| validator 18 | (unassigned machine) | `synv11daswzvvaklsl2e0hxmtz39de62w9qum6c9k` | — | 10.70.10.18 | `KOGnfd6TMR5RSwyskAcuroGjnm64jP+FYY/o9YbUhGM=` | provisioned-inactive |
| validator 19 | (unassigned machine) | `synv11p5emxjn9a0y4u8jsq6qupcuwsgwedxnl0p5` | — | 10.70.10.19 | `ZhXnia8A940RIROmJNP/mYsVvHCLzep4j2y3DP1yOWE=` | provisioned-inactive |
| validator 20 | (unassigned machine) | `synv11gvzqyvuqrtpjck8jdefsfefqz4rjfytw44h` | — | 10.70.10.20 | `doiDRRe93h/l8eg45SDgxM0+ypsREglFvLG6pgu4AQM=` | provisioned-inactive |
| validator 21 | (unassigned machine) | `synv119uv7nqfvypqtm7fgpmsjju5y4yz73apw4hx` | — | 10.70.10.21 | `7OPEeLJgIexbdMnTwFtMNzadpTu/+s6qHfS98UfukSE=` | provisioned-inactive |
| relayer 1 | Relayer-1 | `synv21hr5jcwjfjlhy5zqdg8uhugjsgc3nw2xgjan` | 195.26.241.95:51820 | 10.70.20.1 | `OjSzAhZEUd0fqQOG8dwWSjJzB5O3ZthLuvkViv+Zwxs=` | active |
| relayer 2 | Relayer-2 | `synv21lfuahljzwd8eney8h6zclgqta78sqv0radf` | 94.72.117.108:51820 | 10.70.20.2 | `Njg5AHw9IBxLBieIX21B9i3tKFA3BnXZ62vEc+aLPlY=` | active |
| relayer 3 | Relayer-3 | `synv21k07a05felgr3rsyz27h9g5saeh0gn0v2zq8` | 209.145.48.117:51820 | 10.70.20.3 | `lZk3vedlfBn+SeqA/aQfB6GFVR+FDxTDYVvI49m+tnU=` | active |

Config path pattern:
`testnet-v3-identity-files/<IDENTITY_ID>_<alias>/wireguard/sy-vpn.conf`

## Conflicts / notes

- **`73.79.66.255` is shared** by Val4 and the Archive Validator (LAN
  `192.168.11.229` / `192.168.11.140`). Both serve P2P on `5622`, so
  `73.79.66.255:5622` is **ambiguous as an identity** and must never be used as
  one. Inside the VPN they are unambiguous: `10.70.10.4` vs the archive host.
- Validators 7–21 have identities and full VPN material but **no machine
  assigned yet**; their peer entries carry no `Endpoint` and are learned on
  first handshake (roaming). They are pre-provisioned in every peer's config so
  activating them later requires **no edit to already-deployed configs**.
- Validators 1–6 and relayers 1–3 are active at launch.
