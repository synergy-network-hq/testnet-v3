# Public Validator Onboarding and Seed Registration

## Scope

This document defines the Node Control Panel behavior for onboarding validators into the public-first Synergy testnet P2P network.

The goal is to let a new validator join public P2P discovery without manually editing every existing validator config.

## Design rules

- New validators do not require DNS records.
- New validators do not require manual peer edits on every active validator.
- Public reachability is separate from consensus activation.
- Public P2P discovery uses bootnodes, seed registry, and peer exchange.
- The active Val1-Val6 foundation set keeps static uniform full-mesh public configs until a validator-set change is approved.
- Any consensus activation must use one canonical validator-set update path.

## Onboarding model

Separate two concepts:

| Concept | Question | Source |
| --- | --- | --- |
| P2P discovery | Where can this node be reached? | Public endpoint validation, seed registry, peer exchange |
| Consensus validator set | Is this validator allowed to sign, vote, or propose? | Shared validator-set manifest, on-chain validator set, or approved admin rollout |

A validator that is reachable over P2P is not automatically an active consensus validator.

## Required setup fields

The validator networking setup flow must collect or derive:

- Public P2P IP or hostname.
- Public P2P port, default `5622`.
- NAT mode: direct public IP, router port-forward, or custom public port.
- External reachability test result.
- Seed registration status.
- Last seed heartbeat status.
- Dial-back validation status.
- Validator identity.
- Peer ID or node public key.
- Chain ID.
- Consensus activation status.

The UI must distinguish:

- "This node is reachable on P2P."
- "This node is an active consensus validator."

## Rejected public endpoints

Generated validator configs and seed registration payloads must reject:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `localhost`
- `0.0.0.0`
- `::1`
- Private IPv6 ranges.

## Generated validator config requirements

New validator config output must include:

```toml
bootnodes = [
  "snr://bootstrap@bootnode1.synergynode.xyz:5620",
  "snr://bootstrap@bootnode2.synergynode.xyz:5620",
  "snr://bootstrap@bootnode3.synergynode.xyz:5620"
]

seed_servers = [
  "http://seed1.synergynode.xyz:5621",
  "http://seed2.synergynode.xyz:5621",
  "http://seed3.synergynode.xyz:5621"
]

bootstrap_dns_records = ["_dnsaddr.bootstrap.synergynode.xyz"]
listen_addr = "0.0.0.0:<local_p2p_port>"
public_p2p_address = "<public_ip_or_hostname>:<public_p2p_port>"
enable_seed_registration = true
enable_peer_exchange = true
reject_private_advertise_addrs = true
```

The generated config must not use a private, localhost, LAN, or unspecified public P2P address.

## Seed registration API

The control panel should register a new validator with all three seed servers:

- `http://seed1.synergynode.xyz:5621/register`
- `http://seed2.synergynode.xyz:5621/register`
- `http://seed3.synergynode.xyz:5621/register`

Request body:

```json
{
  "chain_id": "synergy-testnet",
  "role": "validator",
  "validator_address": "<synv11...>",
  "peer_id": "<peer_id>",
  "public_endpoint": "<public_ip_or_host>:<port>",
  "protocol_version": "<version>",
  "app_version": "<version>",
  "current_height": 0,
  "timestamp": "<iso8601>",
  "signature": "<signature_if_supported>"
}
```

Expected response body:

```json
{
  "accepted": true,
  "dialback_status": "success",
  "reason": null,
  "registered_until": "<iso8601>",
  "seed_id": "seed1",
  "recommended_peers": [
    "62.146.182.207:5622",
    "62.146.182.208:5622",
    "62.146.182.209:5622",
    "73.79.66.255:5622",
    "194.163.183.166:5622",
    "157.173.192.45:5622",
    "relay1.synergynode.xyz:5622",
    "relay2.synergynode.xyz:5622"
  ]
}
```

The UI should not mark the node as network reachable until at least one seed reports `dialback_status = success`.

## Heartbeat API

The control panel or runtime should heartbeat to all seed servers:

- `http://seed1.synergynode.xyz:5621/heartbeat`
- `http://seed2.synergynode.xyz:5621/heartbeat`
- `http://seed3.synergynode.xyz:5621/heartbeat`

Heartbeat body fields:

- `validator_address`
- `peer_id`
- `public_endpoint`
- `current_height`
- `sync_status`
- `peer_count`
- `timestamp`
- `signature` when supported

Seeds must expire validators that stop heartbeating before advertising them as healthy.

## Consensus activation paths

Selected path for Node Control Panel onboarding: **Path C, dynamic validator-set activation**.

The Control Panel provisions public P2P reachability through seed registration and peer exchange, then keeps consensus membership gated behind the existing activation workflow (`testnet_activate_validator`, activation preflight, shadow-epoch proof, and runtime validator-set observation). It does not make seed registration a consensus-membership event, and it does not hand-edit Val1-Val6 peer files for every new reachable validator.

The current Val1-Val6 foundation validators still keep their static uniform full-mesh public peer configs as the stability baseline. A future validator is promoted into the active consensus set only after the activation workflow approves it and the runtime validator set observes the same active membership.

### Path A: shared validator-set source

Preferred path.

- Move active validator membership to one shared validator-set manifest or on-chain source.
- All active validators read the same validator set.
- Updates are generated from one canonical source.
- Rollout is uniform and drift-resistant.

### Path B: transitional validator-set update command

Use this if the runtime still depends on static allowlists.

- Add an admin command in the Node Control Panel to approve a new consensus validator.
- Generate a new uniform validator allowlist and peer template.
- Roll it out to active validators one at a time.
- Verify quorum and chain movement after every validator restart.

### Path C: dynamic validator-set activation

Use this if dynamic validator sets are already supported by the runtime.

- Submit or activate the validator through the supported dynamic mechanism.
- Do not hand-edit static allowlists.
- Verify all nodes observe the same active validator set.

## Existing Val1-Val6 baseline

The current foundation validators remain static and uniform:

- Each has the same bootnodes.
- Each has the same seed servers.
- Each has the same DNS bootstrap record.
- Each has the same strict validator allowlist.
- Each peers with the other five validators by public IP.
- Each peers with `relay1.synergynode.xyz:5622` and `relay2.synergynode.xyz:5622`.

New validators should not be added as hardcoded persistent peers to every validator by default. Promote a new validator into the static peer template only after consensus activation requires it and the canonical validator-set update path has approved it.

## Verification checklist

Before showing the validator as ready:

- Config has no private, localhost, LAN, or unspecified public P2P endpoint.
- Public endpoint reachability test passes.
- Node can start from bootnodes and seed servers only.
- Seed registration succeeds on at least one seed.
- Seed dial-back succeeds on at least one seed.
- Heartbeat succeeds.
- Node appears in `/peers?role=validator` after dial-back success.
- Node discovers Val1-Val6 and relayers.
- Node syncs without VPN.
- Observer and Grafana can see the node.
- Explorer/indexer visibility is confirmed if relevant.
- Consensus status is still separate from P2P reachability.

Consensus activation is complete only when:

- The validator is approved through the selected validator-set path.
- All active validators converge on the same validator set.
- Chain height advances after activation.
- Existing validators continue to participate in consensus.
- No manual per-node peer chaos is required.
