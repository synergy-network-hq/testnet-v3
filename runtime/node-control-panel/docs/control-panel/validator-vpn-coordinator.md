# Validator VPN Coordinator and Agent

## Purpose

The validator VPN is the private consensus transport for eligible validators and Synergy-operated relayers. It is not a general service network and it is not a full-tunnel exit path.

Validators 1-6 and relayers 1-3 are the bootstrap deployment only. Future eligible validators are enrolled automatically through the node control panel and must not require manual team-maintained WireGuard peer-list changes.

## Bootstrap Scope

The central Innernet bootstrap is limited to:

| Role | Node | VPN IP |
| --- | --- | --- |
| relayer | relayer-1 | `10.70.20.1/32` |
| relayer | relayer-2 | `10.70.20.2/32` |
| relayer | relayer-3 | `10.70.20.3/32` |
| validator | validator-1 | `10.70.10.1/32` |
| validator | validator-2 | `10.70.10.2/32` |
| validator | validator-3 | `10.70.10.3/32` |
| validator | validator-4 | `10.70.10.4/32` |
| validator | validator-5 | `10.70.10.5/32` |
| validator | validator-6 | `10.70.10.6/32` |

Do not add service nodes, RPC nodes, archive nodes, bootnodes, seed nodes, indexers, observers, or miscellaneous infrastructure to this validator-only VPN.

## Address Plan

- Innernet supernet: `10.70.0.0/16`
- Coordinator server: `10.70.0.1`
- Validators: `10.70.10.1` through `10.70.10.254` (dynamic allocation starts at `.7`)
- Relayers: `10.70.20.1` through `10.70.20.254` (dynamic allocation starts at `.4`)
- The former static `10.69.0.0/16` mesh is a retiring transport. It is not a
  source of new allocations and is removed only after the verified cutover.
- Every peer route must be that peer's exact `/32`.
- Do not use the whole VPN CIDR or the default Internet route as a peer route.

Future validator allocation is coordinator-owned. The desktop never assigns a
VPN address, writes a WireGuard peer, or falls back to the retired static mesh.

## Coordinator

The control service binds to `127.0.0.1` and should sit behind the public
`https://vpn-coordinator.synergy-network.io` reverse proxy. Public validator
enrollment endpoints are intentionally reachable without the coordinator bearer
token; they still validate enrollment signatures and the live `50,000 SNRG`
stake gate before writing enrollment state. Coordinator/admin endpoints remain
bearer-token protected.

Public endpoints:

- `POST /v1/invite`
- `POST /v1/mesh/confirm`
- `GET /v1/mesh/status` with `X-Synergy-Innernet-Enrollment` and `X-Synergy-Innernet-Token`
- `POST /api/validator-vpn/enrollment/challenge`
- `POST /api/validator-vpn/enroll`
- `GET /api/validator-vpn/snapshots/latest`

Bearer-token protected endpoints:

- `POST /v1/migration/bootstrap/invite`
- `POST /v1/migration/bootstrap/reissue`
- `POST /v1/migration/bootstrap/recover-stale`
- `POST /v1/migration/bootstrap/recover-confirmation`
- `GET /v1/migration/bootstrap/status`
- `GET /v1/migration/bootstrap/transports`
- `GET /api/validator-vpn/status`
- `GET /api/validator-vpn/snapshots/{generation}`
- `POST /api/validator-vpn/nodes/{node_id}/heartbeat`
- `POST /api/validator-vpn/nodes/{node_id}/health`
- `POST /api/validator-vpn/nodes/{node_id}/config-ack`
- `GET /api/validator-vpn/propagation/{generation}`
- `POST /api/validator-vpn/relayers`
- `POST /api/validator-vpn/bootstrap/import`

POST /v1/invite is the Phase-1 Electron onboarding API. It requires a
provisioned node id, validator identity, operator wallet, the identity's
matching public key, a detached FN-DSA proof over the exact enrollment message,
and the same live 50,000 SNRG stake gate used by validator enrollment. The
Synergy team issues the one-time token through the protected admin endpoint;
the token is bound to one assignment ID, `synv…` identity, and public key. A
Testnet-v3 validator request must also provide the packaged static VPN IP,
WireGuard public key, and configuration version. The coordinator verifies all
of those bindings and the detached identity proof before authorizing the
Control Panel to install the package's complete static mesh. It does not
allocate a peer, write a peer configuration, or invoke `innernet-server` for a
preconfigured validator. The token is consumed only after POST /v1/mesh/confirm
proves both the assigned local interface and a coordinator-observed WireGuard
handshake. Confirmation returns a signed membership receipt, which the desktop
writes into validator onboarding evidence before activation can continue. The
admin endpoint requires X-Admin-Key equal to the coordinator service token.
Token plaintext is returned once; only its SHA-256 hash is stored; audit state
records proof verification time but never a private key or signature. Invite
requests are limited to 10 per source and 5 per token per minute. Invalid,
expired, or redeemed tokens return 401; rate limits return 429.

`SYNERGY_INNERNET_SERVER_COMMAND` is executed without a shell using the
supported non-interactive Innernet contract: `--config-dir <dir> --data-dir
<dir> add-peer <interface> --name <peer> --cidr <validator|relayer-cidr> --ip
<assigned-ip> --admin false --invite-expires <positive-duration>
--save-config <one-time-path> --yes`. The coordinator reads the one-time TOML
invitation, deletes its local copy before returning, and never exposes
Innernet administration APIs to the renderer or the public Internet. Upstream
`innernet-server` requires UID 0 for this command, so the deployed loopback
coordinator systemd unit explicitly runs as root with no local desktop agent;
do not expose port `47895` directly.

An Innernet replacement is not a rolling change for the current static
`10.69.0.0/16` mesh: Innernet reserves its own server peer and requires its
database to own every assigned address. Use non-overlapping
`SYNERGY_INNERNET_*_ADDRESS_CIDR` plans. While
`SYNERGY_INNERNET_MIGRATION_READY=false`, the protected bootstrap endpoint is
the only path that can create an Innernet invitation. It accepts only the
canonical `relayer-1` through `relayer-3` and `validator-1` through
`validator-6` names, derives their fixed `10.70.20.1/32` through
`10.70.20.3/32` and `10.70.10.1/32` through `10.70.10.6/32` assignments, and
stores its enrollment state separately from the retiring static VPN registry.
It rejects duplicate unconfirmed invitations and refuses every request after
cutover. Redeem each invite on its assigned host, then call
`POST /v1/mesh/confirm` with its one-time confirmation credential and verified
coordinator handshake. `GET /v1/migration/bootstrap/status`, using
`X-Admin-Key`, must report `bootstrap_expected_members=9`,
`bootstrap_complete=true`, and no `bootstrap_pending_member_ids` before setting
`SYNERGY_INNERNET_MIGRATION_READY=true`. Confirmation is server-verified: the
coordinator requires the matching active/redeemed Innernet database peer and a
fresh WireGuard handshake for that peer; client-provided handshake evidence is
not sufficient. The public `POST /v1/invite` route independently enforces the
same completed nine-peer bootstrap gate even after the environment flag is set.
Only after the status proof is complete may the old static configuration be
retired.

Before the coordinator returns any invitation, it verifies that the temporary
unredeemed peer key is attached to the live coordinator `sy-vpn` WireGuard
device with only that peer's `/32` route. This is required for the client to
reach Innernet's internal redemption API through its initial server tunnel. A
missing attachment fails the invitation request instead of producing an
unredeemable credential.

The coordinator firewall must also allow Innernet's redemption API only from
the Innernet interface. For UFW hosts, keep public UDP `51820` for WireGuard
handshakes and add this private-only rule before issuing invitations:

```bash
sudo ufw allow in on sy-vpn to 10.70.0.1 port 51820 proto tcp
```

Do not add a public TCP `51820` rule. The client first reaches the coordinator
with its temporary WireGuard key, then redeems the invitation over TCP through
that private tunnel.

If a bootstrap invitation is lost before redemption, the protected
`POST /v1/migration/bootstrap/reissue` route can recover only that exact
canonical peer. It first expires the old confirmation credential, then proves
the server peer is unredeemed and has never completed a WireGuard handshake
before removing it and creating a replacement one-time invitation. It refuses
confirmed, redeemed, handshaken, non-canonical, or post-cutover peers. Do not
edit the Innernet database manually.
If the temporary key completed a server-observed handshake but the client did
not redeem, the normal reissue endpoint remains blocked. After the handshake
has been stale for more than the five-minute confirmation freshness window, an
administrator may call `POST /v1/migration/bootstrap/recover-stale` with the
canonical `peer_name` and `acknowledge_stale_unredeemed_handshake=true`. That
route rejects redeemed peers, fresh handshakes, missing handshakes, and every
non-canonical or post-cutover request before replacing the temporary peer.
If a client already redeemed and handshook but the caller lost its confirmation
credential, the administrator may call
`POST /v1/migration/bootstrap/recover-confirmation` with the canonical
`peer_name` and `acknowledge_redeemed_membership=true`. The coordinator first
proves the redeemed database peer and fresh server-side handshake, then rotates
only the coordinator confirmation credential. It never returns an invitation,
changes an Innernet peer, or treats client-reported state as proof.
At cutover, the coordinator returns 410 for public legacy enrollment/snapshot
routes and the desktop static VPN commands and agent fail closed. Generated
validator configuration retains `validator_vpn_transports`, but that mapping is
now sourced exclusively from the coordinator-signed Innernet transport
snapshot; it never derives addresses from a peer name, a local interface, or a
static VPN file. The coordinator also fails closed when the server binary,
interface, address/CIDR names, receipt keys, or state directories are not
configured.

`GET /v1/migration/bootstrap/transports` is protected by `X-Admin-Key` and is
for rollout verification only. It returns the same signed validator transport
snapshot distributed to confirmed enrollments without exposing an enrollment
confirmation token. Treat its signature as verification material and do not
publish it or the coordinator bearer token.

The current repo uses workspace JSON state rather than database migrations, so the coordinator stores the equivalent registry, lease, challenge, snapshot, and audit-event model under the monitor workspace at:

```text
testnet/runtime/validator-vpn/validator-vpn-state.json
```

The same state file also stores hashed onboarding tokens and config
acknowledgements. Snapshot generation is the authoritative immutable config
version. After each new signed snapshot, every validator included in that
snapshot must POST an acknowledgement with that generation, applied,
interface_up, and its observed handshake count. The propagation endpoint and
protected coordinator status remain incomplete until every expected validator
has acknowledged successfully. A failed or missing acknowledgement is never
treated as success.

Before real enrollment is allowed, production must configure the coordinator host
with:

- `SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY`
- `SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY`
- `SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE`
- `SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN`
- `SYNERGY_CONTROL_SERVICE_DISABLE_LOCAL_AGENT=true`
- `SYNERGY_INNERNET_SERVER_COMMAND`
- `SYNERGY_INNERNET_INTERFACE`
- `SYNERGY_INNERNET_VALIDATOR_CIDR`
- `SYNERGY_INNERNET_RELAYER_CIDR`
- `SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR`
- `SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR`
- `SYNERGY_INNERNET_CONFIG_DIR`
- `SYNERGY_INNERNET_DATA_DIR`
- `SYNERGY_INNERNET_INVITE_DIR`
- `SYNERGY_INNERNET_INVITE_EXPIRES=30m`
- `SYNERGY_INNERNET_MIGRATION_ID`
- `SYNERGY_INNERNET_MIGRATION_READY=false` during bootstrap, then `true` only
  after the nine-peer status proof succeeds
- `SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY`
- `SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY`

The signing key must be an Ed25519 32-byte seed encoded as
`ed25519:<base64>`. Publish only the public key to validator client packages.
`SYNERGY_VALIDATOR_VPN_ELIGIBLE_VALIDATORS` is optional; if unset, local
eligibility accepts valid setup identities and the public enrollment HTTP path
still enforces the live stake gate.

The repo ships deployment templates under:

```text
deploy/validator-vpn-coordinator/
```

Use `validator-vpn-coordinator.env.example` for the host env file and
`synergy-validator-vpn-coordinator.service` for the systemd unit. The unit runs:

```text
/opt/synergy/node-control-panel/control-service --port 47895 --token ${SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN}
```

## Agent Behavior

The validator VPN agent is responsible for local key ownership and peer updates:

- Generate the WireGuard private key locally if missing.
- Store the private key at `/etc/synergy/validator-vpn/private.key` with mode `0600`.
- Store the public key at `/etc/synergy/validator-vpn/public.key`.
- Never upload or log private keys.
- Request an enrollment challenge.
- Sign the enrollment payload with the configured validator/operator identity.
- Fetch and verify signed peer snapshots.
- Render only exact `/32` peers.
- Apply peer changes with `wg syncconf` where available.
- Heartbeat local health to the coordinator.
- POST a config acknowledgement after every successful snapshot apply.

## Readiness Gates

Do not mark a validator VPN-ready or consensus-ready just because WireGuard is up. Require:

- `sy-validator0` exists and has the assigned `10.70.10.x/32` address.
- Latest signed peer snapshot is applied.
- All three relayers are reachable over the VPN.
- At least three active validator peers are reachable over the VPN.
- Consensus port is reachable over the VPN.
- Chain state is synced or within the configured sync threshold.
- Clock drift is within policy.
- Validator process and identity are healthy.
- Existing consensus activation rules approve the validator.

## Inactivity and Removal

Missing agent heartbeats mark a node degraded. Stale WireGuard handshakes or missing consensus activity mark validators inactive. Inactive, quarantined, or revoked validators are omitted from new active peer snapshots, and their IP lease remains tombstoned for the configured retention period.

Do not automatically remove validators from consensus unless the runtime has a safe consensus-set management path for that action.

## Health Check

Run the local/bootstrap peer health check:

```bash
scripts/testnet/check-validator-vpn.sh
```

The script is read-only. It checks the bootstrap aliases, verifies the `sy-validator0` interface, checks exact peer routes, and avoids printing private keys.

For a local node only:

```bash
scripts/testnet/check-validator-vpn.sh --local
```

For a subset:

```bash
scripts/testnet/check-validator-vpn.sh --aliases synergy-relayer1 synergy-val1
```

Run the coordinator deployment readiness check:

```bash
scripts/testnet/validator-vpn-coordinator-readiness.sh \
  --env-file /etc/synergy/validator-vpn-coordinator.env
```

If protected admin routes are intentionally reachable only on the coordinator
host, run the same readiness check locally with:

```bash
scripts/testnet/validator-vpn-coordinator-readiness.sh \
  --env-file /etc/synergy/validator-vpn-coordinator.env \
  --url http://127.0.0.1:47895 \
  --allow-http
```

The readiness check verifies env-file presence, coordinator token presence,
Ed25519 signing/public-key shape, local-agent disablement, DNS, `/health`,
public latest-snapshot reachability, and token-authenticated coordinator status.
It does not print token or signing-key values.

## Rollout and Rollback

Rollout sequence:

1. Deploy coordinator/control-service changes.
2. Configure coordinator signing and validator eligibility.
3. Deploy the validator VPN agent package.
4. Register relayers 1-3.
5. Enroll validators 1-6.
6. Generate and verify the first signed peer snapshot.
7. Apply VPN configs to the nine bootstrap nodes.
8. Run `scripts/testnet/check-validator-vpn.sh`.
9. Switch enrolled validators' consensus config to prefer VPN IPs.
10. Monitor block time, handshake freshness, peer reachability, and consensus activity.

Rollback:

1. Stop or disable `sy-validator0`.
2. Restore the previous consensus networking config.
3. Preserve private keys unless explicitly rotating or removing identity.
4. Preserve registry, lease, snapshot, and audit history.
5. Leave non-enrolled nodes unchanged.
