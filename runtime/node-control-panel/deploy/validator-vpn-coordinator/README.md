# Validator VPN Coordinator Deployment Artifacts

This directory contains repo-side templates for running the node-control-panel `control-service` as the public validator VPN coordinator behind the `vpn-coordinator.synergy-network.io` reverse proxy.

The public coordinator service binds to `127.0.0.1:47895`. Keep TLS and public exposure in the host reverse proxy. Do not expose the service port directly.

Use `nginx-vpn-coordinator.conf.example` as the public proxy contract. After
cutover, `/health` must return 200, the five `/v1` Innernet routes must reach
the coordinator instead of returning a proxy 404, and the retired static
snapshot route must return 410.

The upstream `innernet-server` command requires UID 0, including its
non-interactive `add-peer` command. The coordinator unit therefore runs as
root with the service hardening in the supplied unit. Keep
`SYNERGY_CONTROL_SERVICE_DISABLE_LOCAL_AGENT=true`, bind only to loopback,
and do not enable `SYNERGY_INNERNET_MIGRATION_READY` until every legacy peer
has been migrated and acknowledged the new mesh generation.

## Required Host Paths

- Runtime resources: `/opt/synergy/node-control-panel`
- Mutable state: `/var/lib/synergy/node-control-panel`
- Env file: `/etc/synergy/validator-vpn-coordinator.env`
- Systemd unit: `/etc/systemd/system/synergy-validator-vpn-coordinator.service`

## Install Skeleton

```bash
sudo install -d -m 0755 /opt/synergy/node-control-panel
sudo install -d -m 0750 /var/lib/synergy/node-control-panel
sudo install -d -m 0750 /etc/synergy
sudo install -m 0640 deploy/validator-vpn-coordinator/validator-vpn-coordinator.env.example \
  /etc/synergy/validator-vpn-coordinator.env
sudo install -m 0644 deploy/validator-vpn-coordinator/synergy-validator-vpn-coordinator.service \
  /etc/systemd/system/synergy-validator-vpn-coordinator.service
```

Edit the env file on the host before enabling the service. Generate real values for:

- `SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN`
- `SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY`
- `SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY`
- `SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY`
- `SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY`
- `SYNERGY_INNERNET_MIGRATION_ID`

Set `SYNERGY_INNERNET_INVITE_EXPIRES=30m` (or another positive single-unit
duration such as `15m` or `2h`). This suppresses the upstream interactive
expiry prompt, and the coordinator limits its confirmation credential to the
shorter of the onboarding-token and Innernet invite lifetimes.

Every signing key must be an Ed25519 32-byte seed encoded as `ed25519:<base64>`. Every public key must be `ed25519:<base64>` and match its signing seed. Keep `SYNERGY_INNERNET_MIGRATION_READY=false` until the existing static VPN has been fully migrated; setting it true retires static enrollment and snapshot routes.

## Pre-Cutover Bootstrap

Do not use public validator enrollment to migrate the existing mesh. With the
cutover flag still `false`, call the loopback coordinator's protected
`POST /v1/migration/bootstrap/invite` route once for each of the nine canonical
names: `relayer-1` through `relayer-3` and `validator-1` through
`validator-6`. The request uses `X-Admin-Key` and a JSON body containing only
`peer_name`; the coordinator derives the role and fixed Innernet `/32` address.
Redeem the returned one-time invitation on that peer, prove a handshake with
the coordinator through `POST /v1/mesh/confirm`, and retain no invitation or
confirmation credential in shell history or logs.

After all nine confirmations, query
`GET /v1/migration/bootstrap/status` on the loopback service using
`X-Admin-Key`. It must show `bootstrap_expected_members=9`,
`bootstrap_complete=true`, and no `bootstrap_pending_member_ids`. The
coordinator will accept a confirmation only after it independently verifies the
matching redeemed peer and fresh WireGuard handshake on the Innernet server.
Only then update the env file to `SYNERGY_INNERNET_MIGRATION_READY=true`,
restart the coordinator, and retire the static mesh. The public `/v1/invite`
path remains fail-closed until that final cutover and continues to enforce the
nine-peer completion proof after the flag is enabled.

If an invitation is lost before its peer redeems it, use the loopback,
admin-protected `POST /v1/migration/bootstrap/reissue` endpoint with the same
canonical `peer_name`. It is intentionally limited to unredeemed peers without
a server-observed handshake; it expires the lost confirmation credential and
generates a new invitation. Never modify the Innernet SQLite database by hand.

Before issuing an invitation, permit the Innernet redemption API on the private
interface only. On UFW hosts:

```bash
sudo ufw allow in on sy-vpn to 10.70.0.1 port 51820 proto tcp
```

Keep UDP `51820` public for WireGuard handshakes, but never open TCP `51820`
to the public Internet. A temporary peer must use the private `sy-vpn` tunnel
to redeem its invitation. If an unredeemed temporary peer handshakes but the
client fails before redemption, do not use normal reissue. Wait until the
handshake is older than the five-minute confirmation window, then call the
admin-only `POST /v1/migration/bootstrap/recover-stale` endpoint with the
canonical `peer_name` and `acknowledge_stale_unredeemed_handshake=true`.
If the client already redeemed and completed a fresh handshake but its
confirmation credential was lost, use the admin-only
`POST /v1/migration/bootstrap/recover-confirmation` endpoint with the canonical
`peer_name` and `acknowledge_redeemed_membership=true`. It rotates only the
coordinator credential after server-side redemption and handshake verification;
it does not create an invitation or modify the peer.

## Readiness Check

Run the read-only readiness script before and after service start:

```bash
scripts/testnet/validator-vpn-coordinator-readiness.sh \
  --env-file /etc/synergy/validator-vpn-coordinator.env
```

For offline config validation only:

```bash
scripts/testnet/validator-vpn-coordinator-readiness.sh \
  --env-file /etc/synergy/validator-vpn-coordinator.env \
  --skip-http
```

If protected admin routes are intentionally not exposed through nginx, run the
HTTP checks locally on the coordinator host:

```bash
scripts/testnet/validator-vpn-coordinator-readiness.sh \
  --env-file /etc/synergy/validator-vpn-coordinator.env \
  --url http://127.0.0.1:47895 \
  --allow-http
```

The script does not print token or signing-key values.
