# Validator VPN Coordinator

This deployment uses the upstream `innernet-server` v2.0.0 binary. Every
command other than shell completion requires UID 0, including `serve` and
`add-peer`. The unit files therefore declare `User=root` explicitly. The
root boundary is narrow: the server is limited to WireGuard/netlink
capabilities and its state directories, while the add-peer trigger denies
network access except localhost.

## Stage The Coordinator

Run these steps on the coordinator host as an operator with root access. Do
not run them through the Control Panel and do not set the migration flag yet.

1. Install and verify the pinned binary:

   ```sh
   install -o root -g root -m 0755 innernet-server-v2.0.0 /usr/bin/innernet-server
   /usr/bin/innernet-server --version
   ```

   The output must contain `innernet-server 2.0.0`.

2. Create the root-only state and request directories:

   ```sh
   install -d -o root -g root -m 0700 /etc/innernet-server
   install -d -o root -g root -m 0700 /var/lib/innernet-server
   install -d -o root -g root -m 0700 /var/lib/validator-vpn-coordinator/invitations
   install -d -o root -g root -m 0700 /run/validator-vpn-coordinator/add-peer
   ```

3. Initialize the innernet network once, as root, using the production
   interface name and approved CIDR plan. The `new` wizard is intentionally
   the only interactive step:

   ```sh
   /usr/bin/innernet-server \
     --config-dir /etc/innernet-server \
     --data-dir /var/lib/innernet-server \
     new
   ```

   Confirm that `/etc/innernet-server/<interface>.conf` and
   `/var/lib/innernet-server/<interface>.db` exist, are root-owned, and are
   mode `0600` or stricter. Do not copy private keys into the repository or
   request files.

4. Install the deployment assets:

   ```sh
   install -o root -g root -m 0644 deploy/validator-vpn-coordinator/innernet-server@.service \
     /etc/systemd/system/innernet-server@.service
   install -o root -g root -m 0644 deploy/validator-vpn-coordinator/innernet-server-add-peer@.service \
     /etc/systemd/system/innernet-server-add-peer@.service
   install -o root -g root -m 0755 deploy/validator-vpn-coordinator/validator-vpn-coordinator-add-peer.sh \
     /usr/local/libexec/validator-vpn-coordinator-add-peer
   install -o root -g root -m 0600 deploy/validator-vpn-coordinator/validator-vpn-coordinator.env.example \
     /etc/default/validator-vpn-coordinator
   systemctl daemon-reload
   systemctl enable innernet-server@<interface>.service
   ```

   Confirm `/etc/default/validator-vpn-coordinator` contains
   `SYNERGY_INNERNET_INVITE_EXPIRES=30m`. This is required because v2.0.0
   otherwise prompts for invite expiry during `add-peer`. The accepted shape
   is a positive integer followed by exactly one unit: `s`, `m`, `h`, `d`, or
   `w`; do not use `0m`, whitespace, or a quoted value.

5. Start the server and run readiness with the migration gate still closed:

   ```sh
   systemctl start innernet-server@<interface>.service
   SYNERGY_INNERNET_INTERFACE=<interface> \
     SYNERGY_INNERNET_MIGRATION_READY=false \
     scripts/testnet/validator-vpn-coordinator-readiness.sh
   ```

## Coordinator Add-Peer Trigger

The coordinator must create a root-owned request file with mode `0600` at
`/run/validator-vpn-coordinator/add-peer/<interface>.env`, containing only
validated values:

```dotenv
PEER_NAME=validator-7
PEER_CIDR=validators
PEER_INVITE_PATH=/var/lib/validator-vpn-coordinator/invitations/validator-7.toml
# Optional per-request override; otherwise the root-owned environment file's
# SYNERGY_INNERNET_INVITE_EXPIRES (recommended: 30m) is used.
# PEER_INVITE_EXPIRES=30m
```

The coordinator then triggers the oneshot as a system service:

```sh
systemctl start innernet-server-add-peer@<interface>.service
```

The wrapper supplies `--name`, `--auto-ip`, `--cidr`, `--admin=false`,
`--yes`, `--invite-expires`, and `--save-config`, so no stdin, prompt, or
operator terminal is needed. It validates names and the invite timestring and
keeps invitation output below the root-only invitation directory. Remove the request file after the result and deliver
the invitation through the existing secure handoff process.

## Migration Gate

Keep this setting exactly as shown until every existing validator has been
migrated, has redeemed the new invitation, and has acknowledged healthy
connectivity on the new interface:

```sh
SYNERGY_INNERNET_MIGRATION_READY=false
```

After the final peer migration and acknowledgment are recorded, run readiness
with `true`. That invocation must verify the root service, v2.0.0 binary, live
systemd service, initialized config/database, and initialized WireGuard
interface before the Control Panel treats the coordinator as ready:

```sh
SYNERGY_INNERNET_INTERFACE=<interface> \
SYNERGY_INNERNET_MIGRATION_READY=true \
scripts/testnet/validator-vpn-coordinator-readiness.sh
```

If any peer is still pending or an acknowledgment is missing, leave the flag
`false`; do not use a successful service start as a substitute for migration
completion.
