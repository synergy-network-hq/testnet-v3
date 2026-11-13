# Archive Validator Grafana/Prometheus Setup Commands

Run these commands on the Archive Validator machine after moving this folder there. The workbook row used for this bundle is `Archive Validator`: public IP `73.79.66.255`, local IP `192.168.11.140`, metrics `6030`, qRPC `5640`.

The Archive Validator is a Mac. The workbook does not list an SSH command for it, so use the Mac directly or whichever operator access path exists for that host.

If the archive runtime is not already installed, use the packaged macOS M4 archive bundle first:

```bash
cd /path/to/synergy-archive-validator-testnet-v3-macos-m4
sudo ./setup-archive-validator-m4.sh --public-host 73.79.66.255 --yes
sudo ./verify-archive-validator-m4.sh
```

Then apply the Grafana/Prometheus observability setup:

```bash
cd /path/to/archive-validator-observability
chmod 0755 install-archive-observability.sh
sudo ./install-archive-observability.sh \
  --node-config /Users/Shared/Synergy/archive-validator/workspace/config/node.toml
```

If the node config lives somewhere else, find it and rerun with the discovered path:

```bash
sudo find /Users/Shared /Volumes -name 'node.toml' 2>/dev/null
sudo ./install-archive-observability.sh --node-config /actual/path/node.toml
```

Verify locally on Archive Validator:

```bash
curl -fsS http://127.0.0.1:6030/metrics | head
curl -fsS http://127.0.0.1:9100/metrics | head
sudo lsof -nP -iTCP:5622 -iTCP:5640 -iTCP:6030 -iTCP:9100 -sTCP:LISTEN
```

Use launchd checks on macOS:

```bash
sudo launchctl print system/io.synergynetwork.archive-validator | head -40
sudo launchctl print system/io.prometheus.node-exporter | head -40
grep -n 'metrics_bind' /Users/Shared/Synergy/archive-validator/workspace/config/node.toml
```

Expected result:

- `127.0.0.1:6030` returns archive runtime metrics locally.
- `127.0.0.1:9100` returns node_exporter host metrics locally.
- From the Observer, Prometheus scrapes `73.79.66.255:6030`, `73.79.66.255:9100`, and probes `73.79.66.255:5640`.
- If the Archive Validator is behind NAT, forward public TCP ports `6030`, `9100`, and `5640` from `73.79.66.255` to the Archive Validator host. qRPC is optional for observability; if this archive package does not expose qRPC, Grafana will show qRPC unavailable while metrics and host panels still work.
