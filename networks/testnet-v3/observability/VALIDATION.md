# Observability Validation

Run these checks from the repository root. They validate the staged observer
configuration only; they do not use SSH and do not mutate any live host.

## Static checks

```sh
cd /Volumes/xcode/Synergy-Network-Projects
OBS=network-components/01-Testnet/observability

# Retired private topology must not occur anywhere in the owned observability tree.
legacy_subnet="$(printf '10.%s.' 69)"
if rg -n "$legacy_subnet" "$OBS"; then exit 1; fi

# Canonical Innernet inventory must include every validator and relayer.
rg -n '10\.70\.10\.[1-6]|10\.70\.20\.[1-3]' "$OBS/TARGET_INVENTORY.md"

# The observer config may not dial validator Innernet addresses directly.
if rg -n 'targets:.*10\.70\.10\.|- 10\.70\.10\.' "$OBS/live-config-after/observer"; then exit 1; fi
```

## Prometheus checks

If `promtool` is installed locally:

```sh
promtool check config "$OBS/live-config-after/observer/prometheus/prometheus.yml"
promtool check rules "$OBS/live-config-after/observer/rules/synergy-canonical-rules.yml" \
  "$OBS/live-config-after/observer/rules/synergy-alerts.yml"
```

The deployed observer equivalent is:

```sh
promtool check config /opt/prometheus/config/prometheus.yml
promtool check rules /opt/prometheus/config/rules/*.yml
```

After an approved deployment, verify `/api/v1/targets` and confirm that every
validator target has `telemetry_path=relayer-*-proxy`, every relayer/service
target has an appropriate `public*` telemetry path, and no target contains
`10.70.10.`.

## Coverage acceptance

- Six validator application metrics, qRPC, and node_exporter proxy targets.
- Three relayer qRPC and node_exporter targets. Relayer application metrics on
  `:6030` are currently not published and are intentionally not scraped.
- Public exporter targets for RPC, Explorer/indexer, and the website/coordinator
  host when those HTTPS routes are published.
- RPC gateway native application metrics, Atlas API exporter, archive snapshot
  probe, observer application metrics, and observer PoSy collector targets.
- Website and validator-VPN coordinator HTTPS health probes.
- All six boot/seed service TCP probes.
- Stale finalized/local data, target-down, qRPC-down, HTTP-down, exporter-down,
  height-gap, quorum, CPU, memory, and disk alerts.

No live SSH change is part of this validation. Connectivity failures after
deployment are evidence about the route contract or exporter state and must
not be fixed by adding direct validator Innernet targets to Prometheus.

## Local deployment artifact

The local-only helper cross-checks the proxy allocation manifest against every
validator app, qRPC, and node-exporter target. It never invokes SSH,
`systemctl`, or a remote deployment:

```sh
OBS=network-components/01-Testnet/observability
"$OBS/scripts/deploy_observability.sh" validate
"$OBS/scripts/deploy_observability.sh" plan
"$OBS/scripts/deploy_observability.sh" stage /tmp/synergy-observability-stage
```

`stage` is repeatable and overwrites only matching artifact files. The staged
bundle contains the observer Prometheus config, all rule files, the proxy
contract, and a deterministic deployment plan. It does not delete unrelated
files or apply changes to `/opt/prometheus`.
