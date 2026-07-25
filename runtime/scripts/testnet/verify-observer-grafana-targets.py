#!/usr/bin/env python3
"""Verify observer monitoring target coverage and optional Prometheus/Grafana health.

Reports are written only when --output is explicitly supplied; otherwise the
report is printed to stdout.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_CONFIG = REPO_ROOT / "ops" / "observability" / "prometheus.observer.yml"

EXPECTED_MONITORING_TARGETS = [
    "bootnode1.synergynode.xyz:5620",
    "bootnode2.synergynode.xyz:5620",
    "bootnode3.synergynode.xyz:5620",
    "seed1.synergynode.xyz:5621",
    "seed2.synergynode.xyz:5621",
    "seed3.synergynode.xyz:5621",
    "relay1.synergynode.xyz:5622",
    "relay2.synergynode.xyz:5622",
    "rpc.synergynode.xyz:5623",
    "testnet-core-rpc.synergy-network.io",
    "archive.synergynode.xyz:5615",
    "62.146.182.207:5622",
    "62.146.182.208:5622",
    "62.146.182.209:5622",
    "73.79.66.255:5622",
    "194.163.183.166:5622",
    "157.173.192.45:5622",
    "74.208.227.23",
]

OBSERVER_P2P = ("209.145.50.9", 5622)

PRIVATE_TARGET_RE = re.compile(
    r"(10\.69\.|10\.\d+\.\d+\.\d+:5622|192\.168\.\d+\.\d+:5622|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+:5622|127\.0\.0\.1:5622|localhost:5622)"
)


@dataclass
class Check:
    status: str
    name: str
    detail: str


def tcp_check(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "reachable"
    except OSError as exc:
        return False, str(exc)


def fetch_json(url: str, timeout: float) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_text(url: str, timeout: float) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def prometheus_targets_url(base: str) -> str:
    return base.rstrip("/") + "/api/v1/targets"


def grafana_health_url(base: str) -> str:
    return base.rstrip("/") + "/api/health"


def render_text(checks: list[Check], output: str | None) -> str:
    lines = [
        "Synergy observer/Grafana target verification",
        f"output={output or 'stdout'}",
        "",
        "== Checks ==",
    ]
    for check in checks:
        lines.append(f"{check.status} {check.name}: {check.detail}")
    passed = sum(1 for check in checks if check.status == "PASS")
    failed = sum(1 for check in checks if check.status == "FAIL")
    skipped = sum(1 for check in checks if check.status == "SKIP")
    lines.extend(["", f"Summary: pass={passed} fail={failed} skip={skipped}"])
    return "\n".join(lines) + "\n"


def write_report(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--prometheus-url")
    parser.add_argument("--grafana-url")
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--require-live-pipeline", action="store_true")
    parser.add_argument("--allow-private-monitoring", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to PATH. Defaults to stdout.")
    args = parser.parse_args()

    checks: list[Check] = []
    config_path = Path(args.config)

    if config_path.exists():
        text = config_path.read_text(encoding="utf-8", errors="replace")
        checks.append(Check("PASS", "observer config readable", str(config_path)))
        for target in EXPECTED_MONITORING_TARGETS:
            if target in text:
                checks.append(Check("PASS", f"config target {target}", "present"))
            else:
                checks.append(Check("FAIL", f"config target {target}", "missing"))
        private_matches = sorted(set(PRIVATE_TARGET_RE.findall(text)))
        if private_matches and not args.allow_private_monitoring:
            checks.append(
                Check(
                    "FAIL",
                    "observer private target hygiene",
                    "private/VPN public-P2P target strings present: " + ", ".join(private_matches),
                )
            )
        elif private_matches:
            checks.append(
                Check(
                    "SKIP",
                    "observer private target hygiene",
                    "private targets allowed by --allow-private-monitoring",
                )
            )
        else:
            checks.append(Check("PASS", "observer private target hygiene", "no private public-P2P targets found"))
        if "10.69.0.250" in text:
            checks.append(Check("FAIL", "observer public P2P address", "stale 10.69.0.250 reference present"))
        else:
            checks.append(Check("PASS", "observer public P2P address", "no stale 10.69.0.250 reference"))
    else:
        checks.append(Check("FAIL", "observer config readable", f"missing {config_path}"))

    ok, detail = tcp_check(OBSERVER_P2P[0], OBSERVER_P2P[1], args.timeout)
    checks.append(
        Check(
            "PASS" if ok else "FAIL",
            f"observer public P2P {OBSERVER_P2P[0]}:{OBSERVER_P2P[1]}",
            detail,
        )
    )

    if args.prometheus_url:
        try:
            payload = fetch_json(prometheus_targets_url(args.prometheus_url), args.timeout)
            rendered = json.dumps(payload, sort_keys=True)
            checks.append(Check("PASS", "Prometheus targets API", "reachable"))
            for target in EXPECTED_MONITORING_TARGETS:
                if target in rendered:
                    checks.append(Check("PASS", f"Prometheus target {target}", "present"))
                else:
                    checks.append(Check("FAIL", f"Prometheus target {target}", "missing"))
            down_count = rendered.count('"health": "down"') + rendered.count('"health":"down"')
            if down_count:
                checks.append(Check("FAIL", "Prometheus target health", f"{down_count} down targets reported"))
            else:
                checks.append(Check("PASS", "Prometheus target health", "no down targets in API response"))
        except Exception as exc:  # noqa: BLE001
            checks.append(Check("FAIL", "Prometheus targets API", str(exc)))
    elif args.require_live_pipeline:
        checks.append(Check("FAIL", "Prometheus targets API", "missing --prometheus-url"))
    else:
        checks.append(Check("SKIP", "Prometheus targets API", "pass --prometheus-url to check live pipeline"))

    if args.grafana_url:
        try:
            text = fetch_text(grafana_health_url(args.grafana_url), args.timeout)
            if "ok" in text.lower() or "database" in text.lower():
                checks.append(Check("PASS", "Grafana health API", "reachable"))
            else:
                checks.append(Check("FAIL", "Grafana health API", f"unexpected response: {text[:200]}"))
        except Exception as exc:  # noqa: BLE001
            checks.append(Check("FAIL", "Grafana health API", str(exc)))
    elif args.require_live_pipeline:
        checks.append(Check("FAIL", "Grafana health API", "missing --grafana-url"))
    else:
        checks.append(Check("SKIP", "Grafana health API", "pass --grafana-url to check live pipeline"))

    failed = any(check.status == "FAIL" for check in checks)
    if args.format == "json":
        report = json.dumps(
            {"checks": [check.__dict__ for check in checks], "failed": failed},
            indent=2,
            sort_keys=True,
        ) + "\n"
    else:
        report = render_text(checks, args.output)
    write_report(report, args.output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
