#!/usr/bin/env python3
"""Verify Synergy validator public P2P reachability and consensus movement.

This script never writes a report unless --output is explicitly supplied. It
does not SSH. Validator RPC/qRPC endpoints are intentionally caller-supplied so
the script does not assume that public P2P addresses expose JSON-RPC.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


VALIDATORS = [
    ("val1", "62.146.182.207", 5622, "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"),
    ("val2", "62.146.182.208", 5622, "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"),
    ("val3", "62.146.182.209", 5622, "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"),
    ("val4", "73.79.66.255", 5622, "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5"),
    ("val5", "194.163.183.166", 5622, "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f"),
    ("val6", "157.173.192.45", 5622, "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx"),
]

HEIGHT_METHODS = [
    ("synergy_getBlockNumber", []),
    ("synergy_blockNumber", []),
    ("synergy_getLatestBlock", []),
    ("eth_blockNumber", []),
]

PEER_METHODS = [
    ("synergy_peers", []),
    ("synergy_peerCount", []),
    ("net_peerCount", []),
]


@dataclass
class Check:
    status: str
    name: str
    detail: str


def parse_validator_rpc(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    valid_names = {name for name, _, _, _ in VALIDATORS}
    for value in values:
        if "=" not in value:
            raise argparse.ArgumentTypeError(
                f"validator RPC must use NAME=URL, got {value!r}"
            )
        name, url = value.split("=", 1)
        name = name.strip().lower()
        if name not in valid_names:
            raise argparse.ArgumentTypeError(
                f"unknown validator {name!r}; expected one of {sorted(valid_names)}"
            )
        parsed[name] = url.strip()
    return parsed


def tcp_check(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "reachable"
    except OSError as exc:
        return False, str(exc)


def rpc_call(url: str, method: str, params: list[Any], timeout: float) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if "error" in payload and payload["error"]:
        raise RuntimeError(payload["error"])
    return payload.get("result")


def parse_height(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not a height")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    if isinstance(value, dict):
        for key in (
            "height",
            "block_height",
            "blockNumber",
            "block_number",
            "number",
            "latest_height",
        ):
            if key in value:
                return parse_height(value[key])
        if "header" in value:
            return parse_height(value["header"])
        if "block" in value:
            return parse_height(value["block"])
    raise ValueError(f"could not parse block height from {value!r}")


def fetch_height(url: str, timeout: float) -> tuple[int | None, str]:
    errors: list[str] = []
    for method, params in HEIGHT_METHODS:
        try:
            return parse_height(rpc_call(url, method, params, timeout)), method
        except Exception as exc:  # noqa: BLE001 - report all method failures
            errors.append(f"{method}: {exc}")
    return None, "; ".join(errors)


def fetch_peer_summary(url: str, timeout: float) -> str:
    for method, params in PEER_METHODS:
        try:
            result = rpc_call(url, method, params, timeout)
        except Exception:
            continue
        if isinstance(result, list):
            return f"{method} returned {len(result)} peers"
        if isinstance(result, str):
            return f"{method} returned {result}"
        if isinstance(result, int):
            return f"{method} returned {result}"
        return f"{method} returned {type(result).__name__}"
    return "peer RPC not available"


def collect_sample(
    label: str, rpc_urls: dict[str, str], timeout: float, checks: list[Check]
) -> dict[str, int]:
    sample: dict[str, int] = {}
    for name, url in sorted(rpc_urls.items()):
        height, source = fetch_height(url, timeout)
        if height is None:
            checks.append(Check("FAIL", f"{label} {name} height", source))
        else:
            sample[name] = height
            checks.append(Check("PASS", f"{label} {name} height", f"{height} via {source}"))
    return sample


def render_text(
    checks: list[Check],
    samples: dict[str, dict[str, int]],
    peer_summaries: dict[str, str],
    args: argparse.Namespace,
) -> str:
    lines = [
        "Synergy validator consensus verification",
        f"interval_seconds={args.interval}",
        f"height_tolerance={args.height_tolerance}",
        f"min_responsive={args.min_responsive}",
        f"output={args.output or 'stdout'}",
        "",
        "== Checks ==",
    ]
    for check in checks:
        lines.append(f"{check.status} {check.name}: {check.detail}")
    lines.extend(["", "== Height samples =="])
    for label in ("h1", "h2", "h3"):
        values = samples.get(label, {})
        rendered = ", ".join(f"{name}={height}" for name, height in sorted(values.items()))
        lines.append(f"{label}: {rendered or 'none'}")
    lines.extend(["", "== Peer RPC summaries =="])
    for name, summary in sorted(peer_summaries.items()):
        lines.append(f"{name}: {summary}")
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
    parser.add_argument(
        "--validator-rpc",
        action="append",
        default=[],
        metavar="NAME=URL",
        help="Validator RPC/qRPC URL. Repeat for val1 through val6 as available.",
    )
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--height-tolerance", type=int, default=5)
    parser.add_argument("--min-responsive", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--tcp-timeout", type=float, default=3.0)
    parser.add_argument("--skip-height-wait", action="store_true")
    parser.add_argument("--require-validator-status", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to PATH. Defaults to stdout.")
    args = parser.parse_args()

    checks: list[Check] = []
    samples: dict[str, dict[str, int]] = {}
    peer_summaries: dict[str, str] = {}
    rpc_urls = parse_validator_rpc(args.validator_rpc)

    for name, host, port, _address in VALIDATORS:
        ok, detail = tcp_check(host, port, args.tcp_timeout)
        checks.append(
            Check(
                "PASS" if ok else "FAIL",
                f"{name} public P2P {host}:{port}",
                detail,
            )
        )

    if len(rpc_urls) < args.min_responsive:
        checks.append(
            Check(
                "FAIL",
                "validator RPC coverage",
                (
                    f"{len(rpc_urls)} RPC URLs supplied; need at least "
                    f"{args.min_responsive}. Use --validator-rpc valN=URL."
                ),
            )
        )
    else:
        checks.append(
            Check(
                "PASS",
                "validator RPC coverage",
                f"{len(rpc_urls)} RPC URLs supplied",
            )
        )

    if rpc_urls:
        samples["h1"] = collect_sample("h1", rpc_urls, args.timeout, checks)
        if not args.skip_height_wait:
            time.sleep(args.interval)
        samples["h2"] = collect_sample("h2", rpc_urls, args.timeout, checks)
        if not args.skip_height_wait:
            time.sleep(args.interval)
        samples["h3"] = collect_sample("h3", rpc_urls, args.timeout, checks)

        common = set(samples["h1"]).intersection(samples["h3"])
        if len(common) < args.min_responsive:
            checks.append(
                Check(
                    "FAIL",
                    "chain movement coverage",
                    f"{len(common)} validators had both h1 and h3 samples",
                )
            )
        else:
            moved = [
                name
                for name in common
                if samples["h3"][name] > samples["h1"][name]
            ]
            if len(moved) >= args.min_responsive:
                checks.append(
                    Check(
                        "PASS",
                        "chain movement",
                        f"{len(moved)} validators advanced from h1 to h3",
                    )
                )
            else:
                checks.append(
                    Check(
                        "FAIL",
                        "chain movement",
                        f"only {len(moved)} validators advanced from h1 to h3",
                    )
                )

        last = samples["h3"]
        if len(last) >= args.min_responsive:
            low = min(last.values())
            high = max(last.values())
            if high - low <= args.height_tolerance:
                checks.append(
                    Check(
                        "PASS",
                        "height convergence",
                        f"spread={high - low}, tolerance={args.height_tolerance}",
                    )
                )
            else:
                checks.append(
                    Check(
                        "FAIL",
                        "height convergence",
                        f"spread={high - low}, tolerance={args.height_tolerance}",
                    )
                )

        for name, url in sorted(rpc_urls.items()):
            peer_summaries[name] = fetch_peer_summary(url, args.timeout)

    if args.require_validator_status:
        checks.append(
            Check(
                "FAIL",
                "validator participation status",
                "no stable validator-status RPC method is encoded; verify with the runtime-specific RPC and extend this script if needed",
            )
        )
    else:
        checks.append(
            Check(
                "SKIP",
                "validator participation status",
                "pass --require-validator-status after wiring the runtime-specific status RPC method",
            )
        )

    failed = any(check.status == "FAIL" for check in checks)
    if args.format == "json":
        report = json.dumps(
            {
                "checks": [check.__dict__ for check in checks],
                "samples": samples,
                "peer_summaries": peer_summaries,
                "failed": failed,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    else:
        report = render_text(checks, samples, peer_summaries, args)
    write_report(report, args.output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
