#!/usr/bin/env python3
"""Verify Synergy seed registry public peer output.

The script defaults to stdout and writes a report only when --output is
provided. By default it performs read-only GET checks. The private-endpoint
rejection probe is opt-in because it sends a POST request.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_SEEDS = [
    "http://seed1.synergynode.xyz:5621",
    "http://seed2.synergynode.xyz:5621",
    "http://seed3.synergynode.xyz:5621",
]

EXPECTED_PUBLIC_RELAYS = {
    "relay1.synergynode.xyz:5622",
    "relay2.synergynode.xyz:5622",
    "relay3.synergynode.xyz:5622",
}

ROLE_FILTERS = [
    "validator",
    "relayer",
    "observer",
    "rpc_gateway",
    "archive_validator",
    "explorer_indexer",
]


@dataclass
class Check:
    status: str
    name: str
    detail: str


def url_join(base: str, path: str) -> str:
    return base.rstrip("/") + path


def http_get(url: str, timeout: float) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url, headers={"Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read(), response.headers.get("Content-Type", "")


def http_post_json(url: str, payload: dict[str, Any], timeout: float) -> tuple[int, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = body
        return exc.code, parsed


def parse_json(body: bytes) -> Any:
    return json.loads(body.decode("utf-8"))


def iter_peer_objects(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("peers", "items", "registry", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return list(value.values())
        if all(isinstance(value, dict) for value in payload.values()):
            return list(payload.values())
    return []


def iter_registry_objects(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    registry = payload.get("registry")
    if not isinstance(registry, list):
        return []
    return [record for record in registry if isinstance(record, dict)]


def extract_endpoint(peer: Any) -> str | None:
    if isinstance(peer, str):
        return normalize_endpoint(peer)
    if not isinstance(peer, dict):
        return None
    for key in (
        "public_endpoint",
        "dial",
        "endpoint",
        "address",
        "addr",
        "public_address",
        "public_p2p_address",
    ):
        value = peer.get(key)
        if isinstance(value, str) and value.strip():
            return normalize_endpoint(value)
    host = peer.get("host") or peer.get("public_host")
    port = peer.get("port") or peer.get("listen_port") or peer.get("public_port")
    if host and port:
        return normalize_endpoint(f"{host}:{port}")
    return None


def normalize_endpoint(endpoint: str) -> str:
    text = endpoint.strip()
    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        if parsed.hostname and parsed.port:
            return f"{parsed.hostname}:{parsed.port}"
        if parsed.netloc:
            return parsed.netloc.rsplit("@", 1)[-1]
    if "@" in text:
        text = text.rsplit("@", 1)[-1]
    return text.strip("/")


def endpoint_host(endpoint: str) -> str:
    text = normalize_endpoint(endpoint)
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")]
    if text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


def is_private_endpoint(endpoint: str) -> bool:
    host = endpoint_host(endpoint).lower()
    if host in {"localhost", "0.0.0.0"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def peer_endpoints(payload: Any) -> set[str]:
    endpoints: set[str] = set()
    for peer in iter_peer_objects(payload):
        endpoint = extract_endpoint(peer)
        if endpoint:
            endpoints.add(endpoint)
    return endpoints


def render_text(checks: list[Check], seed_sets: dict[str, set[str]], output: str | None) -> str:
    lines = [
        "Synergy seed registry verification",
        f"output={output or 'stdout'}",
        "",
        "== Checks ==",
    ]
    for check in checks:
        lines.append(f"{check.status} {check.name}: {check.detail}")
    lines.extend(["", "== Seed endpoint sets =="])
    for seed, endpoints in sorted(seed_sets.items()):
        lines.append(f"{seed}:")
        for endpoint in sorted(endpoints):
            lines.append(f"  {endpoint}")
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
    parser.add_argument("--seed-url", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument(
        "--require-archive",
        action="store_true",
        help="Deprecated fail-closed flag; archive nodes must not be advertised by public bootstrap.",
    )
    parser.add_argument("--probe-private-rejection", action="store_true")
    parser.add_argument("--chain-id", default="synergy-testnet")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", help="Write report to PATH. Defaults to stdout.")
    args = parser.parse_args()

    if args.require_archive:
        print(
            "--require-archive is incompatible with the relayer-only public registry; verify archive readiness through the signed snapshot catalog instead",
            file=sys.stderr,
        )
        return 2

    seeds = args.seed_url or DEFAULT_SEEDS
    checks: list[Check] = []
    seed_sets: dict[str, set[str]] = {}
    role_sets: dict[str, dict[str, set[str]]] = {}
    registry_records: dict[str, list[dict[str, Any]]] = {}

    for seed in seeds:
        seed_sets[seed] = set()
        role_sets[seed] = {}
        registry_records[seed] = []

        for path in ("/health", "/metrics", "/peer-list.json", "/peers"):
            url = url_join(seed, path)
            try:
                status, body, content_type = http_get(url, args.timeout)
                checks.append(Check("PASS", f"{seed} {path}", f"HTTP {status}"))
                if path in {"/peer-list.json", "/peers"}:
                    payload = parse_json(body)
                    seed_sets[seed].update(peer_endpoints(payload))
                    if path == "/peer-list.json":
                        registry_records[seed] = iter_registry_objects(payload)
            except Exception as exc:  # noqa: BLE001 - report endpoint failures
                checks.append(Check("FAIL", f"{seed} {path}", str(exc)))

        for role in ROLE_FILTERS:
            url = url_join(seed, f"/peers?role={urllib.parse.quote(role)}")
            try:
                status, body, _content_type = http_get(url, args.timeout)
                payload = parse_json(body)
                endpoints = peer_endpoints(payload)
                objects = iter_peer_objects(payload)
                invalid_roles = [
                    peer
                    for peer in objects
                    if not isinstance(peer, dict)
                    or str(peer.get("role", "")).strip().lower() != role
                ]
                role_sets[seed][role] = endpoints
                checks.append(
                    Check(
                        "FAIL" if invalid_roles else "PASS",
                        f"{seed} role filter {role}",
                        f"HTTP {status}, endpoints={len(endpoints)}"
                        if not invalid_roles
                        else f"role filter returned {len(invalid_roles)} mislabeled or endpoint-only records",
                    )
                )
                seed_sets[seed].update(endpoints)
            except Exception as exc:  # noqa: BLE001
                checks.append(Check("FAIL", f"{seed} role filter {role}", str(exc)))

        private = sorted(endpoint for endpoint in seed_sets[seed] if is_private_endpoint(endpoint))
        if private:
            checks.append(
                Check(
                    "FAIL",
                    f"{seed} public endpoint hygiene",
                    "private/VPN/local endpoints advertised: " + ", ".join(private),
                )
            )
        else:
            checks.append(Check("PASS", f"{seed} public endpoint hygiene", "no private endpoints advertised"))

        if seed_sets[seed] != EXPECTED_PUBLIC_RELAYS:
            checks.append(
                Check(
                    "FAIL",
                    f"{seed} relayer-only bootstrap",
                    f"expected={sorted(EXPECTED_PUBLIC_RELAYS)}, actual={sorted(seed_sets[seed])}",
                )
            )
        else:
            checks.append(Check("PASS", f"{seed} relayer-only bootstrap", "all three relayers and no direct validator or service-node targets"))

        non_relayer_roles = {
            role: sorted(endpoints)
            for role, endpoints in role_sets[seed].items()
            if role != "relayer" and endpoints
        }
        checks.append(Check(
            "FAIL" if non_relayer_roles else "PASS",
            f"{seed} direct topology isolation",
            f"unexpected public role endpoints: {non_relayer_roles}" if non_relayer_roles else "validator and service-node records are not public dial targets",
        ))

        advertised_registry = {
            (extract_endpoint(record), str(record.get("role", "")).strip().lower())
            for record in registry_records[seed]
            if extract_endpoint(record)
        }
        expected_registry = {(endpoint, "relayer") for endpoint in EXPECTED_PUBLIC_RELAYS}
        checks.append(
            Check(
                "PASS" if advertised_registry == expected_registry else "FAIL",
                f"{seed} registry role integrity",
                "all advertised records are canonical relayers"
                if advertised_registry == expected_registry
                else f"expected={sorted(expected_registry)}, actual={sorted(advertised_registry)}",
            )
        )

        if args.probe_private_rejection:
            payload = {
                "chain_id": args.chain_id,
                "role": "validator",
                "validator_address": "synv1privateprobe000000000000000000000000000",
                "peer_id": "private-endpoint-probe",
                "public_endpoint": "10.69.0.99:5622",
                "protocol_version": "probe",
                "app_version": "probe",
                "current_height": 0,
                "timestamp": "1970-01-01T00:00:00Z",
            }
            try:
                status, response = http_post_json(url_join(seed, "/register"), payload, args.timeout)
                accepted = isinstance(response, dict) and response.get("accepted") is True
                if status >= 400 or not accepted:
                    checks.append(Check("PASS", f"{seed} private endpoint rejection", f"HTTP {status}"))
                else:
                    checks.append(Check("FAIL", f"{seed} private endpoint rejection", f"accepted response: {response!r}"))
            except Exception as exc:  # noqa: BLE001
                checks.append(Check("FAIL", f"{seed} private endpoint rejection", str(exc)))
        else:
            checks.append(
                Check(
                    "SKIP",
                    f"{seed} private endpoint rejection",
                    "read-only mode; pass --probe-private-rejection to send POST /register probe",
                )
            )

    if len(seed_sets) > 1:
        values = list(seed_sets.items())
        base_name, base_set = values[0]
        converged = True
        details: list[str] = []
        for name, endpoints in values[1:]:
            if endpoints != base_set:
                converged = False
                details.append(
                    f"{name} differs from {base_name}: missing={sorted(base_set - endpoints)}, extra={sorted(endpoints - base_set)}"
                )
        checks.append(
            Check(
                "PASS" if converged else "FAIL",
                "seed convergence",
                "all seed endpoint sets match" if converged else "; ".join(details),
            )
        )

    failed = any(check.status == "FAIL" for check in checks)
    if args.format == "json":
        report = json.dumps(
            {
                "checks": [check.__dict__ for check in checks],
                "seed_endpoint_sets": {
                    seed: sorted(endpoints) for seed, endpoints in seed_sets.items()
                },
                "failed": failed,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    else:
        report = render_text(checks, seed_sets, args.output)
    write_report(report, args.output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
