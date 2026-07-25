#!/usr/bin/env python3
"""Mask validator-specific and secret-bearing values from config-like files."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


SECRET_PATTERNS = re.compile(r"(private|secret|token|password|seed|mnemonic)", re.I)
IDENTITY_PATTERNS = re.compile(
    r"(validator_(name|index|id|address)|operator_address|reward_address|account_address|"
    r"public_ip|private_ip|hostname|peer_id|node_id|identity|advertise_addr|wireguard)",
    re.I,
)
PUBLIC_KEY_SAFE = re.compile(r"public_?key|consensus_public_key|node_identity_public_key", re.I)


def mask_key(key: str, value):
    if SECRET_PATTERNS.search(key):
        return "MASKED_SECRET"
    if IDENTITY_PATTERNS.search(key) and not PUBLIC_KEY_SAFE.search(key):
        return "MASKED_IDENTITY"
    return mask_value(value)


def mask_value(value):
    if isinstance(value, dict):
        return {k: mask_key(k, v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [mask_value(v) for v in value]
    return value


def mask_dotenv(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            lines.append(line)
            continue
        key, _value = line.split("=", 1)
        if SECRET_PATTERNS.search(key):
            lines.append(f"{key}=MASKED_SECRET")
        elif IDENTITY_PATTERNS.search(key):
            lines.append(f"{key}=MASKED_IDENTITY")
        else:
            lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def mask_toml_yamlish(text: str) -> str:
    output = []
    assignment = re.compile(r"^(\s*[-A-Za-z0-9_]+(?:\s*:\s*|\s*=\s*)).*$")
    for line in text.splitlines():
        stripped = line.strip()
        key = re.split(r"\s*[:=]\s*", stripped, maxsplit=1)[0] if (":" in stripped or "=" in stripped) else ""
        if key and SECRET_PATTERNS.search(key):
            output.append(assignment.sub(r"\1\"MASKED_SECRET\"", line))
        elif key and IDENTITY_PATTERNS.search(key) and not PUBLIC_KEY_SAFE.search(key):
            output.append(assignment.sub(r"\1\"MASKED_IDENTITY\"", line))
        else:
            output.append(line)
    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: mask-validator-identity.py <file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    text = path.read_text()
    suffix = path.suffix.lower()
    if suffix == ".json":
        print(json.dumps(mask_value(json.loads(text)), indent=2, sort_keys=True))
    elif suffix in {".env"} or path.name.endswith(".env"):
        print(mask_dotenv(text), end="")
    else:
        print(mask_toml_yamlish(text), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

