#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
masker = root / "template/opt/synergy/scripts/mask-validator-identity.py"

with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "identity.json"
    path.write_text(json.dumps({
        "validator_address": "synv11real",
        "private_key": "do-not-print",
        "public_key": "public-ok",
        "nested": {"rpc_token": "secret-token"}
    }))
    out = subprocess.check_output(["python3", str(masker), str(path)], text=True)
    assert "do-not-print" not in out
    assert "secret-token" not in out
    assert "MASKED_SECRET" in out
    assert "MASKED_IDENTITY" in out

print("mask identity ok")

