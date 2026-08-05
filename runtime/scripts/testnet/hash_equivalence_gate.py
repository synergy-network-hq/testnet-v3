#!/usr/bin/env python3
"""Cross-language hash gate.

Proves Python `genesis_tool.hash_json` is byte-identical to Rust
`genesis.rs::hash_json` (blake3 over canonical_json) by recomputing digests
that the RUST recompute path already pinned into the canonical Genesis.
Also runs a fixed golden vector covering unicode, floats, ints, escapes,
empty containers and key ordering.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from genesis_tool import canonical_json, hash_json  # noqa: E402

HERE = Path(__file__).resolve().parents[3]
GENESIS = HERE / "launch/production-node-configs/canonical-genesis/genesis.json"

# ---- 1. fixed golden vector -------------------------------------------------
GOLDEN = {
    "zebra": 1,
    "alpha": [1, 2, 3],
    "nested": {"b": True, "a": None, "c": False},
    "unicode": "Synergy — téstnet ✓",
    "escaped": "quote\" backslash\\ newline\n tab\t",
    "float": 1.5,
    "negative": -42,
    "big": 50000000000000,
    "empty_obj": {},
    "empty_arr": [],
    "empty_str": "",
}
GOLDEN_CANON = canonical_json(GOLDEN)
GOLDEN_HASH = hash_json(GOLDEN)

# ---- 2. digests the Rust recompute path pinned into Genesis ----------------
doc = json.loads(GENESIS.read_text())
integrity = doc["integrity"]

checks = [
    ("integrity.allocation_hash", integrity["allocation_hash"],
     hash_json(doc["allocations"])),
    ("integrity.validator_hash", integrity["validator_hash"],
     hash_json(doc["validators"])),
    ("integrity.contract_hash", integrity["contract_hash"],
     hash_json(doc["contracts"])),
    ("integrity.validator_set_hash", integrity["validator_set_hash"],
     hash_json(doc["contracts"]["validator_registry"]["init_params"]["validators"])),
]

# validator entry 0 key_bundle_hash, per genesis_tool.py derivation
v0 = doc["validators"][0]
checks.append((
    "validators[0].key_bundle_hash", v0["key_bundle_hash"],
    hash_json({
        "account_public_key": v0["account_public_key"],
        "consensus_public_key": v0["consensus_public_key"],
        "identity_public_key": v0["identity_public_key"],
        "node_identity_public_key": v0["node_identity_key"],
        "peer_id": v0["peer_id"],
    }),
))
checks.append((
    "validators[0].validator_id_hash", v0["validator_id_hash"],
    hash_json({"validator_id": v0["validator_id"]}),
))

# ---- 3. full genesis_hash via the Rust payload rules -----------------------
def genesis_hash_payload(value):
    canon = value.get("canonicalization", {})
    inputs = canon.get("genesis_hash_inputs")
    payload = {k: value[k] for k in inputs if k in value} if inputs else dict(value)
    excluded = list(canon.get("excluded_from_genesis_hash", [])) + [
        "integrity.genesis_hash", "integrity.signed_by",
        "integrity.draft_artifact_sha256", "integrity.recompute_required",
        "integrity.recompute_reason", "p2p_identity.network_magic_bytes",
        "p2p_identity.provisional_derivation_note",
    ]
    for path in sorted(set(excluded)):
        parts = path.split(".")
        cur = payload
        for part in parts[:-1]:
            if not isinstance(cur, dict) or part not in cur:
                cur = None
                break
            cur = cur[part]
        if isinstance(cur, dict):
            cur.pop(parts[-1], None)
    return payload

import copy  # noqa: E402
checks.append((
    "integrity.genesis_hash", integrity["genesis_hash"],
    hash_json(genesis_hash_payload(copy.deepcopy(doc))),
))

# ---- report ----------------------------------------------------------------
print("GOLDEN_VECTOR_CANONICAL_BYTES:")
print("  " + GOLDEN_CANON)
print("  utf8_len=%d blake3=%s" % (len(GOLDEN_CANON.encode()), GOLDEN_HASH))
print()
ok = True
for label, pinned, computed in checks:
    match = pinned == computed
    ok = ok and match
    print("%-34s %s" % (label, "MATCH" if match else "MISMATCH"))
    if not match:
        print("   pinned(rust) = %s" % pinned)
        print("   computed(py) = %s" % computed)
print()
print("HASH_EQUIVALENCE_GATE", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
