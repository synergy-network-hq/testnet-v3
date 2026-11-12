#!/usr/bin/env python3
"""Check or apply a pinned Canary transport bundle on one stopped validator."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import time

# These imports can resolve to a sealed live package during a read-only check.
sys.dont_write_bytecode = True

from apqe_layout import PUBLIC
from lifecycle import (
    UPGRADE_INTENT, UNITS, _assert_no_application_processes,
    _attributed_units, _lifecycle_lock, _reject_installation_mounts, _replace_bytes,
    _require_operator, _sealed_receipt, _sync_directory,
)
from synergy_linux import native, require, safe_root

REPLACEMENT_INTENT = "evidence/application-replacement-intent.json"
TRANSPORT = ("transport-root.pub", "transport-registry.json")
CONFIG = ("config/node.json", "config/start-authorized.json")
NETWORK = "posy-apqe-canary-process-49028"
FLEET = {f"Val{n}" for n in range(2, 7)}
PACKAGE = "f92011f14b407754282facd51705aaa0b5a4c688d00c911dd38f593e2b411eab"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def checked_read(path, maximum, owned=False):
    for member in (path, *path.parents):
        require(not member.is_symlink(), f"symlink refused: {member}")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= maximum
            and (not owned or metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o600),
            f"unsafe rotation input: {path}")
    return path.read_bytes()


def bundle(path, expected):
    data = checked_read(path, 512 * 1024)
    require(re.fullmatch(r"[0-9a-f]{64}", expected) and sha(data) == expected,
            "rotation bundle differs from the independently approved digest")
    allowed = {"review.json"} | {f"network/{name}" for name in TRANSPORT} | {
        f"{node}/{config}" for node in FLEET for config in CONFIG
    }
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for member in tar:
            require(member.name in allowed and member.name not in files and member.isfile()
                    and 0 < member.size <= 128 * 1024, "unexpected rotation bundle member")
            files[member.name] = tar.extractfile(member).read()
    require(set(files) == allowed, "incomplete rotation bundle")
    review = json.loads(files.pop("review.json"))
    require(review.get("format") == "synergy-canary-transport-rotation-review-v1"
            and review.get("activation_authorized") is False
            and review.get("chain_id") == 99999 and review.get("network_id") == NETWORK
            and type(review.get("generation")) is int and review["generation"] >= 2
            and set(review.get("nodes", {})) == FLEET
            and review.get("native_offline_preflight_count") == len(FLEET)
            and review.get("files") == {name: sha(body) for name, body in files.items()}
            and review.get("expires_at_unix", 0) > int(time.time()),
            "rotation review scope, file pins or validity differ")
    return review, files


def changes(root, review, files, resumed):
    public = ("validator.pub.json", "enrollment.json")
    identity = json.loads(checked_read(root/"keys/apqe"/public[0], 128 * 1024, True))
    matches = [node for node in FLEET if review["nodes"][node]["node_address"] == identity["node_address"]]
    require(len(matches) == 1, "installed identity does not identify exactly one reviewed validator")
    node = matches[0]
    plan = review["nodes"][node]
    network = set(PUBLIC) - set(TRANSPORT)
    require(set(plan["unchanged_network_sha256"]) == network
            and set(plan["unchanged_validator_public_sha256"]) == set(public),
            "incomplete preserved network or identity pins")
    for prefix, pins in (("network", plan["unchanged_network_sha256"]),
                         ("keys/apqe", plan["unchanged_validator_public_sha256"])):
        for name, expected in pins.items():
            require(sha(checked_read(root/prefix/name, 4 * 1024 * 1024, True)) == expected,
                    f"preserved input differs: {prefix}/{name}")
    old = review["old_transport_sha256"]
    new = review["new_transport_sha256"]
    require(set(old) == set(new) == set(TRANSPORT) and old[TRANSPORT[1]] != new[TRANSPORT[1]]
            and new == {name: sha(files[f"network/{name}"]) for name in TRANSPORT}
            and set(plan["old_file_sha256"]) == set(CONFIG),
            "rotation file pin scope differs")
    current = {rel: checked_read(root/rel, 128 * 1024, True)
               for rel in (*(f"network/{name}" for name in TRANSPORT), *CONFIG)}
    proposed = {rel: files[rel] if rel.startswith("network/") else files[f"{node}/{rel}"]
                for rel in current}
    old_pins = {**{f"network/{name}": value for name, value in old.items()}, **plan["old_file_sha256"]}
    actual = {rel: sha(data) for rel, data in current.items()}
    already = all(data == proposed[rel] for rel, data in current.items())
    require(already or all(value == old_pins[rel] or resumed and current[rel] == proposed[rel]
                           for rel, value in actual.items()), "installed rotation files differ from the reviewed base")
    for rel, field in zip(CONFIG, ("apqe_transport", "public_file_sha256")):
        value = json.loads(current[rel])
        if field == "apqe_transport":
            value[field]["registry_trust_key_sha256"] = new[TRANSPORT[0]]
        else:
            value[field].update(new)
        require(value == json.loads(proposed[rel]), f"rotation proposes unrelated changes: {rel}")
    registry_path = "network/transport-registry.json"
    before, after = [json.loads(value[registry_path])["payload"] for value in (current, proposed)]
    excluded = {"generation", "valid_from_unix", "expires_at_unix"}
    require({k: v for k, v in before.items() if k not in excluded}
            == {k: v for k, v in after.items() if k not in excluded}
            and (before["generation"] + 1 == after["generation"] or
                 (already or resumed) and current[registry_path] == proposed[registry_path])
            and after["generation"] == review["generation"]
            and after["expires_at_unix"] == review["expires_at_unix"],
            "rotation changes validator membership, endpoints or authenticated network")
    return node, identity["node_address"], proposed, already


def preflight(root, review, address, config):
    result = json.loads(native([root/"bin/synergy-node", "preflight", "--config", config]))
    require(result.get("chain_id") == 99999 and result.get("network_id") == NETWORK
            and result.get("genesis_hash") == review["genesis_hash"]
            and result.get("node_address") == address and result.get("active_validator_count") == 5
            and result.get("production_approved") is False
            and all(result.get(field) is True for field in (
                "signed_genesis_verified", "signed_authority_verified", "validator_membership_verified", "read_only")),
            "native preflight did not authenticate the same Canary Genesis, authority and validator")


def rotate(root, archive, expected, apply):
    _require_operator()
    require(root not in (archive, *archive.parents), "rotation bundle must be outside the installation")
    review, files = bundle(archive, expected)
    with _lifecycle_lock(root):
        receipt, _ = _sealed_receipt(root)
        require(receipt.get("package_sha256") == PACKAGE
                and receipt.get("chain_id") == 99999 and receipt.get("network_id") == NETWORK,
                "installed release is not the reviewed Canary release")
        require(not (root/REPLACEMENT_INTENT).exists(), "finish application replacement first")
        _reject_installation_mounts(root)
        units = _attributed_units(root)
        node_unit, vpn_unit = (units[unit] for unit in UNITS)
        vpn_pid = int(vpn_unit.get("MainPID") or 0)
        require(vpn_unit.get("ActiveState") == "active" and vpn_pid > 1,
                "rotation requires the attributed VPN active")
        if apply:
            require(node_unit.get("MainPID") == "0"
                    and node_unit.get("ActiveState") in ("inactive", "failed"),
                    "applying rotation requires PoSy stopped")
            _assert_no_application_processes(root, vpn_pid=vpn_pid)
        # The installed release already blocks startup while this marker exists.
        # The ordinary software upgrader rejects this distinct intent format.
        intent_path = root/UPGRADE_INTENT
        intent = {"format": "synergy-canary-transport-rotation-v1", "root": str(root),
                  "bundle_sha256": expected}
        resumed = intent_path.exists() or intent_path.is_symlink()
        if resumed:
            require(json.loads(checked_read(intent_path, 4096, True)) == intent,
                    "interrupted operation requires its exact original rotation bundle")
        name, address, proposed, already = changes(root, review, files, resumed)
        with tempfile.TemporaryDirectory(prefix="synergy-canary-preflight-") as temporary:
            staged = Path(temporary)
            for filename in TRANSPORT:
                (staged/filename).write_bytes(proposed[f"network/{filename}"])
            config = json.loads(proposed[CONFIG[0]])
            config["apqe_transport"]["registry_path"] = str(staged/TRANSPORT[1])
            config["apqe_transport"]["registry_trust_key_path"] = str(staged/TRANSPORT[0])
            path = staged/"node.json"
            path.write_bytes(json_bytes(config))
            preflight(root, review, address, path)
        if apply and (not already or resumed):
            if not resumed:
                _replace_bytes(root, intent_path, json_bytes(intent), 0o600, expected)
            for rel, data in proposed.items():
                if checked_read(root/rel, 128 * 1024, True) != data:
                    _replace_bytes(root, root/rel, data, 0o600, expected)
            require(changes(root, review, files, True)[3], "rotation did not install all reviewed bytes")
            preflight(root, review, address, root/CONFIG[0])
            intent_path.unlink()
            _sync_directory(intent_path.parent)
        return {"validator": name, "chain_id": 99999, "native_preflight_passed": True,
                "rotation_installed": apply or already, "consensus_started": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "apply"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(rotate(safe_root(args.root), args.bundle.absolute(), args.bundle_sha256,
                            args.command == "apply"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        raise SystemExit(f"Canary transport rotation refused: {error}") from None
