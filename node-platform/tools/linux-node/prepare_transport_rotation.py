"""Build an offline review bundle for a Canary 99999 transport root rotation."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

from apqe_layout import PUBLIC
from synergy_linux import digest, read, require

ROTATED = ("transport-root.pub", "transport-registry.json")
CONFIGS = ("config/node.json", "config/start-authorized.json")
NETWORK = "posy-apqe-canary-process-49028"


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def mapped(value, source, replacement):
    if isinstance(value, dict):
        return {k: mapped(v, source, replacement) for k, v in value.items()}
    if isinstance(value, list):
        return [mapped(v, source, replacement) for v in value]
    if isinstance(value, str) and value.startswith("/opt/Synergy/"):
        relative = value.removeprefix("/opt/Synergy/")
        if relative in {f"network/{name}" for name in ROTATED}:
            return str(replacement / Path(relative).name)
        return str(source / relative)
    return value


def build(args):
    def pins(folder):
        return {name: digest(folder / name) for name in ROTATED}

    require(digest(args.provider_report) == args.provider_sha256,
            "offline APQE provider report differs from the selected pin")
    old = dict(zip(ROTATED, [args.old_root_sha256, args.old_registry_sha256]))
    new = dict(zip(ROTATED, [args.new_root_sha256, args.new_registry_sha256]))
    require(old[ROTATED[1]] != new[ROTATED[1]] and pins(args.candidate) == new,
            "replacement public artifacts differ from the selected pins")
    base_files = {}
    if args.base_review:
        from rotate_transport import bundle
        base, base_files = bundle(args.base_review, args.base_review_sha256)
        require(base["new_transport_sha256"] == old,
                "base review does not identify the selected installed registry")
    new_registry = read(args.candidate / ROTATED[1])["payload"]
    require(new_registry["chain_id"] == 99999 and new_registry["network_id"] == NETWORK,
            "not the selected Canary network")
    files = {f"network/{name}": (args.candidate / name).read_bytes() for name in ROTATED}
    nodes = {}
    with tempfile.TemporaryDirectory(prefix="synergy-transport-rotation-") as tmp:
        for i in range(5):
            name = f"Val{i+2}"
            source = args.inputs / f"node-{i}"
            def selected_bytes(relative):
                key = relative if relative.startswith("network/") else f"{name}/{relative}"
                return base_files[key] if key in base_files else (source / relative).read_bytes()
            old_network = {f: hashlib.sha256(selected_bytes(f"network/{f}")).hexdigest() for f in PUBLIC}
            require({f: old_network[f] for f in ROTATED} == old, f"{name}: original registry pins differ")
            original = json.loads(selected_bytes("network/" + ROTATED[1]))["payload"]
            mutable = {"generation", "valid_from_unix", "expires_at_unix"}
            require({k: v for k, v in original.items() if k not in mutable}
                    == {k: v for k, v in new_registry.items() if k not in mutable}
                    and new_registry["generation"] == original["generation"] + 1,
                    f"{name}: signed registry changes fields outside the approved rotation")
            config, policy = [json.loads(selected_bytes(path)) for path in CONFIGS]
            require(policy["public_file_sha256"] == old_network
                    and config["apqe_transport"]["registry_trust_key_sha256"] == old[ROTATED[0]]
                    and config["chain_id"] == policy["chain_id"] == 99999
                    and config["network_id"] == policy["network_id"] == NETWORK,
                    f"{name}: selected configuration or startup pins differ")
            config["apqe_transport"]["registry_trust_key_sha256"] = new[ROTATED[0]]
            policy["public_file_sha256"].update(new)
            checked = mapped(config, source, args.candidate)
            checked["aegis_provider"] = {
                "report_path": str(args.provider_report),
                "authenticated_report_sha256": args.provider_sha256,
            }
            path = Path(tmp) / f"{name}.json"
            path.write_bytes(encoded(checked))
            run = subprocess.run([args.node_bin, "preflight", "--config", path],
                                 text=True, capture_output=True, timeout=30)
            require(run.returncode == 0, f"{name}: native preflight rejected: {run.stderr.strip()}")
            result = json.loads(run.stdout)
            identity = read(source / "keys/apqe/validator.pub.json")["node_address"]
            require(all(result.get(k) is True for k in (
                "signed_genesis_verified", "signed_authority_verified",
                "validator_membership_verified", "read_only"))
                and result.get("production_approved") is False
                and result.get("chain_id") == 99999 and result.get("network_id") == NETWORK
                and result.get("node_address") == identity
                and result.get("active_validator_count") == 5
                and result.get("genesis_hash") == new_registry["genesis_hash"],
                f"{name}: preflight did not prove unchanged signed authority and membership")
            for path, contents in zip(CONFIGS, [config, policy]):
                files[f"{name}/{path}"] = encoded(contents)
            nodes[name] = {
                "node_address": identity,
                "old_file_sha256": {f: hashlib.sha256(selected_bytes(f)).hexdigest() for f in CONFIGS},
                "unchanged_network_sha256": {k: v for k, v in old_network.items() if k not in ROTATED},
                "unchanged_validator_public_sha256": {
                    f: digest(source / "keys/apqe" / f)
                    for f in ("validator.pub.json", "enrollment.json")
                },
            }
    files["review.json"] = encoded({
        "format": "synergy-canary-transport-rotation-review-v1",
        "chain_id": 99999, "network_id": NETWORK,
        "genesis_hash": new_registry["genesis_hash"],
        "generation": new_registry["generation"], "expires_at_unix": new_registry["expires_at_unix"],
        "old_transport_sha256": old, "new_transport_sha256": new, "nodes": nodes,
        "native_offline_preflight_count": len(nodes),
        "activation_authorized": False,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    })
    with os.fdopen(os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream, \
            tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(data))
    return {"review_sha256": digest(args.output), "native_offline_preflight_count": len(nodes)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("inputs", "candidate", "provider-report", "node-bin", "output"):
        p.add_argument(f"--{name}", type=lambda value: Path(value).absolute(), required=True)
    for name in ("provider", "old-root", "old-registry", "new-root", "new-registry"):
        p.add_argument(f"--{name}-sha256", required=True)
    p.add_argument("--base-review", type=lambda value: Path(value).absolute())
    p.add_argument("--base-review-sha256")
    args = p.parse_args()
    require(bool(args.base_review) == bool(args.base_review_sha256),
            "base review and independent SHA-256 must be supplied together")
    print(json.dumps(build(args)))


if __name__ == "__main__":
    main()
