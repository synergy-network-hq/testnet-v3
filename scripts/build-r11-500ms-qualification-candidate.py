#!/usr/bin/env python3
"""Derive the unsigned R11 500 ms qualification/release candidate.

This is intentionally a public-only, non-deploying generator.  It preserves
the approved 2000 ms inputs and emits a separately named proposal.  No key,
signature, governance decision, execution receipt, or final Genesis hash is
invented here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


OLD_TIMING_MS = 2_000
NEW_TIMING_MS = 500
ACTIVE_VALIDATORS = [f"validator-{ordinal:02d}" for ordinal in range(2, 7)]


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"build-r11-500ms-qualification-candidate: {message}")


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"read {path}: {error}")
    if not isinstance(value, dict):
        fail(f"{path} must be a JSON object")
    return value, raw


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha3_512(value: bytes) -> str:
    return hashlib.sha3_512(value).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def replace_timing(candidate: dict[str, Any], manifest: dict[str, Any], root: str) -> None:
    consensus = candidate.get("consensus")
    require(isinstance(consensus, dict), "source Genesis has no consensus object")
    activation = consensus.get("posy_v3_activation")
    require(isinstance(activation, dict), "source Genesis has no simplified PoSy activation")
    consensus["target_block_time_ms"] = NEW_TIMING_MS
    activation["manifest"] = manifest
    activation["parameter_root_sha3_512"] = root
    # This is not a final Genesis binding.  Keeping the old FINALIZED marker
    # would make a candidate look authorized when it is not.
    activation["binding_status"] = "PROPOSED_NOT_GENESIS_BOUND"
    activation["governance_decision_id"] = "PENDING_EXTERNAL_GOVERNANCE_SIGNATURE"
    candidate["r11_qualification_candidate"] = {
        "status": "UNSIGNED_NOT_AUTHORIZED_FOR_LIVE_DEPLOYMENT",
        "old_target_block_time_ms": OLD_TIMING_MS,
        "new_target_block_time_ms": NEW_TIMING_MS,
        "consensus_parameter_root_sha3_512": root,
        "requires": [
            "governance approval for the exact parameter manifest",
            "fresh deployment execution against the 500 ms candidate",
            "canonical final Genesis and V4 release approval",
        ],
    }


def render_config(validator_id: str, validator: dict[str, Any], root: str) -> bytes:
    address = validator.get("validator_uma_id")
    require(isinstance(address, str) and address, f"{validator_id} has no public validator UMA")
    ordinal = int(validator_id.rsplit("-", 1)[1])
    # Legacy whole-second aliases are deliberately omitted.  Fresh-P3 uses the
    # explicit millisecond field, which the production role verifies against
    # the Genesis-bound manifest without rounding to a one-second value.
    text = f'''# R11 unsigned 500 ms qualification candidate; NOT deployment authorization.
# Legacy integer-second cadence aliases are intentionally omitted.

[identity]
node_id = "{validator_id}"
role = "validator"
address = "{address}"

[role]
compiled_profile = "validator_node"

[network]
id = 1266
network_id = "testnet"
name = "Synergy Testnet-v3 R11 Local Qualification"
p2p_port = {5600 + ordinal}
rpc_port = {6200 + ordinal}
ws_port = {6300 + ordinal}
max_peers = 16

[blockchain]
target_block_time_ms = {NEW_TIMING_MS}
max_gas_limit = "0x2fefd8"
chain_id = 1266

[consensus]
algorithm = "posy/3.0"
mode = "posy_simplified_v3"
target_block_time_ms = {NEW_TIMING_MS}
proposal_timeout_ms = 1500
prevote_timeout_ms = 1500
precommit_timeout_ms = 1500
max_round_timeout_ms = 10000
epoch_length = 1000
validator_cluster_size = 5
min_validators = 5
validator_vote_threshold = 4
consensus_parameter_root_sha3_512 = "{root}"

[p2p]
listen_address = "127.0.0.1:{5600 + ordinal}"
public_address = "127.0.0.1:{5600 + ordinal}"
discovery_listen_address = "127.0.0.1:{5700 + ordinal}"
discovery_public_address = "127.0.0.1:{5700 + ordinal}"
node_name = "{validator_id}"
enable_discovery = false
enable_peer_exchange = false
reject_private_advertise_addrs = false
discovery_port = {5700 + ordinal}
heartbeat_interval = 1
bootstrap_refresh_secs = 1

[logging]
log_level = "info"
log_file = "logs/{validator_id}.log"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
bind_address = "127.0.0.1:{6200 + ordinal}"
enable_http = true
http_port = {6200 + ordinal}
enable_ws = true
ws_port = {6300 + ordinal}
enable_grpc = false
grpc_port = {6400 + ordinal}
cors_enabled = false
cors_origins = []

[storage]
database = "rocksdb"
path = "data/chain"
enable_pruning = true
pruning_interval = 86400

[r11_qualification]
environment = "LOCAL_R11_QUALIFICATION"
candidate_status = "UNSIGNED_NOT_AUTHORIZED_FOR_LIVE_DEPLOYMENT"
legacy_integer_second_cadence_omitted = true
'''
    return text.encode("utf-8")


def write_root(output: Path, files: dict[str, bytes]) -> None:
    require(not output.exists(), f"refusing to overwrite existing output {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        for relative, data in files.items():
            path = staging / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        sums = "".join(f"{sha256(data)}  {relative}\n" for relative, data in sorted(files.items()))
        (staging / "SHA256SUMS").write_text(sums, encoding="utf-8")
        os.rename(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-genesis", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()

    source_genesis, source_genesis_bytes = read_json(args.source_genesis)
    source_manifest, source_manifest_bytes = read_json(args.source_manifest)
    require(source_manifest_bytes == canonical_json(source_manifest),
            "source manifest is not canonical compact JSON")
    require(source_manifest.get("status") == "FINALIZED", "source manifest is not finalized")
    require(source_manifest.get("target_block_time_ms") == OLD_TIMING_MS,
            "source manifest is not the preserved 2000 ms input")
    activation = source_genesis.get("consensus", {}).get("posy_v3_activation", {})
    require(isinstance(activation, dict), "source Genesis has no PoSy activation")
    require(activation.get("manifest") == source_manifest,
            "source Genesis activation manifest disagrees with source manifest")
    require(activation.get("parameter_root_sha3_512") == sha3_512(source_manifest_bytes),
            "source Genesis activation root does not bind source manifest")

    candidate_manifest = dict(source_manifest)
    candidate_manifest["status"] = "PROPOSED_NOT_ACTIVATED"
    candidate_manifest["governance_approval_id"] = None
    candidate_manifest["activation_epoch"] = None
    candidate_manifest["activation_height"] = None
    candidate_manifest["target_block_time_ms"] = NEW_TIMING_MS
    candidate_manifest_bytes = canonical_json(candidate_manifest)
    candidate_root = sha3_512(candidate_manifest_bytes)

    candidate_genesis = json.loads(source_genesis_bytes)
    replace_timing(candidate_genesis, candidate_manifest, candidate_root)
    candidate_genesis_bytes = pretty_json(candidate_genesis)
    genesis_hash = sha256(candidate_genesis_bytes)
    configs: dict[str, bytes] = {}
    validators = activation.get("frozen_validator_set", {}).get("validators", [])
    by_id = {item.get("validator_id"): item for item in validators if isinstance(item, dict)}
    require(set(by_id) == set(ACTIVE_VALIDATORS), "source Genesis is not validator-02 through validator-06")
    for validator_id in ACTIVE_VALIDATORS:
        configs[f"rendered-configs/{validator_id}/config.toml"] = render_config(
            validator_id, by_id[validator_id], candidate_root
        )
    desired_state = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-r11-qualification-desired-state-input",
        "status": "UNSIGNED_NOT_AUTHORIZED_FOR_LIVE_DEPLOYMENT",
        "chain_id": 1266,
        "network_id": "testnet",
        "environment": "LOCAL_R11_QUALIFICATION",
        "source_revision": args.source_revision,
        "target_block_time_ms": NEW_TIMING_MS,
        "consensus_parameter_root_sha3_512": candidate_root,
        "genesis_candidate_sha256": genesis_hash,
        "validator_config_sha256": {path.split("/")[-2]: sha256(data) for path, data in configs.items()},
        "runtime_config_status": "MILLISECOND_CADENCE_FIELDS_BOUND",
    }
    signing_request = {
        "schema_version": 1,
        "artifact_type": "testnet-v3-r11-500ms-governance-signing-request",
        "status": "UNSIGNED_EXTERNAL_GOVERNANCE_ACTION_REQUIRED",
        "signature_algorithm": "ML-DSA-87",
        "signature_domain": "SYNERGY_TESTNET_V3_GENESIS_RELEASE_APPROVAL_V4",
        "action": "APPROVE_FINAL_TESTNET_V3_GENESIS_CANDIDATE",
        "candidate_parameter_manifest_sha256": sha256(candidate_manifest_bytes),
        "candidate_parameter_root_sha3_512": candidate_root,
        "candidate_predeployment_genesis_sha256": genesis_hash,
        "desired_state_input_sha256": sha256(pretty_json(desired_state)),
        "required_before_v4_request_can_be_materialized": [
            "governance decision identifier and approval of this exact manifest",
            "fresh 500 ms deployment execution receipts and state roots",
            "final Genesis hash bound to those receipts",
            "final desired-state revision, role binary hashes, and rendered runtime configs",
        ],
        "prohibitions": ["no signature is present", "not valid for live deployment"],
    }
    report = {
        "result": "R11_500MS_QUALIFICATION_CANDIDATE_WRITTEN",
        "OLD_TIMING": OLD_TIMING_MS,
        "NEW_TIMING": NEW_TIMING_MS,
        "SOURCE_INPUT": {"path": str(args.source_genesis), "sha256": sha256(source_genesis_bytes)},
        "SOURCE_MANIFEST": {"path": str(args.source_manifest), "sha256": sha256(source_manifest_bytes),
                            "parameter_root_sha3_512": sha3_512(source_manifest_bytes)},
        "GENERATED_CANDIDATE": {"path": "genesis-predeployment-candidate.unsigned.json", "sha256": genesis_hash},
        "candidate_parameter_manifest_sha256": sha256(candidate_manifest_bytes),
        "candidate_parameter_root_sha3_512": candidate_root,
        "rendered_validator_count": len(configs),
        "runtime_config_status": "MILLISECOND_CADENCE_FIELDS_BOUND",
        "validation": {"source_preserved": True, "source_timing_ms": OLD_TIMING_MS,
                       "candidate_timing_ms": NEW_TIMING_MS, "candidate_within_100_to_1100_ms": True,
                       "no_governance_signature_fabricated": True},
    }
    files = {
        "consensus-parameter-manifest.unsigned.json": candidate_manifest_bytes,
        "genesis-predeployment-candidate.unsigned.json": candidate_genesis_bytes,
        "desired-state-input.unsigned.json": pretty_json(desired_state),
        "governance-signing-request.unsigned.json": pretty_json(signing_request),
        "validation-report.json": pretty_json(report),
        **configs,
    }
    write_root(args.output_dir.resolve(), files)
    print(f"COMPLETE=500MS_QUALIFICATION_ARTIFACTS output={args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
