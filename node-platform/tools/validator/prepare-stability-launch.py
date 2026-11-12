#!/usr/bin/env python3
"""Public preparation only. Keytool owns typed validation and root derivation.

Inventory JSON:
{
  "deployment": {
    "manifest_path": "/etc/synergy/posy/network-manifest.json",
    "authority_path": "/etc/synergy/posy/authority.json",
    "trust_public_key_path": "/etc/synergy/posy/authority-root.pub",
    "p2p_bindings_path": "/etc/synergy/posy/p2p-bindings.json",
    "transport_registry_path": "/etc/synergy/posy/transport-registry.json",
    "vpn_interface": "wt0", "transport_attestation_public_key": "<verified public pin>",
    "provider_plan_sha256": "<verified provider plan digest>"
  },
  "wallet_public_paths": ["<exactly 32 generated public wallet JSON paths>"],
  "validators": [{
    "number": 2,
    "public_identity_path": "<absolute local generated P2P identity JSON>",
    "p2p": {"metadata_path": "<absolute public metadata>", "public_key_path": "<absolute raw public key>"},
    "consensus": {"metadata_path": "<absolute public metadata>", "public_key_path": "<absolute raw public key>"},
    "ingress": {"metadata_path": "<absolute public metadata>", "public_key_path": "<absolute raw public key>"},
    "deployment": {
      "public_identity_path": "<absolute provisioned identity JSON>",
      "p2p_secret_key_path": "<absolute provisioned new MLDSA65 secret>",
      "consensus_secret_key_path": "<absolute freshly generated MLDSA65 secret>",
      "ingress_secret_key_path": "<absolute provisioned new MLKEM1024 secret>",
      "data_directory": "<absolute fresh isolated state directory>",
      "admin_socket_path": "/run/synergy/posy.sock"
    }
  }]
}
All five validator numbers 2..6 are mandatory. Secret paths are labels only:
this tool never opens those paths. No existing workbook or custody is copied.
"""
import argparse
import hashlib
import json
from pathlib import Path

MAX_PUBLIC_BYTES = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absolute(value):
    require(isinstance(value, str) and Path(value).is_absolute(), "all file paths must be absolute")
    return value


def read_public(path, limit=MAX_PUBLIC_BYTES):
    source = Path(absolute(path))
    require(source.is_file() and source.stat().st_size <= limit, "public input missing or oversized")
    return source.read_bytes()


def bundle(spec, purpose, algorithm, length, address):
    require(set(spec) == {"metadata_path", "public_key_path"}, "invalid public bundle fields")
    metadata = json.loads(read_public(spec["metadata_path"]))
    public = read_public(spec["public_key_path"], length)
    require(len(public) == length, "wrong public key length")
    require(metadata["format_version"] == 1 and metadata["node_address"] == address,
            "public custody identity mismatch")
    require(metadata["algorithm"] == algorithm and metadata["record"]["purpose"] == purpose,
            "public custody algorithm or purpose mismatch")
    require(metadata["record"]["public_key"] == list(public), "raw public key differs from metadata")
    fingerprint_input = b"SYNERGY_KEY_FINGERPRINT_V1" + len(public).to_bytes(8, "big") + public
    require(metadata["public_key_fingerprint"] == hashlib.sha3_256(fingerprint_input).hexdigest(),
            "public fingerprint mismatch")
    return metadata


def prepare(inventory, activation, trust_id, network_id, protected_profile="vc_event_context_v1"):
    require(protected_profile in ("vc_event_context_v1", "processing_groups_v1"),
            "unsupported explicit protected profile")
    require(isinstance(network_id, str) and 0 < len(network_id) <= 128
            and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in network_id)
            and network_id not in ("synergy-posy-stability-20261009", "synergy-posy-baseline-20261010"),
            "explicit fresh network incarnation ID required")
    require(set(inventory) == {"deployment", "validators", "wallet_public_paths"}, "invalid inventory fields")
    require(activation > 0 and activation * 1000 + 999999 * 1000 <= 2**64 - 1,
            "invalid activation or epoch timestamp overflow")
    require(trust_id.strip(), "trust key ID is required")
    common = inventory["deployment"]
    required_common = {"manifest_path", "authority_path", "trust_public_key_path", "p2p_bindings_path",
                       "transport_registry_path", "vpn_interface", "transport_attestation_public_key", "provider_plan_sha256"}
    require(set(common) == required_common, "invalid deployment fields")
    for key in required_common:
        if key.endswith("_path"):
            absolute(common[key])
    require(common["vpn_interface"].strip() and common["transport_attestation_public_key"].strip(), "VPN pins absent")
    digest = common["provider_plan_sha256"]
    require(len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), "invalid provider plan hash")
    require(sorted(v["number"] for v in inventory["validators"]) == list(range(2, 7)), "exact val2-val6 inventory required")
    records, custody, ingress, bindings, configs = [], [], [], {}, {}
    for node in sorted(inventory["validators"], key=lambda v: v["number"]):
        require(set(node) == {"number", "public_identity_path", "p2p", "consensus", "ingress", "deployment"}, "invalid validator fields")
        identity = json.loads(read_public(node["public_identity_path"]))
        address = identity["node_address"]
        require(address.startswith("synv1") and address not in bindings, "canonical unique validator identity required")
        p2p = bundle(node["p2p"], "p2p_identity", "ML-DSA-65", 1952, address)
        consensus = bundle(node["consensus"], "posy_consensus", "ML-DSA-65", 1952, address)
        kem = bundle(node["ingress"], "etdag_decryption", "ML-KEM-1024", 1568, address)
        require(identity["public_key_fingerprint"] == p2p["public_key_fingerprint"], "identity/P2P fingerprint mismatch")
        require(len({m["record"]["id"] for m in (p2p, consensus, kem)}) == 3, "role key IDs must be distinct")
        records.append({"record": {"validator_id": address, "consensus_key_id": consensus["record"]["id"],
                                  "frozen_voting_weight": 100, "status": "active"},
                        "algorithm": "ml_dsa65", "public_key": consensus["record"]["public_key"]})
        custody.append({k: node[k] for k in ("public_identity_path", "p2p", "consensus", "ingress")})
        ingress.append({"key_id": kem["record"]["id"], "validator_id": address,
                        "public_key": {"algorithm": "ML-KEM-1024", "public_key": kem["record"]["public_key"]},
                        "activation_height": 1, "retirement_height": None})
        bindings[address] = {"node_address": address, "key_id": p2p["record"]["id"],
                             "algorithm": "ml_dsa65", "public_key": p2p["record"]["public_key"], "capabilities": []}
        deploy = node["deployment"]
        require(set(deploy) == {"public_identity_path", "p2p_secret_key_path", "consensus_secret_key_path",
                               "ingress_secret_key_path", "data_directory", "admin_socket_path"}, "invalid host deployment paths")
        for value in deploy.values():
            absolute(value)
        number = node["number"]
        endpoint = f"10.69.10.{number}:5622"
        configs[f"val{number}.json"] = {
            "schema_version": 1, "node_name": f"synergy-val{number}-posy-stability", "role": "validator",
            "chain_id": 1266, "network_id": network_id, "manifest_path": common["manifest_path"],
            "public_identity_path": deploy["public_identity_path"], "aegis_key_bindings_path": common["p2p_bindings_path"],
            "aegis_signing_key_path": deploy["p2p_secret_key_path"], "admin_socket_path": deploy["admin_socket_path"],
            "network": {"listen_addresses": [endpoint], "advertised_addresses": [endpoint],
                        "dial_timeout_ms": 5000, "idle_connection_timeout_ms": 60000},
            "p2p": {"max_authenticated_peers": 32, "max_pending_handshakes": 16,
                    "max_frame_bytes": 4 * 1024 * 1024, "gossip_fanout": 4},
            "consensus": {"mode": "validate_and_vote", "authority_binding": common["authority_path"],
                          "authority_trust_key_path": common["trust_public_key_path"],
                          "signing_key_path": deploy["consensus_secret_key_path"],
                          "proposal_timeout_ms": 2000, "round_timeout_ms": 5000, "max_rounds_behind": 64},
            "etdag": {"enabled": True, "ingress_kem_secret_key_path": deploy["ingress_secret_key_path"],
                      "protected_lookahead": 5, "admission_queue_capacity": 4096,
                      "max_vertex_bytes": 2 * 1024 * 1024, "proposal_material_wait_ms": 1500},
            "storage": {"data_directory": deploy["data_directory"], "wal_sync": "every_commit", "max_open_files": 128,
                        "minimum_free_bytes": 2 * 1024**3, "prune_finalized_history_after_blocks": None},
            "rpc": {"enabled": True, "listen_address": "127.0.0.1:8545", "max_request_bytes": 1024**2, "max_concurrent_requests": 64},
            "vpn": {"mode": "required", "interface_name": common["vpn_interface"],
                    "signed_registry_path": common["transport_registry_path"],
                    "attestation_public_key": common["transport_attestation_public_key"], "provider_plan_sha256": digest},
        }
    policy = {"version": 1, "cutoff_relationship": "vc_event_context_v1", "epoch_start_timestamp_ms": activation * 1000,
              "target_block_time_ms": 1000, "parameters": {"profile_id": "POSY-ETDAG-v3.0", "target_height_offset": 5,
                  "max_outstanding_nonce_slots": 4, "ciphertext_size_classes": [512,1024,2048,4096,8192,16384,32768,65536,131072],
                  "max_protected_gas": 30000000, "max_protected_bytes": 8388608},
              "initial_world_state": {"accounts": {}, "protocol": {}}, "cryptographic_profile_root": "",
              "ingress_kem_registry": {"context_root": "", "records": ingress}, "cluster_schedule_version": "",
              "assigned_height_schedule_root": "", "cluster_map_root": "", "assigned_cluster_id": 0,
              "assigned_cluster_membership_root": ""}
    if protected_profile == "processing_groups_v1":
        policy["version"] = 2
        policy["cutoff_relationship"] = protected_profile
        for config in configs.values():
            config["storage"].update(world_memory_budget_bytes=1073741824,
                prune_finalized_history_after_blocks=64)
    wallet_paths = inventory["wallet_public_paths"]
    require(isinstance(wallet_paths, list) and len(wallet_paths) == 32
            and len(set(wallet_paths)) == 32, "exactly 32 fresh wallet public inputs required")
    accounts, wallet_bindings = {}, {}
    for path in wallet_paths:
        wallet = json.loads(read_public(path))
        sender = wallet["sender"]
        binding = wallet["identity_authorization"]["binding"]
        account = wallet["genesis_account"]
        commitment = wallet["genesis_binding_commitment"]
        scopes = binding["authorization_scopes"]
        require(isinstance(sender, str) and sender.startswith("syna1") and sender not in accounts
                and sender == binding["identity_address"], "distinct fresh wallet identity required")
        require(any(scope.get("chain_id") == 1266 and scope.get("network_id") == network_id
                    and scope.get("purpose") == "transaction-signing" for scope in scopes),
                "wallet authorization is outside fresh network domain")
        require(isinstance(account["balance_nwei"], int) and 0 < account["balance_nwei"] < 2**128
                and account["nonce"] == 0 and account["code_hash"] is None,
                "wallet Genesis allocation must be positive with zero nonce")
        require(commitment["effective_at_unix"] == activation
                and commitment["binding_payload_sha3_256"] == binding["binding_payload_sha3_256"]
                and commitment["identity_root_public_key_sha3_256"]
                    == binding["identity_root"]["public_key_sha3_256"],
                "fresh wallet commitment differs from activation/binding")
        accounts[sender] = account
        wallet_bindings[sender] = commitment
    policy["initial_world_state"] = {
        "accounts": accounts,
        "protocol": {"identity_authorization_bindings": list(
            json.dumps(wallet_bindings, sort_keys=True, separators=(",", ":")).encode("utf-8"))},
    }
    recipe = {"authority": {"version": 1, "chain_id": 1266, "network_id": network_id, "epoch": 1,
                 "epoch_start_height": 1, "epoch_end_height": 1000000, "finalized_epoch_seed_root": "",
                 "consensus_parameter_root": "", "validators": records,
                 "anchor_parent": {"kind": "genesis", "reference": {"genesis_hash": "", "block_id": "", "reference_id": ""}},
                 "protected": policy}, "validators": custody,
              "network": {"chain_id": 1266, "network_id": network_id, "protocol_version": "posy/3.0", "activation_unix": activation},
              "authority_trust_key_id": trust_id, "seed_source": {"kind": "genesis_hash"}}
    return {"fresh-genesis-input.json": recipe, "p2p-bindings.json": {"bindings": bindings}, **configs}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("output_directory", type=Path, help="existing canonical launch directory; public outputs replaced in place")
    parser.add_argument("--activation-unix", type=int, required=True, help="operator generation-time UTC seconds")
    parser.add_argument("--authority-trust-key-id", required=True)
    parser.add_argument("--network-id", required=True, help="explicit fresh chain incarnation; no historic default")
    parser.add_argument("--protected-profile", choices=("vc_event_context_v1", "processing_groups_v1"),
                        default="vc_event_context_v1", help="explicit signed profile; async requires processing_groups_v1")
    args = parser.parse_args()
    outputs = prepare(json.loads(read_public(str(args.inventory))), args.activation_unix, args.authority_trust_key_id, args.network_id, args.protected_profile)
    require(args.output_directory.is_absolute() and args.output_directory.is_dir(), "existing absolute canonical output directory required")
    paths = {name: args.output_directory / name for name in outputs}
    require(all(not p.is_symlink() and (not p.exists() or p.is_file()) for p in paths.values()),
            "canonical public artifacts must be regular files")
    for name, value in outputs.items():
        with paths[name].open("w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
    print("Public unsigned recipe/configs prepared. Run prepare-fresh-genesis, then sign and verify all authority/manifest/transport artifacts before deployment.")


if __name__ == "__main__":
    main()
