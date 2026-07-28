#!/usr/bin/env python3
"""
Testnet-v3 validator/relayer WireGuard VPN generator.

Generates the complete VPN material set for the governed Testnet-v3 addressing
plan (runtime/node-control-panel/docs/control-panel/validator-vpn-coordinator.md):

    supernet    10.70.0.0/16
    coordinator 10.70.0.1
    validators  10.70.10.1 .. 10.70.10.21   (validator-1 .. validator-21)
    relayers    10.70.20.1 .. 10.70.20.3    (relayer-1 .. relayer-3)

Identity model — four separate layers, never conflated:
    route            public IP / VPN IP / port   (reach the machine)
    tunnel identity  WireGuard public key        (authenticate the tunnel)
    node identity    synv... address + PoP       (identify the Synergy peer)
    consensus id     validator addr + cons. key  (authorize consensus)

All 24 participants are pre-provisioned as full-mesh peers so that activating
validators 7..21 later requires no edit to already-deployed configs.

Private keys are written ONLY into each node's identity folder (0600, dir 0700).
Public evidence contains public keys and hashes only.
"""

import base64
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_ROOT = ROOT / "testnet-v3-identity-files"
LAUNCH = ROOT / "launch"

CHAIN_ID = 1266
NETWORK_ID = "synergy-testnet-v3"
CONFIG_VERSION = "tnv3-vpn-1"
SUPERNET = "10.70.0.0/16"
COORD_VPN_IP = "10.70.0.1"
COORD_PORT = 51820
WG_PORT = 51820
KEEPALIVE = 25
IFACE = "sy-vpn"

# Public endpoints from the node credentials workbook ("Node Credentials" sheet).
# Only machines that are currently assigned have an endpoint; validators 7..21
# have identities but no machine yet and therefore no Endpoint line (they dial
# out and their endpoint is learned on connect — roaming peers).
WORKBOOK_ENDPOINTS = {
    "validator-1": "62.146.182.207",
    "validator-2": "62.146.182.208",
    "validator-3": "62.146.182.209",
    "validator-4": "73.79.66.255",       # shared public IP with Archive Validator
    "validator-5": "194.163.183.166",
    "validator-6": "157.173.192.45",
    "relayer-1": "195.26.241.95",
    "relayer-2": "94.72.117.108",
    "relayer-3": "209.145.48.117",
}

# Validators activated at Testnet-v3 launch; 7..21 are provisioned but inactive.
ACTIVE_VALIDATORS = {f"validator-{i}" for i in range(1, 7)}
ACTIVE_RELAYERS = {"relayer-1", "relayer-2", "relayer-3"}


def genkey():
    k = X25519PrivateKey.generate()
    priv = base64.b64encode(
        k.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode()
    pub = base64.b64encode(
        k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    return priv, pub


def derive_public(priv_b64: str) -> str:
    """Independently re-derive the public key to prove correspondence."""
    raw = base64.b64decode(priv_b64)
    k = X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(
        k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def write_private(path: Path, content: str):
    path.write_text(content)
    os.chmod(path, 0o600)


def write_public(path: Path, content: str):
    path.write_text(content)
    os.chmod(path, 0o644)


def build_participants():
    """Map governed VPN slots onto the real Testnet-v3 identity folders."""
    parts = []
    for i in range(1, 22):
        folder = IDENTITY_ROOT / f"VNS-A{i + 1:02d}_tnv3-val-stake-{i:02d}"
        manifest = json.loads((folder / "manifest.json").read_text())
        name = f"validator-{i}"
        parts.append(
            {
                "name": name,
                "role": "validator",
                "index": i,
                "identity_id": manifest["id"],
                "alias": manifest["alias"],
                "synv_address": manifest["address"],
                "workbook_node": manifest.get("workbook_node"),
                "vpn_ip": f"10.70.10.{i}",
                "public_ip": WORKBOOK_ENDPOINTS.get(name),
                "folder": folder,
                "activation_status": "active"
                if name in ACTIVE_VALIDATORS
                else "provisioned-inactive",
            }
        )
    for i in range(1, 4):
        folder = IDENTITY_ROOT / f"NODE-RELAYER-{i:02d}_tnv3-relayer-{i:02d}"
        manifest = json.loads((folder / "manifest.json").read_text())
        name = f"relayer-{i}"
        parts.append(
            {
                "name": name,
                "role": "relayer",
                "index": i,
                "identity_id": manifest["id"],
                "alias": manifest["alias"],
                "synv_address": manifest["address"],
                "workbook_node": manifest.get("workbook_node"),
                "vpn_ip": f"10.70.20.{i}",
                "public_ip": WORKBOOK_ENDPOINTS.get(name),
                "folder": folder,
                "activation_status": "active"
                if name in ACTIVE_RELAYERS
                else "provisioned-inactive",
            }
        )
    return parts


def peer_block(p, coord_pub):
    lines = [
        "[Peer]",
        f"# {p['role']} {p['index']} | node identity {p['synv_address']}",
        f"PublicKey = {p['wg_public']}",
        f"AllowedIPs = {p['vpn_ip']}/32",
    ]
    if p["public_ip"]:
        lines.append(f"Endpoint = {p['public_ip']}:{WG_PORT}")
    else:
        lines.append("# Endpoint unassigned (roaming) — learned on first handshake")
    lines.append(f"PersistentKeepalive = {KEEPALIVE}")
    return "\n".join(lines)


def render_node_conf(me, others, coord_pub, generated_at):
    header = f"""# Synergy Testnet-v3 WireGuard configuration
# node identity (authoritative peer identity) : {me['synv_address']}
# role                                        : {me['role']} {me['index']}
# vpn ip (route only)                         : {me['vpn_ip']}
# public ip (route only)                      : {me['public_ip'] or 'unassigned'}
# chain                                       : {NETWORK_ID} (chain_id {CHAIN_ID})
# config version                              : {CONFIG_VERSION}
# generated                                   : {generated_at}
#
# The IP addresses in this file are ROUTES ONLY. WireGuard keys authenticate the
# tunnel. Synergy peer identity is the synv... address proven by possession of
# the corresponding node key. Never treat an endpoint as a node identity.

[Interface]
# Address is this node's VPN route inside {SUPERNET}
Address = {me['vpn_ip']}/16
ListenPort = {WG_PORT}
PrivateKey = <loaded from wireguard-private.key — never inline this value>

[Peer]
# vpn coordinator
PublicKey = {coord_pub}
AllowedIPs = {COORD_VPN_IP}/32
PersistentKeepalive = {KEEPALIVE}
"""
    body = "\n\n".join(peer_block(p, coord_pub) for p in others)
    return header + "\n" + body + "\n"


def render_coordinator_conf(parts, coord_pub, generated_at):
    header = f"""# Synergy Testnet-v3 VPN coordinator WireGuard configuration
# vpn ip        : {COORD_VPN_IP}
# supernet      : {SUPERNET}
# chain         : {NETWORK_ID} (chain_id {CHAIN_ID})
# participants  : {len(parts)} (21 validators + 3 relayers)
# config version: {CONFIG_VERSION}
# generated     : {generated_at}

[Interface]
Address = {COORD_VPN_IP}/16
ListenPort = {COORD_PORT}
PrivateKey = <loaded from coordinator-wireguard-private.key>
"""
    body = "\n\n".join(peer_block(p, coord_pub) for p in parts)
    return header + "\n" + body + "\n"


def main():
    generated_at = datetime.now(timezone.utc).isoformat()
    parts = build_participants()

    # --- key generation -----------------------------------------------------
    coord_priv, coord_pub = genkey()
    assert derive_public(coord_priv) == coord_pub, "coordinator key derivation failed"

    for p in parts:
        priv, pub = genkey()
        if derive_public(priv) != pub:
            sys.exit(f"FATAL: key derivation mismatch for {p['name']}")
        p["wg_private"] = priv
        p["wg_public"] = pub

    pubs = [p["wg_public"] for p in parts] + [coord_pub]
    if len(set(pubs)) != len(pubs):
        sys.exit("FATAL: duplicate WireGuard public key generated")
    ips = [p["vpn_ip"] for p in parts] + [COORD_VPN_IP]
    if len(set(ips)) != len(ips):
        sys.exit("FATAL: duplicate VPN IP assignment")
    synvs = [p["synv_address"] for p in parts]
    if len(set(synvs)) != len(synvs):
        sys.exit("FATAL: duplicate synv node address")

    # --- per-node packages --------------------------------------------------
    checksums = {}
    for p in parts:
        folder = p["folder"]
        os.chmod(folder, 0o700)
        wg_dir = folder / "wireguard"
        wg_dir.mkdir(exist_ok=True)
        os.chmod(wg_dir, 0o700)

        write_private(wg_dir / "wireguard-private.key", p["wg_private"] + "\n")
        write_public(wg_dir / "wireguard-public.key", p["wg_public"] + "\n")

        others = [q for q in parts if q["name"] != p["name"]]
        conf = render_node_conf(p, others, coord_pub, generated_at)
        conf_path = wg_dir / f"{IFACE}.conf"
        write_private(conf_path, conf)

        binding = {
            "config_version": CONFIG_VERSION,
            "chain_id": CHAIN_ID,
            "network_id": NETWORK_ID,
            "node_identity": {
                "synv_address": p["synv_address"],
                "identity_id": p["identity_id"],
                "alias": p["alias"],
                "note": "authoritative Synergy peer identity",
            },
            "wireguard_identity": {
                "public_key": p["wg_public"],
                "public_key_sha256": sha256_hex(p["wg_public"]),
                "note": "authenticates the VPN tunnel only; NOT a Synergy identity",
            },
            "route": {
                "vpn_ip": p["vpn_ip"],
                "public_ip": p["public_ip"],
                "listen_port": WG_PORT,
                "note": "routing metadata only; never an identity",
            },
            "role": p["role"],
            "index": p["index"],
            "workbook_node": p["workbook_node"],
            "activation_status": p["activation_status"],
            "coordinator": {
                "public_key": coord_pub,
                "vpn_ip": COORD_VPN_IP,
                "listen_port": COORD_PORT,
            },
            "config_sha256": sha256_hex(conf),
            "generated_at": generated_at,
        }
        bpath = wg_dir / "vpn-binding.json"
        write_public(bpath, json.dumps(binding, indent=2) + "\n")

        write_public(
            wg_dir / "INSTALL.md",
            f"""# {p['name']} — Testnet-v3 VPN install

Node identity (authoritative): `{p['synv_address']}`
VPN route: `{p['vpn_ip']}`  |  role: {p['role']}  |  status: {p['activation_status']}

## Install
```bash
sudo install -o root -g root -m 0700 -d /etc/wireguard
sudo cp {IFACE}.conf /etc/wireguard/{IFACE}.conf
sudo chmod 0600 /etc/wireguard/{IFACE}.conf
# inject the private key without ever putting it on a command line:
sudo sh -c 'umask 077; printf "PrivateKey = %s\\n" "$(cat wireguard-private.key)" \\
  >> /etc/wireguard/{IFACE}.conf'
sudo systemctl enable --now wg-quick@{IFACE}
```

## Health check
```bash
sudo wg show {IFACE}
ping -c3 {COORD_VPN_IP}          # coordinator reachable
```

## Revocation
Remove this peer from the coordinator registry and from every participant
config, then rotate this node's keypair. Revoking the WireGuard key removes
VPN access; it does NOT by itself revoke consensus authority — that is
governed separately by the validator active set.
""",
        )

        checksums[p["name"]] = {
            "synv_address": p["synv_address"],
            "config_sha256": binding["config_sha256"],
            "wireguard_public_key_sha256": binding["wireguard_identity"][
                "public_key_sha256"
            ],
            "binding_sha256": sha256_hex(bpath.read_text()),
        }

    # --- coordinator package ------------------------------------------------
    coord_dir = LAUNCH / "vpn-coordinator"
    coord_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(coord_dir, 0o700)
    write_private(coord_dir / "coordinator-wireguard-private.key", coord_priv + "\n")
    write_public(coord_dir / "coordinator-wireguard-public.key", coord_pub + "\n")
    coord_conf = render_coordinator_conf(parts, coord_pub, generated_at)
    write_private(coord_dir / f"{IFACE}.conf", coord_conf)
    checksums["coordinator"] = {
        "config_sha256": sha256_hex(coord_conf),
        "wireguard_public_key_sha256": sha256_hex(coord_pub),
    }

    # --- public registry (NO private material) ------------------------------
    registry = {
        "schema_version": "1",
        "config_version": CONFIG_VERSION,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "supernet": SUPERNET,
        "generated_at": generated_at,
        "identity_model": {
            "route": "public IP / VPN IP / port — reach the machine; may change freely",
            "tunnel_identity": "WireGuard public key — authenticates the VPN tunnel",
            "node_identity": "synv... address + proof of possession — identifies the Synergy peer (PRIMARY KEY)",
            "consensus_identity": "validator address + consensus key + active set — authorizes consensus",
        },
        "coordinator": {
            "vpn_ip": COORD_VPN_IP,
            "listen_port": COORD_PORT,
            "wireguard_public_key": coord_pub,
        },
        "participants": [
            {
                "synv_address": p["synv_address"],
                "role": p["role"],
                "index": p["index"],
                "identity_id": p["identity_id"],
                "alias": p["alias"],
                "workbook_node": p["workbook_node"],
                "wireguard_public_key": p["wg_public"],
                "vpn_ip": p["vpn_ip"],
                "public_endpoint": f"{p['public_ip']}:{WG_PORT}" if p["public_ip"] else None,
                "activation_status": p["activation_status"],
                "config_version": CONFIG_VERSION,
            }
            for p in parts
        ],
    }
    reg_path = LAUNCH / "validator-vpn-public-registry.json"
    reg_text = json.dumps(registry, indent=2, sort_keys=True) + "\n"
    write_public(reg_path, reg_text)

    checksums["_registry_sha256"] = sha256_hex(reg_text)
    write_public(
        LAUNCH / "validator-vpn-checksums.json",
        json.dumps(checksums, indent=2, sort_keys=True) + "\n",
    )

    print(f"participants      : {len(parts)} (21 validators + 3 relayers)")
    print(f"coordinator       : {COORD_VPN_IP}:{COORD_PORT}")
    print(f"registry sha256   : {checksums['_registry_sha256']}")
    print(f"active at launch  : {len(ACTIVE_VALIDATORS)} validators + {len(ACTIVE_RELAYERS)} relayers")
    print("private keys written only into per-node identity folders (0600)")


if __name__ == "__main__":
    main()
