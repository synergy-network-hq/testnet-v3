#!/usr/bin/env python3
"""
Testnet-v3 validator VPN validation suite.

Offline structural + cryptographic validation of all 25 WireGuard participants
(21 validators, 3 relayers, 1 coordinator). Reachability/handshake checks are
reported as SKIP here — they require the machines and are run by
validate-validator-vpn-reachability.sh on the VPN.

Exit code 0 = all executed checks pass.
"""

import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_ROOT = ROOT / "testnet-v3-identity-files"
LAUNCH = ROOT / "launch"
REGISTRY = LAUNCH / "validator-vpn-public-registry.json"

SUPERNET_V = "10.70.10."
SUPERNET_R = "10.70.20."
COORD_IP = "10.70.0.1"

failures, warnings, skipped = [], [], []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def derive_public(priv_b64):
    raw = base64.b64decode(priv_b64)
    k = X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(
        k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()


def main():
    check(REGISTRY.exists(), "public registry missing")
    if not REGISTRY.exists():
        report()
        return
    reg = json.loads(REGISTRY.read_text())
    parts = reg["participants"]

    # --- population ---------------------------------------------------------
    vals = [p for p in parts if p["role"] == "validator"]
    rels = [p for p in parts if p["role"] == "relayer"]
    check(len(vals) == 21, f"expected 21 validators, found {len(vals)}")
    check(len(rels) == 3, f"expected 3 relayers, found {len(rels)}")
    check(
        sorted(p["index"] for p in vals) == list(range(1, 22)),
        "validator indexes are not exactly 1..21",
    )
    check(
        sorted(p["index"] for p in rels) == [1, 2, 3],
        "relayer indexes are not exactly 1..3",
    )

    # --- uniqueness ---------------------------------------------------------
    pubs = [p["wireguard_public_key"] for p in parts] + [
        reg["coordinator"]["wireguard_public_key"]
    ]
    check(len(set(pubs)) == len(pubs), "duplicate WireGuard public key")
    ips = [p["vpn_ip"] for p in parts] + [reg["coordinator"]["vpn_ip"]]
    check(len(set(ips)) == len(ips), "duplicate VPN IP")
    synvs = [p["synv_address"] for p in parts]
    check(len(set(synvs)) == len(synvs), "duplicate synv node address")

    # --- subnet plan --------------------------------------------------------
    for p in vals:
        check(
            p["vpn_ip"] == f"{SUPERNET_V}{p['index']}",
            f"{p['synv_address']}: vpn ip {p['vpn_ip']} off plan",
        )
    for p in rels:
        check(
            p["vpn_ip"] == f"{SUPERNET_R}{p['index']}",
            f"{p['synv_address']}: vpn ip {p['vpn_ip']} off plan",
        )
    check(reg["coordinator"]["vpn_ip"] == COORD_IP, "coordinator VPN IP off plan")

    # --- identity binding ---------------------------------------------------
    for p in parts:
        check(
            p["synv_address"].startswith("synv"),
            f"{p['identity_id']}: node identity is not a synv address",
        )
        folder = next(
            (
                d
                for d in IDENTITY_ROOT.iterdir()
                if d.is_dir() and d.name.startswith(p["identity_id"] + "_")
            ),
            None,
        )
        check(folder is not None, f"{p['identity_id']}: identity folder not found")
        if folder is None:
            continue
        manifest = json.loads((folder / "manifest.json").read_text())
        check(
            manifest["address"] == p["synv_address"],
            f"{p['identity_id']}: registry synv != manifest synv",
        )

        wg = folder / "wireguard"
        check(wg.is_dir(), f"{p['identity_id']}: wireguard dir missing")
        if not wg.is_dir():
            continue

        priv_f, pub_f, conf_f = (
            wg / "wireguard-private.key",
            wg / "wireguard-public.key",
            wg / "sy-vpn.conf",
        )
        for f in (priv_f, pub_f, conf_f, wg / "vpn-binding.json"):
            check(f.exists(), f"{p['identity_id']}: {f.name} missing")
        if not (priv_f.exists() and pub_f.exists() and conf_f.exists()):
            continue

        # permissions
        check(
            stat.S_IMODE(wg.stat().st_mode) == 0o700,
            f"{p['identity_id']}: wireguard dir not 0700",
        )
        for f in (priv_f, conf_f):
            check(
                stat.S_IMODE(f.stat().st_mode) == 0o600,
                f"{p['identity_id']}: {f.name} not 0600",
            )

        # private -> public derivation
        priv = priv_f.read_text().strip()
        pub = pub_f.read_text().strip()
        check(
            derive_public(priv) == pub,
            f"{p['identity_id']}: public key does not derive from private key",
        )
        check(
            pub == p["wireguard_public_key"],
            f"{p['identity_id']}: registry pubkey != stored pubkey",
        )

        conf = conf_f.read_text()
        # no private key leakage into the shipped config
        check(
            priv not in conf,
            f"{p['identity_id']}: PRIVATE KEY LEAKED into sy-vpn.conf",
        )
        check(
            "PrivateKey = <loaded from" in conf,
            f"{p['identity_id']}: config does not use external private key load",
        )
        # syntax
        check(conf.count("[Interface]") == 1, f"{p['identity_id']}: bad [Interface]")
        check(
            conf.count("[Peer]") == len(parts),  # 23 peers + coordinator
            f"{p['identity_id']}: expected {len(parts)} peer blocks, "
            f"found {conf.count('[Peer]')}",
        )
        check(
            f"Address = {p['vpn_ip']}/16" in conf,
            f"{p['identity_id']}: interface address mismatch",
        )
        # full mesh: every other participant present, self absent
        for q in parts:
            if q["synv_address"] == p["synv_address"]:
                check(
                    conf.count(f"AllowedIPs = {q['vpn_ip']}/32") == 0,
                    f"{p['identity_id']}: config contains itself as a peer",
                )
            else:
                check(
                    f"AllowedIPs = {q['vpn_ip']}/32" in conf,
                    f"{p['identity_id']}: missing mesh peer {q['synv_address']}",
                )
        check(
            reg["coordinator"]["wireguard_public_key"] in conf,
            f"{p['identity_id']}: coordinator peer missing",
        )
        # every peer block must carry the synv identity, not just an IP
        check(
            conf.count("node identity synv") == len(parts) - 1,
            f"{p['identity_id']}: peer blocks missing synv identity annotation",
        )

    # --- coordinator --------------------------------------------------------
    cdir = LAUNCH / "vpn-coordinator"
    check(cdir.is_dir(), "coordinator package missing")
    if cdir.is_dir():
        cpriv = cdir / "coordinator-wireguard-private.key"
        cconf = cdir / "sy-vpn.conf"
        check(cpriv.exists() and cconf.exists(), "coordinator files missing")
        if cpriv.exists():
            check(
                stat.S_IMODE(cpriv.stat().st_mode) == 0o600,
                "coordinator private key not 0600",
            )
            check(
                derive_public(cpriv.read_text().strip())
                == reg["coordinator"]["wireguard_public_key"],
                "coordinator public key does not derive from private key",
            )
        if cconf.exists():
            cc = cconf.read_text()
            check(
                cc.count("[Peer]") == len(parts),
                f"coordinator: expected {len(parts)} peers, found {cc.count('[Peer]')}",
            )
            for p in parts:
                check(
                    p["wireguard_public_key"] in cc,
                    f"coordinator: missing peer {p['synv_address']}",
                )
                check(
                    p["synv_address"] in cc,
                    f"coordinator: peer {p['identity_id']} not bound to synv identity",
                )

    # --- no private material in public evidence -----------------------------
    reg_text = REGISTRY.read_text()
    for p in parts:
        folder = next(
            (
                d
                for d in IDENTITY_ROOT.iterdir()
                if d.is_dir() and d.name.startswith(p["identity_id"] + "_")
            ),
            None,
        )
        if folder and (folder / "wireguard" / "wireguard-private.key").exists():
            priv = (folder / "wireguard" / "wireguard-private.key").read_text().strip()
            check(priv not in reg_text, f"{p['identity_id']}: private key in registry!")

    # --- activation policy --------------------------------------------------
    active = [p for p in vals if p["activation_status"] == "active"]
    check(
        len(active) == 6,
        f"expected 6 validators active at launch, found {len(active)}",
    )
    for p in vals:
        if p["activation_status"] == "active":
            check(
                p["public_endpoint"] is not None,
                f"{p['synv_address']}: active validator has no route",
            )
        else:
            check(
                p["public_endpoint"] is None,
                f"{p['synv_address']}: inactive validator unexpectedly has an endpoint",
            )

    # --- checks requiring live machines -------------------------------------
    for s in (
        "WireGuard handshake (controlled test)",
        "validator-to-validator reachability",
        "validator-to-relayer reachability",
        "coordinator reachability",
        "unauthorized-peer rejection (live)",
        "reconnection / endpoint-change behavior (live)",
    ):
        skipped.append(s)

    report()


def report():
    print(f"FAIL: {len(failures)}   WARN: {len(warnings)}   SKIP: {len(skipped)}")
    for f in failures:
        print(f"  FAIL  {f}")
    for w in warnings:
        print(f"  WARN  {w}")
    for s in skipped:
        print(f"  SKIP  {s} (requires live machines)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
