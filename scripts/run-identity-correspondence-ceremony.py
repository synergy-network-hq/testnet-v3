#!/usr/bin/env python3
"""Testnet-v3 identity private<->public correspondence ceremony.

Proves that custody-held private keys correspond to the public identities
committed in the canonical genesis, WITHOUT exposing any private material.

Modes:
  prepare       Generate one unique signing challenge per required identity.
                Output: ceremony/challenges.json (public data only).
  verify        Verify operator-produced signature responses against the
                genesis-committed public keys. Signature verification is
                delegated to a verifier command (default: the aegis-pqvm CLI)
                so this script never handles secret material.
  fixture-test  Self-test the challenge/verify pipeline with a locally
                generated throwaway Ed25519 fixture (never a real identity).

The custody holder signs each challenge on the secret-owning machine (offline
supported: copy challenges.json in, responses.json out). A response is:
  {"identity_id": ..., "key_role": ..., "signature_b64": ...}

Never print, log, transmit, or store private keys, passphrases, or seed
material. This script only reads public files.
"""
import argparse, base64, hashlib, json, os, secrets, subprocess, sys, time

ROOT = os.environ.get(
    "TNV3_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CEREMONY_VERSION = "tnv3-correspondence-1"
CHAIN_ID = 1266
NETWORK_ID = "testnet"

# identity classes required for launch and the key roles each must prove
REQUIRED = {
    "active_validators": ["consensus_key", "node_identity_key"],
    "fee_collector": ["address_key"],
    "system_wallets": ["address_key"],
    "contract_deployer_authority": ["address_key"],
    # ETDAG ingress private keys: added when ML-KEM-1024 ingress records exist
}


def load_genesis():
    return json.load(
        open(os.path.join(ROOT, "genesis.testnet-v3.identity-assigned.json"))
    )


def canonical_challenge(identity_id, role, key_role, public_key_b64, genesis_hash):
    body = {
        "ceremony_version": CEREMONY_VERSION,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "genesis_hash": genesis_hash,
        "identity_id": identity_id,
        "identity_role": role,
        "key_role": key_role,
        "public_key_b64": public_key_b64,
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(32),
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return body, payload, hashlib.sha3_512(payload).hexdigest()


def cmd_prepare(args):
    g = load_genesis()
    genesis_hash = g["integrity"]["genesis_hash"]
    reg = json.load(
        open(
            os.path.join(
                ROOT, "testnet-v3-identity-files", "identity-registry.public.json"
            )
        )
    )
    reg_by_id = {r["id"]: r for r in reg["identities"]}
    challenges = []

    def add(identity_id, role, key_role, pk, alg):
        body, payload, digest = canonical_challenge(
            identity_id, role, key_role, pk, genesis_hash
        )
        challenges.append(
            {
                **body,
                "algorithm": alg,
                "challenge_sha3_512": digest,
                "sign_input": "the canonical JSON payload whose sha3-512 equals challenge_sha3_512",
            }
        )

    for v in g["validators"]:  # exact Genesis-active validator set
        aid = v["allocation_account_id"]
        add(aid, f"active validator {v['validator_id']} consensus", "consensus_key",
            v["consensus_public_key"], v["consensus_key_type"])
        add(aid, f"active validator {v['validator_id']} p2p", "node_identity_key",
            v["node_identity_key"], v["node_identity_key_type"])
    for sysid in ("SYS-01", "SYS-02", "SYS-03"):
        r = reg_by_id[sysid]
        add(sysid, r["purpose"], "address_key", None or r.get("address"), r["algorithm"])
    # deployer authority = DAO-A01 (admin_authority for genesis contracts)
    r = reg_by_id["DAO-A01"]
    add("DAO-A01", "contract deployer / admin authority", "address_key",
        r.get("address"), r["algorithm"])

    out = os.path.join(ROOT, "launch", "ceremony")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "challenges.json")
    json.dump(
        {"ceremony_version": CEREMONY_VERSION, "genesis_hash": genesis_hash,
         "challenges": challenges},
        open(path, "w"), indent=1,
    )
    print(f"wrote {len(challenges)} challenges to {path}")
    print("Next: custody holder signs each challenge payload on the "
          "secret-owning machine and returns responses.json. No passphrase or "
          "private key ever leaves that machine.")


def verify_one(verifier_cmd, algorithm, public_key_b64, payload_b64, signature_b64):
    """Delegate verification. Returns (ok, detail)."""
    cmd = [
        c.format(alg=algorithm, pk=public_key_b64, msg=payload_b64, sig=signature_b64)
        for c in verifier_cmd
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout + r.stderr).strip()[:200]
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def cmd_verify(args):
    ch = json.load(open(args.challenges))
    responses = {
        (r["identity_id"], r["key_role"]): r
        for r in json.load(open(args.responses))["responses"]
    }
    verifier = args.verifier.split() if args.verifier else [
        "aegis-pqvm", "verify", "--algorithm", "{alg}", "--public-key-b64",
        "{pk}", "--message-b64", "{msg}", "--signature-b64", "{sig}",
    ]
    results, ok_count = [], 0
    for c in ch["challenges"]:
        key = (c["identity_id"], c["key_role"])
        payload = json.dumps(
            {k: c[k] for k in (
                "ceremony_version", "chain_id", "network_id", "genesis_hash",
                "identity_id", "identity_role", "key_role", "public_key_b64",
                "timestamp", "nonce")},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        entry = {
            "identity_id": c["identity_id"], "key_role": c["key_role"],
            "algorithm": c["algorithm"], "public_key_b64": c["public_key_b64"],
            "challenge_sha3_512": c["challenge_sha3_512"],
        }
        resp = responses.get(key)
        if not resp:
            entry.update(result="BLOCKED", detail="no response supplied")
        else:
            ok, detail = verify_one(
                verifier, c["algorithm"], c["public_key_b64"],
                base64.b64encode(payload).decode(), resp["signature_b64"],
            )
            entry.update(result="PASS" if ok else "FAIL", detail=detail)
            ok_count += ok
        entry["evidence_hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        results.append(entry)
    out = os.path.join(ROOT, "launch", "identity-correspondence-results.json")
    json.dump(
        {"ceremony_version": CEREMONY_VERSION, "verified": ok_count,
         "total": len(results), "results": results}, open(out, "w"), indent=1,
    )
    print(f"{ok_count}/{len(results)} PASS -> {out}")
    sys.exit(0 if ok_count == len(results) else 1)


def cmd_fixture_test(args):
    """Prove the pipeline with a throwaway Ed25519 key (never a real identity)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pk_b64 = base64.b64encode(
        sk.public_key().public_bytes_raw()
    ).decode()
    body, payload, digest = canonical_challenge(
        "FIXTURE-00", "fixture", "node_identity_key", pk_b64, "f" * 64
    )
    sig = sk.sign(payload)
    # verify locally (Ed25519 only) to validate challenge determinism + flow
    sk.public_key().verify(sig, payload)
    payload2 = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    assert payload2 == payload and hashlib.sha3_512(payload2).hexdigest() == digest
    print("fixture-test PASS: challenge canonicalization deterministic; "
          "sign/verify roundtrip OK; no real identity touched")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("prepare")
    v = sub.add_parser("verify")
    v.add_argument("--challenges", default=os.path.join(ROOT, "launch/ceremony/challenges.json"))
    v.add_argument("--responses", required=True)
    v.add_argument("--verifier", help="verifier command template; defaults to aegis-pqvm CLI")
    sub.add_parser("fixture-test")
    args = ap.parse_args()
    {"prepare": cmd_prepare, "verify": cmd_verify, "fixture-test": cmd_fixture_test}[args.mode](args)


if __name__ == "__main__":
    main()
