#!/usr/bin/env python3
"""Compare original finalized proofs from independently selected HTTPS observers."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

PAGE_BYTES = 65536
MAX_PROOF_BYTES = 16 * 1024 * 1024
MAX_PAGES = 2 * MAX_PROOF_BYTES // PAGE_BYTES
HEX = re.compile(r"[0-9a-f]{64}")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_page(endpoint, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": "synergy_getFinalizedProofPageV1", "params": params})
    request = Request(endpoint, data=body.encode(), headers={"Content-Type": "application/json"})
    with build_opener(NoRedirect()).open(request, timeout=10) as response:
        raw = response.read(PAGE_BYTES * 2 + 1)
    if len(raw) > PAGE_BYTES * 2:
        raise ValueError("RPC proof page exceeds response bound")
    result = json.loads(raw)
    if result.get("id") != 1 or result.get("jsonrpc") != "2.0" or "error" in result:
        raise ValueError(f"proof RPC unavailable for {params['kind']} at H{params['height']}")
    return result["result"]


def fetch_proof(endpoint, height, kind, request=request_page):
    data = bytearray()
    pin = total = None
    for _ in range(MAX_PAGES):
        params = dict(height=height, kind=kind, offset=len(data), limit=PAGE_BYTES)
        if pin is not None:
            params["expected_sha256"] = pin
        page = request(endpoint, params)
        digest = page.get("sha256")
        size = page.get("total_bytes")
        if (page.get("version") != 1 or page.get("height") != height
                or page.get("kind") != kind or page.get("encoding") != "base64"
                or page.get("offset") != len(data) or not isinstance(digest, str)
                or not HEX.fullmatch(digest) or type(size) is not int
                or not 0 < size <= MAX_PROOF_BYTES):
            raise ValueError("invalid proof page scope, offset or size")
        if pin is None:
            pin, total = digest, size
        if (digest, size) != (pin, total):
            raise ValueError("proof changed while fetching continuation")
        chunk = base64.b64decode(page["bytes_base64"], validate=True)
        if not 0 < len(chunk) <= min(PAGE_BYTES, total - len(data)):
            raise ValueError("invalid proof page byte count")
        data.extend(chunk)
        expected_next = len(data) if len(data) < total else None
        if "next_offset" not in page or page["next_offset"] != expected_next:
            raise ValueError("noncontiguous proof continuation")
        if expected_next is None:
            if hashlib.sha256(data).hexdigest() != pin:
                raise ValueError("reassembled proof digest mismatch")
            return bytes(data)
    raise ValueError("proof exceeded the continuation page limit")


def subject(result, chain, network, genesis, height):
    finalized = result.get("finalized", {})
    commitments = dict(block_id=finalized.get("block_id"), state_root=result.get("state_root"),
                       protected_execution_root=finalized.get("protected_execution_root"))
    if (result.get("verified") is not True or result.get("chain_id") != chain
            or result.get("network_id") != network or result.get("genesis_hash") != genesis
            or finalized.get("height") != height
            or not all(isinstance(pin, str) and HEX.fullmatch(pin) for pin in commitments.values())):
        raise ValueError("native proof result does not match the selected network or height")
    return commitments


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--observer", action="append", required=True)
    cli.add_argument("--node", type=Path, required=True, help="qualified native synergy-node binary")
    cli.add_argument("--config", type=Path, required=True, help="independently authenticated read-only trust configuration")
    cli.add_argument("--chain", type=int, required=True)
    cli.add_argument("--network", required=True)
    cli.add_argument("--genesis", required=True)
    cli.add_argument("--height", type=int, required=True)
    args = cli.parse_args()
    endpoints = [urlsplit(value) for value in args.observer]
    if (not 1 <= len(endpoints) <= 8 or any(
            e.scheme != "https" or not e.hostname or e.username is not None or e.query or e.fragment
            for e in endpoints) or len({e.hostname for e in endpoints}) != len(endpoints)
            or args.chain <= 0 or args.height <= 0 or not HEX.fullmatch(args.genesis)):
        cli.error("select distinct HTTPS observer hosts and an explicit network and finalized height")

    agreed = None
    try:
        with tempfile.TemporaryDirectory(prefix="posy-finality-") as directory:
            finality = Path(directory, "finality.json")
            block = Path(directory, "block.json")
            for endpoint in args.observer:
                finality.write_bytes(fetch_proof(endpoint, args.height, "finality"))
                block.write_bytes(fetch_proof(endpoint, args.height, "block_commitment"))
                outcome = subprocess.run(
                    [str(args.node.resolve(strict=True)), "finality-proof", "verify",
                     str(args.config.resolve(strict=True)), str(finality), str(block)],
                    check=True, capture_output=True, timeout=90,
                )
                observed = subject(json.loads(outcome.stdout), args.chain, args.network, args.genesis, args.height)
                if agreed is not None and agreed != observed:
                    raise ValueError("verified observer block commitments disagree")
                agreed = observed
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        cli.exit(1, f"Finality verification failed: {error}\n")

    print(json.dumps({"verified": True, "chain_id": args.chain, "network_id": args.network,
                      "genesis_hash": args.genesis, "height": args.height,
                      "observer_count": len(endpoints), **agreed}, sort_keys=True))


if __name__ == "__main__":
    main()
