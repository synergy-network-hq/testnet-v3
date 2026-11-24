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
MAX_PROOF_BYTES = 1024 * 1024
MAX_PAGES = 2 * MAX_PROOF_BYTES // PAGE_BYTES
MAX_HEIGHTS = 8
USER_AGENT = "Synergy-PoSy-Finality-Observer/1.0"
HEX = re.compile(r"[0-9a-f]{64}")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_page(endpoint, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": "synergy_getFinalizedProofPageV1", "params": params})
    request = Request(endpoint, data=body.encode(), headers={
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    })
    with build_opener(NoRedirect()).open(request, timeout=10) as response:
        raw = response.read(PAGE_BYTES * 2 + 1)
    if len(raw) > PAGE_BYTES * 2:
        raise ValueError("RPC proof page exceeds response bound")
    result = json.loads(raw)
    scope = f"{params['kind']} at H{params['height']}"
    if result.get("id") != 1 or result.get("jsonrpc") != "2.0":
        raise ValueError(f"invalid proof RPC response for {scope}")
    if "error" in result:
        error = result["error"]
        if not isinstance(error, dict):
            raise ValueError(f"invalid proof RPC error for {scope}")
        detail = ascii(str(error.get("message", ""))[:240])
        raise ValueError(f"proof RPC unavailable for {scope} ({error.get('code')!r}): {detail}")
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


def subject(result, chain, network, genesis, height, *, witness_only=False):
    finalized = result.get("finalized", {})
    commitments = dict(block_id=finalized.get("block_id"),
                       protected_execution_root=finalized.get("protected_execution_root"))
    if witness_only:
        commitments["finality_certificate_id"] = finalized.get("finality_certificate_id")
    else:
        commitments["state_root"] = result.get("state_root")
    if (result.get("verified") is not True or result.get("chain_id") != chain
            or result.get("network_id") != network or result.get("genesis_hash") != genesis
            or finalized.get("height") != height
            or not all(isinstance(pin, str) and HEX.fullmatch(pin) for pin in commitments.values())):
        raise ValueError("native proof result does not match the selected network or height")
    return commitments


def consensus_position(result, verified_block):
    # The native verifier has already hashed and validated this exact tuple.
    _, parent, _, _, _, _ = json.loads(verified_block)
    epoch = result.get("epoch")
    root = result.get("epoch_context_root")
    timestamp = result.get("consensus_timestamp_unix")
    if (not isinstance(parent, str) or not HEX.fullmatch(parent)
            or type(epoch) is not int or epoch < 0
            or not isinstance(root, str) or not HEX.fullmatch(root)
            or type(timestamp) is not int or timestamp < 0):
        raise ValueError("missing or invalid verified consensus position")
    return dict(parent_block_id=parent, epoch=epoch, epoch_context_root=root,
                consensus_timestamp_unix=timestamp)


def witness_position(proof, commitments, chain, network, height):
    # Read the first QC from the exact document accepted by the native verifier.
    # Its signed context owns the finalized block even when later QCs cross epochs.
    first, _, _ = json.loads(proof)["witness"]["quorum_certificates"]
    context = first["context"]
    parent = first.get("parent_block_id")
    epoch = context.get("epoch")
    root = context.get("epoch_context_root")
    if ((context.get("chain_id"), context.get("network_id"), context.get("height"))
            != (chain, network, height)
            or first.get("block_id") != commitments["block_id"]
            or first.get("protected_execution_root") != commitments["protected_execution_root"]
            or not isinstance(parent, str) or not HEX.fullmatch(parent)
            or type(epoch) is not int or epoch < 1
            or not isinstance(root, str) or not HEX.fullmatch(root)):
        raise ValueError("verified witness does not identify the selected consensus position")
    return dict(parent_block_id=parent, epoch=epoch, epoch_context_root=root)


def check_successor(previous, current):
    if (current["height"] != previous["height"] + 1
            or current["parent_block_id"] != previous["block_id"]):
        raise ValueError("verified blocks do not form a contiguous chain")
    if ("consensus_timestamp_unix" in current
            and current["consensus_timestamp_unix"] < previous["consensus_timestamp_unix"]):
        raise ValueError("verified consensus time regressed")
    delta = current["epoch"] - previous["epoch"]
    same_root = current["epoch_context_root"] == previous["epoch_context_root"]
    if delta not in (0, 1) or same_root != (delta == 0):
        raise ValueError("inconsistent verified epoch succession")
    return delta


def match_world_state(world_bytes, state_root):
    domain = b"SYNERGY_WORLD_STATE_ROOT_V1"
    digest = hashlib.sha3_256(domain + len(world_bytes).to_bytes(8, "big") + world_bytes).hexdigest()
    if digest != state_root:
        raise ValueError("World preimage does not match the authenticated state root")


def select_receipt(block_bytes, transaction_id):
    # The native verifier authenticated the exact block bytes before selection.
    _, _, _, _, transactions, receipts = json.loads(block_bytes)
    if not isinstance(transactions, list) or not isinstance(receipts, list) or len(transactions) != len(receipts):
        raise ValueError("invalid transaction and receipt alignment in verified block")
    matches = [receipt for receipt in receipts if receipt.get("transaction_id") == transaction_id]
    if len(matches) != 1:
        raise ValueError("requested receipt does not occur exactly once in verified block")
    receipt = matches[0]
    status = receipt.get("status")
    gas = receipt.get("gas_used")
    root = receipt.get("state_root_after")
    error = receipt.get("error_code")
    if (type(gas) is not int or not 0 <= gas < 2**64 or not isinstance(root, str)
            or not HEX.fullmatch(root)
            or not ((status == "applied" and error is None)
                    or (status == "reverted" and isinstance(error, str) and error))):
        raise ValueError("invalid canonical receipt in verified block")
    return dict(transaction_id=transaction_id, status=status, gas_used=gas,
                state_root_after=root, error_code=error)


def verify_native(command, height):
    outcome = subprocess.run(command, capture_output=True, timeout=90)
    if outcome.returncode:
        # Do not publish local trust-file paths from the verifier.
        # The parser's generic path-bearing failures can be diagnosed offline.
        stderr = outcome.stderr.decode("utf-8", errors="replace").strip()
        detail = stderr.removeprefix("synergy-node failed closed: ")
        public_diagnostics = (
            "proof lies outside independently authenticated authority history",
            "finality record or exact timeout closure mismatch",
            "block preimage does not match verified finality",
            "verified height has no authenticated consensus time authority",
        )
        reason = detail if detail in public_diagnostics else f"exit {outcome.returncode}"
        raise ValueError(f"native finality verification rejected H{height}: {reason}")
    return json.loads(outcome.stdout)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--observer", action="append", required=True)
    cli.add_argument("--node", type=Path, required=True, help="qualified native synergy-node binary")
    cli.add_argument("--config", type=Path, required=True, help="independently authenticated read-only trust configuration")
    cli.add_argument("--chain", type=int, required=True)
    cli.add_argument("--network", required=True)
    cli.add_argument("--genesis", required=True)
    cli.add_argument("--height", type=int, required=True)
    cli.add_argument("--witness-only", action="store_true",
                     help="authenticate retained three-QC finality without the original block preimage")
    cli.add_argument("--verify-world", action="store_true",
                     help="check original public World bytes against each authenticated block state root")
    cli.add_argument("--receipt-id", help="select a transaction receipt from the authenticated block bytes")
    cli.add_argument("--through-height", type=int, help="verify up to eight consecutive heights")
    cli.add_argument("--require-epoch-transition", action="store_true")
    args = cli.parse_args()
    last = args.height if args.through_height is None else args.through_height
    if not args.height <= last < args.height + MAX_HEIGHTS:
        cli.error("select one to eight consecutive finalized heights")
    if args.witness_only and args.verify_world:
        cli.error("World verification requires an original block preimage")
    if args.receipt_id is not None and (
            not HEX.fullmatch(args.receipt_id) or args.witness_only or last != args.height):
        cli.error("receipt verification requires one finalized height and an exact transaction ID")
    if args.require_epoch_transition and last == args.height:
        cli.error("an epoch transition requires at least two heights")
    endpoints = [urlsplit(value) for value in args.observer]
    if (not 1 <= len(endpoints) <= 8 or any(
            e.scheme != "https" or not e.hostname or e.username is not None or e.query or e.fragment
            for e in endpoints) or len({e.hostname for e in endpoints}) != len(endpoints)
            or args.chain <= 0 or args.height <= 0 or not HEX.fullmatch(args.genesis)):
        cli.error("select distinct HTTPS observer hosts and an explicit network and finalized height")

    range_mode = args.through_height is not None
    observations = []
    transitions = 0
    try:
        node = args.node.resolve(strict=True)
        config = args.config.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="posy-finality-") as directory:
            finality = Path(directory, "finality.json")
            block = Path(directory, "block.json")
            for height in range(args.height, last + 1):
                agreed = None
                for endpoint in args.observer:
                    proof_bytes = fetch_proof(endpoint, height, "finality")
                    finality.write_bytes(proof_bytes)
                    command = [str(node), "finality-proof", "verify", str(config), str(finality)]
                    if not args.witness_only:
                        block_bytes = fetch_proof(endpoint, height, "block_commitment")
                        block.write_bytes(block_bytes)
                        command.append(str(block))
                    native = verify_native(command, height)
                    observed = subject(native, args.chain, args.network, args.genesis, height,
                                       witness_only=args.witness_only)
                    if args.receipt_id is not None:
                        observed["receipt"] = select_receipt(block_bytes, args.receipt_id)
                    if args.verify_world:
                        match_world_state(fetch_proof(endpoint, height, "world_state"),
                                          observed["state_root"])
                    if range_mode:
                        if args.witness_only:
                            observed.update(witness_position(proof_bytes, observed, args.chain,
                                                             args.network, height))
                        else:
                            observed.update(consensus_position(native, block_bytes))
                    if agreed is not None and agreed != observed:
                        raise ValueError(f"verified observer commitments disagree at H{height}")
                    agreed = observed
                record = dict(height=height, **agreed)
                if observations:
                    transitions += check_successor(observations[-1], record)
                observations.append(record)
        if args.require_epoch_transition and transitions == 0:
            raise ValueError("verified range contains no epoch transition")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        cli.exit(1, f"Finality verification failed: {error}\n")

    result = dict(verified=True, chain_id=args.chain, network_id=args.network,
                  genesis_hash=args.genesis, observer_count=len(endpoints))
    if args.witness_only:
        result["block_preimage_verified"] = False
    if args.verify_world:
        result["world_preimage_verified"] = True
    if range_mode:
        result.update(start_height=args.height, through_height=last, epoch_transitions=transitions,
                      observations=observations)
    else:
        result.update(observations[0])
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
