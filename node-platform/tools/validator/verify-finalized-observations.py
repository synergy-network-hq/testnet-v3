#!/usr/bin/env python3
"""Compare original finalized proofs from HTTPS observers or authorized archives."""
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


def read_archived_proof(directory, height, kind):
    path = directory / f"{height}.{kind}.json"
    try:
        with path.open("rb") as source:
            data = source.read(MAX_PROOF_BYTES + 1)
    except FileNotFoundError as error:
        raise ValueError(f"archived {kind} unavailable at H{height}") from error
    if not 0 < len(data) <= MAX_PROOF_BYTES:
        raise ValueError(f"archived {kind} at H{height} exceeds proof bounds or is empty")
    return data


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


def select_world_accounts(world_bytes, addresses):
    # Call only after matching these exact bytes to the native-verified root.
    world = json.loads(world_bytes)
    accounts = world.get("accounts") if isinstance(world, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("invalid accounts map in authenticated World")
    selected = {}
    for address in addresses:
        if address not in accounts:
            selected[address] = None
            continue
        account = accounts[address]
        balance = account.get("balance_nwei") if isinstance(account, dict) else None
        nonce = account.get("nonce") if isinstance(account, dict) else None
        if (type(balance) is not int or not 0 <= balance < 2**128
                or type(nonce) is not int or not 0 <= nonce < 2**64):
            raise ValueError("invalid account balance or nonce in authenticated World")
        # Preserve integer precision when reports are consumed by JavaScript.
        selected[address] = dict(balance_nwei=str(balance), nonce=str(nonce))
    return selected


def select_receipt(block_bytes, transaction_id, *, expected=True):
    # The native verifier authenticated the exact block bytes before selection.
    _, _, _, _, transactions, receipts = json.loads(block_bytes)
    if (not isinstance(transactions, list) or not isinstance(receipts, list)
            or len(transactions) != len(receipts)
            or any(not isinstance(receipt, dict) for receipt in receipts)):
        raise ValueError("invalid transaction and receipt alignment in verified block")
    matches = [receipt for receipt in receipts if receipt.get("transaction_id") == transaction_id]
    if not expected:
        if matches:
            raise ValueError("requested receipt appears outside its expected finalized height")
        return None
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


def verify_plain_transfer(block_bytes, receipt, previous_world, current_world, collector, base_fee):
    # The caller has authenticated both Worlds and the linked block preimages.
    _, _, _, _, transactions, _ = json.loads(block_bytes)
    if len(transactions) != 1 or not isinstance(transactions[0], dict):
        raise ValueError("transfer accounting requires a block with exactly one transaction")
    intent = transactions[0].get("unsigned", {})
    if not isinstance(intent, dict):
        raise ValueError("invalid authenticated transfer intent")
    sender, receiver = intent.get("sender"), intent.get("receiver")
    amount, nonce = intent.get("amount_nwei"), intent.get("nonce")
    limit = intent.get("fee_limit")
    if (not all(isinstance(key, str) and key for key in (sender, receiver))
            or len({sender, receiver, collector}) != 3 or intent.get("class") != "user"
            or intent.get("payload") not in ([], list(b"SYNACT01\x00"))
            or type(amount) is not int or not 0 < amount < 2**128
            or type(nonce) is not int or not 0 <= nonce < 2**64 - 1
            or not isinstance(limit, dict) or receipt["status"] != "applied"):
        raise ValueError("expected an applied native plain transfer with distinct fee collector")
    gas = receipt["gas_used"]
    gas_limit, fee_cap = limit.get("gas_limit"), limit.get("max_fee_per_gas_nwei")
    if (gas != 21_000 or type(gas_limit) is not int or not gas <= gas_limit < 2**64
            or type(fee_cap) is not int or not base_fee <= fee_cap < 2**64):
        raise ValueError("authenticated transfer does not match expected gas or signed fee limits")
    fee = gas * base_fee

    keys = (sender, receiver, collector)
    before = select_world_accounts(previous_world, keys)
    after = select_world_accounts(current_world, keys)
    if before[sender] is None or any(account is None for account in after.values()):
        raise ValueError("missing authenticated transfer account")
    zero = dict(balance_nwei="0", nonce="0")
    for address, delta in ((sender, -amount - fee), (receiver, amount), (collector, fee)):
        prior = before[address] or zero
        final = after[address]
        prior_nonce = int(prior["nonce"])
        if (int(final["balance_nwei"]) != int(prior["balance_nwei"]) + delta
                or int(final["nonce"]) != prior_nonce + (address == sender)
                or (address == sender and prior_nonce != nonce)):
            raise ValueError("authenticated transfer balance, fee, or nonce movement differs")
    return dict(sender=sender, receiver=receiver, fee_collector=collector,
                amount_nwei=str(amount), fee_nwei=str(fee), base_fee_per_gas_nwei=str(base_fee))


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
    sources = cli.add_mutually_exclusive_group(required=True)
    sources.add_argument("--observer", action="append")
    sources.add_argument("--evidence-dir", action="append", type=Path,
                         help="authorized directory of original HEIGHT.KIND.json proof bytes")
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
    cli.add_argument("--account", action="append", default=[],
                     help="exact account key to read from the authenticated World; repeat up to eight times")
    cli.add_argument("--receipt-id", help="select a transaction receipt from the authenticated block bytes")
    cli.add_argument("--receipt-height", type=int,
                     help="height at which the receipt must occur exactly once within the verified range")
    cli.add_argument("--fee-collector", help="independently authenticated fee collector for a plain transfer")
    cli.add_argument("--base-fee-per-gas-nwei", type=int,
                     help="independently authenticated base fee at the transfer height")
    cli.add_argument("--through-height", type=int, help="verify up to eight consecutive heights")
    cli.add_argument("--require-epoch-transition", action="store_true")
    args = cli.parse_args()
    last = args.height if args.through_height is None else args.through_height
    if not args.height <= last < args.height + MAX_HEIGHTS:
        cli.error("select one to eight consecutive finalized heights")
    if (len(args.account) > 8 or len(set(args.account)) != len(args.account)
            or any(not address or len(address) > 128 or not address.isascii()
                   or not address.isprintable() for address in args.account)):
        cli.error("select up to eight distinct account keys")
    verify_transfer = args.fee_collector is not None or args.base_fee_per_gas_nwei is not None
    verify_world = args.verify_world or bool(args.account) or verify_transfer
    if args.witness_only and verify_world:
        cli.error("World verification requires an original block preimage")
    receipt_height = args.receipt_height
    if args.receipt_id is not None:
        if receipt_height is None and last == args.height:
            receipt_height = args.height
        if (not HEX.fullmatch(args.receipt_id) or args.witness_only or receipt_height is None
                or not args.height <= receipt_height <= last):
            cli.error("receipt verification requires original block bytes and an exact transaction ID and height")
    elif receipt_height is not None:
        cli.error("--receipt-height requires --receipt-id")
    if verify_transfer and (
            not args.fee_collector or args.base_fee_per_gas_nwei is None
            or not 0 < args.base_fee_per_gas_nwei < 2**64
            or receipt_height is None or receipt_height <= args.height):
        cli.error("transfer accounting requires a fee collector, positive base fee, and receipt after the first verified height")
    if args.require_epoch_transition and last == args.height:
        cli.error("an epoch transition requires at least two heights")
    if args.chain <= 0 or args.height <= 0 or not HEX.fullmatch(args.genesis):
        cli.error("select an explicit network and finalized height")
    if args.observer:
        endpoints = [urlsplit(value) for value in args.observer]
        if (not 1 <= len(endpoints) <= 8 or any(
                e.scheme != "https" or not e.hostname or e.username is not None or e.query or e.fragment
                for e in endpoints) or len({e.hostname for e in endpoints}) != len(endpoints)):
            cli.error("select one to eight distinct HTTPS observer hosts")
        inputs, read_proof = args.observer, fetch_proof
    else:
        inputs = [directory.resolve() for directory in args.evidence_dir]
        if not 1 <= len(inputs) <= 8 or len(set(inputs)) != len(inputs) or not all(
                directory.is_dir() for directory in inputs):
            cli.error("select one to eight distinct existing evidence directories")
        read_proof = read_archived_proof

    range_mode = args.through_height is not None
    observations = []
    transitions = 0
    try:
        node = args.node.resolve(strict=True)
        config = args.config.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="posy-finality-") as directory:
            finality = Path(directory, "finality.json")
            block = Path(directory, "block.json")
            previous_worlds = {}
            for height in range(args.height, last + 1):
                agreed = None
                for endpoint in inputs:
                    proof_bytes = read_proof(endpoint, height, "finality")
                    finality.write_bytes(proof_bytes)
                    command = [str(node), "finality-proof", "verify", str(config), str(finality)]
                    if not args.witness_only:
                        block_bytes = read_proof(endpoint, height, "block_commitment")
                        block.write_bytes(block_bytes)
                        command.append(str(block))
                    native = verify_native(command, height)
                    observed = subject(native, args.chain, args.network, args.genesis, height,
                                       witness_only=args.witness_only)
                    if args.receipt_id is not None:
                        receipt = select_receipt(block_bytes, args.receipt_id,
                                                 expected=height == receipt_height)
                        if receipt is not None:
                            observed["receipt"] = receipt
                    if verify_world:
                        world_bytes = read_proof(endpoint, height, "world_state")
                        match_world_state(world_bytes, observed["state_root"])
                        if args.account:
                            observed["accounts"] = select_world_accounts(world_bytes, args.account)
                        if verify_transfer and height == receipt_height - 1:
                            previous_worlds[endpoint] = world_bytes
                        if verify_transfer and height == receipt_height:
                            observed["transfer_accounting"] = verify_plain_transfer(
                                block_bytes, observed["receipt"], previous_worlds.pop(endpoint),
                                world_bytes, args.fee_collector, args.base_fee_per_gas_nwei)
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
                  genesis_hash=args.genesis)
    if args.observer:
        result["observer_count"] = len(inputs)
    else:
        result["archive_input_count"] = len(inputs)
    if args.witness_only:
        result["block_preimage_verified"] = False
    if verify_world:
        result["world_preimage_verified"] = True
    if range_mode:
        result.update(start_height=args.height, through_height=last, epoch_transitions=transitions,
                      observations=observations)
        if receipt_height is not None:
            result["receipt_occurrences_in_verified_range"] = 1
    else:
        result.update(observations[0])
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
