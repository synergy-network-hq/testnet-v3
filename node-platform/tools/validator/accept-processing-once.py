#!/usr/bin/env python3
"""Custody-host once-only native authoring gate; no SSH, lifecycle or retries.

Read explicit request JSON on stdin. --preflight is read-only; --execute authors
and submits exactly one NEW intent, then verifies the exact all-five effects
without a transaction-latency acceptance deadline. Never invoke a consumed workdir.
Native keytool alone reads signing custody. The optional existing relay bearer
token is read privately and is never written to evidence or output.
"""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.request

RELAY_TOKEN = None
ACTIVE_ROOT = None
STAGE_TIMES = {}


def stage_elapsed(started):
    """Persist only elapsed durations; raw monotonic epochs are process-local."""
    return {name.replace("_monotonic", "_seconds"): round(value - started, 6)
        for name, value in STAGE_TIMES.items()}


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def sized(value, width=8):
    return len(value).to_bytes(width, "big") + value


def rpc(url, method, params, timeout=5):
    headers = {"Content-Type": "application/json"}
    if RELAY_TOKEN is not None:
        headers["Authorization"] = "Bearer " + RELAY_TOKEN
    req = urllib.request.Request(url, data=encoded({"jsonrpc": "2.0", "id": 1,
        "method": method, "params": params}), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as stream:
        value = json.load(stream)
    if "error" in value:
        raise RuntimeError(f"{method}: {value['error']}")
    return value["result"]


def fleet(endpoints, method, params, deadline=None):
    def one(item):
        name, url = item
        timeout = 5 if deadline is None else min(5, max(.001, deadline-time.monotonic()))
        return name, rpc(url, method, params, timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as workers:
        return dict(workers.map(one, endpoints.items()))


def reconciliation_receipts(endpoints, receipt_id):
    """A retired receipt is not an admission failure.

    The node intentionally drops an admission receipt after its finalized
    transaction is retained/verified elsewhere.  Preflight must pass that
    exact identity to the transaction reconciliation step rather than aborting
    before a new, unrelated nonce can be safely considered.
    """
    def one(item):
        name, url = item
        try:
            return name, rpc(url, "synergy_getProtectedAdmissionReceipt", {"receipt_id": receipt_id})
        except RuntimeError as error:
            if "admission receipt unavailable; verify finalized transaction before retry" in str(error):
                return name, {"status": "unavailable_after_retention", "receipt_id": receipt_id}
            raise
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as workers:
        return dict(workers.map(one, endpoints.items()))


def equal(values):
    assert len({json.dumps(v, sort_keys=True) for v in values.values()}) == 1, "all-five differ"
    return next(iter(values.values()))


def write(root, name, value):
    fd = os.open(root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(root, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)



def complete_handoff(root, result):
    """Keep the only measured stage result until its external consumer succeeds."""
    path = root / "handoff.json"
    current = json.loads(path.read_text())
    assert current["transaction_id"] == result["transaction_id"]
    assert current["receipt_id"] == result["receipt_id"]
    current.update(result)
    temporary = root / ".handoff-result.tmp"
    try:
        write(root, temporary.name, current)
        os.replace(temporary, path)
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def cleanup_operation(root):
    """Only this invocation's disposable files; never custody or live state."""
    handed_off = (root/"handoff.json").exists()
    if not handed_off and not (root/"verified.json").exists() and (root/"submission-intent.json").exists() and not (root/"FAILED.json").exists():
        write(root, "FAILED.json", {"reason": "verification interrupted; reconcile exact intent before any further action", "no_retry": True})
    disposable = ["preflight.json", "context.json", "input.json", "admission.json", "submission-response.json"]
    if (root/"verified.json").exists():
        disposable += ["submission-intent.json", "FAILED.json"]
    elif handed_off:
        # The external all-five verifier owns the exact intent from here.
        # Keep only its immutable handoff and the sole submission identity.
        disposable += ["FAILED.json"]
    for name in disposable:
        try:
            (root/name).unlink()
        except FileNotFoundError:
            pass
    directory = os.open(root, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if not any(root.iterdir()):
        root.rmdir()


def main():
    global RELAY_TOKEN, ACTIVE_ROOT
    assert sys.argv[1:] in [["--preflight"], ["--execute"], ["--author-submit"]]
    STAGE_TIMES.clear()
    request = json.load(sys.stdin)
    if request.get("relay_token_file"):
        fd = os.open(request["relay_token_file"], os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            assert stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600, "private regular0600 relay token required"
            raw_token = os.read(fd, 257).strip()
            assert 32 <= len(raw_token) <= 256 and re.fullmatch(rb"[A-Za-z0-9_-]+", raw_token), "invalid relay token format"
            RELAY_TOKEN = raw_token.decode("ascii")
        finally:
            os.close(fd)
    endpoints = request["endpoints"]
    author_submit = sys.argv[1] == "--author-submit"
    assert set(endpoints) == ({"val2"} if author_submit else {f"val{i}" for i in range(2, 7)})
    root = Path(request["workdir"])
    assert root.is_absolute() and not root.exists(), "fresh immutable operation directory required"
    os.umask(0o077); root.mkdir(mode=0o700)
    ACTIVE_ROOT = root
    config = json.loads(Path(request["config"]).read_text())
    authority = json.loads(Path(config["consensus"]["authority_binding"]).read_text())["payload"]
    assert authority["chain_id"] == config["chain_id"] and authority["network_id"] == config["network_id"]
    public = json.loads(Path(request["wallet_public_path"]).read_text())
    target = json.loads(Path(request["target_wallet_public_path"]).read_text())
    sender = public["sender"]; receiver = request["receiver"]
    mode = request["operation"]
    assert mode in ("register", "transfer")
    telemetry = fleet(endpoints, "synergy_chainTelemetry", {})
    assert all(v["chain_id"] == config["chain_id"] and v["network_identity"] == config["network_id"] for v in telemetry.values())
    height = min(v["finalized_height"] for v in telemetry.values())
    before = equal(fleet(endpoints, "synergy_getAccount", {"address": sender, "at_height": height}))
    receiver_before = equal(fleet(endpoints, "synergy_getAccount", {"address": receiver, "at_height": height}))
    target_before = equal(fleet(endpoints, "synergy_getAccount", {"address": target["sender"], "at_height": height}))
    assert before["authorization_binding"] == public["genesis_binding_commitment"], "sponsor/sender not authorized"
    if sys.argv[1] == "--execute" or "expected_nonce" in request:
        assert before["nonce"] == request["expected_nonce"], "nonce changed; reconcile, never guess/retry"
    assert (sender, before["nonce"]) not in {(x["sender"], x["nonce"]) for x in request["unresolved_intents"]}, "unresolved sender nonce"
    if mode == "register":
        assert not (target_before or {}).get("authorization_binding"), "target already bound; do not register again"
    else:
        assert target["sender"] == sender
    reconciliation = []
    for intent in request["prior_intents"]:
        reconciliation.append({**intent,
            "transaction": fleet(endpoints, "synergy_getTransaction", {"transaction_id": intent["transaction_id"]}),
            "admission": reconciliation_receipts(endpoints, intent["receipt_id"])})
    if sys.argv[1] == "--preflight":
        concise = [{"transaction_id": item["transaction_id"], "receipt_id": item["receipt_id"],
            "transaction": {name: {key: value.get(key) for key in ("status", "block_height", "block_hash")} if value else None
                for name, value in item["transaction"].items()},
            "admission": {name: {key: value.get(key) for key in ("status", "lifecycle_status", "reason_code")} if value else None
                for name, value in item["admission"].items()}} for item in reconciliation]
        print(json.dumps({"preflight_only": True, "height": height, "sender": sender, "nonce": before["nonce"],
            "sender_account": before, "receiver_account": receiver_before, "target_account": target_before,
            "resource_budget": {name: value.get("resource_budget") for name, value in telemetry.items()},
            "prior_intents": concise, "temporary_output_removed": True})); return
    # Bound authoring/transport only; this is not a transaction-processing deadline.
    started = time.monotonic(); deadline = started + 30
    STAGE_TIMES["context_started_monotonic"] = started
    context = rpc(endpoints["val2"], "synergy_getProcessingContextV1", {})
    STAGE_TIMES["context_received_monotonic"] = time.monotonic()
    binding = context["context"]["authority"]
    assert binding["chain_id"] == config["chain_id"] and binding["network_id"] == config["network_id"]
    assert context["ingress_kem_registry"] == authority["protected"]["ingress_kem_registry"]
    assert binding["epoch"] == authority["epoch"] and context["profile_id"] == "etdag-async-processing-v1"
    write(root, "context.json", context)
    gas = request["gas_limit"]
    assert type(gas) is int and 0 < gas <= authority["protected"]["parameters"]["max_protected_gas"]
    amount = 0 if mode == "register" else request["amount_nwei"]
    transfer = {"wallet_public_path": request["wallet_public_path"],
        "transaction_secret_path": request["transaction_secret_path"],
        "admission_context_path": str(root/"context.json"), "sender": sender, "receiver": receiver,
        "amount_nwei": amount, "nonce": before["nonce"], "timestamp_unix": int(time.time()),
        "gas_limit": gas, "max_fee_per_gas_nwei": 40, "gas_class_units": gas, "fee_class": 1,
        "content_blind_order_key": hashlib.sha3_512(sized(b"SYNERGY_REAL_ACCEPTANCE_ORDER_V1")+sized(os.urandom(32))).hexdigest()}
    payload = b""
    if mode == "register":
        carrier = encoded(target["identity_authorization"])
        transfer["action"] = {"kind": "native", "module": "identity", "method": "register_authorization", "input": list(carrier)}
        payload = b"SYNACT01\x01" + sized(b"identity", 4) + sized(b"register_authorization", 4) + sized(carrier, 4)
    write(root, "input.json", transfer)
    subprocess.run([request["keytool"], "prepare-wallet-processing-admission", str(root/"input.json"), str(root/"admission.json")],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True, timeout=max(.001, deadline-time.monotonic()))
    STAGE_TIMES["native_admission_signed_monotonic"] = time.monotonic()
    raw = (root/"admission.json").read_bytes(); admission = json.loads(raw)
    signing = (b"SYNERGY_TRANSACTION_SIGNING_V1" + config["chain_id"].to_bytes(8, "big") + sized(config["network_id"].encode()) + b"\0"
        + sized(sender.encode()) + sized(receiver.encode()) + amount.to_bytes(16, "big") + before["nonce"].to_bytes(8, "big")
        + gas.to_bytes(8, "big") + (40).to_bytes(8, "big") + transfer["timestamp_unix"].to_bytes(8, "big") + sized(payload))
    txid = hashlib.sha3_256(b"SYNERGY_TRANSACTION_ID_V1" + sized(signing)).hexdigest()
    receipt = hashlib.sha3_512(sized(b"SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1") + sized(raw)).hexdigest()
    expected_unsigned = {"network": {"chain_id": config["chain_id"], "network_id": config["network_id"]},
        "class": "user", "sender": sender, "receiver": receiver, "amount_nwei": amount,
        "nonce": before["nonce"], "fee_limit": {"gas_limit": gas, "max_fee_per_gas_nwei": 40},
        "timestamp_unix": transfer["timestamp_unix"], "payload": list(payload)}
    write(root, "submission-intent.json", {"transaction_id": txid, "receipt_id": receipt, "sender": sender,
        "nonce": before["nonce"], "operation": mode, "context_started_monotonic": started,
                "stage_elapsed_seconds": stage_elapsed(started),
        "unsigned": expected_unsigned,
        "only_submission_attempt": True, "no_automatic_retry": True, "admission_sha256": hashlib.sha256(raw).hexdigest()})
    assert time.monotonic() < deadline, "deadline before submission; intent retained"
    response = rpc(endpoints["val2"], "synergy_submitProcessingTransactionV1", admission, min(5, deadline-time.monotonic()))
    STAGE_TIMES["submit_response_monotonic"] = time.monotonic()
    write(root, "submission-response.json", response)
    assert response["receipt_id"] == receipt
    if author_submit:
        # The custody host cannot reach the other validators' loopback RPCs.
        # Retain the exact public intent until the external consumer has
        # returned the all-five result to its caller.  A receipt alone cannot
        # later prove a transfer after normal candidate retention.
        write(root, "handoff.json", {"transaction_id": txid, "receipt_id": receipt,
            "sender": sender, "nonce": before["nonce"], "operation": mode,
            "submitted_at_unix_ms": int(time.time() * 1000),
            "stage_elapsed_seconds": stage_elapsed(started),
            "expected_unsigned": expected_unsigned,
            "sender_before": {key: before[key] for key in ("balance_nwei", "nonce", "state_root", "finalized_height")},
            "receiver_before": None if receiver_before is None else {key: receiver_before[key] for key in ("balance_nwei", "nonce", "state_root", "finalized_height")},
            "external_all_five_verification_required": True,
            "cleanup_rule": "retain handoff until external all-five result is returned",
            "no_automatic_retry": True})
        # Observe locally so network round trips cannot hide short receipt
        # transitions. Return these measurements directly to the consumer.
        receipt_stages = []
        seconds = request.get("observe_receipt_seconds", 0)
        assert isinstance(seconds, (int, float)) and 0 <= seconds <= 180
        until = time.monotonic() + seconds
        previous = None
        observation_error = None
        while seconds and time.monotonic() < until:
            try:
                value = rpc(endpoints["val2"], "synergy_getProtectedAdmissionReceipt", {"receipt_id": receipt})
            except (OSError, RuntimeError) as error:
                # Return consumed timing observations even if the node fails.
                # The immutable submission identity remains for reconciliation;
                # an interrupted observation never authorizes another submit.
                observation_error = {"type": type(error).__name__, "message": str(error)[:240]}
                break
            status = value.get("lifecycle_status", value.get("status"))
            if status != previous:
                receipt_stages.append({"stage": status, "elapsed_seconds": round(time.monotonic()-started, 6),
                    "proof": value.get("stage_evidence")})
                previous = status
            if status in ("finalized", "rejected"):
                break
            time.sleep(.025)
        result = {"handoff": True, "transaction_id": txid, "receipt_id": receipt,
            "sender": sender, "nonce": before["nonce"],
            "stage_elapsed_seconds": stage_elapsed(started),
            "receipt_stages": receipt_stages, "observation_error": observation_error,
            "workdir": str(root)}
        complete_handoff(root, result)
        print(json.dumps(result)); return
    deadline = None
    while True:
        cadence = fleet(endpoints, "synergy_chainTelemetry", {})
        assert all(0 <= item["chain"]["cadence"]["current_gap_ms"] <= 30000 for item in cadence.values()), "block-finality gap exceeds30s"
        admission_status = rpc(endpoints["val2"], "synergy_getProtectedAdmissionReceipt", {"receipt_id": receipt}, 5)
        if admission_status and admission_status.get("status") == "accepted" and "accepted_on_val2_monotonic" not in STAGE_TIMES:
            STAGE_TIMES["accepted_on_val2_monotonic"] = time.monotonic()
        if admission_status and admission_status.get("status") == "rejected":
            write(root, "FAILED.json", {"reason": "native admission rejected", "reason_code": admission_status.get("reason_code"),
                "transaction_id": txid, "receipt_id": receipt, "no_retry": True,
                "stage_elapsed_seconds": stage_elapsed(started)})
            raise RuntimeError("native admission rejected; sole intent retained, never resubmit")
        transactions = fleet(endpoints, "synergy_getTransaction", {"transaction_id": txid}, deadline)
        if all(v and v.get("status") == "applied" for v in transactions.values()):
            STAGE_TIMES["applied_on_all_five_monotonic"] = time.monotonic()
            transaction = equal(transactions); h = transaction["block_height"]
            blocks = fleet(endpoints, "synergy_getBlock", {"height": h}, deadline); block = equal(blocks)
            STAGE_TIMES["matching_block_read_monotonic"] = time.monotonic()
            assert transaction["transaction"]["unsigned"] == expected_unsigned
            assert transaction["transaction"]["signature_algorithm"] == "ML-DSA-87"
            assert block["height"] == h and block["block_hash"] == transaction["block_hash"]
            assert block["finality_certificate_id"] == transaction["finality_certificate_id"]
            assert block["protected_execution_root"] and block["finality_certificate_id"]
            after = equal(fleet(endpoints, "synergy_getAccount", {"address": sender, "at_height": h}, deadline))
            receiver_after = equal(fleet(endpoints, "synergy_getAccount", {"address": receiver, "at_height": h}, deadline))
            target_after = equal(fleet(endpoints, "synergy_getAccount", {"address": target["sender"], "at_height": h}, deadline))
            STAGE_TIMES["all_five_effect_reads_monotonic"] = time.monotonic()
            native = transaction["receipt"]; assert native["status"] == "applied" and native["error_code"] is None
            fee = native["gas_used"] * 40
            assert 0 < native["gas_used"] <= gas
            assert after["nonce"] == before["nonce"] + 1
            assert int(before["balance_nwei"]) - int(after["balance_nwei"]) == amount + fee
            if mode == "register":
                assert target_after["authorization_binding"] == target["genesis_binding_commitment"]
            else:
                assert sender != receiver and int(receiver_after["balance_nwei"]) - int(receiver_before["balance_nwei"]) == amount
                assert native["gas_used"] == 21000
            assert after["state_root"] == receiver_after["state_root"] == block["state_root"]
            write(root, "verified.json", {"transaction_id": txid, "receipt_id": receipt, "height": h,
                "sender": sender, "nonce": before["nonce"], "operation": mode,
                "elapsed_seconds": time.monotonic()-started, "all_five_exact_effects": True,
                "stage_elapsed_seconds": stage_elapsed(started),
                "block_hash": block["block_hash"], "finality_certificate_id": block["finality_certificate_id"],
                "state_root": block["state_root"], "fee_nwei": fee})
            print(json.dumps({"verified": True, "transaction_id": txid, "height": h, "workdir": str(root)})); return
        time.sleep(.1)


if __name__ == "__main__":
    try:
        main()
    finally:
        if ACTIVE_ROOT is not None:
            cleanup_operation(ACTIVE_ROOT)
