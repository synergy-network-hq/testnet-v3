#!/usr/bin/env python3
"""Run evidence-producing Synergy Testnet TPS ramp or sustained tests.

The harness imports the existing signed-transfer helper instead of duplicating
testnet signing keys. Transactions are pre-signed so the reported throughput
measures RPC admission and chain commitment rather than local PQ signing speed.
Use the canonical operator-authorized Testnet RPC surface for benchmark writes.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import importlib.util
import json
import math
import os
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_sam_tool(path: Path):
    spec = importlib.util.spec_from_file_location("synergy_tps_sam_tool", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load signed-transfer helper from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_generated_wallets(wallet_dir: Path) -> dict[str, dict[str, Any]]:
    wallets = {}
    for path in sorted(wallet_dir.glob("wallet-*.json")):
        payload = json.loads(path.read_text())
        address = str(payload.get("address") or "").strip()
        public_key = str(payload.get("public_key") or "").strip()
        private_key = str(payload.get("private_key") or "").strip()
        if not address or not public_key or not private_key:
            raise RuntimeError(f"generated benchmark wallet is incomplete: {path}")
        label = path.stem
        wallets[label] = {
            "label": label,
            "address": address,
            "public_key": public_key,
            "private_key": private_key,
            "public_key_hex": base64.b64decode(public_key).hex(),
            "private_key_hex": base64.b64decode(private_key).hex(),
            "source_file": str(path),
        }
    if not wallets:
        raise RuntimeError(f"no wallet-*.json benchmark identities found in {wallet_dir}")
    return wallets


def rpc_raw(rpc_url: str, method: str, params: list[Any], timeout: int = 25) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"body": body}
        return {"transport_error": f"HTTP {exc.code}", "response": parsed}
    except Exception as exc:  # noqa: BLE001 - evidence must capture transport failures
        return {"transport_error": str(exc)}


def rpc_result(
    rpc_url: str,
    method: str,
    params: list[Any],
    timeout: int = 45,
    attempts: int = 3,
) -> Any:
    response = {}
    for attempt in range(1, attempts + 1):
        response = rpc_raw(rpc_url, method, params, timeout=timeout)
        if not response.get("transport_error"):
            break
        if attempt < attempts:
            time.sleep(attempt)
    if response.get("transport_error"):
        raise RuntimeError(
            f"{method}: {response['transport_error']} after {attempts} attempts"
        )
    if response.get("error"):
        error = response["error"]
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise RuntimeError(f"{method}: {message}")
    return response.get("result")


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * pct
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def quantiles(values: list[float]) -> dict[str, float | None]:
    return {
        "avg": statistics.fmean(values) if values else None,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values) if values else None,
    }


def pending_count(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("pending", "pending_count", "count", "size", "transactions"):
            item = value.get(key)
            if isinstance(item, list):
                return len(item)
            if isinstance(item, int):
                return item
    return None


def tx_hash_from_response(response: dict[str, Any]) -> str:
    result = response.get("result")
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        return str(
            result.get("tx_hash")
            or result.get("hash")
            or (result.get("transaction") or {}).get("hash")
            or ""
        )
    return ""


def response_error(response: dict[str, Any]) -> str | None:
    if response.get("transport_error"):
        return str(response["transport_error"])
    if response.get("error"):
        error = response["error"]
        if isinstance(error, dict):
            return str(error.get("message") or error)
        return str(error)
    result = response.get("result")
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("error") or result)
    return None


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, value: Any, lock: threading.Lock) -> None:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
    with lock:
        with path.open("a") as handle:
            handle.write(encoded + "\n")


def collect_preflight(rpc_url: str, senders: list[dict[str, Any]]) -> dict[str, Any]:
    methods = (
        "synergy_blockNumber",
        "synergy_getLatestBlock",
        "synergy_nodeInfo",
        "synergy_getNodeStatus",
        "synergy_getNetworkStats",
        "synergy_getTransactionPool",
    )
    rpc = {method: rpc_raw(rpc_url, method, []) for method in methods}
    def account(sender: dict[str, Any]) -> dict[str, Any]:
        address = sender["address"]
        return {
            "label": sender["label"],
            "address": address,
            "nonce": rpc_result(rpc_url, "synergy_getAccountNonce", [address]),
            "balance_nwei": rpc_result(
                rpc_url, "synergy_getTokenBalance", [address, "SNRG"]
            ),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(senders))) as executor:
        accounts = list(executor.map(account, senders))
    return {"captured_at": utc_now(), "rpc_url": rpc_url, "rpc": rpc, "accounts": accounts}


def prepare_transactions(
    *,
    sam,
    rpc_url: str,
    wallet_cli: str,
    sender_labels: list[str],
    wallets: dict[str, dict[str, Any]],
    run_id: str,
    stage_id: str,
    total: int,
    amount_nwei: int,
    gas_price: int,
    gas_limit: int,
    signing_workers: int,
) -> tuple[list[dict[str, Any]], dict[str, int], float]:
    def account_nonce(label: str) -> tuple[str, int]:
        nonce = rpc_result(
            rpc_url,
            "synergy_getAccountNonce",
            [wallets[label]["address"]],
        )
        return label, int(nonce or 0)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(16, len(sender_labels))
    ) as executor:
        starting_nonces = dict(executor.map(account_nonce, sender_labels))
    next_nonces = dict(starting_nonces)
    planned = []
    for index in range(total):
        sender_index = index % len(sender_labels)
        sender_label = sender_labels[sender_index]
        receiver_label = sender_labels[(sender_index + 1) % len(sender_labels)]
        if len(sender_labels) == 1:
            receiver_label = "faucet" if sender_label != "faucet" else "token-sales"
        sender = wallets[sender_label]
        receiver = wallets[receiver_label]["address"]
        nonce = next_nonces[sender_label]
        next_nonces[sender_label] += 1
        memo = json.dumps(
            {
                "source": "synergy-tps-benchmark",
                "run_id": run_id,
                "stage_id": stage_id,
                "sequence": index,
                "created_at": utc_now(),
                "unique_ns": time.time_ns(),
            },
            separators=(",", ":"),
        )
        unsigned = sam.build_unsigned_tx(
            sender,
            receiver,
            amount_nwei,
            nonce,
            gas_price,
            gas_limit,
            "fndsa",
            data=memo,
        )
        planned.append(
            {
                "sequence": index,
                "sender_label": sender_label,
                "sender": sender["address"],
                "receiver": receiver,
                "nonce": nonce,
                "unsigned": unsigned,
            }
        )

    started = time.monotonic()

    def sign(item: dict[str, Any]) -> dict[str, Any]:
        signed = sam.sign_tx(
            wallet_cli,
            wallets[item["sender_label"]],
            item["unsigned"],
            "fndsa",
        )
        result = dict(item)
        result.pop("unsigned", None)
        result["signed"] = signed
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=signing_workers) as executor:
        signed = list(executor.map(sign, planned))
    signing_seconds = time.monotonic() - started
    signed.sort(key=lambda item: item["sequence"])
    return signed, starting_nonces, signing_seconds


def submit_stage(
    *,
    rpc_url: str,
    transactions: list[dict[str, Any]],
    target_tps: float,
    events_path: Path,
    event_lock: threading.Lock,
) -> tuple[list[dict[str, Any]], float, float]:
    by_sender: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in transactions:
        by_sender[item["sender_label"]].append(item)

    stage_started_epoch = time.time()
    stage_started_mono = time.monotonic()

    def sender_worker(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        records = []
        for item in items:
            scheduled_mono = stage_started_mono + (item["sequence"] / target_tps)
            delay = scheduled_mono - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            submit_started_epoch = time.time()
            submit_started_mono = time.monotonic()
            response = rpc_raw(
                rpc_url,
                "synergy_sendTransaction",
                [item["signed"]],
                timeout=30,
            )
            submit_ended_epoch = time.time()
            error = response_error(response)
            tx_hash = tx_hash_from_response(response) if error is None else ""
            record = {
                "event": "submission",
                "sequence": item["sequence"],
                "sender_label": item["sender_label"],
                "sender": item["sender"],
                "receiver": item["receiver"],
                "nonce": item["nonce"],
                "scheduled_epoch": stage_started_epoch + (item["sequence"] / target_tps),
                "submit_started_epoch": submit_started_epoch,
                "submit_ended_epoch": submit_ended_epoch,
                "submit_latency_ms": (time.monotonic() - submit_started_mono) * 1000,
                "schedule_lag_ms": max(0.0, (submit_started_mono - scheduled_mono) * 1000),
                "accepted": error is None and bool(tx_hash),
                "tx_hash": tx_hash,
                "error": error,
                "response": response,
            }
            append_jsonl(events_path, record, event_lock)
            records.append(record)
        return records

    all_records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(by_sender)) as executor:
        futures = [executor.submit(sender_worker, items) for items in by_sender.values()]
        for future in concurrent.futures.as_completed(futures):
            all_records.extend(future.result())
    all_records.sort(key=lambda item: item["sequence"])
    submission_elapsed = time.monotonic() - stage_started_mono
    return all_records, stage_started_epoch, submission_elapsed


def wait_for_drain(
    *,
    rpc_url: str,
    timeout_seconds: int,
    events_path: Path,
    event_lock: threading.Lock,
) -> tuple[bool, list[dict[str, Any]], float]:
    started = time.monotonic()
    samples = []
    consecutive_empty = 0
    empty_streak_started_elapsed = None
    while time.monotonic() - started < timeout_seconds:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            pool_future = executor.submit(
                rpc_raw, rpc_url, "synergy_getTransactionPool", []
            )
            height_future = executor.submit(rpc_raw, rpc_url, "synergy_blockNumber", [])
            pool_response = pool_future.result()
            height_response = height_future.result()
        pool = pool_response.get("result") if not pool_response.get("error") else None
        count = pending_count(pool)
        height = height_response.get("result")
        sample = {
            "event": "mempool_sample",
            "captured_epoch": time.time(),
            "pending": count,
            "height": height,
            "pool_error": response_error(pool_response),
            "height_error": response_error(height_response),
        }
        samples.append(sample)
        append_jsonl(events_path, sample, event_lock)
        if count == 0:
            if consecutive_empty == 0:
                empty_streak_started_elapsed = time.monotonic() - started
            consecutive_empty += 1
            if consecutive_empty >= 2:
                return True, samples, float(empty_streak_started_elapsed or 0.0)
        else:
            consecutive_empty = 0
            empty_streak_started_elapsed = None
        time.sleep(1)
    return False, samples, time.monotonic() - started


def collect_receipts(
    *,
    rpc_url: str,
    submissions: list[dict[str, Any]],
    receipt_timeout_seconds: int,
    events_path: Path,
    event_lock: threading.Lock,
) -> list[dict[str, Any]]:
    accepted = [item for item in submissions if item["accepted"] and item["tx_hash"]]
    pending = {item["tx_hash"]: item for item in accepted}
    results: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + receipt_timeout_seconds

    def query(item: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        return item, rpc_raw(
            rpc_url,
            "synergy_getTransactionReceipt",
            [item["tx_hash"]],
            timeout=20,
        )

    while pending and time.monotonic() < deadline:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(pending))) as executor:
            for item, response in executor.map(query, list(pending.values())):
                receipt = response.get("result")
                if isinstance(receipt, dict) and receipt:
                    record = {
                        "event": "receipt",
                        "tx_hash": item["tx_hash"],
                        "sequence": item["sequence"],
                        "observed_epoch": time.time(),
                        "receipt": receipt,
                    }
                    results[item["tx_hash"]] = record
                    append_jsonl(events_path, record, event_lock)
                    pending.pop(item["tx_hash"], None)
        if pending:
            time.sleep(2)

    for item in pending.values():
        record = {
            "event": "receipt_timeout",
            "tx_hash": item["tx_hash"],
            "sequence": item["sequence"],
            "observed_epoch": time.time(),
        }
        results[item["tx_hash"]] = record
        append_jsonl(events_path, record, event_lock)
    return [results[item["tx_hash"]] for item in accepted]


def collect_blocks(rpc_url: str, receipts: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    numbers = sorted(
        {
            int(item["receipt"]["blockNumber"])
            for item in receipts
            if isinstance(item.get("receipt"), dict)
            and item["receipt"].get("blockNumber") is not None
        }
    )
    if numbers and numbers[0] > 0:
        numbers = sorted(set(numbers + [numbers[0] - 1]))

    def query(number: int) -> tuple[int, dict[str, Any]]:
        response = rpc_raw(rpc_url, "synergy_getBlockByNumber", [number], timeout=20)
        result = response.get("result")
        return number, result if isinstance(result, dict) else {}

    blocks = {}
    if numbers:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(numbers))) as executor:
            for number, block in executor.map(query, numbers):
                blocks[number] = block
    return blocks


def duplicate_probe(
    *,
    rpc_url: str,
    transaction: dict[str, Any] | None,
    events_path: Path,
    event_lock: threading.Lock,
) -> dict[str, Any] | None:
    if transaction is None:
        return None
    response = rpc_raw(
        rpc_url,
        "synergy_sendTransaction",
        [transaction["signed"]],
        timeout=30,
    )
    error = response_error(response)
    record = {
        "event": "duplicate_probe",
        "captured_epoch": time.time(),
        "original_sequence": transaction["sequence"],
        "rejected": error is not None,
        "error": error,
        "response": response,
    }
    append_jsonl(events_path, record, event_lock)
    return record


def summarize_stage(
    *,
    stage_id: str,
    target_tps: float,
    duration_seconds: float,
    signing_seconds: float,
    starting_nonces: dict[str, int],
    submissions: list[dict[str, Any]],
    stage_started_epoch: float,
    submission_elapsed: float,
    drained: bool,
    drain_samples: list[dict[str, Any]],
    drain_seconds: float,
    receipts: list[dict[str, Any]],
    blocks: dict[int, dict[str, Any]],
    duplicate: dict[str, Any] | None,
) -> dict[str, Any]:
    attempts = len(submissions)
    accepted = [item for item in submissions if item["accepted"]]
    failed = [item for item in submissions if not item["accepted"]]
    committed = [item for item in receipts if isinstance(item.get("receipt"), dict)]
    submission_by_hash = {item["tx_hash"]: item for item in accepted}
    submit_latencies = [item["submit_latency_ms"] for item in submissions]
    schedule_lags = [item["schedule_lag_ms"] for item in submissions]
    commit_latencies = []
    benchmark_by_block: dict[int, int] = defaultdict(int)
    for item in committed:
        receipt = item["receipt"]
        block_number = int(receipt["blockNumber"])
        benchmark_by_block[block_number] += 1
        block_timestamp = blocks.get(block_number, {}).get("timestamp")
        submitted = submission_by_hash.get(item["tx_hash"])
        if isinstance(block_timestamp, (int, float)) and submitted:
            commit_latencies.append(
                max(0.0, float(block_timestamp) - submitted["submit_started_epoch"])
                * 1000
            )

    per_block = []
    prior_timestamp = None
    for number in sorted(blocks):
        block = blocks[number]
        timestamp = block.get("timestamp")
        if not isinstance(timestamp, (int, float)):
            continue
        count = benchmark_by_block.get(number, 0)
        interval = None
        tps = None
        if prior_timestamp is not None and timestamp > prior_timestamp:
            interval = float(timestamp - prior_timestamp)
            tps = count / interval
        per_block.append(
            {
                "block_number": number,
                "timestamp": timestamp,
                "benchmark_transactions": count,
                "block_transactions": len(block.get("transactions") or []),
                "interval_seconds": interval,
                "benchmark_tps": tps,
            }
        )
        prior_timestamp = float(timestamp)

    included_blocks = [item for item in per_block if item["benchmark_transactions"] > 0]
    first_included = included_blocks[0] if included_blocks else None
    last_included = included_blocks[-1] if included_blocks else None
    previous_to_first = None
    if first_included:
        previous_to_first = next(
            (
                item
                for item in reversed(per_block)
                if item["block_number"] < first_included["block_number"]
            ),
            None,
        )
    block_window_seconds = None
    block_window_tps = None
    if previous_to_first and last_included:
        span = last_included["timestamp"] - previous_to_first["timestamp"]
        if span > 0:
            block_window_seconds = float(span)
            block_window_tps = len(committed) / block_window_seconds

    wall_seconds = max(0.001, (time.time() - stage_started_epoch))
    peak_pending = max(
        (item["pending"] for item in drain_samples if isinstance(item.get("pending"), int)),
        default=None,
    )
    request_start_epochs = sorted(
        float(item["submit_started_epoch"])
        for item in submissions
        if isinstance(item.get("submit_started_epoch"), (int, float))
    )
    request_start_interval_seconds = (
        request_start_epochs[-1] - request_start_epochs[0]
        if len(request_start_epochs) > 1
        else None
    )
    acceptance_rate = len(accepted) / attempts if attempts else 0.0
    finalization_rate = len(committed) / attempts if attempts else 0.0
    error_rate = len(failed) / attempts if attempts else 0.0
    offered_tps_actual = (
        (attempts - 1) / max(0.001, request_start_interval_seconds)
        if attempts > 1 and request_start_interval_seconds is not None
        else target_tps
    )
    offered_rate_ratio = offered_tps_actual / target_tps if target_tps else 0.0
    drain_limit_seconds = max(30.0, duration_seconds * 0.10)
    passed = (
        attempts > 0
        and acceptance_rate >= 0.99
        and finalization_rate >= 0.99
        and error_rate <= 0.01
        and offered_rate_ratio >= 0.95
        and drained
        and drain_seconds <= drain_limit_seconds
    )
    return {
        "stage_id": stage_id,
        "target_tps": target_tps,
        "target_duration_seconds": duration_seconds,
        "attempts": attempts,
        "accepted": len(accepted),
        "committed": len(committed),
        "failed": len(failed),
        "acceptance_rate": acceptance_rate,
        "finalization_rate": finalization_rate,
        "error_rate": error_rate,
        "signing_seconds_excluded_from_test": signing_seconds,
        "submission_elapsed_seconds": submission_elapsed,
        "request_start_interval_seconds": request_start_interval_seconds,
        "offered_tps_actual": offered_tps_actual,
        "offered_rate_ratio": offered_rate_ratio,
        "accepted_tps_submission_window": len(accepted) / max(0.001, submission_elapsed),
        "committed_tps_target_window": len(committed) / max(0.001, duration_seconds),
        "committed_tps_wall": len(committed) / wall_seconds,
        "block_window_seconds": block_window_seconds,
        "committed_tps_block_window": block_window_tps,
        "peak_block_tps": max(
            (item["benchmark_tps"] for item in included_blocks if item["benchmark_tps"] is not None),
            default=None,
        ),
        "rpc_submit_latency_ms": quantiles(submit_latencies),
        "schedule_lag_ms": quantiles(schedule_lags),
        "commit_latency_ms": quantiles(commit_latencies),
        "commit_latency_definition": "client submit start to committed block timestamp; committed receipt is the available inclusion/finality surface",
        "starting_nonces": starting_nonces,
        "mempool_peak_after_submission": peak_pending,
        "mempool_drained": drained,
        "mempool_drain_seconds": drain_seconds,
        "blocks": per_block,
        "duplicate_probe": duplicate,
        "drain_limit_seconds": drain_limit_seconds,
        "pass_criteria": ">=95% of target offered rate, >=99% accepted, >=99% committed, <=1% errors, and mempool drain within max(30s, 10% of test duration)",
        "pass": passed,
        "errors": [item["error"] for item in failed[:20]],
    }


def run_stage(
    *,
    args: argparse.Namespace,
    sam,
    wallets: dict[str, dict[str, Any]],
    sender_labels: list[str],
    wallet_cli: str,
    run_id: str,
    stage_id: str,
    target_tps: float,
    duration_seconds: float,
    total: int,
    output_dir: Path,
) -> dict[str, Any]:
    print(
        f"[{utc_now()}] preparing stage={stage_id} target_tps={target_tps:g} "
        f"duration={duration_seconds:g}s transactions={total}",
        flush=True,
    )
    events_path = output_dir / f"{stage_id}-events.jsonl"
    event_lock = threading.Lock()
    transactions, starting_nonces, signing_seconds = prepare_transactions(
        sam=sam,
        rpc_url=args.rpc_url,
        wallet_cli=wallet_cli,
        sender_labels=sender_labels,
        wallets=wallets,
        run_id=run_id,
        stage_id=stage_id,
        total=total,
        amount_nwei=args.amount_nwei,
        gas_price=args.gas_price,
        gas_limit=args.gas_limit,
        signing_workers=args.signing_workers,
    )
    print(
        f"[{utc_now()}] signed stage={stage_id} transactions={total} "
        f"seconds={signing_seconds:.2f}; starting submissions",
        flush=True,
    )
    submissions, stage_started_epoch, submission_elapsed = submit_stage(
        rpc_url=args.rpc_url,
        transactions=transactions,
        target_tps=target_tps,
        events_path=events_path,
        event_lock=event_lock,
    )
    accepted = sum(item["accepted"] for item in submissions)
    print(
        f"[{utc_now()}] submitted stage={stage_id} attempts={len(submissions)} "
        f"accepted={accepted} elapsed={submission_elapsed:.2f}s; waiting for drain",
        flush=True,
    )
    drained, drain_samples, drain_seconds = wait_for_drain(
        rpc_url=args.rpc_url,
        timeout_seconds=args.drain_timeout_seconds,
        events_path=events_path,
        event_lock=event_lock,
    )
    receipts = collect_receipts(
        rpc_url=args.rpc_url,
        submissions=submissions,
        receipt_timeout_seconds=args.receipt_timeout_seconds,
        events_path=events_path,
        event_lock=event_lock,
    )
    blocks = collect_blocks(args.rpc_url, receipts)
    first_accepted_sequence = next(
        (item["sequence"] for item in submissions if item["accepted"]), None
    )
    original = next(
        (
            item
            for item in transactions
            if item["sequence"] == first_accepted_sequence
        ),
        None,
    )
    duplicate = duplicate_probe(
        rpc_url=args.rpc_url,
        transaction=original,
        events_path=events_path,
        event_lock=event_lock,
    )
    summary = summarize_stage(
        stage_id=stage_id,
        target_tps=target_tps,
        duration_seconds=duration_seconds,
        signing_seconds=signing_seconds,
        starting_nonces=starting_nonces,
        submissions=submissions,
        stage_started_epoch=stage_started_epoch,
        submission_elapsed=submission_elapsed,
        drained=drained,
        drain_samples=drain_samples,
        drain_seconds=drain_seconds,
        receipts=receipts,
        blocks=blocks,
        duplicate=duplicate,
    )
    write_json(output_dir / f"{stage_id}-summary.json", summary)
    print(
        f"[{utc_now()}] complete stage={stage_id} committed={summary['committed']} "
        f"block_window_tps={summary['committed_tps_block_window']} pass={summary['pass']}",
        flush=True,
    )
    return summary


def parse_rates(value: str) -> list[float]:
    rates = []
    for item in value.split(","):
        rate = float(item.strip())
        if rate <= 0:
            raise argparse.ArgumentTypeError("rates must be positive")
        rates.append(rate)
    if not rates:
        raise argparse.ArgumentTypeError("at least one rate is required")
    return rates


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--sam-tool", required=True, type=Path)
    parser.add_argument("--wallet-cli", default=None)
    parser.add_argument("--wallet-dir", type=Path, default=None, help="Use provisioned wallet-*.json identities as benchmark senders")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--mode", choices=("ramp", "sustained"), default="ramp")
    parser.add_argument("--rates", type=parse_rates, default=parse_rates("1,2,4,8,16,32"))
    parser.add_argument("--stage-duration-seconds", type=float, default=15.0)
    parser.add_argument("--sustained-tps", type=float, default=4.0)
    parser.add_argument("--duration-seconds", type=float, default=600.0)
    parser.add_argument("--senders", default="presale,faucet,validator-rewards")
    parser.add_argument("--amount-nwei", type=int, default=1)
    parser.add_argument("--gas-price", type=int, default=1000)
    parser.add_argument("--gas-limit", type=int, default=21000)
    parser.add_argument("--signing-workers", type=int, default=max(2, min(12, os.cpu_count() or 4)))
    parser.add_argument("--drain-timeout-seconds", type=int, default=180)
    parser.add_argument("--receipt-timeout-seconds", type=int, default=180)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.sam_tool.is_file():
        raise SystemExit(f"signed-transfer helper not found: {args.sam_tool}")
    if args.amount_nwei <= 0 or args.gas_price <= 0 or args.gas_limit <= 0:
        raise SystemExit("amount, gas price, and gas limit must be positive")
    if args.stage_duration_seconds <= 0 or args.duration_seconds <= 0:
        raise SystemExit("durations must be positive")
    if args.sustained_tps <= 0:
        raise SystemExit("sustained TPS must be positive")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    sam = load_sam_tool(args.sam_tool)
    if args.wallet_dir is not None:
        wallets = load_generated_wallets(args.wallet_dir)
        sender_labels = list(wallets)
    else:
        sender_labels = [
            sam.normalize_sender_alias(item.strip())
            for item in args.senders.split(",")
            if item.strip()
        ]
        sender_labels = list(dict.fromkeys(sender_labels))
        if not sender_labels:
            raise SystemExit("at least one sender is required")
        supporting_labels = set(sender_labels) | {"faucet", "token-sales"}
        wallets = {label: sam.load_wallet(label) for label in supporting_labels}
    wallet_cli = sam.resolve_wallet_cli(args.wallet_cli)
    run_id = f"TPS-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    preflight = collect_preflight(
        args.rpc_url,
        [dict(wallets[label], label=label) for label in sender_labels],
    )
    preflight.update(
        {
            "run_id": run_id,
            "mode": args.mode,
            "sender_labels": sender_labels,
            "wallet_cli": wallet_cli,
            "signing_workers": args.signing_workers,
            "methodology": {
                "workload": "pre-signed FN-DSA native SNRG transfers with unique memo data",
                "submission_method": "synergy_sendTransaction",
                "reported_throughput_scope": "RPC admission through committed receipt",
                "pass_criteria": ">=95% of target offered rate, >=99% accepted, >=99% committed, <=1% errors, and mempool drain within max(30s, 10% of test duration)",
            },
        }
    )
    write_json(args.output_dir / "preflight.json", preflight)

    summaries = []
    if args.mode == "ramp":
        for index, rate in enumerate(args.rates, start=1):
            total = max(1, round(rate * args.stage_duration_seconds))
            summaries.append(
                run_stage(
                    args=args,
                    sam=sam,
                    wallets=wallets,
                    sender_labels=sender_labels,
                    wallet_cli=wallet_cli,
                    run_id=run_id,
                    stage_id=f"ramp-{index:02d}-{rate:g}tps",
                    target_tps=rate,
                    duration_seconds=args.stage_duration_seconds,
                    total=total,
                    output_dir=args.output_dir,
                )
            )
    else:
        total = max(1, round(args.sustained_tps * args.duration_seconds))
        summaries.append(
            run_stage(
                args=args,
                sam=sam,
                wallets=wallets,
                sender_labels=sender_labels,
                wallet_cli=wallet_cli,
                run_id=run_id,
                stage_id=f"sustained-{args.sustained_tps:g}tps-{args.duration_seconds:g}s",
                target_tps=args.sustained_tps,
                duration_seconds=args.duration_seconds,
                total=total,
                output_dir=args.output_dir,
            )
        )

    passed = [item for item in summaries if item["pass"]]
    aggregate = {
        "run_id": run_id,
        "mode": args.mode,
        "started_at": preflight["captured_at"],
        "completed_at": utc_now(),
        "rpc_url": args.rpc_url,
        "stages": summaries,
        "highest_passing_offered_tps": max(
            (item["target_tps"] for item in passed), default=None
        ),
        "highest_passing_committed_tps_block_window": max(
            (
                item["committed_tps_block_window"]
                for item in passed
                if item["committed_tps_block_window"] is not None
            ),
            default=None,
        ),
        "peak_committed_block_tps": max(
            (
                item["peak_block_tps"]
                for item in summaries
                if item["peak_block_tps"] is not None
            ),
            default=None,
        ),
        "all_stages_pass": len(passed) == len(summaries),
    }
    write_json(args.output_dir / "summary.json", aggregate)
    print(json.dumps(aggregate, indent=2, sort_keys=True), flush=True)
    return 0 if aggregate["all_stages_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
