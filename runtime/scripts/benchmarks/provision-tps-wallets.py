#!/usr/bin/env python3
"""Generate and fund isolated wallets for Synergy Testnet TPS benchmarks."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def derive_runtime_wallet_address(public_key_b64: str, sam: Any) -> str:
    """Derive the canonical 41-character SNTS-01 address used by v19."""
    public_key = base64.b64decode(public_key_b64, validate=True)
    digest = hashlib.sha3_256(public_key).digest()
    digest_bits = int.from_bytes(digest, "big")
    data_values = [
        (digest_bits >> (256 - (5 * (index + 1)))) & 0x1F
        for index in range(30)
    ]
    checksum = sam.bech32_polymod(
        sam.bech32_hrp_expand("synw") + data_values + ([0] * 6)
    ) ^ sam.SYNERGY_BECH32M_CONST
    checksum_values = [
        (checksum >> (5 * (5 - index))) & 0x1F for index in range(6)
    ]
    address = "synw1" + "".join(
        sam.SYNERGY_BECH32_CHARSET[value]
        for value in data_values + checksum_values
    )
    valid, reason = sam.validate_synergy_transfer_address(address)
    if not valid:
        raise RuntimeError(f"derived runtime wallet address is invalid: {reason}")
    return address


def load_benchmark_module(path: Path):
    spec = importlib.util.spec_from_file_location("synergy_tps_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load TPS benchmark module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--sam-tool", required=True, type=Path)
    parser.add_argument("--wallet-cli", required=True)
    parser.add_argument("--address-engine", required=True, type=Path)
    parser.add_argument("--wallet-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--wallet-count", type=int, default=64)
    parser.add_argument("--funding-snrg", type=int, default=10)
    parser.add_argument("--funding-tps", type=float, default=1.5)
    parser.add_argument("--signing-workers", type=int, default=12)
    parser.add_argument("--drain-timeout-seconds", type=int, default=180)
    parser.add_argument("--receipt-timeout-seconds", type=int, default=180)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.wallet_count <= 0 or args.funding_snrg <= 0 or args.funding_tps <= 0:
        raise SystemExit("wallet count, funding amount, and funding TPS must be positive")
    benchmark_path = Path(__file__).with_name("tps-benchmark.py")
    benchmark = load_benchmark_module(benchmark_path)
    sam = benchmark.load_sam_tool(args.sam_tool)
    args.wallet_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    existing = sorted(args.wallet_dir.glob("wallet-*.json"))
    if existing:
        raise SystemExit(
            f"wallet directory already contains {len(existing)} wallet files; use a fresh directory to avoid overwriting keys"
        )

    print(f"[{benchmark.utc_now()}] generating {args.wallet_count} benchmark wallets", flush=True)

    def generate(index: int) -> Path:
        path = args.wallet_dir / f"wallet-{index:03d}.json"
        subprocess.run(
            [
                str(args.address_engine),
                "--node-type",
                "wallet",
                "--output",
                str(path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        identity = json.loads(path.read_text())
        engine_address = str(identity.get("address") or "")
        identity["address_engine_address"] = engine_address
        identity["address"] = derive_runtime_wallet_address(
            str(identity.get("public_key") or ""),
            sam,
        )
        identity["address_derivation"] = "SNTS-01 v19 canonical 41-character form"
        path.write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")
        path.chmod(0o600)
        return path

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, args.wallet_count)) as executor:
        list(executor.map(generate, range(1, args.wallet_count + 1)))

    generated = benchmark.load_generated_wallets(args.wallet_dir)
    funder_labels = ["token-sales", "faucet", "validator-rewards"]
    funders = {label: sam.load_wallet(label) for label in funder_labels}
    starting_nonces = {
        label: int(
            benchmark.rpc_result(
                args.rpc_url,
                "synergy_getAccountNonce",
                [funders[label]["address"]],
            )
            or 0
        )
        for label in funder_labels
    }
    next_nonces = dict(starting_nonces)
    funding_amount_nwei = args.funding_snrg * 1_000_000_000
    planned: list[dict[str, Any]] = []
    run_id = f"TPS-PROVISION-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    for sequence, (wallet_label, wallet) in enumerate(generated.items()):
        funder_label = funder_labels[sequence % len(funder_labels)]
        funder = funders[funder_label]
        nonce = next_nonces[funder_label]
        next_nonces[funder_label] += 1
        data = json.dumps(
            {
                "source": "synergy-tps-wallet-provisioning",
                "run_id": run_id,
                "wallet_label": wallet_label,
                "sequence": sequence,
                "unique_ns": time.time_ns(),
            },
            separators=(",", ":"),
        )
        unsigned = sam.build_unsigned_tx(
            funder,
            wallet["address"],
            funding_amount_nwei,
            nonce,
            1000,
            21000,
            "fndsa",
            data=data,
        )
        planned.append(
            {
                "sequence": sequence,
                "sender_label": funder_label,
                "sender": funder["address"],
                "receiver": wallet["address"],
                "receiver_label": wallet_label,
                "nonce": nonce,
                "unsigned": unsigned,
            }
        )

    def sign(item: dict[str, Any]) -> dict[str, Any]:
        result = dict(item)
        result["signed"] = sam.sign_tx(
            args.wallet_cli,
            funders[item["sender_label"]],
            item["unsigned"],
            "fndsa",
        )
        result.pop("unsigned", None)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.signing_workers) as executor:
        transactions = list(executor.map(sign, planned))
    transactions.sort(key=lambda item: item["sequence"])

    events_path = args.output_dir / "provision-events.jsonl"
    event_lock = threading.Lock()
    submissions, stage_started_epoch, submission_elapsed = benchmark.submit_stage(
        rpc_url=args.rpc_url,
        transactions=transactions,
        target_tps=args.funding_tps,
        events_path=events_path,
        event_lock=event_lock,
    )
    accepted = sum(item["accepted"] for item in submissions)
    print(
        f"[{benchmark.utc_now()}] funding submitted attempts={len(submissions)} accepted={accepted}; waiting for drain",
        flush=True,
    )
    drained, drain_samples, drain_seconds = benchmark.wait_for_drain(
        rpc_url=args.rpc_url,
        timeout_seconds=args.drain_timeout_seconds,
        events_path=events_path,
        event_lock=event_lock,
    )
    receipts = benchmark.collect_receipts(
        rpc_url=args.rpc_url,
        submissions=submissions,
        receipt_timeout_seconds=args.receipt_timeout_seconds,
        events_path=events_path,
        event_lock=event_lock,
    )
    committed = sum(isinstance(item.get("receipt"), dict) for item in receipts)

    def wallet_record(item: tuple[str, dict[str, Any]]) -> dict[str, Any]:
        label, wallet = item
        balance = benchmark.rpc_result(
            args.rpc_url,
            "synergy_getTokenBalance",
            [wallet["address"], "SNRG"],
        )
        nonce = benchmark.rpc_result(
            args.rpc_url,
            "synergy_getAccountNonce",
            [wallet["address"]],
        )
        return {
            "label": label,
            "address": wallet["address"],
            "wallet_file": wallet["source_file"],
            "balance_nwei": balance,
            "nonce": nonce,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        manifest_wallets = list(executor.map(wallet_record, generated.items()))
    funded = sum(int(item["balance_nwei"] or 0) >= funding_amount_nwei for item in manifest_wallets)
    summary = {
        "run_id": run_id,
        "completed_at": benchmark.utc_now(),
        "rpc_url": args.rpc_url,
        "wallet_count": args.wallet_count,
        "funding_snrg_per_wallet": args.funding_snrg,
        "starting_funder_nonces": starting_nonces,
        "attempts": len(submissions),
        "accepted": accepted,
        "committed": committed,
        "funded_wallets": funded,
        "submission_elapsed_seconds": submission_elapsed,
        "stage_started_epoch": stage_started_epoch,
        "mempool_drained": drained,
        "mempool_drain_seconds": drain_seconds,
        "mempool_peak_after_submission": max(
            (item["pending"] for item in drain_samples if isinstance(item.get("pending"), int)),
            default=None,
        ),
        "wallets": manifest_wallets,
        "pass": accepted == args.wallet_count and committed == args.wallet_count and funded == args.wallet_count and drained,
    }
    benchmark.write_json(args.output_dir / "wallet-manifest.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0 if summary["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
