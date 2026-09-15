#!/usr/bin/env python3
"""Alternate SNRG transfers between the faucet and Token Sales wallets.

Default behavior sends 1 SNRG every 5 seconds for one hour, starting with
faucet -> Token Sales, then Token Sales -> faucet, repeating until duration
expires. Transactions are signed locally with wallet-pqc-cli and submitted to
the public Testnet RPC with synergy_sendTransaction.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path


DEFAULT_RPC_URL = "https://testnet-core-rpc.synergy-network.io"
DEFAULT_FAUCET_KEY = "/Users/devpup/Desktop/synergy-testnet-data-files/testnet-keyfiles/faucet.dec.json"
DEFAULT_TOKEN_SALES_KEY = "/Users/devpup/Desktop/synergy-testnet-data-files/new-network-addresses/TokenSalesWallet.dec.json"
NWEI_PER_SNRG = Decimal("1000000000")
DEFAULT_GAS_PRICE = 1000
DEFAULT_GAS_LIMIT = 21000


def load_dag_module():
    module_path = Path(__file__).with_name("send-testnet-dag-transactions.py")
    spec = importlib.util.spec_from_file_location("synergy_dag_tx", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load helper module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dag = load_dag_module()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def amount_to_nwei(amount_snrg: str) -> int:
    try:
        amount = Decimal(amount_snrg)
    except InvalidOperation as exc:
        raise ValueError("--amount-snrg must be a valid decimal") from exc
    if amount <= 0:
        raise ValueError("--amount-snrg must be positive")
    nwei = amount * NWEI_PER_SNRG
    if nwei != nwei.to_integral_value():
        raise ValueError("--amount-snrg supports no more than 9 decimal places")
    return int(nwei)


def format_snrg(nwei: int) -> str:
    value = Decimal(nwei) / NWEI_PER_SNRG
    text = f"{value:.9f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


def write_jsonl(path: Path | None, entry: dict) -> None:
    if path is None:
        return
    with path.open("a") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


def planned_count(duration_seconds: float, interval_seconds: float, max_transactions: int | None) -> int:
    if duration_seconds <= 0:
        raise ValueError("--duration-seconds must be positive")
    if interval_seconds <= 0:
        raise ValueError("--interval-seconds must be positive")
    count = max(1, math.ceil(duration_seconds / interval_seconds))
    if max_transactions is not None:
        count = min(count, max_transactions)
    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send alternating signed 1 SNRG Testnet transfers between faucet and Token Sales wallets."
    )
    parser.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_ENDPOINT", DEFAULT_RPC_URL))
    parser.add_argument("--faucet-key", default=os.environ.get("SYNERGY_FAUCET_KEYFILE", DEFAULT_FAUCET_KEY))
    parser.add_argument("--token-sales-key", default=os.environ.get("SYNERGY_TOKEN_SALES_KEYFILE", DEFAULT_TOKEN_SALES_KEY))
    parser.add_argument("--duration-seconds", type=float, default=3600.0)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--amount-snrg", default="1")
    parser.add_argument("--gas-price", type=int, default=DEFAULT_GAS_PRICE)
    parser.add_argument("--gas-limit", type=int, default=DEFAULT_GAS_LIMIT)
    parser.add_argument("--algo", choices=["fndsa"], default="fndsa")
    parser.add_argument("--wallet-cli", default=None)
    parser.add_argument("--build-cli", action="store_true", help="Build wallet-pqc-cli if it is missing.")
    parser.add_argument("--wait-receipts", action="store_true")
    parser.add_argument("--receipt-timeout-seconds", type=int, default=45)
    parser.add_argument("--skip-balance-check", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-transactions", type=int, default=None, help="Cap transactions for smoke tests.")
    parser.add_argument("--log-file", default=None, help="Optional JSONL log file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    amount_nwei = amount_to_nwei(args.amount_snrg)
    fee_nwei = args.gas_price * args.gas_limit
    total_planned = planned_count(args.duration_seconds, args.interval_seconds, args.max_transactions)
    faucet_planned = (total_planned + 1) // 2
    token_sales_planned = total_planned // 2
    log_file = Path(args.log_file).expanduser() if args.log_file else None

    faucet = dag.load_sender(Path(args.faucet_key).expanduser())
    faucet.label = "faucet"
    token_sales = dag.load_sender(Path(args.token_sales_key).expanduser())
    token_sales.label = "token-sales"

    try:
        wallet_cli = dag.resolve_wallet_cli(args.wallet_cli)
    except FileNotFoundError:
        if args.build_cli:
            dag.build_wallet_cli()
            wallet_cli = dag.resolve_wallet_cli(args.wallet_cli)
        else:
            raise

    head = dag.rpc_call(args.rpc_url, "synergy_blockNumber", [])
    if head.get("error"):
        raise RuntimeError(f"RPC preflight failed: {head['error']}")

    print(f"[{utc_now()}] Faucet <-> Token Sales ping-pong")
    print(f"  rpc_url             : {args.rpc_url}")
    print(f"  head_block          : {head.get('result')}")
    print(f"  wallet_cli          : {wallet_cli}")
    print(f"  faucet              : {faucet.address}")
    print(f"  token_sales         : {token_sales.address}")
    print(f"  amount              : {args.amount_snrg} SNRG ({amount_nwei} nWei)")
    print(f"  interval_seconds    : {args.interval_seconds:g}")
    print(f"  duration_seconds    : {args.duration_seconds:g}")
    print(f"  planned_transactions: {total_planned}")

    for sender, planned in ((faucet, faucet_planned), (token_sales, token_sales_planned)):
        nonce_response = dag.rpc_call(args.rpc_url, "synergy_getAccountNonce", [sender.address])
        if nonce_response.get("error"):
            raise RuntimeError(f"nonce lookup failed for {sender.label}: {nonce_response['error']}")
        sender.nonce = int(nonce_response.get("result") or 0)

        if args.skip_balance_check:
            print(f"  {sender.label}: nonce={sender.nonce} planned_sends={planned}")
            continue

        balance_response = dag.rpc_call(args.rpc_url, "synergy_getTokenBalance", [sender.address, "SNRG"])
        if balance_response.get("error"):
            raise RuntimeError(f"balance lookup failed for {sender.label}: {balance_response['error']}")
        balance = int(balance_response.get("result") or 0)
        required = amount_nwei + (planned * fee_nwei) if planned else 0
        print(
            f"  {sender.label}: nonce={sender.nonce} "
            f"balance={format_snrg(balance)} SNRG planned_sends={planned} "
            f"minimum_start={format_snrg(required)} SNRG"
        )
        if balance < required:
            raise RuntimeError(
                f"{sender.label} balance is too low for the planned run: "
                f"have {format_snrg(balance)} SNRG, need at least {format_snrg(required)} SNRG"
            )

    if args.dry_run:
        print("Dry run complete. No transactions were signed or submitted.")
        return 0

    attempts = 0
    successes = 0
    failures = 0
    start = time.monotonic()
    deadline = start + args.duration_seconds

    while attempts < total_planned and time.monotonic() < deadline:
        target_time = start + (attempts * args.interval_seconds)
        sleep_for = target_time - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)
        if time.monotonic() >= deadline and attempts > 0:
            break

        sender, receiver = (faucet, token_sales) if attempts % 2 == 0 else (token_sales, faucet)
        unsigned = dag.build_unsigned_tx(
            sender,
            receiver.address,
            amount_nwei,
            args.gas_price,
            args.gas_limit,
            None,
            args.algo,
        )

        try:
            signed = dag.sign_tx(wallet_cli, sender, unsigned, args.algo)
            ok, tx_hash_or_error, response = dag.submit_tx(args.rpc_url, signed)
            if ok:
                successes += 1
                print(
                    f"[{utc_now()}] OK {sender.label}->{receiver.label} "
                    f"nonce={sender.nonce} tx={tx_hash_or_error}"
                )
                if args.wait_receipts:
                    confirmed = dag.wait_for_receipt(
                        args.rpc_url,
                        tx_hash_or_error,
                        args.receipt_timeout_seconds,
                    )
                    print(f"[{utc_now()}] receipt tx={tx_hash_or_error} confirmed={str(confirmed).lower()}")
            else:
                failures += 1
                print(
                    f"[{utc_now()}] FAIL {sender.label}->{receiver.label} "
                    f"nonce={sender.nonce} error={tx_hash_or_error}",
                    file=sys.stderr,
                )
            write_jsonl(
                log_file,
                {
                    "time": utc_now(),
                    "ok": ok,
                    "sender_label": sender.label,
                    "sender": sender.address,
                    "receiver_label": receiver.label,
                    "receiver": receiver.address,
                    "nonce": sender.nonce,
                    "amount_nwei": amount_nwei,
                    "tx_hash": tx_hash_or_error if ok else "",
                    "error": "" if ok else tx_hash_or_error,
                    "response": response,
                },
            )
        except Exception as exc:
            failures += 1
            print(
                f"[{utc_now()}] EXC {sender.label}->{receiver.label} "
                f"nonce={sender.nonce} error={exc}",
                file=sys.stderr,
            )
            write_jsonl(
                log_file,
                {
                    "time": utc_now(),
                    "ok": False,
                    "sender_label": sender.label,
                    "sender": sender.address,
                    "receiver_label": receiver.label,
                    "receiver": receiver.address,
                    "nonce": sender.nonce,
                    "amount_nwei": amount_nwei,
                    "error": str(exc),
                },
            )
        finally:
            sender.nonce += 1
            attempts += 1

    print()
    print(f"[{utc_now()}] complete")
    print(f"  attempts : {attempts}")
    print(f"  successes: {successes}")
    print(f"  failures : {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n[{utc_now()}] interrupted", file=sys.stderr)
        raise SystemExit(130)
