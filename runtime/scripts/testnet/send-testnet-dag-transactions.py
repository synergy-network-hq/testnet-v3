#!/usr/bin/env python3
"""Retired wallet-CLI DAG sender.

This file is kept only as an operator breadcrumb for older load-test notes.
It must not be used to prove Synergy Testnet DAG ingestion because it signs
through wallet-pqc-cli instead of the mandatory aegis-pqvm transaction-key
path. Use `synergy-node dag submit-test-fixture --real-aegis-pqvm` or
`synergy-node tx submit-aegis --rpc-url <url>` instead.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path


DEFAULT_RPC_URL = "https://testnet-core-rpc.synergy-network.io"
NWEI_PER_SNRG = Decimal("1000000000")
DEFAULT_GAS_PRICE = 1000
DEFAULT_GAS_LIMIT = 21000


@dataclass
class Sender:
    label: str
    address: str
    private_key_hex: str
    key_path: Path
    nonce: int = 0


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def script_root() -> Path:
    return Path(__file__).resolve().parents[2]


def rpc_call(rpc_url: str, method: str, params: list, timeout: int = 20) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def normalize_private_key(raw: str) -> str:
    cleaned = "".join(raw.split())
    if not cleaned:
        raise ValueError("private key is empty")
    if len(cleaned) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return cleaned.lower()
    return base64.b64decode(cleaned).hex()


def load_sender(path: Path) -> Sender:
    payload = json.loads(path.read_text())
    address = str(payload.get("address") or "").strip()
    private_key = str(payload.get("private_key") or "").strip()
    if not address or not private_key:
        raise ValueError(f"{path} must contain address and private_key fields")
    label = path.name
    for suffix in (".json", ".dec", ".enc", ".pub"):
        if label.endswith(suffix):
            label = label[: -len(suffix)]
    return Sender(
        label=label,
        address=address,
        private_key_hex=normalize_private_key(private_key),
        key_path=path,
    )


def resolve_wallet_cli(cli_arg: str | None) -> str:
    candidates = []
    if cli_arg:
        candidates.append(Path(cli_arg).expanduser())
    env_cli = os.environ.get("SYNERGY_WALLET_CLI")
    if env_cli:
        candidates.append(Path(env_cli).expanduser())
    candidates.append(script_root() / "target" / "debug" / "wallet-pqc-cli")
    which_cli = shutil.which("wallet-pqc-cli")
    if which_cli:
        candidates.append(Path(which_cli))

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    searched = ", ".join(str(c) for c in candidates)
    raise FileNotFoundError(f"wallet-pqc-cli not found. Searched: {searched}")


def build_wallet_cli() -> None:
    root = script_root()
    cargo_toml = root / "Cargo.toml"
    if not cargo_toml.is_file():
        raise FileNotFoundError(f"Cargo.toml not found at {cargo_toml}")
    subprocess.run(
        ["cargo", "build", "--quiet", "--bin", "wallet-pqc-cli"],
        cwd=root,
        check=True,
    )


def amount_to_nwei(args: argparse.Namespace) -> int:
    if args.amount_nwei is not None:
        if args.amount_nwei <= 0:
            raise ValueError("--amount-nwei must be positive")
        return args.amount_nwei
    try:
        amount = Decimal(args.amount_snrg)
    except InvalidOperation as exc:
        raise ValueError("--amount-snrg must be a valid decimal") from exc
    if amount <= 0:
        raise ValueError("--amount-snrg must be positive")
    nwei = amount * NWEI_PER_SNRG
    if nwei != nwei.to_integral_value():
        raise ValueError("--amount-snrg supports no more than 9 decimal places")
    return int(nwei)


def sign_tx(wallet_cli: str, sender: Sender, tx: dict, algo: str) -> dict:
    proc = subprocess.run(
        [
            wallet_cli,
            "sign-tx",
            "--private-key",
            sender.private_key_hex,
            "--tx",
            json.dumps(tx, separators=(",", ":")),
            "--algo",
            algo,
        ],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"wallet-pqc-cli sign-tx failed for {sender.label}: {stderr}")
    output = json.loads(proc.stdout.decode())
    return output["transaction"]


def build_data_field(
    mode: str,
    sender: Sender,
    receiver: str,
    amount_nwei: int,
    memo_prefix: str,
    machine_label: str,
    sequence: int,
) -> str | None:
    if mode == "empty":
        return None

    payload = {
        "source": "dag-load-test",
        "memo": memo_prefix,
        "machine": machine_label,
        "sender_label": sender.label,
        "sequence": sequence,
        "created_at": utc_now(),
    }
    if mode == "dag-memo":
        return "dag_load_test:" + json.dumps(payload, separators=(",", ":"))
    if mode == "token-transfer":
        token_payload = {
            "to": receiver,
            "token": "SNRG",
            "amount": amount_nwei,
            "memo": f"{memo_prefix}:{machine_label}:{sender.label}:{sequence}",
        }
        return "token_transfer:" + json.dumps(token_payload, separators=(",", ":"))
    raise ValueError(f"Unsupported data mode: {mode}")


def build_unsigned_tx(
    sender: Sender,
    receiver: str,
    amount_nwei: int,
    gas_price: int,
    gas_limit: int,
    data: str | None,
    algo: str,
) -> dict:
    return {
        "sender": sender.address,
        "receiver": receiver,
        "amount": amount_nwei,
        "nonce": sender.nonce,
        "signature": [],
        "timestamp": int(time.time()),
        "gas_price": gas_price,
        "gas_limit": gas_limit,
        "data": data,
        "signature_algorithm": algo,
    }


def submit_tx(rpc_url: str, signed_tx: dict) -> tuple[bool, str, dict]:
    response = rpc_call(rpc_url, "synergy_sendTransaction", [signed_tx])
    if response.get("error"):
        return False, str(response["error"]), response
    result = response.get("result")
    if isinstance(result, dict) and result.get("success") is False:
        return False, str(result.get("error") or result), response
    if isinstance(result, str):
        return True, result, response
    if isinstance(result, dict):
        tx_hash = result.get("tx_hash") or result.get("hash") or ""
        return True, str(tx_hash), response
    return True, "", response


def wait_for_receipt(rpc_url: str, tx_hash: str, timeout_seconds: int) -> bool:
    if not tx_hash:
        return False
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        for method in ("synergy_getTransactionReceipt", "synergy_getTransactionByHash"):
            try:
                response = rpc_call(rpc_url, method, [tx_hash], timeout=10)
            except Exception:
                continue
            if response.get("result"):
                return True
        time.sleep(2)
    return False


def pick_receiver(sender_index: int, senders: list[Sender], receivers: list[str]) -> str:
    if receivers:
        return receivers[sender_index % len(receivers)]
    if len(senders) < 2:
        raise ValueError("Provide --receiver when using only one --sender-key")
    return senders[(sender_index + 1) % len(senders)].address


def print_jsonl(path: Path | None, entry: dict) -> None:
    if path is None:
        return
    with path.open("a") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send signed Testnet traffic for real-time DAG observation."
    )
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--sender-key", action="append", required=True, help="JSON key file with address/private_key. Repeat for multiple sources.")
    parser.add_argument("--receiver", action="append", default=[], help="Recipient address. Repeat for round-robin recipients.")
    parser.add_argument("--tx-per-sender", type=int, default=3)
    parser.add_argument("--amount-nwei", type=int, default=1)
    parser.add_argument("--amount-snrg", default=None, help="Alternative amount in SNRG. Overrides --amount-nwei when set.")
    parser.add_argument("--gas-price", type=int, default=DEFAULT_GAS_PRICE)
    parser.add_argument("--gas-limit", type=int, default=DEFAULT_GAS_LIMIT)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--jitter-seconds", type=float, default=0.25)
    parser.add_argument("--machine-label", default=socket.gethostname())
    parser.add_argument("--memo-prefix", default="dag-load")
    parser.add_argument("--data-mode", choices=["dag-memo", "empty", "token-transfer"], default="dag-memo")
    parser.add_argument("--algo", choices=["fndsa"], default="fndsa")
    parser.add_argument("--wallet-cli", default=None)
    parser.add_argument("--build-cli", action="store_true", help="Build wallet-pqc-cli before running if it is missing.")
    parser.add_argument("--skip-balance-check", action="store_true")
    parser.add_argument("--wait-receipts", action="store_true")
    parser.add_argument("--receipt-timeout-seconds", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--log-file", default=None, help="Optional JSONL output path.")
    return parser.parse_args()


def main() -> int:
    print(
        "scripts/testnet/send-testnet-dag-transactions.py is retired: "
        "wallet-pqc-cli DAG traffic is not accepted as Testnet DAG proof. "
        "Use synergy-node dag submit-test-fixture --real-aegis-pqvm or "
        "synergy-node tx submit-aegis --rpc-url <url>.",
        file=sys.stderr,
    )
    return 2

    args = parse_args()
    if args.amount_snrg is not None:
        args.amount_nwei = None
    if args.tx_per_sender <= 0:
        print("--tx-per-sender must be positive", file=sys.stderr)
        return 2

    senders = [load_sender(Path(path).expanduser()) for path in args.sender_key]
    amount_nwei = amount_to_nwei(args)
    max_fee_nwei = args.gas_price * args.gas_limit
    log_file = Path(args.log_file).expanduser() if args.log_file else None

    try:
        wallet_cli = resolve_wallet_cli(args.wallet_cli)
    except FileNotFoundError:
        if args.build_cli:
            build_wallet_cli()
            wallet_cli = resolve_wallet_cli(args.wallet_cli)
        else:
            raise

    head = rpc_call(args.rpc_url, "synergy_blockNumber", [])
    if head.get("error"):
        raise RuntimeError(f"RPC preflight failed: {head['error']}")

    print(f"[{utc_now()}] Synergy Testnet DAG traffic sender")
    print(f"  rpc_url       : {args.rpc_url}")
    print(f"  head_block    : {head.get('result')}")
    print(f"  wallet_cli    : {wallet_cli}")
    print(f"  senders       : {len(senders)}")
    print(f"  tx_per_sender : {args.tx_per_sender}")
    print(f"  amount_nwei   : {amount_nwei}")
    print(f"  data_mode     : {args.data_mode}")
    print(f"  machine_label : {args.machine_label}")

    for sender in senders:
        nonce_response = rpc_call(args.rpc_url, "synergy_getAccountNonce", [sender.address])
        if nonce_response.get("error"):
            raise RuntimeError(f"nonce lookup failed for {sender.label}: {nonce_response['error']}")
        sender.nonce = int(nonce_response.get("result") or 0)

        if not args.skip_balance_check:
            balance_response = rpc_call(args.rpc_url, "synergy_getTokenBalance", [sender.address, "SNRG"])
            if balance_response.get("error"):
                raise RuntimeError(f"balance lookup failed for {sender.label}: {balance_response['error']}")
            balance = int(balance_response.get("result") or 0)
            required = args.tx_per_sender * (amount_nwei + max_fee_nwei)
            print(f"  sender {sender.label}: address={sender.address} nonce={sender.nonce} balance_nwei={balance}")
            if balance < required:
                raise RuntimeError(
                    f"{sender.label} balance {balance} is below estimated requirement {required}"
                )
        else:
            print(f"  sender {sender.label}: address={sender.address} nonce={sender.nonce}")

    if args.dry_run:
        print("Dry run complete. No transactions were signed or submitted.")
        return 0

    attempts = 0
    successes = 0
    failures = 0

    for sequence in range(args.tx_per_sender):
        for sender_index, sender in enumerate(senders):
            receiver = pick_receiver(sender_index, senders, args.receiver)
            data = build_data_field(
                args.data_mode,
                sender,
                receiver,
                amount_nwei,
                args.memo_prefix,
                args.machine_label,
                sequence,
            )
            unsigned = build_unsigned_tx(
                sender,
                receiver,
                amount_nwei,
                args.gas_price,
                args.gas_limit,
                data,
                args.algo,
            )

            attempts += 1
            try:
                signed = sign_tx(wallet_cli, sender, unsigned, args.algo)
                ok, tx_hash_or_error, response = submit_tx(args.rpc_url, signed)
                entry = {
                    "time": utc_now(),
                    "ok": ok,
                    "sender_label": sender.label,
                    "sender": sender.address,
                    "receiver": receiver,
                    "nonce": sender.nonce,
                    "amount_nwei": amount_nwei,
                    "tx_hash": tx_hash_or_error if ok else "",
                    "error": "" if ok else tx_hash_or_error,
                    "response": response,
                }
                print_jsonl(log_file, entry)
                if ok:
                    successes += 1
                    print(f"[{utc_now()}] OK sender={sender.label} nonce={sender.nonce} tx={tx_hash_or_error}")
                    if args.wait_receipts:
                        confirmed = wait_for_receipt(
                            args.rpc_url,
                            tx_hash_or_error,
                            args.receipt_timeout_seconds,
                        )
                        print(f"[{utc_now()}] receipt tx={tx_hash_or_error} confirmed={str(confirmed).lower()}")
                else:
                    failures += 1
                    print(f"[{utc_now()}] FAIL sender={sender.label} nonce={sender.nonce} error={tx_hash_or_error}", file=sys.stderr)
            except (RuntimeError, urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
                failures += 1
                entry = {
                    "time": utc_now(),
                    "ok": False,
                    "sender_label": sender.label,
                    "sender": sender.address,
                    "receiver": receiver,
                    "nonce": sender.nonce,
                    "amount_nwei": amount_nwei,
                    "error": str(exc),
                }
                print_jsonl(log_file, entry)
                print(f"[{utc_now()}] EXC sender={sender.label} nonce={sender.nonce} error={exc}", file=sys.stderr)
            finally:
                sender.nonce += 1

            delay = args.interval_seconds
            if args.jitter_seconds > 0:
                delay += random.uniform(0, args.jitter_seconds)
            if delay > 0:
                time.sleep(delay)

    print()
    print(f"[{utc_now()}] complete")
    print(f"  attempts  : {attempts}")
    print(f"  successes : {successes}")
    print(f"  failures  : {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n[{utc_now()}] interrupted", file=sys.stderr)
        raise SystemExit(130)
