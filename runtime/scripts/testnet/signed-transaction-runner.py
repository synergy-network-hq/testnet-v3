#!/usr/bin/env python3
"""
signed-transaction-runner.py
============================

Continuously signs and submits Synergy transactions to a JSON-RPC endpoint
for a configurable duration. Useful for load-testing testnet against
the public RPC gateway, which only exposes the public-plane method
`synergy_sendTransaction` (i.e. requires already-signed transactions).

Each iteration:
  1. Builds an unsigned transaction with sender, receiver, amount,
     gas_price, gas_limit, the canonical token_transfer data field,
     a fresh timestamp, and the next nonce.
  2. Signs it with `wallet-pqc-cli sign-tx` using the configured
     private key (FN-DSA-1024 by default).
  3. POSTs the signed transaction to `synergy_sendTransaction`.
  4. Logs success/failure and the returned tx hash.
  5. Sleeps until the next interval boundary.

Designed to be invoked from `run-signed-load.sh` but can be run standalone.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def isoz() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str, *, err: bool = False) -> None:
    stream = sys.stderr if err else sys.stdout
    print(msg, file=stream, flush=True)


def jsonrpc_call(rpc_url: str, method: str, params, timeout: int = 15) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    ).encode()
    req = urllib.request.Request(
        rpc_url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def normalize_priv_key(raw: str) -> str:
    """Accept hex or base64; return hex."""
    cleaned = "".join(raw.split())  # strip all whitespace incl. newlines
    if not cleaned:
        raise ValueError("private key file is empty")
    # heuristic: pure hex chars (0-9 a-f A-F) and even length
    is_hex = len(cleaned) % 2 == 0 and all(
        c in "0123456789abcdefABCDEF" for c in cleaned
    )
    if is_hex:
        return cleaned.lower()
    return base64.b64decode(cleaned).hex()


def sign_tx(cli: str, priv_hex: str, tx: dict, algo: str = "fndsa") -> dict:
    proc = subprocess.run(
        [
            cli,
            "sign-tx",
            "--private-key",
            priv_hex,
            "--tx",
            json.dumps(tx, separators=(",", ":")),
            "--algo",
            algo,
        ],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"sign-tx failed (rc={proc.returncode}): {proc.stderr.decode().strip()}"
        )
    out = json.loads(proc.stdout.decode())
    return out["transaction"]


def get_account_nonce(rpc_url: str, address: str) -> int:
    resp = jsonrpc_call(rpc_url, "synergy_getAccountNonce", [address])
    if "error" in resp and resp["error"]:
        raise RuntimeError(f"getAccountNonce error: {resp['error']}")
    return int(resp["result"])


def get_token_balance(rpc_url: str, address: str, token: str = "SNRG") -> int:
    resp = jsonrpc_call(rpc_url, "synergy_getTokenBalance", [address, token])
    if "error" in resp and resp["error"]:
        raise RuntimeError(f"getTokenBalance error: {resp['error']}")
    return int(resp["result"])


def build_unsigned_tx(
    sender: str,
    receiver: str,
    amount_nwei: int,
    nonce: int,
    timestamp: int,
    gas_price: int,
    gas_limit: int,
    memo: str,
    algo: str,
) -> dict:
    data_field = "token_transfer:" + json.dumps(
        {"to": receiver, "token": "SNRG", "amount": amount_nwei, "memo": memo},
        separators=(",", ":"),
    )
    return {
        "sender": sender,
        "receiver": receiver,
        "amount": amount_nwei,
        "nonce": nonce,
        "signature": [],
        "timestamp": timestamp,
        "gas_price": gas_price,
        "gas_limit": gas_limit,
        "data": data_field,
        "signature_algorithm": algo,
    }


def submit_signed(rpc_url: str, signed: dict, timeout: int = 15) -> dict:
    return jsonrpc_call(rpc_url, "synergy_sendTransaction", [signed], timeout=timeout)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("--rpc-url", required=True, help="JSON-RPC endpoint")
    p.add_argument(
        "--cli",
        default=os.path.expanduser(
            "~/Desktop/Testnet/synergy-testnet/target/debug/wallet-pqc-cli"
        ),
        help="path to wallet-pqc-cli binary",
    )
    p.add_argument("--sender", required=True, help="sender wallet address")
    p.add_argument("--receiver", required=True, help="receiver wallet address")
    p.add_argument(
        "--private-key-file",
        required=True,
        help="path to file containing sender's private key (hex or base64)",
    )
    p.add_argument("--amount-nwei", type=int, default=1, help="amount per tx in nWei")
    p.add_argument("--gas-price", type=int, default=1000)
    p.add_argument("--gas-limit", type=int, default=21000)
    p.add_argument("--memo", default="load-test")
    p.add_argument("--duration-seconds", type=int, default=10800)
    p.add_argument("--interval-seconds", type=float, default=5.0)
    p.add_argument("--algo", default="fndsa", choices=["fndsa"])
    p.add_argument(
        "--start-nonce",
        type=int,
        default=None,
        help="explicit starting nonce (default: query RPC)",
    )
    p.add_argument(
        "--max-tx",
        type=int,
        default=0,
        help="optional cap on total transactions (0 = no cap, time-bounded only)",
    )
    p.add_argument(
        "--stop-on-balance-nwei",
        type=int,
        default=0,
        help="stop if sender balance drops below this many nWei (0 = disabled)",
    )
    p.add_argument(
        "--rebuild-cli",
        action="store_true",
        help="if the cli path doesn't exist, attempt `cargo build --bin wallet-pqc-cli`",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not os.path.isfile(args.cli):
        if args.rebuild_cli:
            print(f"[{isoz()}] cli not found; building wallet-pqc-cli")
            manifest = os.path.expanduser(
                "~/Desktop/Testnet/synergy-testnet/src/Cargo.toml"
            )
            subprocess.run(
                [
                    "cargo",
                    "build",
                    "--quiet",
                    "--manifest-path",
                    manifest,
                    "--bin",
                    "wallet-pqc-cli",
                ],
                check=True,
            )
        else:
            print(f"wallet-pqc-cli not found at {args.cli}", file=sys.stderr)
            return 2

    with open(args.private_key_file, "r") as f:
        priv_hex = normalize_priv_key(f.read())

    # Preflight: confirm RPC is up and read starting nonce/balance.
    head = jsonrpc_call(args.rpc_url, "synergy_blockNumber", [])
    if "error" in head and head["error"]:
        print(f"RPC preflight failed: {head['error']}", file=sys.stderr)
        return 3
    head_block = head.get("result")

    nonce = (
        args.start_nonce
        if args.start_nonce is not None
        else get_account_nonce(args.rpc_url, args.sender)
    )
    start_balance = get_token_balance(args.rpc_url, args.sender)

    print(f"[{isoz()}] starting signed-transaction-runner")
    print(f"  rpc_url           : {args.rpc_url}")
    print(f"  head_block        : {head_block}")
    print(f"  sender            : {args.sender}")
    print(f"  receiver          : {args.receiver}")
    print(f"  start_balance_nwei: {start_balance}")
    print(f"  start_nonce       : {nonce}")
    print(f"  amount_nwei       : {args.amount_nwei}")
    print(f"  gas_price/limit   : {args.gas_price}/{args.gas_limit} (max fee/tx={args.gas_price * args.gas_limit} nWei)")
    print(f"  duration_seconds  : {args.duration_seconds}")
    print(f"  interval_seconds  : {args.interval_seconds}")
    print(f"  algo              : {args.algo}")
    print(f"  max_tx            : {args.max_tx or 'unbounded'}")
    sys.stdout.flush()

    start = time.time()
    end = start + args.duration_seconds

    success = 0
    failure = 0
    iter_n = 0
    last_status = start

    while time.time() < end:
        if args.max_tx and iter_n >= args.max_tx:
            print(f"[{isoz()}] reached --max-tx={args.max_tx}, stopping")
            break

        ts = int(time.time())
        unsigned = build_unsigned_tx(
            sender=args.sender,
            receiver=args.receiver,
            amount_nwei=args.amount_nwei,
            nonce=nonce,
            timestamp=ts,
            gas_price=args.gas_price,
            gas_limit=args.gas_limit,
            memo=args.memo,
            algo=args.algo,
        )

        try:
            signed = sign_tx(args.cli, priv_hex, unsigned, algo=args.algo)
            resp = submit_signed(args.rpc_url, signed)
            if "error" in resp and resp["error"]:
                failure += 1
                err = resp["error"].get("message") or resp["error"]
                print(
                    f"[{isoz()}] FAIL nonce={nonce} error={err}",
                    file=sys.stderr,
                )
            else:
                result = resp.get("result") or {}
                if isinstance(result, dict) and result.get("success") is False:
                    failure += 1
                    print(
                        f"[{isoz()}] FAIL nonce={nonce} result={result}",
                        file=sys.stderr,
                    )
                else:
                    success += 1
                    tx_hash = (
                        result.get("tx_hash")
                        if isinstance(result, dict)
                        else None
                    )
                    print(f"[{isoz()}] OK   nonce={nonce} tx={tx_hash}")
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, ValueError) as e:
            failure += 1
            print(f"[{isoz()}] EXC  nonce={nonce} err={e}", file=sys.stderr)

        nonce += 1
        iter_n += 1

        # Periodic balance check / status print every ~30 iters or 60s.
        now = time.time()
        if (iter_n % 30 == 0) or (now - last_status > 60):
            try:
                bal = get_token_balance(args.rpc_url, args.sender)
                print(
                    f"[{isoz()}] STATUS iters={iter_n} ok={success} fail={failure} "
                    f"balance_nwei={bal}"
                )
                if args.stop_on_balance_nwei and bal < args.stop_on_balance_nwei:
                    print(
                        f"[{isoz()}] balance {bal} < threshold "
                        f"{args.stop_on_balance_nwei}, stopping early"
                    )
                    break
            except Exception as e:  # noqa: BLE001
                print(f"[{isoz()}] balance check failed: {e}", file=sys.stderr)
            last_status = now
            sys.stdout.flush()
            sys.stderr.flush()

        # Sleep so iteration boundaries are deterministic regardless of
        # signing/network jitter.
        next_target = start + iter_n * args.interval_seconds
        sleep_for = next_target - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)

    elapsed = time.time() - start
    achieved_rate = (success + failure) / elapsed if elapsed > 0 else 0.0
    print()
    print(f"[{isoz()}] runner complete")
    print(f"  attempts        : {success + failure}")
    print(f"  successes       : {success}")
    print(f"  failures        : {failure}")
    print(f"  elapsed_seconds : {elapsed:.1f}")
    print(f"  achieved_rps    : {achieved_rate:.3f}")
    return 0 if failure == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n[{isoz()}] interrupted", file=sys.stderr)
        sys.exit(130)
