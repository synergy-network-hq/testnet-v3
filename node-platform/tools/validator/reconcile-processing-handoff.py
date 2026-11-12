#!/usr/bin/env python3
"""Read-only all-five consumer for one custody-host processing handoff.

It uses existing SSH masters, never authors/submits/retries a transaction, and
returns a verified result before the caller deletes the disposable handoff.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import time

VALIDATORS = (2, 3, 4, 5, 6)
CONTROL_SOCKETS = {
    2: '/tmp/posy-memory-val2-20261022-control',
    3: '/tmp/posy-memory-val3-20261022-control',
    4: '/tmp/posy-memory-val4-20261022-control',
    5: '/tmp/posy-memory-val5-20261021-audit-control',
    6: '/tmp/posy-memory-val6-20261022-control',
}
READ_HANDOFF = r'''import json,os,stat,sys
root=sys.argv[1]; base='/var/lib/synergy-qualification/'
name=root[len(base):] if root.startswith(base) else ''
if not (name.startswith('pool-commission-') or name.startswith('latency-')) or '/' in name: raise SystemExit(1)
if not stat.S_ISDIR(os.lstat(root).st_mode) or os.lstat(root).st_mode&0o077: raise SystemExit(1)
def read(name,limit):
 p=root+'/'+name; s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or s.st_mode&0o077 or not 0<s.st_size<=limit: raise SystemExit(1)
 with open(p,'rb') as f: return json.load(f)
h=read('handoff.json',1048576); i=read('submission-intent.json',1048576)
if h.get('transaction_id') != i.get('transaction_id') or h.get('receipt_id') != i.get('receipt_id'): raise SystemExit(1)
print(json.dumps({'handoff':h,'intent':i},separators=(',',':')))'''
READ_RPC = r'''import json,sys,urllib.request
def rpc(method,params):
 body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params},separators=(',',':')).encode()
 q=urllib.request.Request('http://127.0.0.1:8545',data=body,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=5) as r: value=json.load(r)
 if value.get('error'): raise RuntimeError('rpc error')
 return value.get('result')
tx=sys.argv[1]
print(json.dumps({'transaction':rpc('synergy_getTransaction',{'transaction_id':tx}),'telemetry':rpc('synergy_chainTelemetry',{})},separators=(',',':')))'''

READ_EFFECT = r'''import json,sys,urllib.request
def rpc(method,params):
 body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params},separators=(',',':')).encode()
 q=urllib.request.Request('http://127.0.0.1:8545',data=body,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=5) as r: value=json.load(r)
 if value.get('error'): raise RuntimeError('rpc error')
 return value.get('result')
sender,receiver=sys.argv[1:]
telemetry=rpc('synergy_chainTelemetry',{})
def account(address):
 value=rpc('synergy_getAccount',{'address':address})
 if not isinstance(value,dict): raise RuntimeError('account unavailable')
 return {key:value.get(key) for key in ('nonce','balance_nwei','state_root','finalized_height','finalized_block_hash')}
print(json.dumps({'sender':account(sender),'receiver':account(receiver),'gap_ms':telemetry.get('chain',{}).get('cadence',{}).get('current_gap_ms')},separators=(',',':')))'''


class ReconciliationError(RuntimeError):
    pass


def reconcile_workload_stream(stream, network_id, chain_id, native_statuses=None, *, max_intents=4096):
    """Consume an interrupted JSONL workload without retaining encrypted payloads.

    The seekable binary stream remains caller-owned. Only original compact
    intents and unresolved identities survive this function. Native admission
    lifecycle observations are reported separately: even ``finalized`` cannot
    replace an all-five Applied receipt. No nonce advancement is treated as proof.
    """
    import posy_async_rpc_baseline as adapter

    if type(max_intents) is not int or not 1 <= max_intents <= 65536:
        raise ReconciliationError('reconciliation intent bound must be 1..65536')
    names = {f'val{i}' for i in VALIDATORS}
    limit = 4 * 1024 * 1024
    records = {}
    proven = set()
    rejected = set()
    submissions = set()

    def compact(record):
        keys = ('transaction_id', 'receipt_id', 'wallet_id', 'sender', 'nonce', 'intent')
        value = {key: record[key] for key in keys}
        if (not isinstance(value['transaction_id'], str) or len(value['transaction_id']) != 64
                or not isinstance(value['receipt_id'], str) or len(value['receipt_id']) != 128
                or not isinstance(value['intent'], dict)
                or len(json.dumps(value, separators=(',', ':'))) > 4096):
            raise ReconciliationError('invalid or oversized compact workload intent')
        return value

    def referenced(ref, before):
        if (not isinstance(ref, dict) or type(ref.get('offset')) is not int
                or type(ref.get('length')) is not int or ref['offset'] < 0
                or not 0 < ref['length'] <= limit or ref['offset'] + ref['length'] > before):
            raise ReconciliationError('invalid or forward workload proof reference')
        position = stream.tell()
        try:
            stream.seek(ref['offset'])
            raw = stream.read(ref['length'])
        finally:
            stream.seek(position)
        if len(raw) != ref['length'] or hashlib.sha3_256(raw).hexdigest() != ref.get('sha3_256'):
            raise ReconciliationError('workload proof reference digest mismatch')
        return json.loads(raw)

    stream.seek(0)
    while True:
        offset = stream.tell()
        raw = stream.readline(limit + 1)
        if not raw:
            break
        if len(raw) > limit or not raw.endswith(b'\n'):
            raise ReconciliationError('oversized or incomplete workload frame; original stream retained')
        frame = json.loads(raw)
        kind = frame.get('kind')
        if kind not in ('authored_processing_admission', 'authored_processing_intent', 'submission', 'finalized_transfer'):
            continue
        record = frame.get('record', {})
        value = compact(record)
        txid = value['transaction_id']
        if txid not in records:
            if len(records) >= max_intents:
                raise ReconciliationError('workload exceeds bounded reconciliation intent capacity')
            records[txid] = value
        elif records[txid] != value:
            raise ReconciliationError('workload identity has conflicting original intents')
        if kind in ('authored_processing_admission', 'authored_processing_intent'):
            continue
        if kind == 'submission':
            submissions.add(txid)
            if record.get('submission_rejection'):
                rejected.add(txid)
            continue
        if txid in proven or txid in rejected:
            raise ReconciliationError('duplicate or rejected workload finalization')
        refs = frame.get('finalized_block_refs', {})
        accounts = frame.get('sender_account_views', {})
        cohort = frame.get('sender_block_cohort', [])
        if set(refs) != names or set(accounts) != names or txid not in cohort or len(set(cohort)) != len(cohort):
            raise ReconciliationError('workload proof lacks exact all-five block/account cohort')
        digest = None
        canonical = None
        cohort_nonces = []
        for name in sorted(names):
            row = referenced(refs[name], offset)
            block = row.get('block')
            if row.get('kind') != 'validator_finalized_block' or row.get('validator') != name:
                raise ReconciliationError('workload proof reference names another validator/frame')
            adapter.validate_block_views({name: block}, record['block_height'], ReconciliationError)
            fingerprint = adapter.block_fingerprint(block)
            if digest is not None and fingerprint != digest:
                raise ReconciliationError('validators disagree on referenced finalized block')
            digest = fingerprint
            if canonical is None:
                canonical = {key: block[key] for key in ('height', 'block_hash', 'state_root')}
                matched = []
                for transaction, receipt in zip(block['transactions'], block['receipts']):
                    if receipt.get('transaction_id') in cohort:
                        matched.append(receipt['transaction_id'])
                        if (receipt.get('status') != 'applied' or receipt.get('error_code') is not None
                                or transaction.get('unsigned', {}).get('sender') != record['sender']):
                            raise ReconciliationError('cohort contains a reverted or different-sender transaction')
                        cohort_nonces.append(transaction['unsigned']['nonce'])
                    if receipt.get('transaction_id') == txid:
                        adapter.validate_finalized_intent(transaction, value, network_id, chain_id, ReconciliationError)
                        gas = receipt.get('gas_used')
                        if (type(gas) is not int or not 0 <= gas <= value['intent']['gas_limit']
                                or receipt.get('status') != 'applied' or receipt.get('error_code') is not None):
                            raise ReconciliationError('workload receipt is not exact Applied intent')
                if matched != cohort or txid not in matched:
                    raise ReconciliationError('finalized cohort differs from original proof')
        if (not cohort_nonces or cohort_nonces != list(range(cohort_nonces[0], cohort_nonces[0] + len(cohort_nonces)))
                or len({json.dumps(account, sort_keys=True, separators=(',', ':')) for account in accounts.values()}) != 1):
            raise ReconciliationError('all-five sender account or nonce cohort differs')
        account = next(iter(accounts.values()))
        if (account.get('address') != record['sender'] or account.get('nonce') != cohort_nonces[-1] + 1
                or account.get('finalized_height') != canonical['height']
                or account.get('finalized_block_hash') != canonical['block_hash']
                or account.get('state_root') != canonical['state_root']):
            raise ReconciliationError('sender account does not match referenced finalized block/cohort')
        proven.add(txid)

    native_statuses = native_statuses or {}
    unresolved = []
    for txid, value in records.items():
        if txid in proven or txid in rejected:
            continue
        views = native_statuses.get(txid, {})
        unresolved.append({**value, 'status': 'unresolved',
                           'submission_recorded': txid in submissions,
                           'native_lifecycle_by_validator': views,
                           'automatic_resubmission_permitted': False})
    return {'authored_intents': len(records), 'submitted_intents': len(submissions), 'all_five_applied_verified': len(proven),
            'explicit_rpc_rejections': len(rejected), 'unresolved_count': len(unresolved),
            'unresolved_intents': unresolved, 'native_lifecycle_is_applied_proof': False,
            'transaction_latency_deadline_seconds': None,
            'original_stream_consumed': True}


def owner():
    path = Path(__file__).with_name('provision-stability-hosts.py')
    spec = importlib.util.spec_from_file_location('posy_owner', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def remote(number: int, code: str, *arguments: str):
    module = owner()
    host = f'synergy-val{number}'
    # Reuse the sole live master selected for this recovery run.  Never allow
    # the helper to establish a replacement connection merely to observe RPC.
    raw = module.remote(host, CONTROL_SOCKETS[number],
                        ['python3', '-c', code, *arguments])
    return json.loads(raw)


def verify(handoff, observations):
    expected_id = handoff.get('transaction_id')
    expected_unsigned = handoff.get('expected_unsigned')
    if not isinstance(expected_id, str) or len(expected_id) != 64 or not isinstance(expected_unsigned, dict):
        raise ReconciliationError('handoff lacks exact transaction identity')
    transactions = []
    for observation in observations.values():
        value = observation.get('transaction')
        if not isinstance(value, dict):
            raise ReconciliationError('history unavailable before all-five verification; no finality claim')
        transactions.append(value)
        gap = observation.get('telemetry', {}).get('chain', {}).get('cadence', {}).get('current_gap_ms')
        if isinstance(gap, bool) or not isinstance(gap, (int, float)) or not math.isfinite(gap) or not 0 <= gap <= 30000:
            raise ReconciliationError('current block finality gap exceeds 30 seconds')
    if len({json.dumps(v, sort_keys=True, separators=(',', ':')) for v in transactions}) != 1:
        raise ReconciliationError('validators returned different transaction views')
    value = transactions[0]
    if (value.get('transaction_id') != expected_id or value.get('status') != 'applied'
            or value.get('transaction', {}).get('unsigned') != expected_unsigned
            or value.get('receipt', {}).get('status') != 'applied'
            or value.get('receipt', {}).get('error_code') is not None):
        raise ReconciliationError('finalized transaction differs from the sole signed intent')
    return {'verified': True, 'transaction_id': expected_id,
            'block_height': value['block_height'], 'block_hash': value['block_hash'],
            'finality_certificate_id': value['finality_certificate_id'],
            'state_root': value['receipt'].get('state_root_after'),
            'all_five_exact_effects': True,
            'handoff_consumed': 'caller may now delete the remote disposable handoff'}


def watch_effects(sender, receiver, expected_sender_nonce, expected_sender_balance,
                  expected_receiver_balance, timeout_seconds):
    """Read a pre-armed all-five effect transition without persisting it.

    A finalized candidate is deliberately short-lived.  This watcher is
    started before the one authorized submission and verifies the exact nonce
    and balances on every validator, rather than racing normal retirement.
    """
    deadline = time.monotonic() + timeout_seconds
    started = time.monotonic()
    while True:
        observations = {
            number: remote(number, READ_EFFECT, sender, receiver)
            for number in VALIDATORS
        }
        matching = []
        for value in observations.values():
            sender_view = value.get('sender', {})
            receiver_view = value.get('receiver', {})
            matching.append(
                sender_view.get('nonce') == expected_sender_nonce
                and sender_view.get('balance_nwei') == expected_sender_balance
                and receiver_view.get('balance_nwei') == expected_receiver_balance
                and isinstance(value.get('gap_ms'), (int, float))
                and 0 <= value['gap_ms'] <= 30000
            )
        roots = {value.get('sender', {}).get('state_root') for value in observations.values()}
        if all(matching) and len(roots) == 1 and None not in roots:
            return {
                'verified': True,
                'all_five_exact_effects': True,
                'state_root': roots.pop(),
                'validator_heights': {
                    f'val{number}': observations[number]['sender']['finalized_height']
                    for number in VALIDATORS
                },
                'elapsed_seconds': round(time.monotonic() - started, 6),
                'disposable_result_consumed': True,
            }
        if time.monotonic() >= deadline:
            return {'verified': False, 'status': 'effect_not_observed_within_window'}
        time.sleep(.05)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('handoff_dir', nargs='?')
    parser.add_argument('--watch-sender')
    parser.add_argument('--watch-receiver')
    parser.add_argument('--expected-sender-nonce', type=int)
    parser.add_argument('--expected-sender-balance')
    parser.add_argument('--expected-receiver-balance')
    parser.add_argument('--timeout-seconds', type=float, default=120.0)
    args = parser.parse_args()
    if not 0 < args.timeout_seconds <= 3600:
        raise ReconciliationError('timeout must be in (0, 3600]')
    watch = (args.watch_sender, args.watch_receiver, args.expected_sender_nonce,
             args.expected_sender_balance, args.expected_receiver_balance)
    if any(value is not None for value in watch):
        if args.handoff_dir or any(value is None for value in watch):
            raise ReconciliationError('watch requires only complete expected account values')
        print(json.dumps(watch_effects(*watch, args.timeout_seconds), separators=(',', ':')))
        return
    if not args.handoff_dir:
        raise ReconciliationError('handoff directory is required outside watch mode')
    handoff = remote(2, READ_HANDOFF, args.handoff_dir)['handoff']
    deadline = time.monotonic() + args.timeout_seconds
    while True:
        observations = {number: remote(number, READ_RPC, handoff['transaction_id']) for number in VALIDATORS}
        if all(value.get('transaction') is not None for value in observations.values()):
            print(json.dumps(verify(handoff, observations), separators=(',', ':')))
            return
        if time.monotonic() >= deadline:
            print(json.dumps({'verified': False, 'transaction_id': handoff['transaction_id'],
                              'status': 'not_finalized_within_observation_window', 'handoff_retained': True}, separators=(',', ':')))
            return
        time.sleep(.1)


if __name__ == '__main__':
    try:
        main()
    except (ReconciliationError, KeyError, TypeError, ValueError) as error:
        print(json.dumps({'verified': False, 'error': str(error)[:240], 'handoff_retained': True}, separators=(',', ':')))
        raise SystemExit(2)
