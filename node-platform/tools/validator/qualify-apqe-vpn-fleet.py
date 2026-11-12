#!/usr/bin/env python3
"""Observe actual APQE validators through existing SSH masters; never deploys.

RPC stays loopback on each validator. SSH is an operator channel, never native
validator authority. No credentials or decrypted transaction contents are logged.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import subprocess
import time

REMOTE = r'''
import json,sys,urllib.request,subprocess
from pathlib import Path
request=json.load(sys.stdin)
if request.get('observe'):
 service=dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show','synergy-node.service','-p','ActiveState,SubState,MainPID,NRestarts'],text=True).splitlines())
 pid=int(service['MainPID']); resources={}
 if pid:
  status=Path('/proc')/str(pid)/'status'
  resources={line.split(':')[0]:line.split(':',1)[1].strip() for line in status.read_text().splitlines() if line.startswith(('VmRSS:','VmHWM:'))}
  values=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()
  resources.update(cpu_user_ticks=int(values[11]),cpu_system_ticks=int(values[12]))
 request={'jsonrpc':'2.0','id':1,'method':'synergy_chainTelemetry','params':request.get('params',{})}
else: service=resources=None
data=json.dumps(request).encode()
with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8545',data,{'Content-Type':'application/json'}),timeout=5) as response:
 data=response.read(2*1024*1024+1)
 if len(data)>2*1024*1024:raise ValueError('bounded RPC response required')
value=json.loads(data)
if 'error' in value:raise ValueError('RPC error: '+json.dumps(value['error']))
if service is not None:value={'service':service,'resources':resources,'telemetry':value['result']}
else:value=value['result']
print(json.dumps(value))
'''


def connection(entry):
    name, alias, socket = entry.split('=', 2)
    if not Path(socket).is_socket():
        raise ValueError('existing SSH master socket required: '+name)
    return name, ['ssh', '-T', '-S', socket, '-o', 'ControlMaster=no', '-o',
                  'ProxyCommand=/usr/bin/false', alias]


def query(host, method=None, params=None):
    name, argv = host
    request = ({'observe': True, 'params': params or {}} if method is None else
               {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})
    result = subprocess.run(argv+[shlex.join(['python3', '-c', REMOTE])],
                            input=json.dumps(request).encode(), capture_output=True, timeout=20)
    if result.returncode:
        # Errors contain no submitted payload or custody information.
        raise RuntimeError(name+': '+result.stderr.decode(errors='replace')[-1500:])
    return json.loads(result.stdout)


def parallel(hosts, method=None, params=None):
    with ThreadPoolExecutor(max_workers=5) as pool:
        values = list(pool.map(lambda h: query(h, method, params), hosts))
    return dict(zip((h[0] for h in hosts), values))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=['observe', 'agreement', 'context', 'submit', 'receipt', 'effects'])
    p.add_argument('--host', action='append', required=True, help='ValN=SSH_ALIAS=EXISTING_SOCKET')
    p.add_argument('--input', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--seconds', type=int, default=180)
    args = p.parse_args()
    hosts = [connection(h) for h in args.host]
    if len(hosts) != 5 or {h[0] for h in hosts} != {f'Val{n}' for n in range(2, 7)}:
        p.error('exactly Val2 through Val6 required')
    if not 1 <= args.seconds <= 86400:
        p.error('bounded duration required')
    if args.operation == 'observe':
        print(json.dumps(parallel(hosts)))
        return
    if args.operation == 'context':
        if args.output is None:
            p.error('fresh --output context file required')
        value = query(hosts[0], 'synergy_getProcessingContextV1')
        with args.output.open('x') as out:
            json.dump(value, out)
        print(json.dumps({'context_saved': str(args.output)}))
        return
    if args.operation in ('submit', 'receipt', 'effects'):
        if args.input is None or args.input.is_symlink() or not args.input.is_file() or args.input.stat().st_size > 1024*1024:
            p.error('bounded regular --input required')
        value = json.loads(args.input.read_bytes())
        if args.operation == 'submit':
            # One attempt only: caller must reconcile an uncertain result.
            result = query(hosts[0], 'synergy_submitProcessingTransactionV1', value)
            if args.output:
                with args.output.open('x') as out:
                    json.dump(result, out)
            print(json.dumps(result))
            return
        if args.operation == 'receipt':
            print(json.dumps(query(hosts[0], 'synergy_getProtectedAdmissionReceipt', {'receipt_id': value['receipt_id']})))
            return
        transaction = value['unsigned']
    else:
        transaction = None
    deadline = time.monotonic()+args.seconds
    first_height = None
    while True:
        observations = parallel(hosts)
        telemetry = [v['telemetry'] for v in observations.values()]
        height = min(int(v['finalized_height']) for v in telemetry)
        if first_height is None:
            first_height = height
        sessions = all(v['transport']['apqe_session_count'] == 4 and
                       v['transport']['authenticated_peer_count'] == 4 for v in telemetry)
        running = all(v['service']['ActiveState'] == 'active' and
                      int(v['service']['MainPID']) > 0 for v in observations.values())
        if sessions and running and height >= max(3, first_height+3):
            historical = parallel(hosts, 'synergy_chainTelemetry', {'at_height': height})
            commitments = [v['common_finalized_commitment'] for v in historical.values()]
            if not commitments[0] or not all(c == commitments[0] for c in commitments):
                raise RuntimeError('finalized commitments disagree at identical height')
            effects = True
            if transaction:
                senders = parallel(hosts, 'synergy_getAccount', {'address': transaction['sender'], 'at_height': height})
                receivers = parallel(hosts, 'synergy_getAccount', {'address': transaction['receiver'], 'at_height': height})
                if any(v['nonce'] > 1 for v in senders.values()):
                    raise RuntimeError('duplicate execution: sender nonce exceeds one')
                effects = all(v['nonce'] == 1 for v in senders.values()) and all(
                    v['balance_nwei'] == str(transaction['amount_nwei']) for v in receivers.values())
            if effects:
                print(json.dumps({'gate': args.operation, 'passed': True, 'height': height,
                                  'commitment': commitments[0], 'validators': observations}))
                return
        if time.monotonic() >= deadline:
            raise RuntimeError('fleet acceptance deadline; last heights='+str([v['finalized_height'] for v in telemetry]))
        time.sleep(2)


if __name__ == '__main__':
    main()
