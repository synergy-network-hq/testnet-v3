#!/usr/bin/env python3
"""Read-only five-host canonical Linux conformance, reusing existing SSH masters."""
import argparse
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--host',action='append',required=True,help='ValN=SSH_ALIAS=EXISTING_CONTROL_SOCKET')
    args=p.parse_args()
    entries=[item.split('=',2) for item in args.host]
    if {e[0] for e in entries}!={'Val2','Val3','Val4','Val5','Val6'} or len(entries)!=5:
        p.error('exactly Val2 through Val6 required')
    if args.output.exists():p.error('new evidence path required')
    spec=importlib.util.spec_from_file_location('connection',SOURCE/'tools/validator/provision-stability-hosts.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    policy=(SOURCE/'tools/linux-node/conformance.py').read_text()
    schema=json.loads((SOURCE/'schemas/node-config.schema.json').read_text())
    data=json.dumps({'source':policy,'schema':schema,'manifest':json.loads(args.manifest.read_text())}).encode()
    code='''import sys,json,datetime
sys.dont_write_bytecode=True
sys.path.insert(0,'/opt/Synergy/tools')
payload=json.load(sys.stdin)
namespace={'__name__':'fleet_readonly'}
exec(payload['source'],namespace)
try:
 r=namespace['installed']('/opt/Synergy',payload['manifest'],True,schema=payload['schema'])
except Exception as e:r={'conformant':False,'error':str(e)}
r['observed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
print(json.dumps(r))'''
    def audit(entry):
        name,alias,socket=entry
        result=subprocess.run(helper.master_arguments(alias,socket)+['exec sudo -n -- '+shlex.join(['python3','-c',code])],input=data,capture_output=True,timeout=120)
        return name,json.loads(result.stdout) if result.returncode==0 else {'conformant':False,'error':'remote collection failed','returncode':result.returncode}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:hosts=dict(pool.map(audit,entries))
    fingerprints={v.get('configuration_fingerprint') for v in hosts.values()}
    result={'format':'synergy-five-validator-conformance-v1','selected_manifest':str(args.manifest),
            'conformance_policy_sha256':__import__('hashlib').sha256(policy.encode()).hexdigest(),
            'conformant':all(v.get('conformant') for v in hosts.values()) and len(fingerprints)==1,
            'normalized_configuration_agrees':len(fingerprints)==1 and None not in fingerprints,'hosts':hosts}
    with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({'conformant':result['conformant'],'hosts':{k:{f:v for f,v in h.items() if f!='normalized_configuration'} for k,h in hosts.items()}}))
    return 0 if result['conformant'] else 1

if __name__=='__main__':sys.exit(main())
