#!/usr/bin/env python3
"""Read-only active deployment comparison through existing SSH control sockets.
No node CLI/import/preflight, key contents, databases, logs, or historical scans.
"""
import argparse
import json
import re
from pathlib import Path
import stat
import subprocess
import sys

R5 = "43eae3fdc42a2bff9e0ba2fa369d708fb60d14e90c6e18a6f344f5071c6cb23b"
R9 = "9658bcd7de73392176f62c5fa4538cb20c6be946af052d8fe556578813d8239d"
# Only these explicit public deployment paths may be opened. Custody/enrollment/
# unlock paths are inspected by lstat only. /proc is used for path references.
PROBE = r"""
import hashlib,json,os,stat,subprocess
from pathlib import Path
ROOT=Path('/opt/Synergy')
MAX=4*1024*1024
def read(p,limit=MAX):
    s=os.lstat(p)
    if not stat.S_ISREG(s.st_mode) or s.st_size>limit:
        raise ValueError('not bounded regular public file: '+str(p))
    with open(p,'rb') as f:
        b=f.read(limit+1)
    if len(b)>limit: raise ValueError('public file grew beyond bound')
    return b
def public(p): return json.loads(read(p))
def digest(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def meta(p):
    try:
        s=os.lstat(p)
        return dict(path=str(p),real=os.path.realpath(p),uid=s.st_uid,gid=s.st_gid,
                    mode=oct(stat.S_IMODE(s.st_mode)),symlink=stat.S_ISLNK(s.st_mode))
    except OSError as e:return dict(path=str(p),error=type(e).__name__)
c=public(ROOT/'config/node.json')
normalized=json.loads(json.dumps(c))
for k in ('node_name','network','public_identity_path'):normalized.pop(k,None)
normalized.get('telemetry',{}).pop('service_name',None)
# Do not print arbitrary configuration values, environment or process arguments.
fingerprint=hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()
props=subprocess.check_output(['systemctl','show','synergy-node.service',
 '--property=MainPID,FragmentPath,DropInPaths,WorkingDirectory,User,Group,LimitNOFILE,LimitNPROC,TasksMax,MemoryMax,MemoryHigh,CPUQuotaPerSecUSec,CPUAffinity,Nice,Restart,RestartUSec'],text=True)
pid=next(x.split('=',1)[1] for x in props.splitlines() if x.startswith('MainPID='))
out=dict(config_fingerprint=fingerprint,chain_id=c.get('chain_id'),network_id=c.get('network_id'),
         node_name=c.get('node_name'),unit=props.splitlines(),package_sha256=digest(ROOT/'package.json'))
paths={str(ROOT),str(ROOT/'config/node.json'),str(ROOT/'bin/synergy-node'),c['storage']['data_directory']}
for k in ('genesis_path','manifest_path','public_identity_path'):
    if c.get(k):paths.add(c[k])
for owner in ('aegis_provider','apqe_transport','consensus','etdag'):
    for k,v in c.get(owner,{}).items():
        if isinstance(v,str) and v.startswith('/'):paths.add(v)
out['paths']=[meta(p) for p in sorted(paths)]
out['suspicious_config_refs']=[p for p in sorted(paths) if '1266' in p.lower() or not (p=='/opt/Synergy' or p.startswith('/opt/Synergy/'))]
out['public_hashes']={rel:digest(ROOT/rel) for rel in (
 'network/genesis.json','network/authority.json','network/network-manifest.json',
 'network/transport-registry.json','lib/apqe/build-report.json')}
manifest=public(ROOT/'package.json')
bad=[]; checked=0
# Restrict manifest-directed reads to public package files; no traversal/keys.
for name,expected in manifest['files'].items():
    rel=Path(name)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel.parts[0] not in (
        'bin','lib','tools','assets','roles') and name!='README.md':
        bad.append(dict(path=name,error='unsafe manifest path'));continue
    p=ROOT/rel
    try:
        if any((ROOT/Path(*rel.parts[:i])).is_symlink() for i in range(1,len(rel.parts)+1)):
            raise ValueError('symlink in package path')
        if not stat.S_ISREG(os.lstat(p).st_mode):raise ValueError('not regular')
        checked+=1
        if digest(p)!=expected:bad.append(dict(path=name,error='hash mismatch'))
    except (OSError,ValueError) as e:bad.append(dict(path=name,error=str(e)))
out['inventory']=dict(checked=checked,mismatches=bad)
if pid!='0':
    proc=Path('/proc')/pid
    args=(proc/'cmdline').read_bytes().split(b'\0')
    args=[a.decode(errors='replace') for a in args if a]
    cfg=next((args[i+1] for i,a in enumerate(args[:-1]) if a=='--config'),None)
    # Flag unexpected args rather than printing values that might be secrets.
    out['active']=dict(pid=int(pid),executable=os.readlink(proc/'exe'),
        executable_sha256=digest(proc/'exe'),cwd=os.readlink(proc/'cwd'),
        config=cfg,argv_expected=args==['/opt/Synergy/bin/synergy-node','start','--config','/opt/Synergy/config/node.json'])
    opened=set()
    for p in (proc/'fd').iterdir():
        try:
            value=os.readlink(p)
            if value.startswith('/') and not value.startswith(('/dev/','/proc/','/run/')):opened.add(value)
        except OSError:pass
    mapped=set()
    for line in (proc/'maps').read_text().splitlines():
        pieces=line.split(maxsplit=5)
        if len(pieces)==6 and pieces[5].startswith('/'):mapped.add(pieces[5])
    out['open_paths']=sorted(opened);out['mapped_paths']=sorted(mapped)
    out['suspicious_active_refs']=[p for p in sorted(opened|mapped) if '1266' in p.lower()]
    out['active_binary_matches_manifest']=out['active']['executable_sha256']==manifest['files'].get('bin/synergy-node')
data=Path(c['storage']['data_directory'])
out['data_roots']=[meta(data/rel) for rel in ('state/execution','blocks/execution-candidates','consensus/posy','etdag')]
pin=data/'blocks/execution-candidates/candidate-pins/index-v1.json'
try:
    d=public(pin)
    out['candidate_pins']=dict(generation=d['generation'],pins=[
        {k:p.get(k) for k in ('height','block_id','slot','bytes')} for p in d['pins']])
except (OSError,ValueError) as e:out['candidate_pins']=dict(error=str(e))
out['legacy_standard_roots']=[meta(p) for p in ('/opt/synergy','/opt/Synergy/chain1266','/var/lib/synergy','/root/.synergy') if os.path.lexists(p)]
print(json.dumps(out,sort_keys=True))
"""

# Current 2026-11-09 rollout defaults only; operator overrides are authoritative
# for a subsequent release. New host aliases require an explicit expectation.
DEFAULT_PACKAGES = {f"synergy-val{n}": R9 if n == 5 else R5 for n in range(2, 7)}

def expected_packages(hosts, overrides):
    if len(hosts) != len(set(hosts)):
        raise ValueError("duplicate host alias")
    for host in hosts:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", host):
            raise ValueError("invalid host alias")
    expected = {host: DEFAULT_PACKAGES[host] for host in hosts if host in DEFAULT_PACKAGES}
    seen = set()
    for item in overrides:
        host, separator, digest = item.partition("=")
        if not separator or host not in hosts:
            raise ValueError("expected package override must name a selected host")
        if host in seen:
            raise ValueError("duplicate expected package override")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("expected package must be a SHA256 hexadecimal digest")
        seen.add(host)
        expected[host] = digest.lower()
    if set(expected) != set(hosts):
        raise ValueError("new host aliases require --expected-package HOST=SHA256")
    return expected

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hosts", nargs="+",
                   default=[f"synergy-val{n}" for n in range(2, 7)])
    p.add_argument("--expected-package", action="append", default=[], metavar="HOST=SHA256",
                   help="override current rollout default; required for new host aliases")
    p.add_argument("--master-dir", type=Path, default=Path.home()/".ssh/atlas-telemetry")
    p.add_argument("--timeout", type=int, default=30, help="bounded seconds per existing connection")
    args = p.parse_args()
    if not 1 <= args.timeout <= 120:
        p.error("--timeout must be 1..120")
    try:
        expected_by_host = expected_packages(args.hosts, args.expected_package)
    except ValueError as error:
        p.error(str(error))
    # Fail before any host probe if any required existing master is absent.
    for host in args.hosts:
        path = args.master_dir/host
        if not path.exists() or not stat.S_ISSOCK(path.stat().st_mode):
            p.error(f"existing SSH master missing: {path}; no new connection authorized")
    baseline = None
    failed = False
    for host in args.hosts:
        command = ["ssh", "-S", str(args.master_dir/host), "-o", "ControlMaster=no",
                   "-o", "ProxyCommand=/usr/bin/false", "-o", "BatchMode=yes", host,
                   "sudo -n python3 -B -"]
        r = subprocess.run(command, input=PROBE, text=True, capture_output=True,
                           timeout=args.timeout, check=False)
        if r.returncode:
            print(json.dumps(dict(host=host,error="read-only probe failed",exit=r.returncode)))
            failed = True
            continue
        d = json.loads(r.stdout)
        expected = expected_by_host[host]
        d.update(host=host,expected_package=expected,
                 expected_release=d["package_sha256"]==expected)
        if baseline is None:
            baseline = d
        d["same_functional_config_as_first"] = d["config_fingerprint"]==baseline["config_fingerprint"]
        d["same_public_artifacts_as_first"] = d["public_hashes"]==baseline["public_hashes"]
        d["interpretation"] = "Each binary is checked against its own expected release; pin generations/heights are not equivalence failures. Sparse checkpoint history requires separate dependency qualification."
        failed |= bool(d["inventory"]["mismatches"] or not d["expected_release"]
                       or not d.get("active_binary_matches_manifest",False)
                       or not d.get("active",{}).get("argv_expected",False)
                       or d.get("suspicious_active_refs") or d["suspicious_config_refs"]
                       or not d["same_functional_config_as_first"]
                       or not d["same_public_artifacts_as_first"])
        print(json.dumps(d,sort_keys=True))
    return int(failed)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError,ValueError,subprocess.TimeoutExpired) as e:
        print(type(e).__name__+": bounded diagnostic failed",file=sys.stderr)
        sys.exit(2)
