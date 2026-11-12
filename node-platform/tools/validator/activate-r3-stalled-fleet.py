#!/usr/bin/env python3
"""Qualified seq14->15 or stopped retained seq15->16 activation; default read-only."""
import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import time
from pathlib import Path

ROOT=Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
# Linux release bytes are deliberately built on APFS rather than in the SMB
# checkout.  The checkout's target directory is not a release-artifact store:
# its contents may not survive the storage guarantees required by the release
# builder.  Keep the approved path narrow rather than accepting an arbitrary
# local file named "synergy-node".
APFS_CANDIDATE_ROOT=Path('/Users/jhutzler/Library/Caches/Synergy-PoSy-qualification-target')
APFS_NODE_RELATIVE=Path('x86_64-unknown-linux-gnu/release/synergy-node')
NATIVE_MAC_KEYTOOL=ROOT/'target/release/synergy-keytool'
REQUIREMENTS={'three_of_five_fail_closed','four_of_five_recovery','fifth_validator_rejoin',
              'wallet_exactly_once','durable_restart','continued_finality_after_restart',
              'committed_r3_exclusion_negatives'}
TEST='authenticated_socket_r3_h51_late_vac_split_recovers_real_wallet_and_restart'

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def qualification(manifest,sha3,length,commitment):
    if manifest.get('schema')!='posy-r3-qualification-v1' or manifest.get('reviewed_by_operator') is not True:
        raise RuntimeError('explicit reviewed qualification manifest required')
    if manifest.get('artifact')!={'sha3_256':sha3,'length':length} or manifest.get('activation_commitment')!=commitment:
        raise RuntimeError('qualification artifact/commitment mismatch')
    source=manifest['test_source']
    path=Path(source['path']).resolve()
    if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=source['sha256']:
        raise RuntimeError('qualification test source mismatch')
    records=manifest.get('requirements',{})
    if set(records)!=REQUIREMENTS:
        raise RuntimeError('qualification coverage incomplete')
    for name,record in records.items():
        if record.get('verified') is not True or not record.get('review_note'):
            raise RuntimeError('unreviewed coverage: '+name)
        evidence=Path(record['log_path'])
        data=evidence.read_bytes()
        if hashlib.sha256(data).hexdigest()!=record['log_sha256'] or record.get('exit_code')!=0:
            raise RuntimeError('qualification log mismatch: '+name)
        if name!='committed_r3_exclusion_negatives' and record.get('test_name')!=TEST:
            raise RuntimeError('unexpected socket qualification name')
        # Human-reviewed outcome records carry the semantic coverage; matching
        # PASS text alone is deliberately insufficient.
    return True


def require_stopped(states):
    if set(states)!=set(range(2,7)):
        raise RuntimeError('missing stopped-fleet evidence')
    for n,state in states.items():
        if int(state['MainPID'])!=0 or state['ActiveState'] not in {'inactive','failed'}:
            raise RuntimeError(f'Val{n} still active: {state}')



STOPPED_READ = r"""
import hashlib,json,subprocess,shlex,sys
from pathlib import Path
base='/etc/synergy/posy-stability';tools='/usr/local/libexec/synergy/posy-stability/'
binary=tools+'synergy-node-r3-recovery'
verify=[tools+'synergy-keytool','verify-release',base+'/release-r3-recovery.json',binary,'1266','val2-posy-consensus-v1',base+'/authority-root.pub','14']
def safe(path):
 p=Path(path)
 if not p.is_file() or p.is_symlink() or any(x.is_symlink() for x in p.parents):raise RuntimeError('unsafe installed path')
 return p
unit=safe('/etc/systemd/system/synergy-posy-stability.service').read_text().splitlines()
if [shlex.split(v.split('=',1)[1]) for v in unit if v.startswith('ExecStart=')]!=[[binary,'start','--config',base+'/node.json']]:raise RuntimeError('installed unit binary mismatch')
if [shlex.split(v.split('=',1)[1]) for v in unit if v.startswith('ExecStartPre=')]!=[verify]:raise RuntimeError('installed unit verifier mismatch')
release=json.loads(safe(verify[2]).read_text())['release']
expected=json.loads(sys.argv[1])
if any(release.get(k)!=expected[k] for k in ['sequence','release_id','protocol_activation_commitment']):raise RuntimeError('installed release identity mismatch')
artifact=safe(binary).read_bytes()
if release['artifact']['sha3_256']!=expected['sha3_256'] or hashlib.sha3_256(artifact).hexdigest()!=expected['sha3_256'] or release['artifact']['length']!=len(artifact):raise RuntimeError('installed artifact mismatch')
safe(base+'/authority-root.pub');subprocess.run(verify,check=True,capture_output=True,timeout=30)
service=dict(v.split('=',1) for v in subprocess.check_output(['systemctl','show','synergy-posy-stability.service','-p','ActiveState','-p','MainPID','-p','NRestarts']).decode().strip().splitlines())
if int(service['MainPID'])!=0 or service['ActiveState'] not in {'inactive','failed'}:raise RuntimeError('fleet not stopped')
configuration=json.loads(safe(base+'/node.json').read_text());root=Path(configuration['storage']['data_directory'])
if not root.is_absolute() or not str(root).startswith('/var/lib/synergy/posy-stability/'):raise RuntimeError('unexpected retained data directory')
state=json.loads(safe(root/'state/execution/finalized-state.json').read_text())['state']
print(json.dumps({'service':service,'commitment':state,'installed_release':expected,'native_verified':True,'unit_commands_verified':True,'config_sha3':hashlib.sha3_256(safe(base+'/node.json').read_bytes()).hexdigest()}))
"""

def validate_retained_stopped(previous,current,expected,tip):
    for snapshot in [previous,current]:
        require_stopped({n:v['service'] for n,v in snapshot.items()})
        for n,state in snapshot.items():
            d=state['commitment']
            if state.get('installed_release')!=expected or state.get('native_verified') is not True or state.get('unit_commands_verified') is not True:
                raise RuntimeError('unverified installed sequence15 evidence')
            if (d['finalized_height'],d['finalized_block_id'],d['state_root'])!=tip or tip[0]!=47:
                raise RuntimeError('retained exact H47 commitment mismatch')
            if int(state['service']['NRestarts'])<0 or not state.get('config_sha3'):
                raise RuntimeError('invalid retained service/config evidence')
    for n in previous:
        if previous[n]!=current[n]:raise RuntimeError('stopped retained evidence changed between snapshots')
    return {'finalized_height':tip[0],'block_hash':tip[1],'state_root':tip[2],'installed_sequence':15}


def self_test():
    zero={n:{'MainPID':'0','ActiveState':'inactive'} for n in range(2,7)}
    require_stopped(zero)
    for field,value in [('MainPID','1'),('ActiveState','active')]:
        bad={n:dict(s) for n,s in zero.items()};bad[2][field]=value
        try:require_stopped(bad)
        except RuntimeError:continue
        raise AssertionError('running fleet accepted')
    for value in [{},{'schema':'posy-r3-qualification-v1','reviewed_by_operator':False}]:
        try:qualification(value,'a'*64,1,'commitment')
        except RuntimeError:continue
        raise AssertionError('absent/unreviewed qualification accepted')
    import copy
    import tempfile
    failed={n:{'MainPID':'0','ActiveState':'failed'} for n in range(2,7)}
    require_stopped(failed)
    expected={'sequence':15,'release_id':'old','sha3_256':'a'*64,'protocol_activation_commitment':'approved'}
    fixture={n:{'service':dict(failed[n],NRestarts='0'),'commitment':{'finalized_height':47,'finalized_block_id':'block','state_root':'root'},'installed_release':dict(expected),'native_verified':True,'unit_commands_verified':True,'config_sha3':'b'*64} for n in range(2,7)}
    validate_retained_stopped(fixture,copy.deepcopy(fixture),expected,(47,'block','root'))
    for kind in ['pid','active','signature','unit','release','height','hash','root','config','restart','missing']:
        bad=copy.deepcopy(fixture)
        if kind=='pid':bad[2]['service']['MainPID']='1'
        elif kind=='active':bad[2]['service']['ActiveState']='active'
        elif kind=='signature':bad[2]['native_verified']=False
        elif kind=='unit':bad[2]['unit_commands_verified']=False
        elif kind=='release':bad[2]['installed_release']['sequence']=14
        elif kind=='height':bad[2]['commitment']['finalized_height']=48
        elif kind=='hash':bad[2]['commitment']['finalized_block_id']='other'
        elif kind=='root':bad[2]['commitment']['state_root']='other'
        elif kind=='config':bad[2]['config_sha3']='changed'
        elif kind=='restart':bad[2]['service']['NRestarts']='1'
        else:del bad[2]
        try:validate_retained_stopped(fixture,bad,expected,(47,'block','root'))
        except RuntimeError:continue
        raise AssertionError('invalid retained stopped evidence accepted: '+kind)
    compile(STOPPED_READ,'stopped probe','exec')
    with tempfile.TemporaryDirectory() as directory:
        log=Path(directory)/'qualification.log';log.write_text('reviewed fixture evidence')
        source=Path(__file__).resolve()
        record={'verified':True,'review_note':'offline guard fixture','log_path':str(log),
                'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'exit_code':0,'test_name':TEST}
        manifest={'schema':'posy-r3-qualification-v1','reviewed_by_operator':True,
                  'artifact':{'sha3_256':'a'*64,'length':1},'activation_commitment':'commitment',
                  'test_source':{'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()},
                  'requirements':{k:dict(record) for k in REQUIREMENTS}}
        assert qualification(manifest,'a'*64,1,'commitment')
        for kind in ['artifact','coverage','log','source','exit']:
            bad=copy.deepcopy(manifest)
            if kind=='artifact':bad['artifact']['sha3_256']='b'*64
            elif kind=='coverage':del bad['requirements']['durable_restart']
            elif kind=='log':bad['requirements']['durable_restart']['log_sha256']='b'*64
            elif kind=='source':bad['test_source']['sha256']='b'*64
            else:bad['requirements']['durable_restart']['exit_code']=1
            try:qualification(bad,'a'*64,1,'commitment')
            except RuntimeError:continue
            raise AssertionError('invalid qualification accepted: '+kind)
    print('R3_ACTIVATION_SELF_TEST_PASSED: retained seq15 stopped H47 positive and 11 negatives, stopped fleet, qualification identity/coverage/source/log/exit and absent/unreviewed guards; no host access')


def bounded_document(path, limit=64*1024*1024):
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file() or not 0<path.stat().st_size<=limit:
        raise RuntimeError('bounded canonical public document required')
    return path.read_bytes()


def configured_master_socket(host):
    """Return the already configured SSH master path without opening SSH."""
    result=subprocess.run(['ssh','-G',host],check=True,capture_output=True,text=True,timeout=15)
    values={}
    for line in result.stdout.splitlines():
        key,separator,value=line.partition(' ')
        if separator:values[key]=value.strip()
    socket=values.get('controlpath')
    if not socket or not Path(socket).is_absolute():
        raise RuntimeError('configured SSH ControlPath required for '+host)
    return socket


def exact_apfs_candidate(path, relative, label):
    path=Path(path)
    expected=(APFS_CANDIDATE_ROOT/relative).resolve()
    if not path.is_absolute() or path.is_symlink() or path.resolve()!=expected:
        raise RuntimeError('approved APFS '+label+' path required')
    return path


def bounded_apfs_evidence(path, limit=64*1024*1024):
    path=Path(path)
    root=APFS_CANDIDATE_ROOT.resolve()
    if not path.is_absolute() or path.is_symlink() or root not in path.resolve().parents:
        raise RuntimeError('approved APFS candidate evidence path required')
    return bounded_document(path,limit)


def native_macos_keytool(path):
    """Pin the local arm64 verifier; a Linux keytool cannot verify on this Mac."""
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or path.resolve()!=NATIVE_MAC_KEYTOOL.resolve():
        raise RuntimeError('canonical native macOS keytool required')
    data=bounded_document(path,256*1024*1024)
    # MH_MAGIC_64 and CPU_TYPE_ARM64 in the native Mach-O header.  This keeps a
    # cross-compiled ELF out of the local signature-verification boundary.
    if data[:8]!=b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01':
        raise RuntimeError('native keytool is not arm64 Mach-O')
    return data


def validate_single_path_plan(plan):
    """Reviewed candidate install is separate from final release qualification."""
    if plan.get('schema')!='posy-single-path-install-v1':raise RuntimeError('single-path plan schema required')
    binary_path=exact_apfs_candidate(plan['binary_path'],APFS_NODE_RELATIVE,'candidate artifact')
    binary=bounded_document(binary_path,256*1024*1024)
    sha3=hashlib.sha3_256(binary).hexdigest()
    if plan.get('artifact')!={'sha3_256':sha3,'length':len(binary)} or binary[:7]!=b'\x7fELF\x02\x01\x01' or binary[18:20]!=b'\x3e\0':
        raise RuntimeError('frozen Linux candidate artifact mismatch')
    provenance_bytes=bounded_apfs_evidence(plan['provenance_path'])
    if hashlib.sha3_256(provenance_bytes).hexdigest()!=plan.get('provenance_sha3_256'):
        raise RuntimeError('candidate provenance pin mismatch')
    provenance=json.loads(provenance_bytes)
    if provenance.get('format_version')!=1 or provenance.get('before')!=provenance.get('after') or not provenance.get('before') or provenance.get('artifact',{}).get('sha3_256')!=sha3 or provenance.get('target')!='x86_64-unknown-linux-gnu':
        raise RuntimeError('complete frozen candidate provenance required')
    release_bytes=bounded_apfs_evidence(plan['signed_release_path'],1024*1024)
    release=json.loads(release_bytes).get('release',{})
    if plan.get('signed_release_sha3_256')!=hashlib.sha3_256(release_bytes).hexdigest() or release.get('artifact',{}).get('sha3_256')!=sha3 or release.get('artifact',{}).get('length')!=len(binary) or release.get('artifact',{}).get('platform')!='x86_64-unknown-linux-gnu':
        raise RuntimeError('signed candidate release artifact mismatch')
    if release.get('protocol_activation_commitment')!=plan.get('protocol_activation_commitment') or not plan.get('protocol_activation_commitment'):
        raise RuntimeError('explicit approved protocol activation binding required')
    if type(plan.get('installed_sequence')) is not int or release.get('sequence',0)<=plan['installed_sequence']:
        raise RuntimeError('candidate release sequence must advance retained installation')
    hosts=plan.get('hosts',[])
    if sorted(h.get('number',0) for h in hosts)!=list(range(2,7)):
        raise RuntimeError('exact Val2 through Val6 inventory required')
    for host in hosts:
        name=f"synergy-val{host['number']}"
        if host.get('host')!=name or host.get('socket')!=configured_master_socket(name):
            raise RuntimeError('existing canonical host/master bindings required')
        if set(host.get('expected',{}))!={'binary_sha3','release_sha3','unit_sha3','config_sha3','trust_sha3','installed_sequence'}:
            raise RuntimeError('current single-path host digest/sequence pins required')
        if host['expected']['installed_sequence']!=plan['installed_sequence']:
            raise RuntimeError('mixed installed sequences rejected')
    # Native local verification must precede even the all-host stop operation.
    keytool=Path(plan['native_keytool_path'])
    if hashlib.sha3_256(native_macos_keytool(keytool)).hexdigest()!=plan.get('native_keytool_sha3_256'):
        raise RuntimeError('native release verifier pin mismatch')
    trust=Path(plan['local_trust_key_path'])
    if hashlib.sha3_256(bounded_document(trust,8192)).hexdigest()!=plan.get('local_trust_sha3_256'):
        raise RuntimeError('local native release trust pin mismatch')
    subprocess.run([str(keytool),'verify-release',plan['signed_release_path'],str(binary_path),'1266','val2-posy-consensus-v1',str(trust),str(plan['installed_sequence'])],check=True,capture_output=True,timeout=60)
    if hashlib.sha3_256(bounded_document(binary_path,256*1024*1024)).hexdigest()!=sha3 or bounded_document(plan['signed_release_path'],1024*1024)!=release_bytes:
        raise RuntimeError('candidate changed during native signature verification')
    blockers=[]
    for approval in ('operator_candidate_install_approved','protocol_activation_approved','source_review_approved'):
        if plan.get(approval) is not True:blockers.append(approval)
    record=plan.get('approval_evidence')
    if not isinstance(record,dict):blockers.append('approval_evidence')
    else:
        evidence=bounded_document(record['path'])
        if hashlib.sha256(evidence).hexdigest()!=record.get('sha256'):raise RuntimeError('approval evidence pin mismatch')
    return binary,release_bytes,hosts,blockers


def single_path_install(plan_path, execute=False):
    plan=json.loads(bounded_document(plan_path))
    binary,envelope,hosts,blockers=validate_single_path_plan(plan)
    owner=load_module('single_path_owner',ROOT/'tools/validator/provision-stability-hosts.py')
    hosts=sorted(hosts,key=lambda h:h['number'])
    def call(host,action,request=None,data=None):
        return owner.single_path_remote(host['host'],host['socket'],action,request,data)
    probes={host['number']:call(host,'probe') for host in hosts}
    for host in hosts:
        snapshot=probes[host['number']]['snapshot']
        if any(snapshot.get(key)!=value for key,value in host['expected'].items()):
            raise RuntimeError('actual canonical installation differs from approved inventory')
        if snapshot['trust_sha3']!=plan['local_trust_sha3_256']:
            raise RuntimeError('native release trust differs across fleet')
    print(json.dumps({'event':'single_path_candidate_preflight','execute':execute,'candidate_artifact':plan['artifact'],
        'installation_approval_blockers':blockers,'hosts':probes,'cleanup_performed':False,
        'candidate_installed':False,'GateE_qualified':False,'GateF_qualified':False,'GateG_qualified':False}),flush=True)
    if not execute:return
    if blockers:raise RuntimeError('candidate installation blocked: '+', '.join(blockers))
    candidate_sha=plan['artifact']['sha3_256'];candidate_sequence=json.loads(envelope)['release']['sequence'];stopped_hosts={};verified={}
    try:
        # Entire fleet is confirmed stopped before opening any canonical inode.
        for host in hosts:
            stopped_hosts[host['number']]=call(host,'stop',{'expected_snapshot':probes[host['number']]['snapshot'],'candidate_sha3':candidate_sha})
        if set(stopped_hosts)!=set(range(2,7)):raise RuntimeError('all-five stopped evidence missing')
        for host in hosts:
            fresh=call(host,'probe')['snapshot']
            if int(fresh['service']['MainPID'])!=0 or fresh['service']['ActiveState'] not in ('inactive','failed') or fresh['processes']:
                raise RuntimeError('all-five complete stop not retained before replacement')
            if any(fresh.get(key)!=host['expected'][key] for key in ('binary_sha3','release_sha3','unit_sha3','config_sha3','trust_sha3','installed_sequence')):
                raise RuntimeError('stopped canonical inputs changed before replacement')
        for host in hosts:
            prior=stopped_hosts[host['number']]
            for kind,data in [('binary',binary),('release',envelope)]:
                call(host,'replace',{'kind':kind,'length':len(data),'sha3_256':hashlib.sha3_256(data).hexdigest(),
                    'config_sha3':prior['config_sha3'],'unit_sha3':prior['unit_sha3'],'boot_id':prior['boot_id']},data)
        for host in hosts:
            verified[host['number']]=call(host,'verify',{'binary_sha3':candidate_sha,
                'release_sha3':hashlib.sha3_256(envelope).hexdigest(),'config_sha3':host['expected']['config_sha3'],
                'trust_sha3':host['expected']['trust_sha3'],'installed_sequence':candidate_sequence-1})
        if set(verified)!=set(range(2,7)) or not all(v.get('native_release_verified') for v in verified.values()):
            raise RuntimeError('all-five installed native release verification required before any start')
        started={host['number']:call(host,'start',verified[host['number']]) for host in hosts}
        print(json.dumps({'event':'single_path_candidate_installed','hosts':started,'qualified_release_promoted':False,
            'GateE_qualified':False,'GateF_qualified':False,'GateG_qualified':False,
            'remaining':'actual five-host finalized execution, TPS and soak qualification'}),flush=True)
    except BaseException:
        failures={}
        for host in hosts:
            try:failures[host['number']]=call(host,'fail_stop',{'candidate_sha3':candidate_sha})
            except Exception as error:failures[host['number']]={'error_type':type(error).__name__,'stop_unconfirmed':True}
        print(json.dumps({'event':'single_path_candidate_failed_no_rollback','hosts':failures,'journals_reset':False}),flush=True)
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--single-path-plan',type=Path,help='reviewed exact candidate plan; replaces only existing canonical stopped files')
    parser.add_argument('--release',choices=['r3-recovery','r3-retained-recovery'],default='r3-recovery')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--qualification-manifest',type=Path)
    parser.add_argument('--expected-height',type=int,required=False)
    parser.add_argument('--expected-block-hash')
    parser.add_argument('--expected-state-root')
    parser.add_argument('--snapshot-interval',type=int,default=10)
    parser.add_argument('--timeout',type=int,default=900)
    args=parser.parse_args()
    if args.self_test:
        if args.execute:parser.error('self-test cannot execute')
        self_test();return
    if args.single_path_plan:
        single_path_install(args.single_path_plan,args.execute);return
    if not 5<=args.snapshot_interval<=60 or not 60<=args.timeout<=1800:
        parser.error('snapshot interval must be 5..60; timeout 60..1800')
    if args.expected_height is None or not args.expected_block_hash or not args.expected_state_root:
        parser.error('explicit expected stalled height/block hash/state root required')
    roll=load_module('r3_roll',ROOT/'tools/validator/roll-r1-tip.py')
    stage=load_module('r3_stage',ROOT/'tools/validator/stage-r3-recovery-release.py')
    stage.BINARY=roll.TOOLS+'synergy-node-'+args.release
    stage.RELEASE=roll.BASE+'/release-'+args.release+'.json'
    if args.release=='r3-retained-recovery' and len(roll.R3_RETAINED_RECOVERY_SHA3)!=64:
        raise RuntimeError('sequence16 artifact hash unpinned; no host access attempted')
    binary=(ROOT/'target/x86_64-unknown-linux-gnu/release/synergy-node').read_bytes()
    unsigned=json.loads((stage.OUT/('release-'+args.release+'.unsigned.json')).read_text())
    unsigned=unsigned.get('release',unsigned);stage.validate(binary,unsigned,args.release)
    envelope=(stage.OUT/('release-'+args.release+'.json')).read_bytes()
    signed=json.loads(envelope)
    if signed.get('release')!=unsigned or not signed.get('signature') or not signed.get('public_key'):
        raise RuntimeError('signed candidate differs or missing')
    if args.execute:
        if not args.qualification_manifest:parser.error('execute requires explicit qualification manifest')
        if args.release=='r3-retained-recovery' and args.qualification_manifest.resolve()!=(stage.OUT/'r3-retained-qualification.json').resolve():
            parser.error('sequence16 requires canonical r3-retained-qualification.json')
        qualification(json.loads(args.qualification_manifest.read_text()),unsigned['artifact']['sha3_256'],len(binary),roll.R3_ACTIVATION_COMMITMENT)
    verify=[roll.TOOLS+'synergy-keytool','verify-release',stage.RELEASE,stage.BINARY,'1266','val2-posy-consensus-v1',roll.BASE+'/authority-root.pub',str(stage.PROFILES[args.release][0]-1)]
    if args.release=='r3-retained-recovery':
        expected={'sequence':15,'release_id':'posy-stability-20261011-r3-recovery',
                  'sha3_256':roll.R3_RECOVERY_SHA3,'protocol_activation_commitment':roll.R3_ACTIVATION_COMMITMENT}
        def snapshot():
            return {n:json.loads(roll.remote(n,['python3','-c',STOPPED_READ,json.dumps(expected)])) for n in range(2,7)}
        first=snapshot();time.sleep(args.snapshot_interval);second=snapshot()
        result=validate_retained_stopped(first,second,expected,(args.expected_height,args.expected_block_hash,args.expected_state_root))
    else:
        def snapshot():return dict(roll.read(n,args.expected_height) for n in range(2,7))
        first=snapshot();time.sleep(args.snapshot_interval);second=snapshot()
        result=roll.validate_stalled_fleet_preflight(first,second)
    if (result['finalized_height'],result['block_hash'],result['state_root'])!=(args.expected_height,args.expected_block_hash,args.expected_state_root):
        raise RuntimeError('expected stalled tip mismatch')
    staged_probe = r'''
import hashlib,json,sys
from pathlib import Path
for path,length,digest in json.loads(sys.argv[1]):
 p=Path(path)
 if p.is_symlink() or not p.is_file() or any(v.is_symlink() for v in p.parents):raise RuntimeError('unsafe staged path')
 data=p.read_bytes()
 if len(data)!=length or hashlib.sha3_256(data).hexdigest()!=digest:raise RuntimeError('staged bytes differ from local candidate')
print('EXACT_STAGED_BYTES_VERIFIED')
'''
    staged=[(stage.BINARY,len(binary),hashlib.sha3_256(binary).hexdigest()),
            (stage.RELEASE,len(envelope),hashlib.sha3_256(envelope).hexdigest())]
    for n in range(2,7):
        roll.remote(n,['python3','-c',staged_probe,json.dumps(staged)])
        roll.remote(n,verify)
        roll.remote(n,['python3','-c',roll.EDIT,json.dumps(verify),'preflight'])
    print(json.dumps({'event':'stalled_activation_preflight_passed','evidence':result,'execute':args.execute}),flush=True)
    if not args.execute:return
    # All preflight and qualification checks complete before the first mutation.
    # Stop the entire fleet before changing any unit; no mixed running releases.
    stop_probe="import json,subprocess;s=subprocess.check_output(['systemctl','show','synergy-posy-stability.service','-p','ActiveState','-p','MainPID']).decode();print(json.dumps(dict(v.split('=',1) for v in s.strip().splitlines())))"
    observed={}
    try:
        for n in range(2,7):roll.remote(n,['systemctl','stop',roll.SERVICE])
        observed={n:json.loads(roll.remote(n,['python3','-c',stop_probe])) for n in range(2,7)}
        require_stopped(observed)
        for n in range(2,7):
            roll.remote(n,['python3','-c',roll.EDIT,json.dumps(verify),'execute'])
            roll.remote(n,['systemd-analyze','verify',roll.UNIT])
            roll.remote(n,['systemctl','daemon-reload'])
        for n in range(2,7):roll.remote(n,['systemctl','start',roll.SERVICE])
        baseline={n:0 for n in range(2,7)}
        states=roll.wait_advancing('R3 initial recovery',baseline,args.timeout)
        for n,state in states.items():
            if state.get('exe')!=stage.BINARY:raise RuntimeError(f'Val{n} unexpected running executable')
        for interval in range(3):
            roll.wait_advancing(f'R3 sustained recovery {interval+1}',baseline,args.timeout)
        print(json.dumps({'event':'R3_STALLED_FLEET_RECOVERED','advancing_samples':4,'baseline_tps_run':False}),flush=True)
    except Exception:
        # Print exact service states at failure without reverting journals or units.
        for n in range(2,7):
            try:observed[n]=json.loads(roll.remote(n,['python3','-c',stop_probe]))
            except Exception as error:observed[n]={'observation_error':str(error)}
        print(json.dumps({'event':'activation_failed_no_rollback','services':observed}),flush=True)
        raise

if __name__=='__main__':main()
