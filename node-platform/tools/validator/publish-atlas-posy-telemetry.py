#!/usr/bin/env python3
"""Publish actual fresh-fleet observations through existing owner SSH masters."""
import argparse
import hashlib
import math
import datetime
import importlib.util
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fleet_owner', ROOT / 'tools/validator/provision-stability-hosts.py')
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
PROBE = r'''
import json,subprocess,urllib.request,datetime,sys,os,stat,hashlib
from pathlib import Path

MAX_INCREMENTAL_BLOCKS=256
MAX_COUNT_BYTES=16*1024*1024
MAX_CANDIDATE_BYTES=8*1024*1024

def read_bytes(path,maximum):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  metadata=os.fstat(stream.fileno())
  if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>maximum:raise ValueError('bounded regular JSON required')
  data=stream.read(maximum+1)
  if len(data)>maximum:raise ValueError('JSON exceeds bound')
 return data

def read_json(path,maximum,prefix=None):
 data=read_bytes(path,maximum)
 return json.loads(data[len(prefix):] if prefix and data.startswith(prefix) else data),len(data)

def count_finalized_accounts(root,observed):
 # Native World history stores a checkpoint plus at most 63 SNWDV001
 # patches. A patch's account count is never the full wallet count.
 height=observed['finalized_height'];patches=[];total=0
 for current in range(height,max(-1,height-64),-1):
  path=root/'state/execution/finalized-world'/f'{current:020}.json'
  value,size=read_json(path,min(64*1024*1024-total,64*1024*1024),b'SNWDV001')
  total+=size
  if total>64*1024*1024:raise ValueError('world replay exceeds observation budget')
  if 'parent_height' in value:
   if value['height']!=current or value['parent_height']!=current-1:raise ValueError('world patch height mismatch')
   patches.append(value)
  else:
   world=value;break
 else:raise ValueError('world checkpoint missing')
 def commitment(world):
  ordered={'accounts':dict(sorted(world['accounts'].items())),'protocol':dict(sorted(world['protocol'].items()))}
  data=json.dumps(ordered,separators=(',',':'),ensure_ascii=False).encode()
  return hashlib.sha3_256(b'SYNERGY_WORLD_STATE_ROOT_V1'+len(data).to_bytes(8,'big')+data).hexdigest()
 state_root=commitment(world)
 for patch in reversed(patches):
  if patch['parent_state_root']!=state_root:raise ValueError('world patch parent mismatch')
  for group in ('accounts','protocol'):
   for key,value in patch[group].items():
    if value is None:world[group].pop(key,None)
    else:world[group][key]=value
  state_root=commitment(world)
  if state_root!=patch['state_root']:raise ValueError('world patch root mismatch')
 if state_root!=observed['state_root']:raise ValueError('world does not match finalized commitment')
 return len(world['accounts'])

def committed_record(root,height):
 value,size=read_json(root/'state/execution/finalized-history'/f'{height:020}.json',4096)
 state=value['state']
 if value['format']!='synergy-finalized-state-v1' or state['finalized_height']!=height:raise ValueError('committed height mismatch')
 return state,size

def count_committed_transactions(root,observed,previous):
 # A cursor is an observation optimization, never chain authority. Its anchor
 # must still match the canonical durable execution history on every probe.
 cursor={'height':0,'block_id':None,'transactions':0}
 height=observed['finalized_height']
 if isinstance(previous,dict) and all(type(previous.get(k)) is int and previous[k]>=0 for k in ['height','transactions']):
  prior=previous['height']
  if 0<prior<=height and isinstance(previous.get('block_id'),str):
   try:
    anchor,_=committed_record(root,prior)
    if anchor['finalized_block_id']==previous['block_id']:cursor=dict(previous)
   except Exception:pass
 bytes_read=0
 for current in range(cursor['height']+1,min(height,cursor['height']+MAX_INCREMENTAL_BLOCKS)+1):
  try:
   commitment,size=committed_record(root,current)
   bytes_read+=size
   remaining=min(MAX_CANDIDATE_BYTES,MAX_COUNT_BYTES-bytes_read)
   if remaining<=0:break
   candidate,size=read_json(root/'blocks/execution-candidates/candidate'/f'{current:020}.json',remaining,b'SNCDV001')
   bytes_read+=size
   if candidate['height']!=current or candidate['block_id']!=commitment['finalized_block_id'] or candidate['state_root']!=commitment['state_root']:break
   if cursor['height'] and candidate['parent_block_id']!=cursor['block_id']:break
   transactions=candidate['transactions']
   if not isinstance(transactions,list):break
   cursor={'height':current,'block_id':candidate['block_id'],'transactions':cursor['transactions']+len(transactions)}
  except Exception:break
 # Only complete observations publish a cumulative total. Partial catch-up,
 # missing history, malformed records, or a changed incarnation stay unknown.
 complete=cursor['height']==height and (height==0 or cursor['block_id']==observed['finalized_block_id'])
 return cursor,cursor['transactions'] if complete else None

configuration,_=read_json(Path('/opt/Synergy/config/node.json'),1024*1024)
root=Path(configuration['storage']['data_directory'])
if root!=Path('/opt/Synergy/data'):raise ValueError('unexpected active data directory')
genesis,_=read_json(Path(configuration['genesis_path']),4*1024*1024)
manifest,_=read_json(Path(configuration['manifest_path']),1024*1024)
if manifest['network_id']!=configuration['network_id'] or manifest['genesis_hash']!=genesis['genesis_hash']:raise ValueError('selected network mismatch')
identity,_=read_json(Path(configuration['public_identity_path']),1024*1024)
previous_bytes=sys.stdin.buffer.read(4097)
previous=json.loads(previous_bytes) if len(previous_bytes)<=4096 and previous_bytes else None
service=dict(x.split('=',1) for x in subprocess.check_output(['systemctl','show','synergy-node.service','-p','SubState','-p','MainPID','-p','NRestarts']).decode().splitlines())
pid=int(service['MainPID'])
if pid:
 arguments=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
 if b'/opt/Synergy/config/node.json' not in arguments:raise ValueError('running configuration mismatch')
pointer=root/'state/execution/finalized-state.json'
observed=read_json(pointer,4096)[0]['state'] if pointer.is_file() else {'finalized_height':0,'finalized_block_id':None}
height=observed['finalized_height']
result={'network_id':configuration['network_id'],'genesis_hash':genesis['genesis_hash'],'address':identity['node_address'],'vpn_ip':configuration['network']['listen_addresses'][0].rsplit(':',1)[0],'service':service,'height':height,'block':None,'wallets':None,'transactions':None,'release_id':None}
result['registry_validity']=None
try:
 policy,_=read_json(Path('/opt/Synergy/config/start-authorized.json'),128*1024)
 transport=configuration['apqe_transport']
 registry_bytes=read_bytes(Path(transport['registry_path']),256*1024)
 trust_bytes=read_bytes(Path(transport['registry_trust_key_path']),4096)
 if (hashlib.sha256(registry_bytes).hexdigest()!=policy['public_file_sha256']['transport-registry.json']
     or hashlib.sha256(trust_bytes).hexdigest()!=transport['registry_trust_key_sha256']):
  raise ValueError('active transport pins differ')
 registry=json.loads(registry_bytes)['payload']
 if registry['network_id']!=configuration['network_id'] or registry['genesis_hash']!=genesis['genesis_hash'] or registry['chain_id']!=configuration['chain_id']:
  raise ValueError('registry identifies another chain')
 result['registry_validity']={key:registry[key] for key in ['generation','valid_from_unix','expires_at_unix']}
except Exception:pass
try:
 body={'jsonrpc':'2.0','id':1,'method':'synergy_getBlock','params':{'height':height,'hash':None}}
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8545',json.dumps(body).encode(),{'Content-Type':'application/json'}),timeout=3) as response:
  data=response.read(8*1024*1024+1)
  if len(data)<=8*1024*1024:result['block']=json.loads(data).get('result')
except Exception:pass
if result['block'] and (result['block'].get('block_hash')!=observed.get('finalized_block_id') or result['block'].get('state_root')!=observed.get('state_root')):result['block']=None
result['baseline_anchor']=None
if len(sys.argv)>1:
 try:
  anchor_height=int(sys.argv[1])
  if 0<anchor_height<=height:
   body={'jsonrpc':'2.0','id':3,'method':'synergy_getBlock','params':{'height':anchor_height,'hash':None}}
   with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8545',json.dumps(body).encode(),{'Content-Type':'application/json'}),timeout=3) as response:
    data=response.read(8*1024*1024+1)
    if len(data)<=8*1024*1024:result['baseline_anchor']=json.loads(data).get('result')
 except Exception:pass
if height:
 try:
  result['wallets']=count_finalized_accounts(root,observed)
 except Exception:pass
result['admission_stats']=None
try:
 body={'jsonrpc':'2.0','id':2,'method':'synergy_getProtectedAdmissionStats','params':{}}
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8545',json.dumps(body).encode(),{'Content-Type':'application/json'}),timeout=3) as response:
  data=response.read(4097)
  if len(data)<=4096:result['admission_stats']=json.loads(data).get('result')
except Exception:pass
result['chain_telemetry']=None
try:
 body={'jsonrpc':'2.0','id':4,'method':'synergy_chainTelemetry','params':{'at_height':height}}
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8545',json.dumps(body).encode(),{'Content-Type':'application/json'}),timeout=3) as response:
  data=response.read(256*1024+1)
  if len(data)<=256*1024:
   telemetry=json.loads(data).get('result')
   if isinstance(telemetry,dict) and telemetry.get('schema_version')==1:
    commitment=telemetry.get('common_finalized_commitment') or {}
    if telemetry.get('network_identity')==configuration['network_id'] and telemetry.get('process_id')==int(service['MainPID']) and commitment.get('height')==height and commitment.get('block_id')==observed.get('finalized_block_id') and commitment.get('state_root')==observed.get('state_root'):
     result['chain_telemetry']=telemetry
except Exception:pass
# Pruned history cannot establish a chain-wide cumulative transaction count.
# Native counters below are used only for measured rates, never invented totals.
result['_transaction_cursor'],result['transactions']=count_committed_transactions(root,observed,previous)
pid=int(service['MainPID'])
if pid:
 try:result['release_id']=json.loads(Path('/opt/Synergy/package.json').read_bytes()).get('release_id')
 except Exception:pass
result['observed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
print(json.dumps(result))
'''
PUBLISH = r'''
import os,sys,json,grp
from pathlib import Path
p=Path('/var/lib/synergy-atlas-posy/telemetry.json');data=sys.stdin.buffer.read(262145)
assert len(data)<=262144;json.loads(data);assert not p.is_symlink()
p.parent.mkdir(mode=0o750,exist_ok=True);gid=grp.getgrnam('synergy-atlas-v3').gr_gid;os.chown(p.parent,0,gid)
tmp=p.parent/'.telemetry-next';fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o640)
with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
os.chown(tmp,0,gid);os.replace(tmp,p)
'''

def read(item):
    number, cursor, anchor_height = item
    try:
        host=f'synergy-val{number}'
        data = owner.remote(host, MASTER_SOCKETS[host], ['python3', '-c', PROBE]+([] if anchor_height is None else [str(anchor_height)]), json.dumps(cursor).encode())
        return number, json.loads(data)
    except Exception:
        return number, {'service': {}, 'height': None, 'block': None, 'wallets': None, 'transactions': None, 'release_id': None, 'observed_at': None}

def observe_throughput(state, previous, history, peak):
    metric = {key: None for key in ['accepted_tps', 'etdag_ordered_tps', 'finalized_tps',
        'peak_finalized_tps', 'sustained_finalized_tps', 'p95_finality_latency_ms',
        'pending_transactions', 'window_seconds', 'sustained_window_seconds']}
    total = state.get('transactions')
    block = state.get('block') or {}
    timestamp = state.get('observed_at')
    if total is None or not timestamp or not block:
        return metric, None, [], None
    current = (datetime.datetime.fromisoformat(timestamp).timestamp(), state['height'], total, block.get('block_hash'))
    valid = previous and 0 < current[0]-previous[0] <= 30 and current[1] >= previous[1] and current[2] >= previous[2]
    if valid and current[1] == previous[1] and current[3] != previous[3]:
        valid = False
    if not valid:
        return metric, current, [], None
    elapsed = current[0]-previous[0]
    count = current[2]-previous[2]
    rate = count/elapsed
    history = [(a,b,c) for a,b,c in history if a >= current[0]-60]
    history.append((previous[0], current[0], count))
    duration = sum(b-a for a,b,_ in history)
    peak = max(peak or 0, rate)
    metric.update(finalized_tps=rate, peak_finalized_tps=peak,
        sustained_finalized_tps=sum(c for _,_,c in history)/duration,
        window_seconds=elapsed, sustained_window_seconds=duration)
    return metric, current, history, peak

def observe_admission_rates(state, previous):
    stats=state.get('admission_stats')
    observed=state.get('observed_at')
    empty={'accepted_tps':None,'etdag_ordered_tps':None}
    if not isinstance(stats,dict) or not observed:return empty,None
    accepted=stats.get('accepted_total');ordered=stats.get('etdag_ordered_total')
    if any(type(value) is not int or value<0 for value in [accepted,ordered]):return empty,None
    current=(datetime.datetime.fromisoformat(observed).timestamp(),state['service'].get('MainPID'),accepted,ordered)
    if not previous or current[1]!=previous[1] or not 0<current[0]-previous[0]<=30 or accepted<previous[2] or ordered<previous[3]:return empty,current
    elapsed=current[0]-previous[0]
    return {'accepted_tps':(accepted-previous[2])/elapsed,'etdag_ordered_tps':(ordered-previous[3])/elapsed},current

MASTER_SOCKETS={}

def safe_native_telemetry(state):
    value=state.get('chain_telemetry')
    if not isinstance(value,dict) or value.get('schema_version')!=1:return None
    if value.get('network_identity')!=state.get('network_id'):return None
    try:
        if value.get('process_id')!=int(state.get('service',{}).get('MainPID',0)):return None
        observed=datetime.datetime.fromisoformat(state['observed_at']).timestamp()*1000
        native=value.get('observed_at_unix_ms')
        if type(native) not in {int,float} or not math.isfinite(native) or not 0<=observed-native<=10000:return None
    except (KeyError,TypeError,ValueError):return None
    return value

def authenticated_peer_count(state):
    native = safe_native_telemetry(state)
    transport = native.get('transport') if native else None
    value = transport.get('authenticated_peer_count') if isinstance(transport, dict) else None
    return value if type(value) is int and value >= 0 else None

def current_proposer(states):
    # Observe the actual PoSy owner. A lease/height calculation cannot model takeover.
    candidates = []
    members = {s.get('address') for s in states.values() if s.get('address')}
    for state in states.values():
        native = safe_native_telemetry(state)
        chain = native.get('chain') if native else None
        if not isinstance(chain, dict): continue
        consensus = chain.get('consensus') or {}
        build = (chain.get('pipeline') or {}).get('processing_build') or {}
        height, round_number = build.get('height'), build.get('round')
        address = build.get('proposer')
        if (type(height) is int and height >= 0 and type(round_number) is int and round_number >= 0
                and height == consensus.get('height') and round_number == consensus.get('round')
                and address in members):
            candidates.append((height, round_number, address))
    if not candidates: return None
    latest = max((h, r) for h, r, _ in candidates)
    owners = {a for h, r, a in candidates if (h, r) == latest}
    if len(owners) != 1: return None
    return {'address': owners.pop(), 'height': latest[0], 'round': latest[1]}

def active_network(states):
    ids={v.get('network_id') for v in states.values()}
    genesis={v.get('genesis_hash') for v in states.values()}
    if set(states)!=set(range(2,7)) or len(ids)!=1 or not all(isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9._-]{1,256}',v) for v in ids) or len(genesis)!=1 or not all(isinstance(v,str) and re.fullmatch(r'[0-9a-f]{64}',v) for v in genesis):
        raise ValueError('all five active configurations must identify one selected genesis and network')
    return next(iter(ids))

def baseline_status(report, states, network_id, now):
    empty={'status':'pending','label':'No completed TPS baseline reported. Observed rates are not maximum capacity.',
           'started_at':None,'updated_at':now.isoformat(),'target_tps':None}
    if report is None:return empty
    empty['status']='failed' if report.get('status')=='failed' else 'unverified'
    empty['label']='Baseline report is incomplete or cannot be bound to this chain.'
    try:
        if report.get('status')!='completed' or report.get('failure') is not None or report['network_id']!=network_id: return empty
        start=datetime.datetime.fromisoformat(report['start_utc']);end=datetime.datetime.fromisoformat(report['end_utc'])
        if not start.tzinfo or not end.tzinfo or end<start or end>now: return empty
        tip=report['end_tip'];height=tip['common_finalized_height']
        if type(height) is not int or height<1:return empty
        if set(tip['validators'])!={f'val{n}' for n in range(2,7)}:return empty
        for state in states.values():
            anchor=state.get('baseline_anchor')
            if not state.get('block') or state['height']<height or not anchor or anchor.get('height')!=height or anchor.get('block_hash')!=tip['block_hash'] or anchor.get('state_root')!=tip['state_root']:return empty
        submitted=report['submitted_transactions'];finalized=report['finalized_transactions']
        if type(submitted) is not int or submitted<=0 or finalized!=submitted or report['backlog']['remaining_in_flight']!=0:return empty
        rates={k:report[k] for k in ['finalized_tps','end_to_end_finalized_tps','offered_rate_tps','load_window_seconds']}
        if any(type(v) not in {int,float} or not math.isfinite(v) or v<0 for v in rates.values()) or rates['load_window_seconds']<=0:return empty
        return {'status':'completed','label':'Completed bounded TPS baseline; this result does not establish maximum capacity.',
                'started_at':start.isoformat(),'updated_at':end.isoformat(),'target_tps':rates['offered_rate_tps'],
                'sustained_window_seconds':rates['load_window_seconds'],'baseline_finalized_tps':rates['finalized_tps'],
                'baseline_end_to_end_finalized_tps':rates['end_to_end_finalized_tps'],'baseline_finalized_transactions':finalized,
                'baseline_end_height':height,'baseline_end_block_id':tip['block_hash']}
    except (KeyError,TypeError,ValueError):return empty

def stalled_status(state, previous, now):
    identity=(state.get('network_id'),state.get('height'),(state.get('block') or {}).get('block_hash'))
    if not state.get('block') or state.get('service',{}).get('SubState')!='running':return False,None
    since=previous[1] if previous and previous[0]==identity else now
    return now-since>=30,(identity,since)


def live_quorum_test_card(network_id, timestamp, evidence_dir=None):
    card={'name':'Live below-quorum halt and recovery','status':'pending','started_at':None,'updated_at':timestamp,'detail':'No validated historical live quorum recovery evidence for this chain.'}
    directory=evidence_dir or ROOT/'target'
    log=directory/'live-quorum-recovery-seq18.log';exit_file=directory/'live-quorum-recovery-seq18.exit'
    try:
        if network_id!='synergy-posy-baseline-20261010' or any(p.is_symlink() or not p.is_file() for p in [log,exit_file]):return card
        if log.stat().st_size>1024*1024 or exit_file.stat().st_size>16 or exit_file.read_text().strip()!='0':return card
        events=[json.loads(line) for line in log.read_text().splitlines() if line.startswith('{')]
        if any(e.get('event')=='LIVE_QUORUM_RECOVERY_FAIL' for e in events):return card
        def one(name):
            values=[e for e in events if e.get('event')==name]
            if len(values)!=1:raise ValueError('missing/duplicate test event')
            return values[0]
        halt=one('below_quorum_observation');four=one('four_validator_recovery_pass');final=one('LIVE_QUORUM_RECOVERY_PASS')
        if halt['before']!=halt['after'] or set(halt['before'])!={'2','3','4'}:return card
        tuples={(p['finalized_height'],p['finalized_block_id'],p['state_root']) for p in halt['before'].values()}
        if len(tuples)!=1 or next(iter(tuples))[0]!=4200:return card
        if four['height']<=4200 or set(four['pointers'])!={'2','3','4','5'}:return card
        gate=[e for e in events if e.get('event')=='matching_advancing_fleet' and e.get('label')=='all-five rejoin']
        if len(gate)!=1 or gate[0]['height']<=four['height']:return card
        if set(final['services'])!={'2','3','4','5','6'} or set(final['pointers'])!=set(final['services']):return card
        for n,service in final['services'].items():
            if int(service['NRestarts'])!=0 or int(service['MainPID'])<=0 or service['ActiveState']!='active' or service['SubState']!='running' or final['pointers'][n]['finalized_height']<gate[0]['height']:return card
        card.update(status='passed',updated_at=datetime.datetime.fromtimestamp(log.stat().st_mtime,datetime.timezone.utc).isoformat(),detail='Historical seq18 live test validated: three validators held matching H4200, four resumed finality, and all five rejoined with zero automatic retries. This completed test does not establish current sustained stability.')
    except (OSError,ValueError,KeyError,TypeError):pass
    return card


def validator_status(state, gap):
    service = state.get('service') or {}
    if not service:
        return 'unreachable', 'Validator observation unavailable'
    substate = service.get('SubState')
    if substate in {'auto-restart', 'auto-restart-queued', 'start', 'start-pre', 'start-post'}:
        return 'restarting', 'Validator service is starting or awaiting automatic restart'
    if substate != 'running':
        return 'offline', 'Validator service is not running'
    if not state.get('block'):
        return 'recovering', 'Finalized RPC observation unavailable'
    return ('syncing' if gap is not None and gap > 2 else 'active'), None


def live_canary_checks(network_id, genesis_hash, nodes, timestamp, states=None):
    if (network_id, genesis_hash) != ('posy-apqe-canary-process-49028',
            '2a770743814a98e61856efb85ebae1461dbac38a7b75ca65fb9f7ffe2e7011dc'):
        return []
    mesh = sum(node['status'] in {'active', 'syncing'} and node['peers'] == 4 for node in nodes)
    matching = {}
    for node in nodes:
        height, block, state = node['finalized_height'], node['finalized_block_id'], node['state_root']
        if type(height) is int and height > 0 and block and state:
            key = (height, block, state)
            matching[key] = matching.get(key, 0) + 1
    agreement = max((height for (height, _, _), count in matching.items() if count >= 4), default=None)
    def check(name, status, detail):
        return {'name': name, 'status': status, 'started_at': None, 'updated_at': timestamp, 'detail': detail}
    checks = [
        check('Canary authenticated validator mesh', 'passed' if mesh == 5 else 'observing',
              f'{mesh}/5 Canary validators currently report four authenticated APQE peers.'),
        check('Canary finalized block agreement', 'passed' if agreement is not None else 'observing',
              f'At least four validators independently report the same finalized block and state at height {agreement}.'
              if agreement is not None else 'Waiting for four validators to report matching commitments at the same height.'),
    ]
    if states is not None:
        registries=[state.get('registry_validity') for state in states.values()]
        valid=(len(registries)==5 and all(isinstance(r,dict) for r in registries)
               and all(r==registries[0] for r in registries))
        remaining=registries[0]['expires_at_unix']-datetime.datetime.fromisoformat(timestamp).timestamp() if valid else None
        status='blocked' if remaining is None or remaining<=0 else 'warning' if remaining<=7*86400 else 'passed'
        detail=('Active pinned registry observations are incomplete or disagree.' if remaining is None else
                f"Active generation {registries[0]['generation']} expires at "
                f"{datetime.datetime.fromtimestamp(registries[0]['expires_at_unix'],datetime.timezone.utc).isoformat()}; "
                f"{max(0,remaining/86400):.1f} days remain. Staged renewals do not extend the active registry.")
        checks.append(check('Live transport registry expiry alert',status,detail))
    return checks


def run(report=None, once=False, test_plan=None):
    ips = {}
    for n in range(2,7):
        config = subprocess.check_output(['ssh','-G',f'synergy-val{n}'],stderr=subprocess.DEVNULL,text=True)
        ips[n] = next(line.split(' ',1)[1] for line in config.splitlines() if line.startswith('hostname '))
    previous = None
    transaction_cursors = {}
    throughput_observations = {}
    throughput_histories = {}
    throughput_peaks = {}
    admission_observations = {}
    finality_observations = {}
    anchor_height=report.get("end_tip",{}).get("common_finalized_height") if report else None
    if type(anchor_height) is not int:anchor_height=None
    while True:
        with ThreadPoolExecutor(max_workers=5) as pool:
            states = dict(pool.map(read, [(n, transaction_cursors.get(n), anchor_height) for n in range(2,7)]))
        for n, state in states.items():
            cursor = state.pop('_transaction_cursor', None)
            if cursor is not None:
                transaction_cursors[n] = cursor
        for n, state in states.items():
            metrics, observation, history, peak = observe_throughput(state,
                throughput_observations.get(n), throughput_histories.get(n, []), throughput_peaks.get(n))
            admission_rates, admission_observation=observe_admission_rates(state,admission_observations.get(n))
            metrics.update(admission_rates)
            native=safe_native_telemetry(state)
            if native is not None:
                rates=native.get('tps') or {}
                for public,internal in [('accepted_tps','accepted_tps'),('etdag_ordered_tps','ordered_tps'),('executed_tps','executed_tps'),('finalized_tps','finalized_tps')]:
                    value=rates.get(internal)
                    metrics[public]=value if type(value) in {int,float} and math.isfinite(value) and value>=0 else None
                metrics['window_seconds']=rates.get('window_seconds')
                backlog=(native.get('admission') or {}).get('queued_requests')
                metrics['pending_transactions']=backlog if type(backlog) is int and backlog>=0 else None
                # Legacy ordered_total is not instrumented by processing-profile ETDAG.
                metrics['etdag_ordered_tps']=None
                metrics.pop('executed_tps',None)

            admission_observations[n]=admission_observation
            state['_throughput'] = metrics
            throughput_observations[n] = observation
            throughput_histories[n] = history
            throughput_peaks[n] = peak
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now.isoformat()
        try:network_id=active_network(states)
        except ValueError as error:
            print(json.dumps({"telemetry_unverified":str(error)}),flush=True);time.sleep(10);continue
        healthy = [(n,s) for n,s in states.items() if s['block']]
        tip_n, tip_state = max(healthy,key=lambda pair:pair[1]['height'],default=(None,None))
        height = tip_state['height'] if tip_state else None
        speed = None
        if previous and height is not None and height>previous[1]:
            speed = (now.timestamp()-previous[0])*1000/(height-previous[1])
        if height is not None and (not previous or height>previous[1]):
            previous = (now.timestamp(),height)
        nodes = []
        for n,s in states.items():
            gap = height-s['height'] if height is not None and s['block'] else None
            running = s['service'].get('SubState')=='running'
            status, status_error = validator_status(s, gap)
            b = s['block'] or {}
            stalled,finality_observations[n]=stalled_status(s,finality_observations.get(n),now.timestamp())
            if stalled:status='stalled'
            native=safe_native_telemetry(s)

            nodes.append({'id':f'val{n}','address':s.get('address'),'public_ip':ips[n],'vpn_ip':s.get('vpn_ip'),'status':status,'height':s['height'] if s['block'] else None,'finalized_height':s['height'] if s['block'] else None,'gap':gap,'peers':authenticated_peer_count(s),'updated_at':s.get('observed_at'),'error':status_error,'finalized_block_id':b.get('block_hash'),'state_root':b.get('state_root'),'service_pid':int(s['service'].get('MainPID',0)),'restarts':int(s['service'].get('NRestarts',0)),'release_id':s['release_id']})
        genesis_hash=next(iter(states.values())).get('genesis_hash')
        tests=live_canary_checks(network_id,genesis_hash,nodes,timestamp,states)
        if test_plan:
            plan=json.loads(test_plan.read_bytes())
            if (plan.get('network_id')!=network_id or plan.get('genesis_hash') not in {None, genesis_hash}
                    or not isinstance(plan.get('tests'),list) or len(tests)+len(plan['tests'])>64):
                raise ValueError('current test plan must match observed network')
            tests.extend(plan['tests'])
        if tip_state:
            accepted_rates=[state['_throughput'].get('accepted_tps') for state in states.values()]
            tip_state['_throughput']['accepted_tps']=sum(accepted_rates) if all(value is not None for value in accepted_rates) else None
        b=tip_state['block'] if tip_state else {}
        payload={'observed_at':timestamp,'chain':{'network_id':network_id,'genesis_hash':genesis_hash,'proposer':current_proposer(states),'height':height,'finalized_height':height,'block_time_ms':speed,'transactions':tip_state['transactions'] if tip_state else None,'wallets':tip_state['wallets'] if tip_state else None,'finalized_block_id':b.get('block_hash'),'state_root':b.get('state_root'),'verified_quorum':None,'throughput':tip_state['_throughput'] if tip_state else None,'load_test':baseline_status(report,states,network_id,now)},'validators':nodes,'tests':tests}
        data=json.dumps(payload).encode()
        try:
            owner.remote('synergy-index',MASTER_SOCKETS['synergy-index'],['python3','-c',PUBLISH],data)
        except (owner.ProvisionError, OSError) as error:
            # A disconnected existing master must not permanently kill live data.
            # Retry only via the same owner socket; never create a second connection.
            print(json.dumps({'telemetry_publish_failed':type(error).__name__}),flush=True)
            if once:raise
            time.sleep(10)
            continue
        print(json.dumps({'observed_at':timestamp,'height':height,'validator_heights':{f'val{n}':state['height'] for n,state in states.items()}}),flush=True)
        if once:return payload
        time.sleep(10)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master-socket',action='append',default=[],metavar='HOST=PATH',help='Existing owner SSH master; one per host')
    parser.add_argument('--test-plan',type=Path,help='Current network-bound qualification status; reread each observation')
    parser.add_argument('--once',action='store_true',help='Publish one observation and exit')
    parser.add_argument('--baseline-report',type=Path,help='Explicit canonical baseline JSON; no automatic discovery')
    args=parser.parse_args()
    for mapping in args.master_socket:
        host,separator,socket=mapping.partition('=')
        if not separator or host in MASTER_SOCKETS:parser.error('unique HOST=PATH master required')
        MASTER_SOCKETS[host]=socket
    if set(MASTER_SOCKETS)!={*[f'synergy-val{n}' for n in range(2,7)],'synergy-index'}:parser.error('explicit six existing owner masters required')
    report=None
    if args.baseline_report:
        path=args.baseline_report.resolve()
        if not path.is_relative_to(ROOT.resolve()) or args.baseline_report.is_symlink() or not path.is_file() or path.stat().st_size>16*1024*1024:
            parser.error('baseline report must be a bounded canonical regular file')
        report=json.loads(path.read_bytes())
    if args.test_plan and (args.test_plan.is_symlink() or not args.test_plan.is_file() or args.test_plan.stat().st_size>65536):parser.error('bounded regular current test plan required')
    run(report,args.once,args.test_plan)
