#!/usr/bin/env python3
"""Restricted NodeNetwork controller. No shell, renderer paths, or secret APIs.

Run only through a root-owned forced command/local privilege rule. The host
operator installs policy and exact one-shot grants; the frontend cannot approve
its own operations. This is a controller, never a network enrollment authority.
"""
import base64
import binascii
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode = True

ROOT = Path('/opt/synergy')
MAX_REQUEST = 16384
MAX_GENESIS_STAGE_REQUEST = 12*1024*1024
GENESIS_FILES = {'genesis.json':4*1024*1024,'authority.json':1024*1024,'authority-root.pub':8192}
ENGINE_MODULES = frozenset(('controller.py','synergy_linux.py','lifecycle.py','conformance.py',
                            'apqe_layout.py','vpn.py','canary_rpc_relay.py','root_guard.py','guest_lifecycle.py','vpn_authorization.py','treasury_send.py'))
READS = frozenset(('gateway_vpn_preflight','upgrade_native_preflight','gateway_install_preflight','gateway_install_status','gateway_target_preflight','gateway_target_status','gateway_target_export','gateway_target_reconcile','gateway_target_commission_preflight','gateway_admission_preflight','gateway_admission_status','gateway_admission_export','gateway_admission_reconcile','treasury_send_preflight','treasury_send_status','treasury_preflight','treasury_status','treasury_export','commissioning_observation','network_transport_status','network_transport_export','guest_resources','guest_preflight','guest_status','guest_boot_diagnostics','target','inventory','health','install_preflight','upgrade_preflight',
                  'recovery_preflight','uninstall_preflight','vpn_status','vpn_unused_preflight','vpn_stop_status','boot_policy_status','vpn_resume_status','vpn_diagnostics','diagnostics','identity_preflight','identity_status',
                  'formation_preflight','formation_status','formation_export','genesis_stage_preflight','genesis_binding_preflight','authorization_status','network_formation_status','network_formation_export'))
MUTATIONS = frozenset(('gateway_install','gateway_target_generate','gateway_target_commission','gateway_admission_prepare','gateway_admission_sign','treasury_send_prepare','treasury_send_submit','treasury_prepare','network_transport_prepare','network_transport_sign','guest_create','guest_stop','guest_resume','guest_remove','install','commission','register','vpn_enroll','vpn_bind','vpn_retire','vpn_cancel_unused','vpn_stop','vpn_resume','boot_policy','start','stop','restart','upgrade','uninstall','identity_generate',
                       'formation_prepare','genesis_stage','genesis_bind','network_formation_prepare','network_formation_sign'))
FORMATION_CONTEXT = 'tmp/formation-context.json'
FORMATION_CUSTODY = 'tmp/pre-genesis-validator'
FORMATION_INTENT = 'tmp/formation-prepare-request.json'
GENESIS_BIND_INTENT = 'tmp/genesis-bind-request.json'
IDENTITY_INTENT = 'tmp/existing-network-identity-request.json'
GENESIS_STAGE = 'tmp/identity-network'
GENESIS_STAGE_WORK = 'tmp/.identity-network-stage'
GENESIS_STAGE_RECEIPT = 'stage-request.json'
VPN_ENROLLMENT = 'vpn-enrollment.json'
VPN_ATTEMPT = 'evidence/vpn-enrollment-attempt.json'
HOST_ACCOUNT = 'synergy-nodenetwork'
HOST_REMOVAL = 'host-removal.json'
HOST_LINKS = {'sshd.conf':Path('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf'),
              'sudoers':Path('/etc/sudoers.d/synergy-nodenetwork')}
MAX_VPN_ENROLLMENT = 16384
LOG_WINDOW = 65536
LOG_LEVEL = re.compile(rb'^(?:\x1b\[[0-9;]*m)*\d{4}-\d\d-\d\dT[^ \t]{1,48}[ \t]+(?:\x1b\[[0-9;]*m)*[ \t]*(ERROR|WARN|INFO|DEBUG|TRACE)\b')
SELECT = frozenset(('release_id','manifest_sha256'))
INSTALL = SELECT | {'network_id','chain_id','node_name'}


class Refused(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def require(condition, message, code='operation_refused'):
    if not condition: raise Refused(code, message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def request_digest(request):
    encoded=(json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
             if request['operation'] in ('genesis_stage','network_formation_prepare','network_transport_prepare','treasury_send_prepare','gateway_admission_prepare','gateway_admission_preflight','gateway_target_commission','gateway_target_commission_preflight') else canonical(request))
    return hashlib.sha256(encoded).hexdigest()


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def genesis_artifact_bytes(artifacts):
    require(isinstance(artifacts,dict) and set(artifacts)==set(GENESIS_FILES)
            and all(isinstance(value,str) for value in artifacts.values()),
            'Exact signed public artifacts required','invalid_request')
    root='authority-root.pub'
    try:
        require(len(artifacts[root])<=10924,'Public authority key exceeds its byte bound','invalid_request')
        decoded=base64.b64decode(artifacts[root],validate=True)
        require(base64.b64encode(decoded).decode('ascii')==artifacts[root],
                'Public authority key base64 is not canonical','invalid_request')
        raw={name:(decoded if name==root else artifacts[name].encode('utf-8')) for name in GENESIS_FILES}
    except (UnicodeError,binascii.Error,ValueError) as exc:
        if isinstance(exc,Refused):raise
        raise Refused('invalid_request','Invalid public artifact encoding') from None
    require(all(0<len(raw[name])<=limit for name,limit in GENESIS_FILES.items()),
            'Public artifact exceeds its byte bound','invalid_request')
    return raw


def exact_count(value):
    if type(value) is str and len(value)<=16 and value.isascii() and value.isdecimal():
        value=int(value)
    return value if type(value) is int and 0<=value<=2**53-1 else None


def log_summary(root):
    path=root/'logs/node.log'
    result={'available':False,'size_bytes':None,'window_bytes':0,'complete_lines':0,
            'severity':dict.fromkeys(('error','warn','info','debug','trace','unclassified'),0)}
    directory=path.parent
    if not directory.exists() and not directory.is_symlink(): return result
    metadata=directory.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.geteuid()
            and not metadata.st_mode&0o022,'Unsafe node log directory')
    try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError: return result
    with os.fdopen(fd,'rb') as stream:
        metadata=os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1
                and metadata.st_uid==os.geteuid() and not metadata.st_mode&0o022,'Unsafe node log file')
        offset=max(0,metadata.st_size-LOG_WINDOW)
        stream.seek(offset)
        data=stream.read(min(metadata.st_size,LOG_WINDOW))
    lines=data.split(b'\n')[:-1]
    if offset: lines=lines[1:]
    for line in lines:
        match=LOG_LEVEL.match(line)
        level=match[1].decode('ascii').lower() if match else 'unclassified'
        result['severity'][level]+=1
    result.update(available=True,size_bytes=exact_count(metadata.st_size),
                  window_bytes=len(data),complete_lines=len(lines))
    return result


def parse_request(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_GENESIS_STAGE_REQUEST, 'Request exceeds limit', 'invalid_request')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON field', 'invalid_request')
            result[key] = value
        return result
    try: value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError): raise Refused('invalid_request', 'Invalid request JSON')
    require(isinstance(value, dict) and set(value) == {'version','operation','parameters'}
            and type(value['version']) is int and value['version'] == 1,
            'Unsupported controller request', 'invalid_request')
    operation, parameters = value['operation'], value['parameters']
    require(isinstance(operation,str) and operation in READS | MUTATIONS
            and isinstance(parameters,dict), 'Unsupported operation', 'invalid_request')
    require(operation=='genesis_stage' or operation in ('network_formation_prepare','network_transport_prepare','treasury_send_prepare','gateway_admission_prepare','gateway_admission_preflight','gateway_target_commission','gateway_target_commission_preflight') and len(raw)<=2*1024*1024 or len(raw)<=MAX_REQUEST,'Request exceeds operation limit','invalid_request')
    if operation=='commissioning_observation' and parameters:
        require(set(parameters)=={'online_addresses'} and isinstance(parameters['online_addresses'],list)
                and len(parameters['online_addresses'])<=5
                and all(isinstance(a,str) and 1<=len(a)<=128 for a in parameters['online_addresses'])
                and parameters['online_addresses']==sorted(set(parameters['online_addresses'])),
                'Exact online commissioning subset required','invalid_request')
        return value
    if operation=='boot_policy':
        require(set(parameters)=={'service','enabled'} and parameters['service'] in ('node','vpn')
                and type(parameters['enabled']) is bool,'Exact service boot policy required','invalid_request')
        return value
    if operation in ('vpn_enroll','vpn_cancel_unused'):
        require(set(parameters) in ((set(),{'attempt_sha256'}) if operation=='vpn_enroll' else ({'attempt_sha256'},))
                and ('attempt_sha256' not in parameters or isinstance(parameters['attempt_sha256'],str)
                     and re.fullmatch('[a-f0-9]{64}',parameters['attempt_sha256'])),
                'Exact native VPN attempt parameters required','invalid_request')
        return value
    if operation=='gateway_vpn_preflight':
        from canary_rpc_relay import gateway_vpn_parameters
        try:gateway_vpn_parameters(parameters)
        except (ValueError,KeyError,TypeError):raise Refused('invalid_request','Exact signed gateway TCP target required') from None
        return value
    if operation.startswith('gateway_target_'):
        from canary_rpc_relay import gateway_target_parameters
        try:gateway_target_parameters(operation,parameters)
        except (ValueError,KeyError,TypeError):raise Refused('invalid_request','Invalid exact gateway target request') from None
        return value
    if operation=='gateway_install_status':
        require(set(parameters)=={'request_sha256'} and isinstance(parameters['request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',parameters['request_sha256']),'Exact original gateway installation digest required','invalid_request')
        return value
    if operation.startswith('gateway_admission_'):
        from canary_rpc_relay import gateway_parameters
        try:gateway_parameters(operation,parameters)
        except (ValueError,KeyError,TypeError):raise Refused('invalid_request','Invalid exact gateway admission request') from None
        return value
    if operation.startswith('treasury_send_'):
        from treasury_send import validate
        try:validate(operation,parameters)
        except (ValueError,KeyError,TypeError):raise Refused('invalid_request','Invalid exact treasury send request')
        return value
    if operation.startswith('treasury_'):
        require(set(parameters)==({'formation_sha256','effective_at_unix'} if operation=='treasury_prepare' else set()),'Exact treasury parameters required','invalid_request')
        if operation=='treasury_prepare':
            require(isinstance(parameters['formation_sha256'],str) and re.fullmatch('[a-f0-9]{64}',parameters['formation_sha256'])
                    and type(parameters['effective_at_unix']) is int and 0<parameters['effective_at_unix']<2**63,
                    'Exact treasury formation and effective time required','invalid_request')
        return value
    if operation.startswith('network_transport_'):
        transport_parameters(operation,parameters)
        return value
    if operation=='guest_resources':
        require(not parameters,'Guest resources read is parameterless','invalid_request')
        return value
    if operation.startswith('guest_'):
        from guest_lifecycle import validate_parameters
        try: validate_parameters(operation, parameters)
        except (ValueError, KeyError, TypeError):
            raise Refused('invalid_request', 'Invalid bounded guest parameters') from None
        return value
    expected = INSTALL if operation in ('install','install_preflight','gateway_install','gateway_install_preflight') else SELECT if operation in ('upgrade','upgrade_preflight','upgrade_native_preflight') else {'confirmation'} if operation == 'uninstall' else {'genesis_sha256'} if operation in ('identity_generate','genesis_bind') else {'formation_sha256'} if operation=='formation_prepare' else {'artifacts'} if operation=='genesis_stage' else {'formation_sha256','recipe_json','registrations_json'} if operation=='network_formation_prepare' else {'review_sha256'} if operation=='network_formation_sign' else set()
    require(set(parameters) == expected, 'Unexpected operation parameters', 'invalid_request')
    if operation=='network_formation_prepare':
        require(isinstance(parameters['recipe_json'],str) and 0<len(parameters['recipe_json'].encode('utf-8'))<=1024*1024
                and isinstance(parameters['registrations_json'],list) and len(parameters['registrations_json'])==5
                and all(isinstance(v,str) and 0<len(v.encode('utf-8'))<=128*1024 for v in parameters['registrations_json']),
                'Bounded recipe and five public registrations required','invalid_request')
    if operation=='genesis_stage':
        genesis_artifact_bytes(parameters['artifacts'])
    if expected & SELECT:
        require(isinstance(parameters['release_id'],str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}',parameters['release_id'])
                and isinstance(parameters['manifest_sha256'],str) and re.fullmatch(r'[a-f0-9]{64}',parameters['manifest_sha256']),
                'Invalid release selection','invalid_request')
    if expected == INSTALL:
        require(type(parameters['chain_id']) is int and 0 < parameters['chain_id'] < 2**64
                and isinstance(parameters['network_id'],str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,127}',parameters['network_id'])
                and isinstance(parameters['node_name'],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',parameters['node_name']),
                'Invalid network or node selection','invalid_request')
    if operation == 'uninstall': require(parameters['confirmation'] == str(ROOT),'Exact root confirmation required','invalid_request')
    for name in expected & {'genesis_sha256','formation_sha256','review_sha256'}:
        pin=parameters[name]
        require(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin),'Exact public artifact SHA-256 required','invalid_request')
    return value


def transport_parameters(operation,p):
    fields={'formation_sha256','genesis_review_sha256','target_provider_report_sha256','valid_from_unix','expires_at_unix','members'}
    require(set(p)==(fields if operation=='network_transport_prepare' else {'review_sha256'} if operation=='network_transport_sign' else set()),
            'Exact transport parameters required','invalid_request')
    for key in set(p)&{'formation_sha256','genesis_review_sha256','target_provider_report_sha256','review_sha256'}:
        require(isinstance(p[key],str) and re.fullmatch('[a-f0-9]{64}',p[key]),'Exact transport pin required','invalid_request')
    if operation!='network_transport_prepare':return
    require(all(type(p[k]) is int and 0<=p[k]<2**53 for k in ('valid_from_unix','expires_at_unix'))
            and 0<p['expires_at_unix']-p['valid_from_unix']<=7*86400,'Bounded transport validity required','invalid_request')
    require(isinstance(p['members'],list) and len(p['members'])==5,'Five public enrollments required','invalid_request')
    for m in p['members']:
        require(isinstance(m,dict) and set(m)=={'enrollment_json','configuration_json','dial_address','transport_key_id'},'Exact public member fields required','invalid_request')
        for key,limit in (('enrollment_json',128*1024),('configuration_json',64*1024)):
            require(isinstance(m[key],str) and 0<len(m[key].encode('utf-8'))<=limit,'Bounded public member required','invalid_request')
        require(isinstance(m['transport_key_id'],str) and 0<len(m['transport_key_id'])<=128
                and all(0x21<=ord(c)<=0x7e for c in m['transport_key_id']),'ASCII transport key identifier required','invalid_request')
        value=m['dial_address']
        require(isinstance(value,str) and len(value)<=128,'Literal isolated socket required','invalid_request')
        try:
            match=re.fullmatch(r'\[([0-9a-fA-F:]+)\]:([0-9]{1,5})|([0-9.]+):([0-9]{1,5})',value)
            require(match is not None,'Literal isolated socket required','invalid_request')
            address=ipaddress.ip_address(match[1] or match[3]);port=int(match[2] or match[4])
            ranges=('127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10','::1/128','fc00::/7')
            require(0<port<=65535 and any(address in ipaddress.ip_network(n) for n in ranges),
                    'Literal isolated socket required','invalid_request')
        except ValueError:raise Refused('invalid_request','Literal isolated socket required') from None


def validate_transport_export(value,review,source):
    files={'network/genesis.json','network/authority.json','network/authority-root.pub','network/network-manifest.json',
           'network/transport-registry.json','network/transport-root.pub','config/node.json','config/start-authorized.json'}
    require(isinstance(value,dict) and set(value)=={'schema','review_sha256','registry_sha256','issuer_root_sha256','fleet_readiness_verified','nodes'}
            and value['schema']=='nodenetwork-network-transport-export-v1' and value['fleet_readiness_verified'] is False
            and all(value[k]==review[k] for k in ('review_sha256','registry_sha256','issuer_root_sha256'))
            and isinstance(value['nodes'],list) and len(value['nodes'])==5,'Exact reviewed public transport export required')
    require(len(json.dumps(value,separators=(',',':'),ensure_ascii=False).encode('utf-8'))<=4*1024*1024,'Public transport export exceeds bound')
    seen=set();shared=None
    pins={'network/genesis.json':source['genesis_sha256'],'network/authority.json':source['authority_sha256'],
          'network/authority-root.pub':source['authority_root_sha256'],'network/transport-registry.json':review['registry_sha256'],
          'network/transport-root.pub':review['issuer_root_sha256']}
    for node in value['nodes']:
        require(isinstance(node,dict) and set(node)=={'address','artifacts'} and isinstance(node['address'],str)
                and node['address'] in review['validator_addresses'] and node['address'] not in seen
                and isinstance(node['artifacts'],dict) and set(node['artifacts'])==files,'Exact public member export required')
        seen.add(node['address']);artifacts=node['artifacts']
        for name,text in artifacts.items():
            require(isinstance(text,str) and 0<len(text.encode('utf-8'))<=1024*1024,'Bounded public artifact required')
            if name.endswith('.pub'):
                try:raw=base64.b64decode(text,validate=True)
                except (ValueError,binascii.Error):raise Refused('operation_refused','Invalid public root encoding') from None
                require(base64.b64encode(raw).decode()==text and len(raw)==(2592 if name.endswith('transport-root.pub') else 1952),'Exact APQE public root required')
            else:raw=text.encode('utf-8')
            if name in pins:require(hashlib.sha256(raw).hexdigest()==pins[name],'Public transport artifact digest differs')
        network={k:v for k,v in artifacts.items() if k.startswith('network/')}
        require(shared is None or shared==network,'Shared signed network artifacts differ')
        shared=network
        start=json.loads(artifacts['config/start-authorized.json'])
        require(isinstance(start,dict) and start.get('production_approved') is False and start.get('all_validators_ready') is False
                and start.get('all_pairs_vpn_verified') is False and set(start.get('validator_addresses',[]))==set(review['validator_addresses']),
                'Export must not claim fleet readiness or production admission')
    require(seen==set(review['validator_addresses']),'Public transport export roster differs')


def engineering_effective_selection(root, policy):
    """Resolve only a sealed installation reached through native-reviewed adoption.

    The immutable initial selection is never replaced by renderer parameters.
    Staging a candidate does not imply that the validator has been upgraded.
    """
    origin=policy.get('engineering_selection')
    if origin is None:return None
    selected=dict(origin)
    update=policy.get('engineering_update')
    if update is not None:
        require(isinstance(update,dict) and update.get('initial_sha256')==policy.get('engineering_initial_authorization_sha256')
                and update.get('formation_sha256')==policy.get('validator_formation_sha256'), 'Update origin differs')
        for value in (update.get('previous_selection'),update.get('selection')):
            require(isinstance(value,dict) and set(value)==set(origin)
                    and all(value.get(k)==origin.get(k) for k in ('network_id','chain_id','node_name')),
                    'Update changes the initial network')
            approved=policy.get('releases',{}).get(value['release_id'],{})
            require(approved.get('manifest_sha256')==value['manifest_sha256']
                    and approved.get('inventory_authenticated') is True
                    and approved.get('networks',{}).get(value['network_id'])==value['chain_id'], 'Update inventory is unapproved')
        from lifecycle import _sealed_receipt
        receipt,manifest=_sealed_receipt(root)
        matches=[value for value in (update['previous_selection'],update['selection'])
                 if value['manifest_sha256']==receipt.get('package_sha256') and value['release_id']==manifest.get('release_id')
                 and all(value[k]==receipt.get(k) for k in ('network_id','chain_id','node_name'))]
        require(len(matches)==1,'Installed release has no exact native adoption lineage')
        selected=dict(matches[0])
    return selected


class Controller:
    def __init__(self, root=ROOT):
        self.root = Path(root)
        self.control = self.root/'tmp/controller'

    def direct(self, path, private=False, maximum=1024*1024):
        path = Path(path)
        require(path.is_absolute() and path.resolve() == path and self.root in (path,*path.parents), 'Path escapes installation')
        for entry in (path,*path.parents):
            st = entry.lstat()
            require(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,os.geteuid())
                    and (not st.st_mode & 0o022 or entry == Path('/tmp') and st.st_mode & stat.S_ISVTX
                         or entry == Path('/private/tmp') and st.st_mode & stat.S_ISVTX), 'Unsafe controller ownership or path')
        st=path.stat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_nlink == 1 and st.st_size <= maximum, 'Unsafe controller file')
        if private: require(stat.S_IMODE(st.st_mode)==0o600,'Controller policy and grants must be private')
        return path

    def public_json(self, path, private=False):
        return json.loads(self.direct(path,private).read_bytes())

    def policy(self):
        path=self.control/'policy.json'
        require(path.exists(),'Host controller policy is not enrolled','qualification_required')
        value=self.public_json(path,True)
        require(value.get('format')=='synergy-nodenetwork-host-policy-v1' and value.get('root')==str(self.root)
                and value.get('community_enrollment') is False and isinstance(value.get('qualified_operations'),list)
                and set(value['qualified_operations']) <= MUTATIONS | READS and isinstance(value.get('releases'),dict),
                'Invalid host controller policy','qualification_required')
        return value

    def approved_package(self, parameters, bootstrap=False):
        from synergy_linux import digest, verify_package
        policy=self.policy()
        selected=policy['releases'].get(parameters['release_id'])
        require(isinstance(selected,dict) and selected.get('manifest_sha256')==parameters['manifest_sha256']
                and selected.get('inventory_authenticated') is True,
                'Release has no authenticated host approval','qualification_required')
        package=self.root/('tmp/bootstrap-master' if bootstrap else 'tmp/update-master')
        self.direct(package/'package.json')
        require(digest(package/'package.json')==parameters['manifest_sha256'],'Selected package digest differs')
        manifest=verify_package(package)
        require(manifest.get('release_id')==parameters['release_id'],'Selected release identity differs')
        return package,manifest,selected

    def audit(self, request):
        path=self.control/'audit.jsonl'
        if path.exists(): self.direct(path,True)
        record=canonical({'request_sha256':request_digest(request),
                          'operation':request['operation'],'time':int(time.time())})+b'\n'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
        try: os.write(fd,record);os.fsync(fd)
        finally: os.close(fd)

    def authorize(self, request, enrollment_pin=None, *, consume=True):
        require(request['operation']=='uninstall' or not (self.control/HOST_REMOVAL).exists(),
                'Host retirement is in progress; finish removal before other changes')
        policy=self.policy()
        require(request['operation'] in policy['qualified_operations'], 'Operation has not passed host qualification','qualification_required')
        key=request_digest(request)
        grant_path=self.control/'grants'/(key+'.json')
        require(grant_path.exists(),'Exact request needs one-time host operator authorization','authorization_required')
        grant=self.public_json(grant_path,True)
        require(grant.get('request_sha256')==key and grant.get('root')==str(self.root)
                and type(grant.get('expires_at')) is int and time.time()<grant['expires_at']<=time.time()+3600,
                'Host authorization expired or differs','authorization_required')
        if policy.get('engineering_authorization') is not None:
            require(grant.get('operation')==request['operation'] and grant.get('authorization_sha256')==policy['engineering_authorization']['sha256']
                    and grant.get('authorization_sequence')==policy['engineering_authorization']['sequence'],'Exact engineering grant operation or receipt differs','authorization_required')
            if request['operation'] in ('install','gateway_install','upgrade'):
                selected=policy.get('engineering_selection',{})
                if request['operation']=='upgrade':
                    current=engineering_effective_selection(self.root,policy)
                    update=policy.get('engineering_update',{})
                    require(update.get('previous_selection')==current,'Upgrade requires its exact not-yet-installed native adoption','authorization_required')
                    selected=update.get('selection',{})
                expected=INSTALL if request['operation'] in ('install','gateway_install') else SELECT
                require(request['parameters']=={key:selected.get(key) for key in expected},'Engineering installation selection differs','authorization_required')
        if request['operation']=='vpn_enroll':
            require(enrollment_pin is not None and grant.get('enrollment_sha256')==enrollment_pin,
                    'One-time host grant does not bind this VPN enrollment','authorization_required')
        if request['operation'] in ('vpn_bind','vpn_retire','vpn_cancel_unused'):
            require(enrollment_pin is not None and grant.get('binding_sha256')==enrollment_pin,
                    'Exact native-verified VPN server binding required','authorization_required')
        if not consume:
            return key
        # Consume before executing. Ambiguous outcomes need observation and a
        # fresh operator grant, never blind resubmission or replay.
        self.audit(request)
        grant_path.unlink()
        return key

    def authorize_guest_resume(self,request,pin):
        from synergy_linux import digest
        from guest_lifecycle import GuestManager,validate_parameters
        require(request['operation']=='guest_resume','Only an exact guest resume may reconcile authorization')
        validate_parameters('guest_resume',request['parameters'])
        key=request_digest(request);grant=self.control/'grants'/(key+'.json')
        record=GuestManager(self.root,self.policy()).receipt();pending=record.get('resume',{})
        require(pending.get('request_sha256')==key and pending.get('grant_sha256')==pin and pending.get('phase')=='prepared'
                and record['request_sha256']==request['parameters']['create_request_sha256'] and pending['sequence']==request['parameters']['resume_sequence'],'Guest authorization intent differs')
        if grant.exists() or grant.is_symlink():require(digest(self.direct(grant,True))==pin,'Original guest grant changed')
        audit=self.control/'audit.jsonl';matches=[]
        if audit.exists():
            audit=self.direct(audit,True);require(audit.stat().st_size<=1024*1024,'Guest audit exceeds bound')
            rows=audit.read_bytes().splitlines();require(len(rows)<=4096,'Guest audit exceeds bound')
            matches=[json.loads(row) for row in rows if json.loads(row).get('request_sha256')==key]
        require(len(matches)<=1,'Ambiguous guest authorization audit')
        if not matches:return self.authorize(request)
        require(set(matches[0])=={'request_sha256','operation','time'} and matches[0]['operation']=='guest_resume'
                and type(matches[0]['time']) is int and 0<=matches[0]['time']<=int(time.time()),'Guest audit differs')
        if grant.exists() or grant.is_symlink():
            require(digest(self.direct(grant,True))==pin,'Original guest grant changed');grant.unlink()

    def vpn_stage(self):
        path=self.control/VPN_ENROLLMENT
        if not path.exists() and not path.is_symlink(): return None
        path=self.direct(path,True)
        require(0<path.stat().st_size<=MAX_VPN_ENROLLMENT,'VPN enrollment input exceeds bound')
        return path

    def identity_preflight(self):
        pending=self.root/'tmp/pending-validator-custody'
        keys=self.root/'keys'
        require(keys.is_dir() and not keys.is_symlink(),'Canonical private keys directory required')
        require(not (self.root/'data').exists() and not (self.root/'data').is_symlink()
                and not pending.exists() and not pending.is_symlink() and not list(keys.iterdir())
                and not self.exists(FORMATION_CUSTODY) and not self.exists(FORMATION_INTENT)
                and not self.exists(IDENTITY_INTENT),
                'Existing custody, incomplete generation or node data must be reconciled before identity provisioning')
        return self.identity_network()

    def exists(self,relative):
        path=self.root/relative
        return path.exists() or path.is_symlink()

    def formation_context_path(self):
        if 'formation-context.json' in self.policy().get('authorization_files',{}):
            return self.control/'authorization/inputs/formation-context.json'
        return self.root/FORMATION_CONTEXT

    def formation_context(self):
        from lifecycle import _sealed_receipt
        receipt,manifest=_sealed_receipt(self.root)
        require(receipt['role']=='validator','A validator package is required')
        self.direct(self.root/'installation.json',True)
        pin=self.policy().get('validator_formation_sha256')
        require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),
                'Host operator has not pinned a formation context','authorization_required')
        path=self.direct(self.formation_context_path(),True)
        with path.open('rb') as stream:raw=stream.read(4097)
        require(0<len(raw)<=4096 and hashlib.sha256(raw).hexdigest()==pin,
                'Independently approved formation context changed')
        value=json.loads(raw)
        require(isinstance(value,dict) and set(value)=={'network_id','chain_id_hex','formation_id'}
                and value['network_id']==receipt['network_id']
                and value['chain_id_hex']==format(receipt['chain_id'],'064x')
                and isinstance(value['formation_id'],str) and re.fullmatch('[a-f0-9]{64}',value['formation_id'])
                and value['formation_id']!='0'*64,'Formation context differs from installation selection')
        report='lib/apqe/build-report.json'
        flags=['--apqe-report',self.root/report,'--apqe-report-sha256',manifest['files'][report]]
        return {'schema':'nodenetwork-formation-v1','formation_sha256':pin,'network_id':receipt['network_id'],
                'chain_id':str(receipt['chain_id']),'formation_id':value['formation_id']},flags

    def treasury(self,request):
        from lifecycle import _lifecycle_lock, _unit_state, _assert_no_application_processes
        from synergy_linux import native
        op=request['operation'];directory=self.root/'keys/formation-treasury'
        intent=self.root/'tmp/treasury-prepare-request.json'
        with _lifecycle_lock(self.root):
            selection,flags=self.formation_context()
            present=any(path.exists() or path.is_symlink() for path in (directory,intent))
            if op=='treasury_status' and not present:return {'pending':False}
            if op=='treasury_preflight':
                require(not present,'Existing treasury must be reconciled; no regeneration','reconciliation_required')
                return {'schema':'nodenetwork-formation-treasury-preflight-v1',
                    **{key:selection[key] for key in ('formation_sha256','network_id','chain_id')},
                    'effective_at_unix':int(time.time())}
            if op=='treasury_prepare':
                require(not present,'Existing treasury must be reconciled; no regeneration','reconciliation_required')
                require(request['parameters']['formation_sha256']==selection['formation_sha256'],'Treasury formation changed')
                require(abs(time.time()-request['parameters']['effective_at_unix'])<=300,'Treasury preparation review expired')
                require(not any(self.exists(path) for path in ('data','tmp/network-formation')),
                        'Prepare treasury before Genesis formation or runtime initialization')
                state=_unit_state('synergy-node.service')
                require((state.get('ActiveState') in ('inactive','failed') or state.get('LoadState')=='not-found') and int(state.get('MainPID',0) or 0)==0,
                        'Stop the node before treasury preparation')
                _assert_no_application_processes(self.root,vpn_pid=_unit_state('synergy-vpn.service').get('MainPID'))
                self.authorize(request)
                raw=canonical(request)
                fd=os.open(intent,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                sync_directory(intent.parent)
                command='prepare-formation-treasury';args=[intent,request_digest(request),directory]
            else:
                self.direct(intent,True)
                command='export-formation-treasury' if op=='treasury_export' else 'review-formation-treasury'
                args=[directory]
            result=json.loads(native([self.root/'bin/synergy-keytool',command,self.formation_context_path(),selection['formation_sha256'],*args,*flags],maximum_stdout=128*1024))
            prepared=parse_request(self.direct(intent,True).read_bytes())
            require(prepared['operation']=='treasury_prepare' and prepared['parameters']['formation_sha256']==selection['formation_sha256']
                    and result.get('request_sha256')==request_digest(prepared)
                    and result.get('effective_at_unix')==prepared['parameters']['effective_at_unix']
                    and all(result.get(key)==selection[key] for key in ('network_id','chain_id','formation_sha256'))
                    and result.get('schema')==('nodenetwork-formation-treasury-export-v1' if op=='treasury_export' else 'nodenetwork-formation-treasury-v1')
                    and result.get('pending') is True and result.get('possession_verified') is True
                    and result.get('allocation_nwei')=='5000000000000000'
                    and isinstance(result.get('address'),str) and result['address'].startswith('syna'),
                    'Native treasury scope, request or custody differs')
            return result

    def network_formation(self,request):
        from lifecycle import _lifecycle_lock, _unit_state, _assert_no_application_processes
        from synergy_linux import native
        op=request['operation']
        directory=self.root/'tmp/network-formation'
        prepare=self.root/'tmp/network-formation-prepare-request.json'
        signing=self.root/'tmp/network-formation-sign-request.json'
        with _lifecycle_lock(self.root):
            selection,flags=self.formation_context()
            if op=='network_formation_status' and not any(p.exists() or p.is_symlink() for p in (directory,prepare,signing)):
                return {'pending':False}
            if op in ('network_formation_prepare','network_formation_sign'):
                state=_unit_state('synergy-node.service')
                require((state.get('ActiveState') in ('inactive','failed') or state.get('LoadState')=='not-found') and int(state.get('MainPID',0) or 0)==0,
                        'Stop the node before creating or signing a fresh network')
                _assert_no_application_processes(self.root,vpn_pid=_unit_state('synergy-vpn.service').get('MainPID'))
                if op=='network_formation_prepare':
                    require(request['parameters']['formation_sha256']==selection['formation_sha256'],'Reviewed formation changed')
                    require(not any(p.exists() or p.is_symlink() for p in (directory,prepare,signing)),
                            'Existing network formation must be reconciled; no regeneration','reconciliation_required')
                    path=prepare
                else:
                    self.direct(prepare,True,2*1024*1024)
                    require(directory.is_dir() and not directory.is_symlink(),'No prepared network formation')
                    require(not signing.exists() and not signing.is_symlink(),'Signing already dispatched; read network formation status','reconciliation_required')
                    current=json.loads(native([self.root/'bin/synergy-keytool','review-network-formation',self.formation_context_path(),selection['formation_sha256'],directory,*flags]))
                    require(current.get('signed') is False and current.get('review_sha256')==request['parameters']['review_sha256'],
                            'Exact unsigned Genesis review changed')
                    path=signing
                self.authorize(request)
                raw=json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
                # Exclusive durable request: never regenerate custody or repeat a signature after an uncertain result.
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                sync_directory(path.parent)
                command='prepare-network-formation' if op=='network_formation_prepare' else 'sign-network-formation'
                args=([path,request_digest(request),directory] if op=='network_formation_prepare' else [directory,path,request_digest(request)])
            else:
                self.direct(prepare,True,2*1024*1024)
                command='export-network-formation' if op=='network_formation_export' else 'review-network-formation'
                args=[directory]
            argv=[self.root/'bin/synergy-keytool',command,self.formation_context_path(),selection['formation_sha256'],*args,*flags]
            raw=native(argv,maximum_stdout=2*1024*1024 if op=='network_formation_export' else 1024*1024)
            result=json.loads(raw)
            if op=='network_formation_export':
                require(result.get('schema')=='nodenetwork-network-formation-export-v1','Unsupported signed network export')
                artifacts=genesis_artifact_bytes(result.get('artifacts'))
                require(all(hashlib.sha256(artifacts[name]).hexdigest()==result.get(field) for name,field in
                            (('genesis.json','genesis_sha256'),('authority.json','authority_sha256'),('authority-root.pub','authority_root_sha256'))),
                        'Signed public artifact bytes differ')
                return result
            require(result.get('schema')=='nodenetwork-network-formation-v1' and result.get('pending') is True
                    and type(result.get('signed')) is bool and result.get('formation_sha256')==selection['formation_sha256']
                    and result.get('network_id')==selection['network_id'] and result.get('chain_id')==selection['chain_id'],
                    'Native network formation scope differs')
            prepare_request=parse_request(self.direct(prepare,True,2*1024*1024).read_bytes())
            require(prepare_request['operation']=='network_formation_prepare' and result.get('request_sha256')==request_digest(prepare_request),
                    'Native formation request evidence differs')
            if result['signed']:
                sign_request=parse_request(self.direct(signing,True).read_bytes())
                require(sign_request['operation']=='network_formation_sign' and result.get('sign_request_sha256')==request_digest(sign_request)
                        and sign_request['parameters']['review_sha256']==result.get('review_sha256'),'Native signing evidence differs')
            return result

    def network_transport(self,request):
        from lifecycle import _lifecycle_lock, _unit_state, _assert_no_application_processes
        from synergy_linux import native
        op=request['operation'];p=request['parameters']
        directory=self.root/'tmp/network-transport'
        prepare=self.root/'tmp/network-transport-prepare-request.json'
        signing=self.root/'tmp/network-transport-sign-request.json'
        formation=self.root/'tmp/network-formation'
        with _lifecycle_lock(self.root):
            selection,flags=self.formation_context()
            source=json.loads(native([self.root/'bin/synergy-keytool','review-network-formation',self.formation_context_path(),selection['formation_sha256'],formation,*flags]))
            require(source.get('schema')=='nodenetwork-network-formation-v1' and source.get('signed') is True
                    and source.get('formation_sha256')==selection['formation_sha256']
                    and source.get('network_id')==selection['network_id'] and source.get('chain_id')==selection['chain_id'],
                    'Verified signed Genesis formation required')
            if op=='network_transport_status' and not any(path.exists() or path.is_symlink() for path in (directory,prepare,signing)):
                return {'schema':'nodenetwork-network-transport-v1','pending':False,'formation_sha256':selection['formation_sha256'],
                        'genesis_review_sha256':source['review_sha256'],'target_provider_report_sha256':flags[-1],
                        'network_id':selection['network_id'],'chain_id':selection['chain_id']}
            if op in ('network_transport_prepare','network_transport_sign'):
                state=_unit_state('synergy-node.service')
                require((state.get('ActiveState') in ('inactive','failed') or state.get('LoadState')=='not-found')
                        and int(state.get('MainPID',0) or 0)==0,'Stop the node before transport issuance')
                _assert_no_application_processes(self.root,vpn_pid=_unit_state('synergy-vpn.service').get('MainPID'))
                if op=='network_transport_prepare':
                    require(p['formation_sha256']==selection['formation_sha256'] and p['genesis_review_sha256']==source['review_sha256']
                            and p['target_provider_report_sha256']==flags[-1],'Exact signed Genesis and installed provider required')
                    require(not any(path.exists() or path.is_symlink() for path in (directory,prepare,signing)),
                            'Existing transport issuance must be reconciled; no regeneration','reconciliation_required')
                    path=prepare
                else:
                    self.direct(prepare,True,2*1024*1024)
                    require(directory.is_dir() and not directory.is_symlink(),'No prepared transport issuance')
                    require(not signing.exists() and not signing.is_symlink(),'Signing already dispatched; read status','reconciliation_required')
                    current=json.loads(native([self.root/'bin/synergy-keytool','review-network-transport',self.formation_context_path(),selection['formation_sha256'],formation,directory,*flags]))
                    self.transport_receipt(current,selection,source,prepare,signing,check_sign=False)
                    require(current.get('signed') is False and current.get('review_sha256')==p['review_sha256'],'Exact unsigned transport review changed')
                    path=signing
                self.authorize(request)
                raw=json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                sync_directory(path.parent)
                command='prepare-network-transport' if op=='network_transport_prepare' else 'sign-network-transport'
                args=[path,request_digest(request),directory] if op=='network_transport_prepare' else [directory,path,request_digest(request)]
            else:
                self.direct(prepare,True,2*1024*1024)
                command='export-network-transport' if op=='network_transport_export' else 'review-network-transport'
                args=[directory]
            result=json.loads(native([self.root/'bin/synergy-keytool',command,self.formation_context_path(),selection['formation_sha256'],formation,*args,*flags],
                                     maximum_stdout=4*1024*1024+1 if op=='network_transport_export' else 1024*1024))
            if op=='network_transport_export':
                # Reverify the durable review/sign requests before releasing public files.
                checked=json.loads(native([self.root/'bin/synergy-keytool','review-network-transport',self.formation_context_path(),selection['formation_sha256'],formation,directory,*flags]))
                self.transport_receipt(checked,selection,source,prepare,signing)
                require(checked.get('signed') is True,'Reviewed transport signature required')
                validate_transport_export(result,checked,source)
                return result
            self.transport_receipt(result,selection,source,prepare,signing)
            return result

    def transport_receipt(self,result,selection,source,prepare,signing,check_sign=True):
        require(isinstance(result,dict) and result.get('schema')=='nodenetwork-network-transport-v1' and result.get('pending') is True
                and type(result.get('signed')) is bool and result.get('formation_sha256')==selection['formation_sha256']
                and result.get('genesis_review_sha256')==source['review_sha256']
                and result.get('genesis_sha256')==source['genesis_sha256'] and result.get('authority_sha256')==source['authority_sha256']
                and result.get('runtime_admission') is False and result.get('fleet_readiness_verified') is False,
                'Native transport scope or admission differs')
        prepared=parse_request(self.direct(prepare,True,2*1024*1024).read_bytes())
        require(prepared['operation']=='network_transport_prepare' and result.get('request_sha256')==request_digest(prepared),
                'Native transport preparation request differs')
        addresses=result.get('validator_addresses')
        require(isinstance(addresses,list) and len(addresses)==5 and all(isinstance(v,str) for v in addresses)
                and len(set(addresses))==5 and set(addresses)==set(source.get('validator_addresses',[])), 'Transport roster differs from signed Genesis')
        for field in ('review_sha256','issuer_root_sha256'):
            require(isinstance(result.get(field),str) and re.fullmatch('[a-f0-9]{64}',result[field]),'Exact native transport pin required')
        if check_sign:
            require(result['signed']==(signing.exists() or signing.is_symlink()),'Incomplete transport signing requires reconciliation')
        if result['signed']:
            signed=parse_request(self.direct(signing,True).read_bytes())
            require(signed['operation']=='network_transport_sign' and signed['parameters']['review_sha256']==result['review_sha256']
                    and result.get('sign_request_sha256')==request_digest(signed),'Native transport signing request differs')

    def formation_preflight(self):
        require(not any(self.exists(path) for path in (FORMATION_CUSTODY,FORMATION_INTENT,
                'tmp/pending-validator-custody',GENESIS_BIND_INTENT,'data'))
                and not list((self.root/'keys').iterdir()),
                'Existing or interrupted custody must be reconciled before any new identity generation')
        return self.formation_context()

    def exact_request_receipt(self,relative,operation,key,pin,create=False):
        from synergy_linux import write_new
        value={'version':1,'operation':operation,'parameters':{key:pin}}
        request_sha256=hashlib.sha256(canonical(value)).hexdigest()
        expected={'format':'nodenetwork-request-custody-v1','request_sha256':request_sha256}
        if create:write_new(self.root/relative,expected)
        else:
            require(self.public_json(self.root/relative,True)==expected,
                    'Durable request identity differs; preserve and reconcile custody','reconciliation_required')
        return request_sha256

    def public_artifact(self,result,name):
        raw=result.get(name+'_json')
        pin=result.get(name+'_sha256')
        require(isinstance(raw,str) and 0<len(raw.encode('utf-8'))<=128*1024
                and isinstance(pin,str) and hashlib.sha256(raw.encode('utf-8')).hexdigest()==pin,
                'Native APQE public artifact digest or size differs')
        return {name+'_json':raw,name+'_sha256':pin}

    def formation_result(self,selection,flags,command,export=False):
        from synergy_linux import native
        pin=selection['formation_sha256']
        request_sha256=self.exact_request_receipt(FORMATION_INTENT,'formation_prepare','formation_sha256',pin)
        result=json.loads(native([self.root/'bin/synergy-keytool',command,self.formation_context_path(),pin,
                                  self.root/FORMATION_CUSTODY,*flags]))
        address=result.get('address')
        require(isinstance(address,str) and re.fullmatch(r'synv1[0-9a-z]{10,90}',address)
                and result.get('possession_verified') is True and result.get('membership_granted') is False,
                'Native APQE formation custody was not confirmed')
        artifact=self.public_artifact(result,'registration')
        if export:
            return {'schema':'nodenetwork-formation-export-v1','address':address,
                    'formation_sha256':pin,**artifact}
        return {**selection,'pending':True,'address':address,'possession_verified':True,
                'membership_granted':False,'request_sha256':request_sha256}

    def formation_prepare(self,request):
        from lifecycle import _lifecycle_lock
        with _lifecycle_lock(self.root):
            selection,flags=self.formation_preflight()
            pin=selection['formation_sha256']
            require(request['parameters']['formation_sha256']==pin,'Reviewed formation context changed')
            self.authorize(request)
            self.exact_request_receipt(FORMATION_INTENT,'formation_prepare','formation_sha256',pin,create=True)
            return self.formation_result(selection,flags,'prepare-validator-formation')

    def formation_status(self,export=False):
        from lifecycle import _lifecycle_lock, _sealed_receipt
        with _lifecycle_lock(self.root):
            _sealed_receipt(self.root)
            if not self.exists(FORMATION_CUSTODY) and not self.exists(FORMATION_INTENT):
                require(not export,'No pending public formation registration')
                return {'pending':False}
            try:
                selection,flags=self.formation_context()
                return self.formation_result(selection,flags,'verify-validator-formation',export)
            except (Refused,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                raise Refused('reconciliation_required','Pending formation custody could not be verified; preserve it for reconciliation.') from None

    def genesis_pins(self):
        pins=self.policy().get('validator_identity_network')
        require(isinstance(pins,dict) and set(pins)==set(GENESIS_FILES)
                and all(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin) for pin in pins.values()),
                'Host operator has not pinned the signed Genesis and its authority','authorization_required')
        return pins

    def genesis_pin_result(self,pins):
        return {'genesis_sha256':pins['genesis.json'],'authority_sha256':pins['authority.json'],
                'authority_root_sha256':pins['authority-root.pub']}

    def genesis_review(self,command,selection,flags,pins,path):
        from synergy_linux import native
        value=json.loads(native([self.root/'bin/synergy-keytool',command,self.formation_context_path(),
            selection['formation_sha256'],self.root/FORMATION_CUSTODY,path,self.root/'tmp/pending-validator-custody',
            *[pins[name] for name in GENESIS_FILES],*flags]))
        require(value.get('genesis_sha256')==pins['genesis.json']
                and value.get('genesis_authority_verified') is True and value.get('membership_verified') is True
                and type(value.get('bound')) is bool and isinstance(value.get('address'),str)
                and re.fullmatch(r'synv1[0-9a-z]{10,90}',value['address']),
                'Native APQE Genesis binding was not confirmed')
        return value

    def genesis_stage(self,request=None):
        from lifecycle import _lifecycle_lock
        from synergy_linux import write_new
        with _lifecycle_lock(self.root):
            require(not any(self.exists(path) for path in (GENESIS_STAGE,GENESIS_STAGE_WORK,GENESIS_BIND_INTENT,
                    'tmp/pending-validator-custody','data')),'Genesis is already staged or requires reconciliation')
            pins=self.genesis_pins()
            # New networks bind pre-Genesis custody. Joining an existing
            # network checks its signed Genesis before creating fresh custody.
            # Neither path can switch modes after formation has started.
            policy=self.policy()
            existing=policy.get('validator_identity_mode')=='existing_network'
            if existing:
                require('validator_formation_sha256' not in policy and not any(self.exists(path)
                        for path in (FORMATION_CONTEXT,FORMATION_CUSTODY,FORMATION_INTENT)),
                        'Existing-network staging conflicts with Genesis formation')
                selection,flags=self.identity_release()
                formation=None
            else:
                selection,flags=self.formation_context()
                formation=self.formation_result(selection,flags,'verify-validator-formation')
            scope=({'address':formation['address']} if formation else
                   {'network_id':selection['network_id'],'chain_id':str(selection['chain_id']),'membership_granted':False})
            if request is None:
                schema='nodenetwork-existing-genesis-stage-policy-v1' if existing else 'nodenetwork-genesis-stage-policy-v1'
                return {'schema':schema,**scope,**self.genesis_pin_result(pins)}
            contents=genesis_artifact_bytes(request['parameters']['artifacts'])
            require(all(hashlib.sha256(contents[name]).hexdigest()==pins[name] for name in GENESIS_FILES),
                    'Public upload differs from independently approved Genesis pins')
            request_sha256=self.authorize(request)
            work=self.root/GENESIS_STAGE_WORK
            work.mkdir(mode=0o700)
            try:
                for name,raw in contents.items():
                    with (work/name).open('xb') as stream:
                        os.fchmod(stream.fileno(),0o600)
                        stream.write(raw);stream.flush();os.fsync(stream.fileno())
                if existing:
                    self.verify_identity_network(selection,flags,pins,work)
                else:
                    verified=self.genesis_review('review-validator-genesis-binding',selection,flags,pins,work)
                    require(not verified['bound'] and verified['address']==formation['address'],
                            'Genesis does not admit the exact prepared local custody')
                write_new(work/GENESIS_STAGE_RECEIPT,{'format':'nodenetwork-genesis-stage-request-v1',
                          'request_sha256':request_sha256,**self.genesis_pin_result(pins)})
                work.rename(self.root/GENESIS_STAGE)
                sync_directory(work.parent)
            finally:
                if work.exists(): shutil.rmtree(work)
            schema='nodenetwork-existing-genesis-stage-v1' if existing else 'nodenetwork-genesis-stage-v1'
            return {'schema':schema,**scope,**self.genesis_pin_result(pins),'request_sha256':request_sha256,
                    'genesis_authority_verified':True,'membership_verified':not existing,'staged':True}

    def genesis_stage_request(self,pins):
        folder=self.root/GENESIS_STAGE
        receipt=folder/GENESIS_STAGE_RECEIPT
        if not self.exists(receipt.relative_to(self.root)):return {}
        artifacts={}
        for name,limit in GENESIS_FILES.items():
            with self.direct(folder/name,True,limit).open('rb') as stream: raw=stream.read(limit+1)
            require(0<len(raw)<=limit and hashlib.sha256(raw).hexdigest()==pins[name],
                    'Staged Genesis public input changed')
            artifacts[name]=base64.b64encode(raw).decode('ascii') if name=='authority-root.pub' else raw.decode('utf-8')
        request_sha256=request_digest({'version':1,'operation':'genesis_stage','parameters':{'artifacts':artifacts}})
        require(self.public_json(receipt,True)=={'format':'nodenetwork-genesis-stage-request-v1',
                'request_sha256':request_sha256,**self.genesis_pin_result(pins)},
                'Genesis staging receipt differs; preserve and reconcile','reconciliation_required')
        return {'stage_request_sha256':request_sha256}

    def genesis_binding(self,request=None, *, locked=False):
        import contextlib
        from lifecycle import _lifecycle_lock
        with contextlib.nullcontext() if locked else _lifecycle_lock(self.root):
            selection,flags=self.formation_context()
            formation_pin=selection['formation_sha256']
            self.exact_request_receipt(FORMATION_INTENT,'formation_prepare','formation_sha256',formation_pin)
            selected,_=self.identity_network()
            pin=selected['genesis_sha256']
            network_pins=self.genesis_pins()
            require(network_pins['genesis.json']==pin,'Reviewed Genesis pins changed')
            pending='tmp/pending-validator-custody'
            had_bound=self.exists(pending) or self.exists(GENESIS_BIND_INTENT)
            def run(command):
                return self.genesis_review(command,selection,flags,network_pins,self.root/GENESIS_STAGE)
            stage_receipt=self.genesis_stage_request(network_pins)
            try:
                result=run('review-validator-genesis-binding')
                require(result['bound']==had_bound,'Partial Genesis binding requires reconciliation')
                if had_bound:
                    self.exact_request_receipt(GENESIS_BIND_INTENT,'genesis_bind','genesis_sha256',pin)
            except (Refused,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                if had_bound:
                    raise Refused('reconciliation_required','Pending Genesis binding could not be verified; preserve it for reconciliation.') from None
                raise
            if request is not None:
                require(not had_bound,'Genesis custody was already bound; use read-only reconciliation')
                require(request['parameters']['genesis_sha256']==pin,'Reviewed Genesis changed')
                self.authorize(request)
                self.exact_request_receipt(GENESIS_BIND_INTENT,'genesis_bind','genesis_sha256',pin,create=True)
                result=run('bind-validator-formation')
                require(result['bound'] is True,'Genesis binding did not return a confirmed result')
            response={'schema':'nodenetwork-genesis-binding-v1',**selected,'address':result['address'],
                      'membership_verified':True,'bound':result['bound'],**stage_receipt}
            if result['bound']:
                response.update(self.public_artifact(result,'enrollment'))
                response['request_sha256']=self.exact_request_receipt(GENESIS_BIND_INTENT,'genesis_bind','genesis_sha256',pin)
            return response

    def identity_release(self):
        from lifecycle import _sealed_receipt
        receipt, manifest = _sealed_receipt(self.root)
        require(receipt['role']=='validator','A validator package is required')
        self.direct(self.root/'installation.json',True)
        report = 'lib/apqe/build-report.json'
        flags = ['--apqe-report',self.root/report,'--apqe-report-sha256',manifest['files'][report]]
        return receipt, flags

    def verify_identity_network(self, receipt, flags, pins, staged):
        from synergy_linux import digest, native, read
        files = {name:self.direct(staged/name,maximum=limit) for name,limit in GENESIS_FILES.items()}
        require(all(digest(path)==pins[name] for name,path in files.items()),'Approved identity network inputs changed')
        network=read(files['genesis.json'])['unsigned']['network']
        require(network['chain_id']==receipt['chain_id'] and network['network_id']==receipt['network_id'],
                'Signed Genesis selects a different installation network')
        native([self.root/'bin/synergy-genesis','verify-binding',files['genesis.json'],
                files['authority-root.pub'],files['authority.json'],*flags])
        return {'network_id':receipt['network_id'],'chain_id':str(receipt['chain_id']),
                'genesis_sha256':pins['genesis.json'],'genesis_authority_verified':True}

    def identity_network(self):
        receipt, flags = self.identity_release()
        pins=self.genesis_pins()
        verified=self.verify_identity_network(receipt,flags,pins,self.root/GENESIS_STAGE)
        if self.policy().get('validator_identity_mode')=='existing_network':
            verified.update(self.genesis_stage_request(pins),
                            schema='nodenetwork-existing-identity-network-v1',membership_granted=False)
        return verified, flags

    def checked_custody(self, selection, flags, command):
        from synergy_linux import native
        chain = format(int(selection['chain_id']),'064x')
        pin = selection['genesis_sha256']
        result = json.loads(native([self.root/'bin/synergy-keytool',command,
                                    chain,pin,self.root/'tmp/pending-validator-custody',*flags]))
        address = result.get('address')
        require(isinstance(address,str) and re.fullmatch(r'synv1[0-9a-z]{10,90}',address)
                and result.get('genesis_sha256')==pin and result.get('chain_id_hex')==chain
                and result.get('possession_verified') is True and result.get('membership_granted') is False,
                'Native APQE returned an unconfirmed custody result; reconcile before retrying')
        return {**selection,'address':address,'possession_verified':True,'membership_granted':False}

    def identity_status(self):
        from lifecycle import _lifecycle_lock, _sealed_receipt
        with _lifecycle_lock(self.root):
            _sealed_receipt(self.root)
            path = self.root/'tmp/pending-validator-custody'
            if not path.exists() and not path.is_symlink():
                require(not self.exists(IDENTITY_INTENT),
                        'Interrupted identity preparation requires local reconciliation','reconciliation_required')
                return {'pending':False}
            try:
                selection, flags = self.identity_network()
                result=self.checked_custody(selection,flags,'verify-validator-custody')
                if self.exists(IDENTITY_INTENT):
                    result['request_sha256']=self.exact_request_receipt(
                        IDENTITY_INTENT,'identity_generate','genesis_sha256',selection['genesis_sha256'])
                return {'pending':True, **result}
            except (Refused,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                raise Refused('reconciliation_required','Pending custody could not be verified. Preserve the files and reconcile locally before trying again.') from None

    def identity_generate(self, request):
        from lifecycle import _lifecycle_lock
        with _lifecycle_lock(self.root):
            selection, flags = self.identity_preflight()
            pin = selection['genesis_sha256']
            require(request['parameters']['genesis_sha256']==pin,'The reviewed Genesis artifact changed; inspect it again')
            self.authorize(request)
            scoped=selection.get('schema')=='nodenetwork-existing-identity-network-v1'
            if scoped:
                key=self.exact_request_receipt(IDENTITY_INTENT,'identity_generate','genesis_sha256',pin,create=True)
            result=self.checked_custody(selection,flags,'provision-validator-custody')
            if scoped: result['request_sha256']=key
            return result

    def vpn_status(self):
        import lifecycle as life
        from vpn import status
        enrollment=self.root/'evidence/vpn-enrollment.json'
        binding=self.root/'evidence/vpn-server-binding.json'
        local=self.public_json(enrollment,True) if enrollment.exists() or enrollment.is_symlink() else None
        server=self.public_json(binding,True) if binding.exists() or binding.is_symlink() else None
        plan=life._integration_plan(self.root)
        owned=life._attributed_units(self.root,plan) if plan else {}
        service=owned.get('synergy-vpn.service')
        recorded=isinstance(local,dict) and local.get('native_enrollment_verified') is True
        attempt=self.root/VPN_ATTEMPT
        attempted=attempt.exists() or attempt.is_symlink()
        if attempted:
            require(self.public_json(attempt,True)=={'format':'nodenetwork-vpn-attempt-v1'},
                    'Invalid VPN enrollment attempt record')
        if attempted:
            from vpn import attempt_state
            attempted=attempt_state(self.root)['retry_after_sha256'] is None
        bound=False
        connected=False
        overlay=None
        if recorded:
            overlay=str(ipaddress.ip_interface(local['overlay_address']))
            bound=(isinstance(server,dict) and server.get('server_binding_verified') is True
                   and bool(server.get('peer_id')) and server.get('wireguard_public_key')==local.get('wireguard_public_key')
                   and ipaddress.ip_address(server['ip'])==ipaddress.ip_interface(overlay).ip)
            if service and service.get('ActiveState')=='active':
                try:
                    current=status(self.root)
                    connected=(current['management']['connected'] is True
                               and current['signal']['connected'] is True
                               and current['publicKey']==local['wireguard_public_key']
                               and ipaddress.ip_interface(current['netbirdIp'])==ipaddress.ip_interface(overlay))
                except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError): pass
        retired=False
        retirement=self.root/'evidence/vpn-retirement.json'
        if retirement.exists() or retirement.is_symlink():
            from vpn import validate_retirement_receipt
            self.public_json(retirement,True)
            require(recorded and bound,'Retirement lacks current enrolled binding')
            validate_retirement_receipt(retirement.read_bytes(),enrollment.read_bytes(),binding.read_bytes())
            retired=True
        return {'schema':'nodenetwork-vpn-status-v1','service_registered':service is not None,
                'enrollment_staged':self.vpn_stage() is not None,'enrollment_recorded':recorded,
                'reconciliation_required':attempted and not recorded,
                'server_bound':bound,'connected':connected,'overlay_address':overlay,
                'enrollment':local if recorded else None,'server_binding':server if bound else None,
                'enrollment_sha256':hashlib.sha256(enrollment.read_bytes()).hexdigest() if recorded else None,
                'server_binding_sha256':hashlib.sha256(binding.read_bytes()).hexdigest() if bound else None,'retired':retired}

    def vpn_provider_binding(self,scope=None):
        policy=self.policy();origin=policy.get('engineering_selection',{});target=policy.get('engineering_target',{})
        require(target.get('kind') in ('local','remote') and target.get('root')==str(self.root),'Original VPN target unavailable')
        identity={'kind':target['kind'],'host':target.get('host').lower() if target.get('host') else None,
                  'port':target.get('port',22) if target['kind']=='remote' else None,'root':target['root']}
        if 'guest' in target:identity['guest']=target['guest']
        result={'target_sha256':hashlib.sha256(canonical(identity)).hexdigest(),
                'manifest_sha256':origin.get('manifest_sha256'),'formation_sha256':policy.get('validator_formation_sha256'),
                'network_id':origin.get('network_id'),'chain_id':origin.get('chain_id')}
        if scope is not None:result['attempt_sha256']=scope
        return result

    def vpn_unused_preflight(self):
        import lifecycle as life
        with life._lifecycle_lock(self.root):return self._vpn_unused_preflight()

    def unregistered_vpn_identity(self,allow_existing=False):
        from vpn import unregistered_default_profile,attempt_state
        identity=unregistered_default_profile(self.root)
        if identity is None:return None
        require(allow_existing and attempt_state(self.root)['attempt_sha256'] is not None,
                'Existing VPN profile lacks an original fresh-attempt fence')
        # The published first-enrollment path checked an empty VPN directory,
        # consumed this exact request, then fenced before starting the daemon.
        original={'version':1,'operation':'vpn_enroll','parameters':{}}
        key=request_digest(original);audit=self.direct(self.control/'audit.jsonl',True)
        require(0<audit.stat().st_size<=1024*1024,'Original VPN audit exceeds bound')
        rows=audit.read_bytes().splitlines();require(len(rows)<=4096,'Original VPN audit exceeds bound')
        matching=[json.loads(row) for row in rows]
        require(any(row=={'operation':'vpn_enroll','request_sha256':key,'time':row.get('time')}
                    and type(row.get('time')) is int and 0<=row['time']<=int(time.time()) for row in matching if isinstance(row,dict))
                and not (self.control/'grants'/(key+'.json')).exists()
                and not (self.control/'grants'/(key+'.json')).is_symlink(),
                'Original fresh VPN enrollment is not durably consumed')
        return identity

    def _vpn_unused_preflight(self):
        import lifecycle as life
        from vpn import attempt_state
        life._sealed_receipt(self.root)
        state=attempt_state(self.root)
        quiescent=(self.vpn_stage() is None and not any(self.exists(p) for p in
                ('evidence/vpn-enrollment.json','evidence/vpn-server-binding.json','run/enrollment.key'))
                and not (self.root/'vpn').is_symlink())
        if quiescent:
            try:self.unregistered_vpn_identity(allow_existing=state['attempt_sha256'] is not None)
            except (ValueError,OSError):quiescent=False
        units=life._attributed_units(self.root,life._integration_plan(self.root))
        quiescent=quiescent and 'synergy-vpn.service' in units and all(value.get('MainPID')=='0'
                and value.get('ActiveState') in ('inactive','failed') for value in units.values())
        if quiescent:
            try:life._assert_no_application_processes(self.root)
            except (ValueError,OSError,subprocess.SubprocessError):quiescent=False
        return {'schema':'nodenetwork-vpn-unused-preflight-v1','quiescent':quiescent,
                'attempt_sha256':state['attempt_sha256'],'scope_sha256':state['scope_sha256'],
                'retry_after_sha256':state['retry_after_sha256'],
                'pending_cancellation_sha256':(self.public_json(self.root/'evidence/vpn-cancel-unused-intent.json',True)['receipt_sha256']
                    if self.exists('evidence/vpn-cancel-unused-intent.json') else None),
                'attempt_scopes':[event['cancellation_sha256'] for event in state['events'] if event['kind']=='attempt'],
                'binding':self.vpn_provider_binding(state['scope_sha256'])}

    def vpn_cancel_unused(self,request):
        import lifecycle as life
        from vpn import attempt_state,append_attempt_event,validate_unused_cancellation,CANCELLATION,public_hash
        with life._lifecycle_lock(self.root):
            current=self._vpn_unused_preflight()
            require(current['quiescent'] is True and current['attempt_sha256'] is not None
                    and request['parameters']=={'attempt_sha256':current['attempt_sha256']},
                    'Unused cancellation requires exact quiescent attempted target')
            policy=self.policy();path=self.control/'authorization/inputs'/CANCELLATION
            receipt=self.public_json(path,True);raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
            require(policy.get('authorization_files',{}).get(CANCELLATION)==digest,'Cancellation differs from native approval')
            validate_unused_cancellation(receipt)
            provider_path=self.control/'authorization/inputs/vpn-provider.json'
            provider=self.public_json(provider_path,True)
            require(hashlib.sha256(provider_path.read_bytes()).hexdigest()==policy.get('authorization_files',{}).get('vpn-provider.json')
                    and receipt['account_id']==provider.get('account_id')
                    and receipt['provider_sha256']==hashlib.sha256(canonical(provider)).hexdigest()
                    and receipt['binding']==current['binding'] and receipt['attempt_sha256']==current['attempt_sha256']
                    and receipt['name']=='nn-'+hashlib.sha256(canonical(current['binding'])).hexdigest()[:60],
                    'Original unused cancellation attribution differs')
            event={'kind':'cancel','receipt':receipt}
            state=attempt_state(self.root);intent_path=self.root/'evidence/vpn-cancel-unused-intent.json'
            key=request_digest(request);receipt_sha=public_hash(receipt)
            if state['retry_after_sha256'] is not None:
                require(state['events'][-1]==event,'Prior unused cancellation differs')
            else:
                pending=None
                if intent_path.exists() or intent_path.is_symlink():
                    pending=self.public_json(intent_path,True)
                    require(set(pending)=={'format','request_sha256','receipt_sha256','attempt_sha256','grant'}
                            and pending['format']=='nodenetwork-vpn-cancel-intent-v1'
                            and pending['request_sha256']==key and pending['receipt_sha256']==receipt_sha
                            and pending['attempt_sha256']==current['attempt_sha256'], 'Pending unused cancellation differs')
                grant_path=self.control/'grants'/(key+'.json')
                if pending is None:
                    grant=self.public_json(grant_path,True)
                    pending={'format':'nodenetwork-vpn-cancel-intent-v1','request_sha256':key,
                             'receipt_sha256':receipt_sha,'attempt_sha256':current['attempt_sha256'],'grant':grant}
                    from vpn import _retirement_write
                    _retirement_write(intent_path,pending)
                grant=pending['grant']
                require(grant.get('operation')=='vpn_cancel_unused' and grant.get('request_sha256')==key
                        and grant.get('binding_sha256')==digest,'Original cancellation grant differs')
                audit=self.control/'audit.jsonl';audited=False
                if audit.exists() or audit.is_symlink():
                    records=[json.loads(line) for line in self.direct(audit,True).read_bytes().splitlines()]
                    matches=[row for row in records if row.get('request_sha256')==key]
                    require(len(matches)<=1 and all(row.get('operation')=='vpn_cancel_unused' for row in matches),
                            'Ambiguous original cancellation audit')
                    audited=bool(matches)
                if not audited:
                    require(self.public_json(grant_path,True)==grant,'Original unconsumed cancellation grant differs')
                    self.authorize(request,digest)
                elif grant_path.exists() or grant_path.is_symlink():
                    require(self.public_json(grant_path,True)==grant,'Remaining cancellation grant differs')
                    grant_path.unlink();life._sync_directory(grant_path.parent)
                state=append_attempt_event(self.root,event)
            if intent_path.exists() or intent_path.is_symlink():
                pending=self.public_json(intent_path,True)
                require(pending.get('request_sha256')==key and pending.get('receipt_sha256')==receipt_sha,
                        'Completed cancellation intent differs')
                intent_path.unlink();life._sync_directory(intent_path.parent)
            return {'schema':'nodenetwork-vpn-unused-cancellation-v1','cancelled':True,
                    'retry_requires_new_confirmation':True,'attempt_sha256':current['attempt_sha256'],
                    'cancellation_sha256':public_hash(event)}

    def _boot_policy_scope(self, enabling=False):
        import lifecycle as life
        from conformance import installed
        from apqe_layout import startup_readiness_authorized
        from root_guard import check_registration
        receipt,_=life._sealed_receipt(self.root)
        check_registration(self.policy().get('root_guard_sha256'))
        for name in (HOST_REMOVAL,):
            require(not (self.control/name).exists() and not (self.control/name).is_symlink(),'Host retirement must reconcile before boot policy')
        for name in (life.UPGRADE_INTENT,life.REPLACEMENT_INTENT,life.AUTHORITY_RECOVERY_INTENT,life.AUTONOMOUS_EPOCH_INTENT,
                     'evidence/vpn-cancel-unused-intent.json','run/enrollment.key','tmp/controller/authorization/inputs/vpn-retirement.json'):
            require(not (self.root/name).exists() and not (self.root/name).is_symlink(),'Pending lifecycle mutation must reconcile before boot policy')
        observed=life.service_boot_state(self.root)
        if enabling:
            require(self.policy().get('engineering_target',{}).get('guest') is None,
                    'Guest validator boot enable is not approved')
            require(receipt.get('role')=='validator' and (self.root/'data').is_dir() and not (self.root/'data').is_symlink(),
                    'Commission the active validator before enabling boot policy')
            installed(self.root,host=True)
            identity=life.verify_identity(self.root)
            startup=life.read(self.root/'config/start-authorized.json')
            authority=life.read(self.root/'network/authority.json')['payload']
            require(startup.get('network_id')==receipt['network_id'] and startup.get('chain_id')==receipt['chain_id']
                    and startup_readiness_authorized(self.root,startup,identity['address']),
                    'Exact commissioned startup approval required')
            life._authorized_validator_ids(startup,authority,identity['address'])
            self.require_bound_validator_vpn()
        return observed

    def boot_policy(self,request):
        import lifecycle as life
        p=request['parameters']
        with life._lifecycle_lock(self.root):
            self._boot_policy_scope(p['enabled'])
            require((self.root/'data').is_dir() and not (self.root/'data').is_symlink(),
                    'Boot policy requires a commissioned installation')
            self.authorize(request)
            life.set_service_boot_policy(self.root,p['service'],p['enabled'])
            return {'schema':'nodenetwork-boot-policy-v1','service':p['service'],
                    'enabled':p['enabled'],'runtime_changed':False}

    def boot_policy_status(self):
        import lifecycle as life
        with life._lifecycle_lock(self.root):
            observed=self._boot_policy_scope()
            result={'schema':'nodenetwork-boot-policy-status-v1','node_enabled':observed['node'],
                    'vpn_enabled':observed['vpn'],'applied':False,'request_sha256':None,'runtime_changed':False}
            audit=self.control/'audit.jsonl'
            if not audit.exists() and not audit.is_symlink():return result
            rows=self.direct(audit,True,1024*1024).read_bytes().splitlines()
            require(len(rows)<=4096,'Boot policy audit exceeds bound')
            requests={request_digest(r):r for r in ({'version':1,'operation':'boot_policy','parameters':{'service':service,'enabled':enabled}}
                      for service in ('node','vpn') for enabled in (False,True))}
            latest=None
            for raw in rows:
                row=json.loads(raw)
                require(isinstance(row,dict) and set(row)=={'request_sha256','operation','time'}
                        and isinstance(row['request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',row['request_sha256'])
                        and row['operation'] in MUTATIONS and type(row['time']) is int and 0<=row['time']<=int(time.time()),
                        'Malformed boot policy audit')
                if row['operation']=='boot_policy':
                    require(row['request_sha256'] in requests,'Unknown boot policy audit request')
                    latest=row['request_sha256']
            if latest is not None:
                grant=self.control/'grants'/(latest+'.json');p=requests[latest]['parameters']
                if not grant.exists() and not grant.is_symlink() and observed[p['service']]==p['enabled']:
                    result.update(applied=True,request_sha256=latest)
            return result

    def vpn_stop_status(self):
        """Reconcile observed postconditions of an audited, consumed stop only."""
        import lifecycle as life
        request={'version':1,'operation':'vpn_stop','parameters':{}}
        key=request_digest(request)
        result={'schema':'nodenetwork-vpn-stop-status-v1','stopped':False,
                'request_sha256':None,'attempt_preserved':True,'provider_action':False}
        with life._lifecycle_lock(self.root):
            life._sealed_receipt(self.root)
            units=life._attributed_units(self.root)
            if not all(units.get(name,{}).get('MainPID')=='0' and
                       units.get(name,{}).get('ActiveState') in ('inactive','failed')
                       for name in ('synergy-node.service','synergy-vpn.service')):return result
            life._assert_no_application_processes(self.root)
            audit=self.control/'audit.jsonl'
            grant=self.control/'grants'/(key+'.json')
            # An audit precedes unlink; a still-present grant is NOT consumed.
            if grant.exists() or grant.is_symlink() or not audit.exists():return result
            audit=self.direct(audit,True)
            require(0<audit.stat().st_size<=1024*1024,'Stop audit exceeds bound')
            lines=audit.read_bytes().splitlines()
            require(len(lines)<=4096,'Stop audit exceeds bound')
            matched=False
            for line in lines:
                row=json.loads(line)
                require(isinstance(row,dict) and set(row)=={'request_sha256','operation','time'}
                        and isinstance(row['request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',row['request_sha256'])
                        and isinstance(row['operation'],str) and row['operation'] in MUTATIONS
                        and type(row['time']) is int and 0<=row['time']<=int(time.time()),'Malformed stop audit')
                if row['operation']=='vpn_stop' or row['request_sha256']==key:
                    require(row['operation']=='vpn_stop' and row['request_sha256']==key,'Stop audit request differs')
                    matched=True
            if matched:result.update(stopped=True,request_sha256=key)
            return result

    def vpn_stop(self,request):
        """Stop only the attributed VPN; never change attempts or provider state."""
        import lifecycle as life
        with life._lifecycle_lock(self.root):
            life._sealed_receipt(self.root)
            units=life._attributed_units(self.root)
            node=units.get('synergy-node.service',{})
            require(node.get('MainPID')=='0' and node.get('ActiveState') in ('inactive','failed'),
                    'Stop the validator before stopping its VPN')
            service=units.get('synergy-vpn.service',{})
            pid=service.get('MainPID')
            require(isinstance(pid,str) and pid.isdecimal() and service.get('ActiveState') in
                    ('active','activating','deactivating','inactive','failed'), 'Owned VPN state unavailable')
            # Exempt only the exact attributed NetBird daemon, not another node process.
            life._assert_no_application_processes(self.root,vpn_pid=int(pid) if pid!='0' else None)
            self.authorize(request)
            life.mutate_owned_service(self.root,'stop','synergy-vpn.service')
            stopped=life._attributed_units(self.root).get('synergy-vpn.service',{})
            require(stopped.get('MainPID')=='0' and stopped.get('ActiveState') in ('inactive','failed'),
                    'VPN stop outcome uncertain; inspect diagnostics before another action')
            life._assert_no_application_processes(self.root)
            return {'schema':'nodenetwork-vpn-stop-v1','stopped':True,
                    'attempt_preserved':True,'provider_action':False}

    def _vpn_resume_scope(self):
        import lifecycle as life
        from vpn import attempt_state,client_environment,retirement_binding,_profile_json,profile_identity
        life._sealed_receipt(self.root)
        units=life._attributed_units(self.root)
        node=units.get('synergy-node.service',{})
        require(node.get('MainPID')=='0' and node.get('ActiveState') in ('inactive','failed'),
                'Stop the validator before resuming its VPN')
        service=units.get('synergy-vpn.service',{});pid=service.get('MainPID')
        require(isinstance(pid,str) and pid.isdecimal() and service.get('ActiveState') in ('active','inactive','failed'),
                'Owned VPN state unavailable')
        life._assert_no_application_processes(self.root,vpn_pid=int(pid) if pid!='0' else None)
        current=self.vpn_status()
        require(current['service_registered'] and current['enrollment_recorded'] and current['server_bound']
                and not current['enrollment_staged'] and not current['reconciliation_required'] and not current['retired'],
                'Resume requires an existing non-retired independently bound VPN peer')
        state=attempt_state(self.root)
        require(state['attempt_sha256'] is not None and state['retry_after_sha256'] is None,
                'Original VPN attempt must be fully enrolled')
        for name in ('evidence/vpn-cancel-unused-intent.json','run/enrollment.key','tmp/controller/authorization/inputs/vpn-retirement.json'):
            path=self.root/name
            require(not path.exists() and not path.is_symlink(),'Pending VPN mutation must reconcile before resume')
        enrollment=self.direct(self.root/'evidence/vpn-enrollment.json',True).read_bytes()
        binding=self.direct(self.root/'evidence/vpn-server-binding.json',True).read_bytes()
        retirement_binding(enrollment,binding)
        provider_path=self.control/'authorization/inputs/vpn-provider.json'
        provider_raw=self.direct(provider_path,True,16384).read_bytes()
        require(hashlib.sha256(provider_raw).hexdigest()==self.policy().get('authorization_files',{}).get('vpn-provider.json'),
                'Approved VPN provider changed')
        provider=json.loads(provider_raw);local=json.loads(enrollment)
        from vpn import management_origin
        expected=self.vpn_provider_binding(state['scope_sha256'])
        require(local.get('hostname')=='nn-'+hashlib.sha256(canonical(expected)).hexdigest()[:60]
                and management_origin(local['management_url'])==provider.get('management_origin'),
                'Enrolled VPN origin or provider differs')
        client_environment(self.root)  # Durable pinned carrier trust; no issuance-expiry check.
        config=_profile_json(self.direct(self.root/'vpn/default.json',True,16384))
        identity=profile_identity(config)
        url=config.get('ManagementURL')
        require(isinstance(url,dict) and url.get('Scheme')=='https' and isinstance(url.get('Host'),str)
                and all(url.get(field) in (None,'',False) for field in ('Opaque','User','Path','RawPath','RawQuery','Fragment'))
                and management_origin('https://'+url['Host'])==provider.get('management_origin'),
                'Contained VPN management origin differs from approved provider')
        return service,current,(enrollment,binding,identity,state)

    def _vpn_resume_observed(self,original):
        from vpn import status,_same_profile_identity,attempt_state
        enrollment,binding,identity,state=original
        require(self.direct(self.root/'evidence/vpn-enrollment.json',True).read_bytes()==enrollment
                and self.direct(self.root/'evidence/vpn-server-binding.json',True).read_bytes()==binding,
                'Original VPN binding changed during resume')
        require(attempt_state(self.root)==state,'Original VPN attempt changed during resume')
        _same_profile_identity(self.root,identity)
        local=json.loads(enrollment);live=status(self.root,timeout=4)
        require(live['publicKey']==local['wireguard_public_key']
                and ipaddress.ip_interface(live['netbirdIp'])==ipaddress.ip_interface(local['overlay_address']),
                'Resumed VPN identity or overlay differs')

    def vpn_resume(self,request):
        import lifecycle as life
        with life._lifecycle_lock(self.root):
            service,current,original=self._vpn_resume_scope()
            require((service['MainPID']=='0' and service['ActiveState'] in ('inactive','failed'))
                    or (service['ActiveState']=='active' and int(service['MainPID'])>0 and current['connected']),
                    'Active unresponsive VPN must be inspected; resume never restarts it','vpn_resume_not_started')
            self.authorize(request)
            if service['MainPID']=='0':life.mutate_owned_service(self.root,'start','synergy-vpn.service')
            for attempt in range(4):
                try:
                    self._vpn_resume_observed(original)
                    after=life._attributed_units(self.root).get('synergy-vpn.service',{})
                    require(after.get('ActiveState')=='active' and isinstance(after.get('MainPID'),str)
                            and after['MainPID'].isdecimal() and int(after['MainPID'])>0,'Resumed VPN service is not active')
                    break
                except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
                    if attempt==3:raise Refused('vpn_reconciliation_required','VPN resume outcome uncertain; read exact resume status before another action') from None
                    time.sleep(1)
            return {'schema':'nodenetwork-vpn-resume-v1','resumed':True,'validator_started':False,'enrollment_preserved':True}

    def vpn_resume_status(self):
        import lifecycle as life
        request={'version':1,'operation':'vpn_resume','parameters':{}};key=request_digest(request)
        result={'schema':'nodenetwork-vpn-resume-status-v1','resumed':False,'request_sha256':None,
                'validator_started':False,'enrollment_preserved':True}
        with life._lifecycle_lock(self.root):
            service,current,original=self._vpn_resume_scope()
            grant=self.control/'grants'/(key+'.json');audit=self.control/'audit.jsonl'
            if grant.exists() or grant.is_symlink() or not audit.exists():return result
            raw=self.direct(audit,True).read_bytes()
            require(0<len(raw)<=1024*1024 and len(raw.splitlines())<=4096,'Resume audit exceeds bound')
            rows=[json.loads(line) for line in raw.splitlines()]
            require(all(isinstance(row,dict) and set(row)=={'request_sha256','operation','time'}
                        and isinstance(row['request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',row['request_sha256'])
                        and row['operation'] in MUTATIONS and type(row['time']) is int and 0<=row['time']<=int(time.time()) for row in rows),
                    'Malformed resume audit')
            if not any(row['request_sha256']==key and row['operation']=='vpn_resume' for row in rows):return result
            require(all(row['operation']=='vpn_resume' for row in rows if row['request_sha256']==key),'Resume audit request differs')
            if service['ActiveState']!='active' or service['MainPID']=='0' or not current['connected']:return result
            self._vpn_resume_observed(original)
            result.update(resumed=True,request_sha256=key)
            return result

    def vpn_diagnostics(self):
        import lifecycle as life
        from vpn import diagnostics
        with life._lifecycle_lock(self.root):
            life._sealed_receipt(self.root)
            current=self.vpn_status()
            sample=[]
            result=diagnostics(self.root,current,observe_live=sample.append)
            result['roster']=self.vpn_roster_diagnostics(current,sample[0] if sample else None)
            return result

    def vpn_roster_diagnostics(self,current,live):
        """Public diagnostic only; approval pins authorize destinations, not readiness."""
        import lifecycle as life
        from synergy_linux import native
        result={'available':False,'error_code':'scope_unavailable',
                'source':'approved_signed_transport','peer_status_sample':'before_probes','local_address':None,'peers':[]}
        try:
            receipt,_=life._sealed_receipt(self.root)
            pins=self.policy()['validator_commissioning_files']
            from apqe_layout import FORMATION_PUBLIC_INPUTS
            require(set(pins)==FORMATION_PUBLIC_INPUTS,'Exact approved transport inputs required')
            def approved(name):
                path=(self.root/name if self.exists('data') else
                      self.control/'authorization/inputs/commissioning'/name)
                raw=self.direct(path,True,1024*1024).read_bytes()
                require(hashlib.sha256(raw).hexdigest()==pins[name],'Approved transport changed')
                return json.loads(raw)
            config=approved('config/node.json')
            require(all(config[k]==receipt[k] for k in ('network_id','chain_id','node_name')),'Network differs')
            entries=approved('network/transport-registry.json')['payload']['validators']
            require(isinstance(entries,list) and len(entries)==5,'Exact signed roster required')
            ips={}
            for entry in entries:
                address=entry['node_address'];host,port=entry['dial_address'].rsplit(':',1)
                ip=ipaddress.ip_address(host.strip('[]'))
                require(isinstance(address,str) and 0<len(address)<=128 and address not in ips
                        and entry['revoked'] is False and port.isdigit() and 0<int(port)<65536
                        and not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local),
                        'Invalid signed roster endpoint')
                ips[address]=str(ip)
            require(len(set(ips.values()))==5 and current['server_bound'] is True,'Bound roster required')
            own=str(ipaddress.ip_address(current['server_binding']['ip']))
            local=[a for a,ip in ips.items() if ip==own]
            require(len(local)==1,'Local endpoint differs')
            result['local_address']=local[0]
        except (ValueError,OSError,KeyError,TypeError,AttributeError):return result
        try:
            details=live['peers']['details']
            require(live['publicKey']==current['server_binding']['wireguard_public_key']
                    and str(ipaddress.ip_interface(live['netbirdIp']).ip)==own,'Local identity differs')
            require(isinstance(details,list) and len(details)<=1024,'Bounded peer inventory required')
            normalized=[(str(ipaddress.ip_interface(peer['netbirdIp']).ip),peer) for peer in details]
        except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
            result['error_code']='status_unavailable';return result
        result.update(available=True,error_code=None)
        for address,ip in sorted(ips.items()):
            if address==local[0]:continue
            matches=[peer for peer_ip,peer in normalized if peer_ip==ip]
            row={'address':address,'ip':ip,'match_count':len(matches),'matches':[],
                 'route_via_wt0':False,'reachable':False,'error_code':None}
            for peer in matches[:5]:
                key=peer.get('publicKey');valid=False
                if isinstance(key,str) and len(key)==44:
                    try:valid=len(base64.b64decode(key,validate=True))==32 and base64.b64encode(base64.b64decode(key)).decode()==key
                    except (ValueError,binascii.Error):pass
                state=peer.get('status')
                row['matches'].append({'wireguard_public_key':key if valid else None,
                    'public_key_format_valid':valid,'status':state if state in ('Connected','Connecting','Disconnected','Idle') else 'unknown'})
            if not matches:row['error_code']='peer_missing'
            elif len(matches)!=1:row['error_code']='peer_duplicate'
            elif matches[0].get('status')!='Connected':row['error_code']='peer_not_connected'
            try:
                route=json.loads(native(['ip','-j','route','get',ip,'from',own],timeout=3))
                require(isinstance(route,list) and len(route)==1 and route[0].get('dev')=='wt0','Route differs')
                row['route_via_wt0']=True
                native(['ping','-n','-I','wt0','-c','1','-W','1',ip],timeout=3)
                row['reachable']=True
            except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
                if row['error_code'] is None:row['error_code']='peer_unreachable' if row['route_via_wt0'] else 'peer_route_unavailable'
            result['peers'].append(row)
        return result

    def vpn_enroll(self,request):
        import lifecycle as life
        from synergy_linux import write_new
        from vpn import enroll,attempt_state,append_attempt_event
        with life._lifecycle_lock(self.root):
            receipt,_=life._sealed_receipt(self.root)
            require(receipt['role'] in ('validator','rpc_gateway'),'VPN workflow requires an installed supported role')
            current=self.vpn_status()
            require(current['service_registered'] and not current['enrollment_recorded'],
                    'Register the contained VPN service before fresh enrollment')
            attempt=self.root/VPN_ATTEMPT
            state=attempt_state(self.root)
            require(request['parameters']==({'attempt_sha256':state['retry_after_sha256']}
                    if state['retry_after_sha256'] is not None else {}),'VPN attempt request differs')
            require(state['attempt_sha256'] is None or state['retry_after_sha256'] is not None,
                    'Prior VPN enrollment needs control-plane reconciliation','vpn_reconciliation_required')
            preserved=self.unregistered_vpn_identity(allow_existing=state['retry_after_sha256'] is not None)
            path=self.vpn_stage()
            require(path is not None,'No approved one-use VPN enrollment is staged','authorization_required')
            with path.open('rb') as stream: data=stream.read(MAX_VPN_ENROLLMENT+1)
            require(0<len(data)<=MAX_VPN_ENROLLMENT,'VPN enrollment input exceeds bound')
            if receipt['role']=='rpc_gateway':
                from canary_rpc_relay import gateway_vpn_enrollment_scope
                gateway_vpn_enrollment_scope(self,receipt,data)
            self.authorize(request,hashlib.sha256(data).hexdigest())
            # Persist the fence before dispatch: the provider can consume the
            # key without returning a receipt or writing any local VPN state.
            if state['retry_after_sha256'] is not None:
                append_attempt_event(self.root,{'kind':'attempt','cancellation_sha256':state['retry_after_sha256'],
                                               'enrollment_sha256':hashlib.sha256(data).hexdigest()})
            else:write_new(attempt,{'format':'nodenetwork-vpn-attempt-v1'})
            life._sync_directory(attempt.parent)
            path.unlink()
            life._sync_directory(path.parent)
            try: enroll(self.root,data,preserved_identity=preserved)
            except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
                raise Refused('vpn_reconciliation_required',
                              'VPN enrollment did not return a verified receipt. Inspect the VPN controller before issuing another credential.') from None
        return self.vpn_status()

    def vpn_bind(self,request):
        import lifecycle as life
        from vpn import bind_server, recover_enrollment, client_environment
        with life._lifecycle_lock(self.root):
            receipt,_=life._sealed_receipt(self.root)
            policy=self.policy()
            path=self.control/'authorization/inputs/vpn-server-binding.json'
            server=self.public_json(path,True)
            raw=path.read_bytes()
            digest=hashlib.sha256(raw).hexdigest()
            require(policy.get('authorization_files',{}).get('vpn-server-binding.json')==digest,
                    'VPN binding differs from native-approved artifact','authorization_required')
            require(set(server)=={'peer_id','ip','name','hostname','connected','new_peer_verified',
                    'one_off_usage_verified','wireguard_public_key','binding','setup_key_id',
                    'provider_account_id','one_off_usage_evidence'},'Exact native provider binding required')
            current=self.vpn_status()
            recovering=(current.get('enrollment_recorded') is False and current.get('reconciliation_required') is True
                        and current.get('enrollment_staged') is False and current.get('service_registered') is True)
            if recovering:
                require(not (self.root/'evidence/vpn-server-binding.json').exists()
                        and not (self.root/'evidence/vpn-server-binding.json').is_symlink(),
                        'Orphan VPN binding must reconcile before recovery')
                # No secret, setup-key dispatch or service action occurs here.
                # Native provider verification is independently bound to the
                # original installation, not its currently adopted software.
                client_environment(self.root)
                provider_path=self.control/'authorization/inputs/vpn-provider.json'
                provider=self.public_json(provider_path,True)
                require(hashlib.sha256(provider_path.read_bytes()).hexdigest()==policy.get('authorization_files',{}).get('vpn-provider.json'),
                        'Original VPN provider artifact differs')
                if receipt.get('role')=='rpc_gateway':
                    from canary_rpc_relay import gateway_vpn_recovery_scope
                    gateway_vpn_recovery_scope(self,receipt,provider)
                from vpn import attempt_state
                expected=self.vpn_provider_binding(attempt_state(self.root)['scope_sha256'])
                require(server['binding']==expected and server['name']=='nn-'+hashlib.sha256(canonical(expected)).hexdigest()[:60]
                        and server['provider_account_id']==provider.get('account_id'), 'Original VPN recovery scope differs')
                units=life._attributed_units(self.root,life._integration_plan(self.root))
                require(units.get('synergy-vpn.service',{}).get('ActiveState')=='active', 'Attributed VPN daemon is not active')
                self.authorize(request,digest)
                recover_enrollment(self.root,server,provider)
            else:
                require(server['wireguard_public_key']==self.public_json(self.root/'evidence/vpn-enrollment.json',True)['wireguard_public_key'],
                        'Native VPN public identity differs')
                require(current['connected'] is True and current['server_bound'] is False,
                        'Fresh connected unbound VPN required')
                self.authorize(request,digest)
            bind_server(self.root,{**server,'id':server['peer_id']})
        return self.vpn_status()

    def vpn_retire(self,request):
        import lifecycle as life
        from vpn import validate_retirement_receipt, _retirement_write, RETIREMENT
        with life._lifecycle_lock(self.root):
            life._sealed_receipt(self.root)
            path=self.control/'authorization/inputs/vpn-retirement.json'
            receipt=self.public_json(path,True);raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
            require(self.policy().get('authorization_files',{}).get('vpn-retirement.json')==digest,
                    'Retirement differs from native-verified provider absence','authorization_required')
            evidence=self.root/'evidence'
            validate_retirement_receipt(raw,(evidence/'vpn-enrollment.json').read_bytes(),
                                         (evidence/'vpn-server-binding.json').read_bytes())
            self.authorize(request,digest)
            _retirement_write(evidence/RETIREMENT,receipt)
        return {'schema':'nodenetwork-vpn-retirement-v1','retired':True,'absence_verified':True,'peer_id':receipt['peer_id']}

    def require_bound_validator_vpn(self):
        current=self.vpn_status()
        require(current['service_registered'] is True
                and current['enrollment_recorded'] is True
                and current['reconciliation_required'] is False
                and current['server_bound'] is True and current['connected'] is True,
                'Current native VPN must match the recorded, independently server-bound validator peer',
                'vpn_readiness_required')

    def commissioned_observation_contents(self,pins):
        """Re-observe installed custody without reopening deleted formation state."""
        from apqe_layout import INPUTS,FORMATION_PUBLIC_INPUTS
        require(set(pins)==FORMATION_PUBLIC_INPUTS,'Exact immutable public commissioning approval required')
        require(not any(self.exists(path) for path in (FORMATION_CUSTODY,FORMATION_INTENT,
            'tmp/pending-validator-custody',GENESIS_BIND_INTENT,'tmp/commissioning')),
            'Partial commissioning must reconcile before observation')
        contents={}
        for name in INPUTS:
            raw=self.direct(self.root/name,True,4*1024*1024).read_bytes()
            require(raw,'Empty installed commissioning input')
            contents[name]=(raw,hashlib.sha256(raw).hexdigest())
        for name in FORMATION_PUBLIC_INPUTS:
            raw=self.direct(self.control/'authorization/inputs/commissioning'/name,True,4*1024*1024).read_bytes()
            require(hashlib.sha256(raw).hexdigest()==pins[name],'Original public commissioning approval changed')
            if name!='config/start-authorized.json':
                require(contents[name][1]==pins[name],'Installed public commissioning input changed')
            else:
                draft=json.loads(raw);actual=json.loads(contents[name][0])
                require(draft.get('all_validators_ready') is False and draft.get('all_pairs_vpn_verified') is False,
                        'Original commissioning draft was not unapproved')
                readiness=self.policy().get('authorization_files',{}).get('commissioning-readiness.json')
                require(isinstance(readiness,str) and re.fullmatch('[a-f0-9]{64}',readiness),'Installed readiness provenance absent')
                from apqe_layout import readiness_startup_policy
                artifact=self.public_json(self.control/'authorization/inputs/commissioning-readiness.json',True)
                require(hashlib.sha256(self.direct(self.control/'authorization/inputs/commissioning-readiness.json',True).read_bytes()).hexdigest()==readiness,
                        'Installed readiness artifact changed')
                expected=readiness_startup_policy(draft,artifact,readiness)
                require(actual==expected,'Installed commissioning policy changed after readiness')
        return contents

    def commissioning_observation(self, *, locked=False, online_addresses=None):
        import tempfile
        import lifecycle as life
        from synergy_linux import native,write_new,digest
        from vpn import status
        from apqe_layout import formation_stage_contents,FORMATION_PUBLIC_INPUTS,PUBLIC,signed_voting_weights,require_online_quorum
        import contextlib
        with contextlib.nullcontext() if locked else life._lifecycle_lock(self.root):
            receipt,_=life._sealed_receipt(self.root)
            require(receipt['role']=='validator','Validator commissioning observation required')
            state=life._unit_state('synergy-node.service')
            require(state.get('MainPID','0') in ('','0') and state.get('ActiveState') in ('inactive','failed'),
                    'Commissioning observations require a stopped uncommissioned validator')
            self.require_bound_validator_vpn()
            commissioned=self.exists('data')
            if not commissioned:
                require(self.genesis_binding(locked=True).get('bound') is True,'Existing local custody must be bound to authenticated Genesis')
            policy=self.policy();pins=policy.get('validator_commissioning_files')
            require(isinstance(pins,dict) and set(pins)==FORMATION_PUBLIC_INPUTS,'Exact approved public commissioning inputs required')
            public=self.control/'authorization/inputs/commissioning'
            contents=(self.commissioned_observation_contents(pins) if commissioned else
                      formation_stage_contents(self.root,pins,public=public))
            # Private staging exists only for the canonical native public verifier;
            # the local keytool above independently verifies custody possession.
            with tempfile.TemporaryDirectory(prefix='commission-observe-',dir=self.root/'tmp') as temporary:
                stage=Path(temporary)
                for name,(raw,_) in contents.items():
                    path=stage/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    with path.open('xb') as stream:
                        os.fchmod(stream.fileno(),0o600);stream.write(raw)
                config=json.loads(contents['config/node.json'][0])
                manifest={'format':'synergy-apqe-commissioning-v1','root':str(self.root),
                    'network_id':config['network_id'],'chain_id':config['chain_id'],'node_name':config['node_name'],
                    'files':{name:pin for name,(_,pin) in contents.items()}}
                write_new(stage/'commissioning.json',manifest)
                life._validate_commissioning_native(self.root,stage,self.root,require_readiness=commissioned)
                if commissioned:
                    # Reuse the canonical custody verifier with exact installed
                    # bytes; no raw secret is decoded or returned by Python.
                    custody=stage/'verify-custody';(custody/'bundle').mkdir(parents=True,mode=0o700);custody.chmod(0o700)
                    mapping={'unlock':'keys/apqe/unlock','bundle/validator.enc.json':'keys/apqe/custody.json',
                        'bundle/enrollment-request.json':'keys/apqe/enrollment.json','node-identity.json':'keys/apqe/validator.pub.json'}
                    for dest,source in mapping.items():
                        path=custody/dest
                        with path.open('xb') as output:os.fchmod(output.fileno(),0o600);output.write(contents[source][0])
                    enrollment=json.loads(contents['keys/apqe/enrollment.json'][0])
                    write_new(custody/'bundle/validator.pub.json',enrollment['payload']['identity'])
                    verified=json.loads(native([self.root/'bin/synergy-keytool','verify-validator-custody',
                        format(config['chain_id'],'064x'),pins['network/genesis.json'],custody,
                        '--apqe-report',self.root/'lib/apqe/build-report.json','--apqe-report-sha256',
                        config['aegis_provider']['authenticated_report_sha256']],timeout=120))
                    address=json.loads(contents['keys/apqe/validator.pub.json'][0])['node_address']
                    require(verified.get('possession_verified') is True and verified.get('address')==address
                        and verified.get('genesis_sha256')==pins['network/genesis.json']
                        and verified.get('chain_id_hex')==format(config['chain_id'],'064x'),
                        'Installed APQE custody possession differs from selected network')
            require(all(config[k]==receipt[k] for k in ('network_id','chain_id','node_name')),'Installed network selection differs')
            identity=json.loads(contents['keys/apqe/validator.pub.json'][0]);address=identity['node_address']
            registry=json.loads(contents['network/transport-registry.json'][0])['payload']
            entries=registry['validators'];require(isinstance(entries,list) and len(entries)==5,'Five signed transport members required')
            roster=sorted(entry['node_address'] for entry in entries)
            require(len(set(roster))==5 and address in roster and not any(entry['revoked'] for entry in entries),'Signed transport roster differs')
            authority=json.loads(contents['network/authority.json'][0])['payload']
            weights=signed_voting_weights(authority,roster)
            online=roster if online_addresses is None else online_addresses
            require(isinstance(online,list) and online==sorted(set(online)) and set(online)<=set(roster),
                    'Exact online commissioning subset differs from signed roster')
            if online:
                require(address in online,'Local validator must belong to observed online subset')
                require_online_quorum(roster,weights,online)
            ips={}
            for entry in entries:
                host,port=entry['dial_address'].rsplit(':',1)
                require(port.isdigit() and 0<int(port)<65536,'Invalid signed transport endpoint')
                ips[entry['node_address']]=str(ipaddress.ip_address(host.strip('[]')))
            require(len(set(ips.values()))==5,'Distinct signed VPN endpoints required')
            enrollment=contents['keys/apqe/enrollment.json'][1]
            require(next(e for e in entries if e['node_address']==address)['enrollment_sha256']==enrollment,
                    'Signed transport enrollment differs from local custody')
            vpn=self.vpn_status();live=status(self.root)
            require(vpn['connected'] is True and vpn['server_bound'] is True,'Current VPN binding required')
            own=vpn['server_binding'];ip=str(ipaddress.ip_address(own['ip']))
            require(ip==ips[address] and live['publicKey']==own['wireguard_public_key']
                    and str(ipaddress.ip_interface(live['netbirdIp']).ip)==ip,'Live VPN identity differs from signed endpoint')
            provider_path=self.control/'authorization/inputs/vpn-provider.json'
            provider_raw=self.direct(provider_path,True,16384).read_bytes()
            provider_pin=hashlib.sha256(provider_raw).hexdigest()
            require(policy.get('authorization_files',{}).get('vpn-provider.json')==provider_pin,'Independent VPN provider approval required')
            provider=json.loads(provider_raw)
            from vpn_authorization import network_scope
            network_scope(provider,{'network_id':receipt['network_id'],'chain_id':receipt['chain_id'],
                                    'formation_sha256':policy.get('validator_formation_sha256')})
            peers=self.commissioning_vpn_peers(live,ips,online,address)
            selection,_=self.formation_context()
            result={'schema':'nodenetwork-commissioning-observation-v1','observed_at_unix':int(time.time()),
                'target':policy['engineering_target'],'manifest_sha256':receipt['package_sha256'],
                'provider_report_sha256':config['aegis_provider']['authenticated_report_sha256'],
                'vpn_provider_sha256':provider_pin,'network_id':receipt['network_id'],'chain_id':str(receipt['chain_id']),
                'formation_sha256':selection['formation_sha256'],'address':address,'enrollment_sha256':enrollment,
                'public_file_sha256':{name:pins['network/'+name] for name in PUBLIC},'commissioning_file_sha256':pins,
                'validator_addresses':roster,'registry_peer_ips':ips,
                'vpn_binding':{'account_id':provider['account_id'],'peer_id':own['peer_id'],'ip':ip,
                    'wireguard_public_key':own['wireguard_public_key'],'enrollment_sha256':vpn['enrollment_sha256'],
                    'server_binding_sha256':vpn['server_binding_sha256']},'peers':peers}
            if online_addresses is not None:
                result.update(schema='nodenetwork-commissioning-observation-v2',online_addresses=online,
                              frozen_voting_weights=weights,observation_kind='prestart_vpn' if online else 'metadata_only')
            return result

    def commissioning_vpn_peers(self,live,ips,online,address):
        from synergy_linux import native
        from vpn import status
        def key(value):
            require(isinstance(value,str) and len(value)==44,'Canonical VPN public identity required')
            raw=base64.b64decode(value,validate=True)
            require(len(raw)==32 and base64.b64encode(raw).decode()==value,'Canonical VPN public identity required')
            return value
        def inventory(sample):
            details=sample['peers']['details']
            require(isinstance(details,list) and len(details)<=1024,'Bounded native VPN peer inventory required')
            return [(str(ipaddress.ip_interface(peer['netbirdIp']).ip),peer) for peer in details]
        if not online:return {}
        key(live['publicKey'])
        before=inventory(live);expected={}
        for other in online:
            if other==address:continue
            matches=[peer for ip,peer in before if ip==ips[other]]
            require(len(matches)==1,'Exact connected VPN peer identity required')
            expected[other]=key(matches[0]['publicKey'])
        for other in expected:
            routes=json.loads(native(['ip','-j','route','get',ips[other],'from',ips[address]],timeout=4))
            require(isinstance(routes,list) and len(routes)==1 and routes[0].get('dev')=='wt0','Peer route must use wt0')
            # A cold lazy connection may consume the first packet. One finite
            # three-packet probe still requires an actual response, never retry.
            native(['ping','-n','-I','wt0','-c','3','-W','2',ips[other]],timeout=9)
        final=status(self.root)
        require(final['management']['connected'] is True and final['signal']['connected'] is True
                and final['publicKey']==live['publicKey']
                and str(ipaddress.ip_interface(final['netbirdIp']).ip)==ips[address],
                'Live VPN identity differs from signed endpoint')
        after=inventory(final);peers={}
        for other,expected_key in expected.items():
            matches=[peer for ip,peer in after if ip==ips[other]]
            require(len(matches)==1 and matches[0]['status']=='Connected'
                    and key(matches[0]['publicKey'])==expected_key,'Exact connected VPN peer identity required')
            peers[other]={'ip':ips[other],'wireguard_public_key':matches[0]['publicKey'],
                          'interface':'wt0','reachable':True}
        return peers

    def commissioning_readiness(self, *, locked=False):
        from apqe_layout import READINESS_FILE,validate_commissioning_readiness
        path=self.control/'authorization/inputs'/READINESS_FILE
        raw=self.direct(path,True,128*1024).read_bytes();pin=hashlib.sha256(raw).hexdigest()
        require(self.policy().get('authorization_files',{}).get(READINESS_FILE)==pin,
                'Readiness requires independent native approval','authorization_required')
        value=json.loads(raw)
        require(raw==canonical(value),'Canonical reviewed readiness bytes required')
        validate_commissioning_readiness(value,self.commissioning_observation(locked=locked,online_addresses=value.get('online_addresses') if value.get('schema')=='nodenetwork-commissioning-readiness-v2' else None),int(time.time()))
        return pin

    def diagnostics(self):
        import lifecycle as life
        from synergy_linux import native
        receipt=self.public_json(self.root/'installation.json')
        plan=life._integration_plan(self.root)
        owned=life._attributed_units(self.root,plan) if plan else {}
        services={}
        for label,unit in (('node','synergy-node.service'),('vpn','synergy-vpn.service')):
            state=owned.get(unit)
            if state is None:
                services[label]=None
                continue
            service={'state':state['ActiveState'] if state.get('ActiveState') in
                     {'active','inactive','failed','activating','deactivating','reloading','maintenance','refreshing'} else None,
                     'pid':exact_count(state.get('MainPID')),'restarts':None,'memory_bytes':None,'cpu_usage_ns':None}
            try:
                raw=native(['/usr/bin/systemctl','show',unit,'--property=NRestarts,MemoryCurrent,CPUUsageNSec'],timeout=4)
                props=dict(line.split(b'=',1) for line in raw.splitlines() if b'=' in line)
                for output,key in (('restarts',b'NRestarts'),('memory_bytes',b'MemoryCurrent'),('cpu_usage_ns',b'CPUUsageNSec')):
                    service[output]=exact_count(props.get(key,b'').decode('ascii'))
            except (ValueError,OSError,subprocess.SubprocessError): pass
            services[label]=service
        storage=os.statvfs(self.root)
        return {'schema':'nodenetwork-diagnostics-v1','observed_at_ms':int(time.time()*1000),
                'installation':{'role':receipt['role'],'network_id':receipt['network_id'],
                                'node_name':receipt['node_name'],'chain_id':str(receipt['chain_id']),
                                'package_sha256':receipt['package_sha256']},
                'services':services,'storage':{'capacity_bytes':exact_count(storage.f_blocks*storage.f_frsize),
                                               'available_bytes':exact_count(storage.f_bavail*storage.f_frsize)},
                'log':log_summary(self.root)}

    def target(self):
        supported=platform.system()=='Linux' and platform.machine()=='x86_64'
        try: policy=self.policy(); qualified=set(policy['qualified_operations']); blocker=None
        except (Refused,OSError,ValueError): policy={}; qualified=set(); blocker='Host controller policy is not enrolled or valid'
        from canary_rpc_relay import gateway_target_available
        target_owner=gateway_target_available(self)
        installed_role=None
        if self.exists('installation.json'):
            try:
                from lifecycle import _sealed_receipt
                role=_sealed_receipt(self.root)[0].get('role')
                if role in ('validator','rpc_gateway'):installed_role=role
            except (ValueError,OSError,KeyError,TypeError):pass
        operations=[]
        for op in sorted(READS | MUTATIONS):
            reason=None if op in READS else blocker or ('Operation has not passed host qualification' if op not in qualified else None)
            if op=='upgrade_native_preflight' and 'runtime_probe.py' not in policy.get('engine_files',{}):
                reason='Authenticated candidate runtime probe engine required'
            if op=='boot_policy' and (not (self.root/'data').is_dir() or (self.root/'data').is_symlink()):
                reason='Commission the active validator before boot policy changes'
            if op.startswith('guest_') and op!='guest_resources' and not isinstance(policy.get('managed_guest'),dict):
                reason='Independently approved guest image, toolchain and resources required'
            if (op.startswith(('gateway_target_','gateway_install')) or op=='gateway_vpn_preflight') and not target_owner:
                reason='Qualified gateway target owner and exact signed origin required'
            if op.startswith('gateway_admission_') and op in MUTATIONS:
                from canary_rpc_relay import gateway_owner_available
                if not gateway_owner_available(self):reason='Qualified role-aware gateway issuer and installed signed formation required'
            if not supported and op!='target': reason='Linux x86_64 target required'
            operations.append({'operation':op,'kind':'read' if op in READS else 'mutation','available':reason is None,'blocker':reason})
        return {'controllerVersion':1,'platform':platform.system().lower(),'architecture':platform.machine(),
                'root':str(self.root),'installed':(self.root/'installation.json').exists(),'installed_role':installed_role,
                'localValidatorSupported':supported,'communityEnrollment':False,'operations':operations}

    def inventory(self):
        from lifecycle import _reject_installation_mounts
        _reject_installation_mounts(self.root)
        result=[]
        for current, dirs, files in os.walk(self.root,followlinks=False):
            for name in sorted(dirs+files):
                path=Path(current)/name; st=path.lstat()
                require(not stat.S_ISLNK(st.st_mode),'Installation contains symlink')
                require(len(result)<20000,'Inventory exceeds bound')
                result.append({'path':path.relative_to(self.root).as_posix(),
                               'type':'directory' if stat.S_ISDIR(st.st_mode) else 'socket' if stat.S_ISSOCK(st.st_mode) else 'file',
                               'bytes':st.st_size})
        return {'root':str(self.root),'members':result,'outsideRootAuditComplete':False}

    def dispatch(self, request):
        from synergy_linux import install, native, read, safe_root
        import lifecycle as life
        op,p=request['operation'],request['parameters']
        if op=='target': return self.target()
        require(platform.system()=='Linux' and platform.machine()=='x86_64','Linux x86_64 target required','unsupported_target')
        if op=='upgrade_native_preflight':
            require('runtime_probe.py' in self.policy().get('engine_files',{}),'Authenticated runtime probe engine required','qualification_required')
            control_inventory(self.root)
            from runtime_probe import upgrade_native_preflight
            return upgrade_native_preflight(self,p)
        if op in ('register','start','stop','restart','health') and self.exists('installation.json') and self.public_json(self.root/'installation.json').get('role')=='rpc_gateway':
            from canary_rpc_relay import gateway_lifecycle
            return gateway_lifecycle(self,request)
        if op=='inventory': return self.inventory()
        if op=='boot_policy_status':return self.boot_policy_status()
        if op=='boot_policy':return self.boot_policy(request)
        if op=='commissioning_observation':return self.commissioning_observation(online_addresses=p.get('online_addresses'))
        # Enrollment/grant readback is required before the first installation.
        # Its own exact engine/policy checks run without inventing a receipt.
        if op=='gateway_vpn_preflight':
            from canary_rpc_relay import gateway_vpn_preflight
            return gateway_vpn_preflight(self,p)
        if op.startswith('gateway_target_'):
            from canary_rpc_relay import gateway_target
            return gateway_target(self,request)
        if op in ('gateway_install','gateway_install_preflight','gateway_install_status'):
            from canary_rpc_relay import gateway_install
            return gateway_install(self,request)
        if op.startswith('gateway_admission_'):
            from canary_rpc_relay import gateway_admission
            return gateway_admission(self,request)
        if op=='authorization_status':
            control_inventory(self.root)
            record=self.policy().get('engineering_authorization')
            provider_report=None
            if self.exists('installation.json'):
                _,sealed=life._sealed_receipt(self.root)
                provider_report=sealed['files'].get('lib/apqe/build-report.json')
            return {'schema':'nodenetwork-engineering-authorization-status-v1','authorization':record,
                    'initial_sha256':self.policy().get('engineering_initial_authorization_sha256'),
                    'selection':engineering_effective_selection(self.root,self.policy()),
                    'initial_selection':self.policy().get('engineering_selection'),
                    'update':self.policy().get('engineering_update'), 'target':self.policy().get('engineering_target'),
                    'formation_sha256':self.policy().get('validator_formation_sha256'),
                    'genesis_pins':self.policy().get('validator_identity_network'),
                    'commissioning_file_sha256':self.policy().get('validator_commissioning_files'),
                    'provider_report_sha256':provider_report,
                    'pending_grants':[path.stem for path in (self.control/'grants').iterdir() if self.public_json(path,True).get('expires_at',0)>time.time()]}
        if op in ('install','install_preflight','upgrade','upgrade_preflight'):
            package,manifest,approval=self.approved_package(p,bootstrap=op.startswith('install'))
            if op.startswith('install'):
                require(approval.get('networks',{}).get(p['network_id'])==p['chain_id'], 'Network not approved for selected release','qualification_required')
                if op=='install_preflight': return {'packageVerified':True,'release':manifest['release_id'],'root':str(self.root),'networkSelectionApproved':True,'genesisAuthorityVerified':False,'activationAuthorized':False}
            elif op=='upgrade_preflight':
                life._sealed_receipt(safe_root(self.root))
                from guest_lifecycle import require_upgrade_compatible
                from conformance import installed
                require_upgrade_compatible(self.root,manifest)
                installed(self.root,host=life._integration_plan(self.root) is not None,
                          stage=life._installation_stage(self.root),
                          schema=self.public_json(package/'assets/node-config.schema.json'),
                          allow_legacy_integrations=True,pending_upgrade_sha256=p['manifest_sha256'])
                return {'packageVerified':True,'release':manifest['release_id'],'automaticRestart':False}
        else: safe_root(self.root)
        if op=='guest_resources':
            from guest_lifecycle import resource_file_pins,operator_public_key
            with life._lifecycle_lock(self.root):
                receipt,manifest=life._sealed_receipt(self.root)
                require('guest' not in self.policy().get('engineering_target',{}),'Guest resources require a physical target')
                files=resource_file_pins(manifest)
                return {'schema':'nodenetwork-guest-resources-v1','release_id':manifest['release_id'],
                    'manifest_sha256':receipt['package_sha256'],
                    'resource_manifest_sha256':manifest['managed_guest_resources']['manifest_sha256'],
                    'archive_limit_bytes':manifest['managed_guest_resources']['archive_limit_bytes'],
                    'files':files,'operator_ssh_public_key':operator_public_key(self.root)}
        if op.startswith('guest_'):
            from guest_lifecycle import GuestManager
            with life._lifecycle_lock(self.root):
                life._sealed_receipt(self.root)
                guest=GuestManager(self.root,self.policy())
                if op=='guest_preflight': return guest.preflight(p)
                def guest_status():
                    observed=guest.status({'guest_id':p['guest_id']});stop=guest.receipt().get('stop',{}) if observed['exists'] else {}
                    expected=request_digest({'version':1,'operation':'guest_stop','parameters':{'guest_id':p['guest_id']}})
                    observed.update({'stop_verified':False,'stop_request_sha256':None,'stopped_resume_request_sha256':None})
                    if stop.get('request_sha256')==expected and observed.get('pid')==0 and observed.get('service_state') in ('inactive','failed'):
                        grant=self.control/'grants'/(expected+'.json');audit=self.control/'audit.jsonl'
                        if not grant.exists() and not grant.is_symlink() and audit.exists():
                            audit=self.direct(audit,True);require(audit.stat().st_size<=1024*1024,'Guest stop audit exceeds bound')
                            rows=audit.read_bytes().splitlines();require(len(rows)<=4096,'Guest stop audit exceeds bound')
                            found=[json.loads(row) for row in rows if json.loads(row).get('request_sha256')==expected]
                            require(all(set(row)=={'operation','request_sha256','time'} and row['operation']=='guest_stop' and type(row['time']) is int and 0<=row['time']<=int(time.time()) for row in found),'Guest stop audit differs')
                            if found:observed.update({'stop_verified':True,'stop_request_sha256':expected,'stopped_resume_request_sha256':stop.get('resume_request_sha256')})
                    return observed
                if op=='guest_status': return guest_status()
                if op=='guest_boot_diagnostics': return guest.boot_diagnostics(p)
                if op=='guest_resume':
                    from synergy_linux import digest
                    key=request_digest(request);prior=guest.receipt().get('resume',{})
                    grant=self.control/'grants'/(key+'.json')
                    pin=prior.get('grant_sha256') if prior.get('request_sha256')==key else digest(self.direct(grant,True))
                    return guest.resume(p,key,pin,lambda:self.authorize_guest_resume(request,pin))
                if op=='guest_create': return guest.create(p,request_digest(request),lambda:self.authorize(request))
                if op=='guest_stop':
                    guest.stop(p,lambda:self.authorize(request),request_digest(request));return guest_status()
                if op=='guest_remove': return guest.remove(p,request_digest(request),lambda:self.authorize(request))
        if op=='health': return json.loads(native([self.root/'bin/synergy-node','health','--admin-socket',self.root/'run/admin.sock']))
        if op=='vpn_status': return self.vpn_status()
        if op=='vpn_unused_preflight': return self.vpn_unused_preflight()
        if op=='vpn_cancel_unused': return self.vpn_cancel_unused(request)
        if op=='vpn_stop_status': return self.vpn_stop_status()
        if op=='vpn_stop': return self.vpn_stop(request)
        if op=='vpn_resume': return self.vpn_resume(request)
        if op=='vpn_resume_status': return self.vpn_resume_status()
        if op=='vpn_diagnostics': return self.vpn_diagnostics()
        if op=='vpn_enroll': return self.vpn_enroll(request)
        if op=='vpn_bind': return self.vpn_bind(request)
        if op=='vpn_retire': return self.vpn_retire(request)
        if op=='identity_preflight': return self.identity_preflight()[0]
        if op=='identity_status': return self.identity_status()
        if op=='identity_generate': return self.identity_generate(request)
        if op.startswith('treasury_send_'):
            from treasury_send import run
            return run(self,request)
        if op.startswith('treasury_'): return self.treasury(request)
        if op.startswith('network_formation_'): return self.network_formation(request)
        if op.startswith('network_transport_'): return self.network_transport(request)
        if op=='formation_preflight':
            with life._lifecycle_lock(self.root): return self.formation_preflight()[0]
        if op=='formation_status': return self.formation_status()
        if op=='formation_export': return self.formation_status(export=True)
        if op=='formation_prepare': return self.formation_prepare(request)
        if op=='genesis_stage_preflight': return self.genesis_stage()
        if op=='genesis_stage': return self.genesis_stage(request)
        if op=='genesis_binding_preflight': return self.genesis_binding()
        if op=='genesis_bind': return self.genesis_binding(request)
        if op=='diagnostics': return self.diagnostics()
        if op=='recovery_preflight':
            return {'qualified':False,'blocker':'Checkpoint import is not exposed until the selected release recovery procedure is qualified','certifiedStateChanged':False}
        if op=='uninstall_preflight':
            with life._lifecycle_lock(self.root):
                life.require_vpn_retired_for_removal(self.root)
                host=host_removal_plan(self.root)
                return {'root':str(self.root),'inventory':self.inventory(),'destructive':True,
                        'managedAccountRemoval':host is not None,'forensicErasureProven':False}
        if op=='commission' and (self.exists(FORMATION_CUSTODY) or self.exists(FORMATION_INTENT)):
            from apqe_layout import FORMATION_PUBLIC_INPUTS
            self.require_bound_validator_vpn()
            binding=self.genesis_binding()
            require(binding['bound'] is True,'Bind the existing custody to authenticated Genesis before commissioning')
            pins=self.policy().get('validator_commissioning_files')
            require(isinstance(pins,dict) and set(pins)==FORMATION_PUBLIC_INPUTS
                    and all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in pins.values()),
                    'Exact host approval for public commissioning inputs required','authorization_required')
            readiness_sha256=self.commissioning_readiness()
            directory=(self.control/'authorization/inputs/commissioning' if self.policy().get('authorization_files') else self.root/'tmp/commissioning-public')
            return life.commission(self.root,self.root/'tmp/commissioning',formation_public_pins=pins,
                                   formation_public_source=directory,readiness_sha256=readiness_sha256,authorize=lambda:self.authorize(request))
        if op in ('register','start','restart'):
            if op in ('start','restart'):
                self.require_bound_validator_vpn()
            from root_guard import check_registration
            check_registration(self.policy().get('root_guard_sha256'))
        if op in ('start','restart'):
            # Archive recovery inside startup validation is not a pure read.
            # Check the exact live grant first, then recheck and consume only
            # after every startup invariant succeeds under the lifecycle lock.
            self.authorize(request,consume=False)
            life.start_check(self.root,authorize=lambda:self.authorize(request))
        else:
            self.authorize(request)
        if op=='install':
            # The canonical installer independently rejects nonempty roots.
            return install(package,self.root,'validator',p['network_id'],p['chain_id'],p['node_name'],staged_master_sha256=p['manifest_sha256'])
        if op=='upgrade': return life.upgrade(self.root,package)
        if op=='commission': return life.commission(self.root,self.root/'tmp/commissioning')
        if op=='register': return life.register(self.root)
        if op in ('start','restart','stop'):
            life.mutate_owned_service(self.root,op,'synergy-node.service')
            return {'requested':op,'healthNotInferred':True}
        if op=='uninstall': return life.remove(self.root,str(self.root))
        raise Refused('invalid_request','Unsupported operation')


def control_inventory(root):
    """Exact host-enrolled namespace. No input grants its own authority."""
    c=Controller(root); policy=c.policy()
    pins=policy.get('engine_files')
    require(isinstance(pins,dict) and ENGINE_MODULES<=set(pins)<=ENGINE_MODULES|{'runtime_probe.py'},
            'Complete pinned controller engine required','qualification_required')
    approved={'tmp/controller/policy.json','tmp/controller/controller.py'}
    for name,expected in pins.items():
        require(isinstance(expected,str) and re.fullmatch('[a-f0-9]{64}',expected),'Malformed engine pin')
        path=c.control/name if name=='controller.py' else c.control/'tools'/name
        c.direct(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest()==expected,'Controller engine bytes differ')
        approved.add(path.relative_to(root).as_posix())
    if (c.control/'gateway-install-request.json').exists() or (c.control/'gateway-install-request.json').is_symlink():
        raw=c.direct(c.control/'gateway-install-request.json',True,16384).read_bytes();request=parse_request(raw)
        require(request['operation']=='gateway_install','Unexpected gateway installation record')
        from canary_rpc_relay import _gateway_target_consumed
        _gateway_target_consumed(c,'gateway_install',request_digest(request))
        approved.add('tmp/controller/gateway-install-request.json')
    if (c.control/'audit.jsonl').exists():
        c.direct(c.control/'audit.jsonl',True);approved.add('tmp/controller/audit.jsonl')
    if c.vpn_stage() is not None:
        approved.add('tmp/controller/'+VPN_ENROLLMENT)
    if (c.control/HOST_REMOVAL).exists():
        c.direct(c.control/HOST_REMOVAL,True);approved.add('tmp/controller/'+HOST_REMOVAL)
    host_files=policy.get('host_files',{})
    require(not host_files or set(host_files)=={'authorized_keys','sshd.conf','sudoers'},'Unexpected host registration inventory')
    for name,expected in host_files.items():
        path=c.direct(c.control/'host'/name,True)
        require(isinstance(expected,str) and hashlib.sha256(path.read_bytes()).hexdigest()==expected,'Host registration drift')
        approved.add(path.relative_to(root).as_posix())
    grants=c.control/'grants'
    require(grants.is_dir() and not grants.is_symlink(),'Grant directory required')
    for path in grants.iterdir():
        require(re.fullmatch('[a-f0-9]{64}\.json',path.name),'Unexpected controller grant member')
        c.direct(path,True);approved.add('tmp/controller/grants/'+path.name)
    directories={'tmp/controller','tmp/controller/grants','tmp/controller/tools'}
    if host_files:directories.add('tmp/controller/host')
    authorization=policy.get('authorization_files',{})
    require(isinstance(authorization,dict),'Malformed authorization inventory')
    # Fixed input names only. Never grants arbitrary caller-selected paths.
    AUTHORIZATION_FILES={'gateway-purpose.json':16384,'commissioning-readiness.json':128*1024,'managed-guest.json':16384,'formation-context.json':4096,'vpn-ca.pem':128*1024,'vpn-provider.json':16384,
        'vpn-server-binding.json':16384,'vpn-retirement.json':16384,'vpn-unused-cancellation.json':16384,
        'commissioning/config/node.json':1024*1024,'commissioning/config/start-authorized.json':65536,
        **{'commissioning/network/'+name:limit for name,limit in {
            'genesis.json':4*1024*1024,'authority.json':1024*1024,'authority-root.pub':8192,
            'network-manifest.json':1024*1024,'transport-registry.json':1024*1024,'transport-root.pub':8192}.items()}}
    require(set(authorization)<=set(AUTHORIZATION_FILES)-{VPN_ENROLLMENT},'Unexpected authorization input')
    for name,pin in authorization.items():
        path=c.direct(c.control/'authorization/inputs'/name,True,AUTHORIZATION_FILES[name])
        require(isinstance(pin,str) and hashlib.sha256(path.read_bytes()).hexdigest()==pin,'Authorization input drift')
        approved.add(path.relative_to(root).as_posix())
        for parent in path.parents:
            if parent==c.control:break
            directories.add(parent.relative_to(root).as_posix())
    actual={p.relative_to(root).as_posix() for p in c.control.rglob('*')}
    require(actual==(approved|directories)-{'tmp/controller'},'Unexpected controller member')
    return approved,directories


def host_removal_plan(root):
    c=Controller(root);policy=c.policy()
    control_inventory(root)
    if not policy.get('host_files'):
        require('host_account' not in policy and not (c.control/HOST_REMOVAL).exists(),
                'Managed host account lacks its registration inventory')
        return None
    pin=policy.get('host_account')
    require(isinstance(pin,dict) and set(pin)=={'uid','gid','label'} and type(pin['uid']) is int
            and 0<pin['uid']<2**32-1 and pin['gid']==65534 and isinstance(pin['label'],str)
            and re.fullmatch(r'Synergy NodeNetwork [a-f0-9]{32}',pin['label']),
            'Managed host account has no bootstrap attribution; independent operator review required')
    intent={'format':'synergy-nodenetwork-host-removal-v1','root':str(root),'account':pin}
    marker=c.control/HOST_REMOVAL
    resuming=marker.exists() or marker.is_symlink()
    if resuming:
        require(c.public_json(marker,True)==intent,'Host retirement intent differs')
    # Shadow's USERGROUPS_ENAB can make userdel remove a same-named group even
    # without --remove. No group was created by bootstrap, so refuse any match.
    try:grp.getgrnam(HOST_ACCOUNT)
    except KeyError:pass
    else:raise Refused('operation_refused','Conflicting host group; independent operator review required')
    try:entry=pwd.getpwnam(HOST_ACCOUNT)
    except KeyError:entry=None
    if entry is None:
        require(resuming,'Managed host account is absent before retirement')
    else:
        require((entry.pw_uid,entry.pw_gid,entry.pw_gecos,entry.pw_dir,entry.pw_shell)==
                (pin['uid'],pin['gid'],pin['label'],'/nonexistent','/bin/sh'),
                'Managed host account attribution differs')
        require([entry.pw_name for entry in pwd.getpwall() if entry.pw_uid==pin['uid']]==[HOST_ACCOUNT],
                'Managed host account UID is shared or nonlocal')
    links=[]
    for name,path in HOST_LINKS.items():
        if resuming and not path.exists() and not path.is_symlink():continue
        require(path.is_symlink() and os.readlink(path)==str(c.control/'host'/name),
                'Host registration link drift')
        links.append(path)
    return marker,intent,links,entry is not None


def remove_host_registrations(root):
    plan=host_removal_plan(root)
    if plan is None:return []
    marker,intent,links,has_account=plan
    if not marker.exists():
        with marker.open('xb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(canonical(intent));stream.flush();os.fsync(stream.fileno())
        fd=os.open(marker.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    for path in links:path.unlink()
    subprocess.run(['/usr/sbin/sshd','-t'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
    subprocess.run(['systemctl','reload','ssh.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
    if has_account:
        # The authenticated request itself still has an SSH session under this
        # dedicated identity. Remove only its OS account, never a home/group.
        subprocess.run(['/usr/sbin/userdel','--force',HOST_ACCOUNT],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
    require(host_removal_plan(root)==(marker,intent,[],False),
            'Managed host account or registration remains')
    return []


def serve(raw, controller=None):
    try:
        request=parse_request(raw)
        result=(controller or Controller()).dispatch(request)
        return {'version':1,'ok':True,'result':result}
    except Refused as error:
        return {'version':1,'ok':False,'error':{'code':error.code,'message':str(error)}}
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        # Provider output, custody paths and arbitrary filesystem diagnostics do
        # not cross into the graphical frontend.
        return {'version':1,'ok':False,'error':{'code':'operation_refused','message':'Controller validation or lifecycle operation failed'}}


def main():
    require(os.geteuid()==0,'Controller requires the enrolled privileged host interface','authorization_required')
    require(len(sys.argv)==1,'Controller accepts JSON stdin only','invalid_request')
    control_inventory(ROOT)
    sys.modules['controller']=sys.modules[__name__]
    sys.path.insert(0,str(ROOT/'tmp/controller/tools'))
    os.environ.update(HOME=str(ROOT),TMPDIR=str(ROOT/'tmp'),XDG_CONFIG_HOME=str(ROOT/'vpn'),
                      XDG_CACHE_HOME=str(ROOT/'cache'),NB_STATE_DIR=str(ROOT/'vpn'),
                      NB_DNS_STATE_FILE=str(ROOT/'vpn/state.json'))
    # Only the separately framed guest transport switches stdout to raw SSH.
    # All tools became importable only after the complete engine was verified.
    import guest_lifecycle
    prefix=guest_lifecycle.read_guest_prefix(sys.stdin.fileno())
    if prefix==guest_lifecycle.GUEST_SSH_MAGIC:
        try:
            guest_lifecycle.serve_guest_ssh(ROOT,Controller().policy(),sys.stdin.fileno(),sys.stdout.fileno())
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
            print('Managed guest channel refused',file=sys.stderr)
        return
    raw=prefix+sys.stdin.buffer.read(MAX_GENESIS_STAGE_REQUEST+1-len(prefix))
    print(json.dumps(serve(raw),sort_keys=True))


if __name__=='__main__':
    try: main()
    except (Refused,OSError,ValueError,KeyError,TypeError):
        print(json.dumps({'version':1,'ok':False,'error':{'code':'authorization_required','message':'Enrolled controller validation failed'}}))
