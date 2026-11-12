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

ROOT = Path('/opt/Synergy')
MAX_REQUEST = 16384
MAX_GENESIS_STAGE_REQUEST = 12*1024*1024
GENESIS_FILES = {'genesis.json':4*1024*1024,'authority.json':1024*1024,'authority-root.pub':8192}
ENGINE_MODULES = frozenset(('controller.py','synergy_linux.py','lifecycle.py','conformance.py',
                            'apqe_layout.py','vpn.py','canary_rpc_relay.py'))
READS = frozenset(('target','inventory','health','install_preflight','upgrade_preflight',
                  'recovery_preflight','uninstall_preflight','vpn_status','diagnostics','identity_preflight','identity_status',
                  'formation_preflight','formation_status','formation_export','genesis_stage_preflight','genesis_binding_preflight'))
MUTATIONS = frozenset(('install','commission','register','vpn_enroll','start','stop','restart','upgrade','uninstall','identity_generate',
                       'formation_prepare','genesis_stage','genesis_bind'))
FORMATION_CONTEXT = 'tmp/formation-context.json'
FORMATION_CUSTODY = 'tmp/pre-genesis-validator'
FORMATION_INTENT = 'tmp/formation-prepare-request.json'
GENESIS_BIND_INTENT = 'tmp/genesis-bind-request.json'
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
             if request['operation']=='genesis_stage' else canonical(request))
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
    require(operation=='genesis_stage' or len(raw)<=MAX_REQUEST,'Request exceeds operation limit','invalid_request')
    expected = INSTALL if operation in ('install','install_preflight') else SELECT if operation in ('upgrade','upgrade_preflight') else {'confirmation'} if operation == 'uninstall' else {'genesis_sha256'} if operation in ('identity_generate','genesis_bind') else {'formation_sha256'} if operation=='formation_prepare' else {'artifacts'} if operation=='genesis_stage' else set()
    require(set(parameters) == expected, 'Unexpected operation parameters', 'invalid_request')
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
    for name in expected & {'genesis_sha256','formation_sha256'}:
        pin=parameters[name]
        require(isinstance(pin,str) and re.fullmatch('[0-9a-f]{64}',pin),'Exact public artifact SHA-256 required','invalid_request')
    return value


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

    def authorize(self, request, enrollment_pin=None):
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
        if request['operation']=='vpn_enroll':
            require(enrollment_pin is not None and grant.get('enrollment_sha256')==enrollment_pin,
                    'One-time host grant does not bind this VPN enrollment','authorization_required')
        # Consume before executing. Ambiguous outcomes need observation and a
        # fresh operator grant, never blind resubmission or replay.
        self.audit(request)
        grant_path.unlink()
        return key

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
                and not self.exists(FORMATION_CUSTODY) and not self.exists(FORMATION_INTENT),
                'Existing custody, incomplete generation or node data must be reconciled before identity provisioning')
        return self.identity_network()

    def exists(self,relative):
        path=self.root/relative
        return path.exists() or path.is_symlink()

    def formation_context(self):
        from lifecycle import _sealed_receipt
        receipt,manifest=_sealed_receipt(self.root)
        require(receipt['role']=='validator','A validator package is required')
        self.direct(self.root/'installation.json',True)
        pin=self.policy().get('validator_formation_sha256')
        require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),
                'Host operator has not pinned a formation context','authorization_required')
        path=self.direct(self.root/FORMATION_CONTEXT,True)
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
        result=json.loads(native([self.root/'bin/synergy-keytool',command,self.root/FORMATION_CONTEXT,pin,
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
        value=json.loads(native([self.root/'bin/synergy-keytool',command,self.root/FORMATION_CONTEXT,
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
            selection,flags=self.formation_context()
            pins=self.genesis_pins()
            formation=self.formation_result(selection,flags,'verify-validator-formation')
            if request is None:
                return {'schema':'nodenetwork-genesis-stage-policy-v1','address':formation['address'],
                        **self.genesis_pin_result(pins)}
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
                verified=self.genesis_review('review-validator-genesis-binding',selection,flags,pins,work)
                require(not verified['bound'] and verified['address']==formation['address'],
                        'Genesis does not admit the exact prepared local custody')
                write_new(work/GENESIS_STAGE_RECEIPT,{'format':'nodenetwork-genesis-stage-request-v1',
                          'request_sha256':request_sha256,**self.genesis_pin_result(pins)})
                work.rename(self.root/GENESIS_STAGE)
                sync_directory(work.parent)
            finally:
                if work.exists(): shutil.rmtree(work)
            return {'schema':'nodenetwork-genesis-stage-v1','address':formation['address'],
                    **self.genesis_pin_result(pins),'request_sha256':request_sha256,
                    'genesis_authority_verified':True,'membership_verified':True,'staged':True}

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

    def genesis_binding(self,request=None):
        from lifecycle import _lifecycle_lock
        with _lifecycle_lock(self.root):
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

    def identity_network(self):
        from lifecycle import _sealed_receipt
        from synergy_linux import digest, native, read
        receipt, manifest = _sealed_receipt(self.root)
        require(receipt['role']=='validator','A validator package is required')
        self.direct(self.root/'installation.json',True)
        pins = self.genesis_pins()
        staged = self.root/GENESIS_STAGE
        files = {name:self.direct(staged/name,maximum=limit) for name,limit in GENESIS_FILES.items()}
        require(all(digest(path)==pins[name] for name,path in files.items()),'Approved identity network inputs changed')
        network=read(files['genesis.json'])['unsigned']['network']
        require(network['chain_id']==receipt['chain_id'] and network['network_id']==receipt['network_id'],
                'Signed Genesis selects a different installation network')
        report = 'lib/apqe/build-report.json'
        flags = ['--apqe-report',self.root/report,'--apqe-report-sha256',manifest['files'][report]]
        native([self.root/'bin/synergy-genesis','verify-binding',files['genesis.json'],
                files['authority-root.pub'],files['authority.json'],*flags])
        return {'network_id':receipt['network_id'],'chain_id':str(receipt['chain_id']),
                'genesis_sha256':pins['genesis.json'],'genesis_authority_verified':True},flags

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
            if not path.exists() and not path.is_symlink(): return {'pending':False}
            try:
                selection, flags = self.identity_network()
                return {'pending':True, **self.checked_custody(selection,flags,'verify-validator-custody')}
            except (Refused,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                raise Refused('reconciliation_required','Pending custody could not be verified. Preserve the files and reconcile locally before trying again.') from None

    def identity_generate(self, request):
        from lifecycle import _lifecycle_lock
        with _lifecycle_lock(self.root):
            selection, flags = self.identity_preflight()
            pin = selection['genesis_sha256']
            require(request['parameters']['genesis_sha256']==pin,'The reviewed Genesis artifact changed; inspect it again')
            self.authorize(request)
            return self.checked_custody(selection,flags,'provision-validator-custody')

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
        return {'schema':'nodenetwork-vpn-status-v1','service_registered':service is not None,
                'enrollment_staged':self.vpn_stage() is not None,'enrollment_recorded':recorded,
                'reconciliation_required':attempted and not recorded,
                'server_bound':bound,'connected':connected,'overlay_address':overlay}

    def vpn_enroll(self,request):
        import lifecycle as life
        from synergy_linux import write_new
        from vpn import enroll
        with life._lifecycle_lock(self.root):
            receipt,_=life._sealed_receipt(self.root)
            require(receipt['role']=='validator','VPN workflow requires an installed validator role')
            current=self.vpn_status()
            require(current['service_registered'] and not current['enrollment_recorded'],
                    'Register the contained VPN service before fresh enrollment')
            attempt=self.root/VPN_ATTEMPT
            require(not attempt.exists() and not attempt.is_symlink(),
                    'Prior VPN enrollment needs control-plane reconciliation','vpn_reconciliation_required')
            require(not list((self.root/'vpn').iterdir()),'Existing VPN state requires reviewed reconciliation')
            path=self.vpn_stage()
            require(path is not None,'No approved one-use VPN enrollment is staged','authorization_required')
            with path.open('rb') as stream: data=stream.read(MAX_VPN_ENROLLMENT+1)
            require(0<len(data)<=MAX_VPN_ENROLLMENT,'VPN enrollment input exceeds bound')
            self.authorize(request,hashlib.sha256(data).hexdigest())
            # Persist the fence before dispatch: the provider can consume the
            # key without returning a receipt or writing any local VPN state.
            write_new(attempt,{'format':'nodenetwork-vpn-attempt-v1'})
            life._sync_directory(attempt.parent)
            path.unlink()
            life._sync_directory(path.parent)
            try: enroll(self.root,data)
            except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
                raise Refused('vpn_reconciliation_required',
                              'VPN enrollment did not return a verified receipt. Inspect the VPN controller before issuing another credential.') from None
        return self.vpn_status()

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
        except (Refused,OSError,ValueError): qualified=set(); blocker='Host controller policy is not enrolled or valid'
        operations=[]
        for op in sorted(READS | MUTATIONS):
            reason=None if op in READS else blocker or ('Operation has not passed host qualification' if op not in qualified else None)
            if not supported and op!='target': reason='Linux x86_64 target required'
            operations.append({'operation':op,'kind':'read' if op in READS else 'mutation','available':reason is None,'blocker':reason})
        return {'controllerVersion':1,'platform':platform.system().lower(),'architecture':platform.machine(),
                'root':str(self.root),'installed':(self.root/'installation.json').exists(),
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
        if op=='inventory': return self.inventory()
        if op in ('install','install_preflight','upgrade','upgrade_preflight'):
            package,manifest,approval=self.approved_package(p,bootstrap=op.startswith('install'))
            if op.startswith('install'):
                require(approval.get('networks',{}).get(p['network_id'])==p['chain_id'], 'Network not approved for selected release','qualification_required')
                if op=='install_preflight': return {'packageVerified':True,'release':manifest['release_id'],'root':str(self.root),'networkSelectionApproved':True,'genesisAuthorityVerified':False,'activationAuthorized':False}
            elif op=='upgrade_preflight':
                life._sealed_receipt(safe_root(self.root))
                return {'packageVerified':True,'release':manifest['release_id'],'automaticRestart':False}
        else: safe_root(self.root)
        if op=='health': return json.loads(native([self.root/'bin/synergy-node','health','--admin-socket',self.root/'run/admin.sock']))
        if op=='vpn_status': return self.vpn_status()
        if op=='vpn_enroll': return self.vpn_enroll(request)
        if op=='identity_preflight': return self.identity_preflight()[0]
        if op=='identity_status': return self.identity_status()
        if op=='identity_generate': return self.identity_generate(request)
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
            host=host_removal_plan(self.root)
            return {'root':str(self.root),'inventory':self.inventory(),'destructive':True,
                    'managedAccountRemoval':host is not None,'forensicErasureProven':False}
        if op=='commission' and (self.exists(FORMATION_CUSTODY) or self.exists(FORMATION_INTENT)):
            from apqe_layout import FORMATION_PUBLIC_INPUTS
            binding=self.genesis_binding()
            require(binding['bound'] is True,'Bind the existing custody to authenticated Genesis before commissioning')
            pins=self.policy().get('validator_commissioning_files')
            require(isinstance(pins,dict) and set(pins)==FORMATION_PUBLIC_INPUTS
                    and all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in pins.values()),
                    'Exact host approval for public commissioning inputs required','authorization_required')
            self.authorize(request)
            return life.commission(self.root,self.root/'tmp/commissioning',formation_public_pins=pins)
        self.authorize(request)
        if op=='install':
            # The canonical installer independently rejects nonempty roots.
            return install(package,self.root,'validator',p['network_id'],p['chain_id'],p['node_name'],staged_master_sha256=p['manifest_sha256'])
        if op=='upgrade': return life.upgrade(self.root,package)
        if op=='commission': return life.commission(self.root,self.root/'tmp/commissioning')
        if op=='register': return life.register(self.root)
        if op in ('start','restart','stop'):
            if op!='stop': life.start_check(self.root)
            life.mutate_owned_service(self.root,op,'synergy-node.service')
            return {'requested':op,'healthNotInferred':True}
        if op=='uninstall': return life.remove(self.root,str(self.root))
        raise Refused('invalid_request','Unsupported operation')


def control_inventory(root):
    """Exact host-enrolled namespace. No input grants its own authority."""
    c=Controller(root); policy=c.policy()
    pins=policy.get('engine_files')
    require(isinstance(pins,dict) and set(pins)==ENGINE_MODULES,
            'Complete pinned controller engine required','qualification_required')
    approved={'tmp/controller/policy.json','tmp/controller/controller.py'}
    for name,expected in pins.items():
        require(isinstance(expected,str) and re.fullmatch('[a-f0-9]{64}',expected),'Malformed engine pin')
        path=c.control/name if name=='controller.py' else c.control/'tools'/name
        c.direct(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest()==expected,'Controller engine bytes differ')
        approved.add(path.relative_to(root).as_posix())
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
    print(json.dumps(serve(sys.stdin.buffer.read(MAX_GENESIS_STAGE_REQUEST+1)),sort_keys=True))


if __name__=='__main__':
    try: main()
    except (Refused,OSError,ValueError,KeyError,TypeError):
        print(json.dumps({'version':1,'ok':False,'error':{'code':'authorization_required','message':'Enrolled controller validation failed'}}))
