"""Current R1 key creation through the existing authenticated native controller.

No derivation/CBOR/crypto is duplicated here. APQE validates the full typed scope;
this layer binds its public transport to the existing exact native request grant.
"""
import base64
import binascii
import json
import os
import re
import stat
from pathlib import Path

FIELDS = frozenset(('release_id','manifest_sha256','slot_ref','role','algorithm',
    'key_generation','operation_nonce_hex','creation_scope_frame_hex',
    'creation_scope_commitment_hex','provider_report_sha256','profile_catalog_commitment_hex'))


def validate(parameters):
    if not isinstance(parameters,dict) or set(parameters)!=FIELDS:
        raise ValueError('Exact R1 creation parameters required')
    for name in ('release_id','slot_ref','role'):
        if not isinstance(parameters[name],str) or not re.fullmatch(r'[!-~]{1,120}',parameters[name]):
            raise ValueError('Bounded ASCII slot, role and release required')
    if parameters['algorithm'] not in ('ML-DSA-87','ML-DSA-65','ML-KEM-1024'):
        raise ValueError('Current role algorithm required')
    generation=parameters['key_generation']
    if not isinstance(generation,str) or not re.fullmatch(r'[1-9][0-9]{0,19}',generation) or int(generation)>2**64-1:
        raise ValueError('Canonical positive u64 generation required')
    for name,width in (('manifest_sha256',64),('operation_nonce_hex',64),
        ('provider_report_sha256',64),('creation_scope_commitment_hex',128),('profile_catalog_commitment_hex',128)):
        if not isinstance(parameters[name],str) or not re.fullmatch('[a-f0-9]{'+str(width)+'}',parameters[name]) or parameters[name]=='0'*width:
            raise ValueError('Exact distinct-width public pin required')
    frame=parameters['creation_scope_frame_hex']
    if not isinstance(frame,str) or not 2<=len(frame)<=8192 or len(frame)%2 or not re.fullmatch('[a-f0-9]+',frame):
        raise ValueError('Bounded canonical APQE scope frame required')


def run(controller,request):
    from controller import Refused, canonical, request_digest, require, sync_directory
    from lifecycle import _lifecycle_lock, _sealed_receipt
    from synergy_linux import native
    validate(request['parameters'])
    with _lifecycle_lock(controller.root):
        installation,manifest=_sealed_receipt(controller.root)
        p=request['parameters']
        require(manifest['release_id']==p['release_id'] and installation['package_sha256']==p['manifest_sha256'],
                'R1 creation request differs from authenticated installed release','qualification_required')
        require(manifest['files'].get('lib/apqe/build-report.json')==p['provider_report_sha256']
                and 'lib/apqe/r1-profile-catalog.cbor' in manifest['files'],
                'Installed R1 provider and complete profile catalog required','qualification_required')
        key=request_digest(request)
        target=controller.control/'r1-creation'/(key+'.json')
        require(not target.exists() and not target.is_symlink(),
                'Prior R1 generation dispatch requires observation; never repeat RNG','reconciliation_required')
        grant=controller.public_json(controller.control/'grants'/(key+'.json'),True)
        expires=grant.get('expires_at')
        # Existing authorize rechecks protected policy, exact grant and expiry,
        # fsyncs its audit and consumes the one-use grant before any dispatch.
        controller.authorize(request)
        directory=target.parent
        directory.mkdir(mode=0o700,exist_ok=True)
        metadata=directory.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.geteuid()
                and stat.S_IMODE(metadata.st_mode)==0o700,'Private native receipt directory required')
        receipt={'format':'synergy-native-r1-creation-v1','root':str(controller.root),
                 'request':request,'request_sha256':key,'expires_at_unix':expires}
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical(receipt));stream.flush();os.fsync(stream.fileno())
        sync_directory(directory)
        result=json.loads(native([controller.root/'bin/synergy-keytool','create-managed-r1-key',controller.root,target,key]))
        require(isinstance(result,dict) and result.get('schema')=='synergy-r1-managed-sealed-key-v1'
                and result.get('request_sha256')==key and result.get('slot_ref')==p['slot_ref']
                and result.get('key_generation')==p['key_generation']
                and result.get('stage')=='sealed_pending' and result.get('runtime_authority_granted') is False,
                'R1 native result differs; preserve custody and reconcile','reconciliation_required')
        return result


def preview(controller,request):
    """Read exact APQE semantics using installed code, without consuming a grant."""
    from controller import canonical,request_digest,require
    from lifecycle import _lifecycle_lock,_sealed_receipt
    from synergy_linux import native
    p=request['parameters'];validate(p)
    with _lifecycle_lock(controller.root):
        _sealed_receipt(controller.root)
        result=json.loads(native([controller.root/'bin/synergy-keytool',
            'inspect-managed-r1-creation',canonical(p).decode('utf-8')]))
        require(isinstance(result,dict) and set(result)=={'schema','inspection','runtime_authority_granted'}
                and result['schema']=='synergy-r1-managed-creation-preview-v1'
                and result['runtime_authority_granted'] is False,
                'Native R1 semantic preview differs')
        inspected=result['inspection']
        require(isinstance(inspected,dict) and inspected.get('authority_granted') is False
                and isinstance(inspected.get('scope'),dict)
                and inspected['scope'].get('authority_granted') is False
                and all(inspected.get(name)==p[name] for name in (
                    'release_id','slot_ref','operation_nonce_hex','manifest_sha256',
                    'provider_report_sha256','profile_catalog_commitment_hex','creation_scope_commitment_hex'))
                and all(inspected['scope'].get(name)==p[name] for name in ('role','algorithm','key_generation')),
                'Native R1 semantic preview correlation differs')
        # This identifies the prospective mutation, not this read-only request.
        # A preview never issues a grant or reserves the slot/generation.
        result['creation_request_sha256']=request_digest(
            {'version':1,'operation':'r1_identity_generate','parameters':p})
        return result


def validate_status(parameters):
    if not isinstance(parameters,dict) or set(parameters)!={'slot_ref','original_request_sha256'}:
        raise ValueError('Exact original R1 request required')
    if not isinstance(parameters['slot_ref'],str) or not re.fullmatch(r'[!-~]{1,120}',parameters['slot_ref']):
        raise ValueError('Bounded exact slot required')
    if not isinstance(parameters['original_request_sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',parameters['original_request_sha256']):
        raise ValueError('Original native request SHA256 required')


def status(controller,request):
    from controller import require
    from lifecycle import _lifecycle_lock, _sealed_receipt
    from synergy_linux import native
    p=request['parameters'];validate_status(p)
    with _lifecycle_lock(controller.root):
        _sealed_receipt(controller.root)
        result=json.loads(native([controller.root/'bin/synergy-keytool','inspect-managed-r1-key',controller.root,p['slot_ref'],p['original_request_sha256']]))
        require(isinstance(result,dict) and result.get('schema')=='synergy-r1-managed-key-status-v1'
                and result.get('slot_ref')==p['slot_ref'] and result.get('original_request_sha256')==p['original_request_sha256']
                and result.get('stage') in ('absent','generating_requires_reconciliation','sealed_pending')
                and result.get('runtime_authority_granted') is False,'Native R1 observation differs')
        return result


def controller_inventory(controller):
    """Attribute protected dispatch residue; never treat it as fresh authority."""
    from controller import parse_request,request_digest,require
    directory=controller.control/'r1-creation'
    if not directory.exists() and not directory.is_symlink(): return set(),set()
    m=directory.lstat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid==os.geteuid() and stat.S_IMODE(m.st_mode)==0o700,
            'Unsafe R1 receipt namespace')
    approved=set()
    for path in directory.iterdir():
        require(re.fullmatch('[a-f0-9]{64}\\.json',path.name),'Unexpected R1 receipt member')
        value=controller.public_json(path,True)
        require(isinstance(value,dict) and set(value)=={'format','root','request','request_sha256','expires_at_unix'}
                and value['format']=='synergy-native-r1-creation-v1' and value['root']==str(controller.root),
                'Invalid attributed R1 dispatch receipt')
        request=parse_request(json.dumps(value['request'],separators=(',',':')).encode())
        key=request_digest(request)
        require(request['operation'] in ('r1_identity_generate','r1_identity_prove','r1_identity_rebind','r1_root_approval_use') and value['request_sha256']==key
                and path.name==key+'.json' and not (controller.control/'grants'/path.name).exists(),
                'R1 dispatch receipt is not a consumed exact request')
        audit=controller.direct(controller.control/'audit.jsonl',True).read_bytes()
        require(any(json.loads(line).get('request_sha256')==key and json.loads(line).get('operation')==request['operation']
                    for line in audit.splitlines()),'R1 receipt lacks original protected dispatch audit')
        approved.add(path.relative_to(controller.root).as_posix())
    return approved,{directory.relative_to(controller.root).as_posix()}


# Local carrier capacity, not an identity/consensus validity rule. The central
# APQE protected receipt admits at most2MiB; this leaves bounded receipt overhead.
MAX_IDENTITY_OPERATION_REQUEST=1024*1024
MAX_ORIGINAL_PUBLIC_RESULT=1024*1024
IDENTITY_OPERATIONS={'r1_identity_prove':('prove-managed-r1-identity','read-managed-r1-identity-proof-result'),
    'r1_identity_rebind':('rebind-managed-r1-identity','read-managed-r1-identity-rebind-result'),
    'r1_root_approval_use':('use-managed-r1-root-approval','read-managed-r1-root-approval-result')}


def _hex(value,width,nonzero=False):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{'+str(width)+'}',value) is not None and (not nonzero or value!='0'*width)


def _public_key(value):
    if not isinstance(value,dict) or set(value)!={'role','algorithm','key_generation','full_public_key_hex'}:
        raise ValueError('Exact public key record required')
    if not isinstance(value['role'],str) or re.fullmatch('[!-~]{1,64}',value['role']) is None:
        raise ValueError('Exact public role required')
    widths={'ML-DSA-65':1952,'ML-DSA-87':2592}
    width=widths.get(value['algorithm']) if isinstance(value['algorithm'],str) else None
    if width is None or not _hex(value['full_public_key_hex'],width*2):
        raise ValueError('Complete current public key required')
    if type(value['key_generation']) is not int or not 1<=value['key_generation']<=2**64-1:
        raise ValueError('Exact public u64 key generation required')


def validate_proof(parameters):
    # Public structural/resource checks only. APQE alone decodes policy/CBOR,
    # matches the approved native scope and creates any private authorization.
    fields={'creation','expected_journal_generation','expected_envelope_commitment_hex','public_key','proof_plan'}
    if not isinstance(parameters,dict) or set(parameters)!=fields:
        raise ValueError('Exact managed identity proof parameters required')
    validate(parameters['creation']);_public_key(parameters['public_key'])
    generation=parameters['expected_journal_generation']
    if not isinstance(generation,str) or not re.fullmatch('[1-9][0-9]{0,19}',generation) or int(generation)>2**64-3:
        raise ValueError('Exact bounded journal generation required')
    if not _hex(parameters['expected_envelope_commitment_hex'],128,True):
        raise ValueError('Exact pending envelope commitment required')
    creation,key=parameters['creation'],parameters['public_key']
    if (creation['role'],creation['algorithm'],creation['key_generation'])!=(key['role'],key['algorithm'],str(key['key_generation'])):
        raise ValueError('Public key differs from original native creation scope')
    plan=parameters['proof_plan']
    if not isinstance(plan,dict) or set(plan)!={'namespace','expected_identity','birth_nonce_hex','enrollment_nonce_hex','birth_policy_frame_hex','current_policy_frame_hex','node'}:
        raise ValueError('Exact public identity proof plan required')
    namespace=plan['namespace'];identity=plan['expected_identity']
    if not isinstance(namespace,str) or re.fullmatch('[a-z0-9]{3,6}',namespace) is None:
        raise ValueError('Exact public namespace required')
    if not isinstance(identity,str) or (identity!='' and re.fullmatch(re.escape(namespace)+r'\.2\.[A-Za-z0-9_-]{64}',identity) is None):
        raise ValueError('Complete exact current identifier required')
    for name in ('birth_nonce_hex','enrollment_nonce_hex'):
        if not _hex(plan[name],64):raise ValueError('Complete public nonce required')
    for name in ('birth_policy_frame_hex','current_policy_frame_hex'):
        value=plan[name]
        if not isinstance(value,str) or not 2<=len(value)<=MAX_IDENTITY_OPERATION_REQUEST or len(value)%2 or re.fullmatch('[a-f0-9]+',value) is None:
            raise ValueError('Bounded complete policy bytes required')
    node=plan['node']
    if node is not None:
        if not isinstance(node,dict) or set(node)!={'node_class','birth_root','role_keys'} or type(node['node_class']) is not int or not 1<=node['node_class']<=5 or namespace!='synv'+str(node['node_class']):
            raise ValueError('Exact current node class required')
        _public_key(node['birth_root'])
        if not isinstance(node['role_keys'],list) or len(node['role_keys'])>64:
            raise ValueError('Bounded public role key list required')
        for key in node['role_keys']:_public_key(key)


def validate_rebind(parameters):
    if not isinstance(parameters,dict) or set(parameters)!={'pending','original_creation_request_digest_hex'}:
        raise ValueError('Exact managed identity rebind parameters required')
    validate_proof(parameters['pending'])
    if not _hex(parameters['original_creation_request_digest_hex'],64,True):
        raise ValueError('Exact original creation request digest required')


def validate_root_approval(parameters):
    """Public carrier bounds only; the sole APQE owner validates scope/authority."""
    fields={'creation','root_index','public_key','stage','expected_journal_generation',
        'expected_envelope_commitment_hex','full_binding_aad_hex',
        'original_creation_request_digest_hex','operation_nonce_hex','lifetime_seconds'}
    if not isinstance(parameters,dict) or set(parameters)!=fields:
        raise ValueError('Exact managed root approval parameters required')
    validate(parameters['creation']);_public_key(parameters['public_key'])
    creation,key=parameters['creation'],parameters['public_key']
    if (creation['role'],creation['algorithm'],creation['key_generation'])!=(key['role'],key['algorithm'],str(key['key_generation'])) or key['algorithm']!='ML-DSA-87':
        raise ValueError('Exact original BootstrapRoot public key required')
    if type(parameters['root_index']) is not int or not 0<=parameters['root_index']<32:
        raise ValueError('Bounded canonical root index required')
    for field,maximum in [('expected_journal_generation',2**64-3),('lifetime_seconds',300)]:
        value=parameters[field]
        if not isinstance(value,str) or re.fullmatch('[1-9][0-9]{0,19}',value) is None or int(value)>maximum:
            raise ValueError('Canonical bounded root approval generation/lifetime required')
    for field,width in [('expected_envelope_commitment_hex',128),
        ('original_creation_request_digest_hex',64),('operation_nonce_hex',64)]:
        if not _hex(parameters[field],width,True):
            raise ValueError('Complete root approval pin/nonce required')
    aad=parameters['full_binding_aad_hex']
    if not isinstance(aad,str) or not 2<=len(aad)<=MAX_IDENTITY_OPERATION_REQUEST or len(aad)%2 or re.fullmatch('[a-f0-9]+',aad) is None:
        raise ValueError('Bounded complete original public binding AAD required')
    stage=parameters['stage']
    if not isinstance(stage,dict):raise ValueError('Exact root approval stage required')
    kind=stage.get('kind')
    if kind=='NIC':
        if set(stage)!={'kind'}:raise ValueError('NIC approval has no later stage fields')
    elif kind=='FORMATION':
        if set(stage)!={'kind','registry_commitment_hex','input_commitment_hex'} or not all(_hex(stage.get(k),128,True) for k in ('registry_commitment_hex','input_commitment_hex')):
            raise ValueError('Complete formation subject required')
    elif kind=='GENESIS':
        if set(stage)!={'kind','genesis_digest_hex'} or not _hex(stage.get('genesis_digest_hex'),96,True):
            raise ValueError('Complete schema2 Genesis subject required')
    else:raise ValueError('Closed root approval purpose required')


def _original_public_result(raw):
    # No report/approval object can stand in for Root's original durable bytes.
    from controller import require
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):raise __import__('controller').Refused('reconciliation_required','Original durable identity result unavailable') from None
    if value is None:return None
    require(isinstance(value,str) and 0<len(value)<=4*((MAX_ORIGINAL_PUBLIC_RESULT+2)//3),
            'Original durable identity result required','reconciliation_required')
    try:
        public=base64.b64decode(value,validate=True)
        require(0<len(public)<=MAX_ORIGINAL_PUBLIC_RESULT and base64.b64encode(public).decode('ascii')==value,
                'Original durable identity result encoding differs','reconciliation_required')
    except (ValueError,binascii.Error):
        raise __import__('controller').Refused('reconciliation_required','Original durable identity result encoding differs') from None
    return value


def run_identity_operation(controller,request):
    from controller import canonical,request_digest,require,sync_directory
    from lifecycle import _lifecycle_lock,_sealed_receipt
    from synergy_linux import native
    operation=request['operation'];p=request['parameters']
    if operation=='r1_identity_prove':validate_proof(p);pending=p
    elif operation=='r1_identity_rebind':validate_rebind(p);pending=p['pending']
    elif operation=='r1_root_approval_use':validate_root_approval(p);pending=p
    else:raise ValueError('Exact managed identity operation required')
    creation=pending['creation'];key=request_digest(request);command,read_command=IDENTITY_OPERATIONS[operation]
    operation_nonce=p['operation_nonce_hex'] if operation=='r1_root_approval_use' else creation['operation_nonce_hex']
    maximum=4*((MAX_ORIGINAL_PUBLIC_RESULT+2)//3)+8
    with _lifecycle_lock(controller.root):
        installation,manifest=_sealed_receipt(controller.root)
        require(manifest['release_id']==creation['release_id'] and installation['package_sha256']==creation['manifest_sha256']
                and manifest['files'].get('lib/apqe/build-report.json')==creation['provider_report_sha256']
                and 'lib/apqe/r1-profile-catalog.cbor' in manifest['files'],
                'Identity operation differs from authenticated installed release','qualification_required')
        # Only Root's same network/nonce/request-bound original result may satisfy
        # a replay. A missing/ambiguous result never authorizes recomputation.
        result=_original_public_result(native([controller.root/'bin/synergy-keytool',read_command,controller.root,
            operation_nonce,key],maximum_stdout=maximum))
        if result is not None:return result
        target=controller.control/'r1-creation'/(key+'.json')
        require(not target.exists() and not target.is_symlink(),
                'Prior identity dispatch is unresolved; reconcile original operation','reconciliation_required')
        grant=controller.public_json(controller.control/'grants'/(key+'.json'),True)
        expires=grant.get('expires_at')
        controller.authorize(request)
        directory=target.parent;directory.mkdir(mode=0o700,exist_ok=True)
        metadata=directory.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.geteuid() and stat.S_IMODE(metadata.st_mode)==0o700,
                'Private native receipt directory required')
        receipt={'format':'synergy-native-r1-creation-v1','root':str(controller.root),
                 'request':request,'request_sha256':key,'expires_at_unix':expires}
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical(receipt));stream.flush();os.fsync(stream.fileno())
        sync_directory(directory)
        result=_original_public_result(native([controller.root/'bin/synergy-keytool',command,controller.root,target,key],maximum_stdout=maximum))
        require(result is not None,'Identity operation returned no durable completion','reconciliation_required')
        return result
