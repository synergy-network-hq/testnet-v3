"""Current R1 key creation through the existing authenticated native controller.

No derivation/CBOR/crypto is duplicated here. APQE validates the full typed scope;
this layer binds its public transport to the existing exact native request grant.
"""
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
        require(request['operation']=='r1_identity_generate' and value['request_sha256']==key
                and path.name==key+'.json' and not (controller.control/'grants'/path.name).exists(),
                'R1 dispatch receipt is not a consumed exact request')
        audit=controller.direct(controller.control/'audit.jsonl',True).read_bytes()
        require(any(json.loads(line).get('request_sha256')==key and json.loads(line).get('operation')=='r1_identity_generate'
                    for line in audit.splitlines()),'R1 receipt lacks original protected dispatch audit')
        approved.add(path.relative_to(controller.root).as_posix())
    return approved,{directory.relative_to(controller.root).as_posix()}
