#!/usr/bin/env python3
"""Prepare a fresh internal Gateway from an independently pinned existing one.

No SSH, service management, NodeNetwork authority, custody generation, or key
export. Private transport inputs are streamed only between owner-only local
files. The source root is never changed. Preparation can target the final root
while it is still occupied; installation separately requires a genuinely absent
root. A service handoff and retirement remain explicit caller responsibilities.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from types import SimpleNamespace

PUBLIC = ('genesis.json','authority.json','authority-root.pub','network-manifest.json',
          'transport-registry.json','transport-root.pub')
SOURCE_FILES = frozenset(('config/node.json','config/canary-rpc-relay.json',
    *('network/'+name for name in PUBLIC),'network/rpc-gateway-admission.json',
    'keys/apqe/gateway-enrollment.json','keys/apqe/gateway-transport.encrypted.json',
    'keys/apqe/gateway-transport.unlock'))
OFFLINE_IDENTITY = ('keys/apqe/gateway-identity.encrypted.json','keys/apqe/gateway-identity.unlock')


def require(value,message):
    if not value:raise ValueError(message)


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'


def checksum(raw):return hashlib.sha256(raw).hexdigest()


def directory(path):
    path=Path(path)
    require(path.is_absolute() and path.resolve()==path,'Explicit canonical local path required')
    for parent in (path,*path.parents):
        if parent.exists():
            info=parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                    'Unsafe local preparation ancestry')
    return path


def source_file(path):
    directory(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=16*1024*1024,
                'Unsafe bounded Gateway input')
        return fd,info
    except BaseException:
        os.close(fd)
        raise


def read_public(path):
    fd,info=source_file(path)
    try:
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(info.st_size+1)
        require(len(raw)==info.st_size,'Gateway input changed')
        return raw
    finally:os.close(fd)


def stream_input(source,destination,expected):
    fd,info=source_file(source);output=None
    try:
        destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        output=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        digest=hashlib.sha256()
        with os.fdopen(fd,'rb',closefd=False) as incoming,os.fdopen(output,'wb',closefd=False) as outgoing:
            for block in iter(lambda:incoming.read(65536),b''):
                digest.update(block);outgoing.write(block)
            outgoing.flush();os.fsync(output)
        after=os.fstat(fd)
        require(all(getattr(after,key)==getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
                and digest.hexdigest()==expected,'Gateway source changed or differs from independent pin')
    finally:
        os.close(fd)
        if output is not None:os.close(output)


def scope_check(scope):
    require(isinstance(scope,dict) and set(scope)=={'package_sha256','network_id','chain_id','node_name',
        'gateway_address','validator_address','listen_address','sentry_endpoints','source_files'},'Exact fresh Gateway scope required')
    # This utility preserves same-incarnation custody and trust from an existing
    # Gateway. A clean 9969 incarnation must never enter that replacement path,
    # including after authorization to generate its genuinely fresh material.
    require(scope['chain_id'] != 9969,
            'Testnet 9969 forbids historical Gateway custody and origin reuse')
    pins=scope['source_files']
    require(isinstance(pins,dict) and set(pins)==SOURCE_FILES
            and all(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) for value in [scope['package_sha256'],*pins.values()]),
            'Independent complete Gateway input pins required')
    require(isinstance(scope['network_id'],str) and re.fullmatch('[a-z0-9][a-z0-9_-]{1,127}',scope['network_id'])
            and type(scope['chain_id']) is int and 0<scope['chain_id']<2**53
            and isinstance(scope['node_name'],str) and re.fullmatch('[a-zA-Z0-9_-]{1,64}',scope['node_name']),
            'Exact fresh Gateway network identity required')
    require(isinstance(scope['gateway_address'],str) and re.fullmatch('synv5[a-z0-9]+',scope['gateway_address'])
            and isinstance(scope['validator_address'],str) and re.fullmatch('synv1[a-z0-9]+',scope['validator_address']),
            'Exact existing public role identities required')
    from rpc_sentry import endpoint,public_address
    import ipaddress
    listen=endpoint(scope['listen_address']);require(listen[0].is_loopback,'Preserve the existing loopback listener')
    endpoints=scope['sentry_endpoints']
    require(isinstance(endpoints,list) and 1<=len(endpoints)<=8 and len(set(endpoints))==len(endpoints)
            and all(public_address(endpoint(value)[0]) for value in endpoints),'Bounded distinct public Sentry endpoints required')


def native_candidate(package,stage,config,relay):
    """Verify exact staged bytes using the existing qualified native owner."""
    import canary_rpc_relay as gateway
    import synergy_linux as boundary
    temporary=json.loads(json.dumps(config));temporary_relay=json.loads(json.dumps(relay))
    temporary.update(genesis_path=str(stage/'network/genesis.json'),manifest_path=str(stage/'network/network-manifest.json'),
        public_identity_path=str(stage/'keys/apqe/gateway-enrollment.json'))
    temporary['consensus'].update(authority_binding=str(stage/'network/authority.json'),authority_trust_key_path=str(stage/'network/authority-root.pub'))
    temporary['apqe_transport'].update(registry_path=str(stage/'network/transport-registry.json'),registry_trust_key_path=str(stage/'network/transport-root.pub'),
        enrollment_path=str(stage/'keys/apqe/gateway-enrollment.json'),custody_path=str(stage/'keys/apqe/gateway-transport.encrypted.json'),custody_unlock_path=str(stage/'keys/apqe/gateway-transport.unlock'))
    temporary['aegis_provider']['report_path']=str(package/'lib/apqe/build-report.json')
    for field,name in [('custody_path','gateway-transport.encrypted.json'),('custody_unlock_path','gateway-transport.unlock'),('enrollment_path','gateway-enrollment.json')]:
        temporary_relay['role'][field]=str(stage/'keys/apqe'/name)
    reply=json.loads(boundary.native([package/'bin/synergy-node','canary-rpc-relay','inspect-target-candidate'],
        data=encoded({'node_configuration':temporary,'relay_configuration':temporary_relay,
                      'admission_json':read_public(stage/'network/rpc-gateway-admission.json').decode()}),maximum_stdout=4096))
    require(reply=={'transport_custody_verified':True,'mutation_performed':False},'Native Gateway custody/admission verification refused')


def prepare(package,source_root,stage,target_root,scope):
    """Pure preparation: no existing root changes and no service operations."""
    require(os.geteuid()==0,'Local root owner required for Gateway custody preparation')
    scope_check(scope)
    import synergy_linux as boundary
    import canary_rpc_relay as gateway
    package,source,stage,target=map(directory,map(Path,(package,source_root,stage,target_root)))
    require(source!=stage and source not in stage.parents and stage not in source.parents and target!=stage
            and package not in stage.parents and stage not in package.parents
            and target.name=='synergy' and len(target.parts)>=3,'Separate private commissioning stage and canonical target required')
    require(not stage.exists() and not stage.is_symlink(),'Fresh input stage required; inspect any prior attempt')
    require(boundary.digest(package/'package.json')==scope['package_sha256'],'Independent package pin differs')
    manifest=boundary.verify_package(package)
    receipt=json.loads(read_public(source/'installation.json'))
    require(receipt.get('role')=='rpc_gateway' and receipt.get('network_id')==scope['network_id']
            and receipt.get('chain_id')==scope['chain_id'] and receipt.get('consensus_started') is False,
            'Existing source is not the selected non-signing Gateway')
    # Read only public JSON. Custody/unlock are hashed and streamed, never decoded.
    raw={name:read_public(source/name) for name in SOURCE_FILES if not name.endswith(('gateway-transport.encrypted.json','gateway-transport.unlock'))}
    require(all(checksum(value)==scope['source_files'][name] for name,value in raw.items()),'Independent original public input differs')
    old=json.loads(raw['config/node.json']);old_relay=json.loads(raw['config/canary-rpc-relay.json']);role=old_relay.get('role',{})
    require(old.get('role')=='rpc_gateway' and old.get('network_id')==scope['network_id'] and old.get('chain_id')==scope['chain_id']
            and old.get('consensus',{}).get('mode')=='observe' and old.get('rpc',{}).get('enabled') is False
            and old.get('consensus',{}).get('signing_key_path') is None and old.get('aegis_signing_key_path') is None,
            'Original Gateway cannot own consensus signing or ordinary RPC')
    require(old_relay.get('listen_address')==scope['listen_address'] and role.get('kind')=='gateway'
            and role.get('gateway_address')==scope['gateway_address'] and role.get('validator_address')==scope['validator_address'],
            'Preserve exact original loopback and public transport identities')
    for field,name in [('custody_path','gateway-transport.encrypted.json'),('custody_unlock_path','gateway-transport.unlock'),('enrollment_path','gateway-enrollment.json')]:
        require(role.get(field)==str(source/'keys/apqe'/name),'Original transport locator differs')
    offline=[(source/name).exists() or (source/name).is_symlink() for name in OFFLINE_IDENTITY]
    require(offline[0]==offline[1],'Incomplete offline Gateway identity pair requires explicit preservation')
    if offline[0]:
        for name in OFFLINE_IDENTITY:
            fd,_=source_file(source/name);os.close(fd)  # Metadata only; never copy the offline identity.
    pins={name:scope['source_files']['network/'+name] for name in PUBLIC}
    pins['provider']=manifest['files']['lib/apqe/build-report.json']
    config=gateway._gateway_target_config(SimpleNamespace(root=target),scope,pins,target/'network')
    relay=gateway.configuration(target,{'listen_address':scope['listen_address'],'role':{'kind':'gateway',
        'gateway_address':scope['gateway_address'],'validator_address':scope['validator_address'],
        'sentry_endpoints':scope['sentry_endpoints'],'allowed_origins':role.get('allowed_origins',[])}})
    stage.mkdir(mode=0o700)
    try:
        for name in SOURCE_FILES-{'config/node.json','config/canary-rpc-relay.json'}:
            stream_input(source/name,stage/name,scope['source_files'][name])
        for name,value in [('config/node.json',config),('config/canary-rpc-relay.json',relay)]:
            path=stage/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as out:os.fchmod(out.fileno(),0o600);out.write(encoded(value));out.flush();os.fsync(out.fileno())
        native_candidate(package,stage,config,relay)
        commissioning=gateway.seal_gateway_inputs(stage,target)
        # Rehash every destination before returning the independently reviewable manifest.
        sealed=json.loads(read_public(stage/'gateway-commissioning.json'))
        require(set(sealed['files'])==gateway.GATEWAY_INPUTS,'Fresh commissioning input set differs')
        for name,pin in sealed['files'].items():
            fd,info=source_file(stage/name)
            try:
                digest=hashlib.sha256()
                with os.fdopen(fd,'rb',closefd=False) as incoming:
                    for block in iter(lambda:incoming.read(65536),b''):digest.update(block)
                require(digest.hexdigest()==pin,'Fresh staged input changed')
            finally:os.close(fd)
        return {'commissioning_sha256':commissioning,'package_sha256':scope['package_sha256'],'target_root':str(target),
                'services_started':False,'source_preserved':True,'offline_identity_preserved_at_source':bool(offline[0]),
                'offline_identity_requires_separate_preservation_before_source_retirement':bool(offline[0])}
    except BaseException:
        shutil.rmtree(stage)
        raise


def install_and_commission(package,stage,target_root,scope,commissioning_sha256):
    """Explicit fresh-root phase only; never switches or registers OS services."""
    scope_check(scope)
    import synergy_linux as boundary
    import canary_rpc_relay as gateway
    package,stage,target=map(directory,map(Path,(package,stage,target_root)))
    require(not target.exists() and not target.is_symlink(),'Fresh target required; old root must be preserved')
    require(boundary.digest(package/'package.json')==scope['package_sha256']
            and checksum(read_public(stage/'gateway-commissioning.json'))==commissioning_sha256,
            'Independently verified package and commissioning pins required')
    boundary.verify_package(package)
    receipt=boundary.install(package,target,'rpc_gateway',scope['network_id'],scope['chain_id'],scope['node_name'])
    result=gateway.commission_gateway(target,stage,commissioning_sha256)
    require(receipt['package_sha256']==scope['package_sha256'] and result['gateway_commissioned'] is True,'Fresh Gateway receipt differs')
    return dict(result,services_started=False,old_root_retired=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('prepare','install'))
    for name in ('package','stage','target','scope'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--source',type=Path);parser.add_argument('--commissioning-sha256')
    args=parser.parse_args();scope=json.loads(read_public(args.scope))
    if args.operation=='prepare':
        require(args.source is not None and args.commissioning_sha256 is None,'Exact source required for preparation')
        result=prepare(args.package,args.source,args.stage,args.target,scope)
    else:
        require(args.source is None and re.fullmatch('[a-f0-9]{64}',args.commissioning_sha256 or ''),'Exact commissioning pin required')
        result=install_and_commission(args.package,args.stage,args.target,scope,args.commissioning_sha256)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Fresh Gateway preparation refused; original root and custody remain untouched')
