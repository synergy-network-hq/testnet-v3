"""Canonical explicit APQE commissioning layout; never grants production approval."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from synergy_linux import digest, read, require, write_new

PROFILE = 'engineering_canary_pq_vsession_v1'
PUBLIC = ('genesis.json','authority.json','authority-root.pub','network-manifest.json',
          'transport-registry.json','transport-root.pub')
KEYS = ('validator.pub.json','enrollment.json','custody.json','unlock')
INPUTS = frozenset(['config/node.json','config/start-authorized.json'] +
                  ['network/'+name for name in PUBLIC] + ['keys/apqe/'+name for name in KEYS])
FORMATION_PUBLIC_INPUTS = INPUTS-frozenset('keys/apqe/'+name for name in KEYS)
BOUND_CUSTODY = {'unlock':'unlock','bundle/validator.enc.json':'custody.json',
                 'bundle/enrollment-request.json':'enrollment.json','node-identity.json':'validator.pub.json'}


def selected(config):
    return config.get('apqe_transport') is not None


def validate_layout(root, source=None, software=None):
    """Structural/path/hash check. Native preflight authenticates public proofs.

    Encrypted custody possession is checked by the native runtime before it
    starts services; this function never claims private key possession.
    """
    root=Path(root); source=Path(source or root); software=Path(software or root)
    config=read(source/'config/node.json'); transport=config.get('apqe_transport')
    require(isinstance(transport,dict) and transport.get('profile')==PROFILE,
            'explicit APQE engineering session profile required; no legacy fallback')
    require(config.get('aegis_signing_key_path') is None
            and config.get('aegis_key_bindings_path') is None
            and config.get('consensus',{}).get('signing_key_path') is None
            and config.get('etdag',{}).get('ingress_kem_secret_key_path') is None,
            'raw native signing/custody paths forbidden for APQE installation')
    expected={'registry_path':root/'network/transport-registry.json',
              'registry_trust_key_path':root/'network/transport-root.pub',
              'enrollment_path':root/'keys/apqe/enrollment.json',
              'custody_path':root/'keys/apqe/custody.json',
              'custody_unlock_path':root/'keys/apqe/unlock'}
    for field,path in expected.items():
        require(transport.get(field)==str(path),'canonical APQE path differs: '+field)
    require(config.get('public_identity_path')==str(root/'keys/apqe/validator.pub.json')
            and config.get('admin_socket_path')==str(root/'run/admin.sock')
            and config.get('storage',{}).get('data_directory')==str(root/'data'),
            'canonical APQE identity/storage/admin paths required')
    require(config.get('genesis_path')==str(root/'network/genesis.json')
            and config.get('manifest_path')==str(root/'network/network-manifest.json')
            and config.get('consensus',{}).get('authority_binding')==str(root/'network/authority.json')
            and config.get('consensus',{}).get('authority_trust_key_path')==str(root/'network/authority-root.pub'),
            'canonical authenticated network paths required')
    provider=config.get('aegis_provider') or {}
    require(provider.get('report_path')==str(root/'lib/apqe/build-report.json')
            and provider.get('authenticated_report_sha256')==digest(software/'lib/apqe/build-report.json'),
            'selected APQE report pin/path mismatch')
    require(transport.get('registry_trust_key_sha256')==digest(source/'network/transport-root.pub')
            and transport.get('genesis_trust_key_sha256')==digest(source/'network/authority-root.pub'),
            'independent APQE trust anchor pin mismatch')
    for name in INPUTS:
        path=source/name; metadata=path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
                and metadata.st_size > 0 and metadata.st_size <= 4*1024*1024
                and not metadata.st_mode & 0o022,'unsafe APQE input: '+name)
        if name in ('keys/apqe/custody.json','keys/apqe/unlock'):
            require(stat.S_IMODE(metadata.st_mode)==0o600,'APQE private input requires0600: '+name)
    identity=read(source/'keys/apqe/validator.pub.json')
    address=identity.get('node_address')
    require(isinstance(address,str) and address.startswith('synv1'),'native validator identity required')
    return {'address':address,'native_possession_verified':False,
            'public_identity_layout_verified':True,'production_approved':False}


def seal_commissioning(stage, root, *, all_validators_ready=False, all_pairs_vpn_verified=False):
    """Seal operator-reviewed provisioning inputs; never infers fleet readiness."""
    stage=Path(stage); root=Path(root)
    require(all_validators_ready is True and all_pairs_vpn_verified is True,
            'explicit completed validator provisioning and VPN pair readiness required')
    config=read(stage/'config/node.json')
    authority=read(stage/'network/authority.json')['payload']
    ids=[e['record']['validator_id'] for e in authority['validators'] if e['record']['status']=='active']
    require(ids and len(ids)==len(set(ids)),'active signed validator inventory required')
    policy={'network_id':config['network_id'],'chain_id':config['chain_id'],
            'all_validators_ready':True,'all_pairs_vpn_verified':True,
            'validator_addresses':ids,'profile':PROFILE,'production_approved':False,
            'public_file_sha256':{name:digest(stage/'network'/name) for name in PUBLIC}}
    write_new(stage/'config/start-authorized.json',policy)
    manifest={'format':'synergy-apqe-commissioning-v1','root':str(root),
              'network_id':config['network_id'],'chain_id':config['chain_id'],
              'node_name':config['node_name'],'files':{name:digest(stage/name) for name in sorted(INPUTS)}}
    write_new(stage/'commissioning.json',manifest)
    return manifest


def require_frozen_tree(directory):
    """Root adopts uploaded inputs before privileged validation or replacement."""
    directory=Path(directory)
    require(directory.is_absolute() and directory.resolve()==directory and directory.is_dir(),
            'canonical frozen input directory required')
    for parent in [directory,*directory.parents]:
        st=parent.stat()
        require(st.st_uid in (0,os.geteuid()) and (not st.st_mode&0o022 or
                parent in (Path('/var/tmp'),Path('/tmp'),Path('/private/tmp')) and st.st_mode&stat.S_ISVTX),
                'input ancestry must be operator-owned and nonwritable')
    for path in directory.rglob('*'):
        st=path.lstat()
        require(not path.is_symlink() and st.st_uid==os.geteuid() and not st.st_mode&0o022
                and (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)),
                'frozen input contains unsafe ownership/type/permissions')


def validate_stage(stage, root, package):
    stage=Path(stage); root=Path(root)
    require(stage.is_absolute() and stage.resolve()==stage and not stage.is_symlink(),
            'canonical commissioning stage required')
    require_frozen_tree(stage)
    names=set()
    for path in stage.rglob('*'):
        st=path.lstat()
        require(not path.is_symlink() and st.st_uid==os.geteuid()
                and not st.st_mode&0o022,'unsafe commissioning stage member')
        if path.is_file(): names.add(path.relative_to(stage).as_posix())
        else: require(path.is_dir(),'special commissioning stage member')
    require(names==INPUTS|{'commissioning.json'},'commissioning stage inventory differs')
    manifest=read(stage/'commissioning.json')
    require(manifest.get('format')=='synergy-apqe-commissioning-v1'
            and manifest.get('root')==str(root) and set(manifest.get('files',{}))==INPUTS,
            'commissioning manifest/root mismatch')
    for name,expected in manifest['files'].items():
        require(re.fullmatch('[0-9a-f]{64}',expected) is not None
                and digest(stage/name)==expected,'commissioning input digest mismatch')
    config=read(stage/'config/node.json')
    for key in ('network_id','chain_id','node_name'):
        require(manifest.get(key)==config.get(key),'commissioning identity mismatch: '+key)
    validate_layout(root,stage,package)
    return manifest


def assemble_formation_stage(root, stage, pins):
    """Materialize approved public inputs and exclusively local bound custody."""
    root=Path(root);stage=Path(stage)
    public=root/'tmp/commissioning-public'
    pending=root/'tmp/pending-validator-custody'
    require(stage==root/'tmp/commissioning' and isinstance(pins,dict)
            and set(pins)==FORMATION_PUBLIC_INPUTS
            and all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in pins.values()),
            'Exact host-approved public commissioning inventory required')
    require_frozen_tree(public)
    require_frozen_tree(pending)
    require({p.relative_to(public).as_posix() for p in public.rglob('*') if p.is_file()}
            ==FORMATION_PUBLIC_INPUTS,'Public commissioning inputs must not contain custody')
    require({p.relative_to(pending).as_posix() for p in pending.rglob('*') if p.is_file()}
            ==set(BOUND_CUSTODY)|{'bundle/validator.pub.json'},'Incomplete or unexpected bound custody')
    sources={name:(public/name,pins[name]) for name in FORMATION_PUBLIC_INPUTS}
    sources.update({'keys/apqe/'+dest:(pending/name,None)
                    for name,dest in BOUND_CUSTODY.items()})
    contents={}
    for name,(source,expected) in sources.items():
        st=source.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=4*1024*1024
                and (not name.startswith('keys/') or stat.S_IMODE(st.st_mode)==0o600),
                'Unsafe formation commissioning source')
        with source.open('rb') as stream: data=stream.read(st.st_size+1)
        actual=hashlib.sha256(data).hexdigest()
        require(len(data)==st.st_size and (expected is None or actual==expected),
                'Formation commissioning input differs from exact approved bytes')
        contents[name]=(data,actual)
    config=json.loads(contents['config/node.json'][0])
    manifest={'format':'synergy-apqe-commissioning-v1','root':str(root),
              'network_id':config['network_id'],'chain_id':config['chain_id'],'node_name':config['node_name'],
              'files':{name:actual for name,(_,actual) in contents.items()}}
    if stage.exists() or stage.is_symlink():
        require(validate_stage(stage,root,root)==manifest,
                'Existing commissioning stage differs; preserve for reconciliation')
        return
    # Exclusive directory, then durable files. A partial stage is deliberately
    # kept if interrupted; it cannot be silently reused with different inputs.
    stage.mkdir(mode=0o700)
    for name,(data,_) in contents.items():
        target=stage/name
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with target.open('xb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
    write_new(stage/'commissioning.json',manifest)
