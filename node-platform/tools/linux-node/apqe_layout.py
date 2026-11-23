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
WALLET_RELEASE_PUBLIC = {
    'wallet-dispatch-managed-artifacts.json': 8 * 1024,
    'wallet-dispatch-release.json': 32 * 1024,
    'wallet-dispatch-release-issuer.pub': 1952,
    'wallet-dispatch-release-issuer-authorization.json': 24 * 1024,
    'wallet-dispatch-ml-dsa-87-qualification.json': 24 * 1024,
}
WALLET_RELEASE_PIN_FIELDS = {
    'attachment_sha256', 'issuer_sha256', 'release_verifier_artifact_sha256',
    'managed_release_manifest_sha256', 'off_chain_approval_sha256', 'release_attestation_sha256',
}
WALLET_RELEASE_PACKAGE_DIRECTORY = 'assets/wallet-dispatch'
WALLET_RELEASE_PACKAGE_FILES = {**WALLET_RELEASE_PUBLIC, 'selection.json': 4096}
BOUND_CUSTODY = {'unlock':'unlock','bundle/validator.enc.json':'custody.json',
                 'bundle/enrollment-request.json':'enrollment.json','node-identity.json':'validator.pub.json'}


def selected(config):
    return config.get('apqe_transport') is not None


def wallet_release_selection(config):
    selection = config.get('consensus', {}).get('managed_wallet_dispatch_release')
    if selection is None:
        return None
    require(isinstance(selection, dict)
            and set(selection) - {'from_sealed_package'} == WALLET_RELEASE_PIN_FIELDS | {'issuer_key_id'}
            and ('from_sealed_package' not in selection or selection['from_sealed_package'] is True)
            and all(isinstance(selection[key], str) and re.fullmatch('[0-9a-f]{64}', selection[key])
                    and selection[key] != '0' * 64 for key in WALLET_RELEASE_PIN_FIELDS)
            and isinstance(selection['issuer_key_id'], str)
            and re.fullmatch(r'[!-~]{1,128}', selection['issuer_key_id']),
            'Exact independently pinned Wallet release selection required')
    return selection


def _canonical_package_manifest(manifest):
    return (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()


def wallet_release_package(package, manifest):
    """Read only release inputs from the independently approved package closure.

    Version 1 pins the base manifest with exactly these six members omitted.
    The controller separately authenticates the complete package manifest.
    """
    prefix = WALLET_RELEASE_PACKAGE_DIRECTORY + '/'
    files = {name[len(prefix):]: pin for name, pin in manifest['files'].items()
             if name.startswith(prefix)}
    source = package/WALLET_RELEASE_PACKAGE_DIRECTORY
    if not files:
        require(not source.exists() and not source.is_symlink(), 'Unexpected Wallet release directory')
        return None
    require(set(files) == set(WALLET_RELEASE_PACKAGE_FILES) and source.is_dir() and not source.is_symlink()
            and {path.name for path in source.iterdir()} == set(files),
            'Exact sealed Wallet release input inventory required')
    for name, maximum in WALLET_RELEASE_PACKAGE_FILES.items():
        path = source/name
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and 0 < metadata.st_size <= maximum and digest(path) == files[name],
                'Sealed Wallet release input differs from the exact package')
    selection_path = source/'selection.json'
    selection_bytes = selection_path.read_bytes()
    selection = wallet_release_selection({'consensus': {
        'managed_wallet_dispatch_release': json.loads(selection_bytes)}})
    require(selection is not None and 'from_sealed_package' not in selection
            and selection_bytes == _canonical_package_manifest(selection)
            and selection['attachment_sha256'] == files['wallet-dispatch-release.json']
            and selection['issuer_sha256'] == files['wallet-dispatch-release-issuer.pub']
            and selection['managed_release_manifest_sha256'] == files['wallet-dispatch-managed-artifacts.json'],
            'Managed Wallet release selection and pinned package bytes differ')
    full = _canonical_package_manifest(manifest)
    manifest_path = package/'package.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink()
            and 0 < manifest_path.stat().st_size == len(full) <= 1024*1024
            and manifest_path.read_bytes() == full, 'Canonical version 1 package manifest required')
    base = {**manifest, 'files': {name: pin for name, pin in manifest['files'].items()
                                  if not name.startswith(prefix)}}
    return {**selection, 'from_sealed_package': True}, hashlib.sha256(_canonical_package_manifest(base)).hexdigest()


def require_wallet_release_preflight(selection, release, base_package_sha256, executable_sha256, report_sha256):
    if selection is None:
        require(release is None, 'Unselected Wallet release returned by native preflight')
        return
    require(isinstance(release, dict) and set(release) == {
        'state', 'initial_adoption_before_close', 'quick_setup_enrollment', 'activation_finalized_height', 'target',
        'managed_release_manifest_sha256', 'base_package_manifest_sha256', 'executable_sha256',
        'apqe_report_sha256',
    } and release['state'] in ('verified_pending', 'active')
        and type(release['quick_setup_enrollment']) is bool
        and type(release['initial_adoption_before_close']) is bool
        and (release['state'] != 'active' or not release['initial_adoption_before_close'])
        and type(release['activation_finalized_height']) is int
        and 0 < release['activation_finalized_height'] < 2**64
        and release['target'] == 'x86_64-unknown-linux-gnu'
        and release['managed_release_manifest_sha256'] == selection['managed_release_manifest_sha256']
        and release['base_package_manifest_sha256'] == base_package_sha256
        and release['executable_sha256'] == executable_sha256
        and release['apqe_report_sha256'] == report_sha256,
        'Native Wallet release preflight differs from the approved Linux package')


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


def formation_stage_contents(root, pins, *, public=None):
    """Materialize approved public inputs and exclusively local bound custody."""
    root=Path(root)
    public=Path(public) if public is not None else root/'tmp/commissioning-public'
    require(public in (root/'tmp/commissioning-public',root/'tmp/controller/authorization/inputs/commissioning'),
            'Only canonical approved public commissioning inputs may be used')
    pending=root/'tmp/pending-validator-custody'
    require(isinstance(pins,dict)
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
    return contents


def assemble_formation_stage(root, stage, pins, *, public=None, readiness_sha256=None):
    root=Path(root);stage=Path(stage)
    require(stage==root/'tmp/commissioning','Canonical commissioning stage required')
    contents=formation_stage_contents(root,pins,public=public)
    if readiness_sha256 is not None:
        require(isinstance(readiness_sha256,str) and re.fullmatch('[a-f0-9]{64}',readiness_sha256),'Verified readiness digest required')
        policy=json.loads(contents['config/start-authorized.json'][0])
        require(policy.get('all_validators_ready') is False and policy.get('all_pairs_vpn_verified') is False,
                'Readiness must be derived from the immutable unapproved draft')
        artifact_path=root/'tmp/controller/authorization/inputs'/READINESS_FILE
        require(digest(artifact_path)==readiness_sha256,'Approved readiness artifact changed')
        policy=readiness_startup_policy(policy,read(artifact_path),readiness_sha256)
        data=json.dumps(policy,sort_keys=True,separators=(',',':')).encode()
        contents['config/start-authorized.json']=(data,hashlib.sha256(data).hexdigest())
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
    import tempfile
    with tempfile.TemporaryDirectory(prefix='commission-prepare-',dir=stage.parent) as directory:
        prepared=Path(directory)/'stage';prepared.mkdir(mode=0o700)
        for name,(data,_) in contents.items():
            target=prepared/name
            target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with target.open('xb') as stream:
                os.fchmod(stream.fileno(),0o600)
                stream.write(data);stream.flush();os.fsync(stream.fileno())
        write_new(prepared/'commissioning.json',manifest)
        os.rename(prepared,stage)
        fd=os.open(stage.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)


READINESS_FILE='commissioning-readiness.json'
OBSERVATION_FIELDS={'schema','observed_at_unix','target','manifest_sha256','provider_report_sha256',
    'vpn_provider_sha256','network_id','chain_id','formation_sha256','address','enrollment_sha256',
    'public_file_sha256','commissioning_file_sha256','validator_addresses','registry_peer_ips','vpn_binding','peers'}


def signed_voting_weights(authority,roster):
    records=authority['validators']
    require(isinstance(records,list) and len(records)<=4096,'Bounded signed authority roster required')
    weights={}
    for entry in records:
        record=entry['record']
        if record['status']!='active':continue
        address=record['validator_id'];weight=record['frozen_voting_weight']
        require(isinstance(address,str) and address not in weights and type(weight) is int and 0<weight<2**128,
                'Distinct positive signed frozen voting weights required')
        weights[address]=str(weight)
    require(set(weights)==set(roster) and len(roster)==len(set(roster)),'Signed authority and transport roster differ')
    return {address:weights[address] for address in sorted(weights)}


def require_online_quorum(roster,weights,online):
    """Operational gate mirrors the runtime's strict checked-u128 dual quorum."""
    require(isinstance(roster,list) and roster==sorted(set(roster)) and roster
            and isinstance(weights,dict) and set(weights)==set(roster)
            and isinstance(online,list) and online==sorted(set(online)) and set(online)<=set(roster),
            'Exact distinct signed roster and online subset required')
    total=selected=0
    for address in roster:
        raw=weights[address]
        require(isinstance(raw,str) and re.fullmatch('[1-9][0-9]{0,38}',raw) and int(raw)<2**128,
                'Canonical positive frozen voting weight required')
        weight=int(raw);total+=weight
        if address in online:selected+=weight
        require(total<2**128 and selected<2**128,'Frozen voting weight sum overflow')
    require(len(online)*3>len(roster)*2,'Online subset fails strict signed count quorum')
    require(selected*3<2**128 and total*2<2**128 and selected*3>total*2,
            'Online subset fails strict signed frozen-weight quorum')
    return True


def readiness_startup_policy(draft,artifact,pin):
    require(draft.get('all_validators_ready') is False and draft.get('all_pairs_vpn_verified') is False,
            'Readiness must derive from the immutable unapproved draft')
    result={**draft,'all_validators_ready':True,'all_pairs_vpn_verified':True,'commissioning_readiness_sha256':pin}
    if artifact.get('schema')=='nodenetwork-commissioning-readiness-v2':
        require(set(artifact)=={'schema','online_addresses','excluded_addresses','observations'}
                and isinstance(artifact['observations'],list) and artifact['observations'],'Exact subset readiness artifact required')
        first=artifact['observations'][0];roster=first['validator_addresses'];online=artifact['online_addresses']
        require_online_quorum(roster,first['frozen_voting_weights'],online)
        require(set(draft['validator_addresses'])==set(roster) and artifact['excluded_addresses']==sorted(set(roster)-set(online)),
                'Startup subset or unobserved roster differs')
        result.update(all_validators_ready=online==roster,all_pairs_vpn_verified=online==roster,
                      quorum_validators_ready=True,online_pairs_vpn_verified=True,
                      online_validator_addresses=online,unobserved_validator_addresses=artifact['excluded_addresses'])
    else:require(artifact.get('schema')=='nodenetwork-commissioning-readiness-v1','Unknown readiness schema')
    return result


def startup_readiness_authorized(root,policy,address=None,authority_source=None):
    """Bind subset startup flags to retained host-approved artifact and signed weights."""
    if 'quorum_validators_ready' not in policy:
        return policy.get('all_validators_ready',policy.get('all_five_ready')) is True and policy.get('all_pairs_vpn_verified') is True
    from controller import Controller
    owner=Controller(root);approved=owner.policy()
    pin=approved.get('authorization_files',{}).get(READINESS_FILE)
    raw=owner.direct(owner.control/'authorization/inputs'/READINESS_FILE,True,128*1024).read_bytes()
    require(isinstance(pin,str) and hashlib.sha256(raw).hexdigest()==pin==policy.get('commissioning_readiness_sha256'),
            'Startup readiness provenance differs')
    artifact=json.loads(raw)
    draft_raw=owner.direct(owner.control/'authorization/inputs/commissioning/config/start-authorized.json',True,4*1024*1024).read_bytes()
    require(hashlib.sha256(draft_raw).hexdigest()==approved['validator_commissioning_files']['config/start-authorized.json'],
            'Original startup approval differs')
    require(policy==readiness_startup_policy(json.loads(draft_raw),artifact,pin),'Derived startup readiness policy differs')
    authority=read(Path(authority_source or root)/'network/authority.json')['payload']
    weights=signed_voting_weights(authority,policy['validator_addresses'])
    require(weights==artifact['observations'][0]['frozen_voting_weights'],'Startup signed frozen weights differ')
    require_online_quorum(sorted(weights),weights,policy['online_validator_addresses'])
    require(address is None or address in policy['online_validator_addresses'],'Unobserved validator cannot start')
    return policy['quorum_validators_ready'] is True and policy['online_pairs_vpn_verified'] is True


OBSERVATION_FIELDS_V2=OBSERVATION_FIELDS|{'online_addresses','frozen_voting_weights','observation_kind'}


def validate_commissioning_readiness(value,local,now):
    """Native-approved observations are operational evidence, never chain authority.

    The controller authenticates the fixed artifact against its host policy first.
    This validation requires exact current local facts and unique target/custody/
    VPN identities for the declared signed-quorum subset and all its directed probes.
    """
    import base64
    import ipaddress
    def pin(v):return isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v)
    def key(v):
        try:return isinstance(v,str) and len(base64.b64decode(v,validate=True))==32 and base64.b64encode(base64.b64decode(v)).decode()==v
        except (ValueError,TypeError):return False
    subset=isinstance(value,dict) and value.get('schema')=='nodenetwork-commissioning-readiness-v2'
    require(isinstance(value,dict) and set(value)==({'schema','observations','online_addresses','excluded_addresses'} if subset else {'schema','observations'})
            and value['schema'] in ('nodenetwork-commissioning-readiness-v1','nodenetwork-commissioning-readiness-v2')
            and isinstance(value['observations'],list),'Exact authenticated controller readiness required')
    observations=value['observations'];roster=local['validator_addresses']
    online=value['online_addresses'] if subset else roster
    if subset:
        require_online_quorum(roster,local['frozen_voting_weights'],online)
        require(local['online_addresses']==online and local['observation_kind']=='prestart_vpn'
                and value['excluded_addresses']==sorted(set(roster)-set(online)),'Online subset or unobserved members differ')
    require(isinstance(roster,list) and len(roster)==5 and roster==sorted(set(roster)), 'Exact five-member signed roster required')
    require([o.get('address') for o in observations if isinstance(o,dict)]==online and local['address'] in online,'Readiness roster/order differs')
    target_ids=set();vpn_ids=set();vpn_keys=set();vpn_ips=set();enrollments=set()
    shared=('manifest_sha256','provider_report_sha256','vpn_provider_sha256','network_id','chain_id',
            'formation_sha256','public_file_sha256','validator_addresses','registry_peer_ips')
    if subset:shared+=('online_addresses','frozen_voting_weights','observation_kind')
    fields=OBSERVATION_FIELDS_V2 if subset else OBSERVATION_FIELDS
    for observation in observations:
        require(set(observation)==fields and observation['schema']==('nodenetwork-commissioning-observation-v2' if subset else 'nodenetwork-commissioning-observation-v1'), 'Unexpected observation fields')
        require(type(observation['observed_at_unix']) is int and -30<=now-observation['observed_at_unix']<=300,
                'Commissioning observations expired or clock differs')
        require(all(observation[k]==local[k] for k in shared),'Commissioning network, roster, provider or master differs')
        require(all(pin(observation[k]) for k in ('manifest_sha256','provider_report_sha256','vpn_provider_sha256','formation_sha256','enrollment_sha256'))
                and isinstance(observation['public_file_sha256'],dict) and set(observation['public_file_sha256'])==set(PUBLIC)
                and all(pin(v) for v in observation['public_file_sha256'].values())
                and isinstance(observation['commissioning_file_sha256'],dict) and set(observation['commissioning_file_sha256'])==FORMATION_PUBLIC_INPUTS
                and all(pin(v) for v in observation['commissioning_file_sha256'].values()),'Bounded exact commissioning pins required')
        require(all(observation['commissioning_file_sha256']['network/'+name]==observation['public_file_sha256'][name] for name in PUBLIC),
                'Public roots differ from exact commissioning inputs')
        require(observation['enrollment_sha256'] not in enrollments,'Duplicate enrolled custody')
        enrollments.add(observation['enrollment_sha256'])
        target=observation['target'];base={'kind','host','port','root','host_key','machine_id_sha256'}
        require(isinstance(target,dict) and set(target) in (base,base|{'guest'}) and target['root']==local['target']['root']
                and target['kind'] in ('local','remote'),'Exact independently authenticated target required')
        if target['kind']=='remote':
            require(isinstance(target['host'],str) and re.fullmatch('[a-zA-Z0-9.:\\[\\]-]{1,253}',target['host'])
                    and type(target['port']) is int and 0<target['port']<65536 and target['machine_id_sha256'] is None
                    and isinstance(target['host_key'],str) and 0<len(target['host_key'])<=2048,'Invalid physical host binding')
        else:
            require(target['host'] is None and target['port'] is None and target['host_key'] is None
                    and pin(target['machine_id_sha256']) and 'guest' not in target,'Invalid local target binding')
        if 'guest' in target:
            from guest_lifecycle import public_ssh,valid_id
            guest=target['guest']
            require(isinstance(guest,dict) and set(guest)=={'guest_id','create_request_sha256','ssh_host_public_key','ssh_host_fingerprint'}
                    and valid_id(guest['guest_id']) and pin(guest['create_request_sha256'])
                    and isinstance(guest['ssh_host_public_key'],str)
                    and public_ssh(guest['ssh_host_public_key'].encode())[1]==guest['ssh_host_fingerprint'],'Guest receipt identity differs')
        target_id=json.dumps(target,sort_keys=True,separators=(',',':'))
        require(target_id not in target_ids,'Duplicate controller target');target_ids.add(target_id)
        own=observation['vpn_binding']
        require(isinstance(own,dict) and set(own)=={'account_id','peer_id','ip','wireguard_public_key','enrollment_sha256','server_binding_sha256'}
                and isinstance(own['account_id'],str) and re.fullmatch('[A-Za-z0-9_-]{1,100}',own['account_id'])
                and own['account_id']==local['vpn_binding']['account_id']
                and isinstance(own['peer_id'],str) and re.fullmatch('[A-Za-z0-9_-]{1,100}',own['peer_id'])
                and key(own['wireguard_public_key']) and pin(own['enrollment_sha256']) and pin(own['server_binding_sha256'])
                and str(ipaddress.ip_address(own['ip']))==own['ip']
                and own['ip']==observation['registry_peer_ips'][observation['address']], 'VPN identity/provider differs from signed endpoint')
        require(own['peer_id'] not in vpn_ids and own['wireguard_public_key'] not in vpn_keys and own['ip'] not in vpn_ips,'Duplicate VPN identity')
        vpn_ids.add(own['peer_id']);vpn_keys.add(own['wireguard_public_key']);vpn_ips.add(own['ip'])
        require(isinstance(observation['peers'],dict) and set(observation['peers'])==set(online)-{observation['address']},'All directed peer observations required')
        if observation['address']==local['address']:
            require(all(observation[k]==local[k] for k in fields-{'observed_at_unix'}),'Local readiness facts changed after native review')
    for observation in observations:
        for other in observations:
            if other['address']==observation['address']:continue
            peer=observation['peers'][other['address']]
            require(isinstance(peer,dict) and peer.get('reachable') is True and peer=={'ip':other['vpn_binding']['ip'],'wireguard_public_key':other['vpn_binding']['wireguard_public_key'],
                           'interface':'wt0','reachable':True},'Directed VPN peer key/IP/probe differs')
    return True
