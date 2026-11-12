#!/usr/bin/env python3
"""Plan/apply one pinned, non-destructive quorum-authority activation from master."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
import lifecycle as life
from apqe_layout import PUBLIC, require_frozen_tree
from synergy_linux import native, require, safe_root

FORMAT = 'synergy-authority-recovery-activation-v1'
PLAN = 'authority-recovery-plan.json'
INTENT = 'evidence/authority-recovery-intent.json'
COMPLETED = 'evidence/authority-recovery-completed.json'
CERT = 'network/authority-recovery-certificate.json'
CONFIG = 'config/node.json'
START = 'config/start-authorized.json'
AUTHORITY = 'network/authority.json'
REGISTRY = 'network/transport-registry.json'
ADMISSION = 'network/rpc-gateway-admission.json'
RELAY = 'config/canary-rpc-relay.json'
RECEIPT = 'installation.json'
LIMIT = 16 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def checked(path, optional=False):
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'linked recovery input forbidden')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional: return None
        raise
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and not before.st_mode & 0o022 and 0 < before.st_size <= LIMIT,
                'unsafe bounded recovery input')
        raw = stream.read(LIMIT + 1)
        after = path.lstat()
        require(len(raw) <= LIMIT and (before.st_dev,before.st_ino,before.st_ctime_ns,before.st_size)
                == (after.st_dev,after.st_ino,after.st_ctime_ns,after.st_size),
                'recovery input changed while read')
        return raw


def pin(raw):
    return None if raw is None else sha(raw)


def staged_name(side, relative):
    return side + '-' + relative.replace('/', '--')


def _write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    life._sync_directory(path.parent)


def verify_certificate(root, certificate, certificate_sha, authority_sha):
    result = json.loads(native([root/'bin/synergy-node', 'authority-recovery', 'check',
                                root/CONFIG, certificate]))
    require(result.get('status') == 'quorum-certificate-verified'
            and result.get('certificate_sha256') == certificate_sha
            and result.get('successor_authority_sha256') == authority_sha
            and result.get('genesis_trust_pin_preserved') is True,
            'native verifier did not authenticate exact quorum recovery certificate')


def _semantic(before, proposed, role, root):
    cert = json.loads(proposed[CERT])
    old_authority = bytes(cert['previous_authority_binding'])
    next_authority = bytes(cert['successor_authority_binding'])
    require(before[AUTHORITY] == old_authority and proposed[AUTHORITY] == next_authority,
            'certificate must bind exact original and successor authority bytes')
    old_payload, new_payload = (json.loads(raw)['payload'] for raw in (old_authority,next_authority))
    require(new_payload['epoch'] == old_payload['epoch'] + 1,
            'strict forward recovery epoch required')
    old_registry, new_registry = (json.loads(raw)['payload'] for raw in (before[REGISTRY],proposed[REGISTRY]))
    mutable = {'epoch','generation','authority_binding_sha256'}
    require(old_registry['authority_binding_sha256'] == sha(old_authority)
            and new_registry['authority_binding_sha256'] == sha(next_authority)
            and old_registry['epoch'] == old_payload['epoch']
            and new_registry['epoch'] == new_payload['epoch']
            and new_registry['generation'] == old_registry['generation'] + 1
            and {k:v for k,v in old_registry.items() if k not in mutable}
                == {k:v for k,v in new_registry.items() if k not in mutable},
            'recovery registry cannot change Genesis, validity, endpoints or credentials')
    config = json.loads(before[CONFIG]); expected = copy.deepcopy(config)
    expected['consensus']['authority_recovery_certificate_path'] = str(root/CERT)
    require(json.loads(proposed[CONFIG]) == expected, 'unrelated node configuration mutation forbidden')
    receipt = json.loads(before[RECEIPT]); expected = dict(receipt,
        authority_recovery_certificate_sha256=sha(proposed[CERT]))
    require(json.loads(proposed[RECEIPT]) == expected, 'unrelated installation receipt mutation forbidden')
    require(config.get('genesis_path') == str(root/'network/genesis.json')
            and config['consensus'].get('authority_binding') == str(root/AUTHORITY)
            and config['consensus'].get('authority_trust_key_path') == str(root/'network/authority-root.pub')
            and config.get('apqe_transport',{}).get('registry_path') == str(root/REGISTRY),
            'canonical original authenticated network paths required')
    if role == 'validator':
        startup = json.loads(before[START]); expected = copy.deepcopy(startup)
        require(set(startup['public_file_sha256']) == set(PUBLIC), 'complete unchanged public pin inventory required')
        expected['public_file_sha256'].update({'authority.json':sha(next_authority),
            'transport-registry.json':sha(proposed[REGISTRY])})
        expected['authority_recovery_certificate_sha256'] = sha(proposed[CERT])
        require(json.loads(proposed[START]) == expected, 'unrelated startup authority mutation forbidden')
    if ADMISSION in before:
        old, new = (json.loads(raw)['payload'] for raw in (before[ADMISSION],proposed[ADMISSION]))
        mutable = {'epoch','generation','authority_binding_sha256','validator_registry_sha256','valid_from_unix','expires_at_unix'}
        require(new['epoch'] == new_payload['epoch'] and new['generation'] == new_registry['generation']
                and new['authority_binding_sha256'] == sha(next_authority)
                and new['validator_registry_sha256'] == sha(proposed[REGISTRY])
                and {k:v for k,v in old.items() if k not in mutable}
                    == {k:v for k,v in new.items() if k not in mutable},
                'recovery admission cannot change gateway identity or credentials')


def prepare(root, stage):
    """Read installed inputs only; emit an exact independently reviewable stage plan."""
    life._require_operator(); require_frozen_tree(stage)
    require(root != stage and root not in stage.parents, 'separate recovery stage required')
    with life._lifecycle_lock(root):
        receipt, _ = life._sealed_receipt(root)
        require(receipt.get('role') in ('validator','rpc_gateway') and receipt.get('chain_id') == 99999,
                'installed Canary validator or gateway required')
        require(not any((root/name).exists() or (root/name).is_symlink()
                for name in (INTENT,life.UPGRADE_INTENT,life.REPLACEMENT_INTENT)), 'finish existing lifecycle intent first')
        role = receipt['role']
        names = {CONFIG,RECEIPT,AUTHORITY,REGISTRY,CERT}
        if role == 'validator': names.add(START)
        if (root/RELAY).exists(): names.add(ADMISSION)
        require(role != 'rpc_gateway' or ADMISSION in names, 'commissioned gateway relay required')
        before = {name:checked(root/name,optional=name==CERT) for name in names}
        proposed = dict(before)
        proposed[CERT] = checked(stage/Path(CERT).name)
        cert = json.loads(proposed[CERT])
        proposed[AUTHORITY] = bytes(cert['successor_authority_binding'])
        proposed[REGISTRY] = checked(stage/Path(REGISTRY).name)
        if ADMISSION in names: proposed[ADMISSION] = checked(stage/Path(ADMISSION).name)
        config = json.loads(before[CONFIG]); config['consensus']['authority_recovery_certificate_path'] = str(root/CERT)
        proposed[CONFIG] = encode(config)
        proposed[RECEIPT] = encode(dict(receipt,authority_recovery_certificate_sha256=sha(proposed[CERT])))
        if START in names:
            startup = json.loads(before[START])
            startup['public_file_sha256'].update({'authority.json':sha(proposed[AUTHORITY]),
                'transport-registry.json':sha(proposed[REGISTRY])})
            startup['authority_recovery_certificate_sha256'] = sha(proposed[CERT])
            proposed[START] = encode(startup)
        _semantic(before,proposed,role,root)
        verify_certificate(root,stage/Path(CERT).name,sha(proposed[CERT]),sha(proposed[AUTHORITY]))
        immutable = {name:sha(checked(root/'network'/name)) for name in PUBLIC
                     if name not in ('authority.json','transport-registry.json')}
        p = {'format':FORMAT,'root':str(root),'role':role,'package_sha256':receipt['package_sha256'],
            'chain_id':receipt['chain_id'],'network_id':receipt['network_id'], 'immutable_network':immutable,
            'before':{name:pin(raw) for name,raw in before.items()},
            'after':{name:sha(raw) for name,raw in proposed.items()}}
        # No installed input is written by planning. Exact old/new public
        # bytes allow interrupted transactions to be retried without inference.
        created = []
        try:
            for side, contents in (('before',before),('after',proposed)):
                for name, raw in sorted(contents.items()):
                    if raw is not None:
                        path = stage/staged_name(side,name)
                        _write_new(path,raw); created.append(path)
            path = stage/PLAN; _write_new(path,encode(p)); created.append(path)
        except BaseException:
            for path in reversed(created): path.unlink()
            life._sync_directory(stage)
            raise
        return {'plan_sha256':sha(encode(p)), 'root':str(root), 'role':role,'installed_files_changed':False}


def load_plan(root, stage, expected):
    require_frozen_tree(stage)
    require(re.fullmatch('[0-9a-f]{64}',expected or '') is not None, 'independent plan pin required')
    raw = checked(stage/PLAN); require(sha(raw)==expected,'recovery plan pin differs')
    p = json.loads(raw)
    require(set(p)=={'format','root','role','package_sha256','chain_id','network_id','immutable_network','before','after'}
            and p['format']==FORMAT and p['root']==str(root) and p['chain_id']==99999
            and p['role'] in ('validator','rpc_gateway'), 'exact Canary activation plan required')
    names = {CONFIG,RECEIPT,AUTHORITY,REGISTRY,CERT}
    if p['role']=='validator': names.add(START)
    if ADMISSION in p['after']: names.add(ADMISSION)
    require(set(p['before'])==set(p['after'])==names
            and (p['role']!='rpc_gateway' or ADMISSION in names), 'exact activation file scope required')
    before, proposed = {}, {}
    for side, contents in (('before',before),('after',proposed)):
        for name, digest in p[side].items():
            require(digest is not None or side=='before' and name==CERT, 'unexpected missing original input')
            value = None if digest is None else checked(stage/staged_name(side,name))
            require(pin(value)==digest,'staged activation input pin differs')
            contents[name]=value
    _semantic(before,proposed,p['role'],root)
    return p,before,proposed


def stopped(root):
    units=life._attributed_units(root)
    for name in (life.UNITS[0],life.RELAY_UNIT):
        if name in units:
            state=units[name]
            require(state.get('ActiveState') in ('inactive','failed') and state.get('MainPID')=='0',
                    'stop attributed node and relay before authority recovery')
    vpn=units.get(life.UNITS[1],{})
    require(vpn.get('ActiveState')=='active' and int(vpn.get('MainPID') or '0')>1,
            'keep attributed VPN running during authority recovery')
    life._assert_no_application_processes(root,vpn_pid=int(vpn['MainPID']))


def preflight(root, role):
    if role=='validator':
        result=json.loads(native([root/'bin/synergy-node','preflight','--config',root/CONFIG]))
        require(result.get('signed_authority_verified') is True and result.get('signed_genesis_verified') is True,
                'native authenticated validator preflight required')
    if (root/RELAY).exists(): native([root/'bin/synergy-node','canary-rpc-relay','check',root/RELAY])


def apply(root, stage, expected):
    life._require_operator(); require(root != stage and root not in stage.parents, 'separate recovery stage required')
    p,before,proposed=load_plan(root,stage,expected)
    intent={'format':FORMAT,'root':str(root),'plan_sha256':expected}
    with life._lifecycle_lock(root):
        receipt,_=life._sealed_receipt(root)
        require(receipt.get('package_sha256')==p['package_sha256'] and receipt.get('role')==p['role']
                and receipt.get('chain_id')==p['chain_id'] and receipt.get('network_id')==p['network_id'],
                'activation installed release or network differs')
        require(not any((root/name).exists() or (root/name).is_symlink()
                for name in (life.UPGRADE_INTENT,life.REPLACEMENT_INTENT)), 'finish other lifecycle intent first')
        life._reject_installation_mounts(root)
        marker=root/INTENT; resumed=marker.exists() or marker.is_symlink()
        if resumed: require(json.loads(checked(marker))==intent,'interrupted recovery requires original exact plan')
        current={name:checked(root/name,optional=name==CERT) for name in p['after']}
        actual={name:pin(raw) for name,raw in current.items()}
        already=actual==p['after']
        require(actual==p['before'] or already or resumed and all(actual[name] in
                (p['before'][name],p['after'][name]) for name in actual), 'installed inputs outside pinned activation')
        require(set(p['immutable_network'])==set(PUBLIC)-{'authority.json','transport-registry.json'},
                'complete preserved Genesis/trust-root pin set required')
        for name,digest in p['immutable_network'].items():
            require(sha(checked(root/'network'/name))==digest,'original Genesis or trust root changed')
        verify_certificate(root,stage/staged_name('after',CERT),p['after'][CERT],p['after'][AUTHORITY])
        if already and not resumed:
            preflight(root,p['role'])
            return {'activation_installed':True,'repeated':True,'services_started':False}
        stopped(root)
        if not resumed: life._replace_bytes(root,marker,encode(intent),0o600,expected)
        # Native owner alone installs authority and durable transition witness.
        # Every interruption retains intent and blocks both service start gates.
        for name in (CERT,CONFIG):
            if checked(root/name,optional=name==CERT)!=proposed[name]:
                life._replace_bytes(root,root/name,proposed[name],0o600,expected)
        action='activate-observer' if p['role']=='rpc_gateway' else 'activate'
        previous_umask=os.umask(0o077)
        try: result=json.loads(native([root/'bin/synergy-node','authority-recovery',action,root/CONFIG]))
        finally: os.umask(previous_umask)
        require(result.get('status')==('observer-trust-activated' if p['role']=='rpc_gateway' else 'activated')
                and result.get('genesis_trust_pin_preserved') is True, 'native authority activation failed')
        require(checked(root/AUTHORITY)==proposed[AUTHORITY],'native activation successor differs')
        for name in (REGISTRY,ADMISSION,START,RECEIPT):
            if name in proposed and checked(root/name)!=proposed[name]:
                life._replace_bytes(root,root/name,proposed[name],0o600,expected)
        require(all(checked(root/name)==raw for name,raw in proposed.items()),'post-activation input mismatch')
        preflight(root,p['role'])
        completed=dict(intent,certificate_sha256=p['after'][CERT],authority_sha256=p['after'][AUTHORITY],
                       package_sha256=p['package_sha256'],native_preflight_passed=True)
        life._replace_bytes(root,root/COMPLETED,encode(completed),0o600,expected)
        marker.unlink();life._sync_directory(marker.parent)
        return {'activation_installed':True,'repeated':resumed,'native_preflight_passed':True,
                'services_started':False,'vpn_reset':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('plan','apply'))
    parser.add_argument('--root',required=True);parser.add_argument('--staged',type=Path,required=True)
    parser.add_argument('--plan-sha256')
    args=parser.parse_args();root=safe_root(args.root);stage=args.staged.absolute()
    result=prepare(root,stage) if args.command=='plan' else apply(root,stage,args.plan_sha256)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,TypeError) as error:
        raise SystemExit(f'Authority activation refused: {error}') from None
