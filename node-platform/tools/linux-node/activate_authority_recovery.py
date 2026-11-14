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
SUCCESSOR_FORMAT = 'synergy-authority-successor-activation-v1'
SUCCESSOR_PROOF = 'successor-proposal.json'
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


def _canary_successor_range(payload):
    epoch, first, last = (payload[key] for key in
                          ('epoch', 'epoch_start_height', 'epoch_end_height'))
    require(payload.get('chain_id') == 99999 and all(type(n) is int for n in (epoch, first, last))
            and 2 <= epoch < (1 << 64) - 1 and 0 < first <= last <= (1 << 64) - 1001,
            'bounded Canary predecessor range required')
    expected_first = 10001 if epoch == 2 else 20001 + 1000 * (epoch - 3)
    expected_last = 20000 if epoch == 2 else expected_first + 999
    require((first, last) == (expected_first, expected_last),
            'predecessor is outside the established 1,000-block Canary continuation schedule')
    return epoch + 1, last + 1, last + 1000


def _semantic(before, proposed, role, root, successor=None):
    cert = json.loads(proposed[CERT] if successor is None else successor)
    if successor is not None:
        require(before[CERT] == proposed[CERT] and before[CONFIG] == proposed[CONFIG]
                and before[RECEIPT] == proposed[RECEIPT],
                'ordinary continuation cannot replace recovery trust, config or installation receipt')
    old_authority = bytes(cert['previous_authority_binding'])
    next_authority = bytes(cert['successor_authority_binding'])
    require(before[AUTHORITY] == old_authority and proposed[AUTHORITY] == next_authority,
            'certificate must bind exact original and successor authority bytes')
    old_payload, new_payload = (json.loads(raw)['payload'] for raw in (old_authority,next_authority))
    require(new_payload['epoch'] == old_payload['epoch'] + 1,
            'strict forward recovery epoch required')
    if successor is not None:
        # Narrow existing operational scope: no roster, key, schedule version,
        # fee, seed, policy, or capacity changes bundled with this continuation.
        adjustable = {'epoch','epoch_start_height','epoch_end_height','anchor_parent',
                      'consensus_parameter_root','protected'}
        require({k:v for k,v in old_payload.items() if k not in adjustable}
                == {k:v for k,v in new_payload.items() if k not in adjustable}
                and (new_payload['epoch'], new_payload['epoch_start_height'],
                     new_payload['epoch_end_height']) == _canary_successor_range(old_payload),
                'only the exact 1,000-block Canary successor with unchanged authority inputs is supported')
        prior_policy, next_policy = old_payload['protected'], new_payload['protected']
        time_key = 'epoch_start_timestamp_ms'
        require({k:v for k,v in prior_policy.items() if k != time_key}
                == {k:v for k,v in next_policy.items() if k != time_key}
                and next_policy[time_key] == prior_policy[time_key] + prior_policy['target_block_time_ms']
                    * (1 + old_payload['epoch_end_height'] - old_payload['epoch_start_height']),
                'successor cannot change protected policy or reset its signed clock')
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


def _stage_location(root,stage,successor):
    if successor:
        require(stage == root/'tmp/authority-successor',
                'successor stage must stay inside canonical installation tmp/authority-successor')
    else:
        require(root != stage and root not in stage.parents,'separate recovery stage required')


def _verify_successor(root, stage, proof_path, proof_sha, proposed, registry, admission):
    node = root/'bin/synergy-node'
    config = root/CONFIG
    proof = checked(proof_path)
    require(sha(proof) == proof_sha, 'exact successor proof pin required')
    old_payload = json.loads(bytes(json.loads(proof)['previous_authority_binding']))['payload']
    next_epoch, _, _ = _canary_successor_range(old_payload)
    result = json.loads(native([node,'authority-successor','check',config,proof_path]))
    require(result.get('status') == 'successor-proof-verified'
            and result.get('successor_proposal_sha256') == proof_sha
            and result.get('successor_authority_sha256') == sha(proposed[AUTHORITY])
            and result.get('epoch') == next_epoch
            and result.get('finalized_height') == old_payload['epoch_end_height'] - 2
            and result.get('genesis_trust_pin_preserved') is True,
            'native verifier did not authenticate exact successor proof')
    cmd = [node,'authority-successor','check-network',config,proof_path,registry,
           stage/'.native-public-verification']
    if admission is not None: cmd.append(admission)
    result = json.loads(native(cmd))
    require(result.get('status') == 'successor-network-verified'
            and result.get('successor_proposal_sha256') == proof_sha
            and result.get('registry_sha256') == sha(proposed[REGISTRY])
            and result.get('admission_sha256') == pin(proposed.get(ADMISSION)),
            'native verifier did not authenticate exact staged transport/relay')


def prepare(root, stage, successor=False):
    """Read installed inputs only; emit an exact independently reviewable stage plan."""
    life._require_operator(); require_frozen_tree(stage)
    _stage_location(root,stage,successor)
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
        proof_path = stage/SUCCESSOR_PROOF if successor else stage/Path(CERT).name
        proof = checked(proof_path)
        if not successor: proposed[CERT] = proof
        cert = json.loads(proof)
        proposed[AUTHORITY] = bytes(cert['successor_authority_binding'])
        registry = stage/Path(REGISTRY).name
        admission = stage/Path(ADMISSION).name if ADMISSION in names else None
        proposed[REGISTRY] = checked(registry)
        if admission is not None: proposed[ADMISSION] = checked(admission)
        if not successor:
            config = json.loads(before[CONFIG]); config['consensus']['authority_recovery_certificate_path'] = str(root/CERT)
            proposed[CONFIG] = encode(config)
            proposed[RECEIPT] = encode(dict(receipt,authority_recovery_certificate_sha256=sha(proposed[CERT])))
        if START in names:
            startup = json.loads(before[START])
            startup['public_file_sha256'].update({'authority.json':sha(proposed[AUTHORITY]),
                'transport-registry.json':sha(proposed[REGISTRY])})
            startup['authority_recovery_certificate_sha256'] = sha(proposed[CERT])
            proposed[START] = encode(startup)
        _semantic(before,proposed,role,root,proof if successor else None)
        if successor:
            life.verify_authority_recovery_pin(root,json.loads(before[CONFIG]),receipt,
                json.loads(before[START]) if START in names else None)
            _verify_successor(root,stage,proof_path,sha(proof),proposed,registry,admission)
        else:
            verify_certificate(root,proof_path,sha(proposed[CERT]),sha(proposed[AUTHORITY]))
        immutable = {name:sha(checked(root/'network'/name)) for name in PUBLIC
                     if name not in ('authority.json','transport-registry.json')}
        p = {'format':SUCCESSOR_FORMAT if successor else FORMAT,'root':str(root),'role':role,'package_sha256':receipt['package_sha256'],
            'chain_id':receipt['chain_id'],'network_id':receipt['network_id'], 'immutable_network':immutable,
            'before':{name:pin(raw) for name,raw in before.items()},
            'after':{name:sha(raw) for name,raw in proposed.items()}}
        if successor: p['successor_proof_sha256'] = sha(proof)
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


def load_plan(root, stage, expected, successor=False):
    require_frozen_tree(stage)
    require(re.fullmatch('[0-9a-f]{64}',expected or '') is not None, 'independent plan pin required')
    raw = checked(stage/PLAN); require(sha(raw)==expected,'recovery plan pin differs')
    p = json.loads(raw)
    fields={'format','root','role','package_sha256','chain_id','network_id','immutable_network','before','after'}
    proof=None
    if successor:
        fields.add('successor_proof_sha256')
        proof=checked(stage/SUCCESSOR_PROOF)
        require(sha(proof)==p.get('successor_proof_sha256'),'exact successor proof pin required')
    require(set(p)==fields and p['format']==(SUCCESSOR_FORMAT if successor else FORMAT) and p['root']==str(root) and p['chain_id']==99999
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
    _semantic(before,proposed,p['role'],root,proof)
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


def successor_stage_pins(p, expected):
    pins = {PLAN:expected, SUCCESSOR_PROOF:p['successor_proof_sha256'],
            Path(REGISTRY).name:p['after'][REGISTRY]}
    if ADMISSION in p['after']: pins[Path(ADMISSION).name]=p['after'][ADMISSION]
    for side in ('before','after'):
        pins.update({staged_name(side,name):digest for name,digest in p[side].items() if digest is not None})
    return pins


def successor_stage_members(stage, pins, *, complete):
    if not stage.exists() and not stage.is_symlink() and not complete: return []
    require_frozen_tree(stage)
    entries=list(stage.iterdir())
    require(all(path.name in pins for path in entries)
            and (not complete or len(entries)==len(pins)), 'undeclared successor staging members')
    for path in entries:
        require(sha(checked(path))==pins[path.name], 'successor staging member pin differs')
    return entries


def finish_successor(root, stage, intent, completed, receipt):
    require(completed['package_sha256']==receipt['package_sha256']
            and completed['role']==receipt['role'] and completed['network_id']==receipt['network_id']
            and receipt['chain_id']==99999 and completed['native_preflight_passed'] is True,
            'installed release or network differs from successor completion')
    require(all(pin(checked(root/name))==digest for name,digest in completed['after'].items()),
            'installed inputs differ from successor completion')
    marker=root/INTENT
    marker_raw=checked(marker,optional=True)
    require(marker_raw is None or json.loads(marker_raw)==intent,
            'interrupted recovery requires original exact plan')
    if marker_raw is None:
        require(not stage.exists() and not stage.is_symlink(),
                'unexpected successor stage after completed activation')
        return
    entries=successor_stage_members(stage,completed['staged'],complete=False)
    preflight(root,receipt['role'])
    for path in entries: path.unlink()
    if stage.exists():
        life._sync_directory(stage)
        stage.rmdir()
    # Also persist the directory removal on retry after an interrupted rmdir.
    life._sync_directory(stage.parent)
    marker.unlink()
    life._sync_directory(marker.parent)


def apply(root, stage, expected, successor=False):
    life._require_operator(); _stage_location(root,stage,successor)
    require(re.fullmatch('[0-9a-f]{64}',expected or '') is not None, 'independent plan pin required')
    intent={'format':SUCCESSOR_FORMAT if successor else FORMAT,'root':str(root),'plan_sha256':expected}
    with life._lifecycle_lock(root):
        receipt,_=life._sealed_receipt(root)
        require(not any((root/name).exists() or (root/name).is_symlink()
                for name in (life.UPGRADE_INTENT,life.REPLACEMENT_INTENT)), 'finish other lifecycle intent first')
        life._reject_installation_mounts(root)
        if successor:
            completed_raw=checked(root/COMPLETED,optional=True)
            completed=json.loads(completed_raw) if completed_raw is not None else {}
            if all(completed.get(key)==value for key,value in intent.items()):
                finish_successor(root,stage,intent,completed,receipt)
                return {'activation_installed':True,'repeated':True,'services_started':False}
        p,before,proposed=load_plan(root,stage,expected,successor)
        require(receipt.get('package_sha256')==p['package_sha256'] and receipt.get('role')==p['role']
                and receipt.get('chain_id')==p['chain_id'] and receipt.get('network_id')==p['network_id'],
                'activation installed release or network differs')
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
        if successor:
            stage_pins=successor_stage_pins(p,expected)
            successor_stage_members(stage,stage_pins,complete=True)
            require(not already or resumed, 'successor installed without exact durable lifecycle intent')
            _verify_successor(root,stage,stage/SUCCESSOR_PROOF,p['successor_proof_sha256'],proposed,
                stage/staged_name('after',REGISTRY),
                stage/staged_name('after',ADMISSION) if ADMISSION in proposed else None)
        else:
            verify_certificate(root,stage/staged_name('after',CERT),p['after'][CERT],p['after'][AUTHORITY])
        if already and not resumed:
            preflight(root,p['role'])
            return {'activation_installed':True,'repeated':True,'services_started':False}
        stopped(root)
        if successor and p['role']=='validator':
            result = json.loads(native([root/'bin/synergy-node','authority-successor','check-local',
                root/CONFIG,stage/SUCCESSOR_PROOF]))
            require(result.get('status')=='successor-local-boundary-verified'
                    and result.get('successor_proposal_sha256')==p['successor_proof_sha256'],
                    'native owner did not verify local durable successor boundary')
        if not resumed: life._replace_bytes(root,marker,encode(intent),0o600,expected)
        # Native owner alone installs authority and durable transition witness.
        # Every interruption retains intent and blocks both service start gates.
        for name in (CERT,CONFIG):
            if checked(root/name,optional=name==CERT)!=proposed[name]:
                life._replace_bytes(root,root/name,proposed[name],0o600,expected)
        action='activate-observer' if p['role']=='rpc_gateway' else 'activate'
        previous_umask=os.umask(0o077)
        cmd=[root/'bin/synergy-node','authority-successor' if successor else 'authority-recovery',
             action,root/CONFIG]
        if successor: cmd.append(stage/SUCCESSOR_PROOF)
        try: result=json.loads(native(cmd))
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
        if successor:
            completed.update(role=p['role'],network_id=p['network_id'],after=p['after'],staged=stage_pins)
        life._replace_bytes(root,root/COMPLETED,encode(completed),0o600,expected)
        if successor: finish_successor(root,stage,intent,completed,receipt)
        else: marker.unlink();life._sync_directory(marker.parent)
        return {'activation_installed':True,'repeated':resumed,'native_preflight_passed':True,
                'services_started':False,'vpn_reset':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('plan','apply','plan-successor','apply-successor'))
    parser.add_argument('--root',required=True);parser.add_argument('--staged',type=Path,required=True)
    parser.add_argument('--plan-sha256')
    args=parser.parse_args();root=safe_root(args.root);stage=args.staged.absolute()
    successor=args.command.endswith('-successor')
    result=prepare(root,stage,successor) if args.command.startswith('plan') else apply(root,stage,args.plan_sha256,successor)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,TypeError) as error:
        raise SystemExit(f'Authority activation refused: {error}') from None
