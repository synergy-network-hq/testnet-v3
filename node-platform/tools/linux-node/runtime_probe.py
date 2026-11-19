"""Read-only execution of an authenticated staged Linux node's origin verifier.

This is a loader/provider/signature smoke check, not network, KEM, consensus,
commissioning, or production qualification. No custody is read or generated.
"""
import hashlib
import json

import lifecycle as life
from controller import SELECT, engineering_effective_selection, require
from synergy_linux import native


SCHEMA = 'nodenetwork-upgrade-native-preflight-v1'
ORIGIN_FIELDS = {
    'genesis_sha256': 'genesis.json',
    'authority_sha256': 'authority.json',
    'authority_root_sha256': 'authority-root.pub',
    'registry_sha256': 'transport-registry.json',
    'issuer_root_sha256': 'transport-root.pub',
    'manifest_sha256': 'network-manifest.json',
}


def _public_origin(c, policy, receipt, manifest, package):
    from apqe_layout import FORMATION_PUBLIC_INPUTS
    from canary_rpc_relay import (GATEWAY_TARGET_PUBLIC, _gateway_request_bytes,
                                 _gateway_target_config, _is_digest, _unique_fields)
    approved = policy.get('authorization_files', {})
    formation = c.direct(c.control/'authorization/inputs/formation-context.json',
                         True, 4096).read_bytes()
    context = json.loads(formation, object_pairs_hook=_unique_fields)
    require(isinstance(context, dict)
            and set(context) == {'network_id', 'chain_id_hex', 'formation_id'}
            and context['network_id'] == receipt['network_id']
            and context['chain_id_hex'] == format(99999, '064x')
            and _is_digest(context['formation_id']) and context['formation_id'] != '0'*64
            and hashlib.sha256(formation).hexdigest()
            == policy.get('validator_formation_sha256') == approved.get('formation-context.json'),
            'Exact approved formation context required')
    names = {'network/'+name for name in GATEWAY_TARGET_PUBLIC}
    if receipt['role'] == 'validator':
        origin = policy.get('validator_commissioning_files')
        require(isinstance(origin, dict) and set(origin) == FORMATION_PUBLIC_INPUTS,
                'Complete validator public origin approval required')
    else:
        origin = policy.get('gateway_origin_files')
        require(isinstance(origin, dict) and set(origin) == names,
                'Complete gateway public origin approval required')
    source = c.control/'authorization/inputs/commissioning/network'
    raw = {name: c.direct(source/name, True, limit).read_bytes()
           for name, limit in GATEWAY_TARGET_PUBLIC.items()}
    pins = {name: origin['network/'+name] for name in GATEWAY_TARGET_PUBLIC}
    require(all(_is_digest(pin)
                and approved.get('commissioning/network/'+name) == pin
                and hashlib.sha256(raw[name]).hexdigest() == pin
                for name, pin in pins.items()), 'Approved public origin bytes differ')
    independent = policy.get('validator_identity_network', {})
    require(all(independent.get(name) == pins[name]
                for name in ('genesis.json', 'authority.json', 'authority-root.pub')),
            'Independent Genesis origin pins differ')
    pins['provider'] = manifest['files'].get('lib/apqe/build-report.json')
    require(_is_digest(pins['provider'])
            and _is_digest(manifest['files'].get('bin/synergy-node')),
            'Authenticated candidate node and provider required')
    # Snapshot::load consumes only signed public origin/provider data. These
    # fixed observe-mode paths never direct it to validator custody or Worlds.
    config = _gateway_target_config(c, receipt, pins, source)
    config['aegis_provider']['report_path'] = str(package/'lib/apqe/build-report.json')
    return pins, raw, formation, _gateway_request_bytes(config)


def upgrade_native_preflight(c, parameters):
    from apqe_layout import require_frozen_tree
    from canary_rpc_relay import _is_digest, _unique_fields
    require(isinstance(parameters, dict) and set(parameters) == SELECT
            and isinstance(parameters.get('release_id'), str)
            and _is_digest(parameters.get('manifest_sha256')),
            'Exact authenticated candidate selection required', 'invalid_request')
    with life._lifecycle_lock(c.root):
        receipt, current = life._sealed_receipt(c.root)
        policy = c.policy()
        require(receipt.get('role') in ('validator', 'rpc_gateway')
                and receipt.get('chain_id') == 99999
                and _is_digest(policy.get('engineering_initial_authorization_sha256')),
                'Engineering Canary installation required')
        selection = engineering_effective_selection(c.root, policy)
        require(isinstance(selection, dict)
                and all(selection.get(k) == receipt.get(k)
                        for k in ('network_id', 'chain_id', 'node_name')),
                'Installed engineering target differs')
        package, manifest, approval = c.approved_package(parameters)
        require_frozen_tree(package)
        require(approval.get('networks', {}).get(receipt['network_id']) == 99999,
                'Candidate network is not approved')
        pins, raw, formation, config = _public_origin(c, policy, receipt, manifest, package)
        expected = {'schema': 'nodenetwork-gateway-origin-v1',
                    'network_id': receipt['network_id'], 'chain_id': '99999',
                    'mutation_performed': False,
                    **{field: pins[name] for field, name in ORIGIN_FIELDS.items()}}
        observed = json.loads(native(
            [package/'bin/synergy-node', 'canary-rpc-relay', 'inspect-origin'],
            data=config, timeout=120, maximum_stdout=8192), object_pairs_hook=_unique_fields)
        require(observed == expected and isinstance(observed, dict)
                and observed.get('mutation_performed') is False,
                'Candidate native signed origin differs')
        # Bind the successful execution to the same bytes and scope throughout
        # the read. A drifted package/origin never produces a success response.
        after_package, after_manifest, after_approval = c.approved_package(parameters)
        require_frozen_tree(after_package)
        require((after_package, after_manifest, after_approval) == (package, manifest, approval)
                and life._sealed_receipt(c.root) == (receipt, current)
                and c.policy() == policy,
                'Installation or candidate changed during native verification')
        require(_public_origin(c, policy, receipt, after_manifest, package)
                == (pins, raw, formation, config), 'Public origin changed during native verification')
        out = {'schema': SCHEMA, 'release_id': manifest['release_id'],
               'manifest_sha256': parameters['manifest_sha256'],
               'provider_report_sha256': pins['provider'],
               'candidate_node_sha256': manifest['files']['bin/synergy-node'],
               'network_id': receipt['network_id'], 'chain_id': '99999',
               **{('network_manifest_sha256' if field == 'manifest_sha256' else field): pins[name]
                  for field, name in ORIGIN_FIELDS.items()},
               'native_origin_verified': True, 'package_verified': True,
               'mutation_performed': False, 'keys_generated': False,
               'services_started': False, 'network_qualified': False,
               'production_qualified': False, 'automatic_retry': False}
        require(len(out) == 21, 'Native probe response shape differs')
        return out
