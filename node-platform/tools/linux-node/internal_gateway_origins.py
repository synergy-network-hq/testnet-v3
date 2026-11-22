"""Read-only preparation of an exact Gateway browser-origin configuration.

This does not publish configuration, reload a service, authorize transactions,
or alter Sentry routes. Applying the returned candidate is a separate managed
operation; never use the route-only updater to bypass its origin invariant.
"""
import json
from pathlib import Path

import canary_rpc_relay as relay
import internal_gateway as gateway


def candidate(before, previous_sha256, allowed_origins, root):
    """Return canonical bytes changing only the explicitly reviewed allowlist."""
    gateway.require(isinstance(before, bytes) and 0 < len(before) <= 65536
                    and relay._is_digest(previous_sha256)
                    and gateway.sha(before) == previous_sha256,
                    'Exact bounded previous Gateway configuration required')
    actual = json.loads(before, object_pairs_hook=relay._unique_fields)
    relay._canonical_gateway_configuration(root, actual)
    gateway.require(isinstance(allowed_origins, list) and allowed_origins,
                    'Explicit nonempty browser origins required')
    changed = json.loads(json.dumps(actual))
    changed['role']['allowed_origins'] = list(allowed_origins)
    # Reuse the role owner's exact HTTPS origin, listener, route and custody
    # locator checks; no separately maintained origin format.
    relay._canonical_gateway_configuration(root, changed)
    gateway.require(changed != actual, 'Gateway browser origins already match')
    return gateway.canonical(changed)


def prepare(root, scope):
    """Verify installed public scope and native custody before returning bytes.

    No input contains private custody. Native inspection reads existing custody
    through its canonical owner; no keys, unlock material or stderr are returned.
    """
    import lifecycle as life
    import synergy_linux as boundary

    fields = {'package_sha256', 'network_id', 'chain_id', 'genesis_sha256',
              'previous_configuration_sha256', 'allowed_origins'}
    gateway.require(isinstance(scope, dict) and set(scope) == fields
                    and all(relay._is_digest(scope[key]) for key in
                            ('package_sha256', 'genesis_sha256', 'previous_configuration_sha256'))
                    and isinstance(scope['network_id'], str) and scope['network_id']
                    and type(scope['chain_id']) is int and 0 < scope['chain_id'] < 2**53,
                    'Exact independently reviewed Gateway origin scope required')
    root = Path(root)
    with life._lifecycle_lock(root):
        receipt, _ = life._sealed_receipt(root)
        gateway.require(receipt['role'] == 'rpc_gateway'
                        and receipt['network_id'] == scope['network_id']
                        and receipt['chain_id'] == scope['chain_id']
                        and gateway.sha(gateway.private(root/'package.json')) == scope['package_sha256']
                        and gateway.sha(gateway.private(root/'network/genesis.json')) == scope['genesis_sha256'],
                        'Installed Gateway origin or package differs')
        before = gateway.private(root/gateway.ROUTE, 65536)
        after = candidate(before, scope['previous_configuration_sha256'], scope['allowed_origins'], root)
        config = json.loads(gateway.private(root/'config/node.json'))
        gateway.require(config['role'] == 'rpc_gateway'
                        and config['network_id'] == scope['network_id']
                        and config['chain_id'] == scope['chain_id'], 'Configured Gateway scope differs')
        admission = gateway.private(root/'network/rpc-gateway-admission.json', 131072)
        gateway.verify_native(boundary, root/'bin/synergy-node', config, after, admission)
        # Native verification must not race a change in the reviewed public input.
        gateway.require(gateway.private(root/gateway.ROUTE, 65536) == before
                        and gateway.private(root/'network/rpc-gateway-admission.json', 131072) == admission
                        and gateway.sha(gateway.private(root/'package.json')) == scope['package_sha256']
                        and gateway.sha(gateway.private(root/'network/genesis.json')) == scope['genesis_sha256']
                        and json.loads(gateway.private(root/'config/node.json')) == config,
                        'Gateway inputs changed during native origin review')
        return after, {'schema': 'synergy-internal-gateway-origins-review-v1',
                       'previous_configuration_sha256': gateway.sha(before),
                       'configuration_sha256': gateway.sha(after),
                       'allowed_origins': list(scope['allowed_origins']),
                       'transport_custody_verified': True, 'mutation_performed': False,
                       'services_reloaded': False}
