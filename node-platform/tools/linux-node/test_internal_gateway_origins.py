import json
from pathlib import Path
import unittest
from contextlib import nullcontext
from unittest.mock import patch

import internal_gateway as gateway
import internal_gateway_origins as origins
import canary_rpc_relay as relay


class GatewayOriginCandidateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/opt/independent/synergy')
        self.spec = {'listen_address': '127.0.0.1:8652', 'role': {
            'kind': 'gateway', 'gateway_address': 'synv5example',
            'validator_address': 'synv1example', 'sentry_endpoints': ['8.8.8.8:8651'],
            'allowed_origins': []}}
        self.before = gateway.canonical(relay.configuration(self.root, self.spec))

    def make(self, **changes):
        args = dict(before=self.before, previous_sha256=gateway.sha(self.before),
                    allowed_origins=['https://example.test'], root=self.root)
        args.update(changes)
        return origins.candidate(**args)

    def test_changes_only_explicit_origins_and_preserves_all_role_inputs(self):
        expected = json.loads(self.before)
        expected['role']['allowed_origins'] = ['https://example.test']
        self.assertEqual(self.make(), gateway.canonical(expected))
        self.assertEqual(json.loads(self.before)['role']['allowed_origins'], [])

    def test_refuses_unsupported_or_ambiguous_origins(self):
        for value in [[], '*', ['*'], ['http://example.test'], ['https://example.test/'],
                      ['https://example.test?x'], ['https://user@example.test'],
                      ['https://example.test', 'https://example.test'],
                      ['https://example.test:'+str(70000)], ['https://example.test\r\nX: value']]:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                self.make(allowed_origins=value)

    def test_wrong_hash_foreign_locator_listener_and_role_refuse(self):
        with self.assertRaises(ValueError):
            self.make(previous_sha256='a'*64)
        for path, value in [(('role', 'custody_path'), '/foreign/key'),
                            (('role', 'kind'), 'validator'),
                            (('listen_address',), '0.0.0.0:8652')]:
            changed = json.loads(self.before)
            target = changed
            for component in path[:-1]: target = target[component]
            target[path[-1]] = value
            raw = gateway.canonical(changed)
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.make(before=raw, previous_sha256=gateway.sha(raw))

    def test_duplicate_fields_and_noop_refuse(self):
        raw = self.before.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
        with self.assertRaises(ValueError):
            self.make(before=raw, previous_sha256=gateway.sha(raw))
        after = self.make()
        with self.assertRaises(ValueError):
            self.make(before=after, previous_sha256=gateway.sha(after))

    def test_prepare_checks_native_custody_and_returns_only_readonly_candidate(self):
        import lifecycle
        import synergy_linux
        raw = {'package.json': b'{}', 'network/genesis.json': b'original-genesis',
               gateway.ROUTE: self.before,
               'config/node.json': gateway.canonical({'role': 'rpc_gateway', 'chain_id': 1234,
                                                       'network_id': 'independent-network'}),
               'network/rpc-gateway-admission.json': b'{}'}
        scope = {'package_sha256': gateway.sha(raw['package.json']),
                 'genesis_sha256': gateway.sha(raw['network/genesis.json']),
                 'previous_configuration_sha256': gateway.sha(self.before),
                 'chain_id': 1234, 'network_id': 'independent-network',
                 'allowed_origins': ['https://example.test']}
        receipt = {'role': 'rpc_gateway', 'chain_id': 1234, 'network_id': 'independent-network'}
        def read(path, *_args): return raw[Path(path).relative_to(self.root).as_posix()]
        for native_reply, succeeds in [({'transport_custody_verified': True, 'mutation_performed': False}, True),
                                       ({'transport_custody_verified': False, 'mutation_performed': False}, False)]:
            with patch.object(lifecycle, '_lifecycle_lock', return_value=nullcontext()), \
                    patch.object(lifecycle, '_sealed_receipt', return_value=(receipt, {})), \
                    patch.object(gateway, 'private', side_effect=read), \
                    patch.object(synergy_linux, 'native', return_value=json.dumps(native_reply)) as native:
                if succeeds:
                    after, review = origins.prepare(self.root, scope)
                    self.assertEqual(after, self.make())
                    self.assertEqual(review['configuration_sha256'], gateway.sha(after))
                    self.assertFalse(review['mutation_performed'])
                    self.assertFalse(review['services_reloaded'])
                else:
                    with self.assertRaises(ValueError): origins.prepare(self.root, scope)
                self.assertEqual(native.call_args.args[0][1:], ['canary-rpc-relay', 'inspect-target-candidate'])

    def test_prepare_scope_is_closed_and_requires_exact_public_pins(self):
        for scope in [{}, {'arbitrary_path': '/foreign'},
                      {'package_sha256': 'a'*64, 'genesis_sha256': 'b'*64,
                       'previous_configuration_sha256': 'c'*64, 'chain_id': True,
                       'network_id': 'network', 'allowed_origins': ['https://example.test']}]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                origins.prepare(self.root, scope)


if __name__ == '__main__':
    unittest.main()
