"""Coordinator/host retirement proof tests; no management server calls."""
import base64
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, call, patch

import lifecycle
import vpn


ACCOUNT = 'expected-account'
ORIGIN = 'https://control.example:8443'
TARGET = '/api/peers/peer-1'
KEY = base64.b64encode(bytes(range(32))).decode()
PEER = {'id': 'peer-1', 'name': 'formation-1', 'hostname': 'guest-1', 'ip': '10.69.0.1'}
ENROLLMENT = {'native_enrollment_verified': True, 'wireguard_public_key': KEY,
              'hostname': PEER['name'], 'overlay_address': PEER['ip'] + '/16', 'management_url': ORIGIN}
BINDING = {'server_binding_verified': True, 'wireguard_public_key': KEY,
           'peer_id': PEER['id'], 'peer_name': PEER['name'], 'hostname': PEER['hostname'], 'ip': PEER['ip']}


def encode(value):
    return json.dumps(value).encode()


class RetirementTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = Path(directory.name)
        self.identity = vpn.retirement_binding(encode(ENROLLMENT), encode(BINDING))
        self.accounts = (200, [{'id': ACCOUNT}])
        self.intent = self.work / vpn.RETIREMENT_INTENT
        self.receipt = self.work / vpn.RETIREMENT
        # Only the OS ownership boundary is simulated on non-root test hosts.
        context = patch.object(vpn, 'retirement_input', side_effect=lambda p, limit=vpn.RETIREMENT_LIMIT: p.read_bytes())
        context.start()
        self.addCleanup(context.stop)

    def test_exact_delete_checks_durable_intent_and_authenticated_absence(self):
        responses = iter([self.accounts, (200, PEER), (204, None), (404, None), (200, [])])

        def exchange(method, path):
            if method == 'DELETE':
                self.assertTrue(self.intent.exists())
                self.assertFalse(self.receipt.exists())
                self.assertEqual(json.loads(self.intent.read_bytes())['binding_sha256'], self.identity['binding_sha256'])
            return next(responses)

        request = Mock(side_effect=exchange)
        self.assertEqual(vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request), self.receipt)
        self.assertEqual(request.call_args_list, [call('GET', '/api/accounts'), call('GET', TARGET),
                                                  call('DELETE', TARGET), call('GET', TARGET), call('GET', '/api/peers')])
        result = json.loads(self.receipt.read_bytes())
        self.assertEqual(result['peer_id'], PEER['id'])
        self.assertIs(result['absence_verified'], True)
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)

    def test_lost_delete_response_reconciles_absence_without_repeating_delete(self):
        request = Mock(side_effect=[self.accounts, (200, PEER), ValueError('connection lost')])
        with self.assertRaisesRegex(ValueError, 'connection lost'):
            vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request)
        self.assertTrue(self.intent.exists())
        self.assertFalse(self.receipt.exists())
        for _ in range(2):
            request = Mock(side_effect=[self.accounts, (404, None), (200, [])])
            self.assertEqual(vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request), self.receipt)
            self.assertTrue(all(operation.args[0] == 'GET' for operation in request.call_args_list))

    def test_wrong_account_first_absence_and_wrong_peer_never_delete(self):
        cases = [[(200, [{'id': 'foreign'}])], [self.accounts, (404, None)],
                 [self.accounts, (200, dict(PEER, hostname='foreign'))],
                 [self.accounts, (200, dict(PEER, id='different'))]]
        for responses in cases:
            with self.subTest(responses=responses):
                request = Mock(side_effect=responses)
                with self.assertRaises(ValueError):
                    vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request)
                self.assertFalse(self.intent.exists() or self.receipt.exists())
                self.assertTrue(all(operation.args[0] == 'GET' for operation in request.call_args_list))

    def test_account_inventory_refuses_replacement_or_unconfirmed_absence(self):
        for inventory in ([dict(PEER, id='replacement')], [{'id': 'malformed'}]):
            with self.subTest(inventory=inventory):
                request = Mock(side_effect=[self.accounts, (200, PEER), (204, None), (404, None), (200, inventory)])
                with self.assertRaisesRegex(ValueError, 'does not confirm absence'):
                    vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request)
                self.assertFalse(self.receipt.exists())
        request = Mock(side_effect=[self.accounts, (404, None), (403, None)])
        with self.assertRaisesRegex(ValueError, 'does not confirm absence'):
            vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request)
        self.assertFalse(self.receipt.exists())

    def test_resume_refuses_changed_binding_before_network(self):
        request = Mock(side_effect=[self.accounts, (200, PEER), (500, None)])
        with self.assertRaisesRegex(ValueError, 'uncertain'):
            vpn._retire_bound_peer(self.work, self.identity, ACCOUNT, request)
        request = Mock()
        with self.assertRaisesRegex(ValueError, 'intent differs'):
            vpn._retire_bound_peer(self.work, dict(self.identity, ip='10.69.0.2'), ACCOUNT, request)
        request.assert_not_called()

    def test_host_import_requires_exact_public_receipt_and_current_binding(self):
        evidence = self.work/'evidence'; evidence.mkdir(mode=0o700)
        (evidence/'vpn-enrollment.json').write_bytes(encode(ENROLLMENT))
        (evidence/'vpn-server-binding.json').write_bytes(encode(BINDING))
        receipt = {'format': 'synergy-vpn-retirement-v1', 'account_id': ACCOUNT, **self.identity,
                   'retired': True, 'absence_verified': True}
        real_lstat = Path.lstat

        def metadata(path):
            info = real_lstat(path)
            return Mock(st_uid=0, st_mode=info.st_mode) if path == evidence else info

        with patch.object(lifecycle, '_require_operator'), patch.object(lifecycle, '_sealed_receipt'), \
                patch.object(lifecycle, '_lifecycle_lock', return_value=nullcontext()), \
                patch.object(Path, 'lstat', metadata):
            raw = encode(receipt)
            with self.assertRaisesRegex(ValueError, 'reviewed'):
                vpn.record_retirement(self.work, raw, 'a' * 64)
            for bad in (dict(receipt, peer_id='foreign'), dict(receipt, absence_verified=1),
                        dict(receipt, account_id=''), dict(receipt, secret='must never import')):
                data = encode(bad)
                with self.assertRaisesRegex(ValueError, 'differs'):
                    vpn.record_retirement(self.work, data, vpn.retirement_hash(data))
            self.assertFalse((evidence/vpn.RETIREMENT).exists())
            self.assertEqual(vpn.record_retirement(self.work, raw, vpn.retirement_hash(raw)), receipt)
            self.assertEqual(vpn.record_retirement(self.work, raw, vpn.retirement_hash(raw)), receipt)

    def test_binding_refuses_unverified_identity_traversal_and_non_https(self):
        for value in (dict(BINDING, peer_id='../victim'), dict(BINDING, server_binding_verified=False),
                      dict(BINDING, ip='10.69.0.2'), dict(BINDING, wireguard_public_key='other')):
            with self.assertRaises(ValueError):
                vpn.retirement_binding(encode(ENROLLMENT), encode(value))
        for origin in ('http://control.example', 'https://user@control.example', 'https://control.example/api',
                       'https://control.example?x=1', 'https://control.example:0'):
            with self.assertRaises(ValueError):
                vpn.management_origin(origin)


if __name__ == '__main__':
    unittest.main()
