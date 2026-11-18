"""Fixed read-only VPN diagnosis: no real daemon, credential or network."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest
import controller
import vpn

REAL_CONTROLLER = controller.Controller


class VpnDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provider = self.root/'tmp/controller/authorization/inputs/vpn-provider.json'
        self.provider.parent.mkdir(parents=True)
        self.provider.write_text(json.dumps({'required_peer_ips': ['10.69.51.205']}))
        self.fake_controller = Mock()
        self.fake_controller.policy.return_value = {'authorization_files': {
            'vpn-provider.json': hashlib.sha256(self.provider.read_bytes()).hexdigest()}}
        self.fake_controller.direct.return_value = self.provider
        self.context = patch.object(vpn, 'client_environment', return_value={'SSL_CERT_FILE': '/contained/public-ca'})
        self.context.start(); self.addCleanup(self.context.stop)
        self.factory = patch.object(controller, 'Controller', return_value=self.fake_controller)
        self.factory.start(); self.addCleanup(self.factory.stop)
        self.enrollment = dict(service_registered=True, enrollment_staged=False,
                               enrollment_recorded=False, reconciliation_required=True, server_bound=False)
        self.public = {'management': {'connected': True}, 'signal': {'connected': True},
                       'publicKey': base64.b64encode(b'p'*32).decode(), 'netbirdIp': '100.64.0.2/16',
                       'private-key': 'NEVER-RETURN-THIS-SECRET'}
        self.commands = []

    def native(self, argv, **options):
        self.commands.append([str(arg) for arg in argv])
        if argv[0] == self.root/'tools/netbird-client':
            self.assertEqual(argv[1:], ['status', '--json'])
            return json.dumps(self.public).encode()
        if argv[0] == 'ip':
            return b'[{"dev":"wt0"}]'
        self.assertEqual(argv, ['ping', '-n', '-I', 'wt0', '-c', '1', '-W', '1', '10.69.51.205'])
        return b''

    def test_connected_client_is_observed_without_any_completed_enrollment_receipt(self):
        with patch.object(vpn, 'native', side_effect=self.native):
            result = vpn.diagnostics(self.root, self.enrollment)
        self.assertFalse(result['enrollment']['enrollment_recorded'])
        self.assertTrue(result['client']['management_connected'])
        self.assertTrue(result['client']['signal_connected'])
        self.assertEqual(result['client']['overlay_address'], '100.64.0.2/16')
        self.assertTrue(result['peers'][0]['reachable'])
        self.assertFalse(result['mutation_performed'])
        self.assertNotIn('NEVER-RETURN', json.dumps(result))
        self.assertEqual(len(self.commands), 3)

    def test_peer_failure_is_categorical_and_never_relays_command_text(self):
        def fail(argv, **options):
            if argv[0] == 'ping': raise ValueError('secret-key private-command-output')
            return self.native(argv, **options)
        with patch.object(vpn, 'native', side_effect=fail):
            result = vpn.diagnostics(self.root, self.enrollment)
        self.assertEqual(result['peers'][0]['error_code'], 'peer_unreachable')
        self.assertTrue(result['peers'][0]['route_via_wt0'])
        self.assertNotIn('secret-key', json.dumps(result))
        with patch.object(vpn, 'native', return_value=b'invalid-json'):
            result = vpn.diagnostics(self.root, self.enrollment)
        self.assertEqual(result['client']['error_code'], 'client_status_unavailable')
        self.assertEqual(result['peers'][0]['error_code'], 'peer_route_unavailable')

    def test_changed_provider_or_refused_ca_never_dispatches_a_client_or_probe(self):
        self.provider.write_text('{"required_peer_ips":["127.0.0.1"]}')
        with patch.object(vpn, 'native') as native:
            result = vpn.diagnostics(self.root, self.enrollment)
            native.assert_not_called()
        self.assertEqual(result['trust']['error_code'], 'approved_trust_scope_refused')
        with patch.object(vpn, 'client_environment', side_effect=ValueError('secret-detail')), patch.object(vpn, 'native') as native:
            result = vpn.diagnostics(self.root, self.enrollment)
            native.assert_not_called()
        self.assertNotIn('secret-detail', json.dumps(result))

    def test_log_is_tail_bounded_public_codes_only_and_rejects_links(self):
        directory = self.root/'logs'; directory.mkdir()
        path = directory/'netbird.log'
        path.write_bytes(b'X'*70000+b'certificate signed by unknown authority secret-api-token')
        real = os.fstat
        def owned(fd):
            actual = real(fd)
            return SimpleNamespace(st_mode=actual.st_mode, st_nlink=actual.st_nlink, st_uid=0,
                                   st_size=actual.st_size, st_mtime_ns=actual.st_mtime_ns)
        with patch.object(vpn.os, 'fstat', side_effect=owned):
            result = vpn.diagnostic_log(self.root)
        self.assertTrue(result['available']); self.assertEqual(result['sampled_bytes'], 65536)
        self.assertEqual(result['codes'], ['tls_untrusted'])
        self.assertNotIn('secret-api-token', json.dumps(result))
        path.unlink(); path.symlink_to(self.provider)
        self.assertFalse(vpn.diagnostic_log(self.root)['available'])
        path.unlink(); directory.rmdir()
        outside = self.root/'outside'; outside.mkdir()
        (outside/'netbird.log').write_bytes(b'certificate signed by unknown authority')
        directory.symlink_to(outside, target_is_directory=True)
        self.assertFalse(vpn.diagnostic_log(self.root)['available'])

    def test_parameterless_controller_read_and_sealed_locked_dispatch(self):
        request = {'version': 1, 'operation': 'vpn_diagnostics', 'parameters': {}}
        self.assertEqual(controller.parse_request(json.dumps(request).encode()), request)
        request['parameters'] = {'path': '/private'}
        with self.assertRaises(controller.Refused): controller.parse_request(json.dumps(request).encode())
        actual = object.__new__(REAL_CONTROLLER)
        actual.root = self.root
        actual.vpn_status = Mock(return_value=self.enrollment)
        import contextlib
        import lifecycle
        with patch.object(lifecycle, '_lifecycle_lock', return_value=contextlib.nullcontext()) as lock, \
             patch.object(lifecycle, '_sealed_receipt') as sealed, \
             patch.object(vpn, 'diagnostics', return_value={'public': True}) as diagnosis:
            self.assertEqual(actual.vpn_diagnostics(), {'public': True})
            lock.assert_called_once_with(self.root)
            sealed.assert_called_once_with(self.root)
            diagnosis.assert_called_once_with(self.root, self.enrollment)
        self.assertIn('vpn_diagnostics', controller.READS)
        self.assertNotIn('vpn_diagnostics', controller.MUTATIONS)


if __name__ == '__main__':
    unittest.main()
