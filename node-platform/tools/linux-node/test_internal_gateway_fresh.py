"""Clean 9969 cannot enter historical Gateway custody replacement."""
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest.mock import patch

import internal_gateway_fresh as gateway


class CleanIncarnationBoundary(unittest.TestCase):
    def scope(self, chain_id):
        return {
            'package_sha256': 'a' * 64,
            'network_id': 'isolated-test-only',
            'chain_id': chain_id,
            'node_name': 'isolated-test-only',
            'gateway_address': 'synv5example',
            'validator_address': 'synv1example',
            'listen_address': '127.0.0.1:8652',
            'sentry_endpoints': ['8.8.8.8:8651'],
            'source_files': {name: 'b' * 64 for name in gateway.SOURCE_FILES},
        }

    def test_historical_same_incarnation_scope_still_validates(self):
        # Pure validation only: no endpoint is dialed and no credentials exist.
        gateway.scope_check(self.scope(1234))

    def test_9969_refuses_before_replacement_inputs_or_native_calls(self):
        root = Path('/isolated-test-only/synergy')
        for operation in ('prepare', 'install'):
            with self.subTest(operation=operation), ExitStack() as stack:
                stack.enter_context(patch.object(gateway.os, 'geteuid', return_value=0))
                spies = [stack.enter_context(patch.object(gateway, name)) for name in
                         ('directory', 'read_public', 'source_file', 'stream_input',
                          'native_candidate')]
                with self.assertRaisesRegex(ValueError, '9969 forbids historical'):
                    if operation == 'prepare':
                        gateway.prepare(root, root, root, root, self.scope(9969))
                    else:
                        gateway.install_and_commission(root, root, root,
                                                       self.scope(9969), 'c' * 64)
                for spy in spies:
                    spy.assert_not_called()

    def test_9969_refuses_even_with_unread_or_missing_old_custody_pins(self):
        scope = self.scope(9969)
        scope['source_files'] = None
        with self.assertRaisesRegex(ValueError, '9969 forbids historical'):
            gateway.scope_check(scope)


if __name__ == '__main__':
    unittest.main()
