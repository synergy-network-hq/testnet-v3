import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import epoch_readiness as readiness
from epoch_readiness import forecast


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.authority = {'sha256': 'a'*64, 'payload': dict(chain_id=99999,
            network_id='canary', epoch=3, epoch_start_height=20001, epoch_end_height=21000)}
        self.registry = {'payload': dict(authority_binding_sha256='a'*64, epoch=3,
            chain_id=99999, network_id='canary', genesis_hash='b'*64, generation=5,
            valid_from_unix=10, expires_at_unix=100)}
        self.telemetry = dict(chain_id=99999, network_identity='canary', genesis_hash='b'*64,
                              epoch=3, finalized_height=20800)

    def report(self):
        return forecast(self.authority, self.registry, self.telemetry, 50)

    def test_warns_before_boundary_and_never_grants_authority(self):
        self.assertEqual(self.report()['status'], 'within-epoch')
        self.telemetry['finalized_height'] = 20898
        r = self.report()
        self.assertEqual(r['status'], 'successor-preparation-due')
        self.assertEqual(r['finalizable_blocks_remaining'], 100)
        self.assertFalse(r['automatic_signing'])
        self.assertTrue(r['signing_authorization_required'])
        self.assertTrue(r['activation_authorization_required'])
        self.assertTrue(r['terminal_qc_required'])

    def test_exact_boundary_and_two_future_windows(self):
        self.telemetry['finalized_height'] = 20998
        r = self.report()
        self.assertEqual(r['status'], 'awaiting-authorized-successor')
        self.assertEqual(r['expected_successor'], dict(epoch=4, first_height=21001, last_height=22000))
        self.assertEqual(r['following_epoch'], dict(epoch=5, first_height=22001, last_height=23000))
        self.assertFalse(r['installed_files_changed'])

    def test_rejects_wrong_live_epoch_chain_network_and_genesis(self):
        for key, value in [('epoch', 4), ('chain_id', 1266), ('network_identity', 'other'),
                           ('genesis_hash', 'c'*64), ('finalized_height', 20999),
                           ('finalized_height', True)]:
            with self.subTest(key=key, value=value):
                bad = dict(self.telemetry, **{key: value})
                with self.assertRaises(ValueError):
                    forecast(self.authority, self.registry, bad, 50)

    def test_rejects_registry_binding_drift_and_unsigned_window_drift(self):
        for target, key, value in [(self.registry['payload'], 'authority_binding_sha256', 'c'*64),
                                   (self.registry['payload'], 'epoch', 4),
                                   (self.authority['payload'], 'epoch_end_height', 22000)]:
            old = target[key]
            target[key] = value
            with self.assertRaises(ValueError): self.report()
            target[key] = old

    def test_registry_expiry_is_a_distinct_blocker(self):
        self.registry['payload']['expires_at_unix'] = 50
        self.assertEqual(self.report()['status'], 'registry-expired-or-not-current')
        self.registry['payload']['expires_at_unix'] = 100
        self.registry['payload']['valid_from_unix'] = 51
        self.assertEqual(self.report()['status'], 'registry-expired-or-not-current')

    def test_does_not_mutate_inputs_and_rejects_invalid_warning_windows(self):
        original = copy.deepcopy((self.authority, self.registry, self.telemetry))
        self.report()
        self.assertEqual(original, (self.authority, self.registry, self.telemetry))
        for count in [0, 1001, True]:
            with self.assertRaises(ValueError):
                forecast(self.authority, self.registry, self.telemetry, 50, count)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base/'synergy'
        self.root.mkdir(mode=0o700)
        self.witness = self.base/'witness.json'
        self.witness.write_bytes(b'public-certified-witness')
        self.witness.chmod(0o600)
        self.output = self.base/'unsigned.json'
        self.calls = []
        patcher = patch.object(readiness, 'safe_root', side_effect=lambda root: Path(root))
        patcher.start(); self.addCleanup(patcher.stop)

    def native(self, args):
        self.calls.append([str(value) for value in args])
        self.assertEqual(args[1:3], ['authority-successor', 'prepare-payload'])
        Path(args[-1]).write_bytes(b'{"epoch":4}')
        return b''

    def test_prepare_reconciles_existing_bytes_without_signing_or_activation(self):
        with patch.object(readiness, 'native', side_effect=self.native):
            first = readiness.prepare(self.root, self.witness, self.output)
            again = readiness.prepare(self.root, self.witness, self.output)
        self.assertFalse(first['repeated'])
        self.assertTrue(again['repeated'])
        self.assertFalse(again['signed'])
        self.assertFalse(again['activated'])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(any(self.base.glob('epoch-readiness-*')))

    def test_failure_and_conflicting_output_leave_inputs_intact_and_clean_scratch(self):
        with patch.object(readiness, 'native', side_effect=ValueError('invalid witness')):
            with self.assertRaises(ValueError): readiness.prepare(self.root, self.witness, self.output)
        self.assertFalse(self.output.exists())
        self.output.write_bytes(b'different-public-proposal')
        self.output.chmod(0o600)
        with patch.object(readiness, 'native', side_effect=self.native):
            with self.assertRaisesRegex(ValueError, 'existing output differs'):
                readiness.prepare(self.root, self.witness, self.output)
        self.assertEqual(self.output.read_bytes(), b'different-public-proposal')
        self.assertEqual(self.witness.read_bytes(), b'public-certified-witness')
        self.assertFalse(any(self.base.glob('epoch-readiness-*')))

    def test_active_root_staging_and_symlink_outputs_are_rejected(self):
        with patch.object(readiness, 'native', side_effect=self.native):
            with self.assertRaises(ValueError):
                readiness.prepare(self.root, self.witness, self.root/'future-authority.json')
            with self.assertRaises(ValueError):
                readiness.prepare(self.root, self.witness, self.base/'outer/../synergy/future.json')
            other = self.base/'other.json'; other.write_bytes(b'{"epoch":4}')
            self.output.symlink_to(other)
            with self.assertRaises(ValueError): readiness.prepare(self.root, self.witness, self.output)
        self.assertEqual(other.read_bytes(), b'{"epoch":4}')


if __name__ == '__main__': unittest.main()
