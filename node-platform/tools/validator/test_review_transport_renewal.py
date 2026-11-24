import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'renewal', Path(__file__).with_name('review-transport-renewal.py'))
renewal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renewal)


class RenewalReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name).resolve()
        self.installed = directory / 'installed'
        self.candidate = directory / 'candidate'
        self.root = b'r' * 2592
        for artifact_dir in (self.installed, self.candidate):
            artifact_dir.mkdir()
            (artifact_dir / renewal.ROOT).write_bytes(self.root)
        self.scope = dict(chain_id=99999, network_id='renewal-fixture',
                          genesis_artifact_sha256='a' * 64, authority_binding_sha256='b' * 64)
        self.expected = dict(self.scope, issuer_root_sha256=renewal.sha(self.root))
        self.write_pair(self.installed, 1, 10, 100)
        self.write_pair(self.candidate, 2, 50, 150)

    def write_pair(self, directory, generation, start, end, registry=None, admission=None):
        common = dict(self.scope, epoch=1, generation=generation, valid_from_unix=start,
                      expires_at_unix=end)
        registry_payload = dict(common, validators=[{'node_address': 'val-01', 'revoked': False}])
        registry_payload.update(registry or {})
        pins = {renewal.REGISTRY: self.write(directory / renewal.REGISTRY, registry_payload)}
        admission_payload = dict(common, gateways=[{'node_address': 'gateway-01'}],
                                 validator_registry_sha256=pins[renewal.REGISTRY])
        admission_payload.update(admission or {})
        pins[renewal.ADMISSION] = self.write(directory / renewal.ADMISSION, admission_payload)
        self.expected[directory.name] = pins

    @staticmethod
    def write(path, payload):
        raw = json.dumps({'payload': payload, 'signature': [1]}).encode()
        path.write_bytes(raw)
        return renewal.sha(raw)

    def review(self, now=60):
        return renewal.review(self.installed, self.candidate, self.expected, now)

    def test_reports_paired_forward_renewal_without_claiming_native_verification(self):
        result = self.review()
        self.assertEqual((result['from_generation'], result['to_generation']), (1, 2))
        self.assertEqual(result['candidate_pins'], self.expected['candidate'])
        self.assertFalse(result['native_signatures_verified'])
        self.assertFalse(result['activation_authorized'])

    def test_rejects_wrong_pin_or_replaced_issuer(self):
        pin = self.expected['candidate'][renewal.REGISTRY]
        self.expected['candidate'][renewal.REGISTRY] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'differs from its exact pin'):
            self.review()
        self.expected['candidate'][renewal.REGISTRY] = pin
        (self.candidate / renewal.ROOT).write_bytes(b'x' * 2592)
        with self.assertRaisesRegex(ValueError, 'preserve the selected issuer'):
            self.review()

    def test_rejects_mismatched_admission_and_network(self):
        self.write_pair(self.candidate, 2, 50, 150,
                        admission={'validator_registry_sha256': 'c' * 64})
        with self.assertRaisesRegex(ValueError, 'does not bind'):
            self.review()
        self.write_pair(self.candidate, 2, 50, 150, registry={'network_id': 'other'})
        with self.assertRaisesRegex(ValueError, 'selected network scope'):
            self.review()

    def test_rejects_changed_roster_and_json_type(self):
        for entries in ([{'node_address': 'val-02', 'revoked': False}],
                        [{'node_address': 'val-01', 'revoked': 0}]):
            with self.subTest(entries=entries):
                self.write_pair(self.candidate, 2, 50, 150, registry={'validators': entries})
                with self.assertRaisesRegex(ValueError, 'protected payload'):
                    self.review()

    def test_rejects_invalid_renewal_windows_and_generation_skip(self):
        with self.assertRaisesRegex(ValueError, 'with overlap'):
            self.review(now=100)
        self.write_pair(self.candidate, 2, 50, 150, admission={'expires_at_unix': 151})
        with self.assertRaisesRegex(ValueError, 'does not bind'):
            self.review()
        self.write_pair(self.candidate, 3, 50, 150)
        with self.assertRaisesRegex(ValueError, 'exactly one generation'):
            self.review()

    def test_rejects_duplicate_json_keys_even_when_pinned(self):
        raw = b'{"payload": {}, "signature": [1], "signature": [2]}'
        (self.candidate / renewal.REGISTRY).write_bytes(raw)
        self.expected['candidate'][renewal.REGISTRY] = renewal.sha(raw)
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            self.review()
