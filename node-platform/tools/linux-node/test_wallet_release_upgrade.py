"""Isolated managed package and restart regressions without a host or service."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import apqe_layout as layout
import lifecycle as life
import wallet_release_package as producer
from synergy_linux import VOLATILE
from synergy_linux import digest
from test_lifecycle import package, save


class WalletReleaseUpgradeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name).resolve()
        self.root = base/'synergy'
        self.candidate = base/'candidate'
        original = package(self.root, 'installed')
        self.manifest = package(self.candidate, 'next')
        for directory in ('tmp', 'evidence'):
            (self.root/directory).mkdir(mode=0o700)
        self.identity = {'role': 'validator', 'chain_id': 99999, 'network_id': 'managed-canary-fixture',
                         'node_name': 'validator-fixture'}
        self.receipt = {**self.identity, 'format': original['format'], 'root': str(self.root),
                        'package_sha256': digest(self.root/'package.json'), 'package_files': original['files']}
        save(self.root/'installation.json', self.receipt)
        self.config = {**self.identity, 'consensus': {'mode': 'validator'},
                       'genesis_path': str(self.root/'network/genesis.json'),
                       'aegis_provider': {'report_path': str(self.root/'lib/apqe/build-report.json'),
                                          'authenticated_report_sha256': 'a'*64}}
        save(self.root/'config/node.json', self.config)
        self.genesis = 'e'*64
        self.preserved = {
            'network/genesis.json': b'exact original signed Genesis fixture',
            'keys/apqe/validator.enc.json': b'original opaque custody',
            'data/history': b'original finalized history',
        }
        for name, contents in self.preserved.items():
            save(self.root/name, contents)
        save(self.root/'network/network-manifest.json', {'genesis_hash': self.genesis})
        report = 'lib/apqe/build-report.json'
        save(self.candidate/report, b'exact new provider report')
        self.manifest['files'][report] = digest(self.candidate/report)
        self.base = copy.deepcopy(self.manifest)
        self.base_package_sha = life._hash_bytes(layout._canonical_package_manifest(self.base))
        selection = {key: 'b'*64 for key in layout.WALLET_RELEASE_PIN_FIELDS}
        selection['issuer_key_id'] = 'exact-release-issuer'
        for name in layout.WALLET_RELEASE_PUBLIC:
            relative = layout.WALLET_RELEASE_PACKAGE_DIRECTORY+'/'+name
            save(self.candidate/relative, f'public test input {name}'.encode())
            self.manifest['files'][relative] = digest(self.candidate/relative)
        for key, name in [('attachment_sha256', 'wallet-dispatch-release.json'),
                          ('issuer_sha256', 'wallet-dispatch-release-issuer.pub'),
                          ('managed_release_manifest_sha256', 'wallet-dispatch-managed-artifacts.json')]:
            selection[key] = digest(self.candidate/layout.WALLET_RELEASE_PACKAGE_DIRECTORY/name)
        relative = layout.WALLET_RELEASE_PACKAGE_DIRECTORY+'/selection.json'
        save(self.candidate/relative, selection)
        self.manifest['files'][relative] = digest(self.candidate/relative)
        save(self.candidate/'package.json', self.manifest)
        self.selection = {**selection, 'from_sealed_package': True}
        self.native_release = {'state': 'verified_pending', 'initial_adoption_before_close': True, 'quick_setup_enrollment': True,
                               'activation_finalized_height': 1001, 'target': 'x86_64-unknown-linux-gnu',
                               'managed_release_manifest_sha256': selection['managed_release_manifest_sha256'],
                               'base_package_manifest_sha256': self.base_package_sha,
                               'executable_sha256': self.manifest['files']['bin/synergy-node'],
                               'apqe_report_sha256': self.manifest['files'][report]}
        self.observations = []
        for mock in (
            patch.object(life, '_require_operator'),
            patch.object(life, '_installation_stage', return_value='commissioned'),
            patch.object(life, '_assert_no_application_processes'),
            patch.object(life, 'recover_consensus_archives'),
            patch.object(life, 'verify_package', side_effect=lambda path: json.loads((path/'package.json').read_bytes())),
            patch.object(life, 'native', side_effect=self.native),
            patch.object(life, '_fresh_conformance'),
            patch('conformance.installed'),
        ):
            mock.start()
            self.addCleanup(mock.stop)

    def native(self, args, **kwargs):
        self.assertEqual(args[:3], [self.candidate/'bin/synergy-node','preflight','--config'])
        config = json.loads(args[-1].read_bytes())
        self.observations.append(config)
        self.assertEqual(config['genesis_path'], self.config['genesis_path'])
        self.assertEqual(config['consensus']['managed_wallet_dispatch_release'], self.selection)
        self.assertEqual(config['aegis_provider']['report_path'], str(self.candidate/'lib/apqe/build-report.json'))
        return json.dumps({**self.identity, 'read_only': True, 'genesis_hash': self.genesis,
                           'signed_genesis_verified': True, 'signed_authority_verified': True,
                           'validator_membership_verified': True, 'wallet_dispatch_release': self.native_release}).encode()

    def test_interruption_after_configuration_write_resumes_with_same_release(self):
        original = life._replace_bytes
        def interrupt(root, path, data, mode, token):
            original(root, path, data, mode, token)
            if path == self.root/'config/node.json':
                raise SystemExit(91)
        with patch.object(life, '_replace_bytes', side_effect=interrupt), self.assertRaises(SystemExit):
            life.upgrade(self.root, self.candidate)
        intent_path = self.root/life.UPGRADE_INTENT
        intent = json.loads(intent_path.read_bytes())
        self.assertEqual(intent['wallet_release']['base_package_manifest_sha256'], self.base_package_sha)
        self.assertEqual(intent['wallet_release']['after_config_sha256'], digest(self.root/'config/node.json'))
        resumed = life.upgrade(self.root, self.candidate)
        self.assertTrue(resumed['resumed'])
        self.assertFalse(resumed['consensus_started'])
        self.assertFalse(intent_path.exists())
        final = json.loads((self.root/'config/node.json').read_bytes())
        self.assertEqual(final['aegis_provider']['report_path'], self.config['aegis_provider']['report_path'])
        self.assertEqual(final['consensus']['managed_wallet_dispatch_release'], self.selection)
        self.assertEqual(resumed['package_sha256'], digest(self.candidate/'package.json'))
        self.assertEqual(len(self.observations), 2)
        for name, contents in self.preserved.items():
            self.assertEqual((self.root/name).read_bytes(), contents)
        self.assertEqual(list((self.root/'tmp').iterdir()), [])

    def test_wrong_native_release_binding_refuses_before_publish(self):
        self.native_release['base_package_manifest_sha256'] = digest(self.candidate/'package.json')
        with self.assertRaisesRegex(ValueError, 'approved Linux package'):
            life.upgrade(self.root, self.candidate)
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
        self.assertEqual(json.loads((self.root/'config/node.json').read_bytes()), self.config)
        self.assertEqual(digest(self.root/'package.json'), self.receipt['package_sha256'])

    def test_later_upgrade_cannot_remove_the_approved_release(self):
        life.upgrade(self.root, self.candidate)
        other = self.root.parent/'ordinary-upgrade'
        package(other, 'ordinary')
        with self.assertRaisesRegex(ValueError, 'cannot remove an independently approved Wallet release'):
            life.upgrade(self.root, other)
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
        self.assertEqual(digest(self.root/'package.json'), digest(self.candidate/'package.json'))

    def test_vote_reserved_at_close_refuses_initial_release_adoption(self):
        self.native_release['initial_adoption_before_close'] = False
        with self.assertRaisesRegex(ValueError, 'previously reserved epoch-close slot'):
            life.upgrade(self.root, self.candidate)
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
        self.assertEqual(json.loads((self.root/'config/node.json').read_bytes()), self.config)

    def test_offline_composer_preserves_exact_base_and_requires_selected_index(self):
        base = self.root.parent/'unsealed-base'
        manifest = {'format': 'synergy-universal-linux-v1', 'architecture': 'x86_64',
                    'release_id': 'wallet-qualification-fixture', 'files': {}}
        elf = b'\x7fELF\x02\x01\x01' + b'\x00'*11 + b'\x3e\x00' + b'fixture'
        names = ['validator', *(f'fixture-role-{i}' for i in range(19))]
        for role in names:
            (base/'roles'/role).mkdir(parents=True, mode=0o700)
        for directory in VOLATILE:
            (base/directory).mkdir(parents=True, exist_ok=True, mode=0o700)
        for executable in ('synergy-node', 'synergy-keytool', 'synergy-genesis', 'netbird'):
            save(base/'bin'/executable, elf + executable.encode())
        save(base/'roles/roles.json', {'roles': names, 'implemented': ['validator']})
        save(base/'assets/node-config.schema.json', b'{}')
        save(base/'tools/runtime_probe.py', b'new stage verifier')
        report = 'lib/apqe/build-report.json'
        save(base/report, b'candidate report')
        manifest['files'] = {p.relative_to(base).as_posix(): digest(p) for p in base.rglob('*') if p.is_file()}
        manifest['apqe_provider'] = {'report_sha256': manifest['files'][report]}
        save(base/'package.json', manifest)
        base_pin = digest(base/'package.json')
        index = producer.artifact_index(base, base_pin, 99999, self.identity['network_id'], self.genesis)
        entry = json.loads(index)['platforms'][0]
        self.assertEqual(entry['base_package_manifest_sha256'], base_pin)
        self.assertEqual(entry['executable_sha256'], digest(base/'bin/synergy-node'))
        inputs = self.candidate/layout.WALLET_RELEASE_PACKAGE_DIRECTORY
        index_path = inputs/'wallet-dispatch-managed-artifacts.json'
        index_path.write_bytes(index)
        selection = json.loads((inputs/'selection.json').read_bytes())
        index_pin = digest(index_path)
        selection['managed_release_manifest_sha256'] = index_pin
        save(inputs/'selection.json', selection)
        output = self.root.parent/'composed'
        with self.assertRaisesRegex(ValueError, 'approved digest'):
            producer.compose(base, base_pin, inputs, 'f'*64, output)
        self.assertFalse(output.exists())
        result = producer.compose(base, base_pin, inputs, index_pin, output)
        self.assertFalse(result['managed_preflight_verified'])
        self.assertEqual(result['base_package_manifest_sha256'], base_pin)
        self.assertNotEqual(result['manifest_sha256'], base_pin)
        self.assertEqual(digest(base/'package.json'), base_pin)
        self.assertEqual(producer.verify_package(output)['files']['bin/synergy-node'], entry['executable_sha256'])
        self.assertEqual(layout.wallet_release_package(output, producer.verify_package(output))[0],
                         {**selection, 'from_sealed_package': True})


if __name__ == '__main__':
    unittest.main()
