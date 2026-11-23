"""Staged native-origin probe trust boundaries; no host, services, or real keys."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import canary_rpc_relay as gateway
import controller
import runtime_probe as probe
from apqe_layout import (WALLET_RELEASE_PACKAGE_DIRECTORY, WALLET_RELEASE_PIN_FIELDS, WALLET_RELEASE_PUBLIC,
                         _canonical_package_manifest)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class RuntimeProbeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()/'synergy'
        self.root.mkdir(mode=0o700)
        self.c = controller.Controller(self.root)
        self.package = self.root/'tmp/update-master'
        self.package.mkdir(mode=0o700, parents=True)
        self.save(self.package/'bin/synergy-node', b'authenticated fixture binary')
        (self.package/'bin/synergy-node').chmod(0o700)
        self.p = {'release_id': 'qualified-candidate', 'manifest_sha256': 'a'*64}
        self.receipt = {'role': 'validator', 'chain_id': 99999,
                        'network_id': 'synergy-posy-canary-fixture', 'node_name': 'validator-02'}
        self.current = {'release_id': 'installed-old'}
        self.manifest = {'release_id': self.p['release_id'],
                         'files': {'bin/synergy-node': 'b'*64,
                                   'lib/apqe/build-report.json': 'c'*64}}
        self.approval = {'networks': {self.receipt['network_id']: 99999}}
        self.policy = {'engineering_initial_authorization_sha256': 'd'*64,
                       'engineering_selection': {**self.receipt}, 'authorization_files': {}}
        self.policy['engineering_selection'].pop('role')
        formation = gateway._gateway_request_bytes({
            'network_id': self.receipt['network_id'], 'chain_id_hex': format(99999, '064x'),
            'formation_id': 'e'*64})
        self.save(self.c.control/'authorization/inputs/formation-context.json', formation)
        self.policy['validator_formation_sha256'] = sha(formation)
        self.policy['authorization_files']['formation-context.json'] = sha(formation)
        self.pins = {}
        for name in gateway.GATEWAY_TARGET_PUBLIC:
            raw = ('fixture public '+name).encode()
            self.pins[name] = sha(raw)
            self.save(self.c.control/'authorization/inputs/commissioning/network'/name, raw)
            self.policy['authorization_files']['commissioning/network/'+name] = sha(raw)
        self.policy['validator_identity_network'] = {name: self.pins[name]
            for name in ('genesis.json', 'authority.json', 'authority-root.pub')}
        self.policy['validator_commissioning_files'] = {
            **{'network/'+name: pin for name, pin in self.pins.items()},
            'config/node.json': 'f'*64, 'config/start-authorized.json': 'f'*64}
        self.native_result = {'schema': 'nodenetwork-gateway-origin-v1',
            'network_id': self.receipt['network_id'], 'chain_id': '99999',
            'mutation_performed': False,
            **{field: self.pins[name] for field, name in probe.ORIGIN_FIELDS.items()}}
        self.calls = []
        for manager in (
            patch.object(self.c, 'policy', side_effect=lambda: copy.deepcopy(self.policy)),
            patch.object(self.c, 'approved_package', side_effect=self.package_read),
            patch('lifecycle._sealed_receipt', side_effect=lambda _: (
                copy.deepcopy(self.receipt), copy.deepcopy(self.current))),
            patch.object(self.c, 'authorize', side_effect=AssertionError('Read must not grant')),
            patch.object(probe, 'native', side_effect=self.native),
        ):
            manager.start()
            self.addCleanup(manager.stop)

    def save(self, path, raw):
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)

    def package_read(self, parameters):
        self.assertEqual(parameters, self.p)
        return self.package, copy.deepcopy(self.manifest), copy.deepcopy(self.approval)

    def native(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[1] == 'preflight-wallet-release':
            executable, _, option, path = args
            self.assertEqual((executable, option), (self.package/'bin/synergy-node', '--config'))
            self.assertEqual(path.parent.parent, self.root/'tmp')
            self.assertEqual((kwargs['timeout'], kwargs['maximum_stdout']), (120, 8192))
            config = json.loads(path.read_bytes())
            self.assertEqual(config['consensus']['managed_wallet_dispatch_release'],
                             {**self.wallet_selection, 'from_sealed_package': True})
            self.assertEqual(config['storage']['data_directory'], str(self.root/'data'))
            self.assertEqual(config['aegis_provider']['report_path'], str(self.package/'lib/apqe/build-report.json'))
            self.assertEqual(Path(config['genesis_path']).parent, path.parent)
            self.assertEqual(set(p.name for p in path.parent.iterdir()),
                             set(gateway.GATEWAY_TARGET_PUBLIC) | {'node.json'})
            return gateway._gateway_request_bytes(self.wallet_result)
        self.assertEqual(args, [self.package/'bin/synergy-node',
                                'canary-rpc-relay', 'inspect-origin'])
        self.assertEqual((kwargs['timeout'], kwargs['maximum_stdout']), (120, 8192))
        config = json.loads(kwargs['data'])
        self.assertEqual(config['aegis_provider'], {
            'report_path': str(self.package/'lib/apqe/build-report.json'),
            'authenticated_report_sha256': 'c'*64})
        self.assertEqual(config['consensus']['mode'], 'observe')
        self.assertFalse(config['rpc']['enabled'])
        return gateway._gateway_request_bytes(self.native_result)

    def run_probe(self):
        return probe.upgrade_native_preflight(self.c, self.p)

    def approve_wallet_release(self):
        genesis = 'f'*64
        manifest = json.dumps({'genesis_hash': genesis}).encode()
        name = 'network-manifest.json'
        self.save(self.c.control/'authorization/inputs/commissioning/network'/name, manifest)
        self.pins[name] = sha(manifest)
        self.policy['authorization_files']['commissioning/network/'+name] = sha(manifest)
        self.policy['validator_commissioning_files']['network/'+name] = sha(manifest)
        self.native_result['manifest_sha256'] = sha(manifest)
        base_hash = sha(_canonical_package_manifest(self.manifest))
        self.wallet_prefix = WALLET_RELEASE_PACKAGE_DIRECTORY + '/'
        files = {name: ('wallet fixture '+name).encode() for name in WALLET_RELEASE_PUBLIC}
        self.wallet_selection = {key: sha(key.encode()) for key in WALLET_RELEASE_PIN_FIELDS}
        self.wallet_selection.update(issuer_key_id='fixture-issuer',
            attachment_sha256=sha(files['wallet-dispatch-release.json']),
            issuer_sha256=sha(files['wallet-dispatch-release-issuer.pub']),
            managed_release_manifest_sha256=sha(files['wallet-dispatch-managed-artifacts.json']))
        files['selection.json'] = _canonical_package_manifest(self.wallet_selection)
        for name, raw in files.items():
            self.save(self.package/self.wallet_prefix/name, raw)
            self.manifest['files'][self.wallet_prefix+name] = sha(raw)
        self.save(self.package/'package.json', _canonical_package_manifest(self.manifest))
        self.p['manifest_sha256'] = sha((self.package/'package.json').read_bytes())
        self.wallet_result = {'schema': 'nodenetwork-wallet-release-preflight-v1', 'read_only': True,
            'chain_id': self.receipt['chain_id'], 'network_id': self.receipt['network_id'],
            'genesis_hash': genesis, 'wallet_dispatch_release': {
                'state': 'verified_pending', 'initial_adoption_before_close': True, 'quick_setup_enrollment': True,
                'activation_finalized_height': 1001, 'target': 'x86_64-unknown-linux-gnu',
                'managed_release_manifest_sha256': self.wallet_selection['managed_release_manifest_sha256'],
                'base_package_manifest_sha256': base_hash,
                'executable_sha256': self.manifest['files']['bin/synergy-node'],
                'apqe_report_sha256': self.manifest['files']['lib/apqe/build-report.json']}}

    def test_validator_and_gateway_probe_fixed_candidate_without_writes_or_grants(self):
        for role in ('validator', 'rpc_gateway'):
            self.receipt['role'] = role
            if role == 'rpc_gateway':
                self.policy['gateway_origin_files'] = {'network/'+k: v for k, v in self.pins.items()}
            before = {p.relative_to(self.root): p.read_bytes()
                      for p in self.root.rglob('*') if p.is_file()}
            out = self.run_probe()
            self.assertEqual(len(out), 21)
            self.assertEqual(out['manifest_sha256'], self.p['manifest_sha256'])
            self.assertEqual(out['network_manifest_sha256'], self.pins['network-manifest.json'])
            self.assertEqual(out['candidate_node_sha256'], 'b'*64)
            self.assertTrue(out['native_origin_verified'])
            self.assertTrue(out['package_verified'])
            for flag in ('mutation_performed', 'keys_generated', 'services_started',
                         'network_qualified', 'production_qualified', 'automatic_retry'):
                self.assertIs(out[flag], False)
            self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                             for p in self.root.rglob('*') if p.is_file()})
        self.assertEqual(len(self.calls), 2)

    def test_unapproved_candidate_or_network_never_executes(self):
        with patch.object(self.c, 'approved_package', side_effect=ValueError('Unapproved')):
            with self.assertRaises(ValueError): self.run_probe()
        self.approval['networks'] = {}
        with self.assertRaises(ValueError): self.run_probe()
        self.assertEqual(self.calls, [])

    def test_foreign_scope_or_missing_engineering_authority_never_executes(self):
        for defect in ('chain', 'role', 'selection', 'initial'):
            policy, receipt = copy.deepcopy(self.policy), copy.deepcopy(self.receipt)
            if defect == 'chain': self.receipt['chain_id'] = 1266
            if defect == 'role': self.receipt['role'] = 'unimplemented'
            if defect == 'selection': self.policy['engineering_selection']['network_id'] = 'foreign'
            if defect == 'initial': self.policy.pop('engineering_initial_authorization_sha256')
            with self.subTest(defect=defect), self.assertRaises(ValueError): self.run_probe()
            self.policy, self.receipt = policy, receipt
        self.assertEqual(self.calls, [])

    def test_altered_origin_provider_or_formation_never_executes(self):
        for defect in ('pin', 'independent', 'provider', 'formation', 'inventory'):
            policy, manifest = copy.deepcopy(self.policy), copy.deepcopy(self.manifest)
            if defect == 'pin': self.policy['authorization_files']['commissioning/network/genesis.json'] = '0'*64
            if defect == 'independent': self.policy['validator_identity_network']['genesis.json'] = '0'*64
            if defect == 'provider': self.manifest['files']['lib/apqe/build-report.json'] = 'bad'
            if defect == 'formation': self.policy['validator_formation_sha256'] = '0'*64
            if defect == 'inventory': self.policy['validator_commissioning_files']['private/extra'] = '0'*64
            with self.subTest(defect=defect), self.assertRaises(ValueError): self.run_probe()
            self.policy, self.manifest = policy, manifest
        self.assertEqual(self.calls, [])

    def test_native_response_requires_exact_scope_shape_and_false_mutation(self):
        for field, value in (('schema', 'foreign'), ('chain_id', 99999),
                             ('registry_sha256', '0'*64), ('mutation_performed', 0),
                             ('extra', 'unapproved')):
            old = copy.deepcopy(self.native_result)
            self.native_result[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.run_probe()
            self.native_result = old
        with patch.object(probe, 'native', return_value=b'{"schema":"a","schema":"b"}'):
            with self.assertRaises(ValueError): self.run_probe()

    def test_native_failure_and_package_drift_never_produce_success(self):
        with patch.object(probe, 'native', side_effect=ValueError('Failed native verifier')):
            with self.assertRaises(ValueError): self.run_probe()
        calls = 0
        def changing(parameters):
            nonlocal calls
            calls += 1
            package, manifest, approval = self.package_read(parameters)
            if calls == 2: manifest['files']['bin/synergy-node'] = '0'*64
            return package, manifest, approval
        with patch.object(self.c, 'approved_package', side_effect=changing):
            with self.assertRaises(ValueError): self.run_probe()

    def test_approved_wallet_release_probes_exact_binary_apqe_and_package_without_install(self):
        self.approve_wallet_release()
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result = self.run_probe()
        self.assertEqual(len(result), 21)
        self.assertEqual(result['manifest_sha256'], self.p['manifest_sha256'])
        self.assertEqual([call[0][1] for call in self.calls], ['canary-rpc-relay', 'preflight-wallet-release'])
        self.assertFalse(result['mutation_performed'])
        self.assertFalse(result['production_qualified'])
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                 for p in self.root.rglob('*') if p.is_file()})
        self.assertFalse(list((self.root/'tmp').glob('wallet-release-preflight-*')))

    def test_wallet_release_refuses_wrong_native_scope_package_report_and_missed_activation(self):
        self.approve_wallet_release()
        self.assertNotEqual(self.wallet_result['wallet_dispatch_release']['base_package_manifest_sha256'],
                            self.p['manifest_sha256'])
        for key, value in (('base_package_manifest_sha256', self.p['manifest_sha256']), ('executable_sha256', '0'*64),
                           ('apqe_report_sha256', '0'*64), ('state', 'missed_activation'),
                           ('quick_setup_enrollment', 1), ('initial_adoption_before_close', False)):
            previous = self.wallet_result['wallet_dispatch_release'][key]
            self.wallet_result['wallet_dispatch_release'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(controller.Refused, 'Candidate native origin response refused'):
                self.run_probe()
            self.wallet_result['wallet_dispatch_release'][key] = previous
        self.wallet_result['genesis_hash'] = '0'*64
        with self.assertRaisesRegex(controller.Refused, 'Candidate native origin response refused'):
            self.run_probe()
        self.assertFalse(list((self.root/'tmp').glob('wallet-release-preflight-*')))

    def test_wallet_release_refuses_incomplete_extra_or_changed_package_before_execution(self):
        self.approve_wallet_release()
        admitted = self.wallet_prefix + 'wallet-dispatch-release.json'
        original = self.manifest['files'].pop(admitted)
        with self.assertRaisesRegex(controller.Refused, 'Authenticated candidate inventory refused'):
            self.run_probe()
        unexpected = self.wallet_prefix + 'unapproved-extra.json'
        self.manifest['files'][admitted] = original
        self.manifest['files'][unexpected] = 'e'*64
        self.save(self.package/unexpected, b'{}')
        with self.assertRaisesRegex(controller.Refused, 'Authenticated candidate inventory refused'):
            self.run_probe()
        self.manifest['files'].pop(unexpected)
        (self.package/unexpected).unlink()
        self.save(self.package/admitted, b'modified signed release')
        with self.assertRaisesRegex(controller.Refused, 'Authenticated candidate inventory refused'):
            self.run_probe()
        self.assertEqual(self.calls, [])

    def test_midprobe_origin_drift_and_unsafe_candidate_tree_are_rejected(self):
        path = self.c.control/'authorization/inputs/commissioning/network/genesis.json'
        def changed(*args, **kwargs):
            out = self.native(*args, **kwargs)
            self.save(path, b'changed during verification')
            return out
        with patch.object(probe, 'native', side_effect=changed):
            with self.assertRaises(ValueError): self.run_probe()
        self.package.chmod(0o777)
        self.calls.clear()
        with self.assertRaises(ValueError): self.run_probe()
        self.assertEqual(self.calls, [])

    def test_renderer_cannot_supply_commands_paths_or_extra_parameters(self):
        for parameters in ({}, {**self.p, 'command': 'arbitrary'},
                           {**self.p, 'manifest_sha256': True},
                           {**self.p, 'path': '/outside'}):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                probe.upgrade_native_preflight(self.c, parameters)
        self.assertEqual(self.calls, [])


    def test_nonexecutable_candidate_is_read_only_fixed_refusal(self):
        path = self.package/'bin/synergy-node'
        for mode in (0o600, 0o755):
            path.chmod(mode)
            with self.assertRaises(controller.Refused) as error: self.run_probe()
            self.assertEqual(error.exception.code, 'runtime_probe_not_executable')
            self.assertEqual(str(error.exception), probe.FAILURES['not_executable'])
            self.assertEqual(path.stat().st_mode & 0o777, mode)
        self.assertEqual(self.calls, [])

    def test_failures_expose_only_fixed_phase_not_private_exception(self):
        cases = [('origin_refused', patch.object(probe, '_public_origin', side_effect=ValueError('PRIVATE'))),
                 ('execution_refused', patch.object(probe, 'native', side_effect=OSError('PRIVATE'))),
                 ('response_refused', patch.object(probe, 'native', return_value=b'PRIVATE'))]
        for phase, manager in cases:
            with manager, self.assertRaises(controller.Refused) as error: self.run_probe()
            self.assertEqual(error.exception.code, 'runtime_probe_'+phase)
            self.assertEqual(str(error.exception), probe.FAILURES[phase])

if __name__ == '__main__': unittest.main()
