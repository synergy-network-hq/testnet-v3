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
