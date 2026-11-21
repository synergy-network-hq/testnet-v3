"""No service/network/provider mutations: canonical relay setup boundary tests."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import canary_rpc_relay as relay
import lifecycle as life
from test_lifecycle import LifecycleTests, save


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.root=Path('/opt/synergy')
        self.selection={'chain_id':14002,'network_id':'relay-fixture'}
        self.validator={'listen_address':'10.69.1.2:8551','role':{'kind':'validator','validator_address':'synv1abc','gateway_vpn_ip':'10.69.1.3'}}
        self.gateway={'listen_address':'127.0.0.1:8552','role':{'kind':'gateway','gateway_address':'synv5abc','validator_address':'synv1abc','validator_relay_port':8551,'allowed_origins':['https://example.com']}}
    def test_role_specific_paths_and_unit_no_autostart(self):
        value=relay.configuration(self.root,self.gateway)
        self.assertEqual(value['role']['custody_path'],'/opt/synergy/keys/apqe/gateway-transport.encrypted.json')
        self.assertNotIn('custody_path',relay.configuration(self.root,self.validator)['role'])
        text=relay.unit_text(self.root)
        self.assertIn('canary-rpc-relay check /opt/synergy/config/canary-rpc-relay.json',text)
        self.assertIn('MemoryMax=268435456',text)
        self.assertNotIn('synergy-node start',text)
    def test_rejects_listener_origin_role_and_path_injection(self):
        for listen in ['0.0.0.0:8552','10.69.1.3:8552','localhost:8552','127.0.0.1:0','127.0.0.1:65536']:
            with self.assertRaises(ValueError):relay.configuration(self.root,dict(self.gateway,listen_address=listen))
        for origin in ['http://example.com','https://user@example.com','https://example.com/#x','https://example.com?x','https://example.com/','https://example.com:99999']:
            with self.assertRaises(ValueError):relay.configuration(self.root,dict(self.gateway,role=dict(self.gateway['role'],allowed_origins=[origin])))
        with self.assertRaises(ValueError):relay.configuration(self.root,dict(self.gateway,role=dict(self.gateway['role'],custody_path='/tmp/key')))
        with self.assertRaises(ValueError):relay.unit_text(Path('/opt/evil\nExecStart=bad/Synergy'))
    def test_explicit_bootstrap_pin_is_gateway_only(self):
        pin = 'a'*64
        def spec(base, value):
            return dict(base, role=dict(base['role'], **{relay.BOOTSTRAP_PIN: value}))
        self.assertEqual(relay.configuration(self.root, spec(self.gateway, pin))['role'][relay.BOOTSTRAP_PIN], pin)
        for invalid in ('A'*64, 'a'*63, None):
            with self.assertRaises(ValueError):
                relay.configuration(self.root, spec(self.gateway, invalid))
        with self.assertRaisesRegex(ValueError, 'unsupported relay role'):
            relay.configuration(self.root, spec(self.validator, pin))

    def test_native_check_failure_removes_only_created_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'synergy';(root/'config').mkdir(parents=True)
            save(root/'config/node.json',self.selection)
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt',return_value=(self.selection,{})),patch.object(relay,'native',side_effect=ValueError('bad signature')):
                with self.assertRaisesRegex(ValueError,'bad signature'):relay.configure(root,self.gateway)
            self.assertEqual([p.name for p in (root/'config').iterdir()],['node.json'])
    def test_configuration_publishes_only_after_actual_native_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'synergy';(root/'config').mkdir(parents=True)
            save(root/'config/node.json',self.selection)
            def checked(args):
                self.assertFalse((root/relay.CONFIG).exists())
                self.assertEqual(args[1:3],['canary-rpc-relay','check'])
                self.assertEqual(json.loads(args[-1].read_text())['node_config_path'],str(root/'config/node.json'))
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt',return_value=(self.selection,{})),patch.object(relay,'native',side_effect=checked):
                result=relay.configure(root,self.gateway)
                self.assertFalse(result['services_started'])
                with self.assertRaisesRegex(ValueError,'already exists'):relay.configure(root,self.gateway)
            self.assertEqual((root/relay.CONFIG).stat().st_mode & 0o777,0o600)


class GatewayBootstrapPinTests(unittest.TestCase):
    def setUp(self):
        temp = ExitStack()
        self.addCleanup(temp.close)
        self.root = Path(temp.enter_context(tempfile.TemporaryDirectory())).resolve()/'synergy'
        for name in ('config', 'evidence'):
            (self.root/name).mkdir(parents=True, mode=0o700, exist_ok=True)
        self.path = self.root/relay.CONFIG
        self.record = self.root/relay.BOOTSTRAP_RECORD
        self.stage = self.root/relay.BOOTSTRAP_STAGED
        self.pin = 'd'*64
        self.config = relay.configuration(self.root, {
            'listen_address': '127.0.0.1:8552', 'role': {'kind': 'gateway',
            'gateway_address': 'synv5abc', 'validator_address': 'synv1abc',
            'validator_relay_port': 8551, 'allowed_origins': ['https://example.com']}})
        save(self.path, self.config)
        self.path.chmod(0o600)
        self.old_raw = self.path.read_bytes()
        self.old_pin = relay._sha(self.old_raw)
        self.state = {'MainPID': '0', 'ActiveState': 'inactive'}
        self.receipt = {'role': 'rpc_gateway', 'chain_id': 99999, 'gateway_commissioned': True}
        self.calls = []
        for name, kwargs in [
            ('_require_operator', {}), ('_reject_installation_mounts', {}),
            ('_sealed_receipt', {'return_value': (self.receipt, {})}),
            ('_attributed_units', {'return_value': {life.RELAY_UNIT: self.state}}),
        ]:
            temp.enter_context(patch.object(life, name, **kwargs))
        temp.enter_context(patch.object(relay, 'native', side_effect=self.checked))

    def checked(self, argv):
        self.assertEqual(argv[:-1], [self.root/'bin/synergy-node', 'canary-rpc-relay', 'check'])
        self.calls.append(argv[-1])
        expected = dict(self.config, role=dict(self.config['role'], **{relay.BOOTSTRAP_PIN: self.pin}))
        self.assertEqual(json.loads(argv[-1].read_bytes()), expected)

    def apply(self):
        return relay.apply_bootstrap_pin(self.root, self.old_pin, self.pin)

    def test_apply_once_and_retry_only_exact_transaction(self):
        result = self.apply()
        self.assertEqual(self.calls, [self.stage])
        self.assertFalse(result['services_started'])
        self.assertFalse(result['already_current'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.record.read_bytes())['phase'], 'complete')
        self.assertTrue(self.apply()['already_current'])
        self.assertEqual(self.calls, [self.stage, self.path])
        with self.assertRaisesRegex(ValueError, 'another request'):
            relay.apply_bootstrap_pin(self.root, self.old_pin, 'b'*64)
        save(self.path, self.config)
        with self.assertRaisesRegex(ValueError, 'differs from completed'):
            relay.verify_bootstrap_pin_record(self.root)

    def test_rejects_running_wrong_prior_and_failed_native_check_without_changes(self):
        self.state.update(MainPID='42', ActiveState='active')
        with self.assertRaisesRegex(ValueError, 'stop the attributed'):
            self.apply()
        self.state.update(MainPID='0', ActiveState='inactive')
        with self.assertRaisesRegex(ValueError, 'exact unpinned prior'):
            relay.apply_bootstrap_pin(self.root, 'b'*64, self.pin)
        self.assertEqual(self.calls, [])
        with patch.object(relay, 'native', side_effect=ValueError('native rejection')):
            with self.assertRaisesRegex(ValueError, 'native rejection'):
                self.apply()
        self.assertEqual(self.path.read_bytes(), self.old_raw)
        self.assertFalse(self.record.exists())
        self.assertFalse(self.stage.exists())

    def test_incomplete_record_blocks_actual_relay_preflight_and_resumes(self):
        original = life._replace_bytes
        def fail_before_completion(root, path, raw, mode, token):
            if path == self.record and json.loads(raw)['phase'] == 'complete':
                raise OSError('interrupted before receipt')
            return original(root, path, raw, mode, token)
        with patch.object(life, '_replace_bytes', side_effect=fail_before_completion):
            with self.assertRaisesRegex(OSError, 'interrupted'):
                self.apply()
        self.assertEqual(json.loads(self.record.read_bytes())['phase'], 'pending')
        save(self.root/'config/node.json', {})
        with patch.object(life, 'verify_authority_recovery_pin'), patch.object(life, 'native') as check:
            with self.assertRaisesRegex(ValueError, 'finish recorded gateway'):
                life.relay_start_check(self.root)
            check.assert_not_called()
        self.assertFalse(self.apply()['already_current'])
        self.assertEqual(self.calls, [self.stage, self.path])
        relay.verify_bootstrap_pin_record(self.root)
        self.assertTrue(self.apply()['already_current'])

    def test_interrupted_after_pending_record_but_before_config_rename_resumes(self):
        original = relay.os.replace
        def fail_before_config_publish(source, target):
            if target == self.path:
                raise OSError('interrupted before publication')
            return original(source, target)
        with patch.object(relay.os, 'replace', side_effect=fail_before_config_publish):
            with self.assertRaisesRegex(OSError, 'interrupted before publication'):
                self.apply()
        self.assertEqual(self.path.read_bytes(), self.old_raw)
        self.assertEqual(json.loads(self.record.read_bytes())['phase'], 'pending')
        self.assertFalse(self.apply()['already_current'])
        self.assertEqual(self.calls, [self.stage, self.stage])
        relay.verify_bootstrap_pin_record(self.root)


class RelayLifecycleTests(LifecycleTests):
    # Inherit isolated existing lifecycle regressions with optional service tests.
    def test_optional_relay_registration_attribution_and_removal(self):
        self.register_fixture()
        save(self.root/relay.CONFIG,{'schema_version':1})
        def state(unit):
            return self.state(unit) if (self.units/unit).exists() else {'LoadState':'not-found','FragmentPath':'','MainPID':'0'}
        with patch.object(life,'_unit_state',side_effect=state):
            result=life.register(self.root)
            self.assertFalse(result['services_started'])
            self.assertIn(life.RELAY_UNIT,life._attributed_units(self.root))
            self.assertEqual(len(life._integration_plan(self.root)['paths']),3)
            life.mutate_owned_service(self.root,'stop',life.RELAY_UNIT)
            self.assertIn(['systemctl','stop',life.RELAY_UNIT],self.operations)
    def test_foreign_relay_unit_is_never_adopted(self):
        self.register_fixture();save(self.root/relay.CONFIG,{})
        save(self.units/life.RELAY_UNIT,b'foreign')
        with patch.object(life,'_unit_state',side_effect=self.state):
            with self.assertRaisesRegex(ValueError,'conflicting relay'):life.register(self.root)
        self.assertEqual(len(life._integration_plan(self.root)['paths']),2)
        self.assertEqual(self.operations,[])
    def test_relay_optional_inventory_survives_upgrade_without_autostart(self):
        save(self.root/relay.CONFIG,{})
        self.register_fixture()
        # fixture's baseline helper intentionally records2; explicitly add3.
        contents=life.rendered_units(self.root)
        save(self.root/'evidence/host-integrations.json',{'root':str(self.root),'paths':[str(self.units/n) for n in contents],
            'sha256':{str(self.units/n):life._hash_bytes(v.encode()) for n,v in contents.items()}})
        with patch.object(life,'_unit_state',side_effect=self.state), self.upgrade_context():
            life.upgrade(self.root,self.candidate)
        self.assertEqual(len(life._integration_plan(self.root)['paths']),3)
        self.assertFalse(any('start' in args or 'restart' in args for args in self.operations))


class GatewayCommissioningTests(unittest.TestCase):
    def fixture(self, base):
        root=base/'synergy'; root.mkdir(mode=0o700)
        staged=base/'staged'; staged.mkdir(mode=0o700)
        receipt={'role':'rpc_gateway','chain_id':99999,'network_id':'canary','root':str(root)}
        save(root/'installation.json',receipt); (root/'keys').mkdir(mode=0o700)
        save(root/'package.json',{'apqe_provider':{'report_sha256':'a'*64}})
        config={'role':'rpc_gateway','chain_id':99999,'network_id':'canary',
            'manifest_path':str(root/'network/network-manifest.json'),'genesis_path':str(root/'network/genesis.json'),
            'consensus':{'mode':'observe','authority_binding':str(root/'network/authority.json'),
                         'authority_trust_key_path':str(root/'network/authority-root.pub')},
            'apqe_transport':{'registry_path':str(root/'network/transport-registry.json'),
                              'registry_trust_key_path':str(root/'network/transport-root.pub')},
            'aegis_provider':{'report_path':str(root/'lib/apqe/build-report.json'),'authenticated_report_sha256':'a'*64}}
        spec={'listen_address':'127.0.0.1:8552','role':{'kind':'gateway','gateway_address':'synv5abc',
            'validator_address':'synv1abc','validator_relay_port':8551,'allowed_origins':[]}}
        for name in relay.GATEWAY_INPUTS:save(staged/name,b'public-or-encrypted-input')
        save(staged/'config/node.json',config);save(staged/relay.CONFIG,relay.configuration(root,spec))
        return root,staged,receipt
    def test_exact_inputs_commission_and_no_validator_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,stage,receipt=self.fixture(Path(tmp).resolve())
            pin=relay.seal_gateway_inputs(stage,root)
            self.assertEqual(len(json.loads((stage/'gateway-commissioning.json').read_text())['files']),12)
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt',return_value=(receipt,{})),patch.object(relay,'_safe_staging'),patch.object(relay,'native') as native:
                result=relay.commission_gateway(root,stage,pin)
                self.assertTrue(result['gateway_commissioned']);self.assertFalse(result['services_started'])
                native.assert_called_once()
                save(root/'keys/apqe/custody.json',{})
                with self.assertRaisesRegex(ValueError,'only own transport'):relay.validate_gateway_layout(root)
    def test_native_rejection_cleans_new_inputs_and_does_not_mark_commissioned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,stage,receipt=self.fixture(Path(tmp).resolve());pin=relay.seal_gateway_inputs(stage,root)
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt',return_value=(receipt,{})),patch.object(relay,'_safe_staging'),patch.object(relay,'native',side_effect=ValueError('invalid admission')):
                with self.assertRaisesRegex(ValueError,'invalid admission'):relay.commission_gateway(root,stage,pin)
            self.assertFalse(any((root/name).exists() for name in relay.GATEWAY_INPUTS))
            self.assertFalse(json.loads((root/'installation.json').read_text()).get('gateway_commissioned',False))
    def test_tampered_staged_input_rejected_before_native_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,stage,receipt=self.fixture(Path(tmp).resolve());pin=relay.seal_gateway_inputs(stage,root)
            save(stage/'keys/apqe/gateway-transport.unlock',b'changed')
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt',return_value=(receipt,{})),patch.object(relay,'_safe_staging'),patch.object(relay,'native') as native:
                with self.assertRaisesRegex(ValueError,'staged input differs'):relay.commission_gateway(root,stage,pin)
                native.assert_not_called()


if __name__=='__main__':unittest.main()
