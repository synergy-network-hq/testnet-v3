"""No service/network/provider mutations: canonical relay setup boundary tests."""
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
        self.root=Path('/opt/Synergy')
        self.validator={'listen_address':'10.69.1.2:8551','role':{'kind':'validator','validator_address':'synv1abc','gateway_vpn_ip':'10.69.1.3'}}
        self.gateway={'listen_address':'127.0.0.1:8552','role':{'kind':'gateway','gateway_address':'synv5abc','validator_address':'synv1abc','validator_relay_port':8551,'allowed_origins':['https://example.com']}}
    def test_role_specific_paths_and_unit_no_autostart(self):
        value=relay.configuration(self.root,self.gateway)
        self.assertEqual(value['role']['custody_path'],'/opt/Synergy/keys/apqe/gateway-transport.encrypted.json')
        self.assertNotIn('custody_path',relay.configuration(self.root,self.validator)['role'])
        text=relay.unit_text(self.root)
        self.assertIn('canary-rpc-relay check /opt/Synergy/config/canary-rpc-relay.json',text)
        self.assertIn('MemoryMax=268435456',text)
        self.assertNotIn('synergy-node start',text)
    def test_rejects_listener_origin_role_and_path_injection(self):
        for listen in ['0.0.0.0:8552','10.69.1.3:8552','localhost:8552','127.0.0.1:0','127.0.0.1:65536']:
            with self.assertRaises(ValueError):relay.configuration(self.root,dict(self.gateway,listen_address=listen))
        for origin in ['http://example.com','https://user@example.com','https://example.com/#x','https://example.com?x','https://example.com/','https://example.com:99999']:
            with self.assertRaises(ValueError):relay.configuration(self.root,dict(self.gateway,role=dict(self.gateway['role'],allowed_origins=[origin])))
        with self.assertRaises(ValueError):relay.configuration(self.root,dict(self.gateway,role=dict(self.gateway['role'],custody_path='/tmp/key')))
        with self.assertRaises(ValueError):relay.unit_text(Path('/opt/evil\nExecStart=bad/Synergy'))
    def test_native_check_failure_removes_only_created_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'Synergy';(root/'config').mkdir(parents=True)
            save(root/'config/node.json',{'chain_id':99999})
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt'),patch.object(relay,'native',side_effect=ValueError('bad signature')):
                with self.assertRaisesRegex(ValueError,'bad signature'):relay.configure(root,self.gateway)
            self.assertEqual([p.name for p in (root/'config').iterdir()],['node.json'])
    def test_configuration_publishes_only_after_actual_native_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'Synergy';(root/'config').mkdir(parents=True)
            save(root/'config/node.json',{'chain_id':99999})
            def checked(args):
                self.assertFalse((root/relay.CONFIG).exists())
                self.assertEqual(args[1:3],['canary-rpc-relay','check'])
                self.assertEqual(json.loads(args[-1].read_text())['node_config_path'],str(root/'config/node.json'))
            with patch.object(life,'_require_operator'),patch.object(life,'_sealed_receipt'),patch.object(relay,'native',side_effect=checked):
                result=relay.configure(root,self.gateway)
                self.assertFalse(result['services_started'])
                with self.assertRaisesRegex(ValueError,'already exists'):relay.configure(root,self.gateway)
            self.assertEqual((root/relay.CONFIG).stat().st_mode & 0o777,0o600)


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
        root=base/'Synergy'; root.mkdir(mode=0o700)
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
