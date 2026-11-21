"""Controller boundary tests; native Linux qualification is separate."""
import hashlib
import base64
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import controller as c


def request(op, parameters=None):
    return {'version':1,'operation':op,'parameters':parameters or {}}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name).resolve()/'synergy'
        self.control=self.root/'tmp/controller'
        (self.control/'grants').mkdir(parents=True,mode=0o700)
        (self.control/'tools').mkdir(mode=0o700)
        for path in (self.root,self.root/'tmp',self.control): path.chmod(0o700)
        self.controller=c.Controller(self.root)
        pins={}
        for name in c.ENGINE_MODULES:
            path=self.control/name if name=='controller.py' else self.control/'tools'/name
            path.write_bytes(('pinned-'+name).encode());path.chmod(0o600)
            pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),
                     'community_enrollment':False,'qualified_operations':['stop'],
                     'releases':{},'engine_files':pins}
        self.save(self.control/'policy.json',self.policy)
    def tearDown(self): self.temp.cleanup()
    def save(self,path,value):
        path.write_bytes(c.canonical(value));path.chmod(0o600)
    def test_optional_runtime_probe_does_not_require_new_engine_on_old_release(self):
        import bootstrap
        self.assertIn('tmp/controller/controller.py',c.control_inventory(self.root)[0])
        self.assertEqual(set(bootstrap.enrolled_engine(self.policy)),c.ENGINE_MODULES)
        query=request('upgrade_native_preflight',{'release_id':'candidate','manifest_sha256':'a'*64})
        self.assertEqual(c.parse_request(c.canonical(query)),query)
        with patch.object(c.platform,'system',return_value='Linux'),patch.object(c.platform,'machine',return_value='x86_64'):
            row=next(v for v in self.controller.target()['operations'] if v['operation']==query['operation'])
            self.assertFalse(row['available'])
            with self.assertRaisesRegex(c.Refused,'engine required'):self.controller.dispatch(query)
        self.assertFalse((self.control/'audit.jsonl').exists())
    def test_inventory_binds_only_exact_staged_network_profile(self):
        path = self.control / 'authorization/inputs/network-provisioning.json'
        path.parent.mkdir(parents=True, mode=0o700)
        self.save(path, {'schema': 'synergy-network-provisioning-v1'})
        self.policy['authorization_files'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()}
        self.save(self.control / 'policy.json', self.policy)
        self.assertIn(path.relative_to(self.root).as_posix(), c.control_inventory(self.root)[0])
        self.save(path, {'schema': 'changed'})
        with self.assertRaisesRegex(c.Refused, 'Authorization input drift'):
            c.control_inventory(self.root)
        self.policy['authorization_files'] = {'unexpected.json': 'a' * 64}
        self.save(self.control / 'policy.json', self.policy)
        with self.assertRaisesRegex(c.Refused, 'Unexpected authorization input'):
            c.control_inventory(self.root)
    def test_runtime_probe_optional_bytes_are_pinned_before_dispatch(self):
        import bootstrap
        path=self.control/'tools/runtime_probe.py';path.write_bytes(b'authenticated new read engine');path.chmod(0o600)
        self.policy['engine_files']['runtime_probe.py']=hashlib.sha256(path.read_bytes()).hexdigest();self.save(self.control/'policy.json',self.policy)
        self.assertIn('tmp/controller/tools/runtime_probe.py',c.control_inventory(self.root)[0])
        self.assertIn('runtime_probe.py',bootstrap.enrolled_engine(self.policy))
        query=request('upgrade_native_preflight',{'release_id':'candidate','manifest_sha256':'a'*64})
        with patch.object(c.platform,'system',return_value='Linux'),patch.object(c.platform,'machine',return_value='x86_64'),patch('runtime_probe.upgrade_native_preflight',return_value={'verified':'read-only'}) as native:
            self.assertTrue(next(v for v in self.controller.target()['operations'] if v['operation']==query['operation'])['available'])
            self.assertEqual(self.controller.dispatch(query),{'verified':'read-only'});native.assert_called_once_with(self.controller,query['parameters'])
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(c.Refused,'bytes differ'):self.controller.dispatch(query)
            self.assertEqual(native.call_count,1)
        self.assertFalse((self.control/'audit.jsonl').exists())
        self.assertEqual(list((self.control/'grants').iterdir()),[])
    def test_runtime_probe_rejects_widened_or_unpinned_engine_and_selection(self):
        for p in ({},{'release_id':'candidate','manifest_sha256':'A'*64},{'release_id':'candidate','manifest_sha256':'a'*64,'shell':'no'}):
            with self.assertRaises(c.Refused):c.parse_request(c.canonical(request('upgrade_native_preflight',p)))
        self.policy['engine_files']['unknown.py']='a'*64;self.save(self.control/'policy.json',self.policy)
        with self.assertRaisesRegex(c.Refused,'Complete pinned'):c.control_inventory(self.root)
    def test_unrecognized_fields_duplicate_json_and_shell_operations_rejected(self):
        for raw in (b'{"version":1,"version":1,"operation":"target","parameters":{}}',
                    c.canonical(request('shell',{'command':'touch /tmp/bad'})),
                    c.canonical(request('health',{'root':'/etc'})),
                    c.canonical({'version':True,'operation':'target','parameters':{}})):
            self.assertEqual(c.serve(raw,self.controller)['error']['code'],'invalid_request')
    def test_grant_is_exact_private_expiring_and_consumed_once(self):
        req=request('stop');key=hashlib.sha256(c.canonical(req)).hexdigest()
        grant=self.control/'grants'/(key+'.json')
        with self.assertRaisesRegex(c.Refused,'one-time'):self.controller.authorize(req)
        self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
        self.controller.authorize(req)
        self.assertFalse(grant.exists())
        self.assertEqual(json.loads((self.control/'audit.jsonl').read_bytes())['request_sha256'],key)
        with self.assertRaisesRegex(c.Refused,'one-time'):self.controller.authorize(req)
        with self.assertRaisesRegex(c.Refused,'qualification'):self.controller.authorize(request('restart'))
    def test_expired_or_writable_grants_cannot_authorize(self):
        req=request('stop');key=hashlib.sha256(c.canonical(req)).hexdigest()
        grant=self.control/'grants'/(key+'.json')
        self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())-1})
        with self.assertRaisesRegex(c.Refused,'expired'):self.controller.authorize(req)
        grant.chmod(0o666)
        with self.assertRaises(c.Refused):self.controller.authorize(req)
        self.assertTrue(grant.exists())
    def test_pinned_controller_namespace_rejects_unknown_or_modified_engine(self):
        files,dirs=c.control_inventory(self.root)
        self.assertIn('tmp/controller/controller.py',files)
        self.assertIn('tmp/controller/grants',dirs)
        extra=self.control/'unexpected';extra.write_text('unsafe')
        with self.assertRaisesRegex(c.Refused,'Unexpected'):c.control_inventory(self.root)
        extra.unlink();(self.control/'tools/lifecycle.py').write_text('changed')
        with self.assertRaisesRegex(c.Refused,'bytes differ'):c.control_inventory(self.root)
    def test_uninstall_review_surfaces_uncertain_enrollment_before_grant(self):
        (self.root/'evidence').mkdir(mode=0o700)
        self.save(self.root/c.VPN_ATTEMPT,{'format':'nodenetwork-vpn-attempt-v1'})
        with patch.object(c.platform,'system',return_value='Linux'), \
             patch.object(c.platform,'machine',return_value='x86_64'), \
             patch('synergy_linux.safe_root',return_value=self.root), \
             patch.object(self.controller,'authorize') as authorize:
            result=c.serve(c.canonical(request('uninstall_preflight')),self.controller)
            self.assertFalse(result['ok'])
            self.assertEqual(result['error']['code'],'vpn_reconciliation_required')
            authorize.assert_not_called()
    def test_controller_refuses_symlink_and_hardlink_files(self):
        path=self.control/'policy.json';path.unlink();path.symlink_to(self.control/'controller.py')
        with self.assertRaises(c.Refused):self.controller.policy()
        path.unlink();os.link(self.control/'controller.py',path)
        with self.assertRaises(c.Refused):self.controller.policy()
    def test_unsupported_target_never_mutates(self):
        with patch.object(c.platform,'system',return_value='Darwin'):
            result=c.serve(c.canonical(request('stop')),self.controller)
        self.assertEqual(result['error']['code'],'unsupported_target')
        self.assertFalse((self.control/'audit.jsonl').exists())
    def test_target_keeps_membership_separate_from_install_support(self):
        with patch.object(c.platform,'system',return_value='Linux'),patch.object(c.platform,'machine',return_value='x86_64'):
            value=self.controller.target()
        self.assertTrue(value['localValidatorSupported'])
        self.assertFalse(value['communityEnrollment'])
        self.assertFalse(next(op for op in value['operations'] if op['operation']=='install')['available'])

    def test_identity_generation_requires_exact_genesis_review_and_grant_before_native_execution(self):
        import synergy_linux
        chosen='a'*64
        self.policy['qualified_operations']=['identity_generate']
        self.save(self.control/'policy.json',self.policy)
        req=request('identity_generate',{'genesis_sha256':chosen})
        grant=self.control/'grants'/(hashlib.sha256(c.canonical(req)).hexdigest()+'.json')
        selection={'chain_id':'999999','network_id':'test-network','genesis_sha256':chosen,
                   'genesis_authority_verified':True}
        with patch.object(self.controller,'identity_preflight',return_value=(selection,[])), \
             patch.object(synergy_linux,'native') as native:
            with self.assertRaisesRegex(c.Refused,'Genesis artifact changed'):
                self.controller.identity_generate(request('identity_generate',{'genesis_sha256':'b'*64}))
            with self.assertRaisesRegex(c.Refused,'one-time'):
                self.controller.identity_generate(req)
            native.assert_not_called()
            self.save(grant,{'root':str(self.root),'request_sha256':grant.stem,'expires_at':int(time.time())+60})
            def run(arguments):
                self.assertFalse(grant.exists())
                self.assertIn(self.root/'tmp/pending-validator-custody',arguments)
                return c.canonical({'address':'synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn',
                    'genesis_sha256':chosen,'chain_id_hex':format(999999,'064x'),
                    'membership_granted':False,'possession_verified':True,'unlock':'not a public result'})
            native.side_effect=run
            self.assertNotIn('unlock',self.controller.identity_generate(req))
            native.assert_called_once()
        self.assertEqual(c.serve(c.canonical(request('identity_generate',{'genesis_sha256':chosen,'unlock':'secret'})),self.controller)['error']['code'],'invalid_request')

    def test_reconcile_identity_without_repeating_generation_or_exposing_custody(self):
        import lifecycle
        import synergy_linux
        path=self.root/'tmp/pending-validator-custody'
        pin='b'*64
        selection={'chain_id':'999999','network_id':'test-network','genesis_sha256':pin,
                   'genesis_authority_verified':True,'schema':'nodenetwork-existing-identity-network-v1'}
        with patch.object(lifecycle,'_sealed_receipt'), \
             patch.object(self.controller,'identity_network',return_value=(selection,[])), \
             patch.object(self.controller,'authorize') as authorize, \
             patch.object(synergy_linux,'native') as native:
            self.assertEqual(self.controller.identity_status(),{'pending':False})
            native.assert_not_called()
            req=request('identity_generate',{'genesis_sha256':pin})
            key=self.controller.exact_request_receipt(
                c.IDENTITY_INTENT,'identity_generate','genesis_sha256',pin,create=True)
            self.assertEqual(key,c.request_digest(req))
            with self.assertRaisesRegex(c.Refused,'Interrupted identity preparation'):
                self.controller.identity_status()
            native.assert_not_called()
            path.mkdir()
            native.return_value=c.canonical({'address':'synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn',
                'genesis_sha256':pin,'chain_id_hex':format(999999,'064x'),
                'membership_granted':False,'possession_verified':True,'unlock':'not a public result'})
            status=self.controller.identity_status()
            self.assertTrue(status['pending'])
            self.assertTrue(status['possession_verified'])
            self.assertEqual(status['request_sha256'],key)
            self.assertNotIn('unlock',status)
            self.assertIn('verify-validator-custody',native.call_args.args[0])
            native.side_effect=ValueError('incomplete')
            with self.assertRaisesRegex(c.Refused,'Preserve the files'):
                self.controller.identity_status()
            self.assertTrue(path.is_dir())
            authorize.assert_not_called()

    def test_vpn_grant_binds_exact_private_input_and_consumes_it_before_dispatch(self):
        import lifecycle
        import vpn
        req=request('vpn_enroll')
        self.policy['qualified_operations']=['vpn_enroll']
        self.save(self.control/'policy.json',self.policy)
        stage=self.control/c.VPN_ENROLLMENT
        self.save(stage,{'setup_key':'test-only-input'})
        data=stage.read_bytes()
        (self.root/'vpn').mkdir(mode=0o700)
        (self.root/'evidence').mkdir(mode=0o700)
        grant=self.control/'grants'/(hashlib.sha256(c.canonical(req)).hexdigest()+'.json')
        record={'request_sha256':grant.stem,'root':str(self.root),
                'expires_at':int(time.time())+60,'enrollment_sha256':'0'*64}
        self.save(grant,record)
        state={'service_registered':True,'enrollment_recorded':False}
        with patch.object(lifecycle,'_sealed_receipt',return_value=({'role':'validator'},{})), \
             patch.object(self.controller,'vpn_status',return_value=state), patch.object(vpn,'enroll') as enroll:
            with self.assertRaisesRegex(c.Refused,'does not bind'):
                self.controller.vpn_enroll(req)
            self.assertTrue(stage.exists() and grant.exists())
            enroll.assert_not_called()
            record['enrollment_sha256']=hashlib.sha256(data).hexdigest()
            self.save(grant,record)
            def uncertain(root, supplied):
                self.assertEqual((root,supplied),(self.root,data))
                self.assertFalse(stage.exists() or grant.exists())
                self.assertTrue((self.root/c.VPN_ATTEMPT).is_file())
                raise ValueError('provider outcome uncertain')
            enroll.side_effect=uncertain
            with self.assertRaisesRegex(c.Refused,'did not return a verified receipt'):
                self.controller.vpn_enroll(req)
            self.save(stage,{'setup_key':'newly-staged-input-is-not-reconciliation'})
            with self.assertRaisesRegex(c.Refused,'needs control-plane reconciliation'):
                self.controller.vpn_enroll(req)
            enroll.assert_called_once()
        for op in ('vpn_enroll','vpn_status','diagnostics'):
            self.assertEqual(c.serve(c.canonical(request(op,{'setup_key':'blocked'})),self.controller)['error']['code'],'invalid_request')

    def test_formation_prepare_exact_grant_and_verified_reconciliation(self):
        import lifecycle
        import synergy_linux
        (self.root/'keys').mkdir(mode=0o700)
        self.policy['qualified_operations']=['formation_prepare']
        self.save(self.control/'policy.json',self.policy)
        selection={'formation_sha256':'a'*64}
        req=request('formation_prepare',selection)
        grant=self.control/'grants'/(c.request_digest(req)+'.json')
        public='{"public":true}'
        address='synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn'
        with patch.object(lifecycle,'_sealed_receipt'),patch.object(self.controller,'formation_context',
                 return_value=(selection,[])),patch.object(synergy_linux,'native') as native:
            self.assertEqual(self.controller.formation_status(),{'pending':False})
            with self.assertRaisesRegex(c.Refused,'changed'):
                self.controller.formation_prepare(request('formation_prepare',{'formation_sha256':'b'*64}))
            with self.assertRaisesRegex(c.Refused,'one-time'):self.controller.formation_prepare(req)
            native.assert_not_called()
            self.save(grant,{'root':str(self.root),'request_sha256':grant.stem,'expires_at':int(time.time())+60})
            def run(arguments):
                self.assertFalse(grant.exists())
                self.assertTrue((self.root/c.FORMATION_INTENT).is_file())
                return c.canonical({'address':address,'registration_json':public,
                    'registration_sha256':hashlib.sha256(public.encode()).hexdigest(),
                    'possession_verified':True,'membership_granted':False,'unlock':'must not be exported'})
            native.side_effect=run
            first=self.controller.formation_prepare(req)
            self.assertEqual(first['request_sha256'],grant.stem)
            self.assertFalse(first['membership_granted'])
            self.assertEqual(self.controller.formation_status(),first)
            exported=self.controller.formation_status(export=True)
            self.assertEqual(exported['registration_json'],public)
            self.assertNotIn('unlock',exported)
            self.assertIn('verify-validator-formation',native.call_args.args[0])
            with self.assertRaisesRegex(c.Refused,'reconciled'):self.controller.formation_prepare(req)

    def test_existing_chain_stages_signed_genesis_without_genesis_membership(self):
        public={'genesis.json':'{"unsigned":{"network":{"chain_id":99999,"network_id":"existing-network"}}}',
                'authority.json':'{}','authority-root.pub':base64.b64encode(b'public-test-key').decode()}
        contents=c.genesis_artifact_bytes(public)
        pins={name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()}
        self.policy.update(qualified_operations=['genesis_stage'],validator_identity_network=pins,
                           validator_identity_mode='existing_network')
        self.save(self.control/'policy.json',self.policy)
        req=request('genesis_stage',{'artifacts':public})
        key=c.request_digest(req)
        grant=self.control/'grants'/(key+'.json')
        release={'network_id':'existing-network','chain_id':99999}
        with patch.object(self.controller,'identity_release',return_value=(release,[])), \
             patch.object(self.controller,'formation_context') as formation, \
             patch('synergy_linux.native') as native:
            policy=self.controller.genesis_stage()
            self.assertEqual(policy['schema'],'nodenetwork-existing-genesis-stage-policy-v1')
            self.assertFalse(policy['membership_granted'])
            self.assertNotIn('address',policy)
            with self.assertRaisesRegex(c.Refused,'one-time'):
                self.controller.genesis_stage(req)
            self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
            native.side_effect=ValueError('invalid Genesis signature')
            with self.assertRaisesRegex(ValueError,'invalid Genesis'):
                self.controller.genesis_stage(req)
            self.assertFalse((self.root/c.GENESIS_STAGE).exists())
            self.assertFalse((self.root/c.GENESIS_STAGE_WORK).exists())
            self.assertFalse(grant.exists())
            native.side_effect=None
            self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
            result=self.controller.genesis_stage(req)
            self.assertFalse(result['membership_verified'])
            self.assertFalse(result['membership_granted'])
            self.assertEqual(result['request_sha256'],key)
            self.assertEqual(self.controller.identity_network()[0]['stage_request_sha256'],key)
            self.assertIn('verify-binding',native.call_args.args[0])
            self.assertFalse((self.root/'tmp/pending-validator-custody').exists())
            with self.assertRaisesRegex(c.Refused,'already staged'):
                self.controller.genesis_stage(req)
            formation.assert_not_called()

    def test_public_genesis_upload_exact_bytes_native_membership_and_reconciliation(self):
        public={'genesis.json':'{"text":"café"}','authority.json':'{}',
                'authority-root.pub':base64.b64encode(b'\xff\x00\x82').decode()}
        contents=c.genesis_artifact_bytes(public)
        pins={name:hashlib.sha256(raw).hexdigest() for name,raw in contents.items()}
        self.policy.update(qualified_operations=['genesis_stage'],validator_identity_network=pins)
        self.save(self.control/'policy.json',self.policy)
        req=request('genesis_stage',{'artifacts':public})
        key=c.request_digest(req)
        grant=self.control/'grants'/(key+'.json')
        self.assertEqual(c.parse_request(c.canonical(req)),req)
        for root_key in ('/wCC\n','Zh==',''):
            malformed=request('genesis_stage',{'artifacts':{**public,'authority-root.pub':root_key}})
            self.assertEqual(c.serve(c.canonical(malformed),self.controller)['error']['code'],'invalid_request')
        selection={'formation_sha256':'a'*64}
        addr='synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn'
        with patch.object(self.controller,'formation_context',return_value=(selection,[])), \
             patch.object(self.controller,'formation_result',return_value={'address':addr}), \
             patch.object(self.controller,'genesis_review') as native:
            policy=self.controller.genesis_stage()
            self.assertEqual(policy['authority_root_sha256'],pins['authority-root.pub'])
            with self.assertRaisesRegex(c.Refused,'one-time'):self.controller.genesis_stage(req)
            self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
            with self.assertRaisesRegex(c.Refused,'independently approved'):
                self.controller.genesis_stage(request('genesis_stage',{'artifacts':{**public,'genesis.json':'{}'}}))
            self.assertTrue(grant.exists())
            native.assert_not_called()
            native.return_value={'bound':False,'address':'other-identity'}
            with self.assertRaisesRegex(c.Refused,'exact prepared'):self.controller.genesis_stage(req)
            self.assertFalse((self.root/c.GENESIS_STAGE).exists())
            self.assertFalse((self.root/c.GENESIS_STAGE_WORK).exists())
            self.assertFalse(grant.exists())
            self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
            native.return_value={'bound':False,'address':addr}
            accepted=self.controller.genesis_stage(req)
            self.assertEqual(accepted['request_sha256'],key)
            self.assertEqual(self.controller.genesis_stage_request(pins),{'stage_request_sha256':key})
            self.assertEqual({name:(self.root/c.GENESIS_STAGE/name).read_bytes() for name in contents},contents)
            with self.assertRaisesRegex(c.Refused,'already staged'):self.controller.genesis_stage(req)
            (self.root/c.GENESIS_STAGE/'genesis.json').write_text('{}')
            with self.assertRaisesRegex(c.Refused,'input changed'):self.controller.genesis_stage_request(pins)

    def test_vpn_connectivity_does_not_imply_server_binding(self):
        import lifecycle
        import vpn
        evidence=self.root/'evidence'; evidence.mkdir(mode=0o700)
        self.save(evidence/'vpn-enrollment.json',{'native_enrollment_verified':True,
                  'overlay_address':'100.64.20.1/16','wireguard_public_key':'expected'})
        online={'publicKey':'different','netbirdIp':'100.64.20.1/16',
                'management':{'connected':True},'signal':{'connected':True}}
        with patch.object(lifecycle,'_integration_plan',return_value={'paths':[]}), \
             patch.object(lifecycle,'_attributed_units',return_value={'synergy-vpn.service':{'ActiveState':'active'}}), \
             patch.object(vpn,'status',return_value=online):
            self.assertFalse(self.controller.vpn_status()['connected'])
            online['publicKey']='expected'
            self.assertTrue(self.controller.vpn_status()['connected'])
            self.assertFalse(self.controller.vpn_status()['server_bound'])
            self.save(evidence/'vpn-server-binding.json',{'server_binding_verified':True,
                      'peer_id':'authenticated-peer','ip':'100.64.20.1','wireguard_public_key':'expected'})
            self.assertTrue(self.controller.vpn_status()['server_bound'])

    def test_formation_commission_start_and_restart_refuse_unbound_vpn_before_grant(self):
        import lifecycle
        import synergy_linux
        (self.root/c.FORMATION_CUSTODY).mkdir(mode=0o700)
        ready={'service_registered':True,'enrollment_recorded':True,
               'reconciliation_required':False,'server_bound':True,'connected':True}
        with patch.object(c.platform,'system',return_value='Linux'), \
             patch.object(c.platform,'machine',return_value='x86_64'), \
             patch.object(synergy_linux,'safe_root'), \
             patch.object(self.controller,'vpn_status') as vpn, \
             patch.object(self.controller,'genesis_binding') as binding, \
             patch.object(self.controller,'authorize') as authorize, \
             patch.object(lifecycle,'commission') as commission, \
             patch.object(lifecycle,'start_check') as start_check, \
             patch.object(lifecycle,'mutate_owned_service') as mutate, \
             patch('root_guard.check_registration') as guard:
            for field in ready:
                vpn.return_value={**ready,field:not ready[field]}
                for operation in ('commission','start','restart'):
                    with self.subTest(field=field,operation=operation), self.assertRaises(c.Refused) as refusal:
                        self.controller.dispatch(request(operation))
                    self.assertEqual(refusal.exception.code,'vpn_readiness_required')
            for action in (binding,authorize,commission,start_check,mutate,guard):action.assert_not_called()
            vpn.return_value=ready
            guard.side_effect=ValueError('registration differs')
            with self.assertRaisesRegex(ValueError,'registration differs'):
                self.controller.dispatch(request('start'))
            authorize.assert_not_called()
            start_check.assert_not_called()
            guard.side_effect=None
            for operation in ('start','restart'):
                self.assertEqual(self.controller.dispatch(request(operation))['requested'],operation)
            self.assertEqual(authorize.call_count,2)
            self.assertEqual(start_check.call_count,2)
            self.assertEqual(mutate.call_count,2)

    def test_start_checks_exact_grant_before_recovery_but_consumes_only_after_validation(self):
        import lifecycle
        import synergy_linux
        self.policy['qualified_operations']=['start','restart']
        self.save(self.control/'policy.json',self.policy)
        with patch.object(c.platform,'system',return_value='Linux'), \
             patch.object(c.platform,'machine',return_value='x86_64'), \
             patch.object(synergy_linux,'safe_root'), \
             patch.object(self.controller,'require_bound_validator_vpn'), \
             patch('root_guard.check_registration'), \
             patch.object(lifecycle,'start_check') as check, \
             patch.object(lifecycle,'mutate_owned_service') as mutate:
            for operation in ('start','restart'):
                query=request(operation); key=c.request_digest(query)
                grant=self.control/'grants'/(key+'.json')
                with self.assertRaises(c.Refused): self.controller.dispatch(query)
                check.assert_not_called(); mutate.assert_not_called()
                self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
                original=grant.read_bytes()
                check.side_effect=ValueError('unsafe startup inventory')
                with self.assertRaisesRegex(ValueError,'unsafe startup inventory'): self.controller.dispatch(query)
                self.assertEqual(grant.read_bytes(),original)
                self.assertFalse((self.control/'audit.jsonl').exists()); mutate.assert_not_called()
                check.reset_mock()
                def expire(root,*,authorize):
                    self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':0})
                    authorize()
                check.side_effect=expire
                with self.assertRaises(c.Refused): self.controller.dispatch(query)
                self.assertTrue(grant.exists()); self.assertFalse((self.control/'audit.jsonl').exists())
                mutate.assert_not_called()
                self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
                check.side_effect=lambda root,*,authorize:authorize()
                self.assertEqual(self.controller.dispatch(query)['requested'],operation)
                self.assertFalse(grant.exists())
                self.assertEqual(json.loads((self.control/'audit.jsonl').read_bytes())['request_sha256'],key)
                (self.control/'audit.jsonl').unlink()
                check.reset_mock(); mutate.reset_mock()

    def test_log_summary_keeps_only_bounded_complete_line_counts(self):
        logs=self.root/'logs'; logs.mkdir(mode=0o700)
        path=logs/'node.log'
        path.write_bytes(b'x'*(2*c.LOG_WINDOW)+b'\n2026-11-11T12:00:01Z  WARN private-content\n'
                         b'2026-11-11T12:00:02Z INFO private-token\nunfinished')
        path.chmod(0o600)
        result=c.log_summary(self.root)
        self.assertEqual(result['window_bytes'],c.LOG_WINDOW)
        self.assertEqual(result['complete_lines'],2)
        self.assertEqual(result['severity']['warn'],1)
        self.assertEqual(result['severity']['info'],1)
        self.assertNotIn('private-token',json.dumps(result))
        path.unlink(); path.symlink_to(self.control/'policy.json')
        with self.assertRaises(OSError): c.log_summary(self.root)

    def test_managed_removal_verifies_account_and_resumes_only_exact_teardown(self):
        pin={'uid':999,'gid':65534,'label':'Synergy NodeNetwork '+'a'*32}
        host=self.control/'host';host.mkdir(mode=0o700)
        links={name:self.root.parent/(name+'.link') for name in c.HOST_LINKS}
        self.policy['host_files']={}
        for name in ('authorized_keys',*links):
            path=host/name;path.write_bytes(name.encode());path.chmod(0o600)
            self.policy['host_files'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
            if name in links:links[name].symlink_to(path)
        entry=SimpleNamespace(pw_name=c.HOST_ACCOUNT,pw_uid=pin['uid'],pw_gid=pin['gid'],
                              pw_gecos=pin['label'],pw_dir='/nonexistent',pw_shell='/bin/sh')
        with patch.object(c,'HOST_LINKS',links),patch.object(c.pwd,'getpwnam',return_value=entry) as lookup, \
             patch.object(c.pwd,'getpwall',return_value=[entry]),patch.object(c.grp,'getgrnam',side_effect=KeyError) as group, \
             patch.object(c.subprocess,'run') as run:
            self.save(self.control/'policy.json',self.policy)
            with self.assertRaisesRegex(c.Refused,'no bootstrap attribution'):c.remove_host_registrations(self.root)
            self.policy['host_account']=pin;self.save(self.control/'policy.json',self.policy)
            entry.pw_uid=998
            with self.assertRaisesRegex(c.Refused,'attribution differs'):c.remove_host_registrations(self.root)
            entry.pw_uid=pin['uid']
            group.side_effect=None
            with self.assertRaisesRegex(c.Refused,'Conflicting host group'):c.remove_host_registrations(self.root)
            group.side_effect=KeyError
            run.assert_not_called()
            self.assertTrue(all(path.is_symlink() for path in links.values()))
            def native(args,**kwargs):
                if args[0]=='/usr/sbin/userdel':
                    self.assertEqual(args,['/usr/sbin/userdel','--force',c.HOST_ACCOUNT])
                    lookup.side_effect=KeyError(c.HOST_ACCOUNT)
            run.side_effect=native
            self.assertEqual(c.remove_host_registrations(self.root),[])
            self.assertTrue((self.control/c.HOST_REMOVAL).is_file())
            self.assertTrue(all(not path.is_symlink() for path in links.values()))
            self.assertEqual(c.remove_host_registrations(self.root),[])
            self.assertEqual(sum(call.args[0][0]=='/usr/sbin/userdel' for call in run.call_args_list),1)

if __name__=='__main__': unittest.main()
