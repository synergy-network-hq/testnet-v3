"""Original-attempt recovery only; no daemon, setup keys or network operations."""
import base64
from contextlib import nullcontext
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import controller
import lifecycle
import vpn


class VpnReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'synergy'; self.root.mkdir()
        (self.root/'evidence').mkdir();(self.root/'vpn').mkdir(mode=0o700)
        self.attempt = self.root/controller.VPN_ATTEMPT
        self.attempt.write_text('{"format":"nodenetwork-vpn-attempt-v1"}')
        self.original_attempt = self.attempt.read_bytes()
        self.control = self.root/'tmp/controller'; self.inputs = self.control/'authorization/inputs'
        self.inputs.mkdir(parents=True)
        self.key = base64.b64encode(b'p'*32).decode()
        self.identity = {'publicKey': self.key, 'netbirdIp': '100.64.0.2/16',
                         'management': {'connected': True}, 'signal': {'connected': True}}
        self.provider = {'account_id': 'account', 'management_origin': 'https://approved.example'}
        target = {'kind': 'remote', 'host': 'validator.example', 'port': 22, 'root': str(self.root)}
        selection = {'manifest_sha256': 'a'*64, 'network_id': 'fresh-network', 'chain_id': 99999}
        self.policy = {'engineering_target': target, 'engineering_selection': selection,
                       'validator_formation_sha256': 'b'*64, 'authorization_files': {}}
        binding = {'target_sha256': hashlib.sha256(controller.canonical(target)).hexdigest(),
                   'manifest_sha256': 'a'*64, 'network_id': 'fresh-network', 'chain_id': 99999,
                   'formation_sha256': 'b'*64}
        self.peer = {'peer_id': 'new-peer', 'ip': '100.64.0.2', 'hostname': 'machine',
                     'name': 'nn-'+hashlib.sha256(controller.canonical(binding)).hexdigest()[:60],
                     'wireguard_public_key': self.key, 'binding': binding, 'setup_key_id': 'used-key',
                     'provider_account_id': 'account', 'one_off_usage_evidence': 'management key counter',
                     'connected': True, 'new_peer_verified': True, 'one_off_usage_verified': True}
        self.write_inputs()
        self.owner = object.__new__(controller.Controller)
        self.owner.root = self.root; self.owner.control = self.control
        self.owner.policy = lambda: self.policy
        self.owner.public_json = lambda path,*args: json.loads(path.read_bytes())
        self.owner.authorize = Mock()
        self.owner.vpn_status = lambda: {'service_registered': True, 'enrollment_recorded':
            (self.root/'evidence/vpn-enrollment.json').exists(), 'enrollment_staged': False,
            'reconciliation_required': not (self.root/'evidence/vpn-enrollment.json').exists(),
            'server_bound': (self.root/'evidence/vpn-server-binding.json').exists(), 'connected': True}
        for name, value in [('_lifecycle_lock', lambda root:nullcontext()), ('_sealed_receipt', lambda root:{}),
                            ('_integration_plan', lambda root:{}), ('_attributed_units',
                             lambda *args:{'synergy-vpn.service': {'ActiveState':'active'}})]:
            mock = patch.object(lifecycle,name,value); mock.start(); self.addCleanup(mock.stop)
        mock = patch.object(vpn,'client_environment',return_value={}); mock.start(); self.addCleanup(mock.stop)
        mock = patch.object(vpn,'status',side_effect=lambda *args:self.identity); mock.start(); self.addCleanup(mock.stop)

    def write_inputs(self):
        for name,value in [('vpn-provider.json',self.provider),('vpn-server-binding.json',self.peer)]:
            path=self.inputs/name; path.write_text(json.dumps(value))
            self.policy['authorization_files'][name]=hashlib.sha256(path.read_bytes()).hexdigest()

    def bind(self):
        return self.owner.vpn_bind({'version':1,'operation':'vpn_bind','parameters':{}})

    def test_recovers_only_identity_and_binding_without_enrollment_or_probe_claim(self):
        with patch.object(vpn,'native') as native, patch.object(vpn,'enroll') as enroll:
            result=self.bind(); native.assert_not_called(); enroll.assert_not_called()
        self.assertTrue(result['server_bound'])
        receipt=json.loads((self.root/'evidence/vpn-enrollment.json').read_bytes())
        self.assertEqual(receipt['verified_peer_ips'],[])
        self.assertFalse(receipt['consensus_started'])
        self.assertEqual(self.attempt.read_bytes(),self.original_attempt)
        self.owner.authorize.assert_called_once()

    def test_wrong_scope_provider_key_address_or_evidence_never_publishes_receipt(self):
        for change in ('scope','provider','key','address','usage'):
            with self.subTest(change=change):
                original=copy.deepcopy(self.peer)
                if change=='scope':self.peer['binding']['manifest_sha256']='c'*64
                if change=='provider':self.peer['provider_account_id']='foreign'
                if change=='key':self.peer['wireguard_public_key']=base64.b64encode(b'q'*32).decode()
                if change=='address':self.peer['ip']='100.64.0.3'
                if change=='usage':self.peer['one_off_usage_verified']=False
                self.write_inputs()
                with self.assertRaises(ValueError):self.bind()
                self.assertFalse((self.root/'evidence/vpn-enrollment.json').exists())
                self.assertEqual(self.attempt.read_bytes(),self.original_attempt)
                self.peer=original

    def test_interruption_after_atomic_receipt_reconciles_exact_binding(self):
        actual=vpn.bind_server
        with patch.object(vpn,'bind_server',side_effect=ValueError('interrupted')):
            with self.assertRaises(ValueError):self.bind()
        self.assertTrue((self.root/'evidence/vpn-enrollment.json').exists())
        self.assertFalse((self.root/'evidence/vpn-server-binding.json').exists())
        self.bind()
        before=(self.root/'evidence/vpn-server-binding.json').read_bytes()
        actual(self.root,{**self.peer,'id':self.peer['peer_id']})
        self.assertEqual((self.root/'evidence/vpn-server-binding.json').read_bytes(),before)
        with self.assertRaises(ValueError):actual(self.root,{**self.peer,'id':'different'})
        self.assertEqual(self.attempt.read_bytes(),self.original_attempt)

    def test_orphan_binding_inactive_daemon_and_changed_identity_refuse(self):
        orphan=self.root/'evidence/vpn-server-binding.json';orphan.write_text('{}')
        with self.assertRaises(ValueError):self.bind()
        orphan.unlink()
        with patch.object(lifecycle,'_attributed_units',return_value={}):
            with self.assertRaises(ValueError):self.bind()
        self.identity['publicKey']=base64.b64encode(b'q'*32).decode()
        with self.assertRaises(ValueError):self.bind()
        self.assertFalse((self.root/'evidence/vpn-enrollment.json').exists())


class UnusedCancellationTests(unittest.TestCase):
    def setUp(self):
        VpnReconciliationTests.setUp(self)
        mock=patch.object(lifecycle,'_attributed_units',return_value={'synergy-vpn.service':{'ActiveState':'failed','MainPID':'0'}})
        mock.start();self.addCleanup(mock.stop)
        mock=patch.object(lifecycle,'_assert_no_application_processes');mock.start();self.addCleanup(mock.stop)
        self.owner.vpn_stage=lambda:None
        self.owner.exists=lambda name:(self.root/name).exists() or (self.root/name).is_symlink()
        def consume(request,*args):
            controller.Controller.audit(self.owner,request)
            (self.control/'grants'/(controller.request_digest(request)+'.json')).unlink()
        (self.control/'grants').mkdir()
        self.owner.authorize=Mock(side_effect=consume)

    write_inputs=VpnReconciliationTests.write_inputs

    def proof(self):
        binding=self.owner.vpn_provider_binding(vpn.attempt_state(self.root)['scope_sha256'])
        return {'format':'nodenetwork-vpn-unused-cancellation-v1','binding':binding,
                'provider_sha256':hashlib.sha256(controller.canonical(self.provider)).hexdigest(),
                'account_id':self.provider['account_id'],'setup_key_id':'exact-key',
                'name':'nn-'+hashlib.sha256(controller.canonical(binding)).hexdigest()[:60],
                'intent_sha256':'d'*64,'attempt_sha256':vpn.attempt_state(self.root)['attempt_sha256'],
                'unused_verified':True,'setup_key_absent':True,'peer_absence_verified':True}

    def cancel(self,proof=None):
        proof=self.proof() if proof is None else proof
        path=self.inputs/vpn.CANCELLATION;path.write_text(json.dumps(proof))
        self.policy['authorization_files'][vpn.CANCELLATION]=hashlib.sha256(path.read_bytes()).hexdigest()
        request={'version':1,'operation':'vpn_cancel_unused','parameters':{'attempt_sha256':proof['attempt_sha256']}}
        key=controller.request_digest(request);grant=self.control/'grants'/(key+'.json')
        if not (self.root/'evidence/vpn-cancel-unused-intent.json').exists() and vpn.attempt_state(self.root)['retry_after_sha256'] is None:
            grant.write_text(json.dumps({'operation':'vpn_cancel_unused','request_sha256':key,'binding_sha256':self.policy['authorization_files'][vpn.CANCELLATION]}))
        return self.owner.vpn_cancel_unused(request)

    def test_cancel_then_explicit_retry_keeps_original_and_all_prior_events(self):
        result=self.cancel();self.assertTrue(result['cancelled'])
        state=vpn.attempt_state(self.root);self.assertEqual(state['retry_after_sha256'],result['cancellation_sha256'])
        before=(self.root/vpn.ATTEMPTS).read_bytes();self.cancel()
        self.assertEqual((self.root/vpn.ATTEMPTS).read_bytes(),before)
        self.owner.authorize.assert_called_once()
        first=state['events'][0]
        for count in range(2):
            state=vpn.append_attempt_event(self.root,{'kind':'attempt','cancellation_sha256':state['retry_after_sha256'],
                                                     'enrollment_sha256':str(count+1)*64})
            self.assertIsNone(state['retry_after_sha256'])
            self.assertEqual(self.owner.vpn_provider_binding(state['scope_sha256'])['attempt_sha256'],state['scope_sha256'])
            result=self.cancel();state=vpn.attempt_state(self.root)
        self.assertEqual(len(state['events']),5);self.assertEqual(state['events'][0],first)
        self.assertEqual(self.attempt.read_bytes(),self.original_attempt)
        lifecycle.require_vpn_retired_for_removal(self.root)

    def test_daemon_defaults_require_original_consumed_audit_then_cancel_retry_preserves_identity(self):
        from test_vpn_default_profile import write_default_profile
        config=write_default_profile(self.root)
        before={p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()}
        self.assertFalse(self.owner.vpn_unused_preflight()['quiescent'])
        original={'version':1,'operation':'vpn_enroll','parameters':{}}
        controller.Controller.audit(self.owner,original)
        self.assertTrue(self.owner.vpn_unused_preflight()['quiescent'])
        grant=self.control/'grants'/(controller.request_digest(original)+'.json');grant.write_text('{}')
        self.assertFalse(self.owner.vpn_unused_preflight()['quiescent']);grant.unlink()
        result=self.cancel();pin=result['cancellation_sha256']
        lifecycle.require_vpn_retired_for_removal(self.root)
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()})
        path=self.control/controller.VPN_ENROLLMENT;path.write_bytes(b'{"test":"opaque-private-fixture"}')
        self.owner.vpn_stage=lambda:path if path.exists() else None
        request={'version':1,'operation':'vpn_enroll','parameters':{'attempt_sha256':pin}}
        (self.control/'grants'/(controller.request_digest(request)+'.json')).write_text('{}')
        with patch.object(lifecycle,'_sealed_receipt',return_value=({'role':'validator'},{})),patch.object(vpn,'enroll',side_effect=ValueError('uncertain')) as dispatch:
            with self.assertRaises(controller.Refused):self.owner.vpn_enroll(request)
            self.assertEqual(dispatch.call_args.kwargs,{'preserved_identity':(config['PrivateKey'],config['SSHKey'])})
            self.assertEqual(before,{p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()})
            with self.assertRaises(ValueError):self.owner.vpn_enroll(request)
            self.assertEqual(dispatch.call_count,1)
        with self.assertRaises(ValueError):lifecycle.require_vpn_retired_for_removal(self.root)
        self.assertEqual(self.attempt.read_bytes(),self.original_attempt)

    def test_new_enroll_is_separately_bound_once_before_dispatch(self):
        result=self.cancel();pin=result['cancellation_sha256']
        path=self.control/controller.VPN_ENROLLMENT;path.write_bytes(b'{"test":"opaque-private-fixture"}')
        self.owner.vpn_stage=lambda:path if path.exists() else None
        request={'version':1,'operation':'vpn_enroll','parameters':{'attempt_sha256':pin}}
        grant=self.control/'grants'/(controller.request_digest(request)+'.json');grant.write_text('{}')
        with patch.object(lifecycle,'_sealed_receipt',return_value=({'role':'validator'},{})),patch.object(vpn,'enroll') as dispatch:
            self.owner.vpn_enroll(request)
            self.assertEqual(dispatch.call_count,1)
            self.assertFalse(path.exists())
            path.write_bytes(b'{"test":"different-private-fixture"}')
            with self.assertRaises(ValueError):self.owner.vpn_enroll(request)
            self.assertEqual(dispatch.call_count,1)
        self.assertEqual(self.attempt.read_bytes(),self.original_attempt)
        self.assertIsNone(vpn.attempt_state(self.root)['retry_after_sha256'])
        self.assertNotEqual(controller.request_digest(request),controller.request_digest({**request,'parameters':{}}))

    def test_interrupted_consumed_cancellation_resumes_original_audit_without_regrant(self):
        original=vpn.append_attempt_event
        with patch.object(vpn,'append_attempt_event',side_effect=ValueError('after grant consumed')):
            with self.assertRaises(ValueError):self.cancel()
        self.owner.authorize.assert_called_once()
        self.assertTrue((self.root/'evidence/vpn-cancel-unused-intent.json').exists())
        self.assertFalse(any((self.control/'grants').iterdir()))
        self.cancel()
        self.owner.authorize.assert_called_once()
        self.assertFalse((self.root/'evidence/vpn-cancel-unused-intent.json').exists())
        self.assertIsNotNone(vpn.attempt_state(self.root)['retry_after_sha256'])
        self.assertEqual(self.attempt.read_bytes(),self.original_attempt)

    def test_real_systemctl_projection_and_missing_pid_fail_closed(self):
        from types import SimpleNamespace
        with patch.object(lifecycle.subprocess,'run',return_value=SimpleNamespace(returncode=0,
                stdout='LoadState=loaded\nActiveState=failed\nMainPID=0\n')):
            unit=lifecycle._unit_state('synergy-vpn.service')
        self.assertEqual(unit['MainPID'],'0')
        with patch.object(lifecycle,'_attributed_units',return_value={'synergy-vpn.service':unit}):
            self.assertTrue(self.owner.vpn_unused_preflight()['quiescent'])
        unit.pop('MainPID')
        with patch.object(lifecycle,'_attributed_units',return_value={'synergy-vpn.service':unit}):
            self.assertFalse(self.owner.vpn_unused_preflight()['quiescent'])

    def test_cancel_audit_before_unlink_and_partial_atomic_stage_resume_once(self):
        def audited_but_grant_remains(request,*args):
            controller.Controller.audit(self.owner,request)
            raise ValueError('interrupted before original grant unlink')
        self.owner.authorize.side_effect=audited_but_grant_remains
        with self.assertRaises(ValueError):self.cancel()
        self.assertEqual(len(list((self.control/'grants').iterdir())),1)
        event={'kind':'cancel','receipt':self.proof()}
        raw=json.dumps({'format':'nodenetwork-vpn-attempts-v1','events':[event]},sort_keys=True,indent=2).encode()+b'\n'
        stage=self.root/'evidence'/('.vpn-attempts.json.upgrade-'+hashlib.sha256(raw).hexdigest()[:16])
        stage.write_bytes(b'partial interrupted staging');stage.chmod(0o600)
        self.cancel()
        self.owner.authorize.assert_called_once()
        self.assertFalse(any((self.control/'grants').iterdir()))
        self.assertFalse(stage.exists())
        self.assertIsNotNone(vpn.attempt_state(self.root)['retry_after_sha256'])

    def test_wrong_target_provider_attempt_or_active_state_never_cancels(self):
        for field,value in [('account_id','foreign'),('attempt_sha256','e'*64),('unused_verified',False)]:
            wrong=self.proof();wrong[field]=value
            with self.assertRaises(ValueError):self.cancel(wrong)
            self.assertFalse((self.root/vpn.ATTEMPTS).exists())
        with patch.object(lifecycle,'_attributed_units',return_value={'synergy-vpn.service':{'ActiveState':'active','MainPID':123}}):
            with self.assertRaises(ValueError):self.cancel()
        with patch.object(lifecycle,'_attributed_units',return_value={'synergy-vpn.service':{'ActiveState':'failed'}}):
            with self.assertRaises(ValueError):self.cancel()
        with patch.object(lifecycle,'_assert_no_application_processes',side_effect=ValueError('live')):
            with self.assertRaises(ValueError):self.cancel()
        (self.root/'vpn/default.json').write_text('{}')
        with self.assertRaises(ValueError):self.cancel()
        self.assertFalse((self.root/vpn.ATTEMPTS).exists())

    def test_stale_or_cross_attempt_history_refuses_before_any_write(self):
        self.cancel();before=(self.root/vpn.ATTEMPTS).read_bytes();state=vpn.attempt_state(self.root)
        for event in ({'kind':'attempt','cancellation_sha256':'f'*64,'enrollment_sha256':'a'*64},
                      state['events'][0]):
            with self.assertRaises(ValueError):vpn.append_attempt_event(self.root,event)
            self.assertEqual((self.root/vpn.ATTEMPTS).read_bytes(),before)
        vpn.append_attempt_event(self.root,{'kind':'attempt','cancellation_sha256':state['retry_after_sha256'],'enrollment_sha256':'a'*64})
        with self.assertRaises(ValueError):lifecycle.require_vpn_retired_for_removal(self.root)


if __name__=='__main__':unittest.main()


class VpnStopTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.owner=object.__new__(controller.Controller);self.owner.root=self.root
        self.owner.authorize=Mock()
        self.request={'version':1,'operation':'vpn_stop','parameters':{}}
        self.units={'synergy-node.service':{'MainPID':'0','ActiveState':'inactive'},
                    'synergy-vpn.service':{'MainPID':'123','ActiveState':'active'}}
        for name,value in [('_lifecycle_lock',lambda root:nullcontext()),('_sealed_receipt',lambda root:({},{}))]:
            context=patch.object(lifecycle,name,value);context.start();self.addCleanup(context.stop)
        self.attribution=patch.object(lifecycle,'_attributed_units',side_effect=lambda root:copy.deepcopy(self.units))
        self.attribution.start();self.addCleanup(self.attribution.stop)
        self.process=patch.object(lifecycle,'_assert_no_application_processes');self.no_process=self.process.start();self.addCleanup(self.process.stop)
        def stop(root,action,unit):
            self.assertEqual((root,action,unit),(self.root,'stop','synergy-vpn.service'))
            self.units[unit]={'MainPID':'0','ActiveState':'inactive'}
        self.mutation=patch.object(lifecycle,'mutate_owned_service',side_effect=stop)
        self.stop=self.mutation.start();self.addCleanup(self.mutation.stop)

    def test_stops_only_owned_vpn_preserves_all_files_and_requires_exact_grant(self):
        for name in ('attempt','custody','state'):(self.root/name).write_bytes(name.encode())
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        self.assertTrue(controller.parse_request(controller.canonical(self.request)))
        result=self.owner.vpn_stop(self.request)
        self.assertEqual(result,{'schema':'nodenetwork-vpn-stop-v1','stopped':True,'attempt_preserved':True,'provider_action':False})
        self.owner.authorize.assert_called_once_with(self.request);self.stop.assert_called_once()
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})
        self.assertEqual(self.no_process.call_args_list[0].kwargs,{'vpn_pid':123})
        self.assertEqual(self.no_process.call_args_list[1].kwargs,{})

    def test_lost_reply_observation_requires_exact_consumed_audit_and_stopped_state(self):
        self.owner.control=self.root/'tmp/controller';self.owner.control.mkdir(parents=True)
        (self.owner.control/'grants').mkdir()
        key=controller.request_digest(self.request);audit=self.owner.control/'audit.jsonl'
        self.owner.direct=lambda path,*args:path
        self.assertFalse(self.owner.vpn_stop_status()['stopped'])
        self.units['synergy-vpn.service']={'MainPID':'0','ActiveState':'inactive'}
        self.assertFalse(self.owner.vpn_stop_status()['stopped'])
        row={'operation':'vpn_stop','request_sha256':key,'time':1}
        audit.write_text(json.dumps(row)+'\n')
        result=self.owner.vpn_stop_status()
        self.assertTrue(result['stopped']);self.assertEqual(result['request_sha256'],key)
        self.owner.authorize.assert_not_called();self.stop.assert_not_called()
        grant=self.owner.control/'grants'/(key+'.json');grant.write_text('{}')
        self.assertFalse(self.owner.vpn_stop_status()['stopped']);grant.unlink()
        for bad in (dict(row,request_sha256='f'*64),dict(row,operation='stop'),dict(row,time=True)):
            audit.write_text(json.dumps(bad)+'\n')
            with self.assertRaises(ValueError):self.owner.vpn_stop_status()
        audit.write_text(json.dumps(row)+'\n')
        self.units['synergy-vpn.service']={'MainPID':'0','ActiveState':'activating'}
        self.assertFalse(self.owner.vpn_stop_status()['stopped'])
        self.stop.assert_not_called()

    def test_active_missing_or_malformed_validator_and_foreign_process_refuse_before_grant(self):
        for node in ({},{'MainPID':'9','ActiveState':'active'},{'MainPID':0,'ActiveState':'inactive'}):
            self.units['synergy-node.service']=node
            with self.assertRaises(ValueError):self.owner.vpn_stop(self.request)
        self.units['synergy-node.service']={'MainPID':'0','ActiveState':'inactive'}
        self.no_process.side_effect=ValueError('unattributed process')
        with self.assertRaises(ValueError):self.owner.vpn_stop(self.request)
        self.owner.authorize.assert_not_called();self.stop.assert_not_called()

    def test_grant_refusal_or_unattributed_service_never_stops_and_uncertain_stop_not_success(self):
        self.owner.authorize.side_effect=ValueError('grant absent')
        with self.assertRaises(ValueError):self.owner.vpn_stop(self.request)
        self.stop.assert_not_called()
        self.owner.authorize.side_effect=None
        self.stop.side_effect=lambda *args:None
        with self.assertRaises(ValueError):self.owner.vpn_stop(self.request)
        self.assertEqual(self.stop.call_count,1)
        self.stop.reset_mock();self.attribution.stop()
        with patch.object(lifecycle,'_attributed_units',side_effect=ValueError('foreign unit')):
            with self.assertRaises(ValueError):self.owner.vpn_stop(self.request)
        self.stop.assert_not_called()
