"""Native coordinator boundaries without management-server or host operations."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import vpn_authorization as v

class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'vpn';self.ca=b'public-test-ca'
        self.p={'version':1,'profile':v.PROFILE,'api_origin':'https://127.0.0.1:18443',
            'management_origin':'https://10.0.2.100:8443','account_id':'account1',
            'auto_groups':['group1'],'required_peer_ips':['10.69.0.254'],'expires_at':2000,'ca_sha256':hashlib.sha256(self.ca).hexdigest()}
        self.b={'target_sha256':'a'*64,'manifest_sha256':'b'*64,'formation_sha256':'c'*64,
                'network_id':'isolated-formation','chain_id':999998}
        self.name='nn-'+hashlib.sha256(v.encode(self.b)).hexdigest()[:60]
        self.key={'id':12,'name':self.name,'type':'one-off','usage_limit':1,'ephemeral':True,
                'used_times':0,'revoked':False,'auto_groups':['group1'],'key':'PRIVATE-TEST-KEY'}
        self.account=(200,[{'id':'account1'}])
        self.local={'native_enrollment_verified':True,'hostname':self.name,
            'management_url':self.p['management_origin'],'overlay_address':'10.69.0.1/16',
            'wireguard_public_key':base64.b64encode(bytes(32)).decode()}
        self.peer={'id':'fresh1','name':self.name,'hostname':'guest1','ip':'10.69.0.1','connected':True}
    def flow(self,responses):
        self.request=Mock(side_effect=responses)
        return v.Authorization(self.root,self.p,self.request,now=lambda:1000)
    def issue(self, inventory=()):
        flow=self.flow([self.account, *((200, rows) for rows in inventory or ([],)), (200,[]), (200,self.key)])
        public,secret=flow.prepare(self.b)
        self.assertEqual(secret,self.key['key']);self.assertEqual(public['setup_key_id'],'12')
        for path in self.root.iterdir():
            self.assertNotIn(secret,path.read_text());self.assertEqual(path.stat().st_mode&0o777,0o600)
        return flow
    def controlled(self):
        self.p={**self.p,'profile':v.CONTROLLED_PROFILE,
                'network_binding':{k:self.b[k] for k in ('network_id','chain_id','formation_sha256')}}
    def gateway_inventory(self):
        self.p={**self.p,'profile':v.GATEWAY_PROFILE,
                'network_binding':{k:self.b[k] for k in ('network_id','chain_id','formation_sha256')},
                'required_gateway_tcp':{'ip':'10.69.0.254','port':8551}}
        del self.p['required_peer_ips']
        peers=[{'id':'upstream','ip':'10.69.0.254','groups':[{'id':'all'},{'id':'relay-target'}]},
               {'id':'other','ip':'10.69.0.253','groups':[{'id':'all'}]}]
        groups=[{'id':'all','name':'All','peers_count':2},
                {'id':'group1','name':'gateway','peers_count':0},
                {'id':'relay-target','name':'signed-upstream','peers_count':1}]
        policies=[{'id':'gateway-policy','enabled':True,'rules':[
            {'enabled':True,'action':'accept','sources':[{'id':'group1'}],
             'destinations':[{'id':'relay-target'}],'bidirectional':False,'protocol':'tcp','ports':['8551']}]}]
        return peers, groups, policies
    def unused(self):
        return {'schema':'nodenetwork-vpn-unused-preflight-v1','quiescent':True,
                'attempt_sha256':'d'*64,'binding':self.b}
    def test_gateway_policy_is_independent_exact_tcp_and_retained_network_scope(self):
        inventory=self.gateway_inventory()
        raw=v.encode(self.p);sha=hashlib.sha256(raw).hexdigest()
        self.assertEqual(v.provider_policy(raw,sha,self.ca,1000),self.p)
        for changed in ({**self.p,'required_peer_ips':['10.69.0.254']},{**self.p,'required_gateway_tcp':{'ip':'10.69.0.254','port':443}},{**self.p,'required_gateway_tcp':{'ip':'127.0.0.1','port':8551}},{**self.p,'expires_at':999}):
            data=v.encode(changed)
            with self.assertRaises(ValueError):v.provider_policy(data,hashlib.sha256(data).hexdigest(),self.ca,1000)
        for groups in ([], ['gateway-group', 'validator-group']):
            data = v.encode({**self.p, 'auto_groups': groups})
            with self.assertRaisesRegex(ValueError, 'one dedicated enrollment group'):
                v.provider_policy(data, hashlib.sha256(data).hexdigest(), self.ca, 1000)
        other={**self.p,'network_binding':{**self.p['network_binding'],'chain_id':self.b['chain_id']+1}}
        other_raw=v.encode(other)
        other_policy=v.provider_policy(other_raw,hashlib.sha256(other_raw).hexdigest(),self.ca,1000)
        with self.assertRaisesRegex(ValueError,'differs from approved scope'):
            v.network_scope(other_policy,self.b)
        with self.assertRaises(ValueError):v.provider_policy(raw,'0'*64,self.ca,1000)
        self.name='nn-'+hashlib.sha256(v.encode(self.b)).hexdigest()[:60];self.key['name']=self.name
        flow=self.issue(inventory)
        self.assertEqual([(call.args[0],call.args[1]) for call in flow.request.call_args_list],
            [('GET','/api/accounts'),('GET','/api/peers'),('GET','/api/groups'),('GET','/api/policies'),
             ('GET','/api/setup-keys'),('POST','/api/setup-keys')])
        before={p:p.read_bytes() for p in self.root.iterdir()}
        self.p['network_binding']['formation_sha256']='f'*64
        with self.assertRaises(ValueError):self.flow([])
        self.request.assert_not_called();self.assertEqual(before,{p:p.read_bytes() for p in self.root.iterdir()})

    def test_gateway_access_failure_precedes_intent_and_key_issuance(self):
        inventory=self.gateway_inventory()
        for invalid in ('default-group', 'occupied-group', 'wrong-upstream', 'shared-upstream',
                        'bidirectional', 'port-range', 'extra-rule', 'no-rule'):
            with self.subTest(invalid=invalid):
                peers, groups, policies=deepcopy(inventory)
                rule=policies[0]['rules'][0]
                if invalid == 'default-group':
                    rule['sources']=[{'id':'all'}]
                elif invalid == 'occupied-group':
                    peers[1]['groups'].append({'id':'group1'})
                elif invalid == 'wrong-upstream':
                    peers[0]['ip']='10.69.0.252'
                elif invalid == 'shared-upstream':
                    peers[1]['groups'].append({'id':'relay-target'})
                elif invalid == 'bidirectional':
                    rule['bidirectional']=True
                elif invalid == 'port-range':
                    rule['port_ranges']=[{'start':8551,'end':8552}]
                elif invalid == 'extra-rule':
                    policies.append({'id':'other-policy','enabled':True,'rules':[
                        {**rule,'destinations':[{'id':'all'}]}]})
                else:
                    policies[0]['enabled']=False
                flow=self.flow([self.account,(200,peers),(200,groups),(200,policies)])
                with self.assertRaises(v.GatewayAccessRefused):
                    flow.prepare(self.b)
                self.assertTrue(all(call.args[0]=='GET' for call in flow.request.call_args_list))
                self.assertEqual(list(self.root.iterdir()),[])

    def test_unused_cancellation_exact_zero_usage_and_absence_is_idempotent(self):
        self.issue()
        flow=self.flow([self.account,(200,[]),(200,[self.key]),(204,None),(404,None),(200,[]),(200,[])])
        proof=flow.cancel_unused(self.unused())
        self.assertTrue(proof['unused_verified']);self.assertNotIn(self.key['key'],json.dumps(proof))
        self.assertEqual(sum(call.args[0]=='DELETE' for call in self.request.call_args_list),1)
        flow=self.flow([self.account,(200,[]),(404,None),(200,[]),(200,[])])
        self.assertEqual(flow.cancel_unused(self.unused()),proof)
        self.assertFalse(any(call.args[0]=='DELETE' for call in self.request.call_args_list))
        with self.assertRaises(ValueError):flow.prepare(self.b)
    def test_unused_cancellation_used_or_matching_peer_never_deletes(self):
        self.issue()
        for responses in ([self.account,(200,[self.peer])],
                          [self.account,(200,[]),(200,[{**self.key,'used_times':1}])],
                          [self.account,(200,[]),(200,[{**self.key,'id':'foreign'}])]):
            flow=self.flow(responses)
            with self.assertRaises(ValueError):flow.cancel_unused(self.unused())
            self.assertFalse(any(call.args[0]=='DELETE' for call in self.request.call_args_list))
            self.assertFalse((self.root/'cancel-unused-intent.json').exists())
    def test_unused_cancellation_uncertain_delete_reconciles_without_second_delete(self):
        self.issue();flow=self.flow([self.account,(200,[]),(200,[self.key]),OSError('uncertain')])
        with self.assertRaises(OSError):flow.cancel_unused(self.unused())
        flow=self.flow([self.account,(200,[]),(200,self.key)])
        with self.assertRaises(ValueError):flow.cancel_unused(self.unused())
        self.assertFalse(any(call.args[0]=='DELETE' for call in self.request.call_args_list))
        flow=self.flow([self.account,(200,[]),(404,None),(200,[]),(200,[])])
        self.assertTrue(flow.cancel_unused(self.unused())['setup_key_absent'])
        wrong=self.unused();wrong['attempt_sha256']='e'*64
        flow=self.flow([self.account,(200,[])])
        with self.assertRaises(ValueError):flow.cancel_unused(wrong)
    def test_unused_cancellation_partial_writes_and_concurrent_cancel_are_fenced(self):
        import fcntl,os
        self.issue()
        stage=self.root/'.cancel-unused-intent.json.stage';stage.write_bytes(b'partial');stage.chmod(0o600)
        flow=self.flow([self.account,(200,[]),(200,[self.key]),OSError('after durable intent')])
        with self.assertRaises(OSError):flow.cancel_unused(self.unused())
        self.assertFalse(stage.exists());self.assertTrue((self.root/'cancel-unused-intent.json').exists())
        stage=self.root/'.cancelled-unused.json.stage';stage.write_bytes(b'partial');stage.chmod(0o600)
        flow=self.flow([self.account,(200,[]),(404,None),(200,[]),(200,[])])
        self.assertTrue(flow.cancel_unused(self.unused())['setup_key_absent']);self.assertFalse(stage.exists())
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            flow=self.flow([])
            with self.assertRaises(BlockingIOError):flow.cancel_unused(self.unused())
            self.request.assert_not_called()
        finally:os.close(fd)

    def test_unused_cancellation_target_scope_and_quiescence_are_exact(self):
        self.issue()
        for wrong in ({**self.unused(),'quiescent':False},{**self.unused(),'binding':{**self.b,'target_sha256':'e'*64}}):
            flow=self.flow([self.account])
            with self.assertRaises(ValueError):flow.cancel_unused(wrong)
            self.assertEqual(self.request.call_count,1)

    def test_controlled_policy_exact_profile_scope_and_pin(self):
        self.controlled()
        raw=v.encode(self.p);sha=hashlib.sha256(raw).hexdigest()
        self.assertEqual(v.provider_policy(raw,sha,self.ca,1000),self.p)
        for changed in ({**self.p,'profile':v.PROFILE},{**self.p,'profile':'unknown'},
                        {k:x for k,x in self.p.items() if k!='network_binding'},
                        {**self.p,'network_binding':{**self.p['network_binding'],'chain_id':True}}):
            data=v.encode(changed)
            with self.assertRaises(ValueError):v.provider_policy(data,hashlib.sha256(data).hexdigest(),self.ca,1000)
        with self.assertRaises(ValueError):v.provider_policy(raw+' '.encode(),sha,self.ca,1000)
        with self.assertRaises(ValueError):v.provider_policy(raw,sha,self.ca,3000)
    def test_controlled_prepare_cross_network_refuses_before_request(self):
        self.controlled();flow=self.flow([])
        for field,value in [('network_id','different'),('chain_id',99),('formation_sha256','f'*64)]:
            with self.assertRaises(ValueError):flow.prepare({**self.b,field:value})
        self.request.assert_not_called();self.assertFalse((self.root/'intent.json').exists())
    def test_controlled_issue_reconcile_and_retained_scope(self):
        self.controlled();self.issue();self.key['used_times']=1
        flow=self.flow([self.account,(200,[self.key]),(200,[self.peer])])
        self.assertTrue(flow.reconcile(self.local)['new_peer_verified'])
        request=Mock()
        for field,value in [('network_id','different'),('chain_id',99),('formation_sha256','f'*64)]:
            changed={**self.p,'network_binding':{**self.p['network_binding'],field:value}}
            for action in (None,'revoke','retire'):
                with self.assertRaises(ValueError):v.Authorization(self.root,changed,request,now=lambda:3000,cleanup_action=action)
        request.assert_not_called()
    def test_controlled_expired_cleanup_and_action_fences(self):
        self.controlled();self.issue()
        raw=v.encode(self.p);sha=hashlib.sha256(raw).hexdigest()
        for action in ('revoke','retire'):
            self.assertEqual(v.provider_policy(raw,sha,self.ca,3000,cleanup_action=action),self.p)
        flow,request=self.cleanup('revoke',[self.account,(200,[self.key]),(204,None),(404,None),(200,[])])
        self.assertTrue(flow.revoke_setup_key()['setup_key_absent'])
        with self.assertRaises(ValueError):flow.prepare(self.b)
        with self.assertRaises(ValueError):flow.reconcile(self.local)
        with self.assertRaises(ValueError):flow.retire_bound_peer({})
    def test_controlled_expired_retire_exact_existing_bound_scope(self):
        self.controlled()
        self.test_expired_exact_bound_peer_cleanup_rejects_foreign_and_reconciles()

    def test_exact_policy_pin_ca_two_origins_expiry(self):
        raw=v.encode(self.p)
        self.assertEqual(v.provider_policy(raw,hashlib.sha256(raw).hexdigest(),self.ca,1000),self.p)
        for field,value in [('api_origin','http://host'),('management_origin','https://user:secret@host'),
                ('api_origin','https://host/'),('api_origin','https://host/?token=x'),
                ('profile','production'),('expires_at',999)]:
            raw=v.encode({**self.p,field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):
                v.provider_policy(raw,hashlib.sha256(raw).hexdigest(),self.ca,1000)
        empty={**self.p,'auto_groups':[]}
        raw=v.encode(empty)
        self.assertEqual(v.provider_policy(raw,hashlib.sha256(raw).hexdigest(),self.ca,1000)['auto_groups'],[])
        raw=v.encode(self.p)
        with self.assertRaises(ValueError):v.provider_policy(raw,'0'*64,self.ca,1000)
        with self.assertRaises(ValueError):v.provider_policy(raw,hashlib.sha256(raw).hexdigest(),b'otherCA',1000)
    def test_intent_precedes_only_post_and_no_secret_persistence(self):
        def exchange(method,path,body=None):
            if path=='/api/accounts':return self.account
            if method=='GET':return 200,[]
            self.assertTrue((self.root/'intent.json').exists())
            self.assertEqual((body['type'],body['usage_limit'],body['expires_in']),('one-off',1,86400))
            return 201,self.key
        flow=v.Authorization(self.root,self.p,exchange,now=lambda:1000)
        public,secret=flow.prepare(self.b);self.assertNotIn(secret,json.dumps(public))
        with self.assertRaisesRegex(ValueError,'never reissue'):flow.prepare(self.b)
    def test_lost_post_never_reissues(self):
        flow=self.flow([self.account,(200,[]),(200,[]),OSError('lost')])
        with self.assertRaises(OSError):flow.prepare(self.b)
        count=self.request.call_count
        with self.assertRaises(ValueError):flow.prepare(self.b)
        self.assertEqual(count,self.request.call_count);self.assertFalse((self.root/'issued.json').exists())
    def test_independent_peer_attribution_and_idempotence(self):
        self.issue()
        for keys in [[{**self.key,'used_times':1}], []]:
            flow=self.flow([self.account,(200,keys),(200,[self.peer])])
            receipt=flow.reconcile(self.local)
            self.assertEqual(receipt['peer_id'],'fresh1');self.assertTrue(receipt['one_off_usage_verified'])
            self.assertNotIn(self.key['key'],json.dumps(receipt))
    def test_wrong_account_before_any_mutation(self):
        flow=self.flow([(200,[{'id':'other'}])])
        with self.assertRaises(ValueError):flow.prepare(self.b)
        self.assertEqual(self.request.call_count,1);self.assertFalse((self.root/'intent.json').exists())
    def test_usage_groups_peer_and_local_identity_substitution(self):
        self.issue()
        for key in [{**self.key,'used_times':0},{**self.key,'used_times':2},
                    {**self.key,'used_times':1,'auto_groups':['other']}]:
            flow=self.flow([self.account,(200,[key])])
            with self.assertRaises(ValueError):flow.reconcile(self.local)
        for peer in [{**self.peer,'ip':'10.69.0.2'},{**self.peer,'connected':False},{**self.peer,'name':'other'}]:
            flow=self.flow([self.account,(200,[{**self.key,'used_times':1}]),(200,[peer])])
            with self.assertRaises(ValueError):flow.reconcile(self.local)
        flow=self.flow([self.account,(200,[{**self.key,'used_times':1}])])
        with self.assertRaises(ValueError):flow.reconcile({**self.local,'wireguard_public_key':'bad'})
        self.assertFalse((self.root/'bound.json').exists())
    def test_revoke_lost_creation_checks_absence(self):
        flow=self.flow([self.account,(200,[]),(200,[]),OSError('lost')])
        with self.assertRaises(OSError):flow.prepare(self.b)
        flow=self.flow([self.account,(200,[self.key]),(204,None),(404,None),(200,[])])
        self.assertTrue(flow.revoke_setup_key()['setup_key_absent'])
        self.assertEqual(self.request.call_args_list[2].args,('DELETE','/api/setup-keys/12'))
        flow=self.flow([self.account,(200,[self.key])])
        with self.assertRaisesRegex(ValueError,'never repeat'):flow.revoke_setup_key()
        self.assertEqual(self.request.call_count,2)
        flow=self.flow([self.account,(200,[]),(404,None),(200,[])])
        self.assertTrue(flow.revoke_setup_key()['setup_key_absent'])
    def test_revoke_rejects_renamed_surviving_exact_id(self):
        self.issue()
        flow=self.flow([self.account,(200,[self.key]),(204,None),(404,None),
                        (200,[{**self.key,'name':'renamed-but-same-id'}])])
        with self.assertRaisesRegex(ValueError,'absence'):flow.revoke_setup_key()
        flow=self.flow([self.account,(200,[]),(200,{**self.key,'name':'renamed'})])
        with self.assertRaisesRegex(ValueError,'Exact provider key absence'):flow.revoke_setup_key()
        self.assertFalse(any(call.args[0]=='DELETE' for call in self.request.call_args_list))

    def test_foreign_name_and_symlink_refused(self):
        flow=self.flow([self.account,(200,[self.peer]),(200,[])])
        with self.assertRaisesRegex(ValueError,'already exists'):flow.prepare(self.b)
        self.assertFalse((self.root/'intent.json').exists())
        (self.root/'intent.json').symlink_to('/etc/passwd')
        flow=self.flow([self.account])
        with self.assertRaises(OSError):flow.reconcile(self.local)
    def test_duplicate_json_and_resource_injection(self):
        with self.assertRaises(ValueError):v.decode(b'{"id":1,"id":2}')
        client=object.__new__(v.HttpsProvider)
        for profile in (v.PROFILE, v.GATEWAY_PROFILE):
            client.profile=profile
            for method,path in [('GET','/api/peers/../accounts'),('POST','/api/accounts'),
                                ('DELETE','https://foreign/api/peers/one'),
                                ('POST','/api/groups'),('PUT','/api/policies/gateway-policy')]:
                with self.assertRaises(ValueError):client.request(method,path)
        client.profile=v.PROFILE
        for path in ('/api/groups','/api/policies'):
            with self.assertRaises(ValueError):client.request('GET',path)
    def test_peer_retirement_preserves_identity_and_reconciles_lost_reply(self):
        self.issue()
        flow=self.flow([self.account,(200,[{**self.key,'used_times':1}]),(200,[self.peer])])
        flow.reconcile(self.local)
        server={'server_binding_verified':True,'peer_id':self.peer['id'],'peer_name':self.name,
            'hostname':self.peer['hostname'],'ip':self.peer['ip'],
            'wireguard_public_key':self.local['wireguard_public_key']}
        evidence={'enrollment':self.local,'server_binding':server,
            'enrollment_sha256':'d'*64,'server_binding_sha256':'e'*64}
        flow=self.flow([self.account,(200,self.peer),OSError('lost delete')])
        with self.assertRaises(OSError):flow.retire_bound_peer(evidence)
        self.assertTrue((self.root/'retire-intent.json').exists())
        flow=self.flow([self.account,(404,None),(200,[])])
        result=flow.retire_bound_peer(evidence)
        self.assertEqual(result['peer_id'],'fresh1');self.assertTrue(result['absence_verified'])
        self.assertFalse(any(call.args[0]=='DELETE' for call in self.request.call_args_list))
        flow=self.flow([self.account,(200,self.peer)])
        with self.assertRaisesRegex(ValueError,'never repeat DELETE'):flow.retire_bound_peer(evidence)

    def cleanup(self,action,responses):
        request=Mock(side_effect=responses)
        return v.Authorization(self.root,self.p,request,now=lambda:3000,cleanup_action=action),request

    def test_expired_cleanup_does_not_issue_bind_or_change_action(self):
        self.issue();raw=v.encode(self.p);sha=hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError,'expired'):v.provider_policy(raw,sha,self.ca,3000)
        for action in ('revoke','retire'):
            self.assertEqual(v.provider_policy(raw,sha,self.ca,3000,cleanup_action=action),self.p)
        for ca,sha0 in [(b'wrong CA',sha),(self.ca,'0'*64)]:
            with self.assertRaises(ValueError):v.provider_policy(raw,sha0,ca,3000,cleanup_action='revoke')
        flow,request=self.cleanup('revoke',[])
        with self.assertRaises(ValueError):flow.prepare(self.b)
        with self.assertRaisesRegex(ValueError,'cannot issue'):flow.reconcile(self.local)
        with self.assertRaisesRegex(ValueError,'change action'):flow.retire_bound_peer({})
        request.assert_not_called()
        normal=v.Authorization(self.root,self.p,request,now=lambda:3000)
        with self.assertRaisesRegex(ValueError,'expired'):normal.reconcile(self.local)
        request.assert_not_called()
        with self.assertRaises(ValueError):v.Authorization(self.root.parent/'missing',self.p,request,cleanup_action='revoke')
        self.assertFalse((self.root.parent/'missing').exists())

    def test_expired_exact_key_cleanup_and_no_duplicate_uncertain_delete(self):
        self.issue()
        flow,request=self.cleanup('revoke',[self.account,(200,[self.key]),OSError('lost delete')])
        with self.assertRaises(OSError):flow.revoke_setup_key()
        self.assertEqual([c.args[0] for c in request.call_args_list].count('DELETE'),1)
        flow,request=self.cleanup('revoke',[self.account,(200,[self.key])])
        with self.assertRaisesRegex(ValueError,'never repeat'):flow.revoke_setup_key()
        self.assertFalse(any(c.args[0]=='DELETE' for c in request.call_args_list))
        flow,request=self.cleanup('revoke',[self.account,(200,[]),(404,None),(200,[])])
        self.assertTrue(flow.revoke_setup_key()['setup_key_absent'])
        self.assertFalse(any(c.args[0]=='DELETE' for c in request.call_args_list))
        changed={**self.p,'account_id':'foreign'}
        with self.assertRaisesRegex(ValueError,'original intent'):v.Authorization(self.root,changed,request,cleanup_action='revoke')
        changed={**self.p,'api_origin':'https://foreign.example'}
        with self.assertRaises(ValueError):v.Authorization(self.root,changed,request,cleanup_action='revoke')

    def test_expired_exact_bound_peer_cleanup_rejects_foreign_and_reconciles(self):
        self.issue();flow=self.flow([self.account,(200,[{**self.key,'used_times':1}]),(200,[self.peer])]);flow.reconcile(self.local)
        server={'server_binding_verified':True,'peer_id':self.peer['id'],'peer_name':self.name,
            'hostname':self.peer['hostname'],'ip':self.peer['ip'],'wireguard_public_key':self.local['wireguard_public_key']}
        evidence={'enrollment':self.local,'server_binding':server,'enrollment_sha256':'d'*64,'server_binding_sha256':'e'*64}
        flow,request=self.cleanup('retire',[self.account])
        with self.assertRaisesRegex(ValueError,'exact native'):flow.retire_bound_peer({**evidence,'server_binding':{**server,'peer_id':'foreign'}})
        self.assertEqual(request.call_count,1)
        flow,request=self.cleanup('retire',[self.account,(200,self.peer),OSError('lost delete')])
        with self.assertRaises(OSError):flow.retire_bound_peer(evidence)
        flow,request=self.cleanup('retire',[self.account,(200,self.peer)])
        with self.assertRaisesRegex(ValueError,'never repeat'):flow.retire_bound_peer(evidence)
        self.assertFalse(any(c.args[0]=='DELETE' for c in request.call_args_list))
        flow,request=self.cleanup('retire',[self.account,(404,None),(200,[])])
        self.assertTrue(flow.retire_bound_peer(evidence)['absence_verified'])
        self.assertFalse(any(c.args[0]=='DELETE' for c in request.call_args_list))

    def test_reconcile_rejects_new_provider_policy_after_issue(self):
        self.issue();self.p={**self.p,'api_origin':'https://different.example'}
        flow=self.flow([self.account])
        with self.assertRaisesRegex(ValueError,'Provider differs'):flow.reconcile(self.local)

    def test_vpn_controller_operations_reject_renderer_material(self):
        import controller
        for name in ('vpn_bind','vpn_retire'):
            wire={'version':1,'operation':name,'parameters':{}}
            self.assertEqual(controller.parse_request(v.encode(wire)),wire)
            for extra in ('credential','server_binding','account_id','path'):
                with self.assertRaises(controller.Refused):
                    controller.parse_request(v.encode({**wire,'parameters':{extra:'renderer'}}))

    def test_controller_inventory_pins_exact_public_vpn_artifacts_and_bounds(self):
        import controller
        import test_controller
        fixture=test_controller.ControllerTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        inputs=fixture.control/'authorization/inputs';inputs.mkdir(parents=True)
        inventory={}
        for name,raw in [('vpn-ca.pem',b'publicCA'),('vpn-provider.json',v.encode(self.p)),
                         ('vpn-server-binding.json',b'{}'),('vpn-retirement.json',b'{}')]:
            path=inputs/name;path.write_bytes(raw);path.chmod(0o600)
            inventory[name]=hashlib.sha256(raw).hexdigest()
        fixture.policy['authorization_files']=inventory;fixture.save(fixture.control/'policy.json',fixture.policy)
        files,_=controller.control_inventory(fixture.root)
        self.assertTrue(all('tmp/controller/authorization/inputs/'+name in files for name in inventory))
        ca=inputs/'vpn-ca.pem';ca.write_bytes(b'x'*(128*1024+1));ca.chmod(0o600)
        fixture.policy['authorization_files']['vpn-ca.pem']=hashlib.sha256(ca.read_bytes()).hexdigest()
        fixture.save(fixture.control/'policy.json',fixture.policy)
        with self.assertRaises(controller.Refused):controller.control_inventory(fixture.root)

    def test_controller_binding_requires_exact_grant_and_local_public_identity(self):
        import controller
        import lifecycle
        import vpn
        from contextlib import nullcontext
        from unittest.mock import patch
        control=self.root/'controller';control.mkdir(parents=True)
        path=control/'authorization/inputs/vpn-server-binding.json';path.parent.mkdir(parents=True)
        server={'peer_id':'fresh1','ip':'10.69.0.1','name':self.name,'hostname':'guest1',
            'connected':True,'new_peer_verified':True,'one_off_usage_verified':True,
            'wireguard_public_key':self.local['wireguard_public_key'],'binding':self.b,
            'setup_key_id':'12','provider_account_id':'account1','one_off_usage_evidence':'providerused1'}
        raw=v.encode(server);path.write_bytes(raw)
        owner=object.__new__(controller.Controller);owner.root=self.root;owner.control=control
        owner.policy=lambda:{'authorization_files':{'vpn-server-binding.json':hashlib.sha256(raw).hexdigest()}}
        owner.public_json=lambda p,private:server if p==path else self.local
        owner.vpn_status=lambda:{'connected':True,'server_bound':False}
        owner.authorize=Mock(side_effect=ValueError('grant missing'))
        with patch.object(lifecycle,'_lifecycle_lock',return_value=nullcontext()),patch.object(lifecycle,'_sealed_receipt',return_value=({'role':'validator'},{})),patch.object(vpn,'bind_server') as bind:
            with self.assertRaisesRegex(ValueError,'grant missing'):owner.vpn_bind({'operation':'vpn_bind'})
            bind.assert_not_called()
            owner.authorize=Mock();owner.vpn_bind({'operation':'vpn_bind'})
            self.assertEqual(owner.authorize.call_args.args[1],hashlib.sha256(raw).hexdigest())
            self.assertEqual(bind.call_args.args[1]['id'],'fresh1')
            changed={**server,'wireguard_public_key':base64.b64encode(b'x'*32).decode()}
            owner.public_json=lambda p,private:changed if p==path else self.local
            with self.assertRaises(controller.Refused):owner.vpn_bind({'operation':'vpn_bind'})

class GatewayAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.ca = b'test-provider-ca'
        self.scope = {
            'version': 1, 'profile': v.GATEWAY_ACCESS_PROFILE, 'api_origin': 'https://netbird.example',
            'management_origin': 'https://netbird.example', 'account_id': 'account',
            'ca_sha256': self.hash(self.ca), 'expires_at': 2000, 'target_sha256': 'a'*64,
            'network_profile_sha256': 'b'*64,
            'required_gateway_tcp': {'ip': '10.10.0.2', 'port': 8551},
            'network_binding': {'network_id': 'independent-canary', 'chain_id': 10, 'formation_sha256': 'c'*64},
        }
        self.inventory = {
            '/api/accounts': [{'id': 'account'}],
            '/api/peers': [
                {'id': 'signed-upstream', 'ip': '10.10.0.2', 'groups': [{'id': 'all'}]},
                {'id': 'unrelated', 'ip': '10.10.0.3', 'groups': [{'id': 'all'}]},
            ],
            '/api/groups': [{'id': 'all', 'name': 'All', 'peers_count': 2}],
            '/api/policies': [],
        }
        self.writes = []
        self.lose = None
        self.flow = v.GatewayAccess(self.scope, self.request, now=lambda: 1000)

    @staticmethod
    def hash(raw):
        return hashlib.sha256(raw).hexdigest()

    def request(self, method, path, body=None):
        if method == 'GET':
            return 200, deepcopy(self.inventory[path])
        self.assertEqual(method, 'POST')
        self.assertIn(path, ('/api/groups', '/api/policies'))
        new_id = 'created-'+str(len(self.writes))
        self.writes.append((path, deepcopy(body)))
        if self.lose == 'before-write':
            raise OSError('unconfirmed remote result')
        created = {'id': new_id, **body}
        if path == '/api/groups':
            members = body['peers']
            created.update(issued='api', peers_count=len(members), peers=[{'id': i} for i in members])
            for peer in self.inventory['/api/peers']:
                if peer['id'] in members:
                    peer['groups'].append({'id': new_id})
        else:
            for key in ('sources', 'destinations'):
                created['rules'][0][key] = [{'id': i} for i in body['rules'][0][key]]
        self.inventory[path].append(deepcopy(created))
        if self.lose == 'after-write':
            raise OSError('reply lost')
        return 200, created

    def approve(self):
        return self.hash(v.encode(self.flow.review()))

    def test_safe_review_apply_and_reconcile_existing_exact_roles(self):
        pin = self.approve()
        self.assertEqual(self.writes, [])
        result = self.flow.apply(self.root, pin)
        self.assertEqual([path for path, _ in self.writes], ['/api/groups', '/api/groups', '/api/policies'])
        self.assertEqual(self.writes[0][1]['peers'], [])
        self.assertEqual(self.writes[1][1]['peers'], ['signed-upstream'])
        (rule,) = self.writes[2][1]['rules']
        self.assertEqual((rule['sources'], rule['destinations'], rule['ports'], rule['bidirectional']),
                         (['created-0'], ['created-1'], ['8551'], False))
        policy = v.encode(result['provider_policy'])
        approved = v.provider_policy(policy, self.hash(policy), self.ca, 1000)
        flow = v.Authorization(self.root/'enrollment', approved, self.request, now=lambda: 1000)
        flow._verify_gateway_access(self.inventory['/api/peers'])
        self.assertEqual(self.flow.apply(self.root, self.approve()), result)
        self.assertEqual(len(self.writes), 3)

    def test_drift_after_review_and_default_policy_refuse_without_writes(self):
        pin = self.approve()
        self.inventory['/api/peers'][0]['id'] = 'other-peer'
        with self.assertRaisesRegex(ValueError, 'changed since the native review'):
            self.flow.apply(self.root, pin)
        self.inventory['/api/policies'] = [{'id': 'default', 'enabled': True, 'rules': [
            {'enabled': True, 'action': 'accept', 'sources': [{'id': 'all'}], 'destinations': [{'id': 'all'}]},
        ]}]
        with self.assertRaisesRegex(ValueError, 'broadens gateway access'):
            self.flow.review()
        self.assertEqual(self.writes, [])

    def test_interrupted_create_observes_exact_resource_and_never_replays(self):
        self.lose = 'after-write'
        with self.assertRaises(OSError):
            self.flow.apply(self.root, self.approve())
        self.lose = None
        self.assertEqual(self.flow.review()['gateway_group']['id'], 'created-0')
        self.flow.apply(self.root, self.approve())
        self.assertEqual(len(self.writes), 3)
        self.assertEqual(sum(body.get('peers') == [] for _, body in self.writes), 1)

    def test_uncertain_absence_does_not_allow_another_ungoverned_write(self):
        self.lose = 'before-write'
        with self.assertRaises(OSError):
            self.flow.apply(self.root, self.approve())
        self.lose = None
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.flow.apply(self.root, self.approve())
        self.assertEqual(len(self.writes), 1)

    def test_access_scope_and_transport_cannot_issue_or_mutate_existing_resources(self):
        raw = v.encode(self.scope)
        pin = self.hash(raw)
        self.assertEqual(v.gateway_access_scope(raw, pin, self.ca, 1000), self.scope)
        for debug_time, document_pin in ((2000, pin), (1000, '0'*64)):
            with self.assertRaises(ValueError):
                v.gateway_access_scope(raw, document_pin, self.ca, debug_time)
        with self.assertRaises(ValueError):
            v.provider_policy(raw, pin, self.ca, 1000)
        client = object.__new__(v.HttpsProvider)
        client.profile = v.GATEWAY_ACCESS_PROFILE
        for method, path in (('POST', '/api/setup-keys'), ('DELETE', '/api/peers/id'),
                             ('PUT', '/api/policies/id'), ('DELETE', '/api/groups/id')):
            with self.assertRaisesRegex(ValueError, 'Unsupported provider resource'):
                client.request(method, path, {} if method == 'POST' else None)


if __name__ == '__main__':
    unittest.main()
