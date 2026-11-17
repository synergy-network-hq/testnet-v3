"""Native coordinator boundaries without management-server or host operations."""
import base64
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
    def issue(self):
        flow=self.flow([self.account,(200,[]),(200,[]),(200,self.key)])
        public,secret=flow.prepare(self.b)
        self.assertEqual(secret,self.key['key']);self.assertEqual(public['setup_key_id'],'12')
        for path in self.root.iterdir():
            self.assertNotIn(secret,path.read_text());self.assertEqual(path.stat().st_mode&0o777,0o600)
        return flow
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
        for method,path in [('GET','/api/peers/../accounts'),('POST','/api/accounts'),
                            ('DELETE','https://foreign/api/peers/one')]:
            with self.assertRaises(ValueError):client.request(method,path)
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
        with patch.object(lifecycle,'_lifecycle_lock',return_value=nullcontext()),patch.object(lifecycle,'_sealed_receipt'),patch.object(vpn,'bind_server') as bind:
            with self.assertRaisesRegex(ValueError,'grant missing'):owner.vpn_bind({'operation':'vpn_bind'})
            bind.assert_not_called()
            owner.authorize=Mock();owner.vpn_bind({'operation':'vpn_bind'})
            self.assertEqual(owner.authorize.call_args.args[1],hashlib.sha256(raw).hexdigest())
            self.assertEqual(bind.call_args.args[1]['id'],'fresh1')
            changed={**server,'wireguard_public_key':base64.b64encode(b'x'*32).decode()}
            owner.public_json=lambda p,private:changed if p==path else self.local
            with self.assertRaises(controller.Refused):owner.vpn_bind({'operation':'vpn_bind'})
if __name__=='__main__':unittest.main()
