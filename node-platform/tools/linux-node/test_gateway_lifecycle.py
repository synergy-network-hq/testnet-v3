"""Managed role dispatch: no host services, custody creation or network calls."""
import contextlib,copy,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import canary_rpc_relay as gateway
import controller
import lifecycle

class GatewayLifecycleTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
  self.c=controller.Controller(self.root);self.c.control.mkdir(mode=0o700,parents=True);(self.c.control/'grants').mkdir(mode=0o700)
  self.receipt={'role':'rpc_gateway','chain_id':99999,'network_id':'engineering-canary','gateway_commissioned':True};self.save('installation.json',self.receipt)
  self.save(gateway.GATEWAY_TARGET+'/commissioned.json',{'retained':'audited fixture'})
  self.save(gateway.CONFIG,{'role':{'kind':'gateway','validator_relay_port':8551,'validator_address':'synv1selected'}})
  self.save('network/transport-registry.json',{'payload':{'validators':[{'node_address':'synv1selected','revoked':False,'dial_address':'10.2.3.4:38638'}]}})
  self.save('evidence/vpn-enrollment.json',{'required_gateway_tcp':{'ip':'10.2.3.4','port':8551}})
  self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),'community_enrollment':False,'qualified_operations':['register','start','stop','restart'],'releases':{}}
  self.save('tmp/controller/policy.json',self.policy)
  self.units={'synergy-node.service':{'ActiveState':'inactive','MainPID':'0'},'synergy-vpn.service':{'ActiveState':'active','MainPID':'11'},lifecycle.RELAY_UNIT:{'ActiveState':'inactive','MainPID':'0'}}
  self.vpn={'service_registered':True,'enrollment_recorded':True,'server_bound':True,'connected':True,'reconciliation_required':False,'retired':False};self.locked=False
  @contextlib.contextmanager
  def lock(_):
   self.assertFalse(self.locked,'nested lifecycle lock would block ExecStartPre');self.locked=True
   try:yield
   finally:self.locked=False
  def mutation(root,action,unit):
   self.assertFalse(self.locked,'systemctl must run after releasing lifecycle lock');self.assertEqual(root,self.root);self.assertEqual(unit,lifecycle.RELAY_UNIT)
  self.patchers=[patch('lifecycle._require_operator'),patch('lifecycle._lifecycle_lock',side_effect=lock),patch('lifecycle._sealed_receipt',side_effect=lambda _:(copy.deepcopy(self.receipt),{})),patch.object(gateway,'_gateway_target_services'),patch.object(gateway,'validate_gateway_layout'),patch('lifecycle._integration_plan',return_value={'owned':True}),patch('lifecycle._attributed_units',side_effect=lambda _:copy.deepcopy(self.units)),patch.object(self.c,'vpn_status',side_effect=lambda:copy.deepcopy(self.vpn)),patch('vpn.verify_gateway_route',return_value={'tcp_verified':True}),patch('lifecycle._relay_start_check_locked'),patch('lifecycle.mutate_owned_service',side_effect=mutation),patch('lifecycle.register',side_effect=lambda root:self.register(root))]
  self.mocks=[p.start() for p in self.patchers]
  for p in self.patchers:self.addCleanup(p.stop)
 def save(self,name,value):
  path=self.root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(controller.canonical(value));path.chmod(0o600)
 def request(self,op,grant=True):
  value={'version':1,'operation':op,'parameters':{}}
  if grant:self.save('tmp/controller/grants/'+controller.request_digest(value)+'.json',{'root':str(self.root),'request_sha256':controller.request_digest(value),'expires_at':int(time.time())+60})
  return value
 def register(self,root):
  self.assertFalse(self.locked);self.assertEqual(root,self.root)
  return {'registered':['/etc/systemd/system/'+v for v in self.units],'services_started':False,'boot_enabled':False}
 def call(self,op,grant=True):return gateway.gateway_lifecycle(self.c,self.request(op,grant))
 def test_start_restart_only_relay_with_fresh_pure_scope_before_grant(self):
  for op in ('start','restart'):
   self.assertEqual(self.call(op),{'requested':op,'healthNotInferred':True})
  self.assertEqual([c.args[1:] for c in self.mocks[-2].call_args_list],[('start',lifecycle.RELAY_UNIT),('restart',lifecycle.RELAY_UNIT)])
  for c in self.mocks[8].call_args_list:self.assertEqual(c.kwargs,{'persist':False,'locked':True})
  self.assertEqual(len((self.c.control/'audit.jsonl').read_bytes().splitlines()),2)
 def test_register_never_starts_or_enables_and_does_not_hold_nested_lock(self):
  value=self.call('register');self.assertFalse(value['services_started']);self.assertFalse(value['boot_enabled']);self.assertEqual(len(value['registered']),3);self.mocks[-2].assert_not_called();self.mocks[8].assert_not_called()
 def test_unsafe_scope_refuses_before_consuming_exact_grant(self):
  for defect in ('uncommissioned','validator_running','disconnected','wrong_tcp','duplicate','revoked','foreign_service'):
   self.receipt['gateway_commissioned']=True;self.units['synergy-node.service']={'ActiveState':'inactive','MainPID':'0'};self.vpn['connected']=True
   self.save('evidence/vpn-enrollment.json',{'required_gateway_tcp':{'ip':'10.2.3.4','port':8551}})
   entries=[{'node_address':'synv1selected','revoked':False,'dial_address':'10.2.3.4:38638'}]
   if defect=='uncommissioned':self.receipt['gateway_commissioned']=False
   if defect=='validator_running':self.units['synergy-node.service']={'ActiveState':'active','MainPID':'17'}
   if defect=='disconnected':self.vpn['connected']=False
   if defect=='wrong_tcp':self.save('evidence/vpn-enrollment.json',{'required_gateway_tcp':{'ip':'10.2.3.5','port':8551}})
   if defect=='duplicate':entries*=2
   if defect=='revoked':entries[0]['revoked']=True
   self.save('network/transport-registry.json',{'payload':{'validators':entries}})
   q=self.request('start');key=controller.request_digest(q)
   with patch.object(gateway,'_gateway_target_services',side_effect=ValueError('foreign unit') if defect=='foreign_service' else None):
    with self.subTest(defect=defect),self.assertRaises(ValueError):gateway.gateway_lifecycle(self.c,q)
   self.assertTrue((self.c.control/'grants'/(key+'.json')).exists())
  self.assertFalse((self.c.control/'audit.jsonl').exists());self.mocks[-2].assert_not_called()
 def test_stop_uses_only_attribution_even_if_admission_or_vpn_unavailable(self):
  self.receipt['gateway_commissioned']=False;self.vpn['connected']=False;self.mocks[4].side_effect=ValueError('expired custody review')
  self.assertEqual(self.call('stop'),{'requested':'stop','healthNotInferred':True});self.mocks[4].assert_not_called();self.mocks[8].assert_not_called()
  del self.units[lifecycle.RELAY_UNIT]
  with self.assertRaises(ValueError):self.call('stop')
 def test_health_is_observation_only_and_does_not_claim_consensus(self):
  self.units[lifecycle.RELAY_UNIT]={'ActiveState':'active','MainPID':'27'};value=self.call('health',False)
  self.assertEqual(len(value),9);self.assertEqual(value['relay'],{'unit':lifecycle.RELAY_UNIT,'state':'active','pid':27});self.assertFalse(value['consensus_participant']);self.assertTrue(value['configured_loopback']);self.assertNotIn('finalized_height',value);self.assertFalse(value['production_qualified']);self.assertFalse((self.c.control/'audit.jsonl').exists());self.mocks[-2].assert_not_called()
 def test_lost_service_reply_preserves_consumed_uncertainty_without_replay(self):
  q=self.request('start');self.mocks[-2].side_effect=OSError('unknown systemctl outcome')
  with self.assertRaises(OSError):gateway.gateway_lifecycle(self.c,q)
  with self.assertRaises(controller.Refused):gateway.gateway_lifecycle(self.c,q)
  self.assertEqual(self.mocks[-2].call_count,1);self.assertEqual(len((self.c.control/'audit.jsonl').read_bytes().splitlines()),1)
 def test_existing_controller_health_route_uses_explicit_gateway_owner_only(self):
  with patch.object(controller.platform,'system',return_value='Linux'),patch.object(controller.platform,'machine',return_value='x86_64'),patch.object(gateway,'gateway_lifecycle',return_value={'role':'rpc_gateway'}) as branch,patch('synergy_linux.native') as native:
   q=self.request('health',False);self.assertEqual(self.c.dispatch(q),{'role':'rpc_gateway'});branch.assert_called_once_with(self.c,q);native.assert_not_called()

 def snapshot(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
 def test_vpn_preflight_binds_signed_selected_ip_genesis_and_never_writes(self):
  import hashlib
  self.save('network/genesis.json',{'signed':'public genesis'})
  digest=hashlib.sha256((self.root/'network/genesis.json').read_bytes()).hexdigest()
  self.policy['validator_identity_network']={'genesis.json':digest};self.save('tmp/controller/policy.json',self.policy)
  q={'version':1,'operation':'gateway_vpn_preflight','parameters':{'required_gateway_tcp':{'ip':'10.2.3.4','port':8551}}}
  self.assertEqual(controller.parse_request(controller.canonical(q)),q)
  before=self.snapshot();value=gateway.gateway_vpn_preflight(self.c,q['parameters'])
  self.assertEqual(value,{'schema':'nodenetwork-gateway-vpn-preflight-v1','required_gateway_tcp':q['parameters']['required_gateway_tcp'],'network_id':'engineering-canary','chain_id':'99999','genesis_sha256':digest,'mutation_performed':False,'production_qualified':False})
  self.assertEqual(before,self.snapshot());self.assertFalse((self.c.control/'audit.jsonl').exists())
  for params in ({'required_gateway_tcp':{'ip':'10.2.3.5','port':8551}},{'required_gateway_tcp':{'ip':'10.2.3.4','port':443}},{'required_gateway_tcp':{'ip':'127.0.0.1','port':8551}},{'required_gateway_tcp':{'ip':'10.2.3.4','port':8551},'extra':True}):
   with self.subTest(params=params),self.assertRaises(ValueError):gateway.gateway_vpn_preflight(self.c,params)
  self.receipt['gateway_commissioned']=False
  with self.assertRaises(ValueError):gateway.gateway_vpn_preflight(self.c,q['parameters'])
  self.receipt['gateway_commissioned']=True;self.policy['validator_identity_network']['genesis.json']='0'*64;self.save('tmp/controller/policy.json',self.policy)
  with self.assertRaises(ValueError):gateway.gateway_vpn_preflight(self.c,q['parameters'])
  self.assertFalse((self.c.control/'audit.jsonl').exists())
 def test_restricted_provider_and_secret_scope_are_verified_before_enrollment(self):
  import hashlib,vpn_authorization as v
  ca=b'public fixture CA';binding={'network_id':'engineering-canary','chain_id':99999,'formation_sha256':'a'*64}
  provider={'version':1,'profile':v.GATEWAY_PROFILE,'management_origin':'https://vpn.example','api_origin':'https://vpn.example','account_id':'account','ca_sha256':hashlib.sha256(ca).hexdigest(),'auto_groups':[],'network_binding':binding,'required_gateway_tcp':{'ip':'10.2.3.4','port':8551},'expires_at':int(time.time())+60}
  raw=v.encode(provider);self.save('tmp/controller/authorization/inputs/vpn-provider.json',provider)
  path=self.c.control/'authorization/inputs/vpn-ca.pem';path.write_bytes(ca);path.chmod(0o600)
  self.policy['authorization_files']={'vpn-provider.json':hashlib.sha256(raw).hexdigest()};self.save('tmp/controller/policy.json',self.policy)
  secret={'setup_key':'private-fixture','hostname':'gateway','management_url':'https://vpn.example','required_gateway_tcp':provider['required_gateway_tcp']}
  with patch.object(self.c,'vpn_provider_binding',return_value=binding):
   before=self.snapshot();self.assertEqual(gateway.gateway_vpn_enrollment_scope(self.c,self.receipt,v.encode(secret)),provider['required_gateway_tcp']);self.assertEqual(before,self.snapshot())
   for changed in ({**secret,'management_url':'https://foreign.example'},{**secret,'required_gateway_tcp':{'ip':'10.2.3.5','port':8551}},{**secret,'required_peer_ips':['10.2.3.4']}):
    with self.assertRaises(ValueError):gateway.gateway_vpn_enrollment_scope(self.c,self.receipt,v.encode(changed))
   gateway.gateway_vpn_recovery_scope(self.c,self.receipt,provider)
   for changed in ({**provider,'profile':v.CONTROLLED_PROFILE},{**provider,'required_gateway_tcp':{'ip':'10.2.3.5','port':8551}},{**provider,'network_binding':{**binding,'formation_sha256':'b'*64}}):
    with self.assertRaises(ValueError):gateway.gateway_vpn_recovery_scope(self.c,self.receipt,changed)
  self.assertFalse((self.c.control/'audit.jsonl').exists())
 def test_target_role_only_from_verified_installation_and_read_preflight_dispatch(self):
  with patch.object(gateway,'gateway_target_available',return_value=True):
   self.assertEqual(self.c.target()['installed_role'],'rpc_gateway')
   self.mocks[2].side_effect=ValueError('seal drift');self.assertIsNone(self.c.target()['installed_role'])
   self.mocks[2].side_effect=None;self.mocks[2].return_value=({'role':'foreign'},{});self.assertIsNone(self.c.target()['installed_role'])
  q={'version':1,'operation':'gateway_vpn_preflight','parameters':{'required_gateway_tcp':{'ip':'10.2.3.4','port':8551}}}
  with patch.object(controller.platform,'system',return_value='Linux'),patch.object(controller.platform,'machine',return_value='x86_64'),patch.object(gateway,'gateway_vpn_preflight',return_value={'checked':True}) as preflight:
   self.assertEqual(self.c.dispatch(q),{'checked':True});preflight.assert_called_once_with(self.c,q['parameters'])
  for params in ({},{'required_gateway_tcp':{'ip':'10.2.3.4','port':True}},{'required_gateway_tcp':{'ip':'10.2.3.4','port':8551},'extra':1}):
   with self.assertRaises(controller.Refused):controller.parse_request(controller.canonical({**q,'parameters':params}))

if __name__=='__main__':unittest.main()
