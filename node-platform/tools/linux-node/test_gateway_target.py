"""Real local controller durability/authorization; native crypto has its own reused fixture."""
import base64,contextlib,copy,hashlib,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import bootstrap as b
import canary_rpc_relay as g
import controller as c

def req(op,p=None):return {'version':1,'operation':op,'parameters':p or {}}
def sha(raw):return hashlib.sha256(raw).hexdigest()

class GatewayTargetTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
  for name in ('tmp','keys','config','network'):(self.root/name).mkdir(mode=0o700)
  self.c=c.Controller(self.root);self.c.control.mkdir(mode=0o700);(self.c.control/'grants').mkdir(mode=0o700)
  self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),'community_enrollment':False,'qualified_operations':['gateway_target_generate','gateway_target_commission'],'releases':{}}
  self.receipt={'format':'synergy-universal-linux-v1','root':str(self.root),'network_id':'synergy-posy-canary-fixture','chain_id':99999,'node_name':'gateway-01','role':'rpc_gateway','package_sha256':'a'*64,'package_files':{'bin/synergy-node':'b'*64},'host_integrations':[],'consensus_started':False}
  self.save(self.root/'installation.json',g._gateway_request_bytes(self.receipt))
  self.raw={n:('public '+n).encode() for n in g.GATEWAY_TARGET_PUBLIC};self.pins={k:sha(v) for k,v in self.raw.items()};self.pins['provider']='a'*64
  self.config=g._gateway_target_config(self.c,self.receipt,self.pins,self.c.control/'authorization/inputs/commissioning/network')
  self.scope={'network_id':self.receipt['network_id'],'chain_id':'99999','genesis_sha256':self.pins['genesis.json']};self.parts=(self.policy,self.receipt,self.pins,self.raw,self.config,self.scope);self.calls=[]
  for manager in (patch.object(g,'_gateway_target_scope',side_effect=lambda _:(self.parts[0],json.loads((self.root/'installation.json').read_bytes()),*self.parts[2:])),patch.object(self.c,'policy',side_effect=lambda:copy.deepcopy(self.policy)),patch('lifecycle._lifecycle_lock',side_effect=lambda _:contextlib.nullcontext()),patch('lifecycle._integration_plan',return_value=None),patch('lifecycle._unit_state',return_value={'LoadState':'not-found','MainPID':'0'}),patch('lifecycle._assert_no_application_processes'),patch.object(g,'native',side_effect=self.native)):
   manager.start();self.addCleanup(manager.stop)
 def save(self,p,raw):
  p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
 def native(self,args,**kw):
  op=args[2];self.calls.append(op)
  if op=='provision':
   self.assertEqual(json.loads(Path(args[3]).read_bytes()),self.config);self.assertGreaterEqual(len(Path(args[5]).read_bytes()),32);self.assertNotEqual(Path(args[5]).read_bytes(),Path(args[6]).read_bytes())
   base=Path(args[4]);base.mkdir(mode=0o700);self.save(base/'gateway-enrollment.json',b'{"payload":{"node_address":"synv5fixture"}}')
   for n in ('gateway-transport.encrypted.json','gateway-identity.encrypted.json'):self.save(base/n,b'{"fixture":"encrypted"}')
   return b''
  if op=='inspect-target-enrollment':
   data=json.loads(kw['data']);self.assertEqual(data['node_configuration'],self.config)
   return json.dumps({'gateway_address':'synv5fixture','enrollment_sha256':sha(data['enrollment_json'].encode()),'mutation_performed':False}).encode()
  if op=='inspect-target-candidate':
   data=json.loads(kw['data']);self.assertEqual(data['node_configuration'],self.config);self.assertEqual(data['admission_json'],'{"public":"admission"}');self.assertEqual(data['relay_configuration']['listen_address'],'127.0.0.1:9944')
   return b'{"transport_custody_verified":true,"mutation_performed":false}'
  if op=='check':return b''
  self.fail('Unexpected native call '+op)
 def grant(self,r):
  key=c.request_digest(r);self.save(self.c.control/'grants'/(key+'.json'),json.dumps({'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+300}).encode())
 def call(self,op,p=None,grant=False):
  r=req(op,p);self.assertEqual(c.parse_request(g._gateway_request_bytes(r)),r)
  if grant:self.grant(r)
  return g.gateway_target(self.c,r)
 def generate(self):return self.call('gateway_target_generate',{'genesis_sha256':self.scope['genesis_sha256']},True)
 def params(self):
  wrapper={'node_configuration':g._gateway_target_config(self.c,self.receipt,self.pins,self.root/'network'),'relay_specification':{'listen_address':'127.0.0.1:9944','role':{'kind':'gateway','gateway_address':'synv5fixture','validator_address':'synv1fixture','validator_relay_port':8551,'allowed_origins':[]}}};admission='{"public":"admission"}';config=g._gateway_request_bytes(wrapper).decode()
  return {'admission_json':admission,'admission_sha256':sha(admission.encode()),'configuration_json':config,'configuration_sha256':sha(config.encode())}
 def test_configured_network_profile_persists_and_cannot_be_rebound(self):
  selection = {'network_id': 'private-observer-network', 'chain_id': 14002}
  self.receipt.update(selection)
  self.save(self.root/'installation.json', g._gateway_request_bytes(self.receipt))
  self.scope.update(network_id=selection['network_id'], chain_id=str(selection['chain_id']))
  self.config.update(selection)
  signed_origin = {name: self.pins[name] for name in self.raw}
  profile = {
   'schema': 'synergy-network-provisioning-v1', 'profile_id': 'private-rpc',
   'network_name': 'Private network', 'genesis_hash': 'f'*64, **selection,
   'node_name': self.receipt['node_name'], 'role': 'rpc_gateway', 'origin': signed_origin,
   'gateway': {'public_hostname': 'rpc.example.test', 'tls': 'required',
    'protocol': 'synergy-json-rpc-v1', 'listen_address': '127.0.0.1:9944',
    'validator_address': 'synv1fixture', 'validator_relay_port': 8551,
    'allowed_origins': [], 'vpn_provider_sha256': '5'*64},
  }
  raw = g._gateway_request_bytes(profile)
  managed = self.c.control/'authorization/inputs'/g.NETWORK_PROFILE
  self.save(managed, raw)
  self.policy['authorization_files'] = {g.NETWORK_PROFILE: sha(raw)}
  self.policy['gateway_origin_files'] = {'network/'+name: pin for name, pin in signed_origin.items()}

  self.assertEqual(self.generate()['chain_id'], '14002')
  parameters = self.params()
  altered = json.loads(parameters['configuration_json'])
  altered['relay_specification']['listen_address'] = '127.0.0.1:9945'
  altered_raw = g._gateway_request_bytes(altered)
  with self.assertRaisesRegex(ValueError, 'approved network profile'):
   self.call('gateway_target_commission_preflight', dict(parameters,
    configuration_json=altered_raw.decode(), configuration_sha256=sha(altered_raw)))

  self.assertEqual(self.call('gateway_target_commission', parameters, True)['state'], 'commissioned')
  installed = self.root/'config'/g.NETWORK_PROFILE
  self.assertEqual(installed.read_bytes(), raw)
  self.assertEqual(self.call('gateway_target_status')['chain_id'], '14002')
  self.save(installed, g._gateway_request_bytes(dict(profile, chain_id=99999)))
  self.assertEqual(self.call('gateway_target_status')['state'], 'uncertain')

 def test_generate_commission_positive_reconcile_export_preserves_all_custody(self):
  self.assertEqual(self.call('gateway_target_preflight')['state'],'ready');self.assertEqual(self.calls,[])
  generated=self.generate();self.assertEqual(generated['state'],'identity_ready');self.assertFalse(generated['transport_custody_verified']);custody={p:p.read_bytes() for p in (self.root/'keys/apqe').iterdir()}
  import lifecycle
  self.assertEqual(lifecycle._installation_stage(self.root),'fresh')
  p=self.params();checked=self.call('gateway_target_commission_preflight',p);self.assertEqual(len(checked),15);self.assertEqual(checked['request_sha256'],c.request_digest(req('gateway_target_commission',p)));self.assertFalse((self.root/'network/genesis.json').exists())
  out=self.call('gateway_target_commission',p,True);self.assertEqual(lifecycle._installation_stage(self.root),'commissioned');self.assertEqual(out['state'],'commissioned');self.assertEqual(len(out),18);export=self.call('gateway_target_export');self.assertEqual(len(export),19);self.assertEqual(sha(export['enrollment_json'].encode()),out['enrollment_sha256'])
  for field in ('generation_request_sha256','commission_request_sha256'):self.assertEqual(self.call('gateway_target_reconcile',{'request_sha256':out[field]}),out)
  with self.assertRaises(ValueError):self.call('gateway_target_reconcile',{'request_sha256':'f'*64})
  for path,raw in custody.items():self.assertEqual(path.read_bytes(),raw)
  self.assertFalse(out['services_started']);self.assertFalse(out['public_listener']);self.assertEqual(len((self.c.control/'audit.jsonl').read_bytes().splitlines()),2)
 def test_interrupted_provision_never_replays_or_proves_nonapplication(self):
  def failed(args,**kw):
   if args[2]=='provision':raise ValueError('fixture interruption')
   return self.native(args,**kw)
  with patch.object(g,'native',side_effect=failed),self.assertRaises(ValueError):self.generate()
  self.assertEqual(self.call('gateway_target_status')['state'],'uncertain')
  with self.assertRaises(ValueError):self.generate()
  self.assertEqual(len((self.c.control/'audit.jsonl').read_bytes().splitlines()),1)
  with self.assertRaises(ValueError):self.call('gateway_target_reconcile',{'request_sha256':'a'*64})
 def test_foreign_unit_and_existing_output_refuse_before_consumption(self):
  r=req('gateway_target_generate',{'genesis_sha256':self.scope['genesis_sha256']});self.grant(r);grant=self.c.control/'grants'/(c.request_digest(r)+'.json')
  for state in ({'LoadState':'loaded','MainPID':'0','FragmentPath':'/foreign.service'},{'LoadState':'not-found','MainPID':'42'}):
   with patch('lifecycle._unit_state',return_value=state),self.assertRaises(ValueError):g.gateway_target(self.c,r)
   self.assertTrue(grant.exists())
  self.save(self.root/'network/foreign.json',b'{}')
  with self.assertRaises(ValueError):g.gateway_target(self.c,r)
  self.assertTrue(grant.exists());self.assertFalse((self.c.control/'audit.jsonl').exists())
 def test_candidate_refuses_foreign_paths_provider_listener_legacy_and_hash(self):
  self.generate();original=self.params()
  for defect in ('listener','provider','path','legacy','hash','extra','existing'):
   p=copy.deepcopy(original);cfg=json.loads(p['configuration_json'])
   if defect=='listener':cfg['relay_specification']['listen_address']='0.0.0.0:9944'
   if defect=='provider':cfg['node_configuration']['aegis_provider']['authenticated_report_sha256']='0'*64
   if defect=='path':cfg['node_configuration']['storage']['data_directory']='/outside'
   if defect=='legacy':cfg['relay_specification']['role'][g.BOOTSTRAP_PIN]='0'*64
   if defect=='extra':cfg['secret']='no'
   if defect=='hash':p['admission_sha256']='0'*64
   if defect=='existing':self.save(self.root/'config/foreign.json',b'{}')
   p.update(configuration_json=g._gateway_request_bytes(cfg).decode(),configuration_sha256=sha(g._gateway_request_bytes(cfg)))
   with self.subTest(defect=defect),self.assertRaises(ValueError):self.call('gateway_target_commission_preflight',p)
  self.assertEqual(len((self.c.control/'audit.jsonl').read_bytes().splitlines()),1)
 def test_positive_state_requires_audit_no_grant_and_exact_private_inventory(self):
  out=self.generate();directory=self.root/g.GATEWAY_TARGET;key=out['generation_request_sha256'];audit=self.c.control/'audit.jsonl';saved=audit.read_bytes()
  for defect in ('audit','grant','unknown','mode','symlink','directory'):
   path=self.root/'keys/apqe/gateway-identity.unlock';raw=path.read_bytes()
   if defect=='audit':self.save(audit,b'')
   if defect=='grant':self.save(self.c.control/'grants'/(key+'.json'),b'{}')
   if defect=='unknown':self.save(directory/'unknown',b'no')
   if defect=='mode':path.chmod(0o644)
   if defect=='symlink':path.unlink();path.symlink_to(self.root/'keys/apqe/gateway-transport.unlock')
   if defect=='directory':(self.root/'keys/apqe').chmod(0o755)
   with self.subTest(defect=defect):self.assertEqual(self.call('gateway_target_status')['state'],'uncertain')
   self.save(audit,saved)
   for extra in (self.c.control/'grants'/(key+'.json'),directory/'unknown'):
    if extra.exists():extra.unlink()
   if path.is_symlink():path.unlink()
   self.save(path,raw);(self.root/'keys/apqe').chmod(0o700)
 def test_absent_and_uncertain_export_have_closed_nineteen_fields(self):
  with patch.object(g,'_gateway_target_scope',side_effect=ValueError('private fixture')):
   out=self.call('gateway_target_export');self.assertEqual(len(out),19);self.assertIsNone(out['enrollment_json']);self.assertFalse(out['available']);self.assertNotIn('private',json.dumps(out))
  self.generate();self.save(self.root/g.GATEWAY_TARGET/'unknown',b'no');self.assertEqual(len(self.call('gateway_target_export')),19)
 def test_initial_origin_exact_seven_and_no_validator_configuration(self):
  formation=g._gateway_request_bytes({'network_id':self.receipt['network_id'],'chain_id_hex':format(99999,'064x'),'formation_id':'f'*64});raw={'formation-context.json':formation,**{'commissioning/network/'+k:v for k,v in self.raw.items()}}
  doc={'chain_id':99999,'artifacts':{k:sha(v) for k,v in raw.items()},'genesis_pins':{k:self.pins[k] for k in ('genesis.json','authority.json','authority-root.pub')},'requests':[{'operation':'gateway_install','request_sha256':'a'*64}]};encoded={k:base64.b64encode(v).decode() for k,v in raw.items()};self.assertEqual(b.authorization_inputs(doc,encoded),raw)
  for defect in ('formation','extra','mixed','genesis'):
   d=copy.deepcopy(doc);e=copy.deepcopy(encoded)
   if defect=='formation':del d['artifacts']['formation-context.json'];del e['formation-context.json']
   if defect=='extra':d['artifacts']['commissioning/config/node.json']=sha(b'{}');e['commissioning/config/node.json']=base64.b64encode(b'{}').decode()
   if defect=='mixed':d['requests'].append({'operation':'install','request_sha256':'b'*64})
   if defect=='genesis':d['genesis_pins']['genesis.json']='0'*64
   with self.subTest(defect=defect),self.assertRaises(ValueError):b.authorization_inputs(d,e)


 def test_private_root_symlink_refuses_without_creating_external_custody(self):
  outside=self.root.parent/'outside';outside.mkdir(mode=0o700);(self.root/'keys').rmdir();(self.root/'keys').symlink_to(outside,target_is_directory=True)
  r=req('gateway_target_generate',{'genesis_sha256':self.scope['genesis_sha256']});self.grant(r)
  with self.assertRaises(ValueError):g.gateway_target(self.c,r)
  self.assertEqual(list(outside.iterdir()),[]);self.assertFalse((self.c.control/'audit.jsonl').exists())
 def test_origin_verifies_unchanged_formation_and_all_independent_public_pins(self):
  formation=g._gateway_request_bytes({'network_id':self.receipt['network_id'],'chain_id_hex':format(99999,'064x'),'formation_id':'f'*64});base=self.c.control/'authorization/inputs'
  self.save(base/'formation-context.json',formation)
  for name,raw in self.raw.items():self.save(base/'commissioning/network'/name,raw)
  policy={'authorization_files':{'formation-context.json':sha(formation),**{'commissioning/network/'+k:v for k,v in self.pins.items() if k!='provider'}},'validator_formation_sha256':sha(formation),'validator_identity_network':{k:self.pins[k] for k in ('genesis.json','authority.json','authority-root.pub')},'gateway_origin_files':{'network/'+k:v for k,v in self.pins.items() if k!='provider'}}
  expected={'schema':'nodenetwork-gateway-origin-v1',**self.scope,'mutation_performed':False,**{key:self.pins[name] for key,name in (('authority_sha256','authority.json'),('authority_root_sha256','authority-root.pub'),('registry_sha256','transport-registry.json'),('issuer_root_sha256','transport-root.pub'),('manifest_sha256','network-manifest.json'))}}
  with patch.object(g,'native',return_value=json.dumps(expected).encode()) as run:
   g._gateway_target_origin(self.c,policy,self.receipt,{'files':{'lib/apqe/build-report.json':'a'*64}},self.root)
   for defect in ('formation','inventory','genesis','bytes'):
    q=copy.deepcopy(policy)
    if defect=='formation':q['validator_formation_sha256']='0'*64
    if defect=='inventory':q['gateway_origin_files']['network/authority.json']='0'*64
    if defect=='genesis':q['validator_identity_network']['genesis.json']='0'*64
    if defect=='bytes':self.save(base/'commissioning/network/authority.json',b'changed')
    with self.subTest(defect=defect),self.assertRaises(ValueError):g._gateway_target_origin(self.c,q,self.receipt,{'files':{'lib/apqe/build-report.json':'a'*64}},self.root)
   self.assertEqual(run.call_count,1)
 def test_install_status_exact_original_raw_ten_receipt_and_audit_only(self):
  p={'release_id':'gateway-test','manifest_sha256':'a'*64,**{k:self.receipt[k] for k in ('network_id','chain_id','node_name')}};original=req('gateway_install',p);key=c.request_digest(original)
  self.policy['qualified_operations'].append('gateway_install');self.save(self.c.control/'gateway-install-request.json',g._gateway_request_bytes(original));self.grant(original);self.c.authorize(original)
  receipt={'format':'synergy-universal-linux-v1','root':str(self.root),'role':'rpc_gateway',**{k:p[k] for k in ('network_id','chain_id','node_name')},'package_sha256':p['manifest_sha256'],'package_files':{'bin/synergy-node':'b'*64},'host_integrations':[],'consensus_started':False}
  self.parts=(self.policy,receipt,*self.parts[2:]);query=req('gateway_install_status',{'request_sha256':key})
  with patch.object(g,'_gateway_target_scope',return_value=self.parts),patch('lifecycle._sealed_receipt',return_value=(receipt,{'release_id':p['release_id']})):
   result=g.gateway_install(self.c,query);self.assertEqual(len(result),8);self.assertEqual(result['request'],original);self.assertEqual(len(result['installation']),10);self.assertEqual(result['installation'],receipt)
   self.grant(original)
   with self.assertRaises(ValueError):g.gateway_install(self.c,query)
   (self.c.control/'grants'/(key+'.json')).unlink();self.save(self.c.control/'audit.jsonl',b'')
   with self.assertRaises(ValueError):g.gateway_install(self.c,query)
 def test_commission_marker_is_attributed_and_install_status_preserves_raw_ten_contract(self):
  original=req('gateway_install',{'release_id':'gateway-test','manifest_sha256':'a'*64,**{k:self.receipt[k] for k in ('network_id','chain_id','node_name')}});key=c.request_digest(original)
  self.policy['qualified_operations'].append('gateway_install');self.save(self.c.control/'gateway-install-request.json',g._gateway_request_bytes(original));self.grant(original);self.c.authorize(original)
  self.generate();self.call('gateway_target_commission',self.params(),True)
  receipt=json.loads((self.root/'installation.json').read_bytes());self.assertTrue(receipt['gateway_commissioned'])
  with patch('lifecycle._sealed_receipt',return_value=(receipt,{'release_id':'gateway-test'})):
   result=g.gateway_install(self.c,req('gateway_install_status',{'request_sha256':key}));self.assertEqual(result['installation'],self.receipt);self.assertEqual(len(result['installation']),10)
  for marker in (False,None):
   bad=dict(receipt,gateway_commissioned=marker);self.save(self.root/'installation.json',g._gateway_request_bytes(bad));self.assertEqual(self.call('gateway_target_status')['state'],'uncertain')
  self.save(self.root/'installation.json',g._gateway_request_bytes(receipt));(self.root/g.GATEWAY_TARGET/'commissioned.json').unlink();self.assertEqual(self.call('gateway_target_status')['state'],'uncertain')
 def test_install_fresh_root_gate_precedes_ready_or_authorization(self):
  from test_controller_startup import IsolatedControllerStartupTests
  import synergy_linux as installer
  with tempfile.TemporaryDirectory() as temp:
   root=IsolatedControllerStartupTests().fixture(temp);target=c.Controller(root)
   stage=root/'tmp/bootstrap-master';stage.mkdir(mode=0o700)
   self.save(stage/'package.json',b'{"fixture":"authenticated package"}')
   self.save(stage/'roles/roles.json',b'{"implemented":["rpc_gateway"]}')
   pin=installer.digest(stage/'package.json')
   p={'release_id':'gateway-test','manifest_sha256':pin,'network_id':'synergy-posy-canary-fixture','chain_id':99999,'node_name':'gateway-01'}
   mutation=req('gateway_install',p);digest=c.request_digest(mutation)
   grant=target.control/'grants'/(digest+'.json');self.save(grant,b'{"fixture":"unused grant"}')
   original={path:path.read_bytes() for path in root.rglob('*') if path.is_file()}
   with patch.object(target,'approved_package',return_value=(stage,{'release_id':p['release_id']},{'networks':{p['network_id']:99999}})),patch.object(g,'native',return_value=g._gateway_request_bytes(g.GATEWAY_TARGET_CAPABILITY)),patch.object(g,'_gateway_target_origin'),patch.object(g,'_gateway_target_services'),patch.object(target,'authorize') as authorize,patch('synergy_linux.install') as install,patch('lifecycle._mountinfo_text',return_value=''):
    checked=g.gateway_install(target,req('gateway_install_preflight',p))
    self.assertTrue(checked['packageVerified']);self.assertFalse(checked['activationAuthorized'])
    self.assertEqual(original,{path:path.read_bytes() for path in root.rglob('*') if path.is_file()})
    for defect in ('chain1266','foreign','symlink','mode','stage_digest'):
     member=root/('chain1266' if defect=='chain1266' else 'foreign');saved=(stage/'package.json').read_bytes()
     if defect=='chain1266':member.mkdir(mode=0o700)
     elif defect=='foreign':self.save(member,b'must survive')
     elif defect=='symlink':member.symlink_to(stage,target_is_directory=True)
     elif defect=='mode':root.chmod(0o755)
     else:self.save(stage/'package.json',b'{"changed":true}')
     try:
      for op in ('gateway_install_preflight','gateway_install'):
       with self.subTest(defect=defect,operation=op),self.assertRaises(ValueError):g.gateway_install(target,req(op,p))
      authorize.assert_not_called();install.assert_not_called()
      self.assertEqual(grant.read_bytes(),original[grant]);self.assertFalse((target.control/'gateway-install-request.json').exists())
     finally:
      if defect=='chain1266':member.rmdir()
      elif defect in ('foreign','symlink'):member.unlink()
      elif defect=='mode':root.chmod(0o700)
      else:self.save(stage/'package.json',saved)

 def test_utf8_commission_request_digest_matches_retained_canonical_bytes(self):
  p=self.params();p['admission_json']='{"public":"é"}';p['admission_sha256']=sha(p['admission_json'].encode());request=req('gateway_target_commission',p)
  self.assertEqual(c.request_digest(request),sha(g._gateway_request_bytes(request)))


 def test_actual_native_parser_accepts_master_generated_configuration_before_origin_reads(self):
  binary=os.environ.get('SYNERGY_GATEWAY_TARGET_FIXTURE_NODE')
  if binary is None:self.skipTest('explicit compiled target owner required')
  before=set(self.root.rglob('*'))
  result=subprocess.run([binary,'canary-rpc-relay','inspect-origin'],input=g._gateway_request_bytes(self.config),capture_output=True,timeout=10,check=False)
  self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
  # Missing signed files are the intended failure: the actual strict serde and
  # configuration validation must already have accepted the master-generated DTO.
  self.assertIn(b'No such file or directory',result.stderr)
  self.assertEqual(set(self.root.rglob('*')),before)

if __name__=='__main__':unittest.main()
