"""Preserve one expired native transport permission without renewal or mutation."""
import copy,hashlib,json,sys
from contextlib import ExitStack,nullcontext
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
import bootstrap as b
import controller as c
import lifecycle as life
from apqe_layout import FORMATION_PUBLIC_INPUTS

class PreservationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
  self.control=self.root/'tmp/controller';(self.control/'grants').mkdir(parents=True,mode=0o700)
  for name in ('config','network','keys'):(self.root/name).mkdir(mode=0o700)
  self.key=c.request_digest({'version':1,'operation':'commission','parameters':{}})
  self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),'community_enrollment':False,'qualified_operations':[],'releases':{},'engineering_authorization':{'sha256':'a'*64,'sequence':21,'expires_at':100},'validator_commissioning_files':{},'authorization_files':{}}
  for name in FORMATION_PUBLIC_INPUTS:
   raw=('native reviewed '+name).encode();path=self.control/'authorization/inputs/commissioning'/name
   path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
   pin=hashlib.sha256(raw).hexdigest();self.policy['validator_commissioning_files'][name]=pin;self.policy['authorization_files']['commissioning/'+name]=pin
  self.policy['validator_identity_network']={name:self.policy['validator_commissioning_files']['network/'+name] for name in c.GENESIS_FILES}
  self.grant={'root':str(self.root),'operation':'commission','request_sha256':self.key,'expires_at':100,'authorization_sha256':'a'*64,'authorization_sequence':21}
  self.path=self.control/'grants'/(self.key+'.json');self.save(self.path,self.grant);self.save(self.control/'policy.json',self.policy)
 def save(self,path,value):path.write_text(json.dumps(value));path.chmod(0o600)
 def facts(self):return b.update_commission_grant(self.root,self.policy,101)
 def snapshot(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
 def test_actual_prior_empty_grants_gate_refuses_but_exact_preservation_keeps_all_bytes(self):
  self.assertTrue(any((self.control/'grants').iterdir())) # Original namespace gate.
  before=self.snapshot();facts=self.facts()
  self.assertEqual(facts,{'request_sha256':self.key,'grant_sha256':hashlib.sha256(self.path.read_bytes()).hexdigest(),'expires_at':100,'commissioning_sha256':hashlib.sha256(json.dumps(self.policy['validator_commissioning_files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()})
  self.assertEqual(before,self.snapshot());self.assertEqual(self.path.read_bytes(),before['tmp/controller/grants/'+self.key+'.json'])
 def test_active_foreign_changed_parent_multiple_or_linked_grants_refuse_unchanged(self):
  for field,value in [('expires_at',102),('operation','start'),('root','/foreign'),('authorization_sha256','b'*64),('authorization_sequence',22),('request_sha256','b'*64)]:
   grant={**self.grant,field:value};self.save(self.path,grant);before=self.snapshot()
   with self.subTest(field=field),self.assertRaises(ValueError):self.facts()
   self.assertEqual(before,self.snapshot())
  self.save(self.path,self.grant);extra=self.control/'grants'/('b'*64+'.json');self.save(extra,{})
  with self.assertRaises(ValueError):self.facts()
  extra.unlink();self.path.unlink();self.path.symlink_to(self.control/'policy.json')
  with self.assertRaises(ValueError):self.facts()
 def test_consumed_audit_partial_published_and_changed_artifact_refuse_without_writes(self):
  cases=['audit','partial','published','artifact','intent','unknown-key']
  for kind in cases:
   with self.subTest(kind=kind):
    if kind=='audit':path=self.control/'audit.jsonl';self.save(path,{'request_sha256':self.key,'operation':'commission','time':99})
    elif kind=='partial':path=self.root/'tmp/commission-prepare-incomplete';path.mkdir()
    elif kind=='published':path=self.root/'network/genesis.json';self.save(path,{})
    elif kind=='artifact':path=self.control/'authorization/inputs/commissioning'/next(iter(FORMATION_PUBLIC_INPUTS));original=path.read_bytes();path.write_bytes(b'changed')
    elif kind=='intent':path=self.root/life.UPGRADE_INTENT;path.parent.mkdir(exist_ok=True);self.save(path,{})
    else:path=self.root/'keys/unknown';self.save(path,{})
    before=self.snapshot()
    with self.assertRaises(ValueError):self.facts()
    self.assertEqual(before,self.snapshot())
    if kind=='artifact':path.write_bytes(original)
    elif path.is_dir():path.rmdir()
    else:path.unlink()
 def test_proof_entrypoint_closed_scope_freshness_and_no_writes(self):
  selection={'release_id':'old','manifest_sha256':'e'*64,'network_id':'fresh','chain_id':99999,'node_name':'validator-02'}
  self.policy.update(engineering_initial_authorization_sha256='b'*64,validator_formation_sha256='c'*64,engineering_target={'root':str(self.root)},engineering_selection=selection)
  engine=self.control/'controller.py';engine.write_bytes(b'# pinned test engine\n');engine.chmod(0o600)
  self.policy['engine_files']={'controller.py':hashlib.sha256(engine.read_bytes()).hexdigest()};self.save(self.control/'policy.json',self.policy)
  context={'initial_sha256':'b'*64,'parent_sha256':'a'*64,'formation_sha256':'c'*64,'target':self.policy['engineering_target'],'selection':selection,'expires_at':200}
  root=self.root
  class FixturePath(type(root)):
   @property
   def parents(self):return tuple(p for p in super().parents if p==root or root in p.parents)
  with ExitStack() as stack:
   stack.enter_context(patch.object(b,'ROOT',FixturePath(root)))
   stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256','b'*64,create=True))
   stack.enter_context(patch.object(b,'enrolled_engine',return_value=('controller.py',)))
   stack.enter_context(patch.object(b,'effective_engineering_selection',return_value=selection))
   stack.enter_context(patch.object(sys,'path',sys.path.copy()))
   stack.enter_context(patch.object(c,'control_inventory'))
   stack.enter_context(patch.object(life,'_lifecycle_lock',side_effect=lambda root:nullcontext()))
   stack.enter_context(patch.object(life,'_sealed_receipt',return_value=({'package_sha256':'e'*64},{})))
   stack.enter_context(patch.object(life,'_unit_state',return_value={'MainPID':'0','ActiveState':'inactive'}))
   guard=stack.enter_context(patch.object(life,'_assert_no_application_processes'))
   stack.enter_context(patch('time.time',return_value=101))
   before=self.snapshot();wire={'context':context,'challenge':'d'*64};result=b.inspect_update_commission_grant(wire)
   self.assertEqual(set(result),{'schema','challenge','parent_sha256','authorization_sequence','preservation','mutation_performed'})
   self.assertEqual(result['challenge'],'d'*64);self.assertFalse(result['mutation_performed']);self.assertEqual(result['preservation'],self.facts());guard.assert_called()
   for field,value in [('parent_sha256','f'*64),('target',{}),('selection',{}),('expires_at',100)]:
    with self.subTest(field=field),self.assertRaises(ValueError):b.inspect_update_commission_grant({'context':{**context,field:value},'challenge':'d'*64})
   with self.assertRaises(ValueError):b.inspect_update_commission_grant({'context':context,'challenge':'not-a-pin'})
   self.assertEqual(before,self.snapshot())
   engine.write_bytes(b'changed')
   with self.assertRaisesRegex(ValueError,'engine drift'):b.inspect_update_commission_grant(wire)

 def test_empty_grants_are_null_and_native_context_requires_exact_conditional_permission(self):
  self.path.unlink();self.assertIsNone(self.facts())
  selection={'release_id':'old','manifest_sha256':'d'*64}
  policy={'engineering_initial_authorization_sha256':'a'*64,'engineering_authorization':{'sha256':'b'*64},'validator_formation_sha256':'c'*64,'engineering_target':{}}
  context={'initial_sha256':'a'*64,'parent_sha256':'b'*64,'formation_sha256':'c'*64,'target':{},'selection':selection,'release_id':'new','manifest_sha256':'e'*64,'expires_at':200}
  with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',context,create=True):self.assertEqual(b.engineering_update_context(policy,selection,'new','e'*64,101),context)
  with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',{**context,'unknown':True},create=True),self.assertRaises(ValueError):b.engineering_update_context(policy,selection,'new','e'*64,101)

if __name__=='__main__':unittest.main()
