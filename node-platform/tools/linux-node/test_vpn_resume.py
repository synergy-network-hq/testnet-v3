"""Existing-peer VPN-only resume: no real service, setup key or provider call."""
import base64
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import controller as c
import lifecycle as life
import vpn

class ResumeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
  self.owner=object.__new__(c.Controller);self.owner.root=self.root;self.owner.control=self.root/'tmp/controller'
  self.request={'version':1,'operation':'vpn_resume','parameters':{}};self.key=c.request_digest(self.request)
  self.policy={'engineering_target':{'kind':'remote','host':'approved.example','port':22,'root':str(self.root)},'engineering_selection':{'manifest_sha256':'a'*64,'network_id':'fresh','chain_id':99999},'validator_formation_sha256':'b'*64,'authorization_files':{}}
  self.owner.policy=lambda:self.policy
  self.write('evidence/vpn-enrollment-attempt.json',{'format':'nodenetwork-vpn-attempt-v1'})
  self.state=vpn.attempt_state(self.root);binding=self.owner.vpn_provider_binding(self.state['scope_sha256'])
  name='nn-'+hashlib.sha256(c.canonical(binding)).hexdigest()[:60]
  self.wg=base64.b64encode(b'p'*32).decode()
  self.write('evidence/vpn-enrollment.json',{'native_enrollment_verified':True,'hostname':name,'wireguard_public_key':self.wg,'overlay_address':'100.64.0.2/16','management_url':'https://approved.example'})
  self.write('evidence/vpn-server-binding.json',{'server_binding_verified':True,'peer_id':'peer','peer_name':name,'hostname':'machine','wireguard_public_key':self.wg,'ip':'100.64.0.2'})
  path=self.write('tmp/controller/authorization/inputs/vpn-provider.json',{'management_origin':'https://approved.example','expires_at':1})
  self.policy['authorization_files']['vpn-provider.json']=hashlib.sha256(path.read_bytes()).hexdigest()
  self.write('vpn/default.json',{'ManagementURL':{'Scheme':'https','Host':'approved.example','Path':''},'PrivateKey':base64.b64encode(b'p'*32).decode(),'SSHKey':'-----BEGIN PRIVATE KEY-----\n'+base64.b64encode(bytes.fromhex('302e020100300506032b657004220420')+b's'*32).decode()+'\n-----END PRIVATE KEY-----\n'})
  self.units={'synergy-node.service':{'MainPID':'0','ActiveState':'inactive'},'synergy-vpn.service':{'MainPID':'0','ActiveState':'inactive'}}
  self.current={'service_registered':True,'enrollment_recorded':True,'server_bound':True,'enrollment_staged':False,'reconciliation_required':False,'retired':False,'connected':False}
  self.owner.vpn_status=lambda:dict(self.current)
  self.live={'publicKey':self.wg,'netbirdIp':'100.64.0.2/16','management':{'connected':True},'signal':{'connected':True}}
  for name,replacement in [('_lifecycle_lock',lambda root:nullcontext()),('_sealed_receipt',Mock(return_value=({},{}))),('_attributed_units',lambda root:self.units),('_assert_no_application_processes',Mock())]:
   ctx=patch.object(life,name,replacement);ctx.start();self.addCleanup(ctx.stop)
  for name,replacement in [('client_environment',Mock(return_value={})),('status',lambda root,**kw:self.live)]:
   ctx=patch.object(vpn,name,replacement);ctx.start();self.addCleanup(ctx.stop)
  self.mutate=patch.object(life,'mutate_owned_service',side_effect=self.start).start();self.addCleanup(patch.stopall)
  self.owner.authorize=Mock(side_effect=self.consume)
 def write(self,name,value):
  path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value));path.chmod(0o600);return path
 def consume(self,request):
  self.write('tmp/controller/audit.jsonl',{'request_sha256':self.key,'operation':'vpn_resume','time':1})
 def start(self,root,operation,unit):
  self.assertEqual((operation,unit),('start','synergy-vpn.service'))
  self.units[unit]={'MainPID':'123','ActiveState':'active'};self.current['connected']=True
 def test_existing_expired_issuer_peer_resumes_and_lost_reply_reconciles_without_restarting(self):
  before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
  result=self.owner.vpn_resume(self.request);self.assertTrue(result['resumed']);self.assertFalse(result['validator_started'])
  self.assertTrue(self.owner.vpn_resume_status()['resumed']);self.assertEqual(self.mutate.call_count,1)
  for path,data in before.items():self.assertEqual(path.read_bytes(),data)
  self.owner.vpn_resume(self.request);self.assertEqual(self.mutate.call_count,1) # healthy exact-peer no-op
 def test_active_unresponsive_running_node_or_pending_peer_refuse_before_authorization(self):
  for change in ('active','node','pending','retired','unbound'):
   with self.subTest(change=change):
    self.units['synergy-vpn.service']={'MainPID':'123' if change=='active' else '0','ActiveState':'active' if change=='active' else 'inactive'}
    self.units['synergy-node.service']={'MainPID':'99' if change=='node' else '0','ActiveState':'active' if change=='node' else 'inactive'}
    self.current.update(enrollment_staged=change=='pending',retired=change=='retired',server_bound=change!='unbound')
    with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  self.owner.authorize.assert_not_called();self.mutate.assert_not_called()
 def test_foreign_provider_changed_key_address_and_timeout_preserve_attempt_fence(self):
  original=(self.root/c.VPN_ATTEMPT).read_bytes()
  for field,value in [('publicKey',base64.b64encode(b'q'*32).decode()),('netbirdIp','100.64.0.9/16')]:
   self.live[field]=value
   with patch.object(c.time,'sleep'),self.assertRaises(c.Refused):self.owner.vpn_resume(self.request)
   self.live.update(publicKey=self.wg,netbirdIp='100.64.0.2/16')
  self.assertEqual((self.root/c.VPN_ATTEMPT).read_bytes(),original)
  self.write('tmp/controller/authorization/inputs/vpn-provider.json',{'management_origin':'https://foreign.example'})
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
 def test_status_requires_consumed_exact_audit_and_never_starts(self):
  self.start(self.root,'start','synergy-vpn.service')
  self.assertFalse(self.owner.vpn_resume_status()['resumed'])
  self.consume(self.request);grant=self.write('tmp/controller/grants/'+self.key+'.json',{})
  self.assertFalse(self.owner.vpn_resume_status()['resumed']);grant.unlink()
  self.assertTrue(self.owner.vpn_resume_status()['resumed'])
  self.write('tmp/controller/audit.jsonl',{'request_sha256':self.key,'operation':'vpn_stop','time':1})
  self.assertFalse(self.owner.vpn_resume_status()['resumed'])
  self.mutate.assert_not_called()
 def test_crash_after_start_reconciles_only_by_live_read(self):
  def interrupted(*args):self.start(*args);raise OSError('lost service response')
  self.mutate.side_effect=interrupted
  with self.assertRaises(OSError):self.owner.vpn_resume(self.request)
  self.assertTrue(self.owner.vpn_resume_status()['resumed']);self.assertEqual(self.mutate.call_count,1)
 def test_changed_custody_pending_retirement_and_unknown_file_ownership_refuse(self):
  path=self.root/'vpn/default.json';path.chmod(0o644)
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  path.chmod(0o600);original=path.read_bytes();path.unlink();path.symlink_to(self.root/'evidence/vpn-enrollment.json')
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  path.unlink();path.write_bytes(original);path.chmod(0o600)
  pending=self.write('tmp/controller/authorization/inputs/vpn-retirement.json',{})
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  pending.unlink();self.owner.authorize.assert_not_called();self.mutate.assert_not_called()
  def change(*args):self.start(*args);self.write('vpn/default.json',{'PrivateKey':'changed','SSHKey':'changed'})
  self.mutate.side_effect=change
  with patch.object(c.time,'sleep'),self.assertRaises(c.Refused):self.owner.vpn_resume(self.request)

 def test_malformed_retained_identity_never_starts_or_consumes_grant(self):
  self.write('vpn/default.json',{'PrivateKey':'not-canonical','SSHKey':'untrusted-format'})
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  self.owner.authorize.assert_not_called();self.mutate.assert_not_called()

 def test_pre_authorize_refusal_code_cannot_describe_post_start_uncertainty(self):
  self.units['synergy-vpn.service']={'MainPID':'123','ActiveState':'active'}
  with self.assertRaises(c.Refused) as rejected:self.owner.vpn_resume(self.request)
  self.assertEqual(rejected.exception.code,'vpn_resume_not_started');self.owner.authorize.assert_not_called()
  self.units['synergy-vpn.service']={'MainPID':'0','ActiveState':'inactive'}
  self.live['publicKey']=base64.b64encode(b'q'*32).decode()
  with patch.object(c.time,'sleep'),self.assertRaises(c.Refused) as uncertain:self.owner.vpn_resume(self.request)
  self.assertEqual(uncertain.exception.code,'vpn_reconciliation_required');self.assertEqual(self.mutate.call_count,1)
 def test_foreign_persisted_management_url_refuses_before_start(self):
  path=self.root/'vpn/default.json';profile=json.loads(path.read_bytes());profile['ManagementURL']['Host']='foreign.example'
  self.write('vpn/default.json',profile)
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  self.owner.authorize.assert_not_called();self.mutate.assert_not_called()

 def test_exact_request_and_grant_are_required(self):
  self.assertEqual(c.parse_request(c.canonical(self.request)),self.request)
  for op in ('vpn_resume','vpn_resume_status'):
   with self.assertRaises(ValueError):c.parse_request(c.canonical({'version':1,'operation':op,'parameters':{'unit':'foreign'}}))
  self.owner.authorize.side_effect=ValueError('grant absent')
  with self.assertRaises(ValueError):self.owner.vpn_resume(self.request)
  self.mutate.assert_not_called()

if __name__=='__main__':unittest.main()
