import contextlib
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import controller as c
import lifecycle as life

class BootPolicyTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
  self.units=Path(self.tmp.name).resolve()/'systemd';self.units.mkdir(mode=0o755)
  self.states={};plan={'root':str(self.root),'paths':[],'sha256':{}}
  for unit in life.UNITS:
   target=self.root/'systemd'/unit;target.parent.mkdir(mode=0o700,exist_ok=True)
   target.write_text('exact owned '+unit);target.chmod(0o600)
   path=self.units/unit;path.symlink_to(target)
   plan['paths'].append(str(path));plan['sha256'][str(path)]=hashlib.sha256(target.read_bytes()).hexdigest()
   self.states[unit]={'LoadState':'loaded','FragmentPath':str(path),'DropInPaths':'','MainPID':'0','ActiveState':'inactive'}
  self.write('evidence/host-integrations.json',plan)
  self.owner=object.__new__(c.Controller);self.owner.root=self.root;self.owner.control=self.root/'tmp/controller'
  self.owner.policy=lambda:{'root_guard_sha256':'a'*64}
  self.owner.require_bound_validator_vpn=Mock()
  self.authorized=[];self.owner.authorize=self.consume
  self.calls=[]
  p=patch.object(life.subprocess,'run',side_effect=self.observe);p.start();self.addCleanup(p.stop)
  for name,value in [('UNIT_DIRECTORY',self.units),('_unit_state',lambda unit:self.states[unit]),('_lifecycle_lock',lambda root:contextlib.nullcontext()),('_sealed_receipt',Mock(return_value=({'role':'validator','network_id':'network','chain_id':99999},{}))),('native',self.native),('verify_identity',Mock(return_value={'address':'active'}))]:
   p=patch.object(life,name,value);p.start();self.addCleanup(p.stop)
  p=patch('root_guard.check_registration');p.start();self.addCleanup(p.stop)
  p=patch('conformance.installed');self.conformance=p.start();self.addCleanup(p.stop)
  (self.root/'data').mkdir(mode=0o700)
  self.write('config/start-authorized.json',{'network_id':'network','chain_id':99999,'all_validators_ready':True,'all_pairs_vpn_verified':True,'validator_addresses':['active']})
  self.write('network/authority.json',{'payload':{'validators':[{'record':{'validator_id':'active','status':'active'}}]}})
 def write(self,name,value):
  path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value));path.chmod(0o600);return path
 def request(self,service='node',enabled=True):return {'version':1,'operation':'boot_policy','parameters':{'service':service,'enabled':enabled}}
 def consume(self,request):
  self.authorized.append(request);audit=self.owner.control/'audit.jsonl';audit.parent.mkdir(parents=True,exist_ok=True)
  with audit.open('a') as out:out.write(json.dumps({'operation':'boot_policy','request_sha256':c.request_digest(request),'time':1})+'\n')
  audit.chmod(0o600)
 def observe(self,args,**kw):
  self.assertEqual(args[:2],['systemctl','is-enabled']);self.assertIn(args[2],life.UNITS)
  enabled=(self.units/'multi-user.target.wants'/args[2]).is_symlink()
  return Mock(returncode=0 if enabled else 1,stdout=b'enabled\n' if enabled else b'linked\n')
 def native(self,args,**kw):
  self.calls.append(args)
  self.assertEqual(args[0],'systemctl')
  if args[1]=='daemon-reload':return b''
  self.fail('Unexpected runtime command')
 def mutations(self):return self.calls
 def test_exact_enable_disable_and_lost_reply_status(self):
  self.assertEqual(life.service_boot_state(self.root),{'node':False,'vpn':False})
  result=self.owner.boot_policy(self.request());self.assertEqual(result,{'schema':'nodenetwork-boot-policy-v1','service':'node','enabled':True,'runtime_changed':False})
  status=self.owner.boot_policy_status();self.assertTrue(status['applied']);self.assertEqual(status['request_sha256'],c.request_digest(self.request()))
  self.assertFalse(status['vpn_enabled']);self.assertEqual(self.mutations(),[['systemctl','daemon-reload']])
  self.owner.boot_policy(self.request(enabled=False));self.assertFalse(self.owner.boot_policy_status()['node_enabled'])
  self.owner.boot_policy(self.request('vpn'));self.assertTrue(self.owner.boot_policy_status()['vpn_enabled'])
 def test_partial_command_failure_can_only_reconcile_observed_exact_state(self):
  original=self.native
  def lost(args,**kw):
   value=original(args,**kw)
   if args[1]=='daemon-reload':raise OSError('lost reply')
   return value
  with patch.object(life,'native',lost),self.assertRaises(OSError):self.owner.boot_policy(self.request())
  self.assertTrue(self.owner.boot_policy_status()['applied'])
  self.assertEqual(len(self.mutations()),1)
  # An unrelated later audit supersedes old success; no automatic command repeats.
  self.consume(self.request(enabled=False));self.assertFalse(self.owner.boot_policy_status()['applied'])
 def test_wrong_link_unknown_registration_and_foreign_unit_refuse_before_grant(self):
  directory=self.units/'multi-user.target.wants';directory.mkdir()
  link=directory/life.UNITS[0];link.symlink_to('/foreign/unit')
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  link.unlink();other=self.units/'other.target.wants';other.mkdir();wrong=other/life.UNITS[0];wrong.symlink_to(self.root/'systemd'/life.UNITS[0])
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  wrong.unlink();(self.root/'systemd'/life.UNITS[0]).write_text('tamper')
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  self.assertFalse(self.authorized);self.assertFalse(self.mutations())
 def test_uncommissioned_guest_inactive_roster_pending_or_unbound_refuse(self):
  (self.root/'data').rmdir()
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  (self.root/'data').mkdir()
  with patch.object(life,'verify_identity',return_value={'address':'guest05'}),self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  path=self.write(life.UPGRADE_INTENT,{})
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  path.unlink()
  self.owner.require_bound_validator_vpn.side_effect=ValueError('unbound')
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request('vpn'))
  self.assertFalse(self.authorized);self.assertFalse(self.mutations())
 def test_disable_does_not_require_connectivity_or_start_services(self):
  self.owner.boot_policy(self.request());self.owner.require_bound_validator_vpn.side_effect=ValueError('offline')
  self.owner.boot_policy(self.request(enabled=False));self.assertFalse(self.owner.boot_policy_status()['node_enabled'])
  self.assertTrue(all(a[1] in ('show','daemon-reload') for a in self.calls))
 def test_observed_mismatch_command_failure_live_grant_and_audit_tamper(self):
  original=self.native
  with patch.object(life.subprocess,'run',return_value=Mock(returncode=1,stdout=b'linked\n')),self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  (self.units/'multi-user.target.wants'/life.UNITS[0]).unlink()
  self.assertFalse(self.owner.boot_policy_status()['applied'])
  with patch.object(life,'native',side_effect=OSError('failed')),self.assertRaises(OSError):self.owner.boot_policy(self.request())
  self.owner.boot_policy(self.request())
  grant=self.write('tmp/controller/grants/'+c.request_digest(self.request())+'.json',{})
  self.assertFalse(self.owner.boot_policy_status()['applied']);grant.unlink()
  self.write('tmp/controller/audit.jsonl',{'operation':'boot_policy','request_sha256':'f'*64,'time':1})
  with self.assertRaises(ValueError):self.owner.boot_policy_status()
 def test_guest_enable_and_unsafe_wants_directory_or_os_state_refuse(self):
  self.owner.policy=lambda:{'engineering_target':{'guest':{'guest_id':'validator-05'}}}
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  self.owner.policy=lambda:{}
  foreign=self.units/'foreign';foreign.mkdir()
  directory=self.units/'multi-user.target.wants';directory.symlink_to(foreign)
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  directory.unlink();directory.mkdir(mode=0o777);directory.chmod(0o777)
  with self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  directory.chmod(0o755)
  for code,raw in ((0,b'enabled-runtime\n'),(1,b'PRIVATE ERROR'),(5,b'disabled\n')):
   with patch.object(life.subprocess,'run',return_value=Mock(returncode=code,stdout=raw)),self.assertRaises(ValueError):self.owner.boot_policy(self.request())
  self.assertFalse(self.authorized);self.assertFalse(self.calls)
 def test_linked_exit_and_boot_link_must_agree(self):
  with patch.object(life.subprocess,'run',return_value=Mock(returncode=0,stdout=b'linked\n')),self.assertRaises(ValueError):life.service_boot_state(self.root)
  self.owner.boot_policy(self.request())
  with patch.object(life.subprocess,'run',return_value=Mock(returncode=1,stdout=b'linked\n')),self.assertRaises(ValueError):life.service_boot_state(self.root)
 def test_real_one_use_grant_consumption_replay_and_status(self):
  import time
  request=self.request();key=c.request_digest(request)
  self.owner.policy=lambda:{'qualified_operations':['boot_policy']}
  self.owner.authorize=lambda request:c.Controller.authorize(self.owner,request)
  grant=self.write('tmp/controller/grants/'+key+'.json',{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+300})
  self.owner.boot_policy(request);self.assertFalse(grant.exists())
  self.assertEqual(self.owner.boot_policy_status()['request_sha256'],key)
  count=len(self.calls)
  with self.assertRaises(c.Refused):self.owner.boot_policy(request)
  self.assertEqual(len(self.calls),count)
 def test_parser_exact_service_boolean_and_parameterless_status(self):
  for service in ('node','vpn'):
   for enabled in (True,False):self.assertEqual(c.parse_request(c.canonical(self.request(service,enabled))),self.request(service,enabled))
  for params in ({'service':'guest','enabled':True},{'service':'node','enabled':1},{'service':'node','enabled':True,'start':True}):
   with self.assertRaises(c.Refused):c.parse_request(c.canonical({'version':1,'operation':'boot_policy','parameters':params}))
  with self.assertRaises(c.Refused):c.parse_request(c.canonical({'version':1,'operation':'boot_policy_status','parameters':{'service':'node'}}))

if __name__=='__main__':unittest.main()
