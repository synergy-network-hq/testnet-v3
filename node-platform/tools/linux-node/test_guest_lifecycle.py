"""Offline ownership/transaction boundaries, not KVM runtime qualification."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import controller
import guest_lifecycle as g
import root_guard
VERIFY_GUARD=g.GuestManager.verify_guard
KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0 '+b'a'*32).decode()

class GuestTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve()/'synergy'
  for n in ('','tmp','hosted-machines','hosted-machines/images','lib','lib/guest-tools','lib/guest-tools/bin'):(self.root/n).mkdir(mode=0o700,exist_ok=True)
  self.system=Path(self.temp.name)/'systemd';self.system.mkdir()
  self.spec={'version':1,'guest_id':'temporary-validator','cpu_count':2,'memory_mib':2048,'disk_gib':8,'ssh_forward_port':22280,'operator_ssh_public_key':KEY,'tools':{}}
  self.file('hosted-machines/images/os.qcow2',b'image');self.spec['image_sha256']=g.digest(self.root/'hosted-machines/images/os.qcow2')
  for tool in g.TOOLS:
   self.file('lib/guest-tools/bin/'+tool,tool.encode(),0o700);self.spec['tools'][tool]=g.digest(self.root/'lib/guest-tools/bin'/tool)
  self.file('lib/guest-tools/bios.bin',b'bios');self.spec['bios_sha256']=g.digest(self.root/'lib/guest-tools/bios.bin')
  self.start_patch(patch.object(g,'SYSTEM',self.system));self.manager=g.GuestManager(self.root,{'managed_guest':self.spec})
  self.params={k:self.spec[k] for k in g.CREATE};self.calls=[];self.authorized=0;self.active=False;self.loaded=False
  self.start_patch(patch.object(self.manager,'command',side_effect=self.command));self.start_patch(patch('lifecycle._unit_state',side_effect=self.state));self.start_patch(patch.object(g,'host_capacity'));self.start_patch(patch.object(g.GuestManager,'verify_process'));self.start_patch(patch.object(g.GuestManager,'verify_guard'));self.start_patch(patch('lifecycle._reject_installation_mounts'))
 def start_patch(self,p):p.start();self.addCleanup(p.stop)
 def file(self,n,data,mode=0o600):
  p=self.root/n;p.write_bytes(data);p.chmod(mode);return p
 def authorize(self):self.authorized+=1
 def state(self,name):return {'LoadState':'loaded' if self.loaded else 'not-found','FragmentPath':str(self.manager.registration) if self.loaded else '', 'DropInPaths':'','ActiveState':'active' if self.active else 'inactive','MainPID':'123' if self.active else '0'}
 def command(self,argv,timeout=120):
  a=list(map(str,argv));self.calls.append(a)
  if 'info' in a:return b'{"format":"qcow2","virtual-size":1024}'
  if Path(a[0]).name=='ssh-keygen':
   self.file('hosted-machines/temporary-validator/ssh-host',b'fixture private SSH');self.file('hosted-machines/temporary-validator/ssh-host.pub',KEY.encode())
  if Path(a[0]).name=='qemu-img' and 'create' in a:self.file('hosted-machines/temporary-validator/disk.qcow2',b'disk')
  if Path(a[0]).name=='genisoimage':self.file('hosted-machines/temporary-validator/seed.iso',b'seed')
  if a[:2]==['/usr/bin/systemctl','daemon-reload']:self.loaded=self.manager.registration.is_symlink()
  if a[:2]==['/usr/bin/systemctl','start']:self.active=True
  if a[:2]==['/usr/bin/systemctl','stop']:self.active=False
  return b''
 def create(self):return self.manager.create(self.params,'a'*64,self.authorize)
 def test_create_stop_remove_repeated_without_regeneration(self):
  r=self.create();self.assertTrue(r['ssh_identity_verified']);self.assertFalse(r['validator_installed']);self.assertFalse(r['guest_os_reachability_verified']);self.assertNotIn('private',json.dumps(r))
  count=len(self.calls);self.create();self.assertEqual(count,len(self.calls));self.assertEqual(1,self.authorized)
  with self.assertRaises(ValueError):self.manager.create(self.params,'b'*64,self.authorize)
  with patch('lifecycle._reject_installation_mounts'):
   with self.assertRaisesRegex(ValueError,'stop'):self.manager.remove(self.params,'b'*64,self.authorize)
   self.manager.stop(self.params,self.authorize);self.assertTrue(self.manager.remove(self.params,'b'*64,self.authorize)['removed'])
   count=len(self.calls);self.assertTrue(self.manager.remove(self.params,'b'*64,self.authorize)['removed']);self.assertEqual(count,len(self.calls))
  with self.assertRaisesRegex(ValueError,'Removed'):self.create()
 def test_wire_and_independent_policy_refuse_arbitrary_choices(self):
  for extra in ({'image_url':'https://evil'},{'ssh_forward_port':1234},{'command':'sh'}):
   with self.assertRaises(controller.Refused):controller.parse_request(controller.canonical({'version':1,'operation':'guest_create','parameters':{**self.params,**extra}}))
  for k,v in (('guest_id','../escape'),('cpu_count',True),('disk_gib',513),('memory_mib',1)):
   with self.assertRaises(ValueError):g.validate_parameters('guest_create',{**self.params,k:v})
  with self.assertRaises(ValueError):g.GuestManager(self.root,{})
  with self.assertRaisesRegex(ValueError,'resources'):self.manager.create({**self.params,'cpu_count':3},'a'*64,self.authorize)
  self.assertEqual(0,self.authorized)
 def test_artifact_drift_external_backing_and_service_override_rejected(self):
  image=self.root/'hosted-machines/images/os.qcow2';image.write_bytes(b'drift')
  with self.assertRaisesRegex(ValueError,'image changed'):self.create()
  image.unlink();image.symlink_to('/etc/passwd')
  with self.assertRaises(ValueError):self.create()
  image.unlink();self.file('hosted-machines/images/os.qcow2',b'image')
  with patch.object(self.manager,'command',return_value=b'{"format":"qcow2","virtual-size":1024,"backing-filename":"/outside"}'):
   with self.assertRaisesRegex(ValueError,'external'):self.create()
  self.create();self.manager.registration.with_name(self.manager.unit_name+'.d').mkdir()
  with self.assertRaisesRegex(ValueError,'override'):self.manager.status(self.params)
 def test_interruption_does_not_regenerate_or_start(self):
  def fail(argv,timeout=120):
   if Path(argv[0]).name=='genisoimage':raise ValueError('seed interrupted')
   return self.command(argv,timeout)
  with patch.object(self.manager,'command',side_effect=fail):
   with self.assertRaisesRegex(ValueError,'interrupted'):self.create()
  count=len(self.calls);r=self.create();self.assertEqual(r['phase'],'creating');self.assertFalse(r['ssh_identity_verified']);self.assertEqual(count,len(self.calls))
  self.assertFalse(any(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls))
  with patch('lifecycle._reject_installation_mounts'):self.assertTrue(self.manager.remove(self.params,'c'*64,self.authorize)['removed'])
 def test_unknown_member_mount_and_foreign_unit_preserved(self):
  self.create();self.manager.stop(self.params,self.authorize);self.file('hosted-machines/temporary-validator/unattributed',b'keep')
  with self.assertRaisesRegex(ValueError,'Unexpected'):self.manager.remove(self.params,'c'*64,self.authorize)
  (self.manager.directory/'unattributed').unlink()
  with patch('lifecycle._reject_installation_mounts',side_effect=ValueError('mount')):
   with self.assertRaisesRegex(ValueError,'mount'):self.manager.remove(self.params,'c'*64,self.authorize)
  self.manager.registration.unlink();self.manager.registration.symlink_to('/foreign')
  with self.assertRaisesRegex(ValueError,'foreign'):self.manager.stop(self.params,self.authorize)
 def test_guest_requires_exact_current_loaded_deletion_guard(self):
  import hashlib
  self.manager.policy['host_account']={}
  unit=b'current independently pinned guardian'
  with patch.object(root_guard,'render',return_value=unit),patch.object(root_guard,'check_registration') as check,patch.object(root_guard,'verify_runtime') as loaded:
   with self.assertRaisesRegex(ValueError,'current attributed deletion guard'):VERIFY_GUARD(self.manager)
   check.assert_not_called();loaded.assert_not_called()
   self.manager.policy['root_guard_sha256']=hashlib.sha256(unit).hexdigest()
   VERIFY_GUARD(self.manager);loaded.assert_called_once_with(root_guard.UNIT,unit)
   loaded.side_effect=ValueError('loaded source differs')
   with self.assertRaisesRegex(ValueError,'loaded source differs'):VERIFY_GUARD(self.manager)

 def test_dispatch_uses_sealed_root_and_lifecycle_lock_before_guest_mutation(self):
  import lifecycle
  import synergy_linux
  from contextlib import contextmanager
  events=[]
  @contextmanager
  def locked(root):
   events.append('locked');yield;events.append('unlocked')
  c=controller.Controller(self.root)
  req={'version':1,'operation':'guest_create','parameters':self.params}
  def create(params,sha,authorize):
   self.assertEqual(events,['locked','sealed'])
   self.assertEqual(sha,controller.request_digest(req));authorize();return {'created':True}
  with patch.object(controller.platform,'system',return_value='Linux'),patch.object(controller.platform,'machine',return_value='x86_64'),patch.object(synergy_linux,'safe_root'),patch.object(lifecycle,'_lifecycle_lock',side_effect=locked),patch.object(lifecycle,'_sealed_receipt',side_effect=lambda root:events.append('sealed')),patch.object(c,'policy',return_value={'managed_guest':self.spec}),patch.object(c,'authorize') as auth,patch.object(g.GuestManager,'create',side_effect=create):
   self.assertEqual(c.dispatch(req),{'created':True});auth.assert_called_once_with(req)
  self.assertEqual(events,['locked','sealed','unlocked'])

 def test_exact_conformance_removal_guard_and_dynamic_unit_attribution(self):
  self.create()
  with patch.object(g.GuestManager,'command',side_effect=self.command):members=g.approved_inventory(self.root,{'managed_guest':self.spec})
  self.assertIn('hosted-machines/temporary-validator/ssh-host',members)
  with self.assertRaisesRegex(ValueError,'reconciled'):g.require_removed(self.root)
  with patch.object(root_guard,'SYSTEM',self.system), patch.object(root_guard,'info',side_effect=lambda p:SimpleNamespace(st_mode=p.lstat().st_mode,st_uid=0)):
   self.assertEqual({self.manager.unit_name:self.manager.target},root_guard.guest_registrations(self.root))
  self.assertIn('user,id=n0,ipv6=off,hostfwd=tcp:127.0.0.1:22280-:22',self.manager.argv());self.assertNotIn('[Install]',self.manager.unit().decode())
  self.file('hosted-machines/untracked',b'keep')
  with patch.object(g.GuestManager,'command',side_effect=self.command):
   with self.assertRaisesRegex(ValueError,'Unattributed'):g.approved_inventory(self.root,{'managed_guest':self.spec})

if __name__=='__main__':unittest.main()
