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
  for n in ('','tmp','hosted-machines','hosted-machines/images','lib','lib/guest-tools','lib/guest-tools/bin','lib/guest-tools/lib'):(self.root/n).mkdir(mode=0o700,exist_ok=True)
  self.system=Path(self.temp.name)/'systemd';self.system.mkdir()
  self.spec={'version':1,'guest_id':'temporary-validator','cpu_count':2,'memory_mib':2048,'disk_gib':8,'ssh_forward_port':22280,'operator_ssh_public_key':KEY,'tools':{}}
  self.file('hosted-machines/images/os.qcow2',b'image');self.spec['image_sha256']=g.digest(self.root/'hosted-machines/images/os.qcow2')
  for tool in g.TOOLS:
   self.file('lib/guest-tools/bin/'+tool,tool.encode(),0o700);self.spec['tools'][tool]=g.digest(self.root/'lib/guest-tools/bin'/tool)
  self.file('lib/guest-tools/bin/'+g.LOADER,b'loader',0o700)
  self.file('lib/guest-tools/lib/libc.so.6',b'libc')
  self.spec['runtime_files']={name:g.digest(self.root/name) for name in ('lib/guest-tools/bin/'+g.LOADER,'lib/guest-tools/lib/libc.so.6')}
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
 def test_software_upgrade_preserves_only_stopped_exact_guest_resources(self):
  self.create()
  pins={'hosted-machines/images/os.qcow2':self.spec['image_sha256'],
        'lib/guest-tools/bios.bin':self.spec['bios_sha256'],
        **{'lib/guest-tools/bin/'+n:v for n,v in self.spec['tools'].items()},**self.spec['runtime_files']}
  manifest={'files':pins,'managed_guest_resources':{'version':1,'manifest_sha256':'f'*64,'archive_limit_bytes':512*1024**2,'files':pins}}
  before={p.name:p.read_bytes() for p in self.manager.directory.iterdir() if p.is_file()}
  with patch.object(controller.Controller,'policy',return_value={'managed_guest':self.spec}),patch.object(g,'operator_public_key',return_value=g.public_ssh(KEY.encode())[0]),patch.object(g.GuestManager,'command',side_effect=self.command):
   with self.assertRaisesRegex(ValueError,'Stop managed guest'):g.require_upgrade_compatible(self.root,manifest)
   self.manager.stop(self.params,self.authorize)
   g.require_upgrade_compatible(self.root,manifest)
   changed=json.loads(json.dumps(manifest));changed['files']['lib/guest-tools/bios.bin']='e'*64;changed['managed_guest_resources']['files']['lib/guest-tools/bios.bin']='e'*64
   with self.assertRaisesRegex(ValueError,'differs'):g.require_upgrade_compatible(self.root,changed)
   (self.manager.directory/'foreign').write_text('unknown')
   with self.assertRaises(ValueError):g.require_upgrade_compatible(self.root,manifest)
   (self.manager.directory/'foreign').unlink()
  self.assertEqual(before,{p.name:p.read_bytes() for p in self.manager.directory.iterdir() if p.is_file()})
 def test_conformance_excludes_only_exact_attributed_guest_unit(self):
  import conformance
  self.legacy();self.manager.stop(self.params,self.authorize)
  names={self.manager.unit_name}
  # This is the actual failing external-service boundary: before ownership
  # attribution, even the legitimate stopped legacy unit is rejected.
  with self.assertRaisesRegex(ValueError,'obsolete or undeclared'):
   conformance.verify_external_services(self.root,names)
  with patch.object(controller.Controller,'policy',return_value={'managed_guest':self.spec}),patch.object(g.GuestManager,'command',side_effect=self.command):
   self.assertEqual(conformance.without_owned_guest_registration(self.root,names),set())
   conformance.verify_external_services(self.root,conformance.without_owned_guest_registration(self.root,names))
   foreign=names|{'synergy-guest-foreign.service'}
   with self.assertRaisesRegex(ValueError,'obsolete or undeclared'):
    conformance.verify_external_services(self.root,conformance.without_owned_guest_registration(self.root,foreign))
   for damage in ('unit','registration','unknown'):
    original=self.manager.target.read_bytes()
    if damage=='unit':self.manager.target.write_bytes(b'tampered')
    elif damage=='registration':self.manager.registration.unlink();self.manager.registration.symlink_to(self.root/'foreign.service')
    else:(self.manager.directory/'unknown').write_text('foreign')
    with self.subTest(damage=damage),self.assertRaises((ValueError,OSError)):
     conformance.without_owned_guest_registration(self.root,names)
    if damage=='unit':self.manager.target.write_bytes(original)
    elif damage=='registration':self.manager.registration.unlink();self.manager.registration.symlink_to(self.manager.target)
    else:(self.manager.directory/'unknown').unlink()
 def test_create_stop_remove_repeated_without_regeneration(self):
  r=self.create();self.assertTrue(r['ssh_identity_verified']);self.assertFalse(r['validator_installed']);self.assertFalse(r['guest_os_reachability_verified']);self.assertNotIn('private',json.dumps(r))
  count=len(self.calls);self.create();self.assertEqual(count,len(self.calls));self.assertEqual(1,self.authorized)
  with self.assertRaises(ValueError):self.manager.create(self.params,'b'*64,self.authorize)
  with patch('lifecycle._reject_installation_mounts'):
   with self.assertRaisesRegex(ValueError,'stop'):self.manager.remove(self.params,'b'*64,self.authorize)
   self.manager.stop(self.params,self.authorize);self.assertTrue(self.manager.remove(self.params,'b'*64,self.authorize)['removed'])
   count=len(self.calls);self.assertTrue(self.manager.remove(self.params,'b'*64,self.authorize)['removed']);self.assertEqual(count,len(self.calls))
  with self.assertRaisesRegex(ValueError,'Removed'):self.create()
 def test_preprovisioned_ssh_identity_is_bound_to_cloudinit_and_durable_receipt(self):
  result=self.create()
  # This is a boundary fixture, not a real keygen/VM qualification: the pinned
  # command adapter above writes a fixed test-only management key pair.
  cloud=json.loads((self.manager.directory/'user-data').read_text().split('\n',1)[1])
  self.assertEqual(cloud['ssh_keys']['ed25519_public'],result['ssh_host_public_key'])
  self.assertEqual(cloud['users'][0]['ssh_authorized_keys'],[self.spec['operator_ssh_public_key']])
  self.assertTrue(cloud['ssh_deletekeys']);self.assertTrue(cloud['disable_root'])
  self.assertFalse(cloud['ssh_pwauth'])
  receipt=json.loads((self.manager.base/'record.json').read_bytes())
  self.assertEqual(receipt['ssh_host_public_key'],result['ssh_host_public_key'])
  self.assertEqual(receipt['ssh_host_fingerprint'],result['ssh_host_fingerprint'])
  # The status API is public-only and does not establish guest boot readiness.
  self.assertFalse(result['guest_os_reachability_verified'])
  self.assertNotIn('fixture private SSH',json.dumps(result))
  altered='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0 '+b'b'*32).decode()
  public=self.manager.directory/'ssh-host.pub';public.write_text(altered)
  with self.assertRaisesRegex(ValueError,'identity changed'):self.manager.status(self.params)
  public.write_text(KEY)
  receipt['ssh_host_fingerprint']='SHA256:unapproved'
  (self.manager.base/'record.json').write_text(json.dumps(receipt))
  with self.assertRaisesRegex(ValueError,'identity changed'):self.manager.status(self.params)
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

 def legacy(self):
  self.create();receipt=self.manager.receipt();receipt.pop('runtime_version');g.atomic(self.manager.base/'record.json',receipt)
  self.manager.target.write_bytes(self.manager.unit(1));self.manager.target.chmod(0o600)
 def resume(self,sequence=1,key='b'*64):return self.manager.resume({'guest_id':self.spec['guest_id'],'resume_sequence':sequence,'create_request_sha256':'a'*64},key,'c'*64,self.authorize)
 def test_legacy_attribution_stop_resume_preserves_all_creation_material(self):
  self.legacy();self.assertEqual(self.manager.status(self.params)['runtime_version'],1)
  saved={name:(self.manager.directory/name).read_bytes() for name in ('disk.qcow2','seed.iso','ssh-host','ssh-host.pub','user-data','meta-data')}
  self.manager.stop(self.params,self.authorize);result=self.resume()
  self.assertTrue(result['resume_verified']);self.assertEqual(result['runtime_version'],2)
  self.assertEqual(result['request_sha256'],'a'*64);self.assertEqual(result['resume_request_sha256'],'b'*64)
  self.assertEqual(self.manager.target.read_bytes(),self.manager.unit(2))
  self.assertIn('stdio',self.manager.argv(2));self.assertNotIn('stdio',self.manager.argv(1))
  self.assertEqual(saved,{name:(self.manager.directory/name).read_bytes() for name in saved})
  count=sum(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls);self.resume();self.assertEqual(sum(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls),count)
  with self.assertRaisesRegex(ValueError,'stop'):self.resume(2,'d'*64)
  self.manager.stop(self.params,self.authorize);self.resume(2,'d'*64)
 def test_resume_interrupted_migration_reconciles_without_keygen_or_blind_start(self):
  self.legacy();self.manager.stop(self.params,self.authorize)
  original=self.command
  def fail(a,timeout=120):
   if list(map(str,a))[:2]==['/usr/bin/systemctl','daemon-reload']:raise ValueError('reload interrupted')
   return original(a,timeout)
  with patch.object(self.manager,'command',side_effect=fail):
   with self.assertRaisesRegex(ValueError,'interrupted'):self.resume()
  self.assertEqual(self.manager.receipt()['resume']['phase'],'prepared')
  self.assertFalse(self.active);self.assertTrue(self.resume()['resume_verified'])
  self.manager.stop(self.params,self.authorize)
  def lost(a,timeout=120):
   value=original(a,timeout)
   if list(map(str,a))[:2]==['/usr/bin/systemctl','start']:raise ValueError('lost reply')
   return value
  with patch.object(self.manager,'command',side_effect=lost):
   with self.assertRaisesRegex(ValueError,'lost reply'):self.resume(2,'d'*64)
  count=sum(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls);self.assertTrue(self.resume(2,'d'*64)['resume_verified']);self.assertEqual(sum(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls),count)
 def test_resume_uncertain_before_start_never_replays_and_foreign_state_refuses(self):
  self.legacy();self.manager.stop(self.params,self.authorize)
  original=self.command
  def before(a,timeout=120):
   if list(map(str,a))[:2]==['/usr/bin/systemctl','start']:raise ValueError('dispatch lost')
   return original(a,timeout)
  with patch.object(self.manager,'command',side_effect=before):
   with self.assertRaisesRegex(ValueError,'dispatch lost'):self.resume()
  count=sum(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls);self.assertFalse(self.resume()['resume_verified']);self.assertEqual(sum(a[:2]==['/usr/bin/systemctl','start'] for a in self.calls),count)
  with self.assertRaisesRegex(ValueError,'stop'):self.resume(2,'d'*64)
  self.manager.target.write_bytes(b'foreign unit')
  with self.assertRaisesRegex(ValueError,'service bytes'):self.manager.stop(self.params,self.authorize)
 def test_boot_diagnostic_categories_only_and_unknown_members_refused(self):
  self.create();log=self.manager.directory/'qemu.log';log.write_bytes(b'secret-private-value'+b'x'*70000+b'Linux version 6\ncloud-init\nKernel panic')
  result=self.manager.boot_diagnostics(self.params)
  self.assertEqual(result['sampled_bytes'],65536);self.assertTrue(result['categories']['kernel_started']);self.assertTrue(result['categories']['kernel_panic'])
  self.assertNotIn('secret',json.dumps(result));self.assertFalse(result['mutation_performed'])
  self.file('hosted-machines/temporary-validator/unknown',b'preserve')
  with self.assertRaisesRegex(ValueError,'Unexpected'):self.manager.boot_diagnostics(self.params)

 def test_enrolled_legacy_guest_exclusion_never_hides_other_process_or_drift(self):
  import bootstrap
  from types import SimpleNamespace
  self.legacy()
  proc=Path(self.temp.name)/'proc';proc.mkdir()
  for name in ('123','124'):(proc/name).mkdir()
  seen=[]
  def guard(root,vpn_pid=None,proc=None):seen.extend(p.name for p in proc.iterdir())
  bootstrap.guest_management_quiescence(self.root,{'managed_guest':self.spec},guard,proc=proc)
  self.assertEqual(seen,['124'])
  def foreign(root,vpn_pid=None,proc=None):raise ValueError('foreign application')
  with self.assertRaisesRegex(ValueError,'foreign application'):bootstrap.guest_management_quiescence(self.root,{'managed_guest':self.spec},foreign,proc=proc)
  self.manager.target.write_bytes(b'foreign')
  with self.assertRaisesRegex(ValueError,'service bytes'):bootstrap.guest_management_quiescence(self.root,{'managed_guest':self.spec},guard,proc=proc)
 def test_resume_audit_grant_interruption_exact_original_only(self):
  self.legacy();self.manager.stop(self.params,self.authorize)
  c=controller.Controller(self.root);c.control.mkdir(mode=0o700);(c.control/'grants').mkdir(mode=0o700)
  request={'version':1,'operation':'guest_resume','parameters':{'guest_id':self.spec['guest_id'],'resume_sequence':1,'create_request_sha256':'a'*64}}
  key=controller.request_digest(request);grant=c.control/'grants'/(key+'.json');grant.write_bytes(b'{"original":"public grant"}');grant.chmod(0o600);pin=g.digest(grant)
  def interrupted():raise ValueError('before authorization')
  with self.assertRaisesRegex(ValueError,'before authorization'):self.manager.resume(request['parameters'],key,pin,interrupted)
  audit=c.control/'audit.jsonl';audit.write_text(json.dumps({'operation':'guest_resume','request_sha256':key,'time':1})+'\n');audit.chmod(0o600)
  with patch.object(c,'policy',return_value={'managed_guest':self.spec}),patch.object(c,'authorize',side_effect=AssertionError('must not authorize twice')):
   c.authorize_guest_resume(request,pin);self.assertFalse(grant.exists())
   c.authorize_guest_resume(request,pin) # crash after unlink: same immutable audit reconciles.
   grant.write_bytes(b'changed grant');grant.chmod(0o600)
   with self.assertRaisesRegex(ValueError,'grant changed'):c.authorize_guest_resume(request,pin)
   grant.unlink();audit.write_text(json.dumps({'operation':'guest_stop','request_sha256':key,'time':1})+'\n')
   with self.assertRaisesRegex(ValueError,'audit differs'):c.authorize_guest_resume(request,pin)
 def test_wrong_creation_and_unknown_runtime_never_consume_resume(self):
  self.legacy();self.manager.stop(self.params,self.authorize);count=self.authorized
  with self.assertRaisesRegex(ValueError,'different creation'):self.manager.resume({'guest_id':self.spec['guest_id'],'resume_sequence':1,'create_request_sha256':'f'*64},'b'*64,'c'*64,self.authorize)
  self.assertEqual(self.authorized,count)
  record=self.manager.receipt();record['runtime_version']=3;g.atomic(self.manager.base/'record.json',record)
  with self.assertRaisesRegex(ValueError,'Unknown guest runtime'):self.manager.status(self.params)

 def test_partial_unit_migration_recovers_exact_prefix_and_rejects_foreign_bytes(self):
  self.legacy();self.manager.stop(self.params,self.authorize)
  def interrupted():raise ValueError('authorization interrupted')
  params={'guest_id':self.spec['guest_id'],'resume_sequence':1,'create_request_sha256':'a'*64}
  with self.assertRaises(ValueError):self.manager.resume(params,'b'*64,'c'*64,interrupted)
  temp=self.file('hosted-machines/temporary-validator/.guest.service.tmp',self.manager.unit(2)[:71])
  self.assertTrue(self.resume()['resume_verified']);self.assertFalse(temp.exists())
  self.manager.stop(self.params,self.authorize)
  with self.assertRaises(ValueError):self.manager.resume({**params,'resume_sequence':2},'d'*64,'c'*64,interrupted)
  self.file('hosted-machines/temporary-validator/.guest.service.tmp',b'foreign unit')
  with self.assertRaisesRegex(ValueError,'Unattributed guest unit temporary'):self.manager.status(self.params)

 def test_exact_sealed_legacy_master_can_adopt_controller_then_stop_and_resume(self):
  import os,importlib.util,hashlib,bootstrap,sys
  selected=os.environ.get('SYNERGY_TEST_LEGACY_GUEST_MASTER')
  if not selected:self.skipTest('Exact retained legacy public master not selected')
  source=Path(selected);manifest=json.loads((source/'package.json').read_bytes());member=source/'tools/guest_lifecycle.py'
  self.assertEqual(hashlib.sha256(member.read_bytes()).hexdigest(),manifest['files']['tools/guest_lifecycle.py'])
  spec=importlib.util.spec_from_file_location('qualified_legacy_guest',member);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
  self.legacy();legacy=old.GuestManager(self.root,{'managed_guest':self.spec})
  self.assertEqual(legacy.unit(),self.manager.unit(1))
  proc=Path(self.temp.name)/'proc';proc.mkdir();(proc/'123').mkdir();(proc/'124').mkdir();seen=[]
  with patch.dict(sys.modules,{'guest_lifecycle':old}),patch.object(old,'SYSTEM',self.system),patch.object(old.GuestManager,'verify_guard'),patch.object(old.GuestManager,'verify_process'):
   bootstrap.guest_management_quiescence(self.root,{'managed_guest':self.spec},lambda root,vpn_pid=None,proc=None:seen.extend(p.name for p in proc.iterdir()),proc=proc)
  self.assertEqual(seen,['124']) # Authenticated candidate controller adoption can pass old owned QEMU.
  self.assertEqual(self.manager.status(self.params)['runtime_version'],1) # New controller still attributes old runtime.
  self.manager.stop(self.params,self.authorize)
  import conformance
  with patch.object(controller.Controller,'policy',return_value={'managed_guest':self.spec}),patch.object(g.GuestManager,'command',side_effect=self.command):
   conformance.verify_external_services(self.root,conformance.without_owned_guest_registration(self.root,{self.manager.unit_name}))
  self.assertTrue(self.resume()['resume_verified'])

if __name__=='__main__':unittest.main()
