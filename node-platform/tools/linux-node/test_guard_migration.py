"""Actual temporary files + simulated systemd; no host service mutation."""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import root_guard as g
VERIFY_RUNTIME=g.verify_runtime

class MigrationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)/'synergy';self.root.mkdir(mode=0o700)
  self.system=Path(self.temp.name)/'systemd';self.system.mkdir()
  (self.system/'multi-user.target.wants').mkdir()
  self.account={'uid':1234,'gid':65534,'label':'Synergy NodeNetwork '+'a'*32}
  self.patch(patch.object(g,'verify_runtime'));self.patch(patch.object(g,'SYSTEM',self.system));self.patch(patch.object(g,'validate_inputs'))
  self.patch(patch.object(g,'root_identity',return_value='a'*32))
  original=g.info
  def info(path):
   v=original(path)
   return None if v is None else SimpleNamespace(st_mode=v.st_mode,st_uid=0,st_nlink=v.st_nlink,st_size=v.st_size)
  self.patch(patch.object(g,'info',side_effect=info))
  self.old_source=b'old registered package source';self.new_source=b'new authenticated package source'
  old=g.render(self.root,self.account,self.old_source)
  self.old_pin=hashlib.sha256(old).hexdigest();self.new_pin=hashlib.sha256(g.render(self.root,self.account,self.new_source)).hexdigest()
  self.unit,self.link=g.paths();self.unit.write_bytes(old);self.unit.chmod(0o600);self.link.symlink_to(self.unit)
  self.active={g.UNIT:True,g.HANDOVER:False};self.loaded={g.UNIT:True,g.HANDOVER:False}
  self.events=[];self.fail=None;self.policy=self.old_pin
  self.patch(patch.object(g,'state',side_effect=self.state));self.patch(patch.object(g,'systemctl',side_effect=self.systemctl))
  self.plan=g.migration_plan(self.root,self.account,self.new_source,hashlib.sha256(self.old_source).hexdigest(),self.old_pin)
 def patch(self,p):p.start();self.addCleanup(p.stop)
 def state(self,name):
  return {'LoadState':'loaded' if self.loaded[name] else 'not-found','FragmentPath':str(self.system/name) if self.loaded[name] else '',
          'DropInPaths':'','ActiveState':'active' if self.active[name] else 'inactive','MainPID':'42' if self.active[name] else '0','ControlPID':'0','KillMode':'control-group'}
 def boundary(self,event):
  if self.fail==event:self.fail=None;raise ValueError('interrupted '+str(event))
 def systemctl(self,*args):
  self.events.append(args)
  if args[0]=='daemon-reload':
   for name in self.loaded:self.loaded[name]=(self.system/name).exists() or self.active[name]
  elif args[0] in ('start','stop'):
   self.active[args[1]]=args[0]=='start'
  self.boundary(args)
 def set_pin(self,pin):self.policy=pin;self.boundary(('policy',))
 def migrate(self):return g.migrate(self.root,self.account,self.plan,self.set_pin)
 def test_active_handover_precedes_stop_then_new_guard_precedes_handover_cleanup(self):
  self.assertEqual(self.migrate(),self.new_pin)
  self.assertLess(self.events.index(('start',g.HANDOVER)),self.events.index(('stop',g.UNIT)))
  self.assertLess(self.events.index(('start',g.UNIT)),self.events.index(('stop',g.HANDOVER)))
  self.assertEqual(self.policy,self.new_pin);self.assertTrue(self.active[g.UNIT]);self.assertFalse((self.system/g.HANDOVER).exists())
  before=list(self.events);self.migrate();self.assertEqual(self.events,before)
 def test_resume_each_service_and_policy_boundary_without_second_successful_restart(self):
  for fail in (('start',g.HANDOVER),('stop',g.UNIT),('start',g.UNIT),('policy',),('stop',g.HANDOVER)):
   with self.subTest(boundary=fail):
    # Reset only this disposable test's systemd/files, no real guest or identity.
    self.unit.write_bytes(base64.b64decode(self.plan['old_unit']));self.policy=self.old_pin
    self.active={g.UNIT:True,g.HANDOVER:False};self.loaded={g.UNIT:True,g.HANDOVER:False};self.events=[]
    self.fail=fail
    with self.assertRaisesRegex(ValueError,'interrupted'):self.migrate()
    g.migration_plan(self.root,self.account,self.new_source,hashlib.sha256(self.old_source).hexdigest(),self.old_pin,self.plan)
    before=self.events.count(('start',g.UNIT));already=self.active[g.UNIT] and g.unit_digest(self.unit)==self.new_pin
    self.migrate();self.assertEqual(self.policy,self.new_pin);self.assertTrue(self.active[g.UNIT]);self.assertFalse((self.system/g.HANDOVER).exists())
    if already:self.assertEqual(before,self.events.count(('start',g.UNIT)))
 def test_interrupted_atomic_new_unit_then_resume(self):
  original=g.replace_unit
  def replace(path,data,allowed):
   original(path,data,allowed)
   if path==self.unit:raise ValueError('interrupted replacement')
  with patch.object(g,'replace_unit',side_effect=replace):
   with self.assertRaisesRegex(ValueError,'interrupted'):self.migrate()
  self.assertTrue(self.active[g.HANDOVER]);self.assertFalse(self.active[g.UNIT])
  self.migrate();self.assertEqual(self.policy,self.new_pin)
 def test_foreign_handover_or_candidate_or_prior_source_never_stops_guard(self):
  for source,pin,record in ((b'tampered',hashlib.sha256(self.old_source).hexdigest(),self.plan),(self.new_source,'c'*64,None)):
   with self.assertRaises(ValueError):g.migration_plan(self.root,self.account,source,pin,self.old_pin,record)
  p=self.system/g.HANDOVER;p.write_bytes(b'foreign service');p.chmod(0o600)
  with self.assertRaisesRegex(ValueError,'foreign'):self.migrate()
  self.assertFalse(any(e==('stop',g.UNIT) for e in self.events));self.assertTrue(self.active[g.UNIT])
 def test_no_ready_handover_cannot_stop_prior_guard(self):
  original=self.systemctl
  def no_ready(*args):
   if args==('start',g.HANDOVER):raise ValueError('handover readiness failed')
   return original(*args)
  with patch.object(g,'systemctl',side_effect=no_ready):
   with self.assertRaisesRegex(ValueError,'readiness'):self.migrate()
  self.assertTrue(self.active[g.UNIT]);self.assertNotIn(('stop',g.UNIT),self.events)
 def test_loaded_pid_command_must_match_exact_embedded_source(self):
  import shlex
  proc=Path(self.temp.name)/'proc';process=proc/'42';process.mkdir(parents=True)
  (process/'exe').symlink_to('/usr/bin/python3')
  unit=self.unit.read_bytes()
  args=next(line[10:] for line in unit.decode().splitlines() if line.startswith('ExecStart='))
  (process/'cmdline').write_bytes(b'\x00'.join(v.encode() for v in shlex.split(args))+b'\x00')
  with patch.object(g,'PROC',proc):
   VERIFY_RUNTIME(g.UNIT,unit)
   (process/'cmdline').write_bytes(b'/usr/bin/python3\x00unrelated.py\x00')
   with self.assertRaisesRegex(ValueError,'loaded guard source differs'):VERIFY_RUNTIME(g.UNIT,unit)
 def test_actual_new_guard_source_requires_ready_and_preserves_legacy_exec(self):
  source=Path(g.__file__).read_bytes()
  self.assertIn(b'Type=notify',g.render(self.root,self.account,source))
  self.assertIn(b'Type=exec',g.render(self.root,self.account,self.old_source))
  unit=g.render_handover(self.root,self.account,source,self.old_pin,self.new_pin)
  self.assertIn(b'Type=notify',unit);self.assertIn(b'NotifyAccess=main',unit)
  self.assertLess(len(unit),32768)

 def test_deleted_root_new_watcher_uses_authenticated_handover(self):
  handover=base64.b64decode(self.plan['handover_unit']);p=self.system/g.HANDOVER;p.write_bytes(handover);p.chmod(0o600)
  self.loaded[g.HANDOVER]=True;self.active[g.HANDOVER]=True
  with patch.object(g,'root_identity',return_value=None):
   self.assertTrue(g.handover_record(self.root,1234,'a'*32,self.new_pin))
  p.write_bytes(handover.replace(b'1234',b'1235'))
  with self.assertRaises(ValueError):g.handover_record(self.root,1234,'a'*32,self.new_pin)

if __name__=='__main__':unittest.main()
