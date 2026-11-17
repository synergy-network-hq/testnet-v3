"""Pinned candidate-plan staging; never modifies a service or host."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import bootstrap as b
import root_guard as g

class StagingTests(unittest.TestCase):
 def fixture(self,source):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
  root=Path(tmp.name);(root/'tools').mkdir();(root/'tools/root_guard.py').write_bytes(source)
  return root,{'files':{'tools/root_guard.py':hashlib.sha256(source).hexdigest()}}
 def test_same_guard_never_executes_candidate_or_mutates_service(self):
  root,manifest=self.fixture(b'not executable Python')
  pin=hashlib.sha256(b'same rendered unit').hexdigest()
  with patch.object(g,'check_registration') as check,patch.object(g,'render',return_value=b'same rendered unit'),patch.object(g,'systemctl') as service:
   b.validate_guard_update(root,{'root_guard_sha256':pin,'host_account':{}},{'package_files':{'tools/root_guard.py':manifest['files']['tools/root_guard.py']}},manifest,root)
   check.assert_called_once_with(pin);service.assert_not_called()
 def test_new_guard_executes_exact_pinned_plan_and_checks_installed_source_binding(self):
  source=b"def migration_plan(root, account, source, previous, pin):\n assert previous=='c'*64 and pin=='a'*64 and account=={'uid':42}\n"
  root,manifest=self.fixture(source)
  with patch.object(g,'check_registration'),patch.object(g,'render',side_effect=ValueError('legacy renderer rejects new profile')),patch.object(g,'systemctl') as service:
   b.validate_guard_update(root,{'root_guard_sha256':'a'*64,'host_account':{'uid':42}},{'package_files':{'tools/root_guard.py':'c'*64}},manifest,root)
   service.assert_not_called()
   with self.assertRaisesRegex(ValueError,'provenance'):
    b.validate_guard_update(root,{'root_guard_sha256':'a'*64,'host_account':{}},{},manifest,root)
 def test_drift_and_missing_migration_refuse_before_candidate_execution(self):
  root,manifest=self.fixture(b"raise AssertionError('must not execute drift')")
  manifest['files']['tools/root_guard.py']='a'*64
  with patch.object(g,'check_registration'),patch.object(g,'render',return_value=b'different'):
   with self.assertRaisesRegex(ValueError,'changed after verification'):
    b.validate_guard_update(root,{'root_guard_sha256':'b'*64,'host_account':{}},{},manifest,root)
  root,manifest=self.fixture(b'no_migration=True')
  with patch.object(g,'check_registration'),patch.object(g,'render',return_value=b'different'):
   with self.assertRaisesRegex(ValueError,'lacks authenticated'):
    b.validate_guard_update(root,{'root_guard_sha256':'b'*64,'host_account':{}},{'package_files':{'tools/root_guard.py':'c'*64}},manifest,root)

if __name__=='__main__':unittest.main()
