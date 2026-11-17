"""Bounded bare-bootstrap cancellation; no actual OS service mutations."""
import io
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch,Mock
import bootstrap as b

class BareRollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()/'synergy'
        self.stage=self.root/'tmp/bootstrap-master';self.control=self.root/'tmp/controller'
        (self.control/'tools').mkdir(parents=True,mode=0o700)
        for name in ('host','grants'):(self.control/name).mkdir(mode=0o700)
        files={};source=Path(b.__file__).parent
        for name in b.ENGINE:
            raw=(source/name).read_bytes();files['tools/'+name]=hashlib.sha256(raw).hexdigest()
            b.save(self.stage/'tools'/name,raw)
            b.save(self.control/name if name=='controller.py' else self.control/'tools'/name,raw)
        roles=['validator']+['role-'+str(i) for i in range(19)]
        raw=json.dumps({'roles':roles}).encode();b.save(self.stage/'roles/roles.json',raw)
        files['roles/roles.json']=hashlib.sha256(raw).hexdigest()
        self.manifest={'format':'synergy-universal-linux-v1','architecture':'x86_64','release_id':'test-old','files':files}
        raw=json.dumps(self.manifest).encode();b.save(self.stage/'package.json',raw)
        self.pin=hashlib.sha256(raw).hexdigest()
        for name in b.DIRECTORIES:(self.stage/name).mkdir(exist_ok=True,mode=0o700)
        for name in roles:(self.stage/'roles'/name).mkdir(mode=0o700)
        host=b.host_contents('ssh-ed25519 '+'A'*68)
        for name,data in host.items():b.save(self.control/'host'/name,data)
        self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),'community_enrollment':False,
            'qualified_operations':[],'releases':{'test-old':{'manifest_sha256':self.pin,'inventory_authenticated':True,'networks':{'test':9}}},
            'engine_files':{name:files['tools/'+name] for name in b.ENGINE},'host_files':{name:hashlib.sha256(data).hexdigest() for name,data in host.items()},
            'host_account':{'uid':1234,'gid':65534,'label':'Synergy NodeNetwork '+'a'*32},'root_guard_sha256':'f'*64}
        self.write_policy()
        for path in (self.root,*self.root.rglob('*')):
            if path.is_dir():path.chmod(0o700)
        self.original_lstat=Path.lstat
    def tearDown(self):self.temp.cleanup()
    def write_policy(self):
        path=self.control/'policy.json';path.write_text(json.dumps(self.policy));path.chmod(0o600)
    def root_metadata(self,path):
        value=self.original_lstat(path)
        fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        return SimpleNamespace(**{name:getattr(value,name) for name in fields},st_uid=0)
    def snapshot(self):
        # Only privileged owner attribution and live OS guard/mount inspection
        # are replaced; namespace, manifest, every engine hash and policy remain real.
        with patch.object(b,'ROOT',self.root),patch.object(b,'NATIVE_AUTHENTICATED_MANIFEST_SHA256',self.pin,create=True), \
             patch.object(Path,'lstat',lambda path:self.root_metadata(path)),patch.object(b,'bare_mounts'), \
             patch.object(b,'bare_administrative_hashes',return_value={}),patch.object(b,'bare_guard',return_value={}), \
             patch.object(b,'bare_no_application_processes'):
            return b.bare_snapshot('test-old',self.pin)
    def test_exact_bare_snapshot_and_unknown_content_refusal(self):
        result,_,_,_=self.snapshot();self.assertEqual(result['software_installed'],False)
        self.assertRegex(result['review_sha256'],'^[a-f0-9]{64}$')
        for name in ('installation.json','keys/custody.json','tmp/controller/grants/'+('a'*64)+'.json','tmp/controller/authorization/secret','hosted-machines/guest/record.json'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_text('unapproved');path.chmod(0o600)
            with self.assertRaises(ValueError,msg=name):self.snapshot()
            path.unlink()
            # Remove only empty test-created parents until a known member.
            while path.parent not in (self.root,self.control,self.control/'grants') and not any(path.parent.iterdir()):
                parent=path.parent;parent.rmdir();path=parent
    def test_pins_policy_and_symlink_fail_closed_before_guard(self):
        path=self.control/'tools/apqe_layout.py';raw=path.read_bytes();path.write_bytes(raw+b'\n')
        with self.assertRaisesRegex(ValueError,'engine drift'):self.snapshot()
        path.write_bytes(raw)
        self.policy['engineering_authorization']={'sha256':'a'*64};self.write_policy()
        with self.assertRaisesRegex(ValueError,'no longer bare'):self.snapshot()
        del self.policy['engineering_authorization'];self.write_policy()
        path.unlink();path.symlink_to(self.stage/'tools/apqe_layout.py')
        with self.assertRaises(ValueError):self.snapshot()
    def test_review_changes_for_public_host_content_even_with_updated_local_pin(self):
        before=self.snapshot()[0]['review_sha256'];path=self.control/'host/authorized_keys'
        raw=path.read_bytes()+b'\n';path.write_bytes(raw)
        self.policy['host_files']['authorized_keys']=hashlib.sha256(raw).hexdigest();self.write_policy()
        self.assertNotEqual(before,self.snapshot()[0]['review_sha256'])
    def test_mount_boundary_is_rejected_even_on_same_device(self):
        row='1 2 0:1 / '+str(self.root)+'/tmp/bootstrap-master rw - ext4 /dev/test rw\n'
        with patch('builtins.open',return_value=io.StringIO(row)):
            with self.assertRaisesRegex(ValueError,'Mounted bare subtree'):b.bare_mounts(self.root)

    def test_apply_requires_same_review_and_uses_original_guard(self):
        result={'review_sha256':'a'*64};guard={'wait_for_retirement':Mock(),'account_present':Mock(return_value=False)}
        account={'host_account':{'uid':1234,'label':'Synergy NodeNetwork '+'a'*32}}
        with patch.object(b,'ROOT',self.root),patch.object(b.os,'geteuid',return_value=0), \
             patch.object(b.sys,'platform','linux'),patch.object(b.os,'uname',return_value=SimpleNamespace(machine='x86_64')), \
             patch.object(b,'bare_snapshot',return_value=(result,guard,account,{})), \
             patch.object(b,'HOST_LINKS',{}),patch.object(b.shutil,'rmtree',wraps=b.shutil.rmtree) as remove:
            with self.assertRaisesRegex(ValueError,'review changed'):b.bare_rollback('test-old',self.pin,'b'*64)
            remove.assert_not_called();guard['wait_for_retirement'].assert_not_called()
            receipt=b.bare_rollback('test-old',self.pin,'a'*64)
            remove.assert_called_once_with(self.root);guard['wait_for_retirement'].assert_called_once()
            self.assertTrue(receipt['registrations_removed']);self.assertFalse(self.root.exists())
    def test_verified_process_guard_blocks_rooted_staged_and_controller_process(self):
        proc=Path(self.temp.name)/'proc';process=proc/'987654';process.mkdir(parents=True)
        (process/'exe').symlink_to('/usr/bin/python3')
        with patch.object(Path,'lstat',lambda path:self.root_metadata(path)):
            for argument in ('tmp/bootstrap-master/bin/synergy-node','tmp/controller/controller.py'):
                (process/'cmdline').write_bytes(b'/usr/bin/python3\0'+str(self.root/argument).encode()+b'\0')
                with self.assertRaisesRegex(ValueError,'application process remains'):
                    b.bare_no_application_processes(self.root,self.policy['engine_files'],proc)
            # The separately attributed original guard uses an exact ROOT
            # argument; it is not an app binary or a path inside the root.
            (process/'cmdline').write_bytes(b'/usr/bin/python3\0-I\0-B\0-c\0pinned guard source\0'+str(self.root).encode()+b'\0')
            b.bare_no_application_processes(self.root,self.policy['engine_files'],proc)

    def test_concurrent_lifecycle_lock_refuses_before_snapshot(self):
        import fcntl
        lock=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(b,'ROOT',self.root),patch.object(b.os,'geteuid',return_value=0), \
                 patch.object(b.sys,'platform','linux'),patch.object(b.os,'uname',return_value=SimpleNamespace(machine='x86_64')), \
                 patch.object(b,'bare_snapshot') as snapshot:
                with self.assertRaises(BlockingIOError):b.bare_rollback('test-old',self.pin,'a'*64)
                snapshot.assert_not_called();self.assertTrue(self.root.exists())
        finally:os.close(lock)

    def test_guard_retirement_failure_is_not_reported_as_success(self):
        guard={'wait_for_retirement':Mock(side_effect=ValueError('retirement incomplete'))}
        with patch.object(b,'ROOT',self.root),patch.object(b.os,'geteuid',return_value=0), \
             patch.object(b.sys,'platform','linux'),patch.object(b.os,'uname',return_value=SimpleNamespace(machine='x86_64')), \
             patch.object(b,'bare_snapshot',return_value=({'review_sha256':'a'*64},guard,{},{})):
            with self.assertRaisesRegex(ValueError,'incomplete'):b.bare_rollback('test-old',self.pin,'a'*64)
            self.assertFalse(self.root.exists())

if __name__=='__main__':unittest.main()
