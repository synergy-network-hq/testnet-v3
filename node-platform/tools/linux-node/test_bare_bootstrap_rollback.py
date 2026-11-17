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
import controller as c

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
        self.authorization_raw=None;self.authorization_pin=None;self.snapshot_function=b.bare_snapshot
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
             patch.object(b,'bare_no_application_processes'), \
             patch.object(b,'NATIVE_AUTHENTICATED_BARE_AUTHORIZATION_JSON',self.authorization_raw,create=True), \
             patch.object(b,'NATIVE_AUTHENTICATED_BARE_AUTHORIZATION_SHA256',self.authorization_pin,create=True):
            return self.snapshot_function('test-old',self.pin)
    def authorize_initial(self):
        # Exact initial staging layout produced by stage_engineering_authorization:
        # original document is supplied independently by the native app, not a
        # mutable target-side self-assertion of its original request inventory.
        formation={'network_id':'test','chain_id_hex':format(9,'064x'),'formation_id':'a'*64}
        payload=json.dumps(formation).encode();formation_pin=hashlib.sha256(payload).hexdigest()
        requests=[{'version':1,'operation':'install','parameters':{'release_id':'test-old','manifest_sha256':self.pin,
                    'network_id':'test','chain_id':9,'node_name':'validator-test'}},
                  {'version':1,'operation':'formation_prepare','parameters':{'formation_sha256':formation_pin}}]
        target={'kind':'remote','host':'127.0.0.1','port':22280,'root':str(self.root),
                'machine_id_sha256':None,'host_key':'[127.0.0.1]:22280 ssh-ed25519 '+'A'*68}
        selection={'release_id':'test-old','manifest_sha256':self.pin,'network_id':'test','chain_id':9,'node_name':'validator-test'}
        doc={'version':1,'profile':b.AUTHORIZATION_PROFILE,'target':target,**selection,'sequence':1,
             'expires_at':1,'artifacts':{'formation-context.json':formation_pin},'genesis_pins':None,
             'requests':[{'operation':request['operation'],'request_sha256':c.request_digest(request)} for request in requests]}
        self.authorization_raw=json.dumps(doc);self.authorization_pin=hashlib.sha256(self.authorization_raw.encode()).hexdigest()
        self.policy.update(engineering_selection=selection,engineering_target=target,
            engineering_initial_authorization_sha256=self.authorization_pin,
            engineering_authorization={'sha256':self.authorization_pin,'sequence':1,'expires_at':1},
            authorization_files=doc['artifacts'],authorization_predecessor_sha256='e'*64,
            validator_formation_sha256=formation_pin,qualified_operations=sorted(request['operation'] for request in requests))
        self.write_policy();b.save(self.control/'authorization/inputs/formation-context.json',payload)
        for request in doc['requests']:
            b.save(self.control/'grants'/(request['request_sha256']+'.json'),json.dumps({**request,
                'root':str(self.root),'expires_at':1,'authorization_sha256':self.authorization_pin,'authorization_sequence':1}).encode())
        return doc

    def observed_bytes(self):
        return {p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_exact_expired_initial_authorization_can_cancel_without_regrant(self):
        self.assertIsNone(self.snapshot()[0]['authorization_sha256'])
        doc=self.authorize_initial();before=self.observed_bytes()
        result=self.snapshot()[0]
        self.assertEqual(result['authorization_sha256'],self.authorization_pin)
        self.assertEqual(self.observed_bytes(),before)
        # Content pins (not just grant metadata timestamps) enter the review.
        grant=self.control/'grants'/(doc['requests'][0]['request_sha256']+'.json')
        grant.write_bytes(grant.read_bytes()+b' ')
        self.assertNotEqual(self.snapshot()[0]['review_sha256'],result['review_sha256'])

    def test_initial_authorization_missing_changed_or_extra_grants_refuse_without_mutation(self):
        doc=self.authorize_initial()
        grant=self.control/'grants'/(doc['requests'][0]['request_sha256']+'.json');original=grant.read_bytes()
        for mode in ('missing','changed','extra'):
            with self.subTest(mode=mode):
                extra=self.control/'grants'/('f'*64+'.json')
                if mode=='missing':grant.unlink()
                elif mode=='changed':
                    value=json.loads(original);value['operation']='start';grant.write_text(json.dumps(value))
                else:b.save(extra,original)
                before=self.observed_bytes()
                with self.assertRaises((ValueError,FileNotFoundError)):self.snapshot()
                self.assertEqual(self.observed_bytes(),before)
                if mode=='extra':extra.unlink()
                else:grant.write_bytes(original);grant.chmod(0o600)

    def test_authorized_apply_rechecks_review_then_uses_existing_retirement(self):
        doc=self.authorize_initial();review=self.snapshot()[0]
        grant=self.control/'grants'/(doc['requests'][0]['request_sha256']+'.json')
        original=grant.read_bytes();grant.write_bytes(original+b' ')
        before=self.observed_bytes()
        guard={'wait_for_retirement':Mock(),'account_present':Mock(return_value=False)}
        def current(_release,_pin):
            result,_,policy,administrative=self.snapshot()
            return result,guard,policy,administrative
        with patch.object(b,'ROOT',self.root),patch.object(b.os,'geteuid',return_value=0), \
             patch.object(b.sys,'platform','linux'),patch.object(b.os,'uname',return_value=SimpleNamespace(machine='x86_64')), \
             patch.object(b,'bare_snapshot',side_effect=current),patch.object(b,'HOST_LINKS',{}):
            with self.assertRaisesRegex(ValueError,'review changed'):
                b.bare_rollback('test-old',self.pin,review['review_sha256'])
            self.assertEqual(self.observed_bytes(),before);guard['wait_for_retirement'].assert_not_called()
            grant.write_bytes(original)
            # A fresh exact read is required after any observed filesystem change.
            refreshed=self.snapshot()[0]
            receipt=b.bare_rollback('test-old',self.pin,refreshed['review_sha256'])
            self.assertEqual(receipt['authorization_sha256'],self.authorization_pin)
            self.assertTrue(receipt['root_removed']);self.assertFalse(self.root.exists())
            guard['wait_for_retirement'].assert_called_once()

    def test_authorization_pin_continuation_and_unknown_state_fail_closed(self):
        self.authorize_initial()
        old_pin=self.authorization_pin;self.authorization_pin='0'*64
        with self.assertRaisesRegex(ValueError,'independent initial'):self.snapshot()
        self.authorization_pin=old_pin
        for member in ('installation.json','tmp/controller/audit.jsonl','tmp/formation-prepare-request.json',
                       'tmp/pre-genesis-validator/custody.json','vpn/state.json','tmp/update-master/file'):
            path=self.root/member;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);b.save(path,b'forbidden')
            before=self.observed_bytes()
            with self.assertRaises(ValueError,msg=member):self.snapshot()
            self.assertEqual(before,self.observed_bytes());path.unlink()
            while path.parent not in (self.root,self.control,self.root/'tmp') and not any(path.parent.iterdir()):
                parent=path.parent;parent.rmdir();path=parent
        self.policy['engineering_authorization']['sequence']=2;self.write_policy()
        with self.assertRaisesRegex(ValueError,'continued'):self.snapshot()

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
