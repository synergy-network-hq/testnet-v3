"""Native engineering update trust/installed-lineage tests; no hosts or services."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
import bootstrap as b
import controller as c

class EngineeringUpdateTests(unittest.TestCase):
    def fixture(self):
        selection={'release_id':'reviewed-old','manifest_sha256':'a'*64,'network_id':'synergy-posy-canary-20261117','chain_id':99999,'node_name':'validator-test'}
        policy={'engineering_selection':selection,'engineering_initial_authorization_sha256':'b'*64,
            'engineering_authorization':{'sha256':'c'*64},'validator_formation_sha256':'d'*64,
            'engineering_target':{'kind':'remote','host':'127.0.0.1','port':22280,'root':'/opt/synergy'},
            'releases':{'reviewed-old':{'manifest_sha256':'a'*64,'inventory_authenticated':True,'networks':{selection['network_id']:99999}}}}
        context={'initial_sha256':'b'*64,'parent_sha256':'c'*64,'formation_sha256':'d'*64,
            'target':policy['engineering_target'],'selection':selection,'release_id':'reviewed-new','manifest_sha256':'e'*64,'expires_at':1300}
        return selection,policy,context
    def test_exact_initial_parent_target_release_and_short_expiry_are_required_before_staging(self):
        selection,policy,context=self.fixture()
        with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',context,create=True):
            self.assertEqual(b.engineering_update_context(policy,selection,'reviewed-new','e'*64,1000),context)
        for field,value in [('initial_sha256','f'*64),('parent_sha256','f'*64),('formation_sha256','f'*64),
                ('target',{}),('selection',{}),('release_id','other'),('manifest_sha256','f'*64),('expires_at',1000),('expires_at',1301),('expires_at',True)]:
            bad=dict(context,**{field:value})
            with self.subTest(field=field),patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',bad,create=True),self.assertRaises(ValueError):
                b.engineering_update_context(policy,selection,'reviewed-new','e'*64,1000)
        with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',None,create=True),self.assertRaises(ValueError):
            b.engineering_update_context(policy,selection,'reviewed-new','e'*64,1000)
        production=copy.deepcopy(policy)
        production.pop('engineering_initial_authorization_sha256')
        with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',context,create=True),self.assertRaises(ValueError):
            b.engineering_update_context(production,selection,'reviewed-new','e'*64,1000)
    def test_staging_does_not_advance_installed_selection_and_only_exact_sealed_upgrade_does(self):
        old,policy,context=self.fixture();new={**old,'release_id':'reviewed-new','manifest_sha256':'e'*64}
        policy['releases']['reviewed-new']={'manifest_sha256':'e'*64,'inventory_authenticated':True,'networks':{old['network_id']:99999}}
        policy['engineering_update']={'initial_sha256':'b'*64,'formation_sha256':'d'*64,'previous_selection':old,'selection':new}
        receipt={k:old[k] for k in ('network_id','chain_id','node_name')}
        with patch('lifecycle._sealed_receipt',return_value=({**receipt,'package_sha256':'a'*64},{'release_id':'reviewed-old'})):
            self.assertEqual(c.engineering_effective_selection(Path('/opt/synergy'),policy),old)
        with patch('lifecycle._sealed_receipt',return_value=({**receipt,'package_sha256':'e'*64},{'release_id':'reviewed-new'})):
            self.assertEqual(c.engineering_effective_selection(Path('/opt/synergy'),policy),new)
            for where,field,value in [('engineering_update','initial_sha256','f'*64),('engineering_update','formation_sha256','f'*64),('engineering_selection','network_id','other-network')]:
                bad=copy.deepcopy(policy);bad[where][field]=value
                with self.assertRaises(ValueError):c.engineering_effective_selection(Path('/opt/synergy'),bad)
            bad=copy.deepcopy(policy);bad['releases']['reviewed-new']['inventory_authenticated']=False
            with self.assertRaises(ValueError):c.engineering_effective_selection(Path('/opt/synergy'),bad)
        with patch('lifecycle._sealed_receipt',return_value=({**receipt,'package_sha256':'f'*64},{'release_id':'other'})),self.assertRaises(ValueError):
            c.engineering_effective_selection(Path('/opt/synergy'),policy)
        with patch('lifecycle._sealed_receipt',side_effect=ValueError('payload drift')),self.assertRaisesRegex(ValueError,'payload drift'):
            c.engineering_effective_selection(Path('/opt/synergy'),policy)

    def test_native_staging_publishes_exact_candidate_and_controller_without_upgrade_or_grants(self):
        self._native_stage_fixture(False)

    def test_native_staging_preserves_exact_expired_commission_grant_across_exchange(self):
        self._native_stage_fixture(True)

    def _native_stage_fixture(self,preserve):
        import ctypes
        import hashlib
        import io
        import json
        import os
        import sys
        import tempfile
        from contextlib import ExitStack
        from types import SimpleNamespace
        import lifecycle
        import synergy_linux
        from test_bootstrap import BootstrapTests
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()/'synergy';control=root/'tmp/controller'
            (control/'tools').mkdir(parents=True,mode=0o700);(control/'grants').mkdir(mode=0o700)
            for path in (root,root/'tmp',control):path.chmod(0o700)
            selection,policy,context=self.fixture();policy['engineering_target']['root']=str(root)
            policy['format']='synergy-nodenetwork-host-policy-v1';policy['root']=str(root);policy['community_enrollment']=False
            policy['qualified_operations']=[];policy['engine_files']={}
            for name in b.ENGINE:
                data=('old-'+name).encode();path=control/name if name=='controller.py' else control/'tools'/name
                path.write_bytes(data);path.chmod(0o600);policy['engine_files'][name]=hashlib.sha256(data).hexdigest()
            policy_path=control/'policy.json';policy_path.write_text(json.dumps(policy));policy_path.chmod(0o600)
            expected_grants=[]
            if preserve:
                import apqe_layout
                import controller as current_controller
                for name in ('config','network','keys'):(root/name).mkdir(mode=0o700)
                policy['engineering_authorization'].update(expires_at=100,sequence=21)
                pins={}
                for name in apqe_layout.FORMATION_PUBLIC_INPUTS:
                    path=control/'authorization/inputs/commissioning'/name
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(('reviewed '+name).encode());path.chmod(0o600)
                    pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
                policy['validator_commissioning_files']=pins
                policy['authorization_files']={'commissioning/'+name:pin for name,pin in pins.items()}
                policy['validator_identity_network']={name:pins['network/'+name] for name in current_controller.GENESIS_FILES}
                key=current_controller.request_digest({'version':1,'operation':'commission','parameters':{}})
                auth=policy['engineering_authorization']
                grant={'root':str(root),'operation':'commission','request_sha256':key,'expires_at':100,'authorization_sha256':auth['sha256'],'authorization_sequence':auth['sequence']}
                path=control/'grants'/(key+'.json');path.write_text(json.dumps(grant));path.chmod(0o600)
                expected_grants=[key+'.json'];preserved_bytes=path.read_bytes()
                policy_path.write_text(json.dumps(policy))
                context['commission_grant_preservation']=b.update_commission_grant(root,policy,1000)
            package,header=BootstrapTests().archive();context['release_id']=header['release_id'];context['manifest_sha256']=header['manifest_sha256']
            receipt={'role':'validator','network_id':selection['network_id'],'chain_id':99999,'node_name':selection['node_name'],'package_sha256':selection['manifest_sha256']}
            real_stat=Path.stat;real_lstat=Path.lstat
            def owned(call):
                def result(path,*args,**kwargs):
                    value=call(path,*args,**kwargs)
                    return SimpleNamespace(**{key:getattr(value,key) for key in dir(value) if key.startswith('st_') and key!='st_uid'},st_uid=0)
                return result
            def exchange(_a,left,_b,right,_flags):
                left,right=Path(os.fsdecode(left)),Path(os.fsdecode(right));swap=left.with_name('exchange-test')
                left.rename(swap);right.rename(left);swap.rename(right);return 0
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys,'path',sys.path.copy()))
                stack.enter_context(patch.object(b,'ROOT',root));stack.enter_context(patch.object(b.os,'geteuid',return_value=0))
                stack.enter_context(patch.object(b.sys,'platform','linux'));stack.enter_context(patch.object(b.os,'uname',return_value=SimpleNamespace(machine='x86_64')))
                stack.enter_context(patch.object(Path,'stat',owned(real_stat)));stack.enter_context(patch.object(Path,'lstat',owned(real_lstat)))
                stack.enter_context(patch.object(ctypes,'CDLL',return_value=SimpleNamespace(renameat2=exchange)))
                stack.enter_context(patch.object(lifecycle,'_sealed_receipt',return_value=(receipt,{'release_id':selection['release_id']})))
                stack.enter_context(patch.object(lifecycle,'_unit_state',return_value={'MainPID':'0','ActiveState':'inactive'}))
                stack.enter_context(patch.object(lifecycle,'_assert_no_application_processes'))
                stack.enter_context(patch.object(c,'control_inventory'))
                stack.enter_context(patch.object(b,'verify_adopted_controller'))
                stack.enter_context(patch.object(synergy_linux,'verify_package',side_effect=lambda path:json.loads((path/'package.json').read_bytes())))
                stack.enter_context(patch('time.time',return_value=1000))
                stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',context,create=True))
                for key,value in [('network_id','foreign'),('chain_id',1266),('node_name','other'),('role','rpc_gateway')]:
                    changed_receipt={**receipt,key:value}
                    with patch.object(lifecycle,'_sealed_receipt',return_value=(changed_receipt,{'release_id':selection['release_id']})),self.assertRaises(ValueError):
                        b.stage_engineering_update(io.BytesIO(),header['release_id'],header['manifest_sha256'])
                    self.assertFalse((root/'tmp/update-master').exists())
                    self.assertEqual(json.loads(policy_path.read_bytes()),policy)
                with patch.object(b,'verify_adopted_controller',side_effect=ValueError('postexchange failure')),self.assertRaisesRegex(ValueError,'postexchange failure'):
                    b.stage_engineering_update(package,header['release_id'],header['manifest_sha256'])
                self.assertTrue((root/'tmp/controller-update/policy.json').exists())
                self.assertTrue((root/'tmp/update-master/package.json').exists())
                # Reconciliation takes no archive stream and does not re-exchange,
                # restage, change grants, or replace installed validator software.
                result=b.stage_engineering_update(None,header['release_id'],header['manifest_sha256'],reconcile=True)
                self.assertTrue(result['controllerAdopted']);self.assertFalse(result['validatorUpgraded'])
                changed=json.loads(policy_path.read_bytes());self.assertEqual(changed['engineering_selection'],selection)
                self.assertEqual(changed['engineering_update']['selection']['manifest_sha256'],header['manifest_sha256'])
                self.assertEqual(sorted(p.name for p in (control/'grants').iterdir()),expected_grants)
                self.assertEqual(changed['engineering_authorization'],policy['engineering_authorization'])
                self.assertEqual((control/'controller.py').read_bytes(),b'canonical engine')
                self.assertFalse((root/'tmp/controller-update').exists())
                before=policy_path.read_bytes()
                with self.assertRaisesRegex(ValueError,'Prior update staging'):b.stage_engineering_update(io.BytesIO(),header['release_id'],header['manifest_sha256'])
                self.assertEqual(policy_path.read_bytes(),before)
                # A different stage needs the exact fresh native-approved false
                # proof. The wire is a separate bounded line, not an SSH argv.
                import tarfile
                original,old_header=BootstrapTests().archive()
                successor=io.BytesIO()
                with tarfile.open(fileobj=original,mode='r') as prior,tarfile.open(fileobj=successor,mode='w') as tar:
                    for member in prior:
                        raw=prior.extractfile(member).read()
                        if member.name=='package.json':
                            value=json.loads(raw);value['release_id']='qualified-successor';raw=json.dumps(value).encode()
                            new_header={'release_id':value['release_id'],'manifest_sha256':hashlib.sha256(raw).hexdigest()}
                        entry=tarfile.TarInfo(member.name);entry.size=len(raw);tar.addfile(entry,io.BytesIO(raw))
                new_context={**context,**new_header}
                current=json.loads(policy_path.read_bytes())
                proof={'context':{key:new_context[key] for key in ('initial_sha256','parent_sha256','formation_sha256','target','selection','expires_at')},
                       'adoption':current['engineering_update'],'request':{'version':1,'operation':'upgrade','parameters':old_header}}
                snapshots={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',new_context), \
                     patch.object(b,'NATIVE_AUTHENTICATED_SUPERSEDED_UPGRADE',True,create=True), \
                     patch.object(b,'NATIVE_AUTHENTICATED_MANIFEST_SHA256',new_header['manifest_sha256'],create=True), \
                     patch.object(b,'upgrade_not_applied_proof',side_effect=ValueError('proof refused')):
                    with self.assertRaisesRegex(ValueError,'proof refused'):
                        b.stage_engineering_update(io.BytesIO(json.dumps(proof).encode()+b'\n'+successor.getvalue()),**{'release_id':new_header['release_id'],'pin':new_header['manifest_sha256']})
                self.assertEqual(snapshots,{p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()})
                with patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',new_context), \
                     patch.object(b,'NATIVE_AUTHENTICATED_SUPERSEDED_UPGRADE',True,create=True), \
                     patch.object(b,'NATIVE_AUTHENTICATED_MANIFEST_SHA256',new_header['manifest_sha256'],create=True), \
                     patch.object(b,'upgrade_not_applied_proof') as verify:
                    result=b.stage_engineering_update(io.BytesIO(json.dumps(proof).encode()+b'\n'+successor.getvalue()),new_header['release_id'],new_header['manifest_sha256'])
                    verify.assert_called_once_with(proof,_already_locked=True,_retiring=True)
                self.assertEqual(result['manifestSha256'],new_header['manifest_sha256'])
                self.assertFalse(result['validatorUpgraded']);self.assertEqual(sorted(p.name for p in (control/'grants').iterdir()),expected_grants)
                if preserve:self.assertEqual((control/'grants'/expected_grants[0]).read_bytes(),preserved_bytes)

    def test_actual_old_nine_to_current_inventory_uses_fresh_isolated_verifier(self):
        # Real controller code and policy inventory, not a mocked inventory call.
        import hashlib,json,tempfile
        from test_controller_startup import IsolatedControllerStartupTests
        with tempfile.TemporaryDirectory() as temporary:
            root=IsolatedControllerStartupTests().fixture(temporary)
            control=root/'tmp/controller';entry=control/'controller.py'
            current=entry.read_bytes();old=current.replace(b",'vpn_authorization.py','treasury_send.py'))",b"))",1)
            self.assertNotEqual(old,current)
            namespace={'__name__':'predecessor_fixture','__file__':str(entry)}
            exec(compile(old,str(entry),'exec'),namespace)
            policy_path=control/'policy.json';policy=json.loads(policy_path.read_bytes())
            del policy['engine_files']['vpn_authorization.py'];del policy['engine_files']['treasury_send.py']
            entry.write_bytes(old);policy['engine_files']['controller.py']=hashlib.sha256(old).hexdigest()
            (control/'tools/vpn_authorization.py').unlink();(control/'tools/treasury_send.py').unlink();policy_path.write_text(json.dumps(policy))
            namespace['control_inventory'](root);b.verify_adopted_controller(root)
            entry.write_bytes(current);policy['engine_files']['controller.py']=hashlib.sha256(current).hexdigest()
            dependency=control/'tools/vpn_authorization.py'
            dependency.write_bytes((Path(c.__file__).parent/'vpn_authorization.py').read_bytes());dependency.chmod(0o600)
            policy['engine_files']['vpn_authorization.py']=hashlib.sha256(dependency.read_bytes()).hexdigest()
            additional=control/'tools/treasury_send.py';additional.write_bytes((Path(c.__file__).parent/'treasury_send.py').read_bytes());additional.chmod(0o600)
            policy['engine_files']['treasury_send.py']=hashlib.sha256(additional.read_bytes()).hexdigest();policy_path.write_text(json.dumps(policy))
            with self.assertRaisesRegex(ValueError,'Complete pinned controller engine'):namespace['control_inventory'](root)
            b.verify_adopted_controller(root)
            dependency.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'Adopted controller verification failed'):b.verify_adopted_controller(root)

    def test_exact_backup_reconciliation_is_restart_safe_and_refuses_foreign_state(self):
        import json,os,shutil,tempfile
        from test_controller_startup import IsolatedControllerStartupTests
        with tempfile.TemporaryDirectory() as temporary:
            root=IsolatedControllerStartupTests().fixture(temporary);control=root/'tmp/controller'
            old,scope,context=self.fixture()
            original=json.loads((control/'policy.json').read_bytes());original.update(scope)
            # Reproduce old public staging under umask 022, then canonical
            # install's historical recursive permission normalization.
            original['authorization_files']={'formation-context.json':'1'*64}
            previous_umask=os.umask(0o022)
            try:b.save(control/'authorization/inputs/formation-context.json',b'public context')
            finally:os.umask(previous_umask)
            self.assertEqual((control/'authorization').stat().st_mode&0o777,0o755)
            (control/'policy.json').write_text(json.dumps(original));backup=root/'tmp/controller-update';shutil.copytree(control,backup)
            for path in (backup/'tools').iterdir():path.chmod(0o700)

            manifest={'release_id':'reviewed-new','files':{'tools/'+name:pin for name,pin in original['engine_files'].items()}}
            policy=copy.deepcopy(original)
            policy['releases']['reviewed-new']={'manifest_sha256':'e'*64,'inventory_authenticated':True,'networks':{old['network_id']:99999}}
            policy['engineering_update']={'initial_sha256':'b'*64,'parent_sha256':'c'*64,'formation_sha256':'d'*64,'previous_selection':old,
                'selection':{**old,'release_id':'reviewed-new','manifest_sha256':'e'*64},
                'request_sha256':c.request_digest({'version':1,'operation':'update_stage','parameters':{'release_id':'reviewed-new','manifest_sha256':'e'*64}})}
            (control/'policy.json').write_text(json.dumps(policy))
            # Compatibility never admits arbitrary executable data/public dirs.
            (backup/'authorization').chmod(0o777)
            with self.assertRaisesRegex(ValueError,'Unsafe update controller member'):b.retire_update_backup(root,manifest,context,old,policy)
            (backup/'authorization').chmod(0o755)
            (backup/'controller.py').chmod(0o700)
            with self.assertRaisesRegex(ValueError,'Unsafe update controller member'):b.retire_update_backup(root,manifest,context,old,policy)
            (backup/'controller.py').chmod(0o600)
            foreign=backup/'foreign';foreign.write_bytes(b'foreign');foreign.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'outside the exact predecessor'):b.retire_update_backup(root,manifest,context,old,policy)
            self.assertTrue(foreign.exists());foreign.unlink()
            altered=copy.deepcopy(policy);altered['engineering_update']['formation_sha256']='f'*64
            with self.assertRaisesRegex(ValueError,'exact adopted policy'):b.retire_update_backup(root,manifest,context,old,altered)
            self.assertTrue((backup/'policy.json').exists())
            (backup/'tools/vpn_authorization.py').unlink()
            before=(control/'policy.json').read_bytes();b.retire_update_backup(root,manifest,context,old,policy)
            self.assertFalse(backup.exists());self.assertEqual(before,(control/'policy.json').read_bytes())
            shutil.copytree(control,backup)
            (backup/'policy.json').write_text(json.dumps(original))
            real_rmdir=Path.rmdir
            def interrupt_last(path):
                if path==backup:raise OSError('interrupted after policy unlink')
                return real_rmdir(path)
            with patch.object(Path,'rmdir',interrupt_last),self.assertRaisesRegex(OSError,'interrupted after policy unlink'):
                b.retire_update_backup(root,manifest,context,old,policy)
            self.assertTrue(backup.is_dir());self.assertEqual(list(backup.iterdir()),[])
            b.retire_update_backup(root,manifest,context,old,policy)
            self.assertFalse(backup.exists())
            b.retire_update_backup(root,manifest,context,old,policy)

    def test_structured_update_refusal_identifies_only_fixed_public_phase(self):
        import contextlib,io,json,sys
        for phase in b.UPDATE_PHASES:
            def refused(*args,**kwargs):
                b.update_phase(phase)
                raise ValueError('SECRET-TOKEN /private/custody arbitrary exception details')
            output=io.StringIO()
            with self.subTest(phase=phase),patch.object(sys,'argv',['bootstrap','--reconcile-engineering-update','release','a'*64]),patch.object(b,'stage_engineering_update',side_effect=refused),contextlib.redirect_stdout(output):
                b.main()
            reply=json.loads(output.getvalue())
            self.assertFalse(reply['ok']);self.assertEqual(reply['error']['code'],'engineering_update_'+phase+'_refused')
            self.assertNotIn('SECRET',output.getvalue());self.assertNotIn('/private',output.getvalue())
        # A later unrelated bootstrap refusal cannot inherit an update phase.
        output=io.StringIO()
        with patch.object(sys,'argv',['bootstrap']),patch.object(b,'bootstrap',side_effect=ValueError('SECRET')),contextlib.redirect_stdout(output):b.main()
        self.assertEqual(json.loads(output.getvalue())['error']['code'],'bootstrap_refused')

if __name__=='__main__':unittest.main()

class SupersededStageTests(unittest.TestCase):
    def test_exact_public_stage_cleanup_partial_restart_and_foreign_refusal(self):
        import tempfile,io,os,json
        from test_bootstrap import BootstrapTests
        for kind in ('complete','partial','last_manifest','unknown','tamper','link','wrongpin','empty'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve()/'synergy';stage=root/'tmp/update-master';stage.mkdir(parents=True,mode=0o700)
                archive,selection=BootstrapTests().archive();b.extract(archive,stage,selection)
                keep=root/'guest-disk';keep.write_bytes(b'unchanged guest disk')
                if kind=='unknown':(stage/'foreign').write_bytes(b'unknown')
                if kind=='tamper':(stage/'tools/controller.py').write_bytes(b'foreign')
                if kind=='link':(stage/'tools/controller.py').unlink();(stage/'tools/controller.py').symlink_to(keep)
                if kind=='wrongpin':selection['manifest_sha256']='0'*64
                if kind in ('unknown','tamper','link','wrongpin'):
                    with self.assertRaises(ValueError):b.retire_superseded_update(root,selection)
                    self.assertTrue(stage.exists());self.assertTrue((stage/'package.json').exists())
                else:
                    real_unlink=Path.unlink;real_rmdir=Path.rmdir;count=[0]
                    def interrupted(path,*a,**k):
                        count[0]+=1
                        if count[0]==3:raise OSError('cleanup interrupted')
                        return real_unlink(path,*a,**k)
                    if kind=='partial':
                        with patch.object(Path,'unlink',interrupted),self.assertRaises(OSError):b.retire_superseded_update(root,selection)
                        self.assertTrue((stage/'package.json').exists());b.retiring_update_members(root,selection)
                    if kind in ('last_manifest','empty'):
                        def last(path,*a,**k):
                            if (kind=='last_manifest' and path==stage/'package.json'):raise OSError('last interrupted')
                            return real_unlink(path,*a,**k)
                        def directory(path,*a,**k):
                            if kind=='empty' and path==stage:raise OSError('directory interrupted')
                            return real_rmdir(path,*a,**k)
                        with patch.object(Path,'unlink',last),patch.object(Path,'rmdir',directory),self.assertRaises(OSError):b.retire_superseded_update(root,selection)
                        b.retiring_update_members(root,selection)
                    events=[];fsync=os.fsync
                    def observed_unlink(path,*a,**k):
                        value=real_unlink(path,*a,**k);events.append(('unlink',path));return value
                    def observed_sync(fd):
                        value=fsync(fd);events.append(('sync',None));return value
                    with patch.object(Path,'unlink',observed_unlink),patch.object(os,'fsync',observed_sync):
                        b.retire_superseded_update(root,selection)
                    self.assertFalse(stage.exists())
                    for index,event in enumerate(events):
                        if event[0]=='unlink':self.assertEqual(events[index+1][0],'sync')
                    # Authority is last, and every prior deletion is durable.
                    unlinked=[path for kind,path in events if kind=='unlink']
                    if unlinked:self.assertEqual(unlinked[-1],stage/'package.json')
                    b.retire_superseded_update(root,selection)
                self.assertEqual(keep.read_bytes(),b'unchanged guest disk')


class UpgradeNotAppliedProofTests(unittest.TestCase):
    def test_readonly_exact_audit_scope_and_partial_refusals(self):self.proof_cases(False)
    def test_unused_stage_zero_consumption_and_full_unchanged_payload(self):self.proof_cases(True)
    def proof_cases(self,unused):
        import tempfile,json,hashlib,time,lifecycle,synergy_linux
        from contextlib import ExitStack
        from types import SimpleNamespace
        for kind in ('valid','intent','completed','partial','grant','audit','scope','verifier','candidate','expired','conformance','retiring','retiring_refused','prior-valid','prior-root','prior-current-candidate','prior-unknown','prior-format','prior-mode','prior-link','prior-resumed','prior-flags'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve()/'synergy';control=root/'tmp/controller'
                (control/'tools').mkdir(parents=True);(control/'grants').mkdir();(root/'evidence').mkdir();(root/'tmp/update-master/assets').mkdir(parents=True)
                old={'release_id':'old','manifest_sha256':'a'*64,'network_id':'canary','chain_id':99999,'node_name':'v'};new={**old,'release_id':'new','manifest_sha256':'e'*64}
                target={'kind':'remote','host':'approved.example','port':22,'root':str(root)}
                context={'initial_sha256':'b'*64,'parent_sha256':'c'*64,'formation_sha256':'d'*64,'target':target,'selection':old,'expires_at':int(time.time())+250}
                adoption={'initial_sha256':'b'*64,'formation_sha256':'d'*64,'previous_selection':old,'selection':new}
                policy={'engine_files':{},'engineering_initial_authorization_sha256':'b'*64,'engineering_authorization':{'sha256':'c'*64},'validator_formation_sha256':'d'*64,'engineering_target':target,'engineering_update':adoption}
                for name in b.ENGINE:
                    raw=('pinned-'+name).encode();path=control/name if name=='controller.py' else control/'tools'/name;path.write_bytes(raw);path.chmod(0o600);policy['engine_files'][name]=hashlib.sha256(raw).hexdigest()
                path=control/'policy.json';path.write_text(json.dumps(policy));path.chmod(0o600)
                request={'version':1,'operation':'upgrade','parameters':{'release_id':'new','manifest_sha256':'e'*64}};key=c.request_digest(request)
                audit=control/'audit.jsonl';audit.write_text(json.dumps({'operation':'upgrade','request_sha256':key,'time':int(time.time())})+'\n');audit.chmod(0o600)
                source="def installed(root,old,**kwargs):\n assert old=={'files':{}}\n assert kwargs['pending_upgrade_sha256']=='"+'e'*64+"'\n return {'verified':True}\n"
                if kind=='conformance':source='def installed(*a,**k): raise ValueError("payload drift")\n'
                if kind in ('retiring','retiring_refused'):
                    source="def approved_upgrade_members(*a): return set()\ndef installed(root,old,**kwargs):\n assert approved_upgrade_members(root,'e'*64,'fresh')=={'tmp/update-master'}\n return {'verified':True}\n"
                verifier=json.dumps({'files':{'tools/conformance.py':hashlib.sha256(source.encode()).hexdigest()}});pin=hashlib.sha256(verifier.encode()).hexdigest()
                wire={'context':context,'adoption':adoption,'request':request,'challenge':'f'*64,'verifier_manifest_json':verifier,'verifier_conformance':source}
                if unused:
                    wire['unused']=True
                    audit.write_text(json.dumps({'operation':'upgrade','request_sha256':'0'*64,'time':0})+'\n') # unrelated prior upgrade remains preserved
                if kind in ('intent','completed'):(root/'evidence'/('upgrade-'+kind+'.json')).write_text('{}')
                elif kind=='partial':(root/'tmp/.file.upgrade-deadbeef').write_text('x')
                elif kind=='grant':(control/'grants'/(key+'.json')).write_text('{}')
                elif kind=='audit':audit.write_text(json.dumps({'operation':'upgrade','request_sha256':key if unused else '0'*64,'time':0}))
                elif kind=='scope':wire['context']['target']={}
                elif kind=='verifier':wire['verifier_conformance']+='\n# foreign'
                elif kind=='candidate':wire['request']['parameters']['manifest_sha256']='0'*64
                elif kind=='expired':wire['context']['expires_at']=0
                if kind.startswith('prior-'):
                    prior={'format':'synergy-software-upgrade-completed-v1','root':str(root),'old_package_sha256':'9'*64,'new_package_sha256':'a'*64,'resumed':True,'consensus_started':False,'automatic_restart':False}
                    if kind=='prior-root':prior['root']='/foreign'
                    elif kind=='prior-current-candidate':prior['new_package_sha256']='e'*64
                    elif kind=='prior-unknown':prior['extra']=True
                    elif kind=='prior-format':prior['old_package_sha256']='not-a-pin'
                    elif kind=='prior-resumed':prior['resumed']=1
                    elif kind=='prior-flags':prior['consensus_started']=0
                    path=root/'evidence/upgrade-completed.json';path.write_text(json.dumps(prior));path.chmod(0o600)
                    if kind=='prior-mode':path.chmod(0o644)
                    elif kind=='prior-link':path.unlink();path.symlink_to(audit)
                before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                ctl=SimpleNamespace(policy=lambda:policy,direct=c.Controller(root).direct)
                with ExitStack() as stack:
                    patches=[(b,'ROOT',root),(b,'NATIVE_AUTHENTICATED_MANIFEST_SHA256',pin),(c,'Controller',lambda root:ctl),(c,'engineering_effective_selection',lambda root,policy:old),
                        (lifecycle,'_sealed_receipt',lambda root:({'package_sha256':'a'*64},{'files':{}})),(lifecycle,'_integration_plan',lambda root:None),(lifecycle,'_installation_stage',lambda root:'uncommissioned'),(lifecycle,'_assert_no_application_processes',lambda *a,**k:None),
                        (synergy_linux,'verify_package',lambda p:{'release_id':'new'}),(synergy_linux,'digest',lambda p:'e'*64),(synergy_linux,'read',lambda p:{})]
                    for owner,name,value in patches:stack.enter_context(patch.object(owner,name,value,create=True))
                    stack.enter_context(patch('guest_lifecycle.require_upgrade_compatible'))
                    if kind in ('retiring','retiring_refused'):
                        stack.enter_context(patch.object(b,'retiring_update_members',return_value={'tmp/update-master'},side_effect=ValueError('foreign stage') if kind=='retiring_refused' else None))
                    if kind in ('valid','retiring','prior-valid'):
                        result=b.upgrade_not_applied_proof(wire,_already_locked=kind=='retiring',_retiring=kind=='retiring');self.assertTrue(result['not_applied']);self.assertFalse(result['mutation_performed']);self.assertEqual(result['request_sha256'],key)
                    else:
                        with self.assertRaises((ValueError,AssertionError)):b.upgrade_not_applied_proof(wire,_retiring=kind=='retiring_refused')
                self.assertEqual(before,{p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()})

class UpgradeProofErrorTests(unittest.TestCase):
    def test_readonly_refusal_exposes_only_fixed_phase_not_exception_or_other_operation(self):
        import io,json
        from contextlib import redirect_stdout
        from types import SimpleNamespace
        for phase in [*b.UPGRADE_PROOF_PHASES,'PRIVATE/path']:
            def refuse(wire):
                b._UPGRADE_PROOF_PHASE=phase
                raise ValueError('PRIVATE key stderr /sensitive/path')
            output=io.StringIO()
            with patch.object(b.sys,'argv',['bootstrap','--upgrade-not-applied-proof']),patch.object(b.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'{}'))),patch.object(b,'upgrade_not_applied_proof',refuse),redirect_stdout(output):b.main()
            value=json.loads(output.getvalue())
            self.assertFalse(value['ok']);self.assertNotIn('PRIVATE',output.getvalue());self.assertNotIn('sensitive',output.getvalue())
            self.assertEqual(value['error']['code'],'upgrade_proof_'+phase+'_refused' if phase in b.UPGRADE_PROOF_PHASES else 'bootstrap_refused')
        output=io.StringIO()
        def other(stream):
            b._UPGRADE_PROOF_PHASE='audit'
            raise ValueError('PRIVATE')
        with patch.object(b.sys,'argv',['bootstrap']),patch.object(b.sys,'stdin',SimpleNamespace(buffer=io.BytesIO())),patch.object(b,'bootstrap',other),redirect_stdout(output):b.main()
        self.assertEqual(json.loads(output.getvalue())['error']['code'],'bootstrap_refused')
