"""Native engineering update trust/installed-lineage tests; no hosts or services."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
import bootstrap as b
import controller as c

class EngineeringUpdateTests(unittest.TestCase):
    def fixture(self):
        selection={'release_id':'reviewed-old','manifest_sha256':'a'*64,'network_id':'nodenetwork-formation-disposable-test','chain_id':99999,'node_name':'validator-test'}
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
                stack.enter_context(patch.object(synergy_linux,'verify_package',side_effect=lambda path:json.loads((path/'package.json').read_bytes())))
                stack.enter_context(patch('time.time',return_value=1000))
                stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_UPDATE_CONTEXT',context,create=True))
                result=b.stage_engineering_update(package,header['release_id'],header['manifest_sha256'])
                self.assertTrue(result['controllerAdopted']);self.assertFalse(result['validatorUpgraded'])
                changed=json.loads(policy_path.read_bytes());self.assertEqual(changed['engineering_selection'],selection)
                self.assertEqual(changed['engineering_update']['selection']['manifest_sha256'],header['manifest_sha256'])
                self.assertEqual(list((control/'grants').iterdir()),[])
                self.assertEqual((control/'controller.py').read_bytes(),b'canonical engine')
                self.assertFalse((root/'tmp/controller-update').exists())
                before=policy_path.read_bytes()
                with self.assertRaisesRegex(ValueError,'Prior update staging'):b.stage_engineering_update(io.BytesIO(),header['release_id'],header['manifest_sha256'])
                self.assertEqual(policy_path.read_bytes(),before)

if __name__=='__main__':unittest.main()
