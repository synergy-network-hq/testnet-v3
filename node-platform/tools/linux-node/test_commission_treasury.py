"""Fresh-key lifecycle regression: real inventory verifier, mocked crypto boundary only.

No custody is generated. Opaque fixture bytes are never exported or interpreted
as keys; native possession itself is independently qualified in keytool tests.
"""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import conformance
import controller
import lifecycle as life
import test_conformance as conformance_fixture

class CommissionTreasuryTests(unittest.TestCase):
    def fixture(self,base,treasury=True):
        root=Path(base).resolve()/'synergy';root.mkdir(mode=0o700)
        manifest,_=conformance_fixture.ConformanceTests().fixture(root)
        (root/'config/node.json').unlink()
        for path in (root/'network').iterdir():path.unlink()
        shutil.rmtree(root/'data')
        selection={'network_id':'synergy-posy-canary-20261117','chain_id':'99999','formation_sha256':'a'*64}
        request={'version':1,'operation':'treasury_prepare','parameters':{'formation_sha256':'a'*64,'effective_at_unix':100}}
        result={'schema':'nodenetwork-formation-treasury-v1','pending':True,'possession_verified':True,
                'request_sha256':controller.request_digest(request),'effective_at_unix':100,**selection}
        if treasury:
            directory=root/'keys/formation-treasury';directory.mkdir(mode=0o700)
            self.save(root/'tmp/treasury-prepare-request.json',controller.canonical(request))
            self.save(directory/'request.json',controller.canonical(request))
            for name in ('treasury-public.json','treasury.enc.json','unlock'):
                self.save(directory/name,b'opaque fixture, not generated custody\n')
        return root,manifest,selection,result
    def save(self,path,raw):path.write_bytes(raw);path.chmod(0o600)
    def snapshot(self,root):return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'keys').rglob('*') if p.is_file()}
    def verified(self,selection,result):
        from contextlib import ExitStack
        stack=ExitStack()
        stack.enter_context(patch.object(controller.Controller,'formation_context',return_value=(selection,[])))
        stack.enter_context(patch.object(controller.Controller,'formation_context_path',lambda owner:owner.root/'tmp/formation-context.json'))
        stack.enter_context(patch('synergy_linux.native',return_value=json.dumps(result).encode()))
        return stack
    def test_fresh_installed_conformance_accepts_only_existing_native_verified_treasury(self):
        for present in (False,True):
            with self.subTest(treasury=present),tempfile.TemporaryDirectory() as tmp:
                root,manifest,selection,result=self.fixture(tmp,present);before=self.snapshot(root)
                with self.verified(selection,result):self.assertTrue(conformance.installed(root,manifest,stage='fresh')['conformant'])
                self.assertEqual(self.snapshot(root),before)
    def test_commission_fresh_gate_preserves_all_treasury_bytes_and_revalidates_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            root,manifest,selection,result=self.fixture(tmp);before=self.snapshot(root)
            staged=root/'tmp/commissioning';staged.mkdir(mode=0o700)
            inputs={'network_id':selection['network_id'],'chain_id':99999,'node_name':'validator-02'}
            def final_check(*args):
                self.assertEqual(self.snapshot(root),before)
                self.assertTrue(conformance.approved_treasury_members(root))
            with self.verified(selection,result),patch.object(life,'_sealed_receipt',return_value=(inputs,manifest)),\
                 patch.object(life,'_validate_commissioning_native',return_value=inputs),\
                 patch.object(life,'_apply_commissioning') as apply,patch.object(life,'_fresh_conformance',side_effect=final_check),\
                 patch.object(life,'_integration_plan',return_value=None):
                self.assertEqual(life._commission_locked(root,staged,None),{'commissioned':True,'consensus_started':False,'production_approved':False})
                apply.assert_called_once_with(root,staged,inputs)
            self.assertEqual(self.snapshot(root),before)
    def test_unknown_incomplete_linked_modes_and_foreign_custody_refuse_before_apply(self):
        for kind in ('unknown-root','unknown-treasury','incomplete','file-link','directory-link','file-mode','directory-mode','keys-mode','intent-mismatch','foreign-scope','unverified'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root,manifest,selection,result=self.fixture(tmp);directory=root/'keys/formation-treasury'
                if kind=='unknown-root':self.save(root/'keys/unknown',b'unknown')
                elif kind=='unknown-treasury':self.save(directory/'unknown',b'unknown')
                elif kind=='incomplete':(directory/'unlock').unlink()
                elif kind=='file-link':(directory/'unlock').unlink();(directory/'unlock').symlink_to(root/'tmp/treasury-prepare-request.json')
                elif kind=='directory-link':directory.rename(root/'tmp/displaced');directory.symlink_to(root/'tmp/displaced',target_is_directory=True)
                elif kind=='file-mode':(directory/'unlock').chmod(0o644)
                elif kind=='directory-mode':directory.chmod(0o755)
                elif kind=='keys-mode':(root/'keys').chmod(0o755)
                elif kind=='intent-mismatch':self.save(root/'tmp/treasury-prepare-request.json',controller.canonical({'version':1,'operation':'treasury_prepare','parameters':{'formation_sha256':'a'*64,'effective_at_unix':101}}))
                elif kind=='foreign-scope':result['formation_sha256']='b'*64
                elif kind=='unverified':result['possession_verified']=False
                before=self.snapshot(root);staged=root/'tmp/commissioning';staged.mkdir(mode=0o700)
                with self.verified(selection,result),patch.object(life,'_sealed_receipt',return_value=({},manifest)),patch.object(life,'_apply_commissioning') as apply:
                    with self.assertRaises((ValueError,FileNotFoundError)):life._commission_locked(root,staged,None)
                    apply.assert_not_called()
                    with self.assertRaises((ValueError,FileNotFoundError)):conformance.installed(root,manifest,stage='fresh')
                self.assertEqual(self.snapshot(root),before)

if __name__=='__main__':unittest.main()
