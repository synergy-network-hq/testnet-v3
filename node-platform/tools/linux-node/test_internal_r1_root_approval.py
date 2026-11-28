"""Public isolated writer tests; native crypto review is mocked explicitly.
No actual identities, credentials, installed-host grants or signatures.
"""
import base64,copy,hashlib,io,json,unittest
from contextlib import ExitStack
from unittest.mock import patch
import bootstrap as b
import controller as c
import test_r1_authorization as existing
class InternalRootApprovalTests(unittest.TestCase):
    setUp=existing.R1AuthorizationTests.setUp
    write=staticmethod(existing.R1AuthorizationTests.write)
    snapshot=existing.R1AuthorizationTests.snapshot
    def proposal(self):
        doc,inputs,_=existing.R1AuthorizationTests.proposal(self)
        selection=doc.pop('r1_creation')['context']['nic_selection']
        inputs.pop('r1/nic-approvals.json');inputs.pop('r1/release-acceptance.json')
        doc['profile']=b.INTERNAL_R1_APPROVAL_PROFILE
        doc['requests']=[{'operation':'r1_root_approval_use','request_sha256':'9'*64}]
        review={'chain_id':str(doc['chain_id']),'nic_selection':selection,'root_index':0,'stage':{'kind':'NIC'},'source':None}
        context={'managed_root':str(self.root),'chain_id':review['chain_id'],'nic_selection':selection,
            'pinned_birth_frame_hex':'80','pinned_root_threshold':1,'profile_catalog_commitment_hex':'c'*128,
            'root_index':0,'public_key':{'role':'bootstrap_root','algorithm':'ML-DSA-87','key_generation':1,'full_public_key_hex':'a1'*2592},
            'stage':review['stage'],'stage_source':{'kind':'PROSPECTIVE_PINNED_BIRTH','nic_hex':'a'*128,'profile_catalog_commitment_hex':'c'*128},
            'approval_plan_commitment_hex':'b'*128,'slot_ref':'PUBLIC-BOOTSTRAP-ROOT',
            'creation_scope_commitment_hex':'d'*128,'original_creation_request_digest_hex':'e'*64,
            'expected_journal_generation':'2','expected_envelope_commitment_hex':'f'*128,'full_binding_aad_hex':'80','max_lifetime_seconds':'60'}
        doc['r1_root_approval']={'review':review,'context':context}
        acceptance={'schema':'synergy-internal-r1-root-approval-release-acceptance-v1','scope':'INTERNAL_NETWORK_CEREMONY',
            'release_id':doc['release_id'],'manifest_sha256':doc['manifest_sha256'],'target':'linux-x86_64',
            'chain_id':review['chain_id'],'nic_hex':'a'*128,'profile_catalog_commitment_hex':'c'*128,
            'bootstrap_input_sha256':selection['pinned_bootstrap_input_sha256'],'catalog_sha256':selection['profile_catalog_sha256'],
            'allowed_stages':['NIC'],'qualification_evidence_sha256':['8'*64]}
        inputs['r1/root-approval-release-acceptance.json']=c.canonical(acceptance)
        doc['artifacts']={name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}
        self.current_doc=doc;return doc,inputs
    def native_review(self,argv,**kwargs):
        self.assertEqual(argv[:3],[self.root/'bin/synergy-keytool','review-managed-r1-root-approval-context',self.root])
        selected=json.loads(argv[3])['nic_selection']
        for key in ('pinned_bootstrap_input_path','profile_catalog_path'):
            self.assertTrue(selected[key].startswith('tmp/controller-authorization/authorization/inputs/'))
            self.assertTrue((self.root/selected[key]).is_file())
        self.assertFalse((self.root/selected['approvals_path']).exists())
        self.assertFalse(any((self.control/'grants').iterdir()))
        ctx=self.current_doc['r1_root_approval']['context']
        result={key:ctx[key] for key in ('chain_id','pinned_birth_frame_hex','pinned_root_threshold','profile_catalog_commitment_hex',
            'root_index','public_key','stage','stage_source','approval_plan_commitment_hex')}
        result.update(schema='synergy-r1-root-approval-context-review-v1',authority_granted=False,nic_hex='a'*128)
        if getattr(self,'tamper',False):result['approval_plan_commitment_hex']='1'*128
        return c.canonical(result)
    def stage(self,doc,inputs,accepted=True):
        raw=c.canonical(doc).decode();pin=hashlib.sha256(raw.encode()).hexdigest()
        wire=c.canonical({'authorization':raw,'artifacts':{name:base64.b64encode(data).decode() for name,data in inputs.items()}})
        with ExitStack() as stack:
            stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin,create=True))
            stack.enter_context(patch.object(c,'MUTATIONS',c.MUTATIONS|{'r1_root_approval_use'}))
            if accepted:stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_INTERNAL_R1_ROOT_APPROVAL_RELEASE_SHA256',doc['artifacts']['r1/root-approval-release-acceptance.json'],create=True))
            return b.stage_engineering_authorization(io.BytesIO(wire))
    def test_actual_review_precedes_atomic_grant_and_original_replay(self):
        doc,inputs=self.proposal();result=self.stage(doc,inputs)
        self.assertTrue(result['applied']);self.review.assert_called_once()
        policy=json.loads((self.control/'policy.json').read_bytes())
        self.assertEqual(policy['r1_root_approval_use_context'],doc['r1_root_approval']['context'])
        self.assertNotIn('r1_initial_creation_context',policy)
        self.assertEqual(policy['qualified_operations'],['r1_root_approval_use'])
        self.assertTrue((self.control/'grants'/('9'*64+'.json')).is_file())
        before=self.snapshot();again=self.stage(doc,inputs)
        self.assertTrue(again['reconciled']);self.assertFalse(again['grants_recreated'])
        self.assertEqual(before,self.snapshot());self.review.assert_called_once()
    def test_missing_independent_acceptance_refuses_before_stage_or_review(self):
        doc,inputs=self.proposal();before=self.snapshot()
        with self.assertRaises(c.Refused):self.stage(doc,inputs,accepted=False)
        self.assertEqual(before,self.snapshot());self.review.assert_not_called()
    def test_tampered_review_rolls_back_before_grant(self):
        doc,inputs=self.proposal();before=self.snapshot();self.tamper=True
        with self.assertRaises(ValueError):self.stage(doc,inputs)
        self.assertEqual(before,self.snapshot());self.assertFalse((self.root/'tmp/controller-authorization').exists())
    def test_internal_scope_refuses_user_creation_future_approval_and_foreign_source(self):
        doc,_=self.proposal()
        for change in [lambda d:d['requests'][0].update(operation='r1_identity_generate'),
            lambda d:d['r1_root_approval']['review'].update(source={'path':'future.json','sha256':'0'*64}),
            lambda d:d['r1_root_approval']['context'].update(genesis_selection={}),
            lambda d:d['r1_root_approval']['review']['nic_selection'].update(managed_root='/elsewhere')]:
            bad=copy.deepcopy(doc);change(bad)
            with self.assertRaises(ValueError):b.internal_r1_approval_selection(bad)
        self.review.assert_not_called()
if __name__=='__main__':unittest.main()
