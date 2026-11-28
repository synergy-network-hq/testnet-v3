"""Isolated writer-control tests. Public syntax fixtures, no real proof/RNG/host.

Only the native release acceptance and Rust proof-review boundaries are mocked;
actual scoped inventory, filesystem staging, audit/grant consumption and cleanup
run in disposable scratch. These tests do not qualify providers or any network.
"""
import base64
import copy
import ctypes
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
import bootstrap as b
import controller as c
import lifecycle
import r1_identity
import synergy_linux


class R1AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='synergy-public-r1-writer-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'synergy'
        self.control=self.root/'tmp/controller'
        (self.control/'tools').mkdir(mode=0o700,parents=True)
        (self.control/'grants').mkdir(mode=0o700)
        for path in (self.root,self.root/'tmp',self.control):path.chmod(0o700)
        pins={}
        for name in c.ENGINE_MODULES:
            path=self.control/name if name=='controller.py' else self.control/'tools'/name
            data=('PUBLIC TEST engine integrity fixture '+name).encode()
            path.write_bytes(data);path.chmod(0o600);pins[name]=hashlib.sha256(data).hexdigest()
        files={'bin/synergy-keytool':b'PUBLIC TEST nonexecutable binary integrity fixture',
               'lib/apqe/build-report.json':b'{"validation":false}',
               'lib/apqe/r1-profile-catalog.cbor':b'PUBLIC TEST package catalog fixture'}
        for name,data in files.items():
            path=self.root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(data);path.chmod(0o600)
        self.package={'format':'synergy-universal-linux-v1','architecture':'x86_64',
            'release_id':'PUBLIC-R1-SOFTWARE','files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
        self.write(self.root/'package.json',self.package)
        self.package_pin=hashlib.sha256((self.root/'package.json').read_bytes()).hexdigest()
        self.receipt={'format':self.package['format'],'root':str(self.root),'role':'validator',
            'network_id':'public-r1-writer-fixture','chain_id':99123,'node_name':'public-validator',
            'package_sha256':self.package_pin,'package_files':self.package['files']}
        self.write(self.root/'installation.json',self.receipt)
        self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),'community_enrollment':False,
            'qualified_operations':[],'engine_files':pins,'releases':{self.package['release_id']:{
                'manifest_sha256':self.package_pin,'inventory_authenticated':True,
                'networks':{self.receipt['network_id']:self.receipt['chain_id']}}}}
        self.write(self.control/'policy.json',self.policy)
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        real_stat,real_lstat=Path.stat,Path.lstat
        def owned(method):
            def metadata(path,*args,**kwargs):
                result=list(method(path,*args,**kwargs));result[4]=0;return os.stat_result(result)
            return metadata
        def exchange(_a,left,_b,right,_flags):
            left,right=Path(os.fsdecode(left)),Path(os.fsdecode(right));swap=left.with_name('public-test-exchange')
            left.rename(swap);right.rename(left);swap.rename(right);return 0
        for owner,name,value in [(b,'ROOT',self.root),(b.os,'geteuid',lambda:0),
                (b.sys,'platform','linux'),(b.os,'uname',lambda:SimpleNamespace(machine='x86_64')),
                (Path,'stat',owned(real_stat)),(Path,'lstat',owned(real_lstat)),
                (ctypes,'CDLL',lambda *args,**kwargs:SimpleNamespace(renameat2=exchange))]:
            self.stack.enter_context(patch.object(owner,name,value))
        self.stack.enter_context(patch.object(sys,'path',sys.path.copy()))
        self.stack.enter_context(patch.object(c.platform,'system',return_value='Linux'))
        self.stack.enter_context(patch.object(c.platform,'machine',return_value='x86_64'))
        self.stack.enter_context(patch('time.time',return_value=1000))
        self.stack.enter_context(patch.object(lifecycle,'_unit_state',return_value={'MainPID':'0','ActiveState':'inactive'}))
        self.stack.enter_context(patch.object(lifecycle,'_assert_no_application_processes'))
        self.acceptance=self.stack.enter_context(patch.object(b,'r1_creation_release_acceptance',wraps=b.r1_creation_release_acceptance))
        self.review=self.stack.enter_context(patch.object(synergy_linux,'native',side_effect=self.native_review))

    @staticmethod
    def write(path,value):
        path.write_bytes(c.canonical(value));path.chmod(0o600)

    def proposal(self,scope='initial',nonce='1'):
        inputs={'r1/birth.json':b'PUBLIC TEST birth, not an authenticated NIC',
                'r1/profile-catalog.cbor':b'PUBLIC TEST catalog, not a proof',
                ('r1/genesis-approvals.json' if scope=='runtime' else 'r1/nic-approvals.json'):b'PUBLIC TEST approval fixture'}
        if scope=='runtime':inputs['r1/genesis-core.cbor']=b'PUBLIC TEST Genesis fixture, never operational'
        pins={name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}
        acceptance={'schema':'nodenetwork-r1-creation-release-acceptance-v1',
            'release_id':self.package['release_id'],'manifest_sha256':self.package_pin,'target':'linux-x86_64',
            'chain_id':str(self.receipt['chain_id']),'nic_hex':'a'*128,'profile_catalog_commitment_hex':'c'*128,
            'bootstrap_input_sha256':pins['r1/birth.json'],'catalog_sha256':pins['r1/profile-catalog.cbor'],
            'allowed_scopes':['initial','formation','runtime'],'qualification_evidence_sha256':['e'*64]}
        inputs['r1/release-acceptance.json']=c.canonical(acceptance)
        pins['r1/release-acceptance.json']=hashlib.sha256(inputs['r1/release-acceptance.json']).hexdigest()
        selection={'managed_root':str(self.root),'pinned_bootstrap_input_path':'tmp/controller/authorization/inputs/r1/birth.json',
            'pinned_bootstrap_input_sha256':pins['r1/birth.json'],
            'profile_catalog_path':'tmp/controller/authorization/inputs/r1/profile-catalog.cbor',
            'profile_catalog_sha256':pins['r1/profile-catalog.cbor'],
            'approvals_path':'tmp/controller/authorization/inputs/'+('r1/genesis-approvals.json' if scope=='runtime' else 'r1/nic-approvals.json'),
            'expected_nic_hex':'a'*128}
        context={'chain_id':str(self.receipt['chain_id']),'allowed_roles':['node_birth_root']}
        if scope=='runtime':
            selection.update(core_path='tmp/controller/authorization/inputs/r1/genesis-core.cbor',expected_genesis_hex='b'*96)
            context.update(genesis_selection=selection,target_namespace='synv1',purpose='NODE_ENROLLMENT')
        else:
            context.update(nic_selection=selection,profile_catalog_commitment_hex='c'*128,
                selected_slots=['PUBLIC-VALIDATOR-ROOT'],custody_object_refs=['PUBLIC-CUSTODY-ROOT'])
            if scope=='formation':context.update(purpose='FORMATION_AUTHENTICATION',allowed_roles=['formation_authentication'])
            else:context.update(purpose='GENESIS_NODE',target_namespace='synv1')
        parameters={'release_id':self.package['release_id'],'manifest_sha256':self.package_pin,
            'slot_ref':'PUBLIC-VALIDATOR-ROOT','role':context['allowed_roles'][0],'algorithm':'ML-DSA-87',
            'key_generation':'1','operation_nonce_hex':nonce*64,'creation_scope_frame_hex':'80',
            'creation_scope_commitment_hex':'d'*128,'provider_report_sha256':self.package['files']['lib/apqe/build-report.json'],
            'profile_catalog_commitment_hex':'c'*128}
        request={'version':1,'operation':'r1_identity_generate','parameters':parameters}
        doc={'version':1,'profile':b.R1_AUTHORIZATION_PROFILE,
            'target':{'kind':'remote','host':'127.0.0.1','port':22281,'root':str(self.root),
                'machine_id_sha256':None,'host_key':'[127.0.0.1]:22281 ssh-ed25519 '+'A'*68},
            'release_id':self.package['release_id'],'manifest_sha256':self.package_pin,
            'network_id':self.receipt['network_id'],'chain_id':self.receipt['chain_id'],'node_name':self.receipt['node_name'],
            'sequence':1,'expires_at':1060,'artifacts':pins,
            'requests':[{'operation':'r1_identity_generate','request_sha256':c.request_digest(request)}],
            'genesis_pins':None,'r1_creation':{'scope':scope,'context':context}}
        return doc,inputs,request

    def native_review(self,argv,**kwargs):
        self.assertEqual(argv[:3],[self.root/'bin/synergy-keytool','review-managed-r1-creation-context',self.root])
        value=json.loads(argv[3]);context=value['context'];scope=value['scope']
        selected=context['genesis_selection' if scope=='runtime' else 'nic_selection']
        for key in ('pinned_bootstrap_input_path','profile_catalog_path','approvals_path')+ (('core_path',) if scope=='runtime' else ()):
            self.assertTrue(selected[key].startswith('tmp/controller-authorization/authorization/inputs/r1/'))
            self.assertTrue((self.root/selected[key]).is_file())
        self.assertFalse(any((self.control/'grants').iterdir()))
        return c.canonical({'schema':'synergy-r1-creation-context-review-v1','scope':scope,'chain_id':context['chain_id'],
            'nic_hex':selected['expected_nic_hex'],'profile_catalog_commitment_hex':'c'*128,
            'genesis_digest_hex':selected.get('expected_genesis_hex'),'creation_authority_granted':False})

    def stage(self,doc,inputs,initial=None,parent=None,nic='a'*128,acceptance_pin='from-isolated-test-owner'):
        raw=c.canonical(doc).decode();pin=hashlib.sha256(raw.encode()).hexdigest()
        wire=c.canonical({'authorization':raw,'artifacts':{name:base64.b64encode(data).decode() for name,data in inputs.items()}})
        with ExitStack() as stack:
            stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin,create=True))
            if nic is not None:stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_NIC_HEX',nic,create=True))
            stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_R1_RELEASE_ACCEPTANCE_SHA256',
                doc['artifacts']['r1/release-acceptance.json'] if acceptance_pin=='from-isolated-test-owner' else acceptance_pin,create=True))
            if initial is not None:stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',initial,create=True))
            if parent is not None:stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',parent,create=True))
            return b.stage_engineering_authorization(io.BytesIO(wire)),pin

    def snapshot(self):
        return {p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_exact_phase_proof_and_rebind_requests_do_not_require_generation_permission(self):
        for scope,operation in [('initial','r1_identity_prove'),('runtime','r1_identity_rebind')]:
            # Independent fixed public writer fixture per scope, with no crypto
            # or operation dispatch. Review remains explicitly mocked above.
            doc,inputs,_=self.proposal(scope);doc['requests']=[{'operation':operation,'request_sha256':'d'*64}]
            value,_,_=b.r1_creation_selection(doc);self.assertEqual(value['scope'],scope)
        doc,inputs,_=self.proposal();doc['requests']=[{'operation':'r1_identity_prove','request_sha256':'d'*64}]
        result,_=self.stage(doc,inputs)
        self.assertTrue(result['applied'])
        policy=json.loads((self.control/'policy.json').read_bytes())
        self.assertEqual(policy['qualified_operations'],['r1_identity_prove'])
        self.assertNotIn('r1_identity_generate',policy['qualified_operations'])
        self.assertTrue((self.control/'grants'/('d'*64+'.json')).is_file())
        self.assertFalse((self.root/'keys').exists());self.assertFalse((self.root/'network').exists())

    def test_formation_cannot_issue_identity_proof_or_rebind_and_initial_cannot_rebind(self):
        before=self.snapshot()
        for scope,operation in [('formation','r1_identity_prove'),('formation','r1_identity_rebind'),('initial','r1_identity_rebind')]:
            doc,inputs,_=self.proposal(scope);doc['requests']=[{'operation':operation,'request_sha256':'d'*64}]
            with self.assertRaises(ValueError):self.stage(doc,inputs)
            self.assertEqual(self.snapshot(),before)
        self.review.assert_not_called()

    def test_initial_writes_exact_context_after_review_without_genesis_or_identity(self):
        doc,inputs,request=self.proposal();result,_=self.stage(doc,inputs)
        policy=json.loads((self.control/'policy.json').read_bytes())
        self.assertTrue(result['applied']);self.review.assert_called_once();self.acceptance.assert_called_once()
        self.assertEqual(policy['r1_initial_creation_context'],doc['r1_creation']['context'])
        self.assertNotIn('validator_formation_sha256',policy);self.assertNotIn('r1_creation_context',policy)
        self.assertEqual(policy['qualified_operations'],['r1_identity_generate'])
        c.control_inventory(self.root)
        c.Controller(self.root).authorize(request)
        self.assertFalse((self.control/'grants'/(c.request_digest(request)+'.json')).exists())
        self.assertFalse((self.root/'keys').exists());self.assertFalse((self.root/'network').exists())

    def test_failed_native_review_or_false_authority_leaves_original_tree_and_no_grant(self):
        doc,inputs,_=self.proposal();before=self.snapshot()
        for outcome in [ValueError('PUBLIC TEST proof review rejection'),c.canonical({
                'schema':'synergy-r1-creation-context-review-v1','scope':'initial','chain_id':'99123',
                'nic_hex':'a'*128,'profile_catalog_commitment_hex':'c'*128,'genesis_digest_hex':None,'creation_authority_granted':True})]:
            if isinstance(outcome,Exception):self.review.side_effect=outcome
            else:self.review.side_effect=None;self.review.return_value=outcome
            with self.assertRaises(ValueError):self.stage(doc,inputs)
            self.assertEqual(self.snapshot(),before)
            self.assertFalse((self.root/'tmp/controller-authorization').exists())

    def test_replay_never_recreates_consumed_grant_and_new_request_uses_original_nic_lineage(self):
        doc,inputs,request=self.proposal();_,initial=self.stage(doc,inputs)
        c.Controller(self.root).authorize(request)
        self.assertTrue(self.stage(doc,inputs)[0]['reconciled']);self.assertEqual(self.review.call_count,1)
        self.assertFalse(any((self.control/'grants').iterdir()))
        nextdoc,nextinputs,_=self.proposal(nonce='2');nextdoc['sequence']=2
        result,_=self.stage(nextdoc,nextinputs,initial,initial)
        self.assertEqual(result['sequence'],2);self.assertEqual(self.review.call_count,2)
        self.assertNotIn('validator_formation_sha256',json.loads((self.control/'policy.json').read_bytes()))

    def test_consumed_hash_wrong_parent_wrong_nic_and_ambiguous_context_refuse_without_changes(self):
        doc,inputs,request=self.proposal();_,initial=self.stage(doc,inputs);c.Controller(self.root).authorize(request)
        before=self.snapshot();doc['sequence']=2
        for parent,nic in [(initial,'a'*128),('f'*64,'a'*128),(initial,'f'*128)]:
            with self.assertRaises(ValueError):self.stage(doc,inputs,initial,parent,nic)
            self.assertEqual(self.snapshot(),before)
        policy=json.loads((self.control/'policy.json').read_bytes());policy['r1_creation_context']={}
        self.write(self.control/'policy.json',policy);before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'Ambiguous'):self.stage(doc,inputs,initial,initial)
        self.assertEqual(self.snapshot(),before)

    def test_installed_validator_and_qualified_release_are_required_before_review(self):
        doc,inputs,_=self.proposal();before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'acceptance unavailable'):self.stage(doc,inputs,acceptance_pin=None)
        self.review.assert_not_called();self.assertEqual(self.snapshot(),before)
        self.receipt['role']='sentry';self.write(self.root/'installation.json',self.receipt);before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'user validator'):self.stage(doc,inputs)
        self.review.assert_not_called();self.assertEqual(self.snapshot(),before)
        (self.root/'installation.json').unlink();before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'already installed'):self.stage(doc,inputs)
        self.assertEqual(self.snapshot(),before)

    def test_closed_schema_rejects_account_root_infrastructure_paths_and_legacy_mixing(self):
        doc,inputs,_=self.proposal()
        changes=[lambda d:d.update(extra=True),lambda d:d['r1_creation'].update(extra=True),
            lambda d:d['r1_creation']['context'].update(purpose='GENESIS_ACCOUNT'),
            lambda d:d['r1_creation']['context'].update(target_namespace='synv2'),
            lambda d:d['r1_creation']['context'].update(allowed_roles=['root']),
            lambda d:d['r1_creation']['context']['nic_selection'].update(profile_catalog_path='../../outside'),
            lambda d:d.update(genesis_pins={'genesis.json':'e'*64,'authority.json':'f'*64,'authority-root.pub':'d'*64}),
            lambda d:d['requests'][0].update(operation='gateway_install'),
            lambda d:d['artifacts'].update({'formation-context.json':'e'*64})]
        before=self.snapshot()
        for change in changes:
            bad=copy.deepcopy(doc);change(bad)
            with self.assertRaises(ValueError):self.stage(bad,inputs)
            self.assertEqual(self.snapshot(),before)
        self.review.assert_not_called()
        legacy=copy.deepcopy(doc);legacy['profile']=b.AUTHORIZATION_PROFILE
        raw=c.canonical(legacy).decode()
        with self.assertRaises(ValueError):b.authorization_document(raw,hashlib.sha256(raw.encode()).hexdigest(),1000)

    def test_formation_then_runtime_preserves_nic_and_original_final_paths(self):
        doc,inputs,request=self.proposal('formation');_,initial=self.stage(doc,inputs)
        c.Controller(self.root).authorize(request)
        runtime,inputs,_=self.proposal('runtime',nonce='2');runtime['sequence']=2
        self.stage(runtime,inputs,initial,initial)
        policy=json.loads((self.control/'policy.json').read_bytes())
        self.assertEqual(policy['r1_creation_context'],runtime['r1_creation']['context'])
        self.assertNotIn('r1_formation_creation_context',policy)
        self.assertTrue((self.control/'authorization/inputs/r1/genesis-core.cbor').exists())
        self.assertFalse((self.root/'tmp/controller-authorization').exists())

    def test_acceptance_record_does_not_approve_its_own_digest_or_wrong_release_network_scope(self):
        doc,inputs,_=self.proposal();before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'owner pin'):self.stage(doc,inputs,acceptance_pin='0'*64)
        changes=[lambda r:r.update(extra=True),lambda r:r.update(manifest_sha256='f'*64),
            lambda r:r.update(release_id='DIFFERENT'),lambda r:r.update(target='darwin-aarch64'),
            lambda r:r.update(nic_hex='f'*128),lambda r:r.update(profile_catalog_commitment_hex='f'*128),
            lambda r:r.update(bootstrap_input_sha256='f'*64),lambda r:r.update(catalog_sha256='f'*64),
            lambda r:r.update(allowed_scopes=['runtime']),lambda r:r.update(allowed_scopes=['initial','initial']),
            lambda r:r.update(qualification_evidence_sha256=[]),lambda r:r.update(qualification_evidence_sha256=['e'*64,'e'*64])]
        for change in changes:
            bad=copy.deepcopy(doc);artifacts=dict(inputs);record=json.loads(artifacts['r1/release-acceptance.json']);change(record)
            artifacts['r1/release-acceptance.json']=c.canonical(record)
            bad['artifacts']['r1/release-acceptance.json']=hashlib.sha256(artifacts['r1/release-acceptance.json']).hexdigest()
            with self.assertRaises(ValueError):self.stage(bad,artifacts)
            self.assertEqual(self.snapshot(),before)
        self.review.assert_not_called()

    def test_native_review_wrong_network_profile_phase_or_extra_field_is_atomic_failure(self):
        doc,inputs,_=self.proposal();before=self.snapshot()
        expected={'schema':'synergy-r1-creation-context-review-v1','scope':'initial','chain_id':'99123',
            'nic_hex':'a'*128,'profile_catalog_commitment_hex':'c'*128,'genesis_digest_hex':None,'creation_authority_granted':False}
        for key,value in [('nic_hex','f'*128),('profile_catalog_commitment_hex','f'*128),
                ('chain_id','99124'),('scope','runtime'),('genesis_digest_hex','b'*96),('extra',True)]:
            wrong=dict(expected);wrong[key]=value;self.review.side_effect=None;self.review.return_value=c.canonical(wrong)
            with self.subTest(field=key),self.assertRaises(ValueError):self.stage(doc,inputs)
            self.assertEqual(self.snapshot(),before);self.assertFalse((self.root/'tmp/controller-authorization').exists())

    def test_same_phase_context_change_and_backwards_phase_cannot_replace_pending_authority(self):
        doc,inputs,request=self.proposal('runtime');_,initial=self.stage(doc,inputs)
        c.Controller(self.root).authorize(request);before=self.snapshot()
        backwards,inputs,_=self.proposal('initial',nonce='2');backwards['sequence']=2
        with self.assertRaisesRegex(ValueError,'backwards'):self.stage(backwards,inputs,initial,initial)
        self.assertEqual(self.snapshot(),before)
        changed,inputs,_=self.proposal('runtime',nonce='2');changed['sequence']=2
        changed['r1_creation']['context']['allowed_roles']=['consensus']
        with self.assertRaisesRegex(ValueError,'substituted'):self.stage(changed,inputs,initial,initial)
        self.assertEqual(self.snapshot(),before)

    def test_public_authorization_status_has_bounded_lineage_without_custody_or_future_identity(self):
        request={'version':1,'operation':'authorization_status','parameters':{}}
        before=c.Controller(self.root).dispatch(request)
        self.assertIsNone(before['r1_creation_network']);self.assertIsNone(before['r1_creation_scope'])
        self.assertIsNone(before['authorization']);self.assertIsNone(before['target']);self.assertIsNone(before['selection'])
        self.assertEqual(before['installed_role'],'validator')
        self.assertEqual(before['installed_selection'],{'release_id':self.package['release_id'],
            'manifest_sha256':self.package_pin,**{key:self.receipt[key] for key in ('network_id','chain_id','node_name')}})
        doc,inputs,_=self.proposal();self.stage(doc,inputs)
        status=c.Controller(self.root).dispatch(request)
        self.assertEqual(status['r1_creation_network'],{'chain_id':'99123','nic_hex':'a'*128,'profile_catalog_commitment_hex':'c'*128})
        self.assertEqual(status['r1_creation_scope'],'initial')
        self.assertNotIn('PUBLIC-CUSTODY-ROOT',json.dumps(status))
        policy=json.loads((self.control/'policy.json').read_bytes());policy['r1_creation_network']['nic_hex']='f'*129
        self.write(self.control/'policy.json',policy)
        with self.assertRaisesRegex(ValueError,'lineage'):c.Controller(self.root).dispatch(request)

    def test_self_service_first_stage_needs_no_old_engineering_or_nic_global_but_continuation_does(self):
        doc,inputs,request=self.proposal();_,initial=self.stage(doc,inputs,nic=None)
        c.Controller(self.root).authorize(request)
        nextdoc,nextinputs,_=self.proposal(nonce='2');nextdoc['sequence']=2;before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'exact R1 NIC'):self.stage(nextdoc,nextinputs,initial,initial,nic=None)
        self.assertEqual(self.snapshot(),before)

    def test_first_r1_after_install_only_authorization_uses_parent_without_fake_formation(self):
        doc,inputs,_=self.proposal();previous='f'*64;doc['sequence']=2
        policy=json.loads((self.control/'policy.json').read_bytes())
        policy.update(engineering_initial_authorization_sha256=previous,
            engineering_authorization={'sha256':previous,'sequence':1,'expires_at':1060},engineering_target=doc['target'],
            engineering_selection={key:doc[key] for key in ('release_id','manifest_sha256','network_id','chain_id','node_name')})
        self.write(self.control/'policy.json',policy)
        self.assertEqual(self.stage(doc,inputs,previous,previous,nic=None)[0]['sequence'],2)
        self.assertNotIn('validator_formation_sha256',json.loads((self.control/'policy.json').read_bytes()))

    def test_old_controller_inventory_and_active_node_refuse_before_review(self):
        doc,inputs,_=self.proposal();before=self.snapshot()
        with patch.object(c,'R1_AUTHORIZATION_FILES',{}):
            with self.assertRaisesRegex(ValueError,'input inventory'):self.stage(doc,inputs)
        with patch.object(lifecycle,'_unit_state',return_value={'MainPID':'123','ActiveState':'active'}):
            with self.assertRaisesRegex(ValueError,'Stop validator'):self.stage(doc,inputs)
        self.review.assert_not_called();self.assertEqual(self.snapshot(),before)


if __name__=='__main__':unittest.main()
