import base64
import copy
import contextlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import controller
import r1_identity


def parameters():
    return dict(release_id='PUBLIC-TEST',manifest_sha256='01'*32,slot_ref='PUBLIC-ROOT-SLOT-1',
        role='root',algorithm='ML-DSA-87',key_generation='1',operation_nonce_hex='02'*32,
        creation_scope_frame_hex='80',creation_scope_commitment_hex='03'*64,
        provider_report_sha256='04'*32,profile_catalog_commitment_hex='05'*64)


def proof_parameters():
    creation=parameters();creation.update(role='node_birth_root',slot_ref='PUBLIC-VALIDATOR-ROOT')
    public={'role':'node_birth_root','algorithm':'ML-DSA-87','key_generation':1,'full_public_key_hex':'11'*2592}
    return {'creation':creation,'expected_journal_generation':'2','expected_envelope_commitment_hex':'22'*64,
        'public_key':public,'proof_plan':{'namespace':'synv1','expected_identity':'synv1.2.'+'A'*64,
            'birth_nonce_hex':'03'*32,'enrollment_nonce_hex':'04'*32,'birth_policy_frame_hex':'80',
            'current_policy_frame_hex':'80','node':{'node_class':1,'birth_root':dict(public),'role_keys':[]}}}


def identity_request(rebind=False):
    p=proof_parameters()
    if rebind:p={'pending':p,'original_creation_request_digest_hex':'33'*32}
    return {'version':1,'operation':'r1_identity_rebind' if rebind else 'r1_identity_prove','parameters':p}


def root_approval_request():
    creation=parameters()
    return {'version':1,'operation':'r1_root_approval_use','parameters':{
        'creation':creation,'root_index':0,'public_key':{'role':creation['role'],
            'algorithm':'ML-DSA-87','key_generation':1,'full_public_key_hex':'11'*2592},
        'stage':{'kind':'NIC'},'expected_journal_generation':'2',
        'expected_envelope_commitment_hex':'22'*64,'full_binding_aad_hex':'80',
        'original_creation_request_digest_hex':'33'*32,'operation_nonce_hex':'09'*32,
        'lifetime_seconds':'60'}}


class RootApprovalOperationBoundary(unittest.TestCase):
    # Structural carrier and mocked process outputs only; no accepted native
    # grant, actual root signature or live ceremony is asserted by these tests.
    def manifest(self,p):
        return ManagedIdentityOperationBoundary.manifest(self,p)

    def test_closed_root_dto_stages_full_widths_and_carrier_capacity(self):
        for stage in [{'kind':'NIC'},{'kind':'FORMATION','registry_commitment_hex':'44'*64,
            'input_commitment_hex':'55'*64},{'kind':'GENESIS','genesis_digest_hex':'66'*48}]:
            request=root_approval_request();request['parameters']['stage']=stage
            self.assertEqual(controller.parse_request(controller.canonical(request)),request)
        original=root_approval_request()['parameters']
        changes=[lambda p:p.update(approved=True),lambda p:p.update(root_index=True),
            lambda p:p.update(root_index=32),lambda p:p['public_key'].update(private_key='PUBLIC-NOT-SECRET'),
            lambda p:p['public_key'].update(full_public_key_hex='11'*1952),
            lambda p:p['public_key'].update(key_generation=True),
            lambda p:p.update(expected_journal_generation=str(2**64-2)),
            lambda p:p.update(lifetime_seconds='0'),lambda p:p.update(lifetime_seconds='301'),
            lambda p:p.update(lifetime_seconds=60),lambda p:p.update(operation_nonce_hex='00'*32),
            lambda p:p.update(full_binding_aad_hex='AA'),
            lambda p:p.update(stage={'kind':'NIC','genesis_digest_hex':'66'*48}),
            lambda p:p.update(stage={'kind':'GENESIS','genesis_digest_hex':'66'*32}),
            lambda p:p.update(stage={'kind':'FORMATION','registry_commitment_hex':'44'*32,'input_commitment_hex':'55'*64}),
            lambda p:p.update(stage={'kind':'FORMATION','registry_commitment_hex':'00'*64,'input_commitment_hex':'55'*64}),
            lambda p:p.update(stage={'kind':'ARBITRARY_MESSAGE'})]
        for mutate in changes:
            p=copy.deepcopy(original);mutate(p)
            with self.assertRaises(ValueError):r1_identity.validate_root_approval(p)
        request=root_approval_request();request['parameters']['full_binding_aad_hex']='80'*10000
        raw=controller.canonical(request);self.assertGreater(len(raw),controller.MAX_REQUEST)
        self.assertEqual(controller.parse_request(raw),request)
        request['parameters']['full_binding_aad_hex']='80'*r1_identity.MAX_IDENTITY_OPERATION_REQUEST
        with self.assertRaises(controller.Refused):controller.parse_request(controller.canonical(request))
        duplicate=controller.canonical(root_approval_request()).replace(b'"root_index":0',b'"root_index":0,"root_index":1')
        with self.assertRaises(controller.Refused):controller.parse_request(duplicate)

    def test_original_root_result_uses_approval_nonce_before_authorize_without_writes(self):
        request=root_approval_request();p=request['parameters'];creation=p['creation']
        original=base64.b64encode(b'PUBLIC-SYNTHETIC-ORIGINAL-ROOT-RECEIPT-ONLY').decode()
        with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-root-replay-') as tmp:
            c=controller.Controller(Path(tmp));before=list(c.root.iterdir())
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':creation['manifest_sha256']},self.manifest(creation))),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=json.dumps(original).encode()) as native:
                self.assertEqual(r1_identity.run_identity_operation(c,request),original)
                authorize.assert_not_called();native.assert_called_once()
                args=native.call_args.args[0]
                self.assertEqual(args[1],'read-managed-r1-root-approval-result')
                self.assertEqual(args[3],p['operation_nonce_hex'])
                self.assertNotEqual(args[3],creation['operation_nonce_hex'])
                self.assertEqual(args[4],controller.request_digest(request))
            self.assertEqual(list(c.root.iterdir()),before)

    def test_root_unknown_result_or_missing_grant_does_not_retry_crypto(self):
        request=root_approval_request();creation=request['parameters']['creation']
        for result in [ValueError('PUBLIC uncertain outcome'),b'null']:
            with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-root-refusal-') as tmp:
                c=controller.Controller(Path(tmp));before=list(c.root.iterdir())
                with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':creation['manifest_sha256']},self.manifest(creation))),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',side_effect=[result]) as native:
                    with self.assertRaises((ValueError,controller.Refused,FileNotFoundError)):
                        r1_identity.run_identity_operation(c,request)
                    authorize.assert_not_called();native.assert_called_once()
                self.assertEqual(list(c.root.iterdir()),before)

    def test_same_root_writer_consumes_grant_then_attributes_original_operation(self):
        request=root_approval_request();creation=request['parameters']['creation']
        original=base64.b64encode(b'PUBLIC-SYNTHETIC-MOCKED-ROOT-RESULT-ONLY').decode()
        with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-root-dispatch-') as tmp:
            c=controller.Controller(Path(tmp).resolve());grants=c.control/'grants';grants.mkdir(mode=0o700,parents=True)
            key=controller.request_digest(request);grant=grants/(key+'.json')
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(c.root),
                'community_enrollment':False,'qualified_operations':[request['operation']],'releases':{}}
            for path,value in [(c.control/'policy.json',policy),(grant,{'root':str(c.root),'request_sha256':key,'expires_at':int(time.time())+60})]:
                path.write_bytes(controller.canonical(value));path.chmod(0o600)
            calls=[]
            def native(argv,**kwargs):
                calls.append(argv[1])
                if argv[1]=='read-managed-r1-root-approval-result':
                    self.assertTrue(grant.exists());self.assertEqual(argv[3],request['parameters']['operation_nonce_hex']);return b'null'
                self.assertEqual(argv[1],'use-managed-r1-root-approval');self.assertFalse(grant.exists())
                audit=[json.loads(line) for line in (c.control/'audit.jsonl').read_bytes().splitlines()]
                self.assertEqual(audit[-1]['operation'],request['operation']);self.assertEqual(audit[-1]['request_sha256'],key)
                receipt=json.loads(Path(argv[3]).read_bytes());self.assertEqual(receipt['request'],request)
                self.assertEqual(receipt['request_sha256'],key);self.assertEqual(argv[4],key)
                return json.dumps(original).encode()
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':creation['manifest_sha256']},self.manifest(creation))),patch('synergy_linux.native',side_effect=native):
                self.assertEqual(r1_identity.run_identity_operation(c,request),original)
            self.assertEqual(calls,['read-managed-r1-root-approval-result','use-managed-r1-root-approval'])
            files,_=r1_identity.controller_inventory(c)
            self.assertIn('tmp/controller/r1-creation/'+key+'.json',files)

    def test_lost_mutation_result_preserves_receipt_and_never_reissues_before_original_read(self):
        request=root_approval_request();creation=request['parameters']['creation']
        public=base64.b64encode(b'PUBLIC-SYNTHETIC-ORIGINAL-AFTER-UNKNOWN-RESULT').decode()
        with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-root-unknown-') as tmp:
            c=controller.Controller(Path(tmp).resolve());grants=c.control/'grants';grants.mkdir(mode=0o700,parents=True)
            key=controller.request_digest(request);grant=grants/(key+'.json')
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(c.root),'community_enrollment':False,
                'qualified_operations':[request['operation']],'releases':{}}
            for path,value in [(c.control/'policy.json',policy),(grant,{'root':str(c.root),'request_sha256':key,'expires_at':int(time.time())+60})]:
                path.write_bytes(controller.canonical(value));path.chmod(0o600)
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':creation['manifest_sha256']},self.manifest(creation))),patch('synergy_linux.native',side_effect=[b'null',ValueError('PUBLIC lost mutation acknowledgement')]) as native:
                with self.assertRaises(ValueError):r1_identity.run_identity_operation(c,request)
                self.assertEqual(native.call_count,2)
            target=c.control/'r1-creation'/(key+'.json');before=target.read_bytes()
            self.assertFalse(grant.exists())
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':creation['manifest_sha256']},self.manifest(creation))),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=b'null') as native:
                with self.assertRaises(controller.Refused):r1_identity.run_identity_operation(c,request)
                authorize.assert_not_called();native.assert_called_once()
                native.return_value=json.dumps(public).encode()
                self.assertEqual(r1_identity.run_identity_operation(c,request),public)
                authorize.assert_not_called();self.assertEqual(native.call_count,2)
            self.assertEqual(target.read_bytes(),before)

    def test_root_operation_has_only_the_existing_internal_controller_dispatch(self):
        request=root_approval_request();c=controller.Controller(Path('/PUBLIC-NONEXISTENT-ROOT/synergy'))
        # Dispatch routing only: platform/installed-root qualification remains
        # the actual native owner, never an authority manufactured by this mock.
        with patch('controller.platform.system',return_value='Linux'),patch('controller.platform.machine',return_value='x86_64'),patch('synergy_linux.safe_root',return_value=c.root),patch.object(c,'exists',return_value=False),patch('r1_identity.run_identity_operation',return_value='PUBLIC-MOCKED-ROUTE-ONLY') as run:
            self.assertEqual(c.dispatch(request),'PUBLIC-MOCKED-ROUTE-ONLY')
            run.assert_called_once_with(c,request)


class ManagedIdentityOperationBoundary(unittest.TestCase):
    # Public syntax and mocked process results only: no genuine grant, identity,
    # provider, private Root completion token or cryptographic success is claimed.
    def manifest(self,p):
        return {'release_id':p['release_id'],'files':{'lib/apqe/build-report.json':p['provider_report_sha256'],
            'lib/apqe/r1-profile-catalog.cbor':'06'*32}}

    def test_exact_nested_dtos_preserve_full_public_keys_and_reject_secret_or_legacy_shapes(self):
        for rebind in [False,True]:
            request=identity_request(rebind);self.assertEqual(controller.parse_request(json.dumps(request).encode()),request)
        p=proof_parameters()
        for mutate in [lambda p:p.update(approved=True),lambda p:p['public_key'].update(private_key='PUBLIC-TEST-NOT-A-SECRET'),
            lambda p:p['public_key'].update(full_public_key_hex='11'*1952),lambda p:p['public_key'].update(key_generation=True),
            lambda p:p.update(expected_journal_generation=str(2**64-2)),lambda p:p['proof_plan'].update(expected_identity='a'*41),
            lambda p:p['proof_plan']['node'].update(node_class=5),lambda p:p['proof_plan'].update(birth_nonce_hex='03'*31)]:
            changed=copy.deepcopy(p);mutate(changed)
            with self.assertRaises(ValueError):r1_identity.validate_proof(changed)
        with self.assertRaises(ValueError):r1_identity.validate_rebind({'pending':p,'original_creation_request_digest_hex':'00'*32})
        p['proof_plan']['current_policy_frame_hex']='80'*9000
        raw=json.dumps({'version':1,'operation':'r1_identity_prove','parameters':p}).encode()
        self.assertGreater(len(raw),controller.MAX_REQUEST);controller.parse_request(raw)
        p['proof_plan']['current_policy_frame_hex']='80'*(1024*1024)
        with self.assertRaises(controller.Refused):controller.parse_request(json.dumps({'version':1,'operation':'r1_identity_prove','parameters':p}).encode())

    def test_completed_replay_returns_original_public_bytes_before_authorization_and_without_writes(self):
        public=base64.b64encode(b'PUBLIC-SYNTHETIC-ORIGINAL-RESULT-NOT-A-CRYPTO-PROOF').decode()
        for rebind in [False,True]:
            request=identity_request(rebind);p=request['parameters']['pending']['creation'] if rebind else request['parameters']['creation']
            with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-identity-replay-') as tmp:
                c=controller.Controller(Path(tmp));before=list(c.root.iterdir())
                with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},self.manifest(p))),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=json.dumps(public).encode()) as native:
                    self.assertEqual(r1_identity.run_identity_operation(c,request),public)
                    authorize.assert_not_called();native.assert_called_once()
                    self.assertIn('read-managed-r1-identity',native.call_args.args[0][1])
                self.assertEqual(list(c.root.iterdir()),before)

    def test_missing_grant_and_ambiguous_original_result_never_dispatch_new_crypto(self):
        request=identity_request();p=request['parameters']['creation']
        with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-identity-no-grant-') as tmp:
            c=controller.Controller(Path(tmp))
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},self.manifest(p))),patch.object(c,'public_json',return_value={'expires_at':1}),patch.object(c,'authorize',side_effect=controller.Refused('authorization_required','PUBLIC TEST missing grant')) as authorize,patch('synergy_linux.native',return_value=b'null') as native:
                with self.assertRaises(controller.Refused):r1_identity.run_identity_operation(c,request)
                authorize.assert_called_once();native.assert_called_once()
                self.assertFalse((c.control/'r1-creation').exists())
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},self.manifest(p))),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',side_effect=ValueError('PUBLIC TEST ambiguous durable result')) as native:
                with self.assertRaises(ValueError):r1_identity.run_identity_operation(c,request)
                authorize.assert_not_called();native.assert_called_once()
                self.assertFalse((c.control/'r1-creation').exists())

    def test_grant_consumption_fsync_failure_prevents_native_identity_and_root_approval_dispatch(self):
        for request in [identity_request(),identity_request(True),root_approval_request()]:
            p=request['parameters']['pending']['creation'] if request['operation']=='r1_identity_rebind' else request['parameters']['creation']
            with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-identity-grant-sync-') as tmp:
                c=controller.Controller(Path(tmp).resolve());grants=c.control/'grants';grants.mkdir(mode=0o700,parents=True)
                key=controller.request_digest(request);grant=grants/(key+'.json')
                policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(c.root),'community_enrollment':False,'qualified_operations':[request['operation']],'releases':{}}
                for path,value in [(c.control/'policy.json',policy),(grant,{'root':str(c.root),'request_sha256':key,'expires_at':int(time.time())+60})]:
                    path.write_bytes(controller.canonical(value));path.chmod(0o600)
                with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},self.manifest(p))),patch('controller.sync_directory',side_effect=OSError('PUBLIC TEST grant fsync failure')) as durable,patch('synergy_linux.native',return_value=b'null') as native:
                    with self.assertRaises(OSError):r1_identity.run_identity_operation(c,request)
                    durable.assert_called_once_with(grants);native.assert_called_once()
                self.assertFalse(grant.exists());self.assertTrue((c.control/'audit.jsonl').exists())
                self.assertFalse((c.control/'r1-creation').exists())

    def test_existing_unresolved_receipt_prevents_new_grant_or_crypto(self):
        request=identity_request();p=request['parameters']['creation']
        with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-identity-pending-') as tmp:
            c=controller.Controller(Path(tmp));directory=c.control/'r1-creation';directory.mkdir(mode=0o700,parents=True)
            target=directory/(controller.request_digest(request)+'.json');target.write_bytes(b'PUBLIC-SYNTHETIC-UNRESOLVED-RECEIPT')
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},self.manifest(p))),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=b'null') as native:
                with self.assertRaises(controller.Refused):r1_identity.run_identity_operation(c,request)
                authorize.assert_not_called();native.assert_called_once()
            self.assertEqual(target.read_bytes(),b'PUBLIC-SYNTHETIC-UNRESOLVED-RECEIPT')

    def test_mocked_dispatch_consumes_existing_exact_grant_before_receipt_and_attributes_it(self):
        public=base64.b64encode(b'PUBLIC-SYNTHETIC-ORCHESTRATION-RESULT-ONLY').decode()
        for rebind in [False,True]:
            request=identity_request(rebind);p=request['parameters']['pending']['creation'] if rebind else request['parameters']['creation']
            with tempfile.TemporaryDirectory(prefix='PUBLIC-SYNTHETIC-identity-dispatch-') as tmp:
                c=controller.Controller(Path(tmp).resolve());grants=c.control/'grants';grants.mkdir(mode=0o700,parents=True)
                key=controller.request_digest(request);grant=grants/(key+'.json')
                policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(c.root),'community_enrollment':False,'qualified_operations':[request['operation']],'releases':{}}
                for path,value in [(c.control/'policy.json',policy),(grant,{'root':str(c.root),'request_sha256':key,'expires_at':int(time.time())+60})]:path.write_bytes(controller.canonical(value));path.chmod(0o600)
                calls=[]
                def native(argv,**kwargs):
                    calls.append(argv[1])
                    if argv[1].startswith('read-'):self.assertTrue(grant.exists());return b'null'
                    self.assertFalse(grant.exists());self.assertTrue((c.control/'audit.jsonl').exists())
                    receipt=json.loads(Path(argv[3]).read_bytes());self.assertEqual(receipt['request'],request)
                    self.assertEqual(receipt['request_sha256'],key);self.assertEqual(argv[4],key)
                    self.assertEqual(receipt['format'],'synergy-native-r1-creation-v1')
                    return json.dumps(public).encode()
                with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},self.manifest(p))),patch('synergy_linux.native',side_effect=native):
                    self.assertEqual(r1_identity.run_identity_operation(c,request),public)
                self.assertEqual(len(calls),2)
                files,_=r1_identity.controller_inventory(c);self.assertIn('tmp/controller/r1-creation/'+key+'.json',files)

    def test_objects_flags_noncanonical_base64_and_null_cannot_claim_completed_result(self):
        for value in [{'approved':True,'production':False},'', 'AB==','AAAA\n',True]:
            with self.assertRaises(controller.Refused):r1_identity._original_public_result(json.dumps(value).encode())
        for raw in [b'not JSON',b'\xff']:
            with self.assertRaises(controller.Refused):r1_identity._original_public_result(raw)


class R1NativeBoundary(unittest.TestCase):
    def test_grant_removal_must_be_durable_before_any_creation_dispatch(self):
        p=parameters();request=dict(version=1,operation='r1_identity_generate',parameters=p)
        with tempfile.TemporaryDirectory(prefix='synergy-public-grant-fence-') as tmp:
            c=controller.Controller(Path(tmp).resolve());grants=c.control/'grants'
            grants.mkdir(mode=0o700,parents=True)
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(c.root),
                'community_enrollment':False,'qualified_operations':['r1_identity_generate'],'releases':{}}
            key=controller.request_digest(request);grant=grants/(key+'.json')
            for path,value in ((c.control/'policy.json',policy),(grant,{
                'root':str(c.root),'request_sha256':key,'expires_at':int(time.time())+60})):
                path.write_text(json.dumps(value));path.chmod(0o600)
            manifest={'release_id':p['release_id'],'files':{
                'lib/apqe/build-report.json':p['provider_report_sha256'],'lib/apqe/r1-profile-catalog.cbor':'06'*32}}
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},manifest)),patch('controller.sync_directory',side_effect=OSError('PUBLIC TEST fsync failure')) as durable,patch('synergy_linux.native') as native:
                with self.assertRaises(OSError):r1_identity.run(c,request)
                durable.assert_called_once_with(grants);native.assert_not_called()
            self.assertFalse(grant.exists())
            self.assertTrue((c.control/'audit.jsonl').exists())
            self.assertFalse((c.control/'r1-creation').exists())

    def test_preview_correlates_prospective_creation_without_authorization_or_state(self):
        p=parameters();request=dict(version=1,operation='r1_identity_preview',parameters=p)
        self.assertEqual(controller.parse_request(json.dumps(request).encode()),request)
        inspection={name:p[name] for name in ('release_id','slot_ref','operation_nonce_hex',
            'manifest_sha256','provider_report_sha256','profile_catalog_commitment_hex','creation_scope_commitment_hex')}
        inspection.update(authority_granted=False,scope={**{name:p[name] for name in
            ('role','algorithm','key_generation')},'authority_granted':False})
        result={'schema':'synergy-r1-managed-creation-preview-v1','inspection':inspection,
            'runtime_authority_granted':False}
        c=controller.Controller(Path('/PUBLIC-NONPRODUCTION-NOT-INSTALLED'))
        with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt'),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=json.dumps(result).encode()) as native:
            observed=r1_identity.preview(c,request)
            self.assertEqual(observed['creation_request_sha256'],controller.request_digest(
                {**request,'operation':'r1_identity_generate'}))
            self.assertNotEqual(observed['creation_request_sha256'],controller.request_digest(request))
            authorize.assert_not_called();native.assert_called_once()
            inspection['scope']['authority_granted']=True
            native.return_value=json.dumps(result).encode()
            with self.assertRaises(controller.Refused):r1_identity.preview(c,request)
            inspection['scope']['authority_granted']=False
            inspection['slot_ref']='OTHER-PUBLIC-SLOT'
            native.return_value=json.dumps(result).encode()
            with self.assertRaises(controller.Refused):r1_identity.preview(c,request)

    def test_consumed_receipt_directory_is_attributed_without_accepting_foreign_files(self):
        with tempfile.TemporaryDirectory(prefix='synergy-public-receipt-inventory-') as tmp:
            c=controller.Controller(Path(tmp));directory=c.control/'r1-creation'
            directory.mkdir(mode=0o700,parents=True)
            self.assertEqual(r1_identity.controller_inventory(c),(set(),{'tmp/controller/r1-creation'}))
            (directory/'foreign.txt').write_text('PUBLIC TEST ONLY')
            with self.assertRaises(controller.Refused):r1_identity.controller_inventory(c)
    def test_status_observes_original_request_without_new_grant_or_dispatch(self):
        p={'slot_ref':'PUBLIC-ROOT-SLOT-1','original_request_sha256':'01'*32}
        request={'version':1,'operation':'r1_identity_status','parameters':p}
        self.assertEqual(controller.parse_request(json.dumps(request).encode()),request)
        result={'schema':'synergy-r1-managed-key-status-v1','stage':'absent',**p,'runtime_authority_granted':False}
        c=controller.Controller(Path('/PUBLIC-NONPRODUCTION-NOT-INSTALLED'))
        with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt'),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=json.dumps(result).encode()) as native:
            self.assertEqual(r1_identity.status(c,request),result)
            authorize.assert_not_called();native.assert_called_once()
    def test_closed_request_preserves_full_width_pins_and_exact_generation(self):
        p=parameters();r1_identity.validate(p)
        request=dict(version=1,operation='r1_identity_generate',parameters=p)
        self.assertEqual(controller.parse_request(json.dumps(request).encode()),request)
        for key,value in [('key_generation',1),('key_generation','01'),('algorithm','FN-DSA-1024'),
            ('creation_scope_commitment_hex','03'*32),('provider_report_sha256','04'*64),
            ('operation_nonce_hex','00'*32),('creation_scope_frame_hex','AA')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                r1_identity.validate({**p,key:value})
        with self.assertRaises(ValueError):r1_identity.validate({**p,'authorized':True})
        with self.assertRaises(controller.Refused):controller.parse_request(json.dumps({**request,'parameters':{'genesis_sha256':'01'*32}}).encode())

    def test_missing_native_grant_cannot_dispatch_or_write_receipt(self):
        p=parameters();request=dict(version=1,operation='r1_identity_generate',parameters=p)
        with tempfile.TemporaryDirectory(prefix='synergy-public-controller-test-') as tmp:
            c=controller.Controller(Path(tmp));manifest={'release_id':p['release_id'],'files':{'lib/apqe/build-report.json':p['provider_report_sha256'],'lib/apqe/r1-profile-catalog.cbor':'06'*32}}
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},manifest)),patch.object(c,'public_json',return_value={'expires_at':1}),patch.object(c,'authorize',side_effect=controller.Refused('authorization_required','missing exact native grant')) as authorize,patch('synergy_linux.native') as native:
                with self.assertRaises(controller.Refused):r1_identity.run(c,request)
                authorize.assert_called_once_with(request);native.assert_not_called()
            self.assertFalse((c.control/'r1-creation').exists())


if __name__=='__main__':unittest.main()
