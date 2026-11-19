"""Release drift, config and footprint rejection tests using disposable state."""
import copy
import json
import os
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import conformance as c
import build_package as builder
from configuration_schema import generate
from synergy_linux import digest
from test_consensus_schema import native_schema

SOURCE=Path(__file__).resolve().parents[2]

class ConformanceTests(unittest.TestCase):
    def test_upgrade_preflight_runs_guest_and_full_conformance_before_any_grant(self):
        import controller,lifecycle
        root=Path('/opt/synergy');owner=controller.Controller(root)
        package=root/'tmp/update-master';parameters={'release_id':'synergy-linux-fixture','manifest_sha256':'a'*64}
        req={'version':1,'operation':'upgrade_preflight','parameters':parameters}
        with patch.object(controller.platform,'system',return_value='Linux'),patch.object(controller.platform,'machine',return_value='x86_64'), \
             patch.object(owner,'approved_package',return_value=(package,{'release_id':parameters['release_id']},{})), \
             patch('synergy_linux.safe_root',return_value=root),patch.object(lifecycle,'_sealed_receipt'), \
             patch.object(lifecycle,'_integration_plan',return_value={}),patch.object(lifecycle,'_installation_stage',return_value='fresh'), \
             patch.object(owner,'public_json',return_value={'schema':'fixture'}),patch.object(owner,'authorize') as authorize, \
             patch('guest_lifecycle.require_upgrade_compatible') as guest,patch.object(c,'installed') as installed:
            for failure in ('guest','conformance',None):
                guest.side_effect=ValueError('guest refusal') if failure=='guest' else None
                installed.side_effect=ValueError('conformance refusal') if failure=='conformance' else None
                if failure:
                    with self.subTest(failure=failure),self.assertRaises(ValueError):owner.dispatch(req)
                else:
                    self.assertTrue(owner.dispatch(req)['packageVerified'])
            authorize.assert_not_called()
            installed.assert_called_with(root,host=True,stage='fresh',schema={'schema':'fixture'},
                                         allow_legacy_integrations=True,pending_upgrade_sha256='a'*64)

    def vpn_attempt_fixture(self,temporary,pending=False):
        import hashlib
        import controller
        import vpn
        from test_controller_startup import IsolatedControllerStartupTests
        root=IsolatedControllerStartupTests().fixture(temporary);(root/'evidence').mkdir(mode=0o700)
        control=root/'tmp/controller';inputs=control/'authorization/inputs';inputs.mkdir(parents=True,mode=0o700);inputs.parent.chmod(0o700)
        policy=json.loads((control/'policy.json').read_bytes())
        policy.update(engineering_selection={'manifest_sha256':'a'*64,'network_id':'fixture-network','chain_id':99999},
                      engineering_target={'kind':'remote','host':'fixture.invalid','port':22,'root':str(root)},validator_formation_sha256='b'*64,authorization_files={})
        original=root/'evidence/vpn-enrollment-attempt.json';original.write_text('{"format":"nodenetwork-vpn-attempt-v1"}');original.chmod(0o600)
        provider={'account_id':'account'};provider_path=inputs/'vpn-provider.json';provider_path.write_text(json.dumps(provider));provider_path.chmod(0o600)
        policy['authorization_files']['vpn-provider.json']=digest(provider_path)
        (control/'policy.json').write_text(json.dumps(policy))
        owner=controller.Controller(root);binding=owner.vpn_provider_binding()
        receipt={'format':'nodenetwork-vpn-unused-cancellation-v1','binding':binding,'provider_sha256':hashlib.sha256(controller.canonical(provider)).hexdigest(),
                 'account_id':'account','setup_key_id':'key','name':'nn-'+hashlib.sha256(controller.canonical(binding)).hexdigest()[:60],
                 'intent_sha256':'c'*64,'attempt_sha256':digest(original),'unused_verified':True,'setup_key_absent':True,'peer_absence_verified':True}
        if pending:
            artifact=inputs/'vpn-unused-cancellation.json';artifact.write_bytes(controller.canonical(receipt));artifact.chmod(0o600)
            policy['authorization_files']['vpn-unused-cancellation.json']=digest(artifact);(control/'policy.json').write_text(json.dumps(policy))
            request={'version':1,'operation':'vpn_cancel_unused','parameters':{'attempt_sha256':digest(original)}};key=controller.request_digest(request)
            grant={'root':str(root),'operation':'vpn_cancel_unused','request_sha256':key,'binding_sha256':digest(artifact),
                   'authorization_sha256':'d'*64,'authorization_sequence':3,'expires_at':1}
            intent={'format':'nodenetwork-vpn-cancel-intent-v1','request_sha256':key,'receipt_sha256':vpn.public_hash(receipt),'attempt_sha256':digest(original),'grant':grant}
            path=root/'evidence/vpn-cancel-unused-intent.json';path.write_text(json.dumps(intent));path.chmod(0o600)
        else:vpn.append_attempt_event(root,{'kind':'cancel','receipt':receipt})
        return root,receipt

    def test_exact_cancel_history_is_accepted_and_wrong_original_scope_refused(self):
        import vpn
        with tempfile.TemporaryDirectory() as temporary:
            root,receipt=self.vpn_attempt_fixture(temporary)
            self.assertIn(vpn.ATTEMPTS,c.approved_vpn_attempt_members(root))
            self.assertTrue(any(rule.fullmatch(vpn.ATTEMPTS) for rule in c.RULES))
            for field,value in [('attempt_sha256','f'*64),('binding',{}),('provider_sha256','f'*64),('unused_verified',False)]:
                changed=copy.deepcopy(receipt);changed[field]=value
                path=root/vpn.ATTEMPTS;path.write_text(json.dumps({'format':'nodenetwork-vpn-attempts-v1','events':[{'kind':'cancel','receipt':changed}]}))
                with self.subTest(field=field),self.assertRaises(ValueError):c.approved_vpn_attempt_members(root)

    def test_pending_cancellation_preserves_expired_audited_grant_but_rejects_wrong_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,_=self.vpn_attempt_fixture(temporary,pending=True)
            name='evidence/vpn-cancel-unused-intent.json';self.assertIn(name,c.approved_vpn_attempt_members(root))
            path=root/name;original=json.loads(path.read_bytes())
            for key in ('request_sha256','binding_sha256','root','operation'):
                changed=copy.deepcopy(original);changed['grant'][key]='wrong';path.write_text(json.dumps(changed))
                with self.subTest(key=key),self.assertRaises(ValueError):c.approved_vpn_attempt_members(root)
            path.write_text(json.dumps(original));path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'Unsafe VPN attempt evidence'):c.approved_vpn_attempt_members(root)

    def test_cancel_history_link_and_capacity_do_not_expand_runtime_allowlist(self):
        import vpn
        with tempfile.TemporaryDirectory() as temporary:
            root,receipt=self.vpn_attempt_fixture(temporary);path=root/vpn.ATTEMPTS
            original=path.read_bytes();path.unlink();path.symlink_to(root/'evidence/vpn-enrollment-attempt.json')
            with self.assertRaisesRegex(ValueError,'Unsafe VPN attempt evidence'):c.approved_vpn_attempt_members(root)
            path.unlink();path.write_bytes(original);path.chmod(0o600)
            path.write_text(json.dumps({'format':'nodenetwork-vpn-attempts-v1','events':[{'kind':'cancel','receipt':receipt}]*129}))
            with self.assertRaises(ValueError):c.approved_vpn_attempt_members(root)
            for name in ('evidence/vpn-attempts-2.json','evidence/vpn-cancel-unused-intent-extra.json'):
                self.assertFalse(any(rule.fullmatch(name) for rule in c.RULES))

    def test_epoch_scoped_processing_store_is_exactly_inventoried(self):
        import re
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir()
            manifest,_=self.fixture(root)
            directory=root/'data/blocks/processing-proposal-inputs-v1-epoch-00000000000000000002'
            directory.mkdir(parents=True,exist_ok=True)
            (directory/'proposal-inputs-v1.json').write_text('{}')
            pending=root/'data/etdag/protected-pipeline/processing-v1-epoch-00000000000000000002'
            pending.mkdir(parents=True)
            (pending/'pending-v1.json').write_text('{}')
            for member in ('slots','completions','finalized','progress'):
                (pending/member).mkdir()
                (pending/member/'0000.json').write_text('{}')
            self.assertTrue(c.installed(root,manifest)['conformant'])
        for suffix in ('-epoch-2','-epoch-00000000000000000002-extra','-epoch-../../keys'):
            path='data/blocks/processing-proposal-inputs-v1'+suffix
            self.assertFalse(any(re.fullmatch(rule,path) for rule in c.RUNTIME_DIRECTORIES))
            self.assertFalse(any(rule.fullmatch(path+'/proposal-inputs-v1.json') for rule in c.RULES))
            path='data/etdag/protected-pipeline/processing-v1'+suffix
            self.assertFalse(any(re.fullmatch(rule,path) for rule in c.RUNTIME_DIRECTORIES))
            self.assertFalse(any(rule.fullmatch(path+'/pending-v1.json') for rule in c.RULES))

    def network_formation_fixture(self, root, signed=False):
        from controller import request_digest
        selection={'formation_sha256':'a'*64,'network_id':'fixture','chain_id':'9001'}
        prepare={'version':1,'operation':'network_formation_prepare','parameters':{
            'formation_sha256':'a'*64,'recipe_json':'{}','registrations_json':['{}']*5}}
        signing={'version':1,'operation':'network_formation_sign','parameters':{'review_sha256':'b'*64}}
        directory=root/'tmp/network-formation';directory.mkdir(mode=0o700)
        names={'request.json','recipe.json','unsigned-genesis.json','unsigned-authority.json',
               'authority-root.pub','authority.enc.json','review.json','unlock'}
        names |= {f'registration-{i}.json' for i in range(5)}
        for name in names:(directory/name).write_text('{}');(directory/name).chmod(0o600)
        raw=json.dumps(prepare,sort_keys=True,separators=(',',':'),ensure_ascii=False)
        (directory/'request.json').write_text(raw)
        prepared=root/'tmp/network-formation-prepare-request.json';prepared.write_text(raw);prepared.chmod(0o600)
        result={'schema':'nodenetwork-network-formation-v1','pending':True,'signed':signed,
                **selection,'request_sha256':request_digest(prepare),'review_sha256':'b'*64}
        if signed:
            (directory/'signed').mkdir(mode=0o700)
            raw=json.dumps(signing,sort_keys=True,separators=(',',':'))
            for name in ('genesis.json','authority.json','sign-request.json'):
                path=directory/'signed'/name;path.write_text(raw if name=='sign-request.json' else '{}');path.chmod(0o600)
            path=root/'tmp/network-formation-sign-request.json';path.write_text(raw);path.chmod(0o600)
            result['sign_request_sha256']=request_digest(signing)
        return selection,result

    def test_native_verified_network_formation_normal_conformance_not_only_upgrade(self):
        for signed in (False,True):
            with self.subTest(signed=signed),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
                selection,result=self.network_formation_fixture(root,signed)
                with patch('controller.Controller.formation_context_path',return_value=root/'tmp/formation-context.json'), patch('controller.Controller.formation_context',return_value=(selection,[])), patch('synergy_linux.native',return_value=json.dumps(result)) as native:
                    self.assertTrue(c.installed(root,manifest)['conformant'])
                    self.assertEqual(native.call_args.args[0][1],'review-network-formation')

    def test_network_formation_exact_inventory_and_private_type_required(self):
        for defect in ('extra','missing','empty-directory','symlink','hardlink','mode','interrupted','request'):
            with self.subTest(defect=defect),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve()/'synergy';root.mkdir();self.fixture(root)
                selection,result=self.network_formation_fixture(root)
                directory=root/'tmp/network-formation'
                if defect=='extra':(directory/'old-key.json').write_text('{}')
                if defect=='missing':(directory/'review.json').unlink()
                if defect=='empty-directory':(directory/'extra').mkdir()
                if defect=='symlink':
                    (directory/'unlock').unlink();(directory/'unlock').symlink_to(root/'package.json')
                if defect=='hardlink':
                    (directory/'unlock').unlink();os.link(directory/'authority.enc.json',directory/'unlock')
                if defect=='mode':(directory/'unlock').chmod(0o644)
                if defect=='interrupted':(directory/'signed-pending').mkdir()
                if defect=='request':(directory/'request.json').write_text('{}')
                with patch('controller.Controller.formation_context_path',return_value=root/'tmp/formation-context.json'), patch('controller.Controller.formation_context',return_value=(selection,[])), patch('synergy_linux.native',return_value=json.dumps(result)):
                    with self.assertRaises(ValueError):c.approved_network_formation_members(root)

    def test_network_formation_native_failure_scope_and_sign_receipt_refused(self):
        for defect in ('provider','network_id','chain_id','formation_sha256','request_sha256','signed','sign_request_sha256','review_sha256'):
            with self.subTest(defect=defect),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve()/'synergy';root.mkdir();self.fixture(root)
                selection,result=self.network_formation_fixture(root,True)
                if defect!='provider':result[defect]=False if defect=='signed' else 'wrong'
                with patch('controller.Controller.formation_context_path',return_value=root/'tmp/formation-context.json'), patch('controller.Controller.formation_context',return_value=(selection,[])), patch('synergy_linux.native',side_effect=ValueError('provider refused') if defect=='provider' else None,return_value=json.dumps(result)):
                    with self.assertRaises(ValueError):c.approved_network_formation_members(root)

    def fixture(self, root):
        root.chmod(0o700)
        for relative in c.DIRECTORIES:(root/relative).mkdir(parents=True)
        (root/'assets/node-config.schema.json').write_text(json.dumps(generate(SOURCE)))
        (root/'bin/synergy-node').write_bytes(b'sealed fixture binary')
        (root/'roles/roles.json').write_text('{"roles":["validator"]}')
        (root/'roles/validator').mkdir()
        files={p.relative_to(root).as_posix():digest(p) for p in root.rglob('*') if p.is_file()}
        manifest={'files':files}
        (root/'package.json').write_text(json.dumps(manifest))
        (root/'installation.json').write_text(json.dumps({'root':str(root),'package_sha256':digest(root/'package.json'),'package_files':files}))
        config={'schema_version':1,'node_name':'validator-02','role':'validator','chain_id':9001,'network_id':'fixture',
                'manifest_path':str(root/'network/network-manifest.json'),'public_identity_path':str(root/'keys/p2p/id.identity.json'),
                'admin_socket_path':str(root/'run/admin.sock'),'storage':{'data_directory':str(root/'data')}}
        (root/'config/node.json').write_text(json.dumps(config))
        for name in ('genesis.json','authority.json','authority-root.pub','network-manifest.json','p2p-bindings.json','transport-registry.json'):(root/'network'/name).write_text('{}')
        (root/'data/metadata').mkdir();(root/'data/metadata/schema-version').write_bytes(b'synergy-node-storage:1')
        for p in root.rglob('*'):os.chmod(p,0o700 if p.is_dir() else 0o600)
        (root/'bin/synergy-node').chmod(0o700)
        return manifest,config

    def test_exact_release_runtime_schema_and_independent_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            self.assertTrue(c.installed(root,manifest)['conformant'])
            p=root/'data/consensus/posy/finality';p.mkdir(parents=True)
            (p/'h7.json').write_text('{"independent":"state"}');os.chmod(p/'h7.json',0o600)
            self.assertTrue(c.installed(root,manifest)['conformant'])
            (p/'unknown-runtime.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'undeclared'):c.installed(root,manifest)

    def test_unknown_executable_and_empty_directory_are_not_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            extra=root/'data/obsolete-release';extra.mkdir()
            with self.assertRaisesRegex(ValueError,'undeclared'):c.installed(root,manifest)
            extra.rmdir();extra=root/'keys/root';extra.mkdir();secret=extra/'root.secret.key';secret.write_text('fixture');secret.chmod(0o700)
            with self.assertRaisesRegex(ValueError,'executable'):c.installed(root,manifest)

    def test_native_recovery_journal_is_declared_without_a_wildcard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            directory=root/'data/consensus/posy';directory.mkdir(parents=True)
            journal=directory/'recovery.json';journal.write_text('{}');journal.chmod(0o600)
            self.assertTrue(c.installed(root,manifest)['conformant'])
            (directory/'recovery-extra.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'undeclared'):c.installed(root,manifest)

    def test_live_delivery_atomic_stage_is_exactly_current_node_pid(self):
        self.assertTrue(c.live_delivery_stage(
            'data/consensus/posy/delivery.tmp-1234-9', 1234))
        for relative,pid in (
            ('data/consensus/posy/delivery.tmp-1235-9', 1234),
            ('data/consensus/posy/delivery.tmp-1234-unbounded', 1234),
            ('data/consensus/posy/other.tmp-1234-9', 1234),
            ('data/consensus/posy/delivery.tmp-1234-9', None),
        ):
            self.assertFalse(c.live_delivery_stage(relative,pid))

    def test_native_processing_group_digest_is_512_bits_not_block_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            directory=root/'data/blocks/processing-proposal-inputs-v1/certified-groups'
            directory.mkdir(parents=True,mode=0o700)
            member=directory/('ab'*64+'.json');member.write_text('{}');member.chmod(0o600)
            self.assertTrue(c.installed(root,manifest)['conformant'])
            member.rename(directory/('ab'*32+'.json'))
            with self.assertRaisesRegex(ValueError,'undeclared'):c.installed(root,manifest)

    def test_additive_archive_schema_and_exact_segment_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            directory=root/'data/consensus/posy';directory.mkdir(parents=True,mode=0o700)
            archive=directory/'consensus-evidence-v1.sqlite3'
            connection=sqlite3.connect(archive)
            native_schema(connection)
            connection.close();archive.chmod(0o600)
            segments=directory/'archive';segments.mkdir(mode=0o700)
            segment=segments/'segment-00000000000000000001.sya';segment.write_bytes(b'fixture');segment.chmod(0o600)
            # Conformance validates footprint/schema. Native storage verifies frames.
            self.assertTrue(c.installed(root,manifest)['conformant'])
            connection=sqlite3.connect(archive);connection.execute('CREATE TABLE obsolete(fixture INTEGER)');connection.commit();connection.close()
            with self.assertRaisesRegex(ValueError,'archive schema'):c.installed(root,manifest)
            connection=sqlite3.connect(archive);connection.execute('DROP TABLE obsolete');connection.commit();connection.close()
            segment.rename(segments/'segment-arbitrary.sya')
            with self.assertRaisesRegex(ValueError,'undeclared'):c.installed(root,manifest)

    def test_software_and_selected_release_drift_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            with self.assertRaisesRegex(ValueError,'selected canonical'):c.installed(root,{'files':{}})
            (root/'bin/synergy-node').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'software drift'):c.installed(root,manifest)

    def test_symlink_and_storage_format_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            (root/'data/link').symlink_to(root/'bin')
            with self.assertRaisesRegex(ValueError,'symlink'):c.installed(root,manifest)
            (root/'data/link').unlink();(root/'data/metadata/schema-version').write_bytes(b'wrong:1')
            with self.assertRaisesRegex(ValueError,'storage schema'):c.installed(root,manifest)

    def test_native_schema_rejects_unknown_nested_or_top_level_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();_,config=self.fixture(root)
            schema=generate(SOURCE)
            for dotted in ('diagnostics','consensus.extra_queue'):
                changed=copy.deepcopy(config)
                target=changed
                keys=dotted.split('.')
                for key in keys[:-1]:target=target.setdefault(key,{})
                target[keys[-1]]=42
                with self.assertRaisesRegex(ValueError,'unknown'):c.validate_schema(changed,schema)
            self.assertEqual(schema,json.loads((SOURCE/'schemas/node-config.schema.json').read_text()))

    def test_only_documented_identity_parameters_normalize(self):
        config={'node_name':'a','chain_id':9001,'network_id':'n','consensus':{'signing_key_path':'/opt/synergy/keys/a','round_timeout_ms':5000}}
        different=copy.deepcopy(config);different['node_name']='b';different['consensus']['signing_key_path']='/opt/synergy/keys/b'
        self.assertEqual(c.normalized_config(config,Path('/opt/synergy')),c.normalized_config(different,Path('/opt/synergy')))
        different['consensus']['round_timeout_ms']=6000
        self.assertNotEqual(c.normalized_config(config,Path('/opt/synergy')),c.normalized_config(different,Path('/opt/synergy')))

    def test_endpoint_normalization_preserves_ports_scope_and_count(self):
        config={'network':{'listen_addresses':['10.1.0.1:5622'],
                           'advertised_addresses':['[fd01::1]:5622']}}
        normalized=lambda value:c.normalized_config(value,Path('/opt/synergy'))
        same=copy.deepcopy(config)
        same['network']['listen_addresses']=['10.1.0.2:5622']
        same['network']['advertised_addresses']=['[fd01::2]:5622']
        self.assertEqual(normalized(config),normalized(same))
        for endpoints in (['10.1.0.2:5623'],['0.0.0.0:5622'],['10.1.0.2:5622']*2):
            changed=copy.deepcopy(same);changed['network']['listen_addresses']=endpoints
            self.assertNotEqual(normalized(config),normalized(changed))

    def test_root_security_and_sealed_executable_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,_=self.fixture(root)
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'root ownership or permissions'):c.installed(root,manifest)
            root.chmod(0o700);(root/'bin/synergy-node').chmod(0o600)
            with self.assertRaisesRegex(ValueError,'software permissions'):c.installed(root,manifest)
            (root/'bin/synergy-node').chmod(0o700)
            link=Path(tmp).resolve()/'link';link.symlink_to(root)
            with self.assertRaisesRegex(ValueError,'non-symlink'):c.installed(link,manifest)

    def test_builder_binds_native_archive_format_and_forward_boundary(self):
        formats=builder.native_storage_formats()
        self.assertEqual(formats['consensus_evidence_sqlite'],2)
        self.assertEqual(formats['consensus_evidence_sqlite_readable'],[1,2])
        self.assertEqual(formats['consensus_archive_segment_header'],'SNPARC02')
        self.assertEqual(formats['downgrade_after_schema2_activation'],'unsupported')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'crates/synergy-posy/src/persistence';p.mkdir(parents=True)
            (p/'evidence_store.rs').write_text('const FORMAT: i64 = 3;')
            (p/'archive_segments.rs').write_text('const HEADER: &[u8; 8] = b"SNPARC03";')
            with self.assertRaisesRegex(ValueError,'compatibility review'):builder.native_storage_formats(root)

    def test_builder_refuses_stale_master_members_before_sealing(self):
        with tempfile.TemporaryDirectory() as tmp:
            master=Path(tmp)/'master';master.mkdir()
            expected=builder.desired_files(SOURCE/'tools/linux-node/templates')
            builder.check_master_inventory(master,expected,['validator'])
            (master/'lib').mkdir();stale=master/'lib/obsolete.so';stale.write_bytes(b'obsolete')
            with self.assertRaisesRegex(ValueError,'unexpected master'):builder.check_master_inventory(master,expected,['validator'])
            self.assertEqual(stale.read_bytes(),b'obsolete')
            stale.unlink();(master/'data').mkdir();(master/'data/old-release').mkdir()
            with self.assertRaisesRegex(ValueError,'unexpected master'):builder.check_master_inventory(master,expected,['validator'])

    def test_uncommissioned_checks_present_configuration_identity_and_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()/'synergy';root.mkdir();manifest,config=self.fixture(root)
            for path in (root/'network').iterdir():path.unlink()
            with patch('synergy_linux.verify_identity',return_value={'native_possession_verified':True}) as verify:
                self.assertTrue(c.installed(root,manifest,stage='uncommissioned')['identity_possession_verified'])
                verify.assert_called_once_with(root)
                config['unexpected']=1;(root/'config/node.json').write_text(json.dumps(config))
                with self.assertRaisesRegex(ValueError,'unknown field'):c.installed(root,manifest,stage='uncommissioned')
                (root/'config/node.json').unlink()
                self.assertTrue(c.installed(root,manifest,stage='uncommissioned')['conformant'])
                history=root/'data/consensus/posy';history.mkdir(parents=True)
                (history/'delivery.json').write_text('{}')
                with self.assertRaisesRegex(ValueError,'chain history'):c.installed(root,manifest,stage='uncommissioned')
            with self.assertRaisesRegex(ValueError,'initialized state'):c.installed(root,manifest,initialized=False)

if __name__=='__main__':unittest.main()
