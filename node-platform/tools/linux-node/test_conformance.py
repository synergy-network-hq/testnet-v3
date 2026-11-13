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
