"""Archive rejection tests for the fixed native bootstrap; no host enrollment."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import bootstrap as b


class BootstrapTests(unittest.TestCase):
    def archive(self,change=None):
        roles=['validator']+[f'role-{i}' for i in range(19)]
        files={'roles/roles.json':json.dumps({'roles':roles}).encode()}
        files.update({'tools/'+name:b'canonical engine' for name in b.ENGINE})
        manifest={'format':'synergy-universal-linux-v1','architecture':'x86_64','release_id':'qualified-test-only',
                  'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
        raw=json.dumps(manifest).encode()
        header={'manifest_sha256':hashlib.sha256(raw).hexdigest(),'release_id':manifest['release_id']}
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as tar:
            def add(name,value):
                info=tarfile.TarInfo(name);info.size=len(value);tar.addfile(info,io.BytesIO(value))
            add('package.json',raw)
            for name,value in files.items():add(name,value)
            if change:change(tar,add)
        data.seek(0)
        return data,header
    def test_valid_inventory_extracts_only_beneath_fresh_stage(self):
        data,header=self.archive()
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)/'Synergy';stage.mkdir()
            result=b.extract(data,stage,header)
            self.assertEqual(result['release_id'],'qualified-test-only')
            self.assertEqual(len(list((stage/'roles').iterdir())),21)
    def test_bad_manifest_pin_fails_before_payload_write(self):
        data,header=self.archive();header['manifest_sha256']='0'*64
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)
            with self.assertRaisesRegex(ValueError,'Manifest differs'):b.extract(data,stage,header)
            self.assertEqual(list(stage.iterdir()),[])
    def test_links_traversal_duplicates_and_undeclared_files_are_refused(self):
        def link(tar,add):
            info=tarfile.TarInfo('link');info.type=tarfile.SYMTYPE;info.linkname='/etc';tar.addfile(info)
        for change in (lambda tar,add:add('../escape',b'bad'),lambda tar,add:add('tools/controller.py',b'duplicate'),
                       lambda tar,add:add('unknown',b'bad'),link):
            data,header=self.archive(change)
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):b.extract(data,Path(temporary),header)
    def test_header_never_accepts_paths_commands_or_qualification_override(self):
        value={'version':1,'manifest_sha256':'0'*64,'release_id':'test','operator_public_key':'ssh-ed25519 '+'A'*68,
               'network_id':'isolated-test','chain_id':9,'node_name':'isolated'}
        self.assertEqual(b.public_header(json.dumps(value).encode()+b'\n'),value)
        for key in ('root','command','qualified_operations'):
            with self.assertRaises(ValueError):b.public_header(json.dumps(dict(value,**{key:'unsafe'})).encode()+b'\n')

    def test_bootstrap_refuses_installed_or_loaded_legacy_validator_units(self):
        scenarios = [
            ('synergy-node.service disabled disabled\n', None),
            ('synergy-vpn.service masked enabled\n', None),
            ('', 'synergy-posy-old.service loaded failed failed Old validator\n'),
        ]
        for installed, loaded in scenarios:
            with self.subTest(installed=installed, loaded=loaded):
                responses = [subprocess.CompletedProcess([], 0, stdout=installed)]
                if loaded is not None:
                    responses.append(subprocess.CompletedProcess([], 0, stdout=loaded))
                with patch.object(b.subprocess, 'run', side_effect=responses):
                    with self.assertRaisesRegex(ValueError, 'Legacy validator service'):
                        b.require_clean_service_namespace()

    def test_missing_validator_and_unrelated_services_do_not_block_clean_bootstrap(self):
        with patch.object(b.subprocess, 'run', side_effect=[
            subprocess.CompletedProcess([], 0, stdout='synergy-chain1266-role@.service enabled enabled\nssh.service enabled enabled\n'),
            subprocess.CompletedProcess([], 0, stdout='synergy-node.service not-found inactive dead\nssh.service loaded active running\n'),
        ]):
            b.require_clean_service_namespace()

if __name__=='__main__':unittest.main()
