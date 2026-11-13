"""Offline package provenance tests; no validators or services are started."""
import json
from pathlib import Path
import tempfile
import unittest

import build_package as build
import synergy_linux as node


class ExistingRootPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.parent=Path(self.temp.name).resolve()
        self.base=self.parent/'base'; self.base.mkdir(mode=0o700)
        for directory in build.DIRECTORIES: (self.base/directory).mkdir(mode=0o700)
        roles=['validator']+['role_'+chr(97+i) for i in range(19)]
        for role in roles: (self.base/'roles'/role).mkdir(mode=0o700)
        node.write_new(self.base/'roles/roles.json',{'roles':roles,'implemented':['validator']})
        for name in ('synergy-node','synergy-keytool','synergy-genesis','netbird'):
            (self.base/'bin'/name).write_bytes(b'\x7fELF\x02\x01\x01'+bytes(11)+b'\x3e\x00')
        (self.base/'tools/synergy_linux.py').write_bytes(b'old root validator')
        (self.base/'tools/lifecycle.py').write_bytes(b'old lifecycle')
        self.files={p.relative_to(self.base).as_posix():node.digest(p)
                    for p in self.base.rglob('*') if p.is_file()}
        node.write_new(self.base/'package.json',{'format':node.MARKER,'architecture':'x86_64',
                       'release_id':'fixture','source_sha256':'a'*64,'files':self.files})
        self.pin=node.digest(self.base/'package.json')
        self.output=self.parent/'synergy'

    def tearDown(self): self.temp.cleanup()

    def test_only_compatibility_tools_change_and_native_provenance_is_retained(self):
        result=build.compose_existing_root_compatibility(self.base,self.output,self.pin)
        manifest=node.verify_package(self.output)
        self.assertFalse(result['qualified'])
        self.assertEqual(manifest['runtime_baseline']['manifest_sha256'],self.pin)
        self.assertEqual(manifest['runtime_baseline']['source_sha256'],'a'*64)
        for name,pin in self.files.items():
            if name not in ('tools/synergy_linux.py','tools/lifecycle.py'):
                self.assertEqual(node.digest(self.output/name),pin)
        for name in ('synergy_linux.py','lifecycle.py'):
            self.assertEqual((self.output/'tools'/name).read_bytes(),
                             (build.SOURCE/'tools/linux-node'/name).read_bytes())
        for name in node.VOLATILE: self.assertEqual(list((self.output/name).iterdir()),[])

    def test_mismatch_corruption_or_runtime_state_cannot_be_repackaged(self):
        with self.assertRaisesRegex(ValueError,'pin mismatch'):
            build.compose_existing_root_compatibility(self.base,self.output,'0'*64)
        self.assertFalse(self.output.exists())
        (self.base/'keys/secret').write_text('fixture only')
        with self.assertRaises(ValueError):
            build.compose_existing_root_compatibility(self.base,self.output,self.pin)
        self.assertFalse(self.output.exists())
        (self.base/'keys/secret').unlink()
        (self.base/'bin/synergy-node').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'digest mismatch'):
            build.compose_existing_root_compatibility(self.base,self.output,self.pin)
        self.assertFalse(self.output.exists())
