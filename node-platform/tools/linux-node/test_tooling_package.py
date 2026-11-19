"""Tool-only releases retain sealed native bytes; no host operations occur."""
import json
import unittest

import build_package as build
import synergy_linux as node
import test_existing_root_package as fixture


class ToolingPackageTests(unittest.TestCase):
    def setUp(self):
        fixture.ExistingRootPackageTests.setUp(self)
        for name in build.TOOLS:
            (self.base/'tools'/name).write_bytes(b'baseline tooling\n')
        self.files={p.relative_to(self.base).as_posix():node.digest(p)
                    for p in self.base.rglob('*') if p.is_file() and p.name!='package.json'}
        self.manifest=json.loads((self.base/'package.json').read_text())
        self.manifest.update(files=self.files,native_build={'source_sha256':'b'*64,'locked':True},
                             native_artifacts={'synergy-node':self.files['bin/synergy-node']})
        (self.base/'package.json').write_text(json.dumps(self.manifest))
        self.pin=node.digest(self.base/'package.json')

    def tearDown(self):self.temp.cleanup()

    def test_full_canonical_tools_update_without_claiming_native_rebuild_or_legacy_root(self):
        result=build.compose_tooling_update(self.base,self.output,self.pin)
        manifest=node.verify_package(self.output)
        self.assertFalse(result['qualified'])
        self.assertTrue(result['release_id'].startswith('synergy-linux-tooling-'))
        self.assertNotIn('existing_root_compatibility',manifest)
        self.assertEqual(manifest['native_build'],self.manifest['native_build'])
        self.assertEqual(manifest['native_artifacts'],self.manifest['native_artifacts'])
        self.assertEqual(manifest['runtime_baseline']['manifest_sha256'],self.pin)
        changed={'tools/'+name for name in build.TOOLS}
        self.assertEqual(manifest['runtime_baseline']['immutable_files'],
                         {n:h for n,h in self.files.items() if n not in changed})
        for name,pin in self.files.items():
            self.assertEqual(node.digest(self.base/name),pin)
            if name not in changed:self.assertEqual(node.digest(self.output/name),pin)
        for name in build.TOOLS:
            self.assertEqual((self.output/'tools'/name).read_bytes(),
                             (build.SOURCE/'tools/linux-node'/name).read_bytes())
        for name in node.VOLATILE:self.assertEqual(list((self.output/name).iterdir()),[])

    def test_tooling_mode_rejects_legacy_base_and_missing_tools(self):
        self.manifest['existing_root_compatibility']='/opt/Synergy'
        (self.base/'package.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError,'lowercase base'):
            build.compose_tooling_update(self.base,self.output,node.digest(self.base/'package.json'))
        self.assertFalse(self.output.exists())
        self.manifest.pop('existing_root_compatibility')
        self.manifest['files'].pop('tools/controller.py')
        (self.base/'tools/controller.py').unlink()
        (self.base/'package.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError,'lacks canonical'):
            build.compose_tooling_update(self.base,self.output,node.digest(self.base/'package.json'))
        self.assertFalse(self.output.exists())

    def test_pin_native_tampering_and_runtime_state_cannot_enter_tooling_release(self):
        with self.assertRaisesRegex(ValueError,'pin mismatch'):
            build.compose_tooling_update(self.base,self.output,'0'*64)
        (self.base/'keys/fixture-secret').write_bytes(b'fixture only')
        with self.assertRaises(ValueError):
            build.compose_tooling_update(self.base,self.output,self.pin)
        (self.base/'keys/fixture-secret').unlink()
        (self.base/'bin/synergy-node').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'digest mismatch'):
            build.compose_tooling_update(self.base,self.output,self.pin)
        self.assertFalse(self.output.exists())
