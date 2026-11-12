"""Offline package-boundary refusal tests; no native qualification claim."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_package as builder


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular non-symlink input required')
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Provenance:
    digest = staticmethod(digest)

    @staticmethod
    def inventory(_root):
        return {'source_revision': 'a' * 40, 'clean': True, 'files': []}

    @staticmethod
    def clean(value):
        return value['clean']


class PackageBoundaryTests(unittest.TestCase):
    def provider(self, root):
        report = {'validation': False, 'backend_policy': {'selected_backend': 'portable'},
                  'required_variant_count': 8, 'artifacts': []}
        for index in range(8):
            name = 'libaegisvariant' + str(index) + '.so'
            (root/name).write_bytes(b'independently-pinned-test-bytes-' + bytes([index]))
            report['artifacts'].append({'path': name, 'sha256': digest(root/name)})
        return report

    def save_report(self, root, report):
        path = root/'build-report.json'
        path.write_text(json.dumps(report))
        return digest(path)

    def test_complete_provider_and_copied_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = self.provider(root)
            files = builder.verify_apqe_provider(root, self.save_report(root, report), Provenance)
            self.assertEqual(len(files), 9)
            builder.verify_copied_provider(root, files, Provenance)
            (root/'libaegisvariant0.so').write_bytes(b'changed after authentication')
            with self.assertRaisesRegex(ValueError, 'copied APQE provider'):
                builder.verify_copied_provider(root, files, Provenance)

    def test_provider_traversal_duplicate_partial_validation_and_wrong_hash(self):
        changes = [
            lambda r: r['artifacts'][0].update(path='../escape.so'),
            lambda r: r['artifacts'][0].update(path='/absolute/libaegis0.so'),
            lambda r: r['artifacts'][1].update(path=r['artifacts'][0]['path']),
            lambda r: r['artifacts'].pop(),
            lambda r: r.update(required_variant_count=7),
            lambda r: r.update(validation=True),
            lambda r: r['backend_policy'].update(selected_backend='optimized'),
            lambda r: r['artifacts'][0].update(sha256='0'*64),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                report = self.provider(root)
                change(report)
                with self.assertRaises(ValueError):
                    builder.verify_apqe_provider(root, self.save_report(root, report), Provenance)

    def test_report_and_library_symlinks_refused(self):
        for link_report in (True, False):
            with self.subTest(report=link_report), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                report = self.provider(root)
                pin = self.save_report(root, report)
                path = root/('build-report.json' if link_report else 'libaegisvariant0.so')
                destination = root/'original'
                path.rename(destination)
                path.symlink_to(destination)
                with self.assertRaises(ValueError):
                    builder.verify_apqe_provider(root, pin, Provenance)

    def manifest(self):
        return {'format': 'synergy-native-linux-build-v1', 'source_sha256': 'source',
                'target': 'x86_64-unknown-linux-gnu', 'profile': 'release', 'locked': True,
                'dependency_sources': {'apqe': 'exact'},
                'native_compiler': {'rustc': 'rustc exact', 'cargo': 'cargo exact',
                                    'host': 'x86_64-unknown-linux-gnu'},
                'glibc_requirement': 'glibc >= 2.43',
                'artifacts': {name: {} for name in ('synergy-node','synergy-keytool','synergy-genesis')}}

    def test_native_manifest_rejects_missing_or_mismatched_bindings(self):
        changes = [lambda v: v.update(source_sha256='wrong'),
                   lambda v: v.update(profile='debug'),
                   lambda v: v.update(target='aarch64-unknown-linux-gnu'),
                   lambda v: v.update(locked=False),
                   lambda v: v.update(dependency_sources={}),
                   lambda v: v.pop('native_compiler'),
                   lambda v: v['native_compiler'].update(host='aarch64'),
                   lambda v: v['native_compiler'].update(cargo=''),
                   lambda v: v.pop('glibc_requirement'),
                   lambda v: v.update(glibc_requirement='any'),
                   lambda v: v.update(glibc_requirement='glibc >= 2.9'),
                   lambda v: v['artifacts'].pop('synergy-genesis')]
        with patch.object(builder, 'required_glibc', return_value='glibc >= 2.43'):
            self.assertEqual(builder.verify_prebuilt_manifest(self.manifest(), 'source', {'apqe':'exact'}, []), self.manifest())
            for index, change in enumerate(changes):
                with self.subTest(index=index):
                    value = self.manifest()
                    change(value)
                    with self.assertRaises(ValueError):
                        builder.verify_prebuilt_manifest(value, 'source', {'apqe':'exact'}, [])

    def test_glibc_derives_numeric_maximum_across_files_and_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            one, two = root/'one', root/'two'
            one.write_bytes(b'x'*(1024*1024-5) + b'GLIBC_2.43\0GLIBC_2.9\0')
            two.write_bytes(b'GLIBC_2.2.5\0GLIBC_PRIVATE\0')
            self.assertEqual(builder.required_glibc([one,two]),'glibc >= 2.43')
            two.write_bytes(b'no version symbols')
            with self.assertRaisesRegex(ValueError, 'requirements absent'):
                builder.required_glibc([two])

    def test_dependency_inventory_binds_source_and_rejects_symlink_or_dirty(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root/'network/core/node-platform'
            source.mkdir(parents=True)
            apqe = root/'network/21-Aegis-Engine/synergy-address-engine'
            apqe.mkdir(parents=True)
            rust = root/'rust'
            (rust/'src').mkdir(parents=True)
            (rust/'Cargo.toml').write_text('[package]\nname="test"\n')
            (rust/'src/lib.rs').write_text('first')
            (apqe/'Cargo.toml').write_text('aegis-selected-backend = { path = "'+str(rust)+'" }')
            with patch.object(builder, 'SOURCE', source):
                before = builder.dependency_sources(Provenance)
                (rust/'src/lib.rs').write_text('second')
                self.assertNotEqual(before, builder.dependency_sources(Provenance))
                (rust/'src/link.rs').symlink_to(rust/'src/lib.rs')
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    builder.dependency_sources(Provenance)
                (rust/'src/link.rs').unlink()
                with patch.object(Provenance, 'clean', return_value=False):
                    with self.assertRaisesRegex(ValueError, 'clean APQE'):
                        builder.dependency_sources(Provenance)


if __name__ == '__main__':
    unittest.main()
