"""Offline template/native-header/inventory tests, not runtime qualification."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
import generate as g


class PlatformMasterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
    def tearDown(self):
        self.tmp.cleanup()
    def test_generation_is_deterministic_and_never_starts_or_qualifies(self):
        first = g.generate(self.root)
        self.assertFalse(first['runtime_qualified'])
        self.assertFalse(first['activation_authorized'])
        self.assertEqual(first, g.generate(self.root, check=True))
        for platform in g.PLATFORMS:
            base = self.root/platform/'synergy'
            self.assertFalse((base/'package.json').exists())
            for path in ('keys/apqe', 'data', 'vpn', 'cache', 'run'):
                self.assertFalse(list((base/path).iterdir()))
            descriptor = json.loads((base/'architecture.json').read_bytes())
            self.assertEqual(len(descriptor['roles']), 20)
            self.assertTrue(descriptor['missing_qualification'])
        job = plistlib.loads((self.root/'macOS/synergy/launchd/network.synergy.node.plist').read_bytes())
        self.assertFalse(job['RunAtLoad'])
        self.assertFalse(job['KeepAlive'])
        self.assertTrue(all(x.startswith(g.PLATFORMS['macOS']['root']) for x in
                            (job['WorkingDirectory'], job['StandardOutPath'], job['StandardErrorPath'])))
        windows = json.loads((self.root/'Windows/synergy/services/node-service.json').read_bytes())
        self.assertFalse(windows['registration_supported'])
    def test_template_drift_and_symlinks_fail_closed(self):
        g.generate(self.root)
        path = self.root/'macOS/synergy/architecture.json'
        path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'drift'):
            g.generate(self.root, check=True)
        path.unlink(); path.symlink_to(self.root/'Windows/synergy/architecture.json')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            g.generate(self.root)
    def fixture(self, platform, arch='x86_64'):
        """Header fixtures exercise target checks; they are not runnable binaries."""
        base = self.root/platform
        base.mkdir()
        files = g.contents(platform)
        if platform == 'macOS':
            binary = b'\xcf\xfa\xed\xfe'+struct.pack('<I', 0x1000007)+bytes(24)
        else:
            binary = bytearray(100)
            binary[:2] = b'MZ'; struct.pack_into('<I', binary, 60, 64)
            binary[64:68] = b'PE\x00\x00'
            struct.pack_into('<H', binary, 68, 0x8664)
            struct.pack_into('<H', binary, 88, 0x20b)
            binary = bytes(binary)
        for name in g.description(platform)['required_native_payload']:
            files[name] = b'{}' if name.endswith('.json') else binary
        for name, data in files.items():
            path = base/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        manifest = {'format': 'synergy-platform-release-v1', 'platform': g.PLATFORMS[platform]['os'],
                    'architecture': arch, 'files': {n: hashlib.sha256(v).hexdigest() for n, v in files.items()}}
        return base, manifest
    def seal(self, base, manifest):
        raw = g.canonical(manifest); (base/'package.json').write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()
    def test_explicit_pin_and_each_native_target(self):
        for platform in g.PLATFORMS:
            base, manifest = self.fixture(platform)
            pin = self.seal(base, manifest)
            result = g.verify_release(base, pin, platform)
            self.assertTrue(result['integrity_verified'])
            self.assertFalse(result['runtime_qualified'])
            with self.assertRaisesRegex(ValueError, 'pin differs'):
                g.verify_release(base, '0'*64, platform)
            manifest['architecture'] = 'aarch64'
            with self.assertRaisesRegex(ValueError, 'architecture differs'):
                g.verify_release(base, self.seal(base, manifest), platform)
    def test_cross_platform_payload_refused_even_with_new_pin(self):
        base, manifest = self.fixture('Windows')
        name = 'bin/synergy-node.exe'
        data = b'\xcf\xfa\xed\xfe'+struct.pack('<I', 0x1000007)+bytes(100)
        (base/name).write_bytes(data)
        manifest['files'][name] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(ValueError, 'Windows PE required'):
            g.verify_release(base, self.seal(base, manifest), 'Windows')
    def test_missing_tampered_and_undeclared_members(self):
        base, manifest = self.fixture('macOS'); pin = self.seal(base, manifest)
        extra = base/'keys/secret'; extra.parent.mkdir(); extra.write_bytes(b'not-a-secret-test')
        with self.assertRaisesRegex(ValueError, 'undeclared'):
            g.verify_release(base, pin, 'macOS')
        manifest['files']['keys/secret'] = hashlib.sha256(extra.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            g.verify_release(base, self.seal(base, manifest), 'macOS')
        extra.unlink(); del manifest['files']['keys/secret']; pin = self.seal(base, manifest)
        member = base/'bin/synergy-node'; member.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            g.verify_release(base, pin, 'macOS')
        member.unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            g.verify_release(base, pin, 'macOS')
    def test_symlink_cannot_escape_or_substitute_payload(self):
        base, manifest = self.fixture('macOS'); pin = self.seal(base, manifest)
        path = base/'bin/synergy-node'; path.unlink(); path.symlink_to(base/'bin/apqe')
        with self.assertRaisesRegex(ValueError, 'links forbidden'):
            g.verify_release(base, pin, 'macOS')
    def test_invalid_pe_offset_and_architecture(self):
        data = bytearray(64); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 0xfffffff0)
        with self.assertRaisesRegex(ValueError, 'Invalid PE'):
            g.native_target(data, 'windows', 'x86_64')
        with self.assertRaisesRegex(ValueError, 'Unsupported architecture'):
            g.native_target(data, 'windows', 'x86')


if __name__ == '__main__':
    unittest.main()
