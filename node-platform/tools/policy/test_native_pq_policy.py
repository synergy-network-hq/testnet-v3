"""Executable guard for forbidden native classical asymmetric implementations.

This checks workspace-owned Rust source/dependencies, never vendored source or
external interoperability adapters. Functional rejection is separately exercised
by transport registry and native transport configuration tests.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CLASSICAL = re.compile(r'\b(?:ed25519_dalek|x25519_dalek|curve25519_dalek|rsa)::|\b(?:k256|p256|p384)::(?:ecdsa|ecdh)')
DEPS = re.compile(r'^\s*(?:ed25519-dalek|x25519-dalek|curve25519-dalek|rsa)\s*=', re.M)

class NativePqPolicy(unittest.TestCase):
    def test_no_classical_asymmetric_implementation_in_native_owners(self):
        violations=[]
        for base in (ROOT/'crates', ROOT/'bin'):
            for path in base.glob('*/src/**/*.rs'):
                # Test strings naming forbidden profiles are rejection inputs;
                # this pattern targets implementation calls/imports instead.
                if path.name.startswith('._'): continue
                if CLASSICAL.search(path.read_text()): violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [], 'Classical asymmetric trust belongs only to an explicitly isolated EVM interoperability adapter')

    def test_no_classical_direct_dependency_in_native_packages(self):
        violations=[]
        for base in (ROOT/'crates',ROOT/'bin'):
            for path in base.glob('*/Cargo.toml'):
                if DEPS.search(path.read_text()): violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [])

if __name__=='__main__': unittest.main()
