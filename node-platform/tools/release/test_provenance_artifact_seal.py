"""Artifact-seal regressions: invalid ELF, unstable bytes, and failed durability."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location("release_provenance",Path(__file__).with_name("provenance.py"))
provenance=importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)

class ArtifactSealTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.artifact=Path(self.directory.name)/"candidate"
        header=b"\x7fELF\x02\x01\x01"+bytes(9)+struct.pack("<HHIQQQIHHHHHH",3,62,1,4215,64,0,0,64,56,1,0,0,0)
        self.artifact.write_bytes(header+struct.pack("<IIQQQQQQ",1,5,0,4096,0,120,120,4096))

    def test_seals_same_valid_bytes_with_two_independent_reads(self):
        with patch.object(provenance,"flush_artifact") as flush:
            result=provenance.seal_artifact(self.artifact)
        flush.assert_called_once_with(self.artifact)
        self.assertEqual(result,{"length":120,"sha3_256":hashlib.sha3_256(self.artifact.read_bytes()).hexdigest()})

    def test_rejects_zero_filled_link_output(self):
        self.artifact.write_bytes(bytes(120))
        with patch.object(provenance,"flush_artifact"),self.assertRaisesRegex(ValueError,"ELF header"):
            provenance.seal_artifact(self.artifact)

    def test_rejects_changed_bytes_even_with_unchanged_metadata(self):
        digest=provenance.digest
        calls=0
        def read_then_change(path,algorithm):
            nonlocal calls
            value=digest(path,algorithm);calls+=1
            if calls==1:
                data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
            return value
        with patch.object(provenance,"flush_artifact"),patch.object(provenance,"artifact_identity",return_value=(1,2,120,3,4)),patch.object(provenance,"digest",side_effect=read_then_change),self.assertRaisesRegex(ValueError,"bytes unstable"):
            provenance.seal_artifact(self.artifact)

    def test_unsupported_flush_blocks_sealing(self):
        with patch.object(provenance,"flush_artifact",side_effect=OSError("unsupported durable flush")),patch.object(provenance,"digest") as digest,self.assertRaises(OSError):
            provenance.seal_artifact(self.artifact)
        digest.assert_not_called()

if __name__=="__main__":unittest.main()
