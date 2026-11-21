import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import chain1266_gateway_relocation as relocation


class RelocationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = Path(folder.name).resolve()
        self.destination = base / "destination"
        self.destination.mkdir(mode=0o700)
        self.source = base / "original"
        self.source.write_bytes(b"encrypted bytes remain opaque")
        data = self.source.read_bytes()
        assets = {"identity.enc.json": (self.source, len(data), hashlib.sha256(data).hexdigest())}
        scope = patch.multiple(relocation, ASSETS=assets, DESTINATION_ROOT=self.destination,
                               directories=lambda p: p.relative_to(base))
        scope.start()
        self.addCleanup(scope.stop)

    def test_complete_verified_payload_publishes_once(self):
        stream = io.BytesIO()
        relocation.send(stream)
        relocation.receive(io.BytesIO(stream.getvalue()))
        deployed = self.destination / relocation.IMPORT
        relocation.verify_destination(deployed)
        self.assertEqual((deployed / "identity.enc.json").read_bytes(), self.source.read_bytes())
        with self.assertRaisesRegex(ValueError, "already exists"):
            relocation.receive(io.BytesIO(stream.getvalue()))

    def test_partial_changed_and_unconfirmed_streams_leave_no_destination(self):
        original = self.source.read_bytes()
        for rejected in (original[:-1], original, b"x" + original[1:] + relocation.END,
                         original + relocation.END + b"trailing"):
            with self.subTest(rejected=rejected), self.assertRaises(ValueError):
                relocation.receive(io.BytesIO(rejected))
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_reconciliation_rejects_replacement_or_added_files(self):
        relocation.receive(io.BytesIO(self.source.read_bytes() + relocation.END))
        deployed = self.destination / relocation.IMPORT
        extra = deployed / "unreviewed"
        extra.touch()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            relocation.verify_destination(deployed)
        extra.unlink()
        (deployed / "identity.enc.json").write_bytes(b"x" * self.source.stat().st_size)
        with self.assertRaisesRegex(ValueError, "digest"):
            relocation.verify_destination(deployed)


class RetirementTests(unittest.TestCase):
    def test_refuses_changed_or_empty_review_before_mutation(self):
        for review in ({"review_sha256": "changed", "paths": {"root": {}}},
                       {"review_sha256": "approved", "paths": {}}):
            with self.subTest(review=review), patch.object(relocation, "source_retirement_plan", return_value=review), \
                    patch.object(relocation, "system_command") as system, \
                    patch.object(relocation, "existing") as existing:
                with self.assertRaisesRegex(ValueError, "Review changed"):
                    relocation.retire_source("approved")
                system.assert_not_called()
                existing.assert_not_called()

    def test_nested_mount_refuses_retirement(self):
        line = "31 22 0:30 / /opt/synergy/runtime/data rw - tmpfs tmpfs rw\n"
        with patch.object(Path, "read_text", return_value=line):
            with self.assertRaisesRegex(ValueError, "contains a mount"):
                relocation.guard_mounts((Path("/opt/synergy"),))
            relocation.guard_mounts((Path("/opt/unrelated"),))


if __name__ == "__main__":
    unittest.main()
