"""R5 trust failures must not create candidates or change the parent."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import build_package as builder


class R5CompositionTests(unittest.TestCase):
    def test_generated_cleanup_tolerates_only_disappearing_metadata(self):
        def invoke(error, name):
            def cleanup(path, onerror):
                onerror(None, name, (type(error), error, None))
            with patch.object(builder.shutil, 'rmtree', side_effect=cleanup):
                builder.remove_generated_tree(Path('/generated/Synergy'))
        invoke(FileNotFoundError(), '/generated/Synergy/bin/._synergy-node')
        with self.assertRaises(FileNotFoundError):
            invoke(FileNotFoundError(), '/generated/Synergy/bin/synergy-node')
        with self.assertRaises(PermissionError):
            invoke(PermissionError(), '/generated/Synergy/bin/._synergy-node')

    def test_promotion_refuses_unpinned_candidate_before_reading_master(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root/'candidate'
            candidate.mkdir()
            (candidate/'package.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'candidate pin differs'):
                builder.promote_r5_controller(candidate, '0'*64, '0'*64, root/'preserved')
            self.assertFalse((root/'preserved').exists())

    def test_wrong_parent_refused_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            original = root/'original'
            original.mkdir()
            (original/'package.json').write_text('{"release_id":"not-r5"}')
            with self.assertRaisesRegex(ValueError, 'manifest pin mismatch'):
                builder.compose_r5_controller(original, root/'Synergy')
            self.assertFalse((root/'Synergy').exists())

    def test_missing_corrupted_and_linked_parent_members_refused(self):
        for kind in ('missing', 'corrupted', 'linked'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                original = root/'original'
                original.mkdir()
                expected = b'original runtime bytes'
                raw = json.dumps({'release_id': builder.R5_RELEASE,
                    'files': {'runtime': hashlib.sha256(expected).hexdigest()}}).encode()
                (original/'package.json').write_bytes(raw)
                if kind == 'corrupted':
                    (original/'runtime').write_bytes(b'changed')
                elif kind == 'linked':
                    (root/'outside').write_bytes(expected)
                    (original/'runtime').symlink_to(root/'outside')
                with patch.object(builder, 'R5_MANIFEST_SHA256', hashlib.sha256(raw).hexdigest()):
                    with self.assertRaisesRegex(ValueError, 'member'):
                        builder.compose_r5_controller(original, root/'Synergy')
                self.assertFalse((root/'Synergy').exists())
                self.assertEqual((original/'package.json').read_bytes(), raw)
