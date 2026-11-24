import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "verify_finalized_observations", Path(__file__).with_name("verify-finalized-observations.py")
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class FinalityObservationTests(unittest.TestCase):
    def test_complete_original_bytes_are_reassembled_with_a_continuation_pin(self):
        original = b"x" * verifier.PAGE_BYTES + b"tail"
        digest = hashlib.sha256(original).hexdigest()

        def fetch(_endpoint, query):
            offset = query["offset"]
            self.assertEqual(query.get("expected_sha256"), digest if offset else None)
            chunk = original[offset:offset + verifier.PAGE_BYTES]
            end = offset + len(chunk)
            return dict(version=1, height=7, kind="finality", encoding="base64",
                        offset=offset, sha256=digest, total_bytes=len(original),
                        next_offset=end if end < len(original) else None,
                        bytes_base64=base64.b64encode(chunk).decode())

        self.assertEqual(verifier.fetch_proof("https://observer", 7, "finality", fetch), original)
        with self.assertRaisesRegex(ValueError, "changed"):
            verifier.fetch_proof("https://observer", 7, "finality", lambda endpoint, query: {
                **fetch(endpoint, query), "sha256": "a" * 64 if query["offset"] else digest
            })
        with self.assertRaisesRegex(ValueError, "noncontiguous"):
            verifier.fetch_proof("https://observer", 7, "finality", lambda endpoint, query: {
                **fetch(endpoint, query), "next_offset": None
            })

    def test_native_result_must_authenticate_the_exact_requested_incarnation(self):
        result = dict(verified=True, chain_id=99999, network_id="canary", genesis_hash="a" * 64,
                      state_root="b" * 64, finalized=dict(height=7, block_id="c" * 64,
                      protected_execution_root="d" * 64))
        self.assertEqual(verifier.subject(result, 99999, "canary", "a" * 64, 7)["state_root"], "b" * 64)
        for invalid in ({**result, "verified": False}, {**result, "genesis_hash": "e" * 64},
                        {**result, "finalized": {**result["finalized"], "height": 8}}):
            with self.assertRaisesRegex(ValueError, "selected network or height"):
                verifier.subject(invalid, 99999, "canary", "a" * 64, 7)

    def test_authenticated_consecutive_blocks_cross_an_epoch_boundary(self):
        before = dict(height=1000, block_id="a" * 64, epoch=4, epoch_context_root="b" * 64,
                      consensus_timestamp_unix=100)
        native = dict(epoch=5, epoch_context_root="c" * 64, consensus_timestamp_unix=101)
        block = json.dumps([1001, before["block_id"], "d" * 64, "e" * 64, [], []])
        after = dict(height=1001, **verifier.consensus_position(native, block))
        self.assertEqual(verifier.check_successor(before, after), 1)
        self.assertEqual(verifier.check_successor(before, {
            **after, "epoch": 4, "epoch_context_root": before["epoch_context_root"]
        }), 0)
        for fields, error in (
            (dict(height=1002), "contiguous"),
            (dict(parent_block_id="f" * 64), "contiguous"),
            (dict(consensus_timestamp_unix=99), "regressed"),
            (dict(epoch=6), "succession"),
            (dict(epoch=4), "succession"),
            (dict(epoch_context_root=before["epoch_context_root"]), "succession"),
        ):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, error):
                verifier.check_successor(before, {**after, **fields})
        with self.assertRaisesRegex(ValueError, "invalid verified consensus position"):
            verifier.consensus_position({**native, "epoch": None}, block)

    def test_public_request_identifies_client_and_reports_missing_evidence(self):
        params = dict(height=9704, kind="block_commitment", offset=0, limit=1024)
        with patch.object(verifier, "build_opener") as opener:
            process = opener.return_value.open
            response = process.return_value.__enter__.return_value
            response.read.return_value = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32001, "message": "requested finalized evidence is not retained"},
            }).encode()
            with self.assertRaisesRegex(ValueError, r"block_commitment at H9704 .*not retained"):
                verifier.request_page("https://observer", params)
            self.assertEqual(process.call_args.args[0].get_header("User-agent"), verifier.USER_AGENT)
