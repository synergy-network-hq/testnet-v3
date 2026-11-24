import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest

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
