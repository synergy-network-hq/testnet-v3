import base64
import hashlib
import importlib.util
import json
import io
from contextlib import redirect_stdout
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

    def test_witness_only_invokes_native_verifier_without_block_preimage(self):
        genesis = "a" * 64
        args = ["verify", "--observer", "https://example.test", "--node", __file__,
                "--config", __file__, "--chain", "99999", "--network", "canary",
                "--genesis", genesis, "--height", "9704", "--witness-only"]
        native = dict(verified=True, chain_id=99999, network_id="canary", genesis_hash=genesis,
                      finalized=dict(height=9704, block_id="b" * 64,
                                     protected_execution_root="c" * 64,
                                     finality_certificate_id="d" * 64))
        with (patch("sys.argv", args),
              patch.object(verifier, "fetch_proof", return_value=b"original") as fetch,
              patch.object(verifier.subprocess, "run") as run, redirect_stdout(io.StringIO()) as out):
            run.return_value.stdout = json.dumps(native).encode()
            verifier.main()
            fetch.assert_called_once_with("https://example.test", 9704, "finality")
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["finality-proof", "verify"])
            self.assertEqual(len(command), 5)
            self.assertEqual(Path(command[-1]).name, "finality.json")
        result = json.loads(out.getvalue())
        self.assertFalse(result["block_preimage_verified"])
        self.assertNotIn("state_root", result)
        self.assertEqual(result["finality_certificate_id"], "d" * 64)

    def test_witness_range_uses_first_verified_qc_context_at_boundary(self):
        network = "canary"
        block_id = "a" * 64
        parent = "b" * 64
        protected_root = "c" * 64
        epoch_root = "d" * 64
        commitments = dict(block_id=block_id, protected_execution_root=protected_root)
        first = dict(block_id=block_id, parent_block_id=parent,
                     protected_execution_root=protected_root,
                     context=dict(chain_id=99999, network_id=network, height=9000, epoch=9,
                                  epoch_context_root=epoch_root))
        descendant = dict(context=dict(epoch=10))
        proof = dict(witness=dict(quorum_certificates=[first, descendant, descendant]))
        at_boundary = verifier.witness_position(json.dumps(proof), commitments, 99999, network, 9000)
        self.assertEqual(at_boundary, dict(parent_block_id=parent, epoch=9, epoch_context_root=epoch_root))
        next_block = dict(height=9001, parent_block_id=block_id, epoch=10, epoch_context_root="e" * 64)
        previous = dict(height=9000, block_id=block_id, **at_boundary)
        self.assertEqual(verifier.check_successor(previous, next_block), 1)
        with self.assertRaisesRegex(ValueError, "contiguous"):
            verifier.check_successor(previous, {**next_block, "parent_block_id": "f" * 64})
        with self.assertRaisesRegex(ValueError, "selected consensus position"):
            verifier.witness_position(json.dumps(proof), commitments, 99999, network, 9001)
