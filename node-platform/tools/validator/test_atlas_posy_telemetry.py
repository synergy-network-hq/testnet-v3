"""Regression checks for the collector's actual native history formats."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "collector", Path(__file__).with_name("publish-atlas-posy-telemetry.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
probe = {}
exec(collector.PROBE.split("configuration,_=")[0], probe)


class NativeHistory(unittest.TestCase):
    def test_expiry_monitor_requires_all_five_pinned_registries(self):
        now = "2026-11-09T00:00:00+00:00"
        nodes = [dict(status="active", peers=4, finalized_height=1,
                      finalized_block_id="block", state_root="root") for _ in range(5)]
        registry = dict(generation=2, valid_from_unix=1794182400, expires_at_unix=1794787200)
        states = {n: {"registry_validity": dict(registry)} for n in range(2, 7)}
        def status():
            return collector.live_canary_checks("posy-apqe-canary-process-49028",
                "2a770743814a98e61856efb85ebae1461dbac38a7b75ca65fb9f7ffe2e7011dc",
                nodes, now, states)[-1]["status"]
        self.assertEqual(status(), "warning")
        states[2]["registry_validity"]["generation"] = 3
        self.assertEqual(status(), "blocked")

    def test_world_delta_reconstruction_checks_the_finalized_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            worlds = root / "state/execution/finalized-world"
            worlds.mkdir(parents=True)
            world = {"accounts": {"syna-test": {"balance_nwei": 1, "nonce": 0, "code_hash": None}}, "protocol": {}}
            def digest(value):
                data = json.dumps(value, separators=(",", ":")).encode()
                return hashlib.sha3_256(b"SYNERGY_WORLD_STATE_ROOT_V1" + len(data).to_bytes(8, "big") + data).hexdigest()
            first = digest(world)
            (worlds / f"{64:020}.json").write_text(json.dumps(world))
            world["accounts"]["syna-other"] = {"balance_nwei": 2, "nonce": 0, "code_hash": None}
            world["accounts"] = dict(sorted(world["accounts"].items()))
            final = digest(world)
            patch = {"height": 65, "parent_height": 64, "parent_state_root": first,
                     "state_root": final, "accounts": {"syna-other": world["accounts"]["syna-other"]}, "protocol": {}}
            path = worlds / f"{65:020}.json"
            path.write_bytes(b"SNWDV001" + json.dumps(patch).encode())
            observed = {"finalized_height": 65, "state_root": final}
            self.assertEqual(probe["count_finalized_accounts"](root, observed), 2)
            patch["parent_state_root"] = "0" * 64
            path.write_bytes(b"SNWDV001" + json.dumps(patch).encode())
            with self.assertRaises(ValueError):
                probe["count_finalized_accounts"](root, observed)

    def test_candidate_count_requires_matching_finalized_commitments(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            history = root / "state/execution/finalized-history"
            candidates = root / "blocks/execution-candidates/candidate"
            history.mkdir(parents=True)
            candidates.mkdir(parents=True)
            state = {"finalized_height": 1, "finalized_block_id": "block", "state_root": "root"}
            (history / f"{1:020}.json").write_text(json.dumps({"format": "synergy-finalized-state-v1", "state": state}))
            candidate = {"height": 1, "block_id": "block", "state_root": "root",
                         "parent_block_id": "genesis", "transactions": []}
            path = candidates / f"{1:020}.json"
            path.write_bytes(b"SNCDV001" + json.dumps(candidate).encode())
            cursor, total = probe["count_committed_transactions"](root, state, None)
            self.assertEqual((cursor["height"], total), (1, 0))
            candidate["block_id"] = "unfinalized"
            path.write_bytes(b"SNCDV001" + json.dumps(candidate).encode())
            self.assertIsNone(probe["count_committed_transactions"](root, state, None)[1])


if __name__ == "__main__":
    unittest.main()
