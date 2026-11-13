import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REPAIR_SCRIPT = REPO_ROOT / "scripts/testnet/repair_chain_body_from_committed_blocks.sh"


def block(height: int) -> dict:
    return {
        "block_index": height,
        "hash": f"hash-{height}",
        "previous_hash": f"hash-{height - 1}",
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ChainBodyRepairTests(unittest.TestCase):
    def run_repair(self, workspace: Path, *, dry_run: bool) -> dict:
        env = os.environ.copy()
        env["SYNERGY_WORKSPACE"] = str(workspace)
        env["SYNERGY_COMMITTED_BLOCK_REPAIR_LOG"] = str(
            workspace / "data/committed_blocks.jsonl"
        )
        if dry_run:
            env["SYNERGY_CHAIN_BODY_REPAIR_DRY_RUN"] = "1"
        else:
            env.pop("SYNERGY_CHAIN_BODY_REPAIR_DRY_RUN", None)
        completed = subprocess.run(
            ["bash", str(REPAIR_SCRIPT)],
            env=env,
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return json.loads(completed.stdout)

    def write_workspace(self, root: Path) -> None:
        data = root / "data"
        data.mkdir(parents=True)
        chain = [block(1), block(10), block(11), block(14)]
        (data / "chain.json").write_text(json.dumps(chain) + "\n", encoding="utf-8")
        locks = {
            "10": {"hash": "hash-10"},
            "20": {"block_hash": "hash-20"},
        }
        (data / "canonical_locks.json").write_text(
            json.dumps(locks) + "\n", encoding="utf-8"
        )
        with (data / "committed_blocks.jsonl").open("w", encoding="utf-8") as handle:
            for height in range(10, 21):
                payload = {
                    "height": height,
                    "hash": f"hash-{height}",
                    "block": block(height),
                }
                handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
        with (data / "committed_qcs.jsonl").open("w", encoding="utf-8") as handle:
            for height in range(10, 21):
                payload = {"height": height, "block_hash": f"hash-{height}"}
                handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def test_rebuilds_retained_window_from_committed_block_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workspace(root)

            dry_run = self.run_repair(root, dry_run=True)
            self.assertFalse(dry_run["chain_body_repaired"])
            self.assertTrue(dry_run["would_repair"])
            self.assertTrue(dry_run["would_replace_from_committed_block_log"])
            self.assertEqual(dry_run["checkpoint_height"], 10)
            self.assertEqual(dry_run["new_tip_height"], 20)

            applied = self.run_repair(root, dry_run=False)
            self.assertTrue(applied["chain_body_repaired"])
            self.assertTrue(applied["replaced_from_committed_block_log"])
            repaired_chain = json.loads((root / "data/chain.json").read_text())
            self.assertEqual([entry["block_index"] for entry in repaired_chain], list(range(10, 21)))

            checkpoint_path = root / "data/state_checkpoint.json"
            checkpoint = json.loads(checkpoint_path.read_text())
            self.assertEqual(checkpoint["format"], "synergy_consensus_state_checkpoint_v1")
            self.assertEqual(checkpoint["height"], 10)
            self.assertEqual(checkpoint["block_hash"], "hash-10")
            self.assertEqual(checkpoint["chain_sha256"], sha256(root / "data/chain.json"))
            self.assertEqual(
                checkpoint["canonical_locks_sha256"],
                sha256(root / "data/canonical_locks.json"),
            )
            self.assertEqual(
                checkpoint["committed_qcs_sha256"],
                sha256(root / "data/committed_qcs.jsonl"),
            )

    def test_refuses_log_window_without_matching_canonical_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_workspace(root)
            locks = {"20": {"block_hash": "wrong-hash-20"}}
            (root / "data/canonical_locks.json").write_text(
                json.dumps(locks) + "\n", encoding="utf-8"
            )

            report = self.run_repair(root, dry_run=True)
            self.assertFalse(report["chain_body_repaired"])
            self.assertEqual(
                report["reason"],
                "no current or backup chain body can cover canonical lock",
            )
            self.assertIn("committed block log", json.dumps(report["candidate_rejections"]))


if __name__ == "__main__":
    unittest.main()
