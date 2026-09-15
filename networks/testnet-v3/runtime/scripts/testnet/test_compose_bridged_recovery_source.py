import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("compose_bridged_recovery_source.py")


def write_qcs(path: Path, entries):
    with path.open("w", encoding="utf-8") as handle:
        for height, block_hash in entries:
            handle.write(
                json.dumps(
                    {
                        "block_hash": block_hash,
                        "qc": {
                            "block_hash": block_hash,
                            "votes": [
                                {
                                    "block_index": height,
                                    "block_hash": block_hash,
                                }
                            ],
                        },
                    }
                )
                + "\n"
            )


def write_state(root: Path, qcs, chain_heights):
    root.mkdir()
    locks = {
        str(height): {"block_hash": f"h{height}"}
        for height in range(min(chain_heights), max(chain_heights) + 1)
    }
    (root / "chain.json").write_text(
        json.dumps(
            [{"block_index": height, "hash": f"h{height}"} for height in chain_heights]
        )
    )
    (root / "canonical_locks.json").write_text(json.dumps(locks))
    (root / "committed_qcs.json").write_text("[]")
    write_qcs(root / "committed_qcs.jsonl", qcs)
    (root / "dag_state.json").write_text("{}")
    (root / "validator_registry.json").write_text('{"validators":{}}')
    (root / "token_state.json").write_text("{}")


class ComposeBridgedRecoverySourceTests(unittest.TestCase):
    def test_admits_matching_prefix_and_source_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            target = base / "target"
            out = base / "out"
            summary = base / "summary.json"

            write_state(source, [(8, "h8"), (9, "h9")], range(1, 10))
            write_state(
                target,
                [(3, "h3"), (4, "h4"), (5, "h5"), (6, "h6"), (7, "h7")],
                range(1, 5),
            )

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--source-dir",
                    str(source),
                    "--target-data-dir",
                    str(target),
                    "--output-dir",
                    str(out),
                    "--bridge-from-height",
                    "4",
                    "--summary",
                    str(summary),
                ],
                check=True,
            )

            data = json.loads(summary.read_text())
            self.assertEqual(data["admitted_target_prefix_first_height"], 4)
            self.assertEqual(data["admitted_target_prefix_last_height"], 7)
            self.assertEqual(data["source_first_qc_height"], 8)
            self.assertEqual(data["derived_qc_height"], 9)

            lines = [
                json.loads(line)
                for line in (out / "committed_qcs.jsonl").read_text().splitlines()
            ]
            heights = [entry["qc"]["votes"][0]["block_index"] for entry in lines]
            self.assertEqual(heights, [4, 5, 6, 7, 8, 9])


if __name__ == "__main__":
    unittest.main()
