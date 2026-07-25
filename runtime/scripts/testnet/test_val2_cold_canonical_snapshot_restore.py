#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("val2_cold_canonical_snapshot_restore.py")


def write_fixture(root: Path):
    source = root / "source"
    target = root / "var/lib/synergy/validator"
    config = root / "etc/synergy/validator"
    workspace = root / "home/node/.synergy/testnet/nodes/validator-workspace"
    source.mkdir(parents=True)
    target.mkdir(parents=True)
    config.mkdir(parents=True)
    workspace.mkdir(parents=True)
    chain = '[{"block_index":10,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]\n'
    locks = '{"10":{"block_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}\n'
    qcs = '{"qc":{"block_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","votes":[{"block_index":10}]}}\n'
    for path in [source, target]:
        (path / "chain.json").write_text(chain if path == source else '[{"block_index":1,"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]\n')
        (path / "canonical_locks.json").write_text(locks if path == source else '{"1":{"block_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}\n')
        (path / "committed_qcs.jsonl").write_text(qcs)
        (path / "committed_qcs.json").write_text("{}\n")
        (path / "dag_state.json").write_text("{}\n")
        (path / "token_state.json").write_text("{}\n")
        (path / "validator_registry.json").write_text("[]\n")
    (target / "consensus_vote_locks.json").write_text('{"637015":{"block_hash":"bad"}}\n')
    (config / "node.env").write_text(
        "SYNERGY_CHAIN_ID=1264\n"
        "SYNERGY_NETWORK=synergy-testnet-v3\n"
        "SYNERGY_GENESIS_HASH=f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789\n"
        "SYNERGY_VALIDATOR_ADDRESS=synv11val2test\n"
    )
    (config / "config.toml").write_text(
        'network = "synergy-testnet-v3"\n'
        "chain_id = 1264\n"
        'genesis_hash = "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789"\n'
        'validator_address = "synv11val2test"\n'
    )
    (config / "keys").mkdir()
    (config / "keys" / "validator.json").write_text("secret\n")
    return source, target, config, workspace


class ColdRestoreTests(unittest.TestCase):
    def run_script(self, *args, check=True):
        proc = subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True)
        if check and proc.returncode != 0:
            raise AssertionError(proc.stderr + proc.stdout)
        return proc

    def test_dry_run_reports_go_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target, config, workspace = write_fixture(root)
            proc = self.run_script(
                "--dry-run",
                "--no-systemd",
                "--skip-helper-verify",
                "--skip-chown",
                "--source-state-dir",
                str(source),
                "--target-root",
                str(target),
                "--config-root",
                str(config),
                "--old-workspace",
                str(workspace),
                "--archive-root",
                str(root / "backups"),
                "--staging-root",
                str(root / "stage"),
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["decision"], "DRY_RUN_GO")
            self.assertTrue((target / "consensus_vote_locks.json").exists())
            self.assertIn("bbbb", (target / "chain.json").read_text())

    def test_apply_archives_replaces_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target, config, workspace = write_fixture(root)
            proc = self.run_script(
                "--apply",
                "--no-systemd",
                "--skip-helper-verify",
                "--skip-chown",
                "--source-state-dir",
                str(source),
                "--target-root",
                str(target),
                "--config-root",
                str(config),
                "--old-workspace",
                str(workspace),
                "--archive-root",
                str(root / "backups"),
                "--staging-root",
                str(root / "stage"),
                "--runtime-user",
                "nobody",
                "--runtime-group",
                "nobody",
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["decision"], "GO")
            self.assertIn("aaaaaaaa", (target / "chain.json").read_text())
            self.assertFalse((target / "consensus_vote_locks.json").exists())
            self.assertEqual(report["identity_before"], report["identity_after"])
            self.assertTrue(Path(report["archive"]["manifest"]).is_file())

    def test_apply_removes_stale_checkpoint_when_source_has_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target, config, workspace = write_fixture(root)
            (target / "state_checkpoint.json").write_text(
                json.dumps(
                    {
                        "height": 1,
                        "block_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    }
                )
                + "\n"
            )
            (target / "state_checkpoint.recovery_manifest.json").write_text("{}\n")
            proc = self.run_script(
                "--apply",
                "--no-systemd",
                "--skip-helper-verify",
                "--skip-chown",
                "--source-state-dir",
                str(source),
                "--target-root",
                str(target),
                "--config-root",
                str(config),
                "--old-workspace",
                str(workspace),
                "--archive-root",
                str(root / "backups"),
                "--staging-root",
                str(root / "stage"),
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["decision"], "GO")
            self.assertFalse((target / "state_checkpoint.json").exists())
            self.assertFalse((target / "state_checkpoint.recovery_manifest.json").exists())
            removed = "\n".join(report["removed_stale_target_files"])
            self.assertIn("state_checkpoint.json", removed)
            self.assertIn("state_checkpoint.recovery_manifest.json", removed)
            archive_files = {entry["path"] for entry in report["archive"]["files"]}
            self.assertIn("state_checkpoint.json", archive_files)
            self.assertIn("state_checkpoint.recovery_manifest.json", archive_files)

    def test_helper_verify_receives_recovery_checkpoint_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target, config, workspace = write_fixture(root)
            helper = root / "synergy-node-helper"
            helper.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "print(json.dumps({'ok': True, 'argv': sys.argv[1:]}))\n"
            )
            helper.chmod(0o755)
            proc = self.run_script(
                "--apply",
                "--no-systemd",
                "--skip-chown",
                "--allow-testnet-recovery-checkpoint",
                "--helper",
                str(helper),
                "--source-state-dir",
                str(source),
                "--target-root",
                str(target),
                "--config-root",
                str(config),
                "--old-workspace",
                str(workspace),
                "--archive-root",
                str(root / "backups"),
                "--staging-root",
                str(root / "stage"),
                "--runtime-user",
                "nobody",
                "--runtime-group",
                "nobody",
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            stage = report["helper_verification"]["stage"]
            active = report["helper_verification"]["active"]
            self.assertTrue(stage["allow_testnet_recovery_checkpoint"])
            self.assertTrue(active["allow_testnet_recovery_checkpoint"])
            self.assertIn("--allow-testnet-recovery-checkpoint", stage["verify_command"])
            self.assertIn("--allow-testnet-recovery-checkpoint", active["verify_command"])

    def test_source_key_material_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target, config, workspace = write_fixture(root)
            (source / "validator.key").write_text("nope\n")
            proc = self.run_script(
                "--dry-run",
                "--no-systemd",
                "--skip-helper-verify",
                "--source-state-dir",
                str(source),
                "--target-root",
                str(target),
                "--config-root",
                str(config),
                "--old-workspace",
                str(workspace),
                "--archive-root",
                str(root / "backups"),
                "--staging-root",
                str(root / "stage"),
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            report = json.loads(proc.stdout)
            codes = {item["code"] for item in report["findings"]}
            self.assertIn("source_contains_forbidden_identity_or_key_material", codes)

    def test_source_appledouble_metadata_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target, config, workspace = write_fixture(root)
            (source / "._chain.json").write_text("apple metadata\n")
            proc = self.run_script(
                "--dry-run",
                "--no-systemd",
                "--skip-helper-verify",
                "--source-state-dir",
                str(source),
                "--target-root",
                str(target),
                "--config-root",
                str(config),
                "--old-workspace",
                str(workspace),
                "--archive-root",
                str(root / "backups"),
                "--staging-root",
                str(root / "stage"),
            )
            report = json.loads(proc.stdout)
            self.assertTrue(report["ok"], report)
            self.assertNotIn("._chain.json", report["source_files"])


if __name__ == "__main__":
    unittest.main()
