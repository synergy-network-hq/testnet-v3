import os
import plistlib
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MACOS_M4 = ROOT / "macos-m4"


class MacosSplitPathContractTests(unittest.TestCase):
    def run_path_contract(self, *assignments: str) -> subprocess.CompletedProcess[str]:
        script = MACOS_M4 / "archive-paths.sh"
        command = f"source {script}; " + " ".join(assignments)
        command += "; archive_paths_validate"
        return subprocess.run(
            ["bash", "-c", command],
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            check=False,
        )

    def test_defaults_match_live_split_layout(self) -> None:
        script = MACOS_M4 / "archive-paths.sh"
        result = subprocess.run(
            [
                "bash",
                "-c",
                f"source {script}; archive_paths_load_defaults; printf '%s\\n' "
                '"${ARCHIVE_APP_ROOT}" "${ARCHIVE_PUBLISH_ROOT}" "${ARCHIVE_STORAGE_VOLUME}"',
            ],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "/Users/Shared/Synergy/archive-validator",
                "/Volumes/Synergy_Archive/archive-validator/snapshots",
                "/Volumes/Synergy_Archive",
            ],
        )

    def test_custom_external_paths_are_accepted_but_runtime_tree_stays_separate(self) -> None:
        result = self.run_path_contract(
            'ARCHIVE_STORAGE_VOLUME="/Volumes/ArchiveDisk"',
            'ARCHIVE_APP_ROOT="/Users/Shared/Synergy/custom-archive"',
            'ARCHIVE_PUBLISH_ROOT="/Volumes/ArchiveDisk/custom-snapshots"',
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_publish_root_inside_runtime_tree_is_rejected(self) -> None:
        result = self.run_path_contract(
            'ARCHIVE_STORAGE_VOLUME="/Volumes/Synergy_Archive"',
            'ARCHIVE_APP_ROOT="/Users/Shared/Synergy/archive-validator"',
            'ARCHIVE_PUBLISH_ROOT="/Users/Shared/Synergy/archive-validator/snapshots"',
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("separate trees", result.stderr)

    def test_worker_plist_is_persistent_and_split_path_renderable(self) -> None:
        template = MACOS_M4 / "launchd" / "io.synergynetwork.archive-snapshot-worker.plist.in"
        plist = plistlib.loads(template.read_bytes())
        arguments = plist["ProgramArguments"]
        self.assertIn("__APP_ROOT__", arguments)
        self.assertIn("__PUBLISH_ROOT__", arguments)
        self.assertIn("__STORAGE_VOLUME__", arguments)
        self.assertTrue(plist["KeepAlive"])
        self.assertEqual(plist["StartInterval"], 300)
        self.assertNotIn("/Volumes/Synergy_Archive-1", template.read_text(encoding="utf-8"))

    def test_archive_validator_has_no_legacy_external_volume_assumption(self) -> None:
        matches = subprocess.run(
            [
                "rg",
                "-n",
                "Synergy_Archive-1",
                str(ROOT / "macos-m4"),
                str(ROOT / "package-archive-validator-macos-m4.sh"),
                str(ROOT / "docs"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(matches.returncode, 1, matches.stdout)


if __name__ == "__main__":
    unittest.main()
