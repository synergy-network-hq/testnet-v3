#!/usr/bin/env python3
"""Tests for deterministic Synergy Testnet genesis artwork generation."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "testnet" / "genesis_art.py"
GENESIS = ROOT / "genesis.testnet.json"
NETWORK_IDENTIFIERS = ROOT / "network-identifiers.testnet.json"
EXPECTED_GENESIS_HASH = "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789"
EXPECTED_NETWORK_MAGIC = "ec6a253c"

REQUIRED_FILES = [
    "synergy-art-styleguide.json",
    "synergy-testnet-artwork-manifest.json",
    "synergy-testnet-genesis-certificate.png",
    "synergy-testnet-genesis-certificate.svg",
    "synergy-testnet-genesis-poster.png",
    "synergy-testnet-genesis-poster.svg",
    "synergy-testnet-genesis-sigil-animated.svg",
    "synergy-testnet-genesis-sigil-engraving.png",
    "synergy-testnet-genesis-sigil-engraving.svg",
    "synergy-testnet-genesis-sigil-minimal.png",
    "synergy-testnet-genesis-sigil-minimal.svg",
    "synergy-testnet-genesis-sigil.png",
    "synergy-testnet-genesis-sigil.svg",
    "synergy-testnet-validator-1-plaque.png",
    "synergy-testnet-validator-1-plaque.svg",
    "synergy-testnet-validator-2-plaque.png",
    "synergy-testnet-validator-2-plaque.svg",
    "synergy-testnet-validator-3-plaque.png",
    "synergy-testnet-validator-3-plaque.svg",
    "synergy-testnet-validator-4-plaque.png",
    "synergy-testnet-validator-4-plaque.svg",
    "synergy-testnet-validator-5-plaque.png",
    "synergy-testnet-validator-5-plaque.svg",
]


def run_generator(out_dir: Path, env_overrides: dict[str, str] | None = None) -> None:
    env = os.environ.copy()
    env.update(env_overrides or {})
    subprocess.run(
        [
            "python3",
            str(GENERATOR),
            "--genesis",
            str(GENESIS),
            "--network-identifiers",
            str(NETWORK_IDENTIFIERS),
            "--out",
            str(out_dir),
            "--png-size",
            "384",
            "--minimal-png-size",
            "256",
            "--poster-png-width",
            "540",
            "--poster-png-height",
            "720",
            "--plaque-png-width",
            "540",
            "--plaque-png-height",
            "360",
            "--certificate-png-width",
            "440",
            "--certificate-png-height",
            "340",
        ],
        cwd=ROOT,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class GenesisArtworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tmp_path = Path(cls.tmp.name)
        cls.out_a = cls.tmp_path / "a"
        cls.out_b = cls.tmp_path / "b"
        run_generator(cls.out_a, {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "1"})
        run_generator(cls.out_b, {"TZ": "Pacific/Honolulu", "LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "random"})

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def read_manifest(self, out_dir: Path) -> dict:
        return json.loads((out_dir / "synergy-testnet-artwork-manifest.json").read_text(encoding="utf-8"))

    def test_svg_bytes_are_identical_across_runs(self) -> None:
        svg_names = sorted(path.name for path in self.out_a.glob("*.svg"))
        self.assertEqual(svg_names, sorted(path.name for path in self.out_b.glob("*.svg")))
        for name in svg_names:
            self.assertEqual((self.out_a / name).read_bytes(), (self.out_b / name).read_bytes(), name)

    def test_manifest_is_identical_across_locale_hash_seed_and_timezone(self) -> None:
        self.assertEqual(
            (self.out_a / "synergy-testnet-artwork-manifest.json").read_bytes(),
            (self.out_b / "synergy-testnet-artwork-manifest.json").read_bytes(),
        )

    def test_required_files_are_generated(self) -> None:
        generated = sorted(path.name for path in self.out_a.iterdir())
        for name in REQUIRED_FILES:
            self.assertIn(name, generated)

    def test_svg_metadata_exists(self) -> None:
        required = {
            "genesis_hash",
            "network_magic_bytes",
            "chain_id",
            "validator_set_hash",
            "state_root",
            "art_seed",
            "dag_topology_seed",
            "generator_version",
        }
        for svg_path in self.out_a.glob("*.svg"):
            root = ET.parse(svg_path).getroot()
            metadata = root.find("{http://www.w3.org/2000/svg}metadata")
            self.assertIsNotNone(metadata, svg_path.name)
            payload = json.loads(metadata.text or "{}")
            self.assertTrue(required.issubset(payload), svg_path.name)
            self.assertEqual(payload["genesis_hash"], EXPECTED_GENESIS_HASH)
            self.assertEqual(payload["network_magic_bytes"], EXPECTED_NETWORK_MAGIC)
            self.assertEqual(payload["generator_version"], "synergy-genesis-art-v2.0.0")

    def test_visible_full_sigil_metadata_requirements(self) -> None:
        svg = (self.out_a / "synergy-testnet-genesis-sigil.svg").read_text(encoding="utf-8")
        self.assertIn("CHAIN 1264", svg)
        self.assertIn("MAGIC ec6a253c", svg)
        self.assertIn("GENESIS HASH 85b26d52...c4394c75", svg)

    def test_minimal_sigil_has_no_raw_genesis_dump(self) -> None:
        svg = (self.out_a / "synergy-testnet-genesis-sigil-minimal.svg").read_text(encoding="utf-8")
        self.assertLessEqual(svg.count(EXPECTED_GENESIS_HASH), 1)
        self.assertNotIn("allocations", svg.lower())
        self.assertNotIn("consensus_public_key", svg.lower())
        self.assertNotIn("account_public_key", svg.lower())

    def test_engraving_has_no_gradient_or_glow_dependency(self) -> None:
        svg = (self.out_a / "synergy-testnet-genesis-sigil-engraving.svg").read_text(encoding="utf-8")
        forbidden = ["linearGradient", "radialGradient", "<filter", "url("]
        for token in forbidden:
            self.assertNotIn(token, svg)

    def test_no_private_key_looking_fields_or_machine_paths_appear(self) -> None:
        forbidden = [
            "private_key",
            "seed_phrase",
            "mnemonic",
            "secret_key",
            "begin private key",
            "/users/",
            "file://",
        ]
        for path in self.out_a.iterdir():
            payload = path.read_bytes().lower()
            for token in forbidden:
                self.assertNotIn(token.encode("utf-8"), payload, path.name)

    def test_validator_plaque_files_are_generated_for_all_five_initial_validators(self) -> None:
        plaques = sorted(path.name for path in self.out_a.glob("synergy-testnet-validator-*-plaque.svg"))
        self.assertEqual(
            plaques,
            [
                "synergy-testnet-validator-1-plaque.svg",
                "synergy-testnet-validator-2-plaque.svg",
                "synergy-testnet-validator-3-plaque.svg",
                "synergy-testnet-validator-4-plaque.svg",
                "synergy-testnet-validator-5-plaque.svg",
            ],
        )

    def test_artwork_manifest_matches_canonical_identity(self) -> None:
        manifest = self.read_manifest(self.out_a)
        self.assertEqual(manifest["genesis_hash"], EXPECTED_GENESIS_HASH)
        self.assertEqual(manifest["network_magic_bytes"], EXPECTED_NETWORK_MAGIC)
        self.assertEqual(manifest["chain_id"], 1264)
        self.assertEqual(manifest["creation_mode"], "deterministic")
        self.assertEqual(len(manifest["validators"]), 5)
        self.assertEqual(len({entry["validator_art_fingerprint"] for entry in manifest["validators"]}), 5)
        self.assertIn("palette", manifest)
        self.assertIn("dag_edges", manifest)
        hashed_svg_png = [entry for entry in manifest["files"] if entry["path"].endswith((".svg", ".png"))]
        self.assertGreaterEqual(len(hashed_svg_png), 21)
        for entry in hashed_svg_png:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(entry["blake3"], r"^[0-9a-f]{64}$")

    def test_styleguide_records_v2_system(self) -> None:
        guide = json.loads((self.out_a / "synergy-art-styleguide.json").read_text(encoding="utf-8"))
        self.assertEqual(guide["generator_version"], "synergy-genesis-art-v2.0.0")
        self.assertEqual(guide["palette"]["brand"]["lime_posy"], "#00ff66")
        self.assertEqual(guide["canonical_identity"]["network_magic_bytes"], EXPECTED_NETWORK_MAGIC)
        self.assertIn("synergy-testnet-genesis-sigil-minimal.svg", guide["artifact_filenames"])


if __name__ == "__main__":
    unittest.main()
