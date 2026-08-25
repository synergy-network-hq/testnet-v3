#!/usr/bin/env python3

from __future__ import annotations

import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("build-fresh-posy-v3-release-package-manifest.py")
SPEC = importlib.util.spec_from_file_location("fresh_posy_release_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)


class EtdagIngressManifestBindingTests(unittest.TestCase):
    genesis_sha256 = "1" * 64
    genesis_hash = "2" * 64

    def artifacts(self, root: Path) -> tuple[Path, Path, dict[int, dict[str, object]]]:
        public_records = []
        runtime_records = []
        for ordinal, validator_id in enumerate(MANIFEST.ACTIVE_IDS, start=1):
            key_bytes = bytes([ordinal, ordinal + 1, ordinal + 2])
            ingress_key_id = f"ingress-{validator_id}"
            public_records.append({
                "validator_id": validator_id,
                "ingress_key_id": ingress_key_id,
                "share_index": ordinal,
                "public_key_base64": base64.b64encode(key_bytes).decode("ascii"),
            })
            runtime_records.append({
                "validator_id": validator_id,
                "ingress_key_id": ingress_key_id,
                "share_index": ordinal,
                "key_bytes": list(key_bytes),
            })
        ingress_records = {
            "schema_version": 1,
            "artifact_type": MANIFEST.INGRESS_RECORDS_ARTIFACT_TYPE,
            "status": MANIFEST.INGRESS_RECORDS_STATUS,
            "chain_id": MANIFEST.CHAIN_ID,
            "runtime_network_id": MANIFEST.NETWORK_ID,
            "protocol_version": MANIFEST.PROTOCOL,
            "genesis_candidate_sha256": self.genesis_sha256,
            "genesis_hash": self.genesis_hash,
            "records": public_records,
        }
        records_path = root / "ingress-records.json"
        records_path.write_text(json.dumps(ingress_records), encoding="utf-8")

        epoch_context_bytes = [1] + [0] * 31
        epoch_context_root = bytes(epoch_context_bytes).hex()
        registry_directory = root / epoch_context_root
        registry_directory.mkdir()
        wrappers = {}
        for target_height in MANIFEST.BOOTSTRAP_ETDAG_TARGET_HEIGHTS:
            registry = {
                "registry_version": MANIFEST.INGRESS_REGISTRY_VERSION,
                "chain_id": MANIFEST.CHAIN_ID,
                "network_id": MANIFEST.NETWORK_ID,
                "protocol_version": MANIFEST.PROTOCOL,
                "epoch": 0,
                "target_height": target_height,
                "assigned_cluster_id": MANIFEST.INITIAL_CLUSTER_ID,
                "records": runtime_records,
            }
            registry_root = MANIFEST.etdag_domain_digest(
                MANIFEST.INGRESS_REGISTRY_DOMAIN,
                MANIFEST.canonical_json([
                    MANIFEST.INGRESS_REGISTRY_VERSION, MANIFEST.CHAIN_ID,
                    MANIFEST.NETWORK_ID, MANIFEST.PROTOCOL, 0, target_height,
                    MANIFEST.INITIAL_CLUSTER_ID, runtime_records,
                ]),
            )
            wrapper = {
                "format": MANIFEST.INGRESS_REGISTRY_FORMAT,
                "epoch_context_root": epoch_context_bytes,
                "epoch": 0,
                "target_height": target_height,
                "assigned_cluster_id": MANIFEST.INITIAL_CLUSTER_ID,
                "registry_root": registry_root,
                "registry": registry,
            }
            (registry_directory / f"epoch-0-height-{target_height}-cluster-0.json").write_bytes(
                MANIFEST.canonical_json(wrapper)
            )
            wrappers[target_height] = wrapper
        return records_path, registry_directory, wrappers

    def validate(self, records_path: Path, registry_directory: Path) -> dict[str, object]:
        return MANIFEST.validate_etdag_ingress_artifacts(
            records_path,
            registry_directory,
            self.genesis_sha256,
            self.genesis_hash,
        )

    def test_accepts_exact_canonical_genesis_bound_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records_path, registry_directory, wrappers = self.artifacts(Path(directory))
            context = self.validate(records_path, registry_directory)
            self.assertEqual(context["epoch"], 0)
            self.assertEqual(context["assigned_cluster_id"], 0)
            self.assertEqual(set(context["registries"]), {"1", "2", "3"})
            self.assertEqual(context["registries"]["3"]["registry_root_sha3_512"],
                             wrappers[3]["registry_root"])

    def test_rejects_registry_root_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records_path, registry_directory, wrappers = self.artifacts(Path(directory))
            wrappers[2]["registry_root"] = "f" * 128
            (registry_directory / "epoch-0-height-2-cluster-0.json").write_bytes(
                MANIFEST.canonical_json(wrappers[2])
            )
            with self.assertRaisesRegex(SystemExit, "root does not match"):
                self.validate(records_path, registry_directory)

    def test_rejects_noncanonical_registry_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records_path, registry_directory, wrappers = self.artifacts(Path(directory))
            (registry_directory / "epoch-0-height-1-cluster-0.json").write_text(
                json.dumps(wrappers[1], indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(SystemExit, "not exact canonical compact JSON"):
                self.validate(records_path, registry_directory)

    def test_rejects_public_record_key_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records_path, registry_directory, _ = self.artifacts(Path(directory))
            records = json.loads(records_path.read_text(encoding="utf-8"))
            records["records"][0]["public_key_base64"] = base64.b64encode(b"wrong").decode("ascii")
            records_path.write_text(json.dumps(records), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "disagrees with runtime registry"):
                self.validate(records_path, registry_directory)


if __name__ == "__main__":
    unittest.main()
