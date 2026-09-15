import importlib.util
import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "macos" / "archive-authority.py"
SPEC = importlib.util.spec_from_file_location("archive_authority", MODULE_PATH)
archive_authority = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(archive_authority)


class ArchiveAuthorityPolicyTests(unittest.TestCase):
    def test_sign_json_replaces_prior_signature_before_signing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aegis = root / "synergy-aegis"
            aegis.write_text("#!/bin/sh\n", encoding="utf-8")
            aegis.chmod(0o700)
            payload = root / "payload.json"
            payload.write_text("{}\n", encoding="utf-8")
            signature = root / "payload.sig"
            signature.write_text("stale", encoding="utf-8")

            original_run = archive_authority.run

            def fake_run(_command):
                self.assertFalse(signature.exists())
                return '{"ok": true}'

            try:
                archive_authority.run = fake_run
                result = archive_authority.sign_json(
                    aegis,
                    root,
                    "SYNERGY_TEST_DOMAIN",
                    payload,
                    signature,
                )
            finally:
                archive_authority.run = original_run

            self.assertEqual(result, {"ok": True})

    def test_public_catalog_entry_has_consumer_urls_and_compatibility(self) -> None:
        entry = {
            "height": 843613,
            "size_compressed": 123,
            "mirror_urls": ["https://archive.example/"],
        }

        archive_authority.enrich_public_catalog_entry(entry)

        self.assertEqual(entry["producer_role"], "archive_validator")
        self.assertEqual(entry["producer_node_kind"], "archive-validator")
        self.assertEqual(
            entry["binary_compatibility"],
            "synergy-testnet-v3-validator-pruned-v1",
        )
        self.assertEqual(
            entry["snapshot_url"],
            "https://archive.example/snapshots/843613/snapshot.tar.zst",
        )
        self.assertEqual(
            entry["manifest_signature_url"],
            "https://archive.example/snapshots/843613/signature.sig",
        )
        self.assertEqual(entry["compressed_size_bytes"], 123)

    def test_catalog_content_root_is_stable_for_key_order(self) -> None:
        left = [{"height": 10, "hash": "abc"}]
        right = [{"hash": "abc", "height": 10}]
        self.assertEqual(
            archive_authority.catalog_content_root(left),
            archive_authority.catalog_content_root(right),
        )

    def valid_consensus_fork(self) -> dict:
        return {
            "fork_height": archive_authority.FORK_HEIGHT,
            "parent_height": archive_authority.FORK_PARENT_HEIGHT,
            "parent_hash": archive_authority.FORK_PARENT_HASH,
            "state_root": "checkpoint-v1:test",
            "old_consensus_algorithm": archive_authority.OLD_CONSENSUS_ALGORITHM,
            "new_consensus_algorithm": archive_authority.POST_FORK_CONSENSUS_ALGORITHM,
            "parser_mode": archive_authority.FORK_PARSER_MODE,
            "new_validator_registry": [
                {
                    "validator_address": f"synv11testvalidator{index}",
                    "consensus_key_type": archive_authority.POST_FORK_CONSENSUS_ALGORITHM,
                    "consensus_public_key": base64.b64encode(
                        bytes([index]) * archive_authority.FNDSA_PUBLIC_KEY_BYTES
                    ).decode("ascii"),
                }
                for index in range(archive_authority.FORK_VALIDATOR_COUNT)
            ],
        }

    def test_default_worker_classes_are_current_role_classes_only(self) -> None:
        self.assertEqual(
            archive_authority.DEFAULT_WORKER_CLASSES,
            [
                "validator-pruned",
                "support-relayer",
                "support-observer",
                "indexer-replay",
                "support-rpc",
                "archive-full",
            ],
        )

    def test_validator_pruned_creation_uses_current_validator_source_role(self) -> None:
        self.assertEqual(
            archive_authority.producer_role_for_snapshot_class("validator-pruned"),
            "VALIDATOR",
        )
        self.assertEqual(
            archive_authority.producer_role_for_snapshot_class("support-rpc"),
            "ARCHIVE_NODE",
        )

    def test_validator_pruned_manifest_source_role_must_be_current_validator(self) -> None:
        self.assertEqual(
            archive_authority.validate_manifest_source_role(
                "validator-pruned",
                {"source_role": "validator"},
            ),
            "VALIDATOR",
        )
        with self.assertRaisesRegex(RuntimeError, "GENESIS_VALIDATOR.*legacy/stale"):
            archive_authority.validate_manifest_source_role(
                "validator-pruned",
                {"source_role": "GENESIS_VALIDATOR"},
            )
        with self.assertRaisesRegex(RuntimeError, "source_role must be VALIDATOR"):
            archive_authority.validate_manifest_source_role(
                "validator-pruned",
                {"source_role": "ARCHIVE_NODE"},
            )

    def test_current_role_class_cadence_and_retention(self) -> None:
        policy = archive_authority.CLASS_POLICY
        self.assertEqual(policy["archive-full"]["cadence"], 15_000)
        for snapshot_class in [
            "validator-pruned",
            "support-relayer",
            "support-observer",
            "indexer-replay",
            "support-rpc",
        ]:
            self.assertEqual(policy[snapshot_class]["cadence"], 5_000)
            self.assertEqual(policy[snapshot_class]["retain"], 2)

    def test_current_roles_have_default_snapshot_coverage(self) -> None:
        coverage = {
            role: snapshot_class
            for snapshot_class in archive_authority.DEFAULT_WORKER_CLASSES
            for role in archive_authority.CLASS_POLICY[snapshot_class]["roles"]
        }
        self.assertEqual(coverage["validator"], "validator-pruned")
        self.assertEqual(coverage["onboarding_validator"], "validator-pruned")
        self.assertEqual(coverage["quarantined_validator"], "validator-pruned")
        self.assertEqual(coverage["rpc"], "support-rpc")
        self.assertEqual(coverage["relayer"], "support-relayer")
        self.assertEqual(coverage["observer"], "support-observer")
        self.assertEqual(coverage["indexer"], "indexer-replay")
        self.assertEqual(coverage["explorer"], "indexer-replay")
        self.assertEqual(coverage["atlas_indexer"], "indexer-replay")
        self.assertEqual(coverage["explorer_indexer"], "indexer-replay")
        self.assertEqual(coverage["rpc_gateway"], "support-rpc")
        self.assertEqual(coverage["archive"], "archive-full")
        self.assertEqual(coverage["archive_validator"], "archive-full")
        self.assertEqual(coverage["snapshot_authority"], "archive-full")

    def test_receiver_operating_systems_include_windows(self) -> None:
        self.assertEqual(
            archive_authority.SUPPORTED_RECEIVER_OPERATING_SYSTEMS,
            ["macos", "linux", "windows"],
        )
        self.assertEqual(archive_authority.RECEIVER_FORMAT["compression"], "zstd")
        self.assertEqual(archive_authority.RECEIVER_FORMAT["archive_container"], "tar")
        self.assertIn("chain.json", archive_authority.RECEIVER_FORMAT["state_files"])

    def test_known_noncanonical_h602192_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "archive-contained"):
            archive_authority.reject_known_noncanonical_archive_state(602_192, "0d1c124fdeadbeef")
        archive_authority.reject_known_noncanonical_archive_state(602_192, "649b76bfabc123")

    def test_archive_canonical_status_marks_known_noncanonical_archive_contained(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            workspace = Path(tempdir)
            locks = {
                "602192": {
                    "height": 602_192,
                    "block_hash": "0d1c124faaaa",
                }
            }
            archive_authority.json_dump(workspace / "data" / "canonical_locks.json", locks)

            status = archive_authority.archive_canonical_status(workspace)

            self.assertEqual(status["state"], "archive-contained")
            self.assertFalse(status["publication_eligible"])
            self.assertEqual(status["height"], 602_192)
            self.assertIn("noncanonical", status["reason"])

    def test_publish_gate_requires_public_marker_matching_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            marker_path = root / "majority-proof.json"
            archive_authority.json_dump(
                marker_path,
                {
                    "source_node_majority_branch_proven": True,
                    "chain_id": archive_authority.CHAIN_ID,
                    "network_id": archive_authority.NETWORK_ID,
                    "genesis_hash": archive_authority.GENESIS_HASH,
                    "height": 601_891,
                    "hash": "goodhash",
                    "source_evidence_path": str(root / "evidence.json"),
                    "recorded_at": 1,
                },
            )
            args = SimpleNamespace(fixture_mode=False, majority_proof_marker=marker_path)
            report = {"snapshot_height": 601_891, "snapshot_hash": "goodhash"}

            proof = archive_authority.enforce_snapshot_publication_gate(args, report)

            self.assertEqual(proof["height"], 601_891)
            self.assertEqual(proof["hash"], "goodhash")
            self.assertEqual(proof["evidence_path"], str(root / "evidence.json"))
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                archive_authority.enforce_snapshot_publication_gate(
                    args,
                    {"snapshot_height": 601_891, "snapshot_hash": "otherhash"},
                )

    def test_publish_gate_rejects_known_noncanonical_snapshot_hash(self) -> None:
        args = SimpleNamespace(fixture_mode=True, majority_proof_marker=None)
        report = {"snapshot_height": 602_192, "snapshot_hash": "0d1c124fbad"}

        with self.assertRaisesRegex(RuntimeError, "archive-contained"):
            archive_authority.enforce_snapshot_publication_gate(args, report)

    def test_worker_requires_proof_marker_to_match_latest_archive_lock(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "proof marker is stale"):
            archive_authority.require_current_majority_proof(
                {"height": 100, "hash": "public-hash"},
                {"height": 101, "hash": "local-hash"},
            )
        with self.assertRaisesRegex(RuntimeError, "has no block hash"):
            archive_authority.require_current_majority_proof(
                {"height": 100, "hash": "public-hash"},
                {"height": 100, "hash": None},
            )
        archive_authority.require_current_majority_proof(
            {"height": 100, "hash": "Public-Hash"},
            {"height": 100, "hash": "public-hash"},
        )

    def test_worker_rejects_publish_root_outside_storage_volume(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            storage = root / "storage"
            storage.mkdir()
            with self.assertRaisesRegex(RuntimeError, "outside storage volume"):
                archive_authority.require_publish_storage(root / "local-publish", storage)

    def test_record_majority_proof_refuses_known_noncanonical_archive_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            evidence = root / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            args = SimpleNamespace(
                evidence_path=evidence,
                output=root / "majority-proof.json",
                height=602_192,
                hash="0d1c124fabcdef",
            )

            with self.assertRaisesRegex(RuntimeError, "archive-contained"):
                archive_authority.record_majority_proof(args)

    def test_source_safety_accepts_resolved_majority_conflict_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            snapshot_root = root / "snapshot-000000010"
            snapshot_root.mkdir()
            archive_authority.json_dump(
                snapshot_root / "chain.json",
                [{"block_index": 10, "hash": "majority-hash"}],
            )
            archive_authority.json_dump(
                snapshot_root / "canonical_locks.json",
                {"10": {"block_hash": "majority-hash"}},
            )
            (snapshot_root / "committed_qcs.jsonl").write_text(
                json.dumps({"height": 10, "block_hash": "majority-hash"}) + "\n",
                encoding="utf-8",
            )
            manifest = root / "snapshot-10-manifest.json"
            archive_authority.json_dump(
                manifest,
                {
                    "snapshot_height": 10,
                    "snapshot_block_hash": "majority-hash",
                    "source_node_majority_branch": True,
                    "conflict_height_hash": "rejected-fork-hash",
                },
            )

            report = archive_authority.source_safety_report(
                snapshot_root,
                manifest,
                fixture_mode=True,
            )

            self.assertEqual(report["resolved_conflict_height_hash"], "rejected-fork-hash")
            self.assertTrue(report["resolved_conflict_source_majority_branch"])

    def test_source_safety_rejects_unresolved_conflict_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            snapshot_root = root / "snapshot-000000010"
            snapshot_root.mkdir()
            archive_authority.json_dump(
                snapshot_root / "chain.json",
                [{"block_index": 10, "hash": "majority-hash"}],
            )
            manifest = root / "snapshot-10-manifest.json"
            archive_authority.json_dump(
                manifest,
                {
                    "snapshot_height": 10,
                    "snapshot_block_hash": "majority-hash",
                    "source_node_majority_branch": False,
                    "conflict_height_hash": "rejected-fork-hash",
                },
            )

            with self.assertRaisesRegex(RuntimeError, "unresolved conflict_height_hash"):
                archive_authority.source_safety_report(
                    snapshot_root,
                    manifest,
                    fixture_mode=True,
                )

    def test_publication_consensus_fork_uses_signed_manifest_when_root_metadata_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            stale_config = root / "config" / "consensus-fork-migration.json"
            stale_config.parent.mkdir(parents=True)
            archive_authority.json_dump(
                stale_config,
                {
                    "fork_height": archive_authority.FORK_HEIGHT,
                    "parent_height": archive_authority.FORK_PARENT_HEIGHT,
                    "parent_hash": archive_authority.FORK_PARENT_HASH,
                    "state_root": "checkpoint-v1:stale",
                    "old_consensus_algorithm": "stale",
                    "new_consensus_algorithm": archive_authority.POST_FORK_CONSENSUS_ALGORITHM,
                    "parser_mode": archive_authority.FORK_PARSER_MODE,
                    "new_validator_registry": [],
                },
            )
            manifest_fork = self.valid_consensus_fork()

            selected = archive_authority.publication_consensus_fork_metadata(
                root,
                {"consensus_fork": manifest_fork},
                archive_authority.FORK_HEIGHT,
            )

            self.assertEqual(selected, manifest_fork)

    def test_catalog_signing_can_derive_fork_from_entries_when_root_metadata_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            stale_config = root / "config" / "consensus-fork-migration.json"
            stale_config.parent.mkdir(parents=True)
            archive_authority.json_dump(
                stale_config,
                {
                    "fork_height": archive_authority.FORK_HEIGHT,
                    "parent_height": archive_authority.FORK_PARENT_HEIGHT,
                    "parent_hash": archive_authority.FORK_PARENT_HASH,
                    "state_root": "checkpoint-v1:stale",
                    "old_consensus_algorithm": "stale",
                    "new_consensus_algorithm": archive_authority.POST_FORK_CONSENSUS_ALGORITHM,
                    "parser_mode": archive_authority.FORK_PARSER_MODE,
                    "new_validator_registry": [],
                },
            )
            catalog = {
                "snapshots": [
                    {
                        "snapshot_id": "snapshot-000204216",
                        "snapshot_class": "validator-pruned",
                        "status": "published",
                        "height": archive_authority.FORK_HEIGHT,
                        "consensus_fork": self.valid_consensus_fork(),
                    }
                ]
            }

            selected = archive_authority.consensus_fork_from_catalog_entries(catalog)

            self.assertEqual(selected, catalog["snapshots"][0]["consensus_fork"])

    def test_catalog_update_retires_invalid_postfork_entries_before_signing(self) -> None:
        stale = {
            "snapshot_id": "snapshot-000204216",
            "snapshot_class": "validator-pruned",
            "status": "published",
            "height": archive_authority.FORK_HEIGHT,
            "verification_status": "green",
            "consensus_fork": {
                "fork_height": archive_authority.FORK_HEIGHT,
                "parent_height": archive_authority.FORK_PARENT_HEIGHT,
                "parent_hash": archive_authority.FORK_PARENT_HASH,
                "state_root": "checkpoint-v1:stale",
                "old_consensus_algorithm": "stale",
                "new_consensus_algorithm": archive_authority.POST_FORK_CONSENSUS_ALGORITHM,
                "parser_mode": archive_authority.FORK_PARSER_MODE,
                "new_validator_registry": [],
            },
        }
        replacement = {
            "snapshot_id": "snapshot-000675736",
            "snapshot_class": "validator-pruned",
            "height": 675_736,
        }

        cleaned = archive_authority.retire_invalid_consensus_fork_entries(
            [stale],
            replacement,
        )

        self.assertEqual(cleaned[0]["status"], "deleted")
        self.assertEqual(cleaned[0]["verification_status"], "red")
        self.assertEqual(cleaned[0]["superseded_by"], "snapshot-000675736")
        self.assertTrue(archive_authority.entry_has_valid_consensus_fork(cleaned[0]))

    def test_catalog_update_retires_legacy_validator_pruned_source_role(self) -> None:
        stale = {
            "snapshot_id": "snapshot-000204216",
            "snapshot_class": "validator-pruned",
            "status": "published",
            "height": archive_authority.FORK_HEIGHT,
            "source_role": "GENESIS_VALIDATOR",
            "verification_status": "green",
        }
        replacement = {
            "snapshot_id": "snapshot-000675736",
            "snapshot_class": "validator-pruned",
            "height": 675_736,
            "source_role": "VALIDATOR",
        }

        cleaned = archive_authority.retire_invalid_source_role_entries(
            [
                stale,
                {
                    "snapshot_id": "snapshot-000204217",
                    "snapshot_class": "validator-pruned",
                    "status": "published",
                    "height": archive_authority.FORK_HEIGHT + 1,
                    "verification_status": "green",
                },
            ],
            replacement,
        )

        self.assertEqual(cleaned[0]["status"], "deleted")
        self.assertEqual(cleaned[0]["verification_status"], "red")
        self.assertEqual(cleaned[0]["superseded_by"], "snapshot-000675736")
        self.assertIn("source_role", cleaned[0]["notes"][0])
        self.assertTrue(
            archive_authority.entry_has_current_validator_pruned_source_role(cleaned[0])
        )
        self.assertEqual(cleaned[1]["status"], "deleted")
        self.assertEqual(cleaned[1]["superseded_by"], "snapshot-000675736")

    def test_write_signed_catalog_ignores_deleted_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            publish_root = root / "published"
            publish_root.mkdir()
            valid_fork = self.valid_consensus_fork()
            catalog = {
                "schema": "synergy-archive-snapshot-catalog-v1",
                "chain_id": archive_authority.CHAIN_ID,
                "network_id": archive_authority.NETWORK_ID,
                "genesis_hash": archive_authority.GENESIS_HASH,
                "updated_at": 1,
                "snapshots": [
                    {
                        "snapshot_id": "snapshot-000204216",
                        "snapshot_class": "validator-pruned",
                        "status": "deleted",
                        "height": archive_authority.FORK_HEIGHT,
                        "consensus_fork": {
                            "old_consensus_algorithm": "stale",
                            "new_validator_registry": [],
                        },
                    },
                    {
                        "snapshot_id": "snapshot-000675736",
                        "snapshot_class": "validator-pruned",
                        "status": "published",
                        "height": 675_736,
                        "consensus_fork": valid_fork,
                    },
                ],
            }
            original_sign = archive_authority.sign_json
            original_verify = archive_authority.verify_json
            try:
                archive_authority.sign_json = lambda *_args, **_kwargs: {"ok": True}
                archive_authority.verify_json = lambda *_args, **_kwargs: {"ok": True}

                archive_authority.write_signed_catalog(
                    Path("/unused/aegis"),
                    root,
                    publish_root,
                    catalog,
                )
            finally:
                archive_authority.sign_json = original_sign
                archive_authority.verify_json = original_verify

            written = json.loads((publish_root / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual(written["consensus_fork"], valid_fork)
            published = [entry for entry in written["snapshots"] if entry["status"] == "published"][0]
            self.assertEqual(
                published["supported_receiver_operating_systems"],
                ["macos", "linux", "windows"],
            )
            self.assertEqual(published["receiver_format"]["compression"], "zstd")

    def test_prune_apply_enforces_two_per_class_without_retired_grace(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            publish_root = root / "published"
            publish_root.mkdir()
            removed_path = publish_root / "testnet-1264" / "support-observer" / "snapshot-000000100"
            removed_path.mkdir(parents=True)
            kept_path = publish_root / "testnet-1264" / "support-observer" / "snapshot-000000300"
            kept_path.mkdir(parents=True)
            archive_removed_path = publish_root / "testnet-1264" / "archive-full" / "snapshot-000010000"
            archive_removed_path.mkdir(parents=True)

            def entry(snapshot_class: str, height: int, local_path: Path, *, pinned: bool = False) -> dict:
                return {
                    "snapshot_id": f"snapshot-{height:09d}",
                    "snapshot_class": snapshot_class,
                    "height": height,
                    "status": "published",
                    "local_path": str(local_path),
                    "pinned": pinned,
                }

            catalog = {
                "schema": "synergy-archive-snapshot-catalog-v1",
                "chain_id": archive_authority.CHAIN_ID,
                "network_id": archive_authority.NETWORK_ID,
                "genesis_hash": archive_authority.GENESIS_HASH,
                "updated_at": 1,
                "snapshots": [
                    entry("support-observer", 100, removed_path, pinned=True),
                    entry("support-observer", 200, publish_root / "snapshot-000000200"),
                    entry("support-observer", 300, kept_path),
                    entry("archive-full", 10_000, archive_removed_path),
                    entry("archive-full", 25_000, publish_root / "snapshot-000025000"),
                    entry("archive-full", 40_000, publish_root / "snapshot-000040000"),
                ],
            }
            archive_authority.json_dump(publish_root / "catalog.json", catalog)

            original_writer = archive_authority.write_signed_catalog
            try:
                archive_authority.write_signed_catalog = lambda _aegis, _root, out, value: archive_authority.json_dump(
                    out / "catalog.json", value
                )
                result = archive_authority.prune(
                    SimpleNamespace(
                        publish_root=publish_root,
                        root=root,
                        aegis=Path("/does/not/matter"),
                        apply=True,
                    )
                )
            finally:
                archive_authority.write_signed_catalog = original_writer

            self.assertTrue(result["ok"])
            self.assertFalse(removed_path.exists())
            self.assertFalse(archive_removed_path.exists())
            self.assertTrue(kept_path.exists())
            pruned = json.loads((publish_root / "catalog.json").read_text(encoding="utf-8"))
            remaining = {
                (item["snapshot_class"], item["snapshot_id"])
                for item in pruned["snapshots"]
            }
            self.assertNotIn(("support-observer", "snapshot-000000100"), remaining)
            self.assertNotIn(("archive-full", "snapshot-000010000"), remaining)
            self.assertIn(("support-observer", "snapshot-000000300"), remaining)
            self.assertEqual(
                sum(1 for item in pruned["snapshots"] if item["snapshot_class"] == "support-observer"),
                2,
            )
            self.assertEqual(
                sum(1 for item in pruned["snapshots"] if item["snapshot_class"] == "archive-full"),
                2,
            )
            self.assertTrue(
                any(action.get("pinned_ignored_for_hard_cap") for action in result["actions"])
            )


if __name__ == "__main__":
    unittest.main()
