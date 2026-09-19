#!/usr/bin/env python3
"""Public metadata regressions; synthetic custody placeholders, no key generation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "freeze", ROOT / "scripts/build-fresh-testnet-v3-genesis-authority-freeze.py")
freeze = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freeze)
PRIOR = ROOT / "launch/posy-v3-genesis-inputs/fresh-genesis-authority-freeze.json"


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prior, prior_hash = freeze.read_prior_freeze(PRIOR)
        self.manifest = {
            "schema_version": "synergy-testnet-v3-authority-custody-replacement-completion-v1",
            "chain_id": 1266, "network_id": "testnet", "release_id": "testnet-v3",
            "registry_version": "SNTS-01-v1.3",
            "publication_protocol": "no-clobber-manifest-last",
            "authority_role_ids": list(freeze.ROLES), "authority_count": 3,
            "replacement_prior_freeze_sha256": prior_hash,
            "replacement_reason": "authorized replacement test",
            "effective_at": "2026-09-05T00:00:00Z",
            "artifact_sha256": {},
        }
        for index, role in enumerate(freeze.ROLES):
            self.make_role(role, index)
        self.publish_manifest()

    def write(self, relative, doc):
        path = self.root / relative
        path.parent.mkdir(exist_ok=True)
        raw = freeze.canonical_json_bytes(doc)
        path.write_bytes(raw)
        self.manifest["artifact_sha256"][str(relative)] = freeze.sha256_bytes(raw)
        return freeze.sha256_bytes(raw)

    def publish_manifest(self):
        (self.root / freeze.REPLACEMENT_MANIFEST).write_bytes(
            freeze.canonical_json_bytes(self.manifest))

    def make_role(self, role, index):
        root_key = bytes([index + 1]) * freeze.ROOT_PUBLIC_KEY_BYTES
        auth_key = bytes([index + 4]) * freeze.AUTH_PUBLIC_KEY_BYTES
        address = freeze.derive_authority_address(root_key)
        old = self.prior[role]
        base = {key: self.manifest[key] for key in (
            "chain_id", "network_id", "release_id", "registry_version",
            "publication_protocol", "replacement_prior_freeze_sha256",
            "replacement_reason", "effective_at")}
        base.update(superseded_identity_address=old["address"],
                    superseded_public_key_sha3_256=old["auth_digest"])
        root = dict(schema_version=freeze.ROOT_SCHEMA, binary_encoding="lowercase-hex",
                    identity_id=role, address=address, address_type="WalletAccount",
                    algorithm=freeze.ROOT_ALGORITHM, public_key=root_key.hex())
        auth = dict(schema_version=freeze.AUTH_SCHEMAS[role], binary_encoding="lowercase-hex",
                    role_id=role, algorithm=freeze.AUTH_ALGORITHM, public_key=auth_key.hex())
        hashes = {
            "root": self.write(f"{role}/identity-root.pub.json", root),
            "auth": self.write(f"{role}/identity.pub.json", auth),
            "root_enc": self.write(f"{role}/identity-root.enc.json", {"synthetic": "root"}),
            "auth_enc": self.write(f"{role}/identity.enc.json", {"synthetic": "authorization"}),
        }
        self.write(f"{role}/identity-root.enc.json.snts07-complete.json", {
            **base, "schema_version": "snts07-new-key-root-completion-v1",
            "identity_id": role, "address": address, "algorithm": freeze.ROOT_ALGORITHM,
            "public_output_sha256": hashes["root"], "encrypted_output_sha256": hashes["root_enc"],
            "key_material_correspondence_verified": True, "address_rederivation_verified": True,
            "post_encrypt_decrypt_verified": True})
        self.write(f"{role}/identity.enc.json.snts07-complete.json", {
            **base, "schema_version": ("snts07-governance-authorization-key-rotation-completion-v1"
                if role == freeze.ROLES[1] else "snts07-authorization-key-generation-completion-v1"),
            "role_id": role, "algorithm": freeze.AUTH_ALGORITHM,
            "public_output_sha256": hashes["auth"], "encrypted_output_sha256": hashes["auth_enc"],
            "ml_dsa_87_signing_correspondence_verified": True, "same_passphrase_decrypt_verified": True,
            "public_key_sha3_256": freeze.sha3_256_bytes(auth_key),
            "new_public_key_sha3_256": freeze.sha3_256_bytes(auth_key)})
        for release in (False, True):
            if release and role != freeze.ROLES[1]:
                continue
            scopes = [freeze.RELEASE_SCOPE] if release else list(freeze.SCOPES)
            binding = {
                "schema_version": "synergy-identity-authorization-binding-v1",
                "binary_encoding": "lowercase-hex", "identity_id": role,
                "identity_address": address,
                "identity_root": {"algorithm": freeze.ROOT_ALGORITHM,
                    "public_key": root_key.hex(), "public_key_sha3_256": freeze.sha3_256_bytes(root_key)},
                "authorization_policy": {"policy_type": "single-key", "threshold": 1,
                    "principals": [{"principal_id": role, "principal_type": "public-key",
                        "algorithm": freeze.AUTH_ALGORITHM, "public_key": auth_key.hex(),
                        "public_key_sha3_256": freeze.sha3_256_bytes(auth_key),
                        "status": "active", "purposes": [scope["purpose"] for scope in scopes]}]},
                "authorization_scopes": scopes, "current_auth_key_hash": freeze.sha3_256_bytes(auth_key),
                "auth_key_history": [{"principal_id": role, "algorithm": freeze.AUTH_ALGORITHM,
                    "public_key_sha3_256": old["auth_digest"], "status": "retired",
                    "retired_at": base["effective_at"], "reason": base["replacement_reason"]}],
                "supersession_history": [{"address": old["address"],
                    "derivation_standard": freeze.REPLACEMENT_DERIVATION,
                    "status": "superseded", "reason": base["replacement_reason"]}],
                "effective_at": base["effective_at"], "binding_payload_sha3_256": "a" * 64,
                "proofs": {"identity_root": {"algorithm": freeze.ROOT_ALGORITHM},
                    "authorization_key_possession": [{"principal_id": role, "algorithm": freeze.AUTH_ALGORITHM}]},
            }
            name = "release-authorization-binding.json" if release else "genesis-authorization-binding.json"
            digest = self.write(f"{role}/{name}", binding)
            self.write(f"{role}/{name}.complete.json", {
                **base, "schema_version": "synergy-authorization-binding-completion-v1",
                "identity_id": role, "role_id": role, "identity_address": address,
                "signature_domain": scopes[0]["signature_domain"], "purpose": scopes[0]["purpose"],
                "authorization_scopes": scopes, "authorization_scope_signed": True,
                "dual_possession_proofs_verified": True, "fn_identity_root_correspondence_verified": True,
                "ml_authorization_key_correspondence_verified": True,
                "binding_output_sha256": digest, "binding_payload_sha3_256": "a" * 64,
                "fn_public_input_sha256": hashes["root"], "fn_encrypted_input_sha256": hashes["root_enc"],
                "ml_public_input_sha256": hashes["auth"], "ml_encrypted_input_sha256": hashes["auth_enc"],
            })

    def mutate_binding(self, role, edit):
        relative = f"{role}/genesis-authorization-binding.json"
        value = json.loads((self.root / relative).read_text())
        edit(value)
        digest = self.write(relative, value)
        receipt_path = relative + ".complete.json"
        receipt = json.loads((self.root / receipt_path).read_text())
        receipt["binding_output_sha256"] = digest
        self.write(receipt_path, receipt)
        self.publish_manifest()

    def test_complete_replacement_links_exact_prior(self):
        result = freeze.build(self.root, PRIOR)
        self.assertEqual(result["authority_count"], 3)
        self.assertEqual(result["authority_replacement"]["prior_freeze_sha256"],
                         freeze.sha256_bytes(PRIOR.read_bytes()))

    def test_requires_explicit_prior(self):
        with self.assertRaisesRegex(freeze.FreezeError, "--prior-freeze"):
            freeze.build(self.root)

    def test_rejects_missing_final_manifest(self):
        (self.root / freeze.REPLACEMENT_MANIFEST).unlink()
        with self.assertRaisesRegex(freeze.FreezeError, "regular non-symlink"):
            freeze.build(self.root, PRIOR)

    def test_rejects_wrong_prior_digest(self):
        self.manifest["replacement_prior_freeze_sha256"] = "0" * 64
        self.publish_manifest()
        with self.assertRaisesRegex(freeze.FreezeError, "prior freeze SHA-256"):
            freeze.build(self.root, PRIOR)

    def test_rejects_wrong_same_role_prior_key(self):
        self.mutate_binding(freeze.ROLES[0], lambda b: b["auth_key_history"][0].update(
            public_key_sha3_256=self.prior[freeze.ROLES[1]]["auth_digest"]))
        with self.assertRaisesRegex(freeze.FreezeError, "retired key public_key_sha3_256"):
            freeze.build(self.root, PRIOR)

    def test_rejects_wrong_same_role_prior_address(self):
        self.mutate_binding(freeze.ROLES[0], lambda b: b["supersession_history"][0].update(
            address=self.prior[freeze.ROLES[1]]["address"]))
        with self.assertRaisesRegex(freeze.FreezeError, "supersession address"):
            freeze.build(self.root, PRIOR)

    def test_rejects_historical_derivation_claim(self):
        self.mutate_binding(freeze.ROLES[0], lambda b: b["supersession_history"][0].update(
            derivation_standard="pre-SNTS-01-v1.3-ML-DSA-87-key-derived-authority-address"))
        with self.assertRaisesRegex(freeze.FreezeError, "derivation_standard"):
            freeze.build(self.root, PRIOR)

    def test_rejects_incomplete_manifest_inventory(self):
        del self.manifest["artifact_sha256"][f"{freeze.ROLES[0]}/identity.pub.json"]
        self.publish_manifest()
        with self.assertRaisesRegex(freeze.FreezeError, "inventory"):
            freeze.build(self.root, PRIOR)

    def test_rejects_post_publication_artifact_change(self):
        (self.root / freeze.ROLES[0] / "identity.pub.json").write_text("{}")
        with self.assertRaisesRegex(freeze.FreezeError, "SHA-256"):
            freeze.build(self.root, PRIOR)

    def test_replacement_receipt_cannot_claim_another_prior(self):
        role = freeze.ROLES[0]
        relative = f"{role}/identity.enc.json.snts07-complete.json"
        receipt = json.loads((self.root / relative).read_text())
        receipt["replacement_prior_freeze_sha256"] = "f" * 64
        self.write(relative, receipt)
        self.publish_manifest()
        with self.assertRaisesRegex(freeze.FreezeError, "replacement_prior_freeze_sha256"):
            freeze.build(self.root, PRIOR)

    def test_receipts_require_prior_even_without_manifest(self):
        (self.root / freeze.REPLACEMENT_MANIFEST).unlink()
        with self.assertRaisesRegex(freeze.FreezeError, "--prior-freeze"):
            freeze.build(self.root)

    def test_legacy_nonreplacement_behavior_is_preserved(self):
        (self.root / freeze.REPLACEMENT_MANIFEST).unlink()
        for role in freeze.ROLES:
            for name in ("genesis-authorization-binding.json", "release-authorization-binding.json"):
                path = self.root / role / name
                if not path.exists():
                    continue
                binding = json.loads(path.read_text())
                if role == freeze.ROLES[1]:
                    binding["supersession_history"][0]["derivation_standard"] = (
                        "pre-SNTS-01-v1.3-ML-DSA-87-key-derived-authority-address")
                else:
                    binding["auth_key_history"] = []
                    binding["supersession_history"] = []
                digest = self.write(f"{role}/{name}", binding)
                receipt_path = f"{role}/{name}.complete.json"
                receipt = json.loads((self.root / receipt_path).read_text())
                receipt["binding_output_sha256"] = digest
                self.write(receipt_path, receipt)
            for path in (self.root / role).iterdir():
                if "complete.json" not in path.name:
                    continue
                receipt = json.loads(path.read_text())
                for key in ("replacement_prior_freeze_sha256", "replacement_reason",
                            "superseded_identity_address", "superseded_public_key_sha3_256"):
                    receipt.pop(key, None)
                path.write_bytes(freeze.canonical_json_bytes(receipt))
        result = freeze.build(self.root)
        self.assertNotIn("authority_replacement", result)
        self.assertEqual(result["authority_count"], 3)

    def test_rejects_prior_address_not_derived_from_root(self):
        prior = json.loads(PRIOR.read_text())
        prior["authorities"][0]["identity_address"] = prior["authorities"][1]["identity_address"]
        path = self.root / "prior.json"
        path.write_text(json.dumps(prior))
        with self.assertRaisesRegex(freeze.FreezeError, "prior identity address"):
            freeze.read_prior_freeze(path)


if __name__ == "__main__":
    unittest.main()
