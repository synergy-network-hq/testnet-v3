import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "formation_review", Path(__file__).with_name("review-replacement-formation.py")
)
formation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(formation)


class FormationReviewTests(unittest.TestCase):
    def test_exact_public_inputs_and_fresh_epoch_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)

            def write(name, value):
                raw = json.dumps(value).encode()
                (directory / name).write_bytes(raw)
                return hashlib.sha256(raw).hexdigest()

            network = dict(chain_id=1266, network_id="replacement-fixture")
            context = dict(chain_id_hex=f"{1266:064x}", network_id=network["network_id"],
                           formation_id="a" * 64)
            addresses = {host: f"synv1fixture{host}" for host in sorted(formation.HOSTS)}
            keys = {host: (bytes([number]) * 1952, bytes([number + 10]) * 1568)
                    for number, host in enumerate(addresses, 1)}
            registrations = {
                host: write(f"{host}.json", {"payload": {
                    "schema_version": "apqe-validator-formation-registration-v1",
                    "formation": context, "identity": {"address": address,
                        "consensus_key": {"public_key": keys[host][0].hex()}},
                    "ingress_key": {"public_key": keys[host][1].hex()},
                }}) for host, address in addresses.items()
            }
            authority = dict(**network, epoch=1, epoch_start_height=1, epoch_end_height=1000,
                             anchor_parent={"kind": "genesis", "reference": {
                                 "genesis_hash": "", "block_id": "", "reference_id": ""}},
                             validators=[{"record": {"validator_id": address, "status": "active",
                                                     "frozen_voting_weight": 100},
                                          "algorithm": "ml_dsa65", "public_key": list(keys[host][0])}
                                         for host, address in addresses.items()],
                             protected={"version": 2, "cutoff_relationship": "processing_groups_v1",
                                        "assigned_cluster_id": 0, "cluster_schedule_version": "",
                                        "epoch_start_timestamp_ms": 1700000000000,
                                        "initial_world_state": {"accounts": {
                                            "syna-fixture": {"balance_nwei": 123, "nonce": 0}}},
                                        "ingress_kem_registry": {"records": [
                                           {"validator_id": address, "activation_height": 1,
                                            "retirement_height": None, "public_key": {
                                                "algorithm": "ML-KEM-1024", "public_key": list(keys[host][1])}}
                                           for host, address in addresses.items()]}})
            recipe = dict(authority=authority, network={**network, "protocol_version": "posy/3.0",
                          "autonomous_epoch_protocol": "posy-autonomous-epochs-v1",
                          "activation_unix": 1700000000},
                          validators=[], seed_source={"kind": "genesis_hash"})
            expectations = dict(**network, formation_sha256=write("formation.json", context),
                                recipe_sha256=write("recipe.json", recipe), registrations=registrations,
                                allocations={"syna-fixture": {"purpose": "authorized_funding", "balance_nwei": "123"}})
            result = formation.review(directory, expectations)
            self.assertEqual(result["validators_by_host"], addresses)
            self.assertTrue(result["native_signature_verification_required"])
            self.assertEqual(result["initial_allocation_total_nwei"], "123")
            self.assertEqual(result["initial_quorum"]["minimum_distinct_signers"], 4)
            self.assertEqual(result["initial_quorum"]["minimum_signed_weight"], "334")
            with self.assertRaisesRegex(ValueError, "approved allocation map"):
                formation.review(directory, {**expectations, "allocations": {}})
            with self.assertRaisesRegex(ValueError, "balance or purpose"):
                formation.review(directory, {**expectations, "allocations": {
                    "syna-fixture": {"purpose": "authorized_funding", "balance_nwei": "124"}}})

            wrong_hosts = dict(registrations)
            wrong_hosts["val5"] = wrong_hosts.pop("val1")
            with self.assertRaisesRegex(ValueError, "host roster"):
                formation.review(directory, {**expectations, "registrations": wrong_hosts})
            authority["epoch_end_height"] = 999999
            changed_pin = write("recipe.json", recipe)
            with self.assertRaisesRegex(ValueError, "reviewed SHA-256"):
                formation.review(directory, expectations)
            expectations["recipe_sha256"] = changed_pin
            with self.assertRaisesRegex(ValueError, "epoch"):
                formation.review(directory, expectations)
            authority["epoch_end_height"] = 1000
            saved_key = authority["validators"][0]["public_key"]
            authority["validators"][0]["public_key"] = authority["validators"][1]["public_key"]
            expectations["recipe_sha256"] = write("recipe.json", recipe)
            with self.assertRaisesRegex(ValueError, "signer, frozen weight or ingress key"):
                formation.review(directory, expectations)
            authority["validators"][0]["public_key"] = saved_key
            recipe["network"].pop("autonomous_epoch_protocol")
            expectations["recipe_sha256"] = write("recipe.json", recipe)
            with self.assertRaisesRegex(ValueError, "fresh PoSy Genesis"):
                formation.review(directory, expectations)
            recipe["network"]["autonomous_epoch_protocol"] = "posy-autonomous-epochs-v1"
            authority["validators"][0] = authority["validators"][1]
            expectations["recipe_sha256"] = write("recipe.json", recipe)
            with self.assertRaisesRegex(ValueError, "authority roster"):
                formation.review(directory, expectations)


    def test_treasury_projection_requires_exact_operator_approval(self):
        recipe = {"authority": {"protected": {"initial_world_state": {"accounts": {}}}},
                  "canary_testing_treasury": {"address": "syna-treasury"}}
        approval = {"syna-treasury": {"purpose": "treasury", "balance_nwei": str(formation.TREASURY_NWEI)}}
        self.assertEqual(formation.review_allocations(recipe, approval), str(formation.TREASURY_NWEI))
        with self.assertRaisesRegex(ValueError, "distinct approved treasury"):
            formation.review_allocations(recipe, {})
