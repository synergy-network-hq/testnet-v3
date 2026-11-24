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
            registrations = {
                host: write(f"{host}.json", {"payload": {
                    "schema_version": "apqe-validator-formation-registration-v1",
                    "formation": context, "identity": {"address": address},
                }}) for host, address in addresses.items()
            }
            authority = dict(**network, epoch=1, epoch_start_height=1, epoch_end_height=1000,
                             anchor_parent={"kind": "genesis", "reference": {
                                 "genesis_hash": "", "block_id": "", "reference_id": ""}},
                             validators=[{"record": {"validator_id": address}}
                                         for address in addresses.values()],
                             protected={"cutoff_relationship": "processing_groups_v1"})
            recipe = dict(authority=authority, network={**network, "protocol_version": "posy/3.0"},
                          validators=[], seed_source={"kind": "genesis_hash"})
            expectations = dict(**network, formation_sha256=write("formation.json", context),
                                recipe_sha256=write("recipe.json", recipe), registrations=registrations)
            result = formation.review(directory, expectations)
            self.assertEqual(result["validators_by_host"], addresses)
            self.assertTrue(result["native_signature_verification_required"])

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
            authority["validators"][0] = authority["validators"][1]
            expectations["recipe_sha256"] = write("recipe.json", recipe)
            with self.assertRaisesRegex(ValueError, "authority roster"):
                formation.review(directory, expectations)
