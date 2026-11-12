import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "prepare_stability_launch", Path(__file__).with_name("prepare-stability-launch.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProtectedProfileRecipeTests(unittest.TestCase):
    def inputs(self):
        deployment = {key: "/isolated/" + key for key in (
            "manifest_path", "authority_path", "trust_public_key_path", "p2p_bindings_path",
            "transport_registry_path")}
        deployment.update(vpn_interface="wt0", transport_attestation_public_key="public-pin",
                          provider_plan_sha256="a" * 64)
        public = {}
        validators = []
        for number in range(2, 7):
            path = f"/public/val{number}"
            public[path] = {"node_address": f"synv1validator{number}", "public_key_fingerprint": "fingerprint"}
            validators.append(dict(number=number, public_identity_path=path, p2p={}, consensus={}, ingress={},
                deployment={key: f"/isolated/val{number}/{key}" for key in (
                    "public_identity_path", "p2p_secret_key_path", "consensus_secret_key_path",
                    "ingress_secret_key_path", "data_directory", "admin_socket_path")}))
        wallets = []
        for number in range(32):
            path = f"/public/wallet{number}"
            wallets.append(path)
            public[path] = dict(sender=f"syna1wallet{number}",
                identity_authorization={"binding": dict(identity_address=f"syna1wallet{number}",
                    authorization_scopes=[dict(chain_id=1266, network_id="fresh-async", purpose="transaction-signing")],
                    binding_payload_sha3_256="binding", identity_root={"public_key_sha3_256": "root"})},
                genesis_account=dict(balance_nwei=1000, nonce=0, code_hash=None),
                genesis_binding_commitment=dict(effective_at_unix=1700000000,
                    binding_payload_sha3_256="binding", identity_root_public_key_sha3_256="root"))
        return dict(deployment=deployment, validators=validators, wallet_public_paths=wallets), public

    def test_async_is_explicit_and_adds_reviewed_local_resource_configuration(self):
        inventory, public = self.inputs()
        def custody(_spec, purpose, _algorithm, _length, address):
            return dict(record=dict(id=purpose + address, public_key=[1]), public_key_fingerprint="fingerprint")
        with patch.object(module, "read_public", side_effect=lambda path: json.dumps(public[path]).encode()), \
             patch.object(module, "bundle", side_effect=custody):
            default = module.prepare(inventory, 1700000000, "canary-root", "fresh-async")
            legacy = module.prepare(inventory, 1700000000, "canary-root", "fresh-async", "vc_event_context_v1")
            processing = module.prepare(inventory, 1700000000, "canary-root", "fresh-async", "processing_groups_v1")
        self.assertEqual(default, legacy)
        expected = copy.deepcopy(legacy)
        policy = expected["fresh-genesis-input.json"]["authority"]["protected"]
        policy.update(version=2, cutoff_relationship="processing_groups_v1")
        for number in range(2,7):
            expected[f"val{number}.json"]["storage"].update(world_memory_budget_bytes=1073741824,
                prune_finalized_history_after_blocks=64)
        self.assertEqual(processing, expected)
        self.assertEqual(policy["parameters"]["target_height_offset"], 5)
        self.assertEqual(policy["parameters"]["profile_id"], "POSY-ETDAG-v3.0")

    def test_unsupported_profile_rejects_before_reading_inputs(self):
        with patch.object(module, "read_public") as read:
            with self.assertRaisesRegex(ValueError, "unsupported explicit protected profile"):
                module.prepare({}, 1700000000, "canary-root", "fresh-async", "unsupported")
            read.assert_not_called()


class SeparateCanaryPathsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "provision_stability_hosts", Path(__file__).with_name("provision-stability-hosts.py")
        )
        cls.provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.provision)

    def test_explicit_canary_rebases_only_fresh_provisioning(self):
        owner = self.provision
        original = owner.FRESH_RECEIVER
        self.assertEqual(owner.fresh_receiver(), original)
        name = "posy-async-canary-20261022"
        paths = owner.fresh_deployment_paths(name)
        code = owner.fresh_receiver(name)
        self.assertNotIn("/posy-stability", code)
        self.assertIn(paths["configuration"], code)
        self.assertIn(paths["executables"], code)
        self.assertIn(paths["state"], code)
        self.assertIn("validator must be stopped", code)
        self.assertIn("existing or partial fresh custody/state refused", code)
        self.assertEqual(owner.FRESH_RECEIVER, original)
        self.assertEqual(owner.REMOTE_CUSTODY, "/etc/synergy/posy-stability/custody")
        compile(code, "fresh-receiver", "exec")

    def test_old_names_and_traversal_cannot_select_canary_paths(self):
        for name in ("posy-stability", "posy-baseline", "production", "posy-async-canary-",
                     "posy-async-canary-../production", "posy-async-canary-Test"):
            with self.assertRaises(self.provision.ProvisionError):
                self.provision.fresh_deployment_paths(name)


class FreshStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "stage_stability_release", Path(__file__).with_name("stage-stability-release.py")
        )
        cls.stage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.stage)

    def fixture(self, root):
        stage = self.stage
        name = "posy-async-canary-test"
        paths = stage.owner.fresh_deployment_paths(name)
        output = paths["public_directory"]
        output.mkdir(parents=True)
        base = paths["configuration"]
        config = dict(chain_id=1266, network_id="fresh-async", manifest_path=base+"/network-manifest.json",
                      aegis_key_bindings_path=base+"/p2p-bindings.json",
                      admin_socket_path="/run/synergy-"+name+"/admin.sock",
                      public_identity_path=base+"/custody/p2p/public.identity.json",
                      aegis_signing_key_path=base+"/custody/p2p/secret.key",
                      consensus=dict(authority_binding=base+"/authority.json",
                                     authority_trust_key_path=base+"/authority-root.pub",
                                     signing_key_path=base+"/custody/consensus/secret.key"),
                      storage=dict(data_directory=paths["state"]),
                      vpn=dict(signed_registry_path=base+"/transport-registry.json"),
                      etdag=dict(ingress_kem_secret_key_path=base+"/custody/ingress/secret.key"))
        authority = dict(payload=dict(chain_id=1266, network_id="fresh-async", protected=dict(
            version=2, cutoff_relationship="processing_groups_v1")))
        for filename in ("genesis.json", "authority-root.pub", "network-manifest.json", "p2p-bindings.json",
                         "transport-registry.json", "release.json"):
            (output/filename).write_bytes(b"public-test-artifact")
        (output/"authority.json").write_text(json.dumps(authority))
        (output/"val2.json").write_text(json.dumps(config))
        binary = bytearray(64)
        binary[:7] = b"\x7fELF\x02\x01\x01"
        binary[18:20] = b"\x3e\x00"
        return name, paths, output, bytes(binary), config, authority

    def test_stage_uses_existing_master_exact_paths_and_never_starts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory, patch.object(self.stage.owner, "ROOT", Path(directory)):
            name, paths, output, binary, _, _ = self.fixture(directory)
            calls = []
            def remote(host, socket, argv, data=None):
                calls.append((host, socket, argv, data))
                return b""
            with patch.object(self.stage.owner, "fingerprint_binary", return_value=binary), \
                 patch.object(self.stage.owner, "master_arguments") as master, \
                 patch.object(self.stage.owner, "remote", side_effect=remote):
                result = self.stage.stage_fresh(2, "host2", "/master2", output, "node", "a"*64,
                    "fresh-async", "fresh-root", name, 1073741824)
            master.assert_called_once_with("host2", "/master2")
            self.assertFalse(result["started"])
            self.assertEqual(result["memory_max_bytes"], 1073741824)
            for host, socket, argv, _ in calls:
                self.assertEqual((host, socket), ("host2", "/master2"))
                self.assertNotIn("/posy-stability", " ".join(map(str, argv)))
                self.assertNotIn("systemctl", argv)
            receiver = calls[1][2][2]
            self.assertIn(paths["executables"]+"/synergy-node", receiver)
            self.assertNotIn(paths["executables"]+"/synergy-keytool", receiver)
            compile(receiver, "fresh-node-receiver", "exec")
            compile(self.stage.FRESH_PREFLIGHT, "fresh-stage-preflight", "exec")
            units = [data for _, _, argv, data in calls if argv[0:2] == ["python3", "-c"]
                     and str(argv[3]).endswith(".service")]
            self.assertEqual(len(units), 1)
            unit = units[0].decode()
            self.assertIn("MemoryMax=1073741824", unit)
            self.assertIn("MemorySwapMax=0", unit)
            self.assertIn("ExecStart="+paths["executables"]+"/synergy-node start --config "+paths["configuration"]+"/node.json", unit)
            self.assertIn("MemoryMax=4G", self.stage.UNIT)
            self.assertNotIn("MemorySwapMax=", self.stage.UNIT)
            self.assertIn("ReadWritePaths="+str(Path(paths["state"]).parent), unit)
            self.assertNotIn("/posy-stability", unit)

    def test_invalid_profile_custody_and_unqualified_memory_reject_before_remote(self):
        import tempfile
        for invalid in ("profile", "custody", "memory"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory, \
                 patch.object(self.stage.owner, "ROOT", Path(directory)):
                name, _, output, binary, config, authority = self.fixture(directory)
                if invalid == "profile":
                    authority["payload"]["protected"]["version"] = 1
                    (output/"authority.json").write_text(json.dumps(authority))
                if invalid == "custody":
                    config["aegis_signing_key_path"] = "/etc/synergy/posy-stability/custody/retired.key"
                    (output/"val2.json").write_text(json.dumps(config))
                with patch.object(self.stage.owner, "fingerprint_binary", return_value=binary), \
                     patch.object(self.stage.owner, "remote") as remote:
                    with self.assertRaises(ValueError):
                        self.stage.stage_fresh(2, "host2", "/master2", output, "node", "a"*64,
                            "fresh-async", "fresh-root", name, None if invalid == "memory" else 1073741824)
                    remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
