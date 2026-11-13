#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("generate_public_p2p_configs.py")
SPEC = importlib.util.spec_from_file_location("generate_public_p2p_configs", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


class PublicP2PTopologyGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.topology = gen.load_topology()
        cls.configs = gen.generate_configs(cls.topology)

    def test_manifest_parses(self) -> None:
        self.assertEqual(self.topology["schema_version"], 1)
        self.assertEqual(self.topology["network"]["environment_id"], "testnet")
        self.assertEqual(self.topology["network"]["release_id"], "testnet-v3")
        self.assertEqual(self.topology["network"]["runtime_network_id"], "synergy-testnet-v3")
        self.assertEqual(len(self.topology["validators"]), 6)
        self.assertEqual(len(self.configs), 19)
        self.assertEqual(self.topology["seed_registry"]["register_endpoint"], "/register")
        self.assertEqual(self.topology["seed_registry"]["heartbeat_endpoint"], "/heartbeat")
        for config in self.configs.values():
            self.assertEqual(config["network"]["id"], 1264)
            self.assertEqual(config["network"]["chain_id"], 1264)
            self.assertEqual(config["network"]["network_id"], "synergy-testnet-v3")

    def test_validator_peer_generation_uses_relayer_support_only(self) -> None:
        all_validator_identities = {validator["validator_address"] for validator in self.topology["validators"]}
        relayer_peers = set(self.topology["common"]["relayer_peers"])
        relayer_peer_order = list(self.topology["common"]["relayer_peers"])
        for validator in self.topology["validators"]:
            config = self.configs[Path("validators") / f"{validator['name'].lower()}.toml"]
            peers = set(config["network"]["persistent_peers"])
            self.assertNotIn(validator["validator_address"], peers)
            self.assertTrue(all_validator_identities.isdisjoint(peers))
            self.assertEqual(peers, relayer_peers)
            self.assertEqual(config["network"]["additional_dial_targets"], relayer_peer_order)

    def test_validators_do_not_publish_or_require_public_endpoints(self) -> None:
        for validator in self.topology["validators"]:
            config = self.configs[Path("validators") / f"{validator['name'].lower()}.toml"]
            with self.subTest(validator=validator["name"]):
                self.assertNotIn("public_endpoint", validator)
                self.assertNotIn("public_p2p_address", config["network"])
                self.assertEqual(config["p2p"]["public_address"], "")
                self.assertEqual(config["p2p"]["listen_address"], "127.0.0.1:5622")
                self.assertFalse(config["p2p"]["enable_discovery"])
                self.assertFalse(config["p2p"]["enable_peer_exchange"])
                self.assertEqual(config["p2p"]["discovery_listen_address"], "127.0.0.1:5680")
                self.assertEqual(config["p2p"]["discovery_public_address"], "")
                self.assertFalse(config["seed_registration"]["enabled"])
                self.assertEqual(config["network"]["validator_vpn_transports"], [])
                self.assertFalse(config["node"]["active_consensus_validator"])

    def test_validator_vpn_ranges_are_reserved_for_post_enrollment(self) -> None:
        self.assertEqual(str(gen.VALIDATOR_VPN_CIDR), "10.70.10.0/24")
        self.assertEqual(str(gen.RELAYER_VPN_CIDR), "10.70.20.0/24")
        self.assertFalse(gen.RETIRED_VALIDATOR_VPN_CIDR.overlaps(gen.VALIDATOR_VPN_CIDR))
        self.assertFalse(gen.RETIRED_VALIDATOR_VPN_CIDR.overlaps(gen.RELAYER_VPN_CIDR))

    def test_generated_public_fields_do_not_contain_private_endpoints(self) -> None:
        public_field_names = {
            "bootnodes",
            "seed_servers",
            "additional_dial_targets",
            "persistent_peers",
            "public_p2p_address",
            "public_address",
            "register_endpoints",
            "heartbeat_endpoints",
            "p2p_peers",
            "monitoring_targets",
        }
        for path, config in self.configs.items():
            for section in config.values():
                for key, value in section.items():
                    if key not in public_field_names:
                        continue
                    values = value if isinstance(value, list) else [value]
                    for endpoint in values:
                        if not endpoint:
                            continue
                        if (
                            config["identity"]["role"] == "validator"
                            and key in {"additional_dial_targets", "persistent_peers"}
                            and str(endpoint).startswith("synv1")
                        ):
                            continue
                        with self.subTest(path=str(path), endpoint=endpoint):
                            self.assertTrue(gen.endpoint_is_public_advertisement(endpoint))
                            self.assertNotIn("10.69.", endpoint)

    def test_stable_infrastructure_uses_dns(self) -> None:
        for section_name in ("bootnodes", "seed_servers", "relayers", "rpc_gateways", "archive_validators"):
            for node in self.topology[section_name]:
                with self.subTest(section=section_name, node=node["name"]):
                    self.assertTrue(gen.endpoint_host_is_dns(node["public_endpoint"]))
                    self.assertIn(".synergynode.xyz", node["public_endpoint"])
        for endpoint in [*self.topology["common"]["bootnodes"], *self.topology["common"]["relayer_peers"]]:
            self.assertTrue(gen.endpoint_host_is_dns(endpoint))
            self.assertIn(".synergynode.xyz", endpoint)
        for endpoint in self.topology["common"]["seed_servers"]:
            self.assertTrue(gen.endpoint_host_is_dns(endpoint))
            self.assertIn(".synergynode.xyz", endpoint)

    def test_validators_have_no_public_ip_endpoints(self) -> None:
        for validator in self.topology["validators"]:
            with self.subTest(validator=validator["name"]):
                self.assertNotIn("public_endpoint", validator)

    def test_rpc_gateway_p2p_is_distinct_from_public_rpc(self) -> None:
        network = self.topology["network"]
        self.assertEqual(network["rpc_gateway_p2p_endpoint"], "rpc.synergynode.xyz:5623")
        self.assertEqual(network["public_rpc_endpoint"], "https://testnet-core-rpc.synergy-network.io")
        self.assertNotEqual(network["rpc_gateway_p2p_endpoint"], network["public_rpc_host"])
        config = self.configs[Path("rpc-gateway") / "rpc-gateway.toml"]
        self.assertEqual(config["network"]["public_p2p_address"], "rpc.synergynode.xyz:5623")
        self.assertEqual(config["rpc_gateway"]["p2p_endpoint"], "rpc.synergynode.xyz:5623")
        self.assertEqual(config["rpc_gateway"]["public_json_rpc_endpoint"], network["public_rpc_endpoint"])
        self.assertNotIn("rpc.synergynode.xyz:5623", config["rpc_gateway"]["public_json_rpc_endpoint"])

    def test_archive_uses_archive_dns_port_5615(self) -> None:
        archive = self.topology["archive_validators"][0]
        self.assertEqual(archive["public_endpoint"], "archive.synergynode.xyz:5615")
        self.assertIn("73.79.66.255:5622", archive["forbidden_public_endpoints"])
        config = self.configs[Path("archive-validator") / "archive-validator.toml"]
        self.assertEqual(config["network"]["public_p2p_address"], "archive.synergynode.xyz:5615")
        self.assertEqual(config["p2p"]["public_address"], "archive.synergynode.xyz:5615")
        self.assertEqual(config["archive_validator"]["public_archive_endpoint"], "archive.synergynode.xyz:5615")
        self.assertNotEqual(config["archive_validator"]["public_archive_endpoint"], "73.79.66.255:5622")

    def test_observer_separates_p2p_peers_from_monitoring_targets(self) -> None:
        observer = self.topology["observers"][0]
        self.assertNotEqual(observer["p2p_peers"], observer["monitoring_targets"])
        self.assertIn("testnet-core-rpc.synergy-network.io", observer["monitoring_targets"])
        self.assertNotIn("testnet-core-rpc.synergy-network.io", observer["p2p_peers"])
        config = self.configs[Path("observer") / "observer.toml"]
        self.assertEqual(config["observer"]["p2p_peers"], observer["p2p_peers"])
        self.assertEqual(config["observer"]["monitoring_targets"], observer["monitoring_targets"])
        self.assertNotEqual(config["network"]["persistent_peers"], config["observer"]["monitoring_targets"])

    def test_explorer_indexer_is_included(self) -> None:
        indexer = self.topology["explorer_indexers"][0]
        self.assertEqual(indexer["name"], "explorer-indexer")
        self.assertIn(Path("explorer-indexer") / "explorer-indexer.toml", self.configs)
        config = self.configs[Path("explorer-indexer") / "explorer-indexer.toml"]
        self.assertEqual(config["network"]["public_p2p_address"], "74.208.227.23:5622")
        self.assertEqual(
            config["network"]["persistent_peers"],
            self.topology["common"]["relayer_peers"],
        )

    def test_public_support_nodes_are_relayer_only(self) -> None:
        expected = self.topology["common"]["relayer_peers"]
        paths = [
            Path("bootnodes") / "bootnode1.toml",
            Path("bootnodes") / "bootnode2.toml",
            Path("bootnodes") / "bootnode3.toml",
            Path("seed-servers") / "seed1.toml",
            Path("seed-servers") / "seed2.toml",
            Path("seed-servers") / "seed3.toml",
            Path("rpc-gateway") / "rpc-gateway.toml",
            Path("observer") / "observer.toml",
            Path("explorer-indexer") / "explorer-indexer.toml",
            Path("archive-validator") / "archive-validator.toml",
        ]
        validator_endpoints = {
            validator.get("public_endpoint") for validator in self.topology["validators"]
        }

        self.assertEqual(
            expected,
            [
                "relay1.synergynode.xyz:5622",
                "relay2.synergynode.xyz:5622",
                "relay3.synergynode.xyz:5622",
            ],
        )
        for path in paths:
            with self.subTest(path=str(path)):
                peers = self.configs[path]["network"]["persistent_peers"]
                self.assertEqual(peers, expected)
                self.assertTrue(validator_endpoints.isdisjoint(peers))

    def test_relayers_do_not_dial_public_validator_endpoints(self) -> None:
        validator_endpoints = {
            validator.get("public_endpoint") for validator in self.topology["validators"]
        }
        for relayer in self.topology["relayers"]:
            config = self.configs[Path("relayers") / f"{relayer['name']}.toml"]
            with self.subTest(relayer=relayer["name"]):
                self.assertTrue(validator_endpoints.isdisjoint(config["network"]["persistent_peers"]))
                self.assertFalse(any(str(peer).startswith("synv1") for peer in config["network"]["persistent_peers"]))

    def test_generated_configs_never_emit_retired_validator_vpn_range(self) -> None:
        for path, config in self.configs.items():
            with self.subTest(path=str(path)):
                self.assertNotIn("10.69.", gen.render_toml(config))

        generated_dir = SCRIPT_PATH.parents[2] / "config" / "testnet" / "generated" / "validators"
        for path in sorted(generated_dir.glob("*.toml")):
            with self.subTest(path=str(path)):
                self.assertNotIn("10.69.", path.read_text(encoding="utf-8"))

        template = (SCRIPT_PATH.parents[2] / "templates" / "validator.toml").read_text(encoding="utf-8")
        self.assertNotIn("10.69.", template)
        self.assertIn("validator_vpn_transports = []", template)
        self.assertIn('listen_address = "127.0.0.1:5622"', template)
        self.assertIn('discovery_listen_address = "127.0.0.1:5680"', template)
        self.assertIn("active_consensus_validator = false", template)

    def test_seed_registry_rejects_private_endpoints(self) -> None:
        bad_endpoints = [
            "10.69.0.1:5622",
            "10.0.0.1:5622",
            "172.16.0.1:5622",
            "192.168.1.10:5622",
            "127.0.0.1:5622",
            "localhost:5622",
            "0.0.0.0:5622",
            "[::1]:5622",
        ]
        for endpoint in bad_endpoints:
            with self.subTest(endpoint=endpoint):
                self.assertFalse(gen.endpoint_is_public_advertisement(endpoint))

    def test_seed_registry_expires_stale_peers(self) -> None:
        now = dt.datetime(2026, 7, 2, 12, 0, tzinfo=dt.timezone.utc)
        fresh = {
            "public_endpoint": "62.146.182.207:5622",
            "dialback_status": "success",
            "health_status": "healthy",
            "last_seen": "2026-07-02T11:59:30Z",
            "ttl_seconds": 120,
        }
        stale = dict(fresh, last_seen="2026-07-02T11:00:00Z")
        self.assertTrue(gen.seed_registry_entry_is_advertisable(fresh, now=now))
        self.assertFalse(gen.seed_registry_entry_is_advertisable(stale, now=now))

    def test_seed_registry_role_filtered_peers(self) -> None:
        now = dt.datetime(2026, 7, 2, 12, 0, tzinfo=dt.timezone.utc)
        entries = [
            {
                "role": "validator",
                "public_endpoint": "62.146.182.207:5622",
                "dialback_status": "success",
                "health_status": "healthy",
                "last_seen": "2026-07-02T11:59:30Z",
                "ttl_seconds": 120,
            },
            {
                "role": "relayer",
                "public_endpoint": "relay1.synergynode.xyz:5622",
                "dialback_status": "success",
                "health_status": "healthy",
                "last_seen": "2026-07-02T11:59:30Z",
                "ttl_seconds": 120,
            },
        ]
        self.assertEqual(gen.seed_registry_peer_view(entries, role="validator", now=now), ["62.146.182.207:5622"])
        self.assertEqual(gen.seed_registry_peer_view(entries, role="relayer", now=now), ["relay1.synergynode.xyz:5622"])

    def test_seed_registry_requires_dialback_success(self) -> None:
        now = dt.datetime(2026, 7, 2, 12, 0, tzinfo=dt.timezone.utc)
        entry = {
            "public_endpoint": "62.146.182.207:5622",
            "dialback_status": "pending",
            "health_status": "healthy",
            "last_seen": "2026-07-02T11:59:30Z",
            "ttl_seconds": 120,
        }
        self.assertFalse(gen.seed_registry_entry_is_advertisable(entry, now=now))

    def test_validator_config_uniformity_and_allowlist(self) -> None:
        allowlist = self.topology["consensus"]["strict_validator_allowlist"]
        relayer_peers = self.topology["common"]["relayer_peers"]
        rendered_allowlists = set()
        for validator in self.topology["validators"]:
            config = self.configs[Path("validators") / f"{validator['name'].lower()}.toml"]
            with self.subTest(validator=validator["name"]):
                self.assertEqual(config["network"]["bootnodes"], [])
                self.assertEqual(config["network"]["seed_servers"], [])
                self.assertEqual(config["network"]["persistent_peers"], config["network"]["additional_dial_targets"])
                for relayer_peer in relayer_peers:
                    self.assertIn(relayer_peer, config["network"]["persistent_peers"])
                self.assertTrue(config["node"]["strict_validator_allowlist"])
                self.assertEqual(config["node"]["allowed_validator_addresses"], allowlist)
                self.assertFalse(config["node"]["active_consensus_validator"])
                self.assertFalse(config["seed_registration"]["enabled"])
                rendered_allowlists.add(tuple(config["node"]["allowed_validator_addresses"]))
        self.assertEqual(rendered_allowlists, {tuple(allowlist)})

    def test_generator_writes_to_requested_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            gen.write_generated_configs(self.configs, output_dir)
            self.assertTrue((output_dir / "validators" / "val1.toml").exists())
            self.assertTrue((output_dir / "archive-validator" / "archive-validator.toml").exists())


if __name__ == "__main__":
    unittest.main()
