#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from http import HTTPStatus
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("seed_service.py")
SPEC = importlib.util.spec_from_file_location("seed_service_under_test", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
seed = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = seed
SPEC.loader.exec_module(seed)


class SeedServiceRegistryTests(unittest.TestCase):
    def make_state(self, *, default_ttl_seconds: int = 120):
        config = seed.SeedConfig(
            label="test-seed",
            seed_id="seed-test",
            allow_dynamic_registration=True,
            default_ttl_seconds=default_ttl_seconds,
            max_ttl_seconds=3600,
            static_dialback_on_start=False,
            state_file="",
        )
        state = seed.SeedState(config)
        state._dialback = lambda endpoint: (True, None)
        return state

    def registry_payload(
        self,
        endpoint: str,
        *,
        role: str = "validator",
        node_name: str = "test-validator",
        peer_id: str = "peer-test-validator",
        ttl_seconds: int = 120,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "chain_id": "synergy-testnet",
            "role": role,
            "node_name": node_name,
            "peer_id": peer_id,
            "public_endpoint": endpoint,
            "protocol_version": "synergy-p2p/1",
            "app_version": "test",
            "current_height": 100,
            "highest_known_height": 101,
            "sync_gap": 1,
            "timestamp": seed.isoformat(),
            "ttl_seconds": ttl_seconds,
        }
        if role == "validator":
            payload["validator_address"] = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
        return payload

    def test_seed_rejects_private_advertised_endpoints(self) -> None:
        bad_endpoints = [
            "10.69.0.1:5622",
            "10.0.0.1:5622",
            "172.16.0.1:5622",
            "172.31.255.255:5622",
            "192.168.1.10:5622",
            "127.0.0.1:5622",
            "169.254.1.1:5622",
            "localhost:5622",
            "0.0.0.0:5622",
            "[::1]:5622",
            "[fc00::1]:5622",
            "[fe80::1]:5622",
        ]
        for endpoint in bad_endpoints:
            with self.subTest(endpoint=endpoint):
                state = self.make_state()
                status, response = state.register(
                    self.registry_payload(endpoint),
                    observed_remote_ip="198.51.100.10",
                    replicate=False,
                )
                self.assertEqual(status, HTTPStatus.BAD_REQUEST)
                self.assertFalse(response["accepted"])
                self.assertIn("reason", response)

    def test_seed_expires_stale_dynamic_peers(self) -> None:
        state = self.make_state(default_ttl_seconds=30)
        endpoint = "62.146.182.207:5622"
        status, response = state.register(
            self.registry_payload(endpoint, ttl_seconds=30),
            observed_remote_ip="198.51.100.10",
            replicate=False,
        )
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(response["dialback_status"], "success")
        self.assertIn(endpoint, [record["public_endpoint"] for record in state.active_records()])

        state.dynamic_peers[endpoint]["expires_at"] = seed.utc_now() - 1

        self.assertNotIn(endpoint, [record["public_endpoint"] for record in state.active_records()])
        self.assertEqual(state.expired_total, 1)

    def test_seed_role_filters_only_return_matching_healthy_peers(self) -> None:
        state = self.make_state()
        validator_endpoint = "62.146.182.207:5622"
        relayer_endpoint = "relay1.synergynode.xyz:5622"

        state.register(
            self.registry_payload(validator_endpoint, role="validator", node_name="val1", peer_id="peer-val1"),
            observed_remote_ip="198.51.100.10",
            replicate=False,
        )
        state.register(
            self.registry_payload(relayer_endpoint, role="relayer", node_name="relay1", peer_id="peer-relay1"),
            observed_remote_ip="198.51.100.11",
            replicate=False,
        )

        self.assertEqual(state.peers_payload(role="validator")["endpoints"], [])
        self.assertEqual(state.peers_payload(role="relayer")["endpoints"], [relayer_endpoint])
        self.assertEqual(state.peers_payload()["endpoints"], [relayer_endpoint])

    def test_public_bootstrap_payload_is_relayer_only(self) -> None:
        config = seed.SeedConfig(
            label="test-seed",
            seed_id="seed-test",
            static_dialback_on_start=False,
            static_registry=[
                {"role": "validator", "public_endpoint": "62.146.182.207:5622"},
                {"role": "observer", "public_endpoint": "observer.example:5622"},
                {"role": "rpc_gateway", "public_endpoint": "rpc.example:5623"},
                {"role": "archive_validator", "public_endpoint": "archive.example:5615"},
                {"role": "relayer", "public_endpoint": "relay1.synergynode.xyz:5622"},
                {"role": "relayer", "public_endpoint": "relay2.synergynode.xyz:5622"},
                {"role": "relayer", "public_endpoint": "relay3.synergynode.xyz:5622"},
            ],
            static_peers=["seed1.synergynode.xyz:5621"],
            bootnodes=[{"hostname": "bootnode1.synergynode.xyz", "port": 5620}],
            dnsaddr_bootstrap=["dnsaddr=/dns4/bootnode1.synergynode.xyz/tcp/5620"],
        )
        payload = seed.SeedState(config).peer_list_payload()

        expected = [
            "relay1.synergynode.xyz:5622",
            "relay2.synergynode.xyz:5622",
            "relay3.synergynode.xyz:5622",
        ]
        self.assertEqual(payload["peers"], expected)
        self.assertEqual(payload["bootnodes"], [])
        self.assertEqual(
            payload["dnsaddr_bootstrap"],
            [f"dnsaddr=/dns4/{endpoint.split(':', 1)[0]}/tcp/5622" for endpoint in expected],
        )
        self.assertEqual(
            [record["public_endpoint"] for record in payload["registry"]],
            expected,
        )

    def test_seed_dialback_status_controls_advertisement_and_heartbeat_recovery(self) -> None:
        state = self.make_state()
        endpoint = "62.146.182.207:5622"
        state._dialback = lambda endpoint: (False, "connection refused")

        status, response = state.register(
            self.registry_payload(endpoint),
            observed_remote_ip="198.51.100.10",
            replicate=False,
        )

        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(response["accepted"])
        self.assertEqual(response["dialback_status"], "failed")
        self.assertEqual(response["health_status"], "unhealthy")
        self.assertNotIn(endpoint, [record["public_endpoint"] for record in state.active_records("validator")])

        state._dialback = lambda endpoint: (True, None)
        status, response = state.heartbeat(
            self.registry_payload(endpoint),
            observed_remote_ip="198.51.100.10",
            replicate=False,
        )

        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(response["dialback_status"], "success")
        self.assertEqual(response["health_status"], "healthy")
        self.assertIn(endpoint, [record["public_endpoint"] for record in state.active_records("validator")])
        self.assertNotIn(endpoint, response["recommended_peers"])
        self.assertIn("relay1.synergynode.xyz:5622", response["recommended_peers"])
        self.assertIn("relay3.synergynode.xyz:5622", response["recommended_peers"])
        self.assertNotIn("62.146.182.208:5622", response["recommended_peers"])


if __name__ == "__main__":
    unittest.main()
