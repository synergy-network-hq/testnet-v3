"""Regression checks for the collector's actual native history formats."""
from contextlib import redirect_stdout
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "collector", Path(__file__).with_name("publish-atlas-posy-telemetry.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
probe = {}
exec(collector.PROBE.split("configuration,_=")[0], probe)


class StaffFeedContract(unittest.TestCase):
    def test_retirement_does_not_fabricate_chain_activity_or_retire_out_of_scope_host(self):
        record = collector.retired_payload('canary-network', 'a' * 64, 99999, '2026-11-17T06:00:00+00:00')
        self.assertEqual(record['chain']['lifecycle'], 'retired')
        for field in ('height', 'finalized_height', 'block_time_ms', 'transactions', 'wallets'):
            self.assertIsNone(record['chain'][field])
        self.assertEqual([node['id'] for node in record['validators'] if node['status'] == 'retired'],
                         ['val2', 'val3', 'val4', 'val6'])
        self.assertEqual(record['validators'][3]['status'], 'unavailable')
        for arguments in [('canary', 'not-a-genesis', 99999, record['observed_at']),
                          ('canary', 'a' * 64, True, record['observed_at']),
                          ('canary', 'a' * 64, 99999, '2026-11-17T06:00:00')]:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                collector.retired_payload(*arguments)

    def test_every_shipped_objective_has_the_required_staff_timestamp_fields(self):
        plan = json.loads(Path(__file__).with_name('canary-99999-atlas-objectives.json').read_bytes())
        for item in plan['tests']:
            with self.subTest(name=item.get('name')):
                self.assertEqual(set(item), {'name', 'status', 'started_at', 'updated_at', 'detail'})
                for key in ('started_at', 'updated_at'):
                    value = item[key]
                    if value is not None:
                        self.assertIsNotNone(collector.datetime.datetime.fromisoformat(value).tzinfo)


class RosterSelection(unittest.TestCase):
    def setUp(self):
        self.network = 'canary-network'
        self.genesis = 'a' * 64
        self.states = {n: self.running(n) for n in range(2, 7)}

    def running(self, n):
        return {
            'network_id': self.network, 'genesis_hash': self.genesis,
            'service': {'SubState': 'running', 'MainPID': str(n)},
            'address': f'validator-{n}', 'height': 23093, 'block': {'block_hash': 'live'},
            'observed_at': '2026-11-16T14:00:00+00:00',
            'chain_telemetry': {'schema_version': 1, 'network_identity': self.network,
                'genesis_hash': self.genesis, 'chain_id': 99999, 'process_id': n,
                'observed_at_unix_ms': 1794837600000, 'epoch': 7, 'epoch_context_root': 'b' * 64},
        }

    def test_four_verified_hosts_can_publish_without_stale_fifth(self):
        self.states[5]['service'] = {'SubState': 'dead', 'MainPID': '0'}
        self.states[5]['network_id'] = 'retired-network'
        self.states[5]['height'] = 99999
        network, genesis, verified = collector.active_network(self.states)
        self.assertEqual((network, genesis, set(verified)), (self.network, self.genesis, {2, 3, 4, 6}))
        roster = collector.roster_observations(self.states, verified, network, genesis)
        self.assertEqual(collector.validator_status(roster[5], None)[0], 'offline')
        self.assertIsNone(roster[5]['block'])
        self.assertIsNone(roster[5]['address'])
        self.states[5] = {}
        network, genesis, verified = collector.active_network(self.states)
        roster = collector.roster_observations(self.states, verified, network, genesis)
        self.assertEqual(collector.validator_status(roster[5], None)[0], 'unreachable')

    def test_chain_and_epoch_are_observed_in_verified_running_samples_only(self):
        self.states[5]['service'] = {'SubState': 'dead', 'MainPID': '0'}
        self.states[5]['chain_telemetry']['epoch'] = 6
        def observed():
            _, _, verified = collector.active_network(self.states)
            return collector.observed_chain_fields(self.states, verified)
        self.assertEqual(observed(), {'chain_id': 99999, 'epoch': 7})
        for field, conflicting in (
            ('epoch', 6), ('epoch', None), ('epoch', True),
            ('epoch_context_root', 'c' * 64), ('epoch_context_root', None),
        ):
            with self.subTest(field=field, conflicting=conflicting):
                native = self.states[4]['chain_telemetry']
                original = native[field]
                native[field] = conflicting
                self.assertEqual(observed(), {'chain_id': 99999})
                native[field] = original
        self.states[5]['service'] = {'SubState': 'running', 'MainPID': '100'}
        self.assertEqual(observed(), {'chain_id': 99999})
        self.states[5]['service'] = {'SubState': 'dead', 'MainPID': '0'}
        for n in (2, 3, 4, 6):
            self.states[n]['chain_telemetry']['chain_id'] = 2**53
        self.assertEqual(observed(), {'epoch': 7})

    def test_foreign_running_config_and_insufficient_native_agreement_fail_closed(self):
        self.states[5]['network_id'] = 'foreign'
        with self.assertRaisesRegex(ValueError, 'one selected genesis and network'):
            collector.active_network(self.states)
        self.states[5] = {}
        self.states[4]['chain_telemetry']['process_id'] = 999
        with self.assertRaisesRegex(ValueError, 'four distinct running'):
            collector.active_network(self.states)

    def test_read_only_report_refuses_foreign_scope_and_never_calls_index_writer(self):
        self.states[5] = {'service': {}, 'block': None}
        for state in self.states.values():
            state.setdefault('wallets', None)
            state.setdefault('transactions', None)
            state.setdefault('release_id', None)
        scope = dict(chain_id=99999, network_id=self.network, genesis_hash=self.genesis)
        masters = {f'synergy-val{n}': f'/tmp/val{n}' for n in (2, 3, 4, 6)}

        def observe(item):
            number = item[0]
            return number, self.states[number]

        with patch.dict(collector.MASTER_SOCKETS, masters, clear=True), \
                patch.object(collector.subprocess, 'check_output', return_value='hostname example.test'), \
                patch.object(collector, 'read', side_effect=observe), \
                patch.object(collector.owner, 'remote') as remote, redirect_stdout(io.StringIO()) as output:
            report = collector.run(once=True, selected=scope, observe_only=True)
            self.assertEqual(report, json.loads(output.getvalue()))
            self.assertEqual(report['chain']['genesis_hash'], self.genesis)
            self.assertEqual(report['chain']['lifecycle'], 'active')
            self.assertIsNone(report['validators'][3]['public_ip'])
            self.assertIsNone(report['validators'][3]['finalized_height'])
            with self.assertRaisesRegex(ValueError, 'explicitly selected network'):
                collector.run(once=True, selected={**scope, 'genesis_hash': 'f' * 64}, observe_only=True)
            remote.assert_not_called()

    def test_selected_publish_uses_existing_index_owner_and_refuses_wrong_genesis(self):
        self.states[5] = {'service': {}, 'block': None}
        for state in self.states.values():
            state.update(wallets=None, transactions=None, release_id=None)
        scope = dict(chain_id=99999, network_id=self.network, genesis_hash=self.genesis)
        owners = {'synergy-index': '/tmp/index'}

        with patch.dict(collector.MASTER_SOCKETS, owners, clear=True), \
                patch.object(collector, 'read', side_effect=lambda item: (item[0], self.states[item[0]])), \
                patch.object(collector.owner, 'remote', return_value=b'') as remote, redirect_stdout(io.StringIO()):
            report = collector.run(once=True, selected=scope)
            remote.assert_called_once()
            host, socket, command, data = remote.call_args.args
            self.assertEqual((host, socket, command), ('synergy-index', '/tmp/index',
                                                      ['python3', '-c', collector.PUBLISH, '99999', self.network, self.genesis]))
            self.assertEqual(json.loads(data), report)
            remote.reset_mock()
            with self.assertRaisesRegex(ValueError, 'explicitly selected network'):
                collector.run(once=True, selected={**scope, 'genesis_hash': 'f' * 64})
            remote.assert_not_called()

    def test_duplicate_identity_does_not_count_twice(self):
        self.states[5] = {}
        self.states[4]['address'] = self.states[3]['address']
        with self.assertRaisesRegex(ValueError, 'four distinct running'):
            collector.active_network(self.states)


class NativeHistory(unittest.TestCase):
    def test_expiry_monitor_requires_all_five_pinned_registries(self):
        now = "2026-11-09T00:00:00+00:00"
        nodes = [dict(status="active", peers=4, finalized_height=1,
                      finalized_block_id="block", state_root="root") for _ in range(5)]
        registry = dict(generation=2, valid_from_unix=1794182400, expires_at_unix=1794787200)
        states = {n: {"registry_validity": dict(registry)} for n in range(2, 7)}
        def status():
            return collector.live_canary_checks("posy-apqe-canary-process-49028",
                "2a770743814a98e61856efb85ebae1461dbac38a7b75ca65fb9f7ffe2e7011dc",
                nodes, now, states)[-1]["status"]
        self.assertEqual(status(), "warning")
        states[2]["registry_validity"]["generation"] = 3
        self.assertEqual(status(), "blocked")

    def test_world_delta_reconstruction_checks_the_finalized_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            worlds = root / "state/execution/finalized-world"
            worlds.mkdir(parents=True)
            world = {"accounts": {"syna-test": {"balance_nwei": 1, "nonce": 0, "code_hash": None}}, "protocol": {}}
            def digest(value):
                data = json.dumps(value, separators=(",", ":")).encode()
                return hashlib.sha3_256(b"SYNERGY_WORLD_STATE_ROOT_V1" + len(data).to_bytes(8, "big") + data).hexdigest()
            first = digest(world)
            (worlds / f"{64:020}.json").write_text(json.dumps(world))
            world["accounts"]["syna-other"] = {"balance_nwei": 2, "nonce": 0, "code_hash": None}
            world["accounts"] = dict(sorted(world["accounts"].items()))
            final = digest(world)
            patch = {"height": 65, "parent_height": 64, "parent_state_root": first,
                     "state_root": final, "accounts": {"syna-other": world["accounts"]["syna-other"]}, "protocol": {}}
            path = worlds / f"{65:020}.json"
            path.write_bytes(b"SNWDV001" + json.dumps(patch).encode())
            observed = {"finalized_height": 65, "state_root": final}
            self.assertEqual(probe["count_finalized_accounts"](root, observed), 2)
            patch["parent_state_root"] = "0" * 64
            path.write_bytes(b"SNWDV001" + json.dumps(patch).encode())
            with self.assertRaises(ValueError):
                probe["count_finalized_accounts"](root, observed)

    def test_candidate_count_requires_matching_finalized_commitments(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            history = root / "state/execution/finalized-history"
            candidates = root / "blocks/execution-candidates/candidate"
            history.mkdir(parents=True)
            candidates.mkdir(parents=True)
            state = {"finalized_height": 1, "finalized_block_id": "block", "state_root": "root"}
            (history / f"{1:020}.json").write_text(json.dumps({"format": "synergy-finalized-state-v1", "state": state}))
            candidate = {"height": 1, "block_id": "block", "state_root": "root",
                         "parent_block_id": "genesis", "transactions": []}
            path = candidates / f"{1:020}.json"
            path.write_bytes(b"SNCDV001" + json.dumps(candidate).encode())
            cursor, total = probe["count_committed_transactions"](root, state, None)
            self.assertEqual((cursor["height"], total), (1, 0))
            candidate["block_id"] = "unfinalized"
            path.write_bytes(b"SNCDV001" + json.dumps(candidate).encode())
            self.assertIsNone(probe["count_committed_transactions"](root, state, None)[1])


if __name__ == "__main__":
    unittest.main()
