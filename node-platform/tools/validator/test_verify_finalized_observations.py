import base64
import hashlib
import importlib.util
import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "verify_finalized_observations", Path(__file__).with_name("verify-finalized-observations.py")
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class FinalityObservationTests(unittest.TestCase):
    def test_complete_original_bytes_are_reassembled_with_a_continuation_pin(self):
        original = b"x" * verifier.PAGE_BYTES + b"tail"
        digest = hashlib.sha256(original).hexdigest()

        def fetch(_endpoint, query):
            offset = query["offset"]
            self.assertEqual(query.get("expected_sha256"), digest if offset else None)
            chunk = original[offset:offset + verifier.PAGE_BYTES]
            end = offset + len(chunk)
            return dict(version=1, height=7, kind="finality", encoding="base64",
                        offset=offset, sha256=digest, total_bytes=len(original),
                        next_offset=end if end < len(original) else None,
                        bytes_base64=base64.b64encode(chunk).decode())

        self.assertEqual(verifier.fetch_proof("https://observer", 7, "finality", fetch), original)
        with self.assertRaisesRegex(ValueError, "changed"):
            verifier.fetch_proof("https://observer", 7, "finality", lambda endpoint, query: {
                **fetch(endpoint, query), "sha256": "a" * 64 if query["offset"] else digest
            })
        with self.assertRaisesRegex(ValueError, "noncontiguous"):
            verifier.fetch_proof("https://observer", 7, "finality", lambda endpoint, query: {
                **fetch(endpoint, query), "next_offset": None
            })

    def test_archive_mode_preserves_exact_native_inputs_without_network_reads(self):
        genesis = "a" * 64
        proof, block = b'{ "finalized": 7 }', b'[7, "original"]'
        native = dict(verified=True, chain_id=99999, network_id="canary", genesis_hash=genesis,
                      state_root="b" * 64, finalized=dict(height=7, block_id="c" * 64,
                      protected_execution_root="d" * 64))

        def verify(command, height):
            self.assertEqual(height, 7)
            self.assertEqual(Path(command[-2]).read_bytes(), proof)
            self.assertEqual(Path(command[-1]).read_bytes(), block)
            return native

        with verifier.tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "7.finality.json").write_bytes(proof)
            (folder / "7.block_commitment.json").write_bytes(block)
            args = ["verify", "--evidence-dir", temporary, "--node", __file__, "--config", __file__,
                    "--chain", "99999", "--network", "canary", "--genesis", genesis, "--height", "7"]
            with (patch("sys.argv", args), patch.object(verifier, "verify_native", side_effect=verify),
                  patch.object(verifier, "fetch_proof") as fetch):
                with redirect_stdout(io.StringIO()) as out:
                    verifier.main()
                self.assertEqual(json.loads(out.getvalue())["archive_input_count"], 1)
                self.assertNotIn("observer_count", json.loads(out.getvalue()))
                (folder / "7.block_commitment.json").unlink()
                with patch("sys.stderr", new=io.StringIO()) as err, self.assertRaises(SystemExit):
                    verifier.main()
                self.assertIn("archived block_commitment unavailable at H7", err.getvalue())
                (folder / "7.block_commitment.json").write_bytes(b"x" * (verifier.MAX_PROOF_BYTES + 1))
                with patch("sys.stderr", new=io.StringIO()) as err, self.assertRaises(SystemExit):
                    verifier.main()
                self.assertIn("exceeds proof bounds", err.getvalue())
            fetch.assert_not_called()

    def test_native_result_must_authenticate_the_exact_requested_incarnation(self):
        result = dict(verified=True, chain_id=99999, network_id="canary", genesis_hash="a" * 64,
                      state_root="b" * 64, finalized=dict(height=7, block_id="c" * 64,
                      protected_execution_root="d" * 64))
        self.assertEqual(verifier.subject(result, 99999, "canary", "a" * 64, 7)["state_root"], "b" * 64)
        for invalid in ({**result, "verified": False}, {**result, "genesis_hash": "e" * 64},
                        {**result, "finalized": {**result["finalized"], "height": 8}}):
            with self.assertRaisesRegex(ValueError, "selected network or height"):
                verifier.subject(invalid, 99999, "canary", "a" * 64, 7)

    def test_authenticated_consecutive_blocks_cross_an_epoch_boundary(self):
        before = dict(height=1000, block_id="a" * 64, epoch=4, epoch_context_root="b" * 64,
                      consensus_timestamp_unix=100)
        native = dict(epoch=5, epoch_context_root="c" * 64, consensus_timestamp_unix=101)
        block = json.dumps([1001, before["block_id"], "d" * 64, "e" * 64, [], []])
        after = dict(height=1001, **verifier.consensus_position(native, block))
        self.assertEqual(verifier.check_successor(before, after), 1)
        self.assertEqual(verifier.check_successor(before, {
            **after, "epoch": 4, "epoch_context_root": before["epoch_context_root"]
        }), 0)
        for fields, error in (
            (dict(height=1002), "contiguous"),
            (dict(parent_block_id="f" * 64), "contiguous"),
            (dict(consensus_timestamp_unix=99), "regressed"),
            (dict(epoch=6), "succession"),
            (dict(epoch=4), "succession"),
            (dict(epoch_context_root=before["epoch_context_root"]), "succession"),
        ):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, error):
                verifier.check_successor(before, {**after, **fields})
        with self.assertRaisesRegex(ValueError, "invalid verified consensus position"):
            verifier.consensus_position({**native, "epoch": None}, block)

    def test_public_request_identifies_client_and_reports_missing_evidence(self):
        params = dict(height=9704, kind="block_commitment", offset=0, limit=1024)
        with patch.object(verifier, "build_opener") as opener:
            process = opener.return_value.open
            response = process.return_value.__enter__.return_value
            response.read.return_value = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32001, "message": "requested finalized evidence is not retained"},
            }).encode()
            with self.assertRaisesRegex(ValueError, r"block_commitment at H9704 .*not retained"):
                verifier.request_page("https://observer", params)
            self.assertEqual(process.call_args.args[0].get_header("User-agent"), verifier.USER_AGENT)

    def test_witness_only_invokes_native_verifier_without_block_preimage(self):
        genesis = "a" * 64
        args = ["verify", "--observer", "https://example.test", "--node", __file__,
                "--config", __file__, "--chain", "99999", "--network", "canary",
                "--genesis", genesis, "--height", "9704", "--witness-only"]
        native = dict(verified=True, chain_id=99999, network_id="canary", genesis_hash=genesis,
                      finalized=dict(height=9704, block_id="b" * 64,
                                     protected_execution_root="c" * 64,
                                     finality_certificate_id="d" * 64))
        with (patch("sys.argv", args),
              patch.object(verifier, "fetch_proof", return_value=b"original") as fetch,
              patch.object(verifier.subprocess, "run") as run, redirect_stdout(io.StringIO()) as out):
            run.return_value.returncode = 0
            run.return_value.stdout = json.dumps(native).encode()
            verifier.main()
            fetch.assert_called_once_with("https://example.test", 9704, "finality")
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["finality-proof", "verify"])
            self.assertEqual(len(command), 5)
            self.assertEqual(Path(command[-1]).name, "finality.json")
        result = json.loads(out.getvalue())
        self.assertFalse(result["block_preimage_verified"])
        self.assertNotIn("state_root", result)
        self.assertEqual(result["finality_certificate_id"], "d" * 64)

    def test_witness_range_uses_first_verified_qc_context_at_boundary(self):
        network = "canary"
        block_id = "a" * 64
        parent = "b" * 64
        protected_root = "c" * 64
        epoch_root = "d" * 64
        commitments = dict(block_id=block_id, protected_execution_root=protected_root)
        first = dict(block_id=block_id, parent_block_id=parent,
                     protected_execution_root=protected_root,
                     context=dict(chain_id=99999, network_id=network, height=9000, epoch=9,
                                  epoch_context_root=epoch_root))
        descendant = dict(context=dict(epoch=10))
        proof = dict(witness=dict(quorum_certificates=[first, descendant, descendant]))
        at_boundary = verifier.witness_position(json.dumps(proof), commitments, 99999, network, 9000)
        self.assertEqual(at_boundary, dict(parent_block_id=parent, epoch=9, epoch_context_root=epoch_root))
        next_block = dict(height=9001, parent_block_id=block_id, epoch=10, epoch_context_root="e" * 64)
        previous = dict(height=9000, block_id=block_id, **at_boundary)
        self.assertEqual(verifier.check_successor(previous, next_block), 1)
        with self.assertRaisesRegex(ValueError, "contiguous"):
            verifier.check_successor(previous, {**next_block, "parent_block_id": "f" * 64})
        with self.assertRaisesRegex(ValueError, "selected consensus position"):
            verifier.witness_position(json.dumps(proof), commitments, 99999, network, 9001)

    def test_native_failure_distinguishes_missing_authority_and_hides_local_paths(self):
        with patch.object(verifier.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = (
                b"synergy-node failed closed: proof lies outside independently authenticated authority history"
            )
            with self.assertRaisesRegex(ValueError, "H131998: proof lies outside"):
                verifier.verify_native(["node"], 131998)
            run.return_value.stderr = b"decode /home/operator/private-config.json"
            with self.assertRaisesRegex(ValueError, r"H131998: exit 1$"):
                verifier.verify_native(["node"], 131998)

    def test_proof_size_bound_matches_native_protocol_before_pagination(self):
        with self.assertRaisesRegex(ValueError, "invalid proof page scope"):
            verifier.fetch_proof("https://observer", 7, "finality", lambda _url, _params: {
                "version": 1, "height": 7, "kind": "finality", "encoding": "base64",
                "offset": 0, "sha256": "a" * 64, "total_bytes": 1024 * 1024 + 1,
            })

    def test_world_root_binds_original_bytes_without_reserialization(self):
        world = b'{"accounts":{"a":"9007199254740993"}}'
        commitment = hashlib.sha3_256(
            b"SYNERGY_WORLD_STATE_ROOT_V1" + len(world).to_bytes(8, "big") + world
        ).hexdigest()
        verifier.match_world_state(world, commitment)
        with self.assertRaisesRegex(ValueError, "authenticated state root"):
            verifier.match_world_state(world.replace(b"993", b"992"), commitment)
        with self.assertRaisesRegex(ValueError, "authenticated state root"):
            verifier.match_world_state(world + b" ", commitment)

    def test_account_reads_require_authenticated_world_and_preserve_large_integers(self):
        genesis = "a" * 64
        balance = 2**128 - 1
        world = json.dumps({"accounts": {
            "present": {"balance_nwei": balance, "nonce": 2**64 - 1, "code_hash": None},
            "zero": {"balance_nwei": 0, "nonce": 0, "code_hash": None},
        }, "protocol": {}}).encode()
        root = hashlib.sha3_256(
            b"SYNERGY_WORLD_STATE_ROOT_V1" + len(world).to_bytes(8, "big") + world
        ).hexdigest()
        native = dict(verified=True, chain_id=99999, network_id="canary", genesis_hash=genesis,
                      state_root=root, finalized=dict(height=7, block_id="b" * 64,
                                                      protected_execution_root="c" * 64))
        args = ["verify", "--observer", "https://example.test", "--node", __file__,
                "--config", __file__, "--chain", "99999", "--network", "canary",
                "--genesis", genesis, "--height", "7", "--account", "present",
                "--account", "zero", "--account", "missing"]

        def proof(_endpoint, _height, kind):
            return world if kind == "world_state" else b"native fixture input"

        with (patch("sys.argv", args), patch.object(verifier, "fetch_proof", side_effect=proof),
              patch.object(verifier, "verify_native", return_value=native),
              redirect_stdout(io.StringIO()) as out):
            verifier.main()
        result = json.loads(out.getvalue())
        self.assertTrue(result["world_preimage_verified"])
        self.assertEqual(result["accounts"], {
            "present": {"balance_nwei": str(balance), "nonce": str(2**64 - 1)},
            "zero": {"balance_nwei": "0", "nonce": "0"},
            "missing": None,
        })

        with (patch("sys.argv", args), patch.object(verifier, "fetch_proof", return_value=b"altered"),
              patch.object(verifier, "verify_native", return_value=native),
              patch.object(verifier, "select_world_accounts") as select,
              self.assertRaises(SystemExit), patch("sys.stderr", new=io.StringIO())):
            verifier.main()
        select.assert_not_called()

    def test_invalid_authenticated_account_values_are_rejected(self):
        for balance, nonce in [(True, 0), (-1, 0), (2**128, 0), (0, 2**64), (0, "0")]:
            with self.subTest(balance=balance, nonce=nonce):
                world = json.dumps({"accounts": {"account": {
                    "balance_nwei": balance, "nonce": nonce,
                }}}).encode()
                with self.assertRaisesRegex(ValueError, "invalid account balance or nonce"):
                    verifier.select_world_accounts(world, ["account"])

    def test_receipt_occurs_at_one_expected_height_across_verified_boundary(self):
        genesis, txid = "a" * 64, "b" * 64
        ids = {1000: "c" * 64, 1001: "d" * 64, 1002: "e" * 64}
        receipt = dict(transaction_id=txid, status="applied", gas_used=21000,
                       state_root_after="f" * 64, error_code=None)
        args = ["verify", "--observer", "https://example.test", "--node", __file__,
                "--config", __file__, "--chain", "99999", "--network", "canary",
                "--genesis", genesis, "--height", "1000", "--through-height", "1002",
                "--require-epoch-transition", "--receipt-id", txid, "--receipt-height", "1001"]

        def native(_command, height):
            epoch = 1 if height == 1000 else 2
            return dict(verified=True, chain_id=99999, network_id="canary", genesis_hash=genesis,
                        state_root="f" * 64, epoch=epoch, epoch_context_root=str(epoch) * 64,
                        consensus_timestamp_unix=height, finalized=dict(
                            height=height, block_id=ids[height], protected_execution_root="9" * 64))

        def proof(_endpoint, height, _kind):
            matches = [receipt] if height in present else []
            return json.dumps([height, ids.get(height - 1, "0" * 64),
                               "0" * 64, "f" * 64, [{}] * len(matches), matches]).encode()

        with (patch("sys.argv", args), patch.object(verifier, "fetch_proof", side_effect=proof),
              patch.object(verifier, "verify_native", side_effect=native)):
            present = {1001}
            with redirect_stdout(io.StringIO()) as out:
                verifier.main()
            result = json.loads(out.getvalue())
            self.assertEqual(result["receipt_occurrences_in_verified_range"], 1)
            self.assertEqual(result["epoch_transitions"], 1)
            self.assertEqual(result["observations"][1]["receipt"], receipt)
            self.assertNotIn("receipt", result["observations"][0])
            self.assertNotIn("receipt", result["observations"][2])
            for present, reason in (({1000, 1001}, "outside its expected"),
                                    ({1001, 1002}, "outside its expected"),
                                    (set(), "does not occur exactly once")):
                with (self.subTest(present=present), patch("sys.stderr", new=io.StringIO()) as err,
                      self.assertRaises(SystemExit)):
                    verifier.main()
                self.assertIn(reason, err.getvalue())

    def test_plain_transfer_proof_checks_exact_debit_credit_fee_and_nonce(self):
        amount, base_fee, gas, nonce = 1000, 2, 21000, 7
        intent = dict(sender="sender", receiver="receiver", amount_nwei=amount, nonce=nonce,
                      payload=[], fee_limit=dict(gas_limit=gas, max_fee_per_gas_nwei=3))
        intent["class"] = "user"
        receipt = dict(status="applied", gas_used=gas)
        before = {"sender": (100000, nonce), "collector": (55, 6)}
        after = {"sender": (57000, nonce + 1), "receiver": (1000, 0), "collector": (42055, 6)}

        def world(accounts):
            return json.dumps({"accounts": {
                key: {"balance_nwei": value, "nonce": counter, "code_hash": None}
                for key, (value, counter) in accounts.items()
            }, "protocol": {}}).encode()

        def verify(accounts=after, tx=intent, expected_base_fee=base_fee, extra=()):
            txs = [{"unsigned": tx}, *extra]
            block = json.dumps([1001, "a" * 64, "b" * 64, "c" * 64, txs, [receipt]])
            return verifier.verify_plain_transfer(block, receipt, world(before), world(accounts),
                                                  "collector", expected_base_fee)

        self.assertEqual(verify()["fee_nwei"], "42000")
        for key, bad_account in (("sender", (57001, 8)), ("receiver", (999, 0)),
                                 ("collector", (42054, 6)), ("sender", (57000, 9)),
                                 ("collector", (42055, 7))):
            with self.subTest(key=key, bad_account=bad_account), self.assertRaisesRegex(
                    ValueError, "balance, fee, or nonce"):
                verify(accounts={**after, key: bad_account})
        with self.assertRaisesRegex(ValueError, "signed fee limits"):
            verify(expected_base_fee=4)
        with self.assertRaisesRegex(ValueError, "exactly one transaction"):
            verify(extra=({"unsigned": intent},))
        with self.assertRaisesRegex(ValueError, "native plain transfer"):
            verify(tx={**intent, "payload": [1]})

    def test_transfer_accounting_cli_requires_both_observers_to_supply_matching_worlds(self):
        genesis, txid = "a" * 64, "b" * 64
        ids = {1000: "c" * 64, 1001: "d" * 64}
        intent = {
            "sender": "sender", "receiver": "receiver", "class": "user", "payload": [],
            "amount_nwei": 10, "nonce": 7,
            "fee_limit": {"gas_limit": 21000, "max_fee_per_gas_nwei": 2},
        }
        prior = {"sender": {"balance_nwei": 90000, "nonce": 7, "code_hash": None}}
        final = {
            "sender": {"balance_nwei": 47990, "nonce": 8, "code_hash": None},
            "receiver": {"balance_nwei": 10, "nonce": 0, "code_hash": None},
            "collector": {"balance_nwei": 42000, "nonce": 0, "code_hash": None},
        }
        worlds = {height: json.dumps({"accounts": accounts, "protocol": {}}).encode()
                  for height, accounts in ((1000, prior), (1001, final))}
        roots = {height: hashlib.sha3_256(
            b"SYNERGY_WORLD_STATE_ROOT_V1" + len(world).to_bytes(8, "big") + world
        ).hexdigest() for height, world in worlds.items()}
        receipt = {"transaction_id": txid, "status": "applied", "gas_used": 21000,
                   "state_root_after": roots[1001], "error_code": None}
        urls = ["https://first.example.test", "https://second.example.test"]
        args = ["verify", "--observer", urls[0], "--observer", urls[1], "--node", __file__,
                "--config", __file__, "--chain", "99999", "--network", "canary",
                "--genesis", genesis, "--height", "1000", "--through-height", "1001",
                "--receipt-height", "1001", "--receipt-id", txid,
                "--fee-collector", "collector", "--base-fee-per-gas-nwei", "2"]

        def proof(endpoint, height, kind):
            if kind == "world_state":
                world = worlds[height]
                return world + b" " if (endpoint, height) == corrupt else world
            if kind == "finality":
                return b"native fixture input"
            txs, receipts = ([{"unsigned": intent}], [receipt]) if height == 1001 else ([], [])
            return json.dumps([height, ids.get(height - 1, "0" * 64),
                               "f" * 64, roots[height], txs, receipts]).encode()

        def native(_command, height):
            epoch = 1 if height == 1000 else 2
            return dict(verified=True, chain_id=99999, network_id="canary", genesis_hash=genesis,
                        state_root=roots[height], epoch=epoch, epoch_context_root=str(epoch) * 64,
                        consensus_timestamp_unix=height, finalized=dict(
                            height=height, block_id=ids[height], protected_execution_root="f" * 64))

        corrupt = None
        with (patch("sys.argv", args), patch.object(verifier, "fetch_proof", side_effect=proof) as fetch,
              patch.object(verifier, "verify_native", side_effect=native)):
            with redirect_stdout(io.StringIO()) as out:
                verifier.main()
            result = json.loads(out.getvalue())
            self.assertEqual(result["observer_count"], 2)
            self.assertTrue(result["world_preimage_verified"])
            self.assertEqual(result["observations"][1]["transfer_accounting"]["fee_nwei"], "42000")
            self.assertNotIn("transfer_accounting", result["observations"][0])
            for height in worlds:
                for endpoint in urls:
                    self.assertIn(((endpoint, height, "world_state"), {}), fetch.call_args_list)
            for height in worlds:
                corrupt = (urls[1], height)
                with (self.subTest(corrupt=corrupt), patch("sys.stderr", new=io.StringIO()) as err,
                      self.assertRaises(SystemExit)):
                    verifier.main()
                self.assertIn("World preimage does not match the authenticated state root", err.getvalue())

    def test_exact_receipt_selection_rejects_missing_duplicate_and_invalid_status(self):
        txid = "a" * 64
        receipt = dict(transaction_id=txid, status="applied", gas_used=21000,
                       state_root_after="b" * 64, error_code=None)
        def block(receipts):
            return json.dumps([7, "c" * 64, "d" * 64, "e" * 64, [{}] * len(receipts), receipts])
        self.assertEqual(verifier.select_receipt(block([receipt]), txid), receipt)
        for receipts in ([], [receipt, receipt], [{**receipt, "transaction_id": "f" * 64}]):
            with self.assertRaisesRegex(ValueError, "exactly once"):
                verifier.select_receipt(block(receipts), txid)
        with self.assertRaisesRegex(ValueError, "invalid canonical receipt"):
            verifier.select_receipt(block([{**receipt, "status": "reverted"}]), txid)
