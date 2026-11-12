import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('reconciler', Path(__file__).with_name('reconcile-processing-handoff.py'))
reconciler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconciler)


class InterruptedWorkloadTests(unittest.TestCase):
    def stream(self, change=None):
        record = {'transaction_id': 'a' * 64, 'receipt_id': 'b' * 128,
                  'wallet_id': 'sender-00', 'sender': 'sender', 'nonce': 3,
                  'intent': {'receiver': 'receiver', 'amount_nwei': 1, 'gas_limit': 21000,
                             'max_fee_per_gas_nwei': 40, 'timestamp_unix': 100}}
        unsigned = {'network': {'chain_id': 9001, 'network_id': 'selected'}, 'class': 'user',
                    'sender': 'sender', 'receiver': 'receiver', 'amount_nwei': 1, 'nonce': 3,
                    'fee_limit': {'gas_limit': 21000, 'max_fee_per_gas_nwei': 40},
                    'timestamp_unix': 100, 'payload': []}
        block = {'height': 20, 'block_hash': 'block', 'state_root': 'state',
                 'finality_certificate_id': 'qc', 'protected_execution_root': 'execution',
                 'transactions': [{'unsigned': unsigned, 'signature_algorithm': 'ML-DSA-87'}],
                 'receipts': [{'transaction_id': record['transaction_id'], 'status': 'applied',
                               'error_code': None, 'gas_used': 21000}]}
        stream = io.BytesIO()
        def append(value):
            raw = json.dumps(value, separators=(',', ':')).encode() + b'\n'
            ref = {'offset': stream.tell(), 'length': len(raw), 'sha3_256': hashlib.sha3_256(raw).hexdigest()}
            stream.write(raw)
            return ref
        append({'kind': 'submission', 'record': record})
        pending = {**record, 'transaction_id': 'c' * 64, 'receipt_id': 'd' * 128, 'nonce': 4}
        append({'kind': 'submission', 'record': pending})
        refs = {}
        for number in range(2, 7):
            name = f'val{number}'
            view = copy.deepcopy(block)
            if change == 'conflicting_block' and number == 6:
                view['state_root'] = 'conflict'
            if change == 'wrong_intent':
                view['transactions'][0]['unsigned']['amount_nwei'] = 2
            if change == 'reverted':
                view['receipts'][0]['status'] = 'reverted'
                view['receipts'][0]['error_code'] = 'async_parent_nonce_stale_v1'
            refs[name] = append({'kind': 'validator_finalized_block', 'validator': name, 'block': view})
        account = {'address': 'sender', 'nonce': 4, 'balance_nwei': '100', 'finalized_height': 20,
                   'finalized_block_hash': 'block', 'state_root': 'state'}
        accounts = {f'val{n}': copy.deepcopy(account) for n in range(2, 7)}
        if change == 'missing_validator':
            refs.pop('val6')
        if change == 'digest':
            refs['val6']['sha3_256'] = '0' * 64
        if change == 'account_nonce':
            for value in accounts.values():
                value['nonce'] = 5
        frame = {'kind': 'finalized_transfer', 'record': {**record, 'block_height': 20},
                 'finalized_block_refs': refs, 'sender_account_views': accounts,
                 'sender_block_cohort': [record['transaction_id']]}
        append(frame)
        if change == 'duplicate':
            append(frame)
        return stream

    def test_consumes_exact_all_five_proof_and_keeps_only_compact_unresolved_intent(self):
        native = {'c' * 64: {'val2': 'finalized'}}
        result = reconciler.reconcile_workload_stream(self.stream(), 'selected', 9001, native)
        self.assertEqual(result['submitted_intents'], 2)
        self.assertEqual(result['all_five_applied_verified'], 1)
        self.assertEqual(result['unresolved_count'], 1)
        unresolved = result['unresolved_intents'][0]
        self.assertEqual(unresolved['transaction_id'], 'c' * 64)
        self.assertEqual(unresolved['status'], 'unresolved')
        self.assertFalse(unresolved['automatic_resubmission_permitted'])
        self.assertEqual(unresolved['native_lifecycle_by_validator'], {'val2': 'finalized'})
        self.assertNotIn('admission', unresolved)
        self.assertIsNone(result['transaction_latency_deadline_seconds'])

    def test_tampered_or_incomplete_proof_never_becomes_applied(self):
        for change in ('conflicting_block', 'wrong_intent', 'reverted', 'missing_validator', 'digest', 'account_nonce', 'duplicate'):
            with self.subTest(change=change), self.assertRaises(reconciler.ReconciliationError):
                reconciler.reconcile_workload_stream(self.stream(change), 'selected', 9001)

    def test_network_identity_remains_enforced(self):
        with self.assertRaises(reconciler.ReconciliationError):
            reconciler.reconcile_workload_stream(self.stream(), 'different', 9001)

    def test_authored_intent_without_submission_frame_remains_uncertain(self):
        stream = self.stream()
        first = json.loads(stream.getvalue().splitlines()[0])
        first['kind'] = 'authored_processing_admission'
        first['admission'] = {'request': 'disposable encrypted body'}
        raw = io.BytesIO(json.dumps(first).encode() + b'\n')
        result = reconciler.reconcile_workload_stream(raw, 'selected', 9001)
        self.assertEqual(result['authored_intents'], 1)
        self.assertEqual(result['submitted_intents'], 0)
        self.assertFalse(result['unresolved_intents'][0]['submission_recorded'])
        self.assertFalse(result['unresolved_intents'][0]['automatic_resubmission_permitted'])
        self.assertNotIn('admission', result['unresolved_intents'][0])

    def test_bounded_ledger_and_truncated_frame_fail_closed(self):
        with self.assertRaisesRegex(reconciler.ReconciliationError, 'capacity'):
            reconciler.reconcile_workload_stream(self.stream(), 'selected', 9001, max_intents=1)
        with self.assertRaisesRegex(reconciler.ReconciliationError, 'incomplete'):
            reconciler.reconcile_workload_stream(io.BytesIO(b'{"kind":"submission"}'), 'selected', 9001)


if __name__ == '__main__':
    unittest.main()
