import importlib.util
from pathlib import Path
import sys
import unittest

spec = importlib.util.spec_from_file_location('posy_scheduling_contract', Path(__file__).with_name('model-posy-admission-scheduling.py'))
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def intent(name='tx', **changes):
    values = dict(transaction_id=name, incarnation='new', sender='wallet', nonce=0,
                  protected_bytes=200, min_target=6, max_target=10, expires_at=100,
                  fixed_target=None, verified_authorization=True)
    values.update(changes)
    return m.Intent(**values)


def eligible(owner, target=6):
    owner.bind('tx', target, 1)
    votes(owner, target)
    owner.availability('tx', target, [0, 1, 2, 3])
    owner.cutoff(target, True)
    owner.order('tx', target, True)
    owner.reveal('tx', target, True)


def votes(owner, target=6):
    for member in range(4):
        owner.availability_vote('tx', target, member, True)


class SchedulingContracts(unittest.TestCase):
    def test_cutoff_admission_race_both_durable_orders(self):
        a = m.SchedulingModel('new'); a.receive(intent(), 0); a.cutoff(6, True)
        with self.assertRaises(m.Rejected): a.bind('tx', 6, 1)
        # Pending target-independent material may use another authorized open target.
        a.bind('tx', 7, 1)
        b = m.SchedulingModel('new'); b.receive(intent(), 0); b.bind('tx', 6, 1); votes(b); b.cutoff(6, True)
        b.availability('tx', 6, [0, 1, 2, 3]); b.order('tx', 6, True)
        with self.assertRaises(m.Rejected): b.bind('tx', 7, 2)

    def test_current_target_bound_envelope_cannot_roll_forward(self):
        a = m.SchedulingModel('new'); a.receive(intent(fixed_target=6), 0); a.cutoff(6, True)
        with self.assertRaises(m.Rejected): a.bind('tx', 7, 1)

    def test_restart_retains_cutoff_binding_and_exactly_once_effect(self):
        a = m.SchedulingModel('new'); a.receive(intent(), 0)
        a.bind('tx', 6, 1); a = m.SchedulingModel.restore(a.snapshot())
        votes(a); a.cutoff(6, True); a = m.SchedulingModel.restore(a.snapshot())
        with self.assertRaises(m.Rejected): a.bind('tx', 7, 1)
        a.availability('tx', 6, [0, 1, 2, 3]); a.order('tx', 6, True); a.reveal('tx', 6, True)
        a.finalize('tx', 6, [6, 7, 8]); a = m.SchedulingModel.restore(a.snapshot())
        a.finalize('tx', 6, [6, 7, 8]); self.assertEqual(a.effects, {'tx': 1}); self.assertEqual(a.nonces['wallet'], 1)

    def test_duplicate_conflict_and_nonce_replay_after_finality(self):
        a = m.SchedulingModel('new'); a.receive(intent(), 0)
        self.assertEqual(a.receive(intent(), 0), 'durably-queued')
        with self.assertRaises(m.Rejected): a.receive(intent(protected_bytes=201), 0)
        eligible(a); a.finalize('tx', 6, [6, 7, 8])
        with self.assertRaises(m.Rejected): a.receive(intent('replay'), 0)

    def test_partition_delayed_reveal_and_three_qc_requirement(self):
        a = m.SchedulingModel('new'); a.receive(intent(), 0); a.bind('tx', 6, 1)
        with self.assertRaises(m.Rejected): a.availability('tx', 6, [0, 1, 2, 2])
        votes(a)
        a.availability('tx', 6, [0, 1, 2, 3]); a.cutoff(6, True); a.order('tx', 6, True)
        with self.assertRaises(m.Rejected): a.propose('tx', 6)

    def test_local_acceptance_without_quorum_before_cutoff_cannot_execute(self):
        a = m.SchedulingModel('new'); a.receive(intent(fixed_target=6), 0)
        a.bind('tx', 6, 1); a.availability_vote('tx', 6, 0, True)
        a.cutoff(6, True)
        for member in [1, 2, 3, 4]:
            with self.assertRaises(m.Rejected): a.availability_vote('tx', 6, member, True)
        with self.assertRaises(m.Rejected): a.availability('tx', 6, [0, 1, 2, 3])
        with self.assertRaises(m.Rejected): a.order('tx', 6, True)
        self.assertEqual(a.empty_candidate(6, True), 6)
        self.assertFalse(a.effects)

    def test_late_certificate_reconstruction_uses_only_retained_pre_cutoff_votes(self):
        a = m.SchedulingModel('new'); a.receive(intent(), 0); a.bind('tx', 6, 1)
        votes(a); a.cutoff(6, True); a = m.SchedulingModel.restore(a.snapshot())
        a.availability_vote('tx', 6, 0, True)
        a.availability('tx', 6, [0, 1, 2, 3]); a.order('tx', 6, True)
        with self.assertRaises(m.Rejected): a.availability_vote('tx', 6, 4, True)
        with self.assertRaises(m.Rejected): a.availability('tx', 6, [0, 1, 2, 4])
        with self.assertRaises(m.Rejected): a.reveal('tx', 6, False)
        a.reveal('tx', 6, True)
        with self.assertRaises(m.Rejected): a.finalize('tx', 6, [6, 7])
        a.finalize('tx', 6, [6, 7, 8]); self.assertEqual(a.effects['tx'], 1)

    def test_expiry_backpressure_and_wrong_incarnation(self):
        a = m.SchedulingModel('new', max_bytes=300); a.receive(intent(), 0)
        with self.assertRaises(m.Rejected): a.receive(intent('second', sender='other'), 0)
        with self.assertRaises(m.Rejected): a.receive(intent('old', incarnation='old'), 0)
        with self.assertRaises(m.Rejected): a.receive(intent('invalid', verified_authorization=False), 0)
        with self.assertRaises(m.Rejected): a.bind('tx', 6, 100)
        self.assertEqual(a.records['tx']['stage'], 'expired')

    def test_empty_progress_does_not_execute_pending_or_bypass_material(self):
        a = m.SchedulingModel('new'); a.receive(intent(), 0)
        with self.assertRaises(m.Rejected): a.empty_candidate(6, False)
        self.assertEqual(a.empty_candidate(6, True), 6)
        self.assertEqual(a.records['tx']['stage'], 'durably-queued'); self.assertFalse(a.effects)
        with self.assertRaises(m.Rejected): a.propose('tx', 6)


class DistributedContracts(unittest.TestCase):
    def transfer(self,**changes):
        args=dict(transaction_id='tx',incarnation='qualification',sender='wallet',nonce=0,target=6)
        args.update(changes);return m.BoundTransfer(**args)

    def test_closed_post_fsync_staging_never_recovers_accepted_receipt(self):
        owner=m.DistributedOwner(0);owner.stage(self.transfer());owner.observe_vc(6)
        self.assertEqual(owner.fsync_ack('tx'),'rejected_closed')
        recovered=owner.restore();self.assertEqual(recovered.receipt('tx'),'rejected_closed')
        self.assertIn('tx',recovered.staged)
        with self.assertRaises(m.Rejected):recovered.sign_availability('tx')

    def test_admitted_before_cutoff_remains_accepted_without_availability_guarantee(self):
        owner=m.DistributedOwner(0);owner.stage(self.transfer());owner.fsync_ack('tx');owner.observe_vc(6)
        self.assertEqual(owner.restore().receipt('tx'),'accepted')
        with self.assertRaises(m.Rejected):owner.sign_availability('tx')
        self.assertFalse(owner.published_availability)

    def test_cutoff_between_signature_and_ack_suppresses_fresh_broadcast(self):
        owner=m.DistributedOwner(0);owner.stage(self.transfer());owner.fsync_ack('tx');owner.sign_availability('tx')
        owner.observe_vc(6);self.assertFalse(owner.availability_fsync_ack('tx'))
        self.assertIn('tx',owner.restore().availability_journal)
        self.assertNotIn('tx',owner.published_availability)

    def test_duplicate_ambiguity_keeps_target_nonce_and_receipt(self):
        owner=m.DistributedOwner(0);owner.stage(self.transfer());owner.fsync_ack('tx')
        self.assertEqual(owner.restore().stage(self.transfer()),'accepted')
        for changed in [dict(target=7),dict(nonce=1),dict(incarnation='old')]:
            with self.assertRaises(m.Rejected):owner.stage(self.transfer(**changed))
        with self.assertRaises(m.Rejected):owner.stage(self.transfer(transaction_id='conflicting-nonce'))

    def test_round_cannot_advance_from_three_timeouts_or_local_clock(self):
        owners=[m.DistributedOwner(i) for i in range(5)]
        statements=[owner.timeout(1,0) for owner in owners[:4]]
        self.assertEqual(owners[0].rounds,{})
        with self.assertRaises(m.Rejected):owners[0].accept_tc(1,0,statements[:3])
        owners[0].accept_tc(1,0,statements)
        self.assertEqual(owners[0].rounds[1],1)
        with self.assertRaises(m.Rejected):owners[0].sign_consensus(1,0,'block')

    def test_restart_preserves_signing_choice_and_corruption_fails_closed(self):
        owner=m.DistributedOwner(0);owner.sign_consensus(1,0,'block');owner=owner.restore()
        with self.assertRaises(m.Rejected):owner.sign_consensus(1,0,'other')
        owner.corrupt=True
        with self.assertRaises(m.Rejected):owner.restore().sign_consensus(2,0,'block2')

    def test_worker_authority_and_generation_fence(self):
        owner=m.DistributedOwner(0);old=(owner.incarnation,owner.epoch,owner.generation)
        owner.generation+=1
        self.assertFalse(owner.accept_worker(old));self.assertFalse(owner.accept_worker(('foreign',2,owner.generation)))
        self.assertTrue(owner.accept_worker((owner.incarnation,owner.epoch,owner.generation)))
        self.assertEqual(owner.worker_results,1)

    def test_one_seed_covers_four_restore_five_rejoin_without_gate_claim(self):
        report=m.run_campaign(m.CampaignConfig(first_seed=17,seeds=1))
        self.assertEqual(report['completed_seeds'],1);self.assertIsNone(report['failure'])
        self.assertFalse(report['gate_c_qualified']);self.assertFalse(report['native_crypto_exercised'])
        for scenario in ('below_quorum_halt','fourth_validator_restoration','fifth_validator_rejoin','nonce_exactly_once_execution'):
            self.assertEqual(report['coverage_seed_counts'][scenario],1)
        self.assertTrue(report['proposed_unbound_model_excluded'])

    def test_three_qcs_require_linked_parent_and_duplicate_replay_is_idempotent(self):
        model=m.DistributedContractModel(4,m.CampaignConfig(seeds=1))
        first=model.certificate(1,0,());second=model.certificate(2,0,());third=model.certificate(3,0,())
        owner=m.DistributedOwner(0)
        owner.accept_qc(third);owner.accept_qc(first);self.assertEqual(owner.finalized,{})
        owner.accept_qc(second);self.assertEqual(owner.finalized,{1:first['block_id']})
        owner.accept_qc(first);self.assertEqual(owner.finalized,{1:first['block_id']})
        broken=m.DistributedOwner(1)
        wrong=m.copy.deepcopy(second);wrong['parent']='foreign'
        broken.accept_qc(first);broken.accept_qc(wrong);broken.accept_qc(third)
        self.assertEqual(broken.finalized,{})

    def test_qc_requires_exact_quorum_incarnation_and_verified_authority(self):
        model=m.DistributedContractModel(4,m.CampaignConfig(seeds=1));qc=model.certificate(1,0,())
        for change in [dict(votes=qc['votes'][:3]),dict(incarnation='old'),dict(verified=False)]:
            candidate={**qc,**change}
            with self.assertRaises(m.Rejected):m.DistributedOwner(0).accept_qc(candidate)

    def test_admission_queue_saturation_rejects_without_state_mutation(self):
        owner=m.DistributedOwner(0)
        for nonce in range(16):owner.stage(self.transfer(transaction_id=str(nonce),sender='wallet-'+str(nonce)))
        before=owner.restore().__dict__
        with self.assertRaises(m.Rejected):owner.stage(self.transfer(transaction_id='overflow',sender='overflow'))
        self.assertEqual(owner.__dict__,before)

    def test_seed_replay_and_bounds_are_explicit(self):
        config=m.CampaignConfig(first_seed=23,seeds=1)
        self.assertEqual(m.run_campaign(config),m.run_campaign(config))
        with self.assertRaises(m.Rejected):m.CampaignConfig(seeds=10001).validate()
        with self.assertRaises(m.Rejected):m.CampaignConfig(retention_heights=4).validate()


if __name__ == '__main__': unittest.main()
