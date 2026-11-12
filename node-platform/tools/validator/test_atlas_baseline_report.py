import copy
import datetime
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('publisher',Path(__file__).with_name('publish-atlas-posy-telemetry.py'))
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)

class NativeTransportObservationTests(unittest.TestCase):
    def setUp(self):
        self.at=datetime.datetime.now(datetime.timezone.utc)
        self.state={'network_id':'current-chain','address':'synv1a','observed_at':self.at.isoformat(),'service':{'MainPID':'42'},
                    'chain_telemetry':{'schema_version':1,'network_identity':'current-chain','process_id':42,
                    'observed_at_unix_ms':self.at.timestamp()*1000,'transport':{'authenticated_peer_count':0},
                    'chain':{'consensus':{'height':21,'round':2},'pipeline':{'processing_build':{'height':21,'round':2,'proposer':'synv1a'}}}}}
    def test_actual_zero_missing_and_invalid_peer_counts(self):
        self.assertEqual(publisher.authenticated_peer_count(self.state),0)
        for value in [None,-1,True,1.5]:
            state=copy.deepcopy(self.state);state['chain_telemetry']['transport']['authenticated_peer_count']=value
            self.assertIsNone(publisher.authenticated_peer_count(state))
        for field,value in [('process_id',43),('network_identity','old-chain'),('observed_at_unix_ms',0)]:
            state=copy.deepcopy(self.state);state['chain_telemetry'][field]=value
            self.assertIsNone(publisher.authenticated_peer_count(state))
    def test_proposer_follows_native_takeover_not_height_modulo(self):
        self.assertEqual(publisher.current_proposer({2:self.state}),{'address':'synv1a','height':21,'round':2})
        other=copy.deepcopy(self.state);other['address']='synv1b'
        for state in [self.state,other]:state['chain_telemetry']['chain']['pipeline']['processing_build']['proposer']='synv1b'
        self.assertEqual(publisher.current_proposer({2:self.state,3:other})['address'],'synv1b')
        other['chain_telemetry']['chain']['pipeline']['processing_build']['proposer']='synv1a'
        self.assertIsNone(publisher.current_proposer({2:self.state,3:other}))
        other['chain_telemetry']['chain']['pipeline']['processing_build']['round']=1
        self.assertIsNone(publisher.current_proposer({3:other}))

class BaselineReportTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime.datetime.now(datetime.timezone.utc)
        self.network='synergy-posy-baseline-20261010'
        self.anchor={'height':47,'block_hash':'a'*64,'state_root':'b'*64}
        self.states={n:{'network_id':self.network,'genesis_hash':'a'*64,'height':48,'block':dict(self.anchor),'baseline_anchor':dict(self.anchor),'service':{'SubState':'running'}} for n in range(2,7)}
        self.report={'status':'completed','failure':None,'network_id':self.network,'start_utc':(self.now-datetime.timedelta(seconds=20)).isoformat(),'end_utc':(self.now-datetime.timedelta(seconds=1)).isoformat(),
                     'end_tip':{'common_finalized_height':47,'block_hash':'a'*64,'state_root':'b'*64,'validators':{f'val{n}':{} for n in range(2,7)}},
                     'submitted_transactions':10,'finalized_transactions':10,'backlog':{'remaining_in_flight':0},'finalized_tps':1.0,'end_to_end_finalized_tps':0.5,'offered_rate_tps':2.0,'load_window_seconds':10.0}
    def test_verified_completed_baseline(self):
        result=publisher.baseline_status(self.report,self.states,self.network,self.now)
        self.assertEqual(result['status'],'completed');self.assertEqual(result['baseline_finalized_tps'],1.0)
    def test_fail_closed(self):
        for field,value in [('status','failed'),('network_id','other'),('finalized_transactions',9),('end_utc',(self.now+datetime.timedelta(seconds=10)).isoformat()),('finalized_tps',float('nan'))]:
            report=copy.deepcopy(self.report);report[field]=value
            self.assertNotEqual(publisher.baseline_status(report,self.states,self.network,self.now)['status'],'completed')
        states=copy.deepcopy(self.states);states[6]['baseline_anchor']['state_root']='c'*64
        self.assertEqual(publisher.baseline_status(self.report,states,self.network,self.now)['status'],'unverified')
    def test_network_and_stall(self):
        self.assertEqual(publisher.active_network(self.states),self.network)
        bad=copy.deepcopy(self.states);bad[6]['network_id']='other'
        with self.assertRaises(ValueError):publisher.active_network(bad)
        bad=copy.deepcopy(self.states);bad[6]['genesis_hash']='b'*64
        with self.assertRaises(ValueError):publisher.active_network(bad)
        stalled,prior=publisher.stalled_status(self.states[2],None,100)
        self.assertFalse(stalled)
        self.assertTrue(publisher.stalled_status(self.states[2],prior,130)[0])
        newer=copy.deepcopy(self.states[2]);newer['height']=49
        self.assertFalse(publisher.stalled_status(newer,prior,131)[0])
    def test_distinguishes_unreachable_stopped_restarting_and_rpc_recovery(self):
        self.assertEqual(publisher.validator_status({'service':{}},None)[0],'unreachable')
        for substate, expected in [('dead','offline'),('auto-restart','restarting'),('start-pre','restarting'),('running','recovering')]:
            self.assertEqual(publisher.validator_status({'service':{'SubState':substate},'block':None},None)[0],expected)
        self.assertEqual(publisher.validator_status(self.states[2],3)[0],'syncing')
        self.assertEqual(publisher.validator_status(self.states[2],0),('active',None))

class LiveQuorumReportTests(unittest.TestCase):
    def test_live_evidence_and_fail_closed(self):
        import tempfile
        import json
        source=publisher.ROOT/'target'
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)
            text=(source/'live-quorum-recovery-seq18.log').read_text()
            (target/'live-quorum-recovery-seq18.log').write_text(text)
            (target/'live-quorum-recovery-seq18.exit').write_text('0')
            def card(network='synergy-posy-baseline-20261010'):
                return publisher.live_quorum_test_card(network,'now',target)
            self.assertEqual(card()['status'],'passed')
            self.assertEqual(card('other')['status'],'pending')
            (target/'live-quorum-recovery-seq18.exit').write_text('1')
            self.assertEqual(card()['status'],'pending')
            (target/'live-quorum-recovery-seq18.exit').write_text('0')
            events=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
            for kind in ['moving','restart','missing']:
                bad=copy.deepcopy(events)
                if kind=='moving':next(e for e in bad if e['event']=='below_quorum_observation')['after']['2']['finalized_height']=4201
                elif kind=='restart':next(e for e in bad if e['event']=='LIVE_QUORUM_RECOVERY_PASS')['services']['5']['NRestarts']='1'
                else:bad=[e for e in bad if e['event']!='four_validator_recovery_pass']
                (target/'live-quorum-recovery-seq18.log').write_text('\n'.join(json.dumps(e) for e in bad))
                self.assertEqual(card()['status'],'pending')

if __name__=='__main__':unittest.main()
