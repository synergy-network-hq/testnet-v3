"""Lazy VPN activation remains bounded and final identity proof stays strict."""
import base64,copy,json,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
import controller,synergy_linux,vpn

class CommissioningVpnProbeTests(unittest.TestCase):
    def setUp(self):
        self.c=object.__new__(controller.Controller);self.c.root=Path('/not-used')
        self.ips={str(i):'10.69.0.'+str(i) for i in range(1,6)}
        self.online=['1','2','3','4'];self.key=lambda i:base64.b64encode(bytes([i])*32).decode()
        self.live={'publicKey':self.key(1),'netbirdIp':'10.69.0.1/16','management':{'connected':True},'signal':{'connected':True},
                   'peers':{'details':[{'netbirdIp':self.ips[str(i)]+'/16','publicKey':self.key(i),'status':'Idle'} for i in range(2,6)]}}
        self.final=copy.deepcopy(self.live)
        for peer in self.final['peers']['details']:peer['status']='Connected'
        self.calls=[]
    def native(self,args,**kw):
        self.calls.append((args,kw))
        if args[0]=='ip':return json.dumps([{'dev':'wt0'}])
        self.assertEqual(args[1:-1],['-n','-I','wt0','-c','3','-W','2'])
        self.assertEqual(kw['timeout'],9);self.assertNotIn('-w',args)
        return '3 packets transmitted, 1 received, 66% packet loss'
    def observe(self):
        with patch.object(synergy_linux,'native',side_effect=self.native),patch.object(vpn,'status',return_value=self.final) as read:
            result=self.c.commissioning_vpn_peers(self.live,self.ips,self.online,'1')
            read.assert_called_once_with(self.c.root)
            return result
    def test_idle_and_first_cold_loss_succeed_only_with_final_connected(self):
        result=self.observe();self.assertEqual(set(result),{'2','3','4'})
        self.assertEqual(len(self.calls),6)
        self.assertTrue(all(p['reachable'] for p in result.values()))
        self.assertNotIn(self.ips['5'],str(self.calls))
    def test_final_idle_key_change_missing_duplicate_and_local_drift_refuse(self):
        original=copy.deepcopy(self.final)
        changes=[lambda j:j['peers']['details'][0].update(status='Idle'),
                 lambda j:j['peers']['details'][0].update(publicKey=self.key(9)),
                 lambda j:j['peers']['details'].pop(0),
                 lambda j:j['peers']['details'].append(copy.deepcopy(j['peers']['details'][0])),
                 lambda j:j.update(publicKey=self.key(9)),lambda j:j.update(netbirdIp='10.69.0.9'),
                 lambda j:j['management'].update(connected=False),lambda j:j['signal'].update(connected=False),
                 lambda j:j['peers']['details'][0].update(publicKey='invalid')]
        for change in changes:
            with self.subTest(change=change):
                self.final=copy.deepcopy(original);change(self.final)
                with self.assertRaises((ValueError,controller.Refused)):self.observe()
    def test_bad_initial_key_or_duplicate_refuses_before_traffic(self):
        for duplicate in (False,True):
            sample=copy.deepcopy(self.live)
            if duplicate:sample['peers']['details'].append(copy.deepcopy(sample['peers']['details'][0]))
            else:sample['peers']['details'][0]['publicKey']='invalid'
            with patch.object(synergy_linux,'native') as run,patch.object(vpn,'status') as read:
                with self.assertRaises((ValueError,controller.Refused)):self.c.commissioning_vpn_peers(sample,self.ips,self.online,'1')
                run.assert_not_called();read.assert_not_called()
    def test_all_packet_loss_or_foreign_route_refuses_without_final_proof(self):
        for route in (False,True):
            def fail(args,**kw):
                if args[0]=='ip':return json.dumps([{'dev':'eth0' if route else 'wt0'}])
                raise subprocess.CalledProcessError(1,args)
            with patch.object(synergy_linux,'native',side_effect=fail),patch.object(vpn,'status') as read:
                with self.assertRaises((ValueError,controller.Refused,subprocess.CalledProcessError)):self.c.commissioning_vpn_peers(self.live,self.ips,self.online,'1')
                read.assert_not_called()
    def test_metadata_discovery_does_not_probe_or_resample(self):
        with patch.object(synergy_linux,'native') as run,patch.object(vpn,'status') as read:
            self.assertEqual(self.c.commissioning_vpn_peers(self.live,self.ips,[],'1'),{})
            run.assert_not_called();read.assert_not_called()

if __name__=='__main__':unittest.main()
