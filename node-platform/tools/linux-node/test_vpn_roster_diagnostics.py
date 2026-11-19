"""Managed public roster diagnostics; no daemon, network or credentials."""
import base64,copy,hashlib,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import controller,lifecycle,synergy_linux,vpn
from apqe_layout import FORMATION_PUBLIC_INPUTS

class RosterDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.c=object.__new__(controller.Controller)
        self.c.root=self.root;self.c.control=self.root/'tmp/controller'
        self.c.exists=Mock(return_value=False);self.c.direct=lambda path,*args:path
        self.receipt={'network_id':'signed-network','chain_id':99999,'node_name':'validator-02'}
        self.key=base64.b64encode(b'k'*32).decode()
        entries=[{'node_address':'address-'+str(i),'dial_address':'10.69.0.'+str(i)+':9000','revoked':False} for i in range(1,6)]
        self.base=self.c.control/'authorization/inputs/commissioning'
        self.pins={name:'a'*64 for name in FORMATION_PUBLIC_INPUTS}
        for name,value in [('config/node.json',self.receipt),('network/transport-registry.json',{'payload':{'validators':entries}})]:
            path=self.base/name;path.parent.mkdir(parents=True,exist_ok=True)
            raw=json.dumps(value).encode();path.write_bytes(raw);self.pins[name]=hashlib.sha256(raw).hexdigest()
        self.c.policy=Mock(return_value={'validator_commissioning_files':self.pins})
        self.current={'server_bound':True,'server_binding':{'ip':'10.69.0.1','wireguard_public_key':self.key}}
        self.live={'publicKey':self.key,'netbirdIp':'10.69.0.1/16','peers':{'details':[
            {'netbirdIp':'10.69.0.'+str(i)+'/16','publicKey':self.key,'status':'Connected'} for i in range(2,6)]}}
        self.calls=[]
    def native(self,args,**kwargs):
        self.calls.append(args)
        return json.dumps([{'dev':'wt0'}]) if args[0]=='ip' else ''
    def diagnose(self):
        with patch.object(lifecycle,'_sealed_receipt',return_value=(self.receipt,None)),patch.object(vpn,'status',return_value=self.live),patch.object(synergy_linux,'native',side_effect=self.native):
            return self.c.vpn_roster_diagnostics(self.current,self.live)
    def test_exact_four_signed_peers_cidr_and_bounded_probes(self):
        result=self.diagnose();self.assertTrue(result['available']);self.assertEqual(len(result['peers']),4)
        self.assertEqual(len(self.calls),8)
        self.assertTrue(all(p['reachable'] and p['matches'][0]['public_key_format_valid'] for p in result['peers']))
        self.assertEqual({c[4] for c in self.calls if c[0]=='ip'},{'10.69.0.'+str(i) for i in range(2,6)})
        self.assertNotIn('ready',json.dumps(result))
    def test_missing_duplicate_disconnected_unknown_are_retained(self):
        self.live['peers']['details']=[{'netbirdIp':'10.69.0.3','publicKey':self.key,'status':'Connected'}]*7+[
            {'netbirdIp':'10.69.0.4','publicKey':self.key,'status':'Disconnected'},
            {'netbirdIp':'10.69.0.5','publicKey':'SECRET DO NOT EXPORT','status':'private error'}]
        rows=self.diagnose()['peers']
        self.assertEqual([r['error_code'] for r in rows],['peer_missing','peer_duplicate','peer_not_connected','peer_not_connected'])
        self.assertEqual(rows[1]['match_count'],7);self.assertEqual(len(rows[1]['matches']),5)
        self.assertEqual(rows[3]['matches'],[{'wireguard_public_key':None,'public_key_format_valid':False,'status':'unknown'}])
        self.assertNotIn('SECRET',json.dumps(rows));self.assertNotIn('private error',json.dumps(rows))
    def test_changed_approval_refuses_without_probes(self):
        (self.base/'network/transport-registry.json').write_text('{}')
        result=self.diagnose();self.assertFalse(result['available']);self.assertEqual(result['error_code'],'scope_unavailable');self.assertEqual(self.calls,[])
    def test_live_identity_or_malformed_inventory_refuses_without_probes(self):
        for change in ('key','inventory'):
            with self.subTest(change=change):
                original=copy.deepcopy(self.live)
                if change=='key':self.live['publicKey']='foreign'
                else:self.live['peers']['details']=[{'netbirdIp':'private invalid'}]
                result=self.diagnose();self.assertEqual(result['error_code'],'status_unavailable');self.assertEqual(result['peers'],[]);self.assertEqual(self.calls,[])
                self.live=original
    def test_probe_failures_do_not_drop_status_or_expose_errors(self):
        def fail(args,**kw):raise subprocess.CalledProcessError(1,args,stderr='DO NOT EXPORT')
        self.native=fail;result=self.diagnose()
        self.assertEqual([r['error_code'] for r in result['peers']],['peer_route_unavailable']*4)
        self.assertTrue(all(r['matches'][0]['status']=='Connected' for r in result['peers']))
        self.assertNotIn('DO NOT EXPORT',json.dumps(result))

if __name__=='__main__':unittest.main()
