"""Root coordinator adapter only; simulated API responses do not qualify live deletion."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import Mock, patch
import vpn
import vpn_authorization as auth

class LegacyPeerTests(unittest.TestCase):
    def setUp(self):
        self.ca=b'public-fixture-ca';self.key='EhHDd/L7fXX+c8x2nyJx8wWUwGRij3AmioVZKiH4/2M='
        self.local={'native_enrollment_verified':True,'wireguard_public_key':self.key,'hostname':'synergy-canary-rpc-99999','management_url':'https://vpn-coordinator.synergy-network.io:443','overlay_address':'10.69.51.205/16'}
        self.binding={'server_binding_verified':True,'wireguard_public_key':self.key,'peer_id':'dboqb9if611ohpqo0e1g','peer_name':self.local['hostname'],'hostname':'vmi3381382','ip':'10.69.51.205'}
        self.policy={'version':1,'profile':auth.CONTROLLED_PROFILE,'network_binding':{'network_id':'posy-apqe-canary-process-49028','chain_id':99999,'formation_sha256':'a'*64},'management_origin':'https://vpn-coordinator.synergy-network.io','api_origin':'https://vpn-coordinator.synergy-network.io','account_id':'original-account','ca_sha256':hashlib.sha256(self.ca).hexdigest(),'auto_groups':[],'required_peer_ips':['10.69.51.205'],'expires_at':1}
        self.enrollment=json.dumps(self.local).encode();self.bound=json.dumps(self.binding).encode();self.raw=auth.encode(self.policy)
        self.expected={'provider_sha256':hashlib.sha256(self.raw).hexdigest(),'account_id':'original-account','enrollment_sha256':hashlib.sha256(self.enrollment).hexdigest(),'binding_sha256':hashlib.sha256(self.bound).hexdigest()}
        self.peer={'id':self.binding['peer_id'],'name':self.binding['peer_name'],'hostname':self.binding['hostname'],'ip':self.binding['ip']}
    def scope(self,**changes):
        args=dict(enrollment=self.enrollment,binding=self.bound,provider_raw=self.raw,expected=self.expected,ca=self.ca,now=1000);args.update(changes)
        return vpn.legacy_canary_retirement_scope(**args)
    def test_expired_original_policy_is_cleanup_only(self):
        policy,identity=self.scope();self.assertEqual(policy['account_id'],'original-account');self.assertEqual(identity['peer_id'],self.peer['id'])
        with self.assertRaises(ValueError):auth.provider_policy(self.raw,self.expected['provider_sha256'],self.ca,1000)
    def test_foreign_scope_or_commitments_refuse(self):
        for defect in ('network','account','ca','provider_pin','binding','key','both_keys'):
            policy=copy.deepcopy(self.policy);expected=copy.deepcopy(self.expected);changes={}
            if defect=='network':
                policy['network_binding']['network_id']='synergy-posy-canary-20261117';changes['provider_raw']=auth.encode(policy);expected['provider_sha256']=hashlib.sha256(changes['provider_raw']).hexdigest()
            if defect=='account':expected['account_id']='another-account'
            if defect=='ca':changes['ca']=b'foreign-ca'
            if defect=='provider_pin':expected['provider_sha256']='b'*64
            if defect=='binding':changes['binding']=self.bound+b' '
            if defect in ('key','both_keys'):
                local=copy.deepcopy(self.local);local['wireguard_public_key']='A'*43+'=';changes['enrollment']=json.dumps(local).encode();expected['enrollment_sha256']=hashlib.sha256(changes['enrollment']).hexdigest()
                if defect=='both_keys':
                    remote=copy.deepcopy(self.binding);remote['wireguard_public_key']=local['wireguard_public_key'];changes['binding']=json.dumps(remote).encode();expected['binding_sha256']=hashlib.sha256(changes['binding']).hexdigest()
            with self.subTest(defect=defect),self.assertRaises(ValueError):self.scope(expected=expected,**changes)
    def test_lost_delete_reconciles_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory).resolve();work.chmod(0o700)
            original=Path.lstat
            def owned(path):
                values=list(original(path));values[4]=0;return os.stat_result(values)
            with patch('time.time',return_value=1000) as clock,patch('lifecycle._require_operator'),patch('lifecycle._lifecycle_lock',side_effect=lambda _:nullcontext()),patch.object(vpn.os,'geteuid',return_value=0),patch.object(Path,'lstat',owned),patch.object(Path,'stat',owned),patch.object(vpn,'retirement_input',side_effect=lambda p,limit=vpn.RETIREMENT_LIMIT:p.read_bytes()):
                def delayed_peer(method,path):
                    if path=='/api/accounts':return 200,[{'id':'original-account'}]
                    clock.return_value=1101
                    return 200,self.peer
                request=Mock(side_effect=delayed_peer)
                with self.assertRaisesRegex(ValueError,'expired before deletion'):
                    vpn.retire_legacy_canary_peer(work,self.enrollment,self.bound,self.raw,self.expected,self.ca,1000,request,review_expires_at=1100)
                self.assertTrue((work/vpn.RETIREMENT_INTENT).exists())
                self.assertFalse(any(c.args[0]=='DELETE' for c in request.call_args_list))
                # A separate explicit invocation represents a fresh native review;
                # the original exact-peer intent remains immutable.
                clock.return_value=1000
                request=Mock(side_effect=[(200,[{'id':'original-account'}]),(200,self.peer),OSError('lost reply')])
                with self.assertRaises(OSError):vpn.retire_legacy_canary_peer(work,self.enrollment,self.bound,self.raw,self.expected,self.ca,1000,request,review_expires_at=1100)
                self.assertTrue((work/vpn.RETIREMENT_INTENT).exists());self.assertFalse((work/vpn.RETIREMENT).exists())
                request=Mock(side_effect=[(200,[{'id':'original-account'}]),(404,None),(200,[])])
                receipt=vpn.retire_legacy_canary_peer(work,self.enrollment,self.bound,self.raw,self.expected,self.ca,1000,request,review_expires_at=1100)
                result=json.loads(receipt.read_bytes());self.assertTrue(result['retired']);self.assertTrue(result['absence_verified']);self.assertFalse(any(c.args[0]=='DELETE' for c in request.call_args_list))
    def test_bad_scope_never_creates_intent_or_contacts_provider(self):
        with tempfile.TemporaryDirectory() as directory,patch('lifecycle._require_operator'):
            expected={**self.expected,'account_id':'foreign'};request=Mock()
            with self.assertRaises(ValueError):vpn.retire_legacy_canary_peer(Path(directory),self.enrollment,self.bound,self.raw,expected,self.ca,1000,request,review_expires_at=1100)
            request.assert_not_called();self.assertEqual(list(Path(directory).iterdir()),[])
    def test_expired_or_oversize_review_never_calls_provider(self):
        for deadline in (999,1000,1121,True):
            with tempfile.TemporaryDirectory() as directory,patch('lifecycle._require_operator'):
                request=Mock()
                with self.assertRaises(ValueError):vpn.retire_legacy_canary_peer(Path(directory),self.enrollment,self.bound,self.raw,self.expected,self.ca,1000,request,review_expires_at=deadline)
                request.assert_not_called();self.assertEqual(list(Path(directory).iterdir()),[])
    def review(self):
        return {'purpose':'nodenetwork-legacy-peer-retirement-v1','plan_sha256':'c'*64,
            'provider_sha256':self.expected['provider_sha256'],'account_id':'original-account',
            'enrollment_sha256':self.expected['enrollment_sha256'],'binding_sha256':self.expected['binding_sha256'],
            'expires_at':1100,'network_id':'posy-apqe-canary-process-49028',
            'genesis_sha256':'d28ab09b6857f670482580a786edd939b090e88aa9378cdd0ad91379a724a9d7',
            'machine_id_sha256':'8683ea9f4da9e9c05c26b6d8070cc13c0f5f75b0cd4a4de863492164f4c1e26d',
            'target':{'kind':'remote','host':'167.86.83.83','port':22,'root':'/opt/Synergy'}}
    def preflight(self,review,request):
        with patch('time.time',return_value=1000):
            return vpn.legacy_canary_peer_preflight(self.enrollment,self.bound,self.raw,self.expected['provider_sha256'],self.ca,review,'c'*64,1000,request)
    def test_new_exact_purpose_uses_transport_trust_without_reusing_network_issuance_scope(self):
        self.policy['network_binding']['network_id']='synergy-posy-canary-20261117'
        self.raw=auth.encode(self.policy);self.expected['provider_sha256']=hashlib.sha256(self.raw).hexdigest()
        request=Mock(side_effect=[(200,[{'id':'original-account'}]),(200,self.peer),(200,[self.peer])])
        result=self.preflight(self.review(),request)
        self.assertTrue(result['account_verified']);self.assertTrue(result['peer_verified'])
        self.assertFalse(result['ready']);self.assertFalse(result['public_key_verified']);self.assertFalse(result['retirement_authorized'])
        self.assertEqual(result['blocker'],'independent_peer_key_binding_unavailable')
        self.assertTrue(all(c.args[0]=='GET' for c in request.call_args_list))
    def test_new_purpose_is_required_and_foreign_account_peer_or_ambiguous_inventory_refuse(self):
        for field,value in [('purpose','enroll'),('plan_sha256','d'*64),('network_id','synergy-posy-canary-20261117'),('expires_at',999),('account_id','foreign')]:
            review=self.review();review[field]=value;request=Mock()
            with self.subTest(field=field),self.assertRaises(ValueError):self.preflight(review,request)
            request.assert_not_called()
        for responses in [[(200,[{'id':'foreign'}])],[(200,[{'id':'original-account'}]),(200,{**self.peer,'id':'foreign'})],[(200,[{'id':'original-account'}]),(200,self.peer),(200,[self.peer,self.peer])]]:
            with self.assertRaises(ValueError):self.preflight(self.review(),Mock(side_effect=responses))
    def test_unverified_api_key_field_is_never_adopted_as_independent_key_proof(self):
        peer={**self.peer,'public_key':self.key,'wireguard_public_key':self.key}
        result=self.preflight(self.review(),Mock(side_effect=[(200,[{'id':'original-account'}]),(200,peer),(200,[peer])]))
        self.assertFalse(result['public_key_verified']);self.assertFalse(result['ready'])

if __name__=='__main__':unittest.main()
