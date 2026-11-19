"""Exact unused-grant negative reconciliation; never authorizes a transfer."""
import copy
import json
import unittest
import test_treasury_send_phase as phase

class TreasurySendReconciliationTests(phase.TreasurySendPhaseTests):
    def prepare_negative(self):
        self.prepare();self.grant()
        for name in self.ctx['genesis_pins']:
            path=self.root/'network'/name;path.write_bytes((self.root/'tmp/identity-network'/name).read_bytes());path.chmod(0o600)
    def negative(self,context=None):return self.prove(context,flag='--treasury-send-not-applied-proof')
    def test_unused_exact_original_grant_and_global_request_absence_prove_false_without_writes(self):
        self.prepare_negative();before=self.snapshot();value=self.negative()
        self.assertTrue(value['ok']);self.assertEqual(set(value['result']),{'schema','challenge','request_sha256','nonce','authorization_sha256','not_applied','mutation_performed'})
        self.assertEqual(value['result'],{'schema':'nodenetwork-treasury-send-not-applied-v1','challenge':'1'*64,
            'request_sha256':self.key,'nonce':0,'authorization_sha256':self.ctx['authorization']['sha256'],
            'not_applied':True,'mutation_performed':False});self.assertEqual(self.snapshot(),before)
        # Nonce is declared, not recovered from nonexistent request bytes.
        other=copy.deepcopy(self.ctx);other['nonce']=1;self.assertTrue(self.negative(other)['ok']);self.assertEqual(self.snapshot(),before)
    def test_any_original_reservation_audit_partial_or_changed_authorization_refuses(self):
        self.prepare_negative()
        for relative in ('tmp/controller-authorization','tmp/controller-authorization.pending','tmp/controller-update',
                         'tmp/treasury-send-crashed','evidence/upgrade-intent.json','evidence/application-replacement-intent.json'):
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('unchanged');before=self.snapshot()
            self.assertFalse(self.negative()['ok'],relative);self.assertEqual(self.snapshot(),before);path.unlink()
        grant=self.control/'grants'/(self.key+'.json');original=grant.read_bytes();grant.unlink();self.assertFalse(self.negative()['ok']);grant.write_bytes(original);grant.chmod(0o600)
        value=json.loads(original);value['authorization_sequence']+=1;grant.write_text(json.dumps(value));self.assertFalse(self.negative()['ok']);grant.write_bytes(original)
        audit=self.control/'audit.jsonl';audit.write_text(json.dumps({'operation':'treasury_send_prepare','request_sha256':self.key,'time':1})+'\n');audit.chmod(0o600)
        before=self.snapshot();self.assertFalse(self.negative()['ok']);self.assertEqual(self.snapshot(),before);audit.unlink()
        path=self.reserve();self.assertFalse(self.negative()['ok']) # Even an EMPTY reservation refuses.
        request=path/'request.json';request.write_bytes(self.request);request.chmod(0o600);self.assertFalse(self.negative()['ok'])
        # Global original-hash attribution: selecting another nonce cannot hide it.
        other=copy.deepcopy(self.ctx);other['nonce']=1
        for name in ('prepared.json','admission.json'):
            f=path/name;f.write_text('public-ciphertext');f.chmod(0o600)
        self.assertFalse(self.negative(other)['ok'])
        prior=json.loads(self.request);prior['parameters']['amount_nwei']='2';request.write_text(json.dumps(prior))
        before=self.snapshot();self.assertTrue(self.negative(other)['ok']);self.assertEqual(self.snapshot(),before)
        prior['parameters']['nonce']=1;request.write_text(json.dumps(prior));self.assertFalse(self.negative(other)['ok'])
    def test_signed_inputs_and_scope_must_remain_exact_and_private(self):
        self.prepare_negative()
        for field,value in [('request_sha256','0'*64),('authorization',{}),('target',{}),('selection',{}),('nonce',False),('expires_at',1),('extra',True)]:
            context=copy.deepcopy(self.ctx);context[field]=value;self.assertFalse(self.negative(context)['ok'],field)
        path=self.root/'network/genesis.json';raw=path.read_bytes();path.write_bytes(b'changed');self.assertFalse(self.negative()['ok']);path.write_bytes(raw)
        path.chmod(0o644);self.assertFalse(self.negative()['ok']);path.chmod(0o600)
        path.unlink();path.symlink_to(self.root/'network/authority.json');self.assertFalse(self.negative()['ok'])

if __name__=='__main__':unittest.main()
