"""Bounded public phase metadata, never a send outcome or recovery authority."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
import bootstrap as b
import test_commission_reconciliation as fixture


class TreasurySendPhaseTests(unittest.TestCase):
    setUp=fixture.CommissionReconciliationTests.setUp
    save_policy=fixture.CommissionReconciliationTests.save_policy
    snapshot=fixture.CommissionReconciliationTests.snapshot
    transport_context=fixture.CommissionReconciliationTests.transport_context
    readiness_context=fixture.CommissionReconciliationTests.readiness_context
    prepare_commission=fixture.CommissionReconciliationTests.prepare
    def prepare(self):
        ctx,oldkey,_=self.prepare_commission();(self.control/'grants'/(oldkey+'.json')).unlink()
        self.request=json.dumps({'operation':'treasury_send_prepare','version':1,'parameters':{'nonce':0,'formation_sha256':ctx['formation_sha256'],'genesis_sha256':ctx['genesis_pins']['genesis.json']}},sort_keys=True,separators=(',',':')).encode()
        self.key=hashlib.sha256(self.request).hexdigest();ctx.update(request_sha256=self.key,nonce=0)
        self.ctx=ctx;self.treasury=self.root/'keys/formation-treasury';self.treasury.mkdir(mode=0o700)
        for name in ('request.json','treasury-public.json','treasury.enc.json','unlock'):
            path=self.treasury/name;path.write_bytes(b'PRIVATE-CUSTODY-DO-NOT-EXPORT');path.chmod(0o600)
        return ctx
    def grant(self):
        ctx=self.ctx;value={'root':str(self.root),'operation':'treasury_send_prepare','request_sha256':self.key,
            'expires_at':ctx['authorization']['expires_at'],'authorization_sha256':ctx['authorization']['sha256'],
            'authorization_sequence':ctx['authorization']['sequence']}
        path=self.control/'grants'/(self.key+'.json');path.write_text(json.dumps(value));path.chmod(0o600);return path
    def reserve(self):
        path=self.treasury/'sends'/'00000000000000000000';path.parent.mkdir(mode=0o700);path.mkdir(mode=0o700);return path
    def prove(self,context=None,challenge='1'*64,flag='--treasury-send-phase-proof'):
        wire={'context':context or self.ctx,'challenge':challenge}
        code="import json,pathlib,sys,io;ns={'__name__':'embedded_proof'};exec(compile(pathlib.Path(%r).read_bytes(),'bootstrap.py','exec'),ns);exec(\"class FixturePath(type(pathlib.Path())):\\n @property\\n def parents(self):return tuple(p for p in super().parents if p.is_relative_to(fixture))\",{'pathlib':pathlib,'fixture':pathlib.Path(%r)},ns);ns['ROOT']=ns['FixturePath'](%r);ns['NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256']='%s';sys.argv=['bootstrap.py',%r];sys.stdin=io.TextIOWrapper(io.BytesIO(%r));ns['main']()"%(str(Path(b.__file__).resolve()),str(self.root),str(self.root),'b'*64,flag,json.dumps(wire).encode())
        result=subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('PRIVATE-CUSTODY',result.stdout)
        return json.loads(result.stdout)
    def test_actual_entrypoint_absent_audited_and_inventory_phases_preserve_bytes(self):
        self.prepare();self.grant();before=self.snapshot();reply=self.prove();self.assertEqual(self.snapshot(),before)
        value=reply['result'];self.assertIs(reply['ok'],True);self.assertEqual(len(value),11)
        self.assertEqual(value['schema'],'nodenetwork-treasury-send-phase-v1');self.assertEqual(value['challenge'],'1'*64)
        self.assertEqual((value['grant_state'],value['audit_state'],value['reservation'],value['request_matches']),('exact','not_consumed','absent',None))
        self.assertFalse(value['mutation_performed']);self.assertNotIn('not_applied',value)
        (self.control/'grants'/(self.key+'.json')).unlink()
        audit=self.control/'audit.jsonl';audit.write_text(json.dumps({'operation':'treasury_send_prepare','request_sha256':self.key,'time':1})+'\n');audit.chmod(0o600)
        self.assertEqual(self.prove()['result']['audit_state'],'consumed');path=self.reserve()
        before=self.snapshot();empty_directory=self.prove()['result'];self.assertEqual(self.snapshot(),before)
        self.assertEqual(empty_directory['reservation'],'partial');self.assertTrue(all(v is None for v in empty_directory['files'].values()))
        for name,raw in [('request.json',self.request),('prepared.json',b'PUBLIC-METADATA'),('admission.json',b'PRIVATE-CIPHERTEXT-DO-NOT-EXPORT'),('dispatch-intent.json',b'PUBLIC-FENCE')]:
            source=path/name;source.write_bytes(raw);source.chmod(0o600)
            before=self.snapshot();value=self.prove()['result'];self.assertEqual(self.snapshot(),before)
            self.assertEqual(value['reservation'],'partial' if name=='request.json' else 'partial' if name=='prepared.json' else 'complete_inventory_unverified')
            self.assertTrue(value['request_matches']);self.assertEqual(value['files'][{'request.json':'request','prepared.json':'prepared','admission.json':'admission','dispatch-intent.json':'dispatch'}[name]],hashlib.sha256(raw).hexdigest())
        bad=copy.deepcopy(self.ctx);bad['nonce']=1
        other=path.parent/'00000000000000000001';other.mkdir(mode=0o700)
        duplicate=other/'request.json';duplicate.write_bytes(self.request);duplicate.chmod(0o600)
        self.assertFalse(self.prove(bad)['ok'])
        (path/'request.json').write_bytes(b'');empty=self.prove()['result']
        self.assertEqual(empty['reservation'],'partial');self.assertEqual(empty['files']['request'],hashlib.sha256(b'').hexdigest());self.assertFalse(empty['request_matches'])
        (path/'request.json').write_bytes(b'OTHER-IMMUTABLE-REQUEST');self.assertFalse(self.prove()['result']['request_matches'])
    def test_wrong_scope_nonce_challenge_and_unknown_wire_fields_refuse(self):
        self.prepare()
        for field,value in [('nonce',-1),('nonce',2**64-1),('nonce',False),('target',{}),('authorization',{}),('initial_sha256','0'*64),('genesis_pins',{}),('formation_sha256','0'*64),('request_sha256','bad'),('selection',{}),('expires_at',1),('extra',True)]:
            ctx=copy.deepcopy(self.ctx);ctx[field]=value;before=self.snapshot();self.assertFalse(self.prove(ctx)['ok'],field);self.assertEqual(self.snapshot(),before)
        self.assertFalse(self.prove(challenge='bad')['ok'])
    def test_links_modes_unknowns_and_malformed_audit_refuse_without_mutation(self):
        self.prepare();path=self.reserve();request=path/'request.json';request.write_bytes(self.request);request.chmod(0o600)
        for relative in ('foreign','request.json'):
            source=path/relative
            if relative=='foreign':source.write_bytes(b'unknown');source.chmod(0o600)
            else:source.chmod(0o644)
            before=self.snapshot();self.assertFalse(self.prove()['ok']);self.assertEqual(self.snapshot(),before)
            source.unlink() if relative=='foreign' else source.chmod(0o600)
        request.unlink();request.symlink_to(self.treasury/'unlock');self.assertFalse(self.prove()['ok']);request.unlink()
        audit=self.control/'audit.jsonl';audit.write_text('{}\n');audit.chmod(0o600);self.assertFalse(self.prove()['ok']);audit.unlink()
        unknown=path.parent/'not-a-nonce';unknown.mkdir();self.assertFalse(self.prove()['ok']);unknown.rmdir()
        path.rmdir();path.symlink_to(self.treasury);self.assertFalse(self.prove()['ok'])
        self.assertNotIn('PRIVATE-CUSTODY',json.dumps(self.prove()))

if __name__=='__main__':unittest.main()
