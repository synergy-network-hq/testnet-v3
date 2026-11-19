"""Exact unaudited commission recovery: isolated embedded proof, no host access."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import bootstrap as b
import controller
import lifecycle
import test_continuation_reconciliation as fixture
from test_commissioning_readiness import observations


class CommissionReconciliationTests(unittest.TestCase):
    setUp=fixture.ContinuationReconciliationTests.setUp
    save_policy=fixture.ContinuationReconciliationTests.save_policy
    snapshot=fixture.ContinuationReconciliationTests.snapshot
    transport_context=fixture.ContinuationReconciliationTests.transport_context
    readiness_context=fixture.ContinuationReconciliationTests.readiness_context

    def prepare(self):
        ctx,_,key=self.readiness_context()
        ctx.pop('artifact_sha256');ctx.pop('dispatch_sha256');ctx.pop('pending_sha256')
        ctx['request_sha256']=key
        self.policy['engineering_authorization']['expires_at']=1000
        ctx['authorization']=copy.deepcopy(self.policy['engineering_authorization'])
        raw=json.dumps(observations(),sort_keys=True,separators=(',',':')).encode()
        pin=hashlib.sha256(raw).hexdigest()
        path=self.control/'authorization/inputs/commissioning-readiness.json'
        path.write_bytes(raw);path.chmod(0o600)
        self.policy.setdefault('authorization_files',{})['commissioning-readiness.json']=pin
        module=self.control/'controller.py'
        module.write_text(module.read_text()+"\ndef binding(self,**kw):\n assert kw=={'locked':True} and not (self.root/'bad-custody').exists()\n return {'bound':True}\nController.genesis_binding=binding\n")
        self.policy['engine_files']['controller.py']=hashlib.sha256(module.read_bytes()).hexdigest()
        life=self.control/'tools/lifecycle.py'
        life.write_text(life.read_text()+"\ndef _attributed_units(root):\n assert not (root/'foreign-unit').exists()\n return {n:_unit_state(n) for n in ('synergy-node.service','synergy-vpn.service')}\n")
        self.policy['engine_files']['lifecycle.py']=hashlib.sha256(life.read_bytes()).hexdigest()
        self.save_policy()
        grant={'root':str(self.root),'operation':'commission','request_sha256':key,'expires_at':1000,
            'authorization_sha256':ctx['authorization']['sha256'],'authorization_sequence':ctx['authorization']['sequence']}
        path=self.control/'grants'/(key+'.json');path.write_text(json.dumps(grant));path.chmod(0o600)
        return ctx,key,pin

    def prove(self,ctx,challenge='1'*64,entrypoint=False):
        wire={'context':ctx,'challenge':challenge}
        code="import json,pathlib;ns={'__name__':'embedded_proof'};exec(compile(pathlib.Path(%r).read_bytes(),'bootstrap.py','exec'),ns);exec(\"class FixturePath(type(pathlib.Path())):\\n @property\\n def parents(self):return tuple(p for p in super().parents if p.is_relative_to(fixture))\",{'pathlib':pathlib,'fixture':pathlib.Path(%r)},ns);ns['ROOT']=ns['FixturePath'](%r);ns['NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256']='%s';print(json.dumps(ns['continuation_not_applied_proof'](json.loads(%r),commission=True)))"%(str(Path(b.__file__).resolve()),str(self.root),str(self.root),'b'*64,json.dumps(wire))
        if entrypoint:
            code=code.rsplit(';print(json.dumps',1)[0]+";import io,sys;sys.argv=['bootstrap.py','--commission-outcome-proof'];sys.stdin=io.TextIOWrapper(io.BytesIO(%r));ns['main']()"%json.dumps(wire).encode()
        return subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True,timeout=5)

    def test_expired_readiness_dispatch_has_no_authorization_or_commission_writes_then_proves_negative(self):
        ctx,key,pin=self.prepare();c=controller.Controller(self.root)
        value=observations();before=self.snapshot()
        with patch('platform.system',return_value='Linux'),patch('platform.machine',return_value='x86_64'),\
             patch('synergy_linux.safe_root',return_value=self.root),patch.object(c,'policy',return_value=self.policy),\
             patch.object(c,'exists',side_effect=lambda p:p==controller.FORMATION_CUSTODY),\
             patch.object(c,'require_bound_validator_vpn'),patch.object(c,'genesis_binding',return_value={'bound':True}),\
             patch.object(c,'commissioning_observation',return_value=value['observations'][0]),\
             patch('controller.time.time',return_value=1400),patch.object(c,'authorize') as authorize,\
             patch.object(lifecycle,'commission') as commission:
            with self.assertRaisesRegex(ValueError,'expired'):
                c.dispatch({'version':1,'operation':'commission','parameters':{}})
            authorize.assert_not_called();commission.assert_not_called()
        self.assertEqual(self.snapshot(),before)
        result=self.prove(ctx);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),{'schema':'nodenetwork-commission-not-applied-v1',
            'challenge':'1'*64,'request_sha256':key,'authorization_sha256':ctx['authorization']['sha256'],
            'readiness_sha256':pin,'not_applied':True,'mutation_performed':False})
        self.assertEqual(self.snapshot(),before)

    def test_exact_entrypoint_closed_envelope_and_challenge(self):
        ctx,_,_=self.prepare();before=self.snapshot();result=self.prove(ctx,entrypoint=True)
        self.assertEqual(result.returncode,0,result.stderr);value=json.loads(result.stdout)
        self.assertEqual(set(value),{'version','ok','result'});self.assertIs(value['ok'],True)
        self.assertEqual(value['result']['challenge'],'1'*64);self.assertEqual(len(value['result']),7)
        self.assertEqual(self.snapshot(),before)

    def test_audit_grant_partials_published_or_unknown_state_refuses_without_writes(self):
        ctx,key,_=self.prepare()
        for relative in ('tmp/controller/audit.jsonl','tmp/controller/grants/'+'f'*64+'.json',
            'data','tmp/commissioning','tmp/controller-authorization','tmp/controller-authorization.pending',
            'tmp/commission-prepare-interrupted','tmp/commission-observe-interrupted','config/node.json',
            'network/authority.json','keys/foreign','bad-custody','active-process','foreign-unit','evidence/upgrade-intent.json'):
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps({'operation':'commission','request_sha256':key,'time':1})+'\n' if relative.endswith('audit.jsonl') else '{}');path.chmod(0o600)
            before=self.snapshot();self.assertNotEqual(self.prove(ctx).returncode,0,relative);self.assertEqual(self.snapshot(),before);path.unlink()
        grant=self.control/'grants'/(key+'.json');original=grant.read_bytes()
        for field,value in [('authorization_sha256','0'*64),('authorization_sequence',10),('operation','start'),('expires_at',1001),('root','/foreign')]:
            bad=json.loads(original);bad[field]=value;grant.write_text(json.dumps(bad))
            before=self.snapshot();self.assertNotEqual(self.prove(ctx).returncode,0,field);self.assertEqual(self.snapshot(),before)
        grant.write_bytes(original);grant.chmod(0o644);self.assertNotEqual(self.prove(ctx).returncode,0);grant.chmod(0o600)
        grant.unlink();self.assertNotEqual(self.prove(ctx).returncode,0)
        grant.symlink_to(self.control/'policy.json');self.assertNotEqual(self.prove(ctx).returncode,0)

    def test_scope_expiry_challenge_payload_and_readiness_drift_refuses(self):
        ctx,_,_=self.prepare()
        for field,value in [('initial_sha256','0'*64),('authorization',{}),('target',{}),('selection',{}),
                            ('genesis_pins',{}),('formation_sha256','0'*64),('request_sha256','0'*64),('expires_at',1),('extra',True)]:
            bad=copy.deepcopy(ctx);bad[field]=value;self.assertNotEqual(self.prove(bad).returncode,0,field)
        self.assertNotEqual(self.prove(ctx,'bad').returncode,0)
        for relative in ('tmp/controller/authorization/inputs/commissioning-readiness.json',
                         'tmp/controller/authorization/inputs/commissioning/config/node.json',
                         'tmp/identity-network/genesis.json'):
            path=self.root/relative;raw=path.read_bytes();path.write_bytes(b'changed')
            before=self.snapshot();self.assertNotEqual(self.prove(ctx).returncode,0,relative);self.assertEqual(self.snapshot(),before);path.write_bytes(raw)

if __name__=='__main__':unittest.main()
