"""Exercise the two-file gateway transaction without changing any live service."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import rotate_gateway_admission as rotation
from rotate_transport import json_bytes, sha

class GatewayRotationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.root = base/'synergy'
        self.stage = base/'stage'
        self.stage.mkdir()
        self.pin_key = sha(b'trust-root')
        self.net = 'test-canary'
        self.receipt = {'role':'rpc_gateway','gateway_commissioned':True,'chain_id':99999,
                        'network_id':self.net,'package_sha256':'b'*64}
        self.old = self.artifacts(2)
        self.new = self.artifacts(3)
        for name, raw in self.old.items(): self.write(self.root/name,raw)
        self.write(self.root/'network/transport-root.pub',b'trust-root')
        self.write(self.root/'config/node.json',json_bytes({'apqe_transport':{
            'registry_trust_key_path':str(self.root/'network/transport-root.pub'),
            'registry_trust_key_sha256':self.pin_key}}))
        self.pin = self.stage_plan(self.new)
        for name, value in (('_require_operator',None),('_reject_installation_mounts',None),
                            ('_sealed_receipt',(self.receipt,{})),('preflight',None),('native',b'')):
            p = patch.object(rotation,name,return_value=value)
            setattr(self,name,p.start());self.addCleanup(p.stop)
        p = patch.object(rotation,'stopped');self.stopped=p.start();self.addCleanup(p.stop)

    def write(self,path,raw):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)

    def artifacts(self,generation,validators=('same',),gateways=('same-gateway',)):
        common = {'chain_id':99999,'network_id':self.net,'generation':generation,
                  'valid_from_unix':generation,'expires_at_unix':generation+50}
        registry = json_bytes({'payload':dict(common,validators=list(validators))})
        admission = json_bytes({'payload':dict(common,gateways=list(gateways),validator_registry_sha256=sha(registry))})
        return {rotation.REGISTRY:registry,rotation.ADMISSION:admission}

    def stage_plan(self,new,from_generation=2,to_generation=3):
        p = {'format':rotation.FORMAT,'package_sha256':self.receipt['package_sha256'],
             'network_id':self.net,'from_generation':from_generation,'to_generation':to_generation,
             'root_sha256':self.pin_key,'before':{k:sha(v) for k,v in self.old.items()},
             'after':{k:sha(v) for k,v in new.items()}}
        for name,raw in new.items(): self.write(self.stage/Path(name).name,raw)
        raw = json_bytes(p)
        self.write(self.stage/'gateway-rotation.json',raw)
        return sha(raw)

    def test_check_no_writes_apply_then_idempotent(self):
        self.assertFalse(rotation.rotate(self.root,self.stage,self.pin,False)['rotation_installed'])
        self.stopped.assert_not_called()
        self.assertTrue(rotation.rotate(self.root,self.stage,self.pin,True)['rotation_installed'])
        self.assertFalse((self.root/rotation.UPGRADE_INTENT).exists())
        self.assertTrue(rotation.rotate(self.root,self.stage,self.pin,True)['rotation_installed'])
        self.stopped.assert_called_once()
        self.native.assert_called_once()

    def test_interrupted_exact_intent_resume_and_foreign_refused(self):
        real_replace = rotation._replace_bytes
        def fail_second(root,path,*args):
            if path == root/rotation.ADMISSION: raise OSError('interrupted')
            return real_replace(root,path,*args)
        with patch.object(rotation,'_replace_bytes',side_effect=fail_second):
            with self.assertRaisesRegex(OSError,'interrupted'):rotation.rotate(self.root,self.stage,self.pin,True)
        self.assertEqual((self.root/rotation.REGISTRY).read_bytes(),self.new[rotation.REGISTRY])
        self.assertEqual((self.root/rotation.ADMISSION).read_bytes(),self.old[rotation.ADMISSION])
        wrong = self.stage_plan(self.artifacts(3,gateways=('other',)))
        with self.assertRaisesRegex(ValueError,'original exact'):rotation.rotate(self.root,self.stage,wrong,True)
        self.pin=self.stage_plan(self.new)
        self.assertTrue(rotation.rotate(self.root,self.stage,self.pin,True)['rotation_installed'])

    def test_rejects_rollback_membership_and_gateway_key_changes(self):
        tests = [(self.artifacts(1),2,1,'strict forward'),
                 (self.artifacts(3,validators=('other',)),2,3,'validator membership'),
                 (self.artifacts(3,gateways=('other',)),2,3,'gateway identities')]
        for new,old_generation,new_generation,message in tests:
            pin = self.stage_plan(new,old_generation,new_generation)
            with self.assertRaisesRegex(ValueError,message):rotation.rotate(self.root,self.stage,pin,True)
        self.preflight.assert_not_called()

    def test_failed_native_preflight_or_running_relay_preserves_files(self):
        self.preflight.side_effect=ValueError('bad signature')
        with self.assertRaisesRegex(ValueError,'bad signature'):rotation.rotate(self.root,self.stage,self.pin,True)
        self.preflight.side_effect=None
        self.stopped.side_effect=ValueError('relay active')
        with self.assertRaisesRegex(ValueError,'relay active'):rotation.rotate(self.root,self.stage,self.pin,True)
        self.assertFalse((self.root/rotation.UPGRADE_INTENT).exists())
        self.assertEqual((self.root/rotation.REGISTRY).read_bytes(),self.old[rotation.REGISTRY])

if __name__ == '__main__': unittest.main()
