import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import provision_validator_relay as relay
from rotate_transport import json_bytes, sha


class ValidatorRelayProvisionTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        base=Path(tmp.name).resolve();self.root=base/'synergy'
        for name in ('network','evidence','config'):(self.root/name).mkdir(parents=True,exist_ok=True)
        self.spec=base/'spec'; self.admission=base/'admission'
        self.spec.write_bytes(b'{}');self.admission.write_bytes(b'{"signed":true}')
        self.result={'admission_path':str(self.root/relay.ADMISSION),'role':{'kind':'validator'}}
        for name,value in (('_require_operator',None),('_sealed_receipt',({'package_sha256':'a'*64},{})),
                           ('_attributed_units',{}),('validate',self.result)):
            p=patch.object(relay,name,return_value=value);p.start();self.addCleanup(p.stop)

    def invoke(self):
        return relay.install(self.root,self.spec,sha(self.spec.read_bytes()),self.admission,
                             sha(self.admission.read_bytes()),'a'*64)

    def configure(self,args):
        if 'configure' in args:
            target=self.root/relay.CONFIG
            target.write_bytes(json_bytes(self.result));target.chmod(0o600)
        return b''

    def test_staged_preflight_before_publication_and_idempotent(self):
        calls=[]
        def native(args):
            calls.append(args)
            if len(calls)==1:
                self.assertFalse((self.root/relay.ADMISSION).exists())
                self.assertNotEqual(json.loads(args[-1].read_bytes())['admission_path'],self.result['admission_path'])
            return self.configure(args)
        with patch.object(relay,'native',side_effect=native):
            self.assertFalse(self.invoke()['already_configured'])
            self.assertTrue(self.invoke()['already_configured'])
        self.assertEqual(sum('configure' in a for a in calls),1)
        self.assertFalse(any('start' in a or 'register' in a for a in calls))

    def test_failed_preflight_does_not_install(self):
        with patch.object(relay,'native',side_effect=ValueError('bad signature')):
            with self.assertRaisesRegex(ValueError,'bad signature'):self.invoke()
        self.assertFalse((self.root/relay.ADMISSION).exists())

    def test_interrupted_configure_resumes_only_identical_admission(self):
        def fail(args):
            if 'configure' in args:raise OSError('interrupted')
            return b''
        with patch.object(relay,'native',side_effect=fail):
            with self.assertRaisesRegex(OSError,'interrupted'):self.invoke()
        self.assertEqual((self.root/relay.ADMISSION).read_bytes(),self.admission.read_bytes())
        with patch.object(relay,'native',side_effect=self.configure):
            self.assertTrue(self.invoke()['configured'])
            self.admission.write_bytes(b'{"different":true}')
            with self.assertRaisesRegex(ValueError,'existing admission differs'):self.invoke()


if __name__=='__main__':unittest.main()
