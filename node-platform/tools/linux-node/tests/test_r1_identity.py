import contextlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import controller
import r1_identity


def parameters():
    return dict(release_id='PUBLIC-TEST',manifest_sha256='01'*32,slot_ref='PUBLIC-ROOT-SLOT-1',
        role='root',algorithm='ML-DSA-87',key_generation='1',operation_nonce_hex='02'*32,
        creation_scope_frame_hex='80',creation_scope_commitment_hex='03'*64,
        provider_report_sha256='04'*32,profile_catalog_commitment_hex='05'*64)


class R1NativeBoundary(unittest.TestCase):
    def test_consumed_receipt_directory_is_attributed_without_accepting_foreign_files(self):
        with tempfile.TemporaryDirectory(prefix='synergy-public-receipt-inventory-') as tmp:
            c=controller.Controller(Path(tmp));directory=c.control/'r1-creation'
            directory.mkdir(mode=0o700,parents=True)
            self.assertEqual(r1_identity.controller_inventory(c),(set(),{'tmp/controller/r1-creation'}))
            (directory/'foreign.txt').write_text('PUBLIC TEST ONLY')
            with self.assertRaises(controller.Refused):r1_identity.controller_inventory(c)
    def test_status_observes_original_request_without_new_grant_or_dispatch(self):
        p={'slot_ref':'PUBLIC-ROOT-SLOT-1','original_request_sha256':'01'*32}
        request={'version':1,'operation':'r1_identity_status','parameters':p}
        self.assertEqual(controller.parse_request(json.dumps(request).encode()),request)
        result={'schema':'synergy-r1-managed-key-status-v1','stage':'absent',**p,'runtime_authority_granted':False}
        c=controller.Controller(Path('/PUBLIC-NONPRODUCTION-NOT-INSTALLED'))
        with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt'),patch.object(c,'authorize') as authorize,patch('synergy_linux.native',return_value=json.dumps(result).encode()) as native:
            self.assertEqual(r1_identity.status(c,request),result)
            authorize.assert_not_called();native.assert_called_once()
    def test_closed_request_preserves_full_width_pins_and_exact_generation(self):
        p=parameters();r1_identity.validate(p)
        request=dict(version=1,operation='r1_identity_generate',parameters=p)
        self.assertEqual(controller.parse_request(json.dumps(request).encode()),request)
        for key,value in [('key_generation',1),('key_generation','01'),('algorithm','FN-DSA-1024'),
            ('creation_scope_commitment_hex','03'*32),('provider_report_sha256','04'*64),
            ('operation_nonce_hex','00'*32),('creation_scope_frame_hex','AA')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                r1_identity.validate({**p,key:value})
        with self.assertRaises(ValueError):r1_identity.validate({**p,'authorized':True})
        with self.assertRaises(controller.Refused):controller.parse_request(json.dumps({**request,'parameters':{'genesis_sha256':'01'*32}}).encode())

    def test_missing_native_grant_cannot_dispatch_or_write_receipt(self):
        p=parameters();request=dict(version=1,operation='r1_identity_generate',parameters=p)
        with tempfile.TemporaryDirectory(prefix='synergy-public-controller-test-') as tmp:
            c=controller.Controller(Path(tmp));manifest={'release_id':p['release_id'],'files':{'lib/apqe/build-report.json':p['provider_report_sha256'],'lib/apqe/r1-profile-catalog.cbor':'06'*32}}
            with patch('lifecycle._lifecycle_lock',return_value=contextlib.nullcontext()),patch('lifecycle._sealed_receipt',return_value=({'package_sha256':p['manifest_sha256']},manifest)),patch.object(c,'public_json',return_value={'expires_at':1}),patch.object(c,'authorize',side_effect=controller.Refused('authorization_required','missing exact native grant')) as authorize,patch('synergy_linux.native') as native:
                with self.assertRaises(controller.Refused):r1_identity.run(c,request)
                authorize.assert_called_once_with(request);native.assert_not_called()
            self.assertFalse((c.control/'r1-creation').exists())


if __name__=='__main__':unittest.main()
