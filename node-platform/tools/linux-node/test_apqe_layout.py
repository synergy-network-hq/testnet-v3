"""Offline layout/refusal tests, not native provider or VPN qualification."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import apqe_layout as layout
import lifecycle
from test_lifecycle import package, save


class ApqeLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name).resolve()
        self.root=self.base/'synergy';self.root.mkdir(mode=0o700)
        (self.root/'tmp').mkdir(mode=0o700)
        self.stage=self.base/'staged';self.stage.mkdir(mode=0o700)
        self.software=self.base/'package';self.software.mkdir(mode=0o700)
        save(self.software/'lib/apqe/build-report.json',b'{}')
        for name in layout.INPUTS-{'config/node.json','config/start-authorized.json'}:
            save(self.stage/name,b'{}')
        save(self.stage/'keys/apqe/validator.pub.json',{'node_address':'synv1fixture'})
        save(self.stage/'network/authority.json',{'payload':{'validators':[{'record':{
            'validator_id':'synv1fixture','status':'active'}}]}})
        self.config={'node_name':'validator-fixture','chain_id':1266,'network_id':'fresh-incarnation',
            'public_identity_path':str(self.root/'keys/apqe/validator.pub.json'),
            'admin_socket_path':str(self.root/'run/admin.sock'),
            'storage':{'data_directory':str(self.root/'data')},
            'genesis_path':str(self.root/'network/genesis.json'),
            'manifest_path':str(self.root/'network/network-manifest.json'),
            'consensus':{'authority_binding':str(self.root/'network/authority.json'),
                'authority_trust_key_path':str(self.root/'network/authority-root.pub')},'etdag':{},
            'aegis_provider':{'report_path':str(self.root/'lib/apqe/build-report.json'),
                'authenticated_report_sha256':layout.digest(self.software/'lib/apqe/build-report.json')},
            'apqe_transport':{'profile':layout.PROFILE,
                'registry_path':str(self.root/'network/transport-registry.json'),
                'registry_trust_key_path':str(self.root/'network/transport-root.pub'),
                'registry_trust_key_sha256':layout.digest(self.stage/'network/transport-root.pub'),
                'genesis_trust_key_sha256':layout.digest(self.stage/'network/authority-root.pub'),
                'enrollment_path':str(self.root/'keys/apqe/enrollment.json'),
                'custody_path':str(self.root/'keys/apqe/custody.json'),
                'custody_unlock_path':str(self.root/'keys/apqe/unlock')}}
        save(self.stage/'config/node.json',self.config)
        layout.seal_commissioning(self.stage,self.root,all_validators_ready=True,all_pairs_vpn_verified=True)
    def tearDown(self):self.temp.cleanup()
    def test_layout_uses_opaque_custody_without_claiming_possession_or_production(self):
        result=layout.validate_layout(self.root,self.stage,self.software)
        self.assertFalse(result['native_possession_verified']);self.assertFalse(result['production_approved'])
    def test_raw_key_fallback_wrong_pin_and_wrong_profile_rejected(self):
        for mutate in [lambda c:c.update(aegis_signing_key_path='/old/secret.key'),
                       lambda c:c['apqe_transport'].update(profile='legacy'),
                       lambda c:c['apqe_transport'].update(registry_trust_key_sha256='0'*64)]:
            config=copy.deepcopy(self.config);mutate(config);save(self.stage/'config/node.json',config)
            with self.assertRaises(ValueError):layout.validate_layout(self.root,self.stage,self.software)
    def test_external_network_paths_refused_before_native_preflight(self):
        fields=[('genesis_path',),('manifest_path',),('consensus','authority_binding'),
                ('consensus','authority_trust_key_path')]
        for fields_path in fields:
            with self.subTest(field=fields_path):
                config=copy.deepcopy(self.config)
                target=config
                for field in fields_path[:-1]: target=target[field]
                target[fields_path[-1]]='/external/authenticated-but-unselected.json'
                save(self.stage/'config/node.json',config)
                with self.assertRaisesRegex(ValueError,'canonical authenticated network'):
                    layout.validate_layout(self.root,self.stage,self.software)

    def test_private_permissions_and_symlink_refused(self):
        private=self.stage/'keys/apqe/unlock';private.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'0600'):layout.validate_layout(self.root,self.stage,self.software)
        private.unlink();private.symlink_to(self.stage/'keys/apqe/custody.json')
        with self.assertRaises(ValueError):layout.validate_layout(self.root,self.stage,self.software)
    def test_native_public_preflight_required_before_any_application_removal(self):
        old=self.root/'data/old-chain';save(old,b'old chain must remain on refusal')
        with patch.object(lifecycle,'_require_operator'),patch.object(lifecycle,'verify_package',return_value={}),\
             patch.object(layout,'validate_stage',return_value=layout.read(self.stage/'commissioning.json')),\
             patch.object(lifecycle,'native',return_value=b'{"signed_genesis_verified":false}'):
            with self.assertRaisesRegex(ValueError,'native APQE public preflight'):
                lifecycle.replace_application(self.root,self.software,self.stage,str(self.root))
        self.assertEqual(old.read_bytes(),b'old chain must remain on refusal')
        self.assertFalse((self.root/'evidence/application-replacement-intent.json').exists())
    def test_exact_replace_authorization_required_before_package_or_stage_access(self):
        with patch.object(lifecycle,'_require_operator'),patch.object(lifecycle,'verify_package') as verify:
            with self.assertRaisesRegex(ValueError,'exact --replace-root'):
                lifecycle.replace_application(self.root,self.software,self.stage,'wrong root')
            verify.assert_not_called()
    def test_commission_check_authenticates_native_public_inputs_without_old_root_changes(self):
        old=self.root/'data/old-chain';save(old,b'untouched old chain')
        before={str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        def preflight(argv,**kwargs):
            config=layout.read(argv[-1])
            self.assertEqual(config['aegis_provider']['report_path'],str(self.software/'lib/apqe/build-report.json'))
            self.assertEqual(config['public_identity_path'],str(self.stage/'keys/apqe/validator.pub.json'))
            return json.dumps({'signed_genesis_verified':True,'signed_authority_verified':True,
                'validator_membership_verified':True,'production_approved':False}).encode()
        with patch.object(lifecycle,'_require_operator'),patch.object(lifecycle,'verify_package'),             patch.object(layout,'validate_stage',return_value=layout.read(self.stage/'commissioning.json')),             patch.object(lifecycle,'native',side_effect=preflight):
            result=lifecycle.commission_check(self.root,self.software,self.stage)
        self.assertTrue(result['commissioning_check_passed']);self.assertFalse(result['application_changed'])
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_sealing_never_infers_validator_or_vpn_readiness(self):
        with self.assertRaisesRegex(ValueError,'explicit completed'):
            layout.seal_commissioning(self.stage,self.root)

    def test_formation_commissioning_uses_only_verified_public_inputs_and_local_custody(self):
        public=self.root/'tmp/commissioning-public'
        pending=self.root/'tmp/pending-validator-custody'
        target=self.root/'tmp/commissioning'
        save(self.root/'lib/apqe/build-report.json',b'{}')
        for name in layout.FORMATION_PUBLIC_INPUTS:save(public/name,(self.stage/name).read_bytes())
        for source,destination in layout.BOUND_CUSTODY.items():
            save(pending/source,(self.stage/'keys/apqe'/destination).read_bytes())
        save(pending/'bundle/validator.pub.json',b'{}')
        pins={name:layout.digest(public/name) for name in layout.FORMATION_PUBLIC_INPUTS}
        with self.assertRaisesRegex(ValueError,'approved bytes'):
            layout.assemble_formation_stage(self.root,target,{**pins,'network/genesis.json':'a'*64})
        self.assertFalse(target.exists())
        save(public/'unlock',b'caller custody is forbidden')
        with self.assertRaisesRegex(ValueError,'must not contain custody'):
            layout.assemble_formation_stage(self.root,target,pins)
        (public/'unlock').unlink()
        layout.assemble_formation_stage(self.root,target,pins)
        self.assertEqual((target/'keys/apqe/custody.json').read_bytes(),(pending/'bundle/validator.enc.json').read_bytes())
        layout.assemble_formation_stage(self.root,target,pins)
        save(pending/'unlock',b'changed local unlock')
        with self.assertRaisesRegex(ValueError,'Existing commissioning stage differs'):
            layout.assemble_formation_stage(self.root,target,pins)


if __name__=='__main__':unittest.main()
