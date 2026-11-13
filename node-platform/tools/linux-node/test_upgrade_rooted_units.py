"""Recorded regular-unit migration and exact disjoint-service policy regressions."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import lifecycle as life
import conformance as conf
from test_lifecycle import LifecycleTests,save


class RootedUpgradeTests(LifecycleTests):
    def test_upgrade_converts_recorded_regular_units_without_stopping_vpn(self):
        self.register_fixture()
        with patch.object(life,'_unit_state',side_effect=self.state), self.upgrade_context():
            result=life.upgrade(self.root,self.candidate)
        for name,text in life.rendered_units(self.root).items():
            path=self.units/name
            self.assertTrue(path.is_symlink());self.assertEqual(path.readlink(),self.root/'systemd'/name)
            self.assertEqual((self.root/'systemd'/name).read_text(),text)
        self.assertFalse(result['vpn_stopped'])
        self.assertFalse(any(v[:2]==['systemctl','stop'] for v in self.operations))

    def test_interrupted_link_publication_retries_same_package_intent(self):
        self.register_fixture();real=os.replace
        def interrupt(source,target):
            if str(source).endswith('.synergy-registration-'+node_pin(self.candidate)[:16]):
                raise OSError('interrupted unit publication')
            return real(source,target)
        with patch.object(life,'_unit_state',side_effect=self.state),self.upgrade_context():
            with patch.object(os,'replace',side_effect=interrupt):
                with self.assertRaisesRegex(OSError,'interrupted unit'):life.upgrade(self.root,self.candidate)
            self.assertTrue((self.root/life.UPGRADE_INTENT).exists())
            self.assertFalse((self.units/life.UNITS[0]).is_symlink())
            life.upgrade(self.root,self.candidate)
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
        self.assertTrue((self.units/life.UNITS[0]).is_symlink())

    def test_preupgrade_legacy_requires_exact_recorded_ownership_final_requires_links(self):
        self.register_fixture();name=life.UNITS[0];text=life.rendered_units(self.root)[name]
        with patch.object(conf,'SERVICE_DIRECTORY',self.units):
            self.assertEqual(conf.verify_registered_unit(self.root,name,'future release unit',True),text)
            with self.assertRaisesRegex(ValueError,'canonical rooted'):conf.verify_registered_unit(self.root,name,text)
            save(self.units/name,b'foreign-unit')
            with self.assertRaisesRegex(ValueError,'recorded ownership'):conf.verify_registered_unit(self.root,name,text,True)

    def test_migration_rejects_foreign_rooted_target_and_override(self):
        self.register_fixture();name=life.UNITS[0];text=life.rendered_units(self.root)[name]
        save(self.root/'systemd'/name,b'foreign-rooted-unit')
        with self.assertRaisesRegex(ValueError,'unattributed unit'):
            life._root_registered_unit(self.root,name,text,'a'*64,{life.digest(self.units/name)})
        self.assertFalse((self.units/name).is_symlink())


def node_pin(path):return hashlib.sha256((path/'package.json').read_bytes()).hexdigest()


class DisjointServiceTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name).resolve();self.root=self.base/'synergy';self.root.mkdir()
        self.units=self.base/'etc/systemd/system';self.units.mkdir(parents=True)
        self.external=self.base/'external';self.external.mkdir()
        self.name='synergy-chain1266-rpc-tunnel.service'
        self.fragment=self.units/self.name;save(self.fragment,b'reviewed-disjoint-fragment')
        self.expected={self.name:(conf.digest(self.fragment),(str(self.external),))}
        self.response='FragmentPath='+str(self.fragment)+'\nDropInPaths=\nExecStart={ path='+str(self.external/'ssh')+' ; argv[]='+str(self.external/'ssh')+' ; start_time=[n/a] ; }\nEnvironmentFiles='+str(self.external/'runtime.env')+' (ignore_errors=no)\n'
        p=patch.object(conf,'SERVICE_DIRECTORY',self.units);p.start();self.addCleanup(p.stop)
        p=patch.object(conf,'EXTERNAL_UNITS',self.expected);p.start();self.addCleanup(p.stop)
        p=patch.object(conf.subprocess,'run',side_effect=self.fake_run);p.start();self.addCleanup(p.stop)

    def fake_run(self,args,**kwargs):return subprocess.CompletedProcess(args,0,stdout=self.response,stderr='')

    def test_reviewed_disjoint_unit_and_environment_paths_are_preserved_unread(self):
        # Environment file intentionally does not exist: verification must not open it.
        before=self.fragment.read_bytes();conf.verify_external_services(self.root,{self.name})
        self.assertEqual(self.fragment.read_bytes(),before)
        self.assertFalse((self.external/'runtime.env').exists())

    def test_unknown_modified_or_overlapping_unit_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'undeclared'):conf.verify_external_services(self.root,{'synergy-unknown.service'})
        save(self.fragment,b'changed-fragment')
        with self.assertRaisesRegex(ValueError,'fragment differs'):conf.verify_external_services(self.root,{self.name})
        save(self.fragment,b'reviewed-disjoint-fragment')
        self.response+='WorkingDirectory='+str(self.root)+'\n'
        with self.assertRaisesRegex(ValueError,'references Canary'):conf.verify_external_services(self.root,{self.name})

    def test_override_or_disjoint_symlink_back_into_canary_is_rejected(self):
        self.response=self.response.replace('DropInPaths=\n','DropInPaths=/etc/override.conf\n')
        with self.assertRaisesRegex(ValueError,'ownership or override'):conf.verify_external_services(self.root,{self.name})
        self.response=self.response.replace('DropInPaths=/etc/override.conf\n','DropInPaths=\n')
        (self.external/'ssh').symlink_to(self.root/'bin/synergy-node')
        with self.assertRaisesRegex(ValueError,'overlaps'):conf.verify_external_services(self.root,{self.name})


if __name__=='__main__':unittest.main()
