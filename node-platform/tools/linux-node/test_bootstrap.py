"""Archive rejection tests for the fixed native bootstrap; no host enrollment."""
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import bootstrap as b


class BootstrapTests(unittest.TestCase):
    def archive(self,change=None):
        roles=['validator']+[f'role-{i}' for i in range(19)]
        files={'roles/roles.json':json.dumps({'roles':roles}).encode()}
        files.update({'bin/'+name:b'authenticated binary fixture' for name in
                      ('synergy-node','synergy-keytool','synergy-genesis','netbird')})
        files.update({'tools/'+name:b'canonical engine' for name in b.ENGINE})
        manifest={'format':'synergy-universal-linux-v1','architecture':'x86_64','release_id':'qualified-test-only',
                  'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
        raw=json.dumps(manifest).encode()
        header={'manifest_sha256':hashlib.sha256(raw).hexdigest(),'release_id':manifest['release_id']}
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as tar:
            def add(name,value):
                info=tarfile.TarInfo(name);info.size=len(value);tar.addfile(info,io.BytesIO(value))
            add('package.json',raw)
            for name,value in files.items():add(name,value)
            if change:change(tar,add)
        data.seek(0)
        return data,header
    def test_valid_inventory_extracts_only_beneath_fresh_stage(self):
        data,header=self.archive()
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)/'synergy';stage.mkdir()
            result=b.extract(data,stage,header)
            self.assertEqual(result['release_id'],'qualified-test-only')
            self.assertEqual(len(list((stage/'roles').iterdir())),21)
    def test_verified_stage_prepares_private_binary_modes_only(self):
        data,header=self.archive()
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)
            manifest=b.extract(data,stage,header)
            node=stage/'bin/synergy-node'
            self.assertEqual(stat.S_IMODE(node.stat().st_mode),0o600)
            b.prepare_stage_executables(stage,manifest)
            b.prepare_stage_executables(stage,manifest)
            self.assertEqual(stat.S_IMODE(node.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((stage/'tools/controller.py').stat().st_mode),0o600)
            node.chmod(0o600)
            node.write_bytes(b'different binary')
            with self.assertRaisesRegex(ValueError,'changed after verification'):
                b.prepare_stage_executables(stage,manifest)
            self.assertEqual(stat.S_IMODE(node.stat().st_mode),0o600)
    def test_bad_manifest_pin_fails_before_payload_write(self):
        data,header=self.archive();header['manifest_sha256']='0'*64
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)
            with self.assertRaisesRegex(ValueError,'Manifest differs'):b.extract(data,stage,header)
            self.assertEqual(list(stage.iterdir()),[])
    def test_links_traversal_duplicates_and_undeclared_files_are_refused(self):
        def link(tar,add):
            info=tarfile.TarInfo('link');info.type=tarfile.SYMTYPE;info.linkname='/etc';tar.addfile(info)
        for change in (lambda tar,add:add('../escape',b'bad'),lambda tar,add:add('tools/controller.py',b'duplicate'),
                       lambda tar,add:add('unknown',b'bad'),link):
            data,header=self.archive(change)
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):b.extract(data,Path(temporary),header)
    def test_header_never_accepts_paths_commands_or_qualification_override(self):
        value={'version':1,'manifest_sha256':'0'*64,'release_id':'test','operator_public_key':'ssh-ed25519 '+'A'*68,
               'network_id':'isolated-test','chain_id':9,'node_name':'isolated'}
        self.assertEqual(b.public_header(json.dumps(value).encode()+b'\n'),value)
        for key in ('root','command','qualified_operations'):
            with self.assertRaises(ValueError):b.public_header(json.dumps(dict(value,**{key:'unsafe'})).encode()+b'\n')

    def test_bootstrap_refuses_installed_or_loaded_legacy_validator_units(self):
        scenarios = [
            ('synergy-node.service disabled disabled\n', None),
            ('synergy-vpn.service masked enabled\n', None),
            ('synergy-canary-old.service bad disabled\n', None),
            ('synergy-posy-old.service linked disabled\n', None),
            ('', 'synergy-posy-old.service loaded failed failed Old validator\n'),
        ]
        for installed, loaded in scenarios:
            with self.subTest(installed=installed, loaded=loaded):
                responses = [subprocess.CompletedProcess([], 0, stdout=installed)]
                if loaded is not None:
                    responses.append(subprocess.CompletedProcess([], 0, stdout=loaded))
                with patch.object(b.subprocess, 'run', side_effect=responses):
                    with self.assertRaisesRegex(ValueError, 'Legacy validator service'):
                        b.require_clean_service_namespace()

    def test_targeted_no_match_semantics_require_successful_manager_inventory(self):
        with patch.object(b.subprocess,'run',side_effect=[
                subprocess.CompletedProcess([],1,stdout='',stderr=''),
                subprocess.CompletedProcess([],0,stdout='',stderr='')]) as run:
            b.require_clean_service_namespace()
        self.assertEqual(run.call_count,2)
        for operation,call in zip(('list-unit-files','list-units'),run.call_args_list):
            self.assertEqual(call.args[0],['/usr/bin/systemctl',operation,'--all','--no-legend','--no-pager','--plain',*b.VALIDATOR_UNIT_PATTERNS])
            self.assertFalse(call.kwargs['check']);self.assertEqual(call.kwargs['timeout'],8)
        # Code 1 is not a generic success fallback. Any diagnostic, nonempty
        # output, different failure, or failed manager query must fail closed.
        cases=[(1,'','I/O error'),(1,'unexpected output',''),(2,'',''),
               (0,'','Failed to connect to bus'),(1,'\n','')]
        for status,stdout,stderr in cases:
            with self.subTest(status=status,stdout=stdout,stderr=stderr),patch.object(b.subprocess,'run',return_value=
                    subprocess.CompletedProcess([],status,stdout=stdout,stderr=stderr)):
                with self.assertRaisesRegex(ValueError,'Service inventory failed'):b.require_clean_service_namespace()
        with patch.object(b.subprocess,'run',side_effect=[
                subprocess.CompletedProcess([],1,stdout='',stderr=''),
                subprocess.CompletedProcess([],1,stdout='',stderr='')]):
            with self.assertRaisesRegex(ValueError,'Service inventory failed'):b.require_clean_service_namespace()
        with patch.object(b.subprocess,'run',side_effect=subprocess.TimeoutExpired('systemctl',8)):
            with self.assertRaises(subprocess.TimeoutExpired):b.require_clean_service_namespace()

    def test_mismatched_and_partial_filtered_inventory_never_proves_clean(self):
        for operation,output in [('list-unit-files','ssh.service enabled enabled\n'),
                ('list-unit-files','Failed to read inventory\n'),
                ('list-units','synergy-node.service not-found inactive\n')]:
            responses=[]
            if operation=='list-units':responses.append(subprocess.CompletedProcess([],0,stdout='',stderr=''))
            responses.append(subprocess.CompletedProcess([],0,stdout=output,stderr=''))
            with self.subTest(operation=operation,output=output),patch.object(b.subprocess,'run',side_effect=responses):
                with self.assertRaises(ValueError):b.require_clean_service_namespace()
        for stdout,stderr in [('x'*2_000_001,''),('','x'*65537)]:
            with patch.object(b.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=stdout,stderr=stderr)):
                with self.assertRaisesRegex(ValueError,'exceeds bound'):b.require_clean_service_namespace()

    def test_filtered_missing_validator_does_not_block_clean_bootstrap(self):
        detail=self.missing_unit_detail()
        with patch.object(b.subprocess, 'run', side_effect=[
            subprocess.CompletedProcess([], 0, stdout=''),
            subprocess.CompletedProcess([], 0, stdout='synergy-node.service not-found inactive dead\n'),
            subprocess.CompletedProcess([], 0, stdout=detail,stderr=''),
        ]):
            b.require_clean_service_namespace()

    @staticmethod
    def missing_unit_detail(**changes):
        values=dict(LoadState='not-found',ActiveState='inactive',SubState='dead',MainPID='0',ControlPID='0',
                    FragmentPath='',SourcePath='',DropInPaths='',UnitFileState='',Triggers='',TriggeredBy='',Job='')
        values.update(changes)
        return ''.join(f'{key}={value}\n' for key,value in values.items())

    def test_deleted_failed_unit_requires_independent_inert_state(self):
        def check(detail,status=0,stderr=''):
            with patch.object(b.subprocess,'run',side_effect=[
                    subprocess.CompletedProcess([],1,stdout='',stderr=''),
                    subprocess.CompletedProcess([],0,stdout='synergy-posy-old.service not-found failed failed Old validator\n',stderr=''),
                    subprocess.CompletedProcess([],status,stdout=detail,stderr=stderr)]):
                b.require_clean_service_namespace()
        check(self.missing_unit_detail(ActiveState='failed',SubState='failed'))
        for field,value in [('LoadState','loaded'),('ActiveState','active'),('SubState','auto-restart'),
                ('MainPID','2'),('ControlPID','3'),('FragmentPath','/etc/systemd/system/old.service'),
                ('SourcePath','/generated/old'),('DropInPaths','/etc/old.conf'),('UnitFileState','masked'),
                ('Triggers','other.service'),('TriggeredBy','old.timer'),('Job','1')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                check(self.missing_unit_detail(ActiveState='failed',SubState='failed',**{field:value})
                      if field not in ('ActiveState','SubState') else self.missing_unit_detail(**{field:value}))
        exact=self.missing_unit_detail(ActiveState='failed',SubState='failed')
        for detail,status,stderr in [(exact,1,''),(exact,0,'warning'),(exact+'MainPID=0\n',0,''),
                (exact.replace('Job=\n',''),0,''),(exact+'Unknown=\n',0,''),('x'*65537,0,'')]:
            with self.subTest(status=status,stderr=stderr),self.assertRaises(ValueError):check(detail,status,stderr)

if __name__=='__main__':unittest.main()
