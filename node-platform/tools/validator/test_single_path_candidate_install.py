import contextlib
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('single_path_activation',Path(__file__).with_name('activate-r3-stalled-fleet.py'))
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)

class CandidateInstallOrdering(unittest.TestCase):
    def fixture(self,fail_verify=None,blockers=None):
        calls=[];stopped=set();hosts=[]
        for number in range(2,7):
            hosts.append({'number':number,'host':f'synergy-val{number}','socket':f'/Users/jhutzler/.ssh/posy-val{number}-control',
                'expected':{'binary_sha3':'old','release_sha3':'old-release','unit_sha3':'unit','config_sha3':'config','trust_sha3':'trust','installed_sequence':19}})
        def remote(host,socket,action,request=None,data=None):
            number=int(host.removeprefix('synergy-val'));calls.append((number,action))
            if action=='probe':
                expected=next(h['expected'] for h in hosts if h['number']==number)
                return {'snapshot':dict(expected,service={'MainPID':'0' if number in stopped else str(number),'ActiveState':'inactive' if number in stopped else 'active'},processes=[] if number in stopped else [{'pid':number}],boot_id='boot'), 'cleanup_inventory':{'historical_binaries':[]}}
            if action=='stop':stopped.add(number);return {'config_sha3':'config','unit_sha3':'unit','boot_id':'boot'}
            if action=='replace':
                self.assertEqual(stopped,set(range(2,7)));self.assertIn(request['kind'],('binary','release'))
                return {'qualified':False}
            if action=='verify':
                self.assertEqual(request['installed_sequence'],19,
                    'sequence20 candidate must be verified against floor19')
                if number==fail_verify:raise RuntimeError('native verification failed')
                return {'native_release_verified':True,'binary_sha3':'candidate'}
            if action=='start':
                self.assertEqual({n for n,a in calls if a=='verify'},set(range(2,7)))
                return {'candidate_installed':True,'qualified':False}
            if action=='fail_stop':stopped.add(number);return {'stopped':True}
            raise AssertionError(action)
        plan={'artifact':{'sha3_256':'candidate','length':3},'local_trust_sha3_256':'trust','installed_sequence':19}
        return calls,plan,hosts,SimpleNamespace(single_path_remote=remote),blockers or []

    def invoke(self,fixture,execute=True):
        calls,plan,hosts,owner,blockers=fixture
        envelope=b'{"release":{"sequence":20}}'
        with patch.object(MODULE,'bounded_document',return_value=json.dumps(plan).encode()),patch.object(MODULE,'validate_single_path_plan',return_value=(b'ELF',envelope,hosts,blockers)),patch.object(MODULE,'load_module',return_value=owner),contextlib.redirect_stdout(io.StringIO()):
            MODULE.single_path_install(Path('/plan'),execute)
        return calls

    def test_all_five_stop_before_any_replace_and_verify_before_any_start(self):
        calls=self.invoke(self.fixture())
        first_replace=next(i for i,(_,action) in enumerate(calls) if action=='replace')
        self.assertEqual({n for n,a in calls[:first_replace] if a=='stop'},set(range(2,7)))
        first_start=next(i for i,(_,action) in enumerate(calls) if action=='start')
        self.assertEqual({n for n,a in calls[:first_start] if a=='verify'},set(range(2,7)))

    def test_one_native_verification_failure_stops_all_and_never_starts(self):
        fixture=self.fixture(fail_verify=4)
        with self.assertRaisesRegex(RuntimeError,'native verification failed'):self.invoke(fixture)
        calls=fixture[0]
        self.assertFalse(any(action=='start' for _,action in calls))
        self.assertEqual({n for n,a in calls if a=='fail_stop'},set(range(2,7)))

    def test_missing_approval_blocks_before_any_host_mutation(self):
        fixture=self.fixture(blockers=['protocol_activation_approved'])
        with self.assertRaisesRegex(RuntimeError,'blocked'):self.invoke(fixture)
        self.assertTrue(all(action=='probe' for _,action in fixture[0]))

    def test_dry_run_only_reads_inventory(self):
        calls=self.invoke(self.fixture(),execute=False)
        self.assertEqual([a for _,a in calls],['probe']*5)


class CandidatePlanValidation(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(dir='/Users/jhutzler/Library/Caches')
        self.addCleanup(temporary.cleanup)
        directory=temporary.name
        root=Path(directory)/'Synergy-PoSy-qualification-target'
        binary=root/'x86_64-unknown-linux-gnu/release/synergy-node'
        binary.parent.mkdir(parents=True)
        binary_bytes=b'\x7fELF\x02\x01\x01'+b'\0'*11+b'\x3e\0'+b'candidate'
        binary.write_bytes(binary_bytes)
        artifact={'sha3_256':hashlib.sha3_256(binary_bytes).hexdigest(),'length':len(binary_bytes)}
        provenance=root/'evidence/build-provenance.json';provenance.parent.mkdir()
        provenance.write_text(json.dumps({'format_version':1,'before':{'revision':'x'},'after':{'revision':'x'},'artifact':artifact,'target':'x86_64-unknown-linux-gnu'}))
        release=root/'evidence/release.json'
        activation='approved-binding'
        release.write_text(json.dumps({'release':{'artifact':dict(artifact,platform='x86_64-unknown-linux-gnu'),'sequence':20,'protocol_activation_commitment':activation}}))
        native=Path(directory)/'native-keytool';native.write_bytes(b'\xcf\xfa\xed\xfe\x0c\0\0\x01'+b'native')
        trust=Path(directory)/'authority-root.pub';trust.write_bytes(b'public')
        approval=Path(directory)/'approval.txt';approval.write_text('approved')
        sockets={f'synergy-val{number}':f'/tmp/master-{number}' for number in range(2,7)}
        expected={'binary_sha3':'old','release_sha3':'old-release','unit_sha3':'unit','config_sha3':'config','trust_sha3':hashlib.sha3_256(trust.read_bytes()).hexdigest(),'installed_sequence':19}
        plan={'schema':'posy-single-path-install-v1','binary_path':str(binary),'artifact':artifact,
              'provenance_path':str(provenance),'provenance_sha3_256':hashlib.sha3_256(provenance.read_bytes()).hexdigest(),
              'signed_release_path':str(release),'signed_release_sha3_256':hashlib.sha3_256(release.read_bytes()).hexdigest(),
              'protocol_activation_commitment':activation,'installed_sequence':19,
              'hosts':[{'number':number,'host':f'synergy-val{number}','socket':sockets[f'synergy-val{number}'],'expected':dict(expected)} for number in range(2,7)],
              'native_keytool_path':str(native),'native_keytool_sha3_256':hashlib.sha3_256(native.read_bytes()).hexdigest(),
              'local_trust_key_path':str(trust),'local_trust_sha3_256':expected['trust_sha3'],
              'approval_evidence':{'path':str(approval),'sha256':hashlib.sha256(approval.read_bytes()).hexdigest()}}
        return root,native,sockets,plan

    def validate(self,root,native,sockets,plan):
        with patch.object(MODULE,'APFS_CANDIDATE_ROOT',root),patch.object(MODULE,'NATIVE_MAC_KEYTOOL',native),patch.object(MODULE,'configured_master_socket',side_effect=lambda host:sockets[host]),patch.object(MODULE.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')):
            return MODULE.validate_single_path_plan(plan)

    def test_accepts_apfs_candidate_and_native_macos_verifier(self):
        root,native,sockets,plan=self.fixture()
        binary,envelope,hosts,blockers=self.validate(root,native,sockets,plan)
        self.assertEqual(binary,Path(plan['binary_path']).read_bytes())
        self.assertEqual(envelope,Path(plan['signed_release_path']).read_bytes())
        self.assertEqual([host['number'] for host in hosts],list(range(2,7)))
        self.assertEqual(blockers,['operator_candidate_install_approved','protocol_activation_approved','source_review_approved'])

    def test_rejects_non_apfs_candidate_and_linux_local_verifier(self):
        root,native,sockets,plan=self.fixture()
        plan['binary_path']=str(Path(__file__).resolve())
        with self.assertRaisesRegex(RuntimeError,'approved APFS candidate artifact path'):
            self.validate(root,native,sockets,plan)
        root,native,sockets,plan=self.fixture()
        linux=Path(str(native)+'-linux');linux.write_bytes(b'\x7fELF\x02\x01\x01'+b'\0'*32)
        plan['native_keytool_path']=str(linux)
        with self.assertRaisesRegex(RuntimeError,'canonical native macOS keytool'):
            self.validate(root,native,sockets,plan)

    def test_rejects_socket_that_is_not_the_existing_configured_master(self):
        root,native,sockets,plan=self.fixture()
        plan['hosts'][0]['socket']='/tmp/not-the-configured-master'
        with self.assertRaisesRegex(RuntimeError,'existing canonical host/master bindings'):
            self.validate(root,native,sockets,plan)

class ExecutableStartTransition(unittest.TestCase):
    def owner(self,process_samples):
        spec=importlib.util.spec_from_file_location('start_owner',Path(__file__).with_name('provision-stability-hosts.py'))
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        definition=next(node for node in ast.parse(owner.SINGLE_PATH_REMOTE).body
                        if isinstance(node,ast.FunctionDef) and node.name=='started_snapshot')
        now=[0.0];samples=iter(process_samples);last=[[]];sleeps=[]
        def processes():
            last[0]=next(samples,last[0]);return last[0]
        def sleep(seconds):
            now[0]+=seconds;sleeps.append(seconds)
        environment={'service':lambda:{'MainPID':'42','ActiveState':'active'},
                     'processes':processes,'snapshot':lambda:{'validated':True},
                     'time':SimpleNamespace(monotonic=lambda:now[0],sleep=sleep)}
        exec(compile(ast.Module(body=[definition],type_ignores=[]),'<start-boundary>','exec'),environment)
        return environment['started_snapshot'],sleeps

    def test_systemd_child_must_become_the_sole_validator_before_acceptance(self):
        start,sleeps=self.owner([[],[],[{'pid':42}]])
        self.assertEqual(start(),{'validated':True})
        self.assertEqual(len(sleeps),2)

    def test_duplicate_or_other_validator_is_never_treated_as_exec_delay(self):
        for sample in ([{'pid':42},{'pid':43}],[{'pid':43}]):
            start,sleeps=self.owner([sample])
            with self.assertRaisesRegex(ValueError,'parallel'):start()
            self.assertEqual(sleeps,[])

    def test_missing_executable_times_out_without_acceptance(self):
        start,_=self.owner([[]])
        with self.assertRaisesRegex(ValueError,'did not appear'):start()

if __name__=='__main__':unittest.main()
