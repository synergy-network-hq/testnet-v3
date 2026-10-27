"""Isolated lifecycle durability tests. No host service mutations or node boot."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import lifecycle as life
import synergy_linux as node


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data,sort_keys=True,indent=2).encode()+b'\n')
    path.chmod(0o600)


def package(path, version):
    files={'bin/synergy-node':b'native-'+version.encode(), 'tools/lifecycle.py':b'policy-'+version.encode(),
           'assets/node-config.schema.json':b'{}', 'README.md':b'public-'+version.encode()}
    for name,data in files.items():
        save(path/name,data)
        if Path(name).parent.name in ('bin','tools'): (path/name).chmod(0o700)
    manifest={'format':node.MARKER,'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    save(path/'package.json',manifest)
    return manifest


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.base=Path(self.temp.name).resolve()
        self.root=self.base/'Synergy'; self.root.mkdir(mode=0o700)
        self.old=package(self.root,'old')
        self.receipt={'format':node.MARKER,'root':str(self.root),'package_sha256':node.digest(self.root/'package.json'),'package_files':self.old['files']}
        save(self.root/'installation.json',self.receipt)
        (self.root/'evidence').mkdir(mode=0o700)
        self.candidate=self.base/'candidate'; self.candidate.mkdir(mode=0o700)
        self.new=package(self.candidate,'new')
        self.units=self.base/'etc/systemd/system';self.units.mkdir(parents=True)
        self.operations=[]
        self.stack=[]
        for target,kwargs in [(life,{'_require_operator':lambda **kw:None,'UNIT_DIRECTORY':self.units}),]:
            self.stack.append(patch.multiple(target,**kwargs));self.stack[-1].start()
        self.stack.append(patch.object(life,'native',side_effect=self.native));self.stack[-1].start()
    def tearDown(self):
        for patcher in reversed(self.stack): patcher.stop()
        self.temp.cleanup()
    def native(self,args,**kwargs):
        self.operations.append([str(x) for x in args])
        if 'render-units' in args: return json.dumps({'units':life.rendered_units(self.root),'wrapper':life.wrapper_text(self.root)}).encode()
        return b'{}'
    def state(self,unit):
        return {'LoadState':'loaded','FragmentPath':str(self.units/unit),'DropInPaths':'','MainPID':'0','ActiveState':'inactive'}
    def register_fixture(self):
        contents=life.rendered_units(self.root)
        for name,text in contents.items(): save(self.units/name,text.encode());(self.units/name).chmod(0o644)
        plan={'root':str(self.root),'paths':[str(self.units/name) for name in life.UNITS],
              'sha256':{str(self.units/name):node.digest(self.units/name) for name in life.UNITS}}
        save(self.root/'evidence/host-integrations.json',plan)
        save(self.root/'tools/netbird-client',life.wrapper_text(self.root).encode());(self.root/'tools/netbird-client').chmod(0o700)
        return plan
    def upgrade_context(self):
        import contextlib
        stack=contextlib.ExitStack()
        stack.enter_context(patch.object(life,'verify_package',return_value=self.new))
        stack.enter_context(patch('conformance.installed',return_value={'conformant':True}))
        stack.enter_context(patch.object(life,'_fresh_conformance',return_value={'conformant':True}))
        stack.enter_context(patch.object(life,'_assert_no_application_processes'))
        return stack
    def test_foreign_vendor_missing_fragment_rejects_all_mutation(self):
        self.register_fixture();(self.units/life.UNITS[0]).unlink()
        foreign={'LoadState':'loaded','FragmentPath':'/usr/lib/systemd/system/synergy-node.service','MainPID':'81','ActiveState':'active'}
        with patch.object(life,'_unit_state',return_value=foreign):
            with self.assertRaisesRegex(ValueError,'foreign replacement'): life.mutate_owned_service(self.root,'stop',life.UNITS[0])
            with self.upgrade_context():
                with self.assertRaisesRegex(ValueError,'foreign replacement'): life.upgrade(self.root,self.candidate)
        self.assertEqual(self.operations,[])
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
    def test_dropin_or_fragment_drift_rejects_service_control(self):
        self.register_fixture()
        for changes in ({'DropInPaths':'/etc/foreign.conf'},{'FragmentPath':'/tmp/foreign.service'}):
            with patch.object(life,'_unit_state',side_effect=lambda unit:dict(self.state(unit),**changes)):
                with self.assertRaises(ValueError):life.mutate_owned_service(self.root,'stop',life.UNITS[0])
        self.assertEqual(self.operations,[])
        with patch.object(life,'_unit_state',side_effect=self.state):life.mutate_owned_service(self.root,'stop',life.UNITS[0])
        self.assertEqual(self.operations,[['systemctl','stop',life.UNITS[0]]])
    def test_unregistered_upgrade_preserves_runtime_bytes_inodes_and_has_no_global_actions(self):
        for name in ('keys/root/private.secret.key','data/history','config/node.json','vpn/default.json'):
            save(self.root/name,b'custody-state-configuration')
        before={name:((self.root/name).stat().st_ino,(self.root/name).read_bytes()) for name in ('keys/root/private.secret.key','data/history','config/node.json','vpn/default.json')}
        with self.upgrade_context(): result=life.upgrade(self.root,self.candidate)
        self.assertFalse(result['vpn_stopped']);self.assertFalse(result['consensus_started'])
        self.assertEqual(self.operations,[])
        for name,expected in before.items():self.assertEqual(((self.root/name).stat().st_ino,(self.root/name).read_bytes()),expected)
        self.assertEqual(node.read(self.root/'package.json'),self.new)
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
    def test_durable_intent_resume_at_each_commit_boundary(self):
        # Fail after actual atomic file replacement, then retry the exact package.
        original=life._replace_bytes
        for boundary in ('bin/synergy-node','package.json','installation.json'):
            with self.subTest(boundary=boundary):
                # Reset only this isolated software fixture and receipts.
                package(self.root,'old');save(self.root/'installation.json',self.receipt)
                (self.root/life.UPGRADE_COMPLETED).unlink(missing_ok=True)
                def fail(root,path,data,mode,token):
                    original(root,path,data,mode,token)
                    if path == root/boundary: raise SystemExit(91)
                with self.upgrade_context(),patch.object(life,'_replace_bytes',side_effect=fail):
                    with self.assertRaises(SystemExit):life.upgrade(self.root,self.candidate)
                self.assertTrue((self.root/life.UPGRADE_INTENT).exists())
                with self.upgrade_context():result=life.upgrade(self.root,self.candidate)
                self.assertTrue(result['resumed']);self.assertFalse((self.root/life.UPGRADE_INTENT).exists())
                for name,value in self.new['files'].items():self.assertEqual(node.digest(self.root/name),value)
    def test_actual_child_exit_resumes_durable_upgrade(self):
        source=Path(life.__file__).resolve().parent
        code="""import sys,os,json
from pathlib import Path
sys.path.insert(0,sys.argv[1]);import lifecycle as life;import conformance
root=Path(sys.argv[2]);candidate=Path(sys.argv[3])
life._require_operator=lambda:None
life.verify_package=lambda path:json.loads((path/'package.json').read_text())
life._assert_no_application_processes=lambda *a,**k:None
conformance.installed=lambda *a,**k:{'conformant':True}
original=life._replace_bytes
def crash(root,path,data,mode,token):
 original(root,path,data,mode,token)
 if path==root/'bin/synergy-node':os._exit(91)
life._replace_bytes=crash
life.upgrade(root,candidate)
"""
        result=subprocess.run([sys.executable,'-B','-c',code,str(source),str(self.root),str(self.candidate)],check=False)
        self.assertEqual(result.returncode,91)
        self.assertTrue((self.root/life.UPGRADE_INTENT).exists())
        with self.upgrade_context():result=life.upgrade(self.root,self.candidate)
        self.assertTrue(result['resumed'])
        self.assertEqual(node.read(self.root/'installation.json')['package_sha256'],node.digest(self.candidate/'package.json'))
    def test_uncommissioned_identity_upgrade_uses_explicit_stage(self):
        save(self.root/'data/metadata/schema-version',b'synergy-node-storage:1')
        save(self.root/'keys/root/root.secret.key',b'original-custody')
        self.assertFalse((self.root/'config/node.json').exists())
        self.assertEqual(life._installation_stage(self.root),'uncommissioned')
        with self.upgrade_context(),patch.object(life,'_fresh_conformance',return_value={'conformant':True}) as final:
            life.upgrade(self.root,self.candidate)
            self.assertEqual(final.call_args.args[3],'uncommissioned')
        self.assertEqual((self.root/'keys/root/root.secret.key').read_bytes(),b'original-custody')
        save(self.root/'network/authority.json',{})
        with self.assertRaisesRegex(ValueError,'partial'):life._installation_stage(self.root)
    def test_register_resumes_own_partial_files_and_rejects_foreign_missing_unit(self):
        self.register_fixture();(self.units/life.UNITS[1]).unlink()
        def states(unit):
            if unit==life.UNITS[1]:return {'LoadState':'not-found','FragmentPath':'','MainPID':'0'}
            return self.state(unit)
        with patch.object(life,'_unit_state',side_effect=states):life.register(self.root)
        self.assertTrue((self.units/life.UNITS[1]).is_file())
        self.assertEqual(self.operations,[['systemctl','daemon-reload']])
    def test_interrupted_intent_staging_before_any_mutation_is_safe_to_retry(self):
        token=node.digest(self.candidate/'package.json')
        staged=self.root/'evidence'/('.upgrade-intent.json.upgrade-'+token[:16])
        save(staged,b'{partial intent')
        with self.upgrade_context():life.upgrade(self.root,self.candidate)
        self.assertFalse(staged.exists())
    def test_resume_refuses_wrong_candidate_or_third_party_bytes(self):
        original=life._replace_bytes
        def fail(root,path,data,mode,token):original(root,path,data,mode,token);raise SystemExit(91)
        with self.upgrade_context(),patch.object(life,'_replace_bytes',side_effect=fail):
            with self.assertRaises(SystemExit):life.upgrade(self.root,self.candidate)
        save(self.root/'README.md',b'not recorded')
        with self.upgrade_context():
            with self.assertRaisesRegex(ValueError,'neither recorded'):life.upgrade(self.root,self.candidate)
        save(self.candidate/'package.json',dict(self.new,changed=True))
        with self.upgrade_context():
            with self.assertRaisesRegex(ValueError,'exact recorded package'):life.upgrade(self.root,self.candidate)
    def test_registered_upgrade_keeps_active_vpn_and_never_starts_services(self):
        self.register_fixture()
        def states(unit): return dict(self.state(unit),**({'MainPID':'99','ActiveState':'active'} if unit==life.UNITS[1] else {}))
        with self.upgrade_context(),patch.object(life,'_unit_state',side_effect=states):result=life.upgrade(self.root,self.candidate)
        self.assertFalse(result['vpn_stopped']);self.assertTrue(result['vpn_restart_required'])
        self.assertEqual([op for op in self.operations if op[0]=='systemctl'],[['systemctl','daemon-reload']])
    def test_running_node_rejected_before_intent(self):
        self.register_fixture()
        with self.upgrade_context(),patch.object(life,'_unit_state',side_effect=lambda unit:dict(self.state(unit),MainPID='100',ActiveState='active')):
            with self.assertRaisesRegex(ValueError,'stop PoSy'):life.upgrade(self.root,self.candidate)
        self.assertFalse((self.root/life.UPGRADE_INTENT).exists());self.assertEqual(self.operations,[])
    def test_authority_set_is_universal_and_exact(self):
        for count in (1,4,5,7,32):
            ids=['validator-'+str(i) for i in range(count)]
            authority={'validators':[{'record':{'validator_id':value,'status':'active'}} for value in ids]+[{'record':{'validator_id':'retired','status':'inactive'}}]}
            self.assertEqual(life._authorized_validator_ids({'validator_addresses':list(reversed(ids))},authority,ids[0]),ids)
            for bad in (ids+ids[:1],ids+['retired'],ids[:-1]):
                with self.assertRaises(ValueError):life._authorized_validator_ids({'validator_addresses':bad},authority,ids[0])
            with self.assertRaises(ValueError):life._authorized_validator_ids({'validator_addresses':ids},authority,'outsider')
    def test_process_guard_permits_only_operator_ancestors_and_attributed_vpn(self):
        proc=self.base/'proc';proc.mkdir()
        def process(pid,image,args,ppid=1):
            directory=proc/str(pid);directory.mkdir();(directory/'exe').symlink_to(image)
            save(directory/'cmdline',b'\0'.join(x.encode() for x in args));save(directory/'stat',f'{pid} (python3) S {ppid} 0'.encode())
        process(51,'/usr/bin/sudo',['sudo','python3',str(self.root/'tools/lifecycle.py'),'upgrade','--root',str(self.root)])
        process(99,str(self.root/'bin/netbird'),['netbird','service','run'])
        with patch.object(life.os,'getppid',return_value=51):life._assert_no_application_processes(self.root,vpn_pid='99',proc=proc)
        process(100,str(self.root/'bin/synergy-node'),['synergy-node','start'])
        with patch.object(life.os,'getppid',return_value=51):
            with self.assertRaisesRegex(ValueError,'application process'):life._assert_no_application_processes(self.root,vpn_pid='99',proc=proc)
    def test_genuine_hot_journal_recovers_original_exact_bytes(self):
        save(self.root/'data/metadata/schema-version',b'synergy-node-storage:1')
        archive=self.root/'data/consensus/posy/consensus-evidence-v1.sqlite3';archive.parent.mkdir(parents=True,mode=0o700)
        connection=sqlite3.connect(archive);connection.executescript('PRAGMA user_version=1;CREATE TABLE evidence(k INTEGER PRIMARY KEY,b BLOB);CREATE TABLE revisions(k INTEGER);CREATE TABLE legacy_timeout(k INTEGER);')
        old=b'original'*1048576
        connection.execute('INSERT INTO evidence VALUES(1,?)',(old,));connection.commit();connection.close();archive.chmod(0o600)
        code="import sqlite3,os,sys;c=sqlite3.connect(sys.argv[1]);c.execute('PRAGMA cache_size=-512');c.execute('PRAGMA cache_spill=1');c.execute('BEGIN IMMEDIATE');c.execute('UPDATE evidence SET b=?',(b\"changed!\"*1048576,));os._exit(91)"
        result=subprocess.run([sys.executable,'-B','-c',code,str(archive)],check=False)
        self.assertEqual(result.returncode,91)
        journal=archive.with_name(archive.name+'-journal');self.assertTrue(journal.exists())
        before=sqlite3.connect(archive.as_uri()+'?mode=ro',uri=True)
        with self.assertRaisesRegex(sqlite3.OperationalError,'readonly'):before.execute('PRAGMA user_version').fetchone()
        before.close()
        self.assertEqual(life.recover_consensus_archives(self.root),{'recovered_existing_archives':1})
        after=sqlite3.connect(archive.as_uri()+'?mode=ro',uri=True)
        self.assertEqual(after.execute('SELECT b FROM evidence').fetchone()[0],old);after.close()
        self.assertEqual((self.root/'data/metadata/schema-version').read_bytes(),b'synergy-node-storage:1')
    def test_recovery_never_creates_missing_archive_and_refuses_unsafe_paths(self):
        save(self.root/'data/metadata/schema-version',b'synergy-node-storage:1')
        directory=self.root/'data/consensus/posy';directory.mkdir(parents=True,mode=0o700)
        self.assertEqual(life.recover_consensus_archives(self.root),{'recovered_existing_archives':0})
        self.assertEqual(list(directory.iterdir()),[])
        archive=directory/'consensus-evidence-v1.sqlite3';archive.symlink_to(self.root/'package.json')
        with self.assertRaises(ValueError):life.recover_consensus_archives(self.root)
        archive.unlink();archive.touch()
        with self.assertRaisesRegex(ValueError,'empty'):life.recover_consensus_archives(self.root)

if __name__=='__main__':unittest.main()
