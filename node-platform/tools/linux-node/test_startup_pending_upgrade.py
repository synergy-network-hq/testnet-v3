"""Exact staged-master coexistence; no host services or native node execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bootstrap
import conformance
import controller
import lifecycle
import synergy_linux
import test_bootstrap


class PendingStartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()/'synergy'
        control = self.root/'tmp/controller'
        control.mkdir(parents=True, mode=0o700)
        for path in (self.root, self.root/'tmp', control): path.chmod(0o700)
        archive, header = test_bootstrap.BootstrapTests().archive()
        self.pending = self.root/'tmp/update-master'
        self.pending.mkdir(mode=0o700)
        bootstrap.extract(archive, self.pending, header)
        roles_path = self.pending/'roles/roles.json'
        roles = json.loads(roles_path.read_bytes()); roles['implemented'] = ['validator']
        roles_path.write_text(json.dumps(roles))
        (self.pending/'bin').mkdir(mode=0o700, exist_ok=True)
        for name in ('synergy-node','synergy-keytool','synergy-genesis','netbird'):
            member = self.pending/'bin'/name
            member.write_bytes(b'\x7fELF\x02\x01\x01'+b'\0'*11+b'\x3e\0'); member.chmod(0o700)
        for name in synergy_linux.VOLATILE: (self.pending/name).mkdir(mode=0o700, exist_ok=True)
        manifest = json.loads((self.pending/'package.json').read_bytes())
        manifest['files'] = {p.relative_to(self.pending).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in self.pending.rglob('*') if p.is_file() and p.name != 'package.json'}
        (self.pending/'package.json').write_text(json.dumps(manifest))
        header['manifest_sha256'] = synergy_linux.digest(self.pending/'package.json')
        (self.root/'tools').mkdir(mode=0o700)
        (self.root/'tools/lifecycle.py').write_bytes(Path(lifecycle.__file__).read_bytes())
        (self.root/'tools/lifecycle.py').chmod(0o700)
        engines = {}
        for name in controller.ENGINE_MODULES:
            raw = (Path(lifecycle.__file__).parent/name).read_bytes()
            (self.root/'tools'/name).write_bytes(raw); (self.root/'tools'/name).chmod(0o700)
            engines[name] = hashlib.sha256(raw).hexdigest()
        self.old = dict(release_id='installed-old', manifest_sha256='a'*64,
                        network_id='signed-network', chain_id=99999, node_name='validator')
        self.new = dict(self.old, **header)
        approval = lambda v: dict(manifest_sha256=v['manifest_sha256'],
                                  inventory_authenticated=True, networks={'signed-network':99999})
        self.policy = dict(format='synergy-nodenetwork-host-policy-v1', root=str(self.root),
            community_enrollment=False, qualified_operations=['start'], engineering_selection=self.old,
            engine_files=engines,
            engineering_initial_authorization_sha256='b'*64, validator_formation_sha256='c'*64,
            releases={self.old['release_id']:approval(self.old), self.new['release_id']:approval(self.new)},
            engineering_update=dict(initial_sha256='b'*64, formation_sha256='c'*64,
                                    previous_selection=self.old, selection=self.new))
        self.policy_path = control/'policy.json'
        self.save_policy()
        self.sealed = patch.object(lifecycle, '_sealed_receipt', return_value=(
            dict(self.old, package_sha256=self.old['manifest_sha256']), {'release_id':self.old['release_id']}))
        self.sealed.start()

    def tearDown(self):
        self.sealed.stop()
        self.temp.cleanup()

    def save_policy(self):
        self.policy_path.write_text(json.dumps(self.policy))
        self.policy_path.chmod(0o600)

    def test_exact_adoption_uses_existing_full_frozen_inventory_validation(self):
        before = {p.relative_to(self.pending).as_posix():p.read_bytes()
                  for p in self.pending.rglob('*') if p.is_file()}
        pin = lifecycle._startup_pending_upgrade(self.root)
        self.assertEqual(pin, self.new['manifest_sha256'])
        members = conformance.approved_upgrade_members(self.root, pin, 'commissioned')
        self.assertIn('tmp/update-master/package.json', members)
        self.assertEqual(before, {p.relative_to(self.pending).as_posix():p.read_bytes()
                                 for p in self.pending.rglob('*') if p.is_file()})
        rogue = self.pending/'unexpected'
        rogue.write_bytes(b'not authorized'); rogue.chmod(0o600)
        with self.assertRaises(ValueError): conformance.approved_upgrade_members(self.root, pin, 'commissioned')

    def test_missing_foreign_or_already_installed_adoption_never_exempts_tree(self):
        original = copy.deepcopy(self.policy)
        for change in ('missing', 'initial', 'formation', 'previous', 'unapproved', 'installed'):
            self.policy = copy.deepcopy(original)
            update = self.policy['engineering_update']
            if change == 'missing': self.policy.pop('engineering_update')
            elif change == 'initial': update['initial_sha256'] = 'f'*64
            elif change == 'formation': update['formation_sha256'] = 'f'*64
            elif change == 'previous': update['previous_selection'] = self.new
            elif change == 'unapproved': self.policy['releases'][self.new['release_id']]['inventory_authenticated'] = False
            elif change == 'installed': update['selection'] = self.old
            self.save_policy()
            with self.subTest(change=change), self.assertRaises(ValueError): lifecycle._startup_pending_upgrade(self.root)
        self.policy = original; self.save_policy()
        (self.pending/'package.json').write_bytes(b'changed')
        with self.assertRaises(ValueError): lifecycle._startup_pending_upgrade(self.root)

    def test_pending_symlink_and_payload_drift_refuse(self):
        member = self.pending/'tools/controller.py'
        original = member.read_bytes()
        member.write_bytes(b'changed')
        with self.assertRaises(ValueError): lifecycle._startup_pending_upgrade(self.root)
        member.unlink(); member.symlink_to(self.root/'tools/lifecycle.py')
        with self.assertRaises(ValueError): lifecycle._startup_pending_upgrade(self.root)
        member.unlink(); member.write_bytes(original); member.chmod(0o600)
        pin = lifecycle._startup_pending_upgrade(self.root)
        member.chmod(0o666)
        with self.assertRaises(ValueError): conformance.approved_upgrade_members(self.root, pin, 'commissioned')

    def test_old_installed_execstartpre_checker_refuses_before_authorization(self):
        (self.root/'tools/lifecycle.py').write_bytes(b'old sealed startup checker')
        with self.assertRaisesRegex(ValueError, 'installed startup checker differs'):
            lifecycle._startup_pending_upgrade(self.root)
        (self.root/'tools/lifecycle.py').write_bytes(Path(lifecycle.__file__).read_bytes())
        (self.root/'tools/conformance.py').write_bytes(b'different installed dependency')
        with self.assertRaisesRegex(ValueError, 'installed startup checker differs'):
            lifecycle._startup_pending_upgrade(self.root)

    def test_real_startup_routes_only_authenticated_pin_to_conformance(self):
        with patch.object(lifecycle, '_require_operator'), \
             patch.object(lifecycle, '_attributed_units'), \
             patch.object(lifecycle, 'recover_consensus_archives'), \
             patch.object(conformance, 'installed', side_effect=ValueError('full conformance refused')) as installed, \
             patch.object(controller.Controller, 'audit') as audit:
            with self.assertRaisesRegex(ValueError, 'full conformance refused'):
                lifecycle.start_check(self.root, authorize=lambda:audit({}))
            installed.assert_called_once_with(self.root, host=True, pending_upgrade_sha256=self.new['manifest_sha256'])
            audit.assert_not_called()
        (self.root/lifecycle.UPGRADE_INTENT).parent.mkdir(mode=0o700, exist_ok=True)
        (self.root/lifecycle.UPGRADE_INTENT).write_bytes(b'uncertain upgrade')
        with patch.object(lifecycle, '_require_operator'), \
             patch.object(lifecycle, 'recover_consensus_archives') as recover:
            with self.assertRaisesRegex(ValueError, 'finish the recorded upgrade'):
                lifecycle.start_check(self.root)
            recover.assert_not_called()

    def test_authorize_runs_only_after_successful_check_while_lock_held(self):
        with patch.object(lifecycle, '_require_operator'), patch.object(lifecycle, '_start_check_locked') as check:
            calls = []
            def authorize():
                with self.assertRaises(BlockingIOError):
                    with lifecycle._lifecycle_lock(self.root): pass
                calls.append('consumed')
            check.side_effect = ValueError('unsafe startup')
            with self.assertRaises(ValueError): lifecycle.start_check(self.root, authorize=authorize)
            self.assertEqual(calls, [])
            check.side_effect = None; check.return_value = {'startup_check_passed':True}
            self.assertEqual(lifecycle.start_check(self.root, authorize=authorize), check.return_value)
            self.assertEqual(calls, ['consumed'])


if __name__ == '__main__': unittest.main()
