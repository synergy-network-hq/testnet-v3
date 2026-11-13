"""Guard attribution and retirement boundaries; never touches host registrations."""
import errno
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

import root_guard as guard


ROOT = Path('/opt/synergy')
SUFFIX = 'a' * 32
PIN = 'b' * 64
UID = 1234


def metadata(mode, uid=0, **extra):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=1, st_size=10, **extra)


def observed(active=False, fragment='', **extra):
    return dict(LoadState='loaded' if fragment else 'not-found', FragmentPath=fragment,
                DropInPaths='', ActiveState='active' if active else 'inactive',
                MainPID='42' if active else '0', ControlPID='0',
                KillMode='control-group', **extra)


class RootIdentityTests(unittest.TestCase):
    def test_invalid_install_input_never_tags_or_registers_any_path(self):
        account = {'label': 'Synergy NodeNetwork ' + SUFFIX, 'uid': UID, 'gid': 65534}
        cases = [(Path('/tmp/unapproved'), account, b'code'),
                 (ROOT, dict(account, uid=0), b'code'),
                 (ROOT, dict(account, uid=True), b'code'),
                 (ROOT, dict(account, gid=0), b'code'),
                 (ROOT, dict(account, label='other'), b'code'),
                 (ROOT, account, b''), (ROOT, account, b'x' * 18001),
                 (ROOT, account, 'not bytes')]
        for root, identity, source in cases:
            with self.subTest(root=root, identity=identity, size=len(source)), \
                    patch.object(guard.os, 'setxattr', create=True) as tag, \
                    patch.object(guard, 'systemctl') as service, \
                    patch.object(Path, 'open') as write:
                with self.assertRaises(ValueError):
                    guard.install(root, identity, source)
                tag.assert_not_called()
                service.assert_not_called()
                write.assert_not_called()

    def test_only_root_owned_nonwritable_real_directory_can_supply_identity(self):
        for entry in (None, metadata(stat.S_IFLNK | 0o777),
                      metadata(stat.S_IFREG | 0o600), metadata(stat.S_IFDIR | 0o700, uid=1000),
                      metadata(stat.S_IFDIR | 0o770), metadata(stat.S_IFDIR | 0o702)):
            with self.subTest(entry=entry), patch.object(guard, 'info', return_value=entry), \
                    patch.object(guard.os, 'getxattr', create=True) as read:
                self.assertIsNone(guard.root_identity(ROOT))
                read.assert_not_called()
        with patch.object(guard, 'info', return_value=metadata(stat.S_IFDIR | 0o700)), \
                patch.object(guard.os, 'getxattr', create=True, return_value=SUFFIX.encode()) as read:
            self.assertEqual(guard.root_identity(ROOT), SUFFIX)
            read.assert_called_once_with(ROOT, guard.ROOT_TAG, follow_symlinks=False)

    def test_absent_or_non_ascii_tag_never_establishes_identity(self):
        for value in (OSError(errno.ENODATA, 'absent'), b'\xff'):
            with patch.object(guard, 'info', return_value=metadata(stat.S_IFDIR | 0o700)), \
                    patch.object(guard.os, 'getxattr', create=True, **(
                        {'side_effect': value} if isinstance(value, OSError) else {'return_value': value})):
                self.assertIsNone(guard.root_identity(ROOT))
        with patch.object(guard, 'info', return_value=metadata(stat.S_IFDIR | 0o700)), \
                patch.object(guard.os, 'getxattr', create=True, side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                guard.root_identity(ROOT)

    def test_watch_refuses_arbitrary_root_uid_or_identity_before_os_access(self):
        for root, uid, suffix in ((Path('/tmp/other'), UID, SUFFIX), (ROOT, 0, SUFFIX),
                                  (ROOT, UID, 'invalid')):
            with self.subTest(root=root, uid=uid, suffix=suffix), \
                    patch.object(guard.os, 'geteuid', return_value=0), \
                    patch.object(guard, 'unit_digest') as digest, patch.object(guard, 'retire') as retire:
                with self.assertRaises(ValueError):
                    guard.watch(root, uid, suffix)
                digest.assert_not_called()
                retire.assert_not_called()

    def test_watch_waits_on_own_tag_then_retires_with_original_pin(self):
        with patch.object(guard.os, 'geteuid', return_value=0), \
                patch.object(guard, 'unit_digest', return_value=PIN), \
                patch.object(guard, 'root_identity', side_effect=[SUFFIX, SUFFIX, None]), \
                patch.object(guard.time, 'sleep') as sleep, patch.object(guard, 'retire') as retire:
            guard.watch(ROOT, UID, SUFFIX)
            self.assertEqual(sleep.call_args_list, [call(2), call(2)])
            retire.assert_called_once_with(ROOT, UID, SUFFIX, PIN)


class AttributionTests(unittest.TestCase):
    def test_guard_digest_rejects_symlink_writable_foreign_or_hardlinked_file(self):
        entries = [metadata(stat.S_IFLNK | 0o777), metadata(stat.S_IFREG | 0o600, uid=1),
                   metadata(stat.S_IFREG | 0o620), metadata(stat.S_IFREG | 0o602)]
        hardlinked = metadata(stat.S_IFREG | 0o600)
        hardlinked.st_nlink = 2
        entries.append(hardlinked)
        oversized = metadata(stat.S_IFREG | 0o600)
        oversized.st_size = 32769
        entries.append(oversized)
        for entry in entries:
            with self.subTest(entry=entry), patch.object(guard, 'info', return_value=entry), \
                    patch.object(Path, 'read_bytes') as read:
                with self.assertRaisesRegex(ValueError, 'unsafe guard'):
                    guard.unit_digest(guard.paths()[0])
                read.assert_not_called()

    def test_link_attribution_requires_exact_root_owned_symlink(self):
        path, target = guard.paths()
        for entry, destination in ((metadata(stat.S_IFREG | 0o600), str(target)),
                                   (metadata(stat.S_IFLNK | 0o777, uid=1000), str(target)),
                                   (metadata(stat.S_IFLNK | 0o777), '/etc/unrelated')):
            with self.subTest(entry=entry, destination=destination), \
                    patch.object(guard, 'info', return_value=entry), \
                    patch.object(guard.os, 'readlink', return_value=destination):
                with self.assertRaisesRegex(ValueError, 'unattributed OS'):
                    guard.owned_link(path, target)

    def test_foreign_effective_fragment_dropin_and_non_group_kill_are_refused(self):
        name = guard.RUNTIME_UNITS[0]
        canonical = str(guard.SYSTEM / name)
        cases = [observed(True, '/usr/lib/systemd/system/unrelated.service'),
                 dict(observed(True, canonical), DropInPaths='/etc/systemd/system/x.conf'),
                 dict(observed(True, canonical), KillMode='process')]
        for value in cases:
            with self.subTest(value=value), patch.object(guard, 'owned_link', return_value=True), \
                    patch.object(guard, 'state', return_value=value):
                with self.assertRaises(ValueError):
                    guard.attributed_runtime(ROOT, name)

    def test_unlinked_active_service_is_not_attributed_by_name_or_fragment(self):
        name = guard.RUNTIME_UNITS[0]
        with patch.object(guard, 'owned_link', return_value=False), \
                patch.object(guard, 'state', return_value=observed(True, str(ROOT / 'systemd' / name))):
            with self.assertRaisesRegex(ValueError, 'unattributed effective service'):
                guard.attributed_runtime(ROOT, name)

    def test_same_name_foreign_account_group_or_uid_alias_is_preserved(self):
        correct = SimpleNamespace(pw_name=guard.ACCOUNT, pw_uid=UID, pw_gid=65534,
                                  pw_gecos='Synergy NodeNetwork ' + SUFFIX,
                                  pw_dir='/nonexistent', pw_shell='/bin/sh')
        for changed in ({'pw_uid': 2345}, {'pw_gecos': 'unrelated'},
                        {'pw_dir': '/home/unrelated'}, {'pw_shell': '/bin/bash'}):
            account = SimpleNamespace(**dict(vars(correct), **changed))
            with self.subTest(changed=changed), \
                    patch.object(guard.grp, 'getgrnam', side_effect=KeyError), \
                    patch.object(guard.pwd, 'getpwnam', return_value=account), \
                    patch.object(guard.pwd, 'getpwall', return_value=[account]):
                with self.assertRaisesRegex(ValueError, 'unattributed dedicated account'):
                    guard.account_present(UID, SUFFIX)
        with patch.object(guard.grp, 'getgrnam', return_value=object()):
            with self.assertRaisesRegex(ValueError, 'unattributed dedicated group'):
                guard.account_present(UID, SUFFIX)
        with patch.object(guard.grp, 'getgrnam', side_effect=KeyError), \
                patch.object(guard.pwd, 'getpwnam', return_value=correct), \
                patch.object(guard.pwd, 'getpwall', return_value=[correct, SimpleNamespace(pw_name='other', pw_uid=UID)]):
            with self.assertRaisesRegex(ValueError, 'unattributed dedicated account'):
                guard.account_present(UID, SUFFIX)


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.unit, self.link = guard.paths()
        self.links = {self.link: self.unit}
        for name in guard.RUNTIME_UNITS:
            self.links[guard.SYSTEM / name] = ROOT / 'systemd' / name
            self.links[guard.SYSTEM / 'multi-user.target.wants' / name] = guard.SYSTEM / name
        for path, filename in guard.CONTROLLER_LINKS.items():
            self.links[path] = ROOT / 'tmp/controller/host' / filename
        self.unrelated = guard.SYSTEM / 'unrelated.service'
        self.links[self.unrelated] = Path('/usr/lib/systemd/system/unrelated.service')
        self.states = {name: observed(True, str(guard.SYSTEM / name)) for name in guard.RUNTIME_UNITS}
        self.states['ssh.service'] = observed(True, '/usr/lib/systemd/system/ssh.service')
        self.account = True
        self.events = []
        self.fail_userdel_once = False
        for target, attribute, replacement in (
                (guard, 'unit_digest', Mock(return_value=PIN)),
                (guard, 'owned_link', Mock(side_effect=self.owned_link)),
                (guard, 'state', Mock(side_effect=lambda name: self.states[name].copy())),
                (guard, 'account_present', Mock(side_effect=lambda uid, suffix: self.account)),
                (guard, 'systemctl', Mock(side_effect=self.systemctl)),
                (guard, 'run', Mock(side_effect=self.command)),
                (Path, 'unlink', lambda path: self.unlink(path))):
            context = patch.object(target, attribute, replacement)
            context.start()
            self.addCleanup(context.stop)

    def owned_link(self, path, target):
        if path not in self.links:
            return False
        guard.require(self.links[path] == target, 'unattributed OS registration: ' + str(path))
        return True

    def systemctl(self, *args):
        self.events.append(('systemctl', *args))
        if args[0] == 'stop':
            self.states[args[1]] = observed(False, str(guard.SYSTEM / args[1]))
        return ''

    def unlink(self, path):
        self.events.append(('unlink', path))
        if path != self.unit:
            del self.links[path]

    def command(self, *args):
        self.events.append(('run', *args))
        if args[0] == '/usr/sbin/userdel':
            if self.fail_userdel_once:
                self.fail_userdel_once = False
                raise subprocess.CalledProcessError(1, args)
            self.account = False
        return ''

    def test_retires_only_attributed_runtime_and_account_and_guard_last(self):
        guard.retire(ROOT, UID, SUFFIX, PIN)
        self.assertEqual(self.links, {self.unrelated: Path('/usr/lib/systemd/system/unrelated.service')})
        self.assertFalse(self.account)
        stops = [event for event in self.events if event[:2] == ('systemctl', 'stop')]
        self.assertEqual(stops, [('systemctl', 'stop', name) for name in guard.RUNTIME_UNITS])
        self.assertEqual(self.events[-3:], [('unlink', self.link), ('unlink', self.unit),
                                            ('systemctl', 'daemon-reload')])
        first_unlink = next(i for i, event in enumerate(self.events) if event[0] == 'unlink')
        self.assertTrue(all(self.events.index(stop) < first_unlink for stop in stops))
        self.assertIn(('run', '/usr/sbin/userdel', '--force', guard.ACCOUNT), self.events)

    def test_foreign_runtime_or_override_prevents_all_removals(self):
        for value in (ValueError('foreign fragment'), ValueError('foreign dropin')):
            with self.subTest(value=value), patch.object(guard, 'attributed_runtime', side_effect=value):
                with self.assertRaisesRegex(ValueError, 'foreign'):
                    guard.retire(ROOT, UID, SUFFIX, PIN)
                self.assertEqual(self.events, [])
                self.assertTrue(self.account)

    def test_foreign_counterpart_does_not_prevent_stopping_other_owned_units(self):
        foreign = guard.RUNTIME_UNITS[0]
        self.links[guard.SYSTEM / foreign] = Path('/usr/lib/systemd/system/foreign.service')
        with self.assertRaisesRegex(ValueError, 'unattributed OS'):
            guard.retire(ROOT, UID, SUFFIX, PIN)
        stops = [event for event in self.events if event[:2] == ('systemctl', 'stop')]
        self.assertEqual(stops, [('systemctl', 'stop', name) for name in guard.RUNTIME_UNITS[1:]])
        self.assertEqual(self.states[foreign]['ActiveState'], 'active')
        self.assertFalse(any(event[0] in ('unlink', 'run') for event in self.events))
        self.assertTrue(self.account)

    def test_foreign_host_link_prevents_account_and_link_removal(self):
        path = next(iter(guard.CONTROLLER_LINKS))
        self.links[path] = Path('/etc/unrelated')
        with self.assertRaisesRegex(ValueError, 'unattributed OS'):
            guard.retire(ROOT, UID, SUFFIX, PIN)
        self.assertFalse(any(event[0] in ('unlink', 'run') for event in self.events))
        self.assertTrue(self.account)

    def test_service_not_quiescent_prevents_destructive_cleanup(self):
        with patch.object(guard, 'quiescent', return_value=False):
            with self.assertRaisesRegex(ValueError, 'still running'):
                guard.retire(ROOT, UID, SUFFIX, PIN)
        self.assertFalse(any(event[0] in ('unlink', 'run') for event in self.events))

    def test_cleanup_retry_after_userdel_failure_keeps_guard_until_success(self):
        self.fail_userdel_once = True
        with self.assertRaises(subprocess.CalledProcessError):
            guard.retire(ROOT, UID, SUFFIX, PIN)
        self.assertTrue(self.account)
        self.assertIn(self.link, self.links)
        self.assertNotIn(('unlink', self.unit), self.events)
        guard.retire(ROOT, UID, SUFFIX, PIN)
        self.assertFalse(self.account)
        self.assertNotIn(self.link, self.links)
        self.assertIn(self.unrelated, self.links)

    def test_guard_pin_mismatch_prevents_any_action(self):
        with patch.object(guard, 'unit_digest', return_value='c' * 64):
            with self.assertRaisesRegex(ValueError, 'guard registration changed'):
                guard.retire(ROOT, UID, SUFFIX, PIN)
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
