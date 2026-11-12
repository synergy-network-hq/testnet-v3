#!/usr/bin/env python3
"""Read-only Linux replacement inventory. Run as root over the existing SSH connection.

Outputs path metadata and effective unit path references only. The output is
evidence for operator review, never a deletion allowlist.
"""
import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path('/opt/Synergy')
SEARCH = tuple(map(Path, ('/opt', '/etc', '/srv', '/usr/local', '/var/lib',
                          '/var/log', '/var/cache', '/var/backups', '/var/tmp',
                          '/run', '/tmp', '/root', '/home', '/usr/lib/systemd/system',
                          '/lib/systemd/system')))
MARKER = re.compile(r'synergy|posy|canary|chain[-_]?1266|testnet[-_]?v3|nodenetwork|netbird|innernet',
                    re.IGNORECASE)
UNIT_SUFFIXES = ('.service', '.socket', '.timer', '.path', '.mount', '.target')
UNIT_PATH = re.compile(r'(?<![\w])/(?:[\w.@%~:+-]+/)*[\w.@%~:+-]+')
SKIP = {'.git', 'node_modules', '.npm', '.cargo', '.rustup'}
PROPERTIES = ('FragmentPath,DropInPaths,WorkingDirectory,RootDirectory,StateDirectory,'
              'RuntimeDirectory,CacheDirectory,LogsDirectory,EnvironmentFiles,'
              'ReadWritePaths,ReadOnlyPaths,BindPaths,BindReadOnlyPaths,'
              'ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ActiveState,MainPID')
MAX_ENTRIES = 250_000
MAX_MATCHES = 8_000


def classify(path):
    if path == ROOT or ROOT in path.parents:
        return 'existing-validator-root'
    name = str(path).lower()
    if any(marker in name for marker in ('chain1266', 'chain-1266', 'testnet-v3', 'testnet_v3')):
        return 'separate-testnet-review'
    if any(marker in name for marker in ('netbird', 'innernet', 'ssh', 'sudoers')):
        return 'shared-infrastructure-review'
    return 'attribution-required'


def matching_entries(roots):
    entries, gaps, visited = {}, set(), 0
    for base in roots:
        if not base.is_dir():
            continue
        dev = base.stat().st_dev
        pending = [base]
        while pending:
            parent = pending.pop()
            try:
                with os.scandir(parent) as children:
                    for child in children:
                        visited += 1
                        if visited > MAX_ENTRIES or len(entries) >= MAX_MATCHES:
                            return entries, gaps | {'entry limit reached'}, visited
                        p = Path(child.path)
                        s = child.stat(follow_symlinks=False)
                        link = os.readlink(p) if stat.S_ISLNK(s.st_mode) else None
                        if MARKER.search(child.name) or (link and MARKER.search(link)):
                            entries[str(p)] = {'kind': 'link' if link is not None else
                                               'directory' if stat.S_ISDIR(s.st_mode) else 'file',
                                               'uid': s.st_uid, 'gid': s.st_gid,
                                               'mode': oct(stat.S_IMODE(s.st_mode)),
                                               'target': link, 'classification': classify(p)}
                            # Report a matched directory as a whole subtree. The
                            # review must approve the exact subtree before removal.
                            continue
                        if stat.S_ISDIR(s.st_mode):
                            if s.st_dev != dev or child.name in SKIP:
                                gaps.add(str(p))
                            else:
                                pending.append(p)
            except OSError as exc:
                gaps.add(f'{parent}: errno {exc.errno}')
    return entries, gaps, visited


def systemctl(*args):
    p = subprocess.run(['/usr/bin/systemctl', *args], capture_output=True, text=True,
                       timeout=8, check=True)
    if len(p.stdout) > 2_000_000:
        raise ValueError('systemd response exceeded bound')
    return p.stdout


def unit_inventory():
    names = set()
    for operation in ('list-units', 'list-unit-files'):
        for line in systemctl(operation, '--all', '--no-legend', '--no-pager', '--plain').splitlines():
            if line.strip():
                name = line.split()[0]
                if name.endswith(UNIT_SUFFIXES) and MARKER.search(name):
                    names.add(name)
    result = {}
    for name in sorted(names):
        if '@.' in name:
            result[name] = {'template': True}
            continue
        if not re.fullmatch(r'[A-Za-z0-9_.@:\\-]+', name):
            result[name] = {'reviewRequired': True}
            continue
        props = dict(row.split('=', 1) for row in
                     systemctl('show', '--property='+PROPERTIES, '--', name).splitlines()
                     if '=' in row)
        result[name] = {'state': props.pop('ActiveState', None),
                        'pid': props.pop('MainPID', None),
                        'references': {k: sorted(set(UNIT_PATH.findall(v)))
                                       for k, v in props.items() if UNIT_PATH.search(v)}}
    return result


def main():
    if os.geteuid() != 0:
        raise SystemExit('Root is required to inventory protected path metadata.')
    entries, gaps, visited = matching_entries(SEARCH)
    try:
        units = unit_inventory()
    except (OSError, subprocess.SubprocessError, ValueError):
        units = {}
        gaps.add('systemd collection failed')
    print(json.dumps({'format': 'synergy-legacy-validator-inventory-v1',
                      'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'search_roots': [str(p) for p in SEARCH],
                      'visited': visited, 'paths': entries, 'units': units,
                      'coverage_gaps': sorted(gaps),
                      'removal_authorized': False}, sort_keys=True))


if __name__ == '__main__':
    main()
