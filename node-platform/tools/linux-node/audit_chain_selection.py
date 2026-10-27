#!/usr/bin/env python3
"""Fail package builds on numeric network selection in reusable source.

Network fixtures, frozen release inputs, and the unused nested vendor snapshot
are inventoried separately. Rust test-only items are excluded by balanced lexical
scope, not by treating an entire mixed production/test file as a fixture.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
# These whole modules are included only by cfg(test) in services/mod.rs or posy.rs.
TEST_MODULES = {f'bin/synergy-node/src/services/{name}_qualification.rs'
                for name in ('etdag', 'posy', 'socket')}
IDENTIFIER = re.compile(r'\b126[46]\b|0[xX]0*4[fF][02]\b|CHAIN.?126[46]|TESTNET.*CHAIN_ID', re.I)
RESTRICTION = re.compile(r'\b(?:chain_id|chainId|CHAIN_ID)\b\s*(?::\s*u(?:16|32|64|128)\s*)?(?:!=|==|:|=)\s*(?:126[46]|0[xX]0*4[fF][02])\b')


def rust_mask(source):
    # Keep offsets/newlines while hiding comments and quoted literal bodies.
    pattern = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|r(#+)?"[\s\S]*?"\1|"(?:\\.|[^"\\])*"', re.M)
    return pattern.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), source)


def test_ranges(source):
    masked = rust_mask(source)
    ranges = []
    for attribute in re.finditer(r'#\[cfg\(test\)\]', masked):
        start = masked.find('{', attribute.end())
        if start < 0:
            continue
        depth = 1
        for end in range(start + 1, len(masked)):
            depth += (masked[end] == '{') - (masked[end] == '}')
            if depth == 0:
                ranges.append((attribute.start(), end + 1))
                break
    return ranges


def classify(path, offset, source, ranges):
    if path in TEST_MODULES:
        return 'network_test_fixture', 'module compiled only through a parent cfg(test) declaration'
    if '/pqcore/' in path:
        return 'dynamic_protocol_value', 'cryptographic numeric table or row comment, unrelated to chain identity'
    if '/aegis-pqsynq/aegis-pqsynq/' in f'/{path}' or '/vendor/' in f'/{path}':
        return 'historical_artifact', 'unselected vendored source; not in the node package build graph'
    if path.startswith(('networks/', 'docs/')) or path.endswith('.md'):
        return 'historical_artifact', 'retained network/release input or historical documentation'
    if any(part in Path(path).parts for part in ('tests', 'test', 'examples')) or Path(path).name.startswith(('test_', 'test-')):
        return 'network_test_fixture', 'explicit test/example input, not a runtime default'
    if path.startswith('tools/validator/'):
        return 'network_test_fixture', 'network-specific qualification or historical deployment recipe; excluded from universal master'
    if path.endswith('.rs') and any(a <= offset < b for a, b in ranges):
        return 'network_test_fixture', 'Rust cfg(test) item'
    line = source[source.rfind('\n', 0, offset) + 1:source.find('\n', offset) if '\n' in source[offset:] else len(source)]
    if 'CHAIN1266' in line or 'Chain 1266' in line:
        return 'historical_artifact', 'frozen V1 domain namespace or historical comment; does not select a numeric chain'
    if path == 'tools/linux-node/audit_chain_selection.py':
        return 'dynamic_protocol_value', 'audit search expression, not runtime selection'
    if path.endswith(('.json', '.toml', '.lock')):
        return 'historical_artifact', 'explicit network configuration or dependency metadata'
    return 'review_required', 'must review before accepting package'


def audit():
    paths = subprocess.check_output(['rg', '--files', '--hidden', '-g', '!target/**', '-g', '!.git/**',
        '-g', '!._*', '-g', '!*.key', '-g', '!*.pem', '-g', '!*.xlsx'], cwd=ROOT).decode().splitlines()
    records, blockers = [], []
    for relative in sorted(paths):
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size > 20 * 1024 * 1024:
            continue
        try:
            source = path.read_text()
        except (UnicodeError, OSError):
            continue
        ranges = test_ranges(source) if path.suffix == '.rs' else []
        for match in IDENTIFIER.finditer(source):
            category, reason = classify(relative, match.start(), source, ranges)
            records.append({'path': relative, 'line': source.count('\n', 0, match.start()) + 1,
                'category': category, 'reason': reason, 'file_sha256': hashlib.sha256(source.encode()).hexdigest()})
        reusable = (relative.startswith(('bin/', 'crates/')) and '/vendor/' not in relative
            and '/aegis-pqsynq/aegis-pqsynq/' not in f'/{relative}'
            and not any(p in Path(relative).parts for p in ('tests', 'test', 'examples'))
            or relative.startswith(('tools/linux-node/', 'services/chain1266-user-ingress/')))
        if reusable and path.suffix in ('.rs', '.py', '.sh', '.mjs') and relative not in TEST_MODULES and not any(p in Path(relative).parts for p in ('tests', 'test', 'examples')) and not Path(relative).name.startswith(('test_', 'test-')):
            for match in RESTRICTION.finditer(source):
                if path.suffix == '.rs' and any(a <= match.start() < b for a, b in ranges):
                    continue
                blockers.append({'path': relative, 'line': source.count('\n', 0, match.start()) + 1})
    return {'occurrences': records, 'prohibited_restrictions': blockers}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = audit()
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'occurrences': len(result['occurrences']), 'prohibited_restrictions': result['prohibited_restrictions']}))
    raise SystemExit(bool(result['prohibited_restrictions']))
