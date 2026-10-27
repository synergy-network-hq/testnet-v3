#!/usr/bin/env python3
"""Read-only installed-release conformance. No secret contents are read or emitted.

Every filesystem member is matched against sealed software or an explicit
runtime filename rule; there are no blanket directory exclusions.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
from synergy_linux import digest, read, require

DIRECTORIES = ('bin','lib','assets','config','network','systemd','tools','data','keys',
               'logs','cache','tmp','run','vpn','snapshots','recovery','evidence','roles')
# Names describe existing native owners, not a second storage implementation.
RUNTIME_FILES = (
 r'installation\.json', r'tools/netbird-client', r'config/(node|start-authorized)\.json',
 r'network/(genesis|authority|network-manifest|p2p-bindings|transport-registry)\.json',
 r'network/(authority-root\.pub|\.synergy-writer\.lock)',
 r'keys/root/root\.(identity-root\.json|secret\.key)',
 r'keys/(p2p|consensus|ingress)/[a-z0-9-]+\.(metadata\.json|identity\.json|public\.key|secret\.key)',
 r'keys/(authority|transport)/[a-zA-Z0-9_-]+\.(metadata\.json|public\.key|secret\.key)',
 r'keys/wallets/(?:[a-zA-Z0-9_-]+/){1,2}(identity-root\.secret\.key|transaction\.secret\.key|wallet\.public\.json|operator-registry\.json)',
 r'keys/wallets/[a-zA-Z0-9_-]+/operator-registry\.json',
 r'vpn/(default|state|active_profile)\.json', r'vpn/netbird/active_profile\.txt',
 r'run/(admin|netbird)\.sock', r'logs/(node|netbird|netbird-service)\.log(?:\.[0-9]+)?',
 r'evidence/(vpn-server-binding|configured-chain-acceptance-[0-9]+|host-integrations|vpn-enrollment|initialization|public-identity|vpn-boot-integration)\.json',
 r'evidence/(upgrade-intent|upgrade-completed|vpn-retirement)\.json',
 r'evidence/(initial-transfer|reverse-transfer)/(submission-intent|submission-response)\.json',
 r'data/(?:[a-z0-9_-]+/){0,5}\.synergy-writer\.lock',
 r'data/metadata/schema-version', r'data/metadata/admin-audit/records\.json',
 r'data/metadata/sync/(active-candidate-request|accepted-checkpoint)\.json',
 r'data/peers/transport-registry-accepted\.json',
 r'data/consensus/validator-management/state\.json',
 r'data/consensus/posy/(delivery|sign-once|ready-h[0-9]+|validation-h[0-9]+|signature-[0-9a-f]{64})\.json',
 r'data/consensus/posy/verified-qcs/qc/[0-9]{20}\.json',
 r'data/consensus/posy/finality/h[0-9]+\.json',
 r'data/consensus/posy/verified-timeouts/h[0-9]+r[0-9]+\.json',
 r'data/consensus/posy/(?:[a-z0-9_-]+/)?consensus-evidence-v1\.sqlite3(?:-journal)?',
 r'data/state/execution/finalized-state\.json',
 r'data/state/execution/(finalized-world|finalized-history|processing-pinned-history)/[0-9]{20}\.json',
 r'data/state/snapshots/(cache-index-v1|active-snapshot-request)\.json',
 r'data/(?:state/execution/(?:finalized-world|finalized-history)|blocks/execution-candidates/(?:candidate-world|candidate)|blocks/processing-proposal-inputs-v1/certified)/\.(pruned-through|retained-heights)',
 r'data/(?:[a-z0-9_-]+/){1,4}\.transactions/[0-9]{10}-[0-9]{20}/(?:intent|manifest\.json|staged/[0-9]{20})',
 r'data/state/snapshots/(manifest-index|manifest|chunk)/[0-9a-f-]+\.json',
 r'data/blocks/execution-candidates/(candidate-world|candidate)/[0-9]{20}\.json',
 r'data/blocks/execution-candidates/candidate-pins/(index-v1\.json|payload/[0-9]{4}\.json)',
 r'data/blocks/processing-proposal-inputs-v1/proposal-inputs-v1\.json',
 r'data/blocks/processing-proposal-inputs-v1/(certified/[0-9]{20}|(?:certified-ids|certified-groups)/[0-9a-f]{64}|(?:inputs|validations)/[0-9]{2})\.json',
 r'data/etdag/admission-receipts/[0-9a-f]{128}/receipt-[0-9a-f]{128}\.json',
 r'data/etdag/protected-pipeline/processing-v1/pending-v1\.json',
 r'data/etdag/protected-pipeline/processing-v1/(slots|completions|finalized|progress)/[0-9]{4}\.json',
)
RUNTIME_DIRECTORIES = (
 r'keys/(root|p2p|consensus|ingress|authority|transport|wallets)',
 r'keys/wallets/(?:[a-zA-Z0-9_-]+/)?[a-zA-Z0-9_-]+', r'vpn/(netbird|root)',
 r'evidence/(initial-transfer|reverse-transfer)',
 r'data/(blocks|state|consensus|metadata|peers|etdag)',
 r'data/(?:[a-z0-9_-]+/){1,4}\.transactions(?:/[0-9]{10}-[0-9]{20}(?:/staged)?)?',
 r'data/metadata/(admin-audit|sync)',
 r'data/consensus/(posy|validator-management)',
 r'data/consensus/posy/(verified-qcs|verified-qcs/qc|verified-timeouts|finality)',
 r'data/state/(execution|snapshots|sxcp-relay-outbox)',
 r'data/state/execution/(finalized-world|finalized-history|processing-pinned-history)',
 r'data/state/snapshots/(manifest-index|manifest|chunk)',
 r'data/blocks/(execution-candidates|processing-proposal-inputs-v1)',
 r'data/blocks/execution-candidates/(candidate-world|candidate|candidate-pins|candidate-pins/payload)',
 r'data/blocks/processing-proposal-inputs-v1/(certified|certified-ids|certified-groups|inputs|validations)',
 r'data/etdag/(admission-receipts|protected-pipeline|availability-shards)',
 r'data/etdag/admission-receipts/[0-9a-f]{128}',
 r'data/etdag/protected-pipeline/(reveal-shares|processing-v1)',
 r'data/etdag/protected-pipeline/processing-v1/(slots|completions|finalized|progress)',
)
RULES = tuple(re.compile('(?:'+p+')\\Z') for p in RUNTIME_FILES)
PARAMETERS = ('node_name', 'public_identity_path', 'aegis_signing_key_path',
              'consensus.signing_key_path', 'etdag.ingress_kem_secret_key_path',
              )


def normalized_config(config, root):
    value = copy.deepcopy(config)
    # Explicit individual identity parameters only. All other values are compared.
    for dotted in PARAMETERS:
        target = value
        fields = dotted.split('.')
        for key in fields[:-1]:
            target = target.get(key, {})
        if fields[-1] in target:
            original = target[fields[-1]]
            target[fields[-1]] = (str(Path(original).parent / '<IDENTITY>')
                                  if dotted != 'node_name' and original is not None
                                  else '<'+dotted+'>')
    # SocketAddr addresses vary by host; port, address family, binding scope,
    # ordering and listener count remain operational configuration.
    for name in ('listen_addresses', 'advertised_addresses'):
        network = value.get('network', {})
        if name not in network: continue
        endpoints = []
        for endpoint in network[name]:
            address, separator, port = endpoint.rpartition(':')
            require(separator and port.isdecimal() and 0 < int(port) <= 65535,
                    'invalid configured network endpoint')
            address = ipaddress.ip_address(address.strip('[]'))
            scope = ('unspecified' if address.is_unspecified else
                     'loopback' if address.is_loopback else 'host')
            endpoints.append(f'<IPv{address.version}:{scope}>:{int(port)}')
        network[name] = endpoints
    def visit(item):
        if isinstance(item, dict): return {k:visit(v) for k,v in item.items()}
        if isinstance(item, list): return [visit(v) for v in item]
        if isinstance(item, str) and item.startswith(str(root)+'/'):
            return '<ROOT>/'+item[len(str(root))+1:]
        return item
    return visit(value)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_schema(value, schema, path='config'):
    """The sealed schema uses this deliberately small dependency-free subset."""
    kinds={'object':dict,'array':list,'string':str,'integer':int,'boolean':bool,'null':type(None)}
    allowed=schema.get('type'); allowed=[allowed] if isinstance(allowed,str) else allowed
    if allowed:
        require(any(type(value) is kinds[k] for k in allowed),path+': schema type mismatch')
    if value is None: return
    if 'const' in schema: require(value==schema['const'],path+': schema constant differs')
    if isinstance(value,dict):
        properties=schema.get('properties',{})
        require(set(schema.get('required',[]))<=value.keys(),path+': required field missing')
        require(schema.get('additionalProperties',True) or value.keys()<=properties.keys(),path+': unknown field')
        for name,child in value.items():
            if name in properties: validate_schema(child,properties[name],path+'.'+name)
    elif isinstance(value,list):
        for child in value: validate_schema(child,schema.get('items',{}),path+'[]')


def installed(root, expected_manifest=None, host=False, initialized=True, schema=None, stage=None):
    stage=stage or ('commissioned' if initialized else 'fresh')
    require(stage in ('fresh','uncommissioned','commissioned'),'unknown installation stage')
    initialized=stage!='fresh'
    root=Path(root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink()
            and root.resolve()==root,'canonical non-symlink installation root required')
    root_stat=root.lstat()
    require(root_stat.st_uid==os.geteuid() and stat.S_IMODE(root_stat.st_mode)==0o700,
            'installation root ownership or permissions differ')
    manifest=read(root/'package.json')
    receipt=read(root/'installation.json')
    if expected_manifest is not None:
        require(manifest==expected_manifest,'installed release differs from selected canonical release')
    require(digest(root/'package.json')==receipt['package_sha256'],'manifest/installation receipt drift')
    require(receipt['package_files']==manifest['files'],'installation inventory differs from release')
    require(receipt['root']==str(root),'installation root mismatch')
    require(stat.S_IMODE((root/'package.json').stat().st_mode)==0o600,
            'package manifest permissions differ')
    for name,expected in manifest['files'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'unsafe manifest path')
        path=root/name
        require(path.is_file() and not path.is_symlink() and digest(path)==expected,'sealed software drift: '+name)
        mode=0o700 if path.parent.name in ('bin','tools') else 0o600
        require(stat.S_IMODE(path.stat().st_mode)==mode,'sealed software permissions differ: '+name)
    for name in DIRECTORIES:
        if name=='data' and not initialized: continue
        require((root/name).is_dir() and not (root/name).is_symlink(),'required directory absent: '+name)
    static_directories={str(p) for name in manifest['files'] for p in Path(name).parents if str(p)!='.'}
    roles=read(root/'roles/roles.json')['roles']
    static_directories.update('roles/'+role for role in roles)
    unknown=[]; runtime=0; directories=0; runtime_names=[]
    for current,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            path=Path(current)/name; relative=path.relative_to(root).as_posix(); st=path.lstat()
            require(not stat.S_ISLNK(st.st_mode),'installation symlink: '+relative)
            require(st.st_uid==root.stat().st_uid,'ownership drift: '+relative)
            private_socket = relative in ('run/admin.sock','run/netbird.sock') and stat.S_ISSOCK(st.st_mode) and stat.S_IMODE((root/'run').stat().st_mode)==0o700
            require(private_socket or not st.st_mode&0o022,'writable by group/other: '+relative)
            if stat.S_ISDIR(st.st_mode):
                # A directory must be a known static/role path or a prefix of a
                # permitted runtime filename, checked with its children below.
                directories+=1
                if relative not in DIRECTORIES and relative not in static_directories and not any(re.fullmatch(pattern,relative) for pattern in RUNTIME_DIRECTORIES): unknown.append(relative+'/')
                continue
            if relative=='package.json' or relative in manifest['files']: continue
            if not any(rule.fullmatch(relative) for rule in RULES): unknown.append(relative); continue
            require(stat.S_ISREG(st.st_mode) or relative in ('run/admin.sock','run/netbird.sock') and stat.S_ISSOCK(st.st_mode),'runtime special member: '+relative)
            require(private_socket or relative=='tools/netbird-client' or not st.st_mode&0o111,'unexpected runtime executable: '+relative)
            if relative.startswith('keys/') and relative.endswith('secret.key'):
                require(stat.S_IMODE(st.st_mode)==0o600,'secret permissions differ: '+relative)
            runtime+=1
            runtime_names.append(relative)
    require(not unknown,'undeclared installed members: '+', '.join(unknown[:20]))
    output={'conformant':True,'release_manifest_sha256':digest(root/'package.json'),
            'software_files':len(manifest['files']),'runtime_files_checked':runtime,'directories_checked':directories,
            'host_integrations_checked':False,'initialized_state_checked':initialized,'installation_stage':stage}
    public_names=('genesis.json','authority.json','authority-root.pub','network-manifest.json','p2p-bindings.json','transport-registry.json')
    if stage!='commissioned':
        require(not any((root/'network'/name).exists() for name in public_names)
                and not (root/'config/start-authorized.json').exists(),
                'uncommissioned stage contains selected network or startup authority')
        if stage=='fresh':
            require(not (root/'config/node.json').exists() and not list((root/'keys').iterdir())
                    and not (root/'data/metadata/schema-version').exists(),
                    'fresh stage contains initialized state')
        else:
            require(not any(name.startswith('data/') and name!='data/metadata/schema-version'
                            and not name.endswith('/.synergy-writer.lock') for name in runtime_names),
                    'uncommissioned stage contains chain history')
            from synergy_linux import verify_identity
            output['identity_possession_verified']=verify_identity(root)['native_possession_verified']
    if initialized:
        require((root/'data/metadata/schema-version').read_bytes()==b'synergy-node-storage:1','storage schema differs')
        output['storage_schema']='synergy-node-storage:1'
    def contained_paths(value):
        for key,item in value.items():
            if isinstance(item,dict): contained_paths(item)
            elif item is not None and (key.endswith('_path') or key in ('authority_binding','data_directory','staging_directory')):
                path=Path(item)
                require(path.is_absolute() and '..' not in path.parts and root in path.parents and root in path.resolve().parents,'configuration path escapes installation: '+key)
    if stage=='commissioned' or (root/'config/node.json').exists():
        config=read(root/'config/node.json')
        validate_schema(config,schema if schema is not None else read(root/'assets/node-config.schema.json'))
        contained_paths(config)
        normalized=normalized_config(config,root)
        output.update(configuration_fingerprint=fingerprint(normalized),normalized_configuration=normalized)
    if stage=='commissioned':
        for name in public_names:
            require((root/'network'/name).is_file(),'required authenticated network input missing: '+name)
    for archive in (root/'data/consensus/posy').rglob('consensus-evidence-v1.sqlite3'):
        import sqlite3
        connection=sqlite3.connect(archive.as_uri()+'?mode=ro',uri=True)
        try:
            require(connection.execute('PRAGMA user_version').fetchone()==(1,),'consensus evidence format differs')
            tables={row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            require(tables=={'evidence','revisions','legacy_timeout'},'consensus evidence schema differs')
        finally:connection.close()
    if host:
        import lifecycle
        for name,text in zip(lifecycle.UNITS,(lifecycle.node_unit(root),lifecycle.vpn_unit(root))):
            path=Path('/etc/systemd/system')/name
            require(path.is_file() and not path.is_symlink() and path.read_text()==text,'canonical service differs: '+name)
            result=subprocess.run(['systemctl','show',name,'--all','--property=DropInPaths,FragmentPath,NeedDaemonReload,Environment,EnvironmentFiles,MemoryMax,MemorySwapMax,TasksMax,LimitNOFILE,ExecStart'],capture_output=True,text=True,check=True)
            require('NeedDaemonReload=no\n' in result.stdout and not any(line.startswith('EnvironmentFiles=') and line!='EnvironmentFiles=' for line in result.stdout.splitlines()),'stale or external service configuration: '+name)
            if name=='synergy-node.service':
                for expected in ('MemoryMax=1073741824','MemorySwapMax=0','TasksMax=512','LimitNOFILE=65536',f'argv[]={root}/bin/synergy-node start --config {root}/config/node.json ;'):
                    require(expected in result.stdout,'effective service policy differs: '+name)
            import shlex
            environment=next((line[12:] for line in result.stdout.splitlines() if line.startswith('Environment=')),'')
            expected_environment={line[len('Environment='):] for line in text.splitlines() if line.startswith('Environment=')}
            require(set(shlex.split(environment))==expected_environment,'effective service environment differs: '+name)
            require('DropInPaths=\n' in result.stdout and 'FragmentPath='+str(path)+'\n' in result.stdout,'service override: '+name)
        expected_wrapper=f'#!/bin/sh\nexport HOME={root} TMPDIR={root}/tmp XDG_CONFIG_HOME={root}/vpn XDG_CACHE_HOME={root}/cache NB_STATE_DIR={root}/vpn NB_DNS_STATE_FILE={root}/vpn/state.json\nexec {root}/bin/netbird --daemon-addr unix://{root}/run/netbird.sock "$@"\n'
        require((root/'tools/netbird-client').read_text()==expected_wrapper,'NetBird wrapper drift')
        registered=subprocess.run(['systemctl','list-unit-files','--no-legend','--no-pager','synergy*','posy*'],capture_output=True,text=True,check=True)
        require({line.split()[0] for line in registered.stdout.splitlines() if line.strip()}<=set(lifecycle.UNITS),'obsolete or undeclared Synergy service registered')
        output['host_integrations_checked']=True
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--expected-manifest',type=Path,required=True)
    parser.add_argument('--host',action='store_true')
    args=parser.parse_args()
    print(json.dumps(installed(args.root,read(args.expected_manifest),args.host),sort_keys=True))

if __name__=='__main__': main()
