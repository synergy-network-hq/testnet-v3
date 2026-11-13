#!/usr/bin/env python3
"""Destructive ONLY on an explicitly selected clean disposable Linux SSH target.

Exercises the real restricted controller and canonical native installer. This is
not consensus, Genesis, custody, VPN or finality qualification. Reuses an existing
host-verified SSH master; cannot silently create another connection or bypass a
host key. No private node material is generated or read.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import time
import sys
sys.dont_write_bytecode=True


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def authorize_bootstrap_software_only(package,ssh,include_register=False):
    """Test-only host operator grant; never part of the public dApp interface."""
    raw=(package/'package.json').read_bytes();manifest=json.loads(raw)
    selection={'release_id':manifest['release_id'],'manifest_sha256':hashlib.sha256(raw).hexdigest(),
               'network_id':'nodenetwork-isolated-qualification','chain_id':999999,'node_name':'validator-bootstrap-test'}
    requests=[{'version':1,'operation':'install','parameters':selection},
              {'version':1,'operation':'uninstall','parameters':{'confirmation':'/opt/synergy'}}]
    if include_register:requests.append({'version':1,'operation':'register','parameters':{}})
    # This fixed root operator procedure is deliberately tied to the known
    # disposable image and cannot activate, provision custody, or join consensus.
    code="""import hashlib,json,os,socket,sys,time
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()=='synergy-disposable-acceptance'
root=Path('/opt/synergy');control=root/'tmp/controller'
assert not (root/'installation.json').exists()
requests=json.loads(sys.stdin.buffer.read());selection=requests[0]['parameters']
assert selection['network_id']=='nodenetwork-isolated-qualification' and selection['chain_id']==999999
ops=[r['operation'] for r in requests]
assert ops in (['install','uninstall'],['install','uninstall','register'])
assert requests[1]['parameters']=={'confirmation':str(root)}
sys.path.insert(0,str(control/'tools'));sys.path.insert(0,str(control))
import controller
controller.control_inventory(root)
policy=json.loads((control/'policy.json').read_bytes())
assert policy['community_enrollment'] is False
assert not policy['qualified_operations'] or (policy['qualified_operations']==ops and policy.get('qualification_scope')=='disposable-software-lifecycle-only')
release=policy['releases'][selection['release_id']]
assert release['manifest_sha256']==selection['manifest_sha256'] and release['inventory_authenticated'] is True
stage=root/'tmp/bootstrap-master'
from synergy_linux import verify_package,digest
assert digest(stage/'package.json')==selection['manifest_sha256']
verify_package(stage)
policy['qualification_scope']='disposable-software-lifecycle-only'
policy['qualified_operations']=ops
release['networks']={selection['network_id']:selection['chain_id']}
temporary=control/'.policy.json.qualify'
try:
    with temporary.open('xb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write(json.dumps(policy,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
    temporary.replace(control/'policy.json')
finally:
    if temporary.exists():temporary.unlink()
for request in requests:
    raw=json.dumps(request,sort_keys=True,separators=(',',':')).encode();key=hashlib.sha256(raw).hexdigest()
    grant={'root':str(root),'request_sha256':key,'expires_at':int(time.time())+1200}
    grant_path=control/'grants'/(key+'.json')
    if grant_path.exists():
        previous=json.loads(grant_path.read_bytes())
        assert previous.get('root')==str(root) and previous.get('request_sha256')==key and previous.get('expires_at',0)<time.time()
        grant_path.unlink()
    with grant_path.open('xb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write(json.dumps(grant).encode());stream.flush();os.fsync(stream.fileno())
controller.control_inventory(root)
print(json.dumps({'scope':'disposable-software-lifecycle-only','requests':requests,'activationAuthorized':False,'communityEnrollment':False}))
"""
    subprocess.run(ssh+['sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(code)],input=canonical(requests),check=True)
    return selection


def qualify_repeat_managed(package,ssh,expected_pin,public_key):
    """Two actual software-only Linux lifecycles through the enrolled account."""
    raw=(package/'package.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected_pin:raise ValueError('Independent disposable package digest differs')
    manifest=json.loads(raw)
    fields=public_key.read_text().split()
    if len(fields)<2 or fields[0]!='ssh-ed25519':raise ValueError('Disposable public operator key required')
    header={'version':1,'manifest_sha256':expected_pin,'release_id':manifest['release_id'],
            'operator_public_key':' '.join(fields[:2]),'network_id':'nodenetwork-isolated-qualification',
            'chain_id':999999,'node_name':'validator-bootstrap-test'}
    assert_absent="""import grp,os,pwd,socket,subprocess
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()=='synergy-disposable-acceptance'
assert not Path('/opt/synergy').exists()
try: pwd.getpwnam('synergy-nodenetwork')
except KeyError: pass
else: raise AssertionError('managed account remains')
try: grp.getgrnam('synergy-nodenetwork')
except KeyError: pass
else: raise AssertionError('unexpected managed group remains')
for path in (Path('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf'),Path('/etc/sudoers.d/synergy-nodenetwork')):
    assert not path.exists() and not path.is_symlink()
assert not any(p.is_symlink() and str(p.readlink()).startswith('/opt/synergy/') for p in Path('/etc/systemd/system').rglob('*'))
subprocess.run(['/usr/sbin/sshd','-t'],check=True)
"""
    def root_command(code):return ssh+['sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(code)]
    bootstrap_code=("import socket\nassert socket.gethostname()=='synergy-disposable-acceptance'\n"
                    +"NATIVE_AUTHENTICATED_MANIFEST_SHA256="+repr(expected_pin)+"\n"
                    +(package/'tools/bootstrap.py').read_text())
    # The shell execs the exact granted command as the dedicated user. Keep the
    # runuser test ancestor distinct from the installed controller command.
    controller='sudo -n /usr/sbin/runuser -u synergy-nodenetwork -- /bin/sh -c '+shlex.quote(
        'exec /usr/bin/sudo -n /usr/bin/python3 -I -B /opt/synergy/tmp/controller/controller.py')
    def invoke(operation,parameters=None):
        data=canonical({'version':1,'operation':operation,'parameters':parameters or {}})
        return json.loads(subprocess.check_output(ssh+[controller],input=data,timeout=30))
    def result(operation,parameters=None):
        reply=invoke(operation,parameters)
        assert reply.get('ok') is True,(operation,reply)
        return reply['result']
    for cycle in (1,2):
        subprocess.run(root_command(assert_absent),check=True,timeout=20)
        process=subprocess.Popen(root_command(bootstrap_code),stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        try:
            process.stdin.write(canonical(header)+b'\n')
            with tarfile.open(fileobj=process.stdin,mode='w|') as archive:
                archive.add(package/'package.json',arcname='package.json',recursive=False)
                for name in sorted(manifest['files']):
                    archive.add(package/name,arcname=name,recursive=False)
            process.stdin.close()
            reply=json.loads(process.stdout.read(65537))
            assert process.wait(timeout=30)==0 and reply.get('ok') is True,reply
        finally:
            if process.poll() is None:process.kill();process.wait()
        assert reply['result']['controllerEnrolled'] and not reply['result']['softwareInstalled']
        params=authorize_bootstrap_software_only(package,ssh,include_register=True)
        assert result('target')['installed'] is False
        assert result('install_preflight',params)['packageVerified'] is True
        assert result('install',params)['consensus_started'] is False
        assert result('target')['installed'] is True
        assert result('register')['services_started'] is False
        assert result('uninstall_preflight')['managedAccountRemoval'] is True
        assert result('uninstall',{'confirmation':'/opt/synergy'})['remaining_host_managed_records']==[]
        subprocess.run(root_command(assert_absent),check=True,timeout=20)
        print(json.dumps({'cycle':cycle,'canonical_bootstrap':True,'controller_account_exercised':True,
                          'native_install':True,'services_registered':True,'logical_removal':True,
                          'managed_account_and_links_absent':True,'activation_qualified':False}),flush=True)


def audit_uninstalled_bootstrap_host(ssh):
    """After native disconnect, retire the fixed test-only Unix account record."""
    code="""import grp,json,os,pwd,socket,subprocess
from pathlib import Path
assert os.geteuid()==0 and socket.gethostname()=='synergy-disposable-acceptance'
assert not Path('/opt/synergy').exists()
for name in ('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf','/etc/sudoers.d/synergy-nodenetwork'):
    path=Path(name);assert not path.exists() and not path.is_symlink()
assert not any(p.is_symlink() and str(p.readlink()).startswith('/opt/synergy/') for p in Path('/etc/systemd/system').rglob('*'))
try:
    account=pwd.getpwnam('synergy-nodenetwork')
except KeyError:account=None
if account:
    assert account.pw_dir=='/nonexistent' and account.pw_uid!=0
    subprocess.run(['/usr/sbin/userdel','synergy-nodenetwork'],check=True)
try:group=grp.getgrnam('synergy-nodenetwork')
except KeyError:group=None
if group:
    assert not group.gr_mem
    subprocess.run(['/usr/sbin/groupdel','synergy-nodenetwork'],check=True)
subprocess.run(['/usr/sbin/sshd','-t'],check=True)
print(json.dumps({'rootAbsent':True,'systemdRegistrationResiduals':False,'sshSudoRegistrationResiduals':False,'dedicatedAccountRetired':True,'fullHostFilesystemAudit':False}))
"""
    import shlex
    subprocess.run(ssh+['sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(code)],check=True)


def qualify(package, ssh):
    manifest=json.loads((package/'package.json').read_bytes())
    pin=hashlib.sha256((package/'package.json').read_bytes()).hexdigest()
    params={'release_id':manifest['release_id'],'manifest_sha256':pin,
            'network_id':'nodenetwork-disposable-qualification','chain_id':999999,'node_name':'disposable-controller'}
    subprocess.run(ssh+['sudo -n test ! -e /opt/synergy'],check=True)
    names=('controller.py','synergy_linux.py','lifecycle.py','conformance.py','apqe_layout.py','vpn.py','canary_rpc_relay.py')
    files={name:(package/'tools'/name).read_bytes() for name in names}
    policy={'format':'synergy-nodenetwork-host-policy-v1','root':'/opt/synergy',
            'community_enrollment':False,'qualification_scope':'disposable-test-only',
            'qualified_operations':['install','uninstall','register','stop'],
            'engine_files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
            'releases':{manifest['release_id']:{'manifest_sha256':pin,'inventory_authenticated':True,
                         'networks':{params['network_id']:params['chain_id']}}}}
    process=subprocess.Popen(ssh+["sudo -n sh -c 'umask 077; mkdir -p /opt/synergy/tmp/controller/tools /opt/synergy/tmp/controller/grants; tar --no-same-owner -xf - -C /opt/synergy/tmp'"],stdin=subprocess.PIPE)
    with tarfile.open(fileobj=process.stdin,mode='w|') as tar:
        for path in sorted(package.rglob('*')):
            if path.name.startswith('._'):continue
            tar.add(path,arcname='bootstrap-master/'+path.relative_to(package).as_posix(),recursive=False)
        def entry(name,data):
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;tar.addfile(info,io.BytesIO(data))
        entry('controller/controller.py',files['controller.py'])
        for name,data in files.items():
            if name!='controller.py':entry('controller/tools/'+name,data)
        entry('controller/policy.json',canonical(policy))
    process.stdin.close();assert process.wait()==0
    command='sudo -n /usr/bin/python3 -I -B /opt/synergy/tmp/controller/controller.py'
    def invoke(op,parameters=None,approve=False):
        req={'version':1,'operation':op,'parameters':parameters or {}};raw=canonical(req)
        if approve:
            key=hashlib.sha256(raw).hexdigest()
            grant=canonical({'root':'/opt/synergy','request_sha256':key,'expires_at':int(time.time())+120})
            create="sudo -n python3 -c 'import sys,os; f=os.open(\"/opt/synergy/tmp/controller/grants/"+key+".json\",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,sys.stdin.buffer.read()); os.close(f)'"
            subprocess.run(ssh+[create],input=grant,check=True)
        response=json.loads(subprocess.check_output(ssh+[command],input=raw))
        return response
    target=invoke('target');assert target['ok'] and target['result']['communityEnrollment'] is False
    bad=dict(params,manifest_sha256='0'*64)
    assert not invoke('install_preflight',bad)['ok']
    assert not invoke('shell')['ok']
    preflight=invoke('install_preflight',params);assert preflight['ok'] and not preflight['result']['genesisAuthorityVerified']
    assert invoke('install',params)['error']['code']=='authorization_required'
    installed=invoke('install',params,approve=True);assert installed['ok'],installed
    assert installed['result']['package_sha256']==pin and not installed['result']['consensus_started']
    inventory=invoke('inventory');assert inventory['ok'];members=len(inventory['result']['members'])
    assert not invoke('start')['ok']
    registered=invoke('register',approve=True);assert registered['ok'],registered
    subprocess.run(ssh+["sudo -n sh -c 'test -L /etc/systemd/system/synergy-node.service && test \"$(readlink /etc/systemd/system/synergy-node.service)\" = /opt/synergy/systemd/synergy-node.service && test -f /opt/synergy/systemd/synergy-node.service && test ! -d /opt/synergy/data'"],check=True)
    scope=invoke('uninstall_preflight');assert scope['ok'] and scope['result']['destructive']
    removed=invoke('uninstall',{'confirmation':'/opt/synergy'},approve=True);assert removed['ok'],removed
    subprocess.run(ssh+["sudo -n python3 -c 'from pathlib import Path; import subprocess; assert not Path(\"/opt/synergy\").exists(); assert not any(p.is_symlink() and str(p.readlink()).startswith(\"/opt/synergy/\") for p in Path(\"/etc/systemd/system\").rglob(\"*\")); r=subprocess.check_output([\"systemctl\",\"show\",\"synergy-node.service\",\"synergy-vpn.service\",\"--property=LoadState,FragmentPath,MainPID\"],text=True); assert \"LoadState=loaded\" not in r and \"MainPID=0\" in r; print(\"root-and-systemd-residual-audit passed\")'"],check=True)
    print(json.dumps({'release':manifest['release_id'],'manifest_sha256':pin,'actual_native_install':True,
                      'inventory_members':members,'rooted_unit_registration':True,'first_pass_uninstall':True,
                      'root_and_systemd_residual_audit':True,'consensus_qualified':False,
                      'full_host_filesystem_audit':False,'portal_end_to_end_qualified':False}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-package',type=Path,required=True)
    parser.add_argument('--ssh-control',required=True)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--target',required=True)
    parser.add_argument('--acknowledge-clean-disposable-target',action='store_true',required=True)
    parser.add_argument('--authorize-existing-bootstrap-software-only',action='store_true')
    parser.add_argument('--audit-uninstalled-bootstrap-host',action='store_true')
    parser.add_argument('--repeat-managed-bootstrap',action='store_true')
    parser.add_argument('--expected-manifest-sha256')
    parser.add_argument('--disposable-operator-public-key',type=Path)
    args=parser.parse_args()
    ssh=['ssh','-S',args.ssh_control,'-o','ControlMaster=no','-o','ProxyCommand=/usr/bin/false',
         '-p',str(args.port),args.target]
    if args.repeat_managed_bootstrap:
        if args.target!='acceptance@127.0.0.1' or not args.expected_manifest_sha256 or not args.disposable_operator_public_key:
            parser.error('Repeat qualification requires the pinned local disposable target, manifest pin and public operator key')
        qualify_repeat_managed(args.disposable_package,ssh,args.expected_manifest_sha256,args.disposable_operator_public_key)
    elif args.audit_uninstalled_bootstrap_host:audit_uninstalled_bootstrap_host(ssh)
    elif args.authorize_existing_bootstrap_software_only:authorize_bootstrap_software_only(args.disposable_package,ssh)
    else:qualify(args.disposable_package,ssh)

if __name__=='__main__':main()
