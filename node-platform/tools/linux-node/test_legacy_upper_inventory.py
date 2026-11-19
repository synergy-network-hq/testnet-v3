"""Read-only fd-walk fixtures; no host inventory, private reads or removal."""
import contextlib,hashlib,json,os,socket,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import bootstrap as b
class RootOwned:
 def __init__(self,info,**overrides):self.info=info;self.overrides=overrides
 def __getattr__(self,key):return self.overrides.get(key,0 if key=='st_uid' else getattr(self.info,key))
class LegacyUpperInventoryTests(unittest.TestCase):
 def setUp(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
  self.files={'README.md':b'public legacy readme','bin/synergy-node':b'public node image','lib/apqe/provider.json':b'public provider report'}
  for relative,raw in self.files.items():
   path=self.root/relative;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
  for relative in ('keys','run','tmp'):(self.root/relative).mkdir(mode=0o700)
  self.private=self.root/'keys/private.key';self.private.write_bytes(b'PRIVATE FIXTURE MUST NEVER BE OPENED');self.private.chmod(0o600)
  self.manifest={'files':{p:hashlib.sha256(raw).hexdigest() for p,raw in self.files.items()}}
  self.save_manifest()
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  fstat=os.fstat;stat=os.stat;lstat=Path.lstat;public=b._handoff_public;opened=os.open
  stack.enter_context(patch.object(b,'bare_mounts'))
  stack.enter_context(patch.object(b,'_handoff_secure_parents'))
  stack.enter_context(patch.object(b.os,'fstat',side_effect=lambda fd:RootOwned(fstat(fd))))
  stack.enter_context(patch.object(b.os,'stat',side_effect=lambda *a,**kw:RootOwned(stat(*a,**kw))))
  stack.enter_context(patch.object(Path,'lstat',autospec=True,side_effect=lambda path:RootOwned(lstat(path))))
  def pinned(path,*args):
   pin,raw=public(path,*args)
   return ('ef491eddd06e4145abc1f396b3c363cb2a7f2ec2d582d1d05cf5d28c6dfc679f' if Path(path).name=='package.json' else pin),raw
  stack.enter_context(patch.object(b,'_handoff_public',side_effect=pinned))
  def no_private(path,*args,**kwargs):
   if str(path).endswith('private.key'):raise AssertionError('Private content opened')
   return opened(path,*args,**kwargs)
  stack.enter_context(patch.object(b.os,'open',side_effect=no_private))
 def save_manifest(self):
  path=self.root/'package.json';path.write_text(json.dumps(self.manifest));path.chmod(0o600)
 def inventory(self):return b._legacy_upper_inventory(self.root)
 def test_recursive_metadata_and_all_software_bind_without_reading_private_bytes(self):
  before={p:(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.root.rglob('*')}
  first,blocked=self.inventory();self.assertEqual(len(first),64);self.assertEqual(blocked,set())
  self.assertEqual(before,{p:(p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.root.rglob('*')})
  self.assertEqual(first,self.inventory()[0])
  self.private.chmod(0o400);self.assertNotEqual(first,self.inventory()[0])
  # Metadata-only unknown runtime is NOT ownership; the caller keeps its
  # mandatory inventory/removal/peer blockers even when this returns no defect.
  sock=socket.socket(socket.AF_UNIX);sock.bind(str(self.root/'run/daemon.sock'));self.addCleanup(sock.close)
  current,unused=self.inventory();self.assertNotEqual(first,current)
 def test_commitment_domain_binds_classification_and_exact_software_map(self):
  original=hashlib.sha256;commits=[]
  def capture(raw=b''):
   if b'legacy-canary-upper-recursive-v1' in raw:commits.append(json.loads(raw))
   return original(raw)
  with patch.object(b.hashlib,'sha256',side_effect=capture):self.inventory()
  self.assertEqual(len(commits),1);value=commits[0]
  self.assertEqual(value['schema'],'legacy-canary-upper-recursive-v1')
  self.assertEqual(value['package_sha256'],'ef491eddd06e4145abc1f396b3c363cb2a7f2ec2d582d1d05cf5d28c6dfc679f')
  self.assertEqual(value['software_sha256'],self.manifest['files'])
  private=[row for row in value['entries'] if row[0]=='keys/private.key']
  self.assertEqual(private[0][2],'runtime_unattributed');self.assertNotIn('PRIVATE FIXTURE',json.dumps(value))
 def test_missing_drifted_or_private_manifest_members_refuse(self):
  node=self.root/'bin/synergy-node';node.write_bytes(b'changed image')
  with self.assertRaises(ValueError):self.inventory()
  node.unlink()
  with self.assertRaises(ValueError):self.inventory()
  node.write_bytes(self.files['bin/synergy-node']);node.chmod(0o600)
  self.manifest['files']['keys/private.key']='a'*64;self.save_manifest()
  with self.assertRaises(ValueError):self.inventory()
 def test_symlinks_never_follow_and_software_hardlinks_refuse(self):
  (self.root/'tmp/outside').symlink_to(self.root.parent,target_is_directory=True)
  self.assertIn('foreign_resources',self.inventory()[1])
  (self.root/'tmp/outside').unlink()
  node=self.root/'bin/synergy-node';alias=self.root/'tmp/node-link';os.link(node,alias)
  with self.assertRaises(ValueError):self.inventory()
  alias.unlink();node.unlink();node.symlink_to(self.private)
  with self.assertRaises(ValueError):self.inventory()
 def test_bounds_and_mount_guard_refuse_no_partial_commitment(self):
  for i in range(513):(self.root/'tmp'/str(i)).mkdir(mode=0o700)
  with self.assertRaises(ValueError):self.inventory()
  with patch.object(b,'bare_mounts',side_effect=ValueError('Mount boundary')),self.assertRaises(ValueError):self.inventory()
 def test_untrusted_subtree_refuses_before_recursive_walk(self):
  path=self.root/'keys';path.chmod(0o777)
  with self.assertRaises(ValueError):self.inventory()
  path.chmod(0o700)
 def test_directory_substitution_and_cross_device_entry_refuse(self):
  real=b.os.stat.side_effect
  def cross(path,*args,**kwargs):
   value=real(path,*args,**kwargs)
   return RootOwned(value,st_dev=value.st_dev+1) if str(path)=='keys' else value
  with patch.object(b.os,'stat',side_effect=cross),self.assertRaises(ValueError):self.inventory()
  node=self.root/'bin/synergy-node';original=b.os.read;changed=False
  def drift(fd,count):
   nonlocal changed
   value=original(fd,count)
   if not changed:
    changed=True;node.rename(self.root/'bin/substituted');node.write_bytes(self.files['bin/synergy-node']);node.chmod(0o600)
   return value
  with patch.object(b.os,'read',side_effect=drift),self.assertRaises(ValueError):self.inventory()
 def test_foreign_package_or_unsafe_manifest_shape_refuses_before_private_walk(self):
  with patch.object(b,'_handoff_public',return_value=('a'*64,b'{}')),self.assertRaises(ValueError):self.inventory()
  for name in ('../escape','/absolute','bin/../secret','config/node.json','keys/private.key','bin//node'):
   self.manifest['files']={name:'a'*64};self.save_manifest()
   with self.subTest(name=name),self.assertRaises(ValueError):self.inventory()
