"""Synthetic SQLite/proc fixtures, never a provider or live key proof."""
import base64,contextlib,copy,hashlib,json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import bootstrap as b
KEY='EhHDd/L7fXX+c8x2nyJx8wWUwGRij3AmioVZKiH4/2M='
class RootOwned:
 def __init__(self,info):self.info=info
 def __getattr__(self,k):return 0 if k=='st_uid' else getattr(self.info,k)
class LegacyPeerKeyProofTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve()
  self.binary=self.root/'netbird-combined';self.binary.write_bytes(b'pinned binary fixture');self.binary.chmod(0o700)
  self.db=self.root/'store.db';self.connection=sqlite3.connect(self.db);self.addCleanup(self.connection.close)
  self.connection.execute('CREATE TABLE peers(account_id TEXT,id TEXT,key TEXT,name TEXT,ip TEXT,private_secret TEXT)')
  self.row=(b.LEGACY_PEER_KEY_ACCOUNT,b.LEGACY_PEER_KEY_ID,KEY,'synergy-canary-rpc-99999',json.dumps('10.69.51.205'),'never-output-this-secret')
  self.connection.execute('INSERT INTO peers VALUES(?,?,?,?,?,?)',self.row);self.connection.commit();self.db.chmod(0o600)
  self.wire={'context':{'account_id':b.LEGACY_PEER_KEY_ACCOUNT,'peer_id':b.LEGACY_PEER_KEY_ID,'wireguard_public_key_sha256':b.LEGACY_PEER_KEY_SHA256,'expires_at':1100},'challenge':'a'*64}
  stack=contextlib.ExitStack();self.addCleanup(stack.close);fstat=os.fstat;lstat=Path.lstat
  for manager in (patch.object(b,'LEGACY_PEER_KEY_BINARY',self.binary),patch.object(b,'LEGACY_PEER_KEY_STORE',self.db),patch.object(b,'LEGACY_PEER_KEY_BINARY_SHA256',hashlib.sha256(self.binary.read_bytes()).hexdigest()),patch.object(b,'_handoff_secure_parents'),patch.object(b.sys,'platform','linux'),patch.object(b.os,'geteuid',return_value=0),patch('time.time',return_value=1000),patch.object(b.os,'fstat',side_effect=lambda fd:RootOwned(fstat(fd))),patch.object(Path,'lstat',autospec=True,side_effect=lambda path:RootOwned(lstat(path)))):stack.enter_context(manager)
  self.owner_original=b._legacy_peer_key_process
  self.owner=stack.enter_context(patch.object(b,'_legacy_peer_key_process',return_value=('123','456',('7',))))
 def snapshot(self):return {p.name:(p.read_bytes(),p.stat().st_mode,p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in self.root.iterdir() if p.is_file()}
 def proof(self):return b.legacy_peer_key_proof(copy.deepcopy(self.wire))
 def test_exact_row_challenge_no_private_projection_or_write(self):
  before=self.snapshot();result=self.proof()
  self.assertEqual(set(result),{'schema','challenge','account_id','peer_id','wireguard_public_key_sha256','ip','peer_name','provider_binary_sha256','provider_revision','verified','mutation_performed'})
  self.assertEqual(result['challenge'],self.wire['challenge']);self.assertTrue(result['verified']);self.assertFalse(result['mutation_performed'])
  self.assertEqual(result['provider_revision'],'79a06720b684768b421f0a54f3bb14f22704994f');self.assertEqual(result['wireguard_public_key_sha256'],hashlib.sha256(base64.b64decode(KEY)).hexdigest())
  self.assertNotIn(KEY,json.dumps(result));self.assertNotIn('never-output',json.dumps(result));self.assertEqual(before,self.snapshot())
 def test_wrong_ambiguous_or_malformed_row_refuses_without_writes(self):
  for field,value in [('account_id','foreign'),('id','foreign'),('key',base64.b64encode(b'x'*32).decode()),('key',KEY+'x'),('key',KEY+'\0hidden'),('name','foreign'),('name','synergy-canary-rpc-99999\0hidden'),('ip','10.69.51.205'),('ip','["10.69.51.205"]'),('ip','"10.69.51.205" '),('ip',None),('key','x'*100000)]:
   self.connection.execute('DELETE FROM peers');self.connection.execute('INSERT INTO peers VALUES(?,?,?,?,?,?)',self.row);self.connection.execute('UPDATE peers SET '+field+'=?',(value,));self.connection.commit();before=self.snapshot()
   with self.subTest(field=field,value=str(value)[:80]),self.assertRaises((ValueError,sqlite3.Error)):self.proof()
   self.assertEqual(before,self.snapshot())
  self.connection.execute('DELETE FROM peers');self.connection.executemany('INSERT INTO peers VALUES(?,?,?,?,?,?)',[self.row,self.row]);self.connection.commit()
  with self.assertRaises(ValueError):self.proof()
 def test_foreign_context_expired_or_extra_never_opens_store(self):
  for key,value in [('account_id','foreign'),('peer_id','foreign'),('wireguard_public_key_sha256','b'*64),('expires_at',1000),('expires_at',1121),('expires_at',True),('extra','no')]:
   wire=copy.deepcopy(self.wire);wire['context'][key]=value
   with patch.object(b,'_legacy_peer_key_file') as opened,self.subTest(key=key),self.assertRaises(ValueError):b.legacy_peer_key_proof(wire)
   opened.assert_not_called()
 def test_unsafe_files_and_process_drift_refuse(self):
  for path in (self.binary,self.db):
   mode=path.stat().st_mode&0o777;path.chmod(0o666)
   with self.assertRaises(ValueError):self.proof()
   path.chmod(mode);other=path.with_name(path.name+'.actual');path.rename(other);path.symlink_to(other)
   with self.assertRaises(ValueError):self.proof()
   path.unlink();other.rename(path)
  self.owner.side_effect=[('123','456',('7',)),('123','789',('7',))]
  with self.assertRaises(ValueError):self.proof()
 def test_wal_or_journal_companions_refuse_without_database_access(self):
  for tail in ('-wal','-shm','-journal'):
   path=Path(str(self.db)+tail);path.write_bytes(b'unsafe recovery member');path.chmod(0o600);before=self.snapshot()
   with self.assertRaises(ValueError):self.proof()
   self.assertEqual(before,self.snapshot());path.unlink()
  self.connection.execute('PRAGMA journal_mode=WAL');self.connection.execute('UPDATE peers SET private_secret=?',('retained-private',));self.connection.commit()
  before=self.snapshot()
  with self.assertRaises(ValueError):self.proof()
  self.assertEqual(before,self.snapshot())
 def test_store_path_replacement_refuses(self):
  def changed(*args):
   if self.owner.call_count==2:self.db.rename(self.root/'original-store');self.db.write_bytes(b'foreign')
   return ('123','456',('7',))
  self.owner.side_effect=changed
  with self.assertRaises(ValueError):self.proof()
 def test_proc_owner_requires_exact_executable_uid_store_and_unique_pid(self):
  proc=self.root/'proc';proc.mkdir();base=proc/'123';base.mkdir();(base/'fd').mkdir()
  (base/'exe').symlink_to(self.binary);(base/'fd/7').symlink_to(self.db)
  (base/'status').write_bytes(b'Uid:\t0\t0\t0\t0\n')
  (base/'stat').write_bytes(b'123 (netbird combined) S '+b'0 '*18+b'456 0')
  # Exercise the actual fixed-owner reader, not the proof fixture's owner stub.
  original_stat=Path.stat
  # The on-disk fixture belongs to this test user; model its root ownership.
  with patch.object(Path,'stat',autospec=True,side_effect=lambda path,*a,**kw:RootOwned(original_stat(path,*a,**kw))):
   with self.binary.open('rb') as binary_file,self.db.open('rb') as store_file:
    binary=os.fstat(binary_file.fileno());store=os.fstat(store_file.fileno())
   actual=self.owner_original(binary,store,proc)
   self.assertEqual(actual,('123','456',('7',)))
   (base/'status').write_bytes(b'Uid:\t1\t0\t0\t0\n')
   with self.assertRaises(ValueError):self.owner_original(binary,store,proc)
   (base/'status').write_bytes(b'Uid:\t0\t0\t0\t0\n')
   (base/'fd/7').unlink();(base/'fd/7').symlink_to(self.binary)
   with self.assertRaises(ValueError):self.owner_original(binary,store,proc)
   (base/'fd/7').unlink();(base/'fd/7').symlink_to(self.db)
   other=proc/'124';other.mkdir();(other/'fd').mkdir();(other/'exe').symlink_to(self.binary);(other/'fd/8').symlink_to(self.db)
   (other/'status').write_bytes((base/'status').read_bytes());(other/'stat').write_bytes((base/'stat').read_bytes())
   with self.assertRaises(ValueError):self.owner_original(binary,store,proc)
 def test_private_view_and_review_expiry_refuse(self):
  self.connection.execute('ALTER TABLE peers RENAME TO private_records')
  self.connection.execute('CREATE VIEW peers AS SELECT * FROM private_records');self.connection.commit();before=self.snapshot()
  with self.assertRaises(sqlite3.Error):self.proof()
  self.assertEqual(before,self.snapshot())
  self.connection.execute('DROP VIEW peers');self.connection.execute('ALTER TABLE private_records RENAME TO peers');self.connection.commit()
  with patch('time.time',side_effect=[1000,1000,1100]),self.assertRaises(ValueError):self.proof()
 def test_standalone_bounded_fixed_refusal(self):
  for raw in (b'{}',b'x'*4097,b'{"context":{},"context":{},"challenge":"a"}'):
   result=subprocess.run([sys.executable,'-I','-B',str(Path(b.__file__).resolve()),'--legacy-peer-key-proof'],input=raw,capture_output=True,timeout=3,check=True)
   self.assertEqual(result.stderr,b'');self.assertEqual(json.loads(result.stdout),{'version':1,'ok':False,'error':{'code':'legacy_peer_key_proof_refused','message':'Exact legacy peer key observation refused; no resources changed'}})
