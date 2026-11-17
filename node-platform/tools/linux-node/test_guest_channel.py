"""Real loopback byte transport only; never creates a VM or validator."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
import guest_lifecycle as g
import bootstrap as b
import test_operator_authorization as authorization_fixture

RAW=b'\0\0\0\x0bssh-ed25519\0\0\0 '+b'x'*32
PUBLIC='ssh-ed25519 '+base64.b64encode(RAW).decode()
FINGERPRINT='SHA256:'+base64.b64encode(hashlib.sha256(RAW).digest()).decode().rstrip('=')
BINDING={'guest_id':'fifth','create_request_sha256':'a'*64,'ssh_host_public_key':PUBLIC,'ssh_host_fingerprint':FINGERPRINT}
HEADER={key:BINDING[key] for key in ('guest_id','create_request_sha256','ssh_host_fingerprint')}

class GuestChannelTests(unittest.TestCase):
 def header(self,raw):
  read,write=os.pipe()
  try:
   os.write(write,raw);os.close(write);write=None
   return g.read_guest_header(read)
  finally:
   os.close(read)
   if write is not None:os.close(write)
 def test_framing_preserves_binary_ssh_and_normal_json_prefix(self):
  read,write=os.pipe()
  raw=json.dumps(HEADER,sort_keys=True,separators=(',',':')).encode()
  try:
   os.write(write,g.GUEST_SSH_MAGIC+raw+b'\nSSH-2.0-test\0binary');os.close(write);write=None
   self.assertEqual(g.read_guest_prefix(read),g.GUEST_SSH_MAGIC)
   self.assertEqual(g.read_guest_header(read),HEADER)
   self.assertEqual(os.read(read,1024),b'SSH-2.0-test\0binary')
  finally:
   os.close(read)
   if write is not None:os.close(write)
  for raw in (json.dumps({**HEADER,'port':22}).encode()+b'\n',json.dumps(HEADER,indent=2).encode()+b'\n',b'{"guest_id":"fifth","guest_id":"other"}\n',b'x'*1024,b'{}\n'):
   with self.assertRaises(ValueError):self.header(raw)
 def test_active_receipt_exact_scope_and_no_endpoint_selection(self):
  status={'exists':True,'phase':'created','service_state':'active','pid':123,'ssh_identity_verified':True,
          'request_sha256':'a'*64,'ssh_host_fingerprint':FINGERPRINT,'ssh_endpoint':{'host':'127.0.0.1','port':22288}}
  manager=SimpleNamespace(spec={'ssh_forward_port':22288},status=Mock(return_value=status))
  self.assertEqual(g.guest_channel_address(manager,HEADER),('127.0.0.1',22288))
  for field,value in [('phase','start-dispatched'),('service_state','inactive'),('pid',0),('request_sha256','b'*64),('ssh_host_fingerprint','SHA256:wrong'),('ssh_endpoint',{'host':'0.0.0.0','port':22288})]:
   altered={**status,field:value};manager.status.return_value=altered
   with self.assertRaises(ValueError):g.guest_channel_address(manager,HEADER)
 def pump(self,payload,response,**limits):
  listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(2)
  address=listener.getsockname();peer=socket.create_connection(address,timeout=2);server,_=listener.accept();listener.close()
  incoming_r,incoming_w=os.pipe();outgoing_r,outgoing_w=os.pipe();errors=[];received=[]
  def remote():
   try:
    server.settimeout(2);data=bytearray()
    while True:
     chunk=server.recv(65536)
     if not chunk:break
     data.extend(chunk)
    received.append(bytes(data))
    if response:server.sendall(response)
   except OSError:pass
   finally:server.close()
  def relay():
   try:g.pump_guest_ssh(peer,incoming_r,outgoing_w,**limits)
   except (ValueError,OSError) as error:errors.append(error)
   finally:os.close(incoming_r);os.close(outgoing_w)
  remote_thread=threading.Thread(target=remote);relay_thread=threading.Thread(target=relay)
  remote_thread.start();relay_thread.start()
  try:
   offset=0
   while offset<len(payload):offset+=os.write(incoming_w,payload[offset:])
   os.close(incoming_w);incoming_w=None
   result=bytearray()
   while True:
    chunk=os.read(outgoing_r,65536)
    if not chunk:break
    result.extend(chunk)
   relay_thread.join(3);remote_thread.join(3)
   self.assertFalse(relay_thread.is_alive());self.assertFalse(remote_thread.is_alive())
   return bytes(result),received,errors
  finally:
   if incoming_w is not None:os.close(incoming_w)
   os.close(outgoing_r)
 def test_real_loopback_backpressure_and_stdin_halfclose(self):
  payload=bytes(range(256))*1000;reply=b'peer-response'+payload[::-1]
  output,received,errors=self.pump(payload,reply,lifetime=3)
  self.assertEqual(errors,[]);self.assertEqual(received,[payload]);self.assertEqual(output,reply)
 def test_byte_limit_and_deadline_close_fail_without_retry(self):
  _,_,errors=self.pump(b'',b'x'*100,byte_limit=20,lifetime=2)
  self.assertTrue(any(isinstance(error,ValueError) for error in errors))
  _,_,errors=self.pump(b'x'*100,b'',byte_limit=20,lifetime=2)
  self.assertTrue(any(isinstance(error,ValueError) for error in errors))
  read,write=os.pipe();output_r,output_w=os.pipe();a,c=socket.socketpair()
  try:
   with self.assertRaisesRegex(ValueError,'lifetime'):g.pump_guest_ssh(a,read,output_w,lifetime=0.01)
  finally:
   c.close()
   for fd in (read,write,output_r,output_w):os.close(fd)
 def test_guest_local_public_key_is_checked_without_reading_private_keys(self):
  import stat
  metadata=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_nlink=1,st_size=len(PUBLIC)+10)
  with patch.object(Path,'lstat',return_value=metadata),patch.object(Path,'resolve',lambda path:path), \
       patch.object(Path,'read_text',return_value=PUBLIC+' guest@test\n') as read:
   b.verify_guest_local_ssh(BINDING)
   read.assert_called_once_with(encoding='ascii')
   read.return_value='ssh-ed25519 '+base64.b64encode(RAW[:-1]+b'z').decode()
   with self.assertRaisesRegex(ValueError,'identity differs'):b.verify_guest_local_ssh(BINDING)
   metadata.st_mode=stat.S_IFLNK|0o777
   with self.assertRaisesRegex(ValueError,'unsafe'):b.verify_guest_local_ssh(BINDING)

 def test_logical_guest_scope_preserves_physical_host_and_rejects_forgery(self):
  helper=authorization_fixture.OperatorAuthorizationTests();doc,_=helper.document();legacy=copy.deepcopy(doc)
  raw,pin=helper.encode(doc);self.assertEqual(b.authorization_document(raw,pin,1000),legacy)
  doc['target']['guest']=BINDING
  raw,pin=helper.encode(doc);self.assertEqual(b.authorization_document(raw,pin,1000)['target']['guest'],BINDING)
  self.assertEqual(doc['target']['host_key'],legacy['target']['host_key'])
  for field,value in [('guest_id','../other'),('create_request_sha256','B'*64),('ssh_host_fingerprint','SHA256:wrong'),('unknown',1)]:
   bad=copy.deepcopy(doc);bad['target']['guest'][field]=value;raw,pin=helper.encode(bad)
   with self.assertRaises(ValueError):b.authorization_document(raw,pin,1000)

if __name__=='__main__':unittest.main()
