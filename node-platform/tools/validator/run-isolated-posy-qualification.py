#!/usr/bin/env python3
"""Run retained native fixtures in sealed Linux namespaces, using exact candidate bytes.
Requires an externally authorized root runner. No SSH, password handling, source
copies, Docker or key generation. The provider is simulated; Gate E remains false.
"""
import argparse
import base64
import concurrent.futures
from contextlib import contextmanager
import hashlib
import http.server
import http.client
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import struct
import sys
import threading
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
MAX=4*1024*1024
PROCESSING_PROFILE="etdag-async-processing-v1"

def processing_export_environment(environment, async_processing):
    """Only an explicit flag selects a fresh signed processing authority."""
    environment=dict(environment)
    environment.pop("SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE",None)
    if async_processing:
        environment["SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE"]=PROCESSING_PROFILE
    return environment

def require_fixture_profile(status, authority, async_processing):
    """Check routing against retained authority; never alter its signed bytes.

    Native launch authenticates the authority signature. This check prevents a
    traffic adapter mismatch before launch; export-status is not authority.
    """
    policy=authority["payload"]["protected"]
    expected=(2,"processing_groups_v1") if async_processing else (1,"vc_event_context_v1")
    if ((policy.get("version"),policy.get("cutoff_relationship"))!=expected
            or authority["payload"].get("network_id")!=status.get("network_id")):
        raise ValueError("explicit traffic profile differs from retained signed fixture authority")
    return {"processing_profile_id":PROCESSING_PROFILE if async_processing else None,
        "protected_policy_version":expected[0],"protected_cutoff_relationship":expected[1]}

def processing_traffic_arguments(async_processing):
    return ["--async-processing"] if async_processing else []

def configure_processing_resources(configs, async_processing, budget, retention, fresh):
    """Explicit fresh local limits, independent of the outer physical cgroup.

    Retained state/configuration is never rewritten by this activation helper.
    Native pruning continues to preserve pending proofs and finality fences.
    """
    if not async_processing:
        if budget is not None or retention is not None:
            raise ValueError("processing resource options require explicit async mode")
        return {}
    if budget!=1073741824 or retention!=64:
        raise ValueError("async qualification requires explicit1GiB per-node accounting and64-block retention")
    selected=[]
    for path in configs:
        config=read(path);storage=config["storage"]
        if not fresh and (storage.get("world_memory_budget_bytes")!=budget
                or storage.get("prune_finalized_history_after_blocks")!=retention):
            raise ValueError("retained async resource configuration differs; refusing rewrite")
        selected.append((path,config))
    if fresh:
        for path,config in selected:
            config["storage"].update(world_memory_budget_bytes=budget,prune_finalized_history_after_blocks=retention)
            with path.open("w") as output:
                json.dump(config,output,sort_keys=True,indent=2);output.write("\n");output.flush();os.fsync(output.fileno())
    return {"per_node_world_accounting_limit_bytes":budget,"retention_blocks":retention,
        "accounting_scope":"independent per native process; physical shared cgroup enforced separately"}

def linux_elf(path):
    """Reject truncated, zero-filled or wrong-architecture link outputs before custody work."""
    if path.is_symlink() or not path.is_file(): raise ValueError("regular Linux ELF required: "+str(path))
    size=path.stat().st_size
    with path.open("rb") as source:
        header=source.read(64)
        if len(header)!=64 or header[:7]!=b"\x7fELF\x02\x01\x01": raise ValueError("invalid Linux ELF header: "+str(path))
        fields=struct.unpack("<HHIQQQIHHHHHH",header[16:])
        kind,machine,version,entry,phoff,_,_,ehsize,phsize,phnum,_,_,_=fields
        if kind not in (2,3) or machine!=62 or version!=1 or ehsize!=64 or phsize!=56 or not 1<=phnum<=1024 or phoff<64 or phoff+phsize*phnum>size:
            raise ValueError("invalid x86-64 ELF program table: "+str(path))
        source.seek(phoff);programs=source.read(phsize*phnum); executable=False
        for index in range(phnum):
            segment,flags,offset,address,_,filesz,memsz,alignment=struct.unpack_from("<IIQQQQQQ",programs,index*phsize)
            if offset+filesz>size or (segment==1 and filesz>memsz): raise ValueError("truncated Linux ELF segment: "+str(path))
            if segment==1 and flags&1 and filesz>0 and address<=entry<address+memsz: executable=True
        if not executable: raise ValueError("Linux ELF executable entry segment missing: "+str(path))

def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>64*1024*1024: raise ValueError("bounded regular input required")
    return json.loads(path.read_text())

def read_artifact_pins(path):
    """Retain exact artifact pins without keeping complete source inventories.

    Both custody checks still independently read the original bounded file. The
    launcher separately authenticates that complete file using its SHA3 pin.
    """
    document=read(path)
    def pin(value):
        return {name:value[name] for name in ("length","sha3_256")}
    return {"artifact":pin(document["artifact"]),
        "companions":{name:pin(document["companions"][name]) for name in
            ("synergy-keytool","synergy-genesis","synergy-fixture-exporter")}}

def hash_file(path):
    h=hashlib.sha3_256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1048576),b""): h.update(b)
    return h.hexdigest()

def save(path,value):
    with path.open("x") as f: json.dump(value,f,sort_keys=True,indent=2); f.write("\n")
    path.chmod(0o600)

@contextmanager
def retain_native_observation_evidence(path, snapshot):
    """Persist bounded public observations on success, failure, or interruption.

    A failed funded phase is retained as failed evidence, never qualification.
    Saving cannot replace the original failure with an unrelated write error.
    """
    failure = None
    try:
        yield
    except BaseException as error:
        failure = type(error).__name__
        raise
    finally:
        try:
            value = snapshot()
            value.update(run_status="failed" if failure else "completed",
                         failure_type=failure, GateD_qualified=False, GateE_qualified=False)
            encoded = json.dumps(value, sort_keys=True, indent=2).encode()+b"\n"
            # 8 MiB compact sample collection can expand when pretty printed.
            if len(encoded)>32*1024*1024:
                raise ValueError("native observation artifact exceeds 32 MiB bound")
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"wb") as output:
                output.write(encoded);output.flush();os.fsync(output.fileno())
        except Exception:
            if failure is None:raise
            print("Native observation evidence could not be persisted; original failure retained.",file=sys.stderr)

def run(*args):
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL,timeout=10)

def stop(process):
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)

def stop_owned_launcher_group(process):
    # The exact session created by this invocation owns all its native signers.
    # A launcher exit alone does not prove its children stopped.
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGKILL):
        try: os.killpg(process.pid,sig)
        except ProcessLookupError: break
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: continue
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        break

def require_thread_network_namespace():
    # Linux setns(CLONE_NEWNET) affects only the calling kernel thread.
    # Never fall back to spawning a subprocess for each RPC.
    if sys.platform != "linux" or not callable(getattr(os,"setns",None)) or not hasattr(os,"CLONE_NEWNET"):
        raise RuntimeError("isolated relay requires Linux thread-local network setns")

@contextmanager
def relay_network_namespace(target_fd):
    require_thread_network_namespace()
    # /proc/self/ns/net names the process leader; a request thread must restore
    # its own original namespace, including when it inherited another namespace.
    original=os.open("/proc/thread-self/ns/net",os.O_RDONLY|os.O_CLOEXEC)
    try:
        try:
            os.setns(target_fd,os.CLONE_NEWNET)
            yield
        finally:
            os.setns(original,os.CLONE_NEWNET)
    finally:
        os.close(original)

def relay_native_rpc(target_fd,index,body):
    if type(index) is not int or not 0<=index<5 or not 0<len(body)<=1024*1024:
        raise ValueError("bounded native relay request required")
    with relay_network_namespace(target_fd):
        connection=http.client.HTTPConnection("127.0.0.1",8545+index,timeout=10)
        try:
            connection.request("POST","/",body=body,headers={"Content-Type":"application/json"})
            response=connection.getresponse()
            payload=response.read(MAX+1)
            if response.status!=200 or len(payload)>MAX:
                raise ValueError("native RPC relay failure")
        finally:
            # Destroy the socket before restoring this request thread. No global
            # urllib opener, proxy lookup, or reusable cross-namespace socket.
            connection.close()
    return payload

class Relay(http.server.ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,index,pid):
        require_thread_network_namespace()
        if address[0]!="127.0.0.1" or type(index) is not int or not 0<=index<5 or type(pid) is not int or pid<=0:
            raise ValueError("isolated loopback relay identity required")
        self.index=index; self.pid=pid; self.slots=threading.BoundedSemaphore(32)
        self.namespace_lock=threading.Lock();self.request_namespace=threading.local()
        self.namespace_fd=os.open(f"/proc/{pid}/ns/net",os.O_RDONLY|os.O_CLOEXEC)
        try: super().__init__(address,RelayHandler)
        except BaseException:
            if self.namespace_fd is not None:
                os.close(self.namespace_fd);self.namespace_fd=None
            raise
    def server_close(self):
        try: super().server_close()
        finally:
            with self.namespace_lock:
                if self.namespace_fd is not None:
                    os.close(self.namespace_fd);self.namespace_fd=None
    def process_request(self,request,address):
        if not self.slots.acquire(False): self.shutdown_request(request); return
        namespace_fd=None
        try:
            # Pin this request before dispatch. Shutdown may close the server's
            # descriptor while daemon workers are still finishing bounded IO.
            with self.namespace_lock:
                if self.namespace_fd is None:raise RuntimeError("isolated relay closed")
                namespace_fd=os.dup(self.namespace_fd)
            worker=threading.Thread(target=self.process_request_thread,args=(request,address,namespace_fd),daemon=True)
            worker.start()
        except BaseException:
            if namespace_fd is not None:os.close(namespace_fd)
            self.slots.release();raise
    def process_request_thread(self,request,address,namespace_fd):
        self.request_namespace.fd=namespace_fd
        try: super().process_request_thread(request,address)
        finally:
            del self.request_namespace.fd
            os.close(namespace_fd)
            self.slots.release()

class RelayHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def setup(self):
        self.request.settimeout(12)
        super().setup()
    def do_POST(self):
        try:
            length=int(self.headers.get("Content-Length","0"))
            if not 0<length<=1024*1024: raise ValueError("RPC request size")
            body=self.rfile.read(length)
            if len(body)!=length: raise ValueError("incomplete request")
            payload=relay_native_rpc(self.server.request_namespace.fd,self.server.index,body)
            self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload)
        except Exception:
            self.close_connection=True
            self.send_error(503,"isolated native RPC unavailable")

def capacity_stages(maximum_rate):
    """Explicit tested-rate ladder; a clean declared ceiling is not maximum TPS."""
    if type(maximum_rate) is not int or not 2<=maximum_rate<=128 or maximum_rate & (maximum_rate-1):
        raise ValueError("capacity ceiling must be a declared power of two in 2..128 TPS")
    stages=[("steady-state-transfer",1,1,1),("baseline-30",1,30,30),("baseline-600",1,600,600)]
    rate=2
    while rate<=maximum_rate:
        stages.append(("offered-"+str(rate),rate,120,rate*120));rate*=2
    stages.append(("highest-clean-600",maximum_rate,600,maximum_rate*600))
    return stages

class NativeObservationStream:
    """Canonical public stream with bounded disk and one complete frame at a time."""
    def __init__(self,path,budget=64*1024*1024):
        self.path=path;self.budget=budget;self.bytes=0;self.samples=0
        self.digest=hashlib.sha3_256()
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        self.output=os.fdopen(fd,"wb")
    def append(self,item):
        encoded=json.dumps(item,sort_keys=True,separators=(",",":")).encode()+b"\n"
        if len(encoded)>1024*1024 or self.bytes+len(encoded)>self.budget:
            raise ValueError("native observation stream evidence budget exhausted")
        if shutil.disk_usage(self.path.parent).free<len(encoded)+1024**3:
            raise ValueError("native observation stream filesystem reserve exhausted")
        self.output.write(encoded);self.output.flush()
        self.digest.update(encoded);self.bytes+=len(encoded);self.samples+=1
    def close(self):
        if not self.output.closed:
            self.output.flush();os.fsync(self.output.fileno());self.output.close()
    def summary(self):
        return {"path":str(self.path),"samples":self.samples,"bytes":self.bytes,
            "budget_bytes":self.budget,"sha3_256":self.digest.hexdigest(),"closed":self.output.closed}

def traffic_schedule(mode,capacity_maximum=8):
    """Declare the workload before launch and reserve its full drain before faults."""
    if mode=="capacity":
        stages=capacity_stages(capacity_maximum)
    elif mode=="memory":
        stages=[("steady-state-transfer",1,1,1),("funded-memory-30",None,300,30)]
    elif mode=="diagnostic":
        stages=[("steady-state-transfer",1,1,1),("baseline-30",1,30,30)]
    else:
        raise ValueError("unknown traffic schedule")
    budget=sum(duration+90 for _,_,duration,_ in stages)+20
    # Scheduled workloads finish their entire clean interval before the outage.
    return stages,budget,(210 if mode=="diagnostic" else budget+30),(None if mode=="diagnostic" else budget+180)

def traffic_stage_arguments(mode,name,rate,duration,count):
    closed=mode=="memory" and name=="funded-memory-30"
    options=["--workload-mode","closed-loop-memory"] if closed else []
    if not closed:
        options += ["--rate-tps",str(rate)]
    return options+["--duration-seconds",str(duration),"--max-tx",str(count)]

def validate_scheduled_traffic_result(mode,name,count,result):
    if mode=="diagnostic":
        return
    if (result.get("status")!="completed" or result.get("finalized_transactions")!=count
            or result.get("generator_limited") is True or result.get("generator_missed_offered_slots",0)):
        raise RuntimeError("traffic stage incomplete or generator-limited; workload remains unqualified")
    if mode=="memory" and name=="funded-memory-30":
        if (result.get("workload_mode")!="closed-loop-memory"
                or result.get("requested_transactions")!=count
                or result.get("attempted_transactions")!=count
                or result.get("submitted_transactions")!=count
                or result.get("remaining_in_flight")!=0
                or result.get("wallet_effects_verified_all_five") is not True
                or result.get("workload_deadline_seconds")!=300
                or result.get("workload_deadline_met") is not True
                or result.get("TPS_qualified") is not False
                or result.get("capacity_result") is not False
                or result.get("offered_rate_tps") is not None
                or result.get("generator_missed_offered_slots") is not None):
            raise RuntimeError("closed-loop memory cohort, deadline or all-five effects unqualified")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("fixture","binary","keytool","genesis","provenance","fixture-exporter"): parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--launcher",type=Path,required=True)
    parser.add_argument("--baseline-harness",type=Path,required=True)
    parser.add_argument("--transport-secret",type=Path)
    parser.add_argument("--export-fresh",action="store_true",help="native exporter creates a new private synthetic authority/fixture")
    parser.add_argument("--async-processing",action="store_true",help="explicit approved async signed fixture and genuine encrypted processing RPC workload")
    parser.add_argument("--world-memory-budget-bytes",type=int,help="explicit fresh async per-node accounting pool; physical cgroup is separate")
    parser.add_argument("--retention-blocks",type=int,help="explicit fresh async finalized retention; pending native proof pins remain protected")
    parser.add_argument("--wallet-pool-size",type=int,default=32)
    parser.add_argument("--epoch-end-height",type=int,default=1000000,help="explicit fresh isolated signed authority horizon; never extends active authority")
    parser.add_argument("--run-id",required=True)
    parser.add_argument("--fault-kind",choices=["restart","quorum"],required=True)
    parser.add_argument("--duration-seconds",type=int,default=360)
    parser.add_argument("--traffic-mode",choices=["diagnostic","memory","capacity"],default="diagnostic",
        help="memory schedules30 proof-verified funded transfers within300s before restart; capacity runs the full ladder; both derive bounded lifetimes, no24h soak support")
    parser.add_argument("--capacity-max-rate",type=int,default=8,help="declared capacity test ceiling, power of two2..128; never assumed chain maximum")
    parser.add_argument("--gas-limit",type=int,required=True)
    parser.add_argument("--max-fee-per-gas-nwei",type=int,required=True)
    parser.add_argument("--gas-class-units",type=int,required=True)
    parser.add_argument("--egress-delay-ms",type=int,default=0)
    parser.add_argument("--egress-loss-percent",type=float,default=0)
    parser.add_argument("--egress-reorder-percent",type=float,default=0)
    parser.add_argument("--partition-validator-index",type=int,choices=range(5))
    parser.add_argument("--partition-start-seconds",type=int,default=140)
    parser.add_argument("--partition-duration-seconds",type=int,default=20)
    parser.add_argument("--execute",action="store_true")
    args=parser.parse_args()
    configure_processing_resources([],args.async_processing,args.world_memory_budget_bytes,args.retention_blocks,False)
    if args.traffic_mode=="memory" and args.wallet_pool_size!=4:
        parser.error("closed-loop memory qualification requires exactly four wallets")
    stages,traffic_budget,fault_stop,lifetime=traffic_schedule(args.traffic_mode,args.capacity_max_rate)
    if lifetime is not None:
        args.duration_seconds=lifetime
    if not 0<=args.egress_delay_ms<=1000 or not 0<=args.egress_loss_percent<=10 or not 0<=args.egress_reorder_percent<=50 or (args.egress_reorder_percent and not args.egress_delay_ms): parser.error("bounded declared native netem profile required")
    if args.traffic_mode in ("memory","capacity") and args.partition_validator_index is not None:
        parser.error("scheduled memory/capacity traffic requires a clean interval; run partition qualification separately")
    if args.partition_validator_index is not None and not 120<=args.partition_start_seconds<args.partition_start_seconds+args.partition_duration_seconds<200: parser.error("partition must heal before retained-journal recovery schedule")
    os.umask(0o077)
    if not args.execute: parser.error("explicit --execute required; script performs isolated host mutations")
    require_thread_network_namespace()
    if sys.platform!="linux" or os.geteuid()!=0 or os.stat("/proc/self/ns/net").st_ino==os.stat("/proc/1/ns/net").st_ino: parser.error("externally authorized root runner inside new unshare --net required")
    if not 300<=args.duration_seconds<=3600 or not args.run_id.replace("-","").replace("_","").isalnum() or len(args.run_id)>128: parser.error("bounded run identity/duration required")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    candidate_root=args.fixture.absolute()
    allowed_parents=(Path("/tmp"),Path("/var/tmp"),ROOT/"target")
    if candidate_root.parent.resolve() not in tuple(p.resolve() for p in allowed_parents) or not candidate_root.name.startswith("posy-isolated-") or args.fixture.is_symlink(): parser.error("dedicated isolated fixture path required before export")
    early_provenance=read_artifact_pins(args.provenance)
    for name,path in (("synergy-node",args.binary),("synergy-keytool",args.keytool),("synergy-genesis",args.genesis),("synergy-fixture-exporter",args.fixture_exporter)):
        linux_elf(path)
        expected=early_provenance["artifact"] if name=="synergy-node" else early_provenance["companions"][name]
        if path.is_symlink() or not path.is_file() or hash_file(path)!=expected["sha3_256"] or path.stat().st_size!=expected["length"]: raise ValueError("exact candidate artifact mismatch before fixture issuance")
    if args.export_fresh:
        if args.fixture.exists() or args.transport_secret is not None or not 1<=args.wallet_pool_size<=64 or not 10000<=args.epoch_end_height<=10000000: parser.error("fresh native export needs absent fixture and bounded wallet pool")
        key=Ed25519PrivateKey.generate()
        public="ed25519:"+base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        provider_digest=hashlib.sha256(b"sealed Linux qualification simulated provider v1").hexdigest()
        env=dict(os.environ,SYNERGY_POSY_ISOLATED_FIXTURE_ROOT=str(args.fixture),SYNERGY_POSY_ISOLATED_ATTESTATION_PUBLIC_KEY=public,SYNERGY_POSY_ISOLATED_PROVIDER_SHA256=provider_digest,SYNERGY_POSY_ISOLATED_WALLET_POOL_SIZE=str(args.wallet_pool_size),SYNERGY_POSY_ISOLATED_EPOCH_END_HEIGHT=str(args.epoch_end_height))
        env=processing_export_environment(env,args.async_processing)
        subprocess.run([str(args.fixture_exporter.resolve()),"services::socket_qualification::export_isolated_posy_process_fixture","--ignored","--exact","--test-threads=1"],env=env,check=True,timeout=300)
        if not args.fixture.exists(): raise ValueError("native export did not create fixture")
        args.transport_secret=args.fixture/"transport-attestation.secret.bin"
        seed=bytearray(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
        fd=os.open(args.transport_secret,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as output: output.write(seed)
        seed[:]=b"\0"*len(seed);del key
    if args.transport_secret is None: parser.error("existing sole synthetic transport custody required")
    root=args.fixture.resolve(strict=True)
    if root.parent not in (Path("/tmp"),Path("/var/tmp"),ROOT/"target") or not root.name.startswith("posy-isolated-") or (root.stat().st_mode&0o777)!=0o700: parser.error("dedicated private native fixture required")
    status=read(root/"export-status.json")
    if status.get("synthetic_keys_only") is not True or status.get("full_signed_genesis") is not True: parser.error("genuine native synthetic fixture required")
    profile=require_fixture_profile(status,read(root/"authority.json"),args.async_processing)
    evidence=root/("qualification-"+args.run_id)
    evidence.mkdir(mode=0o700) # Fresh evidence, retained authority and custody; no copies.
    provenance=read_artifact_pins(args.provenance)
    artifacts={"synergy-node":args.binary,"synergy-keytool":args.keytool,"synergy-genesis":args.genesis,"synergy-fixture-exporter":args.fixture_exporter}
    for name,path in artifacts.items():
        linux_elf(path)
        expected=provenance["artifact"] if name=="synergy-node" else provenance["companions"][name]
        if path.is_symlink() or hash_file(path)!=expected["sha3_256"] or path.stat().st_size!=expected["length"]: raise ValueError("exact candidate artifact mismatch")
    # Consume only already-issued synthetic attestation custody, never generate a key.
    secret=args.transport_secret.resolve(strict=True)
    if root not in secret.parents or secret.is_symlink() or secret.stat().st_size!=32 or secret.stat().st_mode&0o777!=0o600: raise ValueError("fixture-local sole synthetic transport seed required")
    seed=bytearray(secret.read_bytes());key=Ed25519PrivateKey.from_private_bytes(bytes(seed));seed[:]=b"\0"*len(seed)
    pin="ed25519:"+base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
    configs=[root/f"node-{i}"/"config.json" for i in range(5)]
    profile.update(configure_processing_resources(configs,args.async_processing,
        args.world_memory_budget_bytes,args.retention_blocks,args.export_fresh))
    for config in configs:
        if read(config)["vpn"]["attestation_public_key"]!=pin: raise ValueError("native attestation pin mismatch")
    signed=root/"transport-signed.json"
    if not signed.exists():
        unsigned=read(root/"transport-unsigned.json")
        signature=key.sign(json.dumps(unsigned,sort_keys=True,separators=(",",":")).encode())
        save(signed,dict(unsigned,signature="ed25519:"+base64.b64encode(signature).decode()))
    del key
    provider=root/"simulated-provider.py"
    if not provider.exists():
        provider.write_text("#!/usr/bin/python3\nimport os,json\nfrom pathlib import Path\np=Path(os.environ['SYNERGY_POSY_QUALIFICATION_TIMING_CONFIG']).parent/'config.json'\nc=json.loads(p.read_text());ip=c['network']['listen_addresses'][0].split(':')[0]\nprint('Management: Connected\\nSignal: Connected\\nNetBird IP: '+ip)\n")
        provider.chmod(0o700)
    manifest=dict(fixture_kind=status["fixture_kind"],synthetic_keys_only=True,full_signed_genesis=True,diagnostic_only=True,
        network_id=status["network_id"],isolated_network="10.69.10.0/24",binary_path=str(args.binary.resolve()),artifact_sha3_256=hash_file(args.binary),
        genesis_path=str(root/"genesis.sgen"),run_id=args.run_id,simulated_provider_binary=str(provider),
        network_namespace_inode=os.stat("/proc/self/ns/net").st_ino,bridge_interfaces=["br0",*[f"pv{i}" for i in range(5)]],node_namespaces={},nodes=[],
        source_provenance=[{"path":str(Path(__file__).resolve()),"sha3_256":hash_file(Path(__file__))}])
    manifest.update(profile)
    traffic_sources=[args.baseline_harness.resolve()]
    if args.async_processing:
        traffic_sources.append(args.baseline_harness.resolve().with_name("posy_async_rpc_baseline.py"))
    for source in traffic_sources:
        if source.is_symlink() or not source.is_file():raise ValueError("regular traffic adapter source required")
        manifest["source_provenance"].append({"path":str(source),"sha3_256":hash_file(source)})
    keepers=[]; relays=[]; launcher=None; sampler_stop=threading.Event(); sampler=None; partition=None; partition_stop=threading.Event();partition_events=[];observations=[]; observation_failures=[]
    log=None;err=None;observation_stream=None;stage_results=[]
    def observation_snapshot():
        return {"observations":list(observations),"failures":list(observation_failures),
            "artifact":provenance["artifact"],"network_id":manifest["network_id"],
            "partition_events":list(partition_events),
            "sampler_stopped":sampler is None or not sampler.is_alive(),
            "observation_limit":3600,"compact_observation_byte_limit":8*1024*1024,
            "traffic_mode":args.traffic_mode,"completed_traffic_stages":list(stage_results),
            "transaction_profile":profile,
            "stream":observation_stream.summary() if observation_stream is not None else None,
            "observations_scope":"last128 samples; fullstream authoritative public evidence" if observation_stream is not None else "all retained samples",
            "qualification_limit":"native observations retained even when funded phase fails; independent qualification still required",
            "network_impairment":{"egress_delay_ms":args.egress_delay_ms,
                "egress_loss_percent":args.egress_loss_percent,"egress_reorder_percent":args.egress_reorder_percent,
                "classification":"whole authenticated transport; not protocol-selective dropping"}}
    with retain_native_observation_evidence(evidence/"native-observations.json",observation_snapshot):
        try:
            run("ip","link","set","lo","up");run("ip","link","add","br0","type","bridge");run("sysctl","-q","-w","net.ipv6.conf.br0.disable_ipv6=1");run("ip","link","set","br0","up")
            for i,config in enumerate(configs):
                cfg=read(config);identity=read(Path(cfg["public_identity_path"]))["node_address"]
                keeper=subprocess.Popen(["unshare","--net","sleep",str(args.duration_seconds+90)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);keepers.append(keeper)
                deadline=time.monotonic()+5
                while os.stat(f"/proc/{keeper.pid}/ns/net").st_ino==manifest["network_namespace_inode"]:
                    if time.monotonic()>deadline: raise RuntimeError("namespace creation deadline")
                    time.sleep(.01)
                host=f"pv{i}";peer=f"cv{i}";run("ip","link","add",host,"type","veth","peer","name",peer);run("ip","link","set",peer,"netns",str(keeper.pid));run("ip","link","set",host,"master","br0");run("sysctl","-q","-w",f"net.ipv6.conf.{host}.disable_ipv6=1");run("ip","link","set",host,"up")
                prefix=["nsenter","-t",str(keeper.pid),"-n"]
                run(*prefix,"ip","link","set","lo","up");run(*prefix,"ip","link","set",peer,"name","wt0");run(*prefix,"sysctl","-q","-w","net.ipv6.conf.wt0.disable_ipv6=1");run(*prefix,"ip","addr","add",cfg["network"]["listen_addresses"][0].split(":")[0]+"/24","dev","wt0");run(*prefix,"ip","link","set","wt0","up")
                if args.egress_delay_ms or args.egress_loss_percent:
                    impairment=["tc","qdisc","add","dev","wt0","root","netem"]
                    if args.egress_delay_ms: impairment.extend(["delay",str(args.egress_delay_ms)+"ms"])
                    if args.egress_loss_percent: impairment.extend(["loss",str(args.egress_loss_percent)+"%"])
                    if args.egress_reorder_percent: impairment.extend(["reorder",str(args.egress_reorder_percent)+"%","gap","5"])
                    run(*prefix,*impairment)
                timing=config.parent/(args.run_id+"-timing.json")
                save(timing,{"run_id":args.run_id,"artifact_sha3_256":manifest["artifact_sha3_256"],"node_id":cfg["node_name"],"clock_id":args.run_id+"-initial","output":str(config.parent/(args.run_id+"-timing.jsonl"))})
                manifest["nodes"].append({"id":identity,"config_path":str(config),"timing_config_path":str(timing)})
                manifest["node_namespaces"][identity]={"keeper_pid":keeper.pid,"network_namespace_inode":os.stat(f"/proc/{keeper.pid}/ns/net").st_ino}
                relay=Relay(("127.0.0.1",18545+i),i,keeper.pid);relays.append(relay);threading.Thread(target=relay.serve_forever,daemon=True).start()
            # Fault schedules restore the same custody and journals; exact old signer must stop first.
            restart_entries=[]
            indices=[4] if args.fault_kind=="restart" else [3,4]
            for order,index in enumerate(indices):
                cfg=read(configs[index]);replacement=configs[index].parent/(args.run_id+"-restart-config.json")
                cfg["admin_socket_path"]=str(configs[index].parent/(args.run_id+"-restart.sock"));save(replacement,cfg)
                timing=configs[index].parent/(args.run_id+"-restart-timing.json")
                save(timing,{"run_id":args.run_id,"artifact_sha3_256":manifest["artifact_sha3_256"],"node_id":cfg["node_name"],"clock_id":args.run_id+"-restart","output":str(configs[index].parent/(args.run_id+"-restart-timing.jsonl"))})
                restart_entries.append({"kind":"validator_restart","node_id":manifest["nodes"][index]["id"],"stop_after_seconds":fault_stop,"restart_after_seconds":fault_stop+30+30*order,"restart_config_path":str(replacement),"restart_timing_config_path":str(timing)})
            manifest.update(resume_authority_network_id=manifest["network_id"],safety_journal_contract="native-retained-journals-v1")
            manifest["fault_schedule"]=restart_entries if args.fault_kind=="restart" else [{"kind":"quorum_recovery","validators":restart_entries,"halt_settle_seconds":10,"halt_observe_seconds":10}]
            path=root/(args.run_id+"-qualification-manifest.json")
            save(path,manifest)
            command=[sys.executable,str(args.launcher.resolve()),str(path),"--build-provenance",str(args.provenance),"--expected-provenance-sha3",hash_file(args.provenance),"--genesis-binary",str(args.genesis),"--expected-genesis-sha3",hash_file(args.genesis),"--require-genuine-genesis","--execute","--duration-seconds",str(args.duration_seconds)]
            if any(Path(read(c)["storage"]["data_directory"]).exists() for c in configs): command.append("--resume-existing-state")
            log=(evidence/"launcher.stdout.json").open("xb");err=(evidence/"launcher.stderr.log").open("xb")
            launcher=subprocess.Popen(command,stdout=log,stderr=err,start_new_session=True)
            observation_start=time.monotonic()
            observation_policy=read(root/"authority.json")["payload"]
            if args.traffic_mode in ("memory","capacity"):
                observation_stream=NativeObservationStream(evidence/"native-observations.jsonl")
                save(evidence/"traffic-plan.json",{"mode":args.traffic_mode,"stages":[{"name":name,"offered_tps":rate,"workload_mode":"closed-loop-memory" if args.traffic_mode=="memory" and name=="funded-memory-30" else "offered-rate","duration_seconds":duration,"transactions":count} for name,rate,duration,count in stages],
                    "transaction_profile":profile,
                    "fault_stop_seconds":fault_stop,"isolated_lifetime_seconds":args.duration_seconds,
                    "capacity_qualified":False,"live_soak_authorized":False,"declared_ceiling_is_not_network_maximum":True})
            def native_view(index,params):
                start=time.monotonic()-observation_start
                body=json.dumps({"jsonrpc":"2.0","id":1,"method":"synergy_chainTelemetry","params":params}).encode()
                with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{18545+index}",body,{"Content-Type":"application/json"}),timeout=15) as response:
                    raw=response.read(MAX+1)
                if len(raw)>MAX:raise ValueError("native observation response exceeds byte bound")
                value=json.loads(raw)
                if "error" in value: raise ValueError("native telemetry failed")
                return {"query_start":start,"query_end":time.monotonic()-observation_start,"native":{key:value["result"].get(key) for key in ("finalized_height","common_finalized_commitment","network_identity","epoch")}}
            def sample_loop():
                charged=0
                sampled=0
                while not sampler_stop.is_set() and sampled<3600:
                    item={"elapsed_seconds":time.monotonic()-observation_start,"by_validator":{}}
                    def one(index):
                        try: return native_view(index,{})
                        except Exception as e: return {"error":type(e).__name__}
                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                        for index,view in enumerate(pool.map(one,range(5))): item["by_validator"][manifest["nodes"][index]["id"]]=view
                    live=[index for index,node in enumerate(manifest["nodes"]) if isinstance(item["by_validator"][node["id"]].get("native",{}).get("finalized_height"),int)]
                    if live:
                        common=min(item["by_validator"][manifest["nodes"][index]["id"]]["native"]["finalized_height"] for index in live)
                        def pin(index):
                            try: return native_view(index,{"at_height":common})
                            except Exception as e: return {"error":type(e).__name__}
                        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                            for index,view in zip(live,pool.map(pin,live)): item["by_validator"][manifest["nodes"][index]["id"]]["pinned_native"]=view
                    horizon=observation_policy["epoch_end_height"];lookahead=observation_policy["protected"]["parameters"]["target_height_offset"]
                    if any(item["by_validator"][manifest["nodes"][index]["id"]]["native"]["finalized_height"]+2*lookahead>=horizon for index in live):
                        observation_failures.append("signed isolated authority horizon exhausted; no active extension permitted")
                        sampler_stop.set()
                    # Retain real observations, including failed RPC; no synthetic heights.
                    if observation_stream is not None:
                        try:observation_stream.append(item)
                        except Exception as error:
                            observation_failures.append("native observation stream failed: "+type(error).__name__);sampler_stop.set();break
                        observations.append(item)
                        if len(observations)>128:observations.pop(0)
                    else:
                        charged+=len(json.dumps(item))
                        if charged>8*1024*1024:
                            observation_failures.append("native observation evidence budget exhausted");sampler_stop.set();break
                        observations.append(item)
                    sampled+=1
                    sampler_stop.wait(1)
            sampler=threading.Thread(target=sample_loop);sampler.start()
            if args.partition_validator_index is not None:
                def partition_window():
                    if partition_stop.wait(args.partition_start_seconds): return
                    host=f"pv{args.partition_validator_index}"
                    try:
                        run("ip","link","set",host,"down")
                        partition_events.append({"event":"partition_started","validator_id":manifest["nodes"][args.partition_validator_index]["id"],"elapsed_seconds":time.monotonic()-observation_start})
                        partition_stop.wait(args.partition_duration_seconds)
                    except Exception as error: observation_failures.append("partition mutation failed: "+type(error).__name__)
                    finally:
                        try:
                            run("ip","link","set",host,"up")
                            partition_events.append({"event":"partition_healed","validator_id":manifest["nodes"][args.partition_validator_index]["id"],"elapsed_seconds":time.monotonic()-observation_start})
                        except Exception as error: observation_failures.append("partition heal failed: "+type(error).__name__)
                partition=threading.Thread(target=partition_window);partition.start()

            base=[sys.executable,str(args.baseline_harness.resolve()),"--network-id",manifest["network_id"],"--keytool",str(args.keytool),"--wallet-registry",str(root/"wallet-pool.json"),"--max-in-flight",str(min(32,len(read(root/"wallet-pool.json")["wallets"]))),"--receiver",read(root/"wallet/metadata.json")["receiver"],"--gas-limit",str(args.gas_limit),"--max-fee-per-gas-nwei",str(args.max_fee_per_gas_nwei),"--gas-class-units",str(args.gas_class_units),"--fee-class","0","--execute"]
            base.extend(processing_traffic_arguments(args.async_processing))
            for i in range(5): base.extend(["--validator-rpc",f"val{i+2}=http://127.0.0.1:{18545+i}"])
            # Retry only readiness observation, never resubmit an ambiguous transaction manually.
            time.sleep(10)
            if launcher.poll() is not None: raise RuntimeError("native launcher exited before funded qualification")
            for name,rate,duration,count in stages:
                if observation_failures or launcher.poll() is not None:
                    raise RuntimeError("native observation/launcher failure before traffic stage")
                if args.traffic_mode in ("memory","capacity") and time.monotonic()-observation_start+duration+90>=fault_stop:
                    raise RuntimeError("declared clean traffic budget exhausted before fault schedule; no overlap allowed")
                output=evidence/(name+".json")
                subprocess.run(base+traffic_stage_arguments(args.traffic_mode,name,rate,duration,count)+["--output",str(output)],check=True,timeout=duration+90)
                result=read(output)
                validate_scheduled_traffic_result(args.traffic_mode,name,count,result)
                stage_results.append({"name":name,"report_path":str(output),"sha3_256":hash_file(output),"offered_tps":rate,"workload_mode":result.get("workload_mode","offered-rate"),"duration_seconds":duration,"finalized_transactions":result.get("finalized_transactions")})
            launcher.wait(timeout=args.duration_seconds+60)
            sampler_stop.set();sampler.join(timeout=20)
            if observation_failures: raise RuntimeError("native qualification observation failed: "+observation_failures[0])
            log.close();err.close()
            if launcher.returncode: raise RuntimeError("native qualification launcher failed")
            for index in range(5):
                for name in ("qualification-diagnostic-tail.log","qualification-restart-diagnostic-tail.log"):
                    tail=root/f"node-{index}"/name
                    if tail.exists(): tail.rename(evidence/f"node-{index}-{name}")
            fault_report=root/"qualification-fault-events.json"
            if fault_report.exists(): fault_report.rename(evidence/"qualification-fault-events.json")
            save(evidence/"run-plan-result.json",{"artifact":provenance["artifact"],"companions":provenance["companions"],"network_id":manifest["network_id"],"transaction_profile":profile,"fault_kind":args.fault_kind,"traffic_mode":args.traffic_mode,"traffic_stages":stage_results,"capacity_qualified":False,"highest_tested_clean_rate_tps":args.capacity_max_rate if args.traffic_mode=="capacity" else None,"signed_epoch_end_height":read(root/"authority.json")["payload"]["epoch_end_height"],"provider_simulated":True,"GateE_qualified":False,"GateD_qualified":False,"qualification_limit":"independent aggregation of native funded and recovery evidence still required"})
        finally:
            partition_stop.set()
            if partition is not None: partition.join(timeout=15)
            sampler_stop.set()
            if sampler is not None: sampler.join(timeout=20)
            if observation_stream is not None:
                if sampler is not None and sampler.is_alive():
                    observation_failures.append("observation sampler did not stop before stream closure")
                else:observation_stream.close()
            if launcher is not None: stop_owned_launcher_group(launcher)
            for relay in relays: relay.shutdown();relay.server_close()
            for keeper in keepers: stop(keeper)
            if log is not None:log.close()
            if err is not None:err.close()

if __name__=="__main__": main()
