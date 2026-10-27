#!/usr/bin/env python3
"""Bind complete Git-visible inputs and exact bytes to native qualification evidence.
This evidence binding check does not replace native verification or operator review.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import stat
import sys
import fcntl

def digest(path, algorithm="sha256"):
    if path.is_symlink() or not path.is_file(): raise ValueError("regular non-symlink input required")
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""): h.update(block)
    return h.hexdigest()

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

def artifact_identity(path):
    value=path.lstat()
    if not stat.S_ISREG(value.st_mode): raise ValueError("regular non-symlink artifact required: "+str(path))
    return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

def flush_artifact(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode): raise ValueError("regular artifact required")
        os.fsync(descriptor)
        if sys.platform=="darwin":
            # Darwin SDK sys/fcntl.h: F_FULLFSYNC=51 requests device-media flush.
            # Unsupported flush is a release-blocking storage boundary, never ignored.
            fcntl.fcntl(descriptor,getattr(fcntl,"F_FULLFSYNC",51))
    finally: os.close(descriptor)

def seal_artifact(path):
    """Bind only flushed ELF bytes with matching independent reads and file identities."""
    artifact_identity(path)
    flush_artifact(path)
    identity=artifact_identity(path)
    linux_elf(path)
    first=digest(path,"sha3_256")
    if artifact_identity(path)!=identity: raise ValueError("artifact changed during first sealing read: "+str(path))
    linux_elf(path)
    second=digest(path,"sha3_256")
    if artifact_identity(path)!=identity or first!=second:
        raise ValueError("artifact bytes unstable during sealing: "+str(path))
    return {"length":identity[2],"sha3_256":first}

def load(path):
    if path.stat().st_size > 64 * 1024 * 1024: raise ValueError("bounded evidence size exceeded")
    digest(path)
    return json.loads(path.read_text())

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])

def symlink_input(path,checkout,relative,ancestors=()):
    target=os.readlink(path)
    record={"path":relative,"state":"symlink_input","target":target,
            "target_sha256":hashlib.sha256(os.fsencode(target)).hexdigest()}
    try: resolved=path.resolve(strict=True)
    except (OSError,RuntimeError) as error:
        record.update(resolution="unresolved",promotion_eligible=False,reason=type(error).__name__)
        return record
    if checkout not in resolved.parents:
        record.update(resolution="outside_checkout",promotion_eligible=False)
        return record
    if resolved in ancestors:
        record.update(resolution="directory_cycle",promotion_eligible=False)
        return record
    record["resolved_path"]=resolved.relative_to(checkout).as_posix()
    record["promotion_eligible"]=True
    if resolved.is_file():
        record.update(resolution="canonical_file",length=resolved.stat().st_size,sha256=digest(resolved))
    elif resolved.is_dir():
        record.update(resolution="canonical_directory",files=[])
        # Hash the actual link-visible input tree, including ignored files. Do not
        # traverse VCS metadata, follow escaping links or silently omit missing targets.
        for child in sorted(resolved.iterdir()):
            if child.name==".git":continue
            child_relative=child.relative_to(checkout).as_posix()
            if child.is_symlink():record["files"].append(symlink_input(child,checkout,child_relative,(*ancestors,resolved)))
            elif child.is_file():record["files"].append({"path":child_relative,"length":child.stat().st_size,"sha256":digest(child)})
            elif child.is_dir():record["files"].append(directory_input(child,checkout,(*ancestors,resolved)))
            else:raise ValueError("unsupported canonical symlink input: "+child_relative)
    else:record.update(resolution="unsupported_target",promotion_eligible=False)
    return record

def directory_input(path,checkout,ancestors):
    if path in ancestors:raise ValueError("canonical input directory cycle: "+str(path.relative_to(checkout)))
    record={"path":path.relative_to(checkout).as_posix(),"state":"canonical_directory_input","files":[]}
    for child in sorted(path.iterdir()):
        if child.name==".git":continue
        relative=child.relative_to(checkout).as_posix()
        if child.is_symlink():record["files"].append(symlink_input(child,checkout,relative,(*ancestors,path)))
        elif child.is_dir():record["files"].append(directory_input(child,checkout,(*ancestors,path)))
        elif child.is_file():record["files"].append({"path":relative,"length":child.stat().st_size,"sha256":digest(child)})
        else:raise ValueError("unsupported canonical directory input: "+relative)
    return record

def inventory(root):
    paths = sorted(set(git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    records = []; recorded_paths=set()
    for raw in paths:
        raw_relative=raw.decode("utf8"); relative=Path(raw_relative).as_posix(); path=root/relative
        if raw_relative!=relative and not (path.is_dir() and raw_relative==relative+"/"):
            raise ValueError("noncanonical Git input path: "+raw_relative)
        if relative in recorded_paths: raise ValueError("duplicate canonical Git input path: "+relative)
        recorded_paths.add(relative)
        if path.is_symlink():
            records.append(symlink_input(path,root,relative));continue
        if not path.exists():
            # git ls-files includes intentionally deleted tracked entries. Record that
            # exact dirty source state instead of restoring it or silently omitting it.
            records.append({"path":relative,"state":"missing_tracked_input"})
        elif path.is_dir(): records.append({"path":relative, "submodule":inventory(path)})
        else: records.append({"path":relative, "length":path.stat().st_size, "sha256":digest(path)})
    return {"source_revision":git(root,"rev-parse","HEAD").decode().strip(),
            "clean":not bool(git(root,"status","--porcelain","--untracked-files=all")), "files":records}

def eligible_input(entry):
    if entry.get("state")=="missing_tracked_input" or entry.get("promotion_eligible") is False:return False
    return all(eligible_input(child) for child in entry.get("files",[]))

def clean(tree):
    return tree.get("clean") is True and all(eligible_input(f) and ("submodule" not in f or clean(f["submodule"])) for f in tree["files"])

def verify(provenance_path, binary, report_path):
    provenance = load(provenance_path); report = load(report_path)
    linux_elf(binary)
    artifact = seal_artifact(binary)
    if provenance.get("format_version") != 1 or provenance.get("qualification_state") != "unqualified_candidate": raise ValueError("invalid provenance")
    if artifact != provenance.get("artifact") or artifact != report.get("artifact"): raise ValueError("artifact bytes differ")
    if report.get("format_version") != 1 or report.get("provenance_sha256") != digest(provenance_path): raise ValueError("provenance binding mismatch")
    if provenance["before"] != provenance["after"] or not clean(provenance["before"]): raise ValueError("clean unchanged reviewed source required")
    if report.get("qualification_state") != "native_full_process_qualified": raise ValueError("process survival is not qualification")
    genesis = report.get("signed_genesis",{})
    if report.get("companions") != provenance.get("companions") or set(provenance.get("companions",{})) != {"synergy-keytool","synergy-genesis","synergy-fixture-exporter"}: raise ValueError("qualification companion bytes differ")
    for name, expected in provenance["companions"].items():
        companion = binary.parent/name
        linux_elf(companion)
        if seal_artifact(companion) != expected: raise ValueError("promotion companion bytes differ")
    if genesis.get("native_verified") is not True: raise ValueError("signed Genesis verification missing")
    ids = report.get("validator_ids",[])
    if len(ids) != 5 or len(set(ids)) != 5: raise ValueError("five distinct validators required")
    network = report.get("network_identity",{})
    if not all(network.get(k) for k in ("chain_id","incarnation","genesis_commitment","authority_commitment")): raise ValueError("network authority binding missing")
    for name in ("funded_steady_state","restart_rejoin","quorum_recovery"):
        scenario = report.get("scenarios",{}).get(name,{})
        commitments = scenario.get("common_finalized_commitments",[])
        if scenario.get("passed") is not True or set(scenario.get("validator_ids",[])) != set(ids): raise ValueError("native scenario missing: " + name)
        if len(commitments) != 5 or len({json.dumps(c,sort_keys=True) for c in commitments}) != 1: raise ValueError("common finalized commitments missing")
        if not all(c.get("height",0)>0 and c.get("block_id") and c.get("state_root") for c in commitments): raise ValueError("invalid commitment")
    effects = report["scenarios"]["funded_steady_state"].get("native_wallet_effects",[])
    if len(effects)!=5 or len({json.dumps(e,sort_keys=True) for e in effects})!=1: raise ValueError("identical wallet effects missing")
    if not all(e.get("applied_exactly_once") is True and e.get("receiver_credit_nwei",0)>0 and e.get("sender_nonce_delta")==e.get("finalized_transaction_count") and e.get("finalized_transaction_count",0)>0 for e in effects): raise ValueError("genuine funded execution missing")
    refs = report.get("evidence_files",[]); base=report_path.resolve().parent
    if not refs or genesis.get("evidence_path") not in {i["path"] for i in refs}: raise ValueError("native raw evidence missing")
    for item in refs:
        path = base / item["path"]
        if base not in path.resolve().parents or digest(path)!=item["sha256"]: raise ValueError("native evidence binding mismatch")
    print("Exact-byte evidence bound; protocol and operator release approval remain separate")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["inventory","assemble","verify","exporter"])
    for name in ("root","output","before","after","binary","provenance","qualification","keytool","genesis","fixture-exporter","cargo-messages"): p.add_argument("--"+name,type=Path)
    p.add_argument("--feature",action="append",default=[])
    a=p.parse_args()
    if a.mode=="exporter":
        if a.cargo_messages.stat().st_size>64*1024*1024:raise ValueError("bounded Cargo artifact messages required")
        executables=set()
        with a.cargo_messages.open() as stream:
            for line in stream:
                if len(line)>1024*1024:raise ValueError("Cargo message oversized")
                try:message=json.loads(line)
                except ValueError:continue # Cargo progress is not an artifact.
                if (message.get("reason")=="compiler-artifact" and message.get("profile",{}).get("test") is True
                        and message.get("target",{}).get("name")=="synergy-node" and message.get("executable")):
                    executables.add(message["executable"])
        if len(executables)!=1:raise ValueError("exact native fixture exporter test ELF artifact missing or ambiguous")
        exporter=Path(next(iter(executables)))
        digest(exporter)
        seal_artifact(exporter)
        print(exporter);return
    if a.mode=="inventory": result=inventory(a.root.resolve())
    elif a.mode=="assemble":
        sealed={name:seal_artifact(path) for name,path in (("synergy-node",a.binary),("synergy-keytool",a.keytool),("synergy-genesis",a.genesis),("synergy-fixture-exporter",a.fixture_exporter))}
        result={"format_version":1,"qualification_state":"unqualified_candidate","before":load(a.before),"after":load(a.after),"artifact":sealed["synergy-node"]}
        result["target"]="x86_64-unknown-linux-gnu"
        result["build_config"]={"profile":"release","package":"synergy-node","locked":True,"features":sorted(set(a.feature))}
        result["toolchain"]={tool:subprocess.check_output(command).decode().strip() for tool,command in (("rustc",["rustc","-Vv"]),("cargo",["cargo","-V"]),("cc",["cc","--version"]))}
        result["companions"]={name:sealed[name] for name in ("synergy-keytool","synergy-genesis","synergy-fixture-exporter")}
        if result["before"]!=result["after"]: raise ValueError("source changed during build")
    else:
        verify(a.provenance,a.binary,a.qualification); return
    with a.output.open("x") as f: json.dump(result,f,sort_keys=True,indent=2); f.write("\n")

if __name__=="__main__": main()
