#!/usr/bin/env python3
"""Derive exact-candidate qualification from bounded raw native five-validator proofs.
Missing observations fail closed; process survival and declared passing flags do not
supply funded execution, below-quorum safety, recovery or signed Genesis evidence.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ALIASES=[f"val{i}" for i in range(2,7)]

def load(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>64*1024*1024: raise ValueError("bounded regular native proof required")
    return json.loads(path.read_text())

def digest(path,algorithm="sha256"):
    require(not path.is_symlink() and path.is_file(),"regular raw evidence required")
    h=hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1048576),b""):h.update(chunk)
    return h.hexdigest()

def sha(path): return digest(path)


def require(condition,message):
    if not condition: raise ValueError(message)

def same(values):
    require(bool(values) and len({json.dumps(v,sort_keys=True) for v in values})==1,"native views disagree")
    return values[0]

def commitment(value):
    result={"height":value.get("height",value.get("block_height",value.get("common_height"))),"block_id":value.get("block_id",value.get("block_hash")),"state_root":value.get("state_root")}
    require(type(result["height"]) is int and result["height"]>0 and result["block_id"] and result["state_root"],"native finalized commitment missing")
    return result

def proof_stream(report,report_path):
    declared=report.get("raw_proof_stream",{})
    stream=Path(declared.get("path",""))
    if not stream.is_absolute():stream=report_path.parent/stream
    require(report_path.parent.resolve() in stream.resolve().parents,"raw proof stream escaped native run evidence directory")
    require(declared.get("complete") is True,"native proof stream was not durably closed")
    budget=declared.get("budget_bytes")
    require(type(budget) is int and 0<budget<=64*1024*1024*1024,"bounded declared native proof budget required")
    require(stream.stat().st_size==declared.get("length") and 0<stream.stat().st_size<=budget and digest(stream,"sha3_256")==declared.get("sha3_256"),"whole native stream binding failed")
    require(declared.get("records")==len(report.get("transactions",[])),"native proof stream record count mismatch")
    return stream

def funded(report,identities,lookahead,report_path):
    require(report.get("status")=="completed" and report.get("execute") is True,"funded run incomplete")
    records=report.get("transactions",[])
    require(records and report.get("finalized_transactions")==len(records) and len({r["transaction_id"] for r in records})==len(records),"complete unique transaction cohort required")
    stream=proof_stream(report,report_path)
    counts={}; amounts=0; maximum_debits={}; minimum_debits={};ranges=[]
    for record in records:
        reference=record.get("raw_proof_ref",{})
        require(type(reference.get("offset")) is int and reference["offset"]>=0 and type(reference.get("length")) is int and 0<reference["length"]<=4*1024*1024,"bounded contiguous native proof record required")
        with stream.open("rb") as source:source.seek(reference["offset"]);raw=source.read(reference["length"])
        require(len(raw)==reference["length"] and hashlib.sha3_256(raw).hexdigest()==reference.get("sha3_256"),"native record digest mismatch")
        decoded=json.loads(raw)
        require(decoded.get("kind")=="finalized_transfer" and decoded.get("transaction_id")==record["transaction_id"],"native transfer record/query binding mismatch")
        ranges.append((reference["offset"],reference["offset"]+reference["length"]))
        views=decoded.get("finalized_transaction_views",{})
        require(set(views)==set(ALIASES),"raw all-five finalized transaction views missing")
        tx=same(list(views.values()))
        require(tx.get("status")=="applied" and tx.get("block_height",0)>lookahead and tx.get("block_hash") and tx.get("finality_certificate_id"),"genuine steady-state finalized transfer required")
        unsigned=tx.get("transaction",{}).get("unsigned",{})
        require(unsigned.get("sender")==record["sender"] and unsigned.get("nonce")==record["nonce"],"signed sender/nonce mismatch")
        amount=unsigned.get("amount_nwei");gas=tx.get("receipt",{}).get("gas_used")
        require(type(amount) is int and amount>0 and type(gas) is int and 0<=gas<=unsigned.get("gas_limit",-1),"native transfer/gas receipt missing")
        sender=unsigned["sender"];counts[sender]=counts.get(sender,0)+1;amounts+=amount
        minimum_debits[sender]=minimum_debits.get(sender,0)+amount
        maximum_debits[sender]=maximum_debits.get(sender,0)+amount+gas*unsigned["max_fee_per_gas_nwei"]
    offset=0
    for start,end in sorted(ranges):
        require(start==offset,"overlapping or unreferenced native proof records")
        offset=end
    require(offset==stream.stat().st_size,"unreferenced or truncated native proof stream")
    wallet=report.get("wallet_effects_evidence",{}); receiver=wallet.get("receiver",{})
    require(type(wallet.get("before_height")) is int and type(wallet.get("after_height")) is int and wallet["after_height"]>wallet["before_height"],"wallet proof height progression missing")
    sender_records={entry["sender"]:entry for entry in wallet.get("senders",[])}
    require(set(counts)<=set(sender_records),"sender raw wallet state missing")
    credits=[];nonce_totals=[0]*5
    for index,alias in enumerate(ALIASES):
        for sender,count in counts.items():
            entry=sender_records[sender]
            before=entry.get("initial_by_validator",{});after=entry.get("final_by_validator",{})
            require(set(before)==set(ALIASES) and set(after)==set(ALIASES),"all-five sender snapshots missing")
            same(list(before.values()));same(list(after.values()))
            old=before[alias];new=after[alias]
            debit=int(old["balance_nwei"])-int(new["balance_nwei"])
            require(new["nonce"]-old["nonce"]==count and minimum_debits[sender]<=debit<=maximum_debits[sender],"exactly-once nonce or signed fee bound failed")
            nonce_totals[index]+=count
        before=receiver.get("initial_by_validator",{});after=receiver.get("final_by_validator",{})
        require(set(before)==set(ALIASES) and set(after)==set(ALIASES),"all-five receiver snapshots missing")
        same(list(before.values()));same(list(after.values()))
        old=before[alias];new=after[alias]
        credited=int((new or {}).get("balance_nwei",0))-int((old or {}).get("balance_nwei",0))
        require(credited==amounts,"exactly-once receiver credit failed")
        credits.append({"applied_exactly_once":True,"receiver_credit_nwei":credited,"sender_nonce_delta":nonce_totals[index],"finalized_transaction_count":len(records)})
    raw_snapshots=report.get("common_height_snapshots",{})
    require(raw_snapshots,"common pinned native block snapshots missing")
    snapshot=raw_snapshots.get("end",{})
    by_node=snapshot.get("validators",{})
    require(set(by_node)==set(ALIASES),"all-five pinned snapshots missing")
    commitments=[commitment(by_node[a]) for a in ALIASES];same(commitments)
    return {"passed":True,"validator_ids":identities,"common_finalized_commitments":commitments,"native_wallet_effects":credits}

def quorum(report,identities):
    require(report.get("schema_version")==1 and report.get("kind")=="quorum_recovery" and report.get("schedule_completed") is True,"native quorum recovery evidence missing")
    samples=report.get("phase_samples",[])
    phases={p:[s for s in samples if s.get("phase")==p] for p in ("below_quorum","four_validators","five_rejoined")}
    require(all(phases.values()),"all native quorum phases required")
    halt=phases["below_quorum"];require(len(halt)>=2,"durable below-quorum observation interval missing")
    first,last=halt[0],halt[-1];require(len(first["live_node_ids"])==3 and set(first["live_node_ids"])==set(last["live_node_ids"]),"exact three-validator halt required")
    require(first["finalized_heights"]==last["finalized_heights"],"finality advanced below quorum")
    observe=report.get("halt_observe_seconds",5)
    require(type(observe) in (int,float) and 5<=observe<=120,"declared halt observation bounds missing")
    for identity in first["live_node_ids"]:
        require(last["latest_query_bounds"][identity]["start"]-first["latest_query_bounds"][identity]["end"]>=observe,"halt duration not independently observed")
    fourth=phases["four_validators"][-1];fifth=phases["five_rejoined"][-1]
    require(len(fourth["live_node_ids"])==4 and set(fifth["live_node_ids"])==set(identities),"fourth restoration/fifth rejoin missing")
    require(fourth["common_finalized_commitment"]["height"]>max(last["finalized_heights"].values()) and fifth["common_finalized_commitment"]["height"]>fourth["common_finalized_commitment"]["height"],"native automatic recovery progression missing")
    commitments=[commitment(fifth["commitments_by_node"][n]) for n in identities];same(commitments)
    return {"passed":True,"validator_ids":identities,"common_finalized_commitments":commitments}

def rejoin(report,observations,identities):
    require(not observations.get("failures"),"native observation campaign failed")
    events=report.get("fault_events",[])
    stopped=[e for e in events if e.get("event")=="old_signer_stopped"]
    restarted=[e for e in events if e.get("event")=="replacement_started"]
    require(len(stopped)==len(restarted)==1 and stopped[0]["node_id"]==restarted[0]["node_id"] and stopped[0]["elapsed_seconds"]<restarted[0]["elapsed_seconds"],"exact stopped signer and replacement evidence required")
    missing=stopped[0]["node_id"];survivors=set(identities)-{missing}
    middle=[];after=[]
    for sample in observations.get("observations",[]):
        entries=sample.get("by_validator",{})
        if not set(identities)<=set(entries): continue
        live={n for n,v in entries.items() if "native" in v and isinstance(v["native"].get("finalized_height"),int)}
        if stopped[0]["elapsed_seconds"]<sample["elapsed_seconds"]<restarted[0]["elapsed_seconds"] and live==survivors: middle.append(sample)
        if sample["elapsed_seconds"]>restarted[0]["elapsed_seconds"] and live==set(identities): after.append(sample)
    require(len(middle)>=2 and after,"native four-validator progress and five rejoin observations missing")
    for n in survivors: require(middle[-1]["by_validator"][n]["native"]["finalized_height"]>middle[0]["by_validator"][n]["native"]["finalized_height"],"survivor finality did not advance during outage")
    final=after[-1]
    commitments=[commitment(final["by_validator"][n]["pinned_native"]["native"]["common_finalized_commitment"]) for n in identities];same(commitments)
    require(commitments[0]["height"]>max(middle[-1]["by_validator"][n]["native"]["finalized_height"] for n in survivors),"rejoined common finality did not advance")
    return {"passed":True,"validator_ids":identities,"common_finalized_commitments":commitments}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("binary","provenance","fixture","funded-report","baseline-report","restart-launcher-report","restart-observations","quorum-launcher-report","quorum-proof","output"): parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();root=args.fixture.resolve();paths=[args.funded_report,args.baseline_report,args.restart_launcher_report,args.restart_observations,args.quorum_launcher_report,args.quorum_proof]
    paths += [proof_stream(load(path),path) for path in (args.funded_report,args.baseline_report)]
    native_genesis=[load(p)["genesis"] for p in (args.restart_launcher_report,args.quorum_launcher_report)]
    require(all(g.get("native_genesis_verified") is True and g.get("genesis_authority_binding_verified") is True and g.get("signed_authority_preflight_verified") is True for g in native_genesis),"genuine native signed Genesis verification missing")
    genesis=load(root/"genesis.sgen");authority=load(root/"authority.json");registry=load(root/"wallet-pool.json");provenance=load(args.provenance)
    require(all(g.get("verifier_artifact_sha3_256")==provenance["companions"]["synergy-genesis"]["sha3_256"] for g in native_genesis),"native Genesis verifier differs from exact candidate")
    for path in (args.restart_launcher_report,args.quorum_launcher_report):
        launched=load(path)
        require(launched.get("artifact_sha3_256")==provenance["artifact"]["sha3_256"] and launched.get("network_id")==registry["network_id"] and launched.get("run_id"),"native launcher candidate/incarnation binding missing")
    require(load(args.restart_observations).get("artifact")==provenance["artifact"] and load(args.restart_observations).get("network_id")==registry["network_id"],"restart observations candidate/incarnation mismatch")
    require(all(load(path).get("network_id")==registry["network_id"] for path in (args.funded_report,args.baseline_report)),"funded evidence incarnation mismatch")
    require(all(g.get("genesis_hash")==genesis["genesis_hash"] for g in native_genesis),"native Genesis report differs from retained fixture")

    identities=[v["record"]["validator_id"] for v in authority["payload"]["validators"]]
    lookahead=authority["payload"]["protected"]["parameters"]["target_height_offset"]
    steady=funded(load(args.funded_report),identities,lookahead,args.funded_report)
    baseline=funded(load(args.baseline_report),identities,lookahead,args.baseline_report)
    require(load(args.baseline_report).get("finalized_transactions")==30,"complete initial 30-transfer baseline required")
    recovery=quorum(load(args.quorum_proof),identities)
    restart=rejoin(load(args.restart_launcher_report),load(args.restart_observations),identities)
    require(args.output.resolve().parent==root,"aggregate report belongs at native fixture root")
    refs=[]
    for path in paths+[root/"genesis.sgen",root/"authority.json",root/"trust.pub"]:
        relative=path.resolve().relative_to(root);refs.append({"path":str(relative),"sha256":sha(path)})
    require(len(identities)==5 and len(set(identities))==5,"five distinct native identities required")
    report={"format_version":1,"qualification_state":"native_primary_scenarios_verified","GateD_qualified":False,"missing_qualification_gates":["complete mandatory protocol/fault coverage","reproducible 10000-seed campaign","independent qualification review"],"artifact":provenance["artifact"],"companions":provenance["companions"],"provenance_sha256":sha(args.provenance),"validator_ids":identities,
        "network_identity":{"chain_id":authority["payload"]["chain_id"],"incarnation":registry["network_id"],"genesis_commitment":genesis["genesis_hash"],"authority_commitment":hashlib.sha3_256((root/"authority.json").read_bytes()).hexdigest()},
        "signed_genesis":{"native_verified":True,"evidence_path":str(args.quorum_launcher_report.resolve().relative_to(root))},"scenarios":{"funded_steady_state":steady,"restart_rejoin":restart,"quorum_recovery":recovery},"baseline_30":baseline,"evidence_files":refs,"provider_simulated":True,"GateE_qualified":False,"live_activation_approved":False}
    with args.output.open("x") as output:json.dump(report,output,sort_keys=True,indent=2);output.write("\n")
    print("Native evidence aggregated; exact provenance/promotion validation and operator approval remain separate")

if __name__=="__main__":main()
