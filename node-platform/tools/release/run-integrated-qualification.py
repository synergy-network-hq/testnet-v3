#!/usr/bin/env python3
"""Run the frozen native regression/model campaign without changing candidate bytes.
This orchestrates existing genuine native harnesses. They are not full-process fault
coverage and do not authorize deployment, production parameters or a soak.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
SCENARIOS=[
 ("funded admission/cutoff", "services::socket_qualification::authenticated_socket_nonempty_admission_execution_and_closed_cutoff"),
 ("native funded encrypted execution", "services::socket_qualification::authenticated_socket_wallet_admission_finalizes_real_transfer"),
 ("below-quorum halt and retained recovery", "services::socket_qualification::authenticated_socket_below_quorum_halt_and_durable_recovery"),
 ("restart/rejoin", "services::socket_qualification::authenticated_socket_focused_restart_rejoin"),
 ("certified execution gap", "services::socket_qualification::authenticated_socket_restart_with_certified_execution_gap_recovers_without_losing_authority"),
 ("outstanding sync and reorder", "services::socket_qualification::authenticated_socket_outstanding_request_restart_and_reordered_prefetch_recovers"),
 ("timeout before older QC", "services::socket_qualification::authenticated_r1_timeout_before_older_qc_recovers_certified_path_without_journal_changes"),
 ("live QC/TC arrival reorder", "services::socket_qualification::authenticated_live_tc_qc_arrival_order_converges_successor_round"),
 ("dropped timeout retry", "services::socket_qualification::authenticated_socket_dropped_timeout_retries_converge_successor_round"),
 ("retained timeout idle/lease recovery", "services::socket_qualification::authenticated_socket_retained_timeout_retries_after_idle_expiry_and_lease_change"),
 ("late VAC and funded recovery", "services::socket_qualification::authenticated_socket_r3_h51_late_vac_split_recovers_real_wallet_and_restart"),
 ("generation cancellation", "services::preparation::tests::cancelled_owner_cannot_publish_to_replacement_generation"),
 ("mailbox accounting", "services::preparation::tests::retained_completion_keeps_mailbox_reservation_until_consumed"),
 ("worker panic fails closed", "services::preparation::tests::panic_latches_failure_and_prohibits_more_work"),
 ("cached context observes VC", "services::protected_admission::live_cutoff_tests::cached_admission_context_observes_new_verified_cutoff_without_republication"),
 ("receipt journal corruption", "services::protected_admission::durable_receipt_tests::corrupt_or_wrong_authority_observation_fails_closed"),
 ("failed observation durability", "services::protected_admission::durable_receipt_tests::failed_observation_persistence_does_not_publish_accepted_receipt"),
]
UNSUPPORTED=["full-process slow cryptography", "full-process delayed/failed disk acknowledgement", "process kill exactly at signing/admission/certificate/execution/finalized-commit durability boundaries", "full-process stale worker result after epoch replacement", "protocol-selective proposal/vote/QC drops in encrypted transport", "sustained overload followed by verified automatic recovery", "supported historical retention performance bounds", "independent protocol qualification review"]

def digest(path):
    h=hashlib.sha3_256()
    with path.open("rb") as stream:
        for part in iter(lambda:stream.read(1048576),b""):h.update(part)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--output-directory",type=Path,required=True)
    parser.add_argument("--execute",action="store_true")
    args=parser.parse_args()
    if not args.execute:parser.error("explicit --execute required; run only after integrated source freeze")
    os.umask(0o077)
    args.output_directory.mkdir(mode=0o700)
    before=digest(args.binary);records=[]
    try:
        for index,(meaning,name) in enumerate(SCENARIOS):
            output=args.output_directory/f"native-{index:02d}.log"
            # --exact prevents broad expensive repetition. An absent test is a failure,
            # not the false green exit Cargo returns for an empty filter.
            listing=subprocess.run(["cargo","test","--offline","--locked","-p","synergy-node","--features","qualification-timing",name,"--","--list","--exact"],cwd=ROOT,capture_output=True,timeout=600)
            if listing.returncode or (name+": test").encode() not in listing.stdout:raise RuntimeError("native scenario absent: "+name)
            with output.open("xb") as log:
                result=subprocess.run(["cargo","test","--offline","--locked","-p","synergy-node","--features","qualification-timing",name,"--","--exact","--test-threads=1"],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=900)
            records.append({"scenario":meaning,"native_test":name,"passed":result.returncode==0,"evidence_path":output.name,"evidence_sha3_256":digest(output),"classification":"genuine native in-process regression; not full-process artifact proof"})
            if result.returncode:raise RuntimeError("native scenario failed: "+name)
            if digest(args.binary)!=before:raise RuntimeError("candidate bytes changed during qualification")
        output=args.output_directory/"model-10000.json"
        result=subprocess.run([sys.executable,str(ROOT/"tools/validator/model-posy-admission-scheduling.py"),"--seeds","10000","--output",str(output)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=900)
        if result.returncode:raise RuntimeError("deterministic model campaign failed")
        model=json.loads(output.read_text())
        if model.get("completed_seeds")!=10000 or model.get("status")!="abstract_campaign_completed":raise RuntimeError("model campaign incomplete")
        records.append({"scenario":"reproducible 10000-seed model","evidence_path":output.name,"evidence_sha3_256":digest(output),"classification":"abstract contract coverage; not native fault proof"})
    finally:
        report={"artifact_sha3_256":before,"artifact_unchanged":digest(args.binary)==before,"scenarios":records,"unsupported_native_instrumentation":UNSUPPORTED,"GateC_qualified":False,"GateD_qualified":False,"live_activation_approved":False}
        with (args.output_directory/"coverage.json").open("x") as output:json.dump(report,output,sort_keys=True,indent=2);output.write("\n")
    print("Existing native/model campaign complete; missing full-process fault coverage remains explicit")

if __name__=="__main__":main()
