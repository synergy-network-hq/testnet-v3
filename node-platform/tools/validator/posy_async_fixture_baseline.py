"""Exploratory native async fixture mode for run-posy-tps-baseline.py.

This runner measures the existing production-owner fixture, never fabricates
admission or substitutes legacy target-height submission. Host loopback traffic
is explicitly shared; CPU/RSS/disk counters belong to the fixture process.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import time

TEST = "services::socket_qualification::exploratory_tps::processing_async_exploratory_five_validator_tps"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def source_inventory(root):
    names = subprocess.check_output(["rg", "--files", "--hidden", "-g", "*.rs", "-g", "Cargo.toml", "-g", "Cargo.lock", "-g", "!target/**", "-g", "!._*"], cwd=root, text=True).splitlines()
    return {name: digest(root / name) for name in sorted(names)}


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


class RusageV2(ctypes.Structure):
    # Exact rusage_info_v2 layout in the installed macOS SDK sys/resource.h.
    _fields_ = [("uuid", ctypes.c_ubyte * 16)] + [(name, ctypes.c_uint64) for name in (
        "user_ns", "system_ns", "idle_wakeups", "interrupt_wakeups", "pageins", "wired_bytes", "rss_bytes", "physical_footprint_bytes",
        "start_abstime", "exit_abstime", "child_user_ns", "child_system_ns", "child_idle_wakeups", "child_interrupt_wakeups", "child_pageins",
        "child_elapsed_abstime", "disk_read_bytes", "disk_write_bytes")]


def timebase_ratio():
    class Timebase(ctypes.Structure):
        _fields_ = [("numer",ctypes.c_uint32),("denom",ctypes.c_uint32)]
    info = Timebase()
    if ctypes.CDLL("/usr/lib/libSystem.B.dylib").mach_timebase_info(ctypes.byref(info)) != 0 or not info.denom:
        raise ValueError("cannot establish mach absolute time conversion")
    return info.numer / info.denom


def sample_process(pid, libproc):
    usage = RusageV2()
    if libproc.proc_pid_rusage(pid, 2, ctypes.byref(usage)) != 0:
        return {"sample_error": "proc_pid_rusage unavailable"}
    result = {key: getattr(usage, key) for key in ("user_ns", "system_ns", "rss_bytes", "physical_footprint_bytes", "disk_read_bytes", "disk_write_bytes", "pageins")}
    ratio = timebase_ratio()
    # ri_user_time/ri_system_time are mach absolute time units, not nanoseconds.
    for key in ("user_ns","system_ns"):
        result[key] = round(result[key] * ratio)
    return result


def loopback_snapshot():
    result = subprocess.run(["/usr/sbin/netstat", "-ibn", "-I", "lo0"], text=True, capture_output=True, timeout=5)
    counters = {}
    for line in result.stdout.splitlines()[1:]:
        columns = line.split()
        if len(columns) == 10 and columns[2].startswith("<Link"):
            counters = {"received_bytes": int(columns[5]), "sent_bytes": int(columns[8])}
            break
    return {"scope": "host-wide loopback; includes unrelated traffic", "raw": result.stdout, "error": result.stderr, "exit_code": result.returncode, **counters}


def run_fixture(args):
    if not args.execute:
        raise ValueError("exploratory async fixture requires --execute")
    if platform.system() != "Darwin":
        raise ValueError("fixture process resource sampler currently requires macOS; actual-host monitoring is separate")
    binary = args.exploratory_async_fixture.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("fixture test binary must be executable")
    if not args.output:
        raise ValueError("--output is required to preserve fixture raw evidence")
    independent_budgets = bool(getattr(args, "fixture_per_validator_budgets", False))
    maximum_count, maximum_rate = (64, 1000) if independent_budgets else (8, 2)
    if not 1 <= args.max_tx <= maximum_count or not 0 < args.rate_tps <= maximum_rate or not args.max_tx / args.rate_tps <= args.duration_seconds <= 120:
        raise ValueError(f"fixture bounds: 1..{maximum_count} independent wallets, offered rate <={maximum_rate} TPS, window count/rate..120 seconds")
    root = Path(__file__).resolve().parents[2]
    base = args.output.with_suffix("")
    raw_path = base.with_suffix(".transactions.jsonl")
    resource_path = base.with_suffix(".resources.jsonl")
    log_path = base.with_suffix(".runtime.log")
    inventory_path = base.with_suffix(".source.json")
    inventory = source_inventory(root)
    with inventory_path.open("x") as inventory_file:
        inventory_file.write(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
    env = os.environ.copy()
    env.update({"POSY_TPS_RAW": str(raw_path), "POSY_TPS_RATE": str(args.rate_tps), "POSY_TPS_COUNT": str(args.max_tx), "POSY_TPS_WINDOW": str(args.duration_seconds)})
    env["POSY_TPS_PER_VALIDATOR_BUDGETS"] = "1" if independent_budgets else "0"
    native_preparation = bool(getattr(args, "fixture_native_preparation", False))
    env["POSY_TPS_NATIVE_PREPARATION"] = "1" if native_preparation else "0"
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    libproc.proc_pid_rusage.restype = ctypes.c_int
    command = [str(binary), TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"]
    report = {"status": "running", "classification": "exploratory; not verified network capacity", "environment": platform.platform(),
              "binary": str(binary), "binary_sha256": digest(binary), "source_inventory": str(inventory_path), "source_inventory_sha256": digest(inventory_path),
              "command": command, "raw_transactions": str(raw_path), "raw_resources": str(resource_path), "runtime_log": str(log_path),
              "offered_tps": args.rate_tps, "offered_window_seconds": args.duration_seconds, "max_in_flight": args.max_tx,
              "limitations": ["five validators share one macOS process, CPU, filesystem and 1GiB accounting pool", "loopback counters include unrelated host traffic", "short offered window and separate bounded drain; no maximum-capacity or actual-host OOM claim", "finality observed on all five at 1-second sampling; latency is an observation upper bound"]}
    args._partial_report = report
    report["resource_topology"] = "independent1GiBperValidator" if independent_budgets else "shared1GiBAcrossFive"
    if independent_budgets:
        report["limitations"][0] = "five validators share one macOS process, CPU and filesystem; independent unchanged1GiB accounting pools"
    rows = []
    with log_path.open("x") as log, resource_path.open("x") as resource_log:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        report["pid"] = process.pid
        started = time.monotonic()
        last_network = -5.0
        while process.poll() is None:
            row = {"unix_seconds": time.time(), "process_elapsed_seconds": time.monotonic() - started, **sample_process(process.pid, libproc)}
            if row["process_elapsed_seconds"] - last_network >= 5:
                row["loopback"] = loopback_snapshot()
                last_network = row["process_elapsed_seconds"]
            resource_log.write(json.dumps(row) + "\n")
            resource_log.flush()
            rows.append(row)
            time.sleep(1)
        report["exit_code"] = process.returncode
    report["source_unchanged_during_measurement"] = source_inventory(root) == inventory
    report["status"] = "passed" if process.returncode == 0 and report["source_unchanged_during_measurement"] else "failed"
    events = [json.loads(line) for line in raw_path.read_text().splitlines()] if raw_path.exists() else []
    config = next((e for e in events if e["kind"] == "configuration"), None)
    summary = next((e for e in events if e["kind"] == "summary"), None)
    if not config:
        report["status"] = "failed"
        report["failure"] = "fixture did not reach measurement start; inspect preserved runtime evidence"
        return report
    if not summary:
        report["status"] = "failed"
        report["failure"] = "fixture interrupted; partial observations only, no completed-window or wallet-verification pass"
        submissions = [e for e in events if e["kind"] == "submission"]
        admissions = [e for e in events if e["kind"] == "admission"]
        finalities = [e for e in events if e["kind"] == "finality"]
        samples = [e for e in events if e["kind"] == "sample"]
        elapsed = max((e.get("elapsed_seconds", e.get("observed_seconds", e.get("rpc_returned_seconds",0))) for e in events), default=0)
        summary = {"elapsed_seconds":elapsed, "submitted_seconds":[None]*args.max_tx,"admitted_seconds":[None]*args.max_tx,
                   "finalized_seconds":[None]*args.max_tx,"rejected":[False]*args.max_tx,"finalized_count":len(finalities),
                   "initial_height":min(samples[0]["heights"]) if samples else 0,"final_height":min(samples[-1]["heights"]) if samples else 0,
                   "verified_receiver_nwei":None,"reserved_bytes":samples[-1]["reserved_bytes"] if samples else None}
        for e in submissions: summary["submitted_seconds"][e["index"]] = e["submitted_seconds"]
        for e in admissions:
            if e["receipt"].get("admitted"): summary["admitted_seconds"][e["index"]] = e["observed_seconds"]
            else: summary["rejected"][e["index"]] = True
        for e in finalities: summary["finalized_seconds"][e["index"]] = e["observed_seconds"]
        report["incomplete_measurement"] = True
    report["fixture_root"] = config["fixture_root"]
    if independent_budgets and config.get("per_validator_accounting_limit_bytes") != 1024**3:
        raise ValueError("fixture binary did not activate independent1GiB accounting; do not report requested topology as measured")
    if native_preparation and config.get("native_consensus_preparation") is not True:
        raise ValueError("fixture binary did not activate native consensus preparation")
    report["native_consensus_preparation"] = config.get("native_consensus_preparation", False)
    elapsed = summary["elapsed_seconds"]
    submitted = summary["submitted_seconds"]
    admitted = summary["admitted_seconds"]
    finalized = summary["finalized_seconds"]
    latencies = [f-s for f,s in zip(finalized,submitted) if f is not None and s is not None]
    report["measurement"] = {"offered_window_seconds": args.duration_seconds, "including_drain_seconds": elapsed,
        "submitted_count": sum(t is not None for t in submitted), "admitted_count": sum(t is not None for t in admitted), "finalized_count": summary["finalized_count"],
        "submitted_tps_offered_window": sum(t is not None and t <= args.duration_seconds for t in submitted)/args.duration_seconds,
        "admitted_tps_offered_window": sum(t is not None and t <= args.duration_seconds for t in admitted)/args.duration_seconds,
        "finalized_tps_offered_window": sum(t is not None and t <= args.duration_seconds for t in finalized)/args.duration_seconds,
        "finalized_tps_including_drain": summary["finalized_count"]/elapsed,
        "rejected_count": sum(summary["rejected"]), "rejection_rate": sum(summary["rejected"])/len(submitted),
        "admitted_unfinalized_count": sum(a is not None and f is None for a,f in zip(admitted,finalized)),
        "unfinalized_fraction_of_submissions": sum(s is not None and f is None for s,f in zip(submitted,finalized))/max(1,sum(s is not None for s in submitted)),
        "finality_latency_seconds": {"p50":percentile(latencies,.5),"p95":percentile(latencies,.95),"p99":percentile(latencies,.99),"sample_count":len(latencies)},
        "over_30_second_finality_count": sum(t>30 for t in latencies),
        "unfinalized_over_30_seconds_count": sum(s is not None and f is None and not rejected and elapsed-s>30
            for s,f,rejected in zip(submitted,finalized,summary["rejected"])),
        "unfinalized_latency_lower_bounds_seconds": [{"index":i,"at_least_seconds":elapsed-s}
            for i,(s,f,rejected) in enumerate(zip(submitted,finalized,summary["rejected"]))
            if s is not None and f is None and not rejected],
        "latency_population": "percentiles cover finalized submissions; unfinished submissions are censored and reported separately",
        "admission_observation_delay_seconds": {"p50":percentile([a-s for a,s in zip(admitted,submitted) if a is not None and s is not None],.5),
            "p95":percentile([a-s for a,s in zip(admitted,submitted) if a is not None and s is not None],.95),
            "p99":percentile([a-s for a,s in zip(admitted,submitted) if a is not None and s is not None],.99)},
        "block_rate_hz_including_drain": (summary["final_height"]-summary["initial_height"])/elapsed,
        "verified_receiver_nwei":summary["verified_receiver_nwei"]}
    if report["measurement"]["admitted_unfinalized_count"]:
        report["status"] = "failed"
        report["failure"] = "accepted work did not drain within the declared observation; native test exit alone is not a workload pass"
    if report.get("incomplete_measurement"):
        for metric in ("submitted", "admitted", "finalized"):
            report["measurement"][metric+"_tps_offered_window"] = None
        report["measurement"]["partial_observed_seconds"] = elapsed
        report["measurement"]["partial_submitted_tps"] = sum(t is not None for t in submitted)/max(elapsed,1e-9)
        report["measurement"]["partial_admitted_tps"] = sum(t is not None for t in admitted)/max(elapsed,1e-9)
    sample_events = [e for e in events if e["kind"] == "sample"]
    report["memory_accounting"] = {"first_bytes":sample_events[0]["reserved_bytes"],"peak_bytes":max(e["reserved_bytes"] for e in sample_events),"last_bytes":summary["reserved_bytes"]}
    report["memory_accounting"]["scope"] = "sum of five independent pools" if independent_budgets else "one shared pool"
    report["memory_accounting"]["per_validator_peak_bytes"] = [max(e["reserved_bytes_per_validator"][i] for e in sample_events) for i in range(5)] if all("reserved_bytes_per_validator" in e for e in sample_events) else None
    prepared = [e for e in events if e["kind"] == "prepared"]
    report["prepared_work_observations"] = {"basis":"first sampled durable native completion per validator; up to1second observation delay, not execution or finalized TPS", "validators":[{"validator":i,"count":sum(e["validator"]==i for e in prepared),"prepared_tps_offered_window":sum(e["validator"]==i and e["observed_seconds"]<=args.duration_seconds for e in prepared)/args.duration_seconds,"prepared_tps_including_drain":sum(e["validator"]==i for e in prepared)/elapsed} for i in range(5)]}
    report["transaction_finality_timing_passed"] = bool(report["status"] == "passed" and not report["measurement"]["over_30_second_finality_count"] and not report["measurement"]["unfinalized_over_30_seconds_count"])
    report["backlog_peak_members_per_validator"] = [max((e["backlog"][i] or {}).get("members",0) for e in sample_events) for i in range(5)]
    report["backlog_peak_completions_per_validator"] = [max((e["backlog"][i] or {}).get("completions",0) for e in sample_events) for i in range(5)]
    report["block_times"] = {"clock":"monotonic observation of native QC certification and native three-QC finality; protocol timestamps preserved separately", "validators":[]}
    for validator in range(5):
        timing = {"validator":validator}
        for kind in ("certified_block", "finalized_block"):
            blocks = [e for e in events if e["kind"] == kind and e["validator"] == validator]
            # Gaps are kept as gaps, never divided into invented individual block times.
            intervals = [b["observed_seconds"]-a["observed_seconds"] for a,b in zip(blocks,blocks[1:]) if b["height"] == a["height"]+1]
            timing[kind] = {"observed_count":len(blocks),"consecutive_interval_count":len(intervals),
                            "height_gaps":sum(b["height"] != a["height"]+1 for a,b in zip(blocks,blocks[1:])),
                            "average_seconds":sum(intervals)/len(intervals) if intervals else None,
                            "p50_seconds":percentile(intervals,.5),"p95_seconds":percentile(intervals,.95),"p99_seconds":percentile(intervals,.99),
                            "transaction_inclusion_counts":[{"height":b["height"],"count":b["transaction_count"]} for b in blocks if "transaction_count" in b]}
        report["block_times"]["validators"].append(timing)
    report["mean_block_cadence_passed"] = all(
        item[kind]["average_seconds"] is not None and .5 <= item[kind]["average_seconds"] <= 1.5
        for item in report["block_times"]["validators"] for kind in ("certified_block", "finalized_block"))
    # A local performance fixture cannot establish distributed release qualification.
    report["release_qualified"] = False
    active_rows = [r for r in rows if r["unix_seconds"] >= config["started_unix"] and "rss_bytes" in r]
    if active_rows:
        first, last = active_rows[0],active_rows[-1]
        duration = last["unix_seconds"]-first["unix_seconds"]
        cpu = [100*((b["user_ns"]+b["system_ns"])-(a["user_ns"]+a["system_ns"]))/(1e9*(b["unix_seconds"]-a["unix_seconds"])) for a,b in zip(active_rows,active_rows[1:])]
        report["process_resources"] = {"scope":"shared five-validator process; measured load and drain only", "sample_count":len(active_rows),
            "rss_average_bytes":sum(r["rss_bytes"] for r in active_rows)/len(active_rows),"rss_peak_bytes":max(r["rss_bytes"] for r in active_rows),"rss_first_bytes":first["rss_bytes"],"rss_last_bytes":last["rss_bytes"],
            "cpu_average_percent_one_core_100":100*((last["user_ns"]+last["system_ns"])-(first["user_ns"]+first["system_ns"]))/max(1e-9,duration*1e9),"cpu_peak_percent_one_core_100":max(cpu,default=None),
            "disk_read_bytes":last["disk_read_bytes"]-first["disk_read_bytes"],"disk_write_bytes":last["disk_write_bytes"]-first["disk_write_bytes"]}
        network = [r["loopback"] for r in active_rows if "loopback" in r and "received_bytes" in r["loopback"]]
        if len(network) >= 2:
            report["host_loopback_io"] = {"scope":"host-wide, shared, not attributable per validator", "received_bytes":network[-1]["received_bytes"]-network[0]["received_bytes"],"sent_bytes":network[-1]["sent_bytes"]-network[0]["sent_bytes"]}
    return report
