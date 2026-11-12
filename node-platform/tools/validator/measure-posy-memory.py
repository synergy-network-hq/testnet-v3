#!/usr/bin/env python3
"""Run exact Linux test artifacts in isolated, memory-capped transient units.

No validator service, custody, network configuration, or production data is used.
Records process RSS, cgroup anonymous/file memory, OOM events and physical I/O.
This is component/native-fixture qualification, not a production-chain soak.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time


def command(args):
    return subprocess.check_output(args, text=True).strip()


def read(path):
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        return None


def host_memory():
    values = {}
    for line in (read(Path("/proc/meminfo")) or "").splitlines():
        fields = line.split()
        if fields[0].rstrip(":") in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            values[fields[0].rstrip(":")] = int(fields[1]) * 1024
    arc = {}
    for line in (read(Path("/proc/spl/kstat/zfs/arcstats")) or "").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] in ("size", "c", "c_min", "c_max"):
            arc[fields[0]] = int(fields[2])
    vmstat = dict(line.split() for line in (read(Path("/proc/vmstat")) or "").splitlines())
    return {"memory": values, "zfs_arc": arc,
            "host_oom_kill_count": int(vmstat["oom_kill"]) if "oom_kill" in vmstat else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--memory-mib", type=int, default=256)
    parser.add_argument("--profile", choices=["libraries", "recovery", "history-max", "native", "funded"], required=True)
    args = parser.parse_args()
    root = args.manifest.resolve().parent
    if not root.name.startswith("posy-memory-qualification-") or root.parent != Path("/var/tmp"):
        raise ValueError("dedicated /var/tmp qualification directory required")
    if not 128 <= args.memory_mib <= 4096 or args.output.exists():
        raise ValueError("bounded memory and new evidence output required")
    manifest = json.loads(args.manifest.read_text())
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != manifest["measure_script_sha256"]:
        raise ValueError("measurement script identity mismatch")
    support = root / "provenance.py"
    if support.is_symlink() or hashlib.sha256(support.read_bytes()).hexdigest() != manifest["provenance_script_sha256"]:
        raise ValueError("ELF verifier identity mismatch")
    spec = importlib.util.spec_from_file_location("resource_artifact_provenance", support)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    artifacts = {}
    for item in manifest["artifacts"]:
        path = root / item["file"]
        if path.is_symlink() or path.parent != root or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("artifact identity mismatch")
        verifier.linux_elf(path)
        artifacts[item["name"]] = path
    cases = []
    if args.profile == "libraries":
        cases = [(name, name, [], {}) for name in ("synergy_storage", "synergy_state", "synergy_execution", "synergy_etdag", "synergy_posy")]
    elif args.profile == "history-max":
        cases = [("history-4096-max-proof", "synergy_etdag", ["persistence::protected_pipeline::cut_recovery_tests::appended_history_keeps_only_latest_payload_and_reads_originals_with_bounded_recovery", "--exact"], {
            "SYNERGY_RECOVERY_QUAL_GENERATIONS": "4096",
            "SYNERGY_RECOVERY_QUAL_AUTH_BYTES": str(1024 * 1024),
        })]
    elif args.profile == "recovery":
        test = "persistence::protected_pipeline::cut_recovery_tests::appended_history_keeps_only_latest_payload_and_reads_originals_with_bounded_recovery"
        cases = [(f"history-{count}", "synergy_etdag", [test, "--exact"], {
            "SYNERGY_RECOVERY_QUAL_GENERATIONS": str(count),
            "SYNERGY_RECOVERY_QUAL_AUTH_BYTES": str(256 * 1024),
        }) for count in (96, 1024, 4096)]
        cases.append(("history-4096-max-proof", "synergy_etdag", [test, "--exact"], {
            "SYNERGY_RECOVERY_QUAL_GENERATIONS": "4096",
            "SYNERGY_RECOVERY_QUAL_AUTH_BYTES": str(1024 * 1024),
        }))
        cases.append(("timeout-prefix", "synergy-node", ["services::cut_recovery::cache_tests"], {}))
    elif args.profile == "funded":
        cases = [("funded-finality", "synergy-node", ["services::socket_qualification::authenticated_socket_wallet_admission_finalizes_real_transfer", "--exact"], {})]
    else:
        cases = [(label, "synergy-node", [test, "--exact"], {}) for label, test in (
            ("marker-cache", "services::etdag::marker_cache_tests::historical_payloads_retire_but_equivocation_checks_survive"),
            ("timeout-retry", "services::posy::qualification::timeout_retry_references_keep_exact_native_original_bytes_without_history_payloads"),
            ("timeout-pagination", "services::posy::qualification::historical_timeout_locator_pages_bound_multiple_leases_and_do_not_omit_ancestry"),
            ("timeout-history-rejoin", "services::posy::qualification::missing_proposer_times_out_with_four_signers_and_rejoins_after_partition"),
            ("r3", "services::etdag_qualification::r3_genuine_timeout_recovers_three_empty_two_vertex_close_and_restart"),
            ("snapshot", "services::socket_qualification::authenticated_snapshot_is_built_only_on_request_from_durable_restart_state"),
            ("rejoin", "services::socket_qualification::authenticated_socket_protected_finality_and_restart_rejoin"),
            ("prefetch-restart", "services::socket_qualification::authenticated_socket_outstanding_request_restart_and_reordered_prefetch_recovers"),
            ("funded-finality", "services::socket_qualification::authenticated_socket_wallet_admission_finalizes_real_transfer"),
        )]
        cases.insert(0, ("sync-head", "synergy-node", ["services::sync::congestion_tests::posy_verified_head_notifications"], {}))
    with args.output.open("x") as output:
        for number, (label, artifact, filters, env) in enumerate(cases):
            unit = f"posy-memory-qual-{os.getpid()}-{number}"
            temporary = root / f"work-{unit}"
            temporary.mkdir(mode=0o700)
            log = root / f"{unit}-{label}.log"
            # systemd opens StandardOutput as root, so pre-create a user-owned log.
            log.touch(mode=0o600, exist_ok=False)
            argv = ["sudo", "-n", "systemd-run", "--quiet", f"--unit={unit}",
                    f"--property=User={os.getuid()}", f"--property=Group={os.getgid()}",
                    f"--property=WorkingDirectory={root}",
                    f"--property=MemoryMax={args.memory_mib}M", "--property=MemorySwapMax=0",
                    "--property=MemoryAccounting=yes", "--property=IOAccounting=yes",
                    "--property=RemainAfterExit=yes", "--property=RuntimeMaxSec=1200",
                    "--property=TimeoutStopSec=10", "--property=KillMode=control-group",
                    "--property=OOMPolicy=stop", "--property=UMask=0077",
                    f"--property=StandardOutput=append:{log}", f"--property=StandardError=append:{log}",
                    f"--setenv=TMPDIR={temporary}"]
            argv.extend(f"--setenv={key}={value}" for key, value in env.items())
            # Keep the cgroup observable for fast tests; time measures only the native test.
            wrapper = "import subprocess,sys,time; r=subprocess.run(sys.argv[1:]); time.sleep(1); sys.exit(r.returncode)"
            argv.extend(["/usr/bin/python3", "-c", wrapper, "/usr/bin/time", "-v", str(artifacts[artifact]), *filters, "--test-threads=1", "--nocapture"])
            start = time.monotonic()
            rss_peak = 0
            metrics = {}
            completed = False
            host_before = host_memory()
            host_available_min = host_before["memory"].get("MemAvailable", 0)
            host_arc_peak = host_before["zfs_arc"].get("size", 0)
            filesystem = command(["findmnt", "-no", "FSTYPE,SOURCE,TARGET", "-T", str(root)])
            try:
                subprocess.run(argv, check=True)
                while time.monotonic() - start < 1220:
                    status = dict(line.split("=", 1) for line in command([
                        "systemctl", "show", unit, "-p", "SubState", "-p", "ActiveState", "-p", "Result",
                        "-p", "ExecMainStatus", "-p", "ControlGroup", "-p", "MemoryPeak", "-p", "MemoryCurrent",
                    ]).splitlines())
                    host_sample = host_memory()
                    host_available_min = min(host_available_min, host_sample["memory"].get("MemAvailable", host_available_min))
                    host_arc_peak = max(host_arc_peak, host_sample["zfs_arc"].get("size", 0))
                    group = status.get("ControlGroup", "")
                    cgroup = Path("/sys/fs/cgroup") / group.lstrip("/") if group.endswith(unit + ".service") else Path("/nonexistent-posy-test-cgroup")
                    for name in ("memory.events", "memory.peak", "memory.stat", "io.stat", "cpu.stat"):
                        value = read(cgroup / name)
                        if value is not None:
                            metrics[name] = value
                    pids = read(cgroup / "cgroup.procs") or ""
                    rss = 0
                    for pid in pids.split():
                        match = re.search(r"^VmRSS:\s+(\d+) kB$", read(Path("/proc") / pid / "status") or "", re.MULTILINE)
                        if match:
                            rss += int(match[1]) * 1024
                    rss_peak = max(rss_peak, rss)
                    if status.get("SubState") in ("exited", "failed", "dead"):
                        completed = True
                        break
                    time.sleep(0.1)
                text = log.read_text() if log.exists() else ""
                maxima = re.findall(r"Maximum resident set size \(kbytes\): (\d+)", text)
                events = dict(line.split() for line in metrics.get("memory.events", "").splitlines())
                passed = completed and status.get("Result") == "success" and status.get("ExecMainStatus") == "0" and any(int(n) > 0 for n in re.findall(r"test result: ok\. (\d+) passed", text))
                passed = passed and "oom" in events and "oom_kill" in events
                passed = passed and all(int(events.get(name, 0)) == 0 for name in ("oom", "oom_kill", "oom_group_kill"))
                host_after = host_memory()
                if host_before["host_oom_kill_count"] is not None and host_after["host_oom_kill_count"] is not None:
                    passed = passed and host_after["host_oom_kill_count"] == host_before["host_oom_kill_count"]
                record = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          "host": command(["hostname"]), "kernel": command(["uname", "-srmo"]),
                          "case": label, "artifact": artifact, "artifact_sha256": hashlib.sha256(artifacts[artifact].read_bytes()).hexdigest(),
                          "memory_limit_bytes": args.memory_mib * 1024 * 1024, "swap_limit_bytes": 0,
                          "environment": env, "seconds": time.monotonic() - start,
                          "filesystem": filesystem, "host_memory_before": host_before,
                          "host_memory_after": host_after, "host_mem_available_min_bytes": host_available_min,
                          "host_zfs_arc_peak_bytes": host_arc_peak,
                          "status": status, "cgroup": metrics, "sampled_processes_rss_peak_bytes": rss_peak,
                          "time_maximum_rss_bytes": int(maxima[-1]) * 1024 if maxima else None,
                          "remaining_temporary_bytes": sum(p.stat().st_size for p in temporary.rglob("*") if p.is_file()),
                          "passed": passed, "log": str(log)}
                output.write(json.dumps(record, sort_keys=True) + "\n")
                output.flush()
                print(json.dumps({key: record[key] for key in ("host", "case", "seconds", "time_maximum_rss_bytes", "passed")}), flush=True)
                if not passed:
                    raise RuntimeError(f"resource qualification failed: {label}; inspect {log}")
            finally:
                subprocess.run(["sudo", "-n", "systemctl", "stop", unit], check=False, capture_output=True)
                subprocess.run(["sudo", "-n", "systemctl", "reset-failed", unit], check=False, capture_output=True)


if __name__ == "__main__":
    main()
