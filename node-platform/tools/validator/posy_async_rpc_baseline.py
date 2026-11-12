"""Explicit native async RPC workload; legacy target-bound authoring is unchanged.

Bounded sequential unresolved nonces per funded wallet. Fixed offered slots never wait for chain
finality; unavailable wallet/generator slots are counted, not queued as fake load.
Public proofs and timing observations are streamed with the existing byte budget.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import math
import os
import resource
import sys
import stat
from pathlib import Path
import tempfile
import threading
import time

PROFILE = "etdag-async-processing-v1"
MAX_BLOCKS_PER_SAMPLE = 8
MAX_RECEIPTS_PER_SAMPLE = 32
NATIVE_PROCESSING_STAGES = ("certified", "reveal_authorized", "execution_completed")
MAX_OFFERED_TPS = 100000
MAX_TRANSACTIONS = 100000000


def distribution(values):
    values = sorted(values)
    return {"count": len(values), **{f"p{p}": values[max(0, math.ceil(p * len(values) / 100) - 1)] if values else None for p in (50, 95, 99)},
            "maximum": values[-1] if values else None}


def latency_observations(records):
    finalized = [r for r in records if r.get("finalized_mono") is not None]
    return {
        "context_to_finality": distribution([r["finalized_mono"] - r["context_started_mono"] for r in finalized]),
        "submission_to_finality": distribution([r["finalized_mono"] - r["submitted_mono"] for r in finalized]),
        "submission_to_observed_admission": distribution([r["admitted_mono"] - r["submitted_mono"] for r in records if "admitted_mono" in r]),
        "observed_admission_to_finality": distribution([r["finalized_mono"] - r["admitted_mono"] for r in finalized if "admitted_mono" in r]),
        **{field: distribution([r[field] for r in records if field in r])
           for field in ("context_retrieval_seconds", "native_signing_seconds", "submission_transport_seconds")}}


class BoundedDistribution:
    """Fixed logarithmic histogram; percentile upper bounds within 1%, exact max."""
    def __init__(self):
        self.bins = {}; self.count = 0; self.maximum = None
    def append(self, value):
        if not math.isfinite(value) or value < 0:
            raise ValueError("non-finite/negative measurement")
        # Saturate sub-microsecond values and durations above one year. The
        # extreme bins retain exact max, with explicitly bounded percentile bins.
        key = max(-1400, min(1800, math.ceil(math.log(max(value, 1e-6), 1.01))))
        self.bins[key] = self.bins.get(key, 0) + 1
        self.count += 1
        self.maximum = value if self.maximum is None else max(value, self.maximum)
    def summary(self):
        result = {"count": self.count, "maximum": self.maximum,
                  "quantile_basis": "fixed 1-percent logarithmic-bin upper bound"}
        for percentile in (50, 95, 99):
            rank = math.ceil(percentile * self.count / 100); total = 0
            result[f"p{percentile}"] = None
            for key, count in sorted(self.bins.items()):
                total += count
                if total >= rank:
                    result[f"p{percentile}"] = min(self.maximum, 1.01 ** key); break
        return result


class WorkloadTotals:
    """Only unresolved intents remain live; terminal records become counters."""
    def __init__(self, deadline, steady_start=None):
        self.deadline = deadline
        self.steady_start = float("-inf") if steady_start is None else steady_start
        self.counts = dict(submitted=0, finalized=0, admitted=0, rejected=0,
                           submitted_window=0, admitted_window=0, finalized_window=0,
                           authored=0, authored_steady=0, submitted_steady=0, admitted_steady=0, finalized_steady=0)
        self.latencies = {name: BoundedDistribution() for name in (
            "context_to_finality", "submission_to_finality", "submission_to_observed_admission",
            "observed_admission_to_finality", "context_retrieval_seconds",
            "native_signing_seconds", "submission_transport_seconds")}
        self.rejections = []
        self.stage_counts = {stage: 0 for stage in NATIVE_PROCESSING_STAGES}
        self.stage_window_counts = dict(self.stage_counts)
    def consume(self, record):
        submitted = bool(record.get("submission_started"))
        finalized = record.get("finalized_mono") is not None
        rejected = bool(record.get("submission_rejection") or record.get("admission_rejection"))
        c = self.counts
        c["submitted"] += submitted; c["finalized"] += finalized
        c["admitted"] += bool(record.get("accepted")); c["rejected"] += rejected
        c["submitted_window"] += submitted and record["submitted_mono"] <= self.deadline
        c["admitted_window"] += record.get("admitted_mono", record.get("finalized_mono", float("inf"))) <= self.deadline
        c["finalized_window"] += finalized and record["finalized_mono"] <= self.deadline
        for stage, observed in record.get("stage_first_observed_mono", {}).items():
            if stage in self.stage_counts:
                self.stage_counts[stage] += 1
                self.stage_window_counts[stage] += observed <= self.deadline
        c["authored"] += 1
        c["authored_steady"] += self.steady_start <= record.get("authored_mono", record["submitted_mono"]) <= self.deadline
        c["submitted_steady"] += submitted and self.steady_start <= record["submitted_mono"] <= self.deadline
        admitted_at = record.get("admitted_mono", record.get("finalized_mono", float("inf")))
        c["admitted_steady"] += self.steady_start <= admitted_at <= self.deadline
        c["finalized_steady"] += finalized and self.steady_start <= record["finalized_mono"] <= self.deadline
        pairs = {"context_to_finality": ("finalized_mono", "context_started_mono"),
                 "submission_to_finality": ("finalized_mono", "submitted_mono"),
                 "submission_to_observed_admission": ("admitted_mono", "submitted_mono"),
                 "observed_admission_to_finality": ("finalized_mono", "admitted_mono")}
        for name, (end, start) in pairs.items():
            if record.get(end) is not None and start in record:
                self.latencies[name].append(record[end] - record[start])
        for name in ("context_retrieval_seconds", "native_signing_seconds", "submission_transport_seconds"):
            if name in record: self.latencies[name].append(record[name])
        if rejected and len(self.rejections) < 32:
            self.rejections.append({"transaction_id": record["transaction_id"],
                "submission": record.get("submission_rejection"), "admission": record.get("admission_rejection")})
    def latency_summary(self):
        return {name: values.summary() for name, values in self.latencies.items()}

    def processing_stage_summary(self, duration):
        return {stage: {"native_reported_observations": self.stage_counts[stage],
                "offered_window_observations": self.stage_window_counts[stage],
                "observed_tps_lower_bound": self.stage_window_counts[stage] / duration,
                "actual_stage_tps": None}
            for stage in NATIVE_PROCESSING_STAGES}


def record_lifecycle_stage(record, receipt, observed):
    """Receipt polling can miss milestones. Never infer earlier stage times/rates."""
    stage = receipt.get("lifecycle_status")
    if stage not in NATIVE_PROCESSING_STAGES:
        return
    if not isinstance(receipt.get("stage_evidence"), dict) or not receipt["stage_evidence"]:
        raise ValueError("native processing stage lacks its stage evidence")
    record.setdefault("stage_first_observed_mono", {}).setdefault(stage, observed)



class GeneratorResources:
    """Measure this generator and its native signing children, never validator caps."""
    def __init__(self):
        self.started = time.monotonic()
        self.initial = self._usage()

    @staticmethod
    def _usage():
        own = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        scale = 1 if sys.platform == "darwin" else 1024
        return {"process_cpu_seconds": own.ru_utime + own.ru_stime,
                "signer_children_cpu_seconds": children.ru_utime + children.ru_stime,
                "process_peak_rss_bytes": int(own.ru_maxrss * scale),
                "signer_child_peak_rss_bytes": int(children.ru_maxrss * scale)}

    def summary(self):
        current = self._usage()
        elapsed = max(0.000001, time.monotonic() - self.started)
        for name in ("process_cpu_seconds", "signer_children_cpu_seconds"):
            current[name] -= self.initial[name]
        return {**current, "elapsed_seconds": elapsed,
                "mean_process_cpu_cores": current["process_cpu_seconds"] / elapsed,
                "mean_signer_children_cpu_cores": current["signer_children_cpu_seconds"] / elapsed,
                "rss_basis": "OS lifetime high-water marks; child RSS is largest child, not concurrent sum"}


class SingleFlightObserver:
    """One bounded proof reader; slow RPC/proof reads cannot block offered slots."""
    def __init__(self, cancellation):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.future = None
        self.cancellation = cancellation
        self.durations = BoundedDistribution()

    def start(self, action):
        if self.future is not None:
            return False
        def run():
            began = time.monotonic()
            try:
                return action()
            except BaseException:
                self.cancellation.set()
                raise
            finally:
                self.durations.append(time.monotonic() - began)
        self.future = self.executor.submit(run)
        return True

    def poll(self):
        if self.future is None or not self.future.done():
            return False
        future = self.future
        self.future = None
        future.result()
        return True

    def close(self):
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.poll()


def block_fingerprint(block):
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":")).iterencode(block):
        digest.update(chunk.encode())
    return digest.digest()


def due_offer_slots(now, next_slot, rate, capacity, jitter=0.01):
    """Bounded current slots; expired slots are counted, never replayed as load."""
    if next_slot > now: return [], next_slot, 0
    due = int((now - next_slot) * rate) + 1
    expired = min(due, max(0, math.ceil((now - jitter - next_slot) * rate)))
    live = due - expired
    count = min(live, capacity)
    slots = [next_slot + (expired + i) / rate for i in range(count)]
    return slots, next_slot + due / rate, expired + live - count


def processing_receipt_id(encoded):
    """Hash exact native serde output; never reserialize identity carrier maps."""
    domain = b"SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1"
    return hashlib.sha3_512(len(domain).to_bytes(8, "big") + domain
                           + len(encoded).to_bytes(8, "big") + encoded).hexdigest()

def verify_operator_registry(keytool, registry, h):
    """Native session startup authenticates authority, Genesis and all custody.

    EOF supplies no transaction frame, so this validates the existing complete
    operator registry without authoring anything or reading secrets in Python.
    """
    result=h.subprocess.run([str(keytool),"prepare-wallet-admission-session-operator",str(registry)],
        stdin=h.subprocess.DEVNULL,stdout=h.subprocess.DEVNULL,stderr=h.subprocess.DEVNULL,
        check=False,timeout=30)
    if result.returncode:
        raise h.BaselineError("native operator authority/Genesis/custody validation failed; no transaction authored")

def validate_wallet_authority(views, public, error=ValueError):
    """Funding is independent of signing authority. Verify exact finalized binding.

    Native authoring still verifies the carrier signatures and selected network;
    this preflight never installs a presented binding into governed state.
    """
    expected = public.get("genesis_binding_commitment")
    if not isinstance(expected, dict) or not expected:
        raise error("wallet public record lacks its verified binding commitment")
    if set(views) != {f"val{i}" for i in range(2, 7)} or any(not isinstance(view, dict) or "authorization_binding" not in view
                        for view in views.values()):
        raise error("workload wallet lacks explicit all-validator authorization observations")
    bindings = [view["authorization_binding"] for view in views.values()]
    # A genuinely new funded owner has no canonical binding yet. The native
    # authoring path verifies its root-signed carrier, self-derived address,
    # network scope and delegated-key possession before any submission. Never
    # manufacture a binding or accept inconsistent/mismatching existing state.
    if all(binding is None for binding in bindings):
        return "native_first_use_required"
    if any(binding != expected for binding in bindings):
        raise error("workload wallet lacks matching canonical finalized authorization; funding is insufficient")
    return "existing_binding_verified"


def verify_installed_release(args, h):
    """Use the normal read-only installation gate before operator qualification."""
    manifest = getattr(args, "release_manifest", None)
    root = getattr(args, "installation_root", None)
    if manifest is None or root is None:
        raise h.BaselineError("operator qualification requires explicit installation root and reviewed release manifest")
    release = json.loads(manifest.read_text())
    verifier = root / "tools/conformance.py"
    if (verifier.is_symlink() or not verifier.is_file()
            or hashlib.sha256(verifier.read_bytes()).hexdigest() != release["files"].get("tools/conformance.py")):
        raise h.BaselineError("installed conformance verifier differs from selected release")
    result = h.subprocess.run([h.sys.executable, str(verifier), "--root", str(root),
                              "--expected-manifest", str(manifest), "--host"],
                             stdout=h.subprocess.DEVNULL, stderr=h.subprocess.DEVNULL,
                             check=False, timeout=120)
    if result.returncode:
        raise h.BaselineError("installed architecture fails selected release conformance; no workload authorized")


def validate_operator_context(response, authority, error=ValueError):
    policy=authority["protected"]
    if not isinstance(policy.get("ingress_kem_registry"),dict) or response.get("ingress_kem_registry")!=policy["ingress_kem_registry"]:
        raise error("processing ingress keys differ from pinned operator signed authority")


def validate_context(response, network, epoch, chain_id, error=ValueError):
    if not isinstance(response, dict) or not isinstance(response.get("context"), dict):
        raise error("processing context response must be an object")
    context = response["context"]
    authority = context.get("authority", {})
    if not isinstance(authority, dict):
        raise error("processing authority must be an object")
    if (response.get("profile_id") != PROFILE or context.get("profile_id") != PROFILE
            or context.get("context_version") != 1 or type(authority.get("chain_id")) is not int or authority.get("chain_id") != chain_id
            or authority.get("network_id") != network or authority.get("epoch") != epoch
            or not isinstance(response.get("ingress_kem_registry"), dict)):
        raise error("processing context differs from expected native profile/network/epoch")
    # The anchor authenticates keys. It is never an inclusion height or deadline.
    if type(authority.get("target_height")) is not int or authority["target_height"] < 3:
        raise error("processing authorization anchor is invalid")
    return authority


def validate_block_views(views, height, error=ValueError, *, compare=True):
    for name, block in views.items():
        if (not isinstance(block, dict) or block.get("height") != height
                or not all(isinstance(block.get(key), str) and block[key]
                           for key in ("block_hash", "state_root", "finality_certificate_id", "protected_execution_root"))
                or not isinstance(block.get("transactions"), list)
                or not isinstance(block.get("receipts"), list)
                or len(block["transactions"]) != len(block["receipts"])
                or not all(isinstance(item, dict) for item in block["transactions"])):
            raise error(f"{name} invalid native finalized block at H{height}")
    fingerprints = {block_fingerprint(block) for block in views.values()} if compare else {None}
    if len(fingerprints) != 1:
        raise error("validators disagree on native finalized block contents/commitments")
    block = next(iter(views.values()))
    ids = [receipt.get("transaction_id") for receipt in block["receipts"] if isinstance(receipt, dict)]
    if len(ids) != len(block["receipts"]) or len(ids) != len(set(ids)):
        raise error("native finalized block has invalid/duplicate receipt identities")
    return block


def observe_intervals(previous, current):
    """Only adjacent observed heights yield an interval; never fill a gap."""
    if previous is None:
        return {"interval_seconds": None, "height_gap": 0}
    delta = current["height"] - previous["height"]
    if delta < 0:
        raise ValueError("validator finalized height regressed")
    return {"interval_seconds": current["observed_mono"] - previous["observed_mono"] if delta == 1 else None,
            "height_gap": max(0, delta - 1)}



def validate_finalized_intent(transaction, record, network, chain_id, error=ValueError):
    intent = record["intent"]
    expected = {"network": {"chain_id": chain_id, "network_id": network}, "class": "user",
                "sender": record["sender"], "receiver": intent["receiver"],
                "amount_nwei": intent["amount_nwei"], "nonce": record["nonce"],
                "fee_limit": {"gas_limit": intent["gas_limit"], "max_fee_per_gas_nwei": intent["max_fee_per_gas_nwei"]},
                "timestamp_unix": intent["timestamp_unix"], "payload": []}
    if transaction.get("unsigned") != expected or transaction.get("signature_algorithm") != "ML-DSA-87":
        raise error("native finalized transaction differs from exact signed intent")


def run_async(args, h):
    E = h.BaselineError
    endpoints = dict(args.validator_rpc)
    report = {"status": "running", "profile_id": PROFILE, "network_id": args.network_id,
              "transactions": [], "TPS_qualified": False, "capacity_result": False,
              "workload_mode": args.workload_mode, "execute": args.execute}
    args._partial_report = report
    if set(endpoints) != set(h.VALIDATORS) or len(args.validator_rpc) != 5:
        raise E("exactly five distinct validator endpoints required")
    operator=bool(args.operator_wallet_registry)
    if operator:
        verify_installed_release(args, h)
    if not args.wallet_registry or args.remote_signer or args.signer_dir:
        raise E("async pool runs on the explicit custody host; registry required and legacy signer flags prohibited")
    if not args.output:
        raise E("async mode requires --output to retain raw evidence")
    if (not 1 <= args.duration_seconds <= 86400 or not 1 <= args.max_tx <= MAX_TRANSACTIONS
            or not math.isfinite(args.rate_tps) or not 0 < args.rate_tps <= MAX_OFFERED_TPS
            or not 1 <= args.max_in_flight <= 4096 or not 10 <= args.stability_seconds <= 120
            or not math.isfinite(args.maximum_gap_seconds) or not 0 < args.maximum_gap_seconds <= 600):
        raise E("async workload requires existing generator and block stall bounds")
    h.operational_drain_deadline(args, 0)
    wallets = h.wallet_pool_public(args.wallet_registry, args.network_id, operator)
    selected = getattr(args, "wallet_id", [])
    if selected:
        if len(selected) != len(set(selected)) or not set(selected).issubset({w["wallet_id"] for w in wallets}):
            raise E("selected workload wallet IDs must be unique existing registry entries")
        wallets = [w for w in wallets if w["wallet_id"] in selected]
        report["selected_wallet_ids"] = selected
    closed = h.validate_pool_workload(args, len(wallets))
    per_wallet = getattr(args, "max_in_flight_per_wallet", 1)
    if type(per_wallet) is not int or not 1 <= per_wallet <= 256:
        raise E("per-wallet generator window must be an explicit integer in 1..256")
    if args.max_in_flight > len(wallets) * per_wallet or args.receiver in {w["sender"] for w in wallets}:
        raise E("independent sender wallets and receiver required for bounded in-flight cap")
    if any(type(v) is not int or v <= 0 for v in (args.amount_nwei, args.gas_limit, args.max_fee_per_gas_nwei, args.gas_class_units)) or args.gas_class_units != args.gas_limit:
        raise E("positive fee/gas values and matching inner/outer gas classification required")
    registry = json.loads(args.wallet_registry.read_text())
    custody = {entry["wallet_id"]: entry for entry in registry["wallets"]}
    fixture_root = Path(registry["fixture_root"])
    for entry in custody.values():
        for field in ("wallet_public_path", "transaction_secret_path"):
            path = Path(entry[field])
            if not path.is_absolute() or ".." in path.parts or fixture_root not in path.parents:
                raise E("async custody must remain in its explicit isolated fixture")
            if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
                raise E("async custody path must be regular and non-symlink")
            if field == "transaction_secret_path" and (stat.S_IMODE(path.stat().st_mode) != 0o600 or not 0 < path.stat().st_size <= 64 * 1024):
                raise E("async native custody requires bounded 0600 secret; Python never reads it")
    authority_path = Path(registry["authority_binding_path"])
    if authority_path.is_symlink() or not authority_path.is_file() or authority_path.stat().st_size > 4 * 1024 * 1024:
        raise E("bounded fixture authority required")
    authority = json.loads(authority_path.read_text())["payload"]
    policy = authority["protected"]
    if (authority["network_id"] != args.network_id or policy["version"] != 2
            or policy["cutoff_relationship"] != "processing_groups_v1"):
        raise E("pinned signed authority does not select approved async profile")
    chain_id = registry.get("chain_id")
    if type(chain_id) is not int or not 0 < chain_id < 2**64 or type(authority.get("chain_id")) is not int or authority.get("chain_id") != chain_id:
        raise E("selected registry and authenticated authority chain ID differ")
    report["chain_id"] = chain_id
    epoch = authority["epoch"]
    # Launch readiness is checked at actual exec by deployment. This later load
    # stage checks live health plus bounded common finalized progression.
    first = h.sample_fleet(endpoints, args.network_id, native_tips=True, expected_chain_id=chain_id, live_progress=True)
    report["readiness_scope"] = "live healthy services; normal Sync Pending permitted only with verified advancing common finality; actual-exec startup gate remains separate"
    initial_height = first["val2"]["common_height"]
    previous_height = initial_height
    state = first
    progress_at = time.monotonic()
    preflight_start = progress_at
    while time.monotonic() - preflight_start < args.stability_seconds:
        time.sleep(h.POLL_SECONDS)
        state = h.sample_fleet(endpoints, args.network_id, native_tips=True, expected_chain_id=chain_id,
                               native_prior_state=state)
        height = state["val2"]["common_height"]
        if height < previous_height:
            raise E("preflight finalized height regressed")
        if height > previous_height:
            progress_at = time.monotonic()
        elif time.monotonic() - progress_at > args.maximum_gap_seconds:
            raise E("preflight finality stalled")
        previous_height = height
    if previous_height <= initial_height:
        raise E("no preflight finalized progression")
    preflight_cadence = (time.monotonic() - preflight_start) / (previous_height - initial_height)
    report["preflight_average_block_time_seconds"] = preflight_cadence
    if not 0.5 <= preflight_cadence <= 1.5 and not getattr(args, "measure_outside_cadence_target", False):
        raise E("average finalized block cadence over full preflight window is outside 0.5–1.5 seconds")
    report.update(preflight_complete=True, preflight_end_tip=h.tip_record(state), generator_limits={
        "wallet_count": len(wallets), "in_flight_cap": args.max_in_flight,
        "wallet_window_slots": len(wallets) * per_wallet,
        "offered_rate_cap_tps": MAX_OFFERED_TPS,
        "per_wallet_in_flight_cap": per_wallet,
        "nonce_window_basis": "conservative generator bound, not an assertion of native admission-policy enforcement",
        "native_signer": "bounded native command processes; sequential immutable nonce intents per wallet",
        "limitation": "signing/RPC/polling can limit generator; skipped slots never prove chain capacity"})
    keytool = args.keytool.resolve(strict=True)
    if not keytool.is_file() or not os.access(keytool, os.X_OK):
        raise E("native wallet signer executable required")
    if operator:
        verify_operator_registry(keytool,args.wallet_registry,h)
    report.update(custody_mode="operator-wallet-allowlist-v1" if operator else "isolated-synthetic",
        native_operator_registry_verified=operator)
    common = state["val2"]["common_height"]
    for wallet in wallets:
        initial = h.pool_account(endpoints, wallet["sender"], common, include_views=True)
        authority_mode = validate_wallet_authority(initial["validator_views"], json.loads(Path(custody[wallet["wallet_id"]]["wallet_public_path"]).read_text()), E)
        wallet.update(initial)
        wallet["authority_mode"] = authority_mode
        wallet.update(initial_nonce=wallet["nonce"], initial_balance=wallet["balance_nwei"], spent=0,
                      next_nonce=wallet["nonce"], outstanding={}, retired=False)
        if wallet["balance_nwei"] < args.amount_nwei + args.gas_limit * args.max_fee_per_gas_nwei:
            raise E("independent generator wallet is not funded on all five")
    receiver_initial = h.pool_account(endpoints, args.receiver, common, include_views=True)
    report["workload_wallet_authority_verified_all_five"] = all(w["authority_mode"] == "existing_binding_verified" for w in wallets)
    report["workload_wallet_authority_modes"] = {w["wallet_id"]: w["authority_mode"] for w in wallets}
    report["first_use_authority_basis"] = "uniformly absent canonical binding is not preauthorization; native authoring verifies root-signed owner/delegated-key carrier before any submission"
    if not args.execute:
        report["status"] = "dry_run_ready"
        return report
    proof_path = args.raw_proof_stream or args.output.with_suffix(".proof.jsonl")
    if proof_path.absolute() == args.output.absolute():
        raise E("raw proof and summary paths must differ")
    proof = h.RawProofStream(proof_path, args.raw_proof_budget_bytes)
    report["raw_proof_stream"] = proof.metadata()
    report["transaction_record_retention"] = "unresolved only; terminal intent/effects streamed once then aggregated"
    report["latency_quantile_method"] = "fixed 1-percent logarithmic-bin upper bounds; exact maximum"
    cancellation = threading.Event()
    generator_resources = GeneratorResources()
    observer = SingleFlightObserver(cancellation)
    start = time.monotonic()
    deadline = start + args.duration_seconds
    drain_deadline = h.operational_drain_deadline(args, deadline)
    next_slot = None if closed else start
    available = list(wallets)
    jobs = {}
    pending = {}
    transactions = report["transactions"]
    warmup_seconds = getattr(args, "warmup_seconds", None)
    warmup_seconds = min(30, args.duration_seconds / 4) if warmup_seconds is None else warmup_seconds
    if not math.isfinite(warmup_seconds) or not 0 <= warmup_seconds < args.duration_seconds:
        raise E("warmup must be finite and shorter than offered window")
    totals = WorkloadTotals(deadline, start + warmup_seconds)
    published = {}
    published_lock = threading.RLock()
    proof_lock = threading.Lock()
    attempted = skipped = peak = 0
    last_sample = start - 1
    last_progress = start
    last_common = common
    scanned = common
    block_previous = {}
    intervals = {name: BoundedDistribution() for name in endpoints}
    backlog_peak = {"authoring": 0, "submitted_unfinalized": 0}
    gaps = {name: 0 for name in endpoints}
    failure = None
    report.update(start_utc=h.utc_now(), workload_start_mono=start, workload_deadline_mono=deadline,
                  transaction_latency_limit_seconds=None, drain_timeout_seconds=getattr(args,"drain_timeout_seconds",None), maximum_gap_seconds=args.maximum_gap_seconds,
                  block_observation_basis="local monotonic RPC response times; adjacent observed heights only; gaps retained",
                  protocol_timestamp_basis="derived from signed governed epoch start/block-time policy; not wall-clock production time")
    temp_parent = args.temp_dir.resolve(strict=True) if args.temp_dir else None
    temporary = tempfile.TemporaryDirectory(prefix="posy-async-authoring-", dir=temp_parent)
    author_root = Path(temporary.name).resolve(strict=True)
    author_root.chmod(0o700)

    def append(value):
        with proof_lock:
            return proof.append(value)

    def offer(wallet, nonce, scheduled, sequence):
        if cancellation.is_set():
            raise E("async authoring cancelled")
        began = time.monotonic()
        operation_end = min(began + 30, deadline) if closed else began + 30
        context = h.rpc(endpoints[args.submit_validator], "synergy_getProcessingContextV1", {})
        anchor = validate_context(context, args.network_id, epoch, chain_id, E)
        if operator:
            validate_operator_context(context,authority,E)
        received = time.monotonic()
        entry = custody[wallet["wallet_id"]]
        work = author_root / str(sequence)
        work.mkdir(mode=0o700)
        def write(path, value):
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                json.dump(value, output, separators=(",", ":"))
        context_path, input_path, output_path = (work / name for name in ("context.json", "input.json", "admission.json"))
        write(context_path, context)
        timestamp = int(time.time())
        transfer = {"wallet_public_path": entry["wallet_public_path"], "transaction_secret_path": entry["transaction_secret_path"],
                    "admission_context_path": str(context_path), "sender": wallet["sender"], "receiver": args.receiver,
                    "amount_nwei": args.amount_nwei, "nonce": nonce, "timestamp_unix": timestamp,
                    "gas_limit": args.gas_limit, "max_fee_per_gas_nwei": args.max_fee_per_gas_nwei,
                    "gas_class_units": args.gas_class_units, "fee_class": args.fee_class, "content_blind_order_key": h.order_key()}
        write(input_path, transfer)
        if cancellation.is_set() or time.monotonic() >= operation_end:
            raise E("async signing cancelled/deadline reached before authoring")
        result = h.subprocess.run([str(keytool), "prepare-wallet-processing-admission", str(input_path), str(output_path)],
                                  stdin=h.subprocess.DEVNULL, stdout=h.subprocess.DEVNULL, stderr=h.subprocess.DEVNULL,
                                  check=False, timeout=max(0.1, operation_end - time.monotonic()))
        if result.returncode or output_path.is_symlink() or not output_path.is_file() or not 0 < output_path.stat().st_size <= 1024 * 1024:
            raise E("native async wallet authoring failed; no submission")
        encoded = output_path.read_bytes()
        admission = json.loads(encoded)
        # Public request/context bytes are retained in the bounded proof stream;
        # successful generator scratch must scale with concurrency, not duration.
        for path in (context_path, input_path, output_path):
            path.unlink()
        work.rmdir()
        signed_at = time.monotonic()
        txid = h.transaction_id(args.network_id, wallet["sender"], args.receiver, args.amount_nwei, nonce,
                                args.gas_limit, args.max_fee_per_gas_nwei, timestamp, chain_id=chain_id)
        record = {"transaction_id": txid, "receipt_id": processing_receipt_id(encoded), "sender": wallet["sender"],
                  "nonce": nonce, "authorization_height": anchor["target_height"], "wallet_id": wallet["wallet_id"],
                  "scheduled_mono": scheduled, "context_started_mono": began, "authored_mono": signed_at, "submitted_mono": signed_at,
                  "context_retrieval_seconds": received - began, "native_signing_seconds": signed_at - received,
                  "submission_started": False, "accepted": False, "ambiguous_response": False,
                  "intent": {key: transfer[key] for key in ("receiver", "amount_nwei", "gas_limit", "max_fee_per_gas_nwei", "timestamp_unix")}}
        record["admission_sha256"] = hashlib.sha256(encoded).hexdigest()
        del encoded, context
        # One lock order (publication -> proof) also protects atomic journal
        # compaction: it cannot erase an intent between writing and publishing it.
        with published_lock:
            if wallet["next_nonce"] != nonce or nonce in wallet["outstanding"]:
                raise E("nonce reservation changed before immutable intent publication")
            record["raw_admission_ref"] = append({"kind": "authored_processing_intent", "record": dict(record)})
            published[txid] = record
            wallet["outstanding"][nonce] = record
            wallet["next_nonce"] = nonce + 1
        if cancellation.is_set() or time.monotonic() >= operation_end:
            raise E("async submission cancelled/deadline reached")
        record["submission_started"] = True
        record["submitted_mono"] = time.monotonic()
        try:
            response = h.rpc(endpoints[args.submit_validator], "synergy_submitProcessingTransactionV1", admission)
        except h.RpcResponseError as error:
            record["submission_rejection"] = {"code": error.code, "message": error.message}
        except E as error:
            record.update(ambiguous_response=True, submission_error=str(error))
        else:
            if not isinstance(response, dict) or response.get("receipt_id") != record["receipt_id"]:
                record["ambiguous_response"] = True
                raise E("async RPC returned mismatching receipt identity; retain nonce for reconciliation")
        finally:
            record["submission_transport_seconds"] = time.monotonic() - record["submitted_mono"]
        if record.get("submission_rejection") or record.get("ambiguous_response"):
            # Do not create a successor behind an uncertain/rejected nonce. The
            # original remains available for exact observation, never resubmit.
            with published_lock:
                wallet["retired"] = True
        append({"kind": "submission", "record": record})
        return record

    def sample():
        def one(name):
            began = time.monotonic()
            value = h.rpc(endpoints[name], "synergy_chainTelemetry", {})
            ended = time.monotonic()
            if (not isinstance(value, dict) or value.get("chain_id") != chain_id or value.get("network_identity") != args.network_id
                    or value.get("epoch") != epoch or type(value.get("finalized_height")) is not int):
                raise E("async validator telemetry identity/epoch/height mismatch")
            return name, {"query_started_mono": began, "observed_mono": ended, "native": value,
                          "admission_stats": h.rpc(endpoints[name], "synergy_getProtectedAdmissionStats", {})}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as readers:
            readings = dict(readers.map(one, endpoints))
        heights = [item["native"]["finalized_height"] for item in readings.values()]
        if max(heights) - min(heights) > h.MAX_FINALIZED_LAG:
            # Existing bounded aligned-fleet observer distinguishes racing tips
            # from a persistent validator lag; no protocol wait is introduced.
            h.sample_fleet(endpoints, args.network_id, native_tips=True, expected_chain_id=chain_id,
                           native_prior_state=state)
        for name, item in readings.items():
            native = item["native"]
            commitment = native.get("common_finalized_commitment")
            height = native["finalized_height"]
            if not isinstance(commitment, dict) or commitment.get("height") != height:
                raise E("async telemetry lacks exact latest finalized commitment")
            current = {"height": height, "block_id": commitment.get("block_id"), "state_root": commitment.get("state_root"),
                       "finality_certificate_id": commitment.get("finality_certificate_id"), "observed_mono": item["observed_mono"],
                       "query_started_mono": item["query_started_mono"],
                       "protocol_timestamp_unix": (policy["epoch_start_timestamp_ms"] + (height - authority["epoch_start_height"]) * policy["target_block_time_ms"]) // 1000}
            previous = block_previous.get(name)
            if previous is None or previous["height"] != height:
                delta = observe_intervals(previous, current)
                if delta["interval_seconds"] is not None:
                    intervals[name].append(delta["interval_seconds"])
                gaps[name] += delta["height_gap"]
                append({"kind": "finalized_block_observation", "validator": name, **current, **delta})
                block_previous[name] = current
        backlog_peak["authoring"] = max(backlog_peak["authoring"], len(jobs))
        backlog_peak["submitted_unfinalized"] = max(backlog_peak["submitted_unfinalized"], len(pending))
        append({"kind": "fleet_sample", "observed_mono": time.monotonic(), "by_validator": readings,
                "backlog": {"authoring": len(jobs), "submitted_unfinalized": len(pending)}})
        return min(heights)

    def retire(record):
        with published_lock:
            retire_locked(record)

    def retire_locked(record):
        if not record.get("_harvested") or record.get("_aggregated"):
            return
        if (record.get("finalized_mono") is None and not record.get("submission_rejection")
                and not record.get("admission_rejection")):
            return
        totals.consume(record)
        record["_aggregated"] = True
        if record in transactions: transactions.remove(record)
        with published_lock:
            published.pop(record["transaction_id"], None)

    def compact_consumed():
        # The existing single operational journal becomes only the active
        # reconciliation set. Completed proofs have already been consumed here.
        with published_lock:
            active = [{key: value for key, value in record.copy().items()
                       if key not in ("raw_admission_ref", "raw_proof_ref", "_harvested", "_aggregated")}
                      for record in published.values()]
            checkpoint = {"kind": "active_intent_checkpoint", "scanned_finalized_height": scanned,
                "network_id": args.network_id, "chain_id": chain_id,
                "active": active, "totals": dict(totals.counts),
                "latencies": totals.latency_summary()}
            with proof_lock:
                reference = proof.compact(checkpoint)
            for record in published.values():
                record["raw_admission_ref"] = reference
                record.pop("raw_proof_ref", None)

    def finalized_blocks(height):
        nonlocal scanned
        # Exact forward-only bounded reads, never global transaction-history scans.
        for block_height in range(scanned + 1, min(height, scanned + MAX_BLOCKS_PER_SAMPLE) + 1):
            # Keep one canonical block plus at most one comparison response,
            # never five decoded byte-array-heavy blocks and their JSON copies.
            block = None; expected_fingerprint = None; block_refs = {}
            for name in endpoints:
                view = h.rpc(endpoints[name], "synergy_getBlock", {"height": block_height, "hash": None})
                validate_block_views({name: view}, block_height, E, compare=False)
                fingerprint = block_fingerprint(view)
                if expected_fingerprint is not None and fingerprint != expected_fingerprint:
                    raise E("validators disagree on native finalized block contents/commitments")
                if block is None:
                    block_refs[name] = append({"kind": "validator_finalized_block", "validator": name,
                        "observed_mono": time.monotonic(), "block": view,
                        "canonical_sha256": fingerprint.hex()})
                    block = view; expected_fingerprint = fingerprint
                else:
                    block_refs[name] = append({"kind": "validator_finalized_block_match", "validator": name,
                        "observed_mono": time.monotonic(), "height": block_height,
                        "canonical_sha256": fingerprint.hex(), "canonical_block_ref": next(iter(block_refs.values()))})
                del view
            append({"kind": "common_finalized_block", "observed_mono": time.monotonic(), "height": block_height,
                    "block_id": block["block_hash"], "transaction_count": len(block["transactions"])})
            by_wallet = {}
            for transaction, receipt in zip(block["transactions"], block["receipts"]):
                txid = receipt["transaction_id"]
                record = pending.get(txid)
                if record is None:
                    # A submission may finish transport after its block finalized.
                    with published_lock:
                        record = published.get(txid)
                if record is None:
                    if transaction.get("unsigned", {}).get("sender") in {w["sender"] for w in wallets}:
                        raise E("workload sender finalized an unknown transaction; reconcile custody")
                    continue
                if record.get("finalized_mono") is not None:
                    raise E("an authored transaction appeared in more than one finalized block")
                validate_finalized_intent(transaction, record, args.network_id, chain_id, E)
                unsigned = transaction.get("unsigned", {})
                gas = receipt.get("gas_used")
                if (receipt.get("status") != "applied" or unsigned.get("sender") != record["sender"]
                        or unsigned.get("nonce") != record["nonce"] or unsigned.get("receiver") != args.receiver
                        or int(unsigned.get("amount_nwei", -1)) != args.amount_nwei
                        or type(gas) is not int or not 0 <= gas <= args.gas_limit):
                    raise E("native finalized transfer differs from exact authored intent")
                by_wallet.setdefault(record["wallet_id"], []).append((record, gas))
            # An account view is the END of the block. Verify the complete
            # contiguous sender cohort once, rather than pretending each receipt
            # has an intermediate account snapshot when several share a block.
            for wallet_id, cohort in by_wallet.items():
                wallet = next(w for w in wallets if w["wallet_id"] == wallet_id)
                if [record["nonce"] for record, _ in cohort] != list(range(wallet["nonce"], wallet["nonce"] + len(cohort))):
                    raise E("finalized sender cohort skips or reorders a reserved nonce")
                account = h.pool_account(endpoints, wallet["sender"], block_height, include_views=True)
                debit = wallet["balance_nwei"] - account["balance_nwei"]
                amount = len(cohort) * args.amount_nwei
                maximum_fee = sum(gas * record["intent"]["max_fee_per_gas_nwei"] for record, gas in cohort)
                if account["nonce"] != wallet["nonce"] + len(cohort) or not amount <= debit <= amount + maximum_fee:
                    raise E("all-five finalized sender effects differ from exactly-once transfer cohort/fee bound")
                observed = time.monotonic()
                with published_lock:
                    wallet.update(nonce=account["nonce"], balance_nwei=account["balance_nwei"], spent=wallet["spent"] + debit)
                cohort_ids = [record["transaction_id"] for record, _ in cohort]
                for record, _ in cohort:
                    record.update(finalized_mono=observed, block_height=block_height, accepted=True)
                    record["raw_proof_ref"] = append({"kind": "finalized_transfer", "record": dict(record),
                        "finalized_block_refs": block_refs, "sender_account_views": account["validator_views"],
                        "sender_block_cohort": cohort_ids})
                    with published_lock:
                        pending.pop(record["transaction_id"], None)
                        wallet["outstanding"].pop(record["nonce"], None)
                    retire(record)
            scanned = block_height
            compact_consumed()

    def harvest():
        for future, wallet in list(jobs.items()):
            if not future.done():
                continue
            del jobs[future]
            try:
                record = future.result()
            except Exception:
                cancellation.set()
                raise
            with published_lock:
                record["_harvested"] = True
                if record not in transactions:
                    transactions.append(record)
                if record.get("submission_rejection") or record.get("admission_rejection"):
                    record["wallet_retired_after_rejection"] = True
                elif record.get("finalized_mono") is None:
                    pending[record["transaction_id"]] = record
                retire_locked(record)

    receipt_cursor = 0
    def observe():
        nonlocal last_common, last_progress, receipt_cursor
        common = sample()
        if common < last_common:
            raise E("common finalized height regressed")
        if common > last_common:
            last_progress = time.monotonic()
            last_common = common
        elif time.monotonic() - last_progress > args.maximum_gap_seconds:
            raise E("async finality stalled beyond declared gap budget")
        finalized_blocks(common)
        with published_lock:
            pending_snapshot = list(pending.values())
        receipt_started = time.monotonic()
        # Receipt queries are a bounded fair slice, not a duration-sized queue.
        # A slow receipt endpoint must not starve exact forward block proofs.
        count = len(pending_snapshot)
        receipt_start_cursor = receipt_cursor
        for offset in range(min(count, MAX_RECEIPTS_PER_SAMPLE)):
            if offset and time.monotonic() - receipt_started >= h.POLL_SECONDS:
                break
            record = pending_snapshot[(receipt_start_cursor + offset) % count]
            receipt_cursor += 1
            receipt = h.observe_pool_receipt(endpoints[args.submit_validator], record)
            if receipt is not None:
                try:
                    record_lifecycle_stage(record, receipt, time.monotonic())
                except ValueError as error:
                    raise E(str(error)) from error
                if receipt.get("status") == "rejected":
                    record["admission_rejection"] = receipt.get("reason_code", receipt.get("reason"))
                    with published_lock:
                        pending.pop(record["transaction_id"], None)
                    record["wallet_retired_after_rejection"] = True
                    wallet = next(w for w in wallets if w["wallet_id"] == record["wallet_id"])
                    wallet["retired"] = True
                    retire(record)
                    if per_wallet > 1:
                        raise E("async admission rejected; reconcile original sender nonce cohort before further work")
                    continue
                if receipt.get("admitted") is True or receipt.get("status") == "accepted":
                    record.setdefault("admitted_mono", time.monotonic())
                    record["accepted"] = True

    author_workers = min(args.max_in_flight, getattr(args, "author_workers", 8))
    if type(author_workers) is not int or not 1 <= author_workers <= 256:
        raise E("author workers must be in 1..256")
    report["generator_limits"]["author_workers"] = author_workers
    report["generator_limits"]["maximum_parallel_wallet_authors"] = min(author_workers, len(wallets))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=author_workers)
    try:
        while (time.monotonic() < deadline and (not closed or attempted < args.max_tx)) or jobs or pending or observer.future is not None:
            observer.poll()
            if cancellation.is_set():
                # The only background cancellation source is a failed observer;
                # consume its exact exception before scheduling another intent.
                if observer.future is not None:
                    observer.future.result()
                raise E("async workload cancelled before further authoring")
            now = time.monotonic()
            if closed and now >= deadline:
                raise E("closed-loop memory count deadline exceeded")
            if now < deadline and attempted < args.max_tx and (closed or now >= next_slot):
                capacity = min(author_workers - len(jobs), args.max_tx - attempted,
                               args.max_in_flight - len(jobs) - len(pending))
                if closed:
                    slots = [now] * max(0, capacity)
                else:
                    slots, next_slot, missed = due_offer_slots(now, next_slot, args.rate_tps, max(0, capacity))
                    skipped += missed
                for scheduled in slots:
                    authoring_ids = {wallet["wallet_id"] for wallet in jobs.values()}
                    with published_lock:
                        wallet = next((wallet for wallet in available
                            if not wallet["retired"] and wallet["wallet_id"] not in authoring_ids
                            and len(wallet["outstanding"]) < per_wallet), None)
                        nonce = wallet["next_nonce"] if wallet is not None else None
                    if wallet is not None and len(jobs) + len(pending) < args.max_in_flight:
                        available.remove(wallet)
                        available.append(wallet)
                        # Reserve worst-case spend for all unresolved predecessors.
                        if wallet["balance_nwei"] < (len(wallet["outstanding"]) + 1) * (args.amount_nwei + args.gas_limit * args.max_fee_per_gas_nwei):
                            raise E("funded generator wallet budget exhausted")
                        jobs[executor.submit(offer, wallet, nonce, scheduled, attempted)] = wallet
                        attempted += 1
                        peak = max(peak, len(jobs) + len(pending))
                    elif not closed:
                        skipped += 1
            harvest()
            if (now < deadline or jobs or pending) and now - last_sample >= h.POLL_SECONDS and observer.start(observe):
                last_sample = now
            if drain_deadline is not None and time.monotonic() >= drain_deadline:
                raise E("explicit operational drain deadline reached; reconcile original requests before further authoring")
            time.sleep(min(0.01, max(0.000001, next_slot - time.monotonic()))
                       if not closed and attempted < args.max_tx and time.monotonic() < deadline else 0.01)
        executor.shutdown(wait=True)
        observer.close()
        compact_consumed()
        final_state = h.sample_fleet(endpoints, args.network_id, native_tips=True, expected_chain_id=chain_id,
                                     native_prior_state=state)
        final_height = final_state["val2"]["common_height"]
        effects = []
        for wallet in wallets:
            account = h.pool_account(endpoints, wallet["sender"], final_height, include_views=True)
            if account["nonce"] != wallet["nonce"] or account["balance_nwei"] != wallet["initial_balance"] - wallet["spent"]:
                raise E("final all-five sender wallet reconciliation failed")
            effects.append({"sender": wallet["sender"], "initial_nonce": wallet["initial_nonce"], "final_nonce": wallet["nonce"],
                            "initial_by_validator": wallet["validator_views"], "final_by_validator": account["validator_views"]})
        receiver_end = h.pool_account(endpoints, args.receiver, final_height, include_views=True)
        finalized_count = totals.counts["finalized"]
        if receiver_end["balance_nwei"] - receiver_initial["balance_nwei"] != finalized_count * args.amount_nwei:
            raise E("final all-five receiver credits differ from exact finalized cohort")
        now = time.monotonic()
        requested = 30 if closed else min(args.max_tx, math.ceil(args.rate_tps * args.duration_seconds))
        deadline_met = not closed or (finalized_count == 30 and attempted == 30 and now < deadline)
        rejected_count = totals.counts["rejected"]
        clean = finalized_count == requested and attempted == requested and not skipped and rejected_count == 0
        report.update(status="completed" if finalized_count and not rejected_count else "failed", end_utc=h.utc_now(), elapsed_seconds=now - start,
            measurement_complete=True, clean_load_step=clean, workload_authorization_valid=bool(finalized_count) and rejected_count == 0,
            offered_window_seconds=args.duration_seconds,
            cadence_target_met=0.5 <= preflight_cadence <= 1.5,
            measured_outside_cadence_target=getattr(args, "measure_outside_cadence_target", False),
            backlog={"peak": backlog_peak, "remaining_in_flight": 0},
            latency_observation_basis="all-five exact finalized block and wallet proof completion on local client clock; admission observations are upper bounds, no fabricated native timestamps",
            requested_transactions=requested, attempted_transactions=attempted,
            submitted_transactions=totals.counts["submitted"],
            finalized_transactions=finalized_count, remaining_in_flight=0, peak_in_flight=peak,
            generator_missed_offered_slots=None if closed else skipped, generator_limited=None if closed else skipped > 0 or attempted < requested,
            offered_rate_tps=None if closed else args.rate_tps, wallet_effects_verified_all_five=bool(finalized_count),
            workload_deadline_seconds=300 if closed else None, workload_deadline_met=deadline_met,
            observed_client_latency_seconds=totals.latency_summary(),
            native_processing_stage_observations=totals.processing_stage_summary(args.duration_seconds),
            native_stage_measurement_basis="authenticated RPC latest-stage receipt observations only; polling can skip stages; actual native stage TPS/timestamps remain unknown",
            independently_verified_tps=None if closed else totals.counts["finalized_window"] / args.duration_seconds,
            submitted_tps=None if closed else totals.counts["submitted_window"] / args.duration_seconds,
            admitted_tps=None if closed else totals.counts["admitted_window"] / args.duration_seconds,
            finalized_tps=None if closed else totals.counts["finalized_window"] / args.duration_seconds,
            end_to_end_finalized_tps=finalized_count/max(0.001,now-start),
            steady_state={"warmup_seconds": warmup_seconds, "duration_seconds": args.duration_seconds - warmup_seconds,
                "start_mono": start + warmup_seconds, "end_mono": deadline,
                "offered_target_tps": None if closed else args.rate_tps,
                "authored_and_encrypted_transactions": totals.counts["authored_steady"],
                "submitted_transactions": totals.counts["submitted_steady"],
                "observed_admitted_transactions": totals.counts["admitted_steady"],
                "all_five_verified_finalized_transactions": totals.counts["finalized_steady"],
                "authored_and_encrypted_tps": totals.counts["authored_steady"] / (args.duration_seconds - warmup_seconds),
                "submitted_tps": totals.counts["submitted_steady"] / (args.duration_seconds - warmup_seconds),
                "observed_admitted_tps": totals.counts["admitted_steady"] / (args.duration_seconds - warmup_seconds),
                "all_five_verified_finalized_tps": totals.counts["finalized_steady"] / (args.duration_seconds - warmup_seconds),
                "observation_basis": "client monotonic author/submission/first accepted observation/all-five proof completion",
                "native_availability_dependency_completion_tps": None,
                "native_execution_completion_tps": None,
                "native_result_publication_tps": None,
                "proposal_inclusion_tps": None,
                "unavailable_stage_reason": "native per-intent stage timestamps are not supplied by this measurement; no inferred values"},
            admitted_transactions=totals.counts["admitted"],
            measured_submitted_tps=None if closed else totals.counts["submitted_window"] / args.duration_seconds,
            rejection_count=totals.counts["rejected"],
            rejection_rate=totals.counts["rejected"] / max(1, totals.counts["submitted"]),
            rejection_reasons=totals.rejections,
            drain={"offered_window_end_mono": deadline, "drained_at_mono": now,
                   "seconds_after_offered_window": max(0, now - deadline), "unresolved": 0,
                   "finalized_after_offered_window": totals.counts["finalized"] - totals.counts["finalized_window"]},
            resource_observation_scope="generator process/native-child CPU and OS peak RSS measured here; raw fleet telemetry/admission counters retained; concurrent RSS, disk/network/cgroup deltas require existing actual-host monitor",
            block_times={name: {"finalized_observation_intervals_seconds": intervals[name].summary(), "skipped_heights": gaps[name]} for name in endpoints},
            wallet_effects_evidence={"before_height": state["val2"]["common_height"], "after_height": final_height, "senders": effects,
                "receiver": {"initial_by_validator": receiver_initial["validator_views"], "final_by_validator": receiver_end["validator_views"]}},
            end_tip=h.tip_record(final_state), note="One declared offered-load step; capacity needs controlled upper-range sweep, sustainable saturation and overload/drain evidence.")
        if not deadline_met:
            raise E("closed-loop memory cohort missed unchanged 300-second wallet-effects deadline")
        return report
    except BaseException as error:
        failure = str(error) or type(error).__name__
        cancellation.set()
        raise
    finally:
        cancellation.set()
        executor.shutdown(wait=True, cancel_futures=True)
        # Wait for the sole reader before closing/compacting its proof stream.
        # Preserve the original failure if both lanes failed.
        try:
            observer.close()
        except BaseException:
            if failure is None:
                raise
        report["generator_resources"] = generator_resources.summary()
        report["generator_observer"] = {"maximum_concurrent_reads": 1,
            "cycle_seconds": observer.durations.summary(),
            "offered_scheduler_independent": True}
        # Never discard a request that entered transport, including failed workers.
        with published_lock:
            for record in published.values():
                if record not in transactions:
                    transactions.append(record)
        if failure:
            for record in transactions:
                if not record.get("_aggregated"):
                    totals.consume(record); record["_aggregated"] = True
        report["remaining_in_flight"] = sum(r.get("submission_started", False) and r.get("finalized_mono") is None
                                            and not r.get("submission_rejection") and not r.get("admission_rejection") for r in transactions)
        if failure:
            report.update(status="failed", failure=failure, attempted_transactions=attempted,
                          submitted_transactions=totals.counts["submitted"],
                          finalized_transactions=totals.counts["finalized"],
                          admitted_transactions=totals.counts["admitted"],
                          rejection_count=totals.counts["rejected"],
                          measurement_complete=False, clean_load_step=False,
                          observed_client_latency_seconds=totals.latency_summary(),
                          native_processing_stage_observations=totals.processing_stage_summary(args.duration_seconds),
                          drain={"offered_window_end_mono": deadline, "observed_at_mono": time.monotonic(),
                                 "seconds_after_offered_window": max(0, time.monotonic()-deadline),
                                 "unresolved": report["remaining_in_flight"], "complete": False},
                          block_times={name: {"finalized_observation_intervals_seconds": intervals[name].summary(), "skipped_heights": gaps[name]} for name in endpoints},
                          backlog={"peak": backlog_peak, "remaining_in_flight": report["remaining_in_flight"]},
                          generator_limited=None if closed else skipped > 0,
                          generator_missed_offered_slots=None if closed else skipped)
        try:
            append({"kind": "workload_end", "observed_mono": time.monotonic(), "failure": failure,
                    "remaining_in_flight": report["remaining_in_flight"], "attempted": attempted})
        finally:
            proof.close()
            report["raw_proof_stream"] = proof.metadata()
            temporary.cleanup()
