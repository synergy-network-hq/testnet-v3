//! Isolated native state/candidate retention fixture. No network or validator access.
//! Run with an explicit report path: cargo run -p synergy-execution --example
//! retention_qualification -- /absolute/report.json [heights, default2048]
//! [--transaction-every 10 --burst-period 1000 --burst-heights 100
//! --transfers-per-height 4 --restart-every 5000 --sample-every 1000
//! --drain-seconds 30]. Synthetic state transfers are not encrypted ingress.
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use synergy_execution::{BudgetedCandidateStore, BudgetedExecutionCandidate};
use synergy_state::world_resources::{BudgetedWorld, WorldResourceBudget};
use synergy_state::{
    state_root, AccountChange, AccountState, FinalizedState, FinalizedStateStore, StateDiff,
    WorldState,
};

struct MeasuredAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn added(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            added(layout.size());
        }
        result
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc_zeroed(layout) };
        if !result.is_null() {
            added(layout.size());
        }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            if size > layout.size() {
                added(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

struct Options {
    heights: u64,
    transaction_every: u64,
    burst_period: u64,
    burst_heights: u64,
    transfers_per_height: u64,
    restart_every: u64,
    sample_every: u64,
    drain_seconds: u64,
}
impl Options {
    fn parse(args: &[String]) -> Self {
        let mut options = Self {
            heights: 2048,
            transaction_every: 4,
            burst_period: 0,
            burst_heights: 0,
            transfers_per_height: 1,
            restart_every: 128,
            sample_every: 128,
            drain_seconds: 0,
        };
        let mut index = 2;
        if args
            .get(index)
            .is_some_and(|value| !value.starts_with("--"))
        {
            options.heights = args[index].parse().expect("numeric heights");
            index += 1;
        }
        while index < args.len() {
            let value = args
                .get(index + 1)
                .expect("option requires numeric value")
                .parse()
                .expect("numeric option");
            match args[index].as_str() {
                "--transaction-every" => options.transaction_every = value,
                "--burst-period" => options.burst_period = value,
                "--burst-heights" => options.burst_heights = value,
                "--transfers-per-height" => options.transfers_per_height = value,
                "--restart-every" => options.restart_every = value,
                "--sample-every" => options.sample_every = value,
                "--drain-seconds" => options.drain_seconds = value,
                _ => panic!("unknown fixture option"),
            }
            index += 2;
        }
        assert!((128..=1_000_000).contains(&options.heights));
        assert!(
            options.transaction_every > 0 && options.restart_every > 0 && options.sample_every > 0
        );
        assert!(
            options.heights / options.sample_every <= 4096,
            "bounded sample history"
        );
        assert!((1..=64).contains(&options.transfers_per_height) && options.drain_seconds <= 300);
        assert!(options.burst_heights == 0 || (options.burst_period > options.burst_heights));
        options
    }
    fn transactions(&self, height: u64) -> u64 {
        if height.is_multiple_of(self.transaction_every)
            || (self.burst_period > 0 && (height - 1) % self.burst_period < self.burst_heights)
        {
            self.transfers_per_height
        } else {
            0
        }
    }
}

fn encoded_size(value: &impl serde::Serialize) -> u64 {
    struct Counter(u64);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("fixture encoding overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value).unwrap();
    count.0
}

#[cfg(target_os = "linux")]
fn linux_usage() -> serde_json::Value {
    fn read(path: impl AsRef<Path>) -> Option<String> {
        let mut value = String::new();
        std::fs::File::open(path)
            .ok()?
            .take(65537)
            .read_to_string(&mut value)
            .ok()?;
        assert!(value.len() <= 65536, "bounded Linux measurement");
        Some(value)
    }
    let group = read("/proc/self/cgroup").unwrap();
    let leaf = group.lines().find_map(|line| line.strip_prefix("0::"));
    let counters = leaf.map(|leaf| {
        assert!(
            leaf.starts_with('/')
                && !Path::new(leaf)
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
        );
        let root = Path::new("/sys/fs/cgroup").join(leaf.trim_start_matches('/'));
        [
            "memory.current",
            "memory.peak",
            "memory.max",
            "memory.swap.current",
            "memory.swap.max",
            "memory.stat",
            "memory.events",
            "memory.events.local",
            "memory.pressure",
            "cpu.stat",
            "cpu.pressure",
            "io.stat",
            "io.pressure",
        ]
        .into_iter()
        .map(|name| (name, read(root.join(name))))
        .collect::<std::collections::BTreeMap<_, _>>()
    });
    let status = read("/proc/self/status");
    let smaps = read("/proc/self/smaps_rollup");
    let memory_stat = counters
        .as_ref()
        .and_then(|values| values.get("memory.stat"))
        .and_then(Option::as_deref);
    fn counter(raw: Option<&str>, key: &str, scale: u64) -> Option<u64> {
        raw?.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()?.trim_end_matches(':') != key {
                return None;
            }
            parts.next()?.parse::<u64>().ok()?.checked_mul(scale)
        })
    }
    let metrics = serde_json::json!({"anon_bytes":counter(memory_stat,"anon",1),
        "file_bytes":counter(memory_stat,"file",1),"slab_bytes":counter(memory_stat,"slab",1),
        "pss_bytes":counter(smaps.as_deref(),"Pss",1024),
        "private_dirty_bytes":counter(smaps.as_deref(),"Private_Dirty",1024),
        "rss_bytes":counter(status.as_deref(),"VmRSS",1024)});
    serde_json::json!({"status":status,"smaps_rollup":smaps,"metrics_bytes":metrics,
        "process_io":read("/proc/self/io"),"process_stat":read("/proc/self/stat"),
        "fd_count":std::fs::read_dir("/proc/self/fd").unwrap().count(),
        "cgroup_leaf":leaf,"cgroup":counters})
}
#[cfg(not(target_os = "linux"))]
fn linux_usage() -> serde_json::Value {
    serde_json::Value::Null
}

fn files(root: &Path) -> (u64, u64, u64) {
    let mut count = 0;
    let mut bytes = 0;
    let mut directories = 0;
    if !root.exists() {
        return (count, bytes, directories);
    }
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_name().to_string_lossy().starts_with("._") {
            continue;
        }
        let metadata = entry.metadata().unwrap();
        if metadata.is_dir() {
            let (c, b, d) = files(&entry.path());
            count += c;
            bytes += b;
            directories += d + 1;
        } else {
            count += 1;
            bytes += metadata.len();
        }
    }
    (count, bytes, directories)
}
// ABI verified against the installed macOS SDK sys/resource.h and libproc.h.
// rusage_info_v2: UUID followed by eighteen uint64_t counters.
#[cfg(target_os = "macos")]
fn platform_usage() -> serde_json::Value {
    #[repr(C)]
    struct Usage {
        uuid: [u8; 16],
        counters: [u64; 18],
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut std::ffi::c_void) -> i32;
    }
    let mut usage = Usage {
        uuid: [0; 16],
        counters: [0; 18],
    };
    // The initialized repr(C) allocation has the complete SDK v2 layout; this
    // syscall writes only that requested flavor into this exclusively held buffer.
    let result = unsafe {
        proc_pid_rusage(
            std::process::id() as i32,
            2,
            (&mut usage as *mut Usage).cast(),
        )
    };
    if result != 0 {
        return serde_json::Value::Null;
    }
    let value = usage.counters;
    serde_json::json!({"source":"proc_pid_rusage/RUSAGE_INFO_V2", "user_time":value[0], "system_time":value[1],
        "pageins":value[4], "resident_bytes":value[6], "physical_footprint_bytes":value[7],
        "disk_bytes_read":value[16], "disk_bytes_written":value[17]})
}
#[cfg(not(target_os = "macos"))]
fn platform_usage() -> serde_json::Value {
    serde_json::Value::Null
}
fn write_sample(file: &mut std::fs::File, value: serde_json::Value) {
    serde_json::to_writer(&mut *file, &value).unwrap();
    file.write_all(b"\n").unwrap();
    file.flush().unwrap();
}

fn observation(
    height: u64,
    root: &Path,
    budget: &Arc<WorldResourceBudget>,
    started: Instant,
) -> serde_json::Value {
    let rss = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|kib| kib * 1024);
    let (count, bytes, directories) = files(root);
    serde_json::json!({"height":height,"elapsed_seconds":started.elapsed().as_secs_f64(),"allocated_live_bytes":LIVE.load(Ordering::Relaxed),
        "allocated_peak_bytes":PEAK.load(Ordering::Relaxed),"world_reserved_bytes":budget.used(),"rss_bytes":rss,"file_count":count,"logical_bytes":bytes,
        "directory_count":directories,"filesystem_entries":count+directories,
        "platform_usage":platform_usage(),"linux_usage":linux_usage(),
        "linux_process_io":std::fs::read_to_string("/proc/self/io").ok(),
        "linux_cgroup":std::fs::read_to_string("/proc/self/cgroup").ok()})
}

fn drain_window(
    label: &str,
    height: u64,
    root: &Path,
    budget: &Arc<WorldResourceBudget>,
    started: Instant,
    seconds: u64,
    log: &mut std::fs::File,
) -> serde_json::Value {
    let before = Instant::now();
    let mut count = 0;
    let mut ranges = std::collections::BTreeMap::<String, (u64, u64)>::new();
    loop {
        let mut sample = observation(height, root, budget, started);
        sample["phase"] = serde_json::json!(label);
        sample["synthetic_state_backlog"] = serde_json::json!(0);
        for name in [
            "allocated_live_bytes",
            "world_reserved_bytes",
            "rss_bytes",
            "file_count",
            "filesystem_entries",
        ] {
            if let Some(value) = sample[name].as_u64() {
                let range = ranges.entry(name.into()).or_insert((value, value));
                range.0 = range.0.min(value);
                range.1 = range.1.max(value);
            }
        }
        for name in ["anon_bytes", "pss_bytes", "private_dirty_bytes"] {
            if let Some(value) = sample["linux_usage"]["metrics_bytes"][name].as_u64() {
                let range = ranges.entry(name.into()).or_insert((value, value));
                range.0 = range.0.min(value);
                range.1 = range.1.max(value);
            }
        }
        if let Some(value) = sample["linux_usage"]["fd_count"].as_u64() {
            let range = ranges.entry("fd_count".into()).or_insert((value, value));
            range.0 = range.0.min(value);
            range.1 = range.1.max(value);
        }
        write_sample(log, sample);
        count += 1;
        if before.elapsed().as_secs() >= seconds {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    serde_json::json!({"phase":label,"height":height,"duration_seconds":before.elapsed().as_secs_f64(),
        "requested_seconds":seconds,"sample_count":count,"ranges_min_max":ranges,"backlog":0,
        "scope":"synchronous state/candidate workload drained; not ETDAG/native consensus"})
}

fn compare_windows(early: &serde_json::Value, late: &serde_json::Value) -> serde_json::Value {
    // Predetermined absolute allowances for allocator/measurement jitter. The
    // file allowance is three retained64-height reconstruction/checkpoint windows.
    let tolerances = [
        ("allocated_live_bytes", 256 * 1024),
        ("world_reserved_bytes", 256 * 1024),
        ("rss_bytes", 2 * 1024 * 1024),
        ("anon_bytes", 2 * 1024 * 1024),
        ("pss_bytes", 2 * 1024 * 1024),
        ("private_dirty_bytes", 2 * 1024 * 1024),
        ("filesystem_entries", 3 * 64),
        ("fd_count", 2),
    ];
    let mut results = std::collections::BTreeMap::new();
    for (name, allowance) in tolerances {
        let before = early["ranges_min_max"][name][1].as_u64();
        let after = late["ranges_min_max"][name][1].as_u64();
        let passed = before
            .zip(after)
            .map(|(first, last)| last <= first + allowance);
        assert!(
            passed != Some(false),
            "late drained working set exceeded fixed allowance: {name}"
        );
        results.insert(
            name,
            serde_json::json!({"early_max":before,"late_max":after,
            "allowance":allowance,"passed":passed,"unavailable":passed.is_none()}),
        );
    }
    serde_json::json!(results)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() >= 2,
        "explicit absolute output report path required"
    );
    assert!(Path::new(&args[1]).is_absolute());
    let options = Options::parse(&args);
    let heights = options.heights;
    let initial_balance = u128::from(heights * options.transfers_per_height).max(999_999) + 1;
    let root = std::env::temp_dir().join(format!(
        "synergy-retention-measured-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let budget = WorldResourceBudget::new(64 * 1024 * 1024);
    let mut baseline = WorldState::default();
    baseline
        .protocol
        .insert("unchanged-large-payload".into(), vec![7; 8192]);
    for index in 0..256 {
        baseline.accounts.insert(
            format!("account-{index:04}"),
            AccountState {
                balance_nwei: initial_balance,
                nonce: 0,
                code_hash: None,
            },
        );
    }
    let mut parent_world = Arc::new(BudgetedWorld::try_clone_world(&baseline, &budget).unwrap());
    let mut parent = "genesis".to_string();
    let mut candidates =
        BudgetedCandidateStore::new_budgeted(root.join("candidates"), Arc::clone(&budget)).unwrap();
    let mut states =
        FinalizedStateStore::load_budgeted(root.join("states"), Arc::clone(&budget)).unwrap();
    let mut restored_snapshot: Option<FinalizedStateStore> = None;
    let mut snapshots = 0;
    let mut restarts = 0;
    let mut transferred = 0;
    let mut transaction_heights = 0;
    let mut removed = 0;
    let mut cumulative_payload_bytes = 0;
    let mut repeated_full_bytes = 0;
    let started = Instant::now();
    let mut early_window = None;
    let warmup = 256.max(options.restart_every.saturating_add(128));
    let early_height = warmup + (heights % 64 + 64 - warmup % 64) % 64;
    let sample_path = Path::new(&args[1]).with_extension("samples.jsonl");
    let mut sample_log = std::fs::File::create(&sample_path).unwrap();
    write_sample(&mut sample_log, observation(0, &root, &budget, started));
    for height in 1..=heights {
        let transactions = options.transactions(height);
        let world = if transactions > 0 {
            transaction_heights += 1;
            let mut world = parent_world.try_clone().unwrap();
            for _ in 0..transactions {
                let diff = StateDiff {
                    changes: vec![
                        AccountChange {
                            account: "account-0000".into(),
                            debit_nwei: 1,
                            credit_nwei: 0,
                            expected_nonce: Some(transferred),
                            code_hash: None,
                        },
                        AccountChange {
                            account: "account-0001".into(),
                            debit_nwei: 0,
                            credit_nwei: 1,
                            expected_nonce: None,
                            code_hash: None,
                        },
                    ],
                    protocol_changes: vec![],
                };
                world.try_apply(&diff).unwrap();
                diff.apply(&mut baseline).unwrap();
                transferred += 1;
            }
            Arc::new(world)
        } else {
            // Empty heights share the charged immutable parent, without a
            // full-World copy. Real state changes own one bounded next World.
            Arc::clone(&parent_world)
        };
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes("fixture", b"execution"),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("fixture", b"batch"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                "fixture", b"cutoff",
            ),
        };
        let mut candidate = BudgetedExecutionCandidate {
            resource_permit: Some(Arc::new(budget.reserve(16 * 1024).unwrap())),
            height,
            block_id: String::new(),
            parent_block_id: parent,
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: state_root(&world).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: world,
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        assert_eq!(candidate.state_root, state_root(&baseline).unwrap());
        assert_eq!(candidate.state.as_ref().as_ref(), &baseline);
        candidates.put_budgeted(&candidate, &parent_world).unwrap();
        let finalized = FinalizedState {
            finalized_height: height,
            finalized_block_id: candidate.block_id.clone(),
            state_root: candidate.state_root.clone(),
        };
        states
            .commit_verified_world_transition(finalized.clone(), &parent_world, &candidate.state)
            .unwrap();
        if let Some(snapshot) = restored_snapshot.as_mut() {
            snapshot
                .commit_verified_world_transition(finalized, &parent_world, &candidate.state)
                .unwrap();
            snapshot.prune_finalized_history(height, 64).unwrap();
        }
        for (namespace, subdir) in [
            ("candidates", "candidate-world"),
            ("states", "finalized-world"),
        ] {
            cumulative_payload_bytes += std::fs::metadata(
                root.join(namespace)
                    .join(subdir)
                    .join(format!("{height:020}.json")),
            )
            .unwrap()
            .len();
        }
        repeated_full_bytes += 2 * encoded_size(candidate.state.as_ref());
        removed += states
            .prune_finalized_history(height, 64)
            .unwrap()
            .removed_records;
        removed += candidates
            .prune_finalized_history(height, 64)
            .unwrap()
            .removed_records;
        parent = candidate.block_id.clone();
        parent_world = Arc::clone(&candidate.state);
        drop(candidate);
        if height.is_multiple_of(options.restart_every) {
            drop(candidates);
            drop(states);
            candidates =
                BudgetedCandidateStore::new_budgeted(root.join("candidates"), Arc::clone(&budget))
                    .unwrap();
            states = FinalizedStateStore::load_budgeted(root.join("states"), Arc::clone(&budget))
                .unwrap();
            let restored = candidates.get_budgeted(height).unwrap().unwrap();
            assert_eq!(restored.state.as_ref().as_ref(), &baseline);
            assert_eq!(restored.block_id, parent);
            drop(restored);
            let rebuilt = states
                .current_world_state_budgeted(&budget)
                .unwrap()
                .unwrap();
            assert_eq!(rebuilt.as_ref(), &baseline);
            drop(rebuilt);
            restarts += 1;
            let snapshot = states.world_state_bytes_at(height).unwrap().unwrap();
            let world: WorldState = serde_json::from_slice(&snapshot).unwrap();
            assert_eq!(&world, &baseline);
            assert_eq!(
                state_root(&world).unwrap(),
                states.current().unwrap().state_root
            );
            drop(restored_snapshot.take());
            std::fs::remove_dir_all(root.join("snapshot-rejoin")).ok();
            let mut snapshot_store = FinalizedStateStore::load_budgeted(
                root.join("snapshot-rejoin"),
                Arc::clone(&budget),
            )
            .unwrap();
            snapshot_store
                .commit_verified_world_state(states.current().unwrap().clone(), &world)
                .unwrap();
            restored_snapshot = Some(snapshot_store);
            snapshots += 1;
            assert!(candidates.get_budgeted(height - 64).unwrap().is_none());
        }
        if height.is_multiple_of(options.sample_every) || height == heights {
            write_sample(
                &mut sample_log,
                observation(height, &root, &budget, started),
            );
        }
        if early_window.is_none() && height >= early_height && height < heights {
            early_window = Some(drain_window(
                "early-post-warmup-drain",
                height,
                &root,
                &budget,
                started,
                options.drain_seconds,
                &mut sample_log,
            ));
        }
    }
    let late_window = drain_window(
        "late-post-workload-drain",
        heights,
        &root,
        &budget,
        started,
        options.drain_seconds,
        &mut sample_log,
    );
    let window_comparison = early_window
        .as_ref()
        .map(|early| compare_windows(early, &late_window));
    let root_hash = states.current().unwrap().state_root.clone();
    assert_eq!(
        baseline.accounts["account-0000"].balance_nwei,
        initial_balance - u128::from(transferred)
    );
    assert_eq!(
        baseline.accounts["account-0001"].balance_nwei,
        initial_balance + u128::from(transferred)
    );
    assert_eq!(baseline.accounts["account-0000"].nonce, transferred);
    drop((
        candidates,
        states,
        parent_world,
        restored_snapshot,
        baseline,
    ));
    assert_eq!(budget.used(), 0);
    let drained = observation(heights, &root, &budget, started);
    drop(sample_log);
    // Load measurement history only after the measured workload has drained.
    let samples: Vec<serde_json::Value> = std::fs::read_to_string(&sample_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let report = serde_json::json!({"schema_version":2,"heights":heights,"empty_blocks":heights-transaction_heights,
        "transaction_bearing_heights":transaction_heights,"touched_account_transfers":transferred,
        "workload":{"transaction_every":options.transaction_every,"burst_period":options.burst_period,
          "burst_heights":options.burst_heights,"transfers_per_transaction_height":options.transfers_per_height,
          "restart_every":options.restart_every,"sample_every":options.sample_every},
        "equal_duration_post_drain_windows":{"early":early_window,"late":late_window},
        "drained_working_set_comparison":window_comparison,
        "checkpoint_interval":64,"retention_blocks":64,"restart_reconstructions":restarts,"snapshot_restore_rejoins":snapshots,
        "all_roots_and_account_outcomes_match":true,"final_state_root":root_hash,"budget_limit_bytes":budget.limit(),
        "world_payload_bytes_written":cumulative_payload_bytes,"repeated_full_world_reference_bytes":repeated_full_bytes,
        "retired_records":removed,"samples":samples,"after_drain":drained,
        "limitations":["Isolated native state/candidate fixture, not live PoSy qualification.","Transfers exercise touched-account execution state, not encrypted ingress; run native encrypted owner regressions separately.",
        "Allocation counters measure requested heap bytes, excluding allocator metadata and file cache.","Payload counts exclude atomic WAL/staging and filesystem amplification; Darwin proc_pid_rusage or Linux /proc and external time provide available OS counters.",
        "State/candidate heights do not constitute three-QC consensus heights; transaction-bearing here means synthetic touched-account state transitions, not encrypted ingress.",
        "No Linux cgroup metrics when run on macOS. No24h/live stability claim."]});
    std::fs::write(&args[1], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!(
        "{}",
        serde_json::json!({"report":args[1],"heights":heights,"same_roots":true,"world_reservations_after_drain":budget.used()})
    );
    std::fs::remove_dir_all(root).unwrap();
}
