//! Opt-in measurement of genuine encrypted processing on five production owners.
//! No synthetic consensus, replay witnesses, or transaction execution is injected.
use super::*;
use std::io::{Read, Write};
use synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY;

fn submit(
    address: std::net::SocketAddr,
    admission: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,
        "method":"synergy_submitProcessingTransactionV1","params":admission}))
    .map_err(|e| e.to_string())?;
    write!(stream, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream
        .take(4 * 1024 * 1024)
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    let start = response
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or("missing HTTP response")?
        + 4;
    serde_json::from_slice(&response[start..]).map_err(|e| e.to_string())
}

/// Deliberately ignored in ordinary CI: a controlled measurement, not a unit test.
#[test]
#[ignore = "explicit exploratory async TPS measurement; preserves all raw evidence"]
fn processing_async_exploratory_five_validator_tps() {
    let count = std::env::var("POSY_TPS_COUNT")
        .unwrap_or_else(|_| "4".into())
        .parse::<usize>()
        .unwrap();
    let rate = std::env::var("POSY_TPS_RATE")
        .unwrap_or_else(|_| "0.2".into())
        .parse::<f64>()
        .unwrap();
    let window = std::env::var("POSY_TPS_WINDOW")
        .unwrap_or_else(|_| "20".into())
        .parse::<f64>()
        .unwrap();
    let per_validator_budgets =
        std::env::var_os("POSY_TPS_PER_VALIDATOR_BUDGETS").is_some_and(|value| value == "1");
    let maximum_count = if per_validator_budgets { 64 } else { 8 };
    let maximum_rate = if per_validator_budgets { 1000.0 } else { 2.0 };
    assert!(
        (1..=maximum_count).contains(&count)
            && rate.is_finite()
            && rate > 0.0
            && rate <= maximum_rate
    );
    assert!(window.is_finite() && window >= count as f64 / rate && window <= 120.0);
    // Independent wallets allow simultaneous nonce-zero requests; no finality wait
    // gates later submissions. All keys remain fixture-local and are wiped below.
    let mut wallets = (0..count)
        .map(|_| funded_transaction_fixture_with_key())
        .collect::<Vec<_>>();
    let mut world = synergy_state::WorldState::default();
    let mut bindings = std::collections::BTreeMap::<String, serde_json::Value>::new();
    for (_, initial, _) in &wallets {
        world.accounts.extend(initial.accounts.clone());
        let entries: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&initial.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY])
                .unwrap();
        bindings.extend(entries);
    }
    world.protocol.insert(
        IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        serde_json::to_vec(&bindings).unwrap(),
    );
    let prepared = prepare_socket_fixture_profile(world, None, true);
    let output = std::env::var_os("POSY_TPS_RAW")
        .map(PathBuf::from)
        .unwrap_or_else(|| prepared.root.join("exploratory-tps.jsonl"));
    let mut raw = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap();
    let budget = synergy_state::world_resources::WorldResourceBudget::new(1024 * 1024 * 1024);
    // Opt-in capacity fixture topology: the distributed deployment has an
    // independent 1 GiB accounting pool per validator. Keep the historical
    // shared-pool resource fixture as the default and report this distinction.
    let budgets = (0..prepared.configurations.len())
        .map(|_| {
            if per_validator_budgets {
                synergy_state::world_resources::WorldResourceBudget::new(1024 * 1024 * 1024)
            } else {
                budget.clone()
            }
        })
        .collect::<Vec<_>>();
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .enumerate()
        .map(|(index, (c, l))| {
            Node::open_with_wallet_budget(
                c,
                Some(super::super::protected_admission::AdmissionHandle::default()),
                l,
                budgets[index].clone(),
                true,
                None,
            )
        })
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    let response = wallet_rpc_node(
        &mut nodes[0],
        "synergy_getProcessingContextV1",
        serde_json::json!({}),
    );
    let context = serde_json::from_value(response["context"].clone()).unwrap();
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let admissions = wallets
        .iter_mut()
        .map(|(tx, _, key)| {
            let admission = processing_wallet_admission_fixture(tx, &context, &authority, key);
            key.fill(0);
            serde_json::to_value(admission).unwrap()
        })
        .collect::<Vec<_>>();
    let address = nodes[0].configuration.rpc.listen_address.unwrap();
    #[cfg(feature = "qualification-timing")]
    let diagnostics = std::env::var_os("POSY_TPS_TIMING_CONFIG").map(|path| {
        let mut bytes = Vec::new();
        fs::File::open(path)
            .unwrap()
            .take(4097)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(
            bytes.len() <= 4096,
            "fixture diagnostic configuration exceeds bound"
        );
        let config = serde_json::from_slice(&bytes).unwrap();
        super::super::qualification_timing::start_native_fixture(config).unwrap()
    });
    let started = Instant::now();
    let started_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    writeln!(raw,"{}",serde_json::json!({"kind":"configuration","environment":"exploratory-threaded-five-validator-loopback",
        "started_unix":started_unix,"offered_tps":rate,"offered_window_seconds":window,"count":count,"max_in_flight":count,
        "shared_accounting_limit_bytes":if per_validator_budgets { None } else { Some(1024_u64*1024*1024) },
        "per_validator_accounting_limit_bytes":if per_validator_budgets { Some(1024_u64*1024*1024) } else { None },
        "native_consensus_preparation":std::env::var_os("POSY_TPS_NATIVE_PREPARATION").is_some_and(|value| value == "1")
            && nodes.iter().all(|node| node._sync_diagnostic_preparation.is_some()),
        "profile_id":synergy_etdag::PROCESSING_PROFILE_ID,
        "fixture_root":prepared.root,"configuration":prepared.configurations,"context":response,
        "measurement_limitations":["shared macOS process and storage","loopback network","finite offered-load sample; not capacity","drain observed separately from offered window"]})).unwrap();
    raw.flush().unwrap();
    eprintln!(
        "exploratory TPS raw={}, journals={}",
        output.display(),
        prepared.root.display()
    );
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut threads = Vec::new();
    for (index, admission) in admissions.into_iter().enumerate() {
        let sender = sender.clone();
        threads.push(std::thread::spawn(move || {
            let scheduled = Duration::from_secs_f64(index as f64 / rate);
            if let Some(wait) = scheduled.checked_sub(started.elapsed()) {
                std::thread::sleep(wait);
            }
            let submitted = started.elapsed().as_secs_f64();
            sender
                .send((
                    index,
                    submitted,
                    submit(address, admission),
                    started.elapsed().as_secs_f64(),
                ))
                .unwrap();
        }));
    }
    drop(sender);
    let mut receipts = vec![None::<String>; count];
    let mut submitted = vec![None::<f64>; count];
    let mut admitted = vec![None::<f64>; count];
    let mut finalized = vec![None::<f64>; count];
    let mut rejected = vec![false; count];
    let mut completed_rpc = 0;
    let mut next_sample = Instant::now();
    let mut initial_height = None;
    let mut final_height = 0;
    let mut certified_heights = vec![0_u64; nodes.len()];
    let mut finalized_heights = vec![0_u64; nodes.len()];
    let mut observed_prepared = std::collections::BTreeSet::new();
    loop {
        for node in &mut nodes {
            node.poll();
        }
        for (index, node) in nodes.iter().enumerate() {
            if let Some((height, block_id, state_root, transaction_count)) = node
                .ingress
                .processing_certified_measurement(certified_heights[index])
                .unwrap()
            {
                writeln!(raw,"{}",serde_json::json!({"kind":"certified_block","validator":index,"height":height,
                    "previous_observed_height":certified_heights[index],"observed_seconds":started.elapsed().as_secs_f64(),
                    "block_id":block_id,"state_root":state_root,"transaction_count":transaction_count,
                    "protocol_timestamp_unix":authority.consensus_timestamp_unix(height).unwrap()})).unwrap();
                certified_heights[index] = height;
            }
            if let Some(record) = node
                .ingress
                .latest_finality()
                .unwrap()
                .filter(|record| record.height > finalized_heights[index])
            {
                writeln!(raw,"{}",serde_json::json!({"kind":"finalized_block","validator":index,"height":record.height,
                    "previous_observed_height":finalized_heights[index],"observed_seconds":started.elapsed().as_secs_f64(),
                    "record":record,"protocol_timestamp_unix":authority.consensus_timestamp_unix(record.height).unwrap()})).unwrap();
                finalized_heights[index] = record.height;
            }
        }
        while let Ok((index, time, result, returned)) = receiver.try_recv() {
            submitted[index] = Some(time);
            completed_rpc += 1;
            if let Ok(value) = &result {
                receipts[index] = value["result"]["receipt_id"].as_str().map(str::to_owned);
            }
            if receipts[index].is_none() {
                rejected[index] = true;
            }
            writeln!(raw,"{}",serde_json::json!({"kind":"submission","index":index,"submitted_seconds":time,"rpc_returned_seconds":returned,"response":result})).unwrap();
        }
        for index in 0..count {
            if admitted[index].is_none() && !rejected[index] {
                if let Some(id) = &receipts[index] {
                    let receipt = nodes[0]
                        .wallet_admission
                        .as_ref()
                        .unwrap()
                        .receipt(id)
                        .unwrap();
                    if receipt["admitted"] == true || receipt["status"] == "rejected" {
                        if receipt["admitted"] == true {
                            admitted[index] = Some(started.elapsed().as_secs_f64());
                        } else {
                            rejected[index] = true;
                        }
                        writeln!(raw,"{}",serde_json::json!({"kind":"admission","index":index,"observed_seconds":started.elapsed().as_secs_f64(),"receipt":receipt})).unwrap();
                    }
                }
            }
        }
        if Instant::now() >= next_sample {
            let worlds = nodes
                .iter()
                .map(|n| n.ingress.processing_finalized_world().unwrap())
                .collect::<Vec<_>>();
            let heights = worlds
                .iter()
                .map(|v| v.as_ref().map_or(0, |(h, _)| *h))
                .collect::<Vec<_>>();
            final_height = *heights.iter().min().unwrap();
            initial_height.get_or_insert(final_height);
            for (index, (tx, _, _)) in wallets.iter().enumerate() {
                if finalized[index].is_none()
                    && worlds.iter().all(|v| {
                        v.as_ref().is_some_and(|(_, w)| {
                            w.accounts
                                .get(&tx.unsigned.sender)
                                .is_some_and(|a| a.nonce == 1)
                        })
                    })
                {
                    finalized[index] = Some(started.elapsed().as_secs_f64());
                    writeln!(raw,"{}",serde_json::json!({"kind":"finality","index":index,"observed_seconds":finalized[index],"heights":heights,"wallet_nonce":1})).unwrap();
                }
            }
            let backlog = nodes.iter().enumerate().map(|(validator, n)|n.ingress.processing_snapshot().unwrap().map(|s| {
                for completion in &s.completions {
                    let envelope = completion.record.item.envelope_id.0.clone();
                    if observed_prepared.insert((validator, envelope.clone())) {
                        writeln!(raw,"{}",serde_json::json!({"kind":"prepared","validator":validator,
                            "envelope_id":envelope,"observed_seconds":started.elapsed().as_secs_f64(),
                            "group_number":completion.record.item.group_number})).unwrap();
                    }
                }
                serde_json::json!({"members":s.members.len(),"completions":s.completions.len()})
            })).collect::<Vec<_>>();
            let records = nodes
                .iter()
                .map(|n| n.ingress.latest_finality().unwrap())
                .collect::<Vec<_>>();
            writeln!(raw,"{}",serde_json::json!({"kind":"sample","elapsed_seconds":started.elapsed().as_secs_f64(),"heights":heights,
                "finality":records,"backlog":backlog,
                "preparation":nodes.iter().map(|node|node._sync_diagnostic_preparation.as_ref()
                    .map(|pool|pool.handle().observations().unwrap())).collect::<Vec<_>>(),
                "reserved_bytes":if per_validator_budgets { budgets.iter().map(|b| b.used()).sum::<usize>() } else { budget.used() },
                "reserved_bytes_per_validator":budgets.iter().map(|b|b.used()).collect::<Vec<_>>(),
                "admitted":admitted.iter().flatten().count(),"finalized":finalized.iter().flatten().count()})).unwrap();
            raw.flush().unwrap();
            next_sample = Instant::now() + Duration::from_secs(1);
        }
        let done =
            completed_rpc == count && (0..count).all(|i| finalized[i].is_some() || rejected[i]);
        if started.elapsed().as_secs_f64() >= window && done {
            break;
        }
        if started.elapsed().as_secs_f64() >= window + 180.0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    // Verify the observable execution effects independently from durable state.
    let finalized_count = finalized.iter().flatten().count();
    let expected_received = finalized_count as u128 * 7;
    for node in &nodes {
        let layout = synergy_storage::NodeStorageLayout::new(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        let node_budget = node.ingress.world_budget();
        let store = synergy_state::FinalizedStateStore::load_budgeted(
            layout.state().join("execution"),
            Arc::clone(node_budget),
        )
        .unwrap();
        let world = store
            .current_world_state_budgeted(node_budget)
            .unwrap()
            .unwrap();
        let receiver = &wallets[0].0.unsigned.receiver;
        assert_eq!(
            world.accounts.get(receiver).map_or(0, |a| a.balance_nwei),
            expected_received,
            "durable receiver effects differ"
        );
        for (index, (tx, _, _)) in wallets.iter().enumerate() {
            assert_eq!(
                world.accounts[&tx.unsigned.sender].nonce,
                u64::from(finalized[index].is_some()),
                "duplicate or missing execution"
            );
        }
    }
    writeln!(raw,"{}",serde_json::json!({"kind":"summary","elapsed_seconds":started.elapsed().as_secs_f64(),"submitted_seconds":submitted,
        "admitted_seconds":admitted,"finalized_seconds":finalized,"rejected":rejected,"finalized_count":finalized_count,
        "initial_height":initial_height,"final_height":final_height,"verified_receiver_nwei":expected_received,
        "reserved_bytes":if per_validator_budgets { budgets.iter().map(|b|b.used()).sum::<usize>() } else { budget.used() }})).unwrap();
    raw.sync_all().unwrap();
    for node in &mut nodes {
        node.stop();
    }
    #[cfg(feature = "qualification-timing")]
    if let Some(diagnostics) = diagnostics {
        super::super::qualification_timing::clear_process_handle();
        let report = diagnostics.finish();
        eprintln!(
            "TPS_DIAGNOSTIC_REPORT {}",
            serde_json::json!({
                "written":report.written,"dropped":report.dropped,"failures":report.failures,
                "complete":report.complete(),"scope":"shared five-validator fixture; nested durations overlap"
            })
        );
    }
    assert!(
        finalized_count > 0 && (0..count).all(|i| finalized[i].is_some() || rejected[i]),
        "encrypted workload failed to drain; raw evidence {}",
        output.display()
    );
}

// One bounded streaming evidence owner. Full native three-QC witnesses are
// retained on disk, never accumulated in a transaction/block-sized memory graph.
struct EncryptedScaleEvidence {
    file: fs::File,
    bytes: u64,
    previous: String,
}
impl EncryptedScaleEvidence {
    const LIMIT: u64 = 2 * 1024 * 1024 * 1024;
    fn append(&mut self, mut row: serde_json::Value) {
        row["previous_record_hash"] = serde_json::json!(self.previous);
        let mut bytes = serde_json::to_vec(&row).unwrap();
        assert!(
            bytes.len() <= 1024 * 1024,
            "bounded evidence row exceeded1MiB"
        );
        bytes.push(b'\n');
        assert!(
            self.bytes + bytes.len() as u64 <= Self::LIMIT,
            "evidence cap reached; scale acceptance incomplete"
        );
        self.previous = synergy_block::hash_block_bytes(&bytes);
        self.file.write_all(&bytes).unwrap();
        self.bytes += bytes.len() as u64;
    }
}
fn encrypted_scale_metrics(root: &Path, nodes: &[Node], started: Instant) -> serde_json::Value {
    let allocated = |path: &Path| {
        std::process::Command::new("du")
            .args(["-sk"])
            .arg(path)
            .output()
            .ok()
            .filter(|value| value.status.success())
            .and_then(|value| String::from_utf8(value.stdout).ok())
            .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
            .map(|kib| kib * 1024)
    };
    let native_allocated = nodes
        .iter()
        .map(|node| allocated(&node.configuration.storage.data_directory))
        .collect::<Vec<_>>();
    let read_public_proc = |path: &str| {
        fs::File::open(path).ok().and_then(|file| {
            let mut value = String::new();
            file.take(16 * 1024).read_to_string(&mut value).ok()?;
            Some(value)
        })
    };
    serde_json::json!({"kind":"resources","elapsed_seconds":started.elapsed().as_secs_f64(),
        "fixture_allocated_bytes_including_evidence":allocated(root),"native_storage_allocated_bytes_per_validator":native_allocated,"process_id":std::process::id(),
        "linux_process_status":read_public_proc("/proc/self/status"),
        "linux_process_io":read_public_proc("/proc/self/io"),
        "reserved_bytes_per_validator":nodes.iter().map(|node|node.ingress.world_budget().used()).collect::<Vec<_>>(),
        "pending":nodes.iter().map(|node|node.ingress.processing_snapshot().unwrap().map(|snapshot|
            serde_json::json!({"members":snapshot.members.len(),"completions":snapshot.completions.len()}))).collect::<Vec<_>>(),
        "scope":"five native validators and generator share one process/CPU/filesystem; reservations are not per-validator RSS or cgroup evidence"})
}

/// Long acceptance, deliberately excluded from routine CI. A target below10000
/// is an explicit pilot and its summary cannot satisfy the scale gate.
#[test]
#[ignore = "explicit long real encrypted ingress and distinct tx-bearing finalized-block acceptance"]
fn processing_async_encrypted_transaction_bearing_block_scale() {
    use std::collections::BTreeMap;
    use std::sync::mpsc::{sync_channel, TryRecvError, TrySendError};
    use synergy_state::world_resources::WorldResourceBudget;
    let target = std::env::var("POSY_ENCRYPTED_BLOCK_TARGET")
        .unwrap_or_else(|_| "10000".into())
        .parse::<u64>()
        .unwrap();
    let rate = std::env::var("POSY_ENCRYPTED_RATE")
        .unwrap_or_else(|_| "1".into())
        .parse::<f64>()
        .unwrap();
    let maximum_seconds = std::env::var("POSY_ENCRYPTED_MAX_SECONDS")
        .unwrap_or_else(|_| "86400".into())
        .parse::<u64>()
        .unwrap();
    assert!((1..=100_000).contains(&target));
    assert!(rate.is_finite() && rate > 0.0 && rate <= 1000.0);
    assert!((30..=86400).contains(&maximum_seconds));
    let maximum_submitted = target.checked_mul(32).unwrap() + 64;
    let initial_balance = u128::from(maximum_submitted) * (840_000 + 7);
    let wallets = (0..32)
        .map(|_| funded_transaction_fixture_for_network("socket-qualification", initial_balance))
        .collect::<Vec<_>>();
    let mut world = synergy_state::WorldState::default();
    let mut bindings = BTreeMap::<String, serde_json::Value>::new();
    for (_, initial, _) in &wallets {
        world.accounts.extend(initial.accounts.clone());
        let entries: BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&initial.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY])
                .unwrap();
        for (address, binding) in entries {
            assert!(bindings.insert(address, binding).is_none());
        }
    }
    world.protocol.insert(
        IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        serde_json::to_vec(&bindings).unwrap(),
    );
    let prepared = prepare_socket_fixture_profile_with_epoch(
        world,
        None,
        true,
        Some((target * 32 + 128).max(10_000)),
    );
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let started = Instant::now();
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .map(|(mut c, l)| {
            c.storage.prune_finalized_history_after_blocks = Some(64);
            Node::open_with_wallet_budget(
                c,
                Some(super::super::protected_admission::AdmissionHandle::default()),
                l,
                WorldResourceBudget::new(1024 * 1024 * 1024),
                true,
                None,
            )
        })
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    loop {
        for node in &mut nodes {
            node.poll();
        }
        if nodes.iter().all(|node| {
            node.ingress.authenticated_peers().unwrap().len() == 4
                && node
                    .services
                    .iter()
                    .all(|(_, service)| matches!(service.health(), ServiceHealth::Healthy))
        }) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "native five-owner readiness exceeded unchanged5s"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let readiness_ms = started.elapsed().as_millis();
    let exported = wallet_rpc_node(
        &mut nodes[0],
        "synergy_getProcessingContextV1",
        serde_json::json!({}),
    );
    let context: synergy_etdag::ProcessingContext =
        serde_json::from_value(exported["context"].clone()).unwrap();
    let receiver = wallets[0].0.unsigned.receiver.clone();
    let senders = wallets
        .iter()
        .map(|(tx, _, _)| tx.unsigned.sender.clone())
        .collect::<Vec<_>>();
    let output = std::env::var_os("POSY_ENCRYPTED_RAW")
        .map(PathBuf::from)
        .unwrap_or_else(|| prepared.root.join("encrypted-scale.jsonl"));
    let mut evidence = EncryptedScaleEvidence {
        file: fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)
            .unwrap(),
        bytes: 0,
        previous: "0".repeat(64),
    };
    evidence.append(serde_json::json!({"kind":"configuration","target_distinct_tx_bearing_finalized_blocks":target,
        "scale_gate_minimum":10000,"pilot":target<10000,"wallets":32,"maximum_outstanding":32,"configured_outstanding_ceiling":64,
        "offered_tps":rate,"routing":"wallet-index modulo five existing RPC listeners; at most7 outstanding per listener","maximum_seconds":maximum_seconds,"maximum_submitted":maximum_submitted,
        "current_nonce_finality_deadline_ms":30000,
        "latency_start":"per-intent bounded queueing before signing/encryption using selected immutable authenticated context; includes generator/RPC/all-five proof and effects observation",
        "readiness_deadline_ms":5000,"readiness_ms":readiness_ms,
        "per_validator_native_budget_bytes":1024_u64*1024*1024,
        "native_consensus_preparation":std::env::var_os("POSY_TPS_NATIVE_PREPARATION").is_some_and(|value|value=="1")
            &&nodes.iter().all(|node|node._sync_diagnostic_preparation.is_some()),
        "retention_blocks":64,"evidence_limit_bytes":EncryptedScaleEvidence::LIMIT,
        "fixture_root":prepared.root,"context":context,"witness_retention":"full native three-QC witness for every counted tx-bearing block; verified hashes for empty heights","limitations":["single process loopback fixture; not fleet TPS/soak or per-node OS memory qualification",
        "actual native cryptography, authority, ETDAG, PoSy and applied effects; no injected consensus/finality or accelerated clock"]}));
    evidence.append(encrypted_scale_metrics(&prepared.root, &nodes, started));
    evidence.file.sync_data().unwrap();
    eprintln!(
        "ENCRYPTED_SCALE_BEGIN {}",
        serde_json::json!({"raw":output,"fixture_root":prepared.root,
        "target_distinct_tx_bearing_finalized_blocks":target,"pilot":target<10000})
    );
    type Job = (usize, u64, u64, Instant);
    struct Submitted {
        wallet: usize,
        nonce: u64,
        txid: String,
        envelope: String,
        expected_receipt: String,
        ciphertext_bytes: usize,
        started: Instant,
        response: Result<serde_json::Value, String>,
    }
    let (jobs, job_reader) = sync_channel::<Job>(64);
    let (results, result_reader) = sync_channel::<Submitted>(64);
    // The existing RPC owner admits at most16 pending requests. Spread the
    // bounded32-wallet pool over all existing authenticated network instances;
    // no listener cap changes or retries are introduced.
    let addresses = nodes
        .iter()
        .map(|node| node.configuration.rpc.listen_address.unwrap())
        .collect::<Vec<_>>();
    struct FixtureCustody(Vec<(synergy_transaction::SignedTransaction, Vec<u8>)>);
    impl Drop for FixtureCustody {
        fn drop(&mut self) {
            for (_, secret) in &mut self.0 {
                secret.fill(0);
            }
        }
    }
    let custody = FixtureCustody(
        wallets
            .into_iter()
            .map(|(tx, _, secret)| (tx, secret))
            .collect(),
    );
    let schedule_authority = Arc::clone(&authority);
    let signer = std::thread::spawn(move || {
        while let Ok((wallet, nonce, timestamp, submitted)) = job_reader.recv() {
            let (template, secret) = &custody.0[wallet];
            let mut tx = template.clone();
            tx.unsigned.nonce = nonce;
            tx.unsigned.timestamp_unix = timestamp;
            tx.signature = fixture_sign(
                secret,
                SignatureAlgorithm::MlDsa87,
                "long-encrypted-wallet",
                "SYNERGY-TRANSACTION-SIGNING-V1",
                None,
                &tx.unsigned.signing_bytes().unwrap(),
            );
            let admission = processing_wallet_admission_fixture(&tx, &context, &authority, secret);
            let expected_receipt = synergy_etdag::EtdagDigest::from_canonical(
                "SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1",
                &admission,
            )
            .unwrap()
            .0;
            let ciphertext_bytes = admission.request.envelope.ciphertext.len();
            assert!(ciphertext_bytes > 0);
            let response = submit(
                addresses[wallet % addresses.len()],
                serde_json::to_value(&admission).unwrap(),
            );
            let accepted = response.as_ref().is_ok_and(|value| {
                value["result"]["status"] == "queued"
                    && value["result"]["receipt_id"].as_str() == Some(expected_receipt.as_str())
            });
            if results
                .send(Submitted {
                    wallet,
                    nonce,
                    txid: tx.id().unwrap().0,
                    envelope: admission.request.envelope.envelope_id.0,
                    expected_receipt,
                    ciphertext_bytes,
                    started: submitted,
                    response,
                })
                .is_err()
            {
                break;
            }
            if !accepted {
                break;
            }
        }
        drop(custody);
    });
    let mut nonces = vec![0_u64; 32];
    let mut outstanding = vec![None::<Instant>; 32];
    let mut pending = BTreeMap::<String, (usize, u64, Instant)>::new();
    let mut completed = 0_u64;
    let mut submitted = 0_u64;
    let mut bearing = 0_u64;
    let mut next_height = 1_u64;
    let mut next_wallet = 0_usize;
    let mut next_offer = Instant::now();
    let mut last_progress = Instant::now();
    let mut last_report = Instant::now();
    let mut metrics_at = 1024_u64;
    let mut maximum_latency_ms = 0_u128;
    let mut latency_sum_ms = 0_u128;
    let mut generator_limited = 0_u64;
    let mut final_common_state = String::new();
    loop {
        for node in &mut nodes {
            node.poll();
        }
        loop {
            match result_reader.try_recv() {
                Ok(value) => {
                    evidence.append(serde_json::json!({"kind":"submission_response","wallet":value.wallet,"nonce":value.nonce,
                        "transaction_id":value.txid,"response":&value.response,"elapsed_seconds":started.elapsed().as_secs_f64()}));
                    evidence.file.flush().unwrap();
                    let response = value.response.unwrap_or_else(|error| {
                        panic!("encrypted RPC transport failed without retry: {error}")
                    });
                    let receipt = response["result"]["receipt_id"]
                        .as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "real encrypted RPC submission rejected without retry: {response}"
                            )
                        });
                    assert_eq!(
                        receipt, value.expected_receipt,
                        "RPC receipt does not commit to exact signed encrypted admission"
                    );
                    assert_eq!(response["result"]["status"], "queued", "{response}");
                    assert!(pending
                        .insert(
                            value.txid.clone(),
                            (value.wallet, value.nonce, value.started)
                        )
                        .is_none());
                    evidence.append(serde_json::json!({"kind":"submission","transaction_id":value.txid,"envelope_id":value.envelope,
                    "wallet":value.wallet,"nonce":value.nonce,"receipt_id":receipt,"ciphertext_bytes":value.ciphertext_bytes,
                    "receipt_binding":"SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1 exact signed encrypted admission","elapsed_seconds":started.elapsed().as_secs_f64()}));
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => panic!("bounded generator exited before drain"),
            }
        }
        let minimum = nodes
            .iter()
            .map(|node| {
                let finalized = node
                    .ingress
                    .latest_finality()
                    .unwrap()
                    .map_or(0, |record| record.height);
                // PoSy may publish a verified finality record before this
                // validator's Execution/Sync owners materialize its candidate.
                // Observe effects only through their committed watermark; the
                // original outstanding-admission deadline still includes this
                // native catch-up time.
                let committed = node
                    .ingress
                    .processing_finalized_world()
                    .unwrap()
                    .map_or(0, |(height, _)| height);
                finalized.min(committed)
            })
            .min()
            .unwrap();
        // Bound observer work per poll, inspecting every height rather than
        // interpreting sampled latest heights or10k batched tx as10k blocks.
        let first_height = next_height;
        for height in first_height..=minimum.min(first_height + 3) {
            let mut common = None;
            let mut expected_receipts = None;
            let mut applied = Vec::new();
            let mut applied_starts = Vec::new();
            let mut block_evidence = None;
            for (index, node) in nodes.iter().enumerate() {
                let (record, witness) = node
                    .ingress
                    .finalized_record_with_witness(height)
                    .unwrap()
                    .expect("missing native three-QC finality");
                let layout = synergy_storage::NodeStorageLayout::new(
                    node.configuration.storage.data_directory.clone(),
                )
                .unwrap();
                let store = synergy_execution::BudgetedCandidateStore::new_budgeted(
                    layout.blocks().join("execution-candidates"),
                    node.ingress.world_budget().clone(),
                )
                .unwrap();
                let candidate = store.get_budgeted(height).unwrap().unwrap_or_else(|| {
                    panic!(
                        "Execution-committed candidate unavailable: node={index} height={height}"
                    )
                });
                candidate.validate().unwrap();
                assert_eq!(candidate.block_id, record.block_id);
                assert_eq!(
                    candidate.protected_execution_root,
                    record.protected_execution_root
                );
                if index == 0 {
                    common = Some(record.clone());
                    expected_receipts = Some(synergy_block::hash_block_bytes(
                        &serde_json::to_vec(&(&candidate.transactions, &candidate.receipts))
                            .unwrap(),
                    ));
                    assert_eq!(candidate.transactions.len(), candidate.receipts.len());
                    for (tx, receipt) in candidate.transactions.iter().zip(&candidate.receipts) {
                        let txid = tx.id().unwrap().0;
                        let (wallet,nonce,submitted_at)=pending.remove(&txid).expect("finalized transaction was not a genuine outstanding encrypted submission");
                        assert_eq!(tx.unsigned.sender, senders[wallet]);
                        assert_eq!(tx.unsigned.nonce, nonce);
                        assert_eq!(nonces[wallet], nonce);
                        assert_eq!(tx.unsigned.receiver, receiver);
                        assert_eq!(tx.unsigned.amount_nwei, 7);
                        assert_eq!(receipt.transaction_id.0, txid);
                        assert_eq!(receipt.status, synergy_transaction::ReceiptStatus::Applied);
                        assert_eq!(receipt.gas_used, 21000);
                        assert!(receipt.error_code.is_none());
                        applied_starts.push(submitted_at);
                        nonces[wallet] += 1;
                        outstanding[wallet] = None;
                        completed += 1;
                        applied.push(serde_json::json!({"transaction_id":txid,"wallet":wallet,"nonce":nonce,"amount_nwei":7,"gas_used":21000,
                            "receipt_commitment":receipt.commitment().unwrap()}));
                    }
                    if !applied.is_empty() {
                        bearing += 1;
                    }
                    let witness_hash =
                        synergy_block::hash_block_bytes(&serde_json::to_vec(&witness).unwrap());
                    let retained_witness = if candidate.transactions.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::to_value(&witness).unwrap()
                    };
                    block_evidence = Some(
                        serde_json::json!({"kind":"finalized_block","height":height,"record":record,
                        "three_qc_witness":retained_witness,"verified_witness_hash":witness_hash,
                        "state_root":candidate.state_root,"transaction_count":candidate.transactions.len()}),
                    );
                } else {
                    assert_eq!(&record, common.as_ref().unwrap());
                    assert_eq!(
                        expected_receipts.as_ref().unwrap(),
                        &synergy_block::hash_block_bytes(
                            &serde_json::to_vec(&(&candidate.transactions, &candidate.receipts))
                                .unwrap()
                        )
                    );
                }
                for (wallet, sender) in senders.iter().enumerate() {
                    assert_eq!(candidate.state.accounts[sender].nonce, nonces[wallet]);
                    assert_eq!(
                        candidate.state.accounts[sender].balance_nwei,
                        initial_balance - u128::from(nonces[wallet]) * (840_000 + 7)
                    );
                }
                assert_eq!(
                    candidate
                        .state
                        .accounts
                        .get(&receiver)
                        .map_or(0, |account| account.balance_nwei),
                    u128::from(completed) * 7
                );
                if index == 0 {
                    final_common_state = candidate.state_root.clone();
                } else {
                    assert_eq!(candidate.state_root, final_common_state);
                }
            }
            // The observation deadline includes verification of the same exact
            // candidate, receipts and effects on all five, not merely node0.
            for (row, submitted_at) in applied.iter_mut().zip(applied_starts) {
                let latency = submitted_at.elapsed();
                assert!(
                    latency <= Duration::from_secs(30),
                    "encrypted current-nonce all-five effects exceeded unchanged30s"
                );
                maximum_latency_ms = maximum_latency_ms.max(latency.as_millis());
                latency_sum_ms += latency.as_millis();
                row["context_to_all_five_effects_ms_upper_bound"] =
                    serde_json::json!(latency.as_millis());
            }
            let mut row = block_evidence.unwrap();
            row["applied"] = serde_json::json!(applied);
            row["verified_validators"] = serde_json::json!(5);
            evidence.append(row);
            next_height = height + 1;
            last_progress = Instant::now();
        }
        for at in outstanding.iter().flatten() {
            assert!(
                at.elapsed() <= Duration::from_secs(30),
                "queued or encrypted outstanding admission exceeded unchanged30s"
            );
        }
        if bearing >= target && outstanding.iter().all(Option::is_none) {
            break;
        }
        if bearing < target && Instant::now() >= next_offer {
            let wallet = (0..32)
                .map(|offset| (next_wallet + offset) % 32)
                .find(|index| outstanding[*index].is_none());
            if let Some(wallet) = wallet {
                assert!(
                    submitted < maximum_submitted,
                    "bounded generator exhausted before target distinct blocks"
                );
                let timestamp = nodes[0]
                    .ingress
                    .latest_finality()
                    .unwrap()
                    .map_or(1, |record| record.height)
                    .max(3);
                let offered = Instant::now();
                match jobs.try_send((
                    wallet,
                    nonces[wallet],
                    schedule_authority
                        .consensus_timestamp_unix(timestamp)
                        .unwrap(),
                    offered,
                )) {
                    Ok(()) => {
                        outstanding[wallet] = Some(offered);
                        submitted += 1;
                        evidence.append(serde_json::json!({"kind":"offered","wallet":wallet,"nonce":nonces[wallet],
                            "consensus_timestamp_unix":schedule_authority.consensus_timestamp_unix(timestamp).unwrap(),
                            "elapsed_seconds":started.elapsed().as_secs_f64()}));
                        next_wallet = (wallet + 1) % 32;
                    }
                    Err(TrySendError::Full(_)) => {
                        generator_limited += 1;
                    }
                    Err(TrySendError::Disconnected(_)) => panic!("generator stopped"),
                }
            } else {
                generator_limited += 1;
            }
            next_offer = Instant::now() + Duration::from_secs_f64(1.0 / rate);
        }
        assert!(
            last_progress.elapsed() <= Duration::from_secs(30),
            "native finality progress exceeded unchanged30s"
        );
        assert!(
            started.elapsed() < Duration::from_secs(maximum_seconds),
            "bounded long acceptance incomplete at overall deadline"
        );
        if bearing >= metrics_at {
            evidence.append(encrypted_scale_metrics(&prepared.root, &nodes, started));
            metrics_at += 1024;
            evidence.file.sync_data().unwrap();
        }
        if last_report.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "ENCRYPTED_SCALE_PROGRESS {}",
                serde_json::json!({"raw":output,"elapsed_seconds":started.elapsed().as_secs_f64(),
                "common_height":next_height-1,"tx_bearing_finalized_blocks":bearing,"target":target,"submitted":submitted,"applied":completed,
                "outstanding":outstanding.iter().flatten().count(),"evidence_bytes":evidence.bytes})
            );
            evidence.file.flush().unwrap();
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(pending.is_empty());
    assert_eq!(submitted, completed);
    drop(jobs);
    signer.join().unwrap();
    evidence.append(encrypted_scale_metrics(&prepared.root, &nodes, started));
    for node in &mut nodes {
        node.stop();
    }
    let restart_started = Instant::now();
    let mut reopened = Node::open_with_wallet_budget(
        nodes[0].configuration.clone(),
        Some(super::super::protected_admission::AdmissionHandle::default()),
        &prepared.listeners[0],
        WorldResourceBudget::new(1024 * 1024 * 1024),
        true,
        None,
    );
    loop {
        reopened.poll();
        if let Some((_, world)) = reopened.ingress.processing_finalized_world().unwrap() {
            for (wallet, sender) in senders.iter().enumerate() {
                assert_eq!(world.accounts[sender].nonce, nonces[wallet]);
                assert_eq!(
                    world.accounts[sender].balance_nwei,
                    initial_balance - u128::from(nonces[wallet]) * (840_000 + 7)
                );
            }
            assert_eq!(
                world
                    .accounts
                    .get(&receiver)
                    .map_or(0, |account| account.balance_nwei),
                u128::from(completed) * 7
            );
            break;
        }
        assert!(
            restart_started.elapsed() < Duration::from_secs(5),
            "native stopped-fixture restart exceeded unchanged5s"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(restart_started.elapsed() <= Duration::from_secs(5));
    let restart_ready_ms = restart_started.elapsed().as_millis();
    reopened.stop();
    evidence.append(serde_json::json!({"kind":"summary","complete":true,"pilot":target<10000,
        "scale_gate_satisfied":target>=10000&&bearing>=target,"target":target,"tx_bearing_finalized_blocks":bearing,
        "native_finalized_height_checked":next_height-1,"submitted":submitted,"applied":completed,"generator_limited_slots":generator_limited,
        "maximum_latency_ms_upper_bound":maximum_latency_ms,"mean_latency_ms_upper_bound":latency_sum_ms as f64/completed.max(1) as f64,
        "native_restart_readiness_ms":restart_ready_ms,"final_common_state_root":final_common_state,
        "elapsed_seconds":started.elapsed().as_secs_f64(),"final_wallet_nonces":nonces,"fixture_root":prepared.root}));
    evidence.file.sync_all().unwrap();
    eprintln!(
        "ENCRYPTED_SCALE_COMPLETE {}",
        serde_json::json!({"raw":output,"evidence_bytes":evidence.bytes,"last_record_hash":evidence.previous,
        "tx_bearing_finalized_blocks":bearing,"scale_gate_satisfied":target>=10000&&bearing>=target})
    );
}
