//! Uses the existing native five-process acceptance harness. Every process
//! has its own APQE session admission barrier and canonical managed root.
use super::secure_process_canary::process_rpc;
use super::*;
use synergy_aivm::ethereum_execution::{
    conventional_evm_account_key, EvmCompatibilityPolicy, EvmFork, EVM_POLICY_KEY,
};
use synergy_state::{AccountState, WorldState};

pub(super) fn fixture_policy() -> EvmCompatibilityPolicy {
    EvmCompatibilityPolicy {
        schema_version: 1,
        engine: "revm-43.0.3".into(),
        chain_id: 99999,
        fork: EvmFork::Shanghai,
        block_gas_limit: 30_000_000,
        memory_limit: 65536,
        maximum_accounts: 32,
        maximum_storage_slots: 256,
        maximum_code_bytes: 24576,
        maximum_patch_bytes: 262144,
        maximum_receipt_bytes: 262144,
        base_fee_nwei: 10,
        fee_collector: [0x55; 20],
        retain_base_fee_in_native_treasury: true,
        reject_sub_native_precision: true,
        native_exception_policy: "full-gas-no-action-v1".into(),
        blockhash_policy: "native-posy-block-id-v1".into(),
        randomness_policy: "authenticated-epoch-seed-v1".into(),
        rpc_projection_policy: "native-posy-evm-view-v1".into(),
    }
}

fn independent_ethers_module() -> PathBuf {
    let module = std::env::var_os("SYNERGY_ETHERS_MODULE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                "/Volumes/PortableSSD/02-Synergy-Network/08-Synergy-Website/node_modules/ethers",
            )
        });
    assert!(
        module.join("package.json").is_file(),
        "independent ethers6.15.0 required; set SYNERGY_ETHERS_MODULE"
    );
    module
}
pub(super) fn fixture() -> serde_json::Value {
    static FIXTURE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        use std::io::Write;
        // The checked compiler bytecode is unchanged. Independently re-sign
        // these public test-key inputs for the disposable Canary99999 profile;
        // no production Genesis, authorization or live Canary state is altered.
        let mut child=std::process::Command::new("node").args(["-e",r#"
          const fs=require('fs'),e=require(process.argv[1]);if(e.version!=='6.15.0')throw Error('ethers version');
          const f=JSON.parse(fs.readFileSync(0,'utf8')),w=new e.Wallet('0x'+'46'.repeat(32));
          (async()=>{for(const row of f.transactions){const t=e.Transaction.from(row.raw);
            row.raw=await w.signTransaction({type:0,chainId:99999,nonce:t.nonce,gasLimit:t.gasLimit,gasPrice:t.gasPrice,to:t.to,value:t.value,data:t.data});
            row.hash=e.keccak256(row.raw);}f.qualificationChainId=99999;process.stdout.write(JSON.stringify(f));
          })().catch(error=>{console.error(error);process.exitCode=1});
        "#,independent_ethers_module().to_str().unwrap()]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(include_bytes!("../../../../crates/synergy-aivm/tests/fixtures/evm-counter-shanghai.json")).unwrap();
        let output=child.wait_with_output().unwrap();assert!(output.status.success());
        serde_json::from_slice(&output.stdout).unwrap()
    }).clone()
}
pub(super) fn fund_world(world: &mut WorldState) {
    let fixture = fixture();
    let sender: [u8; 20] = hex_decode(fixture["sender"].as_str().unwrap().trim_start_matches("0x"))
        .try_into()
        .unwrap();
    world.protocol.insert(
        EVM_POLICY_KEY.into(),
        serde_json::to_vec(&fixture_policy()).unwrap(),
    );
    world.accounts.insert(
        conventional_evm_account_key(sender),
        AccountState {
            balance_nwei: 10_000_000_000_000,
            nonce: 0,
            code_hash: None,
        },
    );
}
fn receipt(
    configs: &[NodeConfiguration],
    hash: &serde_json::Value,
    root: &Path,
    children: &mut [std::process::Child],
    submitted_at: Instant,
) -> serde_json::Value {
    // Diagnostic functional qualification on the unchanged release artifact.
    // The prior 180s wall-time failure remains a performance failure. Bound
    // this investigation by wall time, actual finalized blocks and liveness.
    let diagnostic =
        std::env::var_os("SYNERGY_EVM_RECEIPT_DIAGNOSTIC").is_some_and(|value| value == "1");
    let started = Instant::now();
    let deadline = started + Duration::from_secs(if diagnostic { 600 } else { 180 });
    let mut last_progress = started;
    let mut first_height = None;
    let mut diagnosed = false;
    let mut previous = 0;
    loop {
        for (index, child) in children.iter_mut().enumerate() {
            if let Some(status) = child.try_wait().unwrap() {
                let log = fs::read_to_string(root.join(format!("node-{index}/process.log")))
                    .unwrap_or_default();
                let start = log
                    .char_indices()
                    .rev()
                    .nth(4096)
                    .map_or(0, |(index, _)| index);
                panic!("actual EVM owner{index} exited {status}: {}", &log[start..]);
            }
        }
        let rows = configs
            .iter()
            .map(|config| {
                process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "eth_getTransactionReceipt",
                    serde_json::json!([hash]),
                )
            })
            .collect::<Vec<_>>();
        if rows
            .iter()
            .all(|row| row.as_ref().is_ok_and(|value| !value.is_null()))
        {
            let first = rows[0].as_ref().unwrap();
            assert!(rows.iter().all(|row| row.as_ref().unwrap() == first));
            eprintln!("Actual EVM submission-to-receipt={:?} receipt-wait={:?} inclusion={} first-observed-native-height={first_height:?} diagnostic={diagnostic}",submitted_at.elapsed(),started.elapsed(),first["blockNumber"]);
            return first.clone();
        }
        let heights = configs
            .iter()
            .map(|config| {
                process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "eth_blockNumber",
                    serde_json::json!([]),
                )
            })
            .collect::<Vec<_>>();
        let height = heights
            .iter()
            .filter_map(|row| {
                row.as_ref()
                    .ok()
                    .and_then(|value| value.as_str())
                    .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
            })
            .min()
            .unwrap_or(0);
        if height > previous {
            previous = height;
            first_height.get_or_insert(height);
            last_progress = Instant::now();
            eprintln!("EVM actual-five-process finalized execution H{height}");
        }
        if diagnostic && !diagnosed && started.elapsed() >= Duration::from_secs(120) {
            diagnosed = true;
            eprintln!(
                "EVM diagnostic pending after {:?}, nativeH{height}, receipt observations={rows:?}",
                started.elapsed()
            );
            diagnostic_public_world(&configs[0], height);
        }
        if Instant::now() >= deadline
            || last_progress.elapsed() >= Duration::from_secs(180)
            || (diagnostic && first_height.is_some_and(|first| height.saturating_sub(first) >= 32))
        {
            for (index, config) in configs.iter().enumerate() {
                let telemetry = process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({}),
                );
                let bounded=telemetry.as_ref().map(|v|serde_json::json!({
                    "height":v["finalized_height"],"pipeline":v["chain"]["pipeline"],
                    "cadence":v["chain"]["cadence"],"resource_budget":v["resource_budget"],
                    "admission":v["admission"],"transport_peers":v["transport"]["apqe_session_count"]}));
                eprintln!("EVM diagnostic deadline node{index} telemetry={bounded:?}");
                let text = fs::read_to_string(root.join(format!("node-{index}/process.log")))
                    .unwrap_or_default();
                let start = text
                    .char_indices()
                    .rev()
                    .nth(4096)
                    .map_or(0, |(index, _)| index);
                eprintln!(
                    "EVM deadline node{index} native log tail: {}",
                    &text[start..]
                );
            }
            diagnostic_public_world(&configs[0], height);
            panic!("EVM actual-five-process finalized receipt deadline: receipts={rows:?}, heights={heights:?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Stream only bounded, already-public finalized state for this immediate
/// diagnosis. No files, pending/decrypted payloads, credentials or custody data.
fn diagnostic_public_world(config: &NodeConfiguration, height: u64) {
    use base64::Engine;
    let result = (|| -> Result<serde_json::Value, String> {
        let mut bytes = Vec::new();
        let mut offset = 0;
        let mut pin = None;
        loop {
            let mut params = serde_json::json!({"height":height,"kind":"world_state","offset":offset,"limit":65536});
            if let Some(pin) = &pin {
                params["expected_sha256"] = serde_json::json!(pin);
            }
            let page = process_rpc(
                config.rpc.listen_address.unwrap(),
                "synergy_getFinalizedProofPageV1",
                params,
            )?;
            if page["total_bytes"].as_u64().is_none_or(|n| n > 1024 * 1024) {
                return Err("diagnostic World bound".into());
            }
            let part = base64::engine::general_purpose::STANDARD
                .decode(
                    page["bytes_base64"]
                        .as_str()
                        .ok_or("diagnostic page encoding")?,
                )
                .map_err(|e| e.to_string())?;
            bytes.extend(part);
            if bytes.len() > 1024 * 1024 {
                return Err("diagnostic World bound".into());
            }
            pin = Some(
                page["sha256"]
                    .as_str()
                    .ok_or("diagnostic page digest")?
                    .to_owned(),
            );
            match page["next_offset"].as_u64() {
                Some(next) => offset = next as usize,
                None => break,
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        let world: WorldState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let accounts=world.accounts.iter().filter(|(k,_)|k.starts_with("0x")).take(8)
            .map(|(k,v)|serde_json::json!({"address":k,"nonce":v.nonce,"balance":v.balance_nwei.to_string(),"code":v.code_hash.is_some()})).collect::<Vec<_>>();
        let mut records = Vec::new();
        for (key, value) in &world.protocol {
            if records.len() == 16 {
                break;
            }
            if key.starts_with("etdag-processing-ready-v1/")
                || key.starts_with("etdag-processing-groups-v1/")
                || key.starts_with("aivm/ethereum/v1/transaction/")
            {
                let decoded: serde_json::Value =
                    serde_json::from_slice(value).map_err(|e| e.to_string())?;
                let view = if key.starts_with("aivm/ethereum/v1/transaction/") {
                    serde_json::json!({"height":decoded["height"],"has_receipt":!decoded["receipt"].is_null(),"rejection":decoded["rejection"]})
                } else if key.contains("/claim/") {
                    serde_json::json!({"group_number":decoded["group_number"],"order_position":decoded["order_position"],"sender":decoded["member"]["envelope"]["sender_id"],"nonce":decoded["member"]["envelope"]["nonce_slot"]})
                } else if key.starts_with("etdag-processing-ready-v1/item/") {
                    let ready: synergy_execution::ProcessingReadyRecord =
                        serde_json::from_slice(value).map_err(|e| e.to_string())?;
                    let meta: serde_json::Value =
                        serde_json::from_slice(&world.protocol["etdag-processing-ready-v1/meta"])
                            .map_err(|e| e.to_string())?;
                    let namespace: synergy_etdag::EtdagDigest =
                        serde_json::from_value(meta["namespace_root"].clone())
                            .map_err(|e| e.to_string())?;
                    let assignment = synergy_execution::verify_processing_record_assignment(
                        &world, &namespace, &ready,
                    )
                    .err()
                    .map(|e| e.to_string());
                    serde_json::json!({"group":ready.item.group_number,"position":ready.item.order_position,
                        "sender":ready.sender_wallet,"nonce":ready.sender_nonce,"gas":ready.item.gas_class_units,
                        "encoded_bytes":ready.item.encoded_bytes,"assignment_error":assignment})
                } else if key.contains("/group/") {
                    serde_json::json!({"group":decoded["group_number"],"remaining":decoded["remaining"],
                        "next_position":decoded["next_position"],"closed":!decoded["closed_by_successor"].is_null()})
                } else {
                    serde_json::json!({"last_number":decoded["last_number"],"generation":decoded["generation"],"count":decoded["count"]})
                };
                records.push(serde_json::json!({"key":key,"value":view}));
            }
        }
        Ok(
            serde_json::json!({"height":height,"world_bytes":bytes.len(),"accounts":accounts,"records":records}),
        )
    })();
    eprintln!("Bounded actual finalized EVM/READY/group diagnostic={result:?}");
}
pub(super) fn qualify(
    configs: &[NodeConfiguration],
    children: &mut [std::process::Child],
    binary: &Path,
    root: &Path,
) {
    let fixture = fixture();
    let module = independent_ethers_module();
    let rpc = configs[0].rpc.listen_address.unwrap();
    assert_eq!(
        process_rpc(rpc, "eth_chainId", serde_json::json!([])).unwrap(),
        "0x1869f"
    );
    let submitted_at = Instant::now();
    let hash = process_rpc(
        rpc,
        "eth_sendRawTransaction",
        serde_json::json!([fixture["transactions"][0]["raw"]]),
    )
    .unwrap();
    assert_eq!(hash, fixture["transactions"][0]["hash"]);
    assert!(
        process_rpc(rpc, "eth_getTransactionReceipt", serde_json::json!([hash]))
            .unwrap()
            .is_null()
    );
    let genesis_restart =
        std::env::var_os("SYNERGY_EVM_GENESIS_RESTART").is_some_and(|value| value == "1");
    if genesis_restart {
        restart_admitter(children, binary, root);
    }
    // No manual reconnect: the actual production APQE network owner must
    // restore its authenticated routes and replay the original durable work.
    let mut observed = vec![receipt(configs, &hash, root, children, submitted_at)];
    assert_eq!(observed[0]["status"], "0x1");
    if genesis_restart {
        verify_ethers_rpc(&module, rpc, &fixture, &observed, None);
        verify_recovered_owners(configs);
        eprintln!("Genesis-anchored original survived abrupt restart with independent receipt/block/MPT verification PASS");
        return;
    }
    for (index, status) in [(1, "0x1"), (2, "0x0"), (3, "0x1"), (4, "0x0"), (7, "0x1")] {
        let submitted_at = Instant::now();
        let hash = process_rpc(
            rpc,
            "eth_sendRawTransaction",
            serde_json::json!([fixture["transactions"][index]["raw"]]),
        )
        .unwrap();
        assert_eq!(hash, fixture["transactions"][index]["hash"]);
        let row = receipt(configs, &hash, root, children, submitted_at);
        eprintln!(
            "EVM fixture{index} finalized at{} status{}",
            row["blockNumber"], row["status"]
        );
        assert_eq!(row["status"], status);
        if index == 1 {
            assert_eq!(row["logs"].as_array().unwrap().len(), 1);
        }
        if index == 2 {
            assert!(row["logs"].as_array().unwrap().is_empty());
        }
        if index == 4 {
            assert_eq!(row["synergyNativeException"], "sub-native-precision");
            assert_eq!(row["gasUsed"], "0xf4240");
        }
        observed.push(row);
        if index == 3 {
            verify_ethers_rpc(&module, rpc, &fixture, &observed, Some(true));
            eprintln!(
                "Independent ethers real ABI/call/estimate/revert/log/block/MPT acceptance PASS"
            );
        }
    }
    verify_ethers_rpc(&module, rpc, &fixture, &observed, Some(false));
    if !genesis_restart {
        let quantity = |value: serde_json::Value| {
            u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let receiver = format!("0x{}", "35".repeat(20));
        let receiver_before = quantity(
            process_rpc(
                rpc,
                "eth_getBalance",
                serde_json::json!([receiver, "latest"]),
            )
            .unwrap(),
        );
        let sender_before = quantity(
            process_rpc(
                rpc,
                "eth_getBalance",
                serde_json::json!([fixture["sender"], "latest"]),
            )
            .unwrap(),
        );
        let signed=std::process::Command::new("node").args(["-e",r#"
          const e=require(process.argv[1]);new e.Wallet('0x'+'46'.repeat(32)).signTransaction({type:0,chainId:99999,nonce:6,
            gasPrice:20000000000n,gasLimit:21000,to:'0x'+'35'.repeat(20),value:1000000000000000000n}).then(raw=>process.stdout.write(raw));
        "#,module.to_str().unwrap()]).output().unwrap();
        assert!(signed.status.success());
        let raw = String::from_utf8(signed.stdout).unwrap();
        assert!(raw.len() < 1024);
        let submitted_at = Instant::now();
        let hash = process_rpc(rpc, "eth_sendRawTransaction", serde_json::json!([raw])).unwrap();
        assert!(
            process_rpc(rpc, "eth_getTransactionReceipt", serde_json::json!([hash]))
                .unwrap()
                .is_null()
        );
        restart_admitter(children, binary, root);
        let recovered = receipt(configs, &hash, root, children, submitted_at);
        assert_eq!(recovered["status"], "0x1");
        assert_eq!(
            process_rpc(
                rpc,
                "eth_getTransactionCount",
                serde_json::json!([fixture["sender"], "latest"])
            )
            .unwrap(),
            "0x7"
        );
        assert_eq!(recovered["gasUsed"], "0x5208");
        for config in configs {
            let rpc = config.rpc.listen_address.unwrap();
            assert_eq!(
                quantity(
                    process_rpc(
                        rpc,
                        "eth_getBalance",
                        serde_json::json!([receiver, "latest"])
                    )
                    .unwrap()
                ),
                receiver_before + 1_000_000_000_000_000_000
            );
            assert_eq!(
                quantity(
                    process_rpc(
                        rpc,
                        "eth_getBalance",
                        serde_json::json!([fixture["sender"], "latest"])
                    )
                    .unwrap()
                ),
                sender_before - 1_000_000_000_000_000_000 - 21_000 * 20_000_000_000
            );
            assert!(process_rpc(rpc, "eth_sendRawTransaction", serde_json::json!([raw])).is_err());
        }
        eprintln!(
            "Exactly-once1SNRG transfer and fee/nonce convergence after autonomous restart PASS"
        );
    }
    verify_recovered_owners(configs);
    eprintln!(
        "EVM actual five-process APQE encryption/restart/PoSy finality/Solidity/ethers RPC PASS"
    );
}

fn verify_recovered_owners(configs: &[NodeConfiguration]) {
    let recovered_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let observations = configs
            .iter()
            .map(|config| {
                process_rpc(
                    config.rpc.listen_address.unwrap(),
                    "synergy_chainTelemetry",
                    serde_json::json!({}),
                )
                .ok()
                .map(|value| {
                    (
                        value["transport"]["apqe_session_count"].as_u64(),
                        value["chain"]["pipeline"]["processing_completion_count"].as_u64(),
                        value["resource_budget"]["used_bytes"].as_u64(),
                    )
                })
            })
            .collect::<Vec<_>>();
        if observations.iter().all(|value| {
            value.is_some_and(|(peers, completions, bytes)| {
                peers == Some(4)
                    && completions == Some(0)
                    && bytes.is_some_and(|bytes| bytes < 256 * 1024 * 1024)
            })
        }) {
            break;
        }
        assert!(
            Instant::now() < recovered_deadline,
            "actual restart routes/completion quiescence did not recover: {observations:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("All five production owners restored four encrypted peers and quiesced finalized EVM work PASS");
}

fn restart_admitter(children: &mut [std::process::Child], binary: &Path, root: &Path) {
    children[0].kill().unwrap();
    children[0].wait().unwrap();
    let log = fs::OpenOptions::new()
        .append(true)
        .open(root.join("node-0/process.log"))
        .unwrap();
    children[0] = std::process::Command::new(binary)
        .args(["start", "--config"])
        .arg(root.join("node-0/config.json"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
}

fn verify_ethers_rpc(
    module: &Path,
    address: std::net::SocketAddr,
    fixture: &serde_json::Value,
    receipts: &[serde_json::Value],
    call: Option<bool>,
) {
    use std::io::Write;
    let mut child=std::process::Command::new("node").args(["-e",r#"
        const fs=require('fs');const e=require(process.argv[1]);if(e.version!=='6.15.0')throw Error('independent ethers version differs');
        const input=JSON.parse(fs.readFileSync(0,'utf8'));
        const qb=x=>{x=BigInt(x);return x===0n?'0x':e.toBeHex(x)};
        const nibbles=x=>Array.from(e.getBytes(x)).flatMap(b=>[b>>4,b&15]);
        const compact=(path,leaf)=>{const odd=path.length%2;let v=[(leaf?2:0)+odd,...(odd?[]:[0]),...path];
          return e.hexlify(Uint8Array.from(Array.from({length:v.length/2},(_,i)=>(v[2*i]<<4)|v[2*i+1])))};
        const ref=node=>e.dataLength(e.encodeRlp(node))<32?node:e.keccak256(e.encodeRlp(node));
        function trieNode(rows,depth){if(rows.length===1)return [compact(rows[0].key.slice(depth),true),rows[0].value];
          let common=depth;while(rows.every(row=>row.key.length>common&&row.key[common]===rows[0].key[common]))common++;
          if(common>depth)return [compact(rows[0].key.slice(depth,common),false),ref(trieNode(rows,common))];
          const out=Array(17).fill('0x');for(let i=0;i<16;i++){const child=rows.filter(row=>row.key[depth]===i);if(child.length)out[i]=ref(trieNode(child,depth+1));}
          const leaf=rows.find(row=>row.key.length===depth);if(leaf)out[16]=leaf.value;return out;}
        function trieRoot(values){if(!values.length)return e.keccak256(e.encodeRlp('0x'));
          const rows=values.map((value,i)=>({key:nibbles(e.encodeRlp(qb(i))),value}));return e.keccak256(e.encodeRlp(trieNode(rows,0)));}

        (async()=>{const p=new e.JsonRpcProvider(input.url,undefined,{batchMaxCount:1});
          if((await p.getNetwork()).chainId!==99999n)throw Error('wrong chain');
          const wallet=new e.Wallet('0x'+'46'.repeat(32));
          for(const chainId of [1266,9969,469,0]){
            const raw=await wallet.signTransaction({type:0,chainId,nonce:6,gasPrice:20000000000n,gasLimit:21000,to:'0x'+'35'.repeat(20),value:0});
            let rejected=false;try{await p.send('eth_sendRawTransaction',[raw]);}catch(error){rejected=true;}
            if(!rejected)throw Error('wrong/unprotected chain authorization admitted');
          }
          const typed=await wallet.signTransaction({type:2,chainId:99999,nonce:6,maxFeePerGas:20000000000n,maxPriorityFeePerGas:1000000000n,gasLimit:21000,to:'0x'+'35'.repeat(20),value:0});
          let typedRejected=false;try{await p.send('eth_sendRawTransaction',[typed]);}catch(error){typedRejected=true;}
          if(!typedRejected)throw Error('unsupported typed transaction admitted');

          for(const row of input.receipts){const r=await p.getTransactionReceipt(row.transactionHash);
            if(!r||r.hash!==row.transactionHash||r.blockHash!==row.blockHash||r.status!==Number(BigInt(row.status)))throw Error('receipt mismatch');
            const t=await p.getTransaction(row.transactionHash);if(!t||t.chainId!==99999n||t.hash!==row.transactionHash)throw Error('transaction mismatch');
          }
          const block=await p.getBlock(input.receipts[0].blockHash);if(!block||block.hash!==input.receipts[0].blockHash)throw Error('native block projection');
          const rawBlock=await p.send('eth_getBlockByNumber',[e.toQuantity(block.number),false]);
          // Geth core/types/gen_header_json.go required fields and fixed widths;
          // this validates a genuine RPC result, not an invented header hash.
          for(const field of ['hash','parentHash','sha3Uncles','stateRoot','transactionsRoot','receiptsRoot'])
            if(!e.isHexString(rawBlock[field],32))throw Error('Ethereum header hash field '+field);
          if(!e.isHexString(rawBlock.miner,20)||!e.isHexString(rawBlock.logsBloom,256)||!e.isHexString(rawBlock.extraData)||e.dataLength(rawBlock.extraData)>32)
            throw Error('Ethereum header address/bloom/extraData schema');
          for(const field of ['number','difficulty','gasLimit','gasUsed','timestamp','baseFeePerGas','totalDifficulty','size'])
            if(typeof rawBlock[field]!=='string'||!/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(rawBlock[field]))throw Error('Ethereum header quantity '+field);
          for(const field of ['gasLimit','gasUsed','timestamp'])if(BigInt(rawBlock[field])>0xffffffffffffffffn)throw Error('Ethereum uint64 '+field);
          if(BigInt(rawBlock.gasUsed)>BigInt(rawBlock.gasLimit)||!Array.isArray(rawBlock.transactions)||!Array.isArray(rawBlock.uncles))throw Error('Ethereum block structure');
          if(rawBlock.nonce!==null&&!e.isHexString(rawBlock.nonce,8))throw Error('Ethereum optional nonce schema');
          if(rawBlock.mixHash!==null&&!e.isHexString(rawBlock.mixHash,32))throw Error('Ethereum optional mixHash schema');
          for(const hash of [...rawBlock.transactions,...rawBlock.uncles])if(!e.isHexString(hash,32))throw Error('Ethereum block member hash');
          const byHash=await p.send('eth_getBlockByHash',[rawBlock.hash,false]);
          if(JSON.stringify(byHash)!==JSON.stringify(rawBlock))throw Error('block number/hash projection differs');
          const txs=[],rcpts=[];for(const hash of rawBlock.transactions){const tx=await p.getTransaction(hash);
            txs.push(e.Transaction.from({type:0,to:tx.to,nonce:tx.nonce,gasLimit:tx.gasLimit,gasPrice:tx.gasPrice,value:tx.value,data:tx.data,chainId:tx.chainId,signature:tx.signature}).serialized);
            const r=await p.send('eth_getTransactionReceipt',[hash]);
            rcpts.push(e.encodeRlp([qb(r.status),qb(r.cumulativeGasUsed),r.logsBloom,r.logs.map(log=>[log.address,log.topics,log.data])]));}
          if(trieRoot(txs)!==rawBlock.transactionsRoot||trieRoot(rcpts)!==rawBlock.receiptsRoot)throw Error('independent Ethereum MPT root mismatch');
          const headerFields=['parentHash','sha3Uncles','miner','stateRoot','transactionsRoot','receiptsRoot','logsBloom','difficulty','number','gasLimit','gasUsed','timestamp','extraData','mixHash','nonce','baseFeePerGas'];
          const quantities=new Set(['difficulty','number','gasLimit','gasUsed','timestamp','baseFeePerGas']);
          const header=headerFields.map(field=>quantities.has(field)?qb(rawBlock[field]):rawBlock[field]);
          const projected=e.encodeRlp([header,txs.map(raw=>e.decodeRlp(raw)),[]]);
          if(BigInt(e.dataLength(projected))!==BigInt(rawBlock.size))throw Error('independent projected RLP block size mismatch');
          const accountRows=[];const emptyRoot=trieRoot([]);
          for(const address of [input.fixture.sender,'0x'+'55'.repeat(20),input.fixture.address]){
            const [balance,nonce,code]=await Promise.all([p.getBalance(address,block.number),p.getTransactionCount(address,block.number),p.getCode(address,block.number)]);
            if(balance===0n&&nonce===0&&code==='0x')continue;
            let storageRoot=emptyRoot;if(code!=='0x'){
              const value=await p.getStorage(address,0,block.number);
              if(BigInt(value)!==0n){const row={key:nibbles(e.keccak256(e.toBeHex(0,32))),value:e.encodeRlp(qb(value))};storageRoot=e.keccak256(e.encodeRlp(trieNode([row],0)));}
            }
            accountRows.push({key:nibbles(e.keccak256(address)),value:e.encodeRlp([qb(nonce),qb(balance),storageRoot,e.keccak256(code)])});
          }
          if(e.keccak256(e.encodeRlp(trieNode(accountRows,0)))!==rawBlock.stateRoot)throw Error('independent Ethereum account/storage MPT root mismatch');


          if(await p.getBalance(input.fixture.sender)<=0n)throw Error('native balance projection');
          if(input.call===true){const logs=await p.getLogs({address:input.fixture.address,fromBlock:input.receipts[1].blockNumber,toBlock:input.receipts[1].blockNumber});if(logs.length!==1)throw Error('finalized logs');
            const iface=new e.Interface(input.fixture.abi);
            const output=await p.call({to:input.fixture.address,data:iface.encodeFunctionData('value')});
            if(iface.decodeFunctionResult('value',output)[0]!==42n)throw Error('independent ABI call');
            let reverted=false;try{await p.call({to:input.fixture.address,data:iface.encodeFunctionData('fail')});}
            catch(error){reverted=error.code==='CALL_EXCEPTION'&&error.reason==='rollback';}if(!reverted)throw Error('standard ABI revert reason');

            if(await p.getStorage(input.fixture.address,0)!==e.toBeHex(42,32))throw Error('storage mismatch');
            const gas=await p.estimateGas({to:input.fixture.address,data:iface.encodeFunctionData('value')});if(gas<21000n)throw Error('gas estimate');
          }else if(input.call===false){if(await p.getTransactionCount(input.fixture.sender)!==6||await p.getCode(input.fixture.address)!=='0x')throw Error('nonce/code mismatch');}
          else if(await p.getTransactionCount(input.fixture.sender)!==1||await p.getCode(input.fixture.address)!==('0x'+input.fixture.runtime.replace(/^0x/,'')))throw Error('recovered deployment nonce/code mismatch');
          p.destroy();
        })().catch(error=>{console.error(error);process.exitCode=1});
    "#,module.to_str().unwrap()]).stdin(std::process::Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&serde_json::json!({"url":format!("http://{address}"),"fixture":fixture,"receipts":receipts,"call":call})).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success(), "independent ethers RPC acceptance failed");
                break;
            }
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("independent ethers RPC deadline exceeded");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
