//! Bounded public batches use the existing authenticated single-call owner.
use super::*;
/// Historical and current carriers share the actual borrowed parser owner.
pub(super) fn batch_items(bytes: &[u8]) -> Result<Vec<&RawValue>, String> {
    synergy_rpc::current_batch::raw_batch_items(bytes)
        .map_err(|_| "invalid or oversized RPC batch".into())
}
pub(super) fn validate_document(bytes: &[u8]) -> Result<(), String> {
    validate_document_with(bytes, |_, method| validate_public_method(method))
}
/// Both historical and current carriers retain one shared body/batch/envelope/
/// distinct scalar-ID policy; only their method/context policy differs.
pub(super) fn validate_document_with(
    bytes: &[u8],
    mut policy: impl FnMut(&[u8], &str) -> Result<(), String>,
) -> Result<(), String> {
    if bytes.len() > MAX_BODY {
        return Err("RPC document exceeds body bound".into());
    }
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'[') {
        let request = validate_request_envelope(bytes)?;
        return policy(bytes, request.method);
    }
    let requests = batch_items(bytes)?;
    let mut ids = std::collections::BTreeSet::new();
    for raw in requests {
        let request = validate_request_envelope(raw.get().as_bytes())?;
        let id: serde_json::Value =
            serde_json::from_str(request.id.get()).map_err(|_| "invalid batch id")?;
        if request.id.get().len() > 256
            || !(id.is_string() || id.is_number())
            || !ids.insert(id.to_string())
        {
            return Err("RPC batch requires distinct bounded scalar ids".into());
        }
        policy(raw.get().as_bytes(), request.method)?;
    }
    Ok(())
}

pub(super) fn forward_batch(
    body: &[u8],
    chain_id: u64,
    network_id: &str,
    genesis: &str,
    mut forward: impl FnMut(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    validate_document(body)?;
    let requests = batch_items(body)?;
    let error = |raw: &RawValue, processed: bool| -> Result<Vec<u8>, String> {
        let request = validate_request(raw.get().as_bytes())?;
        let id: serde_json::Value =
            serde_json::from_str(request.id.get()).map_err(|_| "invalid RPC batch id")?;
        let message = if processed {
            "authenticated RPC outcome unavailable; reconcile the original request"
        } else {
            "RPC batch response capacity reached before dispatch"
        };
        bind_response(&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"error":{
            "code":-32000,"message":message,"data":{"dispatched":processed,"automatic_retry":false}}}))
            .map_err(|_|"cannot encode bounded batch error")?,chain_id,network_id,genesis)
    };
    let errors = requests
        .iter()
        .map(|raw| Ok((error(raw, false)?, error(raw, true)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let error_bytes = errors
        .iter()
        .map(|(a, b)| a.len().max(b.len()))
        .sum::<usize>();
    if error_bytes + requests.len() + 2 > MAX_BODY {
        return Err("RPC batch error envelope exceeds body bound".into());
    }
    let mut remaining = error_bytes;
    let mut result = Vec::with_capacity(8192);
    result.push(b'[');
    for (index, raw) in requests.iter().enumerate() {
        if index > 0 {
            result.push(b',');
        }
        // Reserve bounded errors for all remaining items before any dispatch.
        // A large result never permits an unbounded response allocation or
        // causes an automatic retry of a previously submitted write.
        let (not_dispatched, unconfirmed) = &errors[index];
        let minimum = not_dispatched.len().max(unconfirmed.len());
        remaining -= minimum;
        let reserve = remaining + (requests.len() - index - 1) + 1;
        let available = MAX_BODY.saturating_sub(result.len() + reserve);
        let dispatched = available > minimum;
        let mut reply = if !dispatched {
            not_dispatched.clone()
        } else {
            match forward(raw.get().as_bytes()) {
                Ok(reply) => reply,
                Err(_) => unconfirmed.clone(),
            }
        };
        if reply.len() > available && dispatched {
            reply = unconfirmed.clone();
        }
        if result
            .len()
            .checked_add(reply.len() + 1)
            .is_none_or(|n| n > MAX_BODY)
        {
            return Err("bounded RPC batch response capacity exhausted".into());
        }
        result.extend_from_slice(&reply);
    }
    result.push(b']');
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_validation_precedes_every_dispatch_and_preserves_signed_payload_bytes() {
        let raw=br#"[{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xf86cAbCD"]}, {"jsonrpc":"2.0","id":2,"method":"eth_getLogs","params":[{"topics":[null]}]}]"#;
        let mut seen = Vec::new();
        let result = forward_batch(raw, 99999, "canary", "genesis", |one| {
            seen.push(one.to_vec());
            let request = validate_request(one)?;
            bind_response(
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":[]}}",
                    request.id.get()
                )
                .as_bytes(),
                99999,
                "canary",
                "genesis",
            )
        })
        .unwrap();
        assert_eq!(seen.len(), 2);
        assert!(std::str::from_utf8(&seen[0])
            .unwrap()
            .contains("0xf86cAbCD"));
        let values: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(values[0]["id"], 1);
        assert_eq!(values[1]["chain_context"]["chain_id"], 99999);
        for body in [
            b"[]".as_slice(),
            br#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":1,"method":"b"}]"#,
            br#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","method":"b"}]"#,
        ] {
            let mut called = false;
            assert!(forward_batch(body, 99999, "canary", "genesis", |_| {
                called = true;
                Ok(Vec::new())
            })
            .is_err());
            assert!(!called);
        }
        let oversized = (0..33)
            .map(|id| json!({"jsonrpc":"2.0","id":id,"method":"eth_chainId"}))
            .collect::<Vec<_>>();
        assert!(validate_document(&serde_json::to_vec(&oversized).unwrap()).is_err());
    }
    #[test]
    fn batch_response_pressure_never_retries_a_processed_request() {
        let input=br#"[{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction"},{"jsonrpc":"2.0","id":2,"method":"eth_chainId"}]"#;
        let mut calls = 0;
        let result = forward_batch(input, 99999, "canary", "genesis", |_| {
            calls += 1;
            Ok(vec![b'x'; MAX_BODY])
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert!(result.len() <= MAX_BODY);
        let v: serde_json::Value = serde_json::from_slice(&result).unwrap();
        for r in v.as_array().unwrap() {
            assert_eq!(r["error"]["data"]["dispatched"], true);
            assert_eq!(r["error"]["data"]["automatic_retry"], false);
        }
    }
    #[test]
    fn independent_default_ethers_batches_cross_the_actual_http_carrier() {
        // Transport/schema acceptance only. These fixture values are not claimed
        // native execution, finality, account proofs or a deployed Canary service.
        use std::sync::atomic::{AtomicBool, Ordering};
        let module=std::path::PathBuf::from("/Volumes/PortableSSD/02-Synergy-Network/08-Synergy-Website/node_modules/ethers/lib.esm/index.js");
        assert!(
            module.is_file(),
            "independently installed ethers6.15.0 is mandatory"
        );
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let native = upstream.local_addr().unwrap();
        upstream.set_nonblocking(true).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let public = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let batches = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::clone(&done);
        let native_thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                let (mut stream, _) = match upstream.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("native fixture accept:{e}"),
                };
                let request = read_http(&mut stream, Instant::now() + TIMEOUT).unwrap();
                let parsed: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let value = match parsed["method"].as_str().unwrap() {
                    "eth_chainId" => json!("0x1869f"),
                    "eth_blockNumber" => json!("0x2a"),
                    "eth_getBalance" => json!("0x10"),
                    method => panic!("unexpected ethers method {method}"),
                };
                send_http(
                    &mut stream,
                    200,
                    &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":parsed["id"],"result":value}))
                        .unwrap(),
                    None,
                )
                .unwrap();
            }
        });
        let stop = Arc::clone(&done);
        let observed = Arc::clone(&batches);
        let gateway = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("gateway fixture accept:{e}"),
                };
                let request = read_http(&mut stream, Instant::now() + TIMEOUT).unwrap();
                let mut one = |raw: &[u8]| {
                    bind_response(&call_loopback(native, raw)?, 99999, "canary", "genesis")
                };
                let response = if request.body.first() == Some(&b'[') {
                    observed
                        .lock()
                        .unwrap()
                        .push(batch_items(&request.body).unwrap().len());
                    forward_batch(&request.body, 99999, "canary", "genesis", &mut one).unwrap()
                } else {
                    one(&request.body).unwrap()
                };
                send_http(&mut stream, 200, &response, None).unwrap();
            }
        });
        let script = r#"const timer=setTimeout(()=>process.exit(3),10000);try{const e=await import(process.argv[1]);if(e.version!=='6.15.0')throw Error('independent ethers version');const p=new e.JsonRpcProvider(process.argv[2]);const [h,b,n]=await Promise.all([p.getBlockNumber(),p.getBalance('0x1111111111111111111111111111111111111111'),p.getNetwork()]);p.destroy();if(h!==42||b!==16n||n.chainId!==99999n)throw Error('typed batch result');clearTimeout(timer);process.stdout.write('default ethers batch PASS');}catch(e){clearTimeout(timer);console.error(e);process.exit(1)}"#;
        let result = std::process::Command::new("node")
            .args(["--input-type=module", "--eval", script])
            .arg(module)
            .arg(format!("http://{public}"))
            .output();
        done.store(true, Ordering::Relaxed);
        gateway.join().unwrap();
        native_thread.join().unwrap();
        let result = result.unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, b"default ethers batch PASS");
        assert!(
            batches.lock().unwrap().iter().any(|count| *count >= 2),
            "the default ethers client must actually batch"
        );
    }
}
