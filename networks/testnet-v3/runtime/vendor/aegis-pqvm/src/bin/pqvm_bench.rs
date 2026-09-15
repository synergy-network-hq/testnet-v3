use std::time::{Duration, Instant};

fn parse_iterations() -> u32 {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--iterations" {
            if let Some(v) = args.next() {
                if let Ok(n) = v.parse::<u32>() {
                    return n.max(1);
                }
            }
        }
    }
    100
}

fn bench<F: FnMut()>(name: &str, iterations: u32, mut f: F) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total = start.elapsed();
    let avg = total / iterations;
    println!("{name}: {iterations} iters in {total:?} ({avg:?} avg)");
    avg
}

fn main() {
    let iterations = parse_iterations();
    println!("Aegis PQVM Bench (basic)");
    println!("iterations={iterations}");

    #[cfg(feature = "mlkem")]
    {
        use aegis_pqvm::mlkem::mlkem512::{decapsulate, encapsulate, keypair};
        println!("\nML-KEM-512:");
        bench("keypair", iterations, || {
            let _ = keypair();
        });
        let (pk, sk) = keypair();
        bench("encapsulate", iterations, || {
            let _ = encapsulate(&pk);
        });
        let (_ss, ct) = encapsulate(&pk);
        bench("decapsulate", iterations, || {
            let _ = decapsulate(&ct, &sk);
        });
    }

    #[cfg(feature = "mldsa")]
    {
        use aegis_pqvm::mldsa::mldsa44::{detached_sign, keypair, verify_detached_signature};
        println!("\nML-DSA-44:");
        bench("keypair", iterations, || {
            let _ = keypair();
        });
        let (pk, sk) = keypair();
        let msg = b"aegis pqvm bench";
        bench("sign(detached)", iterations, || {
            let _ = detached_sign(msg, &sk);
        });
        let sig = detached_sign(msg, &sk);
        bench("verify(detached)", iterations, || {
            let _ = verify_detached_signature(&sig, msg, &pk);
        });
    }

    #[cfg(feature = "fndsa")]
    {
        use aegis_pqvm::fndsa::fndsa512::{detached_sign, keypair, verify_detached_signature};
        println!("\nFN-DSA-512:");
        bench("keypair", iterations, || {
            let _ = keypair();
        });
        let (pk, sk) = keypair();
        let msg = b"aegis pqvm bench";
        bench("sign(detached)", iterations, || {
            let _ = detached_sign(msg, &sk);
        });
        let sig = detached_sign(msg, &sk);
        bench("verify(detached)", iterations, || {
            let _ = verify_detached_signature(&sig, msg, &pk);
        });
    }

    println!("\nDone.");
}
