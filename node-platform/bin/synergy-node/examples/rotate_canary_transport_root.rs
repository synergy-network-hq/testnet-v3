//! Offline Canary 99999 registry rotation. The unlock is a 32-byte random value
//! encoded in lowercase hex and supplied on a private stdin pipe.
#[path = "../src/services/apqe_registry_wire.rs"]
mod registry;

use registry::{signing_bytes, SignedRegistry, REGISTRY_CONTEXT};
use std::{
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use synergy_address_engine::{
    apqe::{
        crypto_engine::CryptoEngine, fixed_digest, provider::SignOptions, FixedDigest, Primitives,
        SecretBytes,
    },
    encrypt::{decrypt_with_passphrase, encrypt_with_passphrase, EncryptedEnvelope},
    types::Algorithm,
};

fn sha(bytes: &[u8]) -> String {
    fixed_digest(&Primitives, FixedDigest::Sha256, bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read_pinned(path: &Path, max: u64, digest: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .and_then(|f| {
            if !f.metadata()?.is_file() {
                return Err(io::Error::other("not a regular file"));
            }
            f.take(max + 1).read_to_end(&mut bytes)
        })
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() as u64 > max || sha(&bytes) != digest {
        return Err(format!("input digest mismatch: {}", path.display()));
    }
    Ok(bytes)
}

fn verify(engine: &CryptoEngine, root: &[u8], signed: &SignedRegistry) -> Result<(), String> {
    if root.len() != 2592
        || !engine
            .verify(
                Algorithm::MlDsa87,
                root,
                &signing_bytes(&signed.payload)?,
                &signed.signature,
                SignOptions::Pure {
                    context: REGISTRY_CONTEXT,
                },
            )
            .map_err(|e| e.to_string())?
    {
        return Err("invalid ML-DSA-87 registry signature".into());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn run() -> Result<(), String> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--generate-unlock"] {
        if io::stdout().is_terminal() {
            return Err("unlock generation requires a private output pipe".into());
        }
        let mut random = vec![0; 32];
        Primitives
            .random_bytes(&mut random)
            .map_err(|e| e.to_string())?;
        let random = SecretBytes::from_bytes(random);
        let mut hex = Vec::with_capacity(64);
        const DIGITS: &[u8] = b"0123456789abcdef";
        for &byte in random.as_bytes() {
            hex.extend([
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]);
        }
        return io::stdout()
            .write_all(SecretBytes::from_bytes(hex).as_bytes())
            .map_err(|_| "unlock output failed".into());
    }
    let renew = args.first().is_some_and(|arg| arg == "--renew");
    if renew {
        args.remove(0);
    }
    let [report, report_sha, source, registry_sha, root_sha, output, custody] = args.as_slice()
    else {
        return Err("usage: rotate_canary_transport_root [--renew] <native-report> <report-sha256> <old-network-dir> <old-registry-sha256> <old-root-sha256> <new-public-dir> <custody-file>".into());
    };
    let [source, output, custody] = [source, output, custody].map(PathBuf::from);
    let report = Path::new(report);
    if ![report, &source, &output, &custody]
        .iter()
        .all(|p| p.is_absolute())
    {
        return Err("all paths must be absolute".into());
    }
    let bytes = read_pinned(
        &source.join("transport-registry.json"),
        256 * 1024,
        registry_sha,
    )?;
    let old_root = read_pinned(&source.join("transport-root.pub"), 2592, root_sha)?;
    let old: SignedRegistry = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let engine = synergy_aegis::load_authenticated_native_engine(report, report_sha)?;
    let engine = engine.lock().map_err(|_| "native engine unavailable")?;
    verify(&engine, &old_root, &old)?;
    let p = &old.payload;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    if p.schema_version != 1
        || p.scope != "isolated-development-canary"
        || p.chain_id != 99999
        || p.protocol != "posy/3.0"
        || p.epoch == 0
        || p.generation == 0
        || p.validators.len() != 5
        || p.valid_from_unix >= p.expires_at_unix
        || (renew && (p.valid_from_unix > now || p.expires_at_unix <= now))
        || (!renew && p.expires_at_unix > now)
    {
        return Err(
            "expected an authenticated five-validator Canary 99999 registry with matching validity"
                .into(),
        );
    }
    read_pinned(
        &source.join("genesis.json"),
        4 * 1024 * 1024,
        &p.genesis_artifact_sha256,
    )?;
    read_pinned(
        &source.join("authority.json"),
        1024 * 1024,
        &p.authority_binding_sha256,
    )?;
    let custody_dir = custody.parent().ok_or("missing custody parent")?;
    let custody_metadata = fs::symlink_metadata(custody_dir).map_err(|e| e.to_string())?;
    if !custody_metadata.is_dir()
        || custody_metadata.permissions().mode() & 0o077 != 0
        || custody_dir.starts_with(&output)
        || output.starts_with(custody_dir)
    {
        return Err("custody requires a separate, owner-only directory".into());
    }
    if output.symlink_metadata().is_ok() || (!renew && custody.symlink_metadata().is_ok()) {
        return Err("public output or custody already exists".into());
    }
    if io::stdin().is_terminal() {
        return Err("supply the 64 lowercase hex characters via a private stdin pipe".into());
    }
    let mut input = Vec::with_capacity(66);
    io::stdin()
        .lock()
        .take(66)
        .read_to_end(&mut input)
        .map_err(|_| "unlock read failed")?;
    if input.last() == Some(&b'\n') {
        input.pop();
    }
    let secret = SecretBytes::from_bytes(input);
    let pass =
        std::str::from_utf8(secret.as_bytes()).map_err(|_| "invalid custody unlock encoding")?;
    if pass.len() != 64
        || !pass
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("custody unlock requires 64 lowercase hex characters".into());
    }

    let mut payload = old.payload;
    payload.generation = payload
        .generation
        .checked_add(1)
        .ok_or("registry generation overflow")?;
    payload.valid_from_unix = now;
    // Issue at most seven additional days. The current and new signed
    // windows overlap so the operator can qualify the latter before cutover.
    let expiry_base = if renew { payload.expires_at_unix } else { now };
    payload.expires_at_unix = expiry_base
        .checked_add(7 * 86400)
        .filter(|expiry| *expiry - now <= 14 * 86400)
        .ok_or("registry expiry exceeds the issuance window")?;
    let (public, signer) = if renew {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&custody)
            .map_err(|_| "cannot open owner-only custody")?;
        let metadata = file.metadata().map_err(|_| "cannot inspect custody")?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("custody must be owned by the operator with mode 0600".into());
        }
        let mut bytes = Vec::new();
        file.take(262_145)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read custody")?;
        if bytes.len() > 262_144 {
            return Err("custody input exceeds size bound".into());
        }
        let envelope: EncryptedEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| "invalid custody envelope")?;
        let signer = SecretBytes::from_bytes(decrypt_with_passphrase(
            &engine,
            &Primitives,
            &envelope,
            pass,
        )?);
        if !engine
            .keypair_corresponds(Algorithm::MlDsa87, &old_root, signer.as_bytes())
            .map_err(|e| e.to_string())?
        {
            return Err("encrypted custody does not match the current pinned root".into());
        }
        (old_root.clone(), signer)
    } else {
        let kp = engine
            .generate_keypair(Algorithm::MlDsa87)
            .map_err(|e| e.to_string())?;
        if kp.public_key == old_root {
            return Err("generated the old registry root".into());
        }
        let envelope =
            encrypt_with_passphrase(&engine, &Primitives, kp.private_key.as_bytes(), pass)?;
        let recovered = SecretBytes::from_bytes(decrypt_with_passphrase(
            &engine,
            &Primitives,
            &envelope,
            pass,
        )?);
        if !engine
            .keypair_corresponds(Algorithm::MlDsa87, &kp.public_key, recovered.as_bytes())
            .map_err(|e| e.to_string())?
        {
            return Err("encrypted custody did not recover the new root".into());
        }
        let custody_bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
        write_new(&custody, &custody_bytes, 0o600)
            .map_err(|e| format!("write encrypted custody: {e}"))?;
        fs::File::open(custody_dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        (kp.public_key, kp.private_key)
    };
    let signature = engine
        .sign(
            Algorithm::MlDsa87,
            signer.as_bytes(),
            &signing_bytes(&payload)?,
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .map_err(|e| e.to_string())?;
    let signed = SignedRegistry { payload, signature };
    verify(&engine, &public, &signed)?;
    if !renew && verify(&engine, &old_root, &signed).is_ok() {
        return Err("new registry accepted by the old trust root".into());
    }
    let registry_bytes = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&output)
        .map_err(|e| e.to_string())?;
    let result = write_new(&output.join("transport-root.pub"), &public, 0o644)
        .and_then(|_| {
            write_new(
                &output.join("transport-registry.json"),
                &registry_bytes,
                0o644,
            )
        })
        .and_then(|_| fs::File::open(&output)?.sync_all());
    if let Err(e) = result {
        let _ = fs::remove_file(output.join("transport-root.pub"));
        let _ = fs::remove_file(output.join("transport-registry.json"));
        let _ = fs::remove_dir(&output);
        return Err(format!(
            "public output failed; encrypted custody was retained: {e}"
        ));
    }
    println!("transport root sha256: {}", sha(&public));
    println!("transport registry sha256: {}", sha(&registry_bytes));
    println!(
        "generation: {}; expires at Unix {}",
        signed.payload.generation, signed.payload.expires_at_unix
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Canary registry rotation refused: {e}");
        std::process::exit(1);
    }
}
