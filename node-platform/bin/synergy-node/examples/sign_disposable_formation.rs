//! Offline signer for freshly prepared, explicitly disposable NodeNetwork
//! formation artifacts. Never an approval path for an existing chain.
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

use synergy_address_engine::{
    apqe::{fixed_digest, FixedDigest, Primitives, SecretBytes},
    encrypt::encrypt_with_passphrase,
    types::Algorithm,
};
use synergy_aegis::{
    AegisPolicy, AegisSigner, KeyId, PqvmSigner, PqvmVerifier, SignatureAlgorithm, SigningContext,
};
use synergy_genesis::{
    authority::{AuthorityPayload, SignedAuthorityBinding, AUTHORITY_SIGNING_DOMAIN},
    builder::UnsignedGenesis,
};

fn digest(bytes: &[u8]) -> String {
    fixed_digest(&Primitives, FixedDigest::Sha256, bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn read_pinned(path: &Path, pin: &str) -> Result<Vec<u8>, String> {
    const LIMIT: u64 = 4 * 1024 * 1024;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot read reviewed input")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect reviewed input")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > LIMIT {
        return Err("bounded reviewed regular input required".into());
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input read failed")?;
    if bytes.len() as u64 != metadata.len() || digest(&bytes) != pin {
        return Err("reviewed input digest differs".into());
    }
    Ok(bytes)
}
fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(name))
        .map_err(|_| "fresh owner-only output required")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "cannot persist output".into())
}
fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 4 * 1024 * 1024,
        maximum_signature_bytes: 16 * 1024,
    }
}
fn check_scope(genesis: &UnsignedGenesis, payload: &AuthorityPayload) -> Result<(), String> {
    if genesis.format_version != 2
        || !synergy_config::is_disposable_formation_network(&genesis.network.network_id)
        || genesis.network.chain_id == 0
        || payload.chain_id != genesis.network.chain_id
        || payload.network_id != genesis.network.network_id
        || payload.epoch != 1
        || payload.epoch_start_height != 1
        || payload.validators.len() != 5
        || payload
            .validators
            .iter()
            .any(|v| !v.record.may_sign_consensus())
        || payload.protected.is_none()
    {
        return Err("fresh isolated five-member NodeNetwork formation required".into());
    }
    payload.validate()
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [report, report_pin, genesis, genesis_pin, authority, authority_pin, out] = args.as_slice()
    else {
        return Err("usage: sign_disposable_formation REPORT PIN UNSIGNED_GENESIS PIN UNSIGNED_AUTHORITY PIN NEW_OUTPUT_DIR (64 hex custody password via stdin)".into());
    };
    let genesis: UnsignedGenesis =
        serde_json::from_slice(&read_pinned(Path::new(genesis), genesis_pin)?)
            .map_err(|_| "invalid typed unsigned Genesis")?;
    let payload: AuthorityPayload =
        serde_json::from_slice(&read_pinned(Path::new(authority), authority_pin)?)
            .map_err(|_| "invalid typed unsigned authority")?;
    check_scope(&genesis, &payload)?;
    let out = Path::new(out);
    let parent = out
        .parent()
        .ok_or("explicit direct output parent required")?;
    if !out.is_absolute()
        || fs::canonicalize(parent).ok().as_deref() != Some(parent)
        || out.symlink_metadata().is_ok()
    {
        return Err("fresh output under a direct parent required".into());
    }
    if io::stdin().is_terminal() {
        return Err("use a private stdin pipe".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(65)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read custody unlock")?;
    let raw = SecretBytes::from_bytes(raw);
    if raw.as_bytes().len() != 64
        || !raw
            .as_bytes()
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("custody unlock must be exactly 64 lowercase hex digits".into());
    }
    let password = std::str::from_utf8(raw.as_bytes()).map_err(|_| "invalid custody unlock")?;
    let engine = synergy_aegis::load_authenticated_native_engine(Path::new(report), report_pin)?;
    let (authority, transport, authority_custody, transport_custody) = {
        let lock = engine
            .lock()
            .map_err(|_| "authenticated APQE unavailable")?;
        let authority = lock
            .generate_keypair(Algorithm::MlDsa65)
            .map_err(|_| "APQE authority key generation failed")?;
        let transport = lock
            .generate_keypair(Algorithm::MlDsa87)
            .map_err(|_| "APQE transport issuer generation failed")?;
        let authority_custody = encrypt_with_passphrase(
            &lock,
            &Primitives,
            authority.private_key.as_bytes(),
            password,
        )?;
        let transport_custody = encrypt_with_passphrase(
            &lock,
            &Primitives,
            transport.private_key.as_bytes(),
            password,
        )?;
        (authority, transport, authority_custody, transport_custody)
    };
    let id = KeyId::new(genesis.authority_trust_key_id.clone()).map_err(|e| e.to_string())?;
    let signer = PqvmSigner::with_apqe(
        policy(),
        id.clone(),
        &authority.public_key,
        authority.private_key.as_bytes().to_vec(),
        engine.clone(),
    )
    .map_err(|e| e.to_string())?;
    let signed = synergy_genesis::signing::sign(genesis, &signer, id.clone())?;
    let signature = signer
        .sign(
            &id,
            &SigningContext {
                domain: AUTHORITY_SIGNING_DOMAIN.into(),
                chain_id: payload.chain_id,
                epoch: Some(payload.epoch),
                height: None,
            },
            &payload.signing_bytes()?,
        )
        .map_err(|e| e.to_string())?;
    let binding = SignedAuthorityBinding {
        payload,
        signer_key_id: id.as_str().into(),
        signature: signature.bytes,
    };
    let verifier = PqvmVerifier::with_apqe(policy(), engine).map_err(|e| e.to_string())?;
    synergy_genesis::verify_binding_with_verifier(
        &signed,
        &authority.public_key,
        &binding,
        &verifier,
    )?;
    DirBuilder::new()
        .mode(0o700)
        .create(out)
        .map_err(|_| "fresh private output directory required")?;
    let public = out.join("public");
    DirBuilder::new()
        .mode(0o700)
        .create(&public)
        .map_err(|_| "cannot create public artifacts directory")?;
    let json = |e: serde_json::Error| e.to_string();
    write(
        &public,
        "genesis.json",
        &serde_json::to_vec_pretty(&signed).map_err(json)?,
    )?;
    write(
        &public,
        "authority.json",
        &serde_json::to_vec_pretty(&binding).map_err(json)?,
    )?;
    write(&public, "authority-root.pub", &authority.public_key)?;
    write(out, "transport-root.pub", &transport.public_key)?;
    write(
        out,
        "transport-custody.json",
        &serde_json::to_vec(&transport_custody).map_err(json)?,
    )?;
    write(
        out,
        "authority-custody.json",
        &serde_json::to_vec(&authority_custody).map_err(json)?,
    )?;
    File::open(public)
        .and_then(|f| f.sync_all())
        .and_then(|_| File::open(out)?.sync_all())
        .and_then(|_| File::open(parent)?.sync_all())
        .map_err(|_| "cannot sync formation outputs")?;
    println!(
        "disposable formation verified chain={} genesis_hash={}",
        signed.unsigned.network.chain_id, signed.genesis_hash
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("sign_disposable_formation: {error}");
        std::process::exit(1);
    }
}
