//! LOCAL_R11_QUALIFICATION fixture generator.  It never writes production
//! locations, and validates its Genesis/registry outputs through production
//! loaders and Aegis ML-DSA verification.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};
use synergy_testnet::{
    consensus::simplified_posy::{
        GenesisBoundSimplifiedActivation, SimplifiedIngressKemRegistryArtifact,
        SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT,
    },
    crypto::{
        aegis_pqvm::{AegisPqvmSigner, AegisPqvmVerifier},
        pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey},
    },
    etdag::{IngressKemKeyRecord, IngressKemKeyRegistry, INGRESS_KEM_REGISTRY_VERSION},
    genesis::{load_genesis_from_path, recompute_testnet_v3_candidate_integrity},
    synergy_types::{AegisPqKeyId, AegisPqKeyRole, ClusterMap, Epoch, Hash, Height, ValidatorId},
};
const ENV: &str = "LOCAL_R11_QUALIFICATION";
const DOMAIN: &str = "LOCAL_R11_QUALIFICATION/ArtifactAttestation/v1";
const IDS: [&str; 5] = [
    "validator-02",
    "validator-03",
    "validator-04",
    "validator-05",
    "validator-06",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secret {
    environment: String,
    purpose: String,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    environment: String,
    purpose: String,
    payload_sha256: String,
    signer_uma_id: String,
    signer_key_id: AegisPqKeyId,
    signature: synergy_testnet::synergy_types::AegisPqSignature,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    environment: String,
    chain_id: u64,
    network_id: String,
    protocol_version: String,
    validator_ids: Vec<String>,
    genesis_path: String,
    genesis_hash: String,
    genesis_sha256: String,
    epoch_context_root: String,
    authority_public_key: PQCPublicKey,
    registries: BTreeMap<String, String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("LOCAL_R11_QUALIFICATION_ARTIFACTS_FAILED: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), String> {
    let a = env::args().collect::<Vec<_>>();
    let root = PathBuf::from(arg(&a, "--output-root")?);
    match a.get(1).map(String::as_str){Some("generate")=>generate(&root),Some("verify")=>verify(&root),_=>Err("usage: generate-local-r11-qualification-artifacts <generate|verify> --output-root PATH".into())}
}
fn arg(a: &[String], n: &str) -> Result<String, String> {
    a.windows(2)
        .find(|p| p[0] == n)
        .map(|p| p[1].clone())
        .ok_or_else(|| format!("missing {n}"))
}
fn guard(root: &Path, fresh: bool) -> Result<(), String> {
    let s = root.to_string_lossy().to_ascii_lowercase();
    if !s.contains("local-r11-qualification")
        || ["production", "release", "launch", "canonical", "/config"]
            .iter()
            .any(|x| s.contains(x))
    {
        return Err(
            "output root must be an explicit local-r11-qualification non-production path".into(),
        );
    }
    if fresh && root.exists() {
        return Err("refusing to reuse an existing qualification output root".into());
    }
    Ok(())
}
fn bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn write<T: Serialize>(p: &Path, v: &T, secret: bool) -> Result<Vec<u8>, String> {
    fs::create_dir_all(p.parent().ok_or("path without parent")?).map_err(|e| e.to_string())?;
    let b = bytes(v)?;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .map_err(|e| format!("create {}: {e}", p.display()))?;
    f.write_all(&b).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(b)
}
fn pair(
    m: &mut PQCManager,
    a: PQCAlgorithm,
    id: String,
) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
    let (mut p, mut s) = m.generate_keypair(a)?;
    p.key_id = id.clone();
    s.public_key_id = id;
    Ok((p, s))
}
fn replace(v: &mut Value, k: &BTreeMap<String, PQCPublicKey>) {
    match v {
        Value::Array(a) => {
            for x in a {
                replace(x, k)
            }
        }
        Value::Object(o) => {
            if let Some(id) = o.get("validator_id").and_then(Value::as_str) {
                if let Some(p) = k.get(id) {
                    if let Some(q) = o.get_mut("consensus_public_key") {
                        match q {
                            Value::String(_) => *q = Value::String(B64.encode(&p.key_data)),
                            Value::Object(z) => {
                                z.insert("algorithm".into(), json!("mldsa65"));
                                z.insert("key_id".into(), json!(p.key_id));
                                z.insert("key_bytes".into(), json!(p.key_data));
                            }
                            _ => {}
                        }
                    }
                    if o.contains_key("consensus_key_id") {
                        o.insert("consensus_key_id".into(), json!(p.key_id));
                    }
                }
            }
            for x in o.values_mut() {
                replace(x, k)
            }
        }
        _ => {}
    }
}
fn attest(
    s: &mut AegisPqvmSigner,
    uma: &str,
    k: &AegisPqKeyId,
    purpose: &str,
    b: &[u8],
) -> Result<Attestation, String> {
    Ok(Attestation {
        environment: ENV.into(),
        purpose: purpose.into(),
        payload_sha256: hash(b),
        signer_uma_id: uma.into(),
        signer_key_id: k.clone(),
        signature: s.sign_domain(DOMAIN, b, k).map_err(|e| e.to_string())?,
    })
}
fn check(
    v: &AegisPqvmVerifier,
    p: &PQCPublicKey,
    purpose: &str,
    b: &[u8],
    a: &Attestation,
) -> Result<(), String> {
    if a.environment != ENV
        || a.purpose != purpose
        || a.payload_sha256 != hash(b)
        || a.signer_key_id.0 != p.key_id
    {
        return Err(format!("invalid {purpose} attestation"));
    }
    v.verify_domain_signature(
        DOMAIN,
        b,
        &a.signer_uma_id,
        &a.signer_key_id,
        Epoch(0),
        AegisPqKeyRole::Governance,
        &a.signature,
    )
    .map_err(|e| e.to_string())
}
fn generate(root: &Path) -> Result<(), String> {
    guard(root, true)?;
    let mut m = PQCManager::new();
    let (apu, apr) = pair(
        &mut m,
        PQCAlgorithm::MLDSA87,
        "local-r11-qualification:authority".into(),
    )?;
    let uma = "local-r11-qualification-authority";
    let mut signer = AegisPqvmSigner::initialize_required().map_err(|e| e.to_string())?;
    let aid = signer
        .register_existing_keypair(
            uma,
            apu.clone(),
            apr.clone(),
            vec![AegisPqKeyRole::Governance],
            Epoch(0),
        )
        .map_err(|e| e.to_string())?;
    let verifier = signer.verifier();
    write(
        &root.join("private/authority.mldsa87.json"),
        &Secret {
            environment: ENV.into(),
            purpose: "qualification-authority".into(),
            public_key: apu.clone(),
            private_key: apr,
        },
        true,
    )?;
    let mut keys = BTreeMap::new();
    for id in IDS {
        let (p, s) = pair(
            &mut m,
            PQCAlgorithm::MLDSA65,
            format!("validator-consensus:local-r11-qualification-{id}"),
        )?;
        write(
            &root.join(format!("private/validators/{id}/consensus.mldsa65.json")),
            &Secret {
                environment: ENV.into(),
                purpose: format!("{id}-consensus"),
                public_key: p.clone(),
                private_key: s,
            },
            true,
        )?;
        write(
            &root.join(format!("public/validators/{id}.json")),
            &json!({"environment":ENV,"validator_id":id,"consensus_public_key":p}),
            false,
        )?;
        keys.insert(id.into(), p);
    }
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../launch/posy-v3-genesis-inputs/fresh-p3-genesis-predeployment-public-input.json",
    );
    let mut g: Value = serde_json::from_slice(&fs::read(&src).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if g.pointer("/network/network_id").and_then(Value::as_str) != Some("testnet")
        || g.pointer("/network/chain_id").and_then(Value::as_u64) != Some(1266)
        || g.pointer("/network/consensus_version")
            .and_then(Value::as_str)
            != Some("posy/3.0")
    {
        return Err("source is not fresh P3 testnet Genesis".into());
    }
    g["env"] = json!(ENV);
    replace(&mut g, &keys);
    recompute_testnet_v3_candidate_integrity(&mut g)?;
    let gp = root.join("public/genesis.json");
    let gb = write(&gp, &g, false)?;
    let gd = load_genesis_from_path(&gp)
        .map_err(|e| format!("production Genesis loader rejected fixture: {e}"))?;
    let act: GenesisBoundSimplifiedActivation = serde_json::from_value(
        gd.value()
            .pointer("/consensus/posy_v3_activation")
            .cloned()
            .ok_or("activation missing")?,
    )
    .map_err(|e| e.to_string())?;
    let ec = act.derive_fresh_genesis_epoch_context()?;
    let active = act.frozen_validator_set.active_for_epoch(Epoch(0));
    let cm = ClusterMap::derive_from_finalized_epoch_seed(&active, ec.finalized_epoch_seed_root)?;
    let cid = cm.assignments.first().ok_or("no cluster")?.cluster_id;
    let ga = attest(&mut signer, uma, &aid, "genesis", &gb)?;
    write(&root.join("attestations/genesis.json"), &ga, false)?;
    check(&verifier, &apu, "genesis", &gb, &ga)?;
    let mut regs = BTreeMap::new();
    for h in 3..=20 {
        let mut rs = Vec::new();
        for (i, id) in IDS.iter().enumerate() {
            let (p, s) = pair(
                &mut m,
                PQCAlgorithm::MLKEM1024,
                format!("local-r11-qualification:ingress-kem:{h}:{id}"),
            )?;
            write(
                &root.join(format!("private/ingress-kem/h{h:02}/{id}.mlkem1024.json")),
                &Secret {
                    environment: ENV.into(),
                    purpose: format!("h{h}-ingress-kem-{id}"),
                    public_key: p.clone(),
                    private_key: s,
                },
                true,
            )?;
            rs.push(IngressKemKeyRecord {
                validator_id: ValidatorId((*id).into()),
                ingress_key_id: p.key_id,
                share_index: (i + 1) as u8,
                key_bytes: p.key_data,
            });
        }
        let r = IngressKemKeyRegistry {
            registry_version: INGRESS_KEM_REGISTRY_VERSION,
            chain_id: synergy_testnet::synergy_types::ChainId::synergy_testnet_v3(),
            network_id: synergy_testnet::synergy_types::NetworkId::fresh_posy_testnet_v3(),
            protocol_version: "posy/3.0".into(),
            epoch: Epoch(0),
            target_height: Height(h),
            assigned_cluster_id: cid,
            records: rs,
        };
        r.validate_shape()?;
        let x = SimplifiedIngressKemRegistryArtifact {
            format: SIMPLIFIED_INGRESS_KEM_REGISTRY_ARTIFACT_FORMAT.into(),
            epoch_context_root: ec.root()?,
            epoch: Epoch(0),
            target_height: Height(h),
            assigned_cluster_id: cid,
            registry_root: r.root()?,
            registry: r,
        };
        x.validate(ec.root()?)?;
        let rel = format!(
            "registries/{}/epoch-0-height-{h}-cluster-{}.json",
            ec.root()?.to_hex(),
            cid.0
        );
        let b = write(&root.join(&rel), &x, false)?;
        let a = attest(
            &mut signer,
            uma,
            &aid,
            &format!("ingress-registry-h{h}"),
            &b,
        )?;
        write(
            &root.join(format!("attestations/ingress-registry-h{h}.json")),
            &a,
            false,
        )?;
        check(&verifier, &apu, &format!("ingress-registry-h{h}"), &b, &a)?;
        regs.insert(h.to_string(), rel);
    }
    let mf = Manifest {
        format: "synergy-local-r11-qualification-artifacts-v1".into(),
        environment: ENV.into(),
        chain_id: 1266,
        network_id: "testnet".into(),
        protocol_version: "posy/3.0".into(),
        validator_ids: IDS.iter().map(|x| (*x).into()).collect(),
        genesis_path: "public/genesis.json".into(),
        genesis_hash: gd.hash().into(),
        genesis_sha256: hash(&gb),
        epoch_context_root: ec.root()?.to_hex(),
        authority_public_key: apu.clone(),
        registries: regs,
    };
    let mb = write(&root.join("manifest.json"), &mf, false)?;
    let ma = attest(&mut signer, uma, &aid, "manifest", &mb)?;
    write(&root.join("attestations/manifest.json"), &ma, false)?;
    check(&verifier, &apu, "manifest", &mb, &ma)?;
    verify(root)?;
    println!(
        "LOCAL_R11_QUALIFICATION_ARTIFACTS=YES\nGENESIS={}\nGENESIS_HASH={}",
        gp.display(),
        gd.hash()
    );
    Ok(())
}
fn verify(root: &Path) -> Result<(), String> {
    guard(root, false)?;
    let mb = fs::read(root.join("manifest.json")).map_err(|e| e.to_string())?;
    let mf: Manifest = serde_json::from_slice(&mb).map_err(|e| e.to_string())?;
    if mf.format != "synergy-local-r11-qualification-artifacts-v1"
        || mf.environment != ENV
        || mf.chain_id != 1266
        || mf.network_id != "testnet"
        || mf.protocol_version != "posy/3.0"
        || mf.validator_ids != IDS.iter().map(|x| (*x).into()).collect::<Vec<String>>()
    {
        return Err("invalid local R11 manifest identity".into());
    }
    let sec: Secret = serde_json::from_slice(
        &fs::read(root.join("private/authority.mldsa87.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if sec.environment != ENV || sec.public_key.key_data != mf.authority_public_key.key_data {
        return Err("authority mismatch".into());
    }
    let mut s = AegisPqvmSigner::initialize_required().map_err(|e| e.to_string())?;
    s.register_existing_keypair(
        "local-r11-qualification-authority",
        sec.public_key.clone(),
        sec.private_key,
        vec![AegisPqKeyRole::Governance],
        Epoch(0),
    )
    .map_err(|e| e.to_string())?;
    let v = s.verifier();
    let ma: Attestation = serde_json::from_slice(
        &fs::read(root.join("attestations/manifest.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    check(&v, &mf.authority_public_key, "manifest", &mb, &ma)?;
    let gp = root.join(&mf.genesis_path);
    let gb = fs::read(&gp).map_err(|e| e.to_string())?;
    if hash(&gb) != mf.genesis_sha256 {
        return Err("Genesis sha mismatch".into());
    }
    let gd = load_genesis_from_path(&gp)
        .map_err(|e| format!("production Genesis loader rejected fixture: {e}"))?;
    if gd.hash() != mf.genesis_hash {
        return Err("Genesis hash mismatch".into());
    }
    let ga: Attestation = serde_json::from_slice(
        &fs::read(root.join("attestations/genesis.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    check(&v, &mf.authority_public_key, "genesis", &gb, &ga)?;
    let er = Hash::from_hex(&mf.epoch_context_root).map_err(|e| e.to_string())?;
    for h in 3..=20 {
        let rel = mf
            .registries
            .get(&h.to_string())
            .ok_or("missing registry")?;
        let b = fs::read(root.join(rel)).map_err(|e| e.to_string())?;
        let x: SimplifiedIngressKemRegistryArtifact =
            serde_json::from_slice(&b).map_err(|e| e.to_string())?;
        if bytes(&x)? != b {
            return Err(format!("H{h} noncanonical registry"));
        }
        x.validate(er)?;
        let a: Attestation = serde_json::from_slice(
            &fs::read(root.join(format!("attestations/ingress-registry-h{h}.json")))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        check(
            &v,
            &mf.authority_public_key,
            &format!("ingress-registry-h{h}"),
            &b,
            &a,
        )?;
    }
    println!("LOCAL_R11_QUALIFICATION_ARTIFACT_VERIFY=YES");
    Ok(())
}
