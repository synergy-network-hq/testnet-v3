//! Host-local pre-Genesis APQE custody and binding to independently signed Genesis.
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};
use synergy_address_engine::{
    apqe::{fixed_digest, FixedDigest, Primitives, SecretBytes},
    encrypt::EncryptedEnvelope,
    snts07::decode_lower_hex,
    types::AddressType,
    validator_provisioning::{
        self as apqe, FormationContext, FormationRegistration, NetworkBinding,
    },
};
use synergy_aegis::{AegisPolicy, SignatureAlgorithm};
use synergy_genesis::{authority::SignedAuthorityBinding, signing::SignedGenesis};

const PUBLIC_LIMIT: u64 = 128 * 1024;

fn digest(bytes: &[u8]) -> String {
    fixed_digest(&Primitives, FixedDigest::Sha256, bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn private_dir(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "Private custody directory absent")?;
    if !path.is_absolute()
        || path.canonicalize().ok().as_deref() != Some(path)
        || !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o700
    {
        return Err("Direct owner-only custody directory required".into());
    }
    Ok(())
}

fn read(path: &Path, max: u64, private: bool) -> Result<SecretBytes, String> {
    let parent = path.parent().ok_or("Formation input parent absent")?;
    if !path.is_absolute() || parent.canonicalize().ok().as_deref() != Some(parent) {
        return Err("Formation input path is not direct".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Formation input absent or unsafe")?;
    let m = file
        .metadata()
        .map_err(|_| "Formation input metadata unavailable")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > max
        || m.mode() & 0o022 != 0
        || (private && m.mode() & 0o777 != 0o600)
    {
        return Err("Unsafe or oversized formation input".into());
    }
    let mut file = file.take(max + 1);
    let mut raw = vec![0; m.len() as usize];
    let result = file.read_exact(&mut raw);
    let raw = SecretBytes::from_bytes(raw);
    result.map_err(|_| "Cannot read formation input")?;
    let mut extra = vec![0; 1];
    let result = file.read(&mut extra);
    drop(SecretBytes::from_bytes(extra));
    if result.map_err(|_| "Cannot inspect formation input length")? != 0 {
        return Err("Formation input changed during read".into());
    }
    Ok(raw)
}

fn decode<T: serde::de::DeserializeOwned>(raw: &SecretBytes) -> Result<T, String> {
    serde_json::from_slice(raw.as_bytes()).map_err(|_| "Invalid formation or authority JSON".into())
}
fn pinned(path: &Path, max: u64, private: bool, expected: &str) -> Result<SecretBytes, String> {
    let raw = read(path, max, private)?;
    if digest(raw.as_bytes()) != expected {
        return Err("Independently pinned formation/Genesis input changed".into());
    }
    Ok(raw)
}

pub(crate) fn pinned_context(path: &Path, expected: &str) -> Result<FormationContext, String> {
    let context: FormationContext = decode(&pinned(path, 4096, true, expected)?)?;
    context.validate()?;
    Ok(context)
}

pub(crate) fn public_registration(path: &Path) -> Result<FormationRegistration, String> {
    decode(&read(path, PUBLIC_LIMIT, false)?)
}

fn write(path: &Path, raw: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| "Fresh private formation file required")?;
    file.write_all(raw)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot persist formation file".into())
}

fn sync(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|d| d.sync_all())
        .map_err(|_| "Cannot make formation state durable".into())
}

fn begin(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("Private formation parent required")?;
    private_dir(parent)?;
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "Fresh formation directory unavailable; reconcile existing state")?;
    sync(parent)
}

fn passphrase(raw: &SecretBytes) -> Result<&str, String> {
    let bytes = raw.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("Invalid private formation unlock".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "Invalid private formation unlock".into())
}

fn public_json(raw: &[u8]) -> Result<&str, String> {
    if raw.len() as u64 > PUBLIC_LIMIT {
        return Err("Public formation artifact exceeds its bound".into());
    }
    std::str::from_utf8(raw).map_err(|_| "Invalid UTF-8 public formation artifact".into())
}

pub fn prepare(
    context_path: &Path,
    pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<serde_json::Value, String> {
    let context = pinned_context(context_path, pin)?;
    // Reserve before generation. A crash cannot turn a partial attempt into a
    // fresh identity. Status verifies the entire retained record before use.
    begin(directory)?;
    let mut entropy = vec![0; 32];
    let random = Primitives.random_bytes(&mut entropy);
    let entropy = SecretBytes::from_bytes(entropy);
    random.map_err(|_| "APQE secure randomness unavailable")?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let unlock = SecretBytes::from_bytes(
        entropy
            .as_bytes()
            .iter()
            .flat_map(|b| [HEX[(b >> 4) as usize], HEX[(b & 15) as usize]])
            .collect(),
    );
    let pass = passphrase(&unlock)?;
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    let (registration, envelope) =
        apqe::prepare_formation(&guard, AddressType::NodeClass1, context, pass)?;
    apqe::verify_formation_custody(
        &guard,
        &registration,
        &registration.payload.formation,
        &envelope,
        pass,
    )?;
    drop(guard);
    let registration_raw =
        serde_json::to_vec_pretty(&registration).map_err(|_| "Invalid formation registration")?;
    public_json(&registration_raw)?;
    write(&directory.join("unlock"), unlock.as_bytes())?;
    write(
        &directory.join("formation.enc.json"),
        &serde_json::to_vec_pretty(&envelope).map_err(|_| "Invalid encrypted formation custody")?,
    )?;
    write(
        &directory.join("formation-registration.json"),
        &registration_raw,
    )?;
    sync(directory)?;
    verify(context_path, pin, directory, engine)
}

struct Custody {
    expected: FormationContext,
    registration: FormationRegistration,
    registration_raw: SecretBytes,
    envelope: EncryptedEnvelope,
    unlock: SecretBytes,
}

fn verified(
    context_path: &Path,
    pin: &str,
    directory: &Path,
    engine: &crate::provider::Engine,
) -> Result<Custody, String> {
    private_dir(directory)?;
    let expected = decode(&pinned(context_path, 4096, true, pin)?)?;
    let registration_raw = read(
        &directory.join("formation-registration.json"),
        PUBLIC_LIMIT,
        true,
    )?;
    let registration = decode(&registration_raw)?;
    let envelope = decode(&read(
        &directory.join("formation.enc.json"),
        256 * 1024,
        true,
    )?)?;
    let unlock = read(&directory.join("unlock"), 64, true)?;
    let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
    apqe::verify_formation_custody(
        &guard,
        &registration,
        &expected,
        &envelope,
        passphrase(&unlock)?,
    )?;
    Ok(Custody {
        expected,
        registration,
        registration_raw,
        envelope,
        unlock,
    })
}

pub fn verify(
    context_path: &Path,
    pin: &str,
    directory: &Path,
    engine: crate::provider::Engine,
) -> Result<serde_json::Value, String> {
    let c = verified(context_path, pin, directory, &engine)?;
    Ok(
        serde_json::json!({"address":c.registration.payload.identity.address,
        "registration_sha256":digest(c.registration_raw.as_bytes()),
        "registration_json":public_json(c.registration_raw.as_bytes())?,
        "possession_verified":true,"membership_granted":false}),
    )
}

pub(crate) fn verify_authorized_keys(
    authority: &synergy_genesis::authority::AuthorityPayload,
    registration: &FormationRegistration,
) -> Result<(), String> {
    let id = &registration.payload.identity;
    let consensus = decode_lower_hex(
        "formation consensus public key",
        &id.consensus_key.public_key,
        1952,
    )?;
    let ingress = decode_lower_hex(
        "formation ingress public key",
        &registration.payload.ingress_key.public_key,
        1568,
    )?;
    let mut members = authority
        .validators
        .iter()
        .filter(|v| v.record.validator_id == id.address);
    let local = members
        .next()
        .ok_or("Formation identity is not admitted by signed Genesis")?;
    if members.next().is_some()
        || !local.record.may_sign_consensus()
        || local.algorithm != SignatureAlgorithm::MlDsa65
        || local.public_key != consensus
    {
        return Err("Signed Genesis membership differs from local consensus custody".into());
    }
    let policy = authority
        .protected
        .as_ref()
        .ok_or("Signed authority lacks protected policy")?;
    let registry = &policy.ingress_kem_registry;
    registry
        .validate_protected_profile()
        .map_err(|_| "Invalid signed ingress registry")?;
    let mut active = registry.records.iter().filter(|r| {
        r.validator_id == id.address
            && r.activation_height <= authority.epoch_start_height
            && r.retirement_height
                .is_none_or(|h| h > authority.epoch_start_height)
    });
    if !active
        .next()
        .is_some_and(|record| record.public_key.public_key == ingress)
        || active.next().is_some()
    {
        return Err("Signed authority ingress binding differs from local custody".into());
    }
    Ok(())
}

pub fn genesis(
    context_path: &Path,
    pin: &str,
    directory: &Path,
    paths: [&Path; 2],
    pins: [&str; 3],
    engine: crate::provider::Engine,
    write_bound: bool,
) -> Result<serde_json::Value, String> {
    let [public, bound] = paths;
    let c = verified(context_path, pin, directory, &engine)?;
    let genesis_raw = pinned(
        &public.join("genesis.json"),
        16 * 1024 * 1024,
        false,
        pins[0],
    )?;
    let genesis_sha256 = pins[0].to_owned();
    let signed: SignedGenesis = decode(&genesis_raw)?;
    let authority: SignedAuthorityBinding = decode(&pinned(
        &public.join("authority.json"),
        1024 * 1024,
        false,
        pins[1],
    )?)?;
    let trust = pinned(&public.join("authority-root.pub"), 8192, false, pins[2])?;
    let verifier = crate::provider::verifier(
        AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: 16 * 1024 * 1024,
            maximum_signature_bytes: 16 * 1024,
        },
        Some(engine.clone()),
    )?;
    synergy_genesis::verify_binding_with_verifier(
        &signed,
        trust.as_bytes(),
        &authority,
        &verifier,
    )?;
    let network = &signed.unsigned.network;
    if network.network_id != c.expected.network_id
        || format!("{:064x}", network.chain_id) != c.expected.chain_id_hex
    {
        return Err("Signed Genesis selects a different formation network".into());
    }
    // The native binding verifier has already required Genesis and the
    // signed authority to carry identical frozen membership and policy.
    verify_authorized_keys(&authority.payload, &c.registration)?;
    let identity = &c.registration.payload.identity;
    let mut result = serde_json::json!({"address":identity.address,"genesis_sha256":genesis_sha256,
        "genesis_authority_verified":true,"membership_verified":true,"bound":false});
    if write_bound {
        begin(bound)?;
        let guard = engine.lock().map_err(|_| "APQE provider unavailable")?;
        let (request, envelope) = apqe::bind_formation(
            &guard,
            &c.registration,
            &c.expected,
            &c.envelope,
            passphrase(&c.unlock)?,
            NetworkBinding {
                chain_id_hex: c.expected.chain_id_hex.clone(),
                genesis_sha256: genesis_sha256.clone(),
            },
        )?;
        apqe::verify_custody(
            &guard,
            &request,
            &request.payload.network,
            &envelope,
            passphrase(&c.unlock)?,
        )?;
        drop(guard);
        apqe::write_new_bundle(&bound.join("bundle"), &request, &envelope)?;
        write(
            &bound.join("node-identity.json"),
            &serde_json::to_vec(&crate::validator_custody::runtime_identity(&request)?)
                .map_err(|_| "Cannot encode bound node identity")?,
        )?;
        write(&bound.join("unlock"), c.unlock.as_bytes())?;
        sync(bound)?;
    }
    if bound.exists() || bound.is_symlink() {
        let (_, request, raw) = crate::validator_custody::verify_artifact(
            &c.expected.chain_id_hex,
            &genesis_sha256,
            bound,
            engine,
        )?;
        if serde_json::to_value(&request.payload.identity).map_err(|_| "Invalid bound identity")?
            != serde_json::to_value(identity).map_err(|_| "Invalid formation identity")?
            || request.payload.ingress_key.algorithm != c.registration.payload.ingress_key.algorithm
            || request.payload.ingress_key.public_key
                != c.registration.payload.ingress_key.public_key
        {
            return Err("Bound enrollment differs from prepared formation identity".into());
        }
        result["bound"] = true.into();
        result["enrollment_sha256"] = digest(raw.as_bytes()).into();
        result["enrollment_json"] = public_json(raw.as_bytes())?.into();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::types::Algorithm;
    use synergy_aegis::KeyId;
    use synergy_genesis::builder::UnsignedGenesis;

    #[test]
    #[ignore = "requires the independently authenticated native APQE provider"]
    fn formation_registration_matches_independently_signed_genesis_and_ingress() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("nodenetwork-formation-{}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let engine = crate::provider::native_test_engine();
        let context = FormationContext {
            network_id: "stability-fixture".into(),
            chain_id_hex: format!("{:064x}", 1266),
            formation_id: "ab".repeat(32),
        };
        let context_raw = serde_json::to_vec(&context).unwrap();
        let context_path = root.join("context.json");
        let context_pin = digest(&context_raw);
        write(&context_path, &context_raw).unwrap();
        let directory = root.join("formation");
        let first = prepare(&context_path, &context_pin, &directory, engine.clone()).unwrap();
        assert_eq!(first["membership_granted"], false);
        let registration: FormationRegistration =
            serde_json::from_str(first["registration_json"].as_str().unwrap()).unwrap();
        let authority_pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let root_public = root.join("authority-root.pub");
        let root_secret = root.join("fixture-authority-secret");
        write(&root_public, &authority_pair.public_key).unwrap();
        write(&root_secret, authority_pair.private_key.as_bytes()).unwrap();
        let authority_key_id = KeyId::new("authority-root").unwrap();
        let signer = crate::provider::signer(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: 16 * 1024 * 1024,
                maximum_signature_bytes: 16 * 1024,
            },
            authority_key_id.clone(),
            &authority_pair.public_key,
            authority_pair.private_key.as_bytes().to_vec(),
            Some(engine.clone()),
        )
        .unwrap();

        let mut participants = vec![registration];
        let mut registration_paths = vec![directory.join("formation-registration.json")];
        for i in 1..5 {
            let (participant, _) = apqe::prepare_formation(
                &engine.lock().unwrap(),
                AddressType::NodeClass1,
                context.clone(),
                "fixture-only formation unlock phrase",
            )
            .unwrap();
            let path = root.join(format!("public-formation-{i}.json"));
            write(&path, &serde_json::to_vec(&participant).unwrap()).unwrap();
            participants.push(participant);
            registration_paths.push(path);
        }
        let registration = &participants[0];
        let member = &registration.payload.identity;
        for matching_ingress in [false, true] {
            let artifact_dir = root.join(if matching_ingress { "correct" } else { "wrong" });
            begin(&artifact_dir).unwrap();
            let mut recipe = crate::prepare_authority::tests::genesis_recipe();
            recipe["formation_registrations"] = serde_json::json!(registration_paths);
            for (i, participant) in participants.iter().enumerate() {
                let identity = &participant.payload.identity;
                let ingress = &participant.payload.ingress_key;
                let consensus = decode_lower_hex(
                    "fixture consensus",
                    &identity.consensus_key.public_key,
                    1952,
                )
                .unwrap();
                let ingress = if i == 0 && !matching_ingress {
                    engine
                        .lock()
                        .unwrap()
                        .generate_keypair(Algorithm::MlKem1024)
                        .unwrap()
                        .public_key
                } else {
                    decode_lower_hex("fixture ingress", &ingress.public_key, 1568).unwrap()
                };
                let validator = &mut recipe["authority"]["validators"][i];
                validator["record"]["validator_id"] = serde_json::json!(identity.address);
                validator["public_key"] = serde_json::json!(consensus);
                let ingress_record =
                    &mut recipe["authority"]["protected"]["ingress_kem_registry"]["records"][i];
                ingress_record["validator_id"] = serde_json::json!(identity.address);
                ingress_record["public_key"]["public_key"] = serde_json::json!(ingress);
            }
            let recipe_path = artifact_dir.join("recipe.json");
            let unsigned_path = artifact_dir.join("unsigned.json");
            let payload_path = artifact_dir.join("authority-payload.json");
            write(&recipe_path, &serde_json::to_vec(&recipe).unwrap()).unwrap();
            let composed = crate::prepare_authority::prepare_formation_genesis(
                &recipe_path,
                &context_path,
                &context_pin,
                &unsigned_path,
                &payload_path,
                engine.clone(),
            );
            if !matching_ingress {
                assert!(composed.unwrap_err().contains("ingress binding differs"));
                assert!(!unsigned_path.exists() && !payload_path.exists());
                continue;
            }
            composed.unwrap();
            let unsigned: UnsignedGenesis =
                serde_json::from_slice(&fs::read(unsigned_path).unwrap()).unwrap();
            let signed =
                synergy_genesis::signing::sign(unsigned, &signer, authority_key_id.clone())
                    .unwrap();
            let genesis_raw = serde_json::to_vec(&signed).unwrap();
            write(&artifact_dir.join("genesis.json"), &genesis_raw).unwrap();
            write(
                &artifact_dir.join("authority-root.pub"),
                &authority_pair.public_key,
            )
            .unwrap();
            let authority = artifact_dir.join("authority.json");
            crate::authority::sign_with_provider(
                &payload_path,
                authority_key_id.clone(),
                &root_secret,
                &root_public,
                &authority,
                Some(engine.clone()),
            )
            .unwrap();
            let genesis_pin = digest(&genesis_raw);
            let authority_pin = digest(&fs::read(&authority).unwrap());
            let root_pin = digest(&authority_pair.public_key);
            let bound = root.join("bound");
            let run = |write| {
                genesis(
                    &context_path,
                    &context_pin,
                    &directory,
                    [&artifact_dir, &bound],
                    [&genesis_pin, &authority_pin, &root_pin],
                    engine.clone(),
                    write,
                )
            };
            assert_eq!(run(false).unwrap()["bound"], false);
            assert!(!bound.exists());
            let result = run(true).unwrap();
            assert_eq!(result["address"], first["address"]);
            assert_eq!(result["bound"], true);
            assert_eq!(run(false).unwrap(), result);
            assert!(run(true).is_err());
            let enrollment: apqe::EnrollmentRequest =
                serde_json::from_str(result["enrollment_json"].as_str().unwrap()).unwrap();
            assert_eq!(
                serde_json::to_value(&enrollment.payload.identity).unwrap(),
                serde_json::to_value(member).unwrap()
            );
            assert_eq!(
                enrollment.payload.ingress_key.public_key,
                registration.payload.ingress_key.public_key
            );
        }
    }
}
