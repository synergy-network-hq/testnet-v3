//! Produces the public, unsigned ETDAG artifacts required by fresh PoSy v3.
//!
//! This tool deliberately has no key, passphrase, signing, deployment, or
//! mutable-registry mode.  It turns an approved parameter manifest and fee
//! manifest into their canonical SHA3-512-rooted artifacts, or derives the
//! post-Genesis public membership anchor from the staged Genesis candidate.
//! The separately frozen governance authority must authorize the final
//! release-request that commits to the resulting three roots.

use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus::simplified_posy::load_genesis_bound_simplified_activation;
use synergy_testnet::etdag_governance::{
    build_etdag_governed_membership_anchor, EtdagFeeScheduleArtifact, EtdagFeeScheduleManifest,
    EtdagGovernedGenesisBinding, EtdagGovernedMembershipAnchor, EtdagParameterArtifact,
    EtdagParameterManifest, ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION,
    ETDAG_GOVERNED_GENESIS_BINDING_STATUS,
};
use synergy_testnet::genesis::{
    bind_testnet_v3_genesis_etdag_membership_anchor, load_genesis_from_path,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  testnet-v3-etdag-governed-artifacts --build-binding --parameter-manifest PATH --fee-schedule-manifest PATH --parameter-artifact-out PATH --fee-schedule-artifact-out PATH --binding-out PATH\n  testnet-v3-etdag-governed-artifacts --build-membership-anchor --candidate PATH --governance-decision-id ID --output PATH\n  testnet-v3-etdag-governed-artifacts --attach-membership-anchor --candidate PATH --membership-anchor PATH --output PATH\n\nAll outputs are new public files: existing output paths are refused. This tool never decrypts, signs, or loads private material."
    );
    std::process::exit(2);
}

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("testnet-v3-etdag-governed-artifacts: {}", message.as_ref());
    std::process::exit(1);
}

fn require_path(args: &[String], index: &mut usize) -> PathBuf {
    let value = args.get(*index + 1).unwrap_or_else(|| usage());
    *index += 2;
    PathBuf::from(value)
}

fn read_json<T: DeserializeOwned>(path: &Path, label: &str) -> T {
    let bytes = fs::read(path)
        .unwrap_or_else(|error| fail(format!("read {label} {}: {error}", path.display())));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| fail(format!("decode {label} {}: {error}", path.display())))
}

fn ensure_distinct_new_outputs(outputs: &[&Path]) {
    let mut paths = BTreeSet::new();
    for output in outputs {
        if !paths.insert((*output).to_path_buf()) {
            fail("ETDAG artifact output paths must be distinct");
        }
        if output.exists() {
            fail(format!(
                "refusing to overwrite existing output {}; use a new output path",
                output.display()
            ));
        }
    }
}

fn write_new(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| fail(format!("create {}: {error}", parent.display())));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| fail(format!("create {}: {error}", path.display())));
    file.write_all(bytes)
        .unwrap_or_else(|error| fail(format!("write {}: {error}", path.display())));
    file.sync_all()
        .unwrap_or_else(|error| fail(format!("sync {}: {error}", path.display())));
}

fn build_binding(
    parameter_manifest_path: &Path,
    fee_schedule_manifest_path: &Path,
    parameter_artifact_output: &Path,
    fee_schedule_artifact_output: &Path,
    binding_output: &Path,
) {
    ensure_distinct_new_outputs(&[
        parameter_artifact_output,
        fee_schedule_artifact_output,
        binding_output,
    ]);
    let parameter_manifest: EtdagParameterManifest =
        read_json(parameter_manifest_path, "ETDAG parameter manifest");
    let parameter_artifact = EtdagParameterArtifact::from_manifest(parameter_manifest)
        .unwrap_or_else(|error| fail(format!("parameter manifest rejected: {error}")));
    let fee_manifest: EtdagFeeScheduleManifest =
        read_json(fee_schedule_manifest_path, "ETDAG fee schedule manifest");
    let fee_schedule_artifact = EtdagFeeScheduleArtifact::from_manifest(fee_manifest)
        .unwrap_or_else(|error| fail(format!("fee schedule manifest rejected: {error}")));
    let binding = EtdagGovernedGenesisBinding {
        schema_version: ETDAG_GOVERNED_GENESIS_BINDING_SCHEMA_VERSION,
        status: ETDAG_GOVERNED_GENESIS_BINDING_STATUS.to_string(),
        parameter_artifact: parameter_artifact.clone(),
        fee_schedule_artifact: fee_schedule_artifact.clone(),
    };
    binding
        .validate()
        .unwrap_or_else(|error| fail(format!("ETDAG Genesis binding rejected: {error}")));

    let parameter_bytes = parameter_artifact
        .canonical_bytes()
        .unwrap_or_else(|error| fail(format!("canonical parameter artifact: {error}")));
    let fee_bytes = fee_schedule_artifact
        .canonical_bytes()
        .unwrap_or_else(|error| fail(format!("canonical fee schedule artifact: {error}")));
    let binding_bytes = binding
        .canonical_bytes()
        .unwrap_or_else(|error| fail(format!("canonical ETDAG Genesis binding: {error}")));
    write_new(parameter_artifact_output, &parameter_bytes);
    write_new(fee_schedule_artifact_output, &fee_bytes);
    write_new(binding_output, &binding_bytes);
    println!(
        "{{\n  \"result\": \"UNSIGNED_GOVERNED_ETDAG_BINDING_WRITTEN\",\n  \"parameter_artifact\": \"{}\",\n  \"etdag_parameter_root_sha3_512\": \"{}\",\n  \"fee_schedule_artifact\": \"{}\",\n  \"etdag_fee_schedule_root_sha3_512\": \"{}\",\n  \"binding\": \"{}\",\n  \"governance_decision_id\": \"{}\"\n}}",
        parameter_artifact_output.display(),
        parameter_artifact.etdag_parameter_root_sha3_512.to_hex(),
        fee_schedule_artifact_output.display(),
        fee_schedule_artifact.etdag_fee_schedule_root_sha3_512.to_hex(),
        binding_output.display(),
        binding.parameter_artifact.manifest.governance_decision_id,
    );
}

fn build_membership_anchor(candidate_path: &Path, governance_decision_id: String, output: &Path) {
    ensure_distinct_new_outputs(&[output]);
    let candidate: serde_json::Value = read_json(candidate_path, "fresh PoSy Genesis candidate");
    let activation = load_genesis_bound_simplified_activation(&candidate)
        .unwrap_or_else(|error| fail(format!("load Genesis activation: {error}")))
        .unwrap_or_else(|| fail("fresh PoSy Genesis candidate has no activation binding"));
    let genesis_hash = candidate
        .pointer("/integrity/genesis_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| fail("fresh PoSy Genesis candidate has no integrity.genesis_hash"))
        .to_string();
    let execution_root = candidate
        .pointer("/genesis_deployment/post_deployment_execution_state_root")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| {
            fail("fresh PoSy Genesis candidate has no post-deployment execution-state root")
        })
        .to_string();
    let anchor: EtdagGovernedMembershipAnchor = build_etdag_governed_membership_anchor(
        governance_decision_id,
        genesis_hash,
        execution_root,
        &activation,
    )
    .unwrap_or_else(|error| fail(format!("build governed membership anchor: {error}")));
    let bytes = anchor
        .canonical_bytes()
        .unwrap_or_else(|error| fail(format!("canonical membership anchor: {error}")));
    write_new(output, &bytes);
    println!(
        "{{\n  \"result\": \"UNSIGNED_GOVERNED_ETDAG_MEMBERSHIP_ANCHOR_WRITTEN\",\n  \"membership_anchor\": \"{}\",\n  \"etdag_membership_anchor_digest_sha3_512\": \"{}\",\n  \"governance_decision_id\": \"{}\"\n}}",
        output.display(),
        anchor.anchor_digest.to_hex(),
        anchor.governance_decision_id,
    );
}

/// Attaches the already canonical post-Genesis anchor to a *new* final
/// candidate.  The Genesis binding function checks the activation, execution
/// root, exact five-validator set, and explicit hash exclusion before this
/// command writes anything.  The final runtime loader is then run against the
/// output as a second independent public-input check.
fn attach_membership_anchor(candidate_path: &Path, anchor_path: &Path, output: &Path) {
    ensure_distinct_new_outputs(&[output]);
    let mut candidate: serde_json::Value =
        read_json(candidate_path, "fresh PoSy Genesis candidate");
    let anchor = EtdagGovernedMembershipAnchor::from_canonical_bytes(
        &fs::read(anchor_path).unwrap_or_else(|error| {
            fail(format!(
                "read ETDAG membership anchor {}: {error}",
                anchor_path.display()
            ))
        }),
    )
    .unwrap_or_else(|error| fail(format!("load ETDAG membership anchor: {error}")));
    bind_testnet_v3_genesis_etdag_membership_anchor(&mut candidate, &anchor)
        .unwrap_or_else(|error| fail(format!("attach ETDAG membership anchor: {error}")));
    let mut bytes = serde_json::to_vec_pretty(&candidate)
        .unwrap_or_else(|error| fail(format!("encode anchored fresh P3 candidate: {error}")));
    bytes.push(b'\n');
    write_new(output, &bytes);
    load_genesis_from_path(output).unwrap_or_else(|error| {
        fail(format!(
            "runtime rejected anchored fresh P3 candidate {}: {error}",
            output.display()
        ))
    });
    println!(
        "{{\n  \"result\": \"UNSIGNED_FRESH_P3_GENESIS_CANDIDATE_WITH_ETDAG_MEMBERSHIP_ANCHOR_WRITTEN\",\n  \"candidate\": \"{}\",\n  \"etdag_membership_anchor_digest_sha3_512\": \"{}\"\n}}",
        output.display(),
        anchor.anchor_digest.to_hex(),
    );
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
    }
    let mut build_binding_mode = false;
    let mut build_anchor_mode = false;
    let mut attach_anchor_mode = false;
    let mut parameter_manifest = None;
    let mut fee_schedule_manifest = None;
    let mut parameter_artifact_output = None;
    let mut fee_schedule_artifact_output = None;
    let mut binding_output = None;
    let mut candidate = None;
    let mut governance_decision_id = None;
    let mut membership_anchor = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--build-binding" => {
                build_binding_mode = true;
                index += 1;
            }
            "--build-membership-anchor" => {
                build_anchor_mode = true;
                index += 1;
            }
            "--attach-membership-anchor" => {
                attach_anchor_mode = true;
                index += 1;
            }
            "--parameter-manifest" => parameter_manifest = Some(require_path(&args, &mut index)),
            "--fee-schedule-manifest" => {
                fee_schedule_manifest = Some(require_path(&args, &mut index))
            }
            "--parameter-artifact-out" => {
                parameter_artifact_output = Some(require_path(&args, &mut index))
            }
            "--fee-schedule-artifact-out" => {
                fee_schedule_artifact_output = Some(require_path(&args, &mut index))
            }
            "--binding-out" => binding_output = Some(require_path(&args, &mut index)),
            "--candidate" => candidate = Some(require_path(&args, &mut index)),
            "--governance-decision-id" => {
                governance_decision_id =
                    Some(args.get(index + 1).unwrap_or_else(|| usage()).to_string());
                index += 2;
            }
            "--membership-anchor" => membership_anchor = Some(require_path(&args, &mut index)),
            "--output" => output = Some(require_path(&args, &mut index)),
            _ => usage(),
        }
    }
    if [build_binding_mode, build_anchor_mode, attach_anchor_mode]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
        != 1
    {
        usage();
    }
    if build_binding_mode {
        if candidate.is_some()
            || governance_decision_id.is_some()
            || membership_anchor.is_some()
            || output.is_some()
        {
            usage();
        }
        build_binding(
            &parameter_manifest.unwrap_or_else(|| usage()),
            &fee_schedule_manifest.unwrap_or_else(|| usage()),
            &parameter_artifact_output.unwrap_or_else(|| usage()),
            &fee_schedule_artifact_output.unwrap_or_else(|| usage()),
            &binding_output.unwrap_or_else(|| usage()),
        );
    } else if build_anchor_mode {
        if parameter_manifest.is_some()
            || fee_schedule_manifest.is_some()
            || parameter_artifact_output.is_some()
            || fee_schedule_artifact_output.is_some()
            || binding_output.is_some()
            || membership_anchor.is_some()
        {
            usage();
        }
        build_membership_anchor(
            &candidate.unwrap_or_else(|| usage()),
            governance_decision_id.unwrap_or_else(|| usage()),
            &output.unwrap_or_else(|| usage()),
        );
    } else {
        if parameter_manifest.is_some()
            || fee_schedule_manifest.is_some()
            || parameter_artifact_output.is_some()
            || fee_schedule_artifact_output.is_some()
            || binding_output.is_some()
            || governance_decision_id.is_some()
        {
            usage();
        }
        attach_membership_anchor(
            &candidate.unwrap_or_else(|| usage()),
            &membership_anchor.unwrap_or_else(|| usage()),
            &output.unwrap_or_else(|| usage()),
        );
    }
}
