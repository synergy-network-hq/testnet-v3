//! Read-only 16-host preparation, not a runtime config or authenticated electorate.
//! Node v2.1 pp10,21–23,50–59,67–72,196–197; Identity R1 pp265–271.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use synergy_address::r1_public::{require_nonproduction_fixture, NetworkRef};
use synergy_protocol_types::{NodeClass, R1NodePresentation};

/// Full-width explicit candidate coordinate for non-executing config/compiler tests.
/// No conversion into AuthenticatedPeer/GenesisValidator or runtime authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRuntimeIdentity {
    network: NetworkRef,
    presentation: R1NodePresentation,
}
impl PreparedRuntimeIdentity {
    pub fn parse_fixture(
        network: NetworkRef,
        text: &str,
        class: NodeClass,
    ) -> Result<Self, String> {
        require_nonproduction_fixture(network.chain_id).map_err(str::to_owned)?;
        Ok(Self {
            network,
            presentation: R1NodePresentation::parse(text, class).map_err(str::to_owned)?,
        })
    }
    pub fn network(&self) -> NetworkRef {
        self.network
    }
    pub fn presentation(&self) -> &R1NodePresentation {
        &self.presentation
    }
    pub fn require_coordinate(&self, network: NetworkRef) -> Result<(), &'static str> {
        if self.network != network {
            return Err("candidate node network coordinate mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfrastructureRole {
    Validator,
    Sentry,
    RpcGateway,
    Bootseed,
    Indexer,
    Archive,
}
impl InfrastructureRole {
    fn slot_matches(self, id: &str) -> bool {
        let (prefix, count) = match self {
            Self::Validator => ("VAL", 6),
            Self::Sentry => ("SEN", 3),
            Self::RpcGateway => ("RPC", 2),
            Self::Bootseed => ("BTS", 3),
            Self::Indexer => ("IND", 1),
            Self::Archive => ("ARC", 1),
        };
        (1..=count).any(|i| id == format!("{prefix}-{i:02}"))
    }
    fn source_class(self) -> u8 {
        match self {
            Self::Validator | Self::Sentry | Self::Archive => 1,
            _ => 5,
        }
    }
    fn candidate_voter(self) -> bool {
        self == Self::Validator
    }
    fn candidate_overlay(self) -> bool {
        matches!(self, Self::Validator | Self::Sentry)
    }
    fn public_service(self) -> bool {
        !matches!(self, Self::Validator | Self::Archive)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningMode {
    UserNodenetwork,
    InternalControlled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassStatus {
    SourceConfirmed,
    BlockedClassProfile,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureMember {
    pub inventory_id: String,
    pub host_label: Option<String>,
    pub role: InfrastructureRole,
    pub node_class: Option<u8>,
    pub node_class_status: ClassStatus,
    pub provisioning_mode: ProvisioningMode,
    pub initial_voter: bool,
    pub validator_overlay_allowed: bool,
    pub public_service_allowed: bool,
    pub node_identity: (),
    pub role_keys: (),
    pub authority_binding: (),
    pub host_evidence: (),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureRoster {
    pub schema: String,
    pub chain_id: u64,
    pub status: String,
    pub activation_allowed: bool,
    pub source_workbook_sha256: String,
    pub members: Vec<InfrastructureMember>,
}
#[derive(Debug, Serialize)]
pub struct HostPlan {
    pub inventory_id: String,
    pub role: InfrastructureRole,
    pub node_class: Option<u8>,
    pub node_class_status: ClassStatus,
    pub provisioning_mode: ProvisioningMode,
    pub candidate_initial_voter: bool,
    pub primary_deployment_profile: &'static str,
    pub candidate_validator_overlay: bool,
    pub candidate_public_service: bool,
    pub authenticated_privileges: (),
    pub actual_identity: (),
    pub dependencies: Vec<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct FleetPreparationPlan {
    pub schema: &'static str,
    pub runtime_compatible: bool,
    pub activation_allowed: bool,
    pub actual_outputs: (),
    pub source_workbook_sha256: String,
    pub formation: super::preparation::PreparationPlan,
    pub hosts: Vec<HostPlan>,
}
fn public_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
impl InfrastructureRoster {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 1024 * 1024 {
            return Err("infrastructure input exceeds bound".into());
        }
        let roster: Self = serde_json::from_slice(bytes)
            .map_err(|_| "invalid typed public infrastructure input")?;
        roster.validate()?;
        Ok(roster)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "synergy.infrastructure-preparation/1"
            || self.chain_id != 9969
            || self.status != "staged_not_runtime_genesis"
            || self.activation_allowed
            || self.source_workbook_sha256.len() != 64
            || !self
                .source_workbook_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.members.len() != 16
        {
            return Err("invalid preparation-only infrastructure contract".into());
        }
        let mut ids = BTreeSet::new();
        let mut hosts = BTreeSet::new();
        let mut counts = BTreeMap::new();
        for member in &self.members {
            *counts.entry(member.role).or_insert(0) += 1;
            let class_valid = match member.node_class_status {
                ClassStatus::SourceConfirmed => {
                    member.node_class == Some(member.role.source_class())
                }
                ClassStatus::BlockedClassProfile => member.node_class.is_none(),
            };
            if !public_label(&member.inventory_id)
                || !member.role.slot_matches(&member.inventory_id)
                || !ids.insert(&member.inventory_id)
                || member
                    .host_label
                    .as_ref()
                    .is_some_and(|h| !public_label(h) || !hosts.insert(h.to_ascii_lowercase()))
                || !class_valid
                || member.initial_voter
                    != (member.role == InfrastructureRole::Validator
                        && matches!(
                            member.inventory_id.as_str(),
                            "VAL-01" | "VAL-02" | "VAL-03" | "VAL-04" | "VAL-05"
                        ))
                || member.validator_overlay_allowed != member.role.candidate_overlay()
                || member.public_service_allowed != member.role.public_service()
                || (member.role != InfrastructureRole::Validator
                    && member.provisioning_mode != ProvisioningMode::InternalControlled)
            {
                return Err("invalid/duplicate host plan or unauthorized role capability".into());
            }
        }
        let expected = BTreeMap::from([
            (InfrastructureRole::Validator, 6),
            (InfrastructureRole::Sentry, 3),
            (InfrastructureRole::RpcGateway, 2),
            (InfrastructureRole::Bootseed, 3),
            (InfrastructureRole::Indexer, 1),
            (InfrastructureRole::Archive, 1),
        ]);
        let expected_ids = [
            ("VAL", 6),
            ("SEN", 3),
            ("RPC", 2),
            ("BTS", 3),
            ("IND", 1),
            ("ARC", 1),
        ]
        .into_iter()
        .flat_map(|(prefix, count)| (1..=count).map(move |i| format!("{prefix}-{i:02}")))
        .collect::<BTreeSet<_>>();
        if ids.iter().map(|x| x.to_string()).collect::<BTreeSet<_>>() != expected_ids {
            return Err("infrastructure slots differ from selected16-host plan".into());
        }
        if counts != expected {
            return Err("infrastructure role counts differ from prepared16-host fleet".into());
        }
        Ok(())
    }
    pub fn host_plans(&self) -> Result<Vec<HostPlan>, String> {
        self.validate()?;
        Ok(self.members.iter().map(|m| {
            let mut dependencies = vec!["independent host evidence", "fresh identity and role policy", "qualified authenticated platform release", "separate ceremony authorization"];
            if m.node_class_status == ClassStatus::BlockedClassProfile { dependencies.push("exact class/profile selection"); }
            if m.role == InfrastructureRole::Bootseed { dependencies.push("qualify selected single bootstrap/seed deployment profile, public routing and release; no extra logical node or duplicate identity"); }
            if m.role.candidate_overlay() { dependencies.push("explicit qualified private overlay admission and custody; template is not membership"); }
            if m.role.candidate_voter() { dependencies.push("resolve fleet and authenticate frozen PoSy N/W; candidate is not admitted voter"); }
            HostPlan { inventory_id:m.inventory_id.clone(),role:m.role,node_class:m.node_class,
                node_class_status:m.node_class_status, provisioning_mode:m.provisioning_mode,
                candidate_initial_voter:m.initial_voter,primary_deployment_profile:match m.role { InfrastructureRole::Validator=>"validator",InfrastructureRole::Sentry=>"sentry",InfrastructureRole::RpcGateway=>"rpc_gateway",InfrastructureRole::Indexer=>"indexer",InfrastructureRole::Archive=>"archive",InfrastructureRole::Bootseed=>if m.inventory_id=="BTS-03"{"seed"}else{"bootstrap"}},candidate_validator_overlay:m.validator_overlay_allowed,
                candidate_public_service:m.public_service_allowed,authenticated_privileges:(),actual_identity:(),dependencies }
        }).collect())
    }
}
pub fn plan(
    genesis: &[u8],
    validators: &[u8],
    infrastructure: &[u8],
) -> Result<FleetPreparationPlan, String> {
    let roster = InfrastructureRoster::parse(infrastructure)?;
    Ok(FleetPreparationPlan {
        schema: "synergy.fleet-preparation-plan/1",
        runtime_compatible: false,
        activation_allowed: false,
        actual_outputs: (),
        source_workbook_sha256: roster.source_workbook_sha256.clone(),
        formation: super::preparation::plan(genesis, validators)?,
        hosts: roster.host_plans()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> InfrastructureRoster {
        let mut members = Vec::new();
        for (role, count, prefix) in [
            (InfrastructureRole::Validator, 6, "VAL"),
            (InfrastructureRole::Sentry, 3, "SEN"),
            (InfrastructureRole::RpcGateway, 2, "RPC"),
            (InfrastructureRole::Bootseed, 3, "BTS"),
            (InfrastructureRole::Indexer, 1, "IND"),
            (InfrastructureRole::Archive, 1, "ARC"),
        ] {
            for i in 1..=count {
                members.push(InfrastructureMember {
                    inventory_id: format!("{prefix}-{i:02}"),
                    host_label: Some(format!("synthetic-public-{prefix}-{i}")),
                    role,
                    node_class: Some(role.source_class()),
                    node_class_status: ClassStatus::SourceConfirmed,
                    provisioning_mode: if role == InfrastructureRole::Validator {
                        ProvisioningMode::UserNodenetwork
                    } else {
                        ProvisioningMode::InternalControlled
                    },
                    initial_voter: role.candidate_voter() && i <= 5,
                    validator_overlay_allowed: role.candidate_overlay(),
                    public_service_allowed: role.public_service(),
                    node_identity: (),
                    role_keys: (),
                    authority_binding: (),
                    host_evidence: (),
                });
            }
        }
        InfrastructureRoster {
            schema: "synergy.infrastructure-preparation/1".into(),
            chain_id: 9969,
            status: "staged_not_runtime_genesis".into(),
            activation_allowed: false,
            source_workbook_sha256: "0".repeat(64),
            members,
        }
    }
    #[test]
    fn full_fleet_adapter_keeps_genesis_unsealed_and_outputs_unset() {
        let genesis = super::super::preparation::genesis_template(9969);
        let validators = super::super::preparation::roster_template(9969);
        let result = plan(
            &serde_json::to_vec(&genesis).unwrap(),
            &serde_json::to_vec(&validators).unwrap(),
            &serde_json::to_vec(&fixture()).unwrap(),
        )
        .unwrap();
        assert_eq!(result.hosts.len(), 16);
        assert_eq!(result.formation.quorum_candidate.minimum_signers, 4);
        assert!(!result.activation_allowed && !result.runtime_compatible);
        let value = serde_json::to_value(result).unwrap();
        assert!(value["actual_outputs"].is_null());
        assert!(value["formation"]["runtime_outputs"].is_null());
    }
    #[test]
    fn sixteen_public_host_plans_never_create_authority_or_keys() {
        let r = fixture();
        r.validate().unwrap();
        let plans = r.host_plans().unwrap();
        assert_eq!(plans.len(), 16);
        assert_eq!(
            plans.iter().filter(|h| h.candidate_initial_voter).count(),
            5
        );
        assert_eq!(
            plans
                .iter()
                .filter(|h| h.candidate_validator_overlay)
                .count(),
            9
        );
        let value = serde_json::to_value(plans).unwrap();
        assert!(value
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["actual_identity"].is_null() && x["authenticated_privileges"].is_null()));
    }
    #[test]
    fn rejects_service_vote_overlay_class_and_management_escalation() {
        for index in 6..16 {
            let mut r = fixture();
            r.members[index].initial_voter = true;
            assert!(r.validate().is_err());
        }
        for index in 9..16 {
            let mut r = fixture();
            r.members[index].validator_overlay_allowed = true;
            assert!(r.validate().is_err());
        }
        let mut r = fixture();
        r.members[15].node_class = Some(5);
        assert!(r.validate().is_err());
        let mut r = fixture();
        r.members[6].provisioning_mode = ProvisioningMode::UserNodenetwork;
        assert!(r.validate().is_err());
        let mut r = fixture();
        r.members[15].node_class = None;
        r.members[15].node_class_status = ClassStatus::BlockedClassProfile;
        assert!(r.validate().is_ok());
    }
    #[test]
    fn duplicate_hosts_and_live_material_unknown_fields_rejected() {
        let mut r = fixture();
        r.members[14].host_label = r.members[13].host_label.clone();
        assert!(r.validate().is_err());
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["members"][0]["node_identity"] = serde_json::json!("must-not-enter-live-field");
        assert!(InfrastructureRoster::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["ceremony_authorized"] = serde_json::json!(true);
        assert!(InfrastructureRoster::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn full_width_config_coordinate_keeps_network_and_class_explicit() {
        let network = NetworkRef {
            chain_id: u64::MAX - 1,
            nic: [0x11; 64],
        };
        let text = format!("synv1.2.{}", "A".repeat(64));
        let id = PreparedRuntimeIdentity::parse_fixture(
            network,
            &text,
            NodeClass::ConsensusAndChainIntegrity,
        )
        .unwrap();
        assert_eq!(id.presentation().raw48(), &[0; 48]);
        assert_eq!(id.presentation().as_str().len(), 72);
        assert_eq!(id.network(), network);
        assert!(id
            .require_coordinate(NetworkRef {
                nic: [0x12; 64],
                ..network
            })
            .is_err());
        assert!(id
            .require_coordinate(NetworkRef {
                chain_id: u64::MAX,
                ..network
            })
            .is_err());
        assert!(PreparedRuntimeIdentity::parse_fixture(
            NetworkRef {
                chain_id: 9969,
                nic: [0; 64]
            },
            "",
            NodeClass::ConsensusAndChainIntegrity
        )
        .unwrap_err()
        .contains("CEREMONY_AUTHORIZATION_REQUIRED"));
    }
}

#[cfg(test)]
mod selected_target_tests {
    use super::*;
    #[test]
    fn actual_staged_six_candidates_map_five_voters_and_three_single_bootseed_profiles() {
        let base = std::path::Path::new("/Volumes/PortableSSD/testnet-9969");
        let roster = InfrastructureRoster::parse(
            &std::fs::read(base.join("config/infrastructure-roster.testnet-9969.json")).unwrap(),
        )
        .unwrap();
        let plans = roster.host_plans().unwrap();
        assert_eq!(plans.len(), 16);
        assert_eq!(
            plans.iter().filter(|p| p.candidate_initial_voter).count(),
            5
        );
        assert!(
            !plans
                .iter()
                .find(|p| p.inventory_id == "VAL-06")
                .unwrap()
                .candidate_initial_voter
        );
        for (id, profile) in [
            ("BTS-01", "bootstrap"),
            ("BTS-02", "bootstrap"),
            ("BTS-03", "seed"),
        ] {
            assert_eq!(
                plans
                    .iter()
                    .find(|p| p.inventory_id == id)
                    .unwrap()
                    .primary_deployment_profile,
                profile
            );
        }
        let mut bad = roster.clone();
        bad.members
            .iter_mut()
            .find(|m| m.inventory_id == "VAL-06")
            .unwrap()
            .initial_voter = true;
        assert!(bad.validate().is_err());
        let mut bad = roster.clone();
        bad.members
            .iter_mut()
            .find(|m| m.inventory_id == "VAL-01")
            .unwrap()
            .initial_voter = false;
        assert!(bad.validate().is_err());
        let mut bad = roster;
        bad.members
            .iter_mut()
            .find(|m| m.inventory_id == "BTS-03")
            .unwrap()
            .inventory_id = "BTS-04".into();
        assert!(bad.validate().is_err());
    }
}
