//! Closed implemented profile catalog. Engineering-selected complete definitions
//! are authenticated as values, not caller-provided unknown parameter bags.
use super::{
    artifact_matrix::{ArtifactTarget, PlatformArtifactMatrix},
    GenesisError,
};
use synergy_address_engine::apqe::{
    network_birth_r1::ProfileRef,
    r1_framing::{self as c, Value},
    HashAlgorithm, Primitives,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ProfileKind {
    Genesis = 1,
    NativeIdentity = 2,
    NodePossession = 3,
    NodeRoleBinding = 4,
    AccountPossession = 5,
    CanonicalEncoding = 6,
    State = 7,
    Receipt = 8,
    NativeFees = 9,
    PoSyBlock = 10,
    PoSyFinality = 11,
    PoSyCodec = 12,
    PoSyAuthority = 13,
    ProfileSet = 14,
    RuntimeTransport = 15,
    Policy = 16,
    NetworkBirth = 17,
    RootApproval = 18,
    FormationRegistration = 19,
    FormationRegistry = 20,
    FormationInput = 21,
    NativeTransaction = 22,
    ExecutionPayload = 23,
    // Declared candidate definitions only. ALL stays the exact23 selected set
    // until the coordinated owner freeze; these cannot enter a catalog yet.
    CompleteFormation = 24,
    InitialBootstrapScore = 25,
    ProtocolProfile = 26,
    FormationAssignment = 27,
    PoSySchedule = 28,
    Custody = 29,
    FormationTransport = 30,
    RpcResponse = 31,
    InitialWalletEnrollment = 32,
    NativeRuntimeUse = 33,
    NativeFormationUse = 34,
    RuntimeAdmissionRegistry = 35,
}
impl ProfileKind {
    pub const ALL: [Self; 23] = [
        Self::Genesis,
        Self::NativeIdentity,
        Self::NodePossession,
        Self::NodeRoleBinding,
        Self::AccountPossession,
        Self::CanonicalEncoding,
        Self::State,
        Self::Receipt,
        Self::NativeFees,
        Self::PoSyBlock,
        Self::PoSyFinality,
        Self::PoSyCodec,
        Self::PoSyAuthority,
        Self::ProfileSet,
        Self::RuntimeTransport,
        Self::Policy,
        Self::NetworkBirth,
        Self::RootApproval,
        Self::FormationRegistration,
        Self::FormationRegistry,
        Self::FormationInput,
        Self::NativeTransaction,
        Self::ExecutionPayload,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Genesis => "SYNERGY-GENESIS-R1",
            Self::NativeIdentity => "APQE-NATIVE-ID",
            Self::NodePossession => "APQE-NODE-POSSESSION",
            Self::NodeRoleBinding => "APQE-NODE-ROLE-BINDING",
            Self::AccountPossession => "APQE-ACCOUNT-POSSESSION",
            Self::CanonicalEncoding => "QACE-C14N-02",
            Self::State => "QACE-SMT384-R1",
            Self::Receipt => "QACE-RECEIPT-R1",
            Self::NativeFees => "SYNERGY-NATIVE-CUMULATIVE-FEES-R1",
            Self::PoSyBlock => synergy_posy::r1::BLOCK_PROFILE_NAME,
            Self::PoSyFinality => synergy_posy::r1::FINALITY_PROFILE_NAME,
            Self::PoSyCodec => synergy_posy::r1::CODEC_PROFILE_NAME,
            Self::PoSyAuthority => synergy_posy::r1::AUTHORITY_PROFILE_NAME,
            Self::ProfileSet => "APQE-PROFILE-SET",
            Self::RuntimeTransport => synergy_address_engine::apqe::current_session::PROFILE.name,
            Self::Policy => "APQE-POLICY",
            Self::NetworkBirth => "APQE-BOOT",
            Self::RootApproval => "APQE-ROOT-APPROVAL",
            Self::FormationRegistration => super::formation::REGISTRATION_PROFILE,
            Self::FormationRegistry => super::formation::REGISTRY_PROFILE,
            Self::FormationInput => super::formation::INPUT_PROFILE,
            Self::NativeTransaction => synergy_transaction::r1::PROFILE_NAME,
            Self::ExecutionPayload => synergy_execution::r1_payload::PROFILE_NAME,
            Self::CompleteFormation => super::complete_formation::FORMATION_PROFILE,
            Self::InitialBootstrapScore => super::complete_formation::INITIAL_SCORE_PROFILE,
            Self::ProtocolProfile => synergy_protocol_types::protocol_profile_r1::PROFILE_NAME,
            Self::FormationAssignment => super::complete_formation::ASSIGNMENT_PROFILE,
            Self::PoSySchedule => synergy_posy::r1::SCHEDULE_PROFILE_NAME,
            Self::Custody => "APQE-CUSTODY-R1",
            Self::FormationTransport => synergy_address_engine::apqe::formation_channel::PROFILE.name,
            Self::RpcResponse => synergy_protocol_types::r1_rpc_response::PROFILE_NAME,
            Self::InitialWalletEnrollment => synergy_execution::r1_enrollment::PROFILE_NAME,
            Self::NativeRuntimeUse => synergy_address_engine::apqe::managed_creation::runtime_use::PROFILE.name,
            Self::NativeFormationUse => synergy_address_engine::apqe::managed_creation::formation_use::PROFILE.name,
            Self::RuntimeAdmissionRegistry => synergy_address_engine::apqe::managed_runtime_transport::PROFILE.name,
        }
    }
    pub fn revision(self) -> u32 {
        match self {
            Self::RuntimeTransport => {
                synergy_address_engine::apqe::current_session::PROFILE.revision
            }
            Self::NativeTransaction => synergy_transaction::r1::PROFILE_REVISION,
            Self::ExecutionPayload => synergy_execution::r1_payload::PROFILE_REVISION,
            _ => 1,
        }
    }
    /// Exact independently declared schema bytes, without their own digest.
    pub fn schema(self) -> &'static [u8] {
        match self{
 Self::Genesis=>b"GenesisCoreR1v1=U16(1),U64(chain),NIC64,ProfileRef(ASCII128,U32rev),TimeU64,Bytes(CatalogFrame1048576),Vector4096(Node),Vector65536(Account),Vector4096(Voter=NamespaceASCII6,Raw48,WeightU128),Vector65536(Allocation=IdASCII128,AmountU128,Destination),Vector4(Restricted=KindU16,BalanceU128,Policy64),Vector69(SRPA=SuffixU16,ActiveFalseU8),StateProfile,StateRoot48,ReceiptProfile,ReceiptRoot48;Node=Raw48,ClassU8,PrimaryRoleU16,BirthNonce32,KeyRecord,BirthPolicy,CurrentPolicy,EpochU64,EnrollmentNonce32,Vector4(RoleKey),Vector64(IndexedProof),Vector32(IndexedProof);KeyRecord=RoleASCII64,AlgorithmU16(65|87),GenerationU64,Bytes2592(PublicKey);Policy=NamespaceASCII6,Vector32(Controller=KeyRecord,DeclaredDomainASCII128),Rule=ThresholdU32,Vector32(IndexU32),Option(Rule);Account=NamespaceASCII6,Raw48,BirthNonce32,Policy,EpochU64,TransactionNonceU64,EnrollmentNonce32,Vector32(IndexedProof);IndexedProof=IndexU32,Bytes4627(Signature);Destination=TagU8(Account0,NamespaceASCII6,Raw48|Bond1,ValidatorIdentity,OwnerIdentity,BeneficiaryIdentity|Unassigned2);RoleKey=KindU16(Consensus1|Public2|Private3|Service4),KeyRecord;identity-order=(namespace,raw48)-strict;allocation-order=ASCIIid-strict;restricted-order=kind0..3;full69SRPAliterals-defaultdeny;hash=SHA3-384;domain=SYNERGY/GENESIS/01;wrapper=2;max16777216",
 Self::NativeIdentity=>synergy_address_engine::apqe::native_identity_derivation_r1::NATIVE_PROFILE_SCHEMA,
 Self::Policy=>synergy_address_engine::apqe::native_identity_derivation_r1::POLICY_PROFILE_SCHEMA,
 Self::NetworkBirth=>synergy_address_engine::apqe::network_birth_r1::PROFILE_SCHEMA,
 Self::RootApproval=>synergy_address_engine::apqe::bootstrap_approvals_r1::PROFILE_SCHEMA,
 Self::FormationRegistration=>super::formation::REGISTRATION_SCHEMA,
 Self::FormationRegistry=>super::formation::REGISTRY_SCHEMA,
 Self::FormationInput=>super::formation::INPUT_SCHEMA,
 Self::NativeTransaction=>synergy_transaction::r1::PROFILE_SCHEMA.as_bytes(),
 Self::ExecutionPayload=>synergy_execution::r1_payload::PROFILE_SCHEMA.as_bytes(),
 Self::CompleteFormation=>super::complete_formation::FORMATION_FIELDS_SCHEMA,
 Self::InitialBootstrapScore=>super::complete_formation::INITIAL_SCORE_SCHEMA,
 Self::ProtocolProfile=>synergy_protocol_types::protocol_profile_r1::PROFILE_SCHEMA,
 Self::FormationAssignment=>super::complete_formation::ASSIGNMENT_SCHEMA,
 Self::PoSySchedule=>synergy_posy::r1::SCHEDULE_PROFILE_SCHEMA,
 Self::Custody=>synergy_address_engine::apqe::custody_binding_r1::PROFILE_SCHEMA,
 Self::FormationTransport=>synergy_address_engine::apqe::formation_channel::PROFILE_SCHEMA,
 Self::RpcResponse=>synergy_protocol_types::r1_rpc_response::PROFILE_SCHEMA,
 Self::InitialWalletEnrollment=>synergy_execution::r1_enrollment::PROFILE_SCHEMA.as_bytes(),
 Self::NativeRuntimeUse=>synergy_address_engine::apqe::managed_creation::runtime_use::PROFILE_SCHEMA,
 Self::NativeFormationUse=>synergy_address_engine::apqe::managed_creation::formation_use::PROFILE_SCHEMA,
 Self::RuntimeAdmissionRegistry=>synergy_address_engine::apqe::managed_runtime_transport::PROFILE_SCHEMA,
 Self::NodePossession=>b"F(IDENTITY.NODE.POSSESSION,[APQE-NODE-POSSESSION,1],N,[namespace,raw48,completeKeyRecord,currentPolicyCommit64,enrollment_nonce32]);pure-context=SYNERGY.NODE.POP.R1;ML-DSA-65|87;proof-for-each-distinct-complete-key",
 Self::NodeRoleBinding=>b"KeySet=SHA3-512(F(IDENTITY.NODE.ROLE-KEY-SET,[APQE-NODE-ROLE-BINDING,1],N,[sortedCompleteRoleKeys]));F(IDENTITY.NODE.ROLE-BINDING,[APQE-NODE-ROLE-BINDING,1],N,[namespace,raw48,policy64,keyset64,nonce32,epochU64]);pure-context=SYNERGY.NODE.ROLE-BINDING.R1;ordinary-threshold-controller-indices",
 Self::AccountPossession=>b"F(IDENTITY.ACCOUNT.POSSESSION,[APQE-ACCOUNT-POSSESSION,1],N,[namespace,raw48,completeKeyRecord,policyCommit64,enrollment_nonce32]);pure-context=SYNERGY.ACCOUNT.POP.R1;every-controller;epoch=1;transaction-nonce=0;synm-synu-threshold>=2",
 Self::CanonicalEncoding=>b"QACE-C14N-02:BE-fixed-U8-U16-U32-U64-U128;ASCII=U32(length)||bytes-no-NUL;Bytes=U32(length)||bytes;Vector=U32(count)||ordered-items;Option=U8(0|1)||value-if-present;HashWrapper=U16(2)||ASCII(domain)||typed-value;reject-trailing-and-noncanonical",
 Self::State=>synergy_state::r1::STATE_PROFILE_SCHEMA.as_bytes(),
 Self::Receipt=>synergy_state::r1_receipts::RECEIPT_PROFILE_SCHEMA.as_bytes(),
 Self::ProfileSet=>b"APQE-PROFILE-SET/1;Commit=SHA3-512(F(NETWORK.ACTIVATED-PROFILES,[APQE-PROFILE-SET,1],no-N,Array(Definition)));Definition=Array(KindUnsigned,NameText,RevisionUnsigned,ExactSchemaBytes,SchemaSHA3-38448,ArtifactMatrix,APQEModuleRevisionText,SelectedManifestSHA256Text,ImportManifestSHA256Text);ArtifactMatrix=Array([linux,Targets2],[macos,Targets2],[windows,Targets3]);TargetSlot=Array(exactTargetASCII,Option(ArtifactPins=Array([65,SHA25632],[87,SHA25632],[1024,SHA25632])));Option=[]|[value];targets-linux=linux-x86_64-gnu,linux-arm64-gnu;targets-macos=macos-arm64,macos-x86_64;targets-windows=windows-x86_64-gnu,windows-x86_64-msvc,windows-arm64-msvc;all3groups-and7slots-always;None=unqualified-dependency-not-zeros;exact-current-provider-target-required;production-requires-at-least-one-independently-qualified-target-per-OS-group-not-every-ABI;Some-pins-alone-never-prove-qualification;strict-enum-kind-order;all-implemented-required-variants-exact;schema-digest-excludes-itself;maxframe1048576;artifact-integrity-is-not-production-approval;no-derived-NIC-or-Genesis-in-definitions",

 Self::RuntimeTransport=>synergy_address_engine::apqe::current_session::PROFILE_SCHEMA,
 Self::PoSyAuthority=>synergy_posy::r1::AUTHORITY_PROFILE_SCHEMA,
 Self::PoSyCodec=>synergy_posy::r1::CODEC_PROFILE_SCHEMA,
 Self::PoSyBlock=>synergy_posy::r1::BLOCK_PROFILE_SCHEMA,
 Self::PoSyFinality=>synergy_posy::r1::FINALITY_PROFILE_SCHEMA,
 Self::NativeFees=>b"SYNERGY-NATIVE-CUMULATIVE-FEES-R1:cumulative-weight4:1;integer-nwei;backed-distinct-fee-rounding-escrow;no-per-transaction-floor-complement;no-ordinary-burn;atomic-conservation;Treasury,TreasuryRecovery,SecurityForfeiture,FeeRoundingEscrow-distinct-protocol-records"
 }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDefinition {
    pub kind: ProfileKind,
    pub schema_digest: [u8; 48],
    pub artifact_matrix: PlatformArtifactMatrix,
}
impl ProfileDefinition {
    pub fn from_target_matrix(
        kind: ProfileKind,
        artifact_matrix: PlatformArtifactMatrix,
    ) -> Result<Self, GenesisError> {
        artifact_matrix.canonical_value()?;
        let schema_digest = Primitives
            .hash(HashAlgorithm::Sha3384, kind.schema())
            .map_err(|_| GenesisError::Primitive)?
            .try_into()
            .map_err(|_| GenesisError::Primitive)?;
        Ok(Self {
            kind,
            schema_digest,
            artifact_matrix,
        })
    }
    fn value(&self) -> Result<Value, GenesisError> {
        let expected = Self::from_target_matrix(self.kind, self.artifact_matrix.clone())?;
        if self != &expected {
            return Err(GenesisError::Profile);
        };
        Ok(Value::Array(vec![
            Value::Unsigned(self.kind as u16 as u64),
            c::text(self.kind.name()),
            Value::Unsigned(self.kind.revision() as u64),
            c::bytes(self.kind.schema()),
            c::bytes(&self.schema_digest),
            self.artifact_matrix.canonical_value()?,
            c::text(synergy_address_engine::apqe::provider::MODULE_REVISION),
            c::text(synergy_address_engine::apqe::provider::SELECTED_MANIFEST_SHA256),
            c::text(synergy_address_engine::apqe::provider::IMPORT_MANIFEST_SHA256),
        ]))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileCatalog {
    definitions: Vec<ProfileDefinition>,
}
impl ProfileCatalog {
    pub fn new(definitions: Vec<ProfileDefinition>) -> Result<Self, GenesisError> {
        if definitions.len() != ProfileKind::ALL.len()
            || definitions.iter().map(|d| d.kind).ne(ProfileKind::ALL)
        {
            return Err(GenesisError::Profile);
        };
        for d in &definitions {
            d.value()?;
        }
        Ok(Self { definitions })
    }
    pub fn validate_provider(
        &self,
        engine: &synergy_address_engine::apqe::crypto_engine::CryptoEngine,
    ) -> Result<(), GenesisError> {
        use synergy_address_engine::{apqe::provider, types::Algorithm};
        for d in &self.definitions {
            for algorithm in [Algorithm::MlDsa65, Algorithm::MlDsa87] {
                let actual = engine
                    .provider_provenance(algorithm)
                    .map_err(|_| GenesisError::Profile)?;
                let target = ArtifactTarget::from_provider(actual.target)?;
                let pins = d.artifact_matrix.get(target).ok_or(GenesisError::Profile)?;
                let pin = if algorithm == Algorithm::MlDsa65 {
                    pins.mldsa65
                } else {
                    pins.mldsa87
                };
                if actual.artifact_sha256 != pin
                    || actual.module_revision != provider::MODULE_REVISION
                    || actual.selected_manifest_sha256 != provider::SELECTED_MANIFEST_SHA256
                    || actual.import_manifest_sha256 != provider::IMPORT_MANIFEST_SHA256
                {
                    return Err(GenesisError::Profile);
                }
            }
        }
        Ok(())
    }
    /// Parse a separately pinned complete catalog, using the shared strict APQE
    /// decoder and this executable closed schema. A successful parse supplies
    /// no authentication of the file or release that selected its artifact pins.
    pub fn from_received_frame(received: &[u8]) -> Result<Self, GenesisError> {
        let decoded = Value::decode(received, 1024 * 1024).map_err(|_| GenesisError::Encoding)?;
        let Value::Array(frame) = decoded else {
            return Err(GenesisError::Profile);
        };
        if frame.len() != 5 {
            return Err(GenesisError::Profile);
        }
        let Value::Array(rows) = &frame[4] else {
            return Err(GenesisError::Profile);
        };
        if rows.len() != ProfileKind::ALL.len() {
            return Err(GenesisError::Profile);
        }
        let definitions = rows
            .iter()
            .zip(ProfileKind::ALL)
            .map(|(row, kind)| {
                let Value::Array(fields) = row else {
                    return Err(GenesisError::Profile);
                };
                if fields.len() != 9 {
                    return Err(GenesisError::Profile);
                }
                let matrix = PlatformArtifactMatrix::from_canonical_value(&fields[5])?;
                let definition = ProfileDefinition::from_target_matrix(kind, matrix)?;
                if definition.value()? != *row {
                    return Err(GenesisError::Profile);
                }
                Ok(definition)
            })
            .collect::<Result<Vec<_>, GenesisError>>()?;
        let catalog = Self::new(definitions)?;
        if catalog.canonical_frame()? != received {
            return Err(GenesisError::Profile);
        }
        Ok(catalog)
    }
    pub fn definitions(&self) -> &[ProfileDefinition] {
        &self.definitions
    }
    pub fn canonical_frame(&self) -> Result<Vec<u8>, GenesisError> {
        let values = self
            .definitions
            .iter()
            .map(|x| x.value())
            .collect::<Result<Vec<_>, _>>()?;
        c::frame(
            "NETWORK.ACTIVATED-PROFILES",
            ProfileRef {
                name: "APQE-PROFILE-SET",
                revision: 1,
            },
            None,
            Value::Array(values),
            1024 * 1024,
        )
        .map_err(|_| GenesisError::Encoding)
    }
    pub fn commitment(&self) -> Result<[u8; 64], GenesisError> {
        Primitives
            .hash(HashAlgorithm::Sha3512, &self.canonical_frame()?)
            .map_err(|_| GenesisError::Primitive)?
            .try_into()
            .map_err(|_| GenesisError::Primitive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn matrix(n: u8) -> PlatformArtifactMatrix {
        PlatformArtifactMatrix::darwin_public_validation_only(
            super::super::artifact_matrix::ArtifactPins {
                mldsa65: [n; 32],
                mldsa87: [n; 32],
                mlkem1024: [n; 32],
            },
        )
    }
    fn defs() -> Vec<ProfileDefinition> {
        ProfileKind::ALL
            .into_iter()
            .map(|k| ProfileDefinition::from_target_matrix(k, matrix(7)).unwrap())
            .collect()
    }
    #[test]
    fn received_catalog_maps_exact_schema_matrix_and_rejects_unknowns() {
        let catalog = ProfileCatalog::new(defs()).unwrap();
        let bytes = catalog.canonical_frame().unwrap();
        assert_eq!(
            ProfileCatalog::from_received_frame(&bytes).unwrap(),
            catalog
        );
        let mut changed = Value::decode(&bytes, 1024 * 1024).unwrap();
        let Value::Array(ref mut frame) = changed else {
            panic!()
        };
        let Value::Array(ref mut rows) = frame[4] else {
            panic!()
        };
        let Value::Array(ref mut definition) = rows[0] else {
            panic!()
        };
        definition[3] = c::bytes(b"unapproved-schema");
        assert!(
            ProfileCatalog::from_received_frame(&changed.encode(1024 * 1024).unwrap()).is_err()
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProfileCatalog::from_received_frame(&trailing).is_err());
        assert!(ProfileCatalog::from_received_frame(&vec![0; 1024 * 1024 + 1]).is_err());
    }
    #[test]
    fn closed_catalog_rejects_changed_schema_missing_duplicate_and_order() {
        let a = ProfileCatalog::new(defs()).unwrap();
        assert_ne!(a.commitment().unwrap(), [0; 64]);
        let mut x = defs();
        x[0].schema_digest[0] ^= 1;
        assert!(ProfileCatalog::new(x).is_err());
        let mut x = defs();
        x.pop();
        assert!(ProfileCatalog::new(x).is_err());
        let mut x = defs();
        x.swap(0, 1);
        assert!(ProfileCatalog::new(x).is_err());
        let mut x = defs();
        x[1] = x[0].clone();
        assert!(ProfileCatalog::new(x).is_err());
        assert!(ProfileDefinition::from_target_matrix(ProfileKind::Genesis, matrix(0)).is_err());
        let b = ProfileCatalog::new(
            ProfileKind::ALL
                .into_iter()
                .map(|k| ProfileDefinition::from_target_matrix(k, matrix(8)).unwrap())
                .collect(),
        )
        .unwrap();
        assert_ne!(a.commitment().unwrap(), b.commitment().unwrap());
    }
}
