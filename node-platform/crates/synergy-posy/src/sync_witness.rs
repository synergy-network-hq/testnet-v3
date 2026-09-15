use serde::{Deserialize, Serialize};

use crate::{SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate};

/// Complete consensus evidence needed to replay the three certified heights
/// that finalize one execution candidate through the single PoSy driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalitySyncWitness {
    pub quorum_certificates: [SimplifiedQuorumCertificate; 3],
    pub timeout_certificates: Vec<SimplifiedTimeoutCertificate>,
}
