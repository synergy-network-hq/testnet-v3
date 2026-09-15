use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiCapability {
    Inference,
    Embeddings,
    Multimodal,
    Training,
    FineTuning,
    BoundedAgent,
    Routing,
    Scheduling,
    Metering,
    FederatedCoordination,
    ModelRepository,
    DatasetProvenance,
    VectorMemory,
    Assurance,
}
