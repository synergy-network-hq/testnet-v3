use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentBlindOrderKey(pub EtdagDigest);

pub fn derive_content_blind_order_key(
    order_seed: &EtdagDigest,
    vertex_id: &EtdagDigest,
) -> Result<ContentBlindOrderKey, EtdagError> {
    order_seed.validate()?;
    vertex_id.validate()?;
    EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_CONTENT_BLIND_ORDER_KEY_V1",
        &(order_seed, vertex_id),
    )
    .map(ContentBlindOrderKey)
}
