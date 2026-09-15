//! SynQ key and signature wrapper types.

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQPublicKey {
    pub bytes: Vec<u8>,
}

impl SynQPublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQPrivateKeyRef {
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQSignature {
    pub bytes: Vec<u8>,
}

impl SynQSignature {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}
