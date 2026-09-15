use serde::{Deserialize, Serialize};

use crate::ADDRESS_TOTAL_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierClass {
    KeyControlledAddress,
    ObjectAddress,
    TypedIdentifier,
    ReservedNamespace,
}

impl IdentifierClass {
    pub const fn is_native_address(self) -> bool {
        matches!(self, Self::KeyControlledAddress | Self::ObjectAddress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceStatus {
    Active,
    Reserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Namespace {
    pub prefix: &'static str,
    pub classification: IdentifierClass,
    pub status: NamespaceStatus,
    pub data_symbols: usize,
}

impl Namespace {
    const fn new(
        prefix: &'static str,
        classification: IdentifierClass,
        status: NamespaceStatus,
    ) -> Self {
        Self {
            prefix,
            classification,
            status,
            data_symbols: ADDRESS_TOTAL_LENGTH - prefix.len() - 1 - super::bech32m::CHECKSUM_SYMBOLS,
        }
    }
}

const fn active(prefix: &'static str, classification: IdentifierClass) -> Namespace {
    Namespace::new(prefix, classification, NamespaceStatus::Active)
}

const fn reserved(prefix: &'static str) -> Namespace {
    Namespace::new(
        prefix,
        IdentifierClass::ReservedNamespace,
        NamespaceStatus::Reserved,
    )
}

pub fn namespace(prefix: &str) -> Option<&'static Namespace> {
    match prefix {
        "synw" => Some(&active("synw", IdentifierClass::KeyControlledAddress)),
        "syns" => Some(&active("syns", IdentifierClass::KeyControlledAddress)),
        "syna" => Some(&active("syna", IdentifierClass::KeyControlledAddress)),
        "synz" => Some(&active("synz", IdentifierClass::KeyControlledAddress)),
        "syntxn" => Some(&active("syntxn", IdentifierClass::TypedIdentifier)),
        "synxxn" => Some(&active("synxxn", IdentifierClass::TypedIdentifier)),
        "synb1" => Some(&active("synb1", IdentifierClass::ObjectAddress)),
        "synb2" => Some(&active("synb2", IdentifierClass::ObjectAddress)),
        "synb3" => Some(&active("synb3", IdentifierClass::ObjectAddress)),
        "synn1" => Some(&active("synn1", IdentifierClass::ObjectAddress)),
        "synn2" => Some(&active("synn2", IdentifierClass::ObjectAddress)),
        "synj" => Some(&active("synj", IdentifierClass::ObjectAddress)),
        "synk" => Some(&active("synk", IdentifierClass::ObjectAddress)),
        "synq" => Some(&active("synq", IdentifierClass::ObjectAddress)),
        "sync" => Some(&active("sync", IdentifierClass::ObjectAddress)),
        "synv1" => Some(&active("synv1", IdentifierClass::KeyControlledAddress)),
        "synv2" => Some(&active("synv2", IdentifierClass::KeyControlledAddress)),
        "synv3" => Some(&active("synv3", IdentifierClass::KeyControlledAddress)),
        "synv4" => Some(&active("synv4", IdentifierClass::KeyControlledAddress)),
        "synv5" => Some(&active("synv5", IdentifierClass::KeyControlledAddress)),
        "syngrp1" => Some(&active("syngrp1", IdentifierClass::ObjectAddress)),
        "syngrp2" => Some(&active("syngrp2", IdentifierClass::ObjectAddress)),
        "syngrp3" => Some(&active("syngrp3", IdentifierClass::ObjectAddress)),
        "syngrp4" => Some(&active("syngrp4", IdentifierClass::ObjectAddress)),
        "syngrp5" => Some(&active("syngrp5", IdentifierClass::ObjectAddress)),
        "syndao" => Some(&active("syndao", IdentifierClass::TypedIdentifier)),
        "syno" => Some(&active("syno", IdentifierClass::KeyControlledAddress)),
        "syny" => Some(&active("syny", IdentifierClass::KeyControlledAddress)),
        "synm" => Some(&active("synm", IdentifierClass::KeyControlledAddress)),
        "synu" => Some(&active("synu", IdentifierClass::KeyControlledAddress)),
        "synl" => Some(&active("synl", IdentifierClass::KeyControlledAddress)),
        "synf" => Some(&active("synf", IdentifierClass::ObjectAddress)),
        "synr" => Some(&reserved("synr")),
        "syni" => Some(&reserved("syni")),
        "synp" => Some(&reserved("synp")),
        "syne" => Some(&reserved("syne")),
        _ => None,
    }
}
