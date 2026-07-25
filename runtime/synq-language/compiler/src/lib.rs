#[macro_use]
extern crate pest_derive;

pub mod artifacts;
pub mod ast;
pub mod codegen;
pub mod parser;
pub mod pqc_integration;
pub mod semantic;
pub mod solidity_gen;
pub mod version;

pub use artifacts::{
    ArtifactBundle, ArtifactConfig, ArtifactHashes, SynQAbiArtifact, SynQManifestArtifact,
};
pub use codegen::CodeGenerator;
pub use parser::parse;
pub use pqc_integration::PqcIntegration;
pub use semantic::analyze;
pub use solidity_gen::{SolidityGenerator, SOLIDITY_COMPATIBILITY_WARNING};
pub use version::{get_compiler_version, Version, VersionRequirement};
