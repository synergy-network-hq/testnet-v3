extern crate cc;
extern crate glob;

use std::env;
use std::path::{Path, PathBuf};

macro_rules! build_clean {
    ($variant:expr) => {
        let internals_include_path = &std::env::var("DEP_PQRUST_INTERNALS_INCLUDEPATH").unwrap();
        let common_dir = Path::new("pqclean/common");

        let mut builder = cc::Build::new();
        let target_dir: PathBuf = ["pqclean", "crypto_kem", $variant, "clean"]
            .iter()
            .collect();
        let target = env::var("TARGET").unwrap_or_default();
        if target == "wasm32-wasip1" {
            builder.target("wasm32-wasi");
        }

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        if target_os == "wasi" {
            if let Ok(wasi_sdk_path) = std::env::var("WASI_SDK_DIR") {
                builder.flag(format!("--sysroot={}", wasi_sdk_path).as_str());
            } else if let Ok(wasi_sysroot) = std::env::var("WASI_SYSROOT") {
                builder.flag(format!("--sysroot={}", wasi_sysroot).as_str());
            } else {
                println!(
                    "cargo:warning=WASI target detected but neither WASI_SDK_DIR nor WASI_SYSROOT is set; C compilation may fail."
                );
            }
        }

        let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();

        builder
            .include(internals_include_path)
            .include(&common_dir)
            .include(target_dir)
            .files(
                scheme_files
                    .into_iter()
                    .map(|p| p.unwrap().to_string_lossy().into_owned()),
            );
        builder.compile(format!("{}_clean", $variant).as_str());
    };
}

fn main() {
    #[allow(unused_variables)]
    let aes_enabled = env::var("CARGO_FEATURE_AES").is_ok();
    #[allow(unused_variables)]
    let avx2_enabled = env::var("CARGO_FEATURE_AVX2").is_ok();
    #[allow(unused_variables)]
    let neon_enabled = env::var("CARGO_FEATURE_NEON").is_ok();
    #[allow(unused_variables)]
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    #[allow(unused_variables)]
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    #[allow(unused_variables)]
    let is_windows = target_os == "windows";
    #[allow(unused_variables)]
    let is_macos = target_os == "macos";

    build_clean!("hqc-128");
    build_clean!("hqc-192");
    build_clean!("hqc-256");
}
