extern crate cc;
extern crate dunce;

use std::env;
use std::path::Path;

fn wasm_c_target(rust_target: &str) -> &str {
    match rust_target {
        // Clang toolchains generally recognize `wasm32-wasi`, while Rust uses
        // `wasm32-wasip1` for the target triple.
        "wasm32-wasip1" => "wasm32-wasi",
        _ => rust_target,
    }
}

fn wasi_sysroot() -> Option<String> {
    env::var("WASI_SDK_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            env::var("WASI_SYSROOT")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
}

fn main() {
    let includepath = dunce::canonicalize(Path::new("include")).unwrap();
    println!("cargo:includepath={}", includepath.to_str().unwrap());

    let cfiledir = Path::new("cfiles");
    let common_files = vec![
        cfiledir.join("fips202.c"),
        cfiledir.join("aes.c"),
        cfiledir.join("sha2.c"),
        cfiledir.join("nistseedexpander.c"),
        cfiledir.join("sp800-185.c"),
    ];

    println!("cargo:rerun-if-changed=cfiles/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");

    let mut build = cc::Build::new();

    let target = env::var("TARGET").unwrap_or_default();
    let c_target = wasm_c_target(&target);
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "wasi" {
        if let Some(wasi_sysroot) = wasi_sysroot() {
            build.flag(format!("--sysroot={wasi_sysroot}").as_str());
        } else {
            println!(
                "cargo:warning=WASI target detected but neither WASI_SDK_DIR nor WASI_SYSROOT is set; C compilation may fail."
            );
        }
    }
    build.target(c_target);

    build
        .include(&includepath)
        .files(common_files)
        .compile("pqclean_common");
    println!("cargo:rustc-link-lib=pqclean_common");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let mut builder = cc::Build::new();
    builder.target(c_target);

    if target_os == "wasi" {
        if let Some(wasi_sysroot) = wasi_sysroot() {
            builder.flag(format!("--sysroot={wasi_sysroot}").as_str());
        }
    }

    if target_arch == "x86" || target_arch == "x86_64" {
        if target_env == "msvc" {
            builder.flag("/arch:AVX2");
        } else {
            builder.flag("-mavx2");
        }
        builder
            .file(
                cfiledir
                    .join("keccak4x")
                    .join("KeccakP-1600-times4-SIMD256.c"),
            )
            .compile("keccak4x");
        println!("cargo:rustc-link-lib=keccak4x")
    } else if target_arch == "aarch64" && target_env != "msvc" {
        builder
            .flag("-march=armv8.2-a+sha3")
            .file(cfiledir.join("keccak2x").join("fips202x2.c"))
            .file(cfiledir.join("keccak2x").join("feat.S"))
            .compile("keccak2x");
        println!("cargo:rustc-link-lib=keccak2x")
    }
}
