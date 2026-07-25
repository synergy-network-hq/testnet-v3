use std::{env, path::PathBuf};

fn feature_enabled(name: &str) -> bool {
    env::var_os(format!("CARGO_FEATURE_{}", name.to_ascii_uppercase())).is_some()
}

fn compile_static_lib(name: &str, include_dirs: &[PathBuf], sources: &[PathBuf]) {
    let mut build = cc::Build::new();
    build
        .warnings(false)
        .flag_if_supported("-O3")
        .flag_if_supported("-std=c99");

    for inc in include_dirs {
        build.include(inc);
    }

    for src in sources {
        build.file(src);
    }

    build.compile(name);
}

fn collect_sources(dir: &PathBuf, exclude: &[&str]) -> Vec<PathBuf> {
    let mut out = vec![];
    // Collect C sources and assembly (.S) sources. We intentionally do NOT
    // collect lowercase .s to avoid accidental inclusion of non-preprocessed assembly.
    for ext in ["c", "S"] {
        let pattern = format!("{}/**/*.{}", dir.display(), ext);
        for entry in glob::glob(&pattern).expect("glob failed") {
            let p = entry.expect("glob entry failed");

            // Get path as string for exclusion checks
            let path_str = p.to_string_lossy().to_lowercase();

            // Skip if path contains test directories or files
            if path_str.contains("/test/")
                || path_str.contains("\\test\\")
                || path_str.contains("/tests/")
                || path_str.contains("\\tests\\")
            {
                continue;
            }

            // Check if file should be excluded by name
            let file_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if exclude.iter().any(|&ex| file_name.contains(ex)) {
                continue;
            }

            // Skip test files, KAT generators, and speed test utilities
            if file_name.contains("test")
                || file_name.contains("KAT")
                || file_name.contains("PQCgen")
                || file_name.contains("speed")
                || file_name.contains("cpucycles")
                || file_name.contains("benchmark")
            {
                continue;
            }

            out.push(p);
        }
    }
    out.sort();
    out
}

fn main() {
    // Teach rustc about these custom cfg knobs (prevents "unexpected cfg" warnings)
    // and allows architecture-gated codepaths in the generated PQClean Rust bindings.
    println!("cargo:rustc-check-cfg=cfg(enable_x86_avx2)");
    println!("cargo:rustc-check-cfg=cfg(enable_aarch64_neon)");

    // Set cfg flags based on target architecture (feature-gated code additionally requires
    // the corresponding Cargo feature like `avx2`/`neon` to actually be used).
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "x86_64" && feature_enabled("avx2") {
        println!("cargo:rustc-cfg=enable_x86_avx2");
    }
    if target_arch == "aarch64" && feature_enabled("neon") {
        println!("cargo:rustc-cfg=enable_aarch64_neon");
    }

    // Rebuild if sources change
    println!("cargo:rerun-if-changed=pqclean/");
    println!("cargo:rerun-if-changed=vendor/pqcrypto-internals/");
    println!("cargo:rerun-if-changed=vendor/pqnist/");
    println!("cargo:rerun-if-changed=build.rs");

    // PQClean source root (kept vendored in this crate)
    let pqclean_root = PathBuf::from("pqclean");
    let pqclean_common = pqclean_root.join("common");

    // Shared C primitives provided by pqcrypto-internals (randombytes, fips202, sha2, ...)
    // We compile only the scheme-specific sources from PQClean, and rely on pqcrypto-internals
    // for shared primitives to avoid duplicate symbol definitions across static libs.
    let pqcrypto_internals_include = PathBuf::from("vendor")
        .join("pqcrypto-internals")
        .join("include");

    // Which optimized implementations should we build?
    let enable_avx2 = target_arch == "x86_64" && feature_enabled("avx2");
    let enable_aarch64 = target_arch == "aarch64" && feature_enabled("neon");

    if feature_enabled("mlkem") {
        // The NIST Kyber/ML-KEM reference implementation namespaces its SHAKE/SHA3
        // functions behind `pqcrystals_fips202_ref_*` symbols (via fips202.h macros).
        // We compile those symbols ONCE into a shared static lib to avoid duplicate
        // definitions across ml-kem-{512,768,1024}_clean.
        let pqcrystals_fips202_ref_dir = PathBuf::from("vendor")
            .join("pqnist")
            .join("NIST-ml-kem")
            .join("Reference_Implementation")
            .join("crypto_kem")
            .join("kyber512");
        if pqcrystals_fips202_ref_dir.exists() {
            println!(
                "cargo:rerun-if-changed={}",
                pqcrystals_fips202_ref_dir.join("fips202.c").display()
            );
            compile_static_lib(
                "pqcrystals_fips202_ref",
                &[pqcrystals_fips202_ref_dir.clone()],
                &[pqcrystals_fips202_ref_dir.join("fips202.c")],
            );
        } else {
            eprintln!(
                "Warning: NIST fips202 reference directory not found: {}",
                pqcrystals_fips202_ref_dir.display()
            );
        }

        // ML-KEM implementations (NIST reference implementations, vendored under vendor/pqnist).
        //
        // Important: We compile the NIST reference sources into the *existing* library names that
        // the generated Rust FFI expects (`ml-kem-512_clean`, etc.) and provide small C wrappers
        // that export the `PQCLEAN_*` symbols.
        //
        // We deliberately do NOT compile the NIST `rng.c` / `fips202.c` / `sha*` sources to avoid
        // duplicate symbols. Shared primitives come from `pqcrypto-internals`.

        let nist_mlkem_root = PathBuf::from("vendor")
            .join("pqnist")
            .join("NIST-ml-kem")
            .join("Reference_Implementation")
            .join("crypto_kem");

        let wrappers_dir = PathBuf::from("vendor").join("nist_wrappers");

        let mlkem_configs = [
            (
                "ml-kem-512",
                "kyber512",
                "ml-kem-512_clean.c",
                "ml-kem-512_avx2_forward.c",
                "ml-kem-512_aarch64_forward.c",
            ),
            (
                "ml-kem-768",
                "kyber768",
                "ml-kem-768_clean.c",
                "ml-kem-768_avx2_forward.c",
                "ml-kem-768_aarch64_forward.c",
            ),
            (
                "ml-kem-1024",
                "kyber1024",
                "ml-kem-1024_clean.c",
                "ml-kem-1024_avx2_forward.c",
                "ml-kem-1024_aarch64_forward.c",
            ),
        ];

        for (scheme, nist_subdir, clean_wrapper, avx2_fwd, aarch64_fwd) in mlkem_configs {
            let nist_dir = nist_mlkem_root.join(nist_subdir);
            if !nist_dir.exists() {
                eprintln!(
                    "Warning: NIST ML-KEM directory not found: {}",
                    nist_dir.display()
                );
                continue;
            }

            // Clean lib: compile NIST reference sources + PQClean-symbol wrapper.
            let mut sources = collect_sources(
                &nist_dir,
                &["rng.c", "fips202.c", "sha256.c", "sha512.c", "speed_print"],
            );
            sources.push(wrappers_dir.join(clean_wrapper));

            let include_dirs = vec![pqcrypto_internals_include.clone(), nist_dir.clone()];
            compile_static_lib(&format!("{}_clean", scheme), &include_dirs, &sources);

            // Optimized libs (avx2/aarch64): forwarders that call the clean PQCLEAN_* symbols.
            if enable_avx2 {
                compile_static_lib(
                    &format!("{}_avx2", scheme),
                    &[],
                    &[wrappers_dir.join(avx2_fwd)],
                );
            }
            if enable_aarch64 {
                compile_static_lib(
                    &format!("{}_aarch64", scheme),
                    &[],
                    &[wrappers_dir.join(aarch64_fwd)],
                );
            }
        }
    }

    if feature_enabled("fndsa") {
        // FN-DSA (Falcon) implementations (PQClean), including padded variants
        let fndsa_configs = [
            "falcon-512",
            "falcon-padded-512",
            "falcon-1024",
            "falcon-padded-1024",
        ];

        for scheme in fndsa_configs {
            // Always build the clean implementation.
            let clean_dir = pqclean_root.join("crypto_sign").join(scheme).join("clean");
            if clean_dir.exists() {
                let sources = collect_sources(&clean_dir, &[]);
                let include_dirs = vec![
                    clean_dir.clone(),
                    pqcrypto_internals_include.clone(),
                    pqclean_common.clone(),
                ];
                compile_static_lib(&format!("{}_clean", scheme), &include_dirs, &sources);
            } else {
                eprintln!(
                    "Warning: PQClean directory not found: {}",
                    clean_dir.display()
                );
            }

            // Optional optimized implementations.
            if enable_avx2 {
                let avx2_dir = pqclean_root.join("crypto_sign").join(scheme).join("avx2");
                if avx2_dir.exists() {
                    let sources = collect_sources(&avx2_dir, &[]);
                    let include_dirs = vec![
                        avx2_dir.clone(),
                        pqcrypto_internals_include.clone(),
                        pqclean_common.clone(),
                    ];
                    compile_static_lib(&format!("{}_avx2", scheme), &include_dirs, &sources);
                }
            }
            if enable_aarch64 {
                let aarch64_dir = pqclean_root
                    .join("crypto_sign")
                    .join(scheme)
                    .join("aarch64");
                if aarch64_dir.exists() {
                    let sources = collect_sources(&aarch64_dir, &[]);
                    let include_dirs = vec![
                        aarch64_dir.clone(),
                        pqcrypto_internals_include.clone(),
                        pqclean_common.clone(),
                    ];
                    compile_static_lib(&format!("{}_aarch64", scheme), &include_dirs, &sources);
                }
            }
        }
    }
}
