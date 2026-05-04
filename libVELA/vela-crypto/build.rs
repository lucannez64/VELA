use std::{env, path::PathBuf, process::Command};

fn main() {
    if env::var_os("CARGO_FEATURE_CYCLO_FFI").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // vela-crypto/ lives next to cyclo/ inside libVELA/
    let cyclo_dir = manifest_dir.parent().unwrap().join("cyclo");

    // Use ReleaseSafe for debug Rust builds (keeps bounds/safety checks, avoids
    // GNU stack-protector symbols that are absent from the MSVC linker).
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let zig_optimize = if profile == "release" {
        "ReleaseFast"
    } else {
        "ReleaseSafe"
    };

    // Detect cross-compilation target (set by Cargo when --target is used).
    // Only pass -Dtarget to zig for Android cross-compile; native/other targets
    // use the default host target.
    let cargo_target = env::var("TARGET").ok();
    let host_target = env::var("HOST").ok();
    let is_cross = cargo_target.as_deref() != host_target.as_deref();
    let rust_target_for_zig = is_cross
        .then(|| cargo_target.as_deref())
        .flatten()
        .and_then(rust_to_zig_android_target);

    // Build the Zig cyclo static library (also builds ntt_shim internally).
    let mut zig_args = vec!["build".to_string(), format!("-Doptimize={zig_optimize}")];
    if let Some(zt) = &rust_target_for_zig {
        zig_args.push(format!("-Dtarget={zt}"));
    }
    if is_cross {
        if let Some(rt) = &cargo_target {
            zig_args.push(format!("-Drust-target={rt}"));
        }
    }
    let status = Command::new("zig")
        .args(&zig_args)
        .current_dir(&cyclo_dir)
        .status()
        .expect("failed to invoke `zig build` — is Zig installed?");
    assert!(
        status.success(),
        "`zig build` exited with a non-zero status"
    );

    // Library output paths produced by `zig build`.
    let zig_lib_dir = cyclo_dir.join("zig-out/lib");
    let ntt_lib_dir = match (is_cross, &cargo_target) {
        (true, Some(t)) => cyclo_dir
            .join("ntt_shim")
            .join("target")
            .join(t)
            .join("release"),
        _ => cyclo_dir.join("ntt_shim/target/release"),
    };

    println!("cargo:rustc-link-search=native={}", zig_lib_dir.display());
    println!("cargo:rustc-link-search=native={}", ntt_lib_dir.display());
    println!("cargo:rustc-link-lib=static=cyclo");
    println!("cargo:rustc-link-lib=static=ntt_shim");

    // Windows system libraries required by ntt_shim (Rust/tfhe-ntt).
    // Use CARGO_CFG_TARGET_OS rather than #[cfg(target_os)] because the
    // latter reflects the *host* OS, not the target. On a Windows host
    // building for Android we must not emit Windows linker flags.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=userenv");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ntdll");
    }

    // Re-run when the Cyclo FFI surface or this script changes.
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        cyclo_dir.join("src/cyclo_ffi.zig").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cyclo_dir.join("src/root.zig").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cyclo_dir.join("src/compat_msvc.zig").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cyclo_dir.join("src/compat_msvc_win.zig").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cyclo_dir.join("build.zig").display()
    );
}

fn rust_to_zig_android_target(rust_target: &str) -> Option<&str> {
    match rust_target {
        "aarch64-linux-android" => Some("aarch64-linux-android"),
        "armv7-linux-androideabi" => Some("arm-linux-androideabi"),
        "i686-linux-android" => Some("x86-linux-android"),
        "x86_64-linux-android" => Some("x86_64-linux-android"),
        _ => None,
    }
}
