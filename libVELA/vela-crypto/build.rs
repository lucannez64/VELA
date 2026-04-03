use std::{env, path::PathBuf, process::Command};

fn main() {
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

    // Build the Zig cyclo static library (also builds ntt_shim internally).
    let status = Command::new("zig")
        .args(["build", &format!("-Doptimize={zig_optimize}")])
        .current_dir(&cyclo_dir)
        .status()
        .expect("failed to invoke `zig build` — is Zig installed?");
    assert!(status.success(), "`zig build` exited with a non-zero status");

    // Library output paths produced by `zig build`.
    let zig_lib_dir = cyclo_dir.join("zig-out/lib");
    let ntt_lib_dir = cyclo_dir.join("ntt_shim/target/release");

    println!("cargo:rustc-link-search=native={}", zig_lib_dir.display());
    println!("cargo:rustc-link-search=native={}", ntt_lib_dir.display());
    println!("cargo:rustc-link-lib=static=cyclo");
    println!("cargo:rustc-link-lib=static=ntt_shim");

    // Windows system libraries required by ntt_shim (Rust/tfhe-ntt).
    #[cfg(target_os = "windows")]
    {
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
}
