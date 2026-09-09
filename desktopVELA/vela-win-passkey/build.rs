//! Build script: embed `msix/vela-passkey-provider.manifest` as the Win32
//! manifest resource (RT_MANIFEST, id 1) of the *provider binary only*.
//!
//! Why the exe: Windows grants a process *package identity* only when its
//! manifest carries the `msix` element matching a registered identity
//! (sparse) package — and `WebAuthNPluginAddAuthenticator` refuses any caller
//! without identity (0x80073D54).
//!
//! Why only the bin: a process whose manifest claims identity that it cannot
//! resolve (tests, examples — anything outside the registered external
//! location) gets its classic-COM catalog lookups routed through the package
//! view, which makes `CoCreateInstance` of our own class fail. `cargo:rustc-
//! link-arg-bins` applies the resource to binaries of this package only, so
//! the provider gets identity and every other target stays classic.

use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let manifest = crate_dir.join("msix").join("vela-passkey-provider.manifest");
    if !manifest.exists() {
        // The msix/ directory is optional in a source checkout that only
        // wants the library; the exe will run without package identity and
        // registration will explain itself.
        eprintln!(
            "vela-win-passkey: {} missing; the provider exe will have no \
             package identity (system registration will be refused)",
            manifest.display()
        );
        return;
    }

    let Some(rc) = locate_rc() else {
        eprintln!(
            "vela-win-passkey: rc.exe not found (Windows SDK); the provider exe \
             will have no package identity and system registration will be refused"
        );
        return;
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc_file = out_dir.join("vela-provider-manifest.rc");
    let res_file = out_dir.join("vela-provider-manifest.res");
    // RT_MANIFEST (24), resource id 1 — the standard executable manifest id,
    // which also overrides rustc's default no-identity manifest.
    std::fs::write(
        &rc_file,
        format!("1 24 \"{}\"\n", manifest.display().to_string().replace('\\', "\\\\")),
    )
    .expect("write rc source");

    let status = std::process::Command::new(&rc)
        .args(["/nologo", "/fo"])
        .arg(&res_file)
        .arg(&rc_file)
        .output()
        .expect("run rc.exe");
    if !status.status.success() {
        eprintln!(
            "vela-win-passkey: rc.exe failed ({}); the provider exe will have no \
             package identity",
            String::from_utf8_lossy(&status.stderr)
        );
        return;
    }

    // Bins of this package only — never tests/examples (see module comment).
    println!("cargo:rustc-link-arg-bins={}", res_file.display());
}

/// rc.exe in the newest installed Windows SDK ( Kits\\10\\bin\\<ver>\\<arch> ).
fn locate_rc() -> Option<PathBuf> {
    let kits = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<_> = std::fs::read_dir(&kits)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    versions.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    for version in versions {
        for arch in ["x64", "x86"] {
            let candidate = version.path().join(arch).join("rc.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}
