//! `vela-passkey-provider.exe` — the Windows passkey provider process.
//!
//! Entry points:
//!
//! - (no args) / `-Embedding` — run the COM server. This is how the OS starts
//!   it when a WebAuthn client begins a ceremony routed to VELA.
//! - `--register` / `--unregister` / `--status` / `--sync-credentials` —
//!   manage the system registration (the desktop settings UI shells out to
//!   these: the provider carries package identity, the desktop cannot call
//!   `WebAuthNPluginAddAuthenticator` itself). `--json` makes any of them
//!   print a machine-readable result.
//! - `--whoami` — identity diagnostic.
//!
//! `--register` is two-stage when needed: without package identity it first
//! registers the sparse identity package shipped next to the exe, then
//! re-execs itself (identity binds at process *start*), and only then calls
//! `WebAuthNPluginAddAuthenticator`.

use vela_win_passkey::{
    ffi::WebAuthn, refresh_credential_cache, register, unregister, ProviderStatus,
};

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let primary = args
        .iter()
        .find(|a| {
            matches!(
                a.as_str(),
                "--register"
                    | "--unregister"
                    | "--status"
                    | "--sync-credentials"
                    | "--whoami"
                    | "-Embedding"
                    | "--serve"
            )
        })
        .map(String::as_str);
    let code = match primary {
        None | Some("-Embedding") | Some("--serve") => serve(),
        Some("--whoami") => whoami_cmd(),
        Some("--register") => register_cmd(json, &args),
        Some("--unregister") => unregister_cmd(json),
        Some("--status") => status_cmd(json),
        Some("--sync-credentials") => sync_cmd(json),
        Some(other) => {
            eprintln!("Unknown argument: {other}");
            eprintln!("usage: vela-passkey-provider [--register|--unregister|--status|--sync-credentials|--whoami|-Embedding] [--json]");
            2
        }
    };
    std::process::exit(code);
}

// ── package identity ────────────────────────────────────────────────────────

/// Does this process carry package identity right now?
fn has_identity() -> bool {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentPackageFullName(packagefullnamelength: *mut u32, packagefullname: *mut u16)
        -> i32;
    }
    unsafe {
        let mut len: u32 = 0;
        // APPMODEL_ERROR_NO_PACKAGE (15700) is the only "no identity" answer.
        GetCurrentPackageFullName(&mut len, std::ptr::null_mut()) != 15700
    }
}

/// Register the sparse identity package (msix) shipped next to the exe.
///
/// The OS refuses `WebAuthNPluginAddAuthenticator` from a process without
/// package identity (0x80073D54), and identity binds at process *start* — so
/// after registering the package this process must exit and a fresh one does
/// the platform registration.
fn register_identity_package() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot resolve exe: {e}"))?;
    let dir = exe.parent().ok_or_else(|| "exe has no directory".to_string())?;
    let candidates = [
        // Installed layout (packager resource) and dev flat layout.
        dir.join("passkey-provider").join("VELA.PasskeyProvider.msix"),
        dir.join("VELA.PasskeyProvider.msix"),
        // Dev checkout fallback: the msix build lands in msix/build/.
        dir.join("..")
            .join("desktopVELA")
            .join("vela-win-passkey")
            .join("msix")
            .join("build")
            .join("VELA.PasskeyProvider.msix"),
    ];
    let msix = candidates
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            "VELA.PasskeyProvider.msix not found next to the provider exe (the \
             installer must ship it in passkey-provider/)"
                .to_string()
        })?
        .clone();
    // The external location must be the directory the package's referenced
    // files were staged in: the msix's own directory in both layouts.
    let external = msix
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dir.to_path_buf());

    // Re-register cleanly when a previous version exists: the deployment
    // service refuses the same version twice.
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-AppxPackage VELA.PasskeyProvider | Remove-AppxPackage",
        ])
        .status();

    let ps = format!(
        "Add-AppxPackage -Path '{}' -ExternalLocation '{}'",
        msix.display(),
        external.display()
    );
    let status = std::process::Command::new("powershell")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps,
        ])
        .status()
        .map_err(|e| format!("could not run powershell: {e}"))?;
    if !status.success() {
        return Err(format!(
            "identity package registration failed (exit {:?}). If the error is \
             CERT_E_UNTRUSTEDROOT, the .msix must be signed by a certificate the \
             machine trusts — production installers ship it pre-signed; for dev, \
             use msix/register-dev.ps1",
            status.code()
        ));
    }
    Ok(())
}

// ── commands ────────────────────────────────────────────────────────────────

/// Diagnostic: does this process have package identity at runtime?
/// (kernel32.GetCurrentPackageFullName; APPMODEL_ERROR_NO_PACKAGE if none.)
fn whoami_cmd() -> i32 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentPackageFullName(
            packagefullnamelength: *mut u32,
            packagefullname: *mut u16,
        ) -> i32;
    }
    unsafe {
        let mut len: u32 = 0;
        let rc = GetCurrentPackageFullName(&mut len, std::ptr::null_mut());
        if rc == 15700 {
            println!("No package identity (APPMODEL_ERROR_NO_PACKAGE).");
            return 1;
        }
        if rc != 0 && rc != 122 {
            println!("GetCurrentPackageFullName failed: {rc}");
            return 1;
        }
        let mut buf = vec![0u16; len as usize];
        let mut l2 = len;
        let rc2 = GetCurrentPackageFullName(&mut l2, buf.as_mut_ptr());
        if rc2 != 0 {
            println!("GetCurrentPackageFullName failed (2nd call): {rc2}");
            return 1;
        }
        println!(
            "Package identity: {}",
            String::from_utf16_lossy(&buf[..(l2 - 1) as usize])
        );
        0
    }
}

fn serve() -> i32 {
    let Some(webauthn) = WebAuthn::load() else {
        eprintln!(
            "VELA passkey provider: webauthn.dll plugin API unavailable on this Windows build"
        );
        return 1;
    };
    match vela_win_passkey::com::run(webauthn) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("VELA passkey provider: COM server failed: {e}");
            1
        }
    }
}

fn register_cmd(json: bool, args: &[String]) -> i32 {
    // Stage 1: without identity, bootstrap the package, then re-exec.
    // `--stage2` marks the re-exec: if identity still is not bound then, the
    // exe is outside the package's external location and re-trying would
    // loop forever — fail with the reason instead.
    let stage2 = args.iter().any(|a| a == "--stage2");
    if !has_identity() {
        if stage2 {
            let message = "the identity package is registered but this exe is not \
                           inside its registered external location; re-run the \
                           installer or msix/register-dev.ps1 with this exe's \
                           directory";
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": message }));
            } else {
                eprintln!("Registration failed: {message}");
            }
            return 1;
        }
        if json {
            // The bootstrap is invisible plumbing; report its failure as any
            // other and let stage 2 produce the JSON verdict.
        } else {
            println!("Bootstrapping package identity...");
        }
        if let Err(e) = register_identity_package() {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("Registration failed: {e}");
            }
            return 1;
        }
        let exe = std::env::current_exe().unwrap();
        let mut stage2_args = vec!["--register".to_string(), "--stage2".to_string()];
        if json {
            stage2_args.push("--json".to_string());
        }
        return match std::process::Command::new(exe)
            .args(&stage2_args)
            .status()
        {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                let message = format!("could not re-exec for stage 2: {e}");
                if json {
                    println!("{}", serde_json::json!({ "ok": false, "error": message }));
                } else {
                    eprintln!("Registration failed: {message}");
                }
                1
            }
        };
    }

    // Stage 2: identity present — the real platform registration.
    match register() {
        Ok(status) => {
            // Best-effort autofill sync so freshly-registered providers show
            // existing passkeys immediately; a locked or absent desktop only
            // means the user syncs later.
            let synced = match vela_win_passkey::desktop::all_passkeys() {
                Ok(credentials) => vela_win_passkey::refresh_credential_cache(&credentials).ok(),
                Err(_) => None,
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "com_registered": status.com_registered,
                        "os_registered": status.os_registered,
                        "enabled": status.enabled,
                        "synced": synced,
                    })
                );
            } else {
                print_status(&status);
                match synced {
                    Some(n) => println!("Synced {n} passkey(s) to the OS autofill cache."),
                    None => println!("Autofill sync skipped (desktop unreachable or locked)."),
                }
                println!("Registered. Enable VELA under Settings → Accounts → Passkeys → Advanced options.");
            }
            0
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("Registration failed: {e}");
            }
            1
        }
    }
}

fn unregister_cmd(json: bool) -> i32 {
    match unregister() {
        Ok(()) => {
            if json {
                println!("{}", serde_json::json!({ "ok": true }));
            } else {
                println!("Unregistered; OS autofill cache cleared.");
            }
            0
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("Unregistration failed: {e}");
            }
            1
        }
    }
}

fn status_cmd(json: bool) -> i32 {
    match vela_win_passkey::registration::status() {
        Some(status) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "com_registered": status.com_registered,
                        "os_registered": status.os_registered,
                        "enabled": status.enabled,
                    })
                );
            } else {
                print_status(&status);
            }
            0
        }
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": "webauthn.dll plugin API missing (Windows too old)"
                    })
                );
            } else {
                println!("Provider unavailable: webauthn.dll plugin API missing (Windows too old).");
            }
            1
        }
    }
}

fn sync_cmd(json: bool) -> i32 {
    let credentials = match vela_win_passkey::desktop::all_passkeys() {
        Ok(credentials) => credentials,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("Sync failed: {e}");
            }
            return 1;
        }
    };
    // Full refresh (clear + re-add) so deletions propagate; only after the
    // vault answered — a locked or absent desktop must not empty the cache.
    match vela_win_passkey::refresh_credential_cache(&credentials) {
        Ok(n) => {
            if json {
                println!("{}", serde_json::json!({ "ok": true, "synced": n }));
            } else {
                println!("Synced {n} passkey(s) to the OS autofill cache.");
            }
            0
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "error": e }));
            } else {
                eprintln!("Sync failed: {e}");
            }
            1
        }
    }
}

fn print_status(status: &ProviderStatus) {
    println!("COM registration:   {}", yes_no(status.com_registered));
    println!("Platform registration: {}", yes_no(status.os_registered));
    println!("Enabled (Settings): {}", yes_no(status.enabled));
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("vela-passkey-provider is Windows-only");
    std::process::exit(1);
}

