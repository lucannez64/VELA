//! Registering VELA with Windows as a system-wide passkey provider.
//!
//! Three things make the provider visible to the OS:
//!
//! 1. **COM class registration** (`HKCU\Software\Classes\CLSID\{clsid}`)
//!    pointing `LocalServer32` at `vela-passkey-provider.exe -Embedding`, so
//!    Windows can launch the ceremony server on demand.
//! 2. **`WebAuthNPluginAddAuthenticator`** with the provider's name, logo,
//!    and a CTAP2 `authenticatorGetInfo` blob declaring what VELA actually
//!    implements (ES256 only, internal transport, rk/up/uv). After this the
//!    provider appears in *Settings → Accounts → Passkeys → Advanced
//!    options*, and the user's toggle there is what enables it —
//!    registration alone never routes ceremonies.
//! 3. **Autofill metadata** (`WebAuthNPluginAuthenticatorAddCredentials`):
//!    the OS keeps its own cache of credential metadata for browser autofill;
//!    we push vault passkeys into it on registration and on demand.
//!
//! Uninstalling is the exact inverse (`unregister`), including removing the
//! OS-side credential cache — a provider that registered itself must leave no
//! phantom entries behind.

use crate::cbor;
use crate::desktop::CredentialMetadata;
use crate::ffi::{self, WebAuthn};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
};

/// VELA's plugin authenticator class id (generated once; never reuse for
/// anything else). The OS keys registration, Settings entries, autofill
/// caches and cancellation on this GUID.
pub const COM_CLSID: GUID = GUID::from_u128(0xf9b594a7_0e49_4c9e_8338_f6d30bce33c4);

/// The RP ID Windows allows for *nested* WebAuthn calls made by the plugin
/// itself (VELA does not make any today, but the field is required). VELA's
/// own domain is the honest value: if the plugin ever does make a nested
/// call, it is for vela.app.
pub const PLUGIN_RP_ID: &str = "vela.app";

/// Display name in the Windows passkey Settings page.
pub const AUTHENTICATOR_NAME: &str = "VELA";

/// VELA's AAGUID: all zeroes, matching the extension path's deliberate
/// anti-correlation choice (see `vela-desktop-core::passkey`) so a passkey
/// created in the browser and one created system-wide are indistinguishable
/// to relying parties.
pub const AAGUID: [u8; 16] = [0u8; 16];

/// Per-user COM class key for the provider.
fn clsid_key_path() -> String {
    format!(
        r"Software\Classes\CLSID\{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        COM_CLSID.data1,
        COM_CLSID.data2,
        COM_CLSID.data3,
        COM_CLSID.data4[0],
        COM_CLSID.data4[1],
        COM_CLSID.data4[2],
        COM_CLSID.data4[3],
        COM_CLSID.data4[4],
        COM_CLSID.data4[5],
        COM_CLSID.data4[6],
        COM_CLSID.data4[7],
    )
}

fn reg_set_string(root: HKEY, path: &str, value: Option<&str>, data: &str) -> Result<(), String> {
    use windows::Win32::System::Registry::{RegCloseKey, RegCreateKeyExW, RegSetValueExW};
    unsafe {
        let path_w = ffi::wide(path);
        let mut key = HKEY::default();
        let opened = RegCreateKeyExW(
            root,
            PCWSTR::from_raw(path_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        );
        if opened != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW({path}) failed: win32 error {}", opened.0));
        }
        let data_w: Vec<u16> = data.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2);
        let written = match value {
            Some(value) => {
                let value_w = ffi::wide(value);
                RegSetValueExW(key, PCWSTR::from_raw(value_w.as_ptr()), 0, REG_SZ, Some(bytes))
            }
            None => RegSetValueExW(key, PCWSTR::null(), 0, REG_SZ, Some(bytes)),
        };
        let _ = RegCloseKey(key);
        if written != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW({path}) failed: win32 error {}", written.0));
        }
        Ok(())
    }
}

fn reg_delete_tree(path: &str) {
    use windows::Win32::System::Registry::RegDeleteTreeW;
    unsafe {
        let path_w = ffi::wide(path);
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR::from_raw(path_w.as_ptr()));
    }
}

/// The CTAP2 `authenticatorGetInfo` blob (§6.4 of CTAP2). Everything in it
/// must be true of the desktop's implementation:
/// - versions: `FIDO_2_0` only — VELA implements no 2.1-only features;
/// - aaguid: all-zero, matching the extension path;
/// - options: `up`, `uv`, `rk` all true (discoverable, presence-verified);
/// - transports: `internal` (this is a platform authenticator);
/// - algorithms: ES256 only (`-7`), like `credential_key.rs`.
/// No `extensions` field: VELA supports none, and a false claim here gets the
/// authenticator silently filtered when an RP asks for one.
pub fn authenticator_get_info() -> Vec<u8> {
    let mut out = Vec::new();
    cbor::map(&mut out, 5);

    cbor::integer(&mut out, 1); // versions
    cbor::array(&mut out, 1);
    cbor::text(&mut out, "FIDO_2_0");

    cbor::integer(&mut out, 3); // aaguid
    cbor::bytes(&mut out, &AAGUID);

    cbor::integer(&mut out, 4); // options
    cbor::map(&mut out, 3);
    cbor::text(&mut out, "rk");
    cbor::bool(&mut out, true);
    cbor::text(&mut out, "up");
    cbor::bool(&mut out, true);
    cbor::text(&mut out, "uv");
    cbor::bool(&mut out, true);

    cbor::integer(&mut out, 9); // transports
    cbor::array(&mut out, 1);
    cbor::text(&mut out, "internal");

    cbor::integer(&mut out, 10); // algorithms
    cbor::array(&mut out, 1);
    cbor::map(&mut out, 2);
    cbor::text(&mut out, "alg");
    cbor::integer(&mut out, -7);
    cbor::text(&mut out, "type");
    cbor::text(&mut out, "public-key");

    out
}

/// Simple light/dark-neutral SVG mark, base64 for the options struct.
fn logo_svg_base64() -> &'static str {
    // A minimal "V" glyph on transparent background; theme-agnostic colors.
    const SVG: &str = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><path d='M8 10l16 30L40 10h-8L24 30 16 10z' fill='#4b7bec'/></svg>";
    use base64::Engine as _;
    static ENCODED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ENCODED.get_or_init(|| base64::engine::general_purpose::STANDARD.encode(SVG))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    /// `LocalServer32` points at this exe, so COM can start us.
    pub com_registered: bool,
    /// `WebAuthNPluginAddAuthenticator` accepted us.
    pub os_registered: bool,
    /// The user's toggle in Settings is on.
    pub enabled: bool,
}

/// Register everything: COM class + platform authenticator entry.
pub fn register() -> Result<ProviderStatus, String> {
    let webauthn = WebAuthn::load().ok_or_else(|| {
        "This Windows build does not export the passkey plugin API (requires \
         Windows 11 24H2/25H2 with the 2025-11 or later cumulative update)."
            .to_string()
    })?;

    let exe = std::env::current_exe().map_err(|e| format!("Cannot resolve provider path: {e}"))?;
    let server_cmd = format!("\"{}\" -Embedding", exe.display());

    reg_set_string(
        HKEY_CURRENT_USER,
        &clsid_key_path(),
        None,
        "VELA Passkey Provider",
    )?;
    reg_set_string(
        HKEY_CURRENT_USER,
        &format!("{}\\LocalServer32", clsid_key_path()),
        None,
        &server_cmd,
    )?;

    let name = ffi::wide(AUTHENTICATOR_NAME);
    let rp_id = ffi::wide(PLUGIN_RP_ID);
    let logo = ffi::wide(logo_svg_base64());
    let info = authenticator_get_info();

    // Adding an already-registered authenticator is refused with
    // NTE_EXISTS (0x8009000F) — registration must be idempotent, because
    // every "Enable" click and every `--register` run lands here. When the
    // OS already knows us, refresh the details (name/logo/GetInfo) instead.
    let already_registered = unsafe {
        let mut state: i32 = 0;
        (webauthn.plugin_get_authenticator_state)(&COM_CLSID, &mut state) >= 0
    };

    let hr = if already_registered {
        let details = ffi::WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS {
            pwszAuthenticatorName: PCWSTR::from_raw(name.as_ptr()),
            rclsid: &COM_CLSID,
            rclsidNew: &COM_CLSID,
            pwszLightThemeLogoSvg: PCWSTR::from_raw(logo.as_ptr()),
            pwszDarkThemeLogoSvg: PCWSTR::from_raw(logo.as_ptr()),
            cbAuthenticatorInfo: info.len() as u32,
            pbAuthenticatorInfo: info.as_ptr(),
            cSupportedRpIds: 0, // all RPs the vault has passkeys for
            ppwszSupportedRpIds: std::ptr::null(),
        };
        unsafe { (webauthn.plugin_update_authenticator_details)(&details) }
    } else {
        let options = ffi::WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
            pwszAuthenticatorName: PCWSTR::from_raw(name.as_ptr()),
            rclsid: &COM_CLSID,
            pwszPluginRpId: PCWSTR::from_raw(rp_id.as_ptr()),
            pwszLightThemeLogoSvg: PCWSTR::from_raw(logo.as_ptr()),
            pwszDarkThemeLogoSvg: PCWSTR::from_raw(logo.as_ptr()),
            cbAuthenticatorInfo: info.len() as u32,
            pbAuthenticatorInfo: info.as_ptr(),
            cSupportedRpIds: 0, // all RPs the vault has passkeys for
            ppwszSupportedRpIds: std::ptr::null(),
        };

        unsafe {
            let mut response = std::ptr::null_mut();
            let hr = (webauthn.plugin_add_authenticator)(&options, &mut response);
            if !response.is_null() {
                // The response carries the OS's request-signing public key; we
                // fetch it fresh via the getter when verifying, so nothing to
                // persist here — just release it.
                (webauthn.plugin_free_add_authenticator_response)(response);
            }
            hr
        }
    };
    if hr < 0 {
        if !already_registered {
            // Roll the COM key back so `state()` stays truthful.
            reg_delete_tree(&clsid_key_path());
        }
        return Err(format!(
            "WebAuthNPlugin{} failed: HRESULT {hr:#010x}. \
             Enable the provider toggle in Settings → Accounts → Passkeys if \
             a restart is pending, or confirm the update level.",
            if already_registered { "UpdateAuthenticatorDetails" } else { "AddAuthenticator" }
        ));
    }

    Ok(status().unwrap_or(ProviderStatus {
        com_registered: true,
        os_registered: true,
        enabled: false,
    }))
}

/// Undo everything `register` did, OS-side caches included.
pub fn unregister() -> Result<(), String> {
    let webauthn = WebAuthn::load()
        .ok_or_else(|| "webauthn.dll plugin API unavailable".to_string())?;
    unsafe {
        let _ = (webauthn.plugin_remove_all_credentials)(&COM_CLSID);
        let hr = (webauthn.plugin_remove_authenticator)(&COM_CLSID);
        if hr < 0 {
            return Err(format!("WebAuthNPluginRemoveAuthenticator failed: {hr:#010x}"));
        }
    }
    reg_delete_tree(&clsid_key_path());
    Ok(())
}

/// Current registration state, answering truthfully even when partially
/// registered (e.g. COM key written but the platform refused the API call).
pub fn status() -> Option<ProviderStatus> {
    let webauthn = WebAuthn::load()?;
    let com_registered = reg_string_exists(&clsid_key_path());
    let (os_registered, enabled) = unsafe {
        let mut state: i32 = 0;
        let hr = (webauthn.plugin_get_authenticator_state)(&COM_CLSID, &mut state);
        if hr >= 0 {
            // AUTHENTICATOR_STATE: 0 = Disabled, 1 = Enabled.
            (true, state == 1)
        } else {
            (false, false)
        }
    };
    Some(ProviderStatus {
        com_registered,
        os_registered,
        enabled,
    })
}

fn reg_string_exists(path: &str) -> bool {
    use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryValueExW, KEY_READ};
    unsafe {
        let path_w = ffi::wide(path);
        let mut key = HKEY::default();
        let opened = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(path_w.as_ptr()),
            0,
            KEY_READ,
            &mut key,
        );
        if opened != ERROR_SUCCESS {
            return false;
        }
        let mut type_: REG_VALUE_TYPE = Default::default();
        let mut cb = 0u32;
        let query = RegQueryValueExW(
            key,
            PCWSTR::null(),
            None,
            Some(&mut type_),
            None,
            Some(&mut cb),
        );
        let _ = RegCloseKey(key);
        query == ERROR_SUCCESS || query == ERROR_MORE_DATA
    }
}

/// Full refresh of the OS autofill cache: drop our cached metadata, then
/// re-add everything the vault currently holds.
///
/// The clearing matters. The OS cache is add-only, so a passkey deleted
/// from the vault would otherwise linger as a dead autofill suggestion on
/// every login form until the provider was unregistered.
pub fn refresh_credential_cache(credentials: &[CredentialMetadata]) -> Result<usize, String> {
    if let Err(clear_error) = clear_cached_credentials() {
        // Not fatal on its own: the per-credential path in the push can
        // still replace every entry individually. But say so — the two
        // failures together would otherwise be undiagnosable.
        eprintln!("VELA passkey provider: clearing the OS autofill cache failed: {clear_error}");
    }
    push_credential_metadata(credentials)
}

/// Push credential metadata into the OS autofill cache, tolerating entries
/// that are already cached: `AddCredentials` refuses duplicates with
/// NTE_EXISTS (0x8009000F), so a resync retries each failing entry as
/// remove-then-add — updated metadata lands, stale entries are replaced.
pub fn push_credential_metadata(credentials: &[CredentialMetadata]) -> Result<usize, String> {
    let webauthn = WebAuthn::load()
        .ok_or_else(|| "webauthn.dll plugin API unavailable".to_string())?;

    if credentials.is_empty() {
        // Nothing to add; the clear (if any) already ran. Calling Add with
        // zero entries is not defined behavior worth finding out about.
        return Ok(0);
    }

    // Keep every wide string alive for the duration of the call.
    let mut owned: Vec<(Vec<u16>, Vec<u16>, Vec<u16>, Vec<u16>)> = Vec::new();
    let mut details: Vec<ffi::WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> = Vec::new();
    for c in credentials {
        owned.push((
            ffi::wide(&c.rp_id),
            ffi::wide(&c.rp_name),
            ffi::wide(&c.user_name),
            ffi::wide(&c.user_display_name),
        ));
    }
    for (c, o) in credentials.iter().zip(owned.iter()) {
        details.push(ffi::WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
            cbCredentialId: c.credential_id.len() as u32,
            pbCredentialId: c.credential_id.as_ptr(),
            pwszRpId: PCWSTR::from_raw(o.0.as_ptr()),
            pwszRpName: PCWSTR::from_raw(o.1.as_ptr()),
            cbUserId: c.user_handle.len() as u32,
            pbUserId: c.user_handle.as_ptr(),
            pwszUserName: PCWSTR::from_raw(o.2.as_ptr()),
            pwszUserDisplayName: PCWSTR::from_raw(o.3.as_ptr()),
        });
    }

    let clsid = COM_CLSID;
    let hr = unsafe {
        (webauthn.plugin_add_credentials)(&clsid, details.len() as u32, details.as_ptr())
    };
    if hr >= 0 {
        return Ok(details.len());
    }

    // Batch refused — almost certainly a duplicate (NTE_EXISTS). Refresh
    // entry by entry: remove what the OS cached, then add fresh.
    let mut pushed = 0usize;
    let mut last_error = format!("WebAuthNPluginAuthenticatorAddCredentials failed: {hr:#010x}");
    for detail in &details {
        unsafe {
            let _ = (webauthn.plugin_remove_credentials)(&clsid, 1, detail);
            match (webauthn.plugin_add_credentials)(&clsid, 1, detail) {
                h if h >= 0 => pushed += 1,
                h => {
                    last_error =
                        format!("WebAuthNPluginAuthenticatorAddCredentials failed: {h:#010x}")
                }
            }
        }
    }
    if pushed == details.len() {
        Ok(pushed)
    } else if pushed > 0 {
        eprintln!(
            "VELA passkey provider: partial autofill refresh ({pushed}/{}); {last_error}",
            details.len()
        );
        Ok(pushed)
    } else {
        Err(last_error)
    }
}

/// Drop the OS autofill cache (used before a full re-sync).
pub fn clear_cached_credentials() -> Result<(), String> {
    let webauthn = WebAuthn::load()
        .ok_or_else(|| "webauthn.dll plugin API unavailable".to_string())?;
    let hr = unsafe { (webauthn.plugin_remove_all_credentials)(&COM_CLSID) };
    if hr < 0 {
        return Err(format!("WebAuthNPluginAuthenticatorRemoveAllCredentials failed: {hr:#010x}"));
    }
    Ok(())
}
