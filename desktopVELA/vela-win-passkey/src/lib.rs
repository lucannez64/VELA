//! VELA as a Windows system-wide passkey provider.
//!
//! The browser extension answers WebAuthn for pages that install the VELA
//! shim; this crate makes VELA answer WebAuthn for *everything else* — any
//! browser without the extension, native apps, PWAs — by registering as a
//! Windows 11 plugin passkey authenticator (Settings → Accounts → Passkeys).
//!
//! Architecture, in one line per box:
//!
//! ```text
//!   [browser / app] --WebAuthn--> [Windows webauthn.dll]
//!        --CTAP2 CBOR over COM--> [vela-passkey-provider.exe (this crate)]
//!        --JSON over named pipe--> [vela-desktop-core (vault + presence)]
//! ```
//!
//! The provider is a transport, never a second implementation: the same
//! `passkey::make_credential` / `passkey::get_assertion` the extension drives
//! perform every ceremony, so the one-ceremony-per-presence-token invariant
//! and the `credential_never_leaks` property hold unchanged. See
//! `security/passkey-native-provider-adr.md` for the decision record.

pub mod cbor;

// Everything below talks to Windows APIs; on other platforms the crate
// compiles empty so the workspace still builds (the desktop's
// `commands::provider` has matching cfg-gates).
#[cfg(windows)]
pub mod ceremony;
#[cfg(windows)]
pub mod com;
#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod ffi;
#[cfg(windows)]
pub mod registration;

#[cfg(windows)]
pub use com::IPluginAuthenticatorCom;
#[cfg(windows)]
pub use desktop::CredentialMetadata;
#[cfg(windows)]
pub use registration::{
    authenticator_get_info, push_credential_metadata, refresh_credential_cache, register,
    unregister, ProviderStatus, AAGUID, AUTHENTICATOR_NAME, COM_CLSID, PLUGIN_RP_ID,
};

/// What the COM `GetLockStatus` callback reports.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
#[allow(non_camel_case_types)] // mirrors the platform enum name in webauthnplugin.h
pub enum PLUGIN_LOCK_STATUS {
    PluginLocked = 0,
    PluginUnlocked = 1,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registration blob is a fixed structure the OS parses; changing it
    /// changes what Windows believes about the authenticator. Pin it.
    #[cfg(windows)]
    #[test]
    fn get_info_blob_declares_exactly_what_vela_implements() {
        let info = authenticator_get_info();
        // {"1": ["FIDO_2_0"], "3": h'000...0', "4": {"rk": true, "up": true,
        //  "uv": true}, "9": ["internal"], "10": [{"alg": -7,
        //  "type": "public-key"}]}
        let expected_start: Vec<u8> = [
            0xA5, // map(5)
            0x01, // key 1
            0x81, 0x68, // array(1), text(8)
        ]
        .to_vec();
        assert_eq!(&info[..expected_start.len()], &expected_start[..]);
        let s = String::from_utf8_lossy(&info);
        assert!(s.contains("FIDO_2_0"));
        assert!(s.contains("internal"));
        assert!(s.contains("public-key"));
        assert!(!s.contains("prf"), "VELA does not implement prf");
        assert!(!s.contains("hmac-secret"), "VELA does not implement hmac-secret");
        assert!(!s.contains("FIDO_2_1"), "VELA claims no 2.1 features");
        // Map has exactly 5 keys; each integer-encoded ES256 alg is -7 (0x26).
        assert!(info.starts_with(&[0xA5]));
        assert!(s.contains("alg"));
        // ES256 negative integer encoding appears exactly once.
        assert_eq!(info.iter().filter(|b| **b == 0x26).count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn clsid_is_stable_and_named() {
        // The OS keys every registration artifact on this GUID; it must never
        // drift. If you are changing this test to a new value, that is a
        // *new provider identity*: unregister() the old one first.
        assert_eq!(format!("{COM_CLSID:?}").to_lowercase(), "f9b594a7-0e49-4c9e-8338-f6d30bce33c4");
        assert_eq!(AAGUID, [0u8; 16], "VELA keeps the zero AAGUID everywhere");
    }
}
