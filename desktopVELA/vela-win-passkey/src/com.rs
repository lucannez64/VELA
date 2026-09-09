//! The out-of-proc COM server: `IPluginAuthenticator` as Windows wants it.
//!
//! COM method names are PascalCase by ABI; silence the lint crate-wide.
//!
//! Windows activates `vela-passkey-provider.exe` via the `LocalServer32`
//! registration whenever a WebAuthn client (any browser, any app) starts a
//! ceremony for an RP we serve. The process registers the class object,
//! parks, and answers:
//!
//! - `MakeCredential` / `GetAssertion` — decoded in `ceremony`, executed by
//!   the desktop over the pipe, encoded back with the platform's own helpers.
//! - `GetLockStatus` — the desktop's session state, so Windows can show
//!   "locked" instead of a futile credential picker.
//! - `CancelOperation` — marks the in-flight transaction cancelled; the
//!   ceremony result is discarded when it eventually returns.
//!
//! One ceremony at a time, mirroring the reference implementation: a second
//! request gets `ERROR_BUSY` rather than two Hello prompts fighting for the
//! foreground.

// COM method names are PascalCase by ABI.
#![allow(non_snake_case)]

use std::sync::atomic::{AtomicBool, Ordering};
use windows::core::{GUID, HRESULT, IUnknown, Interface, IUnknown_Vtbl};
use windows::Win32::Foundation::{BOOL, CLASS_E_NOAGGREGATION, E_INVALIDARG, S_OK};
use windows::Win32::System::Com::{
    CoInitializeEx, CoRegisterClassObject, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED,
    REGCLS_MULTIPLEUSE, IClassFactory, IClassFactory_Impl,
};

use crate::ffi::{
    hresult, WebAuthn, WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    WEBAUTHN_PLUGIN_OPERATION_REQUEST, WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
};
use crate::{ceremony, PLUGIN_LOCK_STATUS};

/// `IPluginAuthenticator` from `pluginauthenticator.idl` (uuid 1.0,
/// `d26bcf6f-b54c-43ff-9f06-d5bf148625f7`). The vtable layout is the ABI the
/// platform invokes; only these four methods, in this order, after IUnknown.
#[windows::core::interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
pub unsafe trait IPluginAuthenticatorCom: IUnknown {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;
    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;
    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT;
    unsafe fn GetLockStatus(&self, lockstatus: *mut PLUGIN_LOCK_STATUS) -> HRESULT;
}

/// The provider object itself. Holds no credential state — the vault does.
#[windows::core::implement(IPluginAuthenticatorCom)]
struct Provider {
    webauthn: WebAuthn,
    /// Set when the platform cancels the transaction mid-ceremony.
    cancelled: AtomicBool,
    /// Transaction id of the ceremony in flight, for cancel matching.
    transaction: std::sync::Mutex<Option<GUID>>,
    /// One ceremony at a time.
    busy: AtomicBool,
}

impl Provider {
    fn new(webauthn: WebAuthn) -> Self {
        Self {
            webauthn,
            cancelled: AtomicBool::new(false),
            transaction: std::sync::Mutex::new(None),
            busy: AtomicBool::new(false),
        }
    }

    /// Acquire the single-ceremony slot. `Err` = already busy.
    fn begin(&self, transaction: GUID) -> Result<(), HRESULT> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err(HRESULT(hresult::ERROR_BUSY));
        }
        *self.transaction.lock().unwrap() = Some(transaction);
        self.cancelled.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn end(&self) {
        *self.transaction.lock().unwrap() = None;
        self.busy.store(false, Ordering::SeqCst);
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl IPluginAuthenticatorCom_Impl for Provider_Impl {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        self.ceremony_inner(request, response, Ceremony::Make)
    }

    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        self.ceremony_inner(request, response, Ceremony::Get)
    }

    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT {
        if request.is_null() {
            return E_INVALIDARG;
        }
        let request = &*request;
        let pending = self.transaction.lock().unwrap();
        if *pending == Some(request.transactionId) {
            self.cancelled.store(true, Ordering::SeqCst);
            // The ceremony thread is blocked waiting on the desktop; when the
            // desktop finally answers, the answer is discarded (checked in
            // `ceremony_inner`) and the caller sees the cancel, not a
            // signature produced after the platform withdrew its request.
        }
        S_OK
    }

    unsafe fn GetLockStatus(&self, lockstatus: *mut PLUGIN_LOCK_STATUS) -> HRESULT {
        if lockstatus.is_null() {
            return E_INVALIDARG;
        }
        // Unreachable desktop = locked. The OS then shows its "passkey
        // manager is locked" affordance instead of promising something we
        // cannot deliver while the desktop is closed.
        *lockstatus = match crate::desktop::lock_state() {
            Ok(Some(false)) => PLUGIN_LOCK_STATUS::PluginUnlocked,
            _ => PLUGIN_LOCK_STATUS::PluginLocked,
        };
        S_OK
    }
}

impl Provider_Impl {
    unsafe fn ceremony_inner(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
        which: Ceremony,
    ) -> HRESULT {
        if response.is_null() || request.is_null() {
            return E_INVALIDARG;
        }
        *response = WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
            cbEncodedResponse: 0,
            pbEncodedResponse: std::ptr::null_mut(),
        };
        let request = &*request;

        if let Err(hr) = self.begin(request.transactionId) {
            return hr;
        }
        let outcome = match which {
            Ceremony::Make => ceremony::make_credential(&self.webauthn, request),
            Ceremony::Get => ceremony::get_assertion(&self.webauthn, request),
        };
        self.end();

        match outcome {
            Ok(encoded) => {
                if self.cancelled() {
                    // The platform withdrew the request while the human was
                    // deciding. Never hand back a signature for a cancelled
                    // transaction — return the same code a user rejection
                    // produces so the RP sees "allowed, not completed".
                    return HRESULT(hresult::NTE_USER_CANCELLED);
                }
                // `bytes` is CoTaskMemAlloc'd by the platform's encode helper;
                // ownership transfers to the caller here, so no free.
                *response = WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
                    cbEncodedResponse: encoded.len,
                    pbEncodedResponse: encoded.bytes,
                };
                S_OK
            }
            Err(hr) => HRESULT(hr),
        }
    }
}

#[derive(Clone, Copy)]
enum Ceremony {
    Make,
    Get,
}

/// COM class object (IClassFactory) handing out [`Provider`] instances.
#[windows::core::implement(IClassFactory)]
struct ProviderFactory {
    webauthn: WebAuthn,
}

impl IClassFactory_Impl for ProviderFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Option<&IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut std::ffi::c_void,
    ) -> windows::core::Result<()> {
        unsafe {
            if ppvobject.is_null() || riid.is_null() {
                return Err(windows::core::Error::from_hresult(E_INVALIDARG));
            }
            *ppvobject = std::ptr::null_mut();
            if punkouter.is_some() {
                return Err(windows::core::Error::from_hresult(CLASS_E_NOAGGREGATION));
            }
            let provider: IPluginAuthenticatorCom = Provider::new(self.webauthn).into();
            match provider.query(riid, ppvobject) {
                windows::core::HRESULT(0) => windows::core::Result::Ok(()),
                code => Err(windows::core::Error::from_hresult(windows::core::HRESULT(code.0))),
            }
        }
    }

    fn LockServer(&self, _flock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}
/// Run the server: enter the MTA, publish the class object, park forever.
///
/// COM destroys the process only when it stops needing it, and restarts it on
/// demand through `LocalServer32`; either way, ceremonies keep working. This
/// process holds no secrets — worst case, killing it degrades passkeys until
/// the next activation re-opens it.
pub fn run(webauthn: WebAuthn) -> windows::core::Result<()> {    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

        let factory: IClassFactory = ProviderFactory { webauthn }.into();
        let _cookie = CoRegisterClassObject(
            &crate::COM_CLSID,
            &factory,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE,
        )
        .inspect_err(|e| eprintln!("CoRegisterClassObject failed: {e}"))?;
        // No CoResumeClassObjects here: that pairs with REGCLS_SUSPENDED,
        // which we do not use. Activations flow as soon as registration
        // returns; calling Resume unsuspended fails with RPC_S_INVALID_ARRAY_BOUNDS.

        eprintln!("VELA passkey provider: serving ceremonies");
        // MTA: calls arrive on RPC threads; the main thread only has to stay
        // alive. Sleep in a loop so a Ctrl+C / taskkill still lands cleanly.
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
        // Unreachable: the process is killed, never unwound. `cookie` exists
        // so a future graceful shutdown path can CoRevokeClassObject it.
        #[allow(unreachable_code)]
        {
            let _ = _cookie;
            Ok(())
        }
    }
}





#[cfg(test)]
mod com_activation_tests {
    // End-to-end against the real OS: Windows launches the provider through
    // the registered class object and answers GetLockStatus. Ignored by
    // default because it depends on machine state: the identity package must
    // be registered (msix/register-dev.ps1) and the provider registered
    // (--register). Run explicitly:
    //   cargo test -p vela-win-passkey --lib -- --ignored
    use super::*;

    #[test]
    #[ignore = "requires the provider to be registered on this machine"]
    fn com_activates_and_reports_lock_status() {
        use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_LOCAL_SERVER};
        eprintln!("step: CoInitializeEx");
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok().unwrap();
            eprintln!("step: CoCreateInstance");
            let plugin: IPluginAuthenticatorCom =
                CoCreateInstance(&crate::COM_CLSID, None, CLSCTX_LOCAL_SERVER).unwrap();
            eprintln!("step: got typed interface, calling GetLockStatus");

            // With no desktop running, the only honest answer is "locked".
            let mut status = PLUGIN_LOCK_STATUS::PluginUnlocked;
            let hr = plugin.GetLockStatus(&mut status);
            eprintln!("step: GetLockStatus returned {hr:?} status={status:?}");
            assert_eq!(hr.0, 0, "GetLockStatus failed: {hr:?}");
            assert_eq!(
                status,
                PLUGIN_LOCK_STATUS::PluginLocked,
                "with no desktop running the provider must report locked, not unlocked"
            );
        }
    }
}
