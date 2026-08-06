//! The user-presence gate for passkey ceremonies.
//!
//! This is the only place a [`PresenceToken`] is minted, and the token is what
//! every ceremony in [`crate::passkey`] must spend. The separation matters:
//! the model's `assertion_requires_user_presence` is the lemma that bounds the
//! entire M7 residual, and the first version of that model failed to state it —
//! with the gate removed, a resident adversary could drive unbounded logins as
//! the user at every passkey origin. Keeping token minting in one small module
//! makes "who decided a human was here?" a question with one answer.
//!
//! ## Why this is not [`crate::ipc::server::authorize_plaintext_release`]
//!
//! That function releases a plaintext password and, on a machine with no
//! biometric factor, deliberately proceeds anyway — the reasoning being that
//! idle auto-lock, not a prompt, is what stops a co-resident process draining a
//! vault, and that a prompt which cannot name its caller trains people to click
//! yes. That reasoning does not carry over here:
//!
//!  * a fill is bounded by the working set and by auto-lock; an assertion
//!    oracle is not bounded by anything, because assertions are cheap,
//!    repeatable and leave the vault untouched, so the session never idles out
//!    while it is being drained;
//!  * there is nothing to steal here, so the failure mode is not "a password
//!    leaked" but "the attacker is logged in as you, everywhere, silently".
//!
//! So where the platform cannot verify a user, this asks the user directly
//! rather than assuming them. A confirmation dialog is a weaker factor than a
//! biometric — it proves presence, not identity, and the token records which
//! one happened so [`crate::passkey`] can refuse a relying party that demanded
//! real verification.
//!
//! ## How weak the dialog fallback actually is
//!
//! Weaker than "Wayland stops synthetic input", which is what an earlier
//! version of this comment claimed. Wayland blocks compositor-level injection
//! (`XTEST`), but `/dev/uinput` sits *below* the compositor and presents as a
//! real hardware keyboard. On a machine where the user is in the `input` or
//! `uinput` group — routine for ydotool, gaming peripherals and remote-desktop
//! tools — a co-resident same-UID process can create a virtual keyboard and
//! click Approve for itself. That was confirmed on a real Arch/Hyprland
//! machine, where `/dev/uinput` was group-writable and a virtual device was
//! created from an unprivileged process.
//!
//! So on such a machine the fallback is not a gate against the very adversary
//! the model assumes, and `assertion_requires_user_presence` holds in the
//! theory while being forgeable in practice. What survives untouched is the
//! biometric path: no amount of synthetic input satisfies a fingerprint
//! reader. Treat the dialog as a speed bump for the no-biometric case and the
//! biometric as the real control — and see the `uinput` note in
//! `security/formal/password-manager-ipc-tamarin-results.md`.

use crate::host::Host;
use crate::passkey::PresenceToken;
use std::sync::Arc;

/// What the user is being asked to authorise.
#[derive(Debug, Clone)]
pub struct PresenceRequest {
    /// The relying party the ceremony is for, e.g. `github.com`.
    pub rp_id: String,
    /// Who asked, in human terms — the peer description from the IPC layer.
    pub requester: String,
    /// Registration reads differently from a login, so say which.
    pub kind: CeremonyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyKind {
    Register,
    Authenticate,
}

impl PresenceRequest {
    /// The sentence the user is asked to agree to.
    ///
    /// Names both the site and the caller. A prompt that says only "confirm"
    /// is the kind that gets approved reflexively; one that names an origin the
    /// user is not currently visiting is one they can refuse.
    pub fn prompt(&self) -> String {
        match self.kind {
            CeremonyKind::Register => format!(
                "Create a passkey for {} at the request of {}?",
                self.rp_id, self.requester
            ),
            CeremonyKind::Authenticate => format!(
                "Sign in to {} with your passkey, at the request of {}?",
                self.rp_id, self.requester
            ),
        }
    }
}

/// Why a ceremony was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceDenied {
    /// The user said no, or the prompt failed.
    Declined(String),
    /// Nothing on this machine can ask a human anything.
    NoWayToAsk,
}

impl std::fmt::Display for PresenceDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Declined(message) => write!(f, "{message}"),
            Self::NoWayToAsk => write!(
                f,
                "This machine has no way to confirm you are present, so passkey use is refused."
            ),
        }
    }
}

/// Ask the human, and mint a token only if they said yes.
///
/// Biometric first, because it proves more. Where the platform has no factor
/// enrolled, fall back to an in-app confirmation — which is a real question put
/// to a real person, and on a Wayland session is not something a co-resident
/// process can click for them. Only if there is no window either does this
/// refuse outright, because at that point there is genuinely nobody to ask.
pub fn confirm(host: &Arc<dyn Host>, request: &PresenceRequest) -> Result<PresenceToken, PresenceDenied> {
    let prompt = request.prompt();

    match platform_presence(&prompt) {
        crate::biometric::PresenceOutcome::Confirmed => Ok(PresenceToken::mint(true)),
        crate::biometric::PresenceOutcome::Denied(message) => {
            Err(PresenceDenied::Declined(message))
        }
        crate::biometric::PresenceOutcome::Unavailable => {
            // Presence, not verification: the token records that, and a relying
            // party asking for UV will be refused by the ceremony.
            match host.confirm_presence(&prompt) {
                Some(true) => Ok(PresenceToken::mint(false)),
                Some(false) => Err(PresenceDenied::Declined(
                    "You declined this passkey request.".to_string(),
                )),
                None => Err(PresenceDenied::NoWayToAsk),
            }
        }
    }
}

/// The platform biometric check, with a test seam.
///
/// Whether this machine has an enrolled fingerprint is not something the test
/// suite should depend on: without the seam, the presence tests pass on a
/// laptop with no reader and hang on one with a reader, waiting for a finger
/// nobody is going to offer.
fn platform_presence(prompt: &str) -> crate::biometric::PresenceOutcome {
    #[cfg(test)]
    if FORCE_UNAVAILABLE.load(std::sync::atomic::Ordering::SeqCst) {
        return crate::biometric::PresenceOutcome::Unavailable;
    }
    crate::biometric::verify_presence(prompt)
}

#[cfg(test)]
static FORCE_UNAVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Pin the platform factor to "unavailable" for the rest of this test binary,
/// so the in-app fallback is the path under test. Idempotent, and every caller
/// wants the same value, so it is safe to call from tests running in parallel.
#[cfg(test)]
pub(crate) fn force_platform_presence_unavailable() {
    FORCE_UNAVAILABLE.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_names_both_the_site_and_the_caller() {
        let request = PresenceRequest {
            rp_id: "github.com".to_string(),
            requester: "firefox (pid 4242)".to_string(),
            kind: CeremonyKind::Authenticate,
        };

        let prompt = request.prompt();

        assert!(prompt.contains("github.com"), "{prompt}");
        assert!(prompt.contains("firefox (pid 4242)"), "{prompt}");
    }

    #[test]
    fn registration_and_authentication_read_differently() {
        let base = PresenceRequest {
            rp_id: "github.com".to_string(),
            requester: "firefox".to_string(),
            kind: CeremonyKind::Register,
        };
        let authenticate = PresenceRequest {
            kind: CeremonyKind::Authenticate,
            ..base.clone()
        };

        assert_ne!(base.prompt(), authenticate.prompt());
        assert!(base.prompt().contains("Create a passkey"));
        assert!(authenticate.prompt().contains("Sign in"));
    }
}
