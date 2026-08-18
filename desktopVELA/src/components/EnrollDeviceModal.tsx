import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import QRCode from 'qrcode';
import { useApp } from '../context/AppContext';

interface EnrollmentInvite {
  code: string;
  grant_id: string;
  expires_in: number;
}

interface ClaimedDevice {
  device_name: string | null;
  device_type: string | null;
  fingerprint_choices: string[];
  decoys_unavailable: boolean;
}

interface Props {
  open: boolean;
  onClose: () => void;
  onEnrolled: () => void;
}

const POLL_INTERVAL_MS = 2000;

/**
 * Enroll a new device (enrollment v3, audit P-1).
 *
 * The QR here carries a one-time grant and a server URL and nothing else. The
 * joining device generates its own keys and sends only the public half, so
 * someone who photographs this screen gets an enrollment *attempt* rather than
 * the vault — which is what the v2 code was worth.
 *
 * That moves the risk onto the fingerprint step below, so the question asked
 * there is deliberately not "do these match?". Yes is the habitual answer, and
 * a yes/no prompt fails open: someone not really looking confirms whatever is
 * in front of them. Instead the real fingerprint is shown among indistinguish-
 * able decoys and the user picks the one their other device displays, so not
 * looking fails 3 times in 4. The backend builds that list once per claim and a
 * wrong pick cancels the enrollment outright — neither is this component's to
 * decide, and neither can be undone from here.
 */
export default function EnrollDeviceModal({ open, onClose, onEnrolled }: Props) {
  const { showToast } = useApp();
  const [invite, setInvite] = useState<EnrollmentInvite | null>(null);
  const [qrImage, setQrImage] = useState<string | null>(null);
  const [claim, setClaim] = useState<ClaimedDevice | null>(null);
  const [opening, setOpening] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [enrolledName, setEnrolledName] = useState<string | null>(null);
  const [rejected, setRejected] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [now, setNow] = useState(Date.now());

  // Held in a ref as well so the polling effect can read the current grant
  // without re-subscribing on every render.
  const grantIdRef = useRef<string | null>(null);

  const reset = useCallback(() => {
    setInvite(null);
    setQrImage(null);
    setClaim(null);
    setEnrolledName(null);
    setRejected(false);
    setCodeCopied(false);
    setExpiresAt(null);
    grantIdRef.current = null;
  }, []);

  const start = useCallback(async () => {
    setOpening(true);
    reset();
    try {
      const created = await invoke<EnrollmentInvite>('open_enrollment_invite');
      setInvite(created);
      grantIdRef.current = created.grant_id;
      setExpiresAt(Date.now() + created.expires_in * 1000);
      // A v3 code is a grant id and a URL, so it always fits in one QR — unlike
      // v2, which carried a whole keypair and had to be split into chunks.
      setQrImage(
        await QRCode.toDataURL(created.code, {
          errorCorrectionLevel: 'M',
          margin: 2,
          width: 280,
        }),
      );
    } catch (e) {
      showToast(typeof e === 'string' ? e : 'Could not start enrollment', 'error');
      onClose();
    } finally {
      setOpening(false);
    }
  }, [onClose, reset, showToast]);

  useEffect(() => {
    if (open && !invite && !opening) void start();
    if (!open) reset();
    // Runs on open/close; `start` is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Poll for a claim until one arrives. Stops as soon as there is one: the
  // choices are fixed from that moment and re-fetching them would only risk
  // redrawing the list while the user is reading it.
  useEffect(() => {
    if (!open || !invite || claim || enrolledName || rejected) return;
    let cancelled = false;
    const timer = setInterval(async () => {
      const grantId = grantIdRef.current;
      if (!grantId) return;
      try {
        const found = await invoke<ClaimedDevice | null>('poll_enrollment_claim', { grantId });
        if (!cancelled && found) setClaim(found);
      } catch {
        // Transient while the grant is alive — the countdown below is what
        // tells the user when to give up, not a failed poll.
      }
    }, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [open, invite, claim, enrolledName, rejected]);

  useEffect(() => {
    if (!expiresAt || claim) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [expiresAt, claim]);

  const close = useCallback(() => {
    // Dismissing the dialog must not kill the enrollment. The joining device is
    // about to be walked through its own screens and this one is in the way;
    // when it is reopened, `open_enrollment_invite` resumes the same grant and
    // the poll below picks up the claim — otherwise the user would come back to
    // a dead code and a joining device stuck on a fingerprint to pick.
    reset();
    onClose();
  }, [onClose, reset]);

  // A deliberate abort, unlike `close` above.
  const cancel = useCallback(() => {
    void invoke('cancel_enrollment').catch(() => {});
    close();
  }, [close]);

  const pick = async (choice: string) => {
    const grantId = grantIdRef.current;
    if (!grantId) return;
    setConfirming(true);
    try {
      await invoke<string>('confirm_enrollment', { grantId, chosen: choice });
      setEnrolledName(claim?.device_name || 'The new device');
      setClaim(null);
      onEnrolled();
    } catch (e) {
      // A wrong pick is not a retry — the backend has already discarded the
      // enrollment. Saying so plainly matters more than being gentle: if the
      // codes really did differ, something substituted a key.
      setRejected(true);
      setClaim(null);
      showToast(typeof e === 'string' ? e : 'Enrollment cancelled', 'error');
    } finally {
      setConfirming(false);
    }
  };

  const copyCode = async () => {
    if (!invite) return;
    try {
      await invoke('copy_secret', { text: invite.code });
      setCodeCopied(true);
      setTimeout(() => setCodeCopied(false), 3000);
    } catch {
      showToast('Failed to copy to clipboard', 'error');
    }
  };

  if (!open) return null;

  const secondsLeft = expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : null;
  const expired = secondsLeft === 0 && !claim && !enrolledName;
  const deviceLabel = claim?.device_name?.trim() || 'the new device';

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={close}>
      <div
        className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto shadow-2xl border border-outline-variant/20"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 mb-4">
          <span className="material-symbols-outlined text-2xl text-primary">add_to_queue</span>
          <h2 className="font-headline text-2xl font-bold text-on-surface">Enroll a new device</h2>
        </div>

        {/* ── Done ─────────────────────────────────────────────────────── */}
        {enrolledName && (
          <>
            <div className="mb-6 p-4 bg-green-500/10 border border-green-500/30 rounded-xl">
              <div className="flex items-center gap-2 mb-1">
                <span className="material-symbols-outlined text-green-400 text-lg">check_circle</span>
                <span className="font-label text-sm font-bold text-green-300">Device enrolled</span>
              </div>
              <p className="text-on-surface-variant text-sm">
                {enrolledName} now has access to your vault. It is downloading the vault now.
              </p>
            </div>
            <button
              onClick={close}
              className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors"
            >
              Done
            </button>
          </>
        )}

        {/* ── Wrong pick: cancelled, not retryable ─────────────────────── */}
        {rejected && (
          <>
            <div className="mb-6 p-4 bg-red-500/10 border border-red-500/30 rounded-xl">
              <div className="flex items-center gap-2 mb-1">
                <span className="material-symbols-outlined text-red-400 text-lg">gpp_maybe</span>
                <span className="font-label text-sm font-bold text-red-300">Enrollment cancelled</span>
              </div>
              <p className="text-on-surface-variant text-sm">
                That was not the code the other device is showing, so nothing was enrolled. If you
                picked in a hurry, start again and compare the two screens carefully. If you are
                certain you picked the code your device displayed, stop: something else answered
                this enrollment, and it should not be retried on this network.
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={start}
                className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
              >
                Start again
              </button>
              <button
                onClick={close}
                className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors"
              >
                Close
              </button>
            </div>
          </>
        )}

        {/* ── Pick the fingerprint ─────────────────────────────────────── */}
        {claim && !enrolledName && !rejected && (
          <>
            <p className="text-on-surface-variant text-sm mb-4">
              <strong className="text-on-surface">{deviceLabel}</strong>
              {claim.device_type ? ` (${claim.device_type})` : ''} is asking to join. It is showing a
              code on its screen. Pick the same code below to give it your vault.
            </p>

            {claim.decoys_unavailable ? (
              // No OS randomness, so no decoys could be generated. A predictable
              // decoy set would look like a check without being one, so the
              // backend returned the single true value and this falls back to a
              // plain comparison — and says that it has.
              <>
                <div className="mb-4 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
                  <p className="text-on-surface-variant text-xs">
                    This device could not generate the usual set of alternatives, so compare the two
                    codes yourself instead of picking from a list.
                  </p>
                </div>
                <div className="font-mono text-xl font-bold tracking-widest text-on-surface text-center py-4 bg-surface-bright rounded-xl mb-4">
                  {claim.fingerprint_choices[0]}
                </div>
                <button
                  onClick={() => pick(claim.fingerprint_choices[0])}
                  disabled={confirming}
                  className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                  {confirming ? 'Enrolling…' : 'The codes match — enroll it'}
                </button>
              </>
            ) : (
              <>
                <p className="text-on-surface-variant text-xs mb-3">
                  Only one of these is real. If none of them matches what {deviceLabel} shows, close
                  this dialog — do not guess.
                </p>
                <div className="space-y-3 mb-4">
                  {claim.fingerprint_choices.map(choice => (
                    <button
                      key={choice}
                      onClick={() => pick(choice)}
                      disabled={confirming}
                      className="w-full py-4 px-4 bg-surface-bright hover:bg-surface-container-highest border border-outline-variant/20 hover:border-primary rounded-xl font-mono text-lg font-bold tracking-widest text-on-surface transition-colors disabled:opacity-50"
                    >
                      {choice}
                    </button>
                  ))}
                </div>
              </>
            )}

            <button
              onClick={cancel}
              className="w-full py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
            >
              None of these match — cancel
            </button>
          </>
        )}

        {/* ── Waiting for a device to scan ─────────────────────────────── */}
        {!claim && !enrolledName && !rejected && (
          <>
            <p className="text-on-surface-variant text-sm mb-4">
              On the new device, choose <strong>Join existing account</strong> and scan this code.
              You will then be asked to confirm a short code shown on both screens.
            </p>

            {opening && <p className="text-on-surface-variant text-sm py-8 text-center">Opening…</p>}

            {qrImage && (
              <div className="mb-4 p-4 bg-white rounded-xl flex flex-col items-center">
                <img src={qrImage} alt="Enrollment QR code" className="w-full max-w-[280px] h-auto" />
                <div className="mt-3 text-slate-900 font-label text-sm">Enrollment QR</div>
              </div>
            )}

            {invite && (
              <>
                <div className="bg-surface-bright rounded-xl p-3 mb-4 font-mono text-xs text-on-surface break-all select-all max-h-24 overflow-y-auto">
                  {invite.code}
                </div>
                <p className="text-on-surface-variant text-xs mb-4">
                  This code cannot unlock your vault on its own — it only lets one device ask to
                  join, once. You still have to confirm which device that was. You can close this
                  window and come back later; it will pick up where it left off until the code
                  expires.
                </p>
                <div className="flex items-center justify-center gap-2 mb-4 text-sm text-on-surface-variant">
                  <span className="material-symbols-outlined text-base animate-pulse">sync</span>
                  {expired
                    ? 'This code has expired.'
                    : `Waiting for a device to scan${
                        secondsLeft !== null
                          ? ` · expires in ${Math.floor(secondsLeft / 60)}:${String(
                              secondsLeft % 60,
                            ).padStart(2, '0')}`
                          : ''
                      }`}
                </div>
                <div className="flex gap-3">
                  {expired ? (
                    <button
                      onClick={start}
                      className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors"
                    >
                      New code
                    </button>
                  ) : (
                    <button
                      onClick={copyCode}
                      className="flex-1 flex items-center justify-center gap-2 py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors"
                    >
                      <span className="material-symbols-outlined text-sm">
                        {codeCopied ? 'check' : 'content_copy'}
                      </span>
                      {codeCopied ? 'Copied!' : 'Copy code'}
                    </button>
                  )}
                  <button
                    onClick={close}
                    className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
                  >
                    Close
                  </button>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
