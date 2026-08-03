import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface JoinRequest {
  grant_id: string;
  fingerprint: string;
  server_url: string;
}

interface Props {
  onClose: () => void;
  onComplete: () => void;
}

type Phase = 'entry' | 'waiting' | 'joining';

const POLL_INTERVAL_MS = 2000;

/**
 * Join an existing account from another device's enrollment code.
 *
 * Handles both code versions, because installs mix: a v3 code carries a
 * one-time grant and this device generates its own keys, while a v2 code
 * carries the keys themselves and is imported wholesale. Which one arrived is
 * decided by the backend from the code's prefix, never guessed here.
 *
 * On the v3 path the fingerprint shown below comes from `begin_enrollment_join`,
 * which computes it in-process from the keypair it has just generated. It must
 * stay that way: if this screen ever rendered a fingerprint that arrived over
 * the network, the user would be comparing two devices' agreement about a
 * number rather than about a key, and every binding behind it would stop meaning
 * anything (audit P-1).
 */
export default function JoinAccountModal({ onClose, onComplete }: Props) {
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<Phase>('entry');

  // v3
  const [request, setRequest] = useState<JoinRequest | null>(null);
  const grantIdRef = useRef<string | null>(null);

  // v2
  const [legacyVerification, setLegacyVerification] = useState('');
  const [legacyConfirmed, setLegacyConfirmed] = useState(false);
  const [isLegacy, setIsLegacy] = useState(false);

  // Recompute the v2 out-of-band code whenever the pasted code changes, and
  // require re-confirmation of the new value. On v3 codes there is nothing to
  // show yet — the value the user compares is derived from a key this device
  // has not generated until it claims the grant.
  useEffect(() => {
    setLegacyConfirmed(false);
    const trimmed = code.trim();
    if (!trimmed) {
      setLegacyVerification('');
      setIsLegacy(false);
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const v3 = await invoke<boolean>('is_v3_enrollment_code', { code: trimmed });
        if (cancelled) return;
        setIsLegacy(!v3);
        if (v3) {
          setLegacyVerification('');
          return;
        }
        const shortCode = await invoke<string>('enrollment_verification_code', { code: trimmed });
        if (!cancelled) setLegacyVerification(shortCode);
      } catch {
        if (!cancelled) setLegacyVerification('');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [code]);

  const cancel = useCallback(() => {
    void invoke('cancel_enrollment_join').catch(() => {});
    onClose();
  }, [onClose]);

  const finish = useCallback(
    async (grantId: string) => {
      setPhase('joining');
      try {
        await invoke('finish_enrollment_join', { grantId, password });
        onComplete();
      } catch (e) {
        setError(typeof e === 'string' ? e : 'Could not finish joining. Please start again.');
        setPhase('entry');
        setRequest(null);
        grantIdRef.current = null;
      }
    },
    [onComplete, password],
  );

  // Wait for the other device's user to pick this device's fingerprint.
  useEffect(() => {
    if (phase !== 'waiting' || !request) return;
    let cancelled = false;
    const timer = setInterval(async () => {
      const grantId = grantIdRef.current;
      if (!grantId) return;
      try {
        const status = await invoke<'waiting' | 'enrolled'>('poll_enrollment_join', { grantId });
        if (!cancelled && status === 'enrolled') {
          clearInterval(timer);
          await finish(grantId);
        }
      } catch (e) {
        if (!cancelled) {
          clearInterval(timer);
          setError(typeof e === 'string' ? e : 'The enrollment code is no longer valid.');
          setPhase('entry');
          setRequest(null);
          grantIdRef.current = null;
        }
      }
    }, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [phase, request, finish]);

  const start = async () => {
    const trimmed = code.trim();
    if (!trimmed) {
      setError('Please paste the enrollment code.');
      return;
    }
    if (!password) {
      setError('Please set a password to protect the vault on this device.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const v3 = await invoke<boolean>('is_v3_enrollment_code', { code: trimmed });
      if (v3) {
        const req = await invoke<JoinRequest>('begin_enrollment_join', { code: trimmed });
        setRequest(req);
        grantIdRef.current = req.grant_id;
        setPhase('waiting');
      } else {
        if (!legacyConfirmed) {
          setError('Confirm the verification code matches your other device first.');
          return;
        }
        await invoke('import_enrollment_code', { code: trimmed, password });
        onComplete();
      }
    } catch (e) {
      setError(typeof e === 'string' ? e : 'Could not use this code. Check it and try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={cancel}>
      <div
        className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto shadow-2xl border border-outline-variant/20"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 mb-6">
          <span className="material-symbols-outlined text-2xl text-primary">vpn_key</span>
          <h2 className="font-headline text-2xl font-bold text-on-surface">Join existing account</h2>
        </div>

        {/* ── Waiting for the other device to confirm ──────────────────── */}
        {(phase === 'waiting' || phase === 'joining') && request && (
          <>
            <p className="text-on-surface-variant text-sm mb-5">
              Your other device is now showing several codes. Pick <strong>this</strong> one on it:
            </p>
            <div className="font-mono text-2xl font-bold tracking-widest text-on-surface text-center py-6 bg-surface-bright rounded-xl mb-4">
              {request.fingerprint}
            </div>
            <p className="text-on-surface-variant text-xs mb-5">
              This code is computed on this device from the key it just generated for itself. Nobody
              else can produce it, which is what makes picking it on your other device meaningful.
            </p>
            <div className="flex items-center justify-center gap-2 mb-6 text-sm text-on-surface-variant">
              <span className="material-symbols-outlined text-base animate-pulse">sync</span>
              {phase === 'joining' ? 'Confirmed — downloading your vault…' : 'Waiting for confirmation…'}
            </div>
            {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
            <button
              onClick={cancel}
              disabled={phase === 'joining'}
              className="w-full py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
          </>
        )}

        {/* ── Entry ────────────────────────────────────────────────────── */}
        {phase === 'entry' && (
          <>
            <p className="text-on-surface-variant text-sm mb-5">
              Paste the enrollment code from your other device, then set a password to protect the
              vault on this one.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-on-surface-variant mb-1">
                  Enrollment code
                </label>
                <textarea
                  value={code}
                  onChange={e => setCode(e.target.value)}
                  placeholder="Paste enrollment code here…"
                  rows={4}
                  className="w-full bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 text-on-surface text-xs font-mono placeholder-on-surface-variant/40 focus:outline-none focus:border-primary resize-none"
                />
              </div>

              {isLegacy && legacyVerification && (
                <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="material-symbols-outlined text-amber-400 text-lg">verified_user</span>
                    <span className="font-label text-sm font-bold text-amber-300">
                      Old-style code — verify it
                    </span>
                  </div>
                  <p className="text-on-surface-variant text-xs mb-2">
                    This code carries the vault key itself, so it is only as safe as the way it
                    reached you. Compare the number below against the one on your other device. If
                    they differ, stop.
                  </p>
                  <div className="font-mono text-xl font-bold tracking-widest text-on-surface text-center py-1 mb-2">
                    {legacyVerification}
                  </div>
                  <label className="flex items-center gap-2 text-xs text-on-surface cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={legacyConfirmed}
                      onChange={e => setLegacyConfirmed(e.target.checked)}
                      className="w-4 h-4 rounded border-outline-variant bg-surface-container text-primary accent-primary"
                    />
                    It matches the code on my other device
                  </label>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-on-surface-variant mb-1">
                  Vault password (this device)
                </label>
                <div className="relative">
                  <input
                    type={passwordVisible ? 'text' : 'password'}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="Set a password for this device"
                    className="w-full bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 pr-12 text-on-surface placeholder-on-surface-variant/40 focus:outline-none focus:border-primary"
                  />
                  <button
                    type="button"
                    onClick={() => setPasswordVisible(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface"
                  >
                    <span className="material-symbols-outlined text-xl">
                      {passwordVisible ? 'visibility_off' : 'visibility'}
                    </span>
                  </button>
                </div>
              </div>

              {error && <p className="text-red-400 text-sm">{error}</p>}
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={cancel}
                className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={start}
                disabled={busy || (isLegacy && !legacyConfirmed)}
                className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
              >
                {busy ? 'Working…' : 'Continue'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
