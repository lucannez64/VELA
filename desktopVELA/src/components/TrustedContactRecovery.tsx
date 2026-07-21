import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface Props {
  onComplete: () => void;
  onSkip: () => void;
}

// Share 3 of the account's 2-of-3 recovery split (SPEC.md §4.3). Unlike
// Share 1 (cloud) and Share 2 (server), there is no VELA-operated channel
// for this one — it's handed to the user to deliver to their trusted
// contact however they choose. A lone share below the 2-of-3 threshold is
// information-theoretically indistinguishable from random bytes, so
// showing it plainly here doesn't expose anything about the vault.
export default function TrustedContactRecovery({ onComplete, onSkip }: Props) {
  const { showToast } = useApp();
  const [share, setShare] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [acknowledging, setAcknowledging] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await invoke<string>('get_trusted_contact_share');
        if (!cancelled) setShare(result);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : 'Failed to generate recovery share');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleCopy = async () => {
    if (!share) return;
    try {
      await navigator.clipboard.writeText(share);
      setCopied(true);
      showToast('Recovery share copied', 'success');
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      showToast('Failed to copy', 'error');
    }
  };

  const handleDone = async () => {
    setAcknowledging(true);
    try {
      await invoke('acknowledge_trusted_contact_share');
    } catch (e) {
      // Best-effort bookkeeping only — the share was already generated and
      // shown, so don't block the user on this call failing.
    } finally {
      setAcknowledging(false);
    }
    onComplete();
  };

  return (
    <div className="max-w-lg w-full mx-auto">
      <div className="text-center mb-8">
        <div className="w-16 h-16 mx-auto mb-4 bg-secondary/20 rounded-full flex items-center justify-center">
          <span className="material-symbols-outlined text-secondary text-4xl">person_add</span>
        </div>
        <h3 className="font-headline text-2xl font-bold text-on-surface mb-2">Trusted Contact Recovery</h3>
        <p className="text-on-surface-variant">
          One of three recovery pieces. Send it to someone you trust — they only need to hand it back if you lose every device.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-8">
          <span className="material-symbols-outlined text-3xl text-primary animate-spin">progress_activity</span>
        </div>
      ) : error ? (
        <div className="space-y-4">
          <p className="text-error text-sm text-center">{error}</p>
          <button
            onClick={onSkip}
            className="w-full py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Skip for now
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="p-4 bg-surface-container rounded-xl">
            <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">
              Recovery share — send this to your trusted contact
            </label>
            <p className="font-mono text-sm text-on-surface break-all bg-surface-container-highest rounded-lg p-3">
              {share}
            </p>
          </div>

          <button
            onClick={handleCopy}
            className="w-full py-3 bg-surface-container-highest hover:bg-surface-bright rounded-xl text-on-surface font-medium transition-colors flex items-center justify-center gap-2"
          >
            <span className="material-symbols-outlined text-lg">{copied ? 'check' : 'content_copy'}</span>
            {copied ? 'Copied' : 'Copy to clipboard'}
          </button>

          <div className="p-4 bg-surface-container rounded-xl">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-primary text-lg">info</span>
              <p className="text-sm text-on-surface-variant">
                Send this over any channel you trust (message, email, in person). On its own it reveals nothing
                about your vault — VELA never transmits or stores a copy of it for you.
              </p>
            </div>
          </div>

          <div className="flex gap-4 pt-2">
            <button
              onClick={onSkip}
              className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
            >
              Skip for now
            </button>
            <button
              onClick={handleDone}
              disabled={acknowledging}
              className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-bold hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {acknowledging ? 'Saving...' : "I've sent it"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
