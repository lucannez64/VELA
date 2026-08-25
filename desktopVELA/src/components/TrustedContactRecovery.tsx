import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface Props {
  onComplete: () => void;
  onSkip: () => void;
}

interface ContactShareHandoff {
  version: number;
  account_id: string;
  key_epoch: number;
  split_id: string;
  coordinate: number;
  envelope_b64: string;
}

// Share 3 of the account's 2-of-3 recovery split (SPEC.md §4.3, M18). Unlike
// the manual-copy flow this replaces, the share is sealed into an
// authenticated, recipient-bound envelope for the contact's KEM public key:
// only the holder of that key can open it, and the envelope is bound to this
// exact account, epoch, Shamir split, and coordinate — forwarding or storing
// it elsewhere reveals nothing about the vault.
export default function TrustedContactRecovery({ onComplete, onSkip }: Props) {
  const { showToast } = useApp();
  const [contactKey, setContactKey] = useState('');
  const [handoff, setHandoff] = useState<ContactShareHandoff | null>(null);
  const [sealing, setSealing] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [acknowledging, setAcknowledging] = useState(false);

  const handleSeal = async () => {
    const key = contactKey.trim();
    if (!key) {
      setError("Paste your contact's public key first");
      return;
    }
    setSealing(true);
    setError('');
    try {
      const result = await invoke<ContactShareHandoff>('seal_trusted_contact_share', {
        contactPublicKeyB64: key,
      });
      setHandoff(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to seal recovery envelope');
    } finally {
      setSealing(false);
    }
  };

  const handoffText = handoff ? JSON.stringify(handoff) : '';

  const handleCopy = async () => {
    if (!handoffText) return;
    try {
      // The sealed envelope is not secret, but copy it as a secret anyway so
      // it stays out of clipboard history like every other recovery artifact.
      await invoke('copy_secret', { text: handoffText });
      setCopied(true);
      showToast('Recovery envelope copied', 'success');
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
      // Best-effort bookkeeping only — the envelope was already sealed and
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
          One of three recovery pieces. Paste your contact's public key to seal this recovery
          share into an envelope only they can open.
        </p>
      </div>

      {error && <p className="text-error text-sm text-center mb-4">{error}</p>}

      {!handoff ? (
        <div className="space-y-4">
          <div className="p-4 bg-surface-container rounded-xl">
            <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">
              Contact public key
            </label>
            <textarea
              value={contactKey}
              onChange={(e) => setContactKey(e.target.value)}
              placeholder="Base64 contact public key"
              rows={3}
              className="w-full font-mono text-sm text-on-surface bg-surface-container-highest rounded-lg p-3 resize-none focus:outline-none"
            />
          </div>

          <button
            onClick={handleSeal}
            disabled={sealing}
            className="w-full py-3 bg-primary text-on-primary rounded-xl font-bold hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {sealing ? (
              <span className="material-symbols-outlined text-lg animate-spin">progress_activity</span>
            ) : (
              <span className="material-symbols-outlined text-lg">lock</span>
            )}
            {sealing ? 'Sealing…' : 'Seal envelope'}
          </button>

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
              Sealed recovery envelope — send this to your trusted contact
            </label>
            <p className="font-mono text-xs text-on-surface break-all bg-surface-container-highest rounded-lg p-3 max-h-40 overflow-y-auto">
              {handoffText}
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
                Send this over any channel you trust. Only your contact can open it — it is bound
                to them, to this account, and to the current key epoch, so a stale or redirected
                copy is useless.
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
