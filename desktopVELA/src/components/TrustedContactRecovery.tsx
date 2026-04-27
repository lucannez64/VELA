import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface Props {
  onComplete: () => void;
  onSkip: () => void;
}

export default function TrustedContactRecovery({ onComplete, onSkip }: Props) {
  const { showToast } = useApp();
  const [email, setEmail] = useState('');
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSendInvite = async () => {
    if (!email.trim()) {
      showToast('Please enter an email address', 'error');
      return;
    }

    if (!email.includes('@')) {
      showToast('Please enter a valid email address', 'error');
      return;
    }

    setSending(true);
    try {
      await invoke('send_recovery_invite', { email });
      setSent(true);
      showToast('Recovery invitation queued', 'success');
    } catch (e) {
      showToast('Failed to send invitation', 'error');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="max-w-lg w-full mx-auto">
      <div className="text-center mb-8">
        <div className="w-16 h-16 mx-auto mb-4 bg-secondary/20 rounded-full flex items-center justify-center">
          <span className="material-symbols-outlined text-secondary text-4xl">person_add</span>
        </div>
        <h3 className="font-headline text-2xl font-bold text-on-surface mb-2">
          {sent ? 'Invitation Sent!' : 'Trusted Contact Recovery'}
        </h3>
        <p className="text-on-surface-variant">
          {sent 
            ? `A recovery contact invite has been queued for ${email}.`
            : 'Queue a trusted contact invite for account recovery.'
          }
        </p>
      </div>

      {!sent ? (
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-label uppercase tracking-widest text-slate-500 mb-2">
              VELA Username or Email
            </label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40"
              placeholder="friend@example.com"
            />
          </div>

          <div className="p-4 bg-surface-container rounded-xl">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-primary text-lg">info</span>
              <p className="text-sm text-on-surface-variant">
                The invite is stored locally until contact delivery is configured.
              </p>
            </div>
          </div>

          <div className="flex gap-4 pt-4">
            <button
              onClick={onSkip}
              className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
            >
              Skip for now
            </button>
            <button
              onClick={handleSendInvite}
              disabled={sending}
              className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-bold hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {sending ? 'Sending...' : 'Send Invitation'}
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="p-6 bg-primary/10 border border-primary/30 rounded-xl text-center">
            <span className="material-symbols-outlined text-primary text-5xl mb-3 block">check_circle</span>
            <p className="text-on-surface font-medium">Recovery contact invite queued</p>
          </div>

          <button
            onClick={onComplete}
            className="w-full py-3 bg-primary text-on-primary rounded-xl font-bold hover:bg-primary/90 transition-colors"
          >
            Continue
          </button>
        </div>
      )}
    </div>
  );
}
