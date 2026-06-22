import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface Props {
  open: boolean;
  onClose: () => void;
}

const TTL_PRESETS: { label: string; secs: number }[] = [
  { label: '30 minutes', secs: 30 * 60 },
  { label: '1 hour', secs: 60 * 60 },
  { label: '8 hours', secs: 8 * 60 * 60 },
  { label: '24 hours', secs: 24 * 60 * 60 },
];

/**
 * Approve a browser's temporary, revocable web access to this vault
 * (EPHEMERAL_WEB_ACCESS_DESIGN.md). Paste the code shown by the web page, pick a
 * mode and duration, and seal the capsule to the browser's ephemeral key.
 */
export default function WebAccessModal({ open, onClose }: Props) {
  const { showToast } = useApp();
  const [code, setCode] = useState('');
  const [mode, setMode] = useState<'ro' | 'rw'>('ro');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [ttlSecs, setTtlSecs] = useState(TTL_PRESETS[0].secs);
  const [submitting, setSubmitting] = useState(false);

  if (!open) return null;

  const approve = async () => {
    if (!code.trim()) {
      showToast('Paste the web access code first', 'error');
      return;
    }
    setSubmitting(true);
    try {
      const res = await invoke<{ expires_at: string; mode: string }>('grant_web_session', {
        qrPayload: code.trim(),
        mode,
        ttlSecs,
      });
      const until = new Date(res.expires_at).toLocaleTimeString();
      showToast(
        `Web access granted (${res.mode === 'rw' ? 'read & write' : 'read-only'}) until ${until}`,
        'success',
      );
      setCode('');
      setMode('ro');
      setShowAdvanced(false);
      onClose();
    } catch (e) {
      showToast(`Could not grant web access: ${e}`, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-surface-container p-8 shadow-xl">
        <h2 className="font-headline text-2xl font-bold text-on-surface mb-1">Approve web access</h2>
        <p className="text-on-surface-variant mb-6 text-sm">
          Temporarily open this vault in a browser, with no install and no permanent device. Access
          expires automatically and can be revoked any time.
        </p>

        <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">
          Web access code
        </label>
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Paste the code shown by the web page…"
          rows={4}
          className="w-full rounded-xl bg-surface p-3 text-sm font-mono text-on-surface border border-outline-variant/20 mb-6 resize-none"
        />

        <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">Duration</label>
        <select
          value={ttlSecs}
          onChange={(e) => setTtlSecs(Number(e.target.value))}
          className="w-full rounded-xl bg-surface p-3 text-sm text-on-surface border border-outline-variant/20 mb-6"
        >
          {TTL_PRESETS.map((p) => (
            <option key={p.secs} value={p.secs}>
              {p.label}
            </option>
          ))}
        </select>

        {!showAdvanced ? (
          <button
            onClick={() => setShowAdvanced(true)}
            className="text-sm text-on-surface-variant underline mb-6"
          >
            Advanced — I trust this device
          </button>
        ) : (
          <div className="mb-6">
            <label className="block text-xs uppercase tracking-widest text-slate-500 mb-2">Mode</label>
            <div className="flex gap-3">
              <button
                onClick={() => setMode('ro')}
                className={`flex-1 rounded-xl p-3 text-sm font-label border ${
                  mode === 'ro'
                    ? 'bg-primary text-on-primary border-primary'
                    : 'bg-surface text-on-surface border-outline-variant/20'
                }`}
              >
                Read-only (safer)
              </button>
              <button
                onClick={() => setMode('rw')}
                className={`flex-1 rounded-xl p-3 text-sm font-label border ${
                  mode === 'rw'
                    ? 'bg-primary text-on-primary border-primary'
                    : 'bg-surface text-on-surface border-outline-variant/20'
                }`}
              >
                Read &amp; write
              </button>
            </div>
            {mode === 'rw' && (
              <p className="text-xs text-amber-500 mt-2">
                Read &amp; write sends this device's master key to the browser for the session. Only
                use it on a device you trust.
              </p>
            )}
          </div>
        )}

        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            disabled={submitting}
            className="px-6 py-3 rounded-xl font-bold text-on-surface-variant hover:bg-surface transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={approve}
            disabled={submitting}
            className="px-6 py-3 rounded-xl font-bold bg-primary text-on-primary hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {submitting ? 'Approving…' : 'Approve'}
          </button>
        </div>
      </div>
    </div>
  );
}
