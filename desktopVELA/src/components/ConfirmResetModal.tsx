import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface ConfirmResetModalProps {
  /** Called after the vault was successfully reset. */
  onReset: () => void;
  onCancel: () => void;
}

/**
 * Typed-confirmation gate for `reset_vault`. The backend requires either the
 * master password or the literal text DELETE before it wipes anything — a bare
 * click (or a script driving the UI) must never be able to destroy the vault.
 */
export default function ConfirmResetModal({ onReset, onCancel }: ConfirmResetModalProps) {
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleReset = async () => {
    setBusy(true);
    setError(null);
    try {
      await invoke('reset_vault', { confirm: text });
      onReset();
    } catch (e) {
      setError(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onCancel}>
      <div
        className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-md w-full shadow-2xl border border-red-500/30"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 mb-4">
          <span className="material-symbols-outlined text-red-400 text-2xl">warning</span>
          <h2 className="font-headline text-2xl font-bold text-on-surface">Reset vault?</h2>
        </div>
        <p className="text-on-surface-variant mb-6">
          This action is irreversible. All vault data and credentials on this device will be
          permanently deleted. Type <span className="font-mono text-red-400">DELETE</span> to confirm.
        </p>
        <input
          type="text"
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Type DELETE"
          autoFocus
          className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-red-500/40 mb-4"
        />
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
        <div className="flex gap-4">
          <button
            onClick={onCancel}
            className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Cancel
          </button>
          <button
            disabled={text !== 'DELETE' || busy}
            onClick={handleReset}
            className="flex-1 py-3 bg-red-500 text-white rounded-xl font-medium hover:bg-red-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Reset forever
          </button>
        </div>
      </div>
    </div>
  );
}
