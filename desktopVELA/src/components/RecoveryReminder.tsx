import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface RecoveryStatus {
  cloud_backup_delivered: boolean;
  security_key_delivered: boolean;
  trusted_contact_acknowledged: boolean;
  setup_in_progress: boolean;
}

interface Props {
  onOpenSettings: () => void;
}

/**
 * A standing reminder that this vault has no way back.
 *
 * Setup lets you defer recovery, because a hard gate strands people who have
 * not got a security key to hand and pushes the honest ones towards
 * workarounds. This is the other half of that bargain: deferring is allowed,
 * forgetting is not. Without it, "set this up later" is a polite way of saying
 * "never", and the cost of never lands years afterwards, on someone who has
 * forgotten a master password and cannot be helped by anyone.
 *
 * Deliberately not dismissable. A banner you can close is one you close, and
 * the failure it warns about is unrecoverable rather than inconvenient. It goes
 * away by being fixed.
 */
export default function RecoveryReminder({ onOpenSettings }: Props) {
  const [methods, setMethods] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    const check = async () => {
      try {
        const status = await invoke<RecoveryStatus>('get_recovery_setup_status');
        if (cancelled) return;
        setMethods(
          [
            status.cloud_backup_delivered,
            status.security_key_delivered,
            status.trusted_contact_acknowledged,
          ].filter(Boolean).length
        );
      } catch {
        // A locked vault cannot answer, and a banner is not the place to
        // report that. Stay quiet rather than guessing.
        if (!cancelled) setMethods(null);
      }
    };

    check();
    // Re-check periodically so the banner disappears once recovery is set up
    // in Settings, without needing a restart.
    const interval = setInterval(check, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (methods === null || methods >= 2) {
    return null;
  }

  return (
    <div className="px-4 py-3 bg-error-container/25 border-b border-error/30 flex items-center gap-3">
      <span className="material-symbols-outlined text-error text-xl shrink-0">
        shield_question
      </span>
      <div className="text-sm text-on-surface min-w-0 flex-1">
        This vault has no way back if you forget your master password
        <span className="block text-xs text-on-surface-variant">
          {methods === 0
            ? 'No recovery methods are set up.'
            : '1 of the 2 recovery methods is set up.'}{' '}
          Nobody can restore it for you — not support, not us.
        </span>
      </div>
      <button
        onClick={onOpenSettings}
        className="shrink-0 py-2 px-4 rounded-lg bg-error/90 text-on-error text-sm font-medium hover:opacity-90 transition-opacity"
      >
        Set up recovery
      </button>
    </div>
  );
}
