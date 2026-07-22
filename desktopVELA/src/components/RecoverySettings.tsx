import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import TrustedContactRecovery from './TrustedContactRecovery';
import { unwrapPublicKeyOptions, decodeCreationOptions, credentialToJSON } from '../lib/webauthn';

interface RecoveryStatus {
  cloud_backup_delivered: boolean;
  security_key_delivered: boolean;
  trusted_contact_acknowledged: boolean;
  setup_in_progress: boolean;
}

// Post-setup recovery management (SPEC.md §4.3). Reuses the same backend
// commands as the onboarding recovery step. One rule shapes this UI: the
// three delivered shares all come from a single 2-of-3 split, and once setup
// is finalized the cached shares are wiped — so redoing ANY method later
// forces a fresh split that invalidates everything delivered before. The
// component therefore distinguishes "continue an in-progress setup" (safe,
// same split) from "reconfigure from scratch" (warns, resets all methods).
export default function RecoverySettings() {
  const [status, setStatus] = useState<RecoveryStatus | null>(null);
  const [loadError, setLoadError] = useState('');
  const [editing, setEditing] = useState(false);
  const [showRegenWarning, setShowRegenWarning] = useState(false);
  const [showTrustedContact, setShowTrustedContact] = useState(false);

  const [showCloudBackupPicker, setShowCloudBackupPicker] = useState(false);
  const [cloudRemotes, setCloudRemotes] = useState<string[] | null>(null);
  const [selectedRemote, setSelectedRemote] = useState('');
  const [cloudBackupError, setCloudBackupError] = useState('');
  const [isLoadingRemotes, setIsLoadingRemotes] = useState(false);
  const [isSettingUpCloudBackup, setIsSettingUpCloudBackup] = useState(false);

  const [securityKeyError, setSecurityKeyError] = useState('');
  const [isSettingUpSecurityKey, setIsSettingUpSecurityKey] = useState(false);

  const [isFinalizing, setIsFinalizing] = useState(false);

  const loadStatus = useCallback(async () => {
    try {
      const result = await invoke<RecoveryStatus>('get_recovery_setup_status');
      setStatus(result);
      setLoadError('');
      return result;
    } catch (e) {
      setLoadError(String(e));
      return null;
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  if (loadError) {
    return (
      <div className="bg-surface-container rounded-xl p-6">
        <p className="text-sm text-on-surface-variant">Recovery status unavailable: {loadError}</p>
      </div>
    );
  }

  if (!status) {
    return (
      <div className="bg-surface-container rounded-xl p-6 flex justify-center">
        <span className="material-symbols-outlined text-2xl text-primary animate-spin">progress_activity</span>
      </div>
    );
  }

  const methods = [
    {
      key: 'cloudBackup',
      done: status.cloud_backup_delivered,
      icon: 'cloud_upload',
      title: 'Cloud backup',
      doneLabel: 'Share uploaded via rclone',
      todoLabel: 'Upload a recovery share via rclone',
    },
    {
      key: 'securityKey',
      done: status.security_key_delivered,
      icon: 'key',
      title: 'Security key',
      doneLabel: 'Recovery passkey registered',
      todoLabel: 'Register a passkey to gate the server share',
    },
    {
      key: 'trustedContact',
      done: status.trusted_contact_acknowledged,
      icon: 'person_add',
      title: 'Trusted contact',
      doneLabel: 'Share handed to your contact',
      todoLabel: 'Give a share to someone you trust',
    },
  ] as const;

  const completedCount = methods.filter(m => m.done).length;
  const configured = completedCount >= 2;

  const handleStartEditing = () => {
    if (status.setup_in_progress) {
      // Cached shares still exist — remaining methods complete the same split.
      setEditing(true);
    } else if (completedCount > 0) {
      setShowRegenWarning(true);
    } else {
      setEditing(true);
    }
  };

  const confirmRegenerate = () => {
    // The next method action re-splits on the backend and resets the
    // delivered flags; mirror that locally so the cards don't show stale
    // checkmarks from the previous split.
    setStatus(prev => prev && {
      cloud_backup_delivered: false,
      security_key_delivered: false,
      trusted_contact_acknowledged: false,
      setup_in_progress: prev.setup_in_progress,
    });
    setShowRegenWarning(false);
    setEditing(true);
  };

  const handleOpenCloudBackupPicker = async () => {
    setCloudBackupError('');
    setShowCloudBackupPicker(true);
    setIsLoadingRemotes(true);
    try {
      const remotes = await invoke<string[]>('list_cloud_backup_remotes');
      setCloudRemotes(remotes);
      if (remotes.length > 0) setSelectedRemote(remotes[0]);
    } catch (e) {
      setCloudRemotes([]);
      setCloudBackupError(e instanceof Error ? e.message : 'Could not list rclone remotes');
    } finally {
      setIsLoadingRemotes(false);
    }
  };

  const handleConfirmCloudBackup = async () => {
    if (!selectedRemote) return;
    setIsSettingUpCloudBackup(true);
    setCloudBackupError('');
    try {
      await invoke('setup_cloud_backup_recovery', { remote: selectedRemote });
      setShowCloudBackupPicker(false);
      await loadStatus();
    } catch (e) {
      setCloudBackupError(e instanceof Error ? e.message : 'Cloud backup upload failed');
    } finally {
      setIsSettingUpCloudBackup(false);
    }
  };

  const handleSecurityKeySetup = async () => {
    if (!navigator.credentials?.create) {
      setSecurityKeyError('WebAuthn is not available in this WebView.');
      return;
    }
    setSecurityKeyError('');
    setIsSettingUpSecurityKey(true);
    try {
      const response = await invoke<any>('start_recovery_webauthn_registration');
      const publicKey = unwrapPublicKeyOptions(response);
      const credential = await navigator.credentials.create({
        publicKey: decodeCreationOptions(publicKey),
      });
      if (!credential) {
        throw new Error('No credential was created');
      }
      const registered = await invoke<boolean>('finish_recovery_webauthn_registration', {
        credential: credentialToJSON(credential as PublicKeyCredential),
      });
      if (registered) {
        await loadStatus();
      }
    } catch (e) {
      setSecurityKeyError(e instanceof Error ? e.message : 'Security key setup failed');
    } finally {
      setIsSettingUpSecurityKey(false);
    }
  };

  const handleFinish = async () => {
    setIsFinalizing(true);
    try {
      await invoke('finalize_recovery_setup');
    } catch (e) {
      // Best-effort cleanup of the local pending-shares cache — the shares
      // that were actually delivered are unaffected either way.
    } finally {
      setIsFinalizing(false);
    }
    await loadStatus();
    setEditing(false);
  };

  if (!editing) {
    return (
      <div className="bg-surface-container rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <span
              className={`material-symbols-outlined text-2xl ${configured ? 'text-primary' : 'text-amber-500'}`}
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              {configured ? 'verified_user' : 'gpp_maybe'}
            </span>
            <div>
              <label className="font-body font-medium text-on-surface">
                {configured
                  ? 'Recovery is configured'
                  : status.setup_in_progress
                    ? 'Recovery setup in progress'
                    : 'Recovery not configured'}
              </label>
              <p className="text-sm text-on-surface-variant">
                {configured
                  ? `${completedCount} of 3 methods active — any 2 can restore your vault`
                  : status.setup_in_progress
                    ? 'Finish configuring at least 2 methods'
                    : 'Set up at least 2 methods to restore your vault if all devices are lost'}
              </p>
            </div>
          </div>
          <button
            onClick={handleStartEditing}
            className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors"
          >
            {status.setup_in_progress ? 'Continue setup' : configured ? 'Reconfigure' : 'Set up recovery'}
          </button>
        </div>

        <div className="space-y-2 pt-2 border-t border-outline-variant/20">
          {methods.map(method => (
            <div key={method.key} className="flex items-center gap-3">
              <span className={`material-symbols-outlined text-lg ${method.done ? 'text-primary' : 'text-on-surface-variant/50'}`}>
                {method.done ? 'check_circle' : 'radio_button_unchecked'}
              </span>
              <span className="text-sm text-on-surface">{method.title}</span>
              <span className="text-sm text-on-surface-variant ml-auto">
                {method.done ? method.doneLabel : 'Not set up'}
              </span>
            </div>
          ))}
        </div>

        {showRegenWarning && (
          <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={() => setShowRegenWarning(false)}>
            <div
              className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-md w-full shadow-2xl border border-amber-500/30"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center gap-3 mb-4">
                <span className="material-symbols-outlined text-amber-500 text-2xl">warning</span>
                <h2 className="font-headline text-2xl font-bold text-on-surface">Regenerate recovery shares?</h2>
              </div>
              <p className="text-on-surface-variant mb-6">
                Changing recovery methods creates a fresh set of shares. Shares from your previous
                setup can't be mixed with new ones, so you'll need to complete at least 2 methods
                again — including re-sending a new share to your trusted contact if you use that
                method. Your vault stays intact either way.
              </p>
              <div className="flex gap-4">
                <button
                  onClick={() => setShowRegenWarning(false)}
                  className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={confirmRegenerate}
                  className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-bold hover:opacity-90 transition-opacity"
                >
                  Reconfigure
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="bg-surface-container rounded-xl p-6 space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <label className="font-body font-medium text-on-surface">Recovery methods</label>
          <p className="text-sm text-on-surface-variant">
            Complete at least 2 — any 2 shares can restore your vault
          </p>
        </div>
        <button
          onClick={() => { loadStatus(); setEditing(false); }}
          className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors"
        >
          Close
        </button>
      </div>

      <div className={`p-4 rounded-xl border ${status.cloud_backup_delivered ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface-container-low'}`}>
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={`material-symbols-outlined ${status.cloud_backup_delivered ? 'text-primary' : 'text-on-surface-variant'}`}>
              {status.cloud_backup_delivered ? 'check_circle' : 'cloud_upload'}
            </span>
            <div>
              <div className="font-body font-medium text-on-surface">Cloud backup</div>
              <div className="text-sm text-on-surface-variant">
                {status.cloud_backup_delivered ? 'Share uploaded' : 'Upload a recovery share via rclone'}
              </div>
            </div>
          </div>
          {!status.cloud_backup_delivered && !showCloudBackupPicker && (
            <button
              onClick={handleOpenCloudBackupPicker}
              className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
            >
              Enable
            </button>
          )}
        </div>

        {!status.cloud_backup_delivered && showCloudBackupPicker && (
          <div className="mt-4 pt-4 border-t border-outline-variant/20 space-y-3">
            {isLoadingRemotes ? (
              <p className="text-sm text-on-surface-variant">Looking for configured rclone remotes...</p>
            ) : cloudRemotes && cloudRemotes.length > 0 ? (
              <>
                <label className="block text-xs font-label uppercase tracking-widest text-outline">
                  Choose a remote
                </label>
                <select
                  value={selectedRemote}
                  onChange={e => setSelectedRemote(e.target.value)}
                  className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40"
                >
                  {cloudRemotes.map(remote => (
                    <option key={remote} value={remote}>{remote}</option>
                  ))}
                </select>
                <div className="flex gap-2">
                  <button
                    onClick={() => setShowCloudBackupPicker(false)}
                    className="flex-1 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleConfirmCloudBackup}
                    disabled={isSettingUpCloudBackup}
                    className="flex-1 py-2 bg-primary text-on-primary rounded-lg text-sm font-bold hover:bg-primary/90 transition-colors disabled:opacity-50"
                  >
                    {isSettingUpCloudBackup ? 'Uploading...' : 'Upload share'}
                  </button>
                </div>
              </>
            ) : (
              <>
                <p className="text-sm text-on-surface-variant">
                  No configured rclone remotes found. Install{' '}
                  <span className="font-mono text-on-surface">rclone</span> and run{' '}
                  <span className="font-mono text-on-surface">rclone config</span> to add one
                  (Google Drive, S3, iCloud via WebDAV, etc.), then come back here.
                </p>
                <button
                  onClick={() => setShowCloudBackupPicker(false)}
                  className="w-full py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                >
                  Close
                </button>
              </>
            )}
            {cloudBackupError && (
              <p className="text-sm text-error">{cloudBackupError}</p>
            )}
          </div>
        )}
      </div>

      <div className={`p-4 rounded-xl border ${status.security_key_delivered ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface-container-low'}`}>
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={`material-symbols-outlined ${status.security_key_delivered ? 'text-primary' : 'text-on-surface-variant'}`}>
              {status.security_key_delivered ? 'check_circle' : 'key'}
            </span>
            <div>
              <div className="font-body font-medium text-on-surface">Security key</div>
              <div className="text-sm text-on-surface-variant">
                {status.security_key_delivered ? 'Passkey registered' : 'Register a passkey to gate the server share'}
              </div>
            </div>
          </div>
          {!status.security_key_delivered && (
            <button
              onClick={handleSecurityKeySetup}
              disabled={isSettingUpSecurityKey}
              className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
            >
              {isSettingUpSecurityKey ? 'Waiting...' : 'Enable'}
            </button>
          )}
        </div>
        {securityKeyError && (
          <p className="mt-3 text-sm text-error">{securityKeyError}</p>
        )}
      </div>

      <div className={`p-4 rounded-xl border ${status.trusted_contact_acknowledged ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface-container-low'}`}>
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={`material-symbols-outlined ${status.trusted_contact_acknowledged ? 'text-primary' : 'text-on-surface-variant'}`}>
              {status.trusted_contact_acknowledged ? 'check_circle' : 'person_add'}
            </span>
            <div>
              <div className="font-body font-medium text-on-surface">Trusted contact</div>
              <div className="text-sm text-on-surface-variant">
                {status.trusted_contact_acknowledged ? 'Share sent' : 'Give a share to someone you trust'}
              </div>
            </div>
          </div>
          {!status.trusted_contact_acknowledged && (
            <button
              onClick={() => setShowTrustedContact(true)}
              className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
            >
              Get my share
            </button>
          )}
        </div>
      </div>

      <div>
        <div className="flex justify-between text-sm text-on-surface-variant mb-2">
          <span>Progress</span>
          <span>{completedCount >= 2 ? '2/2 complete' : `${completedCount}/2 required`}</span>
        </div>
        <div className="h-2 bg-surface-container-highest rounded-full overflow-hidden">
          <div
            className="h-full bg-primary rounded-full transition-all"
            style={{ width: `${Math.min(completedCount, 2) / 2 * 100}%` }}
          />
        </div>
      </div>

      <button
        onClick={handleFinish}
        disabled={completedCount < 2 || isFinalizing}
        className="w-full py-3 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {isFinalizing ? 'Finishing...' : 'Finish recovery setup'}
      </button>

      {showTrustedContact && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-lg w-full shadow-2xl my-auto">
            <TrustedContactRecovery
              onComplete={async () => {
                await loadStatus();
                setShowTrustedContact(false);
              }}
              onSkip={() => setShowTrustedContact(false)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
