import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { unwrapPublicKeyOptions, decodeRequestOptions, credentialToJSON } from '../lib/webauthn';

interface Props {
  onComplete: () => void;
  onClose: () => void;
}

interface CloudRecoveryShare {
  user_id: string;
  share_b64: string;
}

type Step = 'remote' | 'confirm' | 'device';

// Account recovery (SPEC.md §4.3): reconstruct the RMS from Share 1 (cloud
// backup) + Share 2 (server, released only after a WebAuthn assertion
// against the recovery passkey), then register this device against the
// existing account and pull the vault down. Used when every enrolled device
// has been lost — there is no peer device to hand over an enrollment code.
export default function RecoverAccountModal({ onComplete, onClose }: Props) {
  const [step, setStep] = useState<Step>('remote');
  const [remotes, setRemotes] = useState<string[] | null>(null);
  const [selectedRemote, setSelectedRemote] = useState('');
  const [isLoadingRemotes, setIsLoadingRemotes] = useState(true);
  const [isFetchingShare, setIsFetchingShare] = useState(false);
  const [share, setShare] = useState<CloudRecoveryShare | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [credential, setCredential] = useState<Record<string, unknown> | null>(null);
  const [recoveryId, setRecoveryId] = useState<string | undefined>(undefined);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [isFinishing, setIsFinishing] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    invoke<string[]>('list_cloud_backup_remotes')
      .then(list => {
        setRemotes(list);
        if (list.length > 0) setSelectedRemote(list[0]);
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Could not list rclone remotes'))
      .finally(() => setIsLoadingRemotes(false));
  }, []);

  const handleFetchShare = async () => {
    if (!selectedRemote) return;
    setIsFetchingShare(true);
    setError('');
    try {
      const result = await invoke<CloudRecoveryShare>('fetch_cloud_recovery_share', {
        remote: selectedRemote,
      });
      setShare(result);
      setStep('confirm');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to download Share 1 from this remote');
    } finally {
      setIsFetchingShare(false);
    }
  };

  const handleVerify = async () => {
    if (!share) return;
    if (!navigator.credentials?.get) {
      setError('WebAuthn is not available in this WebView.');
      return;
    }
    setIsVerifying(true);
    setError('');
    try {
      const response = await invoke<any>('initiate_account_recovery', { userId: share.user_id });
      const publicKey = unwrapPublicKeyOptions(response);
      const assertion = await navigator.credentials.get({
        publicKey: decodeRequestOptions(publicKey),
      });
      if (!assertion) {
        throw new Error('No security key response was received');
      }
      setCredential(credentialToJSON(assertion as PublicKeyCredential));
      setRecoveryId(response?.recovery_id ?? response?.recoveryId ?? undefined);
      setStep('device');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Security key verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleFinish = async () => {
    if (!share || !credential) return;
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setIsFinishing(true);
    setError('');
    try {
      await invoke('complete_account_recovery', {
        userId: share.user_id,
        share1B64: share.share_b64,
        credential,
        recoveryId,
        password,
        deviceName: deviceName.trim() || undefined,
      });
      onComplete();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Account recovery failed');
    } finally {
      setIsFinishing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={onClose}>
      <div
        className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto shadow-2xl border border-outline-variant/20"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 mb-6">
          <span className="material-symbols-outlined text-2xl text-primary">restore</span>
          <h2 className="font-headline text-2xl font-bold text-on-surface">Recover my account</h2>
        </div>

        {step === 'remote' && (
          <div className="space-y-4">
            <p className="text-on-surface-variant text-sm">
              Pick the cloud remote where Share 1 of your recovery backup was uploaded.
            </p>
            {isLoadingRemotes ? (
              <p className="text-sm text-on-surface-variant">Checking configured rclone remotes...</p>
            ) : remotes && remotes.length > 0 ? (
              <>
                <select
                  value={selectedRemote}
                  onChange={e => setSelectedRemote(e.target.value)}
                  className="w-full bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 text-on-surface focus:outline-none focus:border-primary"
                >
                  {remotes.map(remote => (
                    <option key={remote} value={remote}>{remote}</option>
                  ))}
                </select>
                <button
                  onClick={handleFetchShare}
                  disabled={isFetchingShare}
                  className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                  {isFetchingShare ? 'Downloading...' : 'Continue'}
                </button>
              </>
            ) : (
              <p className="text-sm text-on-surface-variant">
                No configured rclone remotes found. Install{' '}
                <span className="font-mono text-on-surface">rclone</span> and configure the same
                remote used during recovery setup, then come back here.
              </p>
            )}
          </div>
        )}

        {step === 'confirm' && share && (
          <div className="space-y-4">
            <p className="text-on-surface-variant text-sm">
              Found a recovery backup for account:
            </p>
            <div className="font-mono text-xs bg-surface-bright rounded-lg px-4 py-3 break-all text-on-surface">
              {share.user_id}
            </div>
            <p className="text-on-surface-variant text-sm">
              Next, verify with the security key (passkey) you registered for recovery.
            </p>
            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {isVerifying ? 'Waiting for security key...' : 'Verify with security key'}
            </button>
          </div>
        )}

        {step === 'device' && (
          <div className="space-y-4">
            <p className="text-on-surface-variant text-sm">
              Set a password to protect the vault on this device, and optionally name it.
            </p>
            <div>
              <label className="block text-xs font-medium text-on-surface-variant mb-1">Device name (optional)</label>
              <input
                type="text"
                value={deviceName}
                onChange={e => setDeviceName(e.target.value)}
                placeholder="This device"
                className="w-full bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 text-on-surface placeholder-on-surface-variant/40 focus:outline-none focus:border-primary"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-on-surface-variant mb-1">Vault password (this device)</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Set a password for this device"
                className="w-full bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 text-on-surface placeholder-on-surface-variant/40 focus:outline-none focus:border-primary"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-on-surface-variant mb-1">Confirm password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                placeholder="Confirm password"
                className="w-full bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 text-on-surface placeholder-on-surface-variant/40 focus:outline-none focus:border-primary"
              />
            </div>
            <button
              onClick={handleFinish}
              disabled={isFinishing}
              className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              {isFinishing ? 'Recovering vault...' : 'Recover vault'}
            </button>
          </div>
        )}

        {error && <p className="mt-4 text-sm text-error">{error}</p>}

        <button
          onClick={onClose}
          className="w-full mt-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-xl text-sm transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
