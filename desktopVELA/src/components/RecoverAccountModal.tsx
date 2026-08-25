import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { unwrapPublicKeyOptions, decodeRequestOptions, credentialToJSON } from '../lib/webauthn';

interface Props {
  onComplete: () => void;
  onClose: () => void;
}

interface CloudRecoveryShare {
  user_id: string;
  key_epoch: number;
  split_id?: string;
  share_b64: string;
}

type Step = 'remote' | 'account' | 'confirm' | 'contact' | 'contactRespond' | 'device';

// M18: an authenticated response envelope from the trusted contact, produced
// by re-sealing their held share to this device's ephemeral request key.
interface ContactResponse {
  account_id: string;
  key_epoch: number;
  split_id?: string;
  coordinate: number;
  envelope_b64: string;
}

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
  const [shares, setShares] = useState<CloudRecoveryShare[]>([]);
  const [share, setShare] = useState<CloudRecoveryShare | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [credential, setCredential] = useState<Record<string, unknown> | null>(null);
  const [recoveryId, setRecoveryId] = useState<string | undefined>(undefined);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [isFinishing, setIsFinishing] = useState(false);
  const [error, setError] = useState('');
  // M18 trusted-contact path state.
  const [requestPublicKey, setRequestPublicKey] = useState('');
  const [requestSecretKey, setRequestSecretKey] = useState('');
  const [contactResponseText, setContactResponseText] = useState('');

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
      // One remote can hold backups for several accounts (each in its own
      // per-account path); the scan returns all of them.
      const result = await invoke<CloudRecoveryShare[]>('fetch_cloud_recovery_shares', {
        remote: selectedRemote,
      });
      if (result.length === 1) {
        setShare(result[0]);
        setStep('confirm');
      } else {
        setShares(result);
        setStep('account');
      }
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

  const handleStartContactFlow = async () => {
    setError('');
    try {
      const request = await invoke<{ public_key_b64: string; secret_key_b64: string }>(
        'generate_recovery_request',
      );
      setRequestPublicKey(request.public_key_b64);
      // Kept in memory only for the lifetime of this modal.
      setRequestSecretKey(request.secret_key_b64);
      setStep('contact');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not start contact recovery');
    }
  };

  const handleContactFinish = async () => {
    if (!share || !requestSecretKey) return;
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    let parsed: ContactResponse;
    try {
      parsed = JSON.parse(contactResponseText);
    } catch (e) {
      setError('The trusted-contact response is not valid JSON');
      return;
    }
    setIsFinishing(true);
    setError('');
    try {
      await invoke('complete_account_recovery_with_contact', {
        userId: share.user_id,
        firstShareB64: share.share_b64,
        firstShareKeyEpoch: share.key_epoch,
        firstShareSplitId: share.split_id,
        firstShareChannel: 'cloud',
        requestSecretKeyB64: requestSecretKey,
        contactResponseJson: JSON.stringify(parsed),
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
        share1KeyEpoch: share.key_epoch,
        share1SplitId: share.split_id,
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

        {step === 'account' && (
          <div className="space-y-4">
            <p className="text-on-surface-variant text-sm">
              This remote holds recovery backups for more than one account. Pick the one you are
              recovering:
            </p>
            <div className="space-y-2">
              {shares.map(s => (
                <button
                  key={`${s.user_id}:${s.key_epoch}:${s.split_id ?? 'legacy'}`}
                  onClick={() => {
                    setShare(s);
                    setStep('confirm');
                  }}
                  className="w-full text-left font-mono text-xs bg-surface-bright hover:bg-surface-container-highest rounded-lg px-4 py-3 break-all text-on-surface transition-colors"
                >
                  {s.user_id} · epoch {s.key_epoch}
                </button>
              ))}
            </div>
          </div>
        )}

        {step === 'confirm' && share && (
          <div className="space-y-4">
            <p className="text-on-surface-variant text-sm">
              Found a recovery backup for account:
            </p>
            <div className="font-mono text-xs bg-surface-bright rounded-lg px-4 py-3 break-all text-on-surface">
              {share.user_id} · epoch {share.key_epoch}
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
            <div className="flex items-center gap-2 text-xs text-on-surface-variant">
              <span className="flex-1 border-t border-outline-variant/30" />or<span className="flex-1 border-t border-outline-variant/30" />
            </div>
            <p className="text-on-surface-variant text-sm">
              Lost your security key? Recover through your trusted contact instead — they hand
              back their sealed share and no security key is needed.
            </p>
            <button
              onClick={handleStartContactFlow}
              className="w-full py-3 bg-surface-container-highest hover:bg-surface-bright rounded-xl text-on-surface font-medium transition-colors"
            >
              Use trusted contact share
            </button>
          </div>
        )}

        {step === 'contact' && (
          <div className="space-y-4">
            <p className="text-on-surface-variant text-sm">
              Show this request code to your trusted contact. Their VELA app opens the envelope you
              gave them and seals the share back to this device — only this device can open it.
            </p>
            <div className="font-mono text-xs bg-surface-bright rounded-lg px-4 py-3 break-all text-on-surface">
              {requestPublicKey}
            </div>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(requestPublicKey).catch(() => {});
              }}
              className="w-full py-2 bg-surface-container-highest hover:bg-surface-bright rounded-xl text-sm text-on-surface transition-colors"
            >
              Copy request code
            </button>
            <button
              onClick={() => setStep('contactRespond')}
              disabled={!requestPublicKey}
              className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              I have their response
            </button>
          </div>
        )}

        {step === 'contactRespond' && (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-on-surface-variant mb-1">
                Trusted-contact response (paste the JSON their app produced)
              </label>
              <textarea
                value={contactResponseText}
                onChange={e => setContactResponseText(e.target.value)}
                rows={4}
                className="w-full font-mono text-xs bg-surface-bright border border-outline-variant/30 rounded-xl px-4 py-3 text-on-surface focus:outline-none focus:border-primary resize-none"
              />
            </div>
            <button
              onClick={() => setStep('device')}
              disabled={!contactResponseText.trim()}
              className="w-full py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
            >
              Continue
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
              onClick={credential ? handleFinish : handleContactFinish}
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
