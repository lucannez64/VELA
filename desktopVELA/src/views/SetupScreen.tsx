import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import TrustedContactRecovery from '../components/TrustedContactRecovery';
import { unwrapPublicKeyOptions, decodeCreationOptions, credentialToJSON } from '../lib/webauthn';

type SetupStep = 'welcome' | 'biometric' | 'password' | 'recovery' | 'complete';

interface Props {
  step: SetupStep;
  onStepChange: (step: SetupStep) => void;
  onComplete: () => void;
}

export default function SetupScreen({ step, onStepChange, onComplete }: Props) {
  const [recoverySteps, setRecoverySteps] = useState({
    cloudBackup: false,
    securityKey: false,
    trustedContact: false,
  });
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [showTrustedContact, setShowTrustedContact] = useState(false);
  const [masterPassword, setMasterPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [passwordError, setPasswordError] = useState('');
  const [biometricAvailable, setBiometricAvailable] = useState<boolean | null>(null);
  const [biometricError, setBiometricError] = useState('');
  const [recoveryError, setRecoveryError] = useState('');
  const [isSettingUpSecurityKey, setIsSettingUpSecurityKey] = useState(false);
  const [showCloudBackupPicker, setShowCloudBackupPicker] = useState(false);
  const [cloudRemotes, setCloudRemotes] = useState<string[] | null>(null);
  const [selectedRemote, setSelectedRemote] = useState('');
  const [cloudBackupError, setCloudBackupError] = useState('');
  const [isLoadingRemotes, setIsLoadingRemotes] = useState(false);
  const [isSettingUpCloudBackup, setIsSettingUpCloudBackup] = useState(false);

  useEffect(() => {
    checkBiometricAvailability();
  }, []);

  useEffect(() => {
    if (step === 'biometric' && biometricAvailable === false) {
      onStepChange('password');
    }
  }, [step, biometricAvailable, onStepChange]);

  const checkBiometricAvailability = async () => {
    try {
      const status = await invoke<{ enrolled: boolean; provider: string }>('check_enrollment');
      setBiometricAvailable(status.provider !== 'none' && status.provider !== 'masterpassword');
    } catch (e) {
      setBiometricAvailable(false);
    }
  };

  const handleCreateVault = () => {
    if (biometricAvailable === null) {
      return;
    }
    if (biometricAvailable === true) {
      onStepChange('biometric');
    } else {
      onStepChange('password');
    }
  };

  const handleBiometricEnroll = async () => {
    setIsEnrolling(true);
    setBiometricError('');
    try {
      const status = await invoke<{ enrolled: boolean; provider: string }>('check_enrollment');
      if (!status.enrolled || status.provider === 'none' || status.provider === 'masterpassword') {
        onStepChange('password');
        return;
      }
      
      const hasVault = await invoke<boolean>('check_vault_exists');
      
      if (!hasVault) {
        onStepChange('password');
        return;
      }
      
      const result = await invoke<{ success: boolean; error_message?: string }>('authenticate');
      if (result.success) {
        onStepChange('recovery');
      } else {
        setBiometricError(result.error_message || 'Authentication failed - use password instead');
        setIsEnrolling(false);
      }
    } catch (e) {
      onStepChange('password');
    } finally {
      setIsEnrolling(false);
    }
  };

  const handlePasswordSetup = async () => {
    if (masterPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return;
    }
    if (masterPassword !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }
    
    setIsEnrolling(true);
    setPasswordError('');
    try {
      await invoke('create_vault_with_password', { password: masterPassword });
      onStepChange('recovery');
    } catch (e) {
      console.error('Vault creation failed:', e);
      setPasswordError('Failed to create vault');
    } finally {
      setIsEnrolling(false);
    }
  };

  const completedSteps = Object.values(recoverySteps).filter(Boolean).length;

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
      setCloudBackupError(
        e instanceof Error ? e.message : 'Could not list rclone remotes'
      );
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
      setRecoverySteps(prev => ({ ...prev, cloudBackup: true }));
      setShowCloudBackupPicker(false);
    } catch (e) {
      setCloudBackupError(e instanceof Error ? e.message : 'Cloud backup upload failed');
    } finally {
      setIsSettingUpCloudBackup(false);
    }
  };

  const handleFinishRecoverySetup = async () => {
    try {
      await invoke('finalize_recovery_setup');
    } catch (e) {
      // Best-effort cleanup of the local pending-shares cache — the shares
      // that were actually delivered are unaffected either way.
    }
    onStepChange('complete');
  };

  const handleSecurityKeySetup = async () => {
    if (!navigator.credentials?.create) {
      setRecoveryError('WebAuthn is not available in this WebView.');
      return;
    }

      setRecoveryError('');
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
        setRecoverySteps(prev => ({ ...prev, securityKey: true }));
      }
    } catch (e) {
      setRecoveryError(e instanceof Error ? e.message : 'Security key setup failed');
    } finally {
      setIsSettingUpSecurityKey(false);
    }
  };

  if (showTrustedContact) {
    return (
      <main className="relative flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <button
          onClick={() => setShowTrustedContact(false)}
          className="absolute top-4 left-4 sm:top-6 sm:left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
        >
          <span className="material-symbols-outlined">arrow_back</span>
          Back
        </button>
        <TrustedContactRecovery 
          onComplete={() => {
            setRecoverySteps(prev => ({ ...prev, trustedContact: true }));
            setShowTrustedContact(false);
          }}
          onSkip={() => {
            setShowTrustedContact(false);
          }}
        />
      </main>
  );
}

  if (step === 'welcome') {
    return (
      <main className="relative flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <div className="max-w-lg w-full text-center my-auto">
          <div className="w-24 h-24 mx-auto mb-8 bg-surface-container rounded-2xl flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-6xl" style={{ fontVariationSettings: "'FILL' 1" }}>lock</span>
          </div>
          
          <h2 className="font-headline text-3xl font-bold text-on-surface mb-4">Welcome to VELA</h2>
          <p className="text-on-surface-variant mb-8 leading-relaxed">
            Your passwordless, zero-knowledge vault with post-quantum security.
          </p>

          <div className="space-y-4">
            <button
              onClick={handleCreateVault}
              disabled={biometricAvailable === null}
              className="w-full py-4 px-6 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {biometricAvailable === null ? 'Checking...' : 'Create new vault'}
            </button>
            
            <button
              onClick={() => onStepChange('password')}
              disabled={biometricAvailable === null}
              className="w-full py-4 px-6 bg-surface-container text-on-surface font-bold rounded-xl hover:bg-surface-container-high transition-colors border border-outline-variant disabled:opacity-50"
            >
              I have an existing vault
            </button>
          </div>
        </div>
      </main>
    );
  }

  if (step === 'biometric') {
    if (biometricAvailable === null || biometricAvailable === false) {
      return null;
    }

    return (
      <main className="relative flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <div className="max-w-lg w-full text-center my-auto">
          <button
            onClick={() => onStepChange('welcome')}
            className="absolute top-4 left-4 sm:top-6 sm:left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
          >
            <span className="material-symbols-outlined">arrow_back</span>
            Back
          </button>
          
          <div className="w-20 h-20 mx-auto mb-8 bg-surface-container rounded-2xl flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-5xl" style={{ fontVariationSettings: "'FILL' 1" }}>fingerprint</span>
          </div>
          
          <h2 className="font-headline text-3xl font-bold text-on-surface mb-4">Set up biometrics</h2>
          <p className="text-on-surface-variant mb-8 leading-relaxed">
            VELA uses Windows Hello to protect your vault.
            Your fingerprint or face will be the primary way to unlock VELA.
          </p>

          <button
            onClick={handleBiometricEnroll}
            disabled={isEnrolling}
            className="w-full py-4 px-6 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            {isEnrolling ? 'Setting up...' : 'Enable Windows Hello'}
          </button>

          {biometricError && (
            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-xl">
              <p className="text-red-400 text-sm">{biometricError}</p>
              <button
                onClick={() => onStepChange('password')}
                className="mt-2 text-primary hover:underline text-sm"
              >
                Use password instead
              </button>
            </div>
          )}

          <div className="mt-6 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-amber-500">info</span>
              <p className="text-sm text-left text-amber-200">
                You'll also set up a master password as a backup in the next step.
              </p>
            </div>
          </div>
        </div>
      </main>
    );
  }

  if (step === 'password') {
    return (
      <main className="relative flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <div className="max-w-lg w-full text-center my-auto">
          <button
            onClick={() => onStepChange('welcome')}
            className="absolute top-4 left-4 sm:top-6 sm:left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
          >
            <span className="material-symbols-outlined">arrow_back</span>
            Back
          </button>
          
          <div className="w-20 h-20 mx-auto mb-8 bg-surface-container rounded-2xl flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-5xl" style={{ fontVariationSettings: "'FILL' 1" }}>password</span>
          </div>
          
          <h2 className="font-headline text-3xl font-bold text-on-surface mb-4">Set up master password</h2>
          <p className="text-on-surface-variant mb-8 leading-relaxed">
            Create a strong master password to protect your vault. This will be used to recover your vault if biometrics fail.
          </p>

          <div className="space-y-4 text-left">
            <div>
              <label className="block text-sm text-on-surface-variant mb-2">Master Password</label>
              <div className="relative">
              <input
                type={passwordVisible ? 'text' : 'password'}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                placeholder="Enter master password (min 8 characters)"
                className="w-full px-4 py-3 pr-12 bg-surface-container rounded-xl border border-outline-variant focus:border-primary outline-none text-on-surface placeholder:text-on-surface-variant/50"
                disabled={isEnrolling}
              />
              <button
                type="button"
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); setPasswordVisible(v => !v); }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface transition-colors"
                tabIndex={-1}
              >
                <span className="material-symbols-outlined text-xl">{passwordVisible ? 'visibility_off' : 'visibility'}</span>
              </button>
              </div>
            </div>
            
            <div>
              <label className="block text-sm text-on-surface-variant mb-2">Confirm Password</label>
              <div className="relative">
              <input
                type={passwordVisible ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm your password"
                className="w-full px-4 py-3 pr-12 bg-surface-container rounded-xl border border-outline-variant focus:border-primary outline-none text-on-surface placeholder:text-on-surface-variant/50"
                disabled={isEnrolling}
              />
              <button
                type="button"
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); setPasswordVisible(v => !v); }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface transition-colors"
                tabIndex={-1}
              >
                <span className="material-symbols-outlined text-xl">{passwordVisible ? 'visibility_off' : 'visibility'}</span>
              </button>
              </div>
            </div>

            {passwordError && (
              <p className="text-red-400 text-sm">{passwordError}</p>
            )}

            <button
              onClick={handlePasswordSetup}
              disabled={isEnrolling || masterPassword.length < 8}
              className="w-full py-4 px-6 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              {isEnrolling ? 'Creating Vault...' : 'Create Vault'}
            </button>
          </div>
        </div>
      </main>
    );
  }

  if (step === 'recovery') {
    return (
      <main className="relative flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <button
          onClick={() => onStepChange('password')}
          className="absolute top-4 left-4 sm:top-6 sm:left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
        >
          <span className="material-symbols-outlined">arrow_back</span>
          Back
        </button>
        
        <div className="max-w-xl w-full my-auto">
          <h2 className="font-headline text-3xl font-bold text-on-surface mb-2">Set up recovery</h2>
          <p className="text-on-surface-variant mb-8">
            Configure at least 2 recovery methods to restore your vault if all devices are lost.
          </p>

          <div className="space-y-4 mb-8">
            <div className={`p-6 rounded-xl border ${recoverySteps.cloudBackup ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface-container'}`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${recoverySteps.cloudBackup ? 'bg-primary' : 'bg-surface-container-highest'}`}>
                    {recoverySteps.cloudBackup ? (
                      <span className="material-symbols-outlined text-on-primary text-lg">check</span>
                    ) : (
                      <span className="font-bold text-sm">1</span>
                    )}
                  </div>
                  <div>
                    <div className="font-body font-medium text-on-surface">Cloud backup</div>
                    <div className="text-sm text-on-surface-variant">
                      {recoverySteps.cloudBackup ? `Uploaded to ${selectedRemote}` : 'Upload a recovery share via rclone'}
                    </div>
                  </div>
                </div>
                {!recoverySteps.cloudBackup && !showCloudBackupPicker && (
                  <div className="flex gap-2">
                    <button
                      onClick={handleOpenCloudBackupPicker}
                      className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                    >
                      Enable
                    </button>
                  </div>
                )}
              </div>

              {!recoverySteps.cloudBackup && showCloudBackupPicker && (
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

            <div className={`p-6 rounded-xl border ${recoverySteps.securityKey ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface-container'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${recoverySteps.securityKey ? 'bg-primary' : 'bg-surface-container-highest'}`}>
                    {recoverySteps.securityKey ? (
                      <span className="material-symbols-outlined text-on-primary text-lg">check</span>
                    ) : (
                      <span className="font-bold text-sm">2</span>
                    )}
                  </div>
                  <div>
                    <div className="font-body font-medium text-on-surface">Security Key</div>
                    <div className="text-sm text-on-surface-variant">
                      {recoverySteps.securityKey ? 'Passkey registered' : 'Passkey recovery enabled'}
                    </div>
                  </div>
                </div>
                {!recoverySteps.securityKey && (
                  <button 
                    onClick={handleSecurityKeySetup}
                    disabled={isSettingUpSecurityKey}
                    className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                  >
                    {isSettingUpSecurityKey ? 'Waiting...' : 'Enable'}
                  </button>
                )}
              </div>
              {recoveryError && (
                <p className="mt-3 text-sm text-error">{recoveryError}</p>
              )}
            </div>

            <div className="p-6 rounded-xl border border-outline-variant bg-surface-container">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${recoverySteps.trustedContact ? 'bg-primary' : 'bg-surface-container-highest'}`}>
                    {recoverySteps.trustedContact ? (
                      <span className="material-symbols-outlined text-on-primary text-lg">check</span>
                    ) : (
                      <span className="font-bold text-sm">3</span>
                    )}
                  </div>
                  <div>
                    <div className="font-body font-medium text-on-surface">Trusted contact</div>
                    <div className="text-sm text-on-surface-variant">
                      {recoverySteps.trustedContact ? 'Share sent' : 'Optional but recommended'}
                    </div>
                  </div>
                </div>
                {!recoverySteps.trustedContact && (
                  <div className="flex gap-2">
                    <button
                      onClick={() => setShowTrustedContact(true)}
                      className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                    >
                      Get my share
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="mb-6">
            <div className="flex justify-between text-sm text-on-surface-variant mb-2">
              <span>Recovery setup progress</span>
              <span>{completedSteps >= 2 ? '2/2 complete' : `${completedSteps}/2 required`}</span>
            </div>
            <div className="h-2 bg-surface-container-highest rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all"
                style={{ width: `${Math.min(completedSteps, 2) / 2 * 100}%` }}
              />
            </div>
          </div>

          <button
            onClick={handleFinishRecoverySetup}
            disabled={completedSteps < 2}
            className="w-full py-4 px-6 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Continue
          </button>
        </div>
      </main>
    );
  }

  if (step === 'complete') {
    return (
      <main className="relative flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <button
          onClick={() => onStepChange('recovery')}
          className="absolute top-4 left-4 sm:top-6 sm:left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
        >
          <span className="material-symbols-outlined">arrow_back</span>
          Back
        </button>

        <div className="max-w-lg w-full text-center my-auto">
          <div className="w-24 h-24 mx-auto mb-8 bg-primary/20 rounded-full flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-6xl" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
          </div>
          
          <h2 className="font-headline text-3xl font-bold text-on-surface mb-8">You're all set.</h2>

          <div className="space-y-3 mb-8 text-left">
            <div className="flex items-center gap-3 p-3 bg-primary/5 rounded-lg">
              <span className="material-symbols-outlined text-primary">check</span>
              <span className="text-on-surface">Vault created</span>
            </div>
            <div className="flex items-center gap-3 p-3 bg-primary/5 rounded-lg">
              <span className="material-symbols-outlined text-primary">check</span>
              <span className="text-on-surface">Recovery configured</span>
            </div>
          </div>

          <button
            onClick={onComplete}
            className="w-full py-4 px-6 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity"
          >
            Open my vault
          </button>
        </div>
      </main>
    );
  }

  return null;
}
