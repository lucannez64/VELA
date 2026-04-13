import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import TrustedContactRecovery from '../components/TrustedContactRecovery';

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

  if (showTrustedContact) {
    return (
      <main className="flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <button
          onClick={() => setShowTrustedContact(false)}
          className="absolute top-24 left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
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
      <main className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-lg w-full text-center">
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
      <main className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-lg w-full text-center">
          <button
            onClick={() => onStepChange('welcome')}
            className="absolute top-24 left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
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
      <main className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-lg w-full text-center">
          <button
            onClick={() => onStepChange('welcome')}
            className="absolute top-24 left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
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
      <main className="flex-1 flex items-center justify-center p-6 overflow-y-auto">
        <button
          onClick={() => onStepChange('password')}
          className="absolute top-24 left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
        >
          <span className="material-symbols-outlined">arrow_back</span>
          Back
        </button>
        
        <div className="max-w-xl w-full">
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
                      <span className="material-symbols-outlined text-white text-lg">check</span>
                    ) : (
                      <span className="font-bold text-sm">1</span>
                    )}
                  </div>
                  <div>
                    <div className="font-body font-medium text-on-surface">Cloud backup</div>
                    <div className="text-sm text-on-surface-variant">
                      {recoverySteps.cloudBackup ? 'Saved to device' : 'Store a recovery share'}
                    </div>
                  </div>
                </div>
                {!recoverySteps.cloudBackup && (
                  <div className="flex gap-2">
                    <button 
                      onClick={() => setRecoverySteps(prev => ({ ...prev, cloudBackup: true }))}
                      className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                    >
                      Enable
                    </button>
                  </div>
                )}
              </div>
            </div>

            <div className={`p-6 rounded-xl border ${recoverySteps.securityKey ? 'border-primary bg-primary/5' : 'border-outline-variant bg-surface-container'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${recoverySteps.securityKey ? 'bg-primary' : 'bg-surface-container-highest'}`}>
                    {recoverySteps.securityKey ? (
                      <span className="material-symbols-outlined text-white text-lg">check</span>
                    ) : (
                      <span className="font-bold text-sm">2</span>
                    )}
                  </div>
                  <div>
                    <div className="font-body font-medium text-on-surface">Security Key</div>
                    <div className="text-sm text-on-surface-variant">
                      {recoverySteps.securityKey ? 'Master password enabled' : 'Password recovery enabled'}
                    </div>
                  </div>
                </div>
                {!recoverySteps.securityKey && (
                  <button 
                    onClick={() => setRecoverySteps(prev => ({ ...prev, securityKey: true }))}
                    className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                  >
                    Enable
                  </button>
                )}
              </div>
            </div>

            <div className="p-6 rounded-xl border border-outline-variant bg-surface-container">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${recoverySteps.trustedContact ? 'bg-primary' : 'bg-surface-container-highest'}`}>
                    {recoverySteps.trustedContact ? (
                      <span className="material-symbols-outlined text-white text-lg">check</span>
                    ) : (
                      <span className="font-bold text-sm">3</span>
                    )}
                  </div>
                  <div>
                    <div className="font-body font-medium text-on-surface">Trusted contact</div>
                    <div className="text-sm text-on-surface-variant">Optional but recommended</div>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button 
                    onClick={() => setRecoverySteps(prev => ({ ...prev, trustedContact: true }))}
                    className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                  >
                    Skip
                  </button>
                  <button 
                    onClick={() => setShowTrustedContact(true)}
                    className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                  >
                    Invite
                  </button>
                </div>
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
                style={{ width: `${Math.max(completedSteps, 2) / 2 * 100}%` }}
              />
            </div>
          </div>

          <button
            onClick={() => onStepChange('complete')}
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
      <main className="flex-1 flex items-center justify-center p-6">
        <button
          onClick={() => onStepChange('recovery')}
          className="absolute top-24 left-6 flex items-center gap-2 text-on-surface-variant hover:text-on-surface"
        >
          <span className="material-symbols-outlined">arrow_back</span>
          Back
        </button>
        
        <div className="max-w-lg w-full text-center">
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
