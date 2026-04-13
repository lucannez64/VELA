import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface Props {
  onReauth: () => Promise<void>;
}

export default function SessionExpiredOverlay({ onReauth }: Props) {
  const [biometricAvailable, setBiometricAvailable] = useState<boolean | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  useEffect(() => {
    checkBiometric();
  }, []);

  const checkBiometric = async () => {
    try {
      const status = await invoke<{ enrolled: boolean; provider: string }>('check_enrollment');
      const hasBiometric = status.enrolled && status.provider !== 'none' && status.provider !== 'masterpassword';
      setBiometricAvailable(hasBiometric);
    } catch (e) {
      setBiometricAvailable(false);
    }
  };

  const handleBiometricAuth = async () => {
    setIsAuthenticating(true);
    setError(null);
    try {
      const result = await invoke<{ success: boolean; error_message?: string }>('authenticate');
      if (result.success) {
        await invoke('unlock_session', { deviceId: 'device-1', userId: 'user-1' });
        await onReauth();
      } else {
        setShowPassword(true);
      }
    } catch (e) {
      setShowPassword(true);
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handlePasswordAuth = async () => {
    if (!password.trim()) {
      setError('Please enter your password');
      return;
    }
    
    setIsAuthenticating(true);
    setError(null);

    try {
      const result = await invoke<{ success: boolean; error_message?: string }>('authenticate_password', { password });
      if (result.success) {
        await invoke('unlock_session_with_password', { password });
        await onReauth();
      } else {
        setError(result.error_message || 'Invalid password');
      }
    } catch (e) {
      setError('Authentication failed');
    } finally {
      setIsAuthenticating(false);
    }
  };

  if (showPassword || biometricAvailable === false) {
    return (
      <div className="fixed inset-0 z-40 bg-surface/80 backdrop-blur-sm flex items-center justify-center">
        <div className="glass-panel p-8 rounded-2xl border border-outline-variant/20 text-center max-w-md">
          <div className="w-20 h-20 mx-auto mb-6 bg-surface-container rounded-full flex items-center justify-center">
            <span className="material-symbols-outlined text-accent-violet text-5xl" style={{ fontVariationSettings: "'wght' 200" }}>password</span>
          </div>
          <h2 className="font-headline text-2xl font-bold text-on-surface mb-2">Session expired</h2>
          <p className="text-on-surface-variant mb-4">Enter your master password to continue</p>
          
          <div className="relative">
            <input
              type={passwordVisible ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handlePasswordAuth()}
              placeholder="Master password"
              className="w-full px-4 py-3 pr-12 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40 mb-4"
              disabled={isAuthenticating}
              autoFocus
            />
            <button
              type="button"
              onClick={(e) => { e.preventDefault(); e.stopPropagation(); setPasswordVisible(v => !v); }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface transition-colors mb-4"
              tabIndex={-1}
            >
              <span className="material-symbols-outlined text-xl">{passwordVisible ? 'visibility_off' : 'visibility'}</span>
            </button>
          </div>
          
          {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
          
          <button
            onClick={handlePasswordAuth}
            disabled={isAuthenticating || !password.trim()}
            className="px-8 py-3 bg-primary text-on-primary font-bold rounded-xl hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isAuthenticating ? 'Unlocking...' : 'Unlock'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-40 bg-surface/80 backdrop-blur-sm flex items-center justify-center">
      <div className="glass-panel p-8 rounded-2xl border border-outline-variant/20 text-center max-w-md">
        <div className="w-20 h-20 mx-auto mb-6 bg-surface-container rounded-full flex items-center justify-center">
          <span className="material-symbols-outlined text-accent-violet text-5xl" style={{ fontVariationSettings: "'wght' 200" }}>fingerprint</span>
        </div>
        <h2 className="font-headline text-2xl font-bold text-on-surface mb-2">Session expired</h2>
        <p className="text-on-surface-variant mb-6">Touch sensor to continue</p>
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
        <button
          onClick={handleBiometricAuth}
          disabled={isAuthenticating || biometricAvailable === null}
          className="px-8 py-3 bg-primary text-on-primary font-bold rounded-xl hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed mb-3"
        >
          {isAuthenticating ? 'Authenticating...' : 'Authenticate'}
        </button>
        <button
          onClick={() => setShowPassword(true)}
          className="block w-full text-primary text-sm hover:underline"
        >
          Use password instead
        </button>
      </div>
    </div>
  );
}