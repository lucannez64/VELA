import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface Props {
  onUnlock: () => void;
}

export default function BiometricGate({ onUnlock }: Props) {
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [showPassword, setShowPassword] = useState(false);
  const [password, setPassword] = useState('');
  const [biometricAvailable, setBiometricAvailable] = useState(true);

  useEffect(() => {
    checkBiometricAvailability();
  }, []);

  const checkBiometricAvailability = async () => {
    try {
      const status = await invoke<{ enrolled: boolean; provider: string }>('check_enrollment');
      const hasBiometric = status.enrolled && status.provider !== 'none' && status.provider !== 'masterpassword';
      setBiometricAvailable(hasBiometric);
      if (hasBiometric) {
        triggerAuth();
      }
    } catch (e) {
      setBiometricAvailable(false);
    }
  };

  const triggerAuth = async () => {
    setIsAuthenticating(true);
    setError(null);

    try {
      const result = await invoke<{ success: boolean; error_message?: string; retry_count?: number }>('authenticate');
      
      if (result.success) {
        try {
          await invoke('unlock_session', { deviceId: 'device-1', userId: 'user-1' });
          await refreshSession();
        } catch (e) {
          setError('Failed to unlock session');
          setRetryCount(prev => prev + 1);
          return;
        }
      } else {
        setError(result.error_message || 'Authentication failed');
        setRetryCount(prev => prev + 1);
      }
    } catch (e) {
      setError('Authentication failed');
      setRetryCount(prev => prev + 1);
    } finally {
      setIsAuthenticating(false);
    }
  };

  const triggerPasswordAuth = async () => {
    if (!password.trim()) {
      setError('Please enter your password');
      return;
    }
    
    setIsAuthenticating(true);
    setError(null);

    try {
      const result = await invoke<{ success: boolean; error_message?: string }>('authenticate_password', { password });
      
      if (result.success) {
        try {
          await invoke('unlock_session_with_password', { password });
          await refreshSession();
        } catch (e) {
          setError('Failed to unlock vault');
          setRetryCount(prev => prev + 1);
        }
      } else {
        setError(result.error_message || 'Invalid password');
        setRetryCount(prev => prev + 1);
      }
    } catch (e) {
      setError('Authentication failed');
      setRetryCount(prev => prev + 1);
    } finally {
      setIsAuthenticating(false);
    }
  };

  const refreshSession = async () => {
    try {
      const { invoke: inv } = await import('@tauri-apps/api/core');
      const status = await inv<{ active: boolean; session_time_remaining_secs: number; device_name: string | null; lock_state: string }>('get_session_status');
      if (status.active) {
        onUnlock();
      }
    } catch (e) {
      console.error('Failed to refresh session:', e);
    }
  };

  const isLocked = retryCount >= 5;

  if (showPassword || !biometricAvailable) {
    return (
      <main className="relative h-full obsidian-gradient flex flex-col items-center justify-between py-16 px-6">
        <header className="flex flex-col items-center space-y-2">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary-container border border-primary/20 flex items-center justify-center rounded-lg">
              <span className="material-symbols-outlined text-primary text-2xl" style={{ fontVariationSettings: "'FILL' 1" }}>shield_lock</span>
            </div>
            <h1 className="font-headline text-3xl font-bold tracking-[0.25em] text-primary">VELA</h1>
          </div>
          <p className="font-label text-xs uppercase tracking-[0.4em] text-on-surface-variant opacity-60">Zero-Knowledge Vault</p>
        </header>

        <section className="flex flex-col items-center justify-center space-y-8 w-full max-w-md">
          <div className="w-full text-center">
            <span className="material-symbols-outlined text-accent-violet text-6xl mb-4" style={{ fontVariationSettings: "'wght' 200" }}>
              password
            </span>
            <h2 className="font-headline text-2xl font-light tracking-tight text-on-surface mb-2">
              Enter Master Password
            </h2>
            <p className="text-on-surface-variant text-sm">
              {biometricAvailable ? 'Biometric authentication failed' : 'Biometric not available on this device'}
            </p>
          </div>

          <div className="w-full space-y-4">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && triggerPasswordAuth()}
              placeholder="Enter your master password"
              className="w-full px-4 py-3 bg-surface-container rounded-xl border border-outline-variant focus:border-primary outline-none text-on-surface placeholder:text-on-surface-variant/50"
              disabled={isAuthenticating || isLocked}
            />
            
            {error && (
              <p className="text-red-400 text-sm text-center">
                {error}
              </p>
            )}

            <button
              onClick={triggerPasswordAuth}
              disabled={isAuthenticating || isLocked || !password.trim()}
              className="w-full py-4 px-6 bg-gradient-to-r from-primary to-primary-dim text-on-primary font-bold rounded-xl hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isAuthenticating ? 'Unlocking...' : 'Unlock'}
            </button>
          </div>

          {biometricAvailable && (
            <button
              onClick={() => {
                setShowPassword(false);
                setError(null);
                setPassword('');
              }}
              className="flex items-center gap-2 text-primary hover:underline text-sm"
            >
              <span className="material-symbols-outlined text-lg">fingerprint</span>
              Use biometric instead
            </button>
          )}
        </section>

        <footer className="text-center">
          <p className="font-body text-xs text-on-surface-variant/40 italic">
            Securely encrypted with Post-Quantum AES-256
          </p>
        </footer>
      </main>
    );
  }

  return (
    <main className="relative h-full obsidian-gradient flex flex-col items-center justify-between py-16 px-6">
      <header className="flex flex-col items-center space-y-2">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-primary-container border border-primary/20 flex items-center justify-center rounded-lg">
            <span className="material-symbols-outlined text-primary text-2xl" style={{ fontVariationSettings: "'FILL' 1" }}>shield_lock</span>
          </div>
          <h1 className="font-headline text-3xl font-bold tracking-[0.25em] text-primary">VELA</h1>
        </div>
        <p className="font-label text-xs uppercase tracking-[0.4em] text-on-surface-variant opacity-60">Zero-Knowledge Vault</p>
      </header>

      <section className="flex flex-col items-center justify-center space-y-12">
        <div className="relative flex items-center justify-center">
          <div className="absolute w-64 h-64 border border-accent-violet/10 rounded-full scale-110"></div>
          <div className="absolute w-48 h-48 border border-accent-violet/20 rounded-full scale-105"></div>
          
          <button
            onClick={triggerAuth}
            disabled={isAuthenticating || isLocked}
            className="relative w-40 h-40 bg-surface-container-high rounded-full biometric-glow flex items-center justify-center border border-accent-violet/30 hover:border-accent-violet transition-all duration-500 group active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <div className="absolute inset-0 rounded-full bg-accent-violet/5 group-hover:bg-accent-violet/10 transition-colors"></div>
            <span 
              className={`material-symbols-outlined text-accent-violet text-7xl ${isAuthenticating ? 'animate-pulse' : ''}`}
              style={{ fontVariationSettings: "'wght' 200" }}
            >
              fingerprint
            </span>
          </button>
        </div>

        <div className="text-center space-y-3">
          <h2 className="font-headline text-2xl font-light tracking-tight text-on-surface">
            {isLocked ? 'Too many attempts' : 'Touch sensor to unlock'}
          </h2>
          <div className="flex items-center justify-center gap-2">
            <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse shadow-[0_0_8px_rgba(115,219,154,0.6)]"></span>
            <p className="font-label text-sm text-on-surface-variant tracking-wide">
              {isLocked ? 'WAIT 30 SECONDS' : 'AUTHENTICATION READY'}
            </p>
          </div>
          {error && (
            <p className="text-red-400 text-sm mt-2">
              {error} — try again ({5 - retryCount} attempts remaining)
            </p>
          )}
        </div>
      </section>

      <footer className="flex flex-col items-center space-y-8 w-full max-w-md">
        <div className="w-full flex items-center gap-4 px-12">
          <div className="h-px flex-grow bg-outline-variant/20"></div>
          <span className="font-label text-[10px] tracking-widest text-on-surface-variant uppercase">Alternative Access</span>
          <div className="h-px flex-grow bg-outline-variant/20"></div>
        </div>

        <div className="flex gap-4">
          <button 
            onClick={() => setShowPassword(true)}
            className="flex items-center gap-3 px-6 py-3 bg-surface-container rounded-xl border border-transparent hover:border-outline-variant/30 hover:bg-surface-container-high transition-all text-on-surface"
          >
            <span className="material-symbols-outlined text-xl">password</span>
            <span className="font-body text-sm font-medium">Master Password</span>
          </button>
        </div>

        <p className="font-body text-xs text-on-surface-variant/40 italic">
          Securely encrypted with Post-Quantum AES-256
        </p>

        <button
          onClick={async () => {
            if (confirm('This will PERMANENTLY DELETE all vault data and credentials. Are you sure?')) {
              try {
                await invoke('reset_vault');
                window.location.reload();
              } catch (e) {
                alert('Reset failed: ' + String(e) + '\n\nPlease close the app and try again.');
              }
            }
          }}
          className="text-xs text-on-surface-variant/40 hover:text-red-400/60 underline transition-colors mt-2"
        >
          Can't access your vault? Reset
        </button>
      </footer>

      <div className="fixed top-0 left-0 w-32 h-32 opacity-20 pointer-events-none">
        <div className="absolute top-0 left-0 w-full h-full border-t border-l border-accent-violet/40 rounded-tl-3xl"></div>
      </div>
      <div className="fixed bottom-0 right-0 w-32 h-32 opacity-20 pointer-events-none">
        <div className="absolute bottom-0 right-0 w-full h-full border-b border-r border-accent-violet/40 rounded-br-3xl"></div>
      </div>

      <div className="fixed top-6 right-6 flex items-center gap-3 bg-on-secondary-container/40 backdrop-blur-md px-4 py-2 rounded-full border border-secondary/10">
        <div className="relative w-2 h-2">
          <div className="absolute inset-0 bg-secondary rounded-full animate-ping opacity-75"></div>
          <div className="relative bg-secondary w-2 h-2 rounded-full"></div>
        </div>
        <span className="font-label text-[10px] font-bold tracking-widest text-secondary uppercase">Secure Session Active</span>
      </div>
    </main>
  );
}
