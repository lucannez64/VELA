import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface Props {
  onCreateVault: () => void;
  onAddExisting: () => void;
}

export default function WelcomeScreen({ onCreateVault, onAddExisting }: Props) {
  const [biometricAvailable, setBiometricAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    checkBiometric();
  }, []);

  const checkBiometric = async () => {
    try {
      const status = await invoke<{ enrolled: boolean; provider: string }>('check_enrollment');
      const hasRealBiometric = status.enrolled && status.provider !== 'none' && status.provider !== 'masterpassword';
      setBiometricAvailable(hasRealBiometric);
    } catch (e) {
      setBiometricAvailable(false);
    }
  };

  const handleCreateVault = () => {
    if (biometricAvailable === false) {
      onAddExisting();
    } else {
      onCreateVault();
    }
  };

  const handleResetAndCreate = async () => {
    if (confirm('This will delete ALL vault data and credentials. Are you sure?')) {
      try {
        await invoke('reset_vault');
      } catch (e) {
        console.error('Reset failed:', e);
      }
      handleCreateVault();
    }
  };

  return (
    <main className="flex-1 flex items-center justify-center p-6 relative overflow-hidden">
      <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute top-[-10%] right-[-10%] w-[50%] h-[50%] bg-primary/5 rounded-full blur-[120px]"></div>
        <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] bg-secondary/5 rounded-full blur-[100px]"></div>
      </div>

      <div className="z-10 w-full max-w-4xl grid md:grid-cols-12 gap-0 overflow-hidden rounded-xl shadow-2xl bg-surface-container-low">
        <div className="hidden md:flex md:col-span-5 bg-surface-container flex-col justify-between p-12 relative overflow-hidden">
          <div className="z-10">
            <div 
              className="text-primary font-headline font-bold text-2xl tracking-[0.2em] mb-8 cursor-pointer hover:text-primary/80"
              onClick={handleResetAndCreate}
              title="Click to reset everything"
            >VELA</div>
            <div className="space-y-4">
              <div className="flex items-center gap-3 text-secondary">
                <span className="material-symbols-outlined text-sm">verified_user</span>
                <span className="font-label text-xs uppercase tracking-widest font-semibold">Post-Quantum Ready</span>
              </div>
              <h2 className="font-headline text-3xl font-light leading-tight text-on-surface">
                Secure your identity in the void.
              </h2>
            </div>
          </div>

          <div className="z-10 mt-auto">
            <div className="bg-on-secondary-container/40 p-4 rounded-lg border border-primary/10 security-pulse">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-primary" style={{ fontVariationSettings: "'FILL' 1" }}>security</span>
                <div>
                  <div className="font-headline font-bold text-sm text-primary">Active Protection</div>
                  <div className="font-label text-[10px] text-on-surface-variant uppercase tracking-wider">Zero-Knowledge Protocol Engaged</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="md:col-span-7 p-10 md:p-16 flex flex-col justify-center bg-surface-container-low">
          <div className="max-w-md mx-auto w-full">
            <header className="mb-12">
              <h1 className="font-headline text-4xl md:text-5xl font-bold tracking-tight text-on-surface mb-4">
                Your vault.<br />No passwords.
              </h1>
              <p className="text-on-surface-variant font-body text-lg leading-relaxed">
                Access your secrets through device-native biometrics and post-quantum encryption.
              </p>
            </header>

            <div className="space-y-4">
              <button 
                onClick={handleCreateVault}
                disabled={biometricAvailable === null}
                className="w-full group relative flex items-center justify-between bg-gradient-to-r from-primary to-primary-dim p-[1px] rounded-xl transition-all active:scale-95 duration-200 disabled:opacity-50"
              >
                <div className="w-full bg-surface-container-lowest group-hover:bg-transparent transition-colors py-4 px-6 rounded-[calc(0.75rem-1px)] flex items-center justify-between">
                  <span className="font-headline font-bold text-on-surface tracking-wide">
                    {biometricAvailable === null ? 'Checking...' : 'Create new vault'}
                  </span>
                  <span className="material-symbols-outlined text-primary group-hover:text-on-primary transition-colors" style={{ fontVariationSettings: "'FILL' 1" }}>add_circle</span>
                </div>
              </button>

              <button 
                onClick={onAddExisting}
                disabled={biometricAvailable === null}
                className="w-full flex items-center justify-between bg-surface-container-highest hover:bg-surface-bright py-4 px-6 rounded-xl transition-all active:scale-95 duration-200 disabled:opacity-50"
              >
                <span className="font-headline font-medium text-on-surface tracking-wide">Add existing device</span>
                <span className="material-symbols-outlined text-on-surface-variant">devices</span>
              </button>
            </div>

            <footer className="mt-16 pt-8 border-t border-outline-variant/10">
              <div className="flex items-center gap-6">
                <div className="flex -space-x-2">
                  <div className="w-8 h-8 rounded-full border-2 border-surface-container-low bg-surface-bright flex items-center justify-center">
                    <span className="material-symbols-outlined text-[14px]">key</span>
                  </div>
                  <div className="w-8 h-8 rounded-full border-2 border-surface-container-low bg-surface-bright flex items-center justify-center">
                    <span className="material-symbols-outlined text-[14px]">fingerprint</span>
                  </div>
                  <div className="w-8 h-8 rounded-full border-2 border-surface-container-low bg-surface-bright flex items-center justify-center">
                    <span className="material-symbols-outlined text-[14px]">face</span>
                  </div>
                </div>
                <p className="font-label text-xs text-on-surface-variant leading-tight">
                  Trusted by individuals requiring<br />
                  <span className="text-secondary">sovereign data control.</span>
                </p>
              </div>
            </footer>
          </div>
        </div>
      </div>
    </main>
  );
}
