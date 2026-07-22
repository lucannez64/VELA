import { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { AppProvider, useApp, SessionStatus, VaultItem, fromBackendItem, Settings } from './context/AppContext';
import { applyTheme } from './themes';
import TitleBar from './components/TitleBar';
import Sidebar from './components/Sidebar';
import WelcomeScreen from './views/WelcomeScreen';
import SetupScreen from './views/SetupScreen';
import BiometricGate from './views/BiometricGate';
import VaultBrowser from './views/VaultBrowser';
import ItemDetail from './views/ItemDetail';
import DevicesScreen from './views/DevicesScreen';
import SharingScreen from './views/SharingScreen';
import AuditLogScreen from './views/AuditLogScreen';
import BreachMonitorScreen from './views/BreachMonitorScreen';
import SettingsScreen from './views/SettingsScreen';
import SessionExpiredOverlay from './components/SessionExpiredOverlay';
import Toast from './components/Toast';
import AddItemModal from './components/AddItemModal';
import ConflictResolution from './components/ConflictResolution';
import { useClipboard } from './hooks/useClipboard';

type SetupStep = 'welcome' | 'biometric' | 'password' | 'recovery' | 'complete';

interface SyncConflict {
  item_id: string;
  local_version: VaultItem;
  server_version: VaultItem;
  conflict_detected_at: string;
}

function AppContent() {
  const [setupComplete, setSetupComplete] = useState(false);
  const [setupStep, setSetupStep] = useState<SetupStep>('welcome');
  const [isFirstLaunch, setIsFirstLaunch] = useState(true);
  const [checkingVault, setCheckingVault] = useState(true);
  const [sessionChecked, setSessionChecked] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [conflicts, setConflicts] = useState<SyncConflict[]>([]);
  const { session, setSession, items, setItems, toast, showToast, selectedItem, setSelectedItem, currentView, setCurrentView, settings, setSettings } = useApp();
  const { clearClipboard } = useClipboard();
  const syncingRef = useRef(false);
  const sessionActiveRef = useRef(false);
  sessionActiveRef.current = !!session?.active;
  const lastActivityRef = useRef(Date.now());

  const loadItems = useCallback(async () => {
    try {
      const vaultItems = await invoke<any[]>('get_items');
      const mapped = vaultItems.map(fromBackendItem);
      setItems(mapped as VaultItem[]);
    } catch (e) {
      console.error('Failed to load items:', e);
    }
  }, [setItems]);

  const doSync = useCallback(async () => {
    if (syncingRef.current) return;
    syncingRef.current = true;
    try {
      const result = await invoke<{ last_synced: string | null; conflicts: SyncConflict[]; error: string | null }>('trigger_sync');
      await loadItems();
      if (result.error) {
        showToast(result.error, 'info');
      } else if (result.conflicts.length > 0) {
        setConflicts(result.conflicts);
        showToast(`${result.conflicts.length} conflict(s) detected`, 'error');
      } else {
        setConflicts([]);
        showToast('Vault synced', 'success');
      }
    } catch (e) {
      showToast('Sync failed: ' + String(e), 'error');
    } finally {
      syncingRef.current = false;
    }
  }, [loadItems, showToast]);

  const doSyncRef = useRef(doSync);
  doSyncRef.current = doSync;

  const clearClipboardRef = useRef(clearClipboard);
  clearClipboardRef.current = clearClipboard;

  const refreshSession = async () => {
    try {
      const status = await invoke<SessionStatus>('get_session_status');
      setSession(status);
      return status;
    } catch (e) {
      console.error('Failed to refresh session:', e);
      return null;
    }
  };

  const refreshSessionOnly = async () => {
    await refreshSession();
  };

  useEffect(() => {
    const init = async () => {
      try {
        console.log('Checking if vault exists...');
        const vaultExists = await invoke<boolean>('check_vault_exists');
        console.log('Vault exists:', vaultExists);
        
        if (vaultExists) {
          setIsFirstLaunch(false);
          setSetupComplete(true);
        }

        try {
          const loadedSettings = await invoke<Settings>('get_settings');
          setSettings(loadedSettings);
        } catch (e) {
          console.error('Failed to load settings:', e);
        }
        
        const sessionStatus = await refreshSession();
        console.log('Session status:', sessionStatus);
        
        setCheckingVault(false);
        setSessionChecked(true);
        
        if (sessionStatus?.active) {
          await loadItems();
        }
      } catch (e) {
        console.error('Init failed:', e);
        setCheckingVault(false);
        setSessionChecked(true);
      }
    };
    
    init();

    const unlistenSessionLocked = listen('session-locked', () => {
      setSession(prev => prev ? { ...prev, active: false, lock_state: 'locked' } : null);
      setItems([]);
      setSelectedItem(null);
      clearClipboardRef.current();
    });

    // A result picked in the dedicated quick-search window (see
    // commands/window.rs); the payload is the item as the popup received it
    // from search_items.
    const unlistenOpenItem = listen<VaultItem>('open-item', event => {
      if (!sessionActiveRef.current) return;
      setSelectedItem(event.payload);
      setCurrentView('vault');
    });

    const unlistenSync = listen('trigger-sync', () => {
      doSyncRef.current();
    });

    const unlistenVaultItemsChanged = listen('vault-items-changed', () => {
      loadItems();
    });

    return () => {
      unlistenSessionLocked.then(fn => fn());
      unlistenOpenItem.then(fn => fn());
      unlistenSync.then(fn => fn());
      unlistenVaultItemsChanged.then(fn => fn());
    };
  }, []);

  useEffect(() => {
    if (session?.active && settings?.sync_on_startup) {
      doSyncRef.current();
    }
  }, [session?.active, settings?.sync_on_startup]);

  // Apply the configured theme; follow OS preference when set to "system".
  useEffect(() => {
    const setting = settings?.theme ?? 'system';
    applyTheme(setting);
    if (setting !== 'system') return;
    const media = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => applyTheme('system');
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [settings?.theme]);

  useEffect(() => {
    if (session?.active) {
      loadItems();
    }
  }, [session?.active, loadItems]);

  useEffect(() => {
    if (!selectedItem) return;
    const freshItem = items.find(item => item.id === selectedItem.id);
    if (freshItem && freshItem !== selectedItem) {
      setSelectedItem(freshItem);
    } else if (!freshItem) {
      setSelectedItem(null);
    }
  }, [items, selectedItem, setSelectedItem]);

  useEffect(() => {
    const bumpActivity = () => { lastActivityRef.current = Date.now(); };
    const events = ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'] as const;
    events.forEach(e => window.addEventListener(e, bumpActivity, { passive: true }));
    return () => events.forEach(e => window.removeEventListener(e, bumpActivity));
  }, []);

  // Decorative `infinite` CSS animations (security-pulse, animate-pulse, ...) keep
  // WebKit's compositor and the native GTK window repainting every frame even when
  // VELA is unfocused or occluded, which on this software-rendered (non-GPU-composited)
  // WebKitGTK path burns ~30% of a CPU core doing nothing useful. Freeze them whenever
  // the window isn't the focused, visible one; resume is instant on refocus.
  useEffect(() => {
    const root = document.documentElement;
    const update = () => {
      root.classList.toggle('anim-paused', document.hidden || !document.hasFocus());
    };
    update();
    window.addEventListener('focus', update);
    window.addEventListener('blur', update);
    document.addEventListener('visibilitychange', update);
    return () => {
      window.removeEventListener('focus', update);
      window.removeEventListener('blur', update);
      document.removeEventListener('visibilitychange', update);
    };
  }, []);

  useEffect(() => {
    if (!session?.active) return;

    lastActivityRef.current = Date.now();
    const autoLockSecs = (settings?.auto_lock_minutes ?? 15) * 60;
    const interval = setInterval(() => {
      if (autoLockSecs <= 0) return; // 0 = never auto-lock
      setSession(prev => {
        if (!prev || !prev.active) return prev;
        const idleSecs = Math.floor((Date.now() - lastActivityRef.current) / 1000);
        const remaining = Math.max(0, autoLockSecs - idleSecs);
        return { ...prev, session_time_remaining_secs: remaining };
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [session?.active, settings?.auto_lock_minutes, setSession]);

  useEffect(() => {
    if (!session?.active) return;
    const syncMinutes = settings?.background_sync_minutes ?? 5;
    if (syncMinutes <= 0) return;
    const interval = setInterval(() => {
      doSyncRef.current();
    }, syncMinutes * 60 * 1000);
    return () => clearInterval(interval);
  }, [session?.active, settings?.background_sync_minutes]);

  useEffect(() => {
    if (session?.session_time_remaining_secs === 0 && session?.active) {
      invoke('lock_session').then(() => {
        setSession(prev => prev ? { ...prev, active: false, lock_state: 'locked' } : null);
      });
    }
  }, [session?.session_time_remaining_secs, session?.active, setSession]);

  if (checkingVault || !sessionChecked) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-surface obsidian-gradient">
        <div className="w-14 h-14 rounded-2xl bg-primary-container border border-primary/20 flex items-center justify-center mb-4">
          <span className="material-symbols-outlined text-primary text-3xl" style={{ fontVariationSettings: "'FILL' 1" }}>shield_lock</span>
        </div>
        <span className="font-headline text-xl font-bold tracking-[0.25em] text-primary mb-6">VELA</span>
        <span className="material-symbols-outlined text-2xl text-on-surface-variant animate-spin">progress_activity</span>
      </div>
    );
  }

  if (isFirstLaunch) {
    return (
      <div className="h-screen flex flex-col bg-surface">
        <TitleBar />
        <WelcomeScreen onCreateVault={() => {
          setSetupStep('biometric');
          setIsFirstLaunch(false);
        }} onAddExisting={() => {
          setSetupStep('biometric');
          setIsFirstLaunch(false);
        }} onImportComplete={async () => {
          setIsFirstLaunch(false);
          setSetupComplete(true);
          await refreshSession();
        }} onAccountRecovered={async () => {
          setIsFirstLaunch(false);
          setSetupComplete(true);
          await refreshSession();
        }} />
      </div>
    );
  }

  if (!setupComplete) {
    return (
      <div className="h-screen flex flex-col bg-surface">
        <TitleBar />
        <SetupScreen 
          step={setupStep} 
          onStepChange={setSetupStep}
          onComplete={() => setSetupComplete(true)}
        />
      </div>
    );
  }

  if (!session?.active) {
    return (
      <div className="h-screen flex flex-col bg-surface">
        <TitleBar />
        <BiometricGate onUnlock={async () => {
          await refreshSession();
        }} />
        {toast && <Toast {...toast} />}
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-surface">
      <TitleBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar 
          onAddItem={() => setShowAddModal(true)} 
        />
        <main className="flex-1 flex overflow-hidden">
          {currentView === 'vault' && (
            selectedItem ? (
              <ItemDetail 
                item={selectedItem} 
                onEdit={() => {
                  setShowAddModal(true);
                }}
              />
            ) : (
              <VaultBrowser 
                items={items} 
                onRefresh={loadItems}
                onAddItem={() => setShowAddModal(true)}
              />
            )
          )}
          {currentView === 'devices' && <DevicesScreen onItemsChanged={loadItems} />}
          {currentView === 'sharing' && <SharingScreen />}
          {currentView === 'audit' && <AuditLogScreen />}
          {currentView === 'breachMonitor' && <BreachMonitorScreen />}
          {currentView === 'settings' && <SettingsScreen />}
        </main>
      </div>
      {session.session_time_remaining_secs <= 60 && (
        <SessionExpiredOverlay onReauth={refreshSessionOnly} />
      )}
      {toast && <Toast {...toast} />}
      {showAddModal && (
        <AddItemModal 
          editItem={selectedItem}
          onClose={() => {
            setShowAddModal(false);
            setSelectedItem(null);
          }} 
          onSave={loadItems}
        />
      )}
      {conflicts.length > 0 && (
        <ConflictResolution 
          conflicts={conflicts}
          onResolved={() => setConflicts([])}
          onClose={() => setConflicts([])}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <AppContent />
    </AppProvider>
  );
}
