import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { AppProvider, useApp, SessionStatus, VaultItem, fromBackendItem } from './context/AppContext';
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
import QuickSearchOverlay from './components/QuickSearchOverlay';
import SessionExpiredOverlay from './components/SessionExpiredOverlay';
import Toast from './components/Toast';
import AddItemModal from './components/AddItemModal';
import ConflictResolution from './components/ConflictResolution';

type SetupStep = 'welcome' | 'biometric' | 'password' | 'recovery' | 'complete';

function AppContent() {
  const [setupComplete, setSetupComplete] = useState(false);
  const [setupStep, setSetupStep] = useState<SetupStep>('welcome');
  const [isFirstLaunch, setIsFirstLaunch] = useState(true);
  const [checkingVault, setCheckingVault] = useState(true);
  const [sessionChecked, setSessionChecked] = useState(false);
  const [quickSearchOpen, setQuickSearchOpen] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [conflicts, setConflicts] = useState<any[]>([]);
  const { session, setSession, items, setItems, toast, showToast, selectedItem, setSelectedItem, currentView } = useApp();

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

  const loadItems = async () => {
    try {
      const vaultItems = await invoke<any[]>('get_items');
      const items = vaultItems.map(fromBackendItem);
      setItems(items as VaultItem[]);
    } catch (e) {
      console.error('Failed to load items:', e);
    }
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
    });

    const unlistenQuickSearch = listen('open-quick-search', () => {
      setQuickSearchOpen(true);
    });

    const unlistenSync = listen('trigger-sync', () => {
      showToast('Syncing vault...', 'info');
    });

    return () => {
      unlistenSessionLocked.then(fn => fn());
      unlistenQuickSearch.then(fn => fn());
      unlistenSync.then(fn => fn());
    };
  }, []);

  useEffect(() => {
    if (session?.active) {
      loadItems();
    }
  }, [session?.active]);

  useEffect(() => {
    if (!session?.active) return;
    
    const interval = setInterval(() => {
      setSession(prev => {
        if (!prev || !prev.active) return prev;
        const remaining = Math.max(0, prev.session_time_remaining_secs - 1);
        return { ...prev, session_time_remaining_secs: remaining };
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [session?.active, setSession]);

  useEffect(() => {
    if (session?.session_time_remaining_secs === 0 && session?.active) {
      invoke('lock_session').then(() => {
        setSession(prev => prev ? { ...prev, active: false, lock_state: 'locked' } : null);
      });
    }
  }, [session?.session_time_remaining_secs, session?.active, setSession]);

  if (checkingVault || !sessionChecked) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-surface">
        <span className="material-symbols-outlined text-4xl text-primary animate-spin">progress_activity</span>
        <p className="mt-4 text-on-surface-variant">Loading...</p>
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
        {quickSearchOpen && <QuickSearchOverlay />}
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
          {currentView === 'devices' && <DevicesScreen />}
          {currentView === 'sharing' && <SharingScreen />}
          {currentView === 'audit' && <AuditLogScreen />}
          {currentView === 'breachMonitor' && <BreachMonitorScreen />}
          {currentView === 'settings' && <SettingsScreen />}
        </main>
      </div>
      {session.session_time_remaining_secs <= 60 && (
        <SessionExpiredOverlay onReauth={refreshSessionOnly} />
      )}
      {quickSearchOpen && <QuickSearchOverlay />}
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
