import { invoke } from '@tauri-apps/api/core';
import { useApp, View } from '../context/AppContext';

interface Props {
  onAddItem: () => void;
}

const navItems: { id: View; label: string; icon: string }[] = [
  { id: 'vault', label: 'Vault', icon: 'shield' },
  { id: 'devices', label: 'Devices', icon: 'devices' },
  { id: 'sharing', label: 'Sharing', icon: 'share_reviews' },
  { id: 'audit', label: 'Audit Log', icon: 'history' },
  { id: 'breachMonitor', label: 'Breach Monitor', icon: 'security' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

export default function Sidebar({ onAddItem }: Props) {
  const { currentView, setCurrentView, setSelectedItem, setSession, setItems, showToast } = useApp();

  const handleNavClick = (view: View) => {
    setCurrentView(view);
    if (view !== 'vault') {
      setSelectedItem(null);
    }
  };

  const handleLock = async () => {
    try {
      await invoke('lock_session');
      setSession(prev => prev ? { ...prev, active: false, lock_state: 'locked' as const } : null);
      setItems([]);
      setSelectedItem(null);
      showToast('Session locked', 'info');
    } catch (e) {
      console.error('Lock failed:', e);
    }
  };

  return (
    <aside className="w-16 lg:w-64 flex flex-col bg-surface-container-low border-r border-outline-variant/5 transition-[width] duration-200">
      <div className="flex flex-col py-6 space-y-1">
        <div className="hidden lg:block px-6 mb-6">
          <h2 className="text-primary font-headline font-black uppercase tracking-widest text-xs">VELA VAULT</h2>
          <p className="text-outline text-[10px] tracking-tighter">Zero-Knowledge Active</p>
        </div>

        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => handleNavClick(item.id)}
            title={item.label}
            className={`
              px-2 lg:px-6 py-3 flex items-center justify-center lg:justify-start gap-3 font-body text-sm transition-all
              ${currentView === item.id
                ? 'text-primary border-l-4 border-primary bg-surface-container'
                : 'text-on-surface-variant border-l-4 border-transparent hover:bg-surface-container hover:text-primary'
              }
            `}
          >
            <span
              className="material-symbols-outlined text-lg"
              style={{ fontVariationSettings: currentView === item.id ? "'FILL' 1" : "'FILL' 0" }}
            >
              {item.icon}
            </span>
            <span className="hidden lg:inline">{item.label}</span>
          </button>
        ))}
      </div>

      <div className="mt-auto p-3 lg:p-6 space-y-3">
        <button
          onClick={onAddItem}
          title="Add Item"
          className="w-full py-3 bg-primary/10 text-primary rounded-xl font-label text-sm tracking-wider hover:bg-primary/20 transition-colors flex items-center justify-center gap-2"
        >
          <span className="material-symbols-outlined text-lg">add</span>
          <span className="hidden lg:inline">Add Item</span>
        </button>
        <button
          onClick={handleLock}
          title="Lock Session"
          className="w-full py-3 bg-surface-container-highest text-on-surface rounded-lg font-label text-xs tracking-widest uppercase hover:bg-surface-bright transition-colors flex items-center justify-center gap-2"
        >
          <span className="material-symbols-outlined text-base lg:hidden">lock</span>
          <span className="hidden lg:inline">Lock Session</span>
        </button>
      </div>
    </aside>
  );
}
