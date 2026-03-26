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
    <aside className="w-64 flex flex-col bg-surface-container-low border-r border-outline-variant/5">
      <div className="flex flex-col py-6 space-y-1">
        <div className="px-6 mb-6">
          <h2 className="text-primary font-headline font-black uppercase tracking-widest text-xs">VELA VAULT</h2>
          <p className="text-slate-500 text-[10px] tracking-tighter">Zero-Knowledge Active</p>
        </div>

        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => handleNavClick(item.id)}
            className={`
              px-6 py-3 flex items-center gap-3 font-body text-sm transition-all
              ${currentView === item.id
                ? 'text-primary border-l-4 border-primary bg-surface-container'
                : 'text-slate-400 border-l-4 border-transparent hover:bg-surface-container hover:text-primary'
              }
            `}
          >
            <span 
              className="material-symbols-outlined text-lg"
              style={{ fontVariationSettings: currentView === item.id ? "'FILL' 1" : "'FILL' 0" }}
            >
              {item.icon}
            </span>
            {item.label}
          </button>
        ))}
      </div>

      <div className="mt-auto p-6 space-y-3">
        <button 
          onClick={onAddItem}
          className="w-full py-3 bg-primary/10 text-primary rounded-xl font-label text-sm tracking-wider hover:bg-primary/20 transition-colors flex items-center justify-center gap-2"
        >
          <span className="material-symbols-outlined text-lg">add</span>
          Add Item
        </button>
        <button 
          onClick={handleLock}
          className="w-full py-3 bg-surface-container-highest text-on-surface rounded-lg font-label text-xs tracking-widest uppercase hover:bg-surface-bright transition-colors"
        >
          Lock Session
        </button>
      </div>
    </aside>
  );
}
