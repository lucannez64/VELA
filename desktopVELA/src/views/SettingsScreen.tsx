import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, Settings } from '../context/AppContext';

export default function SettingsScreen() {
  const { showToast, setSession, setItems, setSelectedItem } = useApp();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [syncing, setSyncing] = useState(false);

  const handleSyncNow = async () => {
    if (syncing) return;
    setSyncing(true);
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('trigger_sync');
      showToast('Vault synced', 'success');
    } catch (e) {
      showToast('Sync failed', 'error');
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const result = await invoke<Settings>('get_settings');
      setSettings(result);
    } catch (e) {
      showToast('Failed to load settings', 'error');
    }
  };

  const handleUpdateSettings = async (newSettings: Settings) => {
    try {
      await invoke('update_settings', { settings: newSettings });
      setSettings(newSettings);
      showToast('Settings saved', 'success');
    } catch (e) {
      showToast('Failed to save settings', 'error');
    }
  };

  const handleCopyUserId = () => {
    if (settings?.user_id) {
      navigator.clipboard.writeText(settings.user_id);
      showToast('User ID copied', 'success');
    }
  };

  const handleSignOut = async () => {
    try {
      await invoke('lock_session');
      setSession(prev => prev ? { ...prev, active: false, lock_state: 'locked' as const } : null);
      setItems([]);
      setSelectedItem(null);
      showToast('Signed out', 'info');
    } catch (e) {
      showToast('Failed to sign out', 'error');
    }
  };

  const handleDeleteVault = async () => {
    try {
      await invoke('reset_vault');
      setSession(null);
      setItems([]);
      setSelectedItem(null);
      setShowDeleteModal(false);
      setDeleteConfirmText('');
      window.location.reload();
    } catch (e) {
      showToast('Failed to delete vault: ' + String(e), 'error');
    }
  };

  if (!settings) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <span className="material-symbols-outlined text-4xl text-primary animate-spin">progress_activity</span>
      </div>
    );
  }

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <h1 className="font-headline text-3xl font-bold text-on-surface mb-8">Settings</h1>

      <div className="max-w-2xl space-y-8">
        <section>
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Security</h2>
          <div className="bg-surface-container rounded-xl p-6 space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Auto-lock after idle</label>
                <p className="text-sm text-on-surface-variant">Automatically lock when inactive</p>
              </div>
              <select 
                value={settings.auto_lock_minutes}
                onChange={e => handleUpdateSettings({ ...settings, auto_lock_minutes: Number(e.target.value) })}
                className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface outline-none focus:ring-2 focus:ring-primary/40"
              >
                <option value={1}>1 minute</option>
                <option value={5}>5 minutes</option>
                <option value={15}>15 minutes</option>
                <option value={30}>30 minutes</option>
                <option value={60}>1 hour</option>
              </select>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Clipboard clear delay</label>
                <p className="text-sm text-on-surface-variant">Time before copied data is cleared</p>
              </div>
              <select 
                value={settings.clipboard_clear_seconds}
                onChange={e => handleUpdateSettings({ ...settings, clipboard_clear_seconds: Number(e.target.value) })}
                className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface outline-none focus:ring-2 focus:ring-primary/40"
              >
                <option value={15}>15 seconds</option>
                <option value={30}>30 seconds</option>
                <option value={60}>1 minute</option>
                <option value={120}>2 minutes</option>
              </select>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Require biometrics on reveal</label>
                <p className="text-sm text-on-surface-variant">Authenticate before showing passwords</p>
              </div>
              <button 
                onClick={() => handleUpdateSettings({ ...settings, require_biometric_on_reveal: !settings.require_biometric_on_reveal })}
                className={`w-12 h-7 rounded-full transition-colors ${settings.require_biometric_on_reveal ? 'bg-primary' : 'bg-surface-container-highest'}`}
              >
                <div className={`w-5 h-5 rounded-full bg-white transition-transform ${settings.require_biometric_on_reveal ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>
          </div>
        </section>

        <section>
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Sync</h2>
          <div className="bg-surface-container rounded-xl p-6 space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Sync on startup</label>
                <p className="text-sm text-on-surface-variant">Automatically sync when app opens</p>
              </div>
              <button 
                onClick={() => handleUpdateSettings({ ...settings, sync_on_startup: !settings.sync_on_startup })}
                className={`w-12 h-7 rounded-full transition-colors ${settings.sync_on_startup ? 'bg-primary' : 'bg-surface-container-highest'}`}
              >
                <div className={`w-5 h-5 rounded-full bg-white transition-transform ${settings.sync_on_startup ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Background sync interval</label>
                <p className="text-sm text-on-surface-variant">How often to sync in the background</p>
              </div>
              <select 
                value={settings.background_sync_minutes}
                onChange={e => handleUpdateSettings({ ...settings, background_sync_minutes: Number(e.target.value) })}
                className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface outline-none focus:ring-2 focus:ring-primary/40"
              >
                <option value={1}>1 minute</option>
                <option value={5}>5 minutes</option>
                <option value={15}>15 minutes</option>
                <option value={30}>30 minutes</option>
              </select>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Last synced</label>
                <p className="text-sm text-on-surface-variant">Most recent sync time</p>
              </div>
              <button onClick={handleSyncNow} disabled={syncing} className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors disabled:opacity-50">
                {syncing ? 'Syncing...' : 'Sync now'}
              </button>
            </div>
          </div>
        </section>

        <section>
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Import / Export</h2>
          <div className="bg-surface-container rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Export vault</label>
                <p className="text-sm text-on-surface-variant">Download as Bitwarden-compatible JSON</p>
              </div>
              <button
                onClick={async () => {
                  try {
                    const json = await invoke<string>('export_vault_bitwarden_json');
                    const blob = new Blob([json], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `vela-export-${new Date().toISOString().slice(0, 10)}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                    showToast('Vault exported', 'success');
                  } catch (e) {
                    showToast('Export failed: ' + String(e), 'error');
                  }
                }}
                className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors"
              >
                Export
              </button>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">Import vault</label>
                <p className="text-sm text-on-surface-variant">Import from Bitwarden-compatible JSON</p>
              </div>
              <input
                type="file"
                accept=".json"
                id="import-file-input"
                className="hidden"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  try {
                    const text = await file.text();
                    const result = await invoke<{ added: number; skipped: number; total: number }>('import_vault_bitwarden_json', { data: text });
                    showToast(`Imported ${result.added} of ${result.total} items`, 'success');
                  } catch (err) {
                    showToast('Import failed: ' + String(err), 'error');
                  }
                  e.target.value = '';
                }}
              />
              <button
                onClick={() => document.getElementById('import-file-input')?.click()}
                className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors"
              >
                Import
              </button>
            </div>
          </div>
        </section>

        <section>
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Browser Extension</h2>
          <div className="bg-surface-container rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className={`w-3 h-3 rounded-full ${settings.extension_connected ? 'bg-primary' : 'bg-amber-500'}`}></span>
                <div>
                  <label className="font-body font-medium text-on-surface">
                    Extension {settings.extension_connected ? 'connected' : 'not found'}
                  </label>
                  {settings.extension_version && (
                    <p className="text-sm text-on-surface-variant">{settings.extension_version}</p>
                  )}
                </div>
              </div>
              <button className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors">
                Manage extension
              </button>
            </div>
          </div>
        </section>

        <section>
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Account</h2>
          <div className="bg-surface-container rounded-xl p-6 space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <label className="font-body font-medium text-on-surface">User ID</label>
                <p className="font-mono text-xs text-on-surface-variant">{settings.user_id}</p>
              </div>
              <button onClick={handleCopyUserId} className="px-4 py-2 bg-surface-container-highest rounded-lg text-on-surface hover:bg-surface-bright transition-colors">
                Copy
              </button>
            </div>

            <div className="flex gap-4">
              <button 
                onClick={handleSignOut}
                className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
              >
                Sign out and lock
              </button>
              <button 
                onClick={() => setShowDeleteModal(true)}
                className="flex-1 py-3 bg-red-500/10 text-red-400 rounded-xl font-medium hover:bg-red-500/20 transition-colors"
              >
                Delete vault
              </button>
            </div>
          </div>
        </section>
      </div>

      {showDeleteModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={() => setShowDeleteModal(false)}>
          <div 
            className="bg-surface-container rounded-2xl p-8 max-w-md w-full mx-4 shadow-2xl border border-red-500/30"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 mb-4">
              <span className="material-symbols-outlined text-red-400 text-2xl">warning</span>
              <h2 className="font-headline text-2xl font-bold text-on-surface">Delete vault?</h2>
            </div>
            <p className="text-on-surface-variant mb-6">
              This action is irreversible. All your data will be permanently deleted. 
              Type <span className="font-mono text-red-400">DELETE</span> to confirm.
            </p>
            <input 
              type="text"
              value={deleteConfirmText}
              onChange={e => setDeleteConfirmText(e.target.value)}
              placeholder="Type DELETE"
              className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-red-500/40 mb-6"
            />
            <div className="flex gap-4">
              <button 
                onClick={() => { setShowDeleteModal(false); setDeleteConfirmText(''); }}
                className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
              >
                Cancel
              </button>
              <button 
                disabled={deleteConfirmText !== 'DELETE'}
                onClick={handleDeleteVault}
                className="flex-1 py-3 bg-red-500 text-white rounded-xl font-medium hover:bg-red-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Delete forever
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
