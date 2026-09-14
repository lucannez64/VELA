import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, DeletedItem, VaultItem } from '../context/AppContext';

function getIcon(type: string) {
  switch (type) {
    case 'login': return 'key';
    case 'creditCard': return 'credit_card';
    case 'secureNote': return 'note';
    case 'passkey': return 'passkey';
    default: return 'shield';
  }
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/** The trash (§1.2): deleted items restorable until purged (explicitly, or
 *  by the 30-day retention the deletion tombstones already had). Entries the
 *  user did not delete on this device carry no "deleted by" label beyond the
 *  timestamp — the audit log has the device. */
export default function TrashView() {
  const { showToast, setItems, items } = useApp();
  const [entries, setEntries] = useState<DeletedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmingPurge, setConfirmingPurge] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setEntries(await invoke<DeletedItem[]>('get_deleted_items'));
    } catch (e) {
      console.error('Failed to load trash:', e);
      showToast('Failed to load trash', 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => { load(); }, [load]);

  const handleRestore = async (entry: DeletedItem) => {
    try {
      const restored = await invoke<VaultItem>('restore_item', { id: entry.item.id });
      setEntries(prev => prev.filter(e => e.item.id !== entry.item.id));
      // `setItems` takes the list, not an updater: read the context's value.
      setItems([...items, restored].sort((a, b) => a.name.localeCompare(b.name)));
      showToast(`Restored "${restored.name}"`, 'success');
    } catch (e) {
      console.error('Failed to restore item:', e);
      showToast('Failed to restore item', 'error');
    }
  };

  const handlePurge = async (entry: DeletedItem) => {
    if (confirmingPurge !== entry.item.id) {
      setConfirmingPurge(entry.item.id);
      return;
    }
    try {
      await invoke('purge_deleted_item', { id: entry.item.id });
      setEntries(prev => prev.filter(e => e.item.id !== entry.item.id));
      showToast(`Deleted "${entry.item.name}" forever`, 'success');
    } catch (e) {
      console.error('Failed to purge item:', e);
      showToast('Failed to delete item', 'error');
    } finally {
      setConfirmingPurge(null);
    }
  };

  return (
    <div className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
      <div className="mb-8">
        <h2 className="font-headline text-2xl font-bold text-on-surface flex items-center gap-3">
          <span className="material-symbols-outlined text-on-surface-variant">delete</span>
          Trash
        </h2>
        <p className="text-sm text-on-surface-variant mt-1">
          Deleted items stay here for 30 days. Restoring an item syncs it back
          to every device.
        </p>
      </div>

      {loading ? (
        <p className="text-on-surface-variant">Loading…</p>
      ) : entries.length === 0 ? (
        <div className="text-center py-16">
          <span className="material-symbols-outlined text-6xl text-outline-variant mb-4 block">delete_sweep</span>
          <p className="text-on-surface-variant">The trash is empty</p>
        </div>
      ) : (
        <div className="space-y-3 max-w-3xl">
          {entries.map(entry => (
            <div
              key={entry.item.id}
              className="flex items-center justify-between gap-4 p-4 bg-surface-container-low rounded-xl"
            >
              <div className="flex items-center gap-4 min-w-0">
                <span className="material-symbols-outlined text-on-surface-variant">
                  {getIcon(entry.item.item_type)}
                </span>
                <div className="min-w-0">
                  <h3 className="font-body font-bold text-on-surface truncate">{entry.item.name}</h3>
                  <p className="text-xs text-on-surface-variant">
                    Deleted {formatDate(entry.deleted_at)}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => handleRestore(entry)}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-primary/10 text-primary text-sm font-medium hover:bg-primary/20 transition-colors"
                >
                  <span className="material-symbols-outlined text-sm">restore_from_trash</span>
                  Restore
                </button>
                <button
                  onClick={() => handlePurge(entry)}
                  className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    confirmingPurge === entry.item.id
                      ? 'bg-red-500/20 text-red-400'
                      : 'bg-surface-container-highest text-on-surface-variant hover:text-red-400'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">delete_forever</span>
                  {confirmingPurge === entry.item.id ? 'Confirm' : 'Delete forever'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
