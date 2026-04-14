import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface AuditAction {
  action_type: string;
  // VaultSync
  chunk_count?: number;
  // DeviceEnrolled / DeviceRevoked
  device_id?: string;
  enrolling_device_id?: string;
  revoking_device_id?: string;
  // ShareSent / ShareReceived
  recipient_user_id?: string;
  sender_user_id?: string;
  // ItemAdded / ItemUpdated / ItemDeleted
  item_type?: string;
  // PasswordGenerated
  length?: number;
}

interface AuditEntry {
  id: string;
  timestamp: string;
  action: AuditAction;
  device_name: string;
}

const actionLabels: Record<string, { label: string; icon: string; color: string }> = {
  vault_sync: { label: 'Vault synced', icon: 'sync', color: 'text-primary' },
  vault_created: { label: 'Vault created', icon: 'add_circle', color: 'text-secondary' },
  vault_unlocked: { label: 'Vault unlocked', icon: 'lock_open', color: 'text-primary' },
  vault_locked: { label: 'Vault locked', icon: 'lock', color: 'text-on-surface-variant' },
  device_enrolled: { label: 'Device enrolled', icon: 'devices', color: 'text-secondary' },
  device_revoked: { label: 'Device revoked', icon: 'device_unknown', color: 'text-red-400' },
  share_sent: { label: 'Share sent', icon: 'send', color: 'text-primary' },
  share_received: { label: 'Share received', icon: 'inbox', color: 'text-secondary' },
  item_added: { label: 'Item added', icon: 'add', color: 'text-primary' },
  item_updated: { label: 'Item updated', icon: 'edit', color: 'text-secondary' },
  item_deleted: { label: 'Item deleted', icon: 'delete', color: 'text-red-400' },
  password_generated: { label: 'Password generated', icon: 'password', color: 'text-primary' },
  settings_changed: { label: 'Settings changed', icon: 'settings', color: 'text-on-surface-variant' },
};

function getActionDetails(action: AuditAction): string | null {
  switch (action.action_type) {
    case 'vault_sync': return action.chunk_count != null ? `${action.chunk_count} chunk(s)` : null;
    case 'device_enrolled': return action.device_id ? `Device ${action.device_id.slice(0, 8)}…` : null;
    case 'device_revoked': return action.device_id ? `Device ${action.device_id.slice(0, 8)}…` : null;
    case 'share_sent': return action.recipient_user_id ? `To ${action.recipient_user_id.slice(0, 8)}…` : null;
    case 'share_received': return action.sender_user_id ? `From ${action.sender_user_id.slice(0, 8)}…` : null;
    case 'item_added':
    case 'item_updated':
    case 'item_deleted': return action.item_type ?? null;
    case 'password_generated': return action.length != null ? `${action.length} characters` : null;
    default: return null;
  }
}

export default function AuditLogScreen() {
  const { showToast } = useApp();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAuditLog();
  }, []);

  const loadAuditLog = async () => {
    setLoading(true);
    try {
      const result = await invoke<AuditEntry[]>('get_audit_log');
      setEntries(result.slice().reverse());
    } catch (e) {
      showToast('Failed to load audit log', 'error');
    } finally {
      setLoading(false);
    }
  };

  const getActionInfo = (action: AuditAction) => {
    return actionLabels[action.action_type] || { label: action.action_type, icon: 'info', color: 'text-on-surface-variant' };
  };

  const groupByDate = (entries: AuditEntry[]) => {
    const groups: Record<string, AuditEntry[]> = {};
    entries.forEach(entry => {
      const date = new Date(entry.timestamp).toLocaleDateString('en-US', { 
        month: 'long', 
        day: 'numeric', 
        year: 'numeric' 
      });
      if (!groups[date]) groups[date] = [];
      groups[date].push(entry);
    });
    return groups;
  };

  const groupedEntries = groupByDate(entries);

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="font-headline text-3xl font-bold text-on-surface mb-2">Activity Log</h1>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-secondary text-lg">lock</span>
            <p className="text-on-surface-variant text-sm">Encrypted end-to-end. Only your enrolled devices can read this.</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 bg-secondary/10 rounded-full">
          <span className="w-2 h-2 bg-secondary rounded-full"></span>
          <span className="font-label text-xs text-secondary uppercase tracking-widest">Encrypted</span>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <span className="material-symbols-outlined text-4xl text-primary animate-spin">progress_activity</span>
        </div>
      ) : (
        <>
          <div className="space-y-8">
            {Object.entries(groupedEntries).map(([date, dateEntries]) => (
              <div key={date}>
                <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">{date}</h2>
                <div className="space-y-2">
                  {dateEntries.map(entry => {
                    const actionInfo = getActionInfo(entry.action);
                    const details = getActionDetails(entry.action);
                    return (
                      <div
                        key={entry.id}
                        className="flex items-center gap-4 p-4 bg-surface-container rounded-xl hover:bg-surface-container-high transition-colors"
                      >
                        <div className="w-10 h-10 rounded-full bg-surface-container-highest flex items-center justify-center">
                          <span className={`material-symbols-outlined ${actionInfo.color}`}>{actionInfo.icon}</span>
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-body font-medium text-on-surface">{actionInfo.label}</span>
                          </div>
                          {details && (
                            <p className="text-sm text-on-surface-variant">{details}</p>
                          )}
                        </div>
                        <span className="text-sm text-on-surface-variant font-mono">
                          {new Date(entry.timestamp).toLocaleTimeString('en-US', { 
                            hour: '2-digit', 
                            minute: '2-digit' 
                          })}
                        </span>
                        <span className="text-sm text-on-surface-variant">{entry.device_name}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {entries.length >= 10 && (
            <div className="mt-8 text-center">
              <button className="px-6 py-3 bg-surface-container hover:bg-surface-container-high rounded-xl text-on-surface font-medium transition-colors">
                Load more
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
