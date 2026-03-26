import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  device_name: string;
  details: string | null;
}

const actionLabels: Record<string, { label: string; icon: string; color: string }> = {
  vault_synced: { label: 'Vault synced', icon: 'sync', color: 'text-primary' },
  device_enrolled: { label: 'Device enrolled', icon: 'devices', color: 'text-secondary' },
  device_revoked: { label: 'Device revoked', icon: 'device_unknown', color: 'text-red-400' },
  share_sent: { label: 'Share sent', icon: 'send', color: 'text-primary' },
  share_received: { label: 'Share received', icon: 'inbox', color: 'text-secondary' },
  share_accepted: { label: 'Share accepted', icon: 'check_circle', color: 'text-primary' },
  share_declined: { label: 'Share declined', icon: 'cancel', color: 'text-amber-400' },
};

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
      setEntries(result);
    } catch (e) {
      showToast('Failed to load audit log', 'error');
    } finally {
      setLoading(false);
    }
  };

  const getActionInfo = (action: string) => {
    return actionLabels[action] || { label: action, icon: 'info', color: 'text-on-surface-variant' };
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
                          {entry.details && (
                            <p className="text-sm text-on-surface-variant">{entry.details}</p>
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
