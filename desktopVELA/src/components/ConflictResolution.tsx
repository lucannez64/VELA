import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem } from '../context/AppContext';

interface ConflictItem {
  item_id: string;
  local_version: VaultItem;
  server_version: VaultItem;
  conflict_detected_at: string;
}

interface Props {
  conflicts: ConflictItem[];
  onResolved: () => void;
  onClose: () => void;
}

export default function ConflictResolution({ conflicts, onResolved, onClose }: Props) {
  const { showToast } = useApp();
  const [currentIndex, setCurrentIndex] = useState(0);
  const conflict = conflicts[currentIndex];

  const handleKeepLocal = async () => {
    try {
      await invoke('update_item', { item: conflict.local_version });
      await invoke('resolve_conflict', { itemId: conflict.item_id, useLocal: true });
      showToast('Kept local version', 'success');
      moveToNext();
    } catch (e) {
      showToast('Failed to resolve conflict', 'error');
    }
  };

  const handleKeepServer = async () => {
    try {
      await invoke('update_item', { item: conflict.server_version });
      await invoke('resolve_conflict', { itemId: conflict.item_id, useLocal: false });
      showToast('Kept server version', 'success');
      moveToNext();
    } catch (e) {
      showToast('Failed to resolve conflict', 'error');
    }
  };

  const handleKeepBoth = async () => {
    try {
      const duplicated = {
        ...conflict.local_version,
        id: '',
        name: `${conflict.local_version.name} (conflict copy)`,
      };
      await invoke('add_item', { item: duplicated });
      await invoke('resolve_conflict', { itemId: conflict.item_id, useLocal: true });
      showToast('Kept both versions', 'success');
      moveToNext();
    } catch (e) {
      showToast('Failed to resolve conflict', 'error');
    }
  };

  const moveToNext = () => {
    if (currentIndex < conflicts.length - 1) {
      setCurrentIndex(prev => prev + 1);
    } else {
      onResolved();
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getChangedFields = () => {
    const local = conflict.local_version;
    const server = conflict.server_version;
    const changed: string[] = [];

    if (local.username !== server.username) changed.push('Username');
    if (local.password !== server.password) changed.push('Password');
    if (local.totp !== server.totp) changed.push('TOTP');
    if (local.notes !== server.notes) changed.push('Notes');

    return changed;
  };

  const changedFields = conflict ? getChangedFields() : [];

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={onClose}>
      <div 
        className="bg-surface-container w-full max-w-3xl rounded-2xl shadow-2xl border border-amber-500/30 overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="p-6 border-b border-outline-variant/10">
          <div className="flex items-center gap-3 mb-2">
            <span className="material-symbols-outlined text-amber-500">warning</span>
            <h2 className="font-headline text-2xl font-bold text-on-surface">
              Sync Conflict — {conflict?.local_version.name}
            </h2>
          </div>
          <p className="text-on-surface-variant">
            Choose which version to keep, or keep both.
          </p>
          <div className="flex items-center gap-2 mt-2">
            <span className="text-xs text-amber-500 font-label">
              {currentIndex + 1} of {conflicts.length} conflict{conflicts.length > 1 ? 's' : ''}
            </span>
          </div>
        </div>

        <div className="p-6">
          <div className="grid grid-cols-2 gap-6">
            <div className="p-6 bg-surface-container-high rounded-xl border border-outline-variant/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-headline font-bold text-on-surface">This device</h3>
                <span className="text-xs text-on-surface-variant font-mono">
                  {formatDate(conflict?.local_version.updated_at || '')}
                </span>
              </div>
              <div className="space-y-3">
                {changedFields.includes('Username') && (
                  <div>
                    <span className="text-xs text-amber-500 font-label">Username</span>
                    <p className="text-sm text-on-surface">{conflict?.local_version.username || '(none)'}</p>
                  </div>
                )}
                {changedFields.includes('Password') && (
                  <div>
                    <span className="text-xs text-amber-500 font-label">Password</span>
                    <p className="text-sm text-on-surface font-mono">[changed]</p>
                  </div>
                )}
                {changedFields.includes('TOTP') && (
                  <div>
                    <span className="text-xs text-amber-500 font-label">TOTP</span>
                    <p className="text-sm text-on-surface">
                      {conflict?.local_version.totp || '(none)'}
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="p-6 bg-surface-container-high rounded-xl border border-outline-variant/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-headline font-bold text-on-surface">Server version</h3>
                <span className="text-xs text-on-surface-variant font-mono">
                  {formatDate(conflict?.server_version.updated_at || '')}
                </span>
              </div>
              <div className="space-y-3">
                {changedFields.includes('Username') && (
                  <div>
                    <span className="text-xs text-amber-500 font-label">Username</span>
                    <p className="text-sm text-on-surface">{conflict?.server_version.username || '(none)'}</p>
                  </div>
                )}
                {changedFields.includes('Password') && (
                  <div>
                    <span className="text-xs text-amber-500 font-label">Password</span>
                    <p className="text-sm text-on-surface font-mono">[changed]</p>
                  </div>
                )}
                {changedFields.includes('TOTP') && (
                  <div>
                    <span className="text-xs text-amber-500 font-label">TOTP</span>
                    <p className="text-sm text-on-surface">
                      {conflict?.server_version.totp || '(none)'}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="flex gap-4 p-6 border-t border-outline-variant/10">
          <button
            onClick={handleKeepLocal}
            className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Keep this device
          </button>
          <button
            onClick={handleKeepServer}
            className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Keep server
          </button>
          <button
            onClick={handleKeepBoth}
            className="flex-1 py-3 bg-primary/20 text-primary rounded-xl font-medium hover:bg-primary/30 transition-colors"
          >
            Keep both
          </button>
        </div>
      </div>
    </div>
  );
}
