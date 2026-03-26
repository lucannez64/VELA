import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface Device {
  id: string;
  name: string;
  device_type: 'desktop' | 'mobile';
  enrolled_at: string;
  last_active: string | null;
  this_device: boolean;
  revoked: boolean;
}

export default function DevicesScreen() {
  const { showToast } = useApp();
  const [devices, setDevices] = useState<Device[]>([]);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [showRevokeModal, setShowRevokeModal] = useState<Device | null>(null);

  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      const result = await invoke<Device[]>('get_devices');
      setDevices(result);
    } catch (e) {
      showToast('Failed to load devices', 'error');
    }
  };

  const handleRevoke = async () => {
    if (!showRevokeModal) return;
    
    setRevokingId(showRevokeModal.id);
    try {
      await invoke('revoke_device', { 
        request: { 
          device_id: showRevokeModal.id, 
          confirm: true 
        } 
      });
      showToast('Device revoked', 'success');
      setShowRevokeModal(null);
      loadDevices();
    } catch (e) {
      showToast('Failed to revoke device', 'error');
    } finally {
      setRevokingId(null);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  const formatLastActive = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) return 'Just now';
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
    return formatDate(dateStr);
  };

  const getDeviceIcon = (type: string) => {
    return type === 'desktop' ? 'laptop_mac' : 'smartphone';
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="font-headline text-3xl font-bold text-on-surface mb-2">My Devices</h1>
          <p className="text-on-surface-variant">Manage devices that have access to your vault</p>
        </div>
        <button className="flex items-center gap-2 bg-primary text-on-primary px-6 py-3 rounded-xl font-bold hover:bg-primary/90 transition-colors">
          <span className="material-symbols-outlined">add</span>
          Enroll new device
        </button>
      </div>

      <div className="space-y-4">
        {devices.map(device => (
          <div 
            key={device.id}
            className={`p-6 rounded-xl bg-surface-container border ${device.revoked ? 'border-red-500/30 opacity-60' : 'border-outline-variant/5'}`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl bg-surface-bright flex items-center justify-center">
                  <span className="material-symbols-outlined text-2xl text-primary">{getDeviceIcon(device.device_type)}</span>
                </div>
                <div>
                  <div className="flex items-center gap-3">
                    <h3 className="font-body font-bold text-on-surface">
                      {device.name}
                      {device.this_device && (
                        <span className="ml-2 text-xs text-primary">(this device)</span>
                      )}
                    </h3>
                    {device.revoked && (
                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs font-label">Revoked</span>
                    )}
                  </div>
                  <p className="text-sm text-on-surface-variant">
                    Enrolled: {formatDate(device.enrolled_at)} · Last active: {formatLastActive(device.last_active)}
                  </p>
                </div>
              </div>
              
              {!device.revoked && (
                <button 
                  onClick={() => setShowRevokeModal(device)}
                  className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors text-red-400 hover:text-red-300"
                >
                  {device.this_device ? 'Revoke (signs out everywhere)' : 'Revoke'}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {showRevokeModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={() => setShowRevokeModal(null)}>
          <div 
            className="bg-surface-container rounded-2xl p-8 max-w-md w-full mx-4 shadow-2xl border border-outline-variant/20"
            onClick={e => e.stopPropagation()}
          >
            <h2 className="font-headline text-2xl font-bold text-on-surface mb-4">
              Revoke {showRevokeModal.name}?
            </h2>
            <p className="text-on-surface-variant mb-6">
              This will immediately sign out that device and prevent it from accessing your vault. 
              It cannot be undone — the device must be re-enrolled to regain access.
            </p>
            <div className="flex gap-4">
              <button 
                onClick={() => setShowRevokeModal(null)}
                className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
              >
                Cancel
              </button>
              <button 
                onClick={handleRevoke}
                disabled={revokingId === showRevokeModal.id}
                className="flex-1 py-3 bg-red-500 text-white rounded-xl font-medium hover:bg-red-600 transition-colors disabled:opacity-50"
              >
                {revokingId === showRevokeModal.id ? 'Revoking...' : 'Revoke device'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
