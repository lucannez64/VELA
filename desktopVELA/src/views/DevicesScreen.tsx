import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import QRCode from 'qrcode';
import { useApp } from '../context/AppContext';
import WebAccessModal from '../components/WebAccessModal';

interface Device {
  id: string;
  name: string;
  device_type: 'desktop' | 'mobile';
  enrolled_at: string;
  last_active: string | null;
  this_device: boolean;
  revoked: boolean;
  pending: boolean;
}

interface WebSession {
  id: string;
  mode: string;
  status: string;
  created_at: string;
  expires_at: string | null;
}

interface Props {
  onItemsChanged?: () => void;
}

export default function DevicesScreen({ onItemsChanged }: Props) {
  const { showToast } = useApp();
  const [devices, setDevices] = useState<Device[]>([]);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [showRevokeModal, setShowRevokeModal] = useState<Device | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [showWebAccess, setShowWebAccess] = useState(false);
  const [webSessions, setWebSessions] = useState<WebSession[]>([]);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);
  const [enrollmentCode, setEnrollmentCode] = useState<string | null>(null);
  const [codeCopied, setCodeCopied] = useState(false);
  const [qrImages, setQrImages] = useState<string[]>([]);
  const [qrIndex, setQrIndex] = useState(0);
  const [hideRevoked, setHideRevoked] = useState(false);

  useEffect(() => {
    loadDevices();
    loadWebSessions();
    // Auto-refresh web sessions every 30 s so sessions approved by another device
    // become visible without manual refresh (real-time notification substitute).
    const t = setInterval(loadWebSessions, 30_000);
    return () => clearInterval(t);
  }, []);

  const displayDevices = devices
    .filter(d => !hideRevoked || !d.revoked)
    .sort((a, b) => {
      const statusOrder = (d: Device) => d.pending ? 0 : d.revoked ? 2 : 1;
      const statusDiff = statusOrder(a) - statusOrder(b);
      if (statusDiff !== 0) return statusDiff;
      return new Date(b.enrolled_at).getTime() - new Date(a.enrolled_at).getTime();
    });

  const loadDevices = async () => {
    try {
      const result = await invoke<Device[]>('get_devices');
      setDevices(result);
    } catch (e) {
      showToast('Failed to load devices', 'error');
    }
  };

  const loadWebSessions = async () => {
    try {
      const result = await invoke<WebSession[]>('list_web_sessions');
      setWebSessions(result);
    } catch {
      // silently ignore — user may not have any sessions
    }
  };

  const handleRevokeWebSession = async (session: WebSession) => {
    setRevokingSessionId(session.id);
    try {
      await invoke('revoke_web_session', { sessionId: session.id });
      showToast('Web session revoked', 'success');
      await loadWebSessions();
    } catch (e) {
      showToast('Failed to revoke web session', 'error');
    } finally {
      setRevokingSessionId(null);
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
      onItemsChanged?.();
    } catch (e) {
      showToast('Failed to revoke device', 'error');
    } finally {
      setRevokingId(null);
    }
  };

  const handleEnrollDevice = async () => {
    setEnrolling(true);
    setEnrollmentCode(null);
    setCodeCopied(false);
    try {
      const code = await invoke<string>('generate_enrollment_code');
      setEnrollmentCode(code);
      const chunks = createEnrollmentQrChunks(code);
      setQrImages(await Promise.all(chunks.map(chunk => QRCode.toDataURL(chunk, {
        errorCorrectionLevel: 'L',
        margin: 2,
        width: 280,
      }))));
      setQrIndex(0);
      loadDevices();
      onItemsChanged?.();
    } catch (e: any) {
      showToast(typeof e === 'string' ? e : 'Enrollment failed', 'error');
    } finally {
      setEnrolling(false);
    }
  };

  const handleCopyCode = async () => {
    if (!enrollmentCode) return;
    try {
      await writeText(enrollmentCode);
      setCodeCopied(true);
      setTimeout(() => setCodeCopied(false), 3000);
    } catch {
      showToast('Failed to copy to clipboard', 'error');
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
    <div className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-8">
        <div>
          <h1 className="font-headline text-2xl sm:text-3xl font-bold text-on-surface mb-2">My Devices</h1>
          <p className="text-on-surface-variant">Manage devices that have access to your vault</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => setShowWebAccess(true)}
            className="flex items-center gap-2 bg-surface text-on-surface border border-outline-variant/20 px-4 sm:px-6 py-3 rounded-xl font-bold hover:bg-surface-container-high transition-colors"
          >
            <span className="material-symbols-outlined">public</span>
            Web access
          </button>
          <button
            onClick={handleEnrollDevice}
            disabled={enrolling}
            className="flex items-center gap-2 bg-primary text-on-primary px-4 sm:px-6 py-3 rounded-xl font-bold hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            <span className="material-symbols-outlined">add</span>
            {enrolling ? 'Generating code…' : 'Enroll new device'}
          </button>
        </div>
      </div>

      <WebAccessModal open={showWebAccess} onClose={() => setShowWebAccess(false)} />


      <div className="flex items-center justify-between mb-4">
        <span className="text-sm text-on-surface-variant">
          {displayDevices.length} device{displayDevices.length !== 1 ? 's' : ''}
        </span>
        <label className="flex items-center gap-2 text-sm text-on-surface-variant cursor-pointer select-none">
          <input
            type="checkbox"
            checked={hideRevoked}
            onChange={e => setHideRevoked(e.target.checked)}
            className="w-4 h-4 rounded border-outline-variant bg-surface-container text-primary accent-primary"
          />
          Hide revoked
        </label>
      </div>

      <div className="space-y-4">
        {displayDevices.map(device => (
          <div 
            key={device.id}
            className={`p-6 rounded-xl bg-surface-container border ${device.revoked ? 'border-red-500/30 opacity-60' : 'border-outline-variant/5'}`}
          >
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div className="flex items-center gap-4 min-w-0">
                <div className="w-14 h-14 shrink-0 rounded-xl bg-surface-bright flex items-center justify-center">
                  <span className="material-symbols-outlined text-2xl text-primary">{getDeviceIcon(device.device_type)}</span>
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <h3 className="font-body font-bold text-on-surface break-words">
                      {device.name}
                      {device.this_device && (
                        <span className="ml-2 text-xs text-primary">(this device)</span>
                      )}
                    </h3>
                    {device.revoked && (
                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs font-label">Revoked</span>
                    )}
                    {device.pending && !device.revoked && (
                      <span className="px-2 py-0.5 bg-amber-500/20 text-amber-300 rounded text-xs font-label">Pending</span>
                    )}
                  </div>
                  <p className="text-sm text-on-surface-variant">
                    {device.pending ? 'Enrollment code generated' : `Enrolled: ${formatDate(device.enrolled_at)}`} · Last active: {formatLastActive(device.last_active)}
                  </p>
                </div>
              </div>

              {!device.revoked && (
                <button
                  onClick={() => setShowRevokeModal(device)}
                  className="self-start sm:self-center shrink-0 px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors text-red-400 hover:text-red-300"
                >
                  {device.pending ? 'Cancel enrollment' : device.this_device ? 'Revoke (signs out everywhere)' : 'Revoke'}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Web Sessions */}
      <div className="mt-10">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
          <div>
            <h2 className="font-headline text-xl font-bold text-on-surface">Temporary Web Sessions</h2>
            <p className="text-sm text-on-surface-variant">Active browser sessions approved from this account</p>
          </div>
          <button
            onClick={loadWebSessions}
            className="flex items-center gap-2 bg-surface text-on-surface border border-outline-variant/20 px-4 py-2 rounded-xl text-sm hover:bg-surface-container-high transition-colors"
          >
            <span className="material-symbols-outlined text-sm">refresh</span>
            Refresh
          </button>
        </div>
        {webSessions.length === 0 ? (
          <div className="p-6 rounded-xl bg-surface-container border border-outline-variant/5 text-on-surface-variant text-sm">
            No active web sessions.
          </div>
        ) : (
          <div className="space-y-3">
            {webSessions.map(ws => (
              <div key={ws.id} className="p-5 rounded-xl bg-surface-container border border-outline-variant/5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div className="flex items-center gap-4 min-w-0">
                  <div className="w-11 h-11 shrink-0 rounded-xl bg-surface-bright flex items-center justify-center">
                    <span className="material-symbols-outlined text-xl text-primary">language</span>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-on-surface">Web Browser</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-label ${ws.mode === 'rw' ? 'bg-violet-500/20 text-violet-300' : 'bg-primary/20 text-primary'}`}>
                        {ws.mode === 'rw' ? 'Read-Write' : 'Read-Only'}
                      </span>
                    </div>
                    <p className="text-sm text-on-surface-variant">
                      Started {formatDate(ws.created_at)}
                      {ws.expires_at && ` · Expires ${formatLastActive(ws.expires_at)}`}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => handleRevokeWebSession(ws)}
                  disabled={revokingSessionId === ws.id}
                  className="self-start sm:self-center shrink-0 px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors text-red-400 hover:text-red-300 disabled:opacity-50"
                >
                  {revokingSessionId === ws.id ? 'Revoking…' : 'Revoke'}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {enrollmentCode && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={() => setEnrollmentCode(null)}>
          <div
            className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto shadow-2xl border border-outline-variant/20"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 mb-4">
              <span className="material-symbols-outlined text-2xl text-primary">key</span>
              <h2 className="font-headline text-2xl font-bold text-on-surface">Enrollment Code</h2>
            </div>
            <p className="text-on-surface-variant text-sm mb-4">
              Scan the QR code from the Android app or copy this code and paste it on the new device under <strong>Join existing account</strong>.
              The code is valid for one use and contains sensitive key material — do not share it over unencrypted channels.
              Closing this dialog keeps the device pending until it is used or cancelled from the Devices list.
            </p>
            {qrImages.length > 0 && (
              <div className="mb-4 p-4 bg-white rounded-xl flex flex-col items-center">
                <img src={qrImages[qrIndex]} alt={`Enrollment QR ${qrIndex + 1} of ${qrImages.length}`} className="w-full max-w-[280px] h-auto" />
                <div className="mt-3 text-slate-900 font-label text-sm">
                  {qrImages.length === 1 ? 'Enrollment QR' : `QR part ${qrIndex + 1} of ${qrImages.length}`}
                </div>
                {qrImages.length > 1 && <div className="mt-3 flex gap-2">
                  <button
                    onClick={() => setQrIndex(i => Math.max(0, i - 1))}
                    disabled={qrIndex === 0}
                    className="px-3 py-2 rounded-lg bg-slate-200 disabled:opacity-40 text-slate-900 text-sm"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setQrIndex(i => Math.min(qrImages.length - 1, i + 1))}
                    disabled={qrIndex === qrImages.length - 1}
                    className="px-3 py-2 rounded-lg bg-slate-900 disabled:opacity-40 text-white text-sm"
                  >
                    Next
                  </button>
                </div>}
              </div>
            )}
            <div className="bg-surface-bright rounded-xl p-3 mb-4 font-mono text-xs text-on-surface break-all select-all max-h-36 overflow-y-auto">
              {enrollmentCode}
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleCopyCode}
                className="flex-1 flex items-center justify-center gap-2 py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors"
              >
                <span className="material-symbols-outlined text-sm">
                  {codeCopied ? 'check' : 'content_copy'}
                </span>
                {codeCopied ? 'Copied!' : 'Copy code'}
              </button>
              <button
                onClick={() => setEnrollmentCode(null)}
                className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {showRevokeModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={() => setShowRevokeModal(null)}>
          <div
            className="bg-surface-container rounded-2xl p-4 sm:p-8 max-w-md w-full mx-4 shadow-2xl border border-outline-variant/20"
            onClick={e => e.stopPropagation()}
          >
            <h2 className="font-headline text-2xl font-bold text-on-surface mb-4">
              {showRevokeModal.pending ? 'Cancel pending enrollment?' : `Revoke ${showRevokeModal.name}?`}
            </h2>
            <p className="text-on-surface-variant mb-6">
              {showRevokeModal.pending
                ? 'This deletes the unused enrollment slot. The code will no longer work.'
                : 'This will immediately sign out that device and prevent it from accessing your vault. It cannot be undone — the device must be re-enrolled to regain access.'}
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
                {revokingId === showRevokeModal.id ? 'Revoking...' : showRevokeModal.pending ? 'Cancel enrollment' : 'Revoke device'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const QR_CHUNK_SIZE = 900;
const QR_PREFIX = 'VELA-ENROLL';

function createEnrollmentQrChunks(code: string): string[] {
  if (code.length <= QR_CHUNK_SIZE) {
    return [code];
  }

  const chunks: string[] = [];
  for (let offset = 0; offset < code.length; offset += QR_CHUNK_SIZE) {
    chunks.push(code.slice(offset, offset + QR_CHUNK_SIZE));
  }
  return chunks.map((chunk, index) => `${QR_PREFIX}:${index + 1}/${chunks.length}:${chunk}`);
}
