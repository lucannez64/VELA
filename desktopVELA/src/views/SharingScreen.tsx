import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

interface Share {
  id: string;
  item_id: string;
  item_name: string;
  item_type: string;
  direction: 'received' | 'sent';
  from: string;
  to: string | null;
  shared_at: string;
  accepted: boolean | null;
}

export default function SharingScreen() {
  const { showToast } = useApp();
  const [shares, setShares] = useState<Share[]>([]);
  const [activeTab, setActiveTab] = useState<'received' | 'sent'>('received');
  const [_showShareModal, _setShowShareModal] = useState(false);

  useEffect(() => {
    loadShares();
  }, []);

  const loadShares = async () => {
    try {
      const result = await invoke<Share[]>('get_shares');
      setShares(result);
    } catch (e) {
      showToast('Failed to load shares', 'error');
    }
  };

  const handleAccept = async (shareId: string) => {
    try {
      await invoke('accept_share', { shareId });
      showToast('Share accepted', 'success');
      loadShares();
    } catch (e) {
      showToast('Failed to accept share', 'error');
    }
  };

  const handleDecline = async (shareId: string) => {
    try {
      await invoke('decline_share', { shareId });
      showToast('Share declined', 'info');
      loadShares();
    } catch (e) {
      showToast('Failed to decline share', 'error');
    }
  };

  const filteredShares = shares.filter(s => s.direction === activeTab);

  const getIcon = (type: string) => {
    switch (type) {
      case 'login': return 'key';
      case 'creditcard': return 'credit_card';
      default: return 'shield';
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <h1 className="font-headline text-3xl font-bold text-on-surface mb-2">Sharing</h1>
      <p className="text-on-surface-variant mb-8">Securely share vault items with other VELA users</p>

      <div className="flex gap-4 mb-6">
        <button
          onClick={() => setActiveTab('received')}
          className={`px-4 py-2 rounded-lg font-label text-sm transition-colors ${
            activeTab === 'received'
              ? 'bg-primary/10 text-primary'
              : 'text-on-surface-variant hover:bg-surface-container'
          }`}
        >
          Received
        </button>
        <button
          onClick={() => setActiveTab('sent')}
          className={`px-4 py-2 rounded-lg font-label text-sm transition-colors ${
            activeTab === 'sent'
              ? 'bg-primary/10 text-primary'
              : 'text-on-surface-variant hover:bg-surface-container'
          }`}
        >
          Sent
        </button>
      </div>

      {activeTab === 'received' && (
        <div className="mb-8">
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Received</h2>
          {filteredShares.length === 0 ? (
            <div className="p-8 bg-surface-container rounded-xl text-center">
              <span className="material-symbols-outlined text-4xl text-outline-variant mb-2 block">inbox</span>
              <p className="text-on-surface-variant">No items shared with you yet</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredShares.map(share => (
                <div key={share.id} className="p-6 bg-surface-container rounded-xl border border-outline-variant/5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-surface-bright flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary">{getIcon(share.item_type)}</span>
                      </div>
                      <div>
                        <h3 className="font-body font-bold text-on-surface">{share.item_name}</h3>
                        <p className="text-sm text-on-surface-variant">
                          From: {share.from} · {formatDate(share.shared_at)}
                        </p>
                      </div>
                    </div>
                    {share.accepted === null ? (
                      <div className="flex gap-2">
                        <button 
                          onClick={() => handleDecline(share.id)}
                          className="px-4 py-2 bg-surface-container-highest hover:bg-surface-bright rounded-lg text-sm transition-colors"
                        >
                          Decline
                        </button>
                        <button 
                          onClick={() => handleAccept(share.id)}
                          className="px-4 py-2 bg-primary text-on-primary rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
                        >
                          Accept
                        </button>
                      </div>
                    ) : share.accepted ? (
                      <span className="px-3 py-1 bg-primary/10 text-primary rounded-full text-xs font-label">Accepted</span>
                    ) : (
                      <span className="px-3 py-1 bg-surface-container-highest text-on-surface-variant rounded-full text-xs font-label">Declined</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'sent' && (
        <div className="mb-8">
          <h2 className="font-label text-xs uppercase tracking-widest text-slate-500 mb-4">Sent</h2>
          {filteredShares.length === 0 ? (
            <div className="p-8 bg-surface-container rounded-xl text-center">
              <span className="material-symbols-outlined text-4xl text-outline-variant mb-2 block">send</span>
              <p className="text-on-surface-variant">You haven't shared any items yet</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredShares.map(share => (
                <div key={share.id} className="p-6 bg-surface-container rounded-xl border border-outline-variant/5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-surface-bright flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary">{getIcon(share.item_type)}</span>
                      </div>
                      <div>
                        <h3 className="font-body font-bold text-on-surface">
                          {share.item_name}
                          <span className="ml-2 text-on-surface-variant font-normal">→ {share.to}</span>
                        </h3>
                        <p className="text-sm text-on-surface-variant">{formatDate(share.shared_at)}</p>
                      </div>
                    </div>
                    <button className="px-4 py-2 text-red-400 hover:bg-red-500/10 rounded-lg text-sm transition-colors">
                      Revoke access
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
