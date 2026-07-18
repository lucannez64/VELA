import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem } from '../context/AppContext';

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
  const { showToast, items, pendingShareItemId, setPendingShareItemId } = useApp();
  const [shares, setShares] = useState<Share[]>([]);
  const [activeTab, setActiveTab] = useState<'received' | 'sent'>('received');
  const [showShareModal, setShowShareModal] = useState(false);
  const [shareModalItemId, setShareModalItemId] = useState<string | null>(null);

  useEffect(() => {
    loadShares();
    if (pendingShareItemId) {
      setShareModalItemId(pendingShareItemId);
      setShowShareModal(true);
      setPendingShareItemId(null);
    }
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
      showToast('Failed to decline share: ' + String(e), 'error');
    }
  };

  const handleDismiss = async (shareId: string) => {
    try {
      await invoke('delete_share', { shareId });
      loadShares();
    } catch (e) {
      showToast('Failed to dismiss: ' + String(e), 'error');
    }
  };

  const handleRevokeSent = async (shareId: string) => {
    try {
      await invoke('delete_share', { shareId });
      showToast('Access revoked', 'success');
      loadShares();
    } catch (e) {
      showToast('Failed to revoke access', 'error');
    }
  };

  const filteredShares = shares.filter(s => s.direction === activeTab);

  const getIcon = (type: string) => {
    switch (type) {
      case 'login': return 'key';
      case 'creditCard': return 'credit_card';
      case 'secureNote': return 'note';
      default: return 'shield';
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  return (
    <div className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-2">
        <div>
          <h1 className="font-headline text-2xl sm:text-3xl font-bold text-on-surface mb-2">Sharing</h1>
          <p className="text-on-surface-variant">Securely share vault items with other VELA users</p>
        </div>
        <button
          onClick={() => { setShareModalItemId(null); setShowShareModal(true); }}
          className="flex items-center gap-2 bg-primary text-on-primary px-6 py-3 rounded-xl font-bold hover:bg-primary/90 transition-colors"
        >
          <span className="material-symbols-outlined">share</span>
          Share item
        </button>
      </div>

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
          <h2 className="font-label text-xs uppercase tracking-widest text-outline mb-4">Received</h2>
          {filteredShares.length === 0 ? (
            <div className="p-8 bg-surface-container rounded-xl text-center">
              <span className="material-symbols-outlined text-4xl text-outline-variant mb-2 block">inbox</span>
              <p className="text-on-surface-variant">No items shared with you yet</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredShares.map(share => (
                <div key={share.id} className="p-4 sm:p-6 bg-surface-container rounded-xl border border-outline-variant/5">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                    <div className="flex items-center gap-4 min-w-0">
                      <div className="w-12 h-12 shrink-0 rounded-xl bg-surface-bright flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary">{getIcon(share.item_type)}</span>
                      </div>
                      <div className="min-w-0">
                        <h3 className="font-body font-bold text-on-surface break-words">{share.item_name}</h3>
                        <p className="text-sm text-on-surface-variant">
                          From: {share.from} · {formatDate(share.shared_at)}
                        </p>
                      </div>
                    </div>
                    {share.accepted === null ? (
                      <div className="flex gap-2 shrink-0">
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
                    ) : (
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded-full text-xs font-label ${share.accepted ? 'bg-primary/10 text-primary' : 'bg-surface-container-highest text-on-surface-variant'}`}>
                          {share.accepted ? 'Accepted' : 'Declined'}
                        </span>
                        <button
                          onClick={() => handleDismiss(share.id)}
                          className="p-1.5 hover:bg-surface-bright rounded-lg transition-colors text-on-surface-variant hover:text-on-surface"
                          title="Clear from inbox"
                        >
                          <span className="material-symbols-outlined text-sm">close</span>
                        </button>
                      </div>
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
          <h2 className="font-label text-xs uppercase tracking-widest text-outline mb-4">Sent</h2>
          {filteredShares.length === 0 ? (
            <div className="p-8 bg-surface-container rounded-xl text-center">
              <span className="material-symbols-outlined text-4xl text-outline-variant mb-2 block">send</span>
              <p className="text-on-surface-variant">You haven't shared any items yet</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredShares.map(share => (
                <div key={share.id} className="p-4 sm:p-6 bg-surface-container rounded-xl border border-outline-variant/5">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                    <div className="flex items-center gap-4 min-w-0">
                      <div className="w-12 h-12 shrink-0 rounded-xl bg-surface-bright flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary">{getIcon(share.item_type)}</span>
                      </div>
                      <div className="min-w-0">
                        <h3 className="font-body font-bold text-on-surface break-words">
                          {share.item_name}
                          <span className="ml-2 text-on-surface-variant font-normal">→ {share.to}</span>
                        </h3>
                        <p className="text-sm text-on-surface-variant">{formatDate(share.shared_at)}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => handleRevokeSent(share.id)}
                      className="self-start sm:self-center shrink-0 px-4 py-2 text-red-400 hover:bg-red-500/10 rounded-lg text-sm transition-colors"
                    >
                      Revoke access
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {showShareModal && (
        <ShareModal
          items={items}
          initialItemId={shareModalItemId}
          onClose={() => setShowShareModal(false)}
          onShared={() => { setShowShareModal(false); loadShares(); }}
        />
      )}
    </div>
  );
}

function ShareModal({ items, initialItemId, onClose, onShared }: { items: VaultItem[]; initialItemId: string | null; onClose: () => void; onShared: () => void }) {
  const { showToast } = useApp();
  const [selectedItemId, setSelectedItemId] = useState(initialItemId ?? '');
  const [recipient, setRecipient] = useState('');
  const [sending, setSending] = useState(false);

  const shareableItems = items.filter(i => !i.shared);

  const handleSend = async () => {
    if (!selectedItemId || !recipient.trim()) {
      showToast('Select an item and enter a recipient', 'error');
      return;
    }
    setSending(true);
    try {
      await invoke('send_share', {
        request: {
          item_id: selectedItemId,
          recipient: recipient.trim(),
          allow_edit: false,
          notify_on_accept: true,
        },
      });
      showToast('Item shared', 'success');
      onShared();
    } catch (e) {
      showToast('Failed to share item: ' + String(e), 'error');
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center" onClick={onClose}>
      <div 
        className="bg-surface-container rounded-2xl p-8 max-w-md w-full mx-4 shadow-2xl border border-outline-variant/20"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
            <span className="material-symbols-outlined text-primary">share</span>
          </div>
          <h2 className="font-headline text-xl font-bold text-on-surface">Share vault item</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="font-label text-xs uppercase tracking-widest text-outline block mb-2">Item</label>
            <select 
              value={selectedItemId}
              onChange={e => setSelectedItemId(e.target.value)}
              className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="">Select an item...</option>
              {shareableItems.map(item => (
                <option key={item.id} value={item.id}>{item.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="font-label text-xs uppercase tracking-widest text-outline block mb-2">Recipient (User ID)</label>
            <input
              type="text"
              value={recipient}
              onChange={e => setRecipient(e.target.value)}
              placeholder="Enter recipient's VELA user ID"
              className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>
        </div>

        <div className="flex gap-4 mt-6">
          <button 
            onClick={onClose}
            className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Cancel
          </button>
          <button 
            onClick={handleSend}
            disabled={sending || !selectedItemId || !recipient.trim()}
            className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {sending ? 'Sharing...' : 'Share'}
          </button>
        </div>
      </div>
    </div>
  );
}
