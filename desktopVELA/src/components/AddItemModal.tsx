import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem, toBackendItem } from '../context/AppContext';
import PasswordGenerator from './PasswordGenerator';

interface Props {
  editItem?: VaultItem | null;
  onClose: () => void;
  onSave: () => void;
}

export default function AddItemModal({ editItem, onClose, onSave }: Props) {
  const { showToast } = useApp();
  const [itemType, setItemType] = useState<'login' | 'creditCard' | 'secureNote'>(
    (editItem?.item_type === 'login' || editItem?.item_type === 'creditCard' || editItem?.item_type === 'secureNote') 
      ? editItem.item_type 
      : 'login'
  );
  const [showPasswordGenerator, setShowPasswordGenerator] = useState(false);
  const [form, setForm] = useState({
    name: editItem?.name || '',
    username: editItem?.username || '',
    password: editItem?.password || '',
    url: editItem?.url || '',
    totp: editItem?.totp || '',
    notes: editItem?.notes || '',
    cardNumber: editItem?.card_number || '',
    cardExp: editItem?.card_exp || '',
    cardCvv: editItem?.card_cvv || '',
    cardPin: editItem?.card_pin || '',
    cardholderName: editItem?.cardholder_name || '',
    secureNote: editItem?.secure_note_content || '',
  });

  const handleSubmit = async () => {
    if (!form.name.trim()) {
      showToast('Name is required', 'error');
      return;
    }

    try {
      const now = new Date().toISOString();
      const baseItem: VaultItem = {
        id: editItem?.id || '',
        name: form.name,
        item_type: itemType,
        username: form.username || undefined,
        password: form.password || undefined,
        url: form.url || undefined,
        totp: form.totp || undefined,
        notes: form.notes || undefined,
        card_number: form.cardNumber || undefined,
        card_exp: form.cardExp || undefined,
        card_cvv: form.cardCvv || undefined,
        card_pin: form.cardPin || undefined,
        cardholder_name: form.cardholderName || undefined,
        secure_note_content: itemType === 'secureNote' ? form.secureNote : undefined,
        created_at: editItem?.created_at || now,
        updated_at: now,
        last_modified_device: editItem?.last_modified_device,
        favorite: editItem?.favorite || false,
        shared: editItem?.shared || false,
        share_recipient: editItem?.share_recipient,
      };

      const backendItem = toBackendItem(baseItem);

      if (editItem) {
        await invoke('update_item', { item: backendItem });
        showToast('Item updated', 'success');
      } else {
        await invoke('add_item', { item: backendItem });
        showToast('Item created', 'success');
      }
      onSave();
      onClose();
    } catch (e) {
      console.error('Failed to save item:', e);
      showToast('Failed to save item', 'error');
    }
  };

  const handlePasswordSelect = (password: string) => {
    setForm(prev => ({ ...prev, password }));
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-surface-container w-full max-w-2xl max-h-[90vh] rounded-2xl shadow-2xl border border-outline-variant/20 overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-6 border-b border-outline-variant/10">
          <h2 className="font-headline text-2xl font-bold text-on-surface">
            {editItem ? 'Edit Item' : 'Add New Item'}
          </h2>
          <button onClick={onClose} className="p-2 hover:bg-surface-container-high rounded-lg">
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {!editItem && (
          <div className="flex gap-2 p-4 border-b border-outline-variant/10">
            {(['login', 'creditCard', 'secureNote'] as const).map(type => (
              <button
                key={type}
                onClick={() => setItemType(type)}
                className={`flex-1 py-3 px-4 rounded-xl font-label text-sm capitalize transition-colors ${
                  itemType === type 
                    ? 'bg-primary/10 text-primary border border-primary' 
                    : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
                }`}
              >
                {type === 'creditCard' ? 'Card' : type}
              </button>
            ))}
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-6">
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Name *</label>
              <input
                type="text"
                value={form.name}
                onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40"
                placeholder="Item name"
              />
            </div>

            {itemType === 'login' && (
              <>
                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Username</label>
                  <input
                    type="text"
                    value={form.username}
                    onChange={e => setForm(prev => ({ ...prev, username: e.target.value }))}
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40"
                    placeholder="username@email.com"
                  />
                </div>

                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      value={form.password}
                      onChange={e => setForm(prev => ({ ...prev, password: e.target.value }))}
                      className="w-full px-4 py-3 pr-24 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40 font-mono"
                      placeholder="Password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPasswordGenerator(!showPasswordGenerator)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 px-3 py-1 bg-primary/20 text-primary text-xs font-label rounded-lg hover:bg-primary/30 transition-colors"
                    >
                      Generate
                    </button>
                    {showPasswordGenerator && (
                      <PasswordGenerator 
                        onSelect={handlePasswordSelect}
                        onClose={() => setShowPasswordGenerator(false)}
                      />
                    )}
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Website URL</label>
                  <input
                    type="url"
                    value={form.url}
                    onChange={e => setForm(prev => ({ ...prev, url: e.target.value }))}
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40"
                    placeholder="https://example.com"
                  />
                </div>

                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">TOTP Secret</label>
                  <input
                    type="text"
                    value={form.totp}
                    onChange={e => setForm(prev => ({ ...prev, totp: e.target.value }))}
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40 font-mono"
                    placeholder="Base32 secret or paste OTPAUTH URL"
                  />
                </div>

                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Notes</label>
                  <textarea
                    value={form.notes}
                    onChange={e => setForm(prev => ({ ...prev, notes: e.target.value }))}
                    rows={3}
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40 resize-none"
                    placeholder="Additional notes..."
                  />
                </div>
              </>
            )}

            {itemType === 'creditCard' && (
              <>
                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Card Number</label>
                  <input
                    type="text"
                    value={form.cardNumber}
                    onChange={e => setForm(prev => ({ ...prev, cardNumber: e.target.value.replace(/\D/g, '').replace(/(\d{4})/g, '$1 ').trim() }))}
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40 font-mono tracking-wider"
                    placeholder="•••• •••• •••• ••••"
                    maxLength={19}
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Expiry</label>
                    <input
                      type="text"
                      value={form.cardExp}
                      onChange={e => setForm(prev => ({ ...prev, cardExp: e.target.value }))}
                      className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40 font-mono"
                      placeholder="MM/YY"
                      maxLength={5}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">CVV</label>
                    <input
                      type="text"
                      value={form.cardCvv}
                      onChange={e => setForm(prev => ({ ...prev, cardCvv: e.target.value.replace(/\D/g, '') }))}
                      className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40 font-mono"
                      placeholder="•••"
                      maxLength={4}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">PIN</label>
                    <input
                      type="text"
                      value={form.cardPin}
                      onChange={e => setForm(prev => ({ ...prev, cardPin: e.target.value.replace(/\D/g, '') }))}
                      className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface outline-none focus:ring-2 focus:ring-primary/40 font-mono"
                      placeholder="••••"
                      maxLength={6}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Cardholder Name</label>
                  <input
                    type="text"
                    value={form.cardholderName}
                    onChange={e => setForm(prev => ({ ...prev, cardholderName: e.target.value }))}
                    className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40"
                    placeholder="JOHN DOE"
                  />
                </div>
              </>
            )}

            {itemType === 'secureNote' && (
              <div>
                <label className="block text-xs font-label uppercase tracking-widest text-outline mb-2">Content</label>
                <textarea
                  value={form.secureNote}
                  onChange={e => setForm(prev => ({ ...prev, secureNote: e.target.value }))}
                  rows={10}
                  className="w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40 resize-none font-mono"
                  placeholder="Your secure note content..."
                />
              </div>
            )}
          </div>
        </div>

        <div className="flex gap-4 p-6 border-t border-outline-variant/10">
          <button
            onClick={onClose}
            className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-bold hover:bg-primary/90 transition-colors"
          >
            {editItem ? 'Save Changes' : 'Create Item'}
          </button>
        </div>
      </div>
    </div>
  );
}
