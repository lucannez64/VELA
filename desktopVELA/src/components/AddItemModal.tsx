import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem, toBackendItem } from '../context/AppContext';
import PasswordGenerator from './PasswordGenerator';

interface Props {
  editItem?: VaultItem | null;
  onClose: () => void;
  onSave: () => void | Promise<void>;
}

export default function AddItemModal({ editItem, onClose, onSave }: Props) {
  const { showToast } = useApp();
  const dialogRef = useRef<HTMLDivElement>(null);
  const savingRef = useRef(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    dialogRef.current?.querySelector<HTMLInputElement>('input')?.focus();
    return () => { previousFocus?.focus(); };
  }, []);

  const handleClose = () => {
    if (!savingRef.current) onClose();
  };
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
    credentialChangeNeedsReauth: editItem?.credential_change_needs_reauth ?? false,
    allowSecondFactorDowngrade: editItem?.allow_second_factor_downgrade ?? false,
  });

  const handleSubmit = async () => {
    if (savingRef.current) return;
    if (!form.name.trim()) {
      showToast('Name is required', 'error');
      return;
    }

    savingRef.current = true;
    setSaving(true);
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
        // Sent explicitly, because the form showed both controls and a submit
        // is therefore a decision. A frontend without these controls sends
        // neither key and the backend keeps whatever was there.
        credential_change_needs_reauth:
          itemType === 'login' ? form.credentialChangeNeedsReauth : undefined,
        allow_second_factor_downgrade:
          itemType === 'login' ? form.allowSecondFactorDowngrade : undefined,
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
      await onSave();
      onClose();
    } catch (e) {
      console.error('Failed to save item:', e);
      showToast('Failed to save item', 'error');
    } finally {
      savingRef.current = false;
      setSaving(false);
    }
  };

  const handlePasswordSelect = (password: string) => {
    setForm(prev => ({ ...prev, password }));
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={handleClose}>
      <div
        ref={dialogRef}
        role="dialog" aria-modal="true" aria-labelledby="item-editor-title" aria-busy={saving}
        onKeyDown={event => {
          if (event.key === 'Escape') {
            event.stopPropagation();
            handleClose();
          }
          if (event.key === 'Tab') {
            const controls = [...event.currentTarget.querySelectorAll<HTMLElement>(
              'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), [tabindex="0"]',
            )].filter(control => control.getClientRects().length > 0);
            const first = controls[0];
            const last = controls[controls.length - 1];
            if (event.shiftKey && document.activeElement === first) {
              event.preventDefault();
              last?.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
              event.preventDefault();
              first?.focus();
            }
          }
        }}
        className="bg-surface-container w-full max-w-2xl max-h-[calc(100dvh-2rem)] rounded-2xl shadow-2xl border border-outline-variant/20 overflow-hidden flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center justify-between gap-2 p-4 sm:p-6 border-b border-outline-variant/10">
          <h2 id="item-editor-title" className="font-headline text-2xl font-bold text-on-surface">
            {editItem ? 'Edit Item' : 'Add New Item'}
          </h2>
          <button disabled={saving} aria-label="Close item editor" onClick={handleClose} className="shrink-0 p-2 hover:bg-surface-container-high rounded-lg">
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {!editItem && (
          <div className="flex shrink-0 gap-2 p-4 border-b border-outline-variant/10">
            {(['login', 'creditCard', 'secureNote'] as const).map(type => (
              <button
                key={type}
                onClick={() => setItemType(type)}
                className={`flex-1 min-w-0 py-3 px-2 sm:px-4 rounded-xl font-label text-sm capitalize transition-colors ${
                  itemType === type 
                    ? 'bg-primary/10 text-primary border border-primary' 
                    : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'
                }`}
              >
                {type === 'creditCard' ? 'Card' : type === 'secureNote' ? 'Secure Note' : 'Login'}
              </button>
            ))}
          </div>
        )}

        <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain p-4 sm:p-6">
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
                      spellCheck={false}
                      autoComplete="off"
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
                    spellCheck={false}
                    autoComplete="off"
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
                    spellCheck={false}
                    autoComplete="off"
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

                {/*
                  Sign-in behaviour: two settings that change what VELA does when
                  it signs in to this site for you. Both are described by their
                  consequence rather than their mechanism, because the mechanism
                  is not what anybody is deciding about.
                */}
                <div className="pt-2 border-t border-outline-variant/40">
                  <div className="text-xs font-label uppercase tracking-widest text-outline mb-3">
                    Sign-in behaviour
                  </div>

                  <label className="flex gap-3 items-start cursor-pointer mb-4">
                    <input
                      type="checkbox"
                      checked={form.credentialChangeNeedsReauth}
                      onChange={e =>
                        setForm(prev => ({ ...prev, credentialChangeNeedsReauth: e.target.checked }))
                      }
                      className="mt-1 accent-primary w-4 h-4 shrink-0"
                    />
                    <span className="text-sm text-on-surface">
                      This site asks for my current password before changing it
                      <span className="block text-xs text-on-surface-variant mt-0.5">
                        If it does, signing out ends a stolen session's power. If it
                        does not, whoever holds a session can change the password and
                        keep the account.
                      </span>
                    </span>
                  </label>

                  {/*
                    Only meaningful once there is a code to answer with, and
                    showing an unusable switch invites ticking it "just in case".
                  */}
                  {form.totp.trim() !== '' && (
                    <label className="flex gap-3 items-start cursor-pointer rounded-xl p-3 bg-error-container/20 border border-error/30">
                      <input
                        type="checkbox"
                        checked={form.allowSecondFactorDowngrade}
                        onChange={e =>
                          setForm(prev => ({ ...prev, allowSecondFactorDowngrade: e.target.checked }))
                        }
                        className="mt-1 accent-error w-4 h-4 shrink-0"
                      />
                      <span className="text-sm text-on-surface">
                        Use my authenticator code even when this site asks for a
                        security key
                        <span className="block text-xs text-on-surface-variant mt-0.5">
                          Lets VELA finish signing in on its own, by deliberately
                          taking the weaker of the two factors the site offered. A
                          security key cannot be phished; a code can. Leave this off
                          unless you would rather finish those sign-ins yourself.
                        </span>
                      </span>
                    </label>
                  )}
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

        <div className="flex shrink-0 gap-4 p-4 sm:p-6 border-t border-outline-variant/10">
          <button
            disabled={saving}
            onClick={handleClose}
            className="flex-1 py-3 bg-surface-container-highest text-on-surface rounded-xl font-medium hover:bg-surface-bright transition-colors"
          >
            Cancel
          </button>
          <button
            disabled={saving}
            onClick={handleSubmit}
            className="flex-1 py-3 bg-primary text-on-primary rounded-xl font-bold hover:bg-primary/90 transition-colors disabled:opacity-60 disabled:cursor-wait"
          >
            {saving ? 'Saving…' : editItem ? 'Save Changes' : 'Create Item'}
          </button>
        </div>
      </div>
    </div>
  );
}
