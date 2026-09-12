import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem, toBackendItem, CustomField } from '../context/AppContext';
import PasswordGenerator from './PasswordGenerator';

interface Props {
  editItem?: VaultItem | null;
  onClose: () => void;
  onSave: () => void;
}

type ItemType =
  | 'login'
  | 'creditCard'
  | 'secureNote'
  | 'address'
  | 'bankAccount'
  | 'apiKey'
  | 'sshKey';

const ITEM_TYPE_OPTIONS: { value: ItemType; label: string }[] = [
  { value: 'login', label: 'Login' },
  { value: 'creditCard', label: 'Credit Card' },
  { value: 'secureNote', label: 'Secure Note' },
  { value: 'address', label: 'Address' },
  { value: 'bankAccount', label: 'Bank Account' },
  { value: 'apiKey', label: 'API Key' },
  { value: 'sshKey', label: 'SSH Key' },
];

const inputClass =
  'w-full px-4 py-3 bg-surface-container-highest rounded-xl text-on-surface placeholder:text-on-surface-variant/50 outline-none focus:ring-2 focus:ring-primary/40';
const labelClass = 'block text-xs font-label uppercase tracking-widest text-outline mb-2';

export default function AddItemModal({ editItem, onClose, onSave }: Props) {
  const { showToast } = useApp();
  const supportedTypes: ItemType[] = ['login', 'creditCard', 'secureNote', 'address', 'bankAccount', 'apiKey', 'sshKey'];
  const [itemType, setItemType] = useState<ItemType>(
    editItem && (supportedTypes as string[]).includes(editItem.item_type)
      ? (editItem.item_type as ItemType)
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
    // §1.3: one optional folder, tags as a comma-separated list.
    // Canonicalized (trimmed, deduped, sorted) backend-side on save.
    folder: editItem?.folder || '',
    tags: (editItem?.tags || []).join(', '),
    // §1.3 new item types.
    fullName: editItem?.full_name || '',
    street: editItem?.street || '',
    streetLine2: editItem?.street_line2 || '',
    city: editItem?.city || '',
    state: editItem?.state || '',
    postalCode: editItem?.postal_code || '',
    country: editItem?.country || '',
    phone: editItem?.phone || '',
    bankName: editItem?.bank_name || '',
    accountKind: editItem?.account_kind || '',
    holder: editItem?.holder || '',
    accountNumber: editItem?.account_number || '',
    routingNumber: editItem?.routing_number || '',
    iban: editItem?.iban || '',
    swift: editItem?.swift || '',
    apiKey: editItem?.api_key || '',
    expires: editItem?.expires || '',
    sshKind: editItem?.kind || '',
    publicKey: editItem?.public_key || '',
    privateKey: editItem?.private_key || '',
    passphrase: editItem?.passphrase || '',
    comment: editItem?.comment || '',
  });
  // §1.3: user-defined extra fields, editable on every item type.
  const [customFields, setCustomFields] = useState<CustomField[]>(
    (editItem?.custom_fields || []).map(f => ({ ...f }))
  );

  const setField = (key: keyof typeof form, value: string) =>
    setForm(prev => ({ ...prev, [key]: value }));

  const addCustomField = () =>
    setCustomFields(prev => [...prev, { label: '', value: '', field_type: 'text' }]);
  const updateCustomField = (index: number, patch: Partial<CustomField>) =>
    setCustomFields(prev => prev.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  const removeCustomField = (index: number) =>
    setCustomFields(prev => prev.filter((_, i) => i !== index));

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
        // Sent explicitly, because the form showed both controls and a submit
        // is therefore a decision. A frontend without these controls sends
        // neither key and the backend keeps whatever was there.
        credential_change_needs_reauth:
          itemType === 'login' ? form.credentialChangeNeedsReauth : undefined,
        allow_second_factor_downgrade:
          itemType === 'login' ? form.allowSecondFactorDowngrade : undefined,
        tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
        folder: form.folder.trim() || undefined,
        custom_fields: customFields
          .filter(f => f.label.trim() || f.value.trim())
          .map(f => ({ label: f.label.trim(), value: f.value, field_type: f.field_type })),
        // §1.3 new types — only the fields the chosen type carries.
        ...(itemType === 'address'
          ? {
              full_name: form.fullName,
              street: form.street,
              street_line2: form.streetLine2,
              city: form.city,
              state: form.state,
              postal_code: form.postalCode,
              country: form.country,
              phone: form.phone,
            }
          : {}),
        ...(itemType === 'bankAccount'
          ? {
              bank_name: form.bankName,
              account_kind: form.accountKind,
              holder: form.holder,
              account_number: form.accountNumber,
              routing_number: form.routingNumber,
              iban: form.iban,
              swift: form.swift,
            }
          : {}),
        ...(itemType === 'apiKey'
          ? {
              url: form.url,
              username: form.username,
              api_key: form.apiKey,
              expires: form.expires || undefined,
            }
          : {}),
        ...(itemType === 'sshKey'
          ? {
              kind: form.sshKind,
              public_key: form.publicKey,
              private_key: form.privateKey,
              passphrase: form.passphrase || undefined,
              comment: form.comment,
            }
          : {}),
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
          <div className="p-4 border-b border-outline-variant/10">
            <label className={labelClass}>Type</label>
            <select
              value={itemType}
              onChange={e => setItemType(e.target.value as ItemType)}
              className={`${inputClass} capitalize`}
            >
              {ITEM_TYPE_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-6">
          <div className="space-y-4">
            <div>
              <label className={labelClass}>Name *</label>
              <input
                type="text"
                value={form.name}
                onChange={e => setField('name', e.target.value)}
                className={inputClass}
                placeholder="Item name"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className={labelClass}>Folder</label>
                <input
                  type="text"
                  value={form.folder}
                  onChange={e => setField('folder', e.target.value)}
                  className={inputClass}
                  placeholder="Optional folder"
                />
              </div>
              <div>
                <label className={labelClass}>Tags</label>
                <input
                  type="text"
                  value={form.tags}
                  onChange={e => setField('tags', e.target.value)}
                  className={inputClass}
                  placeholder="comma, separated, tags"
                />
              </div>
            </div>

            {itemType === 'login' && (
              <>
                <div>
                  <label className={labelClass}>Username</label>
                  <input
                    type="text"
                    value={form.username}
                    onChange={e => setField('username', e.target.value)}
                    className={inputClass}
                    placeholder="username@email.com"
                  />
                </div>

                <div>
                  <label className={labelClass}>Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      value={form.password}
                      onChange={e => setField('password', e.target.value)}
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
                  <label className={labelClass}>Website URL</label>
                  <input
                    type="url"
                    value={form.url}
                    onChange={e => setField('url', e.target.value)}
                    spellCheck={false}
                    autoComplete="off"
                    className={inputClass}
                    placeholder="https://example.com"
                  />
                </div>

                <div>
                  <label className={labelClass}>TOTP Secret</label>
                  <input
                    type="text"
                    value={form.totp}
                    onChange={e => setField('totp', e.target.value)}
                    spellCheck={false}
                    autoComplete="off"
                    className={`${inputClass} font-mono`}
                    placeholder="Base32 secret or paste OTPAUTH URL"
                  />
                </div>

                <div>
                  <label className={labelClass}>Notes</label>
                  <textarea
                    value={form.notes}
                    onChange={e => setField('notes', e.target.value)}
                    rows={3}
                    className={`${inputClass} resize-none`}
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
                  <label className={labelClass}>Card Number</label>
                  <input
                    type="text"
                    value={form.cardNumber}
                    onChange={e => setField('cardNumber', e.target.value.replace(/\D/g, '').replace(/(\d{4})/g, '$1 ').trim())}
                    className={`${inputClass} font-mono tracking-wider`}
                    placeholder="•••• •••• •••• ••••"
                    maxLength={19}
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div>
                    <label className={labelClass}>Expiry</label>
                    <input
                      type="text"
                      value={form.cardExp}
                      onChange={e => setField('cardExp', e.target.value)}
                      className={`${inputClass} font-mono`}
                      placeholder="MM/YY"
                      maxLength={5}
                    />
                  </div>
                  <div>
                    <label className={labelClass}>CVV</label>
                    <input
                      type="text"
                      value={form.cardCvv}
                      onChange={e => setField('cardCvv', e.target.value.replace(/\D/g, ''))}
                      className={`${inputClass} font-mono`}
                      placeholder="•••"
                      maxLength={4}
                    />
                  </div>
                  <div>
                    <label className={labelClass}>PIN</label>
                    <input
                      type="text"
                      value={form.cardPin}
                      onChange={e => setField('cardPin', e.target.value.replace(/\D/g, ''))}
                      className={`${inputClass} font-mono`}
                      placeholder="••••"
                      maxLength={6}
                    />
                  </div>
                </div>

                <div>
                  <label className={labelClass}>Cardholder Name</label>
                  <input
                    type="text"
                    value={form.cardholderName}
                    onChange={e => setField('cardholderName', e.target.value)}
                    className={inputClass}
                    placeholder="JOHN DOE"
                  />
                </div>
              </>
            )}

            {itemType === 'secureNote' && (
              <div>
                <label className={labelClass}>Content</label>
                <textarea
                  value={form.secureNote}
                  onChange={e => setField('secureNote', e.target.value)}
                  rows={10}
                  className={`${inputClass} resize-none font-mono`}
                  placeholder="Your secure note content..."
                />
              </div>
            )}

            {itemType === 'address' && (
              <>
                <div>
                  <label className={labelClass}>Full Name</label>
                  <input
                    type="text"
                    value={form.fullName}
                    onChange={e => setField('fullName', e.target.value)}
                    className={inputClass}
                    placeholder="Ada Lovelace"
                  />
                </div>
                <div>
                  <label className={labelClass}>Street</label>
                  <input
                    type="text"
                    value={form.street}
                    onChange={e => setField('street', e.target.value)}
                    className={inputClass}
                    placeholder="12 Analytical Way"
                  />
                </div>
                <div>
                  <label className={labelClass}>Street line 2</label>
                  <input
                    type="text"
                    value={form.streetLine2}
                    onChange={e => setField('streetLine2', e.target.value)}
                    className={inputClass}
                    placeholder="Apartment, suite… (optional)"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className={labelClass}>City</label>
                    <input type="text" value={form.city} onChange={e => setField('city', e.target.value)} className={inputClass} />
                  </div>
                  <div>
                    <label className={labelClass}>State / Region</label>
                    <input type="text" value={form.state} onChange={e => setField('state', e.target.value)} className={inputClass} />
                  </div>
                  <div>
                    <label className={labelClass}>Postal Code</label>
                    <input type="text" value={form.postalCode} onChange={e => setField('postalCode', e.target.value)} className={inputClass} />
                  </div>
                  <div>
                    <label className={labelClass}>Country</label>
                    <input type="text" value={form.country} onChange={e => setField('country', e.target.value)} className={inputClass} />
                  </div>
                </div>
                <div>
                  <label className={labelClass}>Phone</label>
                  <input type="tel" value={form.phone} onChange={e => setField('phone', e.target.value)} className={inputClass} placeholder="+1 555 000 1234" />
                </div>
              </>
            )}

            {itemType === 'bankAccount' && (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className={labelClass}>Bank Name</label>
                    <input type="text" value={form.bankName} onChange={e => setField('bankName', e.target.value)} className={inputClass} placeholder="First Example Bank" />
                  </div>
                  <div>
                    <label className={labelClass}>Account Type</label>
                    <input type="text" value={form.accountKind} onChange={e => setField('accountKind', e.target.value)} className={inputClass} placeholder="checking" />
                  </div>
                </div>
                <div>
                  <label className={labelClass}>Holder</label>
                  <input type="text" value={form.holder} onChange={e => setField('holder', e.target.value)} className={inputClass} placeholder="Ada Lovelace" />
                </div>
                <div>
                  <label className={labelClass}>Account Number</label>
                  <input
                    type="password"
                    value={form.accountNumber}
                    onChange={e => setField('accountNumber', e.target.value)}
                    spellCheck={false}
                    autoComplete="off"
                    className={`${inputClass} font-mono`}
                    placeholder="••••••••"
                  />
                </div>
                <div>
                  <label className={labelClass}>Routing Number</label>
                  <input type="text" value={form.routingNumber} onChange={e => setField('routingNumber', e.target.value)} className={`${inputClass} font-mono`} placeholder="012345678" />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className={labelClass}>IBAN</label>
                    <input type="text" value={form.iban} onChange={e => setField('iban', e.target.value)} className={`${inputClass} font-mono`} placeholder="GB29 …" />
                  </div>
                  <div>
                    <label className={labelClass}>SWIFT / BIC</label>
                    <input type="text" value={form.swift} onChange={e => setField('swift', e.target.value)} className={`${inputClass} font-mono`} placeholder="EXAMGB22" />
                  </div>
                </div>
              </>
            )}

            {itemType === 'apiKey' && (
              <>
                <div>
                  <label className={labelClass}>Service URL</label>
                  <input type="url" value={form.url} onChange={e => setField('url', e.target.value)} className={inputClass} placeholder="https://api.example" />
                </div>
                <div>
                  <label className={labelClass}>Username / Account</label>
                  <input type="text" value={form.username} onChange={e => setField('username', e.target.value)} className={inputClass} />
                </div>
                <div>
                  <label className={labelClass}>API Key</label>
                  <input
                    type="password"
                    value={form.apiKey}
                    onChange={e => setField('apiKey', e.target.value)}
                    spellCheck={false}
                    autoComplete="off"
                    className={`${inputClass} font-mono`}
                    placeholder="sk-…"
                  />
                </div>
                <div>
                  <label className={labelClass}>Expires</label>
                  <input type="text" value={form.expires} onChange={e => setField('expires', e.target.value)} className={inputClass} placeholder="2027-01 (free-form, optional)" />
                </div>
              </>
            )}

            {itemType === 'sshKey' && (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className={labelClass}>Key Type</label>
                    <input type="text" value={form.sshKind} onChange={e => setField('sshKind', e.target.value)} className={inputClass} placeholder="ed25519" />
                  </div>
                  <div>
                    <label className={labelClass}>Comment</label>
                    <input type="text" value={form.comment} onChange={e => setField('comment', e.target.value)} className={inputClass} placeholder="ada@laptop" />
                  </div>
                </div>
                <div>
                  <label className={labelClass}>Public Key</label>
                  <textarea
                    value={form.publicKey}
                    onChange={e => setField('publicKey', e.target.value)}
                    rows={3}
                    className={`${inputClass} resize-none font-mono`}
                    placeholder="ssh-ed25519 AAAA…"
                  />
                </div>
                <div>
                  <label className={labelClass}>Private Key</label>
                  <textarea
                    value={form.privateKey}
                    onChange={e => setField('privateKey', e.target.value)}
                    rows={5}
                    className={`${inputClass} resize-none font-mono`}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  />
                </div>
                <div>
                  <label className={labelClass}>Passphrase</label>
                  <input
                    type="password"
                    value={form.passphrase}
                    onChange={e => setField('passphrase', e.target.value)}
                    className={`${inputClass} font-mono`}
                    placeholder="Optional"
                  />
                </div>
              </>
            )}

            {/* §1.3: user-defined extra fields, on every item type. */}
            <div className="pt-2 border-t border-outline-variant/40">
              <div className="flex items-center justify-between mb-3">
                <div className="text-xs font-label uppercase tracking-widest text-outline">Custom fields</div>
                <button
                  type="button"
                  onClick={addCustomField}
                  className="flex items-center gap-1 px-3 py-1 rounded-lg bg-primary/10 text-primary text-xs font-label hover:bg-primary/20 transition-colors"
                >
                  <span className="material-symbols-outlined text-sm">add</span>
                  Add field
                </button>
              </div>
              {customFields.map((field, index) => (
                <div key={index} className="flex gap-2 items-start mb-2">
                  <input
                    type="text"
                    value={field.label}
                    onChange={e => updateCustomField(index, { label: e.target.value })}
                    className="w-1/3 px-3 py-2 bg-surface-container-highest rounded-lg text-on-surface text-sm outline-none focus:ring-2 focus:ring-primary/40"
                    placeholder="Label"
                  />
                  <input
                    type={field.field_type === 'hidden' ? 'password' : 'text'}
                    value={field.value}
                    onChange={e => updateCustomField(index, { value: e.target.value })}
                    className={`flex-1 px-3 py-2 bg-surface-container-highest rounded-lg text-on-surface text-sm outline-none focus:ring-2 focus:ring-primary/40 ${field.field_type === 'hidden' ? 'font-mono' : ''}`}
                    placeholder={field.field_type === 'hidden' ? 'Hidden value' : 'Value'}
                  />
                  <select
                    value={field.field_type}
                    onChange={e => updateCustomField(index, { field_type: e.target.value as CustomField['field_type'] })}
                    className="px-2 py-2 bg-surface-container-highest rounded-lg text-on-surface-variant text-xs outline-none"
                    title="Hidden values are masked like passwords"
                  >
                    <option value="text">text</option>
                    <option value="hidden">hidden</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => removeCustomField(index)}
                    className="p-2 text-on-surface-variant hover:text-red-400 rounded-lg transition-colors"
                    title="Remove field"
                  >
                    <span className="material-symbols-outlined text-sm">close</span>
                  </button>
                </div>
              ))}
            </div>
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
