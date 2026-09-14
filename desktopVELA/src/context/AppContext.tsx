import { createContext, useContext, useState, useCallback, useMemo, useRef, ReactNode, Dispatch, SetStateAction } from 'react';
import type { ThemeSetting } from '../themes';

export interface SessionStatus {
  active: boolean;
  session_time_remaining_secs: number;
  device_name: string | null;
  lock_state: 'locked' | 'unlocked' | 'syncing' | 'error' | 'conflict';
}

export interface VaultItem {
  id: string;
  name: string;
  item_type:
    | 'login'
    | 'creditCard'
    | 'secureNote'
    | 'identity'
    | 'file'
    | 'breachMonitor'
    | 'passkey'
    | 'address'
    | 'bankAccount'
    | 'apiKey'
    | 'sshKey';
  username?: string;
  password?: string;
  url?: string;
  totp?: string;
  notes?: string;
  // Passkey metadata. The private key never leaves the vault — the backend
  // deliberately does not expose it over IPC (VaultItem::Passkey has no
  // Serialize exposure of the key), so none of these are secrets.
  rp_id?: string;
  rp_name?: string;
  credential_id?: string;
  user_handle?: string;
  sign_count?: number;
  /// Does this site make you re-prove the old password before changing it?
  /// Decides what an in-core login session is worth if it leaks.
  credential_change_needs_reauth?: boolean;
  /// May VELA answer a second-factor prompt with this item's TOTP code when the
  /// site asked for something stronger? Weakens the site's own choice, so it is
  /// off unless the owner turns it on.
  allow_second_factor_downgrade?: boolean;
  card_number?: string;
  card_exp?: string;
  card_cvv?: string;
  card_pin?: string;
  cardholder_name?: string;
  secure_note_content?: string;
  email?: string;
  checked_at?: string;
  breach_count?: number;
  breaches?: BreachEntry[];
  // §1.3: user-defined extra fields, attachable to every item type. `hidden`
  // values are masked like passwords.
  custom_fields?: CustomField[];
  // §1.3: previous password values, newest first (logins only).
  password_history?: PasswordHistoryEntry[];
  // §1.3 new item types — direct wire spellings.
  // address
  full_name?: string;
  street?: string;
  street_line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
  phone?: string;
  // bankAccount
  bank_name?: string;
  account_kind?: string;
  holder?: string;
  account_number?: string;
  routing_number?: string;
  iban?: string;
  swift?: string;
  // apiKey
  api_key?: string;
  expires?: string;
  // sshKey
  kind?: string;
  public_key?: string;
  private_key?: string;
  passphrase?: string;
  comment?: string;
  created_at: string;
  updated_at: string;
  last_modified_device?: string;
  favorite: boolean;
  /** §1.1 organization: canonical tags and one optional folder name. */
  tags: string[];
  folder?: string;
  shared: boolean;
  share_recipient?: string;
}

export interface DeletedItem {
  item: VaultItem;
  deleted_at: string;
  deleted_by?: string;
}

export interface CustomField {
  label: string;
  value: string;
  field_type: 'text' | 'hidden';
}

export interface PasswordHistoryEntry {
  password: string;
  changed_at: string;
}

export interface BreachEntry {
  name: string;
  title: string;
  domain: string;
  breach_date: string;
  description: string;
  data_classes: string[];
  is_verified: boolean;
  is_fabricated: boolean;
  is_sensitive: boolean;
  is_retired: boolean;
  is_spam_list: boolean;
}

export function isLoginItem(item: VaultItem): item is VaultItem & { item_type: 'login' } {
  return item.item_type === 'login';
}

export function isCreditCardItem(item: VaultItem): item is VaultItem & { item_type: 'creditCard' } {
  return item.item_type === 'creditCard';
}

export function isSecureNoteItem(item: VaultItem): item is VaultItem & { item_type: 'secureNote' } {
  return item.item_type === 'secureNote';
}

export function isBreachMonitorItem(item: VaultItem): item is VaultItem & { item_type: 'breachMonitor' } {
  return item.item_type === 'breachMonitor';
}

export function isPasskeyItem(item: VaultItem): item is VaultItem & { item_type: 'passkey' } {
  return item.item_type === 'passkey';
}

export function toBackendItem(item: VaultItem): object {
  const base = {
    id: item.id,
    name: item.name,
    created_at: item.created_at,
    updated_at: item.updated_at,
    last_modified_device: item.last_modified_device || null,
    favorite: item.favorite,
    tags: item.tags || [],
    folder: item.folder || null,
    // §1.3: sent unconditionally, like `tags` — `update_item` replaces the
    // whole item, so omitting the key would wipe fields set on another
    // device. An empty list means "none".
    customFields: (item.custom_fields || []).map(f => ({
      label: f.label,
      value: f.value || '',
      field_type: f.field_type || 'text',
    })),
    shared: item.shared,
    share_recipient: item.share_recipient || null,
  };

  switch (item.item_type) {
    case 'login':
      return {
        ...base,
        item_type: 'login',
        url: item.url || '',
        username: item.username || '',
        password: item.password || '',
        totp: item.totp || null,
        notes: item.notes || null,
        // Omitted, not `false`, when the user has never decided. The backend
        // treats an absent key as "unchanged" and an explicit `false` as
        // "turned off" — sending false here would silently clear a decision
        // made on another device. See VaultItem::preserving_app_ids.
        ...(item.credential_change_needs_reauth === undefined
          ? {}
          : { credential_change_needs_reauth: item.credential_change_needs_reauth }),
        ...(item.allow_second_factor_downgrade === undefined
          ? {}
          : { allow_second_factor_downgrade: item.allow_second_factor_downgrade }),
      };
    case 'creditCard':
      return {
        ...base,
        item_type: 'creditCard',
        number: item.card_number || '',
        exp: item.card_exp || '',
        cvv: item.card_cvv || '',
        pin: item.card_pin || null,
        cardholder_name: item.cardholder_name || null,
        notes: item.notes || null,
      };
    case 'secureNote':
      return {
        ...base,
        item_type: 'secureNote',
        title: item.name,
        content: item.secure_note_content || '',
        notes: item.notes || null,
      };
    case 'breachMonitor':
      return {
        ...base,
        item_type: 'breachMonitor',
        email: item.email || '',
        checked_at: item.checked_at || null,
        breach_count: item.breach_count || 0,
        breaches: item.breaches || [],
      };
    case 'passkey':
      // Read-only round-trip: the UI never holds the private key, and
      // `update_item` restores the stored credential server-side (well,
      // desktop-side) from the vault. Send what we have.
      return {
        ...base,
        item_type: 'passkey',
        rp_id: item.rp_id || '',
        rp_name: item.rp_name || '',
        credential_id: item.credential_id || '',
        user_handle: item.user_handle || '',
        user_name: item.username || '',
        user_display_name: item.username || '',
      };
    // ── §1.3 item model depth ─────────────────────────────────────────────
    case 'address':
      return {
        ...base,
        item_type: 'address',
        full_name: item.full_name || '',
        street: item.street || '',
        street_line2: item.street_line2 || '',
        city: item.city || '',
        state: item.state || '',
        postal_code: item.postal_code || '',
        country: item.country || '',
        phone: item.phone || '',
      };
    case 'bankAccount':
      return {
        ...base,
        item_type: 'bankAccount',
        bank_name: item.bank_name || '',
        account_kind: item.account_kind || '',
        holder: item.holder || '',
        account_number: item.account_number || '',
        routing_number: item.routing_number || '',
        iban: item.iban || '',
        swift: item.swift || '',
      };
    case 'apiKey':
      return {
        ...base,
        item_type: 'apiKey',
        url: item.url || '',
        username: item.username || '',
        api_key: item.api_key || '',
        expires: item.expires || null,
      };
    case 'sshKey':
      return {
        ...base,
        item_type: 'sshKey',
        kind: item.kind || '',
        public_key: item.public_key || '',
        private_key: item.private_key || '',
        passphrase: item.passphrase || '',
        comment: item.comment || '',
      };
    default:
      return { ...base, item_type: item.item_type };
  }
}

export function fromBackendItem(item: any): VaultItem {
  const base = {
    id: item.id || '',
    name: item.name || '',
    created_at: item.created_at || new Date().toISOString(),
    updated_at: item.updated_at || new Date().toISOString(),
    last_modified_device: item.last_modified_device,
    favorite: item.favorite || false,
    tags: item.tags || [],
    folder: item.folder || undefined,
    custom_fields: (item.customFields || []).map((f: any) => ({
      label: f.label || '',
      value: f.value || '',
      field_type: (f.field_type || 'text') as 'text' | 'hidden',
    })),
    password_history: item.password_history || undefined,
    shared: item.shared || false,
    share_recipient: item.share_recipient,
  };

  switch (item.item_type) {
    case 'login':
      return {
        ...base,
        item_type: 'login',
        url: item.url,
        username: item.username,
        password: item.password,
        totp: item.totp,
        notes: item.notes,
        credential_change_needs_reauth: item.credential_change_needs_reauth,
        allow_second_factor_downgrade: item.allow_second_factor_downgrade,
      };
    case 'creditCard':
      return {
        ...base,
        item_type: 'creditCard',
        card_number: item.number,
        card_exp: item.exp,
        card_cvv: item.cvv,
        card_pin: item.pin,
        cardholder_name: item.cardholder_name,
        notes: item.notes,
      };
    case 'secureNote':
      return {
        ...base,
        item_type: 'secureNote',
        secure_note_content: item.content,
        notes: item.notes,
      };
    case 'breachMonitor':
      return {
        ...base,
        item_type: 'breachMonitor',
        email: item.email,
        checked_at: item.checked_at,
        breach_count: item.breach_count || 0,
        breaches: item.breaches || [],
      };
    case 'passkey':
      return {
        ...base,
        item_type: 'passkey',
        rp_id: item.rp_id,
        rp_name: item.rp_name,
        credential_id: item.credential_id,
        user_handle: item.user_handle,
        // The username the passkey authenticates as — rendered by the same
        // field the logins use.
        username: item.user_name,
      };
    // ── §1.3 item model depth ─────────────────────────────────────────────
    case 'address':
      return {
        ...base,
        item_type: 'address',
        full_name: item.full_name,
        street: item.street,
        street_line2: item.street_line2,
        city: item.city,
        state: item.state,
        postal_code: item.postal_code,
        country: item.country,
        phone: item.phone,
      };
    case 'bankAccount':
      return {
        ...base,
        item_type: 'bankAccount',
        bank_name: item.bank_name,
        account_kind: item.account_kind,
        holder: item.holder,
        account_number: item.account_number,
        routing_number: item.routing_number,
        iban: item.iban,
        swift: item.swift,
      };
    case 'apiKey':
      return {
        ...base,
        item_type: 'apiKey',
        url: item.url,
        username: item.username,
        api_key: item.api_key,
        expires: item.expires || undefined,
      };
    case 'sshKey':
      return {
        ...base,
        item_type: 'sshKey',
        kind: item.kind,
        public_key: item.public_key,
        private_key: item.private_key,
        passphrase: item.passphrase,
        comment: item.comment,
      };
    default:
      return { ...base, item_type: item.item_type };
  }
}

export interface Settings {
  auto_lock_minutes: number;
  clipboard_clear_seconds: number;
  require_biometric_on_reveal: boolean;
  sync_on_startup: boolean;
  background_sync_minutes: number;
  theme: ThemeSetting;
  compact_list: boolean;
  user_id: string;
  server_url: string;
  quick_search_shortcut: string;
  extension_connected: boolean;
  extension_version?: string;
}

type View = 'vault' | 'devices' | 'sharing' | 'audit' | 'settings' | 'breachMonitor' | 'trash';
type SetupStep = 'welcome' | 'biometric' | 'recovery' | 'complete';

interface AppContextType {
  session: SessionStatus | null;
  setSession: Dispatch<SetStateAction<SessionStatus | null>>;
  isSetupComplete: boolean;
  setSetupComplete: (complete: boolean) => void;
  currentView: View;
  setCurrentView: (view: View) => void;
  selectedItem: VaultItem | null;
  setSelectedItem: (item: VaultItem | null) => void;
  quickSearchOpen: boolean;
  setQuickSearchOpen: (open: boolean) => void;
  toast: { message: string; type: 'success' | 'error' | 'info' } | null;
  showToast: (message: string, type: 'success' | 'error' | 'info') => void;
  items: VaultItem[];
  setItems: (items: VaultItem[]) => void;
  settings: Settings | null;
  setSettings: (settings: Settings | null) => void;
  clipboardTimer: ReturnType<typeof setTimeout> | null;
  setClipboardTimer: (timer: ReturnType<typeof setTimeout> | null) => void;
  pendingShareItemId: string | null;
  setPendingShareItemId: (id: string | null) => void;
}

const AppContext = createContext<AppContextType | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionStatus | null>(null);
  const [isSetupComplete, setSetupComplete] = useState(false);
  const [currentView, setCurrentView] = useState<View>('vault');
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [quickSearchOpen, setQuickSearchOpen] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [clipboardTimer, setClipboardTimer] = useState<NodeJS.Timeout | null>(null);
  const [pendingShareItemId, setPendingShareItemId] = useState<string | null>(null);
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((message: string, type: 'success' | 'error' | 'info') => {
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
    }
    setToast({ message, type });
    toastTimerRef.current = setTimeout(() => {
      setToast(null);
      toastTimerRef.current = null;
    }, 3000);
  }, []);

  const value: AppContextType = useMemo(() => ({
    session,
    setSession,
    isSetupComplete,
    setSetupComplete,
    currentView,
    setCurrentView,
    selectedItem,
    setSelectedItem,
    quickSearchOpen,
    setQuickSearchOpen,
    toast,
    showToast,
    items,
    setItems,
    settings,
    setSettings,
    clipboardTimer,
    setClipboardTimer,
    pendingShareItemId,
    setPendingShareItemId,
  }), [
    session,
    isSetupComplete,
    currentView,
    selectedItem,
    quickSearchOpen,
    toast,
    showToast,
    items,
    settings,
    clipboardTimer,
    pendingShareItemId,
  ]);

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within AppProvider');
  }
  return context;
}

export type { View, SetupStep };
