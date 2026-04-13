import { createContext, useContext, useState, useCallback, ReactNode, Dispatch, SetStateAction } from 'react';

export interface SessionStatus {
  active: boolean;
  session_time_remaining_secs: number;
  device_name: string | null;
  lock_state: 'locked' | 'unlocked' | 'syncing' | 'error' | 'conflict';
}

export interface VaultItem {
  id: string;
  name: string;
  item_type: 'login' | 'creditCard' | 'secureNote' | 'identity' | 'file' | 'breachMonitor';
  username?: string;
  password?: string;
  url?: string;
  totp?: string;
  notes?: string;
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
  created_at: string;
  updated_at: string;
  last_modified_device?: string;
  favorite: boolean;
  shared: boolean;
  share_recipient?: string;
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

export function toBackendItem(item: VaultItem): object {
  const base = {
    id: item.id,
    name: item.name,
    created_at: item.created_at,
    updated_at: item.updated_at,
    last_modified_device: item.last_modified_device || null,
    favorite: item.favorite,
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
  theme: 'system' | 'dark' | 'light';
  compact_list: boolean;
  user_id: string;
  extension_connected: boolean;
  extension_version?: string;
}

type View = 'vault' | 'devices' | 'sharing' | 'audit' | 'settings' | 'breachMonitor';
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

  const showToast = useCallback((message: string, type: 'success' | 'error' | 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  const value: AppContextType = {
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
  };

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
