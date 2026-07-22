import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { VaultItem, Settings } from '../context/AppContext';
import { applyTheme } from '../themes';

// Standalone UI for the dedicated `quick-search` window (see
// commands/window.rs). Runs in its own webview without AppProvider — the
// main window owns all app state; this popup only searches via the backend
// and hands the chosen item back through `quick_search_open_item`.
export default function QuickSearchWindow() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<VaultItem[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [locked, setLocked] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  // Guards against an older, slower query's response overwriting a newer,
  // faster one's results — requests can resolve out of order.
  const latestRequestId = useRef(0);

  const close = useCallback(() => {
    setQuery('');
    setResults([]);
    setSelectedIndex(0);
    invoke('hide_quick_search').catch(() => {});
  }, []);

  const handleSelect = useCallback((item: VaultItem | null) => {
    setQuery('');
    setResults([]);
    setSelectedIndex(0);
    invoke('quick_search_open_item', { item }).catch(() => {});
  }, []);

  // The popup follows the configured theme like the main window does.
  useEffect(() => {
    let setting: string | undefined;
    invoke<Settings>('get_settings')
      .then(s => {
        setting = s.theme;
        applyTheme(s.theme);
      })
      .catch(() => applyTheme('system'));
    const media = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => {
      if (!setting || setting === 'system') applyTheme('system');
    };
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, []);

  // The window is hidden, not destroyed, when dismissed — reset and refocus
  // whenever the shortcut shows it again.
  useEffect(() => {
    const unlisten = listen('quick-search-shown', () => {
      setQuery('');
      setResults([]);
      setSelectedIndex(0);
      setLocked(false);
      inputRef.current?.focus();
    });
    return () => {
      unlisten.then(fn => fn());
    };
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter') {
        if (locked) {
          handleSelect(null);
        } else if (results[selectedIndex]) {
          handleSelect(results[selectedIndex]);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [results, selectedIndex, locked, handleSelect, close]);

  useEffect(() => {
    latestRequestId.current += 1;
    const requestId = latestRequestId.current;

    if (query.length === 0) {
      setResults([]);
      return;
    }

    (async () => {
      try {
        const items = await invoke<VaultItem[]>('search_items', { query });
        if (requestId !== latestRequestId.current) return; // superseded
        setLocked(false);
        setResults(items.slice(0, 8));
        setSelectedIndex(0);
      } catch (e) {
        if (requestId !== latestRequestId.current) return;
        setResults([]);
        setLocked(true);
      }
    })();
  }, [query]);

  const getIcon = (type: string) => {
    switch (type) {
      case 'login': return 'key';
      case 'creditCard': return 'credit_card';
      case 'secureNote': return 'note';
      default: return 'shield';
    }
  };

  return (
    <div className="h-screen flex flex-col bg-surface-container border border-outline-variant/20 overflow-hidden">
      <div className="flex items-center gap-4 px-6 py-4 border-b border-outline-variant/10">
        <span className="material-symbols-outlined text-primary text-2xl">search</span>
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Search vault..."
          className="flex-1 bg-transparent text-lg text-on-surface placeholder:text-on-surface-variant/50 outline-none"
          autoFocus
        />
        <span className="text-xs text-outline font-label">ESC to close</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {locked && (
          <button
            onClick={() => handleSelect(null)}
            className="w-full px-6 py-8 text-center text-outline hover:bg-surface-container-high transition-colors"
          >
            <span className="material-symbols-outlined text-4xl mb-2 block">lock</span>
            <p className="text-sm">Vault is locked — press Enter to open VELA</p>
          </button>
        )}

        {!locked && results.length === 0 && query.length > 0 && (
          <div className="px-6 py-8 text-center text-outline">
            <span className="material-symbols-outlined text-4xl mb-2 block">search_off</span>
            <p className="text-sm">No results found</p>
          </div>
        )}

        {!locked && results.map((item, index) => (
          <button
            key={item.id}
            onClick={() => handleSelect(item)}
            className={`
              w-full px-6 py-3 flex items-center gap-4 text-left transition-colors
              ${index === selectedIndex ? 'bg-primary/10 text-primary' : 'hover:bg-surface-container'}
            `}
          >
            <span className="material-symbols-outlined text-xl">{getIcon(item.item_type)}</span>
            <div className="flex-1">
              <div className="font-body font-medium text-on-surface">{item.name}</div>
              {item.url && (
                <div className="text-xs text-on-surface-variant">{item.url}</div>
              )}
            </div>
            {index === selectedIndex && (
              <span className="text-xs text-primary font-label">Enter to select</span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
