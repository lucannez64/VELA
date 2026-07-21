import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem } from '../context/AppContext';

interface QuickSearchOverlayProps {
  onClose: () => void;
}

export default function QuickSearchOverlay({ onClose }: QuickSearchOverlayProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<VaultItem[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const { setSelectedItem, setCurrentView } = useApp();
  // Guards against an older, slower query's response overwriting a newer,
  // faster one's results — requests can resolve out of order.
  const latestRequestId = useRef(0);

  const handleSelect = useCallback((item: VaultItem) => {
    onClose();
    setSelectedItem(item);
    setCurrentView('vault');
  }, [onClose, setSelectedItem, setCurrentView]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter' && results[selectedIndex]) {
        handleSelect(results[selectedIndex]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [results, selectedIndex, handleSelect, onClose]);

  useEffect(() => {
    latestRequestId.current += 1;
    const requestId = latestRequestId.current;

    if (query.length === 0) {
      setResults([]);
      return;
    }

    searchItems(query, requestId);
  }, [query]);

  const searchItems = async (searchQuery: string, requestId: number) => {
    try {
      const items = await invoke<VaultItem[]>('search_items', { query: searchQuery });
      if (requestId !== latestRequestId.current) return; // a newer query already superseded this one
      setResults(items.slice(0, 8));
      setSelectedIndex(0);
    } catch (e) {
      console.error('Search failed:', e);
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'login': return 'key';
      case 'creditCard': return 'credit_card';
      case 'secureNote': return 'note';
      default: return 'shield';
    }
  };

  return (
    <div 
      className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center pt-[15vh]"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl mx-4 bg-surface-container rounded-2xl shadow-2xl border border-outline-variant/20 overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-4 px-6 py-4 border-b border-outline-variant/10">
          <span className="material-symbols-outlined text-primary text-2xl">search</span>
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search vault..."
            className="flex-1 bg-transparent text-lg text-on-surface placeholder:text-on-surface-variant/50 outline-none"
            autoFocus
          />
          <span className="text-xs text-outline font-label">ESC to close</span>
        </div>

        <div className="max-h-80 overflow-y-auto">
          {results.length === 0 && query.length > 0 && (
            <div className="px-6 py-8 text-center text-outline">
              <span className="material-symbols-outlined text-4xl mb-2 block">search_off</span>
              <p className="text-sm">No results found</p>
            </div>
          )}
          
          {results.map((item, index) => (
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
    </div>
  );
}
