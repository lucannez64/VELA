import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem } from '../context/AppContext';

interface Props {
  items: VaultItem[];
  onRefresh: () => void;
  onAddItem: () => void;
}

interface VaultHealth {
  weak_passwords: number;
  reused_passwords: number;
  total_logins: number;
  health_score: number;
  status: string;
}

type FilterType = 'all' | 'login' | 'creditCard' | 'secureNote';
const faviconCache = new Map<string, string | null>();

export default function VaultBrowser({ items: propItems, onRefresh: _onRefresh, onAddItem }: Props) {
  const { setSelectedItem, showToast } = useApp();
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<FilterType>('all');
  const [filteredItems, setFilteredItems] = useState<VaultItem[]>([]);
  const [vaultHealth, setVaultHealth] = useState<VaultHealth | null>(null);

  useEffect(() => {
    let result = propItems;
    
    if (filter !== 'all') {
      result = result.filter(item => item.item_type === filter);
    }
    
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(item => 
        item.name.toLowerCase().includes(query) ||
        item.username?.toLowerCase().includes(query) ||
        item.url?.toLowerCase().includes(query)
      );
    }
    
    setFilteredItems(result);
  }, [propItems, filter, searchQuery]);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const health = await invoke<VaultHealth>('get_vault_health');
        setVaultHealth(health);
      } catch (e) {
        console.error('Failed to fetch vault health:', e);
      }
    };
    fetchHealth();
  }, [propItems]);

  const groupedItems = filteredItems.reduce((acc, item) => {
    const letter = (item.name.trim()[0] || '#').toUpperCase();
    if (!acc[letter]) acc[letter] = [];
    acc[letter].push(item);
    return acc;
  }, {} as Record<string, VaultItem[]>);

  const getIcon = (type: string) => {
    switch (type) {
      case 'login': return 'key';
      case 'creditCard': return 'credit_card';
      case 'secureNote': return 'note';
      default: return 'shield';
    }
  };

  const handleOpenUrl = (url: string) => {
    if (url) {
      window.open(url, '_blank');
    }
  };

  const handleCopy = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      showToast(`${label} copied`, 'success');
    } catch (e) {
      showToast('Failed to copy', 'error');
    }
  };

  const typeCounts = {
    all: propItems.length,
    login: propItems.filter(i => i.item_type === 'login').length,
    creditCard: propItems.filter(i => i.item_type === 'creditCard').length,
    secureNote: propItems.filter(i => i.item_type === 'secureNote').length,
  };

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-8">
        <div className="relative w-full max-w-xl">
          <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-outline-variant">search</span>
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-surface-container-lowest border-none rounded-xl py-4 pl-12 pr-6 text-on-surface placeholder:text-on-surface-variant/50 focus:ring-1 focus:ring-primary/40 focus:bg-surface-container-low transition-all font-body"
            placeholder="Search vault..."
            type="text"
          />
        </div>
        <button 
          onClick={onAddItem}
          className="flex items-center gap-2 bg-primary text-on-primary px-6 py-3 rounded-xl font-bold hover:bg-primary/90 transition-colors"
        >
          <span className="material-symbols-outlined">add</span>
          <span>Add Item</span>
        </button>
      </div>

      <div className="flex items-center gap-8 mb-8 overflow-x-auto pb-2">
        {(['all', 'login', 'creditCard', 'secureNote'] as FilterType[]).map(type => (
          <button
            key={type}
            onClick={() => setFilter(type)}
            className={`group flex items-center gap-2 pb-4 font-label font-medium text-sm border-b-2 transition-colors ${
              filter === type 
                ? 'text-primary border-primary' 
                : 'text-on-surface-variant hover:text-on-surface border-transparent'
            }`}
          >
            {type === 'all' ? 'All' : type === 'creditCard' ? 'Cards' : type === 'secureNote' ? 'Secure Notes' : 'Logins'}
            <span className={`px-2 py-0.5 rounded text-[10px] ${filter === type ? 'bg-primary/10' : 'bg-surface-container-highest'}`}>
              {typeCounts[type]}
            </span>
          </button>
        ))}
      </div>

      <div className="space-y-8">
        {Object.entries(groupedItems).sort().map(([letter, items]) => (
          <section key={letter}>
            <div className="flex items-center gap-4 mb-4">
              <span className="font-headline text-2xl font-bold text-outline-variant/30">{letter}</span>
              <div className="h-px flex-1 bg-outline-variant/10"></div>
            </div>
            <div className="grid grid-cols-1 gap-3">
              {items.map(item => (
                <div
                  key={item.id}
                  onClick={() => setSelectedItem(item)}
                  className="group flex items-center justify-between gap-4 p-4 bg-surface-container-low rounded-xl hover:bg-surface-container transition-all cursor-pointer"
                >
                  <div className="flex items-center gap-4 min-w-0">
                    <ItemIcon item={item} icon={getIcon(item.item_type)} />
                    <div className="min-w-0">
                      <h3 className="font-body font-bold text-on-surface truncate">{item.name}</h3>
                      <p className="font-mono text-xs text-on-surface-variant/60 truncate">
                        {item.username || item.url || (item.item_type === 'creditCard' ? `Ending in •••• ${item.card_number?.slice(-4)}` : '••••••••')}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6 shrink-0">
                    {item.shared && (
                      item.share_recipient
                        ? <div className="px-2 py-0.5 rounded bg-primary/10 text-[10px] text-primary font-label font-bold uppercase tracking-widest flex items-center gap-1">
                            <span className="material-symbols-outlined text-[10px]" style={{fontSize:'10px'}}>share</span>Shared
                          </div>
                        : <div className="px-2 py-0.5 rounded bg-on-secondary-container/20 text-[10px] text-secondary font-label font-bold uppercase tracking-widest flex items-center gap-1">
                            <span className="material-symbols-outlined text-[10px]" style={{fontSize:'10px'}}>download</span>Received
                          </div>
                    )}
                    <span className="hidden md:block font-mono text-xs text-outline-variant tracking-tighter">
                      {item.item_type === 'creditCard' ? `EXP: ${item.card_exp}` : '••••••••••••'}
                    </span>
                    <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button 
                        onClick={(e) => { e.stopPropagation(); handleCopy(item.password || item.username || '', 'Item'); }}
                        className="p-2 hover:text-primary transition-colors"
                      >
                        <span className="material-symbols-outlined text-sm">content_copy</span>
                      </button>
                      {item.url && (
                        <button 
                          onClick={(e) => { e.stopPropagation(); handleOpenUrl(item.url || ''); }}
                          className="p-2 hover:text-primary transition-colors"
                        >
                          <span className="material-symbols-outlined text-sm">open_in_new</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        ))}
      </div>

      {filteredItems.length === 0 && (
        <div className="text-center py-16">
          <span className="material-symbols-outlined text-6xl text-outline-variant mb-4 block">search_off</span>
          <p className="text-on-surface-variant mb-4">No items found</p>
          <button 
            onClick={onAddItem}
            className="px-6 py-3 bg-primary/10 text-primary rounded-xl font-medium hover:bg-primary/20 transition-colors"
          >
            Add your first item
          </button>
        </div>
      )}

      <div className="mt-12 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel p-8 rounded-2xl border border-outline-variant/10">
          <div className="flex justify-between items-start mb-6">
            <div>
              <h4 className="font-headline text-xl font-bold text-on-surface mb-1">Vault Health</h4>
              <p className="text-sm text-on-surface-variant">Continuous audit of your security status</p>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-bold font-label ${
              vaultHealth?.status === 'OPTIMAL' ? 'bg-primary/20 text-primary' :
              vaultHealth?.status === 'GOOD' ? 'bg-green-500/20 text-green-400' :
              vaultHealth?.status === 'FAIR' ? 'bg-amber-500/20 text-amber-400' :
              'bg-red-500/20 text-red-400'
            }`}>
              {vaultHealth?.status || 'LOADING...'}
            </span>
          </div>
          <div className="space-y-6">
            <div>
              <div className="flex justify-between text-xs mb-2">
                <span className="font-label text-outline-variant">SECURITY SCORE</span>
                <span className="font-mono text-primary">{Math.round(vaultHealth?.health_score || 0)}%</span>
              </div>
              <div className="h-2 bg-surface-container-highest rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full ${
                    (vaultHealth?.health_score || 0) >= 90 ? 'bg-primary shadow-[0_0_12px_#73db9a]' :
                    (vaultHealth?.health_score || 0) >= 70 ? 'bg-green-400' :
                    (vaultHealth?.health_score || 0) >= 50 ? 'bg-amber-400' :
                    'bg-red-400'
                  }`}
                  style={{ width: `${vaultHealth?.health_score || 0}%` }}
                ></div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-surface-container rounded-xl">
                <p className="text-[10px] font-label text-outline-variant uppercase tracking-widest mb-1">Weak Passwords</p>
                <p className={`text-2xl font-headline font-bold ${(vaultHealth?.weak_passwords || 0) > 0 ? 'text-amber-400' : 'text-on-surface'}`}>
                  {vaultHealth?.weak_passwords || 0}
                </p>
              </div>
              <div className="p-4 bg-surface-container rounded-xl">
                <p className="text-[10px] font-label text-outline-variant uppercase tracking-widest mb-1">Reused Items</p>
                <p className={`text-2xl font-headline font-bold ${(vaultHealth?.reused_passwords || 0) > 0 ? 'text-tertiary' : 'text-on-surface'}`}>
                  {vaultHealth?.reused_passwords || 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-br from-surface-container-highest to-surface-container p-8 rounded-2xl border border-outline-variant/10 flex flex-col justify-between">
          <div>
            <span className="material-symbols-outlined text-primary mb-4 text-3xl">security</span>
            <h4 className="font-headline text-lg font-bold text-on-surface mb-2">Dark Web Monitor</h4>
            <p className="text-sm text-on-surface-variant leading-relaxed">We scan for leaked credentials in real-time across the obsidian network.</p>
          </div>
          <button className="mt-8 text-xs font-bold font-label text-primary uppercase tracking-[0.2em] flex items-center gap-2 group">
            RUN FULL SCAN
            <span className="material-symbols-outlined text-sm group-hover:translate-x-1 transition-transform">arrow_forward</span>
          </button>
        </div>
      </div>
    </div>
  );
}

function ItemIcon({ item, icon }: { item: VaultItem; icon: string }) {
  const [failed, setFailed] = useState(false);
  const [favicon, setFavicon] = useState<string | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;

    if (item.item_type !== 'login' || !item.url) {
      setFavicon(undefined);
      setFailed(false);
      return;
    }

    const cacheKey = item.url;
    const cached = faviconCache.get(cacheKey);
    if (cached !== undefined) {
      setFavicon(cached ?? undefined);
      setFailed(cached === null);
      return;
    }

    setFavicon(undefined);
    setFailed(false);

    invoke<string | null>('fetch_favicon', { url: item.url })
      .then((result) => {
        if (cancelled) return;
        faviconCache.set(cacheKey, result);
        setFavicon(result ?? undefined);
        setFailed(!result);
      })
      .catch(() => {
        if (cancelled) return;
        faviconCache.set(cacheKey, null);
        setFailed(true);
      });

    return () => {
      cancelled = true;
    };
  }, [item.item_type, item.url]);

  if (favicon && !failed) {
    return (
      <img
        src={favicon}
        alt=""
        className="w-12 h-12 shrink-0 rounded-xl object-cover bg-surface-bright"
        onError={() => setFailed(true)}
      />
    );
  }

  return (
    <div className="w-12 h-12 shrink-0 rounded-xl bg-surface-bright flex items-center justify-center">
      <span className="material-symbols-outlined text-primary">{icon}</span>
    </div>
  );
}
