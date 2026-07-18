import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp, VaultItem, toBackendItem } from '../context/AppContext';
import { useClipboard } from '../hooks/useClipboard';
import FaviconIcon from '../components/FaviconIcon';

interface Props {
  item: VaultItem;
  onEdit?: () => void;
}

export default function ItemDetail({ item, onEdit }: Props) {
  const { setSelectedItem, showToast, setCurrentView, setPendingShareItemId } = useApp();
  const { copyToClipboard } = useClipboard();
  const [showPassword, setShowPassword] = useState(false);
  const [showCardNumber, setShowCardNumber] = useState(false);
  const [showCVV, setShowCVV] = useState(false);
  const [showCardPin, setShowCardPin] = useState(false);
  const [totpTimeLeft, setTotpTimeLeft] = useState(30);
  const [totpCode, setTotpCode] = useState('--- ---');
  const [favorite, setFavorite] = useState(item.favorite);

  useEffect(() => {
    setFavorite(item.favorite);
  }, [item.favorite]);

  useEffect(() => {
    setShowPassword(false);
  }, [item.id]);

  useEffect(() => {
    const generateTOTP = async () => {
      if (!item.totp) return;
      try {
        const result = await invoke<{ code: string; remaining_secs: number }>('generate_totp', { secret: item.totp });
        setTotpCode(result.code.slice(0, 3) + ' ' + result.code.slice(3));
        setTotpTimeLeft(result.remaining_secs);
      } catch (e) {
        console.error('Failed to generate TOTP:', e);
      }
    };

    generateTOTP();
    const interval = setInterval(generateTOTP, 1000);
    return () => clearInterval(interval);
  }, [item.totp]);

  const handleDelete = async () => {
    if (confirm('Are you sure you want to delete this item?')) {
      try {
        await invoke('delete_item', { id: item.id });
        setSelectedItem(null);
        showToast('Item deleted', 'success');
      } catch (e) {
        showToast('Failed to delete', 'error');
      }
    }
  };

  const handleToggleFavorite = async () => {
    const newValue = !favorite;
    setFavorite(newValue);
    try {
      await invoke('update_item', { item: { ...toBackendItem({ ...item, favorite: newValue }), favorite: newValue } });
    } catch (e) {
      setFavorite(!newValue);
      showToast('Failed to update item', 'error');
    }
  };

  const handleShare = () => {
    setPendingShareItemId(item.id);
    setCurrentView('sharing');
  };

  const getIcon = () => {
    switch (item.item_type) {
      case 'login': return 'key';
      case 'creditCard': return 'credit_card';
      case 'secureNote': return 'note';
      default: return 'shield';
    }
  };

  const isReceivedShare = item.shared && !item.share_recipient;

  return (
    <div className="flex-1 bg-surface-container-lowest overflow-y-auto">
      <div className="max-w-5xl mx-auto py-6 sm:py-10 px-4 sm:px-6 lg:px-10">
        <div className="flex flex-col xl:flex-row xl:items-start xl:justify-between gap-6 mb-10">
          <div className="flex items-start gap-5 min-w-0">
            <button onClick={() => setSelectedItem(null)} className="mt-7 shrink-0 text-on-surface-variant hover:text-primary transition-colors">
              <span className="material-symbols-outlined">arrow_back</span>
            </button>
            <div className="relative">
              <FaviconIcon
                url={item.url}
                itemType={item.item_type}
                icon={getIcon()}
                className="w-20 h-20 rounded-2xl bg-surface-bright shadow-2xl"
                fallbackClassName="text-4xl text-primary"
              />
              <div className="absolute -bottom-2 -right-2 bg-secondary text-on-secondary px-2 py-0.5 rounded text-[10px] font-bold tracking-widest uppercase">SECURE</div>
            </div>
            <div className="min-w-0 pt-2">
              <h1 className="font-headline text-3xl lg:text-4xl font-bold tracking-tight mb-1 break-words leading-tight">{item.name}</h1>
              <div className="flex flex-wrap items-center gap-2">
                <span className="w-2 h-2 shrink-0 rounded-full bg-primary"></span>
                <p className="text-on-surface-variant font-label text-xs tracking-wider uppercase">Zero-Knowledge {item.item_type}</p>
                {isReceivedShare && (
                  <span className="ml-2 px-2 py-0.5 rounded bg-on-secondary-container/20 text-[10px] text-secondary font-label font-bold uppercase tracking-widest">Shared with you · Read-only</span>
                )}
              </div>
            </div>
          </div>
          <div className="flex flex-wrap gap-3 shrink-0 xl:justify-end">
            <button onClick={handleToggleFavorite} className={`w-10 h-10 rounded-full flex items-center justify-center bg-surface-container-highest hover:bg-surface-bright transition-colors ${favorite ? 'text-amber-400' : ''}`}>
              <span className="material-symbols-outlined text-xl text-amber-400" style={favorite ? { fontVariationSettings: "'FILL' 1" } : undefined}>star</span>
            </button>
            {!isReceivedShare && (
              <button
                onClick={onEdit}
                className="w-10 h-10 rounded-full flex items-center justify-center bg-surface-container-highest hover:bg-surface-bright transition-colors">
                <span className="material-symbols-outlined text-xl">edit</span>
              </button>
            )}
            {!isReceivedShare && (
              <button
                onClick={handleShare}
                className="px-5 h-10 rounded-full flex items-center gap-2 bg-primary text-on-primary font-bold text-sm glow-button transition-all"
              >
                <span className="material-symbols-outlined text-sm">share</span>
                Share Access
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {item.username && (
            <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5 min-w-0">
              <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Username</label>
              <div className="flex items-center justify-between gap-3 min-w-0">
                <span className="text-on-surface text-lg font-medium min-w-0 break-all">{item.username}</span>
                <button 
                  onClick={() => copyToClipboard(item.username!, 'Username')}
                  className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                >
                  <span className="material-symbols-outlined text-xl">content_copy</span>
                </button>
              </div>
            </div>
          )}

          {item.password && (
            <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5 min-w-0">
              <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Password</label>
              <div className="flex items-center justify-between gap-3 min-w-0">
                <span className={`text-on-surface text-xl lg:text-2xl tracking-[0.2em] font-mono leading-none pt-1 min-w-0 break-all ${!showPassword ? '' : 'text-primary'}`}>
                  {showPassword ? item.password : '••••••••••••'}
                </span>
                <div className="flex gap-1 shrink-0">
                  <button 
                    onClick={() => setShowPassword(!showPassword)}
                    className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-on-surface-variant"
                  >
                    <span className="material-symbols-outlined text-xl">{showPassword ? 'visibility_off' : 'visibility'}</span>
                  </button>
                  <button 
                    onClick={() => item.password && copyToClipboard(item.password, 'Password')}
                    className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                  >
                    <span className="material-symbols-outlined text-xl">content_copy</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {item.totp && (
            <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5 col-span-1 md:col-span-2">
              <div className="flex items-center justify-between mb-4">
                <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline">
                  TOTP (2FA) <span className="ml-2 text-primary">ACTIVE</span>
                </label>
                <span className="text-[10px] text-outline font-mono">EXPIRES IN {totpTimeLeft}S</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-baseline gap-4">
                  <span className="text-on-surface text-3xl sm:text-4xl font-mono tracking-widest font-light break-all">{totpCode}</span>
                </div>
                <button 
                  onClick={() => copyToClipboard(totpCode.replace(' ', ''), 'Code')}
                  className="px-4 py-2 bg-surface-container-highest rounded-lg flex items-center gap-2 hover:bg-surface-bright transition-colors text-sm font-medium"
                >
                  <span className="material-symbols-outlined text-sm">content_copy</span>
                  Copy Code
                </button>
              </div>
              <div className="mt-6 h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
                <div 
                  className="h-full bg-primary rounded-full transition-all duration-1000" 
                  style={{ width: `${(totpTimeLeft / 30) * 100}%` }}
                />
              </div>
            </div>
          )}

          {item.url && (
            <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5 min-w-0">
              <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Website</label>
              <div className="flex items-center justify-between gap-3 min-w-0">
                <a 
                  href={item.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-on-surface hover:text-primary transition-colors text-sm flex items-center gap-2 underline decoration-outline-variant underline-offset-4 min-w-0 break-all"
                >
                  {item.url}
                  <span className="material-symbols-outlined text-xs shrink-0">open_in_new</span>
                </a>
                <button 
                  onClick={() => copyToClipboard(item.url!, 'URL')}
                  className="p-2 shrink-0 hover:bg-surface-container-highest rounded-lg transition-colors text-outline"
                >
                  <span className="material-symbols-outlined text-xl">content_copy</span>
                </button>
              </div>
            </div>
          )}

          {item.card_number && (
            <>
              {item.cardholder_name && (
                <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
                  <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Cardholder Name</label>
                  <div className="flex items-center justify-between">
                    <span className="text-on-surface text-lg font-medium">{item.cardholder_name}</span>
                    <button 
                      onClick={() => copyToClipboard(item.cardholder_name!, 'Cardholder name')}
                      className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                    >
                      <span className="material-symbols-outlined text-xl">content_copy</span>
                    </button>
                  </div>
                </div>
              )}

              <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
                <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Card Number</label>
                <div className="flex items-center justify-between">
                  <span className="text-on-surface text-xl font-mono tracking-wider">
                    {showCardNumber ? item.card_number : `•••• •••• •••• ${item.card_number?.slice(-4)}`}
                  </span>
                  <div className="flex gap-1">
                    <button 
                      onClick={() => setShowCardNumber(!showCardNumber)}
                      className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-on-surface-variant"
                    >
                      <span className="material-symbols-outlined text-xl">{showCardNumber ? 'visibility_off' : 'visibility'}</span>
                    </button>
                    <button 
                      onClick={() => copyToClipboard(item.card_number!, 'Card number')}
                      className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                    >
                      <span className="material-symbols-outlined text-xl">content_copy</span>
                    </button>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
                  <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Expiry</label>
                  <div className="flex items-center justify-between">
                    <span className="text-on-surface font-mono">{item.card_exp || '—'}</span>
                    {item.card_exp && (
                      <button 
                        onClick={() => copyToClipboard(item.card_exp!, 'Expiry')}
                        className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                      >
                        <span className="material-symbols-outlined text-xl">content_copy</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
                  <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">CVV</label>
                  <div className="flex items-center justify-between">
                    <span className="text-on-surface font-mono">{showCVV ? item.card_cvv : '•••'}</span>
                    <div className="flex gap-1">
                      <button 
                        onClick={() => setShowCVV(!showCVV)}
                        className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-on-surface-variant"
                      >
                        <span className="material-symbols-outlined text-xl">{showCVV ? 'visibility_off' : 'visibility'}</span>
                      </button>
                      {item.card_cvv && (
                        <button 
                          onClick={() => copyToClipboard(item.card_cvv!, 'CVV')}
                          className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                        >
                          <span className="material-symbols-outlined text-xl">content_copy</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {item.card_pin && (
                <div className="p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
                  <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">PIN</label>
                  <div className="flex items-center justify-between">
                    <span className="text-on-surface font-mono">{showCardPin ? item.card_pin : '••••'}</span>
                    <div className="flex gap-1">
                      <button 
                        onClick={() => setShowCardPin(!showCardPin)}
                        className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-on-surface-variant"
                      >
                        <span className="material-symbols-outlined text-xl">{showCardPin ? 'visibility_off' : 'visibility'}</span>
                      </button>
                      <button 
                        onClick={() => copyToClipboard(item.card_pin!, 'PIN')}
                        className="p-2 hover:bg-surface-container-highest rounded-lg transition-colors text-primary"
                      >
                        <span className="material-symbols-outlined text-xl">content_copy</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {item.secure_note_content && (
          <div className="mt-6 p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
            <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Secure Note</label>
            <p className="text-on-surface whitespace-pre-wrap font-mono">{item.secure_note_content}</p>
          </div>
        )}

        {item.notes && (
          <div className="mt-6 p-6 rounded-2xl bg-surface-container-low border border-outline-variant/5">
            <label className="font-label text-[10px] tracking-[0.2em] uppercase text-outline block mb-4">Additional Notes</label>
            <p className="text-on-surface whitespace-pre-wrap text-sm leading-relaxed">{item.notes}</p>
          </div>
        )}

        <div className="mt-12 pt-8 border-t border-outline-variant/10 flex justify-between items-center">
          {!isReceivedShare ? (
            <button
              onClick={handleDelete}
              className="px-4 py-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
            >
              <span className="material-symbols-outlined text-sm mr-2">delete</span>
              Delete
            </button>
          ) : (
            <div />
          )}
          <div className="flex flex-wrap gap-8">
            <div className="flex flex-col">
              <span className="font-label text-[10px] tracking-[0.2em] uppercase text-outline mb-1">Last Modified</span>
              <span className="text-xs text-on-surface">{new Date(item.updated_at).toLocaleDateString()}</span>
            </div>
            <div className="flex flex-col">
              <span className="font-label text-[10px] tracking-[0.2em] uppercase text-outline mb-1">Encryption</span>
              <span className="text-xs text-secondary font-mono">AES-256-GCM</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
