import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';

const faviconCache = new Map<string, string | null>();

interface Props {
  url?: string;
  itemType: string;
  icon: string;
  className?: string;
  fallbackClassName?: string;
}

export default function FaviconIcon({
  url,
  itemType,
  icon,
  className = 'w-12 h-12 rounded-xl bg-surface-bright',
  fallbackClassName = 'text-primary',
}: Props) {
  const [failed, setFailed] = useState(false);
  const [favicon, setFavicon] = useState<string | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;

    if (itemType !== 'login' || !url) {
      setFavicon(undefined);
      setFailed(false);
      return;
    }

    const cacheKey = url;
    const cached = faviconCache.get(cacheKey);
    if (cached !== undefined) {
      setFavicon(cached ?? undefined);
      setFailed(cached === null);
      return;
    }

    setFavicon(undefined);
    setFailed(false);

    invoke<string | null>('fetch_favicon', { url })
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
  }, [itemType, url]);

  if (favicon && !failed) {
    return (
      <img
        src={favicon}
        alt=""
        className={`shrink-0 object-cover ${className}`}
        onError={() => setFailed(true)}
      />
    );
  }

  return (
    <div
      className={`shrink-0 flex items-center justify-center ${className}`}
    >
      <span className={`material-symbols-outlined ${fallbackClassName}`}>{icon}</span>
    </div>
  );
}
