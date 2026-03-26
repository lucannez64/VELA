import { useCallback, useRef } from 'react';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { useApp } from '../context/AppContext';

export function useClipboard() {
  const { showToast, settings, setClipboardTimer } = useApp();
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const copyToClipboard = useCallback(async (text: string, label: string = 'Value') => {
    try {
      await writeText(text);
      
      const clearDelay = (settings?.clipboard_clear_seconds ?? 30) * 1000;
      
      showToast(`${label} copied (clears in ${clearDelay / 1000}s)`, 'success');

      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }

      timerRef.current = setTimeout(async () => {
        try {
          await writeText('');
          showToast('Clipboard cleared', 'info');
        } catch (e) {
          console.error('Failed to clear clipboard:', e);
        }
        timerRef.current = null;
      }, clearDelay);

      setClipboardTimer(timerRef.current);
    } catch (e) {
      console.error('Failed to copy to clipboard:', e);
      showToast('Failed to copy', 'error');
    }
  }, [settings, showToast, setClipboardTimer]);

  const clearClipboard = useCallback(async () => {
    try {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      await writeText('');
    } catch (e) {
      console.error('Failed to clear clipboard:', e);
    }
  }, []);

  return { copyToClipboard, clearClipboard };
}
