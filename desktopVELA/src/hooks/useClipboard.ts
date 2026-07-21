import { useCallback } from 'react';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { useApp } from '../context/AppContext';

// The pending-clear timer lives in AppContext (not a local ref) so that a
// clearClipboard() call from a different component instance — e.g. the lock
// button — can cancel the timer a copy started from ItemDetail. A local ref
// would only ever be visible to the hook instance that created it.
export function useClipboard() {
  const { showToast, settings, clipboardTimer, setClipboardTimer } = useApp();

  const copyToClipboard = useCallback(async (text: string, label: string = 'Value') => {
    try {
      await writeText(text);

      const clearDelay = (settings?.clipboard_clear_seconds ?? 30) * 1000;

      showToast(`${label} copied (clears in ${clearDelay / 1000}s)`, 'success');

      if (clipboardTimer) {
        clearTimeout(clipboardTimer);
      }

      const timer = setTimeout(async () => {
        try {
          await writeText('');
          showToast('Clipboard cleared', 'info');
        } catch (e) {
          console.error('Failed to clear clipboard:', e);
        }
        setClipboardTimer(null);
      }, clearDelay);

      setClipboardTimer(timer);
    } catch (e) {
      console.error('Failed to copy to clipboard:', e);
      showToast('Failed to copy', 'error');
    }
  }, [settings, showToast, clipboardTimer, setClipboardTimer]);

  const clearClipboard = useCallback(async () => {
    try {
      if (clipboardTimer) {
        clearTimeout(clipboardTimer);
        setClipboardTimer(null);
      }
      await writeText('');
    } catch (e) {
      console.error('Failed to clear clipboard:', e);
    }
  }, [clipboardTimer, setClipboardTimer]);

  return { copyToClipboard, clearClipboard };
}
