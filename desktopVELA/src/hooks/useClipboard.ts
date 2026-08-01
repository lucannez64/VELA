import { useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

// Copies go through our own `copy_secret` command rather than
// @tauri-apps/plugin-clipboard-manager: the plugin writes plain text, which
// leaves the copied password in the OS clipboard history (Win+V and cloud
// clipboard on Windows, Klipper or a `wl-paste --watch` recorder on Linux),
// where clearing the clipboard afterwards can no longer reach it. The command
// marks the copy concealed with whatever convention the platform has — see
// vela-desktop-core/src/clipboard.rs.
//
// Clearing is `clear_clipboard`, which wipes only if the clipboard still holds
// the secret we copied; writing '' unconditionally, as this hook used to,
// would throw away whatever the user had copied from another app in between.
//
// The pending-clear timer lives in AppContext (not a local ref) so that a
// clearClipboard() call from a different component instance — e.g. the lock
// button — can cancel the timer a copy started from ItemDetail. A local ref
// would only ever be visible to the hook instance that created it.
export function useClipboard() {
  const { showToast, settings, clipboardTimer, setClipboardTimer } = useApp();

  const copyToClipboard = useCallback(async (text: string, label: string = 'Value') => {
    try {
      await invoke('copy_secret', { text });

      const clearDelay = (settings?.clipboard_clear_seconds ?? 30) * 1000;

      showToast(`${label} copied (clears in ${clearDelay / 1000}s)`, 'success');

      if (clipboardTimer) {
        clearTimeout(clipboardTimer);
      }

      const timer = setTimeout(async () => {
        try {
          if (await invoke<boolean>('clear_clipboard')) {
            showToast('Clipboard cleared', 'info');
          }
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
      await invoke('clear_clipboard');
    } catch (e) {
      console.error('Failed to clear clipboard:', e);
    }
  }, [clipboardTimer, setClipboardTimer]);

  return { copyToClipboard, clearClipboard };
}
