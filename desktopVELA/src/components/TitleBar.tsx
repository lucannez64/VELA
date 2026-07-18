import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useApp } from '../context/AppContext';

export default function TitleBar() {
  const { session, setSession, setItems, setSelectedItem } = useApp();
  const [alwaysOnTop, setAlwaysOnTop] = useState(false);

  const handleMinimize = () => invoke('minimize_window');
  const handleMaximize = () => invoke('maximize_window');
  const handleClose = () => invoke('close_window');

  const handleLock = async () => {
    try {
      await invoke('lock_session');
      setSession(prev => prev ? { ...prev, active: false, lock_state: 'locked' } : null);
      setItems([]);
      setSelectedItem(null);
    } catch (e) {
      console.error('Lock failed:', e);
    }
  };

  const handleAlwaysOnTop = async () => {
    try {
      await invoke('toggle_always_on_top');
      setAlwaysOnTop(prev => !prev);
    } catch (e) {
      console.error('Toggle always on top failed:', e);
    }
  };

  const formatTime = (secs: number) => {
    const minutes = Math.floor(secs / 60);
    const seconds = secs % 60;
    return `${minutes}m ${seconds.toString().padStart(2, '0')}s`;
  };

  const getTimerColor = () => {
    if (!session?.active) return 'text-outline';
    if (session.session_time_remaining_secs <= 60) return 'text-red-500 animate-pulse';
    if (session.session_time_remaining_secs <= 180) return 'text-amber-500';
    return 'text-on-surface-variant';
  };

  return (
    <header
      className="h-14 bg-surface border-b border-outline-variant/10 flex justify-between items-center px-4 drag-region"
      onDoubleClick={(e) => {
        // Only toggle maximize when the drag region itself is double-clicked,
        // not the interactive controls inside the title bar.
        if ((e.target as HTMLElement).closest('.no-drag, button')) return;
        handleMaximize();
      }}
      title="Drag to move · double-click to maximize"
    >
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-primary-container border border-primary/20 flex items-center justify-center">
          <span className="material-symbols-outlined text-primary text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>shield_lock</span>
        </div>
        <span className="hidden sm:inline text-lg font-bold tracking-[0.2em] text-primary font-headline">VELA</span>
        <div className="hidden md:flex items-center gap-2 ml-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-on-secondary-container/10 rounded-full security-pulse">
            <span className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_rgb(var(--color-primary))]"></span>
            <span className="font-label uppercase tracking-widest text-[10px] text-primary">Zero-Knowledge Active</span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 sm:gap-4 no-drag">
        <div className="flex items-center gap-2 font-label text-xs text-outline">
          <span className="hidden sm:inline">Session:</span>
          <span className={`font-mono ${getTimerColor()}`}>
            {session?.active ? formatTime(session.session_time_remaining_secs) : '--'}
          </span>
        </div>
        <button
          onClick={handleLock}
          className="p-2 text-outline hover:bg-surface-container hover:text-primary transition-colors rounded-lg"
          title="Lock Now"
        >
          <span className="material-symbols-outlined text-xl">lock_open</span>
        </button>
        <button
          onClick={handleAlwaysOnTop}
          className={`hidden sm:block p-2 transition-colors rounded-lg ${alwaysOnTop ? 'text-primary bg-primary/10' : 'text-outline hover:bg-surface-container hover:text-primary'}`}
          title="Always on Top"
        >
          <span className="material-symbols-outlined text-xl">{alwaysOnTop ? 'keep' : 'push_pin'}</span>
        </button>
        <div className="flex items-center gap-1 ml-2">
          <button
            onClick={handleMinimize}
            className="w-8 h-8 flex items-center justify-center text-on-surface-variant hover:bg-surface-container hover:text-on-surface transition-colors rounded"
            title="Minimize"
          >
            <span className="material-symbols-outlined text-lg">remove</span>
          </button>
          <button
            onClick={handleMaximize}
            className="w-8 h-8 flex items-center justify-center text-on-surface-variant hover:bg-surface-container hover:text-on-surface transition-colors rounded"
            title="Maximize / Restore"
          >
            <span className="material-symbols-outlined text-lg">crop_square</span>
          </button>
          <button
            onClick={handleClose}
            className="w-8 h-8 flex items-center justify-center text-on-surface-variant hover:bg-red-500/20 hover:text-red-400 transition-colors rounded"
            title="Close to tray"
          >
            <span className="material-symbols-outlined text-lg">close</span>
          </button>
        </div>
      </div>
    </header>
  );
}
