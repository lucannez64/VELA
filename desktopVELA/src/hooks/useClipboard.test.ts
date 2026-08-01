import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useClipboard } from './useClipboard';

const mocks = vi.hoisted(() => {
  const ctx = {
    showToast: vi.fn(),
    settings: { clipboard_clear_seconds: 30 } as { clipboard_clear_seconds: number } | undefined,
    clipboardTimer: null as ReturnType<typeof setTimeout> | null,
    setClipboardTimer: null as unknown as (t: ReturnType<typeof setTimeout> | null) => void,
  };
  ctx.setClipboardTimer = vi.fn((t: ReturnType<typeof setTimeout> | null) => {
    ctx.clipboardTimer = t;
  });
  return { ctx, writeText: vi.fn() };
});

vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: mocks.writeText,
}));

vi.mock('../context/AppContext', () => ({
  useApp: () => mocks.ctx,
}));

beforeEach(() => {
  vi.useFakeTimers();
  mocks.writeText.mockResolvedValue(undefined);
});

afterEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  mocks.ctx.clipboardTimer = null;
  mocks.ctx.settings = { clipboard_clear_seconds: 30 };
});

describe('copyToClipboard', () => {
  it('writes the value and schedules the auto-clear', async () => {
    const { result } = renderHook(() => useClipboard());

    await act(async () => {
      await result.current.copyToClipboard('s3cret', 'Password');
    });

    expect(mocks.writeText).toHaveBeenCalledWith('s3cret');
    expect(mocks.ctx.showToast).toHaveBeenCalledWith('Password copied (clears in 30s)', 'success');
    expect(mocks.ctx.clipboardTimer).not.toBeNull();

    // Not yet cleared before the delay elapses.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(29_000);
    });
    expect(mocks.writeText).not.toHaveBeenCalledWith('');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(mocks.writeText).toHaveBeenCalledWith('');
    expect(mocks.ctx.showToast).toHaveBeenCalledWith('Clipboard cleared', 'info');
    expect(mocks.ctx.setClipboardTimer).toHaveBeenCalledWith(null);
  });

  it('uses the default label when none is given', async () => {
    const { result } = renderHook(() => useClipboard());
    await act(async () => {
      await result.current.copyToClipboard('x');
    });
    expect(mocks.ctx.showToast).toHaveBeenCalledWith('Value copied (clears in 30s)', 'success');
  });

  it('honours the configured clear delay', async () => {
    mocks.ctx.settings = { clipboard_clear_seconds: 5 };
    const { result } = renderHook(() => useClipboard());

    await act(async () => {
      await result.current.copyToClipboard('x', 'TOTP');
    });
    expect(mocks.ctx.showToast).toHaveBeenCalledWith('TOTP copied (clears in 5s)', 'success');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(mocks.writeText).toHaveBeenCalledWith('');
  });

  it('falls back to 30s when settings are unavailable', async () => {
    mocks.ctx.settings = undefined;
    const { result } = renderHook(() => useClipboard());
    await act(async () => {
      await result.current.copyToClipboard('x');
    });
    expect(mocks.ctx.showToast).toHaveBeenCalledWith('Value copied (clears in 30s)', 'success');
  });

  it('a second copy cancels the pending clear of the first', async () => {
    const { result, rerender } = renderHook(() => useClipboard());

    await act(async () => {
      await result.current.copyToClipboard('first');
    });
    rerender(); // hook re-reads the context with the stored timer
    await act(async () => {
      await result.current.copyToClipboard('second');
    });

    // One auto-clear fires (for the second copy), not two.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    const clears = mocks.writeText.mock.calls.filter(([v]) => v === '');
    expect(clears).toHaveLength(1);
  });

  it('reports a failed copy and does not schedule a clear', async () => {
    mocks.writeText.mockRejectedValueOnce(new Error('clipboard busy'));
    const { result } = renderHook(() => useClipboard());

    await act(async () => {
      await result.current.copyToClipboard('x');
    });

    expect(mocks.ctx.showToast).toHaveBeenCalledWith('Failed to copy', 'error');
    expect(mocks.ctx.clipboardTimer).toBeNull();
  });
});

describe('clearClipboard', () => {
  it('clears immediately and cancels the pending auto-clear', async () => {
    const { result, rerender } = renderHook(() => useClipboard());

    await act(async () => {
      await result.current.copyToClipboard('s3cret');
    });
    rerender();

    await act(async () => {
      await result.current.clearClipboard();
    });
    expect(mocks.writeText).toHaveBeenCalledWith('');
    expect(mocks.ctx.setClipboardTimer).toHaveBeenCalledWith(null);

    // The cancelled timer must not fire a second clear or a toast later.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    const clears = mocks.writeText.mock.calls.filter(([v]) => v === '');
    expect(clears).toHaveLength(1);
    expect(mocks.ctx.showToast).not.toHaveBeenCalledWith('Clipboard cleared', 'info');
  });
});
