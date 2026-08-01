import { afterEach, describe, expect, it, vi } from 'vitest';
import { THEMES, applyTheme, resolveTheme, systemPreferredTheme } from './themes';

function mockMatchMedia(lightPreferred: boolean) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: lightPreferred && query === '(prefers-color-scheme: light)',
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })) as unknown as typeof window.matchMedia;
}

afterEach(() => {
  vi.restoreAllMocks();
  delete document.documentElement.dataset.theme;
});

describe('THEMES registry', () => {
  it('has unique ids and well-formed metadata', () => {
    const ids = THEMES.map(t => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const theme of THEMES) {
      expect(theme.label).toBeTruthy();
      expect(theme.swatches).toHaveLength(4);
    }
  });

  it('marks latte as the only light theme', () => {
    expect(THEMES.filter(t => !t.dark).map(t => t.id)).toEqual(['latte']);
  });
});

describe('systemPreferredTheme', () => {
  it('returns latte when the OS prefers light', () => {
    mockMatchMedia(true);
    expect(systemPreferredTheme()).toBe('latte');
  });

  it('returns vela when the OS prefers dark', () => {
    mockMatchMedia(false);
    expect(systemPreferredTheme()).toBe('vela');
  });
});

describe('resolveTheme', () => {
  it('passes through concrete theme ids', () => {
    mockMatchMedia(false);
    for (const theme of THEMES) {
      expect(resolveTheme(theme.id)).toBe(theme.id);
    }
  });

  it('maps legacy dark -> vela', () => {
    expect(resolveTheme('dark')).toBe('vela');
  });

  it('maps legacy light -> latte', () => {
    expect(resolveTheme('light')).toBe('latte');
  });

  it('resolves "system" from the OS preference', () => {
    mockMatchMedia(true);
    expect(resolveTheme('system')).toBe('latte');
    mockMatchMedia(false);
    expect(resolveTheme('system')).toBe('vela');
  });

  it.each([undefined, null, ''])('resolves %s from the OS preference', setting => {
    mockMatchMedia(true);
    expect(resolveTheme(setting)).toBe('latte');
  });

  it('falls back to vela for unknown values', () => {
    mockMatchMedia(true); // fallback ignores system preference
    expect(resolveTheme('dracula')).toBe('vela');
    expect(resolveTheme('DARK')).toBe('vela');
  });
});

describe('applyTheme', () => {
  it('sets data-theme on <html> and returns the resolved id', () => {
    mockMatchMedia(false);
    expect(applyTheme('gruvbox')).toBe('gruvbox');
    expect(document.documentElement.dataset.theme).toBe('gruvbox');
  });

  it('applies the legacy mapping to the DOM', () => {
    mockMatchMedia(false);
    expect(applyTheme('dark')).toBe('vela');
    expect(document.documentElement.dataset.theme).toBe('vela');
  });
});
