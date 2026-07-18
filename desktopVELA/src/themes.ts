/**
 * Theme registry and resolution logic.
 *
 * Themes are applied by setting `data-theme` on <html>; all colors flow from
 * the CSS custom properties defined in index.css.
 */

export type ThemeId = 'vela' | 'macchiato' | 'latte' | 'gruvbox';

/** Values that may be stored in settings, including legacy ones. */
export type ThemeSetting = ThemeId | 'system' | 'dark' | 'light';

export interface ThemeMeta {
  id: ThemeId;
  label: string;
  description: string;
  dark: boolean;
  /** [background, container, primary, accent] preview colors for the picker. */
  swatches: [string, string, string, string];
}

export const THEMES: ThemeMeta[] = [
  {
    id: 'vela',
    label: 'VELA Dark',
    description: 'Default obsidian look',
    dark: true,
    swatches: ['#121416', '#1e2022', '#73db9a', '#8b5cf6'],
  },
  {
    id: 'macchiato',
    label: 'Macchiato',
    description: 'Catppuccin Macchiato',
    dark: true,
    swatches: ['#24273a', '#363a4f', '#a6da95', '#c6a0f6'],
  },
  {
    id: 'latte',
    label: 'Latte',
    description: 'Catppuccin Latte — light',
    dark: false,
    swatches: ['#eff1f5', '#dce0e8', '#40a02b', '#8839ef'],
  },
  {
    id: 'gruvbox',
    label: 'Gruvbox',
    description: 'Retro groove, warm dark',
    dark: true,
    swatches: ['#282828', '#3c3836', '#b8bb26', '#d3869b'],
  },
];

const LEGACY_MAP: Record<string, ThemeId> = {
  dark: 'vela',
  light: 'latte',
};

function isThemeId(value: string): value is ThemeId {
  return THEMES.some(t => t.id === value);
}

export function systemPreferredTheme(): ThemeId {
  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: light)').matches) {
    return 'latte';
  }
  return 'vela';
}

/** Maps a stored setting (including legacy values) to a concrete theme id. */
export function resolveTheme(setting: ThemeSetting | string | undefined | null): ThemeId {
  if (!setting || setting === 'system') {
    return systemPreferredTheme();
  }
  if (isThemeId(setting)) {
    return setting;
  }
  return LEGACY_MAP[setting] ?? 'vela';
}

export function applyTheme(setting: ThemeSetting | string | undefined | null): ThemeId {
  const resolved = resolveTheme(setting);
  document.documentElement.dataset.theme = resolved;
  return resolved;
}
