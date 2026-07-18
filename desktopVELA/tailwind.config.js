/** @type {import('tailwindcss').Config} */

// Colors are resolved from CSS custom properties so the active theme
// (data-theme attribute on <html>) can redefine them at runtime.
// Values are space-separated RGB channels to support Tailwind opacity modifiers.
const themeColor = (name) => `rgb(var(${name}) / <alpha-value>)`;

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: themeColor('--color-primary'),
        'primary-dim': themeColor('--color-primary-dim'),
        secondary: themeColor('--color-secondary'),
        error: themeColor('--color-error'),
        'accent-violet': themeColor('--color-accent-violet'),
        surface: themeColor('--color-surface'),
        'surface-dim': themeColor('--color-surface-dim'),
        'surface-bright': themeColor('--color-surface-bright'),
        'surface-container-lowest': themeColor('--color-surface-container-lowest'),
        'surface-container-low': themeColor('--color-surface-container-low'),
        'surface-container': themeColor('--color-surface-container'),
        'surface-container-high': themeColor('--color-surface-container-high'),
        'surface-container-highest': themeColor('--color-surface-container-highest'),
        'surface-variant': themeColor('--color-surface-variant'),
        'on-surface': themeColor('--color-on-surface'),
        'on-surface-variant': themeColor('--color-on-surface-variant'),
        'on-primary': themeColor('--color-on-primary'),
        'on-secondary': themeColor('--color-on-secondary'),
        outline: themeColor('--color-outline'),
        'outline-variant': themeColor('--color-outline-variant'),
      },
      fontFamily: {
        headline: ['Space Grotesk', 'sans-serif'],
        body: ['Manrope', 'sans-serif'],
        label: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'ping-slow': 'ping 2s cubic-bezier(0, 0, 0.2, 1) infinite',
      },
    },
  },
  plugins: [],
}
