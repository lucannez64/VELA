/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: '#73db9a',
        'primary-dim': '#1c8f56',
        secondary: '#44e2cd',
        error: '#ffb4ab',
        'accent-violet': '#8b5cf6',
        surface: '#121416',
        'surface-dim': '#121416',
        'surface-bright': '#37393b',
        'surface-container-lowest': '#0c0e10',
        'surface-container-low': '#1a1c1e',
        'surface-container': '#1e2022',
        'surface-container-high': '#282a2c',
        'surface-container-highest': '#333537',
        'surface-variant': '#333537',
        'on-surface': '#e2e2e5',
        'on-surface-variant': '#c4c7c7',
        'on-primary': '#00391d',
        'on-secondary': '#003731',
        outline: '#8e9192',
        'outline-variant': '#444748',
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
