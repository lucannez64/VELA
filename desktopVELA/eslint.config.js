import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: [
      'dist',
      'node_modules',
      'target',
      'src-tauri',
      'src-gpui',
      'src-gpui-spike',
      'vendor',
      '*.config.js',
      '*.config.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // Tauri IPC responses are typed at the boundary, not through generics.
      '@typescript-eslint/no-explicit-any': 'off',
      // Unused vars are almost always real bugs; keep `_`-prefixed escapes.
      // Caught errors are exempt: `catch (e) { /* fallback */ }` is the
      // established pattern in this codebase (~25 sites).
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    ...reactHooks.configs.flat.recommended,
    rules: {
      ...reactHooks.configs.flat.recommended.rules,
      // The v7 preset ships the React Compiler static-analysis rules
      // (immutability/purity/refs/set-state-in-effect/incompatible-library).
      // They exist for codebases opting into the compiler; this one predates
      // it and would need a component-level rewrite to comply. Keep the two
      // classic rules that catch real hook bugs regardless.
      'react-hooks/immutability': 'off',
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/refs': 'off',
      'react-hooks/purity': 'off',
      'react-hooks/incompatible-library': 'off',
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    plugins: { 'react-refresh': reactRefresh },
    rules: {
      // Vite HMR works best when component files only export components.
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },
  {
    // Context modules intentionally co-export the provider component and the
    // consumer hook — the whole point of the file.
    files: ['src/context/**'],
    rules: {
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    // Test files: vitest is imported explicitly, but `bun run build`'s tsc
    // pass doesn't need lint to be stricter than the app code.
    files: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
)
