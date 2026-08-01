# VELA Desktop Application

A passwordless, zero-knowledge vault desktop application built with Tauri and React.

## Features

- **Biometric Authentication**: Windows Hello / Touch ID integration via TPM 2.0
- **Zero-Knowledge Architecture**: Your vault data is encrypted end-to-end
- **System Tray**: Runs in background with system tray presence
- **Global Shortcuts**: Quick search overlay with `Ctrl+Alt+V` (see [Global shortcut on Linux](#global-shortcut-on-linux) for Wayland)
- **Session Management**: Auto-lock with configurable timeout
- **Multi-Device Sync**: Secure vault synchronization across devices
- **Secure Sharing**: Share vault items with other VELA users
- **Audit Log**: Encrypted activity tracking
- **Browser Extension Integration**: Native IPC for autofill

## Design

The application follows the VELA design system:
- Dark-first UI with monochrome base palette
- Accent color: Deep Indigo / Electric Violet (#8b5cf6)
- Primary color: VELA Green (#73db9a)
- Typography: Space Grotesk (headlines), Manrope (body), Inter (labels), JetBrains Mono (code)

### Theming

All colors are design tokens backed by CSS custom properties (`rgb(var(--token) / <alpha>)`)
defined in `src/index.css` and mapped in `tailwind.config.js`. The active theme is selected
via the `data-theme` attribute on `<html>` and can be changed in **Settings → Appearance**:

| Theme | `data-theme` | Style |
| --- | --- | --- |
| System | (follows OS) | VELA Dark or Latte based on OS preference |
| VELA Dark | `vela` | Default obsidian theme |
| Macchiato | `macchiato` | Catppuccin Macchiato |
| Latte | `latte` | Catppuccin Latte (light) |
| Gruvbox | `gruvbox` | Gruvbox Dark |

Theme metadata and resolution logic (including legacy `dark`/`light` setting values) live in
`src/themes.ts`. When adding UI, always use the semantic tokens (`bg-surface-container`,
`text-on-surface-variant`, `text-outline`, …) instead of fixed palette colors so every theme
renders correctly.

## Prerequisites

- Node.js 18+
- Rust 1.70+
- Windows 10/11 with TPM 2.0 (for biometric features)

## Getting Started

### Install dependencies

```bash
npm install
```

### Run in development mode

```bash
npm run tauri dev
```

### Build for production

```bash
npm run tauri build
```

## Testing

Rust workspace tests (core backend, Tauri app, gpui app):

```bash
# Shared core backend (used by both desktop variants)
DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent cargo test -p vela-desktop-core

# gpui binary (theme/QR/audit-log formatting tests)
cargo test -p vela-desktop-gpui

# Headless end-to-end sync tests: real vela-desktop-core drives by an
# in-process mock of the server, against a Rust mirror of the Android
# client's sync logic (same libVELA crypto via JNI-style derivation).
# Covers enrollment codes, chunk upload/download, Lamport-ordered merge,
# tombstones and cross-client decryption. No device or emulator needed.
DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent cargo test -p vela-e2e

# Tauri package (requires dist/ — run `bun run build` once first)
cargo test -p vela-desktop
```

The `DBUS_SESSION_BUS_ADDRESS` override makes the Linux Secret Service probes
fail fast and deterministically on machines without a session bus (CI, headless);
the tests are hermetic and never touch the real keychain or app data dir.

Frontend unit tests (vitest + Testing Library, covering `themes.ts`,
`lib/webauthn.ts`, `hooks/useClipboard.ts`):

```bash
bun run test        # single run
bun run test:watch  # watch mode
```

Frontend lint (ESLint flat config in `eslint.config.js` — TypeScript +
react-hooks + react-refresh rules; the React Compiler static-analysis rules
are off since the codebase predates the compiler):

```bash
bun run lint
```

## Project Structure

```
desktopVELA/
├── src/                    # React frontend
│   ├── components/         # Reusable UI components
│   ├── views/             # Screen components
│   ├── App.tsx            # Main application
│   └── main.tsx           # Entry point
├── src-tauri/              # Rust backend
│   ├── src/
│   │   ├── main.rs        # Application entry
│   │   ├── commands/      # Tauri commands
│   │   ├── biometric.rs    # Biometric integration
│   │   ├── session.rs      # Session management
│   │   ├── vault.rs        # Vault operations
│   │   └── ipc.rs          # IPC for browser extension
│   └── icons/              # App icons
├── vela-desktop-core/      # Shared core backend (both desktop variants)
├── vela-e2e/               # Headless end-to-end sync tests
├── src-gpui/               # Native gpui build (Linux)
└── package.json
```

## Key UX Features

1. **Session Timer**: Visible countdown in title bar
2. **Biometric Unlock Gate**: Full-screen authentication overlay
3. **Quick Search**: Global shortcut overlay for instant search
4. **Auto-Lock**: Configurable idle timeout
5. **Clipboard Clear**: Automatic clipboard clearing after 30s

## Global shortcut on Linux

On X11 the quick-search shortcut is a plain key grab via
`tauri-plugin-global-shortcut` and works out of the box.

On **Wayland** compositors don't allow apps to grab keys, so VELA binds the
shortcut through the XDG Desktop Portal `GlobalShortcuts` interface instead
(shortcut id `quick-search`, app id `com.vela.vault`).

Portals identify callers by app id, and for non-sandboxed apps VELA has to
register `com.vela.vault` itself via the host portal registry — which only
succeeds when a `com.vela.vault.desktop` entry is installed. The deb/rpm
bundles ship one (`src-tauri/assets/com.vela.vault.desktop`); if you
installed another way (AUR, manual) and the startup log shows
`Could not register 'com.vela.vault' with the desktop portal`, drop a copy
into `~/.local/share/applications/com.vela.vault.desktop`.

What happens after binding depends on your portal backend:

- **KDE / GNOME**: a system dialog asks you to confirm the binding the first
  time; the preferred trigger from Settings is offered as the default. Manage
  it later in the system shortcut settings.
- **Hyprland** (`xdg-desktop-portal-hyprland`): preferred triggers are
  ignored — the compositor owns the keybind. Add to `hyprland.conf`:

  ```ini
  bind = CTRL ALT, V, global, com.vela.vault:quick-search
  windowrule = float, title:^(VELA Quick Search)$
  ```

  The `windowrule` keeps the quick-search popup floating instead of being
  tiled into the layout. Run `hyprctl globalshortcuts` while VELA is running
  to confirm the exact `appid:id` pair registered with the portal.

The shortcut opens a dedicated always-on-top popup window on the active
workspace (the main window stays where it is); it hides on Escape or focus
loss, and selecting a result focuses the main window on that item.

Changing the shortcut in **Settings → Security** updates the preferred
trigger hint used at next launch; on Hyprland only the `bind` line matters.
If your compositor's portal doesn't implement GlobalShortcuts at all, VELA
logs an error at startup and the shortcut is unavailable — as a fallback you
can bind a compositor key to focus/launch VELA.

## Security

- All vault data encrypted with AES-256-GCM
- Post-quantum ready with hybrid ML-KEM + X25519
- TPM 2.0 / Secure Enclave integration for key storage
- No master password - biometric authentication only

## License

Proprietary - VELA
