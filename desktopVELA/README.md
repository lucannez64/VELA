# VELA Desktop Application

A passwordless, zero-knowledge vault desktop application built with Tauri and React.

## Features

- **Biometric Authentication**: Windows Hello / Touch ID integration via TPM 2.0
- **Zero-Knowledge Architecture**: Your vault data is encrypted end-to-end
- **System Tray**: Runs in background with system tray presence
- **Global Shortcuts**: Quick search overlay with `Ctrl+Shift+V`
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
└── package.json
```

## Key UX Features

1. **Session Timer**: Visible countdown in title bar
2. **Biometric Unlock Gate**: Full-screen authentication overlay
3. **Quick Search**: Global shortcut overlay for instant search
4. **Auto-Lock**: Configurable idle timeout
5. **Clipboard Clear**: Automatic clipboard clearing after 30s

## Security

- All vault data encrypted with AES-256-GCM
- Post-quantum ready with hybrid ML-KEM + X25519
- TPM 2.0 / Secure Enclave integration for key storage
- No master password - biometric authentication only

## License

Proprietary - VELA
