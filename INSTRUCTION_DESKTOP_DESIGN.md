# VELA Desktop App — UX Design Instructions

**Version:** 1.0
**Date:** 2026-03-24
**Platform:** Windows / macOS / Linux (Rust + Tauri)
**Role of this document:** Full UX specification for a designer AI to generate screens, components, and interaction flows.

---

## 1. Product Identity & Positioning

VELA is a **passwordless, zero-knowledge vault**. It never asks for a master password. Authentication is proven through biometrics and hardware-bound keys (TPM / Secure Enclave) using a lattice-based zero-knowledge proof scheme. The server never sees your plaintext data.

### Design Tone
- **Calm confidence.** Security without fear. Never technical jargon in user-facing copy.
- **Minimal chrome.** Only surface what the user needs right now.
- **Trust signals are quiet but present.** A small lock icon or pulse indicator communicates "secure" without alarming the user.
- **No passwords, no popups asking for a PIN.** The UX should feel like unlocking a premium device — biometric touch → open.

### Visual Language
- Dark-first design (with automatic light mode follow).
- Monochrome base palette (near-black surface, near-white text) with one accent color (deep indigo / electric violet) used sparingly for active states, CTAs, and status pulses.
- Dense but airy: compact rows with generous vertical rhythm.
- Typography: a humanist sans-serif for vault items, monospace only for sensitive revealed values (passwords, card numbers, recovery codes).

---

## 2. App Architecture Overview

The desktop app runs as a **background daemon with a system tray presence**. The main window is a companion interface that can be opened on demand. This is not an always-visible browser tab — it is a vault you open, use briefly, and close.

```
┌─────────────────────────────────────────────────┐
│  System Tray Icon                                │
│  (pulse = syncing · lock = session locked)       │
│                └── Click → Main Window (toggle)  │
├─────────────────────────────────────────────────┤
│  Main Window (Tauri webview)                     │
│  ├── Setup Flow (first launch only)              │
│  ├── Biometric Unlock Gate                       │
│  ├── Vault Browser                               │
│  │   ├── Item List                               │
│  │   ├── Item Detail / Edit                      │
│  │   └── Search                                  │
│  ├── Devices                                     │
│  ├── Sharing Inbox                               │
│  ├── Audit Log                                   │
│  └── Settings                                    │
└─────────────────────────────────────────────────┘
```

---

## 3. System Tray

### 3.1 States

| State | Icon Appearance | Tooltip |
|---|---|---|
| Locked (no active session) | Solid lock icon | "VELA — Locked" |
| Unlocked & idle | Dimmed logo | "VELA — Active" |
| Syncing | Animated ring around logo | "VELA — Syncing…" |
| Sync conflict | Logo + small amber dot | "VELA — Conflict needs review" |
| Error (no network / auth failure) | Logo + small red dot | "VELA — Connection error" |

### 3.2 Right-Click Context Menu

```
  Open VELA
  ──────────
  Lock Now
  Sync Now
  ──────────
  Quit
```

"Lock Now" ends the active session immediately (RMS cleared from memory, ZKP re-authentication will be required next open).

### 3.3 Click Behavior
- **Single left-click:** Toggle the main window (open if closed, focus if open, hide if focused).
- **The window never fully quits** unless the user chooses Quit. It persists as a daemon to serve the browser extension.

---

## 4. Main Window Shell

### 4.1 Layout

```
┌─────────────────────────────────────────────────────────────┐
│ ╔═══╗  VELA                     🔒 Locked / 🟢 Session: 7m │
│ ╚═══╝                                              [⚙]  [×] │
├──────────────┬──────────────────────────────────────────────┤
│  Sidebar     │  Content Pane                                 │
│              │                                               │
│  Vault       │                                               │
│  Devices     │                                               │
│  Sharing     │                                               │
│  Audit Log   │                                               │
│  Settings    │                                               │
│              │                                               │
└──────────────┴──────────────────────────────────────────────┘
```

- **Top-right status bar:** Shows lock/unlock state and remaining session time (counts down from 15 min; resets on activity). Clicking it when locked triggers biometric auth. Clicking it when unlocked offers "Lock Now".
- **Window is resizable but has a minimum size of 820 × 560 px.**
- **Frameless window** (custom title bar drawn by the app). Drag region is the top bar.
- **The sidebar is always visible** once unlocked. Collapsed on mobile-style narrow widths (< 600 px wide) into icon-only mode.

### 4.2 Session Timer

- Displayed as `Session: Xm` where X counts down.
- Turns amber at ≤ 3 minutes remaining.
- Turns red and pulses at ≤ 1 minute remaining.
- When the session expires mid-use, an overlay appears (see §7 Biometric Gate).
- The timer resets on every vault interaction (browsing, editing, copying).

---

## 5. First Launch & Setup Flow

Triggered once: when no device identity is found in the local keystore.

### 5.1 Screen Sequence

**Step 1 — Welcome**
```
         ╔═══════════════════════════════╗
         ║   VELA                        ║
         ║                               ║
         ║   Your vault. No passwords.   ║
         ║                               ║
         ║   [  Create new vault  ]      ║
         ║   [  Add existing device  ]   ║
         ╚═══════════════════════════════╝
```
- "Create new vault" → §5.2 New Identity Setup.
- "Add existing device" → §11 Device Enrollment (QR flow as new device).

---

**Step 2 — Biometric Registration**
```
  Set up biometrics

  VELA uses your device's hardware security chip (TPM) to protect your
  vault. No password is ever created.

  Your fingerprint or face will be the only way to unlock VELA.

  [  Enable Windows Hello / Touch ID  ]

  ──────────────────────────────────────
  ⚠  Cannot use a PIN or password as fallback. Hardware biometrics required.
```
- This step calls the OS biometric enrollment API. If biometrics are unavailable, show a blocking error screen explaining the requirement.

---

**Step 3 — Recovery Setup (mandatory, non-skippable)**

```
  Set up recovery (2 of 3 steps)

  If you lose all your devices, you'll need these to recover your vault.

  ████████████  Step 1 of 2 complete: Cloud backup (iCloud / Google Drive)

  [ Connect Google Drive ]   [ Connect iCloud ]

  ──────────────────────────────────────────────────────────────────
  Step 2: Hardware security key
  Plug in your FIDO2 / passkey device (YubiKey, etc.)

  [ Register security key ]

  ──────────────────────────────────────────────────────────────────
  Step 3: Trusted contact  (optional but recommended)
  Share a recovery fragment with a trusted VELA contact.

  [ Skip for now ]   [ Invite contact ]
```

- Progress bar shows steps completed.
- Cannot proceed to the vault until steps 1 and 2 are done. Step 3 is optional.
- Each step has a checkmark state when complete.

---

**Step 4 — Setup Complete**
```
  You're all set.

  ✓  Vault created
  ✓  Biometrics registered
  ✓  Recovery configured

  [  Open my vault  ]
```

---

## 6. Biometric Unlock Gate

### 6.1 Initial Lock Screen (app opened, no active session)

This is the first thing seen when opening the app after it's locked. The vault content pane is not visible — the whole window shows this overlay.

```
╔══════════════════════════════════════════════════╗
║                                                  ║
║                   ╔═══╗                          ║
║                   ║ ⌘ ║  VELA                   ║
║                   ╚═══╝                          ║
║                                                  ║
║          Touch sensor to unlock                  ║
║                                                  ║
║              ┌──────────────┐                    ║
║              │  Fingerprint │  ← animated pulse  ║
║              │  icon        │                    ║
║              └──────────────┘                    ║
║                                                  ║
║          Or use Face ID / Windows Hello          ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

- Biometric prompt fires automatically on window focus (no button press needed).
- The pulse animation is the only motion — everything else is static.
- On success, the overlay fades out (300ms) revealing the vault.
- On failure (rejected biometric), the icon shakes and a small message appears: "Authentication failed — try again" with a retry count (locks out at 5 fails with a 30-second cooldown).

### 6.2 Mid-Session Expiry Overlay

When the session timer expires while the window is open, a semi-transparent overlay covers only the content pane (sidebar remains visible but items are blurred):

```
  ┌────────────────────────────────────────┐
  │                                        │
  │   Session expired.                     │
  │   Touch sensor to continue.            │
  │                                        │
  │        [ Fingerprint icon ]            │
  │                                        │
  └────────────────────────────────────────┘
```

The user does not lose their place in the UI — after re-auth the overlay disappears and they are back exactly where they were.

---

## 7. Vault Browser

### 7.1 Item List

Default view when unlocked. The content pane shows a list of all vault items.

```
  ┌─────────────────────────────────────────────────────────┐
  │  🔍  Search vault…                          [+ Add Item] │
  ├────────┬────────────────────────────────────────────────┤
  │  All   │  Logins (42)  Cards (3)  Notes (8)  Files (2)  │
  ├────────┴────────────────────────────────────────────────┤
  │                                                         │
  │  ▸ A                                                    │
  │    [🔑]  Amazon                   amazon.com      [⋯]  │
  │    [🔑]  Apple ID                 apple.com       [⋯]  │
  │                                                         │
  │  ▸ G                                                    │
  │    [🔑]  GitHub                   github.com      [⋯]  │
  │    [💳]  Visa ····4242                             [⋯]  │
  │                                                         │
  │  ▸ N                                                    │
  │    [📝]  Netflix                  netflix.com     [⋯]  │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

**List row behavior:**
- Click a row → Item Detail panel slides in from right (two-pane layout).
- Hover shows a quick-copy button (clipboard icon) for the primary field (password for logins, number for cards).
- `[⋯]` overflow menu: Copy username, Copy password, Open URL, Edit, Move to trash.
- Rows are grouped alphabetically with collapsible letter headers.
- Tabs at top filter by item type.

### 7.2 Search

- Triggered by clicking the search bar or pressing `Ctrl+F` / `Cmd+F`.
- Searches across: item name, URL, username, note title.
- Results appear inline in the list (no separate screen), highlighted.
- `Escape` clears search.
- Fuzzy matching: "amz" matches "Amazon".

### 7.3 Item Detail — Login

Clicking a Login row opens the detail panel (or a full pane in single-column narrow mode):

```
  ┌─────────────────────────────────────────────────────────┐
  │  ← Back                          [Edit]  [Delete]       │
  │                                                         │
  │   [🔑]  Amazon                                          │
  │         amazon.com                                      │
  │                                                         │
  │  ─────────────────────────────────────────────────────  │
  │  Username                                               │
  │  john@example.com                           [📋 Copy]  │
  │                                                         │
  │  Password                                               │
  │  ●●●●●●●●●●●●                     [👁 Reveal] [📋 Copy] │
  │                                                         │
  │  TOTP (2FA)                                             │
  │  ● ● ●  5 3 2                     ████░░ 18s   [📋 Copy] │
  │                                                         │
  │  Website                                                │
  │  https://amazon.com                          [↗ Open]  │
  │                                                         │
  │  Notes                                                  │
  │  (empty)                                                │
  │                                                         │
  │  ─────────────────────────────────────────────────────  │
  │  Last modified: 2026-03-12 · by MacBook Pro             │
  └─────────────────────────────────────────────────────────┘
```

- Password is **always masked by default**. Reveal requires an explicit click. Re-masks automatically after 30 seconds.
- TOTP shows a live countdown progress bar and the current 6-digit code. Updates in real time.
- Copying to clipboard auto-clears after 30 seconds (small toast shows countdown: "Clipboard clears in 28s").
- "Last modified" shows the device name, not a device ID.

### 7.4 Item Detail — Credit Card

```
  [💳]  Visa

  Card Number
  ····  ····  ····  4242                       [👁] [📋 Copy]

  Cardholder Name
  John Doe                                          [📋 Copy]

  Expiry          CVV                PIN
  08 / 28         ●●●  [👁]          ●●●●  [👁]
  [📋 Copy]       [📋 Copy]          [📋 Copy]
```

Card number masked except last 4 by default. Visual card art (gradient block showing card type icon) at the top.

### 7.5 Item Detail — Secure Note

Full-screen-ish text area view. Markdown rendered. Edit toggles to raw markdown editor.

### 7.6 Item Detail — File

```
  [📁]  Tax Return 2025.pdf

  Size:    2.3 MB
  Type:    PDF document
  Uploaded: 2026-01-30

  [  Download  ]   [  Delete  ]
```

Progress bar during download. File is decrypted locally before saving to disk. A prompt asks where to save it.

### 7.7 Add / Edit Item

Full form view. Fields vary by item type (selected via a type picker at top of the form).

**Login form fields:**
- Name (required)
- URL
- Username
- Password (with "Generate" button → opens password generator popover)
- TOTP secret (paste or scan QR)
- Notes (multiline)

**Password Generator Popover:**
```
  Generated: Kv#9mP!qLw3x         [🔄 Regenerate]  [📋 Use this]

  Length:  ────●──────  20
  ☑ Uppercase  ☑ Lowercase  ☑ Numbers  ☑ Symbols
  ☐ Easy to type   ☐ Pronounceable
```

---

## 8. Conflict Resolution

When a sync conflict exists (two devices edited the same item between syncs), VELA surfaces it non-intrusively.

### 8.1 Conflict Banner

In the vault browser, a dismissible amber banner appears at the top:

```
  ⚠  1 item has a sync conflict. [ Review → ]
```

### 8.2 Conflict Review Screen

Accessed via the banner or from the item's overflow menu.

```
  Sync Conflict — Amazon (Login)

  Choose which version to keep, or keep both.

  ┌───────────────────────────┐  ┌───────────────────────────┐
  │  This device              │  │  MacBook Pro              │
  │  Modified: Mar 22, 09:14  │  │  Modified: Mar 22, 11:03  │
  │                           │  │                           │
  │  Username: john@work.com  │  │  Username: john@work.com  │
  │  Password: [changed]      │  │  Password: [changed]      │
  │  TOTP: (none)             │  │  TOTP: 123456…            │
  └───────────────────────────┘  └───────────────────────────┘

           [Keep this device]   [Keep MacBook Pro]   [Keep both]
```

- "Keep both" creates a duplicate item with "(conflict copy)" appended to the name.
- Differences between versions are highlighted in amber.

---

## 9. Device Management

Accessible from the sidebar "Devices" section.

### 9.1 Device List

```
  My Devices

  ┌─────────────────────────────────────────────────────────┐
  │  [💻]  MacBook Pro (this device)                        │
  │        Enrolled: 2026-02-01 · Last active: Just now     │
  │                                              [Revoke ▾] │
  ├─────────────────────────────────────────────────────────┤
  │  [📱]  iPhone 15 Pro                                    │
  │        Enrolled: 2026-02-01 · Last active: 2 hours ago  │
  │                                              [Revoke ▾] │
  ├─────────────────────────────────────────────────────────┤
  │  [💻]  Windows Desktop                                  │
  │        Enrolled: 2026-03-10 · Last active: 4 days ago   │
  │                                              [Revoke ▾] │
  └─────────────────────────────────────────────────────────┘

  [+ Enroll new device]
```

"This device" is labeled clearly and the Revoke button for it reads "Revoke (signs out everywhere)" with extra confirmation.

### 9.2 Revoking a Device

Clicking Revoke → confirmation modal:

```
  Revoke iPhone 15 Pro?

  This will immediately sign out that device and prevent it from
  accessing your vault. It cannot be undone — the device must be
  re-enrolled to regain access.

  [Cancel]   [Revoke device]
```

After revocation, the device row shows a "Revoked" badge and fades, then disappears on next refresh.

### 9.3 Enroll New Device (as authorizing device)

When the user clicks "+ Enroll new device" on this (authorizing) device:

```
  Enroll a new device

  On your new device, open VELA and choose "Add existing device."
  It will display a QR code. Scan it here.

  ┌─────────────────────────────────────┐
  │                                     │
  │      [Camera viewfinder / QR]       │
  │                                     │
  └─────────────────────────────────────┘

  [ Open camera ]

  ── or ──

  [ Paste public key manually ]
```

After scanning:
```
  New device recognized.

  Name this device:   [ Windows Desktop PC      ]

  Enrollment will be authorized using your biometrics.

  [Cancel]   [Authorize device →]
```

Biometric prompt fires on confirm. Success shows:

```
  ✓  Device enrolled successfully.

  The new device can now access your vault after it completes
  its setup.
```

---

## 10. Secure Sharing

Accessible from "Sharing" in the sidebar.

### 10.1 Sharing Inbox

```
  Sharing

  ┌── Received ──────────────────────────────────────────────┐
  │                                                          │
  │  [🔑]  Netflix (Login)                                   │
  │        From: alice@example.com  ·  Mar 21                │
  │        [ Accept ]  [ Decline ]                           │
  │                                                          │
  └──────────────────────────────────────────────────────────┘

  ┌── Sent ──────────────────────────────────────────────────┐
  │                                                          │
  │  [🔑]  Spotify (Login)   →  bob@example.com  ·  Mar 18  │
  │        [ Revoke access ]                                 │
  │                                                          │
  └──────────────────────────────────────────────────────────┘
```

### 10.2 Sending a Share

From item detail overflow menu → "Share with VELA user":

```
  Share Amazon (Login)

  Recipient VELA username or email:
  [ alice@example.com              ]

  ☐ Allow recipient to edit
  ☑ Notify me when accepted

  [Cancel]   [Send encrypted share]
```

---

## 11. Recovery Setup & Management

Accessible from Settings → Recovery.

```
  Recovery Configuration

  If all your devices are lost, you'll need 2 of the following 3
  shares to recover your vault.

  ┌──────────────────────────────────────────────────────────┐
  │  ✓  Share 1 — Cloud backup        Google Drive   [Change]│
  │  ✓  Share 2 — Security key        YubiKey 5 NFC          │
  │  ○  Share 3 — Trusted contact     Not configured  [Set up]│
  └──────────────────────────────────────────────────────────┘

  ⚠  Without shares 1 and 2, vault recovery is impossible.
```

### 11.1 Recovery Walkthrough (first time)

Step-by-step wizard covering:
1. Connect cloud provider → OAuth flow in a browser webview inside the app.
2. Register FIDO2 key → OS FIDO2 prompt.
3. Invite trusted contact → enter VELA contact; sends an encrypted share fragment via the server.

---

## 12. Audit Log

Accessible from sidebar "Audit Log."

```
  Activity Log

  Encrypted end-to-end. Only your enrolled devices can read this.

  ┌──────────────────────────────────────────────────────────┐
  │  Mar 24, 2026  09:41  Vault synced          MacBook Pro  │
  │  Mar 23, 2026  18:02  Device enrolled       iPhone 15   │
  │  Mar 23, 2026  17:58  Vault synced          iPhone 15   │
  │  Mar 22, 2026  11:04  Vault synced          Windows PC  │
  │  Mar 22, 2026  09:13  Vault synced          MacBook Pro │
  │  Mar 10, 2026  14:30  Device enrolled       Windows PC  │
  └──────────────────────────────────────────────────────────┘

  [ Load more ]
```

- Events are read-only, chronological (newest first).
- No item-level detail is shown (only sync event counts, device lifecycle events, share send/receive).
- A small lock badge at the top confirms E2E encryption status.

---

## 13. Settings

```
  Settings

  ┌── Security ───────────────────────────────────────────────┐
  │  Auto-lock after idle        [ 5 minutes ▾ ]             │
  │  Clipboard clear delay       [ 30 seconds ▾ ]            │
  │  Require biometrics on reveal  ☐                         │
  └───────────────────────────────────────────────────────────┘

  ┌── Sync ────────────────────────────────────────────────────┐
  │  Sync on startup             ☑                            │
  │  Background sync interval    [ 5 minutes ▾ ]              │
  │  Last synced: Mar 24, 2026  09:41                         │
  │  [ Sync now ]                                             │
  └───────────────────────────────────────────────────────────┘

  ┌── Browser Extension ───────────────────────────────────────┐
  │  Extension connected         🟢 Chrome (v3.1.0)           │
  │  [ Manage extension permissions ]                         │
  └───────────────────────────────────────────────────────────┘

  ┌── Appearance ──────────────────────────────────────────────┐
  │  Theme          [ System default ▾ ]                      │
  │  Compact list   ☐                                         │
  └───────────────────────────────────────────────────────────┘

  ┌── Account ─────────────────────────────────────────────────┐
  │  User ID: vela://abc123…                  [ Copy ]        │
  │  [ Sign out and lock ]                                    │
  │  [ Delete vault (irreversible) ]                          │
  └───────────────────────────────────────────────────────────┘
```

---

## 14. Browser Extension Integration

### 14.1 Extension Connection Status

When the browser extension is connected (native messaging active), a small green dot appears next to "Browser Extension" in settings and a subtle indicator is shown in the status bar.

### 14.2 Biometric Prompt Triggered by Extension

When the browser extension requests autofill data, a **non-modal notification popup** appears over the system tray / in the active window:

```
  ┌────────────────────────────────────┐
  │  VELA                              │
  │                                    │
  │  Chrome is requesting autofill for │
  │  amazon.com                        │
  │                                    │
  │  Touch sensor to approve.          │
  │                                    │
  │  [Fingerprint icon / pulse]        │
  │                                    │
  │  [ Deny ]                          │
  └────────────────────────────────────┘
```

- This prompt appears even if the VELA main window is closed.
- It auto-dismisses and denies after 15 seconds of no response.
- Biometric approval causes the decrypted item to be sent to the extension. The RMS never enters browser memory.
- If multiple items match the domain, a list is shown:

```
  Which account?

  ○  john@work.com   (Amazon Business)
  ○  john@example.com  (Personal Amazon)

  [ Cancel ]
```

---

## 15. Key UX Rules & Constraints

1. **Never show the raw RMS or any raw key material** in any screen, ever.
2. **Passwords are always masked by default.** Reveal is always opt-in per interaction.
3. **Clipboard always clears** after the configured delay (default 30s). Always show a toast countdown.
4. **No master password field exists anywhere** in the app — if any designer generates one, it is incorrect.
5. **All destructive actions** (revoke device, delete vault, delete item) require a typed confirmation or secondary biometric step.
6. **Session timer is always visible** when unlocked — users must never be surprised by an expiry.
7. **Biometric prompts are not custom dialogs** — they use the OS native biometric UI where possible (Windows Hello overlay, macOS Touch ID sheet). VELA's UI shows a waiting state while the OS prompt is active.
8. **Sync errors do not block vault access.** The user can use a local-only mode when offline, with an unobtrusive sync-error indicator.
9. **No onboarding tooltips or coach marks** after initial setup. The app is used by security-conscious users who prefer clean UI.
10. **Keyboard navigation is first-class.** Tab, Enter, Escape, and arrow keys must work throughout. Global shortcut `Ctrl+Shift+V` / `Cmd+Shift+V` opens the quick-search overlay from anywhere on the OS.

---

## 16. Quick-Search Overlay (Global Shortcut)

Triggered by `Ctrl+Shift+V` / `Cmd+Shift+V` from anywhere on the OS — a floating mini-window appears above all other windows:

```
  ╔═══════════════════════════════════════╗
  ║  🔍  Search vault…                    ║
  ╟───────────────────────────────────────╢
  ║  [🔑]  Amazon         amazon.com      ║
  ║  [🔑]  Apple ID       apple.com       ║
  ║  [📝]  AWS Notes                      ║
  ╚═══════════════════════════════════════╝
```

- Appears anchored to the bottom-center of the primary monitor.
- Escape closes it.
- Arrow keys navigate items. Enter copies the primary field (password for logins).
- If session is locked, this overlay shows the biometric prompt first.
- Does not require the main window to be open.

---

## 17. Error & Edge Case Screens

### 17.1 No Network / Server Unreachable

```
  ⚡  Offline mode

  VELA can't reach the sync server. Your local vault is still available.
  Changes will sync when the connection is restored.
```
Small persistent indicator in top bar. Vault remains fully usable.

### 17.2 Hardware Enclave Unavailable

```
  ⚠  Secure hardware unavailable

  VELA requires a TPM 2.0 chip or equivalent hardware security module
  to store your keys. None was detected on this device.

  VELA cannot run in software-only mode on desktop.

  [ Learn more ]   [ Quit ]
```
Hard stop — no fallback on desktop.

### 17.3 Extension Fallback Warning (Extension-Side, shown in extension popup)

If the browser extension is operating without the native desktop daemon (WASM fallback mode), the VELA extension popup shows a persistent banner:

```
  ⚠  Reduced security mode
  Desktop app not found. Your vault key is in browser memory.
  Install the VELA desktop app for full protection.
  [ Learn more ]
```

This is extension-side UI, included here for completeness.

---

## 18. Accessibility Requirements

- All interactive elements must meet WCAG 2.1 AA contrast ratios.
- Biometric prompt states must include text labels (not icon-only).
- Focus ring must be clearly visible on all interactive elements.
- Screen reader labels required on all icon buttons.
- Masked password fields must have ARIA label "Password, currently hidden. Press to reveal."
- The session countdown timer must be announced by screen readers at the 5-minute and 1-minute marks.

---

## 19. Animation Principles

- **Duration:** 150–300ms. No animations longer than 300ms for navigation transitions.
- **Easing:** `ease-out` for elements entering the screen; `ease-in` for elements leaving.
- **No decorative animation.** Every animation communicates state: sync ring = working, pulse = awaiting input, shake = error.
- **Reduce motion respected.** When OS reduce-motion is enabled, all transitions are instant cuts.

---

*End of VELA Desktop App UX Design Instructions v1.0*
