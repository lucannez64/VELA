# Animated GPUI Instrument preview

Direction 04 is available as an opt-in native GPUI interface. The classic
interface remains the default for installations without a saved preview choice.

From `desktopVELA`:

```sh
# Disposable local vault with fake items and activity history
cargo run -p vela-desktop-gpui -- --demo --ui=instrument

# Normal vault, with the existing authentication and session handling
cargo run -p vela-desktop-gpui -- --ui=instrument

# Force the original interface
cargo run -p vela-desktop-gpui -- --ui=classic
```

The executable is named `vela-desktop`; the same flags work on a built binary.
`VELA_UI=instrument` is an alternative to the CLI flag. CLI takes precedence
over the environment, which takes precedence over a remembered interface choice.

Press **Ctrl+Alt+U** to switch between interfaces without restarting. The More
sheet also has a Classic interface action. Switching reconstructs the shell,
so navigation, search, selection and open editor state are reset. Save edits
before switching. Runtime choices are remembered in `ui-preview` beside the
vault store; switching to classic removes that file. A CLI override only
applies to that launch. Demo mode does not remember interface choices.

For a lasting rollback, switch to classic with Ctrl+Alt+U or More → Classic interface.
`--ui=classic` always forces classic for the current launch. No vault format
migration is involved.

## Implemented

- Compact Instrument window title bar with dot-matrix VELA branding, live session
  status/countdown, lock action and outline window controls. Dragging and double
  click to maximize work on the title bar. Ctrl+Alt+U also switches its design.

- Native sunrise painting, radiating lines and dot-matrix glyphs.
- Staggered tile entrances, animated counters and health gauge, detail entrance
  and generator readout animations. Set `VELA_REDUCED_MOTION=1` to shorten them.
- Overview derived from vault items and the encrypted activity log: counts,
  password reuse, strength, age, favourites, 2FA, health and activity heatmap.
  Health means logins without weak, reused or old passwords divided by logins;
  it does not represent protection against every security threat.
- Virtualized vault list with name/username/URL search, type and risk filters,
  favourites and sorting. Details include reveal/copy, favourite, share, edit,
  confirmed delete and live TOTP codes. Secrets are concealed on selection
  changes and data reload; leaving the vault stops its TOTP task.
- Password generator using the existing core implementation and entropy result.
- Dedicated lock screen with sunrise artwork and a password/biometric unlock
  card, using the existing authentication, retry and lockout handlers.
- Devices with dot-matrix counts, access cards, enrolled/active metadata and
  connected enrollment, web-access and revoke-confirmation controls.
- Activity with a real 14-day chart, category filters and a virtualized timeline.
- Settings follows the reference's single scrolling document: General, Security,
  Sync, Browser extension, Recovery, Backup & export and Danger zone. Section
  links scroll to their cards. Full theme previews, compact segmented options,
  switches and action rows use the existing persistence and confirmation paths.
- Add/Edit Item uses a right-hand drawer, with an initial four-card type chooser
  for new items, redesigned inputs, and fixed header/footer around scrolling
  rich fields. Dialogs have short entrance animations that respect reduced motion. Enrollment uses the same dialog chrome around the real v3 QR,
  manual enrollment code and fingerprint verification. Web access has compact
  duration/access choices and preserves the real grant command.
- Sharing has equally visible **Share with a VELA user** and **New share link**
  actions. Both open their own labelled item picker and continue to the existing
  recipient invitation or expiry/passphrase flow respectively.
- Sharing has the reference's Links / Sent / Received tabs, item rows,
  active-link sunrise card, VELA ID card and real create/accept/decline/revoke
  actions. Breach watch has dedicated monitored-email and password-check cards
  and retains its real email/password checking and add-email flow.
- The item editor retains its existing implementation.
  Existing clipboard expiry, auto-lock, authentication and synchronization
  paths remain in use for normal vaults.
- Night, Paper, Catppuccin Macchiato and Catppuccin Latte theme previews.
  Paper uses the existing persisted `light` setting; classic mode still maps
  that value to its original light palette. Gruvbox remains available in classic.
  Wide windows use a labelled rail
  and side-by-side details; smaller desktop windows use an icon rail and an
  overlaid detail sheet. Below 760px the rail yields to the bottom dock.
  The rail uses the local reference SVG outline icons and a profile footer.
  The floating Overview / Vault / Generate / More dock is visible at every
  size; More opens the reference-style profile card and grouped navigation.
  The profile page shows actual account identity and vault counts.
  Overview tiles stack when the health panel cannot fit. Detail-sheet controls
  block clicks from falling through to the dismissing backdrop.

The separate HTML prototype has additional layouts and interactions. Native
collection/bulk controls are not implemented in this preview. Use the classic UI for collection navigation and the existing editor
for rich fields; the new detail renderer currently shows the main item fields.

## Demo isolation

`--demo` creates a disposable encrypted store in a unique temporary directory,
with fake `.example.test` credentials, a test card, notes, identity, folders,
tags, activity entries and explicitly labelled demo device cards. It bypasses
normal startup authentication and does
not start sync, the IPC host or quick-search integration. Edits apply only to
the disposable vault. A restart creates a new demo; normal exit removes its
store. After locking a demo, restart with `--demo` to open a fresh vault.
Secondary screens still use real application views, so network actions
are not simulated as they are in the HTML prototype.

## Verification

Native screenshots and interaction checks under headless gamescope/Xwayland
covered 1440×900, 1024×720 and 390×820: overview, scrolling, vault filtering, details,
TOTP, generator, existing editor, runtime classic/Instrument switching and
Ctrl+K search. The normal-size check exposed a clipped health panel; the
layout now stacks earlier. Follow-up native checks covered the bottom dock,
More menu, Devices, filtered Activity, Settings and the new lock screen.

The revised GPUI run passes 58 tests, including reveal/copy/hide/close at
390/1024/1440px, device revoke confirmation, activity filtering, Settings
section jumps, aligned columns for varied item names, Sharing tab/picker
controls, Breach form opening without network requests, and lock-screen reveal
without starting authentication. The existing
`views::app_shell::organization_tests::collections_use_sidebar_on_desktop_and_header_on_small_windows`
is excluded because it stalled in the earlier full run. The build succeeds
with existing warnings. This is not a completed native accessibility or
Hyprland acceptance pass; real-vault interaction should be reviewed locally
using the opt-in flag.

The native auto-lock implementation clamps idle limits to 1 minute–1 day,
so its final option is **1 day**, rather than the HTML study's unsupported
**Never**. Clipboard clearing supports **Never**. Recovery rows display actual
setup state rather than the study's synthetic contact/server-share data.

Follow-up dialog checks cover drawer geometry at 390/945/1440px, fixed actions
while scrolling, both sharing entry points and their options, enrollment stages
in both interfaces, and web-access mode/empty-code validation. These checks do
not send invitations, publish links, or approve a real device/browser session.

Native follow-up captures at 945×1025 cover the new type chooser, editor form,
direct invitation options, link options, and web-access dialog.

The editor's embedded password generator uses the Instrument readout, entropy
meter, length presets, character/easy-to-type pills and Use action. Its classic
layout remains available in classic mode. Sharing-picker highlights follow
pointer hover as well as keyboard movement; dialog actions have hover feedback.
Regression checks cover row hover and generator options/Use at 320px width.
