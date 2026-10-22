# Android Instrument interface

The Android app uses the Instrument design (direction 04) across its Compose
screens and its system surfaces. Unlike the desktop preview, this is a direct
restyle: there is no `--ui=` switch, because Android has no classic shell left
to fall back to. The vault format, sync, autofill decisions and passkey logic
are unchanged.

## What changed

- **Screens** (`androidVELA/app/src/main/java/com/vela/android/ui/screens/`):
  overview, vault browser, item detail, generator, More, settings, unlock, and
  the `InstrumentScreens.kt` layouts used by devices, activity, sharing and
  breach watch. Navigation is Overview · Vault · Generate · More, with the same
  destination graph as before.
- **Components** (`ui/components/`): one shared button, text field, card,
  segmented control, status badge, top bar and `Instrument*` primitives
  (dot-matrix labels, sunrise artwork, brand mark). No screen keeps a private
  copy of these styles.
- **Overview** follows the mobile reference: time-of-day greeting, the quiet
  sync line beside the wordmark, the attention card with a real weak/reused
  password count, and a `Recently opened` list ordered by actual opens (a small
  preference store, not the audit log). The favourites/generate tiles share
  one height.
- **Navigation** is the floating pill dock from the reference, with icons above
  the labels and a filled active entry. It is the same composable in the app
  shell and in the review screen. More groups its rows into bordered sections
  with hairline dividers instead of one card per row.
- **Theme** (`ui/theme/`): Night, Paper, Catppuccin Macchiato, Catppuccin
  Latte and Gruvbox, plus "System" which follows the OS light/dark setting.
  `VelaTheme` now also supplies the palette's `TextPrimary` as Material's
  default content colour, so uncoloured `Text` no longer renders black on a
  dark surface (that bug affected More row titles, generator toggle labels and
  parts of Settings).
- **Autofill** (`autofill/VelaAutofillService.kt`,
  `res/layout/autofill_dataset.xml`, `res/drawable/autofill_bg_*.xml`): the
  suggestion card shows the VELA mark, title, masked subtitle and a mono VELA
  badge. It follows the saved theme (or the OS setting for "System"), not a
  fixed light palette. Field matching, browser allowlists, save prompts and
  redaction are untouched.
- **Passkey approval** (`ui/components/CredentialConfirmation.kt`,
  `security/passkey/PasskeyPromptActivity.kt`): sunrise header, mono eyebrow,
  "requested by" card, approve/cancel pills, error and busy states. Origin
  checks, the approval step and biometric/PIN verification use the existing
  code paths.
- **Item sheets**: the production add/edit routes open the shared Instrument
  sheet over the current screen. The debug review calls the same `AddItemScreen`,
  including its password generator, TOTP scanning controls, card CVV/PIN and notes.
  Existing richer-vault write guards and item metadata are retained.
- **Direct sharing**: the real sharing flow uses the Instrument item picker and
  share sheet, retaining Android's recipient **user ID** and existing send API.
  Share-link and permission controls in the synthetic design review are concepts;
  they do not add an Android share-link backend.
- **Motion**: staggered screen arrivals, press feedback, animated toggles and dock
  selection, a rotating generator action, readout transitions and sheet entrances.
- **Android-only settings** stay available under More → Settings: autofill
  service and trusted browsers, passkey provider selection, sync, recovery,
  devices and web access.

## Refinements after device review

- The dock has an explicit label line height and a 3dp icon gap, avoiding the
  large inherited body-text line box.
- Add/edit opens the same generator as the Generate tab in a dedicated sheet,
  with the visible coloured readout, regenerate/copy actions, passphrase mode,
  all four character groups and an explicit use action.
- Login details expose **Autofill in apps** near the heading. The installed-app
  picker retains signing-key verification and removable links; the debug review
  exercises the same UI using in-memory assignments. Editing a login preserves
  its `appIds`.
- Delete is visible in the details header and has a confirmation sheet. The
  review can delete its example items too.
- Settings uses a two-column theme grid and grouped timing rows with choice
  sheets. System, Gruvbox and the Android provider/trust/sync settings remain.

## Launcher and startup

The launcher, themed launcher icon (Android 13+), and autofill/passkey provider
badge share Instrument's dotted violet V. The launcher uses adaptive resources
for all densities, with every dot inside the 66dp safe circle.

MainActivity uses a native branded starting window: Night background, dotted V,
and an Inter wordmark derived from the bundled licensed font. Android 12+
reveals the dot rows and fades into the real first frame; Android 8–11 uses the
same static artwork. No timer holds startup open. The normal Compose theme and
vault screenshot protection remain active after launch.

Preview the actual startup artwork without opening a vault:

```sh
adb shell am start -n com.vela.android/.InstrumentReviewActivity --es surface startup
```

## Collections and richer items

The Android app now writes richer vaults (schema 2) instead of being
read-only:

- **Collections** on the vault screen opens a manager for nested folders and
  tags. Create, rename, move, and delete; deleting a folder or tag keeps its
  items and clears the stale reference.
- **Filtering** is a folder (optionally including subfolders) or a tag, applied
  on top of search and type filters.
- **Editing** covers folder, tags, custom fields (text, concealed, boolean),
  additional URLs, and identity details (contact fields and addresses).
  Unknown record types are preserved and shown read-only.
- **Enabling** collections saves an encrypted safety copy, turns on the shared
  server write-version gate, and then switches the local vault to schema 2.
  Validation, merge and repair run in `vela-core` through the JNI bridge, so
  mobile and desktop cannot disagree about names, cycles or tombstones.

Older clients still preserve the data they cannot edit. iOS and browser
access remain read-only until their own editors ship; the extension's
autofill path already reads cards, identities and richer address data.

## Build and install

```sh
cd androidVELA
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`local.properties` must point `sdk.dir` at an Android SDK with platform 35 and
the NDK used by the Rust bridge; the bridge is built by Gradle.

## Review screens without a real vault

`app/src/debug` contains `InstrumentReviewActivity`, which renders the
production components with synthetic data. It is not part of a release build.

```sh
adb shell am start -n com.vela.android/.InstrumentReviewActivity --es surface vault
```

`surface` accepts `overview`, `vault`, `detail`, `generate`, `more`, `settings`, `lock`,
`autofill`, and for the passkey sheet `passkey`, `create`, `error` or `working`.
The in-app bottom bar navigates between the four main tabs; the passkey
variants show the approval, error and busy states. Nothing on that screen
touches a vault, an account or a credential.

The real app keeps `FLAG_SECURE` on vault screens, so device streams and
`screencap` show black there by design. Use the review activity for visual
checks, or drive the real app through accessibility.

## Verification

- 119 JVM unit tests pass (`./gradlew :app:testDebugUnitTest`).
- Sign-in and create passkey sheets, autofill cards, overview, vault, detail,
  generator, More, settings and lock were rendered on an Android 17 (API 37)
  x86_64 emulator in Night and Latte.
- Final production smoke check on the laptop emulator: created and unlocked a
  local password vault, opened the real add sheet, generated a password, saved
  a login, reopened and edited it, and opened the direct-share sheet. No share
  was sent. The suggestion and passkey visual checks used synthetic data.
- Earlier emulator crashes during this work were host-side QEMU faults in the
  device's gRPC streaming path, not app crashes; the same screens render on a
  second host without them.

The UI verification build reused the existing JNI libraries:

```sh
./gradlew --no-daemon :app:assembleDebug :app:testDebugUnitTest -x buildRustBridge \
  -Pkotlin.compiler.execution.strategy=in-process
```

This verifies Kotlin/Compose, resources, packaging and JVM tests; it is not a
fresh Rust bridge build or an end-to-end passkey ceremony test. Android controls
its own credential chooser and biometric prompt; VELA styles its suggestion
rows and approval screens.

## Rollback

There is no data migration for the visual changes. Review the Android diff and
revert only the presentation changes you intend to remove. This checkout also
contains independent richer-item and sync work; do not restore whole directories
or `MainActivity.kt` wholesale, because that would discard those changes too.
