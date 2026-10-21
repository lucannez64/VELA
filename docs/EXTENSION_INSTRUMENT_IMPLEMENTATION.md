# Extension Instrument UI

The live extension now uses the visual direction in `extension-redesign-instrument.html`.
It ships by default; the earlier concept files remain design studies.

Implemented surfaces: site matches and account search, generator and passphrase
controls, alias-provider and site settings, a floating navigation dock, four
remembered themes, login/card/identity dropdowns, the explicit TOTP chooser, account
selection, save/update topbars, review dialogs, and the in-page generator/alias UI.
All fonts and icons are bundled. No remote font service is used. Hover, focus,
entrance and readout transitions respect `prefers-reduced-motion`.

The popup has Logins, Cards and Identities filters. Login search covers this
website's matching accounts; card and identity search covers saved items of the
selected type. Card and identity suggestions open on field focus using metadata
only. Clicking a field icon keeps its chooser open, including clicks on nested
SVG elements. Full details are requested only when a suggestion or popup filter
is selected. Open Vault opens the complete desktop vault.

Identity autofill releases names, email, phone, company and postal addresses.
Each saved address is a separate choice. SSNs, notes and custom fields are
excluded by the desktop before IPC release. Identity fields use standard
HTML autocomplete tokens and common name/address attributes. Plain login
emails retain login suggestions. Hidden, disabled and read-only fields are
skipped; form and shipping/billing sections stay separate.

Cards show masked numbers in the popup and support cardholder, number, CVV,
combined expiry, month inputs and split month/year inputs or selects. PINs are
excluded by the native host. Popup fills resolve the selected ID through the
native host again and refuse a changed active page.

Identity support needs both the rebuilt desktop and native messaging host.
Build from the repository root:

```sh
cargo build --manifest-path desktopVELA/Cargo.toml -p vela-desktop-gpui -p vela-nm-host
```

Use the resulting `vela-desktop` and `vela-native-messaging-host` binaries and
point the existing browser host registration at the new host as described in
`extension/README.md`. Then reload the extension. An older host will continue
to support cards but cannot answer identity requests.

## Build and load

From `extension/`, run `node build.js` (or the existing Bun build script).

- Chrome/Chromium: Load unpacked `extension/dist/chrome` from the Extensions page,
  or Reload that extension if this directory was already loaded.
- Firefox: use `about:debugging` → This Firefox → Load Temporary Add-on and choose
  `extension/dist/firefox/manifest.json`. The build also writes the unsigned
  `extension/dist/vela-firefox.xpi`. Ordinary permanent Firefox installation still
  requires the project's signing workflow.

## Local interaction fixture

Run `node scripts/ui-preview-server.cjs` after building. At
`http://localhost:8877/popup/popup.html` or `/content-test.html`, production UI
scripts run against synthetic browser/native responses. `?state=locked`,
`?state=offline`, and `?state=empty` exercise popup states. This harness and its
fake data are not packaged in the extension.

Paste `scripts/ui-smoke-checks.js` into the fixture's console, then run
`await runVelaUiChecks()`. Reload between runs. It covers navigation, search,
copy, generator modes and length, themes, passive secret-fetch boundaries, focus-triggered suggestions and nested icon clicks,
TOTP/card/identity selection and fills, save dispatch, never-save confirmation and
persistence, and generator use without a stale dropdown overlay.

Verification also runs the existing RFC6238, host-risk and passkey-shim scripts,
checks both package manifests/resources, and lints the Firefox package. Native
messaging in an installed browser, biometric prompts and signed installation
still need a real-browser acceptance check.

The Firefox package lint reports zero errors, with warnings about minimum-version
API compatibility and dynamic HTML assignments. UI tests use synthetic native
responses. The native host integration test separately runs the real host and
desktop IPC server against a temporary vault, covering cards and identities,
response whitelists and the browser-ancestry gate.

The final synthetic-browser smoke run passed 62 assertions across popup and
content views, with no browser exceptions. Existing tests passed all six
RFC6238 vectors, eleven host-risk cases, and ten passkey-shim checks. Both
build targets contain their referenced assets, five bundled font files and
three font licenses; test fixtures are excluded. Firefox XPI ZIP integrity passed.

`node scripts/vault-autofill-test.cjs` checks the real background handlers for
active-tab/origin/frame authorization, native item ID resolution, and page
changes during native lookup. Desktop autofill tests cover identity whitelisting,
passive metadata, locked sessions and existing card/login behavior.

The action popup pins its root and body to 380 × 600 CSS pixels. Its intrinsic
width does not depend on Chromium’s initial popup viewport.


## Vault editor and collections

More → **Folders, tags & rich items** opens a dedicated extension tab. It manages
nested folders and tags, filters items and applies folder/tag assignments to a
selection. Login, card, note and identity editors include typed custom fields,
additional websites and multiple postal addresses. Unknown rich-record
properties survive edits. Passkey private keys never leave the native process;
other item types can be organized through the list without a credential editor.
Received shares remain read-only.

The background accepts management requests only from the exact extension editor
page, with its own extension sender ID. The native host uses the existing kernel
peer gate; the credential provider cannot use this route. Native approval is
required before reading one item or mutating the vault. List replies contain
only an allowlist of metadata; plaintext reads require a durable activity-log
entry and consume the per-unlock release budget. Editor credentials are never
stored in extension storage and clear after two idle minutes or page exit.

Additional URL records are editable storage; destination-specific autofill
release rules remain in force. Use the local-only synthetic UI fixture with
`node scripts/manager-preview.cjs` for browser interaction checks; it is excluded
from extension builds. Install the matching desktop and native host before using
the production editor.
