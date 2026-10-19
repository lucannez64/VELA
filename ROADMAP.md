# VELA 1.0 Roadmap

Status: draft, 2026-09-29.

VELA's *feature* surface is already 1.0-sized: the whole
`## [Unreleased]` block in `CHANGELOG.md` is the product (vault, sync, ORAM,
PQ hybrid auth, recovery, sharing, passkeys, autofill, ephemeral web, rekeying).
There is no separate feature roadmap because features are not the gap.

This document tracks what actually stands between the current tree and a
declared **1.0**: making the thing a signed, updatable, store-listed,
policy-covered artifact rather than a set of source trees plus CI releases.

Everything below is currently *absent* from `SPEC.md`, `CHANGELOG.md`,
`README.md`, `docs/INSTALL.md`, `SECURITY_AUDIT.md`, `SECURITY_REDTEAM.md`,
and `.github/workflows/`. When an item lands, move it into `CHANGELOG.md`.

---

## Definition of 1.0

A release is 1.0 when:

- [ ] Every install path ships **signed, notarized** binaries.
- [ ] There is an **auto-update** channel for desktop, mobile, and extension.
- [ ] Every artifact has **checksums + an SBOM + a provenance attestation**.
- [ ] Desktop, Android, extension are available from **first-party stores**,
      not only sideloading.
- [ ] Root **security policy, privacy policy, and disclosure contact** exist.
- [ ] Version numbers are real **semver**, decoupled from commit count.
- [ ] A user who loses a device has **documented, tested recovery**.

---

## P0 — Release integrity

### Signing & notarization

- [ ] **Windows Authenticode** for the MSI, NSIS `.exe`, and the passkey MSIX.
      `desktopVELA/src-tauri/tauri.conf.json` still has
      `"certificateThumbprint": null` and `"timestampUrl": ""`; the GPUI
      packaging path in `.github/workflows/release-desktop.yml` signs nothing —
      `desktopVELA/vela-win-passkey/msix/register-dev.ps1` signs only locally
      with a dev PFX. Use Azure Trusted Signing or an EV cert and timestamp all
      outputs, or SmartScreen will flag every install.
- [ ] **Apple notarization + hardened runtime** for the macOS bundle
      (`.github/workflows/desktop-macos.yml`) and the iOS app
      (`.github/workflows/ios-app.yml`). `CODE_SIGNING_ALLOWED: NO` is fine for
      CI, never for a ship build.
- [ ] **Linux**: sign the `.deb`/`.rpm` (and the AUR `sha256sums` already
      handled in `release-desktop.yml`), publish the signing key.

### Auto-update

- [ ] **Desktop updater.** No update mechanism exists anywhere: no
      `tauri-plugin-updater`, no Sparkle/WinSparkle, no MSIX update path. Add a
      signed-manifest update channel (Tauri updater for the fallback, an
      equivalent for the native GPUI front end) with signature verification and
      rollback.
- [ ] **Android**: in-app update or Play-managed update path.
- [ ] **Extension**: publish to stores so browser auto-update applies
      (currently `extension-release.yml` publishes only to GitHub + unlisted
      AMO).
- [ ] Document the **update trust model** (who can sign a release, key custody).

### Supply chain & provenance

- [ ] **SBOM** per release (e.g. `cargo sbom` / `syft`), attached to the GitHub
      release.
- [ ] **Checksums + signatures** for every artifact, published in the release.
- [ ] **Provenance attestation** (SLSA-style / `actions/attest-build-provenance`)
      so a download can be tied back to the commit and workflow.
- [x] Publish a **`security.txt`** at `.well-known/security.txt`.
      Done 2026-09-29; email/PGP fields still placeholders.

---

## P0 — Store presence

`docs/INSTALL.md` states plainly: *"everything below is self-hosted and
sideloaded. There are no store listings yet."* This is the largest single block
of 1.0 work.

- [ ] **Chrome Web Store** listing for `extension/dist/chrome`.
- [ ] **Microsoft Edge Add-ons** listing.
- [ ] **Firefox AMO** — promote from `--channel unlisted` to a public listing in
      `.github/workflows/extension-release.yml`.
- [ ] **Google Play** listing for `androidVELA` (release signing already exists
      via `ANDROID_KEYSTORE_BASE64` in `release-android.yml`).
- [ ] **Apple App Store** listing for `iosVELA`.
- [ ] Store-required artifacts: **privacy policy URL**, **data-safety /
      nutrition-label** declarations, per-permission justifications, screenshots.
- [ ] Remove or justify unused extension permissions before review
      (`extension/manifest.json`).
- [ ] **macOS desktop** distribution decision: notarized download vs. MAS build.

---

## P1 — Legal, disclosure, governance

- [x] **Root `SECURITY.md`** with a coordinated-disclosure process and contact.
      Done 2026-09-29; the reporting email is still a placeholder pending a
      project domain.
- [ ] **Privacy policy** (required by every store; must state what the server
      sees even though the vault is zero-knowledge).
- [ ] **`CONTRIBUTING.md`** and **`CODE_OF_CONDUCT.md`**.
- [ ] **License consistency**: root says MIT (`LICENSE`, `README.md`), but the
      AUR `PKGBUILD` generated in `release-desktop.yml` declares
      `license=('custom')`. Align these and add SPDX headers.
- [ ] **CVE / vulnerability response process** (who triages, SLA, advisories).

---

## P1 — Product parity & UX

- [ ] **Printable / offline recovery kit.** The 2-of-3 Shamir setup exists, but
      there is nothing that generates a paper or PDF emergency kit. Users will
      lose shares without one.
- [ ] **Localization / i18n framework.** No i18n infrastructure anywhere; all
      strings are hardcoded across the GPUI, Tauri/React, Android, and iOS
      front ends.
- [ ] **Accessibility pass** — keyboard navigation and screen-reader support,
      especially for the native GPUI front end (`desktopVELA/src-gpui/`).
- [ ] **User-facing documentation / help center / onboarding.** `docs/` is all
      maintainer material; `docs/INSTALL.md` is a developer guide. Add a
      "what happens if I lose my phone" guide and in-app onboarding beyond the
      account/recovery prompts.
- [ ] **Client capability-parity matrix**, so gaps like extension TOTP are
      tracked rather than discovered by users.

---

## P2 — Operational

- [ ] **Semver.** Every release workflow derives `0.1.<commit-count>`
      (`release-desktop.yml`, `release-android.yml`, `extension-release.yml`);
      `tauri.conf.json` is `0.1.0`; the extension manifest is `1.0.4`. Move to
      real semver with a separate **protocol version** field for `SPEC.md`
      compatibility, and a documented support window.
- [ ] **Completed-release changelog.** `CHANGELOG.md` has a huge `[Unreleased]`
      block; cut it into a dated `1.0.0` section as part of the release.
- [ ] **Fix doc drift**: `README.md` / `docs/INSTALL.md` tell users to copy
      `serverVELA/.env.example`, but no `.env.example` exists in the repo.
- [ ] **Release notes / support channel** — a place users can report bugs and
      see known issues.
- [ ] **Backup/restore drill** documented and exercised for the server
      (`migrate export|import`) and for client vaults.

---

## Explicitly out of scope (deliberate positions — do not "fix")

- **No telemetry or crash reporting.** Correct for this product; keep it and
  state it in the privacy policy.
- **Side-channel and rubber-hose resistance** remain out of scope per
  `SPEC.md` §9 "Out of Scope (v2.0)"; reference that in the disclosure docs
  rather than silently changing it.

---

## Notes on How to Use This File

- Ordered by priority within each section; P0 items gate the 1.0 tag.
- Each item names the file(s) it touches so it can be picked up cold.
- When an item ships, delete it here and add it to `CHANGELOG.md`.
