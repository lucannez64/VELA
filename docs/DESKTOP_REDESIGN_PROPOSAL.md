# Current direction: 04 — instrument

Open `desktop-redesign-direction-04.html` for the standalone HTML prototype.
An opt-in animated GPUI implementation is now available; see
[GPUI preview instructions](GPUI_INSTRUMENT_PREVIEW.md) for its implemented
scope, testing and rollback. Directions 01–03 remain for comparison.
The flows below describe the HTML prototype.

## Why a fourth direction

Direction 03 took the calm parts of the ten reference shots (pearl surfaces, citron, rounded modules) and set aside their signature elements. Direction 04 adopts those elements and gives each one a password-manager job:

- Dot-matrix numerals (wellness dashboard): item counts, health score, one-time codes, generator entropy. Rendered by a 5×7 dot font drawn in SVG, with no external font.
- Violet → ember sunrise, grain and radiating lines (Sovra): the vault hero tile and the gradient brand mark. The hero stays dark in both themes, like Sovra's split poster.
- Mono metadata, `01 / VAULT` section numbers, severity tags, a tinted "noticed" card, timeline and heatmap (Halden): security issues, breach watch and activity.
- Thin gauge with ticks and dotted bars (Soma): vault health and password age.
- Pill controls, floating pill dock on phones, lime signal colour (editor, Soma, Halden).

Every figure is computed from the fake items: health = logins with no issue ÷ logins. Issues (exposed, reused, weak, over a year old) come from item data. Reuse is detected by comparing passwords, not by a stored flag.

## Working flows

Overview bento → Review an issue → item details explain why → "Generate a new password" → "Use for <item>". The issue clears, the health score and counts update, and the activity entry appears. Also covered: search (jumps to the vault), type tabs, at-risk filter, sorting, favourites, reveal, live one-time code with countdown ring, generator (length and character sets, entropy computed from the pool), simulated breach check, Night/Paper themes, keyboard list navigation, Ctrl K, Esc, and reset. Secondary screens, all reachable from the rail on desktop and the More sheet on phones, use the same instrument language and the real app's feature set:

- Sharing: tabs for links, sent and received. Links show time left as a dotted bar, one-view and passphrase tags, copy, and two-step revoke. "New share link" (also the share button on any item) picks an item, expiry, one-view and passphrase, then shows the ready link. Received shares can be accepted, which adds the item, or declined. Your VELA ID is shown with a copy button.
- Devices: device cards with access level, last active and two-step revoke; revoked devices can be shown. "Enroll new device" shows a dot-matrix one-time code with a 5-minute ring, then a verification code to compare and an access choice. Temporary web sessions have a time-left bar and revoke. "Approve web access" takes a code, a duration, and read-only or read-write.
- Activity: a day-grouped encrypted log with category filters, a 14-day dot chart and counts by kind. Every action in the prototype writes to this log, and the overview tile reads from it.
- Settings: a section index (General, Security, Sync, Browser extension, Recovery, Backup & export, Danger zone). Segmented choices and switches save and log a change; Sync now, security key, key rotation and backup run demo actions. Deleting the vault requires typing DELETE.
- Profile: an identity hero with VELA ID and live counts; sign-in and unlock methods; the contact public key; a session summary; sign out.

- Item editor: a right-hand drawer on desktop and a full screen on phones. It opens from "New item" (or + in the vault header on phones) with a type picker, and from the pencil button on any item for editing.
  - Login: several websites, username, and password with show/hide and the generator, which fills the field directly. A live strength meter shows estimated bits and warns when the password matches another login. A two-factor setup key shows a dot-matrix code preview.
  - Card: a live card preview that detects the brand and masks the number, plus a card-number check, expiry and concealed security code.
  - Note and identity: their own fields.
  - Every type: folder (with suggestions), favourite, tags (Enter or comma to add, Backspace to remove), custom text or hidden fields, and notes.
  - Saving: the name is required. The footer shows unsaved changes, and Ctrl S saves. Closing or pressing Esc with unsaved edits asks before discarding. Deleting an existing item takes two steps.
  - Saved items appear in the vault, details, health and activity log.
- Themes: Night, Paper, Catppuccin Macchiato and Catppuccin Latte, picked from the palette button, the More sheet or Settings → Appearance. The choice is remembered in this browser. Every colour, including the sunrise, dot-matrix gradient and pixel cluster, comes from theme variables. The Catppuccin themes use the official palettes (mauve primary, green signal, red risk, peach warning); Latte keeps a Macchiato-coloured hero, the same way Paper keeps a dark one.

Copy, lock, export/import and passphrase change only show a toast.

Layout: ≥1240px full rail with side-by-side details; 760–1240px icon rail with a slide-in detail sheet; <760px single column, full-screen sheet and floating dock. On phones the dock is Overview · Vault · Generate · More. More (also opened by the avatar in the top bar, or by the profile card on desktop) is a bottom sheet with the profile, Favourites, Needs attention, Generator, Sharing, Devices, Activity, Settings, theme and Lock vault, so every rail destination is reachable on every size. The badge on More shows the at-risk count.

Verification: 115 scripted Playwright checks at 1440, 1024 and 390px (flows above, no horizontal overflow, no console errors), plus visual review of the overview (dark/paper), vault, generator, tablet sheet and phone sheet. This is prototype validation only; GPUI has no SVG circle-grid primitive, so the dot font would need a small custom element in a native implementation.

Revert by deleting `desktop-redesign-direction-04.html` and this section.

---

# Current direction: 03 — soft structure

Open `desktop-redesign-direction-03.html`. This is a standalone interactive proposal using fake data, not a native GPUI redesign. Directions 01 and 02 remain available for comparison. No app, vault, or schema code changed in this iteration.

## Reference interpretation

The user supplied eleven screenshots after the linked Dribbble pages could not be loaded. These images, rather than inferred page descriptions, are the visual basis for this iteration.

- Soma close-ups and the foldable device composition: pearl surfaces, pale citron accents, delicate dividers, fine secondary labels, strong numeric/type hierarchy, large rounded modules, and restrained concentric geometry. Applied to the workspace, pinned credentials, and password action surface. Health charts and sensor graphics were not repurposed as unsupported security statistics.
- Sovra branding: confident wordmark scale, dark framing, careful negative space, and concentrated color. Applied as a quieter dark outer frame and larger VELA wordmark. The proposal retains its original VELA mark; it does not copy Sovra's mark or its branding assets.
- Dark wellness and fraud-monitoring references: clear module hierarchy, small contextual metadata, and status tied to actions. Applied to the selected credential view and its copy/reveal controls, without invented protection percentages or AI alerts.
- Mindpalace, the editor, banking, and Steam examples: contained workspaces, rounded modules, a distinct navigation frame, and purposeful accents. Applied to the shell, drawer geometry, and a consistent set of pill/round controls. No promotional artwork or unrelated photography was added to a password-manager workflow.

## What changes from direction 02

The flat table treatment becomes a soft modular workspace. A dark labeled navigation frame surrounds an inset light workspace. Pinned credentials have their own useful shortcut surfaces; the library is a compact list inside a single rounded module. On wide windows, a selected credential gets a dedicated panel with a citron password surface and one clear Copy password action. On smaller windows, opening an item shows a detail sheet. Navigation becomes a drawer below 560px. Daylight and Dusk share the same geometry.

Typography uses embedded subsets of VELA's bundled Inter and Space Grotesk fonts. This prototype is self-contained and makes no external font, asset, or API requests. The rounded modules and pin cards deliberately introduce more visual structure than the prior flat table. Pinned items can be collapsed and row density can be reduced by the top grid button, so the appearance is reviewable alongside list capacity.

## Working prototype flows and limits

Search; folder/tag scoping; subfolder filtering; type filtering; name/recent sorting; pin/unpin; pin collapse; comfortable/compact density; Daylight/Dusk; item details; fake secret reveal; login/note create/edit; plain-text custom fields; draft protection with explicit discard; and reset. Copy and lock only show preview feedback; they do not access the clipboard or a real vault. Card and identity editors, concealed/typed custom fields, additional URL editing, collection CRUD, and full accessibility verification remain native implementation work.

Browser checks at 1100px, 945px, and 360px covered horizontal containment, library counts, folder/subfolder filtering, search and empty results, details, secret concealment on selection changes, editor initial focus, unsaved edit protection/discard, create/edit with a custom field, pinning, collapsed pins, compact density, Dusk mode, and reset. Inspected the default design at 1100px/728px, the dark detail sheet at 945px, and the editor at 390px. This is prototype validation, not native Hyprland verification. The prototype uses a fixed-height preview workspace; a native implementation must adapt to both available width and height.

## Reversibility

Remove only `docs/desktop-redesign-direction-03.html` and this direction note to discard this iteration. Keep the current app unchanged until a direction is selected. Native adoption should follow the opt-in presentation flag and shared-state approach described below. The experimental CLI flag remains a proposal and does not yet exist.

---

# Current direction: 02 — vault first

The first workspace proposal below is retained for comparison. The newer standalone prototype is `desktop-redesign-direction-02.html`. Neither changes the native app.

Direction 02 replaces the always-visible three-pane dashboard with a two-pane library and an on-demand detail/editor sheet. It adds an independent light/dark treatment, embedded subsets of VELA's existing Inter and Space Grotesk fonts, clearer item typography, comfortable/compact density, type tabs, sorting, and quick-copy previews. Search is persistent at the top. Folders and tags stay labeled on desktop; narrow windows use a navigation drawer. Common editor fields are visible, while organization and additional fields expand on demand. Unsaved edits require saving or explicit discard.

Prototype behavior: synthetic search/filter/sort/favorites; open/close/reveal; login/note creation and editing; plain-text additional fields; keyboard focus and navigation; and reset. Copy and lock only show feedback. No clipboard, real vault, server, sync, or encryption operation occurs. Card/identity editors, typed/concealed additional fields, folder/tag management, and a full accessibility audit remain outside this proposal. No experimental native CLI switch exists yet.

Verified browser checks at 945px and 360px: no horizontal page overflow, folder and subfolder filtering, search/empty results, detail opening, secret concealment on selection changes, editor focus, draft protection and discard, synthetic create/edit with an additional field, theme/density toggles, detail containment, and reset. Inspected the detail sheet at 728px and the editor at 390px. Native rendering still needs separate implementation and verification.

Revert this iteration by removing only `docs/desktop-redesign-direction-02.html` and this direction note. The original prototype remains available. If accepted, use the opt-in native rollout described below, with no schema or vault-data changes.

---

# Desktop vault workspace proposal

Status: reviewable prototype, not an implemented native redesign.

Open `desktop-redesign-proposal.html` in a browser. Everything runs locally with synthetic data held in memory. Reset or reload restores the initial data. Copy buttons preview feedback; they do not write to the clipboard. Lock and Settings show explanatory feedback. Card/identity editing and additional typed fields are layout placeholders rather than complete editors. No production files, accounts, vaults, schemas, or network APIs are changed by this prototype.

## Problems addressed

The existing 945px screenshot gives a small collection three visible item cards. Separate alphabet headings, large card gaps, and stacked collection controls consume the available height. Collapsing the navigation to unlabelled icons also makes folders and tags harder to discover.

The proposal uses a connected navigation/list/detail workspace. Organization remains visible; rows are 59px tall, separated by selection and hover rather than floating card surfaces. The selected item's credentials, reveal/copy actions, notes, and organization stay in a separate pane. Favorites appear first, then names alphabetically. The list has one type filter instead of a row of tabs whose widths depend on labels and counts. A compact subfolder checkbox stays beside that filter.

At 680px and above the workspace has three panes. Below that, the list fills the available width, labeled navigation becomes a drawer, and selecting an item opens a detail screen with an explicit back action. This breakpoint is a prototype choice to validate against GPUI font metrics and minimum useful pane widths. At 1050px and above the navigation and list gain width. Each pane scrolls independently; editor actions remain fixed at the bottom of the side sheet.

## Visual system for the native implementation

Keep VELA's existing palettes and bundled fonts, while clarifying their roles. Use Inter for navigation, labels, controls and row metadata, Space Grotesk for major headings, and JetBrains Mono for secrets. Use existing theme colors through semantic roles instead of hardcoding this prototype's green palette. Validate all four themes, especially focus, muted text, disabled controls, and selection contrast.

Use a consistent spacing scale of 4/8/12/16/24/32px. Regular actions are 32px high, primary editor actions 36–40px, form fields 36–40px, and list rows 56–60px. Reserve the mint fill for the main creation/save action; use a low contrast selected-row background, subtle borders between panes, and restrained surface levels. Reuse one set of native buttons, inputs, selectors, and focus treatments.

The editor puts the common fields first and organization second. Additional URLs and typed custom fields expand on demand. Keep Card and Identity sections appropriate to their type. Preserve drafts during responsive resizing, warn before discarding meaningful edits, and keep validation next to the relevant field. The prototype intentionally does not implement those complete native data flows.

Bulk selection should be an explicit Select action or modifier selection. Its contextual toolbar appears only while selecting. Folder/tag management belongs beside its navigation section, with contextual rename/move/delete actions; avoid permanently exposing management controls in the content header. These flows are follow-up native work, not demonstrated by the prototype.

## Reversible native rollout

1. Add an actual `--experimental-vault-ui` CLI switch. It does not exist yet. Keep the current vault view as the default and make the prototype-inspired view opt-in.
2. Implement a separate workspace renderer, reusing existing app state, organization commands, vault operations, and the shared controls. Do not fork encryption or introduce a schema migration for presentation changes. Keep the current Add/Edit actions usable while the new editor is incomplete.
3. Preserve the selected folder, tag, item, search, and draft in view state across pane transitions. Reset revealed secrets when the selected item changes. Respect all existing clipboard expiry, locking, and auto-lock behavior.
4. Enable only in `--demo` first. Test 320/390/680/945/1280px and short windows under Hyprland; inspect real native screenshots. Include keyboard navigation, screen-reader labels, focus restoration, empty states, mixed bulk tags, long titles, many folders, and scrolling with custom fields/additional URLs.
5. Extend the opt-in to real vaults after demo verification, using the same persistence and validation paths. Change the default only after user review.

Rollback: relaunch without the experimental switch. No data rollback should be necessary because presentation never alters the schema. Keep the flag and existing view until the redesigned flows have been accepted. Avoid a checkout-wide reset: the current branch contains substantial unrelated feature work.

For this proposal alone, rollback is simply deleting `docs/desktop-redesign-proposal.html` and this document. No native app changes were made in this proposal turn.

## Reference direction and verification

- [Dribbble: password management](https://dribbble.com/tags/password-management): public password-manager concepts used as visual reference, not proof of production usability.
- [Shakuro portfolio](https://shakuro.com/works): product/workspace design reference. No assets or layouts copied.
- [Mobbin web apps](https://mobbin.com/discover/apps/web): detailed flows were gated by login and were not inspected.

Rendered and inspected at 1100px, 728px, and 390px. Browser checks at 945px and 360px verified no horizontal page overflow; scoped counts; subfolder filtering; search and empty results; reveal reset when selection changes; editor focus; synthetic create/edit/cancel/reset; and detail/editor containment. This verifies the HTML proposal, not GPUI implementation or native accessibility.
