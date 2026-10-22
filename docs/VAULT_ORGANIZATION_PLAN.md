# Vault organization and richer items

Proposed implementation plan, 2026-10-20. This is the next feature milestone;
full importer coverage follows it. This document does not describe shipped
behavior.

## Implementation status

Started 2026-10-20 with the shared schema foundation in
`libVELA/vela-core/src/rich_items.rs`. Implemented:

- Folder/tag records, UUID assignments, logical revisions and persistent
  organization tombstones, with create/rename/move/delete operations.
- Deterministic organization merge, cycle-safe display parents and stale
  assignment repair. The caller must persist organization and item assignment
  changes together; these operations do not mutate live credential items.
- Typed custom fields, additional URL records and identity/address details,
  with validation, redacted debug output and string cleanup on drop.
- Forward-compatible unknown custom-field types and URL match modes (preserved
  but read-only), plus opaque extra properties on rich records.
- Golden JSON fixtures and focused compatibility/merge/validation tests.

Current implementation: desktop (GPUI/Tauri), Android and iOS provide
folder/tag management, filtering and rich-item editing on schema 2. Activation
keeps an encrypted safety copy and the server enforces a write-version floor.
Mobile validation and organization merge use the shared Rust bridge. The browser
extension has a dedicated editor tab for collection management, bulk assignments
and login/card/note/identity rich fields, through the matching desktop native
host. Ephemeral web still does not manage collections. Additional websites are
stored and editable; expanding destination credential-release matching remains
separate work. This describes the combined PR, not a released build.

Initial limits constrain the new field validators only; total encrypted vault
and chunk capacity must still be checked during persistence integration.

Verification for this slice: shared-core tests and host Rust checks for the
WASM, Android and Apple bridges. Full Android/iOS app builds and browser/device
verification are not part of this schema-only slice. Strict Clippy currently
needs an exemption for two pre-existing `needless_return` warnings in
`vela-core/src/vault.rs`. Desktop dependency resolution has an existing
`core-foundation` 0.10.0/0.10.1 conflict; resolve it before the desktop
integration build. Neither issue changes the schema tests' result.

## Product scope

- Each item can belong to one optional folder. Folders can be nested.
- Each item can have multiple tags, independently of its folder.
- Custom fields are ordered, named values with text, concealed-text and boolean
  types. Concealed values require explicit reveal/copy and must not appear in
  logs, list previews or general search results.
- Logins retain a primary URL and support additional URLs with explicit match
  rules. Matching must not broaden credential release to unrelated origins.
- Identities support names, email, phone, company and postal-address fields,
  retaining the existing identity fields for compatibility.
- Existing cards and notes remain supported. New item templates and attachment
  redesign are separate work; this milestone extends the existing types.

## Proposed schema contract

These names describe new wire fields. Existing wire keys remain unchanged;
the schema version below is a vault-data version, independent of `SPEC.md`'s
protocol v2 and application release versions.

### Vault envelope and organization records

Add these fields to the encrypted `VaultStore` envelope:

```text
schemaVersion: integer                 # absent means legacy schema 1
folders: Folder[]                      # default []
tags: Tag[]                            # default []
organizationTombstones: OrganizationTombstone[]  # default []

Folder = {
  id: UUID, name: string, parentId: UUID | null,
  revision: { counter: u64, deviceId: string },
  createdAt: RFC3339, updatedAt: RFC3339
}
Tag = {
  id: UUID, name: string,
  revision: { counter: u64, deviceId: string },
  createdAt: RFC3339, updatedAt: RFC3339
}
OrganizationTombstone = { kind: "folder" | "tag", id: UUID }
```

Use the existing encrypted vault stream rather than a new plaintext server
index. Extend whole-store persistence, chunk assembly, equality and merge
paths: adding fields to `VaultStore` alone is insufficient. The server learns
the minimum supported write version, never folder names or membership.

Add common item metadata `folderId: UUID | null`, `tagIds: UUID[]`, and
`customFields: CustomField[]`, defaulting to null/empty for legacy items.
Assignment IDs are references, not copies of folder/tag names. Empty folders
and unused tags remain real records so they survive sync and backup.

Names are trimmed and Unicode NFC-normalized, retaining display case. Reject
empty names. Interactive create/rename rejects case-folded duplicates among
sibling folders or among tags; concurrent duplicates retain their distinct
IDs and are shown for user resolution. Do not merge records by name during
sync. Importers can map source paths to IDs later.

### Custom fields

```text
CustomField = {
  id: UUID,
  label: string,
  type: "text" | "concealed" | "boolean",
  value: string | boolean
}
```

The array defines display order. Require a nonempty label and a value matching
the declared type; duplicate labels are allowed because imported items may
contain them. A concealed value is encrypted in the vault like every other
field; its type controls reveal behavior, not a separate encryption scheme.
Treat all custom-field values as potentially sensitive for debug output,
clipboard handling and memory cleanup, including fields marked as plain text.
Do not send values in validation errors or audit events. Exclude values from
general search in the first release; labels may be searched.

Future field types must round-trip as opaque data on preservation-capable
clients; unknown types render read-only. Do not coerce them to text. Preserve
unrecognized item properties through storage and updates, but never expose
opaque properties automatically to browser IPC, logs, sharing or autofill.

### Login URLs and identities

Retain the existing login `url` as its primary URL. Add:

```text
additionalUrls: [{ id: UUID, url: string, match: "exact" | "origin" }]
```

Default a newly added URL to `origin`. Exact matching compares the normalized
URL without its fragment; origin matching compares scheme, host and effective
port. Reject credentials embedded in URLs. Restrict new autofill candidates
to HTTPS URLs, with the existing explicit local-development exception where
applicable. Do not add wildcard, regex or automatic parent-domain matching in
this milestone. Preserve the primary URL's current matching behavior.

An additional URL is a user-authorized alternate site for the login, not an
alias inferred from its name. Candidate discovery, approval, credential
release, save/update prompts and TOTP release must agree on the matched URL.
Until that whole path is implemented, additional URLs are storage/display
only. Passkeys remain bound to their RP IDs; login URL changes never change
passkey scope.

Keep existing identity `firstName`, `lastName` and `ssn` keys and aliases.
Add optional `identityDetails` with `middleName`, `preferredName`, `email`,
`phone`, `company`, `jobTitle`, and an ordered `addresses` array. Each address
has a UUID, optional label, `line1`, `line2`, `city`, `region`, `postalCode`
and `countryCode`. Do not make country-specific fields mandatory. Preserve
source values; use custom fields for additional identity attributes. Existing
card fields remain the canonical fields; extra card data can use custom fields.

### Initial validation limits

Proposed initial ceilings: 128 characters for folder/tag names and field
labels; folder depth 16; 64 tags, 128 custom fields, 32 additional URLs and
16 addresses per item; 16 KiB UTF-8 per custom-field string; and 4 KiB per
URL. Enforce limits in shared validation and every writer, not only UI inputs.
Check these against existing vault/chunk size limits before implementation
and retain stricter existing total-size ceilings. Existing or imported data
above a limit must produce an explicit report or read-only state, never silent
truncation. These ceilings are product defaults to validate, not claims about
current format capacity.

## Organization semantics and conflict handling

- **Move/rename:** change the organization record, retaining its UUID. Moving
  a folder moves its displayed subtree without rewriting item assignments.
  Reject moving a folder into itself or a descendant.
- **Delete folder:** remove only the selected folder; promote its children
  to its parent and unfile its directly assigned items. The confirmation states
  both effects and the affected counts. Deleting a subtree is deferred.
- **Delete tag:** remove the tag from all items without deleting any item.
- **Missing/deleted references:** render affected items as unfiled or omit the
  unavailable tag. Keep their credential data intact. Repair stale references
  on a supported write, rather than making the vault unreadable.
- **Record merge:** increment a per-record logical counter on mutation. Merge
  by `(counter, deviceId)` lexicographic order for a deterministic result,
  using a persisted counter and checked overflow. Wall-clock timestamps are
  display metadata, not the organization conflict authority. Concurrent
  rename/move resolves to the winning record; no automatic duplicate copies.
- **Deletion:** organization tombstones permanently suppress the old UUID,
  even if an offline device later submits a rename. Recreating a folder/tag
  creates a new UUID. Retain these tombstones for this milestone; do not copy
  the existing item's 30-day tombstone pruning policy without an acknowledged
  device checkpoint design.
- **Cycles after merge:** keep raw winning records, but derive an acyclic
  display tree by treating the lexicographically greatest folder UUID in each
  cycle as a root. Missing parents also display at root. Show a repair notice;
  an explicit move writes the repair. All clients use the same rule.
- **Item edits:** folder/tag assignments and custom-field ordering remain
  part of the whole-item edit and existing item conflict-resolution flow.
  Do not claim automatic union of concurrent tag changes. Audit current
  conflict detection across clients before enabling writers, including equal
  timestamps; retain both versions when edits cannot be resolved safely.
- **Bulk changes:** validate the selection and unlocked state first, then
  commit one local vault transaction and one sync request. On failure, retain
  the selection and show the error; do not report partial success as complete.

## Desktop UX contract

Both GPUI and Tauri implement the same behavior:

- Sidebar retains type filters and Favorites, then adds collapsible Folders
  and Tags sections. Include All items and Unfiled. Empty folders remain
  visible. Creation is available from each section's action menu.
- Selecting a folder includes descendants by default; an "Include subfolders"
  control switches to direct members. A selected tag requires that tag.
  Organization filters intersect with the active type and search query.
  Clearing filters always returns to the complete vault.
- Folder rows offer rename, move and delete. Tag rows offer rename and delete.
  Menus and dialogs work with keyboard navigation; drag-and-drop is optional
  follow-up work, not required to organize a vault.
- Item editors add an Organization section: optional folder picker with full
  paths and a searchable multi-tag picker with explicit tag creation. Details
  show clickable folder/tag labels that apply the corresponding filter.
- Multi-select adds Move to folder, Add tags and Remove tags. Display the
  affected count. Read-only received shares cannot be included in a credential
  edit operation; explain exclusions before committing.
- Item editors add an ordered Custom fields section with a type selector,
  label/value controls, add/remove and move-up/move-down actions. Concealed
  fields start masked and reset on item change, lock or editor close. No secret
  values appear in toasts or previews.
- Login editors keep Primary URL and add an Additional sites section. Display
  the origin and match mode explicitly before saving a new association.
  Identity editors group Personal, Contact and Addresses fields, allowing
  optional fields without forcing users to fill a country-specific form.
- Details use existing copy/reveal controls and clipboard timeout policy.
  Preserve form input on validation/save errors and prevent duplicate submits.

## Sharing, backup and importer boundary

Folder/tag records and assignments are personal organization metadata. Strip
them from outgoing item shares and one-off links. Custom fields and additional
URLs are item contents: show them in a share preview and retain only fields
supported by the recipient format. Preserve received-share read-only behavior;
personal organization of received shares is deferred until local assignments
are separated from the shared item. Unknown properties are excluded unless
their sharing semantics have been explicitly defined.

Native encrypted backup includes the schema version, organization records,
tombstones, assignments and every item field. Restore remaps IDs only when
merging into another vault, using one consistent mapping for all references;
full replacement restore preserves IDs. Show a preview and never combine
foreign organization tombstones with an existing vault without remapping.
Interchange exports state unsupported fields before writing. This milestone
must provide a complete native backup even though expanded imports come later.

## Compatibility rollout and rollback

1. **Inventory and fixtures:** record every serializer, writer, chunk assembler,
   backup and sharing path. Add legacy and proposed-schema fixtures, including
   unknown fields, shared items and conflict cases. Inventory the actual
   device/client versions; the repository alone does not establish deployment.
2. **Preservation release:** ship new-schema read/preserve support on desktop,
   Android, iOS and ephemeral web, with feature creation disabled. Patch-style
   editor updates distinguish omitted fields from explicit clearing. Unknown
   properties survive edits without being exposed to untrusted consumers.
3. **Server gate:** add a per-account minimum vault-write schema and a writer
   capability on authenticated requests. Once upgraded, reject absent or
   insufficient capabilities before any vault mutation, especially chunk PUT,
   and cover rekey/recovery/session paths that can replace data. Inventory all
   mutation routes before declaring the gate complete. This is an accidental
   compatibility guard, not protection against a malicious authenticated client
   that falsely advertises support.
4. **Activation:** offer activation on an updated desktop after a successful
   complete backup and sync. Warn that old clients must upgrade. Set the server
   gate before uploading new-schema data; then migrate and enable editors.
   Journal activation so retries resume safely. A crash may temporarily block
   old writers, but must never permit them to overwrite upgraded data. Standalone
   local vaults can migrate without a server; their next sync must establish
   the gate first. Old/self-hosted servers without gating cannot enable synced
   rich-data writes; explain the required server upgrade.
5. **Desktop enablement:** release both desktop editors together. Updated
   mobile/web clients can preserve all new fields even while their editing
   features remain read-only. Handle stale offline edits by pulling and merging
   with the new schema before their first upload.
6. **Mobile/web enablement:** add supported editors and filters, updating the
   capability matrix. Feature flags control creation, not whether existing
   richer data is retained.
7. **Rollback:** disable new creation if needed but retain preservation readers
   and the write gate. Never downgrade an upgraded vault by dropping fields.
   Restoring the pre-activation backup is an explicit user restore that can
   discard later changes, not an automatic rollback. Local rollback to an old
   app binary is unsupported after activation and must be documented.

Do not promise that an old client will display new data correctly in read-only
mode. It may still render a partial local copy; existing binary behavior cannot
be retroactively fixed. Test actual supported old releases at the gate.

## Implementation sequence

1. **Schema and compatibility.** Define stable folder/tag identifiers, parent
   references, item assignments and field types. Define rename/delete behavior,
   cycle prevention, duplicate names and merge conflicts. Preserve current JSON
   keys and decode old vaults with empty/default organization data. Keep all
   organization data encrypted alongside the vault.
2. **Serialization and sync.** Update both Rust models, Kotlin models/codecs,
   Swift Codable models, WASM paths and desktop/web conversion layers. Verify
   that clients without editors preserve the new fields. Establish an upgrade
   or write-gating policy for already-released clients that discard unknown
   fields; adding defaults to the new models cannot repair older binaries.
3. **Desktop organization.** Implement folder/tag create, rename and delete;
   sidebar/filter navigation; assignment in editors; and bulk assignment/move.
   Deleting a folder or tag must not delete its items. Use stable identifiers
   so renames do not require changing every assigned item.
4. **Richer editors and details.** Implement custom-field add/remove/reorder,
   concealed values, multiple URLs and fuller identities in GPUI and Tauri.
   Update lookup/autofill consumers for multiple URLs under the same origin
   checks as existing credentials. Custom fields are storage/display-only
   initially; automatic form filling requires a separate explicit mapping.
5. **Mobile and web workflows.** Add organization and richer-item editing after
   preservation is verified. Keep a capability matrix distinguishing storage,
   display, editing and autofill support on each client.
6. **Exports and importer expansion.** Make native encrypted export/restore
   complete for the new model. Map supported fields to interchange formats and
   disclose losses. Then expand competitor importers to the richer model.

## Repository integration points

- `libVELA/vela-core/src/vault.rs`: shared vault schema and store.
- `desktopVELA/vela-desktop-core/src/vault.rs`: separate desktop vault model.
- `desktopVELA/vela-desktop-core/src/commands/vault.rs`: item updates, search
  and export paths.
- `desktopVELA/src-gpui/src/views/`: native editors and vault browser.
- `desktopVELA/src/context/AppContext.tsx`: renderer item conversion.
- `desktopVELA/src/components/` and `desktopVELA/src/views/`: Tauri UI.
- `androidVELA/app/src/main/java/com/vela/android/core/VaultModels.kt` and
  `VaultJson.kt`: Android models and explicit JSON codec.
- `iosVELA/Shared/Vault.swift`: Swift item representation.
- `webVELA/`, `libVELA/vela-wasm-bridge/`, and the Apple/Android bridges:
  inspect all decode/encode and edit paths for preservation.
- `desktopVELA/vela-desktop-core/src/import.rs`: importer integration after
  the destination schema and editors exist.

## Completion criteria

- Old vaults still load. A new vault survives save/load and cross-client edits
  without losing organization, fields or existing credentials.
- Folder moves, tag changes and offline concurrent edits converge under a
  documented conflict policy; deleted organization records do not reappear
  from stale clients.
- Both desktop front ends can organize items and create, edit and display all
  fields in scope. Mobile/web limitations are explicit and preserve data.
- Concealed custom fields receive the same redaction and secret-lifecycle
  handling as other secrets; copying follows existing clipboard policy.
- Sharing has an explicit rule for organization metadata: local folder/tag
  structure must not leak incidentally to recipients.
- Additional URL matches pass origin-bound credential-release checks.
- A native encrypted backup restores all supported fields and organization on
  a clean installation. Interchange exports clearly disclose unsupported data.
- Focused compatibility, sync, secret-redaction and backup tests pass before
  importer work begins.

## Verification plan and delivery slices

Deliver reviewable changes in this order; do not enable product writes merely
because the schema change compiles:

1. Schema types, shared validation rules and golden serialization fixtures.
   Test legacy defaults, unknown-field preservation, sensitive debug output,
   invalid references and size limits in Rust/Kotlin/Swift/web conversions.
2. Organization merge and persistence support. Test opposite merge orders,
   concurrent moves creating cycles, delete versus offline rename, missing
   parents, duplicate names and tombstones older than 30 days. Exercise the
   real chunked sync path rather than only comparing in-memory stores.
3. Writer gate and journaled activation. Test an actual old client, omitted
   capability, unsupported server, interrupted activation, stale offline writes,
   rekey and ephemeral web writes. Verify rejected writes leave stored chunks
   unchanged. Confirm legacy accounts remain usable before activation.
4. Both desktop organization UIs. Verify create/rename/move/delete, empty
   folders, intersecting filters, bulk changes, keyboard use and save failures
   with a realistically sized vault. Check both front ends against the same
   behavior contract.
5. Rich item editors plus release-path integration. Test edit-save-sync-edit
   across clients, explicit clearing versus omission, concealed-field lifecycle,
   alternate-site credential/TOTP approval, and passkey RP isolation.
6. Native backup and sharing. Restore a rich fixture on a clean installation;
   verify every reference, field and unknown property survives. Check outgoing
   shares exclude personal organization and unexpected opaque properties.
7. Mobile/web editors and documentation. Publish the supported-client matrix
   and upgrade/recovery instructions. Only then begin full importer expansion.

Before the schema implementation starts, validate proposed limits against
existing chunk capacity and inventory all write routes. These are engineering
checks within the plan; no further product approval is required for routine
implementation choices. Changes to the scope or user-visible deletion/sharing
semantics should be reflected here before implementation.
