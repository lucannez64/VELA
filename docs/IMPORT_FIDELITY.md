# Import fidelity and migration report

Status: 2026-10-22. Covers the desktop importers. Mobile and browser clients
still receive data through sync rather than a local file picker; that is part
of the client matrix below, not a hidden gap.

## Capability matrix

| Client | File import | Logins / notes | Cards | Identities | Custom fields | Folders / tags | `.1pux` |
|---|---|---|---|---|---|---|---|
| Desktop GPUI | Yes | Yes | Yes (Bitwarden JSON, 1Password `.1pux`) | Yes (Bitwarden JSON, `.1pux`) | Yes, when collections are enabled | Yes, when collections are enabled | Yes |
| Desktop Tauri | Yes (same core importer) | Yes | Yes | Yes | Yes, when collections are enabled | Yes, when collections are enabled | Yes |
| Android | No local file picker | Sync only | Sync only | Sync only | Sync only | Sync only | No |
| iOS | No local file picker | Sync only | Sync only | Sync only | Sync only | Sync only | No |
| Browser extension / web | No vault import | — | — | — | — | — | — |

Adding a native picker to Android and iOS is follow-up work; the shared core
importer is the place to reuse rather than reimplementing per platform.

## Source fidelity

| Source | Imported as | Organization | Field losses |
|---|---|---|---|
| Bitwarden JSON | logins, notes, cards, identities | folder per item; tags not native to Bitwarden | collection ids and card brand are counted in the report |
| 1Password `.1pux` | logins, notes, cards, identities | vault name becomes a folder; item tags become tags | attachments and document/file items are counted; unknown item types are skipped |
| 1Password `.1pif` | logins, notes | folder records are metadata only | cards/identities are counted |
| 1Password CSV | logins, notes | none | cards/identities cannot be represented in the CSV |
| Bitwarden CSV | logins, notes | folder/group becomes a folder | cards/identities cannot be represented in the CSV |
| KeePass / KeePassXC CSV | logins, notes | group path becomes a nested folder | attachments and custom fields are not in the CSV |
| Chrome / Edge / Safari CSV | logins | none | no notes/TOTP/custom fields |
| Proton Pass JSON | logins, aliases, notes | vault name becomes a folder | card/identity item types are counted as unsupported |

## The import report

`ImportResult` (shared by both desktop front ends) returns:

- `added`, `duplicates`, `skipped`, `total` — the original row accounting.
- `preserved` — items whose folders, tags, custom fields, extra URLs or
  identity details were stored as first-class rich data.
- `converted` — attributes that had to be flattened into notes, either because
  the vault has not enabled collections yet or because a record could not be
  represented.
- `unsupported` — field-level losses such as `attachments ×3` or
  `card brand ×1`.
- `source` — the detected format.

The desktop UI shows these in the import status line. Nothing is reported as
preserved unless it actually landed in the vault; the conversion path is
explicit and keeps the original text in notes.

## Collection activation

Rich attributes only become first-class when the vault is on schema 2:

- On an upgraded vault, folders and tags are created as needed, custom fields
  and additional URLs are written into item metadata, and identities carry
  their email/phone/company/address details.
- On a schema-1 vault, the same data is appended to the item's notes
  (`Folder:`, `Tags:`, `Custom fields:`, `Additional websites:`, `Identity:`)
  and counted as `converted`. Cards and identities are still created as real
  items.

## Backup restore

The encrypted `.vela` archive remains the full-fidelity restore path:
`schema_version`, organization records, tombstones and every item type round
trip. `encrypted_archive_restores_rich_vault_on_a_clean_install` covers
restoring a rich vault into a fresh state; `encrypted_archive_roundtrips_every_item_type`
covers passkeys, TOTP seeds and metadata. File importers are for leaving another
manager, not for restoring VELA's own backup.
