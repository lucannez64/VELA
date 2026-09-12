# VELA Roadmap

What is shipped is in [`CHANGELOG.md`](../CHANGELOG.md); what the protocol
guarantees is in [`SPEC.md`](../SPEC.md). This file is the honest list of what is
*not* built yet, grouped by how soon it belongs in a release, with the design
constraint that makes each item non-trivial called out next to it.

This is a plan, not a promise. Items move between tiers as the audience decision
in §0 is made and as the assurance work in §5 closes.

## How to read this

- **Tier** is intent, not a date. **Now** = needed for a credible 1.0 for the
  audience we pick; **Next** = high value, unblocked once Now lands; **Later /
  research** = real, but gated on a design or proof we do not have yet.
- Every item lists **what**, **why**, and **constraints / done-when** so the next
  person can pick it up without re-deriving the pitfalls.
- Security-negative features are not listed as "nice to have." If an item could
  weaken a property in `SPEC.md` §9, it is marked and must ship behind a design
  doc and (where applicable) a `security/formal/` model.

---

## 0. Foundational decision — pick the 1.0 audience

**DECIDED (2026-09): self-hosted individual/family.** VELA 1.0 is for people
running their own server for themselves and the people they choose to share
individual items with. Organize + polish + sync quality + trust artifacts are
the roadmap; shared collections stop at the existing per-item/family sharing
(M19). Roles, admin/audit views, SCIM/SSO and policy controls are **out of
scope** for 1.0 — §3.2 stays a research item unless this decision is revisited,
and §1.1's organization schema is deliberately per-vault simple (no groups).

Everything below is ordered differently for a **self-hosted power user** than for
a **team/enterprise buyer**. This decision constrains the organization schema in
§1.1 and whether §6 (enterprise controls) is real work or out of scope.

- **Self-hosted individual/family:** organize + polish + sync quality + trust
  artifacts are the roadmap. Shared collections stop at family sharing.
- **Team/enterprise:** shared collections, roles, admin/audit views, SCIM/SSO,
  and policy controls become Now, and the organization schema has to be designed
  for groups from the start.

**Decision owner:** project owner. **Done when:** recorded in this file and
reflected in how §1.1's schema is designed.

---

## 1. Now — table stakes for a 1.0

### 1.1 Vault organization (folders / tags / collections)

**Status. Shipped (core + all clients), merge semantics below.**

**What.** Give users structure: at minimum **tags**, plus an optional single
"folder" per item, with filtering/search over both. Full nested trees and shared
collections are explicitly *not* part of this item (see §2.1).

**Why.** This is the most conspicuous parity gap. The model today is flat
(`VaultMeta { id, name, notes, …, favorite, shared, share_recipient }` in
`libVELA/vela-core/src/vault.rs`) and there is no folder/tag/collection concept
anywhere — no schema field, no client UI.

**Design (as built).** `VaultMeta` gains `tags: Vec<String>` and
`folder: Option<String>` — the folder is stored as its *name* on the item, not
as a separate synced entity, so there is nothing new to sync and no merge
surface beyond the item itself. A folder rename is a client-side batch update;
a nested tree would need its own design.

**Constraints / done-when.**

- Organization data lives **inside the encrypted vault JSON tree**. No
  server-visible `/collections` endpoint exists or was added: item counts and
  structure stay hidden, preserving the metadata-hiding claim in `SPEC.md` §5.
- A-2 round-trip holds: both fields are `#[serde(default)]` (folder also
  `skip_serializing_if`), so a client that predates them parses and
  round-trips; the typed mirrors on every client carry them (verified by
  round-trip tests in both Rust cores).
- Merge is decided and documented, in `vela-sync-policy::merge_org_fields`:
  **tags union** (the additive edit two devices make concurrently must not
  fight) with **per-tag removal records** so a removed tag is not
  resurrected by a stale copy — a removal suppresses the union'd tag on any
  copy whose last edit predates the removal, and an edit of a copy made
  *after* the removal that still carries the tag counts as re-adding it
  (the same whole-item reasoning every other field gets). Removal records
  use the same 30-day retention window as item tombstones. The documented
  residual edge: if another device edits the item *after* your removal
  without ever having seen it, the tag survives that merge — removing it
  again records a newer removal that then beats every copy. Full
  per-tag add-timestamps (an LWW element set) would close even that, at the
  cost of a more complex tag schema; deferred. **Folder** is single-valued
  last-writer-wins on `updated_at`.
  Implemented in the desktop merge *and* conflict resolution
  (`vela-desktop-core/src/sync.rs`), Android's `mergeVaultStores` (+ the
  `VaultStore.updateItem` write path), and iOS's `VaultMerge` (+ the
  `VaultViewModel.update` write path). Deterministic under a simulated
  concurrent edit
  (`a_tag_added_offline_survives_a_concurrent_edit_deterministically`,
  `a_tag_removal_beats_stale_copies_but_not_later_edits`).
- Tags are canonical on write (trimmed, case-insensitively deduplicated,
  sorted) by the same rule on every platform, so merged output is identical
  regardless of which side was "server".
- Done: organizational metadata syncs end-to-end across desktop (Tauri/React +
  gpui)/Android/iOS/web (passthrough)/extension (reads nothing it didn't
  before), an old client's JSON round-trips, and merge is deterministic under a
  simulated concurrent edit.

### 1.2 Trash / recycle bin

**Status. Shipped (core + all clients).**

**What.** A user-facing deleted-items bin with restore and permanent delete.

**Why.** `Tombstone { id, deleted_at, deleted_by }` already exists in
`libVELA/vela-core/src/vault.rs` for sync correctness, but there was no UI to
see, restore, or purge deleted items. Users expect an undo.

**Design (as built).** `delete_item` moves the item's full content into an
encrypted `deleted_items` list inside the vault JSON *and* writes the
tombstone — unchanged semantics: the tombstone is what sync propagates, the
copy is what makes an undo possible. Restore stamps a fresh `updated_at`
(newer than every tombstone, so the restore propagates), drops the tombstone
and the trash entry, and clears `last_modified_device` so the next sync is
replication, not a phantom conflict. Purge is explicit (two-step in the UI)
and keeps the tombstone, or sync would resurrect the item from another
device. Trash entries share the tombstones' 30-day retention; each device's
trash merges by "newest deletion wins", yielding to any live copy newer than
the deletion — the done-when "restorable on a second device" falls out of
that rule. The trash lives inside the encrypted vault JSON: no
server-visible structure was added.

**Done when / verified.** A deleted item is restorable from a second
device's trash after the deletion syncs — covered by
`a_remote_deletion_trashes_locally_and_a_restore_survives_sync` (desktop),
`testRemoteDeletionTrashesLocallyAndRestoreSurvivesSync` (iOS), and the
trash-carrying Android merge; desktop React and gpui both ship a Trash
screen (list, restore, two-step delete-forever); Android and iOS carry the
trash through their data layers and sync. Deletion stays a tombstone (never
a physical removal before every device has seen it), purge is explicit, and
the bin is conflict-merge aware (a trashed entry never suppresses a live
copy that is newer than the deletion).

### 1.3 Item model depth

**Status. Shipped (core + all clients round-trip; full editor on React desktop).**

**What.** Password history (previous values with timestamps) and **custom
fields**; add the missing common types (address, bank account, API key, SSH key).
The CLI/SSH agent already landed, so SSH-key storage is a natural pair.

**Why.** Flat, fixed schemas are a top usability complaint against any password
manager, and password history is expected the moment a user lets VELA rotate a
credential.

**Design (as built).**
- **Password history** lives on the login variant
  (`password_history: [{password, changed_at}]`, newest first, capped at 12).
  Every editing client records the *old* value against the *stored* copy when
  an edit changes the password — desktop `update_item`, Android
  `VaultStore.updateItem`, iOS `VaultViewModel.update` — so a rotation through
  any client keeps the trail. Recorded values zeroize like the live password.
- **Custom fields** live on `VaultMeta`
  (`custom_fields: [{label, value, field_type: text|hidden}]`), available to
  every item type. A `hidden` value is a secret: it zeroizes with the item's
  other secrets and prints `[REDACTED]` from `Debug`.
- **New item types**: `address` (no secrets), `bankAccount` (account number +
  IBAN are secrets), `apiKey` (the key is a secret — it *does* leave the vault,
  so it gets the password treatment), `sshKey` (private key + passphrase are
  secrets; the public key is the copyable display value). All wire as
  `item_type` camelCase tags with snake_case variant fields.

**Constraints / done-when (verified).** The A-2 rule holds everywhere
(`item_model_depth_fields_round_trip_through_serde`,
`new_item_types_round_trip_and_protect_their_secrets`); secrets in custom
fields and password history are zeroized from `Debug` and wiped on drop
(`dropping_new_item_types_wipes_their_secrets`), exactly like the existing
fields. History is recorded on change on every editing client
(`a_password_change_is_recorded_in_the_history` desktop/iOS, Android's store
diff). Custom fields and the new types round-trip across desktop, Android
(their own typed variants + JSON), iOS (flat struct + `ItemKind` cases), web
(passthrough) and the extension. Merge note: custom fields and history take
the same whole-item last-writer-wins as every other field — the
additive-merge machinery of §1.1 was deliberately not extended here; a
concurrent custom-field edit from two devices surfaces as a normal conflict.

**Known UI gaps (data complete everywhere).** Creating the new types and
editing custom fields is available on the React desktop (the primary front
end); gpui, Android and iOS display them read-only (gpui gates its Edit
button to the kinds it can edit, so an item is never silently converted).
SSH-key storage is ready for the CLI/SSH agent to consume; wiring the agent
to serve these keys is follow-up work.

### 1.4 Audit-log and device-management UI

**What.** Surface the encrypted device audit log (`SPEC.md` §4.4) and device
management (list, revoke, see enrollment events) in the clients.

**Why.** The protocol already records enrollment/revocation/sync/share events and
supports revocation cascades, but a user cannot see or act on any of it. For a
security product, the audit trail is a feature, not an implementation detail.

**Constraints / done-when.** Decryption happens client-side under `audit_key`;
the server never gains a query surface. Done when a user can see devices and
events and revoke a device from the UI.

---

## 2. Next

### 2.1 Shared collections (family / team)

**What.** Extend per-item sharing (M19, `SPEC.md` §5.4) to folders/collections:
membership, per-recipient re-sealing, membership changes, and revocation.

**Why.** "Share this folder with my family/team" is the natural next ask once
§1.1 exists, and it is what pushes a personal vault into shared use.

**Constraints.** This is a large protocol lift, not a UI feature: recipient key
management, re-seal on every member's edit, membership-change semantics, and
revocation that (per M19) stops future pulls but cannot remotely delete a
recipient's copy. Decide whether the audience is family (small N, no roles) or
teams (roles, ownership, admin) before designing — see §0. Needs its own design
doc and a `share-channel` model extension.

### 2.2 Sync and scale quality

**What.** Measure and improve Path ORAM cost at realistic vault sizes; improve
conflict-resolution UX (surfacing conflict copies, manual resolve/merge).

**Why.** The trivial/Path ORAM threshold is an engineering choice (`SPEC.md`
§5.2), and `docs/RESEARCH_POTENTIAL.md` §4 flags measured overheads as a
prerequisite for the systems paper *and* as a real UX concern. Conflict merge
rules exist; the resolution experience is likely rough.

**Constraints / done-when.** Numbers before conclusions: ORAM bytes/latency vs.
vault size and vs. a plaintext-manifest baseline; unlock latency across the four
platforms. Done when the crossover is measured and conflicts are resolvable in
the UI on every client.

### 2.3 Platform parity

**What.** Autofill polish, an iOS app/autofill extension, accessibility, and
localization.

**Why.** Android autofill and the browser extension are hardened, but parity
across platforms and reach beyond English/accessible users is table stakes for
adoption.

**Constraints.** Autofill must keep the existing approval doctrine (biometrics
prove presence, not identity; explicit dialog when no biometric factor) and must
not weaken the OS-authenticated IPC gate.

### 2.4 Assurance gaps (from `docs/RESEARCH_POTENTIAL.md` §4)

**What.**
- Prove the ORAM stash bound for bounded parameters (currently *statistical*, not
  a proof — formal-venue reviewers will ask), or position it honestly.
- Add a Dolev–Yao-style local-adversary model for the native-messaging gate
  (the credential-less IPC mechanism in §2.3 of that doc has no model).
- Measure IPC approval and ORAM path timing (SPEC §9 currently waves side
  channels off as out of scope).

**Why.** These are the gaps between "machine-checked where we looked" and
"reviewers cannot poke a hole." Cheap relative to their value for a security
product.

**Done when.** Each gap is either closed with an artifact under `security/` or
explicitly re-scoped in `SPEC.md` §9 with a reason.

### 2.5 Trust and release engineering

**What.** A public threat-model / security whitepaper, signed and reproducible
builds, and a vulnerability-disclosure policy.

**Why.** For a vault, this is roadmap material, not marketing: it is what lets a
security-conscious user or auditor trust the offline claims.

**Done when.** A published threat-model doc, reproducible-build verification
steps documented in `docs/INSTALL.md`, and a disclosure policy with a contact.

---

## 3. Later / research

### 3.1 Coercion resistance — decoy vault / duress password

**What.** A deniable alternate vault and/or a duress credential, addressing the
coercion threat `SPEC.md` §9 currently marks **out of scope** ("future versions
may explore threshold decryption or secret sharing with decoy shares").

**Status.** **Design spike only.** Do not put this in a release milestone until
the deniability model passes. A badly built decoy is *worse than none* because it
sells deniability the system does not have.

**Why it is hard (summary — full analysis in
[`security/coercion-resistance-design.md`](../security/coercion-resistance-design.md)).**

- Open source cuts against deniability: an adversary who knows the feature exists
  can assume any vault you hand over is the decoy and keep coercing.
- Biometric unlock bypasses the duress path; the hybrid identity key authenticates
  the server independent of which vault is unlocked.
- `share_ek`, device identity keys, the audit log, and recovery shares are all
  separate surfaces that can reveal a second vault exists.
- Recovery is the leak: what do the Shamir shares protect?
- "Duress wipes the vault" fights sync, is triggerable by accident, and destroys
  real data with no undo — do not make auto-wipe the default.

**The one genuine advantage.** VELA's fixed-size padded blobs plus ORAM mean two
vaults *can* be size-indistinguishable in a way competing vaults cannot. That is
the angle worth researching.

**Deliverables, in order.**
1. Threat-model doc (`security/coercion-resistance-design.md`).
2. Interaction analysis with hardware unlock, recovery, audit log, and share keys.
3. A deniability model under `security/formal/` (the project already models the
   neighboring mechanisms).
4. Prototype behind a flag, only after (3) passes.

**Lineage to position against:** VeraCrypt hidden volumes, duress-PIN literature,
and `docs/RESEARCH_POTENTIAL.md`.

### 3.2 Enterprise / team controls

**What.** Roles, ownership, admin/audit views, SCIM/SSO, policy controls.

**Gate.** Only real work if §0 selects a team/enterprise audience; otherwise
explicitly out of scope. If in scope, it constrains §1.1 and §2.1 and must be
designed together with them.

---

## 4. Explicit non-goals (for now)

- Client-side malware / keyloggers, cold-boot and RAM readout (`SPEC.md` §9).
- Network-layer DoS.
- A general replacement for autofill: in-core/browser-driven login remains a
  niche (`security/in-core-login-future-work.md`).

## 5. Cross-cutting constraints (apply to every item)

- **Metadata hiding:** never add a server-visible structure for user data.
- **A-2 round-trip:** new fields default + alias, or an old client deletes them
  for everyone.
- **Formal assurance:** mechanism changes touch a `security/formal/` model.
- **Audit trail:** security-relevant user actions append to the encrypted device
  audit log.
