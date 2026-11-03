# P1 — Journal implementation inventory

Scope: map every operation of the real desktop share-journal implementation to
the rules of `security/formal/m28_share_journal.spthy` (M28), as the input to
plan steps P3a (extract the journal step function) and P3b (journal step refines
M28). This document is read-only analysis: no code, model, fixture or gate was
changed, and no proof was run for it.

Sources read for this inventory:

- `security/formal/m28_share_journal.spthy` (rules, restriction, ten lemmas)
- `security/formal/share-journal-correspondence.md`
- `security/formal/m29_signed_share_commit.spthy`,
  `security/formal/signed-share-commit-correspondence.md`
- `security/formal/m28-trace-equivalence/README.md`
- `security/assurance/08-formalization-status.md` § "All-pairs journal goals"
  (lines 915–969)
- `security/assurance/09-target-contract.md` § "Trusted interfaces"
  (lines 7–35)
- `security/assurance/20-formalization-plan.md` rows P1, P3a, P3b, P3c, P3d,
  P4–P8 (lines 92–106)
- `desktopVELA/vela-desktop-core/src/{store,sharing,sync,recovery,lib}.rs`,
  `commands/session.rs`, `commands/vault.rs`
- `libVELA/vela-client-share-policy/src/lib.rs`,
  `libVELA/vela-client-share-policy/verify-fstar.sh`
- `libVELA/vela-android-bridge/src/lib.rs`,
  `libVELA/vela-apple-bridge/src/lib.rs`
- `security/assurance/proof-logs/current/os-interface-inventory/inventory.json`

Line numbers are from the worktree at the commit named in the final report.

---

## 1. What M28 states, briefly

M28 models one recoverable desktop share commit **after** authenticated
admission (`m28_share_journal.spthy:4–23`). It assumes the fsync+rename helper is
an atomic durable single-file replacement and separates snapshot acquisition,
journal persistence, vault persistence, journal cleanup, crashes and recovery.
Signing, byte encodings, filesystem correctness, local edits and cross-process
writes are explicitly out of scope. `Chain(slot, generation, pin)` is proof
instrumentation, not a state fact; the source bridge to the `.spthy` is reviewed
manually (`share-journal-correspondence.md:64–82`).

Consequences for this inventory: M28 does **not** model (a) the server, (b)
local edits/deletions/tombstones, (c) multiple processes, (d) fs failure states
other than "rule did not fire", (e) more than one pin/generation per slot.

## 2. M28 rules, restrictions and lemmas

### 2.1 Rules

| Rule | Line | What it models | Action facts | Durable state change |
|---|---|---|---|---|
| `Initialize` | 29 | A fresh profile/slot with a fresh initial item | `Initialized(~slot)` | creates `!Profile`, `!ReadyGeneration('initial','initial')`, `DiskClean(slot,'initial','initial','initial',~item)`, `Chain(slot,'initial','initial')`, `Out(slot)` |
| `ReadSnapshot` | 38 | Taking a snapshot of the last durable clean generation | `SnapshotRead(slot,~tx,gen,pinned)` | `Snapshot(slot,~tx,gen,pinned)` (linear, consumed by one `PersistJournal`) |
| `PersistJournal` | 43 | Durable write of pin + intended item to the share journal, then the vault is still old | `RevisionIncreases(pinned,next_revision)`, `JournalDurable(slot,tx,successor(gen),pinned,next_revision,payload)` | `DiskClean → DiskPending(slot,tx,successor(gen),next_revision,payload,vrev,vpayload)`; `Chain → (successor(gen), next_revision)` |
| `PersistVault` | 51 | Durable write of the pending item to the vault | `VaultDurable(slot,tx,gen,next,payload)` | `DiskPending → DiskApplied(slot,tx,gen,next,payload,next,payload)` |
| `ClearJournal` | 56 | Durable removal of the pending record after the vault write | `JournalCleared(slot,tx,gen,pinned)` | `DiskApplied → DiskClean(slot,gen,pinned,vrev,vpayload)`, re-produces `!ReadyGeneration(slot,gen,pinned)`, `Chain` unchanged |
| `Crash` | 64 | Arbitrary crash; durable files unchanged | `Crash(slot)` | consumes `!Profile`; nothing else changes |
| `OpenVault` | 68 | Exposing vault contents to the UI | `Opened(slot,gen,pinned,revision,payload)` | requires `DiskClean`; state unchanged |

Restriction `Increasing` (`:74–75`) turns `RevisionIncreases(old,next)` into the
strict subterm order `old << next`, an over-approximation of the `u64`
comparison.

### 2.2 Lemmas (the ten M28 verdicts the refinement must preserve)

| Lemma | Line | Statement (informal) |
|---|---|---|
| `open_has_matching_content_and_pin` | 77 | `Opened` implies the opened pin equals the vault revision |
| `application_requires_prior_durable_journal` | 81 | no `VaultDurable` without an earlier `JournalDurable` for the same tx/payload |
| `cleanup_requires_prior_durable_vault` | 86 | no `JournalCleared` without an earlier `VaultDurable` |
| `commit_uses_snapshot_generation` | 91 | `JournalDurable(...,successor(g),...)` needs an earlier `SnapshotRead(...,g,...)` |
| `each_transaction_applies_at_most_once` | 96 | one tx cannot produce two `VaultDurable` events |
| `pins_advance_on_every_commit` | 101 | every `JournalDurable` has `old << next` |
| `recovery_is_reachable` | 105 | crash between journal and vault, then apply, clear, open is reachable |
| `committed_pins_never_decrease` | 119 | for two `JournalCleared` in a slot, earlier `r1 << r2` (all-pairs) |
| `a_generation_commits_at_most_once` | 124 | two `JournalDurable` with the same generation are the same timepoint (all-pairs) |
| `two_successive_commits_advance` | 132 | two real commits with a strict revision advance are reachable (non-vacuity witness) |

08 states that these are instrumented-model results (the `Chain` thread was
added for them), and that the direct `.spthy` proof on the un-instrumented rules
did not finish in 600 s (`08-formalization-status.md:915–939`).

### 2.3 M29 delta (for the signed path)

M29 replaces the post-admission action names and adds pin/first-contact
semantics: `FirstJournal`/`UpdateJournal` emit `JournalAdmitted`,
`PersistVault`/`ClearJournal`/`OpenVault` emit `RemoteApplied`/`Cleared`/
`Opened`, and `PinObserved` is instrumentation. Its durable-state shapes match
M28 (`DiskClean`/`DiskPending`/`DiskApplied` plus a `tx`), and its
`applied_requires_prior_authenticated_journal` and
`open_has_matching_pin_and_content` are the M29 analogues of the M28 lemmas
(`m29_signed_share_commit.spthy:50–100,112–138`). The Rust journal mechanics
are one implementation; M29's extra rules are the admission/pin layer that
`vela-client-share-policy` already checks. This inventory therefore keys on M28
rule names and notes the M29 name where it differs.

---

## 3. The Rust implementation

### 3.1 Data model

`desktopVELA/vela-desktop-core/src/sharing.rs`:

- `SHARES_FILE = "shares.enc"` (`:18`) under `Store::store_path()`.
- `ShareStore { generation: u64, pending_items: Vec<PendingShareItem>,
  sent_shares: Vec<Share>, received_shares: Vec<Share> }` (`:89–97`).
  `generation` and `pending_items` are `#[serde(default)]`, so a legacy
  `shares.enc` decodes as generation 0 with no pending record (test at
  `:1343–1365`).
- `PendingShareItem { before: Option<VaultItem>, after: VaultItem }`
  (`:99–103`). There is **no** persisted phase flag: "pending" means
  `!pending_items.is_empty()`.
- `StoredSharePin { sender_user_id, sender_vk_b64, lineage_id, revision }`
  (`:55–60`) is stored **per received share** in `received_shares[].pin`
  (`Share.pin`, `:45–46`). Sent shares carry a separate `revision: u64`
  (`:41–42`).
- The whole `ShareStore` (pins + pending + metadata) is one encrypted file, so
  one atomic replacement publishes pin and intended content together — the
  property `write_share_store`'s doc comment claims (`:175–178`) and the
  correspondence table relies on (`share-journal-correspondence.md:13–14`).

The vault is a second file, `vault.enc`, written by `Store::save_vault`
(`store.rs:424–439`).

### 3.2 Functions that perform each step

| Function | Location | Role |
|---|---|---|
| `read_share_store` | `sharing.rs:125–139` | read + decrypt + decode `shares.enc`; `NotFound` ⇒ empty default; any decrypt/parse error is fatal |
| `write_share_store` | `sharing.rs:141–156` | encode, encrypt, `store::write_secret_file`, then the test-only `share-write` checkpoint |
| `share_commit_checkpoint` | `sharing.rs:164–173` | test fault injection at `journal`/`vault`/`share-write` boundaries |
| `finish_pending_items` | `sharing.rs:179–217` | re-arm journal, decide + apply each pending item, save vault, clear pending |
| `recover_share_commit` | `sharing.rs:221–228` | startup recovery entry: read store, finish pending |
| `load_share_store` | `sharing.rs:230–248` | read under `key_transition_lock`; finishes pending if present; notifies `vault_changed` |
| `save_share_store` | `sharing.rs:253–279` | re-read current, generation check, write journal, then finish pending |
| `sync_received_linked_items` | `sharing.rs:459–510` | admission of updates, builds `pending_items` + advances pins (in memory) |
| `accept_share` | `sharing.rs:770–845` | first-contact admission, builds pending insert + pin, commits, then deletes server inbox item |
| `decline_share` | `sharing.rs:849–879` | metadata-only: drop the share record |
| `delete_share` | `sharing.rs:885–955` | local vault unmark/delete, then metadata-only save |
| `send_share` | `sharing.rs:656–766` | server send, local vault "shared" mark, metadata-only save |
| `push_sent_share_update_inner` | `sharing.rs:577–651` | sent-share revision bump, metadata-only save |
| `refresh_linked_shares_inner` / `get_shares` | `sharing.rs:296–355`, `515–572` | network refresh + metadata-only save |
| `Store::save_vault` | `store.rs:424–439` | whole-vault encrypted replacement |
| `Store::load_vault` | `store.rs:441–462` | read vault, `recover_share_commit` before returning |
| `write_secret_file` | `store.rs:691–726` | the single atomic-replacement helper |
| `AppState::persist_current_vault` | `lib.rs:338–358` | vault write under `key_transition_lock` |
| unlock paths | `commands/session.rs:353–359` (biometric), `:459–462` (password) | `recover_pending_rms_migration` → `Crypto` → `Store::load_vault` (which runs share recovery) |
| RMS migration journal (not the share journal) | `store.rs:271–304`, `308–369`, `371–400`; driven by `sync.rs:173–236`, `241–307` | separate two-way old/new RMS bridge, `rms_migration.json` |
| recovery publication journal (not the share journal) | `recovery.rs:204–250` | `recovery_setup.enc`, phase ordering for recovery-share publication |

Bridges: `libVELA/vela-android-bridge/src/lib.rs` and
`libVELA/vela-apple-bridge/src/lib.rs` contain only the **recovery publication**
planner (`journal_present`/`journal_epoch`, e.g. Android `:339–344,1611–1616`;
Apple `:301–306,1510–1515`). Neither bridge contains `shares.enc`,
`pending_items` or a share-journal commit path (grep over `libVELA`). So P3a/P3b
are desktop-only today; mobile share persistence is outside this inventory
(unverified rather than excluded).

### 3.2b The six journal steps, by function

| Step | Functions (in call order) |
|---|---|
| persist journal | `save_share_store` `:267–270` → `write_share_store` `:146–152` → `write_secret_file` `store.rs:691–726` |
| durability re-arm | `finish_pending_items` `:188–191` → `write_share_store` |
| apply to vault | `finish_pending_items` `:192–206` (in memory) → `store.save_vault` `:209` → `write_secret_file` on `vault.enc` |
| clear / cleanup | `finish_pending_items` `:212–215` (pending cleared, generation kept) → `write_share_store`; record-level cleanup is `decline_share`/`delete_share`/`remove_share` |
| crash recovery on startup | `commands/session.rs:353–359`/`:459–462` → `Store::load_vault` `store.rs:441–462` → `recover_share_commit` `sharing.rs:221–228` → `finish_pending_items` |
| generation / pin handling | `next_store_generation` (`vela-client-share-policy/src/lib.rs:301–308`) called at `sharing.rs:261–266`; pin constructed at `:823`/`:505` from `admitted.pin`; sent-share revision at `:618–621` with `checked_add` overflow rejection; admission revision ordering in `plan_share_admission` (`lib.rs:91–97,118–130`) |

### 3.3 Exact filesystem sequences

`write_secret_file` (`store.rs:691–726`) is the only replacement primitive used
by the share journal; it performs, in order:

1. `fs::create_dir_all(parent)`, then `set_permissions(parent, 0o700)`
   (`:692–695`, `728–739`).
2. Build `shares.<uuid>.tmp` and open it `write + create_new`, mode `0o600`
   (`:701–710`).
3. `set_permissions(tmp, 0o600)` (`:711`).
4. `write_all(bytes)` (`:712`).
5. `file.sync_all()` — **file fsync** (`:713`), then drop the handle (`:714`).
6. `fs::rename(tmp, path)` — atomic replacement of `shares.enc` (`:715`).
7. Unix only: open the parent directory and `sync_all()` — **directory fsync**
   (`:716–719`).
8. On any error, best-effort `fs::remove_file(tmp)` (`:722–724`).

The inventory's textual filesystem hits agree: `sharing.rs:130` (`std::fs::read`)
and `store.rs:703,713,715,718,723` (`os-interface-inventory/inventory.json`).

Named sequences used in §4:

- **S1 read**: `fs::read(shares.enc)` → AEAD decrypt → JSON decode
  (`sharing.rs:129–138`).
- **S2 journal replace**: steps 1–8 above on `shares.enc`.
- **S3 vault replace**: `save_vault` = encrypt whole vault, `create_dir_all`
  parent if absent (`store.rs:430–434`), then steps 1–8 on `vault.enc`.
- **S4 clear**: S2 with `pending_items` cleared and `generation` unchanged
  (`sharing.rs:212–215`).

**A. New commit (`accept_share` first contact, or an accepted update)**

with `save_share_store` + `finish_pending_items`:

1. S1 (in `load_share_store`) — plus S2→S3→S4 first if a pending record is
   already readable (`sharing.rs:238–244`).
2. admission in memory: `share_envelope::admit` → policy
   (`sharing.rs:784–802`, `479–506`); pending item + new pin updated in the
   in-memory snapshot (`:813–824`, `:501–505`).
3. S1′ again in `save_share_store` (`:260`), generation check
   `next_store_generation(current.generation, snapshot.generation,
   !current.pending_items.is_empty())` (`:261–266`); reject on mismatch.
4. S2 with `generation = current+1` and `pending_items` non-empty (`:267–270`).
5. `share_commit_checkpoint("journal")` (test only, `:272–273`).
6. S2 **again** with identical content — the re-arm in `finish_pending_items`
   (`:191`).
7. per pending item: `vault.get_item`, tombstone scan, `recovery_should_apply`
   (`:192–199`), then `update_item`/`add_item` **in memory** (`:200–204`).
8. S3 (`store.save_vault`, `:209`), then checkpoint `vault` (`:210–211`).
9. S4 (`write_share_store` with `pending_items` cleared, `:212–215`).
10. `state.vault_changed.notify_one()` (`:276`).

**B. Startup / open recovery**

`commands/session.rs:353–359` or `:459–462` → `Store::load_vault`
(`store.rs:441–462`) → S1 of `vault.enc` → `recover_share_commit` (`:447`,
`:459`) → S1 of `shares.enc` (`sharing.rs:226`) → steps 6–9 above if pending is
non-empty, else no write at all.

**C. In-process retry** (`load_share_store` with a readable pending record,
`sharing.rs:237–246`): S1 then steps 6–9. Used by `get_shares`, `send_share`,
`delete_share`, `decline_share` on their next call.

**D. Metadata-only commit** (`decline_share:875`, `get_shares:560`,
`refresh_linked_shares_inner:353`, `push_sent_share_update_inner:649`,
`send_share:755`, `delete_share:951`): steps 3–5 only (`generation` still
advances; no pending items, no vault write).

**E. Local "shared" mark** (`send_share`): server send (`:736–743`) → in-memory
vault mark (`:745–751`) → S3 via `persist_current_vault` (`:752`, error
discarded) → S2 metadata-only save (`:755`). `delete_share` is the mirror:
in-memory unmark/delete (`:926–938`) → S3 (`:947`, error discarded) → S2
(`:951`).

**F. Unlock ordering**: `recover_pending_rms_migration` (RMS journal, possibly
rewrites `shares.enc` under the new RMS via `rekey_secret_files`,
`store.rs:147–233`) → `Crypto::new` → `load_vault` → share recovery (B). So
share recovery always observes **one** RMS, and runs after the RMS journal is
resolved.

---

## 4. Mapping M28 ↔ Rust

Legend: *fidelity* is this author's manual judgement, not a checked result.

| M28 rule | Rust function(s) | FS sequence | Fidelity / notes |
|---|---|---|---|
| `Initialize` | no explicit function; `ShareStore::default()` (generation 0, empty) via `serde(default)` on a missing `shares.enc` (`sharing.rs:132`), and `VaultStore::new` (`vault.rs:691–701`) | none (first S2 creates the file) | **Implicit.** No `Initialized`/`Out` equivalent. `'initial'` maps to `generation == 0` with no pending record. |
| `ReadSnapshot` | `read_share_store` (`sharing.rs:125–139`) called from `load_share_store` (`:237`) and from `save_share_store` (`:260`) | S1 / S1′ | **Partial.** M28 needs a *fresh* `~tx` and a `!ReadyGeneration` membership; Rust has neither. Freshness is replaced by `sharing_mutex` + the generation-equality check at commit; a readable pending store is recovered rather than snapshotted (M28 has no read-pending rule). Every committed generation is implicitly "ready". |
| `PersistJournal` | `save_share_store` write (`sharing.rs:267–270`) → `write_share_store` (`:141–156`) → `write_secret_file` | S2, steps 3–5 of A | **Good on ordering, weak on granularity.** Generation+pin+payload are published by one file replacement before any vault write, as M28 requires. Gaps: (i) `pending_items` is a vector (several item changes per generation), M28 has one payload per commit; (ii) the store generation also advances for metadata-only saves (D), which M28 does not model; (iii) `Snapshot` consumption is implicit, so the `commit_uses_snapshot_generation` relation becomes "the snapshot object carries `generation`, checked for equality at write time". |
| `PersistVault` | `finish_pending_items` loop (`sharing.rs:192–206`) + `store.save_vault` (`:209`) | S3, step 8 of A | **Ordering matches; atomicity differs.** M28 applies one pending payload; Rust writes the *whole* vault once, so one S3 can realize several pending item applications. The in-memory apply happens before S3, so a crash between them is invisible to the durable model (recovery re-reads). Repeated identical S3 writes during recovery are the stutter the correspondence doc already documents (`share-journal-correspondence.md:84–88`). |
| `ClearJournal` | `write_share_store(finished)` (`sharing.rs:212–215`) | S4, step 9 of A | **Matches**, including preserving `generation`: the clear path calls `write_share_store` directly, *not* `save_share_store`, so the generation is not incremented. It also keeps every pin in the file, re-producing `ReadyGeneration`-like availability. |
| `Crash` | no code; test injection at `sharing.rs:164–173` (phases `journal`, `vault`, `share-write`) | — | **Absent by construction.** Every crash point between steps 4/6/8/9 is exercised by `interrupted_linked_update_recovers_content_and_pin_on_open` (`:1225–1270`), `interrupted_first_acceptance_recovers_exactly_one_item` (`:1272–1295`), `recovery_preserves_a_local_edit_after_an_interrupted_commit` (`:1366–1390`), `recovery_does_not_resurrect_a_deleted_received_copy` (`:1413–1434`), `uncertain_journal_write_is_rearmed_before_recovery_changes_vault` (`:1469–1498`). |
| `OpenVault` | `Store::load_vault` (`store.rs:441–462`) → `recover_share_commit` (`:447`, `:459`); caller publishes the vault in `commands/session.rs:380–383` | B | **Matches the composite**, not a single rule: Rust cannot open without first finishing recovery, whereas M28's `OpenVault` is guarded by `DiskClean` and therefore follows `PersistVault`+`ClearJournal`. Fail-closed on a corrupt journal (`sharing.rs:130–137`; test `:1318–1326`) is an unmodelled branch (no silent reset to `DiskClean`). |

### 4.1 Rust steps with no M28 rule (stutters / unmodelled behaviour)

| Rust step | Where | Classification |
|---|---|---|
| Re-arm write of an unchanged pending journal before touching the vault | `sharing.rs:188–191` | Idempotent same-content replacement ⇒ **stutter** (no `JournalDurable` event), but P3b/P3d must prove the replacement is observationally identical (same bytes, same generation) and that a failure leaves the phase unchanged. Test `:1469–1498`. |
| Second S2 in the same successful commit (step 6 always follows step 4) | same | stutter; a crash between the two leaves the same durable state. |
| Non-no-op S3 during recovery from `DiskApplied` (vault already applied) | `sharing.rs:209` | stutter, already documented in `share-journal-correspondence.md:84–88`. |
| Generation advance with an empty `pending_items` (metadata-only save) | `sharing.rs:267–270` (D) | **not modelled**: M28's `PersistJournal` always carries a payload and a `successor(gen)` advancing `Chain`. Needs either a quotient on commit generations or an added stutter/metadata rule in P3b. |
| In-memory vault mutation before S3 | `sharing.rs:200–204` | outside the durable model; harmless while recovery re-reads, but must be stated as an abstraction (`state.vault` is volatile). |
| Local edit wins / tombstone skip | `recovery_should_apply` (`sharing.rs:195–199`, `vault.rs:812–817`) | **not modelled** by M28 (plan P5). A locally deleted received copy freezes the pin: `if let Some(before)` at `sharing.rs:497` wraps both the pending push and the pin update, so no pin advance is recorded while the item is absent. |
| Sent-share revision bump and `with_shared_status` marks | `sharing.rs:618–646`, `745–751`, `926–930` | not modelled; `sent_shares[].revision` is not an M28 pin. |
| Server effects around the local commit | `send_share:736–743`; `accept_share:826–834`; `delete_share:896–919` | not modelled; M28 has no network. Note `send_share` sends before the local save, so a rejected stale save (`:261–266`) leaves a server-side share with no local record. |
| Failure of a write after rename | `store.rs:715` then error at `:718` | **not modelled as a rule**: two durable outcomes. 09 permits this ("failures may leave either the before or the after state", `09-target-contract.md:11–14`), so P3b needs a relational/may-step, not a deterministic function. |
| Decode/decrypt failure | `sharing.rs:130–138` | unmodelled branch; the required outcome (fail closed, keep pins) has a regression test (`:1318–1326`) but no model. |

### 4.2 M28 rules/aspects with no Rust counterpart

| M28 element | Status in Rust |
|---|---|
| `Crash` rule | No code; crashes are process death/power loss. Modelled only by test fault injection. |
| `!ReadyGeneration` guard on `ReadSnapshot` | No counterpart; there is no readiness fact. Any readable store may be read, and staleness is only caught at commit (`next_store_generation`). M28's design (snapshot only after a clear) is stronger than the code. |
| Fresh `~tx` per snapshot | No counterpart; the optimistic generation check plus `sharing_mutex` plays this role, and the tx identity for `application_requires_prior_durable_journal` / `each_transaction_applies_at_most_once` has to be *derived* (e.g. the generation at which the pending record was written). |
| One pin and one payload per slot | Rust has one store-wide generation, one `pending_items` vector, and one pin **per received share**. The refinement needs a projection: fix one received share (one lineage) as the slot, frame all other shares, and either restrict commits to one pending item or extend the model to a set of payloads (plan P4). |
| `vrev`/`vpayload` provenance labels | Not serialized (documented at `share-journal-correspondence.md:84–86`); they are implicit in the whole `vault.enc` replacement. |
| `Out(slot)` in `Initialize` | No counterpart; slot identity is the store directory + profile, chosen by the app data path (`store.rs:78–91`). |

### 4.3 Where the code relies on the 09 filesystem contract

`09-target-contract.md:9–16` trusts: successful file sync, then atomic
replacement, then directory sync, has the advertised durability; a failed write
may be visible without confirmed durability, and "reading it does not upgrade
that status". The code's reliance is exactly:

1. `write_secret_file` treats `Ok` as a durability acknowledgement only after
   `rename` **and** the Unix directory fsync (`store.rs:713–719`). This is the
   whole basis for mapping `Ok` to `JournalDurable`/`VaultDurable`/
   `JournalCleared`.
2. `finish_pending_items:188–191` implements the "reading it does not upgrade
   that status" clause: a visible pending record is re-written before the vault
   is touched, and a failed re-arm aborts recovery (`:191`'s `?`). Regression:
   `sharing.rs:1469–1498`.
3. The comment at `store.rs:696–699` states the failure model the code assumes
   ("failures before rename leave the old file intact; an error after rename is
   an uncertain commit and callers must allow replay").
4. Directory fsync is `#[cfg(unix)]` (`store.rs:716–719`); on Windows the same
   contract is trusted without a directory handle. This is a platform gap to
   record in P3c/P3d, not a code defect observed here.

Outside the contract, and therefore excluded by 09: a second process writing
`shares.enc`/`vault.enc`, disk-image rollback, malicious same-UID access. The
code's protection is cooperative (`sharing_mutex`, `key_transition_lock`,
generation check), which is what the model one-linear-state assumption encodes
(`share-journal-correspondence.md:18`).

### 4.4 Ordering differences from the model

| # | M28 order | Rust order | Why it matters |
|---|---|---|---|
| O1 | `PersistJournal` → `PersistVault` → `ClearJournal` | S2 → S2(re-arm) → S3 → S4 | one extra journal write; must be a stutter |
| O2 | snapshot read is a linear precondition of the commit | read at `load_share_store`, possibly much earlier (across network awaits in `send_share`), re-checked by generation equality at `:260–266` | the observation/commit split is wider than the model's; a stale snapshot is rejected (test `:1206–1223`), which corresponds to M28 simply not firing `PersistJournal` |
| O3 | `PersistVault` and `ClearJournal` observe the exact `DiskPending` written by the model | `finish_pending_items` re-reads nothing; it trusts the in-memory snapshot it was handed, whose `generation` was just validated | model-equivalent only under "no concurrent writer", i.e. `sharing_mutex` |
| O4 | vault application is decided by the model's state | decided by comparing live vault content to a `before` captured under a **read** lock (`sharing.rs:466–506`), applied later under a write lock | local-edit wins is a policy outside M28 (P5); not an M28 ordering violation |
| O5 | nothing writes before `PersistJournal` | `send_share`/`delete_share` write the vault (S3) **before** the journal save | reverse order for local mark operations; M28 does not model them, but P5 must, and the crash window is real (durable `shared` flag, no sent record) |
| O6 | `OpenVault` after `ClearJournal` | `load_vault` always recovers first, and fails closed if recovery cannot complete | matches the composite; the "open a pending vault" state is unreachable through the public path |
| O7 | CMS/metadata absent | metadata saves advance the generation | breaks the "generation = commit count" reading (see §4.1) |

---

## 5. Is the journal step already a pure function?

**No — only three decisions are.** Extracted and hax-checked today
(`libVELA/vela-client-share-policy/src/lib.rs`, selected in
`verify-fstar.sh`):

| Pure function | Line | What it decides | Caller |
|---|---|---|---|
| `initial_acceptance_is_authorized(accepted, has_pin, has_payload)` | 278–281 | may this received share be accepted for the first time | `sharing.rs:784` |
| `next_store_generation(current, snapshot, pending) -> Option<u64>` | 301–308 | accept/refuse a commit and the next generation | `sharing.rs:261` |
| `recovery_should_apply(matches_before, present, tombstoned)` | 338–345 | apply or skip one pending item | `sharing.rs:195` |

Their postconditions and negative theorems are in the same file
(`:283–365`), and the runner extracts nineteen entry points
(`verify-fstar.sh:16–18`, single `-i` list on line 17). Everything else that constitutes the journal step is
effectful and bound to `AppState`:

- `finish_pending_items` mixes (a) the durability re-arm, (b) per-item equality
  and tombstone decisions, (c) vault mutation, (d) `save_vault`, (e) the clear
  write, and (f) test fault injection, in one 39-line function taking
  `&Store, &Crypto, &mut VaultStore, &mut ShareStore`.
- `save_share_store` mixes lock acquisition, crypto selection, a second disk
  read, generation planning, the journal write, and pending completion.
- `read_share_store`/`write_share_store` mix serialization, AEAD and the fs
  helper.
- `sync_received_linked_items`/`accept_share` compute the pending item and the
  new pin inline inside network/lock-heavy functions.

So P3a needs a real split, not just annotations.

### 5.1 P3a refactor sketch

Target shape (mirroring the repo's existing driver/interpreter pattern: pure
model inside a hax-extractable crate, IO interpreter outside):

1. **New pure crate** `libVELA/vela-client-share-journal` (dependency-free like
   `vela-client-share-policy`; `String`/`u64`/`Option`/`Vec` only, no `serde`,
   no `std::fs`, no `Crypto`). Keep `serde`/AEAD in `sharing.rs`.
2. **`ShareJournal` plain model**: `{ generation: u64, pending: Vec<PendingItem> }`
   plus `ItemRef`, `RecoveryObservation { id, matches_before, present, tombstoned }`,
   `CommitObservation { current_generation, snapshot_generation, disk_pending }`.
3. **`JournalPhase` state machine** `Clean { generation, pins }`,
   `Pending { generation, pins, items }`, `Applied { ... }` with
   `step(phase, input) -> Option<(JournalAction, JournalPhase)>` where
   `JournalAction ∈ { WriteJournal, WriteVault, ClearJournal }`. This is the
   function P3b relates to `PersistJournal`/`PersistVault`/`ClearJournal`; it is
   a *planner*, so the real code must interpret exactly one action per call.
4. **Split the existing functions** (names to create):
   - `sharing::save_share_store` → `plan_share_commit(current_gen, snapshot_gen,
     disk_pending) -> CommitDecision` (reuse/keep `next_store_generation`) +
     `apply_commit_plan(snapshot, next_gen) -> ShareStore` (pure, sets
     generation) + `persist_journal(...)` (IO) + `finish_pending_items`.
   - `sharing::finish_pending_items` → `plan_recovery_application(pending:
     &[PendingShareItem], obs: &[RecoveryObservation]) -> Vec<RecoveryDecision>`
     (pure; each decision wraps `recovery_should_apply`) +
     `apply_recovery_decisions(vault, &decisions)` (IO/memory) +
     `clear_pending(snapshot) -> ShareStore` (pure) + the two writes.
   - `sharing::read_share_store` → `decode_share_store(&[u8]) -> Result<ShareStore,
     DecodeError>` (pure, with a plain codec) + `read_share_file` (IO/AEAD).
   - `sharing::sync_received_linked_items` → `plan_pin_update(share: &ShareView,
     item_present: bool, admitted_revision: u64) -> Option<(PendingItem,
     StoredSharePin)>` (pure; the admit decision stays in
     `plan_share_admission`).
   - `sharing::accept_share` → `plan_first_acceptance(share: &ShareView,
     admitted_revision: u64, new_item_id: &str) -> Option<(PendingItem,
     StoredSharePin)>` (pure).
   - `store::write_secret_file` stays **trusted** (P3c/P3d). Optionally expose
     its order as data (`enum ReplaceStep { TempWrite, FileSync, Rename,
     DirSync }`) so P3d can name the phases; no behaviour change.
5. **Types must stay extractable**: `ShareStore`/`PendingShareItem` currently
   derive `serde`, and `VaultItem` is large. Pass *views*
   (`ShareView`, `PendingItem { id, before_digest }`) into the pure crate rather
   than moving `VaultItem`; a digest/`before` equality supplied as a Boolean
   fact is the same abstraction `recovery_should_apply` already uses.
6. **Wire-up**: `verify-fstar.sh` extracts only listed symbols, so add each new
   `plan_*`/`step` function to its `-i` include list (currently
   `verify-fstar.sh:17`) and add postconditions in the style of
   `next_store_generation`. Add a `tests/` case per decision (the crate has
   `tests/exhaustive.rs`).
7. **What P3a must not try to prove**: AEAD/codec, locks, fs durability, or the
   stutter/may-step questions. Those are P3c (fs model), P3d (phase
   realisation), P4 (collection equality for `pending_items`), P5
   (edits/deletions) and P6 (RMS migration).

Minimal first slice that unlocks P3b: `plan_share_commit` +
`plan_recovery_application` + `clear_pending`. They are small, pure, and already
exist in embryo as the three checked policy functions.

---

## 6. Findings

1. **The commit skeleton matches M28, with one extra journal write.** Journal
   (pin+payload) → vault → journal clear is implemented in that order
   (`sharing.rs:270`, `:209`, `:214`), and the clear write deliberately does not
   advance the generation, matching `ClearJournal`'s preserved `Chain` pair.
2. **Generation is a store-write counter, not a commit counter.**
   `save_share_store` advances it for metadata-only saves too (`:268`), so the
   M28 `successor` chain holds only after quotienting out non-commit writes, or
   after adding a metadata/stutter rule. This is the single largest gap for
   P3b.
3. **M28 is one pin/payload per slot; Rust is many pins and a batched pending
   vector behind one generation.** `sync_received_linked_items` can enqueue
   several item changes (`:468–507`) applied by one `PersistVault` (S3). P4's
   collection equality is a prerequisite, not a nicety.
4. **Read/commit split is wider than the model.** Nothing forces the snapshot to
   be "fresh" other than `sharing_mutex` and the equality check at `:261`;
   M28's `~tx`/`ReadyGeneration` preconditions have no Rust analogue.
5. **Uncertain-write handling is correct but needs a may-step in the
   refinement.** `write_secret_file` returns `Ok` only after directory fsync;
   an error after `rename` may leave either state (`09:11–14`), and the re-arm
   at `:191` handles it. M28 rules are deterministic, so P3b must relate one
   Rust write to `{stutter | modelled step}`.
6. **Local edits/deletions are interleaved with journal state outside the
   model** (`:195–199`, `:497`), including a pin that does not advance while the
   received copy is deleted. Documented as P5 work; today the only checked
   decision is `recovery_should_apply`.
7. **`send_share`/`delete_share` write the vault before the journal and ignore
   that write's error** (`:752`, `:947`). These are local mark operations M28
   excludes, but P5's composition will have to cover the reverse order.
8. **Server effects bracket the local commit** (send before, accept/delete
   around it) and can diverge on failure; M28/M29 exclude the network.
9. **Fail-closed behaviour on a corrupt `shares.enc` is unmodelled but
   tested** (`:1318–1326`); it is the right behaviour (no pin reset) and should
   be stated as an assumption/observation in P3b rather than proved from M28.
10. **Share recovery runs outside `key_transition_lock`.** `recover_share_commit`
    and `finish_pending_items` take no RMS lock; they rely on being called from
    `load_vault` during unlock, after the RMS journal is resolved
    (`commands/session.rs:353–359`/`:459–462`). `save_share_store` and
    `load_share_store` do take it (`:254`, `:231`). P6 must record this
    asymmetry.
11. **Directory fsync is Unix-only** (`store.rs:716–719`); Windows relies on the
    09 contract without a directory handle. Record in P3c/P3d.
12. **Other writers touch `vault.enc` without `sharing_mutex`** (`sync.rs:1532`,
    `:1719`, `:1741`, `:1789`; `commands/vault.rs:35–38`; `recovery.rs:1456`),
    so M28's one-linear-state-per-profile assumption is cooperative only (P7).
13. **Mobile bridges have no share journal.** They implement only the recovery
    publication journal planner, so this inventory's mapping is desktop-scoped.

## 7. What is unverified

- No Tamarin or F* gate was run for this inventory; all verdicts cited are from
  the existing docs and logs.
- Fidelity judgements in §4 are manual. In particular the claim that the re-arm
  and the duplicated S2 are observationally identical stutters is argued from
  the code (same snapshot, same generation, `write_secret_file` replaces the
  whole file) but not proved.
- The exact set of `shares.enc` writers outside `vela-desktop-core` was not
  audited (bridges checked; CLI/other tools not searched exhaustively).
- Windows actual behaviour of `File::open(parent)` being skipped was not tested
  here.
- Whether `VaultItem` equality is byte-for-byte stable across serialization
  round trips (needed by `recovery_should_apply`'s `current == before`) is
  assumed from `vault.rs`'s serde model, not re-derived.

## 8. Suggested follow-ups

1. **P3a**: create `vela-client-share-journal` with `plan_share_commit`,
   `plan_recovery_application`, `clear_pending`, `step`; make
   `sharing.rs` call them; extend `verify-fstar.sh`'s include list. Keep
   `write_secret_file` out of extraction.
2. **P3b**: decide the generation abstraction (quotient on commit generations
   vs. an added metadata/stutter rule) and the slot projection (one received
   share as the M28 slot, frames for the rest) before writing the refinement.
3. **P4**: formalize `pending_items` as a sequence with the observed
   first-wins duplicate semantics (second pending item for the same id sees
   `current != before` and is skipped, but is still removed by the clear).
4. **P3d/P8**: turn the S2/S3/S4 order and the re-arm into a named `FsPlan` so
   the proof can cite `store.rs:691–726` phases rather than line numbers.
5. **P5**: cover `send_share`/`delete_share` reverse order and the
   deleted-item pin freeze.
6. **P6**: state the recovery-outside-`key_transition_lock` fact and why unlock
   ordering makes it safe.
7. **P7**: either extend `sharing_mutex` to the direct `vault.enc` writers
   listed in finding 12 or record the exclusion explicitly in 09.
