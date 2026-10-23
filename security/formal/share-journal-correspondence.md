# M28 and the production sharing journal

This mapping is manually reviewed, not a checked trace-refinement theorem.
M28 begins after authenticated admission and abstracts durable file replacement.
The policy functions below are extracted from the Rust actually called by the
desktop. File I/O, data comparisons and lock semantics remain outside them.

| Concrete boundary | Checked decision or M28 rule | Remaining assumption/obligation |
|---|---|---|
| `accept_share` observes accepted status, pin and capsule presence | F* `initial_acceptance_is_authorized` | Trust the loaded record and its identity; mutex covers one AppState |
| `save_share_store` compares current and snapshot generations and pending journal state | F* `next_store_generation`; M28 `ReadSnapshot` / `PersistJournal` | Reads and generation comparison must be inside serialized operation; u64 overflow is rejected, while M28 successor terms are unbounded |
| `write_share_store` encrypts new pins and intended item mutations before any vault mutation | M28 `PersistJournal` | AEAD, serialization and durable atomic single-file replacement are trusted; no Rust/FS refinement proof |
| `finish_pending_items` compares current item with preimage and checks tombstone | F* `recovery_should_apply` | Equality of real VaultItems, current presence and tombstone lookup are supplied facts; M28 excludes competing local edits/deletions |
| `save_vault` finishes before pending changes are cleared | M28 `PersistVault`, `ClearJournal` | Successful sync/rename must provide the advertised durability and ordering; uncertain failure may correspond to pre- or post-write state |
| `Store::load_vault` calls recovery before returning contents | M28 `OpenVault` after cleanup | Actual restart/loader ordering is inspected and tested, not formally refined |
| `sharing_mutex` serializes complete read/modify/write workflows | One linear product-state per profile in M28 | Tokio mutual exclusion and participation of every caller are trusted; independent processes are excluded |
| Failed or repeated recovery writes | Crashes are stuttering transitions on durable state; persistence rules resume afterward | Volatile snapshots are retained as an overapproximation; external disk-image rollback and faulty storage are excluded |

The product fact contains both durable files as separate fields. PersistJournal
changes share metadata only; PersistVault changes vault fields only; ClearJournal
changes metadata only. This represents independent writes rather than assuming
an atomic two-file transaction. OpenVault checks a relation between independently
named pin/revision fields; equality is a proved invariant, not its rule guard.

Candidate revisions can be adversarial terms satisfying strict subterm increase,
as in M19c, overapproximating the intended u64 ordering. Authentication is a
precondition of this focused model. There is no machine-checked composition
between M19c, M28, the crypto constructor and the desktop implementation.
Seven exact local verdicts are in the assurance evidence. Stronger all-pairs
goals remain unproved as recorded in the formalization ledger.

The vault revision in M28 is a provenance label, not a separate serialized
VaultItem field. Repeated identical physical writes during recovery are
abstracted as stuttering; application uniqueness concerns logical content
transitions, not the number of fsync/write syscalls. Pending/applied states
classify the pair of durable files; they are not an extra persisted phase flag.
These abstraction choices still require a concrete refinement theorem.

Recovery now explicitly re-arms a read pending journal with a successful durable
write before changing the vault. A visible journal from an earlier failed write
is not treated as a durability acknowledgment. An injected-error regression
failed before this safeguard and passes after it. This strengthens the concrete
mapping to journal-before-vault ordering; a full I/O trace proof is still open.
