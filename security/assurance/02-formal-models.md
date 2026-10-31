# 2. Formal models

All models live in [`security/formal/`](../formal/). There are 37 Tamarin
theories (`.spthy`), 3 ProVerif models (`.pv`) and 10 CryptoVerif games (`.ocv`). Each theory's header
comment states its scope. This document collects those scopes in one place
and makes the adversary in each model explicit, because the models differ
a lot in how much adversary they include.

Per-family assurance records with lemma-by-lemma prose:
`*-results.md` in the same directory. The original index is
[`security/formal/README.md`](../formal/README.md).

## 2.1 Common modelling conventions

**Symbolic models use ideal cryptography.** Tamarin and ProVerif use ideal
signatures, hashes and encryption, or uninterpreted/private functions. Some
models abstract a hybrid as one primitive; M29 represents the two signature
checks separately. These models do not prove primitive implementation security.

**Computational exceptions are scoped.** Ten CryptoVerif games cover the
idealized v2 KEM combiner, modular KEM-DEM encryption, AND signatures, v2 RMS
possession proofs and authenticated Shamir reconstruction, plus an explicitly
unproved legacy baseline. They use named
primitive assumptions and a random oracle, not a complete Rust construction
refinement. The uniform prime-order DH model does not establish concrete
X25519 clamping/cofactor correspondence. See
[the computational model boundary](../formal/cryptoverif/README.md).

**Unbounded sessions, bounded by fuel in some models.** Most theories allow
unbounded sessions. To make Tamarin terminate, some theories bound
repetition with linear "fuel" facts (M23: at most two epoch adoptions per
device; M26: grant, device, share-key, web-session, and rotation fuel).
Attacks that need more repetitions than the fuel allows are out of scope for
those theories.

**Linear facts model atomic database guards.** A consumed linear fact
(`Grant`, `CurrentEpoch`, `LinkLive`, …) is the symbolic stand-in for a SQL
compare-and-swap or a sled atomic take. Whether the real storage operation
is actually atomic is checked by the **[EXEC]** race tests, not by the
symbolic proof.

**Reachability lemmas.** Every family includes `exists-trace` lemmas that
show the honest path completes. This guards against vacuous safety proofs.
The lemma counts below include them.

**Lemma counting.** Counts are the number of top-level `lemma` and
`exists-trace` declarations, which is exactly what the CI runners compare
against.

## 2.2 Adversary classes

The models use five adversary classes. Each model in §2.3 names its class.

| Class | Capabilities | Does not get |
|---|---|---|
| **DY-net** | Full Dolev-Yao control of the `In`/`Out` network: read, drop, reorder, replay, inject, and compute with every public term and constructor | Private function symbols, fresh secrets that are never output, honest parties' long-term keys |
| **SDC** (same-domain capability) | DY-net, plus it *is* a co-resident same-UID process: it can emit any request a legitimate local client could (M1–M10) | Kernel-attested peer identity (in M6 and later, it must be a browser-spawned host or a `CompromisedBrowser`), human approval facts |
| **SDC+corrupt** | SDC, plus a `Corrupt_Client` rule that leaks a paired client's private key (M8, M10) | The vault key or passkey keys held inside the core |
| **Adversarial storage** | Can replay, relabel, and recombine envelopes held by an untrusted custodian (cloud in M15/M18; the server's advertised clock and epoch in M23) | Ability to forge authenticated origin (abstracted as an origin check standing in for MAC verification) |
| **Ordering-only** | **No** network adversary. The theory proves that honest state transitions happen only in certain orders (linearity, provenance, invalidation) | Everything: there are no `In`/`Out` facts. Secrecy and MITM claims are out of scope |

Except in the malicious-server M13b/M19c additions documented below, the **server** is modelled as an honest party that enforces its own state
machine in M11–M21 and M26. It is never a fully malicious state-machine
deviator in these theories. Confidentiality against a malicious server rests
on the cryptographic architecture (**[ARG]**), and server-side state
enforcement is cross-checked by **[REF]** and **[EXEC]**. See
[§5 T-2](05-known-limitations.md#trusted-components).

**Long-term key compromise** is modelled in the new M19c/M27 reveal rules, but generally **not** outside those theories and M8/M10
(`Corrupt_Client`). M19b states explicitly that device-key theft is outside
its boundary. No theory models RMS compromise followed by recovery
(post-compromise security), except that M11/M26 prove old-epoch artifacts
are stranded.

## 2.3 Model catalogue

### Credential release (M1–M10), the "working-set" ladder

Design-space analysis for releasing credentials to a browser. Run locally
with Tamarin 1.12.0. **Not gated by the historical CI run; current CI adds a gate** ([§5 G-2](05-known-limitations.md#gaps-in-the-assurance-itself)).

| Model | Lemmas | Adversary | What it shows |
|---|---:|---|---|
| `m1_indomain` | 1 | SDC | **Falsified by design.** No in-domain check can protect a credential from a same-UID requester |
| `m2_se_alone` | 2 | SDC | **`secrecy` falsified by design.** A hardware key without a decision escape still leaks |
| `m3_de_se` | 2 | SDC | Human approval plus hardware key bounds leakage to the approved working set |
| `m4_bool_naive` | 1 | SDC | An unbound boolean approval is replayable and worthless |
| `m5_tr_originbound` | 2 | SDC | An origin-bound signature has zero persistent value to the adversary |
| `m6_ipc_handshake` | 17 | SDC (browser-spawn gated) | The deployed browser↔desktop handshake: pairing with a human-compared fingerprint, per-client signing keys, single-use (client, origin, item) grants, and a request-nonce replay cache that gives injective agreement |
| `m7_oneshot_assertion` | 7 | SDC | A passkey assertion is load-bearing and gated. `credential_never_leaks` |
| `m8_hybrid` | 14 | SDC+corrupt | M7 for passkey origins and M6 for legacy origins, with an airtight mode split. Passkey items never leak even when a client is corrupted |
| `m9a_in_core_login` | 7 | SDC | In-core login for plain-form sites: the credential never enters the domain |
| `m9b_engine_login` | 3 | SDC | **`credential_never_leaks` falsified by design.** An embedded browser engine leaks |
| `m9c_inprocess_sandbox` | 6 | SDC | **Two lemmas falsified by design.** A JS sandbox inside the core lets an escape take the whole vault |
| `m9d_captcha_artifact` | 6 | SDC | A CAPTCHA token minted by the browser is adversary-observable, and that changes nothing |
| `m10_full_ladder` | 20 | SDC+corrupt | The deployed per-origin ladder M7 → M9a → M6 |
| **Total** | **88** | | **83 verified, 5 falsified by design**: `m1.secrecy`, `m2.secrecy`, `m9b.credential_never_leaks`, `m9c.credential_never_leaks`, `m9c.unused_credentials_stay_secret`. Any other falsification is a regression |

Quantitative companion: `password-manager-ipc-leak-graph.py` (how many items
leak over time). The symbolic models cannot count, so the 25-domain-per-unlock
cap is argued, not proved.

### Vault epoch rotation (M11)

| Model | Lemmas | Adversary | Scope and assumptions |
|---|---:|---|---|
| `m11_rekey_epoch_state_machine` | 15 | Ordering-only (outputs only, no `In`) | ACTIVE ↔ FREEZING lifecycle; commit requires two "completeness witnesses" that stand in for universal set checks the real SQL performs; commit, abort, and timeout are exclusive; acknowledgement gating. `E` is arbitrary, so the one-step proof covers every N → N+1 |
| `m11b_rekey_capsule_binding` | 4 | DY-net on the capsule transport | Outer labels are attacker-supplied. The inner `{epoch, rotation_id, rms}` is a `[private]` constructor standing in for AEAD under an RMS_N-derived transition key. Relabel and replay attempts cannot change what is adopted |
| `m11c_rekey_mutation_authority` | 12 | Ordering-only | Web, recovery, and enrollment mutations execute only when their authenticated authority epoch equals the live epoch at the atomic boundary |

### Web sessions (M12, M20)

| Model | Lemmas | Adversary | Scope and assumptions |
|---|---:|---|---|
| `m12_web_session_capability` | 14 | DY-net (limited `In`/`Out`) | Pending → RO/RW grant → capsule → challenge → token → renewal, revocation, expiry. Browser-key proof is a `[private]` constructor `webproof/3`, so signature verification is idealised |
| `m20_web_session_pass_through` | 7 | Ordering-only | Route gating encoded structurally: no rule exists for web tokens on account routes. Renewal is single-use here to keep the state finite; M12 covers reuse |

### Enrollment and recovery (M13–M18)

| Model | Lemmas | Adversary | Scope and assumptions |
|---|---:|---|---|
| `m13_device_enrollment_ceremony` | 16 | **Ordering-only** | The header says explicitly that there is no `In`/`Out`, no secrecy, and no MITM. `primary_sig/6 [private]` is an internal binding token, not a verifiable signature. Proves single claim, inspection before confirmation, exact key binding, and one device per grant |
| `m14_account_recovery_lifecycle` | 18 | Ordering-only | WebAuthn assertion with UV is an honest rule. Proves challenge and grant linearity, credential/epoch binding, replacement, revocation, expiry, and rotation invalidation |
| `m15_client_recovery_boundary` | 15 | Adversarial storage (cloud) + DY-net | The cloud envelope is attacker-controlled. The server response is trusted as authoritative for the account and active epoch. Share authentication is abstracted as an exact-origin check |
| `m16_recovery_publication_consistency` | 14 | Ordering-only | Two-phase stage/finalize/promote. Cloud durability and provider API correctness are assumed |
| `m17_recovery_publication_recovery` | 14 | Ordering-only + crash rules | A crash before every local commit, then resume. Filesystem, Keychain/Keystore, and HTTP durability are assumed |
| `m18_pair_selection` | 15 | Adversarial storage (cloud) + DY-net on contact responses | The full 2-of-3 threshold with three availability witnesses. The contact envelope `tenv/5` and response `resp/6` are opened only with the requester key `reqk`. Shamir coordinates are fixed per split by construction |

### Sharing (M19, M21)

| Model | Lemmas | Adversary | Scope and assumptions |
|---|---:|---|---|
| `m19a_ek_registry_baseline` | 2 | DY-net | **Baseline.** Proves the pre-fix key-substitution attack is reachable (an `exists-trace` that verifies) |
| `m19b_share_channel` | 6 | Ordering-only on capsules | Registration requires possession of `!DevKey` (abstracting a signature). **Device-key theft and capsule exposure are not modelled.** The relay is honest-but-curious. The `signing` builtin is declared but unused |
| `m21_link_revocation_finality` | 3 | Ordering-only | Revocation consumes `LinkLive`. No read occurs after revocation. Sender provenance comes through `!DevKey` |

### Client sync (M23)

| Model | Lemmas | Adversary | Scope and assumptions |
|---|---:|---|---|
| `m23_sync_admission` | 11 | Adversarial storage (server advertises any clock or epoch) | Epochs are `succ` terms, so "exactly +1" is structural. **Bootstrap-only clock:** advancing clocks from admitted revisions are not modelled. Fuel allows at most two adoptions per device |

### Composition (M26)

| Model | Lemmas | Adversary | Scope and assumptions |
|---|---:|---|---|
| `m26_composition` | 4 | Ordering-only | M18 possession grants, M19 share-key registration, and M20 web pass-through share one linear `CurrentEpoch`. Rotation strands all three. Fuel-bounded |
| `m26a_recovery_provenance` | 6 | Ordering-only | Every link of the possession-recovery chain traces to the staged commitment and live epoch |

These are *abstract* compositions. They re-state each subsystem as a few
rules around a shared epoch token. They do not literally compose the M18,
M19, and M20 theories.

### ORAM access-pattern hiding (M22, ProVerif)

Observational equivalence (`equivalence P Q`) against a DY-net adversary on
public channel `c`. The adversary is the server: it sees every request and
chooses every response.

| Model | Result | Scope and assumptions |
|---|---|---|
| `m22a_static_position_baseline` | Equivalence **cannot be proved** (attack found, as intended) | A deterministic public position map links paths to manifest chunk ids |
| `m22b_trivial_oram_hiding` | Equivalence **true** | ≤4 chunks: the whole tree is swept, so transcripts are identical |
| `m22c_path_oram_hiding` | Equivalence **true** | Two accesses to the same chunk, each to a fresh random leaf (`new leaf`), with write-backs under an opaque AEAD (`aead_stash`, no destructor) |

M22 assumptions, stated plainly:

- Leaf freshness is modelled with `new`, so it assumes the client RNG and
  `prepare_access` really draw a fresh uniform leaf. That is checked by
  **[STAT]**, not proved.
- One tree, two rounds, one chunk per world. Read and write are not
  distinguished. Stash dynamics, bucket occupancy, and timing are abstracted
  away. Stash behaviour is covered statistically by M24.
- The only hax-extracted content is `use_trivial_oram_with_threshold` (a
  single `≤` comparison). The access transcripts themselves are written by
  hand ([§3.4](03-implementation-correspondence.md#34-proverif-extraction-m22)).

### Path ORAM stash dynamics (M24, statistical)

`libVELA/vela-crypto/tests/oram_stash_bounds.rs` drives the real `PathOram`
against a tree-structured fake server for thousands of random accesses. It
checks round-trip integrity, bucket padding, unregister completeness, and a
stash bound with wide margins. This is testing, not proof. An EasyCrypt
supermartingale proof is listed as out of scope.

## 2.4 Historical baseline lemma totals

| Family | Theories | Lemmas | CI |
|---|---:|---:|---|
| Credential release M1–M10 | 13 | 88 (83 ✓, 5 ✗ by design) | no |
| M11 rekey | 3 | 31 | yes |
| M12 session, M20 gating | 2 | 21 | yes |
| M13–M18 enrollment and recovery | 6 | 92 | yes |
| M19 sharing, M21 revocation | 3 | 11 | yes |
| M23 sync | 1 | 11 | yes |
| M26 composition | 2 | 10 | yes |
| **Tamarin total** | **30** | **264** | 176 in CI |
| M22 ProVerif | 3 | 3 equivalence queries | yes |

> `security/formal/README.md` historically quoted per-model counts (for example
> "15" for M13, "5" for M19b, "8" for M23) that predate later lemma
> additions. The counts above are taken from the theories and match CI run
> 39864715971.

## 2.5 How to read a model quickly

1. Read the header comment: scope, adversary, expected verdict.
2. Check for `In(`/`Out(`. Without them, the theory is ordering-only.
3. Check `[private]` function symbols. Each one is an idealised
   authentication or encryption step that the implementation must realise.
4. Check linear "fuel" facts. They bound repetition.
5. Run with `--prove` and look for `verified`, `falsified`, and
   `analysis incomplete`. The runners fail on the latter two (except
   M1–M10's intended falsifications) and on any `WARNING:`.

## Current network-adversary additions

The historical catalogue above describes the original 30 theories. Five more
now model concrete wire boundaries. All 17 added lemmas were locally verified
with Tamarin 1.12.0 / Maude 3.5.1; the new CI gate is configured but not yet
witnessed by a successful run.

| Theory | Lemmas | Adversary and result |
|---|---:|---|
| `m13b_enrollment_v3_baseline` | 1 | Malicious server: an attack witness leaks RMS by substituting the KEM key |
| `m13b_enrollment_key_binding` | 4 | Malicious server; both-key fingerprint and authentic human comparison; secrecy, key provenance, reachability |
| `m19c_share_v1_baseline` | 1 | Malicious server: forged-update witness, no compromised keys |
| `m19c_share_sender_authentication` | 5 | Malicious server plus key reveals; honest-pin provenance, pin/lineage stability, revision growth, recipient-key secrecy, reachability |
| `m27_device_authentication` | 6 | DY network, honest server, device-key reveal and selected signing oracles; challenge provenance/single-use and registered-user binding |

[The rule-to-Rust table](../formal/network-boundary-correspondence.md) is part
of the model definition. In particular: M13b assumes an ideal human comparison
and proves no adoption authentication; M19c permits arbitrary positive sender
revisions (a conservative overapproximation), assumes an honest initial
recipient key directory for secrecy, and does not authenticate first contact;
M27 separates lookup from issuance and permits revocation races. These models
remain hand-written abstractions rather than extracted Rust protocols.

## Recoverable share storage (M28)

[`m28_share_journal.spthy`](../formal/m28_share_journal.spthy) adds ten locally
verified properties: the original seven about journal/vault/cleanup ordering,
matching pins/content on opening, snapshot-generation provenance,
per-transaction application uniqueness, per-commit revision advancement and
crash/recovery reachability; the two exact all-pairs goals
`committed_pins_never_decrease` (for any two cleanups in a slot, the later
cleanup pins a strictly larger revision) and
`a_generation_commits_at_most_once` (one slot cannot make the same generation
durable in two transactions); and the witness
`two_successive_commits_advance`, which exhibits two successive real commits
with a strict revision advance so both antecedents are reachable. The two
all-pairs goals are stated over emitted action events only; no state fact
appears in a trace formula.

The all-pairs proofs use the linear `Chain(slot, generation, pin)` ghost fact,
threaded through `Initialize`, `PersistJournal` and `ClearJournal`. No guard
or security restriction was changed. The [F★ development](../formal/m28-trace-equivalence/README.md)
checks event-preserving step/trace lifting and projection between two typed,
initialized, single-slot encodings, with and without Chain. This is a checked
sub-step of the correspondence argument; it does not import the Tamarin
verdicts. Its transfer theorem takes the encoded trace property as a proof
argument. Separate direct inductions now prove the all-pairs goals for
encoded core/lift traces, with an explicit strict-order argument for pins and
no order requirement for generation uniqueness. A concrete unary order and
checked two-commit trace establish non-vacuity only for the encoding, not the
Tamarin source. The full source term/subterm interpretation remains open.

Two source obligations remain unproved: original Tamarin traces must embed
into the core encoding, and their encoded lifts must correspond to admissible
instrumented Tamarin traces. Attacker input derivability, global freshness,
term/sort representation, initialization and multi-slot projection require
that bridge. Thus the actual all-pairs verdicts remain results about the
instrumented Tamarin model. The source bridge and Rust/filesystem refinement
remain open; the handwritten F★ artifact adds no extracted Rust contracts.

The product-state facts encode separate writes to the two files. Durable
single-file replacement is trusted; local edits, native persistence and
independent processes are outside this model. Stale snapshots survive crashes
as an overapproximation. Generation successor terms abstract checked u64
increments; overflow is rejected by the separately checked production policy.
The journal runner also runs `check-action-atoms.py`, which rejects lemma or
restriction atoms whose fact name/arity is not emitted in a rule action list;
its regression rejects the historical `DiskClean(...) @ #i` shape. This is a
lightweight source guard against vacuous trace formulas, not a soundness
certificate. See [formalization status](08-formalization-status.md) for the
exact claims and nonclaims.

## Composed signed sharing and commit (M29)

M29 adds eleven checked lemmas to the same transition system: independent
ML-DSA/Ed25519 keys and reveals, actual sender provenance, first-pin uniqueness
and preservation, separate journal/vault/cleanup, matching content/pin views,
and honest crash/recovery/update reachability. It gives the attacker signed
plaintext and makes no hybrid-KEM confidentiality claim. See the
[code mapping](../formal/signed-share-commit-correspondence.md) and
[selected boundary](09-target-contract.md). The journal runner checks M28/M29
and rejects missing verdicts, warnings or timeouts.
