module Vela_rekey_policy_rekey_driver_composition

/// Concurrent composition of the *extracted* vault key-rotation driver
/// (`Vela_rekey_policy.Rekey_driver`) over one account's shared key row.
///
/// A schedule is an arbitrary finite interleaving of actions: `Spawn` starts a
/// `start`, `capsules`, `commit` or `abort` request from any device or web
/// session, with any rotation-id and epoch headers; `Step i c` makes request
/// `i` perform the executor call for the effect its own extracted driver
/// emitted last, with the outcome `c` chosen by the scheduler (I/O failures,
/// pacing, probe results, clock expiry, the CAS's other SQL clauses). Every
/// observation that is a fact about the key row (`key_epoch`, `rekey_state`,
/// `rekey_starter`, `rekey_id`, `last_rekey_*`) is computed from the live
/// world at the step the handler reads it. The freeze CAS, the commit CAS and
/// `rollback_rekey` evaluate their SQL guard against the live row and apply
/// their write in that same step; the observation they return is exactly
/// whether the write happened.
///
/// The counters are keyed on the driver's decisions: a commit is counted when
/// the extracted driver's `committed` flag rises, an abort when the rollback
/// the driver emitted wins, a web-session step when the handler would perform
/// any executor call for a web-session request.
///
/// Theorems, for every schedule (`composition_theorem` and its corollaries):
///
/// 1. `at_most_one_commit_per_epoch`: the epochs commits were decided from are
///    pairwise distinct;
/// 2. `no_commit_after_abort`: no commit of a rotation after its abort
///    (explicit, timeout, or failed freeze transaction), and no rollback of a
///    committed rotation;
/// 3. `committed_ids_are_unique`;
/// 4. `committed_and_aborted_are_disjoint`;
/// 5. `commit_only_after_completeness`: a commit is decided only by a request
///    to which both completeness probes returned `Empty`;
/// 6. `starter_only_authority`: every commit and every winning abort removes
///    a rotation the request's own device started (`rollback_rekey` does not
///    check the starter; the driver's load-time check does);
/// 7. `web_session_never_authorizes`: no executor call is performed for a web
///    session.
///
/// The witnesses at the end show the theorems are not vacuous: a full rotation
/// commits, a second commit, a non-starter abort and a commit of an aborted
/// rotation are refused, the starter's abort wins, a web session is refused.
///
/// Assumptions (not proved here): each SQL statement is atomic and
/// linearizable; the freeze transaction is linearized at its freeze CAS, and a
/// failed transaction commit reverts exactly that write (the transaction's
/// write lock keeps other writers out, so this over-approximates); rotation
/// ids are fresh per freeze CAS (server UUIDs); the handler performs exactly
/// the effect its driver emitted, in the step it observes the result. The
/// capsule writes, chunk rows, the clock and the readiness/completeness tables
/// are abstracted into scheduler choices.

open FStar.Mul
open Core_models
open Vela_rekey_policy
open Vela_rekey_policy.Rekey_driver
open Vela_rekey_policy_rekey_driver_lemmas

// ── What one driver step can decide ────────────────────────────────────────

/// The loaded row the driver just consumed named a freezing rotation, this
/// device as its starter, and the request's rotation-id header as its id.
let rollback_authorized (ev: t_RekeyEvent) : bool =
  match ev with
  | RekeyEvent_State (StateObservation_Loaded s)
  | RekeyEvent_Timeout (TimeoutObservation_Raced s) ->
      s.f_freezing && s.f_starter_matches && s.f_header_matches
  | _ -> false

let is_commit_updated (ev: t_RekeyEvent) : bool =
  match ev with
  | RekeyEvent_CommitCas CasObservation_Updated -> true
  | _ -> false

let is_chunks_empty (ev: t_RekeyEvent) : bool =
  match ev with
  | RekeyEvent_Chunks ProbeObservation_Empty -> true
  | _ -> false

let is_devices_empty (ev: t_RekeyEvent) : bool =
  match ev with
  | RekeyEvent_Devices ProbeObservation_Empty -> true
  | _ -> false

let is_commit_cas_stage (d: t_RekeyDriver) : bool =
  match d.f_stage with
  | RekeyStage_CommitCas -> true
  | _ -> false

let is_rollback_effect (e: t_RekeyEffect) : bool =
  match e with
  | RekeyEffect_RollbackAttempt -> true
  | _ -> false

/// The facts the composition needs from one extracted `rekey_step`:
/// a commit is decided exactly on an observed winning commit CAS; a commit
/// request's completeness flags only rise on an `Empty` probe; and an abort's
/// rollback is only emitted right after a load that named this device as the
/// starter of the live rotation the request names.
let frame (d: t_RekeyDriver) (ev: t_RekeyEvent) (t': t_RekeyTransition) : prop =
  (t'.f_driver.f_committed /\ not d.f_committed ==> is_commit_updated ev) /\
  (is_commit_updated ev /\ is_commit_cas_stage d ==> t'.f_driver.f_committed) /\
  (d.f_op == RekeyOp_Commit ==>
     (t'.f_driver.f_chunks_complete ==> d.f_chunks_complete \/ is_chunks_empty ev) /\
     (t'.f_driver.f_capsules_complete ==> d.f_capsules_complete \/ is_devices_empty ev)) /\
  (is_rollback_effect t'.f_effect ==> rollback_authorized ev)

#push-options "--fuel 4 --ifuel 2"

let frame_rate_limit (d: t_RekeyDriver) (o: t_RateLimitObservation)
  : Lemma (requires rekey_state_is_sound d)
          (ensures frame d (RekeyEvent_RateLimit o) (rekey_step d (RekeyEvent_RateLimit o))) =
  match o with
  | RateLimitObservation_Allowed -> ()
  | RateLimitObservation_Limited -> ()

let frame_state_start (d: t_RekeyDriver) (o: t_StateObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Start)
          (ensures frame d (RekeyEvent_State o) (rekey_step d (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let frame_state_capsules (d: t_RekeyDriver) (o: t_StateObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Capsules)
          (ensures frame d (RekeyEvent_State o) (rekey_step d (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let frame_state_commit (d: t_RekeyDriver) (o: t_StateObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Commit)
          (ensures frame d (RekeyEvent_State o) (rekey_step d (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let frame_state_abort (d: t_RekeyDriver) (o: t_StateObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Abort)
          (ensures frame d (RekeyEvent_State o) (rekey_step d (RekeyEvent_State o))) =
  match o with
  | StateObservation_Loaded _ -> ()
  | StateObservation_Storage -> ()
  | StateObservation_NotFound -> ()

let frame_timeout_start (d: t_RekeyDriver) (o: t_TimeoutObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Start)
          (ensures frame d (RekeyEvent_Timeout o) (rekey_step d (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let frame_timeout_capsules (d: t_RekeyDriver) (o: t_TimeoutObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Capsules)
          (ensures frame d (RekeyEvent_Timeout o) (rekey_step d (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let frame_timeout_commit (d: t_RekeyDriver) (o: t_TimeoutObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Commit)
          (ensures frame d (RekeyEvent_Timeout o) (rekey_step d (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let frame_timeout_abort (d: t_RekeyDriver) (o: t_TimeoutObservation)
  : Lemma (requires rekey_state_is_sound d /\ d.f_op == RekeyOp_Abort)
          (ensures frame d (RekeyEvent_Timeout o) (rekey_step d (RekeyEvent_Timeout o))) =
  match o with
  | TimeoutObservation_RolledBack -> ()
  | TimeoutObservation_Raced _ -> ()
  | TimeoutObservation_Storage -> ()

let frame_probe (d: t_RekeyDriver) (ev: t_RekeyEvent)
  : Lemma (requires rekey_state_is_sound d /\
                    (match ev with
                     | RekeyEvent_Oram _ | RekeyEvent_Capable _ | RekeyEvent_Acknowledged _
                     | RekeyEvent_Chunks _ | RekeyEvent_Devices _ -> true
                     | _ -> false))
          (ensures frame d ev (rekey_step d ev)) =
  match ev with
  | RekeyEvent_Oram ProbeObservation_Empty -> ()
  | RekeyEvent_Oram ProbeObservation_Found -> ()
  | RekeyEvent_Oram ProbeObservation_Storage -> ()
  | RekeyEvent_Capable ProbeObservation_Empty -> ()
  | RekeyEvent_Capable ProbeObservation_Found -> ()
  | RekeyEvent_Capable ProbeObservation_Storage -> ()
  | RekeyEvent_Acknowledged ProbeObservation_Empty -> ()
  | RekeyEvent_Acknowledged ProbeObservation_Found -> ()
  | RekeyEvent_Acknowledged ProbeObservation_Storage -> ()
  | RekeyEvent_Chunks ProbeObservation_Empty -> ()
  | RekeyEvent_Chunks ProbeObservation_Found -> ()
  | RekeyEvent_Chunks ProbeObservation_Storage -> ()
  | RekeyEvent_Devices ProbeObservation_Empty -> ()
  | RekeyEvent_Devices ProbeObservation_Found -> ()
  | RekeyEvent_Devices ProbeObservation_Storage -> ()
  | _ -> ()

let frame_freeze (d: t_RekeyDriver) (ev: t_RekeyEvent)
  : Lemma (requires rekey_state_is_sound d /\
                    (match ev with
                     | RekeyEvent_Transaction _ | RekeyEvent_Inventory _ | RekeyEvent_FreezeCas _
                     | RekeyEvent_Cleanup _ | RekeyEvent_TxCommit _ -> true
                     | _ -> false))
          (ensures frame d ev (rekey_step d ev)) =
  match ev with
  | RekeyEvent_Transaction TransactionObservation_Committed -> ()
  | RekeyEvent_Transaction TransactionObservation_Failed -> ()
  | RekeyEvent_Inventory InventoryObservation_Read -> ()
  | RekeyEvent_Inventory InventoryObservation_Failed -> ()
  | RekeyEvent_FreezeCas CasObservation_Updated -> ()
  | RekeyEvent_FreezeCas CasObservation_Skipped -> ()
  | RekeyEvent_FreezeCas CasObservation_Storage -> ()
  | RekeyEvent_Cleanup CleanupObservation_Done -> ()
  | RekeyEvent_Cleanup CleanupObservation_Storage -> ()
  | RekeyEvent_TxCommit TransactionObservation_Committed -> ()
  | RekeyEvent_TxCommit TransactionObservation_Failed -> ()
  | _ -> ()

let frame_capsule (d: t_RekeyDriver) (o: t_CapsuleObservation)
  : Lemma (requires rekey_state_is_sound d)
          (ensures frame d (RekeyEvent_Capsule o) (rekey_step d (RekeyEvent_Capsule o))) =
  match o with
  | CapsuleObservation_Stored -> ()
  | CapsuleObservation_Invalid -> ()
  | CapsuleObservation_NotTarget -> ()
  | CapsuleObservation_Storage -> ()

let frame_commit (d: t_RekeyDriver) (ev: t_RekeyEvent)
  : Lemma (requires rekey_state_is_sound d /\
                    (match ev with
                     | RekeyEvent_CommitCas _ | RekeyEvent_Sweep _ | RekeyEvent_Published
                     | RekeyEvent_Rollback _ -> true
                     | _ -> false))
          (ensures frame d ev (rekey_step d ev)) =
  match ev with
  | RekeyEvent_CommitCas CasObservation_Updated -> ()
  | RekeyEvent_CommitCas CasObservation_Skipped -> ()
  | RekeyEvent_CommitCas CasObservation_Storage -> ()
  | RekeyEvent_Sweep SweepObservation_Done -> ()
  | RekeyEvent_Sweep SweepObservation_Failed -> ()
  | RekeyEvent_Published -> ()
  | RekeyEvent_Rollback RollbackObservation_RolledBack -> ()
  | RekeyEvent_Rollback RollbackObservation_Raced -> ()
  | RekeyEvent_Rollback RollbackObservation_Storage -> ()
  | _ -> ()

#pop-options

let frame_state (d: t_RekeyDriver) (o: t_StateObservation)
  : Lemma (requires rekey_state_is_sound d)
          (ensures frame d (RekeyEvent_State o) (rekey_step d (RekeyEvent_State o))) =
  match d.f_op with
  | RekeyOp_Start -> frame_state_start d o
  | RekeyOp_Capsules -> frame_state_capsules d o
  | RekeyOp_Commit -> frame_state_commit d o
  | RekeyOp_Abort -> frame_state_abort d o

let frame_timeout (d: t_RekeyDriver) (o: t_TimeoutObservation)
  : Lemma (requires rekey_state_is_sound d)
          (ensures frame d (RekeyEvent_Timeout o) (rekey_step d (RekeyEvent_Timeout o))) =
  match d.f_op with
  | RekeyOp_Start -> frame_timeout_start d o
  | RekeyOp_Capsules -> frame_timeout_capsules d o
  | RekeyOp_Commit -> frame_timeout_commit d o
  | RekeyOp_Abort -> frame_timeout_abort d o

/// Every extracted transition satisfies `frame`.
let step_frame (d: t_RekeyDriver) (ev: t_RekeyEvent)
  : Lemma (requires rekey_state_is_sound d) (ensures frame d ev (rekey_step d ev)) =
  match ev with
  | RekeyEvent_RateLimit o -> frame_rate_limit d o
  | RekeyEvent_State o -> frame_state d o
  | RekeyEvent_Timeout o -> frame_timeout d o
  | RekeyEvent_Capsule o -> frame_capsule d o
  | RekeyEvent_Oram _ | RekeyEvent_Capable _ | RekeyEvent_Acknowledged _
  | RekeyEvent_Chunks _ | RekeyEvent_Devices _ -> frame_probe d ev
  | RekeyEvent_Transaction _ | RekeyEvent_Inventory _ | RekeyEvent_FreezeCas _
  | RekeyEvent_Cleanup _ | RekeyEvent_TxCommit _ -> frame_freeze d ev
  | RekeyEvent_CommitCas _ | RekeyEvent_Sweep _ | RekeyEvent_Published
  | RekeyEvent_Rollback _ -> frame_commit d ev

let next_epoch_succ (e t: i64)
  : Lemma (requires next_epoch e == Core_models.Option.Option_Some t)
          (ensures v t = v e + 1) = ()

let b2n (b: bool) : nat = if b then 1 else 0

// ── List vocabulary (Core_models shadows the unqualified names) ────────────

let rec mem_id (x: nat) (l: list nat) : bool =
  match l with
  | [] -> false
  | y :: t -> x = y || mem_id x t

let rec nodup_ids (l: list nat) : bool =
  match l with
  | [] -> true
  | y :: t -> not (mem_id y t) && nodup_ids t

let rec disjoint_ids (a b: list nat) : bool =
  match a with
  | [] -> true
  | x :: t -> not (mem_id x b) && disjoint_ids t b

let rec ids_lt (l: list nat) (n: nat) : bool =
  match l with
  | [] -> true
  | x :: t -> x < n && ids_lt t n

let rec mem_epoch (x: int) (l: list int) : bool =
  match l with
  | [] -> false
  | y :: t -> x = y || mem_epoch x t

let rec nodup_epochs (l: list int) : bool =
  match l with
  | [] -> true
  | y :: t -> not (mem_epoch y t) && nodup_epochs t

let rec epochs_lt (l: list int) (n: int) : bool =
  match l with
  | [] -> true
  | x :: t -> x < n && epochs_lt t n

/// `(rotation id, starting device)` for every rotation a freeze CAS created.
let rec starter_of (l: list (nat & nat)) (rid: nat) : option nat =
  match l with
  | [] -> None
  | (r, d) :: t -> if r = rid then Some d else starter_of t rid

let rec started_lt (l: list (nat & nat)) (n: nat) : bool =
  match l with
  | [] -> true
  | (r, _) :: t -> r < n && started_lt t n

let rec ids_lt_mem (l: list nat) (n x: nat)
  : Lemma (requires ids_lt l n /\ mem_id x l) (ensures x < n) =
  match l with
  | y :: t -> if x = y then () else ids_lt_mem t n x

let rec ids_lt_succ (l: list nat) (n: nat)
  : Lemma (requires ids_lt l n) (ensures ids_lt l (n + 1)) =
  match l with
  | [] -> ()
  | _ :: t -> ids_lt_succ t n

let rec disjoint_cons_right (a b: list nat) (x: nat)
  : Lemma (requires disjoint_ids a b /\ not (mem_id x a))
          (ensures disjoint_ids a (x :: b)) =
  match a with
  | [] -> ()
  | _ :: t -> disjoint_cons_right t b x

let rec epochs_lt_mem (l: list int) (n x: int)
  : Lemma (requires epochs_lt l n /\ mem_epoch x l) (ensures x < n) =
  match l with
  | y :: t -> if x = y then () else epochs_lt_mem t n x

let rec epochs_lt_mono (l: list int) (n m: int)
  : Lemma (requires epochs_lt l n /\ n <= m) (ensures epochs_lt l m) =
  match l with
  | [] -> ()
  | _ :: t -> epochs_lt_mono t n m

let rec starter_of_lt (l: list (nat & nat)) (n h: nat)
  : Lemma (requires started_lt l n /\ Some? (starter_of l h)) (ensures h < n) =
  match l with
  | (r, _) :: t -> if r = h then () else starter_of_lt t n h

let rec started_lt_succ (l: list (nat & nat)) (n: nat)
  : Lemma (requires started_lt l n) (ensures started_lt l (n + 1)) =
  match l with
  | [] -> ()
  | _ :: t -> started_lt_succ t n

let rec update (#a: Type) (l: list a) (i: nat) (x: a) : Tot (list a) (decreases l) =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then x :: t else h :: update t (i - 1) x

let rec snoc (#a: Type) (l: list a) (x: a) : Tot (list a) (decreases l) =
  match l with
  | [] -> [x]
  | h :: t -> h :: snoc t x

// ── The shared world ───────────────────────────────────────────────────────

/// One in-flight rotation request. `q_t` is the request's own extracted
/// driver value and the effect it emitted last. `q_dev` is the session's
/// device, `q_web` whether the session is a browser web session, `q_header`
/// the `X-Vela-Rekey-Id` header and `q_replay` the `X-Vela-Epoch` header.
/// `q_seen_*` is the key row the handler loaded last (the timeout rollback
/// targets it); `q_minted` the rotation id this start request's freeze CAS
/// wrote. `q_chunks_ok`/`q_devices_ok` record that the chunk-shadow and the
/// device-capsule completeness probes returned `Empty` to this request.
noeq type req = {
  q_t: t_RekeyTransition;
  q_dev: nat;
  q_web: bool;
  q_header: option nat;
  q_replay: option i64;
  q_seen_epoch: i64;
  q_seen_rid: option nat;
  q_minted: option nat;
  q_chunks_ok: bool;
  q_devices_ok: bool;
}

/// The account's `users` row (`key_epoch`, `rekey_state`, `rekey_starter`,
/// `rekey_id`, `last_rekey_id`, `last_rekey_epoch`), the history of rotation
/// ids (started with their starter, committed with the epoch they committed
/// from, aborted), the in-flight requests, and the counters.
noeq type world = {
  w_epoch: i64;
  w_freezing: bool;
  w_starter: nat;
  w_rid: nat;
  w_last_rid: option nat;
  w_last_epoch: option i64;
  /// The next fresh rotation id (the server mints a UUID per freeze CAS).
  w_next_rid: nat;
  w_started: list (nat & nat);
  w_committed: list nat;
  w_commit_epochs: list int;
  w_aborted: list nat;
  w_reqs: list req;
  /// Commits the driver decided from an epoch that already had a commit.
  w_epoch_double_commit: nat;
  /// Commits the driver decided for an aborted rotation id.
  w_commit_after_abort: nat;
  /// Commits the driver decided for an already committed rotation id.
  w_duplicate_commit: nat;
  /// Rollbacks (abort, timeout, failed freeze) applied to a committed id.
  w_abort_after_commit: nat;
  /// Commits the driver decided without both completeness probes passing.
  w_unchecked_commit: nat;
  /// Commits the driver decided for a rotation another device started.
  w_non_starter_commit: nat;
  /// Abort rollbacks the driver emitted that removed another device's rotation.
  w_non_starter_abort: nat;
  /// Executor calls performed for a web-session request.
  w_web_step: nat;
  /// Reachability aids.
  w_freezes: nat;
  w_commits: nat;
  w_aborts: nat;
}

let opt_i64 (o: option i64) : Core_models.Option.t_Option i64 =
  match o with
  | Some x -> Core_models.Option.Option_Some x
  | None -> Core_models.Option.Option_None

/// The handler's `observation()` of the live row for this request.
let key_obs (w: world) (q: req) (expired: bool) : t_KeyStateObs =
  { f_epoch = w.w_epoch;
    f_freezing = w.w_freezing;
    f_starter_matches = w.w_freezing && w.w_starter = q.q_dev;
    f_rotation_id_present = w.w_freezing;
    f_header_present = Some? q.q_header;
    f_header_matches = (if w.w_freezing then q.q_header = Some w.w_rid else None? q.q_header);
    f_replay_target = opt_i64 q.q_replay;
    f_replay_recorded = opt_i64 w.w_last_epoch;
    f_replay_id_matches = Some? q.q_header && q.q_header = w.w_last_rid;
    f_expired = w.w_freezing && expired }

let is_verdict (e: t_RekeyEffect) : bool =
  match e with
  | RekeyEffect_Complete | RekeyEffect_CompleteReplay | RekeyEffect_Fail _ | RekeyEffect_Idle -> true
  | _ -> false

// ── Invariant ──────────────────────────────────────────────────────────────

let req_ok (started: list (nat & nat)) (q: req) : prop =
  rekey_state_is_sound q.q_t.f_driver /\
  rekey_effect_is_sound q.q_t.f_driver q.q_t.f_effect /\
  (q.q_web ==> is_verdict q.q_t.f_effect) /\
  (q.q_t.f_driver.f_op == RekeyOp_Commit ==>
     (q.q_t.f_driver.f_chunks_complete ==> q.q_chunks_ok) /\
     (q.q_t.f_driver.f_capsules_complete ==> q.q_devices_ok)) /\
  (is_rollback_effect q.q_t.f_effect ==>
     (match q.q_header with
      | Some h -> starter_of started h == Some q.q_dev
      | None -> False))

let rec all_reqs_ok (started: list (nat & nat)) (l: list req) : prop =
  match l with
  | [] -> True
  | q :: t -> req_ok started q /\ all_reqs_ok started t

let counters_zero (w: world) : prop =
  w.w_epoch_double_commit = 0 /\
  w.w_commit_after_abort = 0 /\
  w.w_duplicate_commit = 0 /\
  w.w_abort_after_commit = 0 /\
  w.w_unchecked_commit = 0 /\
  w.w_non_starter_commit = 0 /\
  w.w_non_starter_abort = 0 /\
  w.w_web_step = 0

let row_ok (w: world) : prop =
  started_lt w.w_started w.w_next_rid /\
  ids_lt w.w_committed w.w_next_rid /\
  ids_lt w.w_aborted w.w_next_rid /\
  (w.w_freezing ==>
     w.w_rid < w.w_next_rid /\
     starter_of w.w_started w.w_rid == Some w.w_starter /\
     not (mem_id w.w_rid w.w_committed) /\
     not (mem_id w.w_rid w.w_aborted)) /\
  nodup_ids w.w_committed /\
  nodup_ids w.w_aborted /\
  disjoint_ids w.w_committed w.w_aborted /\
  epochs_lt w.w_commit_epochs (v w.w_epoch) /\
  nodup_epochs w.w_commit_epochs

let inv (w: world) : prop =
  row_ok w /\ counters_zero w /\ all_reqs_ok w.w_started w.w_reqs

// ── Request list lemmas ────────────────────────────────────────────────────

let rec all_reqs_ok_index (s: list (nat & nat)) (l: list req) (i: nat)
  : Lemma (requires all_reqs_ok s l /\ i < FStar.List.Tot.length l)
          (ensures req_ok s (FStar.List.Tot.index l i)) =
  match l with
  | _ :: t -> if i = 0 then () else all_reqs_ok_index s t (i - 1)

let rec all_reqs_ok_update (s: list (nat & nat)) (l: list req) (i: nat) (q: req)
  : Lemma (requires all_reqs_ok s l /\ req_ok s q)
          (ensures all_reqs_ok s (update l i q)) =
  match l with
  | [] -> ()
  | _ :: t -> if i = 0 then () else all_reqs_ok_update s t (i - 1) q

let rec all_reqs_ok_snoc (s: list (nat & nat)) (l: list req) (q: req)
  : Lemma (requires all_reqs_ok s l /\ req_ok s q)
          (ensures all_reqs_ok s (snoc l q)) =
  match l with
  | [] -> ()
  | _ :: t -> all_reqs_ok_snoc s t q

/// A freeze CAS adds a fresh rotation id; no request's starter fact changes.
let req_ok_fresh (s: list (nat & nat)) (n dev: nat) (q: req)
  : Lemma (requires started_lt s n /\ req_ok s q)
          (ensures req_ok ((n, dev) :: s) q) =
  match q.q_header with
  | Some h -> if Some? (starter_of s h) then starter_of_lt s n h
  | None -> ()

let rec all_reqs_ok_fresh (s: list (nat & nat)) (n dev: nat) (l: list req)
  : Lemma (requires started_lt s n /\ all_reqs_ok s l)
          (ensures all_reqs_ok ((n, dev) :: s) l) =
  match l with
  | [] -> ()
  | q :: t -> req_ok_fresh s n dev q; all_reqs_ok_fresh s n dev t

// ── One handler step ───────────────────────────────────────────────────────

let set_req (w: world) (i: nat) (q: req) : world =
  { w with w_reqs = update w.w_reqs i q }

/// Feed `ev` to request `i`'s driver: the handler's executor call for the
/// current effect returned `ev`.
let deliver (w: world) (i: nat) (q: req{rekey_state_is_sound q.q_t.f_driver})
  (ev: t_RekeyEvent) : world =
  set_req w i
    { q with q_t = rekey_step q.q_t.f_driver ev;
             q_chunks_ok = q.q_chunks_ok || is_chunks_empty ev;
             q_devices_ok = q.q_devices_ok || is_devices_empty ev }

/// `load_key_state`: the request remembers the row it read.
let reload (w: world) (q: req) : req =
  { q with q_seen_epoch = w.w_epoch;
           q_seen_rid = if w.w_freezing then Some w.w_rid else None }

/// `rollback_rekey` won: the live rotation ends without advancing the epoch.
let clear_rotation (w: world) : world =
  { w with w_freezing = false;
           w_aborted = w.w_rid :: w.w_aborted;
           w_abort_after_commit = w.w_abort_after_commit + b2n (mem_id w.w_rid w.w_committed);
           w_aborts = w.w_aborts + 1 }

let sound_req = q: req{rekey_state_is_sound q.q_t.f_driver}

let step_load (w: world) (i: nat) (q: sound_req) (ok expired: bool) : world =
  if ok
  then deliver w i (reload w q) (RekeyEvent_State (StateObservation_Loaded (key_obs w q expired)))
  else deliver w i q (RekeyEvent_State StateObservation_Storage)

let timeout_guard (w: world) (q: req) : bool =
  w.w_freezing && w.w_epoch =. q.q_seen_epoch && q.q_seen_rid = Some w.w_rid

let step_timeout (w: world) (i: nat) (q: sound_req) (ok expired: bool) : world =
  if not ok
  then deliver w i q (RekeyEvent_Timeout TimeoutObservation_Storage)
  else if timeout_guard w q
  then deliver (clear_rotation w) i q (RekeyEvent_Timeout TimeoutObservation_RolledBack)
  else deliver w i (reload w q)
         (RekeyEvent_Timeout (TimeoutObservation_Raced (key_obs w q expired)))

/// The freeze CAS: `rekey_state IS NULL AND key_epoch = from` (plus the
/// readiness `NOT EXISTS` clauses, `sql`). It mints a fresh rotation id.
let freeze_guard (w: world) (d: t_RekeyDriver) (sql: bool) : bool =
  sql && not w.w_freezing && w.w_epoch =. d.f_from_epoch

let freeze_row (w: world) (dev: nat) : world =
  { w with w_freezing = true;
           w_starter = dev;
           w_rid = w.w_next_rid;
           w_next_rid = w.w_next_rid + 1;
           w_started = (w.w_next_rid, dev) :: w.w_started;
           w_freezes = w.w_freezes + 1 }

let step_freeze (w: world) (i: nat) (q: sound_req) (ok sql: bool) : world =
  if not ok
  then deliver w i q (RekeyEvent_FreezeCas CasObservation_Storage)
  else if freeze_guard w q.q_t.f_driver sql
  then deliver (freeze_row w q.q_dev) i ({ q with q_minted = Some w.w_next_rid })
         (RekeyEvent_FreezeCas CasObservation_Updated)
  else deliver w i q (RekeyEvent_FreezeCas CasObservation_Skipped)

/// A failed freeze-transaction commit leaves the row as it was: if this
/// request's freeze is still the live one it is rolled back (its id was never
/// returned to the client).
let step_tx_commit (w: world) (i: nat) (q: sound_req) (ok: bool) : world =
  if ok
  then deliver w i q (RekeyEvent_TxCommit TransactionObservation_Committed)
  else if w.w_freezing && q.q_minted = Some w.w_rid
  then deliver (clear_rotation w) i q (RekeyEvent_TxCommit TransactionObservation_Failed)
  else deliver w i q (RekeyEvent_TxCommit TransactionObservation_Failed)

/// The commit CAS: `key_epoch = from AND rekey_state = 'freezing' AND
/// rekey_starter = device AND rekey_id = header` (plus the completeness
/// `NOT EXISTS` clauses, `sql`).
let commit_guard (w: world) (q: req) (d: t_RekeyDriver) (sql: bool) : bool =
  sql && w.w_freezing && w.w_epoch =. d.f_from_epoch && w.w_starter = q.q_dev &&
  q.q_header = Some w.w_rid

let header_id (q: req) : nat =
  match q.q_header with
  | Some h -> h
  | None -> 0

/// The driver decided to commit the rotation its request names.
let record_commit (w: world) (q: req) (d: t_RekeyDriver) : world =
  let rid = header_id q in
  { w with
    w_epoch_double_commit =
      w.w_epoch_double_commit + b2n (mem_epoch (v d.f_from_epoch) w.w_commit_epochs);
    w_commit_after_abort = w.w_commit_after_abort + b2n (mem_id rid w.w_aborted);
    w_duplicate_commit = w.w_duplicate_commit + b2n (mem_id rid w.w_committed);
    w_unchecked_commit =
      w.w_unchecked_commit + b2n (not (q.q_chunks_ok && q.q_devices_ok));
    w_non_starter_commit =
      w.w_non_starter_commit + b2n (starter_of w.w_started rid <> Some q.q_dev);
    w_committed = rid :: w.w_committed;
    w_commit_epochs = v d.f_from_epoch :: w.w_commit_epochs;
    w_commits = w.w_commits + 1 }

/// The commit CAS's row update.
let apply_commit (w: world) (q: req) (d: t_RekeyDriver) : world =
  { w with w_epoch = d.f_to_epoch;
           w_freezing = false;
           w_last_rid = q.q_header;
           w_last_epoch = Some d.f_to_epoch }

let commit_obs (w: world) (q: req) (d: t_RekeyDriver) (ok sql: bool) : t_CasObservation =
  if not ok then CasObservation_Storage
  else if commit_guard w q d sql then CasObservation_Updated
  else CasObservation_Skipped

let decides_commit (d: t_RekeyDriver{rekey_state_is_sound d}) (ev: t_RekeyEvent) : bool =
  (rekey_step d ev).f_driver.f_committed && not d.f_committed

let step_commit (w: world) (i: nat) (q: sound_req) (ok sql: bool) : world =
  let d = q.q_t.f_driver in
  let ev = RekeyEvent_CommitCas (commit_obs w q d ok sql) in
  let w1 = if decides_commit d ev then record_commit w q d else w in
  let w2 = if is_commit_updated ev then apply_commit w1 q d else w1 in
  deliver w2 i q ev

/// `rollback_rekey(epoch, header)`: `key_epoch = epoch AND rekey_state =
/// 'freezing' AND rekey_id = header`. It does not check the starter.
let rollback_guard (w: world) (q: req) (d: t_RekeyDriver) : bool =
  w.w_freezing && w.w_epoch =. d.f_epoch && q.q_header = Some w.w_rid

let abort_row (w: world) (q: req) : world =
  let w' = clear_rotation w in
  { w' with w_non_starter_abort =
              w.w_non_starter_abort + b2n (starter_of w.w_started w.w_rid <> Some q.q_dev) }

let step_rollback (w: world) (i: nat) (q: sound_req) (ok: bool) : world =
  let d = q.q_t.f_driver in
  if not ok
  then deliver w i q (RekeyEvent_Rollback RollbackObservation_Storage)
  else if rollback_guard w q d
  then deliver (abort_row w q) i q (RekeyEvent_Rollback RollbackObservation_RolledBack)
  else deliver w i q (RekeyEvent_Rollback RollbackObservation_Raced)

/// The scheduler's choice for one executor call: whether the I/O succeeds
/// (and the request is not paced), whether the loaded rotation has expired,
/// the readiness/completeness probe result, the capsule write result, and
/// whether the CAS's other SQL clauses hold.
noeq type choice = {
  c_ok: bool;
  c_expired: bool;
  c_probe: t_ProbeObservation;
  c_capsule: t_CapsuleObservation;
  c_sql: bool;
}

/// Effects whose observation is not a fact about the key row.
let local_event (e: t_RekeyEffect) (c: choice) : option t_RekeyEvent =
  match e with
  | RekeyEffect_RateLimit ->
      Some (RekeyEvent_RateLimit
              (if c.c_ok then RateLimitObservation_Allowed else RateLimitObservation_Limited))
  | RekeyEffect_CheckOram -> Some (RekeyEvent_Oram c.c_probe)
  | RekeyEffect_CheckCapable -> Some (RekeyEvent_Capable c.c_probe)
  | RekeyEffect_CheckAcknowledged -> Some (RekeyEvent_Acknowledged c.c_probe)
  | RekeyEffect_BeginFreezeTransaction ->
      Some (RekeyEvent_Transaction
              (if c.c_ok then TransactionObservation_Committed else TransactionObservation_Failed))
  | RekeyEffect_ReadInventory ->
      Some (RekeyEvent_Inventory
              (if c.c_ok then InventoryObservation_Read else InventoryObservation_Failed))
  | RekeyEffect_CleanupChunks ->
      Some (RekeyEvent_Cleanup (if c.c_ok then CleanupObservation_Done else CleanupObservation_Storage))
  | RekeyEffect_WriteCapsule _ -> Some (RekeyEvent_Capsule c.c_capsule)
  | RekeyEffect_CheckChunkShadows -> Some (RekeyEvent_Chunks c.c_probe)
  | RekeyEffect_CheckDeviceCapsules -> Some (RekeyEvent_Devices c.c_probe)
  | RekeyEffect_SweepOldChunks ->
      Some (RekeyEvent_Sweep (if c.c_ok then SweepObservation_Done else SweepObservation_Failed))
  | RekeyEffect_PublishEpoch -> Some RekeyEvent_Published
  | _ -> None

/// Request `i` performs the executor call for its current effect. A verdict
/// performs nothing.
let step_req (w: world) (i: nat) (c: choice) : world =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let q = FStar.List.Tot.index w.w_reqs i in
    if is_verdict q.q_t.f_effect || not (rekey_state_is_sound q.q_t.f_driver) then w
    else begin
      let w = { w with w_web_step = w.w_web_step + b2n q.q_web } in
      match q.q_t.f_effect with
      | RekeyEffect_LoadState -> step_load w i q c.c_ok c.c_expired
      | RekeyEffect_TimeoutRollback -> step_timeout w i q c.c_ok c.c_expired
      | RekeyEffect_FreezeCas -> step_freeze w i q c.c_ok c.c_sql
      | RekeyEffect_CommitFreezeTransaction -> step_tx_commit w i q c.c_ok
      | RekeyEffect_CommitCas -> step_commit w i q c.c_ok c.c_sql
      | RekeyEffect_RollbackAttempt -> step_rollback w i q c.c_ok
      | e ->
          (match local_event e c with
           | Some ev -> deliver w i q ev
           | None -> w)
    end
  end else w

let request_of (web: bool) (capsules: i64) : t_RekeyRequest =
  { f_authenticated = true; f_device_scope = not web; f_capsule_count = capsules }

let begin_op (op: t_RekeyOp) (r: t_RekeyRequest) : t_RekeyTransition =
  match op with
  | RekeyOp_Start -> begin_start r
  | RekeyOp_Capsules -> begin_capsules r
  | RekeyOp_Commit -> begin_commit r
  | RekeyOp_Abort -> begin_abort r

let new_req (op: t_RekeyOp) (dev: nat) (web: bool) (header: option nat)
  (replay: option i64) (capsules: i64) : req =
  { q_t = begin_op op (request_of web capsules);
    q_dev = dev;
    q_web = web;
    q_header = header;
    q_replay = replay;
    q_seen_epoch = mk_i64 0;
    q_seen_rid = None;
    q_minted = None;
    q_chunks_ok = false;
    q_devices_ok = false }

noeq type action =
  /// A new request from device `dev` (a web session if `web`) to the entry
  /// point `op`, with its rotation-id and epoch headers and capsule count.
  | Spawn : op: t_RekeyOp -> dev: nat -> web: bool -> header: option nat ->
            replay: option i64 -> capsules: i64 -> action
  /// Request `i` performs one executor call.
  | Step : i: nat -> c: choice -> action

let world_step (w: world) (a: action) : world =
  match a with
  | Spawn op dev web header replay capsules ->
      { w with w_reqs = snoc w.w_reqs (new_req op dev web header replay capsules) }
  | Step i c -> step_req w i c

let rec run_world (w: world) (schedule: list action) : Tot world (decreases schedule) =
  match schedule with
  | [] -> w
  | a :: rest -> run_world (world_step w a) rest

// ── Invariant preservation ─────────────────────────────────────────────────

let header_starter (s: list (nat & nat)) (q: req) : prop =
  match q.q_header with
  | Some h -> starter_of s h == Some q.q_dev
  | None -> False

/// The request performs a step: it is sound, not a web session, and has not
/// reached a verdict.
let stepping (w: world) (q: req) : prop =
  inv w /\ req_ok w.w_started q /\ not q.q_web /\ not (is_verdict q.q_t.f_effect)

let deliver_inv (w: world) (i: nat) (q: sound_req) (ev: t_RekeyEvent)
  : Lemma (requires stepping w q /\ (rollback_authorized ev ==> header_starter w.w_started q))
          (ensures inv (deliver w i q ev)) =
  let d = q.q_t.f_driver in
  step_frame d ev;
  let q' = { q with q_t = rekey_step d ev;
                    q_chunks_ok = q.q_chunks_ok || is_chunks_empty ev;
                    q_devices_ok = q.q_devices_ok || is_devices_empty ev } in
  assert (req_ok w.w_started q');
  all_reqs_ok_update w.w_started w.w_reqs i q'

/// A load hands the driver the live row; if that row authorizes a rollback
/// for this request, the request's header names a rotation this device
/// started.
let load_authorizes (w: world) (q: req) (expired: bool)
  : Lemma (requires row_ok w /\
                    rollback_authorized
                      (RekeyEvent_State (StateObservation_Loaded (key_obs w q expired))))
          (ensures header_starter w.w_started q) = ()

let raced_authorizes (w: world) (q: req) (expired: bool)
  : Lemma (requires row_ok w /\
                    rollback_authorized
                      (RekeyEvent_Timeout (TimeoutObservation_Raced (key_obs w q expired))))
          (ensures header_starter w.w_started q) = ()

let clear_rotation_inv (w: world)
  : Lemma (requires inv w /\ w.w_freezing) (ensures inv (clear_rotation w)) =
  disjoint_cons_right w.w_committed w.w_aborted w.w_rid

let abort_row_inv (w: world) (q: req)
  : Lemma (requires inv w /\ w.w_freezing /\ q.q_header == Some w.w_rid /\
                    header_starter w.w_started q)
          (ensures inv (abort_row w q)) =
  clear_rotation_inv w

let freeze_row_inv (w: world) (dev: nat)
  : Lemma (requires inv w /\ not w.w_freezing) (ensures inv (freeze_row w dev)) =
  let n = w.w_next_rid in
  started_lt_succ w.w_started n;
  ids_lt_succ w.w_committed n;
  ids_lt_succ w.w_aborted n;
  if mem_id n w.w_committed then ids_lt_mem w.w_committed n n;
  if mem_id n w.w_aborted then ids_lt_mem w.w_aborted n n;
  all_reqs_ok_fresh w.w_started n dev w.w_reqs

/// The commit the driver decides on a winning commit CAS keeps every
/// invariant, and none of its counters fire.
let commit_world_inv (w: world) (q: req) (sql: bool)
  : Lemma (requires inv w /\ req_ok w.w_started q /\
                    q.q_t.f_effect == RekeyEffect_CommitCas /\
                    commit_guard w q q.q_t.f_driver sql)
          (ensures inv (apply_commit (record_commit w q q.q_t.f_driver) q q.q_t.f_driver)) =
  let d = q.q_t.f_driver in
  next_epoch_succ d.f_from_epoch d.f_to_epoch;
  if mem_epoch (v d.f_from_epoch) w.w_commit_epochs
  then epochs_lt_mem w.w_commit_epochs (v w.w_epoch) (v d.f_from_epoch);
  epochs_lt_mono w.w_commit_epochs (v w.w_epoch) (v d.f_to_epoch)

let step_load_inv (w: world) (i: nat) (q: sound_req) (ok expired: bool)
  : Lemma (requires stepping w q) (ensures inv (step_load w i q ok expired)) =
  if ok then begin
    let ev = RekeyEvent_State (StateObservation_Loaded (key_obs w q expired)) in
    if rollback_authorized ev then load_authorizes w q expired;
    deliver_inv w i (reload w q) ev
  end else deliver_inv w i q (RekeyEvent_State StateObservation_Storage)

let step_timeout_inv (w: world) (i: nat) (q: sound_req) (ok expired: bool)
  : Lemma (requires stepping w q) (ensures inv (step_timeout w i q ok expired)) =
  if not ok then deliver_inv w i q (RekeyEvent_Timeout TimeoutObservation_Storage)
  else if timeout_guard w q then begin
    clear_rotation_inv w;
    deliver_inv (clear_rotation w) i q (RekeyEvent_Timeout TimeoutObservation_RolledBack)
  end else begin
    let ev = RekeyEvent_Timeout (TimeoutObservation_Raced (key_obs w q expired)) in
    if rollback_authorized ev then raced_authorizes w q expired;
    deliver_inv w i (reload w q) ev
  end

let step_freeze_inv (w: world) (i: nat) (q: sound_req) (ok sql: bool)
  : Lemma (requires stepping w q /\ q.q_t.f_effect == RekeyEffect_FreezeCas)
          (ensures inv (step_freeze w i q ok sql)) =
  if not ok then deliver_inv w i q (RekeyEvent_FreezeCas CasObservation_Storage)
  else if freeze_guard w q.q_t.f_driver sql then begin
    freeze_row_inv w q.q_dev;
    req_ok_fresh w.w_started w.w_next_rid q.q_dev q;
    deliver_inv (freeze_row w q.q_dev) i ({ q with q_minted = Some w.w_next_rid })
      (RekeyEvent_FreezeCas CasObservation_Updated)
  end else deliver_inv w i q (RekeyEvent_FreezeCas CasObservation_Skipped)

let step_tx_commit_inv (w: world) (i: nat) (q: sound_req) (ok: bool)
  : Lemma (requires stepping w q) (ensures inv (step_tx_commit w i q ok)) =
  if ok then deliver_inv w i q (RekeyEvent_TxCommit TransactionObservation_Committed)
  else if w.w_freezing && q.q_minted = Some w.w_rid then begin
    clear_rotation_inv w;
    deliver_inv (clear_rotation w) i q (RekeyEvent_TxCommit TransactionObservation_Failed)
  end else deliver_inv w i q (RekeyEvent_TxCommit TransactionObservation_Failed)

let step_commit_inv (w: world) (i: nat) (q: sound_req) (ok sql: bool)
  : Lemma (requires stepping w q /\ q.q_t.f_effect == RekeyEffect_CommitCas)
          (ensures inv (step_commit w i q ok sql)) =
  let d = q.q_t.f_driver in
  let ev = RekeyEvent_CommitCas (commit_obs w q d ok sql) in
  step_frame d ev;
  if is_commit_updated ev then begin
    assert (decides_commit d ev);
    commit_world_inv w q sql;
    deliver_inv (apply_commit (record_commit w q d) q d) i q ev
  end else begin
    assert (not (decides_commit d ev));
    deliver_inv w i q ev
  end

let step_rollback_inv (w: world) (i: nat) (q: sound_req) (ok: bool)
  : Lemma (requires stepping w q /\ q.q_t.f_effect == RekeyEffect_RollbackAttempt)
          (ensures inv (step_rollback w i q ok)) =
  let d = q.q_t.f_driver in
  if not ok then deliver_inv w i q (RekeyEvent_Rollback RollbackObservation_Storage)
  else if rollback_guard w q d then begin
    abort_row_inv w q;
    deliver_inv (abort_row w q) i q (RekeyEvent_Rollback RollbackObservation_RolledBack)
  end else deliver_inv w i q (RekeyEvent_Rollback RollbackObservation_Raced)

let local_event_inv (w: world) (i: nat) (q: sound_req) (c: choice)
  : Lemma (requires stepping w q)
          (ensures (match local_event q.q_t.f_effect c with
                    | Some ev -> inv (deliver w i q ev)
                    | None -> True)) =
  match local_event q.q_t.f_effect c with
  | Some ev -> deliver_inv w i q ev
  | None -> ()

let step_req_inv (w: world) (i: nat) (c: choice)
  : Lemma (requires inv w) (ensures inv (step_req w i c)) =
  if i < FStar.List.Tot.length w.w_reqs then begin
    let q = FStar.List.Tot.index w.w_reqs i in
    all_reqs_ok_index w.w_started w.w_reqs i;
    if is_verdict q.q_t.f_effect || not (rekey_state_is_sound q.q_t.f_driver) then ()
    else begin
      let w' = { w with w_web_step = w.w_web_step + b2n q.q_web } in
      assert (stepping w' q);
      match q.q_t.f_effect with
      | RekeyEffect_LoadState -> step_load_inv w' i q c.c_ok c.c_expired
      | RekeyEffect_TimeoutRollback -> step_timeout_inv w' i q c.c_ok c.c_expired
      | RekeyEffect_FreezeCas -> step_freeze_inv w' i q c.c_ok c.c_sql
      | RekeyEffect_CommitFreezeTransaction -> step_tx_commit_inv w' i q c.c_ok
      | RekeyEffect_CommitCas -> step_commit_inv w' i q c.c_ok c.c_sql
      | RekeyEffect_RollbackAttempt -> step_rollback_inv w' i q c.c_ok
      | _ -> local_event_inv w' i q c
    end
  end

/// A web session is refused by every entry point before any executor call.
let begin_web_refused (op: t_RekeyOp) (capsules: i64)
  : Lemma (is_verdict (begin_op op (request_of true capsules)).f_effect) =
  match op with
  | RekeyOp_Start -> ()
  | RekeyOp_Capsules -> ()
  | RekeyOp_Commit -> ()
  | RekeyOp_Abort -> ()

let new_req_ok (s: list (nat & nat)) (op: t_RekeyOp) (dev: nat) (web: bool)
  (header: option nat) (replay: option i64) (capsules: i64)
  : Lemma (req_ok s (new_req op dev web header replay capsules)) =
  if web then begin_web_refused op capsules;
  match op with
  | RekeyOp_Start -> ()
  | RekeyOp_Capsules -> ()
  | RekeyOp_Commit -> ()
  | RekeyOp_Abort -> ()

let world_step_inv (w: world) (a: action)
  : Lemma (requires inv w) (ensures inv (world_step w a)) =
  match a with
  | Spawn op dev web header replay capsules ->
      new_req_ok w.w_started op dev web header replay capsules;
      all_reqs_ok_snoc w.w_started w.w_reqs (new_req op dev web header replay capsules)
  | Step i c -> step_req_inv w i c

let rec run_world_inv (w: world) (schedule: list action)
  : Lemma (requires inv w) (ensures inv (run_world w schedule)) (decreases schedule) =
  match schedule with
  | [] -> ()
  | a :: rest -> world_step_inv w a; run_world_inv (world_step w a) rest

// ── Headline theorems ──────────────────────────────────────────────────────

let initial : world =
  { w_epoch = v_INITIAL_EPOCH;
    w_freezing = false;
    w_starter = 0;
    w_rid = 0;
    w_last_rid = None;
    w_last_epoch = None;
    w_next_rid = 0;
    w_started = [];
    w_committed = [];
    w_commit_epochs = [];
    w_aborted = [];
    w_reqs = [];
    w_epoch_double_commit = 0;
    w_commit_after_abort = 0;
    w_duplicate_commit = 0;
    w_abort_after_commit = 0;
    w_unchecked_commit = 0;
    w_non_starter_commit = 0;
    w_non_starter_abort = 0;
    w_web_step = 0;
    w_freezes = 0;
    w_commits = 0;
    w_aborts = 0 }

let initial_inv () : Lemma (inv initial) = ()

/// For every interleaving of start/capsules/commit/abort requests (from any
/// devices and web sessions, with any headers, any I/O outcome, any clock):
/// every invariant holds and no counter fires.
let composition_theorem (schedule: list action)
  : Lemma (inv (run_world initial schedule)) =
  initial_inv ();
  run_world_inv initial schedule

/// 1. At most one committed rotation per epoch: the epochs commits were
///    decided from are pairwise distinct, and no commit is decided from an
///    epoch that already committed.
let at_most_one_commit_per_epoch (schedule: list action)
  : Lemma (let w = run_world initial schedule in
           nodup_epochs w.w_commit_epochs /\ w.w_epoch_double_commit = 0) =
  composition_theorem schedule

/// 2. No commit after an abort (explicit, timeout or failed freeze) of the
///    same rotation, and no rollback of a committed rotation.
let no_commit_after_abort (schedule: list action)
  : Lemma (let w = run_world initial schedule in
           w.w_commit_after_abort = 0 /\ w.w_abort_after_commit = 0) =
  composition_theorem schedule

/// 3. Committed rotation ids are unique.
let committed_ids_are_unique (schedule: list action)
  : Lemma (let w = run_world initial schedule in
           nodup_ids w.w_committed /\ w.w_duplicate_commit = 0) =
  composition_theorem schedule

/// 4. The committed and aborted rotation ids are disjoint.
let committed_and_aborted_are_disjoint (schedule: list action)
  : Lemma (disjoint_ids (run_world initial schedule).w_committed
                        (run_world initial schedule).w_aborted) =
  composition_theorem schedule

/// 5. A commit is decided only by a request to which both completeness
///    probes (chunk shadows, device capsules) returned `Empty`.
let commit_only_after_completeness (schedule: list action)
  : Lemma ((run_world initial schedule).w_unchecked_commit = 0) =
  composition_theorem schedule

/// 6. Only the starter commits or aborts: every commit the driver decides and
///    every abort rollback it emits that wins removes a rotation this
///    request's device started.
let starter_only_authority (schedule: list action)
  : Lemma (let w = run_world initial schedule in
           w.w_non_starter_commit = 0 /\ w.w_non_starter_abort = 0) =
  composition_theorem schedule

/// 7. A web session never authorizes any rotation step: no executor call is
///    ever performed for a web-session request.
let web_session_never_authorizes (schedule: list action)
  : Lemma ((run_world initial schedule).w_web_step = 0) =
  composition_theorem schedule

// ── Reachability witnesses ─────────────────────────────────────────────────
//
// The theorems are not vacuous: the schedules below drive the extracted
// drivers through a full rotation (start, commit), a refused second commit, a
// refused abort by another device, the starter's abort, a refused commit of
// the aborted rotation, and a refused web session.

let ok_choice : choice =
  { c_ok = true; c_expired = false; c_probe = ProbeObservation_Empty;
    c_capsule = CapsuleObservation_Stored; c_sql = true }

/// Whether request `i` exists and satisfies `p` (total, for the witnesses).
let req_is (w: world) (i: nat) (p: req -> bool) : bool =
  match FStar.List.Tot.nth w.w_reqs i with
  | Some q -> p q
  | None -> false

let refused (q: req) : bool =
  is_verdict q.q_t.f_effect && not q.q_t.f_driver.f_committed &&
  not q.q_t.f_driver.f_rolled_back

let rolled_back (q: req) : bool = q.q_t.f_driver.f_rolled_back

let web_refused (q: req) : bool =
  q.q_t.f_effect = RekeyEffect_Fail RekeyFailure_WebSessionForbidden

let rec steps (i: nat) (n: nat) : list action =
  if n = 0 then [] else Step i ok_choice :: steps i (n - 1)

/// Device 7 starts a rotation (request 0, ten executor calls) and commits it
/// (request 1, seven executor calls).
let rotation : list action =
  [Spawn RekeyOp_Start 7 false None None (mk_i64 0)] @ steps 0 10 @
  [Spawn RekeyOp_Commit 7 false (Some 0) None (mk_i64 0)] @ steps 1 7

let w_rotation : world = run_world initial rotation

#push-options "--fuel 4 --ifuel 2"

let rotation_commits_once ()
  : Lemma (w_rotation.w_freezes = 1 /\ w_rotation.w_commits = 1 /\
           w_rotation.w_committed = [0] /\ w_rotation.w_commit_epochs = [1] /\
           v w_rotation.w_epoch = 2 /\ w_rotation.w_freezing = false) =
  assert_norm (w_rotation.w_freezes = 1 /\ w_rotation.w_commits = 1 /\
               w_rotation.w_committed = [0] /\ w_rotation.w_commit_epochs = [1] /\
               v w_rotation.w_epoch = 2 /\ w_rotation.w_freezing = false)

/// Request 2 replays the commit of rotation 0 without the epoch header: it is
/// refused at its state load and nothing else commits.
let w_second_commit : world =
  run_world w_rotation
    ([Spawn RekeyOp_Commit 7 false (Some 0) None (mk_i64 0)] @ steps 2 7)

let second_commit_is_refused ()
  : Lemma (w_second_commit.w_commits = 1 /\ w_second_commit.w_committed = [0] /\
           req_is w_second_commit 2 refused) =
  assert_norm (w_second_commit.w_commits = 1 /\ w_second_commit.w_committed = [0] /\
               req_is w_second_commit 2 refused)

/// Device 7 starts rotation 1 (request 3); device 8 tries to abort it
/// (request 4) and is refused; device 7 aborts it (request 5); device 7's
/// commit of rotation 1 (request 6) is then refused.
let w_abort : world =
  run_world w_second_commit
    ([Spawn RekeyOp_Start 7 false None None (mk_i64 0)] @ steps 3 10 @
     [Spawn RekeyOp_Abort 8 false (Some 1) None (mk_i64 0)] @ steps 4 4 @
     [Spawn RekeyOp_Abort 7 false (Some 1) None (mk_i64 0)] @ steps 5 4 @
     [Spawn RekeyOp_Commit 7 false (Some 1) None (mk_i64 0)] @ steps 6 7)

let non_starter_abort_is_refused_and_starter_abort_wins ()
  : Lemma (w_abort.w_freezes = 2 /\ w_abort.w_aborts = 1 /\
           w_abort.w_aborted = [1] /\ w_abort.w_committed = [0] /\
           w_abort.w_commits = 1 /\ w_abort.w_freezing = false /\
           req_is w_abort 4 refused /\ req_is w_abort 5 rolled_back /\
           req_is w_abort 6 refused) =
  assert_norm (w_abort.w_freezes = 2 /\ w_abort.w_aborts = 1 /\
               w_abort.w_aborted = [1] /\ w_abort.w_committed = [0] /\
               w_abort.w_commits = 1 /\ w_abort.w_freezing = false /\
               req_is w_abort 4 refused /\ req_is w_abort 5 rolled_back /\
               req_is w_abort 6 refused)

/// A web session's start (request 7) is refused before any executor call;
/// stepping it performs nothing.
let w_web : world =
  run_world w_abort ([Spawn RekeyOp_Start 9 true None None (mk_i64 0)] @ steps 7 3)

let web_session_is_refused ()
  : Lemma (w_web.w_web_step = 0 /\ w_web.w_freezes = 2 /\
           req_is w_web 7 web_refused) =
  assert_norm (w_web.w_web_step = 0 /\ w_web.w_freezes = 2 /\
               req_is w_web 7 web_refused)

#pop-options
