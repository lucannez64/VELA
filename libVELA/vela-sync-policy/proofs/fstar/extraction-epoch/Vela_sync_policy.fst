module Vela_sync_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

let v_INITIAL_EPOCH: i64 = mk_i64 1

/// Epoch observations for a client that deliberately does **not** adopt a
/// rotated RMS automatically. The two integers are the epoch the server's
/// manifest advertises and the epoch this device authenticated from its local
/// `key_epoch.enc` marker. Passing two numbers — rather than a precomputed
/// `matches`/`is_next` boolean — keeps the comparison itself in verified code.
type t_SyncEpochFacts = {
  f_server_epoch:i64;
  f_local_epoch:i64
}

/// Mobile chunk downloads require the manifest epoch and the locally
/// authenticated epoch to be exactly equal and positive. A mismatch is a
/// rotation this device has not adopted yet; it must refuse rather than guess.
let sync_epochs_agree_for_download (facts: t_SyncEpochFacts) : bool =
  facts.f_server_epoch >=. v_INITIAL_EPOCH && facts.f_local_epoch >=. v_INITIAL_EPOCH &&
  facts.f_server_epoch =. facts.f_local_epoch

let sync_epoch_decision_matches_spec (facts: t_SyncEpochFacts) (allowed: bool) : bool =
  allowed =. (sync_epochs_agree_for_download facts <: bool)

let plan_sync_epoch_match (facts: t_SyncEpochFacts)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun allowed ->
          let allowed:bool = allowed in
          sync_epoch_decision_matches_spec facts allowed) = sync_epochs_agree_for_download facts

let equal_positive_epoch_admits_download (_: Prims.unit)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. true) =
  sync_epochs_agree_for_download ({ f_server_epoch = mk_i64 4; f_local_epoch = mk_i64 4 }
      <:
      t_SyncEpochFacts)

let mismatched_positive_epoch_admits_download (_: Prims.unit)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  sync_epochs_agree_for_download ({ f_server_epoch = mk_i64 4; f_local_epoch = mk_i64 5 }
      <:
      t_SyncEpochFacts)

let nonpositive_epoch_admits_download (_: Prims.unit)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  sync_epochs_agree_for_download ({ f_server_epoch = mk_i64 0; f_local_epoch = mk_i64 0 }
      <:
      t_SyncEpochFacts)
