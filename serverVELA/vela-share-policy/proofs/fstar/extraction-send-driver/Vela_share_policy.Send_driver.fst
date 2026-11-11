module Vela_share_policy.Send_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// A link carries one item; generous for a large secure note.
let v_MAX_SEND_BYTES: i64 = mk_i64 256 *! mk_i64 1024

/// Largest accepted link lifetime: 30 days.
let v_MAX_TTL_SECS: i64 = ((mk_i64 30 *! mk_i64 24 <: i64) *! mk_i64 60 <: i64) *! mk_i64 60

/// Smallest accepted link lifetime: 5 minutes.
let v_MIN_TTL_SECS: i64 = mk_i64 5 *! mk_i64 60

/// Lifetime used when the request names none: 24 hours.
let v_DEFAULT_TTL_SECS: i64 = (mk_i64 24 *! mk_i64 60 <: i64) *! mk_i64 60

/// Largest explicit view count.
let v_MAX_VIEWS_CEILING: i64 = mk_i64 1000

/// Smallest accepted Argon2id salt.
let v_MIN_KDF_SALT_LEN: i64 = mk_i64 8

let clamp_ttl (has_ttl: bool) (ttl_secs: i64) : i64 =
  if ~.has_ttl
  then v_DEFAULT_TTL_SECS
  else
    if ttl_secs <. v_MIN_TTL_SECS
    then v_MIN_TTL_SECS
    else if ttl_secs >. v_MAX_TTL_SECS then v_MAX_TTL_SECS else ttl_secs

/// `view_once` pins the count to exactly one; otherwise clamp to the ceiling.
/// Returns `(present, value)` because an absent cap is not zero.
let resolve_max_views (view_once has_max_views: bool) (max_views: i64) : (bool & i64) =
  if view_once
  then true, mk_i64 1 <: (bool & i64)
  else
    if ~.has_max_views
    then false, mk_i64 0 <: (bool & i64)
    else
      if max_views <. mk_i64 1
      then true, mk_i64 1 <: (bool & i64)
      else
        if max_views >. v_MAX_VIEWS_CEILING
        then true, v_MAX_VIEWS_CEILING <: (bool & i64)
        else true, max_views <: (bool & i64)

/// Request-side observations for `POST /send`. Decode failures are recorded
/// separately so the handler's historical error precedence is preserved.
type t_CreateObservation = {
  f_owner_present:bool;
  f_ciphertext_decode_failed:bool;
  f_ciphertext_len:i64;
  f_has_passphrase:bool;
  f_kdf_salt_present:bool;
  f_kdf_salt_decode_failed:bool;
  f_kdf_salt_len:i64;
  f_has_ttl:bool;
  f_ttl_secs:i64;
  f_has_max_views:bool;
  f_max_views:i64;
  f_view_once:bool
}

/// Outcome of the atomic view-consume `UPDATE`.
type t_ConsumeObservation =
  | ConsumeObservation_Consumed : t_ConsumeObservation
  | ConsumeObservation_Unavailable : t_ConsumeObservation
  | ConsumeObservation_Error : t_ConsumeObservation

/// Outcome of the row `SELECT` after a successful consume.
type t_ReadObservation =
  | ReadObservation_Payload { f_view_once:bool }: t_ReadObservation
  | ReadObservation_Missing : t_ReadObservation
  | ReadObservation_Unreadable : t_ReadObservation

/// Outcome of the view-once cleanup `DELETE`. The handler ignores it.
type t_RemoveObservation = {
  f_removed:bool;
  f_failed:bool
}

/// Outcome of a guarded `DELETE`/`UPDATE`, as observed by the handler.
type t_RowsObservation = {
  f_rows:u64;
  f_failed:bool
}

/// Which request this per-request driver belongs to.
type t_SendRequestKind =
  | SendRequestKind_Create : t_SendRequestKind
  | SendRequestKind_Fetch : t_SendRequestKind
  | SendRequestKind_Delete : t_SendRequestKind

/// Where the request is in its decision sequence.
type t_SendStage =
  | SendStage_Start : t_SendStage
  | SendStage_Read : t_SendStage
  | SendStage_Remove : t_SendStage
  | SendStage_Done : t_SendStage

/// Failure categories, preserving the handler's historical status/message
/// precedence. The handler renders them; this module never formats a message.
type t_SendFailure =
  | SendFailure_Unauthenticated : t_SendFailure
  | SendFailure_MalformedCiphertext : t_SendFailure
  | SendFailure_EmptyCiphertext : t_SendFailure
  | SendFailure_CiphertextTooLarge : t_SendFailure
  | SendFailure_MissingKdfSalt : t_SendFailure
  | SendFailure_MalformedKdfSalt : t_SendFailure
  | SendFailure_KdfSaltTooShort : t_SendFailure
  | SendFailure_InsertStorage : t_SendFailure
  | SendFailure_NotFound : t_SendFailure
  | SendFailure_ConsumeStorage : t_SendFailure
  | SendFailure_RowUnreadable : t_SendFailure
  | SendFailure_DeleteStorage : t_SendFailure

/// The exact create authority: nothing but this permit may reach the insert.
type t_CreatePermit = {
  f_ttl_secs:i64;
  f_max_views_present:bool;
  f_max_views:i64;
  f_view_once:bool
}

/// The exact delete authority: only an authenticated owner obtains it.
type t_DeletePermit = { f_owner_bound:bool }

/// The effect the handler must perform next (`Idle` means "do nothing").
type t_SendEffect =
  | SendEffect_InsertSend : t_CreatePermit -> t_SendEffect
  | SendEffect_ConsumeView : t_SendEffect
  | SendEffect_ReadSend : t_SendEffect
  | SendEffect_RemoveFetched : t_SendEffect
  | SendEffect_DeleteLink : t_DeletePermit -> t_SendEffect
  | SendEffect_CompleteCreate : t_SendEffect
  | SendEffect_CompleteFetch : t_SendEffect
  | SendEffect_CompleteDelete { f_deleted:bool }: t_SendEffect
  | SendEffect_Fail : t_SendFailure -> t_SendEffect
  | SendEffect_Idle : t_SendEffect

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about SQL beyond the effect's observation.
type t_SendDriver = {
  f_request:t_SendRequestKind;
  f_stage:t_SendStage;
  f_authorized:bool;
  f_wrote:bool;
  f_consumed:bool;
  f_delivered:bool;
  f_removed:bool;
  f_deleted:bool;
  f_succeeded:bool;
  f_failed:bool
}

/// One driver event.
type t_SendEvent =
  | SendEvent_SendInserted : t_RowsObservation -> t_SendEvent
  | SendEvent_ViewConsumed : t_ConsumeObservation -> t_SendEvent
  | SendEvent_SendRead : t_ReadObservation -> t_SendEvent
  | SendEvent_SendRemoved : t_RemoveObservation -> t_SendEvent
  | SendEvent_SendDeleted : t_RowsObservation -> t_SendEvent

type t_SendTransition = {
  f_driver:t_SendDriver;
  f_effect:t_SendEffect
}

let is_create (d: t_SendDriver) : bool =
  match d.f_request <: t_SendRequestKind with
  | SendRequestKind_Create  -> true
  | _ -> false

let is_fetch (d: t_SendDriver) : bool =
  match d.f_request <: t_SendRequestKind with
  | SendRequestKind_Fetch  -> true
  | _ -> false

let is_delete (d: t_SendDriver) : bool =
  match d.f_request <: t_SendRequestKind with
  | SendRequestKind_Delete  -> true
  | _ -> false

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
let send_state_is_sound (d: t_SendDriver) : bool =
  let start_clean:bool =
    d.f_authorized && ~.d.f_consumed && ~.d.f_delivered && ~.d.f_removed && ~.d.f_deleted &&
    ~.d.f_succeeded &&
    ~.d.f_failed &&
    (if is_create d || is_delete d then d.f_wrote else ~.d.f_wrote)
  in
  let read_clean:bool =
    d.f_authorized && d.f_consumed && ~.d.f_wrote && ~.d.f_delivered && ~.d.f_removed &&
    ~.d.f_deleted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let remove_clean:bool =
    d.f_authorized && d.f_consumed && d.f_delivered && ~.d.f_removed && ~.d.f_wrote && ~.d.f_deleted &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  in
  let done_clean:bool =
    (d.f_succeeded || d.f_failed) && ~.(d.f_succeeded && d.f_failed) &&
    (~.d.f_succeeded || is_create d && d.f_wrote || is_fetch d && d.f_consumed && d.f_delivered ||
    is_delete d && d.f_wrote) &&
    (~.d.f_failed || ~.d.f_deleted && ~.d.f_delivered && (~.(is_fetch d <: bool) || ~.d.f_removed))
  in
  (match d.f_stage <: t_SendStage with
    | SendStage_Start  -> start_clean
    | SendStage_Read  -> read_clean
    | SendStage_Remove  -> remove_clean
    | SendStage_Done  -> done_clean) &&
  (~.d.f_consumed || is_fetch d) &&
  (~.d.f_delivered || d.f_consumed) &&
  (~.d.f_removed || d.f_delivered) &&
  (~.d.f_removed || is_fetch d) &&
  (~.d.f_wrote || is_create d || is_delete d) &&
  (~.d.f_deleted || is_delete d && d.f_wrote) &&
  (~.(match d.f_stage <: t_SendStage with
    | SendStage_Read  -> true
    | _ -> false) ||
  is_fetch d && d.f_consumed) &&
  (~.(match d.f_stage <: t_SendStage with
    | SendStage_Remove  -> true
    | _ -> false) ||
  is_fetch d && d.f_consumed && d.f_delivered)

/// Every effect the driver emits agrees with the state it produces.
let send_effect_is_sound (d: t_SendDriver) (v_effect: t_SendEffect) : bool =
  match v_effect <: t_SendEffect with
  | SendEffect_InsertSend permit ->
    is_create d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote &&
    ~.d.f_consumed &&
    ~.d.f_delivered &&
    ~.d.f_succeeded &&
    ~.d.f_failed &&
    permit.f_ttl_secs >=. v_MIN_TTL_SECS &&
    permit.f_ttl_secs <=. v_MAX_TTL_SECS &&
    (~.permit.f_max_views_present ||
    permit.f_max_views >=. mk_i64 1 && permit.f_max_views <=. v_MAX_VIEWS_CEILING) &&
    (~.permit.f_view_once || permit.f_max_views_present && permit.f_max_views =. mk_i64 1)
  | SendEffect_ConsumeView  ->
    is_fetch d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    ~.d.f_consumed &&
    ~.d.f_delivered &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | SendEffect_ReadSend  ->
    is_fetch d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Read  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_consumed &&
    ~.d.f_delivered &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | SendEffect_RemoveFetched  ->
    is_fetch d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Remove  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_consumed &&
    d.f_delivered &&
    ~.d.f_removed &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | SendEffect_DeleteLink permit ->
    is_delete d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Start  -> true
      | _ -> false) &&
    d.f_authorized &&
    d.f_wrote &&
    permit.f_owner_bound &&
    ~.d.f_consumed &&
    ~.d.f_delivered &&
    ~.d.f_succeeded &&
    ~.d.f_failed
  | SendEffect_CompleteCreate  ->
    is_create d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Done  -> true
      | _ -> false) &&
    d.f_succeeded &&
    ~.d.f_failed &&
    d.f_wrote
  | SendEffect_CompleteFetch  ->
    is_fetch d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Done  -> true
      | _ -> false) &&
    d.f_succeeded &&
    ~.d.f_failed &&
    d.f_consumed &&
    d.f_delivered
  | SendEffect_CompleteDelete { f_deleted = deleted } ->
    is_delete d &&
    (match d.f_stage <: t_SendStage with
      | SendStage_Done  -> true
      | _ -> false) &&
    d.f_succeeded &&
    ~.d.f_failed &&
    d.f_wrote &&
    d.f_deleted =. deleted
  | SendEffect_Fail _ ->
    (match d.f_stage <: t_SendStage with
      | SendStage_Done  -> true
      | _ -> false) &&
    d.f_failed &&
    ~.d.f_succeeded &&
    ~.d.f_deleted &&
    ~.d.f_delivered
  | SendEffect_Idle  -> true

let fresh_driver (request: t_SendRequestKind) : t_SendDriver =
  {
    f_request = request;
    f_stage = SendStage_Start <: t_SendStage;
    f_authorized = false;
    f_wrote = false;
    f_consumed = false;
    f_delivered = false;
    f_removed = false;
    f_deleted = false;
    f_succeeded = false;
    f_failed = false
  }
  <:
  t_SendDriver

let transition (d: t_SendDriver) (v_effect: t_SendEffect) : t_SendTransition =
  { f_driver = d; f_effect = v_effect } <: t_SendTransition

let idle (d: t_SendDriver) : t_SendTransition = transition d (SendEffect_Idle <: t_SendEffect)

let terminal (d: t_SendDriver) (failure: t_SendFailure) : t_SendTransition =
  transition ({ d with f_stage = SendStage_Done <: t_SendStage; f_failed = true } <: t_SendDriver)
    (SendEffect_Fail failure <: t_SendEffect)

let complete (d: t_SendDriver) (v_effect: t_SendEffect) : t_SendTransition =
  transition ({ d with f_stage = SendStage_Done <: t_SendStage; f_succeeded = true } <: t_SendDriver
    )
    v_effect

/// Start `POST /send`. The handler has decoded nothing yet; the observation
/// carries the request\'s decoded lengths and decode failures. Every size, salt
/// and TTL bound is decided here, and the permit carries the clamped values the
/// insert must use.
let begin_create (observation: t_CreateObservation)
    : Prims.Pure t_SendTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_state_is_sound result.f_driver &&
          send_effect_is_sound result.f_driver result.f_effect) =
  let base:t_SendDriver = fresh_driver (SendRequestKind_Create <: t_SendRequestKind) in
  if ~.observation.f_owner_present
  then terminal base (SendFailure_Unauthenticated <: t_SendFailure)
  else
    if observation.f_ciphertext_decode_failed
    then terminal base (SendFailure_MalformedCiphertext <: t_SendFailure)
    else
      if observation.f_ciphertext_len =. mk_i64 0
      then terminal base (SendFailure_EmptyCiphertext <: t_SendFailure)
      else
        if observation.f_ciphertext_len >. v_MAX_SEND_BYTES
        then terminal base (SendFailure_CiphertextTooLarge <: t_SendFailure)
        else
          if observation.f_has_passphrase && ~.observation.f_kdf_salt_present
          then terminal base (SendFailure_MissingKdfSalt <: t_SendFailure)
          else
            if observation.f_has_passphrase && observation.f_kdf_salt_decode_failed
            then terminal base (SendFailure_MalformedKdfSalt <: t_SendFailure)
            else
              if observation.f_has_passphrase && observation.f_kdf_salt_len <. v_MIN_KDF_SALT_LEN
              then terminal base (SendFailure_KdfSaltTooShort <: t_SendFailure)
              else
                let ttl_secs:i64 = clamp_ttl observation.f_has_ttl observation.f_ttl_secs in
                let (max_views_present: bool), (max_views: i64) =
                  resolve_max_views observation.f_view_once
                    observation.f_has_max_views
                    observation.f_max_views
                in
                transition ({ base with f_authorized = true; f_wrote = true } <: t_SendDriver)
                  (SendEffect_InsertSend
                    ({
                        f_ttl_secs = ttl_secs;
                        f_max_views_present = max_views_present;
                        f_max_views = max_views;
                        f_view_once = observation.f_view_once
                      }
                      <:
                      t_CreatePermit)
                    <:
                    t_SendEffect)

let on_send_inserted (d: t_SendDriver) (observation: t_RowsObservation)
    : Prims.Pure t_SendTransition
      (requires
        send_state_is_sound d && is_create d &&
        (match d.f_stage <: t_SendStage with
          | SendStage_Start  -> true
          | _ -> false) &&
        d.f_wrote)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound d <: bool) || send_state_is_sound result.f_driver)) =
  if observation.f_failed
  then terminal d (SendFailure_InsertStorage <: t_SendFailure)
  else complete d (SendEffect_CompleteCreate <: t_SendEffect)

/// Start `GET /send/:id`. The first effect is the atomic view consume.
let begin_fetch (_: Prims.unit)
    : Prims.Pure t_SendTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_state_is_sound result.f_driver &&
          send_effect_is_sound result.f_driver result.f_effect) =
  transition ({
        (fresh_driver (SendRequestKind_Fetch <: t_SendRequestKind) <: t_SendDriver) with
        f_authorized = true
      }
      <:
      t_SendDriver)
    (SendEffect_ConsumeView <: t_SendEffect)

let on_view_consumed (d: t_SendDriver) (observation: t_ConsumeObservation)
    : Prims.Pure t_SendTransition
      (requires
        send_state_is_sound d && is_fetch d &&
        (match d.f_stage <: t_SendStage with
          | SendStage_Start  -> true
          | _ -> false) &&
        d.f_authorized)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound d <: bool) || send_state_is_sound result.f_driver)) =
  match observation <: t_ConsumeObservation with
  | ConsumeObservation_Consumed  ->
    transition ({ d with f_stage = SendStage_Read <: t_SendStage; f_consumed = true }
        <:
        t_SendDriver)
      (SendEffect_ReadSend <: t_SendEffect)
  | ConsumeObservation_Unavailable  -> terminal d (SendFailure_NotFound <: t_SendFailure)
  | ConsumeObservation_Error  -> terminal d (SendFailure_ConsumeStorage <: t_SendFailure)

let on_send_read (d: t_SendDriver) (observation: t_ReadObservation)
    : Prims.Pure t_SendTransition
      (requires
        send_state_is_sound d && is_fetch d &&
        (match d.f_stage <: t_SendStage with
          | SendStage_Read  -> true
          | _ -> false) &&
        d.f_consumed)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound d <: bool) || send_state_is_sound result.f_driver)) =
  match observation <: t_ReadObservation with
  | ReadObservation_Payload { f_view_once = view_once } ->
    if view_once
    then
      transition ({ d with f_stage = SendStage_Remove <: t_SendStage; f_delivered = true }
          <:
          t_SendDriver)
        (SendEffect_RemoveFetched <: t_SendEffect)
    else
      complete ({ d with f_delivered = true } <: t_SendDriver)
        (SendEffect_CompleteFetch <: t_SendEffect)
  | ReadObservation_Missing  -> terminal d (SendFailure_NotFound <: t_SendFailure)
  | ReadObservation_Unreadable  -> terminal d (SendFailure_RowUnreadable <: t_SendFailure)

let on_send_removed (d: t_SendDriver) (observation: t_RemoveObservation)
    : Prims.Pure t_SendTransition
      (requires
        send_state_is_sound d && is_fetch d &&
        (match d.f_stage <: t_SendStage with
          | SendStage_Remove  -> true
          | _ -> false) &&
        d.f_delivered)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound d <: bool) || send_state_is_sound result.f_driver)) =
  let _:t_RemoveObservation = observation in
  complete ({ d with f_removed = true } <: t_SendDriver) (SendEffect_CompleteFetch <: t_SendEffect)

/// Start `DELETE /send/:id`. Only an authenticated owner obtains the delete
/// permit; the SQL statement additionally carries the owner equality.
let begin_delete (owner_present: bool)
    : Prims.Pure t_SendTransition
      Prims.l_True
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_state_is_sound result.f_driver &&
          send_effect_is_sound result.f_driver result.f_effect) =
  let base:t_SendDriver = fresh_driver (SendRequestKind_Delete <: t_SendRequestKind) in
  if ~.owner_present
  then terminal base (SendFailure_Unauthenticated <: t_SendFailure)
  else
    transition ({ base with f_authorized = true; f_wrote = true } <: t_SendDriver)
      (SendEffect_DeleteLink ({ f_owner_bound = true } <: t_DeletePermit) <: t_SendEffect)

let on_send_deleted (d: t_SendDriver) (observation: t_RowsObservation)
    : Prims.Pure t_SendTransition
      (requires
        send_state_is_sound d && is_delete d &&
        (match d.f_stage <: t_SendStage with
          | SendStage_Start  -> true
          | _ -> false) &&
        d.f_wrote)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound d <: bool) || send_state_is_sound result.f_driver)) =
  if observation.f_failed
  then terminal d (SendFailure_DeleteStorage <: t_SendFailure)
  else
    let deleted:bool = observation.f_rows >. mk_u64 0 in
    complete ({ d with f_deleted = deleted } <: t_SendDriver)
      (SendEffect_CompleteDelete ({ f_deleted = deleted }) <: t_SendEffect)

/// The complete, total transition relation. Events that do not match the
/// current request/stage (and every event after `Done`) are ignored.
let step (driver: t_SendDriver) (event: t_SendEvent)
    : Prims.Pure t_SendTransition
      (requires send_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound driver <: bool) || send_state_is_sound result.f_driver)) =
  match event <: t_SendEvent with
  | SendEvent_SendInserted observation ->
    if
      is_create driver &&
      (match driver.f_stage <: t_SendStage with
        | SendStage_Start  -> true
        | _ -> false) &&
      driver.f_wrote
    then on_send_inserted driver observation
    else idle driver
  | SendEvent_ViewConsumed observation ->
    if
      is_fetch driver &&
      (match driver.f_stage <: t_SendStage with
        | SendStage_Start  -> true
        | _ -> false) &&
      driver.f_authorized
    then on_view_consumed driver observation
    else idle driver
  | SendEvent_SendRead observation ->
    if
      is_fetch driver &&
      (match driver.f_stage <: t_SendStage with
        | SendStage_Read  -> true
        | _ -> false) &&
      driver.f_consumed
    then on_send_read driver observation
    else idle driver
  | SendEvent_SendRemoved observation ->
    if
      is_fetch driver &&
      (match driver.f_stage <: t_SendStage with
        | SendStage_Remove  -> true
        | _ -> false) &&
      driver.f_delivered
    then on_send_removed driver observation
    else idle driver
  | SendEvent_SendDeleted observation ->
    if
      is_delete driver &&
      (match driver.f_stage <: t_SendStage with
        | SendStage_Start  -> true
        | _ -> false) &&
      driver.f_wrote
    then on_send_deleted driver observation
    else idle driver

/// Total wrapper: the handler feeds the insert outcome.
let on_send_inserted_event (driver: t_SendDriver) (observation: t_RowsObservation)
    : Prims.Pure t_SendTransition
      (requires send_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound driver <: bool) || send_state_is_sound result.f_driver)) =
  step driver (SendEvent_SendInserted observation <: t_SendEvent)

/// Total wrapper: the handler feeds the atomic consume outcome.
let on_view_consumed_event (driver: t_SendDriver) (observation: t_ConsumeObservation)
    : Prims.Pure t_SendTransition
      (requires send_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound driver <: bool) || send_state_is_sound result.f_driver)) =
  step driver (SendEvent_ViewConsumed observation <: t_SendEvent)

/// Total wrapper: the handler feeds the row read.
let on_send_read_event (driver: t_SendDriver) (observation: t_ReadObservation)
    : Prims.Pure t_SendTransition
      (requires send_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound driver <: bool) || send_state_is_sound result.f_driver)) =
  step driver (SendEvent_SendRead observation <: t_SendEvent)

/// Total wrapper: the handler feeds the cleanup outcome.
let on_send_removed_event (driver: t_SendDriver) (observation: t_RemoveObservation)
    : Prims.Pure t_SendTransition
      (requires send_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound driver <: bool) || send_state_is_sound result.f_driver)) =
  step driver (SendEvent_SendRemoved observation <: t_SendEvent)

/// Total wrapper: the handler feeds the owner-scoped delete outcome.
let on_send_deleted_event (driver: t_SendDriver) (observation: t_RowsObservation)
    : Prims.Pure t_SendTransition
      (requires send_state_is_sound driver)
      (ensures
        fun result ->
          let result:t_SendTransition = result in
          send_effect_is_sound result.f_driver result.f_effect &&
          (~.(send_state_is_sound driver <: bool) || send_state_is_sound result.f_driver)) =
  step driver (SendEvent_SendDeleted observation <: t_SendEvent)
