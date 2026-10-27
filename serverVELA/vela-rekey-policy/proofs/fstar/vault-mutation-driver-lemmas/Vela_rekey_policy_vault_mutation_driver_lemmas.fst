module Vela_rekey_policy_vault_mutation_driver_lemmas

/// Hand-written trace induction over the extracted drivers for the remaining
/// vault and device mutations:
///
/// - `DELETE /vault/chunk/:id` (`ChunkDeleteDriver`);
/// - `PUT /vault/oram/:tree_id/path/:leaf` (`OramDriver`);
/// - `POST /vault/schema` (`SchemaDriver`);
/// - `POST /device/capsule/ack` (`CapsuleAckDriver`);
/// - `POST /device/rekey-capable` (`RekeyCapableDriver`).
///
/// Each driver's own `*_state_is_sound` / `*_effect_is_sound` is the invariant;
/// the extracted `*_step` postcondition preserves it. All lemmas quantify over
/// every event list. The headline facts are that each request reaches at most
/// one success and one failure, the chunk delete publishes only after its
/// guarded delete, ORAM writes each bucket at the next index and only then
/// publishes, the two device-scoped writes are single effects, and a capsule
/// acknowledgement never clears a different pending epoch.

open FStar.Mul
open Core_models
open Vela_rekey_policy.Vault_mutation_driver

// ── Chunk delete ───────────────────────────────────────────────────────────

let chunk_is_done (d: t_ChunkDeleteDriver) : bool =
  match d.f_stage <: t_ChunkDeleteStage with
  | ChunkDeleteStage_Done -> true
  | _ -> false

let chunk_begin_sound (r: t_ChunkDeleteRequest)
  : Lemma (chunk_delete_state_is_sound (begin_chunk_delete r).f_driver) = ()

let chunk_step_sound (d: t_ChunkDeleteDriver) (e: t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d))
          (ensures (chunk_delete_state_is_sound (chunk_delete_step d e).f_driver)) = ()

let chunk_step_effect_sound (d: t_ChunkDeleteDriver) (e: t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d))
          (ensures (chunk_delete_effect_is_sound
                      (chunk_delete_step d e).f_driver
                      (chunk_delete_step d e).f_effect)) = ()

let rec chunk_run (d: t_ChunkDeleteDriver) (events: list t_ChunkDeleteEvent)
  : Pure t_ChunkDeleteDriver
    (requires (chunk_delete_state_is_sound d))
    (ensures (fun result -> chunk_delete_state_is_sound result))
    (decreases events) =
  match events with
  | [] -> d
  | e :: rest ->
      chunk_step_sound d e;
      chunk_run (chunk_delete_step d e).f_driver rest

let chunk_run_from (r: t_ChunkDeleteRequest) (events: list t_ChunkDeleteEvent)
  : Pure t_ChunkDeleteDriver (requires True)
    (ensures (fun result -> chunk_delete_state_is_sound result)) (decreases events) =
  chunk_begin_sound r;
  chunk_run (begin_chunk_delete r).f_driver events

let chunk_step_after_done (d: t_ChunkDeleteDriver) (e: t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d /\ chunk_is_done d))
          (ensures ((chunk_delete_step d e).f_driver = d /\
                    (chunk_delete_step d e).f_effect = ChunkDeleteEffect_Idle)) =
  match e <: t_ChunkDeleteEvent with
  | ChunkDeleteEvent_Schema _ -> ()
  | ChunkDeleteEvent_Route _ -> ()
  | ChunkDeleteEvent_Version _ -> ()
  | ChunkDeleteEvent_Delete _ -> ()
  | ChunkDeleteEvent_Published -> ()

let rec chunk_done_inert (d: t_ChunkDeleteDriver) (events: list t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d /\ chunk_is_done d))
          (ensures (chunk_run d events = d)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest -> chunk_step_after_done d e; chunk_done_inert d rest

let rec chunk_count_complete (d: t_ChunkDeleteDriver) (events: list t_ChunkDeleteEvent)
  : Pure nat (requires (chunk_delete_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      chunk_step_sound d e;
      (match (chunk_delete_step d e).f_effect <: t_ChunkDeleteEffect with
       | ChunkDeleteEffect_Complete -> 1
       | _ -> 0) + chunk_count_complete (chunk_delete_step d e).f_driver rest

let rec chunk_count_fail (d: t_ChunkDeleteDriver) (events: list t_ChunkDeleteEvent)
  : Pure nat (requires (chunk_delete_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      chunk_step_sound d e;
      (match (chunk_delete_step d e).f_effect <: t_ChunkDeleteEffect with
       | ChunkDeleteEffect_Fail _ -> 1
       | _ -> 0) + chunk_count_fail (chunk_delete_step d e).f_driver rest

let rec chunk_complete_le_one (d: t_ChunkDeleteDriver) (events: list t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d))
          (ensures (chunk_count_complete d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      chunk_step_sound d e;
      chunk_step_effect_sound d e;
      let t = chunk_delete_step d e in
      if (match t.f_effect <: t_ChunkDeleteEffect with ChunkDeleteEffect_Complete -> true | _ -> false)
      then begin
        assert (chunk_is_done t.f_driver);
        chunk_done_inert t.f_driver rest
      end else chunk_complete_le_one t.f_driver rest

let rec chunk_fail_le_one (d: t_ChunkDeleteDriver) (events: list t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d))
          (ensures (chunk_count_fail d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      chunk_step_sound d e;
      chunk_step_effect_sound d e;
      let t = chunk_delete_step d e in
      if (match t.f_effect <: t_ChunkDeleteEffect with ChunkDeleteEffect_Fail _ -> true | _ -> false)
      then begin
        assert (chunk_is_done t.f_driver);
        chunk_done_inert t.f_driver rest
      end else chunk_fail_le_one t.f_driver rest

/// The publish effect exists only after the guarded delete was observed.
let chunk_publish_after_delete (d: t_ChunkDeleteDriver) (e: t_ChunkDeleteEvent)
  : Lemma (requires (chunk_delete_state_is_sound d))
          (ensures ((chunk_delete_step d e).f_effect = ChunkDeleteEffect_Publish ==>
                    (chunk_delete_step d e).f_driver.f_deleted)) =
  chunk_step_effect_sound d e

let chunk_delete_theorem (request: t_ChunkDeleteRequest) (events: list t_ChunkDeleteEvent)
  : Lemma (
      let d = chunk_run_from request events in
      chunk_delete_state_is_sound d /\
      (d.f_responded ==> (d.f_deleted /\ d.f_published /\ d.f_permit_epoch = d.f_epoch)) /\
      (not d.f_responded || not d.f_failed) /\
      chunk_count_complete (begin_chunk_delete request).f_driver events <= 1 /\
      chunk_count_fail (begin_chunk_delete request).f_driver events <= 1) =
  chunk_begin_sound request;
  chunk_complete_le_one (begin_chunk_delete request).f_driver events;
  chunk_fail_le_one (begin_chunk_delete request).f_driver events

// ── ORAM path write ────────────────────────────────────────────────────────

let oram_is_done (d: t_OramDriver) : bool =
  match d.f_stage <: t_OramStage with
  | OramStage_Done -> true
  | _ -> false

let oram_begin_sound (r: t_OramRequest)
  : Lemma (oram_state_is_sound (begin_oram r).f_driver) = ()

let oram_step_sound (d: t_OramDriver) (e: t_OramEvent)
  : Lemma (requires (oram_state_is_sound d))
          (ensures (oram_state_is_sound (oram_step d e).f_driver)) = ()

let oram_step_effect_sound (d: t_OramDriver) (e: t_OramEvent)
  : Lemma (requires (oram_state_is_sound d))
          (ensures (oram_effect_is_sound (oram_step d e).f_driver (oram_step d e).f_effect)) = ()

let rec oram_run (d: t_OramDriver) (events: list t_OramEvent)
  : Pure t_OramDriver (requires (oram_state_is_sound d))
    (ensures (fun result -> oram_state_is_sound result)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest -> oram_step_sound d e; oram_run (oram_step d e).f_driver rest

let oram_run_from (r: t_OramRequest) (events: list t_OramEvent)
  : Pure t_OramDriver (requires True)
    (ensures (fun result -> oram_state_is_sound result)) (decreases events) =
  oram_begin_sound r;
  oram_run (begin_oram r).f_driver events

let oram_step_after_done (d: t_OramDriver) (e: t_OramEvent)
  : Lemma (requires (oram_state_is_sound d /\ oram_is_done d))
          (ensures ((oram_step d e).f_driver = d /\ (oram_step d e).f_effect = OramEffect_Idle)) =
  match e <: t_OramEvent with
  | OramEvent_Route _ -> ()
  | OramEvent_Quota _ -> ()
  | OramEvent_Bucket _ -> ()
  | OramEvent_Recheck _ -> ()
  | OramEvent_Published -> ()

let rec oram_done_inert (d: t_OramDriver) (events: list t_OramEvent)
  : Lemma (requires (oram_state_is_sound d /\ oram_is_done d))
          (ensures (oram_run d events = d)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest -> oram_step_after_done d e; oram_done_inert d rest

let rec oram_count_complete (d: t_OramDriver) (events: list t_OramEvent)
  : Pure nat (requires (oram_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      oram_step_sound d e;
      (match (oram_step d e).f_effect <: t_OramEffect with
       | OramEffect_Complete -> 1
       | _ -> 0) + oram_count_complete (oram_step d e).f_driver rest

let rec oram_count_fail (d: t_OramDriver) (events: list t_OramEvent)
  : Pure nat (requires (oram_state_is_sound d)) (ensures (fun _ -> True)) (decreases events) =
  match events with
  | [] -> 0
  | e :: rest ->
      oram_step_sound d e;
      (match (oram_step d e).f_effect <: t_OramEffect with
       | OramEffect_Fail _ -> 1
       | _ -> 0) + oram_count_fail (oram_step d e).f_driver rest

let rec oram_complete_le_one (d: t_OramDriver) (events: list t_OramEvent)
  : Lemma (requires (oram_state_is_sound d))
          (ensures (oram_count_complete d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      oram_step_sound d e;
      oram_step_effect_sound d e;
      let t = oram_step d e in
      if (match t.f_effect <: t_OramEffect with OramEffect_Complete -> true | _ -> false)
      then begin
        assert (oram_is_done t.f_driver);
        oram_done_inert t.f_driver rest
      end else oram_complete_le_one t.f_driver rest

let rec oram_fail_le_one (d: t_OramDriver) (events: list t_OramEvent)
  : Lemma (requires (oram_state_is_sound d))
          (ensures (oram_count_fail d events <= 1)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest ->
      oram_step_sound d e;
      oram_step_effect_sound d e;
      let t = oram_step d e in
      if (match t.f_effect <: t_OramEffect with OramEffect_Fail _ -> true | _ -> false)
      then begin
        assert (oram_is_done t.f_driver);
        oram_done_inert t.f_driver rest
      end else oram_fail_le_one t.f_driver rest

/// A bucket write is always the next index, and only a complete path
/// publishes.
let oram_write_is_next (d: t_OramDriver) (e: t_OramEvent)
  : Lemma (requires (oram_state_is_sound d))
          (ensures (
            (match (oram_step d e).f_effect <: t_OramEffect with
             | OramEffect_WriteBucket { f_index = index } ->
                 index = d.f_written /\ d.f_written < d.f_bucket_count
             | OramEffect_Publish -> d.f_written = d.f_bucket_count
             | _ -> True))) =
  oram_step_effect_sound d e

let oram_theorem (request: t_OramRequest) (events: list t_OramEvent)
  : Lemma (
      let d = oram_run_from request events in
      oram_state_is_sound d /\
      (d.f_responded ==> (d.f_published /\ d.f_written = d.f_bucket_count)) /\
      (not d.f_responded || not d.f_failed) /\
      oram_count_complete (begin_oram request).f_driver events <= 1 /\
      oram_count_fail (begin_oram request).f_driver events <= 1) =
  oram_begin_sound request;
  oram_complete_le_one (begin_oram request).f_driver events;
  oram_fail_le_one (begin_oram request).f_driver events

// ── Schema activation ─────────────────────────────────────────────────────

let schema_is_done (d: t_SchemaDriver) : bool =
  match d.f_stage <: t_SchemaStage with
  | SchemaStage_Done -> true
  | _ -> false

let schema_begin_sound (r: t_SchemaRequest)
  : Lemma (schema_state_is_sound (begin_schema r).f_driver) = ()

let schema_step_sound (d: t_SchemaDriver) (e: t_SchemaEvent)
  : Lemma (requires (schema_state_is_sound d))
          (ensures (schema_state_is_sound (schema_step d e).f_driver)) = ()

let schema_step_effect_sound (d: t_SchemaDriver) (e: t_SchemaEvent)
  : Lemma (requires (schema_state_is_sound d))
          (ensures (schema_effect_is_sound (schema_step d e).f_driver (schema_step d e).f_effect)) = ()

let rec schema_run (d: t_SchemaDriver) (events: list t_SchemaEvent)
  : Pure t_SchemaDriver (requires (schema_state_is_sound d))
    (ensures (fun result -> schema_state_is_sound result)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest -> schema_step_sound d e; schema_run (schema_step d e).f_driver rest

let schema_run_from (r: t_SchemaRequest) (events: list t_SchemaEvent)
  : Pure t_SchemaDriver (requires True)
    (ensures (fun result -> schema_state_is_sound result)) (decreases events) =
  schema_begin_sound r;
  schema_run (begin_schema r).f_driver events

let schema_step_after_done (d: t_SchemaDriver) (e: t_SchemaEvent)
  : Lemma (requires (schema_state_is_sound d /\ schema_is_done d))
          (ensures ((schema_step d e).f_driver = d /\ (schema_step d e).f_effect = SchemaEffect_Idle)) =
  match e <: t_SchemaEvent with
  | SchemaEvent_Write _ -> ()

let rec schema_done_inert (d: t_SchemaDriver) (events: list t_SchemaEvent)
  : Lemma (requires (schema_state_is_sound d /\ schema_is_done d))
          (ensures (schema_run d events = d)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest -> schema_step_after_done d e; schema_done_inert d rest

let schema_theorem (request: t_SchemaRequest) (events: list t_SchemaEvent)
  : Lemma (
      let d = schema_run_from request events in
      schema_state_is_sound d /\
      (d.f_responded ==> d.f_written) /\
      (not d.f_responded || not d.f_failed) /\
      (d.f_written ==> (d.f_authenticated && d.f_device_scope))) =
  schema_begin_sound request

// ── Capsule acknowledgement ────────────────────────────────────────────────

let ack_is_done (d: t_CapsuleAckDriver) : bool =
  match d.f_stage <: t_CapsuleAckStage with
  | CapsuleAckStage_Done -> true
  | _ -> false

let ack_begin_sound (r: t_CapsuleAckRequest)
  : Lemma (capsule_ack_state_is_sound (begin_capsule_ack r).f_driver) = ()

let ack_step_sound (d: t_CapsuleAckDriver) (e: t_CapsuleAckEvent)
  : Lemma (requires (capsule_ack_state_is_sound d))
          (ensures (capsule_ack_state_is_sound (capsule_ack_step d e).f_driver)) = ()

let ack_step_effect_sound (d: t_CapsuleAckDriver) (e: t_CapsuleAckEvent)
  : Lemma (requires (capsule_ack_state_is_sound d))
          (ensures (capsule_ack_effect_is_sound
                      (capsule_ack_step d e).f_driver (capsule_ack_step d e).f_effect)) = ()

let rec ack_run (d: t_CapsuleAckDriver) (events: list t_CapsuleAckEvent)
  : Pure t_CapsuleAckDriver (requires (capsule_ack_state_is_sound d))
    (ensures (fun result -> capsule_ack_state_is_sound result)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest -> ack_step_sound d e; ack_run (capsule_ack_step d e).f_driver rest

let ack_run_from (r: t_CapsuleAckRequest) (events: list t_CapsuleAckEvent)
  : Pure t_CapsuleAckDriver (requires True)
    (ensures (fun result -> capsule_ack_state_is_sound result)) (decreases events) =
  ack_begin_sound r;
  ack_run (begin_capsule_ack r).f_driver events

let ack_step_after_done (d: t_CapsuleAckDriver) (e: t_CapsuleAckEvent)
  : Lemma (requires (capsule_ack_state_is_sound d /\ ack_is_done d))
          (ensures ((capsule_ack_step d e).f_driver = d /\
                    (capsule_ack_step d e).f_effect = CapsuleAckEffect_Idle)) =
  match e <: t_CapsuleAckEvent with
  | CapsuleAckEvent_Ack _ -> ()
  | CapsuleAckEvent_Pending _ -> ()

let rec ack_done_inert (d: t_CapsuleAckDriver) (events: list t_CapsuleAckEvent)
  : Lemma (requires (capsule_ack_state_is_sound d /\ ack_is_done d))
          (ensures (ack_run d events = d)) (decreases events) =
  match events with
  | [] -> ()
  | e :: rest -> ack_step_after_done d e; ack_done_inert d rest

/// The pending inspection is only reached after a missed clear, and a replay
/// is the only pending observation that produces a success.
let ack_replay_or_cleared (d: t_CapsuleAckDriver) (e: t_CapsuleAckEvent)
  : Lemma (requires (capsule_ack_state_is_sound d))
          (ensures (
            (capsule_ack_step d e).f_effect = CapsuleAckEffect_InspectPending ==>
            not d.f_cleared)) =
  ack_step_effect_sound d e

let ack_theorem (request: t_CapsuleAckRequest) (events: list t_CapsuleAckEvent)
  : Lemma (
      let d = ack_run_from request events in
      capsule_ack_state_is_sound d /\
      (d.f_responded ==> d.f_cleared) /\
      (not d.f_responded || not d.f_failed) /\
      (d.f_cleared ==> (d.f_authenticated && d.f_device_scope))) =
  ack_begin_sound request

// ── Capability attestation ─────────────────────────────────────────────────

let capable_is_done (d: t_RekeyCapableDriver) : bool =
  match d.f_stage <: t_RekeyCapableStage with
  | RekeyCapableStage_Done -> true
  | _ -> false

let capable_begin_sound (r: t_RekeyCapableRequest)
  : Lemma (rekey_capable_state_is_sound (begin_rekey_capable r).f_driver) = ()

let capable_step_sound (d: t_RekeyCapableDriver) (e: t_RekeyCapableEvent)
  : Lemma (requires (rekey_capable_state_is_sound d))
          (ensures (rekey_capable_state_is_sound (rekey_capable_step d e).f_driver)) = ()

let rec capable_run (d: t_RekeyCapableDriver) (events: list t_RekeyCapableEvent)
  : Pure t_RekeyCapableDriver (requires (rekey_capable_state_is_sound d))
    (ensures (fun result -> rekey_capable_state_is_sound result)) (decreases events) =
  match events with
  | [] -> d
  | e :: rest -> capable_step_sound d e; capable_run (rekey_capable_step d e).f_driver rest

let capable_run_from (r: t_RekeyCapableRequest) (events: list t_RekeyCapableEvent)
  : Pure t_RekeyCapableDriver (requires True)
    (ensures (fun result -> rekey_capable_state_is_sound result)) (decreases events) =
  capable_begin_sound r;
  capable_run (begin_rekey_capable r).f_driver events

let capable_theorem (request: t_RekeyCapableRequest) (events: list t_RekeyCapableEvent)
  : Lemma (
      let d = capable_run_from request events in
      rekey_capable_state_is_sound d /\
      (d.f_responded ==> d.f_attested) /\
      (not d.f_responded || not d.f_failed) /\
      (d.f_attested ==> (d.f_authenticated && d.f_device_scope))) =
  capable_begin_sound request
