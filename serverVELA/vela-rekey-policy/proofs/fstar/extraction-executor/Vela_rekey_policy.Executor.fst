module Vela_rekey_policy.Executor
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// One statement an executor may run. Field names follow the bound
/// parameters; [`render`] fixes their order and their SQL types.
type t_VaultStmt =
  | VaultStmt_SelectChunkVersion {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_SelectChunkRow {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_SelectChunkExists {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_InsertChunkCreate {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_lamport_clock:i64;
    f_last_writer:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String;
    f_epoch:i64;
    f_now:Alloc.String.t_String;
    f_permit_epoch:i64
  }: t_VaultStmt
  | VaultStmt_InsertChunkShadow {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_lamport_clock:i64;
    f_last_writer:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String;
    f_epoch:i64;
    f_now:Alloc.String.t_String;
    f_read_epoch:i64;
    f_starter:Alloc.String.t_String;
    f_rotation_id:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_UpdateChunkCas {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_version:i64;
    f_lamport_clock:i64;
    f_last_writer:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String;
    f_epoch:i64;
    f_now:Alloc.String.t_String;
    f_permit_epoch:i64
  }: t_VaultStmt
  | VaultStmt_DeleteChunkCas {
    f_chunk_id:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_SelectInventory {
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_DeleteChunksNotEpoch {
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_DeleteChunksAboveEpoch {
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_DeleteChunksBelowEpoch {
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_FreezeCas {
    f_user:Alloc.String.t_String;
    f_from_epoch:i64;
    f_now:Alloc.String.t_String;
    f_starter:Alloc.String.t_String;
    f_rotation_id:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_CommitCas {
    f_user:Alloc.String.t_String;
    f_from_epoch:i64;
    f_to_epoch:i64;
    f_starter:Alloc.String.t_String;
    f_rotation_id:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_RollbackCas {
    f_user:Alloc.String.t_String;
    f_epoch:i64;
    f_rotation_id:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_RefreshShadowActivity {
    f_user:Alloc.String.t_String;
    f_read_epoch:i64;
    f_starter:Alloc.String.t_String;
    f_rotation_id:Alloc.String.t_String;
    f_now:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_ClearAttemptCapsules {
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_WriteDeviceCapsule {
    f_device:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_capsule:Alloc.String.t_String;
    f_capsule_epoch:i64;
    f_from_epoch:i64;
    f_starter:Alloc.String.t_String;
    f_rotation_id:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_SelectPendingCapsule {
    f_device:Alloc.String.t_String;
    f_user:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_AckDeviceCapsule {
    f_device:Alloc.String.t_String;
    f_user:Alloc.String.t_String;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_AttestCapable {
    f_device:Alloc.String.t_String;
    f_user:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_ProbeOram { f_user:Alloc.String.t_String }: t_VaultStmt
  | VaultStmt_ProbeCapable { f_user:Alloc.String.t_String }: t_VaultStmt
  | VaultStmt_ProbeAcknowledged { f_user:Alloc.String.t_String }: t_VaultStmt
  | VaultStmt_ProbeChunkShadows {
    f_user:Alloc.String.t_String;
    f_from_epoch:i64;
    f_to_epoch:i64
  }: t_VaultStmt
  | VaultStmt_ProbeDeviceCapsules {
    f_user:Alloc.String.t_String;
    f_to_epoch:i64
  }: t_VaultStmt
  | VaultStmt_SelectOramBucket {
    f_user:Alloc.String.t_String;
    f_tree_id:Alloc.String.t_String;
    f_bucket_index:i64;
    f_epoch:i64
  }: t_VaultStmt
  | VaultStmt_InsertOramBucket {
    f_user:Alloc.String.t_String;
    f_tree_id:Alloc.String.t_String;
    f_bucket_index:i64;
    f_lamport_clock:i64;
    f_last_writer:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String;
    f_epoch:i64;
    f_now:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_UpdateOramBucketCas {
    f_user:Alloc.String.t_String;
    f_tree_id:Alloc.String.t_String;
    f_bucket_index:i64;
    f_version:i64;
    f_lamport_clock:i64;
    f_last_writer:Alloc.String.t_String;
    f_ciphertext:Alloc.String.t_String;
    f_epoch:i64;
    f_now:Alloc.String.t_String
  }: t_VaultStmt
  | VaultStmt_SchemaFloorSet { f_key:Alloc.String.t_String }: t_VaultStmt
  | VaultStmt_Commit : t_VaultStmt

/// What one write statement (or the commit) returned.
type t_WriteOutcome =
  | WriteOutcome_Applied : u64 -> t_WriteOutcome
  | WriteOutcome_Failed : t_WriteOutcome

/// What one read statement returned: its rows, or an error.
type t_ReadOutcome (v_R: Type0) =
  | ReadOutcome_Rows : v_R -> t_ReadOutcome v_R
  | ReadOutcome_Failed : t_ReadOutcome v_R

/// The cells of a `SelectChunkRow` row, as the handler decodes them.
type t_ChunkRowView = {
  f_chunk_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_user_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_version:Core_models.Option.t_Option i64;
  f_lamport_clock:Core_models.Option.t_Option i64;
  f_last_writer:Core_models.Option.t_Option Alloc.String.t_String;
  f_ciphertext:Core_models.Option.t_Option Alloc.String.t_String;
  f_epoch:Core_models.Option.t_Option i64
}

/// One `SelectInventory` row.
type t_InventoryRowView = {
  f_chunk_id:Core_models.Option.t_Option Alloc.String.t_String;
  f_version:Core_models.Option.t_Option i64;
  f_lamport_clock:Core_models.Option.t_Option i64
}

/// The `SelectPendingCapsule` row: its `rms_capsule_epoch` cell.
type t_PendingRowView = { f_epoch:Core_models.Option.t_Option i64 }

/// `DeleteChunkIo::delete_row`: one guarded delete (autocommit).
let plan_delete_chunk (chunk_id user: Alloc.String.t_String) (epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_DeleteChunkCas ({ f_chunk_id = chunk_id; f_user = user; f_epoch = epoch })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `DeleteChunkIo::read_version`.
let plan_read_version (chunk_id user: Alloc.String.t_String) (epoch: i64) : t_VaultStmt =
  VaultStmt_SelectChunkVersion ({ f_chunk_id = chunk_id; f_user = user; f_epoch = epoch })
  <:
  t_VaultStmt

/// `PutChunkIo::reread_version`.
let plan_reread_version (chunk_id user: Alloc.String.t_String) (epoch: i64) : t_VaultStmt =
  VaultStmt_SelectChunkVersion ({ f_chunk_id = chunk_id; f_user = user; f_epoch = epoch })
  <:
  t_VaultStmt

/// `GetChunkIo::lookup_chunk`.
let plan_read_chunk (chunk_id user: Alloc.String.t_String) (epoch: i64) : t_VaultStmt =
  VaultStmt_SelectChunkRow ({ f_chunk_id = chunk_id; f_user = user; f_epoch = epoch })
  <:
  t_VaultStmt

/// The create path's uniqueness probe.
let plan_chunk_exists (chunk_id user: Alloc.String.t_String) (epoch: i64) : t_VaultStmt =
  VaultStmt_SelectChunkExists ({ f_chunk_id = chunk_id; f_user = user; f_epoch = epoch })
  <:
  t_VaultStmt

/// `PutChunkIo::guarded_write` for `If-Match: 0`, ACTIVE account.
let plan_chunk_create
      (chunk_id user: Alloc.String.t_String)
      (lamport_clock: i64)
      (last_writer ciphertext: Alloc.String.t_String)
      (epoch: i64)
      (now: Alloc.String.t_String)
      (permit_epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_InsertChunkCreate
            ({
                f_chunk_id = chunk_id;
                f_user = user;
                f_lamport_clock = lamport_clock;
                f_last_writer = last_writer;
                f_ciphertext = ciphertext;
                f_epoch = epoch;
                f_now = now;
                f_permit_epoch = permit_epoch
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `PutChunkIo::guarded_write` for `If-Match: 0`, shadow (`FREEZING`).
let plan_chunk_shadow
      (chunk_id user: Alloc.String.t_String)
      (lamport_clock: i64)
      (last_writer ciphertext: Alloc.String.t_String)
      (epoch: i64)
      (now: Alloc.String.t_String)
      (read_epoch: i64)
      (starter rotation_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_InsertChunkShadow
            ({
                f_chunk_id = chunk_id;
                f_user = user;
                f_lamport_clock = lamport_clock;
                f_last_writer = last_writer;
                f_ciphertext = ciphertext;
                f_epoch = epoch;
                f_now = now;
                f_read_epoch = read_epoch;
                f_starter = starter;
                f_rotation_id = rotation_id
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `PutChunkIo::guarded_write` for `If-Match: version`.
let plan_chunk_update
      (chunk_id user: Alloc.String.t_String)
      (version lamport_clock: i64)
      (last_writer ciphertext: Alloc.String.t_String)
      (epoch: i64)
      (now: Alloc.String.t_String)
      (permit_epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_UpdateChunkCas
            ({
                f_chunk_id = chunk_id;
                f_user = user;
                f_version = version;
                f_lamport_clock = lamport_clock;
                f_last_writer = last_writer;
                f_ciphertext = ciphertext;
                f_epoch = epoch;
                f_now = now;
                f_permit_epoch = permit_epoch
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `RekeyIo::read_inventory`.
let plan_read_inventory (user: Alloc.String.t_String) (epoch: i64) : t_VaultStmt =
  VaultStmt_SelectInventory ({ f_user = user; f_epoch = epoch }) <: t_VaultStmt

/// `RekeyIo::freeze_cas`.
let plan_freeze_cas
      (user: Alloc.String.t_String)
      (from_epoch: i64)
      (now starter rotation_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_FreezeCas
            ({
                f_user = user;
                f_from_epoch = from_epoch;
                f_now = now;
                f_starter = starter;
                f_rotation_id = rotation_id
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// The freeze transaction after its CAS reported a row: drop every other
/// epoch's chunks.
let plan_freeze_cleanup (user: Alloc.String.t_String) (epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [VaultStmt_DeleteChunksNotEpoch ({ f_user = user; f_epoch = epoch }) <: t_VaultStmt]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// The transaction's own commit statement.
let plan_commit_transaction (_: Prims.unit) : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list = [VaultStmt_Commit <: t_VaultStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `RekeyIo::commit_cas`.
let plan_commit_cas
      (user: Alloc.String.t_String)
      (from_epoch to_epoch: i64)
      (starter rotation_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_CommitCas
            ({
                f_user = user;
                f_from_epoch = from_epoch;
                f_to_epoch = to_epoch;
                f_starter = starter;
                f_rotation_id = rotation_id
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// The post-commit sweep of superseded rows (autocommit).
let plan_sweep_old_chunks (user: Alloc.String.t_String) (new_epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [VaultStmt_DeleteChunksBelowEpoch ({ f_user = user; f_epoch = new_epoch }) <: t_VaultStmt]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `RekeyIo::rollback_attempt`, the CAS half.
let plan_rollback_cas
      (user: Alloc.String.t_String)
      (epoch: i64)
      (rotation_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_RollbackCas ({ f_user = user; f_epoch = epoch; f_rotation_id = rotation_id })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// The rollback transaction after its CAS reported a row: drop this attempt's
/// chunks and capsules.
let plan_rollback_cleanup (user: Alloc.String.t_String) (epoch target_epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_DeleteChunksAboveEpoch
            ({
                f_user
                =
                Core_models.Clone.f_clone #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  user;
                f_epoch = epoch
              })
            <:
            t_VaultStmt;
            VaultStmt_ClearAttemptCapsules ({ f_user = user; f_epoch = target_epoch })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
        Rust_primitives.Hax.array_of_list 2 list)
      <:
      t_Slice t_VaultStmt)

/// `record_shadow_activity`: the guarded deadline refresh.
let plan_shadow_activity
      (user: Alloc.String.t_String)
      (read_epoch: i64)
      (starter rotation_id now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_RefreshShadowActivity
            ({
                f_user = user;
                f_read_epoch = read_epoch;
                f_starter = starter;
                f_rotation_id = rotation_id;
                f_now = now
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `RekeyIo::check_oram`.
let plan_probe_oram (user: Alloc.String.t_String) : t_VaultStmt =
  VaultStmt_ProbeOram ({ f_user = user }) <: t_VaultStmt

/// `RekeyIo::check_capable`.
let plan_probe_capable (user: Alloc.String.t_String) : t_VaultStmt =
  VaultStmt_ProbeCapable ({ f_user = user }) <: t_VaultStmt

/// `RekeyIo::check_acknowledged`.
let plan_probe_acknowledged (user: Alloc.String.t_String) : t_VaultStmt =
  VaultStmt_ProbeAcknowledged ({ f_user = user }) <: t_VaultStmt

/// `RekeyIo::check_chunk_shadows`.
let plan_probe_chunk_shadows (user: Alloc.String.t_String) (from_epoch to_epoch: i64) : t_VaultStmt =
  VaultStmt_ProbeChunkShadows ({ f_user = user; f_from_epoch = from_epoch; f_to_epoch = to_epoch })
  <:
  t_VaultStmt

/// `RekeyIo::check_device_capsules`.
let plan_probe_device_capsules (user: Alloc.String.t_String) (to_epoch: i64) : t_VaultStmt =
  VaultStmt_ProbeDeviceCapsules ({ f_user = user; f_to_epoch = to_epoch }) <: t_VaultStmt

/// `RekeyIo::write_capsule`: one guarded device write.
let plan_write_capsule
      (device user capsule: Alloc.String.t_String)
      (capsule_epoch from_epoch: i64)
      (starter rotation_id: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_WriteDeviceCapsule
            ({
                f_device = device;
                f_user = user;
                f_capsule = capsule;
                f_capsule_epoch = capsule_epoch;
                f_from_epoch = from_epoch;
                f_starter = starter;
                f_rotation_id = rotation_id
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `CapsuleAckIo::acknowledge`.
let plan_ack_capsule (device user: Alloc.String.t_String) (epoch: i64)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_AckDeviceCapsule ({ f_device = device; f_user = user; f_epoch = epoch })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `CapsuleAckIo::inspect_pending`.
let plan_pending_capsule (device user: Alloc.String.t_String) : t_VaultStmt =
  VaultStmt_SelectPendingCapsule ({ f_device = device; f_user = user }) <: t_VaultStmt

/// `CapableIo::attest`.
let plan_attest_capable (device user: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list = [VaultStmt_AttestCapable ({ f_device = device; f_user = user }) <: t_VaultStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `ActivateIo::write_floor`: the one durable store write, for `key`.
let plan_schema_floor (key: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list = [VaultStmt_SchemaFloorSet ({ f_key = key }) <: t_VaultStmt] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// The ORAM create path's uniqueness probe.
let plan_oram_exists (user tree_id: Alloc.String.t_String) (bucket_index epoch: i64) : t_VaultStmt =
  VaultStmt_SelectOramBucket
  ({ f_user = user; f_tree_id = tree_id; f_bucket_index = bucket_index; f_epoch = epoch })
  <:
  t_VaultStmt

/// `PutOramIo::write_bucket` for `if_match == 0`.
let plan_oram_insert
      (user tree_id: Alloc.String.t_String)
      (bucket_index lamport_clock: i64)
      (last_writer ciphertext: Alloc.String.t_String)
      (epoch: i64)
      (now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_InsertOramBucket
            ({
                f_user = user;
                f_tree_id = tree_id;
                f_bucket_index = bucket_index;
                f_lamport_clock = lamport_clock;
                f_last_writer = last_writer;
                f_ciphertext = ciphertext;
                f_epoch = epoch;
                f_now = now
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `PutOramIo::write_bucket` for `if_match == version`.
let plan_oram_update
      (user tree_id: Alloc.String.t_String)
      (bucket_index version lamport_clock: i64)
      (last_writer ciphertext: Alloc.String.t_String)
      (epoch: i64)
      (now: Alloc.String.t_String)
    : Alloc.Vec.t_Vec t_VaultStmt Alloc.Alloc.t_Global =
  Alloc.Slice.impl__into_vec #t_VaultStmt
    #Alloc.Alloc.t_Global
    ((let list =
          [
            VaultStmt_UpdateOramBucketCas
            ({
                f_user = user;
                f_tree_id = tree_id;
                f_bucket_index = bucket_index;
                f_version = version;
                f_lamport_clock = lamport_clock;
                f_last_writer = last_writer;
                f_ciphertext = ciphertext;
                f_epoch = epoch;
                f_now = now
              })
            <:
            t_VaultStmt
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
        Rust_primitives.Hax.array_of_list 1 list)
      <:
      t_Slice t_VaultStmt)

/// `read_version`/`reread_version`: the stored version, missing, or storage.
let classify_version (outcome: t_ReadOutcome (Core_models.Option.t_Option i64))
    : Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation =
  match outcome <: t_ReadOutcome (Core_models.Option.t_Option i64) with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Vault_mutation_driver.VersionObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation
  | ReadOutcome_Rows (Core_models.Option.Option_Some version) ->
    Vela_rekey_policy.Vault_mutation_driver.VersionObservation_Found
    ({ Vela_rekey_policy.Vault_mutation_driver.f_version = version })
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation
  | ReadOutcome_Rows (Core_models.Option.Option_None ) ->
    Vela_rekey_policy.Vault_mutation_driver.VersionObservation_Missing
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_VersionObservation

/// `reread_version`: the version the guarded write committed.
let classify_reread (outcome: t_ReadOutcome (Core_models.Option.t_Option i64))
    : Vela_rekey_policy.Vault_upload_driver.t_RereadObservation =
  match outcome <: t_ReadOutcome (Core_models.Option.t_Option i64) with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Vault_upload_driver.RereadObservation_Failed
    <:
    Vela_rekey_policy.Vault_upload_driver.t_RereadObservation
  | ReadOutcome_Rows (Core_models.Option.Option_Some version) ->
    Vela_rekey_policy.Vault_upload_driver.RereadObservation_Read
    ({ Vela_rekey_policy.Vault_upload_driver.f_version = version })
    <:
    Vela_rekey_policy.Vault_upload_driver.t_RereadObservation
  | ReadOutcome_Rows (Core_models.Option.Option_None ) ->
    Vela_rekey_policy.Vault_upload_driver.RereadObservation_Missing
    <:
    Vela_rekey_policy.Vault_upload_driver.t_RereadObservation

/// `delete_row`: deleted only when the one guarded statement changed a row.
let classify_delete (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
      Vela_rekey_policy.Vault_mutation_driver.DeleteObservation_Deleted
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_mutation_driver.DeleteObservation_Skipped
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_mutation_driver.DeleteObservation_Storage
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation
  else
    Vela_rekey_policy.Vault_mutation_driver.DeleteObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_DeleteObservation

/// `lookup_chunk`: the observation the read driver consumes. The row cells are
/// the stored truth; `decode_failed` is the handler's row-decoding verdict.
let classify_chunk_read
      (caller: Alloc.String.t_String)
      (read_epoch: i64)
      (decode_failed: bool)
      (outcome: t_ReadOutcome (Core_models.Option.t_Option t_ChunkRowView))
    : Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation =
  match outcome <: t_ReadOutcome (Core_models.Option.t_Option t_ChunkRowView) with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Vault_upload_driver.ReadLookupObservation_QueryFailed
    <:
    Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation
  | ReadOutcome_Rows (Core_models.Option.Option_None ) ->
    Vela_rekey_policy.Vault_upload_driver.ReadLookupObservation_Missing
    <:
    Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation
  | _ ->
    match
      (match outcome <: t_ReadOutcome (Core_models.Option.t_Option t_ChunkRowView) with
        | ReadOutcome_Rows (Core_models.Option.Option_Some row) ->
          (match decode_failed <: bool with
            | true ->
              Core_models.Option.Option_Some
              (Vela_rekey_policy.Vault_upload_driver.ReadLookupObservation_Malformed
                <:
                Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation)
              <:
              Core_models.Option.t_Option
              Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation
            | _ ->
              Core_models.Option.Option_None
              <:
              Core_models.Option.t_Option
              Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation)
        | _ ->
          Core_models.Option.Option_None
          <:
          Core_models.Option.t_Option Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation)
      <:
      Core_models.Option.t_Option Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation
    with
    | Core_models.Option.Option_Some x -> x
    | Core_models.Option.Option_None  ->
      match outcome <: t_ReadOutcome (Core_models.Option.t_Option t_ChunkRowView) with
      | ReadOutcome_Rows (Core_models.Option.Option_Some row) ->
        Vela_rekey_policy.Vault_upload_driver.ReadLookupObservation_Found
        ({
            Vela_rekey_policy.Vault_upload_driver.f_account_matches
            =
            (match row.f_user_id <: Core_models.Option.t_Option Alloc.String.t_String with
              | Core_models.Option.Option_Some owner -> owner =. caller
              | Core_models.Option.Option_None  -> false);
            Vela_rekey_policy.Vault_upload_driver.f_epoch_matches
            =
            row.f_epoch =.
            (Core_models.Option.Option_Some read_epoch <: Core_models.Option.t_Option i64);
            Vela_rekey_policy.Vault_upload_driver.f_version
            =
            Core_models.Option.impl__unwrap_or #i64 row.f_version (mk_i64 0);
            Vela_rekey_policy.Vault_upload_driver.f_lamport_clock
            =
            Core_models.Option.impl__unwrap_or #i64 row.f_lamport_clock (mk_i64 0)
          })
        <:
        Vela_rekey_policy.Vault_upload_driver.t_ReadLookupObservation

/// The create path: the uniqueness probe runs first, then the guarded insert.
/// A constraint error after the probe is the concurrent-create conflict.
let classify_chunk_create
      (probe: t_ReadOutcome bool)
      (duplicate: bool)
      (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_upload_driver.t_WriteObservation =
  match probe <: t_ReadOutcome bool with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
    <:
    Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
  | ReadOutcome_Rows true ->
    Vela_rekey_policy.Vault_upload_driver.WriteObservation_Existing
    <:
    Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
  | ReadOutcome_Rows false ->
    if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
    then
      match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
      | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
        Vela_rekey_policy.Vault_upload_driver.WriteObservation_Inserted
        <:
        Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
      | WriteOutcome_Applied _ ->
        Vela_rekey_policy.Vault_upload_driver.WriteObservation_Skipped
        <:
        Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
      | _ ->
        match
          (match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
            | WriteOutcome_Failed  ->
              (match duplicate <: bool with
                | true ->
                  Core_models.Option.Option_Some
                  (Vela_rekey_policy.Vault_upload_driver.WriteObservation_Duplicate
                    <:
                    Vela_rekey_policy.Vault_upload_driver.t_WriteObservation)
                  <:
                  Core_models.Option.t_Option
                  Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
                | _ ->
                  Core_models.Option.Option_None
                  <:
                  Core_models.Option.t_Option
                  Vela_rekey_policy.Vault_upload_driver.t_WriteObservation)
            | _ ->
              Core_models.Option.Option_None
              <:
              Core_models.Option.t_Option Vela_rekey_policy.Vault_upload_driver.t_WriteObservation)
          <:
          Core_models.Option.t_Option Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
        with
        | Core_models.Option.Option_Some x -> x
        | Core_models.Option.Option_None  ->
          match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
          | WriteOutcome_Failed  ->
            Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
            <:
            Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
    else
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation

/// The shadow path: the upsert changed its one row, or reported nothing.
let classify_chunk_shadow (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_upload_driver.t_WriteObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Inserted
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Skipped
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
  else
    Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
    <:
    Vela_rekey_policy.Vault_upload_driver.t_WriteObservation

/// The replace path: a version CAS that changed a row updated it.
let classify_chunk_update (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_upload_driver.t_WriteObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Skipped
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Updated
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
      <:
      Vela_rekey_policy.Vault_upload_driver.t_WriteObservation
  else
    Vela_rekey_policy.Vault_upload_driver.WriteObservation_Failed
    <:
    Vela_rekey_policy.Vault_upload_driver.t_WriteObservation

/// `read_inventory`: the rows at the account's epoch.
let classify_inventory
      (outcome: t_ReadOutcome (Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global))
    : Vela_rekey_policy.Rekey_driver.t_InventoryObservation =
  match outcome <: t_ReadOutcome (Alloc.Vec.t_Vec t_InventoryRowView Alloc.Alloc.t_Global) with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Rekey_driver.InventoryObservation_Failed
    <:
    Vela_rekey_policy.Rekey_driver.t_InventoryObservation
  | ReadOutcome_Rows _ ->
    Vela_rekey_policy.Rekey_driver.InventoryObservation_Read
    <:
    Vela_rekey_policy.Rekey_driver.t_InventoryObservation

/// A completeness probe: whether it found a blocking row.
let classify_probe (outcome: t_ReadOutcome bool) : Vela_rekey_policy.Rekey_driver.t_ProbeObservation =
  match outcome <: t_ReadOutcome bool with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Rekey_driver.ProbeObservation_Storage
    <:
    Vela_rekey_policy.Rekey_driver.t_ProbeObservation
  | ReadOutcome_Rows true ->
    Vela_rekey_policy.Rekey_driver.ProbeObservation_Found
    <:
    Vela_rekey_policy.Rekey_driver.t_ProbeObservation
  | ReadOutcome_Rows false ->
    Vela_rekey_policy.Rekey_driver.ProbeObservation_Empty
    <:
    Vela_rekey_policy.Rekey_driver.t_ProbeObservation

/// The freeze CAS.
let classify_freeze_cas (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Rekey_driver.t_CasObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
      Vela_rekey_policy.Rekey_driver.CasObservation_Updated
      <:
      Vela_rekey_policy.Rekey_driver.t_CasObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Rekey_driver.CasObservation_Skipped
      <:
      Vela_rekey_policy.Rekey_driver.t_CasObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Rekey_driver.CasObservation_Storage
      <:
      Vela_rekey_policy.Rekey_driver.t_CasObservation
  else
    Vela_rekey_policy.Rekey_driver.CasObservation_Storage
    <:
    Vela_rekey_policy.Rekey_driver.t_CasObservation

/// A transaction's commit.
let classify_transaction (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Rekey_driver.t_TransactionObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 0
  then
    Vela_rekey_policy.Rekey_driver.TransactionObservation_Failed
    <:
    Vela_rekey_policy.Rekey_driver.t_TransactionObservation
  else
    match
      outcomes.[ (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) -! mk_usize 1
        <:
        usize ]
      <:
      t_WriteOutcome
    with
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Rekey_driver.TransactionObservation_Committed
      <:
      Vela_rekey_policy.Rekey_driver.t_TransactionObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Rekey_driver.TransactionObservation_Failed
      <:
      Vela_rekey_policy.Rekey_driver.t_TransactionObservation

/// The freeze transaction's cleanup.
let classify_cleanup (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Rekey_driver.t_CleanupObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Rekey_driver.CleanupObservation_Done
      <:
      Vela_rekey_policy.Rekey_driver.t_CleanupObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Rekey_driver.CleanupObservation_Storage
      <:
      Vela_rekey_policy.Rekey_driver.t_CleanupObservation
  else
    Vela_rekey_policy.Rekey_driver.CleanupObservation_Storage
    <:
    Vela_rekey_policy.Rekey_driver.t_CleanupObservation

/// The post-commit sweep.
let classify_sweep (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Rekey_driver.t_SweepObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Rekey_driver.SweepObservation_Done
      <:
      Vela_rekey_policy.Rekey_driver.t_SweepObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Rekey_driver.SweepObservation_Failed
      <:
      Vela_rekey_policy.Rekey_driver.t_SweepObservation
  else
    Vela_rekey_policy.Rekey_driver.SweepObservation_Failed
    <:
    Vela_rekey_policy.Rekey_driver.t_SweepObservation

/// The abort/timeout transaction: four statements (the CAS, the chunk delete,
/// the capsule clear and the commit). Rolled back only when the CAS changed the
/// account row and the cleanup and commit followed.
let classify_rollback (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Rekey_driver.t_RollbackObservation =
  if Core_models.Slice.impl__is_empty #t_WriteOutcome outcomes
  then
    Vela_rekey_policy.Rekey_driver.RollbackObservation_Storage
    <:
    Vela_rekey_policy.Rekey_driver.t_RollbackObservation
  else
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Rekey_driver.RollbackObservation_Storage
      <:
      Vela_rekey_policy.Rekey_driver.t_RollbackObservation
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
      Vela_rekey_policy.Rekey_driver.RollbackObservation_Raced
      <:
      Vela_rekey_policy.Rekey_driver.t_RollbackObservation
    | WriteOutcome_Applied _ ->
      if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 4
      then
        match outcomes.[ mk_usize 1 ] <: t_WriteOutcome with
        | WriteOutcome_Failed  ->
          Vela_rekey_policy.Rekey_driver.RollbackObservation_Storage
          <:
          Vela_rekey_policy.Rekey_driver.t_RollbackObservation
        | WriteOutcome_Applied _ ->
          match outcomes.[ mk_usize 2 ] <: t_WriteOutcome with
          | WriteOutcome_Failed  ->
            Vela_rekey_policy.Rekey_driver.RollbackObservation_Storage
            <:
            Vela_rekey_policy.Rekey_driver.t_RollbackObservation
          | WriteOutcome_Applied _ ->
            match outcomes.[ mk_usize 3 ] <: t_WriteOutcome with
            | WriteOutcome_Applied _ ->
              Vela_rekey_policy.Rekey_driver.RollbackObservation_RolledBack
              <:
              Vela_rekey_policy.Rekey_driver.t_RollbackObservation
            | WriteOutcome_Failed  ->
              Vela_rekey_policy.Rekey_driver.RollbackObservation_Storage
              <:
              Vela_rekey_policy.Rekey_driver.t_RollbackObservation
      else
        Vela_rekey_policy.Rekey_driver.RollbackObservation_Storage
        <:
        Vela_rekey_policy.Rekey_driver.t_RollbackObservation

/// `record_shadow_activity`: refreshed only when the guarded refresh matched.
let classify_shadow_activity (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
      Vela_rekey_policy.Vault_upload_driver.ActivityObservation_Refreshed
      <:
      Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_upload_driver.ActivityObservation_Ended
      <:
      Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_upload_driver.ActivityObservation_Failed
      <:
      Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation
  else
    Vela_rekey_policy.Vault_upload_driver.ActivityObservation_Failed
    <:
    Vela_rekey_policy.Vault_upload_driver.t_ActivityObservation

/// `write_capsule`: stored only when the guarded device update matched.
let classify_capsule_write (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Rekey_driver.t_CapsuleObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
      Vela_rekey_policy.Rekey_driver.CapsuleObservation_NotTarget
      <:
      Vela_rekey_policy.Rekey_driver.t_CapsuleObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Rekey_driver.CapsuleObservation_Stored
      <:
      Vela_rekey_policy.Rekey_driver.t_CapsuleObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Rekey_driver.CapsuleObservation_Storage
      <:
      Vela_rekey_policy.Rekey_driver.t_CapsuleObservation
  else
    Vela_rekey_policy.Rekey_driver.CapsuleObservation_Storage
    <:
    Vela_rekey_policy.Rekey_driver.t_CapsuleObservation

/// `inspect_pending`: a missing row, a pending epoch, or a replay.
let classify_pending (outcome: t_ReadOutcome (Core_models.Option.t_Option t_PendingRowView))
    : Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation =
  match outcome <: t_ReadOutcome (Core_models.Option.t_Option t_PendingRowView) with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Vault_mutation_driver.PendingObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation
  | ReadOutcome_Rows (Core_models.Option.Option_None ) ->
    Vela_rekey_policy.Vault_mutation_driver.PendingObservation_Missing
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation
  | _ ->
    match
      (match outcome <: t_ReadOutcome (Core_models.Option.t_Option t_PendingRowView) with
        | ReadOutcome_Rows (Core_models.Option.Option_Some row) ->
          (match Core_models.Option.impl__is_some #i64 row.f_epoch <: bool with
            | true ->
              Core_models.Option.Option_Some
              (Vela_rekey_policy.Vault_mutation_driver.PendingObservation_Pending
                <:
                Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation)
              <:
              Core_models.Option.t_Option
              Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation
            | _ ->
              Core_models.Option.Option_None
              <:
              Core_models.Option.t_Option
              Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation)
        | _ ->
          Core_models.Option.Option_None
          <:
          Core_models.Option.t_Option Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation)
      <:
      Core_models.Option.t_Option Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation
    with
    | Core_models.Option.Option_Some x -> x
    | Core_models.Option.Option_None  ->
      match outcome <: t_ReadOutcome (Core_models.Option.t_Option t_PendingRowView) with
      | ReadOutcome_Rows (Core_models.Option.Option_Some _) ->
        Vela_rekey_policy.Vault_mutation_driver.PendingObservation_Replay
        <:
        Vela_rekey_policy.Vault_mutation_driver.t_PendingObservation

/// `acknowledge`: cleared only when the guarded clear matched the epoch.
let classify_ack (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_mutation_driver.t_AckObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
      Vela_rekey_policy.Vault_mutation_driver.AckObservation_Cleared
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_AckObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_mutation_driver.AckObservation_Missed
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_AckObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_mutation_driver.AckObservation_Storage
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_AckObservation
  else
    Vela_rekey_policy.Vault_mutation_driver.AckObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_AckObservation

/// `attest`: attested only when the guarded update matched the live device.
let classify_attest (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
      Vela_rekey_policy.Vault_mutation_driver.AttestObservation_Attested
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_mutation_driver.AttestObservation_Missing
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_mutation_driver.AttestObservation_Storage
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation
  else
    Vela_rekey_policy.Vault_mutation_driver.AttestObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_AttestObservation

/// `write_floor`: the one durable store write.
let classify_schema_write (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_mutation_driver.SchemaWriteObservation_Written
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_mutation_driver.SchemaWriteObservation_Storage
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation
  else
    Vela_rekey_policy.Vault_mutation_driver.SchemaWriteObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_SchemaWriteObservation

/// The ORAM create path: the uniqueness probe, then the guarded insert.
let classify_oram_create (probe: t_ReadOutcome bool) (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation =
  match probe <: t_ReadOutcome bool with
  | ReadOutcome_Failed  ->
    Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
  | ReadOutcome_Rows true ->
    Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Existing
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
  | ReadOutcome_Rows false ->
    if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
    then
      match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
      | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 1) ->
        Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Written
        <:
        Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
      | WriteOutcome_Applied _ ->
        Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Skipped
        <:
        Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
      | WriteOutcome_Failed  ->
        Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Storage
        <:
        Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
    else
      Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Storage
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation

/// The ORAM replace path: a version CAS on the bucket row.
let classify_oram_update (outcomes: t_Slice t_WriteOutcome)
    : Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation =
  if (Core_models.Slice.impl__len #t_WriteOutcome outcomes <: usize) =. mk_usize 1
  then
    match outcomes.[ mk_usize 0 ] <: t_WriteOutcome with
    | WriteOutcome_Applied (Rust_primitives.Integers.MkInt 0) ->
      Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Skipped
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
    | WriteOutcome_Applied _ ->
      Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Written
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
    | WriteOutcome_Failed  ->
      Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Storage
      <:
      Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
  else
    Vela_rekey_policy.Vault_mutation_driver.BucketObservation_Storage
    <:
    Vela_rekey_policy.Vault_mutation_driver.t_BucketObservation
