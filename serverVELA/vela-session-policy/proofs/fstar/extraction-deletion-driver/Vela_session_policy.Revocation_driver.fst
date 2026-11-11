module Vela_session_policy.Revocation_driver
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// The observations that decide whether an authenticated request proceeds.
/// The middleware reads them in the same order it historically did.
type t_AdmissionObservation = {
  f_jti_revoked:bool;
  f_device_revoked:bool;
  f_account_present:bool;
  f_device_row_active:bool;
  f_device_scoped:bool
}

/// Why an authenticated request was refused.
type t_AdmissionRefusal =
  | AdmissionRefusal_JtiRevoked : t_AdmissionRefusal
  | AdmissionRefusal_DeviceRevoked : t_AdmissionRefusal
  | AdmissionRefusal_AccountAbsent : t_AdmissionRefusal
  | AdmissionRefusal_DeviceRowRevoked : t_AdmissionRefusal

type t_AdmissionDecision =
  | AdmissionDecision_Admit : t_AdmissionDecision
  | AdmissionDecision_Reject : t_AdmissionRefusal -> t_AdmissionDecision

let admission_is_authorized (o: t_AdmissionObservation) : bool =
  ~.o.f_jti_revoked && ~.o.f_device_revoked && o.f_account_present &&
  (~.o.f_device_scoped || o.f_device_row_active)

/// The independent, historical-precedence specification of the admission
/// decision: a JTI marker wins over a device sentinel, which wins over account
/// absence, which wins over the durable device-row guard.
let admission_decision_matches_spec (o: t_AdmissionObservation) (decision: t_AdmissionDecision)
    : bool =
  match decision <: t_AdmissionDecision with
  | AdmissionDecision_Admit  -> admission_is_authorized o
  | AdmissionDecision_Reject refusal ->
    match refusal <: t_AdmissionRefusal with
    | AdmissionRefusal_JtiRevoked  -> o.f_jti_revoked
    | AdmissionRefusal_DeviceRevoked  -> ~.o.f_jti_revoked && o.f_device_revoked
    | AdmissionRefusal_AccountAbsent  ->
      ~.o.f_jti_revoked && ~.o.f_device_revoked && ~.o.f_account_present
    | AdmissionRefusal_DeviceRowRevoked  ->
      ~.o.f_jti_revoked && ~.o.f_device_revoked && o.f_account_present && o.f_device_scoped &&
      ~.o.f_device_row_active

let plan_admission (observation: t_AdmissionObservation)
    : Prims.Pure t_AdmissionDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_AdmissionDecision = decision in
          admission_decision_matches_spec observation decision) =
  if observation.f_jti_revoked
  then
    AdmissionDecision_Reject (AdmissionRefusal_JtiRevoked <: t_AdmissionRefusal)
    <:
    t_AdmissionDecision
  else
    if observation.f_device_revoked
    then
      AdmissionDecision_Reject (AdmissionRefusal_DeviceRevoked <: t_AdmissionRefusal)
      <:
      t_AdmissionDecision
    else
      if ~.observation.f_account_present
      then
        AdmissionDecision_Reject (AdmissionRefusal_AccountAbsent <: t_AdmissionRefusal)
        <:
        t_AdmissionDecision
      else
        if observation.f_device_scoped && ~.observation.f_device_row_active
        then
          AdmissionDecision_Reject (AdmissionRefusal_DeviceRowRevoked <: t_AdmissionRefusal)
          <:
          t_AdmissionDecision
        else AdmissionDecision_Admit <: t_AdmissionDecision
