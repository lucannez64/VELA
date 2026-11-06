module Vela_session_policy.Challenge
#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"
open FStar.Mul
open Core_models

/// The decision after the atomic challenge take.
type t_ChallengeConsumption =
  | ChallengeConsumption_Accepted : t_ChallengeConsumption
  | ChallengeConsumption_Missing : t_ChallengeConsumption
  | ChallengeConsumption_WrongPurpose : t_ChallengeConsumption
