module Vela_crypto.Signing
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// Checked AND-composition gate. Primitive verification results are observations;
/// security of either primitive is a separate trusted assumption.
let hybrid_components_verify (ml_dsa_ok ed25519_ok: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. (ml_dsa_ok && ed25519_ok)) = ml_dsa_ok && ed25519_ok

let invalid_ml_component_can_authenticate (ed25519_ok: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) = hybrid_components_verify false ed25519_ok

let invalid_ed_component_can_authenticate (ml_dsa_ok: bool)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) = hybrid_components_verify ml_dsa_ok false
