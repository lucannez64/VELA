module Vela_crypto.Signing
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

/// ML-DSA-87 public-key length.
let v_ML_DSA_VK_LEN: usize = mk_usize 2592

/// ML-DSA-87 signature length (as produced by fips204 v0.4.x).
let v_ML_DSA_SIG_LEN: usize = mk_usize 4627

/// Ed25519 public-key length.
let v_ED25519_VK_LEN: usize = mk_usize 32

/// Ed25519 signature length.
let v_ED25519_SIG_LEN: usize = mk_usize 64

/// Total hybrid verifying-key wire length.
let v_HYBRID_VK_LEN: usize = v_ML_DSA_VK_LEN +! v_ED25519_VK_LEN

/// Total hybrid signature wire length.
let v_HYBRID_SIG_LEN: usize = v_ML_DSA_SIG_LEN +! v_ED25519_SIG_LEN

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
