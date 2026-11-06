module Vela_session_policy
#set-options "--fuel 0 --ifuel 1 --z3rlimit 100"
open FStar.Mul
open Core_models

let v_TOKEN_LIFETIME_SECS: i64 = mk_i64 15 *! mk_i64 60

let v_DEVICE_HARD_CAP_SECS: i64 = (mk_i64 8 *! mk_i64 60 <: i64) *! mk_i64 60

let v_RENEWAL_WINDOW_SECS: i64 = mk_i64 5 *! mk_i64 60

let v_INITIAL_EPOCH: i64 = mk_i64 1

type t_CapabilityScope =
  | CapabilityScope_Device : t_CapabilityScope
  | CapabilityScope_WebSession : t_CapabilityScope

type t_ScopeClaim =
  | ScopeClaim_MissingLegacy : t_ScopeClaim
  | ScopeClaim_Device : t_ScopeClaim
  | ScopeClaim_WebSession : t_ScopeClaim
  | ScopeClaim_Unknown : t_ScopeClaim

type t_ScopeDecision =
  | ScopeDecision_Accept : t_CapabilityScope -> t_ScopeDecision
  | ScopeDecision_Reject : t_ScopeDecision

let scope_decision_matches_spec (claim: t_ScopeClaim) (decision: t_ScopeDecision) : bool =
  match claim, decision <: (t_ScopeClaim & t_ScopeDecision) with
  | ScopeClaim_MissingLegacy , ScopeDecision_Accept (CapabilityScope_Device )
  | ScopeClaim_Device , ScopeDecision_Accept (CapabilityScope_Device )
  | ScopeClaim_WebSession , ScopeDecision_Accept (CapabilityScope_WebSession )
  | ScopeClaim_Unknown , ScopeDecision_Reject  -> true
  | _ -> false

/// Parse the authenticated scope claim. Missing scope retains the bounded
/// legacy-device behavior; an explicit unknown value fails closed.
let parse_scope_claim (claim: t_ScopeClaim)
    : Prims.Pure t_ScopeDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_ScopeDecision = decision in
          scope_decision_matches_spec claim decision) =
  match claim <: t_ScopeClaim with
  | ScopeClaim_MissingLegacy
  | ScopeClaim_Device  ->
    ScopeDecision_Accept (CapabilityScope_Device <: t_CapabilityScope) <: t_ScopeDecision
  | ScopeClaim_WebSession  ->
    ScopeDecision_Accept (CapabilityScope_WebSession <: t_CapabilityScope) <: t_ScopeDecision
  | ScopeClaim_Unknown  -> ScopeDecision_Reject <: t_ScopeDecision

type t_SessionPhase =
  | SessionPhase_Pending : t_SessionPhase
  | SessionPhase_Granted : t_SessionPhase
  | SessionPhase_Revoked : t_SessionPhase
  | SessionPhase_Expired : t_SessionPhase

type t_SessionMode =
  | SessionMode_ReadOnly : t_SessionMode
  | SessionMode_ReadWrite : t_SessionMode

type t_GrantFacts = {
  f_phase:t_SessionPhase;
  f_mode:t_SessionMode;
  f_approver_matches:bool;
  f_nonce_matches:bool;
  f_has_web_vk:bool;
  f_declared_epoch:i64
}

type t_GrantPermit = {
  f_mode:t_SessionMode;
  f_epoch:i64
}

type t_GrantDecision =
  | GrantDecision_Grant : t_GrantPermit -> t_GrantDecision
  | GrantDecision_Reject : t_GrantDecision

let grant_is_authorized (facts: t_GrantFacts) : bool =
  (match facts.f_phase <: t_SessionPhase with
    | SessionPhase_Pending  -> true
    | _ -> false) &&
  facts.f_approver_matches &&
  facts.f_nonce_matches &&
  facts.f_declared_epoch >=. v_INITIAL_EPOCH &&
  ((match facts.f_mode <: t_SessionMode with
    | SessionMode_ReadOnly  -> true
    | _ -> false) ||
  facts.f_has_web_vk)

type t_WebTokenFacts = {
  f_phase:t_SessionPhase;
  f_mode:t_SessionMode;
  f_approver_bound:bool;
  f_nonce_bound:bool;
  f_challenge_consumed:bool;
  f_signature_valid:bool
}

/// Decoded observations from the session row and authenticated grant request.
/// UUID parsing, nonce comparison and row loading remain caller obligations;
/// account equality and nonce-length enforcement are computed here.
type t_GrantObservation = {
  f_phase:t_SessionPhase;
  f_mode:t_SessionMode;
  f_approver_user:Core_models.Option.t_Option u128;
  f_authenticated_user:u128;
  f_nonce_length:usize;
  f_nonce_equal:bool;
  f_has_web_vk:bool;
  f_declared_epoch:i64
}

let observed_approver_matches (expected: Core_models.Option.t_Option u128) (actual: u128) : bool =
  match expected <: Core_models.Option.t_Option u128 with
  | Core_models.Option.Option_Some user -> user =. actual
  | Core_models.Option.Option_None  -> false

let observed_users_match (user approver: Core_models.Option.t_Option u128) : bool =
  match user, approver <: (Core_models.Option.t_Option u128 & Core_models.Option.t_Option u128) with
  | Core_models.Option.Option_Some user, Core_models.Option.Option_Some approver -> user =. approver
  | _ -> false

/// Observations after the actual challenge take and signature verification.
/// Absent accounts never establish a binding, including the (None, None) case.
type t_WebTokenObservation = {
  f_phase:t_SessionPhase;
  f_mode:t_SessionMode;
  f_granted_user:Core_models.Option.t_Option u128;
  f_approver_user:Core_models.Option.t_Option u128;
  f_nonce_present:bool;
  f_challenge_consumed:bool;
  f_signature_valid:bool
}

type t_TokenClaims = {
  f_scope:t_CapabilityScope;
  f_key_epoch:Core_models.Option.t_Option i64;
  f_expires_at:i64;
  f_hard_cap:i64
}

/// The only value the production signer accepts. Its fields are private so
/// server code cannot bypass the verified constructors.
type t_TokenPlan = {
  f_scope:t_CapabilityScope;
  f_key_epoch:Core_models.Option.t_Option i64;
  f_expires_at:i64;
  f_hard_cap:i64
}

let impl_TokenPlan__claims (self: t_TokenPlan) : t_TokenClaims =
  {
    f_scope = self.f_scope;
    f_key_epoch = self.f_key_epoch;
    f_expires_at = self.f_expires_at;
    f_hard_cap = self.f_hard_cap
  }
  <:
  t_TokenClaims

type t_TokenDecision =
  | TokenDecision_Issue : t_TokenPlan -> t_TokenDecision
  | TokenDecision_Reject : t_TokenDecision

type t_RenewalDecision =
  | RenewalDecision_Renew : t_TokenPlan -> t_RenewalDecision
  | RenewalDecision_Keep : t_RenewalDecision
  | RenewalDecision_Reject : t_RenewalDecision

let add_lifetime_without_overflow (now: i64) : i64 =
  if now >. (Core_models.Num.impl_i64__MAX -! v_TOKEN_LIFETIME_SECS <: i64)
  then Core_models.Num.impl_i64__MAX
  else now +! v_TOKEN_LIFETIME_SECS

let add_device_cap_without_overflow (now: i64) : Core_models.Option.t_Option i64 =
  if now >. (Core_models.Num.impl_i64__MAX -! v_DEVICE_HARD_CAP_SECS <: i64)
  then Core_models.Option.Option_None <: Core_models.Option.t_Option i64
  else
    Core_models.Option.Option_Some (now +! v_DEVICE_HARD_CAP_SECS)
    <:
    Core_models.Option.t_Option i64

let bounded_expiry (now hard_cap: i64) : i64 =
  let normal_expiry:i64 = add_lifetime_without_overflow now in
  if normal_expiry <. hard_cap then normal_expiry else hard_cap

let claims_shape_is_valid (claims: t_TokenClaims) : bool =
  match claims.f_scope <: t_CapabilityScope with
  | CapabilityScope_Device  -> Core_models.Option.impl__is_none #i64 claims.f_key_epoch
  | CapabilityScope_WebSession  ->
    match claims.f_key_epoch <: Core_models.Option.t_Option i64 with
    | Core_models.Option.Option_Some epoch -> epoch >=. v_INITIAL_EPOCH
    | Core_models.Option.Option_None  -> true

let token_plan_is_valid (plan: t_TokenPlan) (now: i64) : bool =
  let claims:t_TokenClaims = impl_TokenPlan__claims plan in
  now >=. mk_i64 0 && claims_shape_is_valid claims && claims.f_hard_cap >. now &&
  claims.f_expires_at >. now &&
  claims.f_expires_at <=. claims.f_hard_cap

let device_decision_matches_spec
      (now: i64)
      (requested_hard_cap: Core_models.Option.t_Option i64)
      (decision: t_TokenDecision)
    : bool =
  match decision <: t_TokenDecision with
  | TokenDecision_Issue plan ->
    token_plan_is_valid plan now &&
    (match plan.f_scope <: t_CapabilityScope with
      | CapabilityScope_Device  -> true
      | _ -> false) &&
    Core_models.Option.impl__is_none #i64 plan.f_key_epoch &&
    plan.f_expires_at =. (bounded_expiry now plan.f_hard_cap <: i64) &&
    (match requested_hard_cap <: Core_models.Option.t_Option i64 with
      | Core_models.Option.Option_Some cap -> plan.f_hard_cap =. cap
      | Core_models.Option.Option_None  ->
        (add_device_cap_without_overflow now <: Core_models.Option.t_Option i64) =.
        (Core_models.Option.Option_Some plan.f_hard_cap <: Core_models.Option.t_Option i64))
  | TokenDecision_Reject  ->
    now <. mk_i64 0 ||
    (match requested_hard_cap <: Core_models.Option.t_Option i64 with
      | Core_models.Option.Option_Some cap -> cap <=. now
      | Core_models.Option.Option_None  ->
        Core_models.Option.impl__is_none #i64
          (add_device_cap_without_overflow now <: Core_models.Option.t_Option i64))

let plan_device_token (now: i64) (requested_hard_cap: Core_models.Option.t_Option i64)
    : Prims.Pure t_TokenDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_TokenDecision = decision in
          device_decision_matches_spec now requested_hard_cap decision) =
  if now <. mk_i64 0
  then TokenDecision_Reject <: t_TokenDecision
  else
    match
      (match requested_hard_cap <: Core_models.Option.t_Option i64 with
        | Core_models.Option.Option_Some cap ->
          (match cap >. now <: bool with
            | true -> Core_models.Option.Option_Some cap <: Core_models.Option.t_Option i64
            | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option i64)
        | _ -> Core_models.Option.Option_None <: Core_models.Option.t_Option i64)
      <:
      Core_models.Option.t_Option i64
    with
    | Core_models.Option.Option_Some x ->
      let hard_cap:i64 = x in
      TokenDecision_Issue
      ({
          f_scope = CapabilityScope_Device <: t_CapabilityScope;
          f_key_epoch = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
          f_expires_at = bounded_expiry now hard_cap;
          f_hard_cap = hard_cap
        }
        <:
        t_TokenPlan)
      <:
      t_TokenDecision
    | Core_models.Option.Option_None  ->
      match requested_hard_cap <: Core_models.Option.t_Option i64 with
      | Core_models.Option.Option_Some _ -> TokenDecision_Reject <: t_TokenDecision
      | Core_models.Option.Option_None  ->
        match add_device_cap_without_overflow now <: Core_models.Option.t_Option i64 with
        | Core_models.Option.Option_Some cap ->
          let hard_cap:i64 = cap in
          TokenDecision_Issue
          ({
              f_scope = CapabilityScope_Device <: t_CapabilityScope;
              f_key_epoch = Core_models.Option.Option_None <: Core_models.Option.t_Option i64;
              f_expires_at = bounded_expiry now hard_cap;
              f_hard_cap = hard_cap
            }
            <:
            t_TokenPlan)
          <:
          t_TokenDecision
        | Core_models.Option.Option_None  -> TokenDecision_Reject <: t_TokenDecision

let web_exchange_is_authorized (facts: t_WebTokenFacts) (now hard_cap epoch: i64) : bool =
  now >=. mk_i64 0 && hard_cap >. now && epoch >=. v_INITIAL_EPOCH &&
  (match facts.f_phase <: t_SessionPhase with
    | SessionPhase_Granted  -> true
    | _ -> false) &&
  (match facts.f_mode <: t_SessionMode with
    | SessionMode_ReadWrite  -> true
    | _ -> false) &&
  facts.f_approver_bound &&
  facts.f_nonce_bound &&
  facts.f_challenge_consumed &&
  facts.f_signature_valid

let web_decision_matches_spec
      (facts: t_WebTokenFacts)
      (now hard_cap epoch: i64)
      (decision: t_TokenDecision)
    : bool =
  match decision <: t_TokenDecision with
  | TokenDecision_Issue plan ->
    web_exchange_is_authorized facts now hard_cap epoch && token_plan_is_valid plan now &&
    (match plan.f_scope <: t_CapabilityScope with
      | CapabilityScope_WebSession  -> true
      | _ -> false) &&
    plan.f_key_epoch =. (Core_models.Option.Option_Some epoch <: Core_models.Option.t_Option i64) &&
    plan.f_hard_cap =. hard_cap &&
    plan.f_expires_at =. (bounded_expiry now hard_cap <: i64)
  | TokenDecision_Reject  -> ~.(web_exchange_is_authorized facts now hard_cap epoch <: bool)

let plan_web_session_token (facts: t_WebTokenFacts) (now hard_cap epoch: i64)
    : Prims.Pure t_TokenDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_TokenDecision = decision in
          web_decision_matches_spec facts now hard_cap epoch decision) =
  if ~.(web_exchange_is_authorized facts now hard_cap epoch <: bool)
  then TokenDecision_Reject <: t_TokenDecision
  else
    TokenDecision_Issue
    ({
        f_scope = CapabilityScope_WebSession <: t_CapabilityScope;
        f_key_epoch = Core_models.Option.Option_Some epoch <: Core_models.Option.t_Option i64;
        f_expires_at = bounded_expiry now hard_cap;
        f_hard_cap = hard_cap
      }
      <:
      t_TokenPlan)
    <:
    t_TokenDecision

let renewal_input_is_valid (claims: t_TokenClaims) (now: i64) : bool =
  now >=. mk_i64 0 && claims_shape_is_valid claims && claims.f_hard_cap >. now &&
  claims.f_expires_at >. now &&
  claims.f_expires_at <=. claims.f_hard_cap

type t_RouteClass =
  | RouteClass_Vault : t_RouteClass
  | RouteClass_PermanentAccount : t_RouteClass

type t_RoutePermit = { f_class:t_RouteClass }

type t_RouteDecision =
  | RouteDecision_Allow : t_RoutePermit -> t_RouteDecision
  | RouteDecision_Reject : t_RouteDecision

let v_DEFAULT_WEB_TTL_SECS: i64 = mk_i64 30 *! mk_i64 60

let v_MIN_WEB_TTL_SECS: i64 = mk_i64 60

let v_MAX_WEB_TTL_SECS: i64 = (mk_i64 24 *! mk_i64 60 <: i64) *! mk_i64 60

/// Clamp a browser-requested TTL to [60 s, 24 h], defaulting to 30 min.
/// Written with comparisons only (no min/max) so hax extracts a decision
/// that F* discharges without i64 op encoding.
let clamp_web_ttl (requested: Core_models.Option.t_Option i64) : i64 =
  match requested <: Core_models.Option.t_Option i64 with
  | Core_models.Option.Option_None  -> v_DEFAULT_WEB_TTL_SECS
  | Core_models.Option.Option_Some r ->
    let requested:i64 = r in
    if requested <. v_MIN_WEB_TTL_SECS
    then v_MIN_WEB_TTL_SECS
    else if requested >. v_MAX_WEB_TTL_SECS then v_MAX_WEB_TTL_SECS else requested

/// A granted session past its expiry is terminal for admission purposes.
/// `now` and `expires_at` are unix seconds. A missing expiry never expires
/// here — pending-session reaping is a separate mechanism.
let web_session_expired (now: i64) (expires_at: Core_models.Option.t_Option i64) : bool =
  match expires_at <: Core_models.Option.t_Option i64 with
  | Core_models.Option.Option_Some expires_at -> now >=. expires_at
  | Core_models.Option.Option_None  -> false

let ttl_clamp_can_be_violated (requested: Core_models.Option.t_Option i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let clamped:i64 = clamp_web_ttl requested in
  clamped <. v_MIN_WEB_TTL_SECS || clamped >. v_MAX_WEB_TTL_SECS

let route_is_authorized (scope: t_CapabilityScope) (v_class: t_RouteClass) : bool =
  (match scope <: t_CapabilityScope with
    | CapabilityScope_Device  -> true
    | _ -> false) ||
  (match v_class <: t_RouteClass with
    | RouteClass_Vault  -> true
    | _ -> false)

/// Direct theorem used by the F* gate: a terminal web session cannot issue a
/// token regardless of the other presented facts.
let terminal_session_issues_token (phase: t_SessionPhase) (now hard_cap epoch: i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  if
    ~.(match phase <: t_SessionPhase with
      | SessionPhase_Revoked  -> true
      | _ -> false) &&
    ~.(match phase <: t_SessionPhase with
      | SessionPhase_Expired  -> true
      | _ -> false)
  then false
  else
    match
      plan_web_session_token ({
            f_phase = phase;
            f_mode = SessionMode_ReadWrite <: t_SessionMode;
            f_approver_bound = true;
            f_nonce_bound = true;
            f_challenge_consumed = true;
            f_signature_valid = true
          }
          <:
          t_WebTokenFacts)
        now
        hard_cap
        epoch
      <:
      t_TokenDecision
    with
    | TokenDecision_Issue _ -> true
    | _ -> false

let same_session_mode (a b: t_SessionMode) : bool =
  match a, b <: (t_SessionMode & t_SessionMode) with
  | SessionMode_ReadOnly , SessionMode_ReadOnly
  | SessionMode_ReadWrite , SessionMode_ReadWrite  -> true
  | _ -> false

let grant_decision_matches_spec (facts: t_GrantFacts) (decision: t_GrantDecision) : bool =
  match decision <: t_GrantDecision with
  | GrantDecision_Grant permit ->
    grant_is_authorized facts && same_session_mode permit.f_mode facts.f_mode &&
    permit.f_epoch =. facts.f_declared_epoch
  | GrantDecision_Reject  -> ~.(grant_is_authorized facts <: bool)

/// Produce the values consumed by the atomic pending/account-epoch grant CAS.
let plan_grant (facts: t_GrantFacts)
    : Prims.Pure t_GrantDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_GrantDecision = decision in
          grant_decision_matches_spec facts decision) =
  if grant_is_authorized facts
  then
    GrantDecision_Grant
    ({ f_mode = facts.f_mode; f_epoch = facts.f_declared_epoch } <: t_GrantPermit)
    <:
    t_GrantDecision
  else GrantDecision_Reject <: t_GrantDecision

let same_capability_scope (a b: t_CapabilityScope) : bool =
  match a, b <: (t_CapabilityScope & t_CapabilityScope) with
  | CapabilityScope_Device , CapabilityScope_Device
  | CapabilityScope_WebSession , CapabilityScope_WebSession  -> true
  | _ -> false

let renewal_decision_matches_spec (claims: t_TokenClaims) (now: i64) (decision: t_RenewalDecision)
    : bool =
  if ~.(renewal_input_is_valid claims now <: bool)
  then
    match decision <: t_RenewalDecision with
    | RenewalDecision_Reject  -> true
    | _ -> false
  else
    let inside_window:bool = now >=. (claims.f_expires_at -! v_RENEWAL_WINDOW_SECS <: i64) in
    if inside_window && claims.f_expires_at <. claims.f_hard_cap
    then
      match decision <: t_RenewalDecision with
      | RenewalDecision_Renew plan ->
        token_plan_is_valid plan now && same_capability_scope plan.f_scope claims.f_scope &&
        plan.f_key_epoch =. claims.f_key_epoch &&
        plan.f_hard_cap =. claims.f_hard_cap &&
        plan.f_expires_at =. (bounded_expiry now claims.f_hard_cap <: i64)
      | _ -> false
    else
      match decision <: t_RenewalDecision with
      | RenewalDecision_Keep  -> true
      | _ -> false

/// Renew only a live, structurally valid token, preserving its exact scope,
/// epoch binding, and hard cap.
let plan_renewal (claims: t_TokenClaims) (now: i64)
    : Prims.Pure t_RenewalDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_RenewalDecision = decision in
          renewal_decision_matches_spec claims now decision) =
  if ~.(renewal_input_is_valid claims now <: bool)
  then RenewalDecision_Reject <: t_RenewalDecision
  else
    if
      now <. (claims.f_expires_at -! v_RENEWAL_WINDOW_SECS <: i64) ||
      claims.f_expires_at =. claims.f_hard_cap
    then RenewalDecision_Keep <: t_RenewalDecision
    else
      RenewalDecision_Renew
      ({
          f_scope = claims.f_scope;
          f_key_epoch = claims.f_key_epoch;
          f_expires_at = bounded_expiry now claims.f_hard_cap;
          f_hard_cap = claims.f_hard_cap
        }
        <:
        t_TokenPlan)
      <:
      t_RenewalDecision

/// Direct theorem used by the F* gate: renewal never changes the authority
/// class or epoch carried by an accepted input token.
let renewal_escalates_authority (claims: t_TokenClaims) (now: i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  match plan_renewal claims now <: t_RenewalDecision with
  | RenewalDecision_Renew plan ->
    ~.(same_capability_scope plan.f_scope claims.f_scope <: bool) ||
    plan.f_key_epoch <>. claims.f_key_epoch
  | RenewalDecision_Keep  | RenewalDecision_Reject  -> false

let same_route_class (a b: t_RouteClass) : bool =
  match a, b <: (t_RouteClass & t_RouteClass) with
  | RouteClass_Vault , RouteClass_Vault
  | RouteClass_PermanentAccount , RouteClass_PermanentAccount  -> true
  | _ -> false

let route_decision_matches_spec
      (scope: t_CapabilityScope)
      (v_class: t_RouteClass)
      (decision: t_RouteDecision)
    : bool =
  match decision <: t_RouteDecision with
  | RouteDecision_Allow permit ->
    route_is_authorized scope v_class && same_route_class permit.f_class v_class
  | RouteDecision_Reject  -> ~.(route_is_authorized scope v_class <: bool)

let authorize_route (scope: t_CapabilityScope) (v_class: t_RouteClass)
    : Prims.Pure t_RouteDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_RouteDecision = decision in
          route_decision_matches_spec scope v_class decision) =
  if route_is_authorized scope v_class
  then RouteDecision_Allow ({ f_class = v_class } <: t_RoutePermit) <: t_RouteDecision
  else RouteDecision_Reject <: t_RouteDecision

let same_session_phase (a b: t_SessionPhase) : bool =
  match a, b <: (t_SessionPhase & t_SessionPhase) with
  | SessionPhase_Pending , SessionPhase_Pending
  | SessionPhase_Granted , SessionPhase_Granted
  | SessionPhase_Revoked , SessionPhase_Revoked
  | SessionPhase_Expired , SessionPhase_Expired  -> true
  | _ -> false

let grant_facts_match_observation (o: t_GrantObservation) (f: t_GrantFacts) : bool =
  same_session_phase f.f_phase o.f_phase && same_session_mode f.f_mode o.f_mode &&
  f.f_approver_matches =.
  (observed_approver_matches o.f_approver_user o.f_authenticated_user <: bool) &&
  f.f_nonce_matches =. ((o.f_nonce_length =. mk_usize 32 <: bool) && o.f_nonce_equal) &&
  f.f_has_web_vk =. o.f_has_web_vk &&
  f.f_declared_epoch =. o.f_declared_epoch

let grant_facts (observation: t_GrantObservation)
    : Prims.Pure t_GrantFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_GrantFacts = facts in
          grant_facts_match_observation observation facts) =
  {
    f_phase = observation.f_phase;
    f_mode = observation.f_mode;
    f_approver_matches
    =
    observed_approver_matches observation.f_approver_user observation.f_authenticated_user;
    f_nonce_matches = observation.f_nonce_length =. mk_usize 32 && observation.f_nonce_equal;
    f_has_web_vk = observation.f_has_web_vk;
    f_declared_epoch = observation.f_declared_epoch
  }
  <:
  t_GrantFacts

let web_facts_match_observation (o: t_WebTokenObservation) (f: t_WebTokenFacts) : bool =
  same_session_phase f.f_phase o.f_phase && same_session_mode f.f_mode o.f_mode &&
  f.f_approver_bound =. (observed_users_match o.f_granted_user o.f_approver_user <: bool) &&
  f.f_nonce_bound =. o.f_nonce_present &&
  f.f_challenge_consumed =. o.f_challenge_consumed &&
  f.f_signature_valid =. o.f_signature_valid

let web_token_facts (observation: t_WebTokenObservation)
    : Prims.Pure t_WebTokenFacts
      Prims.l_True
      (ensures
        fun facts ->
          let facts:t_WebTokenFacts = facts in
          web_facts_match_observation observation facts) =
  {
    f_phase = observation.f_phase;
    f_mode = observation.f_mode;
    f_approver_bound = observed_users_match observation.f_granted_user observation.f_approver_user;
    f_nonce_bound = observation.f_nonce_present;
    f_challenge_consumed = observation.f_challenge_consumed;
    f_signature_valid = observation.f_signature_valid
  }
  <:
  t_WebTokenFacts

let plan_observed_grant (observation: t_GrantObservation)
    : Prims.Pure t_GrantDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_GrantDecision = decision in
          grant_decision_matches_spec (grant_facts observation <: t_GrantFacts) decision) =
  plan_grant (grant_facts observation <: t_GrantFacts)

let plan_observed_web_token (observation: t_WebTokenObservation) (now hard_cap epoch: i64)
    : Prims.Pure t_TokenDecision
      Prims.l_True
      (ensures
        fun decision ->
          let decision:t_TokenDecision = decision in
          web_decision_matches_spec (web_token_facts observation <: t_WebTokenFacts)
            now
            hard_cap
            epoch
            decision) =
  plan_web_session_token (web_token_facts observation <: t_WebTokenFacts) now hard_cap epoch

let missing_approver_observation_can_grant (observation: t_GrantObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_GrantObservation =
    {
      observation with
      f_approver_user = Core_models.Option.Option_None <: Core_models.Option.t_Option u128
    }
    <:
    t_GrantObservation
  in
  match plan_observed_grant observation <: t_GrantDecision with
  | GrantDecision_Grant _ -> true
  | _ -> false

let wrong_nonce_length_observation_can_grant (observation: t_GrantObservation)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  if observation.f_nonce_length =. mk_usize 32
  then false
  else
    let observation:t_GrantObservation =
      { observation with f_nonce_equal = true } <: t_GrantObservation
    in
    match plan_observed_grant observation <: t_GrantDecision with
    | GrantDecision_Grant _ -> true
    | _ -> false

let cross_account_observation_can_issue
      (observation: t_WebTokenObservation)
      (user approver: u128)
      (now hard_cap epoch: i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  if user =. approver
  then false
  else
    let observation:t_WebTokenObservation =
      {
        observation with
        f_granted_user = Core_models.Option.Option_Some user <: Core_models.Option.t_Option u128
      }
      <:
      t_WebTokenObservation
    in
    let observation:t_WebTokenObservation =
      {
        observation with
        f_approver_user
        =
        Core_models.Option.Option_Some approver <: Core_models.Option.t_Option u128
      }
      <:
      t_WebTokenObservation
    in
    match plan_observed_web_token observation now hard_cap epoch <: t_TokenDecision with
    | TokenDecision_Issue _ -> true
    | _ -> false

let missing_accounts_observation_can_issue
      (observation: t_WebTokenObservation)
      (now hard_cap epoch: i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_WebTokenObservation =
    {
      observation with
      f_granted_user = Core_models.Option.Option_None <: Core_models.Option.t_Option u128
    }
    <:
    t_WebTokenObservation
  in
  let observation:t_WebTokenObservation =
    {
      observation with
      f_approver_user = Core_models.Option.Option_None <: Core_models.Option.t_Option u128
    }
    <:
    t_WebTokenObservation
  in
  match plan_observed_web_token observation now hard_cap epoch <: t_TokenDecision with
  | TokenDecision_Issue _ -> true
  | _ -> false

let unconsumed_challenge_observation_can_issue
      (observation: t_WebTokenObservation)
      (now hard_cap epoch: i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_WebTokenObservation =
    { observation with f_challenge_consumed = false } <: t_WebTokenObservation
  in
  match plan_observed_web_token observation now hard_cap epoch <: t_TokenDecision with
  | TokenDecision_Issue _ -> true
  | _ -> false

let invalid_signature_observation_can_issue
      (observation: t_WebTokenObservation)
      (now hard_cap epoch: i64)
    : Prims.Pure bool
      Prims.l_True
      (ensures
        fun result ->
          let result:bool = result in
          result =. false) =
  let observation:t_WebTokenObservation =
    { observation with f_signature_valid = false } <: t_WebTokenObservation
  in
  match plan_observed_web_token observation now hard_cap epoch <: t_TokenDecision with
  | TokenDecision_Issue _ -> true
  | _ -> false
