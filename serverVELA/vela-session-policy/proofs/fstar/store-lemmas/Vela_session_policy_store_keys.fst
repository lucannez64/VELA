module Vela_session_policy_store_keys

/// O4: the session store key builders are injective and their namespaces are
/// disjoint.
///
/// `src/store.rs` builds every key with `store_key` (`prefix + id`) or
/// `store_key_scoped` (`prefix + scope + ":" + id`) instead of `format!`.
/// hax extracts both helpers into `Vela_session_policy.Store`; the local
/// models in `proofs/fstar/models` define `String::push_str`/`str_concat` as
/// `^`, so the extracted keys are ordinary concatenations here.
///
/// The Rust sources give hypothesis **H**: the last identifier of every
/// two-argument key, and the sole identifier of the `rl:websession:token:`
/// key, contains no `:`. UUIDs, base64 challenges and users are colon-free;
/// an IP may contain `:` (IPv6) but is never the last argument. H is an
/// explicit precondition below, not an assumption; `witness_H_*` shows it is
/// inhabited and fails exactly where expected.
///
/// The 18 key formats are enumerated as `builder`; `prefix_of` is the literal
/// prefix and `key_of` is the key. The main theorems are
/// `key_of_disjoint` / `plan_key_disjoint` (different builders never collide)
/// and the 18 `key_*_injective` lemmas (same builder, same key implies same
/// arguments).

open FStar.Mul
open Core_models
open Vela_session_policy.Store

module S = FStar.String
module L = FStar.List.Tot
module LP = FStar.List.Tot.Properties

type text = Alloc.String.t_String

// ── Character lists, colons and the last separator ─────────────────────────

/// No ':' among the characters.
let rec no_colon (l: list FStar.Char.char) : Tot bool (decreases l) =
  match l with
  | [] -> true
  | c :: rest -> (c <> ':' && no_colon rest)

/// The last ':' in a list, split into the prefix before it and the suffix
/// after it.
let rec last_colon (l: list FStar.Char.char)
  : Tot (option (list FStar.Char.char & list FStar.Char.char)) (decreases l) =
  match l with
  | [] -> None
  | c :: rest ->
    (match last_colon rest with
     | Some (p, s) -> Some (c :: p, s)
     | None -> if c = ':' then Some ([], rest) else None)

let rec last_colon_none (l: list FStar.Char.char)
  : Lemma (requires no_colon l) (ensures last_colon l == None) (decreases l) =
  match l with
  | [] -> ()
  | c :: rest -> last_colon_none rest

let rec last_colon_append (p s: list FStar.Char.char)
  : Lemma (requires no_colon s)
          (ensures last_colon (p @ ':' :: s) == Some (p, s))
          (decreases p) =
  match p with
  | [] -> last_colon_none s
  | c :: rest -> last_colon_append rest s

/// The split at the last ':' is unique when the suffix is colon-free.
let last_colon_unique (p1 s1 p2 s2: list FStar.Char.char)
  : Lemma (requires no_colon s1 /\ no_colon s2 /\
                    p1 @ ':' :: s1 == p2 @ ':' :: s2)
          (ensures p1 == p2 /\ s1 == s2) =
  last_colon_append p1 s1;
  last_colon_append p2 s2

/// A string has no ':' iff its character list does.
let colon_free (s: string) : bool = no_colon (S.list_of_string s)

/// A colon in the middle of any two strings.
let rec no_colon_append_colon (l1 l2: list FStar.Char.char)
  : Lemma (ensures no_colon (l1 @ ':' :: l2) == false) (decreases l1) =
  match l1 with
  | [] -> ()
  | c :: rest -> no_colon_append_colon rest l2

// ── String concatenation facts ─────────────────────────────────────────────

let list_of_string_injective (a b: string)
  : Lemma (requires S.list_of_string a == S.list_of_string b) (ensures a == b) =
  S.string_of_list_of_string a;
  S.string_of_list_of_string b

let concat_empty_l (s: string) : Lemma (("" ^ s) == s) =
  S.list_of_concat "" s;
  LP.append_nil_l (S.list_of_string s);
  S.string_of_list_of_string ("" ^ s);
  S.string_of_list_of_string s

let concat_assoc (a b c: string) : Lemma (((a ^ b) ^ c) == (a ^ (b ^ c))) =
  S.list_of_concat a b;
  S.list_of_concat (a ^ b) c;
  S.list_of_concat b c;
  S.list_of_concat a (b ^ c);
  LP.append_assoc (S.list_of_string a) (S.list_of_string b) (S.list_of_string c);
  S.string_of_list_of_string ((a ^ b) ^ c);
  S.string_of_list_of_string (a ^ (b ^ c))

/// `scope ^ ":" ^ id` as characters.
let list_of_scoped (scope id: string)
  : Lemma (S.list_of_string ((scope ^ ":") ^ id) ==
           (S.list_of_string scope @ [':']) @ S.list_of_string id) =
  S.list_of_concat scope ":";
  S.list_of_concat (scope ^ ":") id

let colon_free_append_colon (a b: string)
  : Lemma (colon_free (a ^ (":" ^ b)) == false) =
  S.list_of_concat a (":" ^ b);
  S.list_of_concat ":" b;
  no_colon_append_colon (S.list_of_string a) (S.list_of_string b)

/// The last character of the prefix decides.
let rec index_append_l (#a: Type) (l1 l2: list a)
  (i: nat{i < L.length (l1 @ l2)})
  : Lemma (requires i < L.length l1)
          (ensures (L.index (l1 @ l2) i == L.index l1 i))
          (decreases l1) =
  match l1 with
  | [] -> ()
  | h :: tl -> if i = 0 then () else index_append_l tl l2 (i - 1)

let prefix_differs (p q: string) (i: nat) (s t: string)
  : Lemma (requires i < S.length p /\ i < S.length q /\
                    S.index p i <> S.index q i)
          (ensures (p ^ s) <> (q ^ t)) =
  let lp = S.list_of_string p in
  let lq = S.list_of_string q in
  if p ^ s = q ^ t then begin
    S.list_of_concat p s;
    S.list_of_concat q t;
    S.index_list_of_string p i;
    S.index_list_of_string q i;
    LP.append_length lp (S.list_of_string s);
    LP.append_length lq (S.list_of_string t);
    index_append_l lp (S.list_of_string s) i;
    index_append_l lq (S.list_of_string t) i;
    list_of_string_injective (p ^ s) (q ^ t)
  end

// ── The extracted builders compute plain concatenation ─────────────────────

let store_key_eq (p id: string)
  : Lemma (store_key p id == Alloc.String.String (p ^ id)) =
  concat_empty_l p

let store_key_scoped_eq (p scope id: string)
  : Lemma (store_key_scoped p scope id ==
           Alloc.String.String (((p ^ scope) ^ ":") ^ id)) =
  concat_empty_l p

let key1 (p: string) (id: text) : text = store_key p id._0

let key2 (p: string) (scope id: text) : text =
  store_key_scoped p scope._0 id._0

let key1_eq (p: string) (id: text)
  : Lemma (key1 p id == Alloc.String.String (p ^ id._0)) =
  store_key_eq p id._0

let key2_eq (p: string) (scope id: text)
  : Lemma (key2 p scope id ==
           Alloc.String.String (((p ^ scope._0) ^ ":") ^ id._0)) =
  store_key_scoped_eq p scope._0 id._0

/// A fixed prefix and one identifier: injective.
let key1_injective (p: string) (a b: text)
  : Lemma (requires key1 p a == key1 p b) (ensures a == b) =
  key1_eq p a;
  key1_eq p b;
  let Alloc.String.String sa = a in
  let Alloc.String.String sb = b in
  concat_empty_l p;
  S.concat_injective p p sa sb

/// A fixed two-argument prefix: unique split at the last ':' under H.
let key2_injective (p: string) (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 p s1 id1 == key2 p s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_eq p s1 id1;
  key2_eq p s2 id2;
  let Alloc.String.String sc1 = s1 in
  let Alloc.String.String sc2 = s2 in
  let Alloc.String.String i1 = id1 in
  let Alloc.String.String i2 = id2 in
  concat_assoc p sc1 ":";
  concat_assoc p sc2 ":";
  concat_assoc p (sc1 ^ ":") i1;
  concat_assoc p (sc2 ^ ":") i2;
  S.concat_injective p p ((sc1 ^ ":") ^ i1) ((sc2 ^ ":") ^ i2);
  list_of_scoped sc1 i1;
  list_of_scoped sc2 i2;
  LP.append_assoc (S.list_of_string sc1) [':'] (S.list_of_string i1);
  LP.append_assoc (S.list_of_string sc2) [':'] (S.list_of_string i2);
  last_colon_unique (S.list_of_string sc1) (S.list_of_string i1)
                    (S.list_of_string sc2) (S.list_of_string i2);
  S.string_of_list_of_string sc1;
  S.string_of_list_of_string sc2;
  S.string_of_list_of_string i1;
  S.string_of_list_of_string i2

// ── Different prefixes ─────────────────────────────────────────────────────

/// The first differing character of two lists, if any.
let rec first_diff (l1 l2: list FStar.Char.char) : Tot (option nat) (decreases l1) =
  match l1, l2 with
  | [], _ -> None
  | _, [] -> None
  | c1 :: r1, c2 :: r2 ->
    if c1 = c2
    then (match first_diff r1 r2 with
          | Some i -> Some (i + 1)
          | None -> None)
    else Some 0

let rec first_diff_some (l1 l2: list FStar.Char.char) (i: nat)
  : Lemma (requires first_diff l1 l2 == Some i)
          (ensures i < L.length l1 /\ i < L.length l2 /\
                   L.index l1 i <> L.index l2 i)
          (decreases l1) =
  match l1, l2 with
  | [], _ -> ()
  | _, [] -> ()
  | c1 :: r1, c2 :: r2 ->
    if c1 = c2
    then (match first_diff r1 r2 with
          | Some n -> first_diff_some r1 r2 n
          | None -> ())
    else ()

/// The two prefixes differ somewhere, so no suffixes can make the keys equal.
let disjointb (p q: string) : bool =
  Some? (first_diff (S.list_of_string p) (S.list_of_string q))

/// `first_diff` finds the same first difference in either argument order, so
/// `disjointb` is symmetric.
let rec first_diff_sym (l1 l2: list FStar.Char.char)
  : Lemma (ensures Some? (first_diff l1 l2) = Some? (first_diff l2 l1))
          (decreases l1) =
  match l1, l2 with
  | [], _ -> ()
  | _, [] -> ()
  | c1 :: r1, c2 :: r2 ->
    if c1 = c2 then first_diff_sym r1 r2 else ()

let disjointb_sym (p q: string) : Lemma (disjointb p q = disjointb q p) =
  first_diff_sym (S.list_of_string p) (S.list_of_string q)

let disjointb_sound (p q: string) (s t: string)
  : Lemma (requires disjointb p q) (ensures (p ^ s) <> (q ^ t)) =
  match first_diff (S.list_of_string p) (S.list_of_string q) with
  | Some i ->
    first_diff_some (S.list_of_string p) (S.list_of_string q) i;
    S.index_list_of_string p i;
    S.index_list_of_string q i;
    prefix_differs p q i s t
  | None -> ()

// ── The 18 key formats ─────────────────────────────────────────────────────

type builder =
  | BLogout             // jti:revoked:
  | BSentinel           // device:revoked:
  | BChallenge          // challenge:
  | BStreakVerify       // rl:streak:verify:{ip}:{device}
  | BBackoffVerify      // rl:backoff:verify:{ip}:{device}
  | BVerifyFailDev      // rl:verify:fail:dev:{ip}:{device}
  | BDeviceJtis         // device:jtis:{device}
  | BChallengeIp        // rl:challenge:ip:{ip}
  | BRegisterIp         // rl:register:ip:{ip}
  | BVerifyIp           // rl:verify:ip:{ip}
  | BWebStartIp         // rl:websession:start:ip:{ip}
  | BWebTokenIp         // rl:websession:token:ip:{ip}:{session}
  | BWebToken           // rl:websession:token:{session}
  | BWebBackoff         // rl:backoff:websession:token:{ip}:{session}
  | BWebStreak          // rl:streak:websession:token:{ip}:{session}
  | BWebPollIp          // rl:websession:poll:ip:{ip}
  | BWebKeysUser        // rl:websession:keys:user:{user}
  | BTokenIssued        // web_session:token_issued:{session}

/// The arguments a format uses. One-argument formats ignore `ka_scope`,
/// except `rl:verify:ip:`, whose plan reads the IP from the shared
/// `(ip, device)` tuple (`plan_login_limits`).
type key_args = {
  ka_scope: text;
  ka_id: text;
}

let prefix_of (b: builder) : string =
  match b with
  | BLogout -> "jti:revoked:"
  | BSentinel -> "device:revoked:"
  | BChallenge -> "challenge:"
  | BStreakVerify -> "rl:streak:verify:"
  | BBackoffVerify -> "rl:backoff:verify:"
  | BVerifyFailDev -> "rl:verify:fail:dev:"
  | BDeviceJtis -> "device:jtis:"
  | BChallengeIp -> "rl:challenge:ip:"
  | BRegisterIp -> "rl:register:ip:"
  | BVerifyIp -> "rl:verify:ip:"
  | BWebStartIp -> "rl:websession:start:ip:"
  | BWebTokenIp -> "rl:websession:token:ip:"
  | BWebToken -> "rl:websession:token:"
  | BWebBackoff -> "rl:backoff:websession:token:"
  | BWebStreak -> "rl:streak:websession:token:"
  | BWebPollIp -> "rl:websession:poll:ip:"
  | BWebKeysUser -> "rl:websession:keys:user:"
  | BTokenIssued -> "web_session:token_issued:"

let key_of (b: builder) (a: key_args) : text =
  match b with
  | BLogout -> key1 "jti:revoked:" a.ka_id
  | BSentinel -> key1 "device:revoked:" a.ka_id
  | BChallenge -> key1 "challenge:" a.ka_id
  | BStreakVerify -> key2 "rl:streak:verify:" a.ka_scope a.ka_id
  | BBackoffVerify -> key2 "rl:backoff:verify:" a.ka_scope a.ka_id
  | BVerifyFailDev -> key2 "rl:verify:fail:dev:" a.ka_scope a.ka_id
  | BDeviceJtis -> key1 "device:jtis:" a.ka_id
  | BChallengeIp -> key1 "rl:challenge:ip:" a.ka_id
  | BRegisterIp -> key1 "rl:register:ip:" a.ka_id
  | BVerifyIp -> key1 "rl:verify:ip:" a.ka_scope
  | BWebStartIp -> key1 "rl:websession:start:ip:" a.ka_id
  | BWebTokenIp -> key2 "rl:websession:token:ip:" a.ka_scope a.ka_id
  | BWebToken -> key1 "rl:websession:token:" a.ka_id
  | BWebBackoff -> key2 "rl:backoff:websession:token:" a.ka_scope a.ka_id
  | BWebStreak -> key2 "rl:streak:websession:token:" a.ka_scope a.ka_id
  | BWebPollIp -> key1 "rl:websession:poll:ip:" a.ka_id
  | BWebKeysUser -> key1 "rl:websession:keys:user:" a.ka_id
  | BTokenIssued -> key1 "web_session:token_issued:" a.ka_id

/// The suffix after the literal prefix: `id`, or `scope ^ ":" ^ id`.
let suffix_of (b: builder) (a: key_args) : string =
  match b with
  | BStreakVerify | BBackoffVerify | BVerifyFailDev | BWebTokenIp
  | BWebBackoff | BWebStreak -> (a.ka_scope._0 ^ (":" ^ a.ka_id._0))
  | BVerifyIp -> a.ka_scope._0
  | _ -> a.ka_id._0

let key_of_string (b: builder) (a: key_args) : string =
  prefix_of b ^ suffix_of b a

/// Hypothesis H: the final identifier is colon-free where the split (or the
/// `rl:websession:token:` / `rl:websession:token:ip:` bridge) needs it.
let key_hypothesis (b: builder) (a: key_args) : bool =
  match b with
  | BStreakVerify | BBackoffVerify | BVerifyFailDev | BWebTokenIp
  | BWebBackoff | BWebStreak | BWebToken -> colon_free a.ka_id._0
  | _ -> true

/// Every extracted key is its literal prefix concatenated with its suffix.
let key_of_eq (b: builder) (a: key_args)
  : Lemma (key_of b a == Alloc.String.String (key_of_string b a)) =
  match b with
  | BLogout -> key1_eq "jti:revoked:" a.ka_id
  | BSentinel -> key1_eq "device:revoked:" a.ka_id
  | BChallenge -> key1_eq "challenge:" a.ka_id
  | BDeviceJtis -> key1_eq "device:jtis:" a.ka_id
  | BChallengeIp -> key1_eq "rl:challenge:ip:" a.ka_id
  | BRegisterIp -> key1_eq "rl:register:ip:" a.ka_id
  | BVerifyIp -> key1_eq "rl:verify:ip:" a.ka_scope
  | BWebStartIp -> key1_eq "rl:websession:start:ip:" a.ka_id
  | BWebToken -> key1_eq "rl:websession:token:" a.ka_id
  | BWebPollIp -> key1_eq "rl:websession:poll:ip:" a.ka_id
  | BWebKeysUser -> key1_eq "rl:websession:keys:user:" a.ka_id
  | BTokenIssued -> key1_eq "web_session:token_issued:" a.ka_id
  | BStreakVerify ->
    key2_eq "rl:streak:verify:" a.ka_scope a.ka_id;
    concat_assoc "rl:streak:verify:" a.ka_scope._0 ":";
    concat_assoc a.ka_scope._0 ":" a.ka_id._0;
    concat_assoc "rl:streak:verify:" (a.ka_scope._0 ^ ":") a.ka_id._0
  | BBackoffVerify ->
    key2_eq "rl:backoff:verify:" a.ka_scope a.ka_id;
    concat_assoc "rl:backoff:verify:" a.ka_scope._0 ":";
    concat_assoc a.ka_scope._0 ":" a.ka_id._0;
    concat_assoc "rl:backoff:verify:" (a.ka_scope._0 ^ ":") a.ka_id._0
  | BVerifyFailDev ->
    key2_eq "rl:verify:fail:dev:" a.ka_scope a.ka_id;
    concat_assoc "rl:verify:fail:dev:" a.ka_scope._0 ":";
    concat_assoc a.ka_scope._0 ":" a.ka_id._0;
    concat_assoc "rl:verify:fail:dev:" (a.ka_scope._0 ^ ":") a.ka_id._0
  | BWebTokenIp ->
    key2_eq "rl:websession:token:ip:" a.ka_scope a.ka_id;
    concat_assoc "rl:websession:token:ip:" a.ka_scope._0 ":";
    concat_assoc a.ka_scope._0 ":" a.ka_id._0;
    concat_assoc "rl:websession:token:ip:" (a.ka_scope._0 ^ ":") a.ka_id._0
  | BWebBackoff ->
    key2_eq "rl:backoff:websession:token:" a.ka_scope a.ka_id;
    concat_assoc "rl:backoff:websession:token:" a.ka_scope._0 ":";
    concat_assoc a.ka_scope._0 ":" a.ka_id._0;
    concat_assoc "rl:backoff:websession:token:" (a.ka_scope._0 ^ ":") a.ka_id._0
  | BWebStreak ->
    key2_eq "rl:streak:websession:token:" a.ka_scope a.ka_id;
    concat_assoc "rl:streak:websession:token:" a.ka_scope._0 ":";
    concat_assoc a.ka_scope._0 ":" a.ka_id._0;
    concat_assoc "rl:streak:websession:token:" (a.ka_scope._0 ^ ":") a.ka_id._0

// ── Injectivity of every format ────────────────────────────────────────────

let key_logout_injective (a b: text)
  : Lemma (requires key1 "jti:revoked:" a == key1 "jti:revoked:" b)
          (ensures a == b) = key1_injective "jti:revoked:" a b

let key_sentinel_injective (a b: text)
  : Lemma (requires key1 "device:revoked:" a == key1 "device:revoked:" b)
          (ensures a == b) = key1_injective "device:revoked:" a b

let key_challenge_injective (a b: text)
  : Lemma (requires key1 "challenge:" a == key1 "challenge:" b)
          (ensures a == b) = key1_injective "challenge:" a b

let key_streak_verify_injective (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 "rl:streak:verify:" s1 id1 ==
                    key2 "rl:streak:verify:" s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_injective "rl:streak:verify:" s1 s2 id1 id2

let key_backoff_verify_injective (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 "rl:backoff:verify:" s1 id1 ==
                    key2 "rl:backoff:verify:" s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_injective "rl:backoff:verify:" s1 s2 id1 id2

let key_verify_fail_dev_injective (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 "rl:verify:fail:dev:" s1 id1 ==
                    key2 "rl:verify:fail:dev:" s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_injective "rl:verify:fail:dev:" s1 s2 id1 id2

let key_device_jtis_injective (a b: text)
  : Lemma (requires key1 "device:jtis:" a == key1 "device:jtis:" b)
          (ensures a == b) = key1_injective "device:jtis:" a b

let key_challenge_ip_injective (a b: text)
  : Lemma (requires key1 "rl:challenge:ip:" a == key1 "rl:challenge:ip:" b)
          (ensures a == b) = key1_injective "rl:challenge:ip:" a b

let key_register_ip_injective (a b: text)
  : Lemma (requires key1 "rl:register:ip:" a == key1 "rl:register:ip:" b)
          (ensures a == b) = key1_injective "rl:register:ip:" a b

let key_verify_ip_injective (a b: text)
  : Lemma (requires key1 "rl:verify:ip:" a == key1 "rl:verify:ip:" b)
          (ensures a == b) = key1_injective "rl:verify:ip:" a b

let key_web_start_ip_injective (a b: text)
  : Lemma (requires key1 "rl:websession:start:ip:" a == key1 "rl:websession:start:ip:" b)
          (ensures a == b) = key1_injective "rl:websession:start:ip:" a b

let key_web_token_ip_injective (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 "rl:websession:token:ip:" s1 id1 ==
                    key2 "rl:websession:token:ip:" s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_injective "rl:websession:token:ip:" s1 s2 id1 id2

let key_web_token_injective (a b: text)
  : Lemma (requires colon_free a._0 /\ colon_free b._0 /\
                    key1 "rl:websession:token:" a == key1 "rl:websession:token:" b)
          (ensures a == b) = key1_injective "rl:websession:token:" a b

let key_web_backoff_injective (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 "rl:backoff:websession:token:" s1 id1 ==
                    key2 "rl:backoff:websession:token:" s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_injective "rl:backoff:websession:token:" s1 s2 id1 id2

let key_web_streak_injective (s1 s2 id1 id2: text)
  : Lemma (requires colon_free id1._0 /\ colon_free id2._0 /\
                    key2 "rl:streak:websession:token:" s1 id1 ==
                    key2 "rl:streak:websession:token:" s2 id2)
          (ensures s1 == s2 /\ id1 == id2) =
  key2_injective "rl:streak:websession:token:" s1 s2 id1 id2

let key_web_poll_ip_injective (a b: text)
  : Lemma (requires key1 "rl:websession:poll:ip:" a == key1 "rl:websession:poll:ip:" b)
          (ensures a == b) = key1_injective "rl:websession:poll:ip:" a b

let key_web_keys_user_injective (a b: text)
  : Lemma (requires key1 "rl:websession:keys:user:" a == key1 "rl:websession:keys:user:" b)
          (ensures a == b) = key1_injective "rl:websession:keys:user:" a b

let key_token_issued_injective (a b: text)
  : Lemma (requires key1 "web_session:token_issued:" a == key1 "web_session:token_issued:" b)
          (ensures a == b) = key1_injective "web_session:token_issued:" a b

// ── The literal prefix set and its pairwise separation ──────────────────────
let prefixes : list string =
  [ "jti:revoked:";
    "device:revoked:";
    "challenge:";
    "rl:streak:verify:";
    "rl:backoff:verify:";
    "rl:verify:fail:dev:";
    "device:jtis:";
    "rl:challenge:ip:";
    "rl:register:ip:";
    "rl:verify:ip:";
    "rl:websession:start:ip:";
    "rl:websession:token:ip:";
    "rl:websession:token:";
    "rl:backoff:websession:token:";
    "rl:streak:websession:token:";
    "rl:websession:poll:ip:";
    "rl:websession:keys:user:";
    "web_session:token_issued:" ]
/// The 17 prefixes other than `rl:websession:token:`.
let prefixes_without_token : list string =
  [ "jti:revoked:";
    "device:revoked:";
    "challenge:";
    "rl:streak:verify:";
    "rl:backoff:verify:";
    "rl:verify:fail:dev:";
    "device:jtis:";
    "rl:challenge:ip:";
    "rl:register:ip:";
    "rl:verify:ip:";
    "rl:websession:start:ip:";
    "rl:websession:token:ip:";
    "rl:backoff:websession:token:";
    "rl:streak:websession:token:";
    "rl:websession:poll:ip:";
    "rl:websession:keys:user:";
    "web_session:token_issued:" ]
/// The 17 prefixes other than `rl:websession:token:ip:`.
let prefixes_without_token_ip : list string =
  [ "jti:revoked:";
    "device:revoked:";
    "challenge:";
    "rl:streak:verify:";
    "rl:backoff:verify:";
    "rl:verify:fail:dev:";
    "device:jtis:";
    "rl:challenge:ip:";
    "rl:register:ip:";
    "rl:verify:ip:";
    "rl:websession:start:ip:";
    "rl:websession:token:";
    "rl:backoff:websession:token:";
    "rl:streak:websession:token:";
    "rl:websession:poll:ip:";
    "rl:websession:keys:user:";
    "web_session:token_issued:" ]

/// Total list lookup: gives the `n`-th prefix, or "" past the end.
let rec nth_prefix (l: list string) (n: nat) : Tot string (decreases l) =
  match l, n with
  | [], _ -> ""
  | h :: _, 0 -> h
  | _ :: tl, _ -> nth_prefix tl (n - 1)

let rec nth_prefix_mem (l: list string) (n: nat)
  : Lemma (requires n < L.length l) (ensures L.mem (nth_prefix l n) l)
          (decreases l) =
  match l, n with
  | [], _ -> ()
  | h :: _, 0 -> ()
  | _ :: tl, _ -> nth_prefix_mem tl (n - 1)

let prefix_index (b: builder) : nat =
  match b with
  | BLogout -> 0
  | BSentinel -> 1
  | BChallenge -> 2
  | BStreakVerify -> 3
  | BBackoffVerify -> 4
  | BVerifyFailDev -> 5
  | BDeviceJtis -> 6
  | BChallengeIp -> 7
  | BRegisterIp -> 8
  | BVerifyIp -> 9
  | BWebStartIp -> 10
  | BWebTokenIp -> 11
  | BWebToken -> 12
  | BWebBackoff -> 13
  | BWebStreak -> 14
  | BWebPollIp -> 15
  | BWebKeysUser -> 16
  | BTokenIssued -> 17

let prefix_index_eq (b: builder) : Lemma (prefix_of b == nth_prefix prefixes (prefix_index b)) =
  match b with
  | BLogout -> assert_norm (prefix_of BLogout == nth_prefix prefixes (prefix_index BLogout))
  | BSentinel -> assert_norm (prefix_of BSentinel == nth_prefix prefixes (prefix_index BSentinel))
  | BChallenge -> assert_norm (prefix_of BChallenge == nth_prefix prefixes (prefix_index BChallenge))
  | BStreakVerify -> assert_norm (prefix_of BStreakVerify == nth_prefix prefixes (prefix_index BStreakVerify))
  | BBackoffVerify -> assert_norm (prefix_of BBackoffVerify == nth_prefix prefixes (prefix_index BBackoffVerify))
  | BVerifyFailDev -> assert_norm (prefix_of BVerifyFailDev == nth_prefix prefixes (prefix_index BVerifyFailDev))
  | BDeviceJtis -> assert_norm (prefix_of BDeviceJtis == nth_prefix prefixes (prefix_index BDeviceJtis))
  | BChallengeIp -> assert_norm (prefix_of BChallengeIp == nth_prefix prefixes (prefix_index BChallengeIp))
  | BRegisterIp -> assert_norm (prefix_of BRegisterIp == nth_prefix prefixes (prefix_index BRegisterIp))
  | BVerifyIp -> assert_norm (prefix_of BVerifyIp == nth_prefix prefixes (prefix_index BVerifyIp))
  | BWebStartIp -> assert_norm (prefix_of BWebStartIp == nth_prefix prefixes (prefix_index BWebStartIp))
  | BWebTokenIp -> assert_norm (prefix_of BWebTokenIp == nth_prefix prefixes (prefix_index BWebTokenIp))
  | BWebToken -> assert_norm (prefix_of BWebToken == nth_prefix prefixes (prefix_index BWebToken))
  | BWebBackoff -> assert_norm (prefix_of BWebBackoff == nth_prefix prefixes (prefix_index BWebBackoff))
  | BWebStreak -> assert_norm (prefix_of BWebStreak == nth_prefix prefixes (prefix_index BWebStreak))
  | BWebPollIp -> assert_norm (prefix_of BWebPollIp == nth_prefix prefixes (prefix_index BWebPollIp))
  | BWebKeysUser -> assert_norm (prefix_of BWebKeysUser == nth_prefix prefixes (prefix_index BWebKeysUser))
  | BTokenIssued -> assert_norm (prefix_of BTokenIssued == nth_prefix prefixes (prefix_index BTokenIssued))
let prefix_index_bound (b: builder) : Lemma (prefix_index b < L.length prefixes) =
  match b with
  | BLogout -> assert_norm (prefix_index BLogout < L.length prefixes)
  | BSentinel -> assert_norm (prefix_index BSentinel < L.length prefixes)
  | BChallenge -> assert_norm (prefix_index BChallenge < L.length prefixes)
  | BStreakVerify -> assert_norm (prefix_index BStreakVerify < L.length prefixes)
  | BBackoffVerify -> assert_norm (prefix_index BBackoffVerify < L.length prefixes)
  | BVerifyFailDev -> assert_norm (prefix_index BVerifyFailDev < L.length prefixes)
  | BDeviceJtis -> assert_norm (prefix_index BDeviceJtis < L.length prefixes)
  | BChallengeIp -> assert_norm (prefix_index BChallengeIp < L.length prefixes)
  | BRegisterIp -> assert_norm (prefix_index BRegisterIp < L.length prefixes)
  | BVerifyIp -> assert_norm (prefix_index BVerifyIp < L.length prefixes)
  | BWebStartIp -> assert_norm (prefix_index BWebStartIp < L.length prefixes)
  | BWebTokenIp -> assert_norm (prefix_index BWebTokenIp < L.length prefixes)
  | BWebToken -> assert_norm (prefix_index BWebToken < L.length prefixes)
  | BWebBackoff -> assert_norm (prefix_index BWebBackoff < L.length prefixes)
  | BWebStreak -> assert_norm (prefix_index BWebStreak < L.length prefixes)
  | BWebPollIp -> assert_norm (prefix_index BWebPollIp < L.length prefixes)
  | BWebKeysUser -> assert_norm (prefix_index BWebKeysUser < L.length prefixes)
  | BTokenIssued -> assert_norm (prefix_index BTokenIssued < L.length prefixes)
let prefix_index_without_token (b: builder) : nat =
  match b with
  | BLogout -> 0
  | BSentinel -> 1
  | BChallenge -> 2
  | BStreakVerify -> 3
  | BBackoffVerify -> 4
  | BVerifyFailDev -> 5
  | BDeviceJtis -> 6
  | BChallengeIp -> 7
  | BRegisterIp -> 8
  | BVerifyIp -> 9
  | BWebStartIp -> 10
  | BWebTokenIp -> 11
  | BWebBackoff -> 12
  | BWebStreak -> 13
  | BWebPollIp -> 14
  | BWebKeysUser -> 15
  | BTokenIssued -> 16

  | BWebToken -> 0
/// The list omits `rl:websession:token:`, so the equation holds for every
/// builder except `BWebToken`. The excluded branch is vacuous under the
/// precondition; `prefix_index_without_token BWebToken` is only a dummy.
let prefix_index_without_token_eq (b: builder)
  : Lemma (requires b <> BWebToken)
          (ensures prefix_of b == nth_prefix prefixes_without_token (prefix_index_without_token b)) =
  match b with
  | BWebToken -> ()
  | BLogout -> assert_norm (prefix_of BLogout == nth_prefix prefixes_without_token (prefix_index_without_token BLogout))
  | BSentinel -> assert_norm (prefix_of BSentinel == nth_prefix prefixes_without_token (prefix_index_without_token BSentinel))
  | BChallenge -> assert_norm (prefix_of BChallenge == nth_prefix prefixes_without_token (prefix_index_without_token BChallenge))
  | BStreakVerify -> assert_norm (prefix_of BStreakVerify == nth_prefix prefixes_without_token (prefix_index_without_token BStreakVerify))
  | BBackoffVerify -> assert_norm (prefix_of BBackoffVerify == nth_prefix prefixes_without_token (prefix_index_without_token BBackoffVerify))
  | BVerifyFailDev -> assert_norm (prefix_of BVerifyFailDev == nth_prefix prefixes_without_token (prefix_index_without_token BVerifyFailDev))
  | BDeviceJtis -> assert_norm (prefix_of BDeviceJtis == nth_prefix prefixes_without_token (prefix_index_without_token BDeviceJtis))
  | BChallengeIp -> assert_norm (prefix_of BChallengeIp == nth_prefix prefixes_without_token (prefix_index_without_token BChallengeIp))
  | BRegisterIp -> assert_norm (prefix_of BRegisterIp == nth_prefix prefixes_without_token (prefix_index_without_token BRegisterIp))
  | BVerifyIp -> assert_norm (prefix_of BVerifyIp == nth_prefix prefixes_without_token (prefix_index_without_token BVerifyIp))
  | BWebStartIp -> assert_norm (prefix_of BWebStartIp == nth_prefix prefixes_without_token (prefix_index_without_token BWebStartIp))
  | BWebTokenIp -> assert_norm (prefix_of BWebTokenIp == nth_prefix prefixes_without_token (prefix_index_without_token BWebTokenIp))
  | BWebBackoff -> assert_norm (prefix_of BWebBackoff == nth_prefix prefixes_without_token (prefix_index_without_token BWebBackoff))
  | BWebStreak -> assert_norm (prefix_of BWebStreak == nth_prefix prefixes_without_token (prefix_index_without_token BWebStreak))
  | BWebPollIp -> assert_norm (prefix_of BWebPollIp == nth_prefix prefixes_without_token (prefix_index_without_token BWebPollIp))
  | BWebKeysUser -> assert_norm (prefix_of BWebKeysUser == nth_prefix prefixes_without_token (prefix_index_without_token BWebKeysUser))
  | BTokenIssued -> assert_norm (prefix_of BTokenIssued == nth_prefix prefixes_without_token (prefix_index_without_token BTokenIssued))
let prefix_index_without_token_bound (b: builder) : Lemma (prefix_index_without_token b < L.length prefixes_without_token) =
  match b with
  | BLogout -> assert_norm (prefix_index_without_token BLogout < L.length prefixes_without_token)
  | BSentinel -> assert_norm (prefix_index_without_token BSentinel < L.length prefixes_without_token)
  | BChallenge -> assert_norm (prefix_index_without_token BChallenge < L.length prefixes_without_token)
  | BStreakVerify -> assert_norm (prefix_index_without_token BStreakVerify < L.length prefixes_without_token)
  | BBackoffVerify -> assert_norm (prefix_index_without_token BBackoffVerify < L.length prefixes_without_token)
  | BVerifyFailDev -> assert_norm (prefix_index_without_token BVerifyFailDev < L.length prefixes_without_token)
  | BDeviceJtis -> assert_norm (prefix_index_without_token BDeviceJtis < L.length prefixes_without_token)
  | BChallengeIp -> assert_norm (prefix_index_without_token BChallengeIp < L.length prefixes_without_token)
  | BRegisterIp -> assert_norm (prefix_index_without_token BRegisterIp < L.length prefixes_without_token)
  | BVerifyIp -> assert_norm (prefix_index_without_token BVerifyIp < L.length prefixes_without_token)
  | BWebStartIp -> assert_norm (prefix_index_without_token BWebStartIp < L.length prefixes_without_token)
  | BWebTokenIp -> assert_norm (prefix_index_without_token BWebTokenIp < L.length prefixes_without_token)
  | BWebBackoff -> assert_norm (prefix_index_without_token BWebBackoff < L.length prefixes_without_token)
  | BWebStreak -> assert_norm (prefix_index_without_token BWebStreak < L.length prefixes_without_token)
  | BWebPollIp -> assert_norm (prefix_index_without_token BWebPollIp < L.length prefixes_without_token)
  | BWebKeysUser -> assert_norm (prefix_index_without_token BWebKeysUser < L.length prefixes_without_token)
  | BTokenIssued -> assert_norm (prefix_index_without_token BTokenIssued < L.length prefixes_without_token)
  | BWebToken -> assert_norm (prefix_index_without_token BWebToken < L.length prefixes_without_token)
let prefix_index_without_token_ip (b: builder) : nat =
  match b with
  | BLogout -> 0
  | BSentinel -> 1
  | BChallenge -> 2
  | BStreakVerify -> 3
  | BBackoffVerify -> 4
  | BVerifyFailDev -> 5
  | BDeviceJtis -> 6
  | BChallengeIp -> 7
  | BRegisterIp -> 8
  | BVerifyIp -> 9
  | BWebStartIp -> 10
  | BWebToken -> 11
  | BWebBackoff -> 12
  | BWebStreak -> 13
  | BWebPollIp -> 14
  | BWebKeysUser -> 15
  | BTokenIssued -> 16

  | BWebTokenIp -> 0
let prefix_index_without_token_ip_eq (b: builder)
  : Lemma (requires b <> BWebTokenIp)
          (ensures prefix_of b == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip b)) =
  match b with
  | BWebTokenIp -> ()
  | BLogout -> assert_norm (prefix_of BLogout == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BLogout))
  | BSentinel -> assert_norm (prefix_of BSentinel == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BSentinel))
  | BChallenge -> assert_norm (prefix_of BChallenge == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BChallenge))
  | BStreakVerify -> assert_norm (prefix_of BStreakVerify == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BStreakVerify))
  | BBackoffVerify -> assert_norm (prefix_of BBackoffVerify == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BBackoffVerify))
  | BVerifyFailDev -> assert_norm (prefix_of BVerifyFailDev == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BVerifyFailDev))
  | BDeviceJtis -> assert_norm (prefix_of BDeviceJtis == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BDeviceJtis))
  | BChallengeIp -> assert_norm (prefix_of BChallengeIp == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BChallengeIp))
  | BRegisterIp -> assert_norm (prefix_of BRegisterIp == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BRegisterIp))
  | BVerifyIp -> assert_norm (prefix_of BVerifyIp == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BVerifyIp))
  | BWebStartIp -> assert_norm (prefix_of BWebStartIp == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BWebStartIp))
  | BWebToken -> assert_norm (prefix_of BWebToken == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BWebToken))
  | BWebBackoff -> assert_norm (prefix_of BWebBackoff == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BWebBackoff))
  | BWebStreak -> assert_norm (prefix_of BWebStreak == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BWebStreak))
  | BWebPollIp -> assert_norm (prefix_of BWebPollIp == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BWebPollIp))
  | BWebKeysUser -> assert_norm (prefix_of BWebKeysUser == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BWebKeysUser))
  | BTokenIssued -> assert_norm (prefix_of BTokenIssued == nth_prefix prefixes_without_token_ip (prefix_index_without_token_ip BTokenIssued))
let prefix_index_without_token_ip_bound (b: builder) : Lemma (prefix_index_without_token_ip b < L.length prefixes_without_token_ip) =
  match b with
  | BLogout -> assert_norm (prefix_index_without_token_ip BLogout < L.length prefixes_without_token_ip)
  | BSentinel -> assert_norm (prefix_index_without_token_ip BSentinel < L.length prefixes_without_token_ip)
  | BChallenge -> assert_norm (prefix_index_without_token_ip BChallenge < L.length prefixes_without_token_ip)
  | BStreakVerify -> assert_norm (prefix_index_without_token_ip BStreakVerify < L.length prefixes_without_token_ip)
  | BBackoffVerify -> assert_norm (prefix_index_without_token_ip BBackoffVerify < L.length prefixes_without_token_ip)
  | BVerifyFailDev -> assert_norm (prefix_index_without_token_ip BVerifyFailDev < L.length prefixes_without_token_ip)
  | BDeviceJtis -> assert_norm (prefix_index_without_token_ip BDeviceJtis < L.length prefixes_without_token_ip)
  | BChallengeIp -> assert_norm (prefix_index_without_token_ip BChallengeIp < L.length prefixes_without_token_ip)
  | BRegisterIp -> assert_norm (prefix_index_without_token_ip BRegisterIp < L.length prefixes_without_token_ip)
  | BVerifyIp -> assert_norm (prefix_index_without_token_ip BVerifyIp < L.length prefixes_without_token_ip)
  | BWebStartIp -> assert_norm (prefix_index_without_token_ip BWebStartIp < L.length prefixes_without_token_ip)
  | BWebToken -> assert_norm (prefix_index_without_token_ip BWebToken < L.length prefixes_without_token_ip)
  | BWebBackoff -> assert_norm (prefix_index_without_token_ip BWebBackoff < L.length prefixes_without_token_ip)
  | BWebStreak -> assert_norm (prefix_index_without_token_ip BWebStreak < L.length prefixes_without_token_ip)
  | BWebPollIp -> assert_norm (prefix_index_without_token_ip BWebPollIp < L.length prefixes_without_token_ip)
  | BWebKeysUser -> assert_norm (prefix_index_without_token_ip BWebKeysUser < L.length prefixes_without_token_ip)
  | BTokenIssued -> assert_norm (prefix_index_without_token_ip BTokenIssued < L.length prefixes_without_token_ip)
  | BWebTokenIp -> assert_norm (prefix_index_without_token_ip BWebTokenIp < L.length prefixes_without_token_ip)
let prefix_mem (b: builder) : Lemma (L.mem (prefix_of b) prefixes) =
  prefix_index_eq b;
  prefix_index_bound b;
  nth_prefix_mem prefixes (prefix_index b)

let prefix_mem_without_token (b: builder)
  : Lemma (requires b <> BWebToken)
          (ensures L.mem (prefix_of b) prefixes_without_token) =
  prefix_index_without_token_eq b;
  prefix_index_without_token_bound b;
  nth_prefix_mem prefixes_without_token (prefix_index_without_token b)

let prefix_mem_without_token_ip (b: builder)
  : Lemma (requires b <> BWebTokenIp)
          (ensures L.mem (prefix_of b) prefixes_without_token_ip) =
  prefix_index_without_token_ip_eq b;
  prefix_index_without_token_ip_bound b;
  nth_prefix_mem prefixes_without_token_ip (prefix_index_without_token_ip b)


/// Distinct constructors name distinct literal prefixes.
let prefix_of_injective (b1 b2: builder)
  : Lemma (requires prefix_of b1 == prefix_of b2) (ensures b1 == b2) =
  match b1, b2 with
  | BLogout, BLogout -> ()
  | BLogout, BSentinel -> ()
  | BLogout, BChallenge -> ()
  | BLogout, BStreakVerify -> ()
  | BLogout, BBackoffVerify -> ()
  | BLogout, BVerifyFailDev -> ()
  | BLogout, BDeviceJtis -> ()
  | BLogout, BChallengeIp -> ()
  | BLogout, BRegisterIp -> ()
  | BLogout, BVerifyIp -> ()
  | BLogout, BWebStartIp -> ()
  | BLogout, BWebTokenIp -> ()
  | BLogout, BWebToken -> ()
  | BLogout, BWebBackoff -> ()
  | BLogout, BWebStreak -> ()
  | BLogout, BWebPollIp -> ()
  | BLogout, BWebKeysUser -> ()
  | BLogout, BTokenIssued -> ()
  | BSentinel, BLogout -> ()
  | BSentinel, BSentinel -> ()
  | BSentinel, BChallenge -> ()
  | BSentinel, BStreakVerify -> ()
  | BSentinel, BBackoffVerify -> ()
  | BSentinel, BVerifyFailDev -> ()
  | BSentinel, BDeviceJtis -> ()
  | BSentinel, BChallengeIp -> ()
  | BSentinel, BRegisterIp -> ()
  | BSentinel, BVerifyIp -> ()
  | BSentinel, BWebStartIp -> ()
  | BSentinel, BWebTokenIp -> ()
  | BSentinel, BWebToken -> ()
  | BSentinel, BWebBackoff -> ()
  | BSentinel, BWebStreak -> ()
  | BSentinel, BWebPollIp -> ()
  | BSentinel, BWebKeysUser -> ()
  | BSentinel, BTokenIssued -> ()
  | BChallenge, BLogout -> ()
  | BChallenge, BSentinel -> ()
  | BChallenge, BChallenge -> ()
  | BChallenge, BStreakVerify -> ()
  | BChallenge, BBackoffVerify -> ()
  | BChallenge, BVerifyFailDev -> ()
  | BChallenge, BDeviceJtis -> ()
  | BChallenge, BChallengeIp -> ()
  | BChallenge, BRegisterIp -> ()
  | BChallenge, BVerifyIp -> ()
  | BChallenge, BWebStartIp -> ()
  | BChallenge, BWebTokenIp -> ()
  | BChallenge, BWebToken -> ()
  | BChallenge, BWebBackoff -> ()
  | BChallenge, BWebStreak -> ()
  | BChallenge, BWebPollIp -> ()
  | BChallenge, BWebKeysUser -> ()
  | BChallenge, BTokenIssued -> ()
  | BStreakVerify, BLogout -> ()
  | BStreakVerify, BSentinel -> ()
  | BStreakVerify, BChallenge -> ()
  | BStreakVerify, BStreakVerify -> ()
  | BStreakVerify, BBackoffVerify -> ()
  | BStreakVerify, BVerifyFailDev -> ()
  | BStreakVerify, BDeviceJtis -> ()
  | BStreakVerify, BChallengeIp -> ()
  | BStreakVerify, BRegisterIp -> ()
  | BStreakVerify, BVerifyIp -> ()
  | BStreakVerify, BWebStartIp -> ()
  | BStreakVerify, BWebTokenIp -> ()
  | BStreakVerify, BWebToken -> ()
  | BStreakVerify, BWebBackoff -> ()
  | BStreakVerify, BWebStreak -> ()
  | BStreakVerify, BWebPollIp -> ()
  | BStreakVerify, BWebKeysUser -> ()
  | BStreakVerify, BTokenIssued -> ()
  | BBackoffVerify, BLogout -> ()
  | BBackoffVerify, BSentinel -> ()
  | BBackoffVerify, BChallenge -> ()
  | BBackoffVerify, BStreakVerify -> ()
  | BBackoffVerify, BBackoffVerify -> ()
  | BBackoffVerify, BVerifyFailDev -> ()
  | BBackoffVerify, BDeviceJtis -> ()
  | BBackoffVerify, BChallengeIp -> ()
  | BBackoffVerify, BRegisterIp -> ()
  | BBackoffVerify, BVerifyIp -> ()
  | BBackoffVerify, BWebStartIp -> ()
  | BBackoffVerify, BWebTokenIp -> ()
  | BBackoffVerify, BWebToken -> ()
  | BBackoffVerify, BWebBackoff -> ()
  | BBackoffVerify, BWebStreak -> ()
  | BBackoffVerify, BWebPollIp -> ()
  | BBackoffVerify, BWebKeysUser -> ()
  | BBackoffVerify, BTokenIssued -> ()
  | BVerifyFailDev, BLogout -> ()
  | BVerifyFailDev, BSentinel -> ()
  | BVerifyFailDev, BChallenge -> ()
  | BVerifyFailDev, BStreakVerify -> ()
  | BVerifyFailDev, BBackoffVerify -> ()
  | BVerifyFailDev, BVerifyFailDev -> ()
  | BVerifyFailDev, BDeviceJtis -> ()
  | BVerifyFailDev, BChallengeIp -> ()
  | BVerifyFailDev, BRegisterIp -> ()
  | BVerifyFailDev, BVerifyIp -> ()
  | BVerifyFailDev, BWebStartIp -> ()
  | BVerifyFailDev, BWebTokenIp -> ()
  | BVerifyFailDev, BWebToken -> ()
  | BVerifyFailDev, BWebBackoff -> ()
  | BVerifyFailDev, BWebStreak -> ()
  | BVerifyFailDev, BWebPollIp -> ()
  | BVerifyFailDev, BWebKeysUser -> ()
  | BVerifyFailDev, BTokenIssued -> ()
  | BDeviceJtis, BLogout -> ()
  | BDeviceJtis, BSentinel -> ()
  | BDeviceJtis, BChallenge -> ()
  | BDeviceJtis, BStreakVerify -> ()
  | BDeviceJtis, BBackoffVerify -> ()
  | BDeviceJtis, BVerifyFailDev -> ()
  | BDeviceJtis, BDeviceJtis -> ()
  | BDeviceJtis, BChallengeIp -> ()
  | BDeviceJtis, BRegisterIp -> ()
  | BDeviceJtis, BVerifyIp -> ()
  | BDeviceJtis, BWebStartIp -> ()
  | BDeviceJtis, BWebTokenIp -> ()
  | BDeviceJtis, BWebToken -> ()
  | BDeviceJtis, BWebBackoff -> ()
  | BDeviceJtis, BWebStreak -> ()
  | BDeviceJtis, BWebPollIp -> ()
  | BDeviceJtis, BWebKeysUser -> ()
  | BDeviceJtis, BTokenIssued -> ()
  | BChallengeIp, BLogout -> ()
  | BChallengeIp, BSentinel -> ()
  | BChallengeIp, BChallenge -> ()
  | BChallengeIp, BStreakVerify -> ()
  | BChallengeIp, BBackoffVerify -> ()
  | BChallengeIp, BVerifyFailDev -> ()
  | BChallengeIp, BDeviceJtis -> ()
  | BChallengeIp, BChallengeIp -> ()
  | BChallengeIp, BRegisterIp -> ()
  | BChallengeIp, BVerifyIp -> ()
  | BChallengeIp, BWebStartIp -> ()
  | BChallengeIp, BWebTokenIp -> ()
  | BChallengeIp, BWebToken -> ()
  | BChallengeIp, BWebBackoff -> ()
  | BChallengeIp, BWebStreak -> ()
  | BChallengeIp, BWebPollIp -> ()
  | BChallengeIp, BWebKeysUser -> ()
  | BChallengeIp, BTokenIssued -> ()
  | BRegisterIp, BLogout -> ()
  | BRegisterIp, BSentinel -> ()
  | BRegisterIp, BChallenge -> ()
  | BRegisterIp, BStreakVerify -> ()
  | BRegisterIp, BBackoffVerify -> ()
  | BRegisterIp, BVerifyFailDev -> ()
  | BRegisterIp, BDeviceJtis -> ()
  | BRegisterIp, BChallengeIp -> ()
  | BRegisterIp, BRegisterIp -> ()
  | BRegisterIp, BVerifyIp -> ()
  | BRegisterIp, BWebStartIp -> ()
  | BRegisterIp, BWebTokenIp -> ()
  | BRegisterIp, BWebToken -> ()
  | BRegisterIp, BWebBackoff -> ()
  | BRegisterIp, BWebStreak -> ()
  | BRegisterIp, BWebPollIp -> ()
  | BRegisterIp, BWebKeysUser -> ()
  | BRegisterIp, BTokenIssued -> ()
  | BVerifyIp, BLogout -> ()
  | BVerifyIp, BSentinel -> ()
  | BVerifyIp, BChallenge -> ()
  | BVerifyIp, BStreakVerify -> ()
  | BVerifyIp, BBackoffVerify -> ()
  | BVerifyIp, BVerifyFailDev -> ()
  | BVerifyIp, BDeviceJtis -> ()
  | BVerifyIp, BChallengeIp -> ()
  | BVerifyIp, BRegisterIp -> ()
  | BVerifyIp, BVerifyIp -> ()
  | BVerifyIp, BWebStartIp -> ()
  | BVerifyIp, BWebTokenIp -> ()
  | BVerifyIp, BWebToken -> ()
  | BVerifyIp, BWebBackoff -> ()
  | BVerifyIp, BWebStreak -> ()
  | BVerifyIp, BWebPollIp -> ()
  | BVerifyIp, BWebKeysUser -> ()
  | BVerifyIp, BTokenIssued -> ()
  | BWebStartIp, BLogout -> ()
  | BWebStartIp, BSentinel -> ()
  | BWebStartIp, BChallenge -> ()
  | BWebStartIp, BStreakVerify -> ()
  | BWebStartIp, BBackoffVerify -> ()
  | BWebStartIp, BVerifyFailDev -> ()
  | BWebStartIp, BDeviceJtis -> ()
  | BWebStartIp, BChallengeIp -> ()
  | BWebStartIp, BRegisterIp -> ()
  | BWebStartIp, BVerifyIp -> ()
  | BWebStartIp, BWebStartIp -> ()
  | BWebStartIp, BWebTokenIp -> ()
  | BWebStartIp, BWebToken -> ()
  | BWebStartIp, BWebBackoff -> ()
  | BWebStartIp, BWebStreak -> ()
  | BWebStartIp, BWebPollIp -> ()
  | BWebStartIp, BWebKeysUser -> ()
  | BWebStartIp, BTokenIssued -> ()
  | BWebTokenIp, BLogout -> ()
  | BWebTokenIp, BSentinel -> ()
  | BWebTokenIp, BChallenge -> ()
  | BWebTokenIp, BStreakVerify -> ()
  | BWebTokenIp, BBackoffVerify -> ()
  | BWebTokenIp, BVerifyFailDev -> ()
  | BWebTokenIp, BDeviceJtis -> ()
  | BWebTokenIp, BChallengeIp -> ()
  | BWebTokenIp, BRegisterIp -> ()
  | BWebTokenIp, BVerifyIp -> ()
  | BWebTokenIp, BWebStartIp -> ()
  | BWebTokenIp, BWebTokenIp -> ()
  | BWebTokenIp, BWebToken -> ()
  | BWebTokenIp, BWebBackoff -> ()
  | BWebTokenIp, BWebStreak -> ()
  | BWebTokenIp, BWebPollIp -> ()
  | BWebTokenIp, BWebKeysUser -> ()
  | BWebTokenIp, BTokenIssued -> ()
  | BWebToken, BLogout -> ()
  | BWebToken, BSentinel -> ()
  | BWebToken, BChallenge -> ()
  | BWebToken, BStreakVerify -> ()
  | BWebToken, BBackoffVerify -> ()
  | BWebToken, BVerifyFailDev -> ()
  | BWebToken, BDeviceJtis -> ()
  | BWebToken, BChallengeIp -> ()
  | BWebToken, BRegisterIp -> ()
  | BWebToken, BVerifyIp -> ()
  | BWebToken, BWebStartIp -> ()
  | BWebToken, BWebTokenIp -> ()
  | BWebToken, BWebToken -> ()
  | BWebToken, BWebBackoff -> ()
  | BWebToken, BWebStreak -> ()
  | BWebToken, BWebPollIp -> ()
  | BWebToken, BWebKeysUser -> ()
  | BWebToken, BTokenIssued -> ()
  | BWebBackoff, BLogout -> ()
  | BWebBackoff, BSentinel -> ()
  | BWebBackoff, BChallenge -> ()
  | BWebBackoff, BStreakVerify -> ()
  | BWebBackoff, BBackoffVerify -> ()
  | BWebBackoff, BVerifyFailDev -> ()
  | BWebBackoff, BDeviceJtis -> ()
  | BWebBackoff, BChallengeIp -> ()
  | BWebBackoff, BRegisterIp -> ()
  | BWebBackoff, BVerifyIp -> ()
  | BWebBackoff, BWebStartIp -> ()
  | BWebBackoff, BWebTokenIp -> ()
  | BWebBackoff, BWebToken -> ()
  | BWebBackoff, BWebBackoff -> ()
  | BWebBackoff, BWebStreak -> ()
  | BWebBackoff, BWebPollIp -> ()
  | BWebBackoff, BWebKeysUser -> ()
  | BWebBackoff, BTokenIssued -> ()
  | BWebStreak, BLogout -> ()
  | BWebStreak, BSentinel -> ()
  | BWebStreak, BChallenge -> ()
  | BWebStreak, BStreakVerify -> ()
  | BWebStreak, BBackoffVerify -> ()
  | BWebStreak, BVerifyFailDev -> ()
  | BWebStreak, BDeviceJtis -> ()
  | BWebStreak, BChallengeIp -> ()
  | BWebStreak, BRegisterIp -> ()
  | BWebStreak, BVerifyIp -> ()
  | BWebStreak, BWebStartIp -> ()
  | BWebStreak, BWebTokenIp -> ()
  | BWebStreak, BWebToken -> ()
  | BWebStreak, BWebBackoff -> ()
  | BWebStreak, BWebStreak -> ()
  | BWebStreak, BWebPollIp -> ()
  | BWebStreak, BWebKeysUser -> ()
  | BWebStreak, BTokenIssued -> ()
  | BWebPollIp, BLogout -> ()
  | BWebPollIp, BSentinel -> ()
  | BWebPollIp, BChallenge -> ()
  | BWebPollIp, BStreakVerify -> ()
  | BWebPollIp, BBackoffVerify -> ()
  | BWebPollIp, BVerifyFailDev -> ()
  | BWebPollIp, BDeviceJtis -> ()
  | BWebPollIp, BChallengeIp -> ()
  | BWebPollIp, BRegisterIp -> ()
  | BWebPollIp, BVerifyIp -> ()
  | BWebPollIp, BWebStartIp -> ()
  | BWebPollIp, BWebTokenIp -> ()
  | BWebPollIp, BWebToken -> ()
  | BWebPollIp, BWebBackoff -> ()
  | BWebPollIp, BWebStreak -> ()
  | BWebPollIp, BWebPollIp -> ()
  | BWebPollIp, BWebKeysUser -> ()
  | BWebPollIp, BTokenIssued -> ()
  | BWebKeysUser, BLogout -> ()
  | BWebKeysUser, BSentinel -> ()
  | BWebKeysUser, BChallenge -> ()
  | BWebKeysUser, BStreakVerify -> ()
  | BWebKeysUser, BBackoffVerify -> ()
  | BWebKeysUser, BVerifyFailDev -> ()
  | BWebKeysUser, BDeviceJtis -> ()
  | BWebKeysUser, BChallengeIp -> ()
  | BWebKeysUser, BRegisterIp -> ()
  | BWebKeysUser, BVerifyIp -> ()
  | BWebKeysUser, BWebStartIp -> ()
  | BWebKeysUser, BWebTokenIp -> ()
  | BWebKeysUser, BWebToken -> ()
  | BWebKeysUser, BWebBackoff -> ()
  | BWebKeysUser, BWebStreak -> ()
  | BWebKeysUser, BWebPollIp -> ()
  | BWebKeysUser, BWebKeysUser -> ()
  | BWebKeysUser, BTokenIssued -> ()
  | BTokenIssued, BLogout -> ()
  | BTokenIssued, BSentinel -> ()
  | BTokenIssued, BChallenge -> ()
  | BTokenIssued, BStreakVerify -> ()
  | BTokenIssued, BBackoffVerify -> ()
  | BTokenIssued, BVerifyFailDev -> ()
  | BTokenIssued, BDeviceJtis -> ()
  | BTokenIssued, BChallengeIp -> ()
  | BTokenIssued, BRegisterIp -> ()
  | BTokenIssued, BVerifyIp -> ()
  | BTokenIssued, BWebStartIp -> ()
  | BTokenIssued, BWebTokenIp -> ()
  | BTokenIssued, BWebToken -> ()
  | BTokenIssued, BWebBackoff -> ()
  | BTokenIssued, BWebStreak -> ()
  | BTokenIssued, BWebPollIp -> ()
  | BTokenIssued, BWebKeysUser -> ()
  | BTokenIssued, BTokenIssued -> ()

// ── Pairwise disjointness of the literal prefixes ──────────────────────────

let rec all_with (p: string) (qs: list string) : Tot bool (decreases qs) =
  match qs with
  | [] -> true
  | q :: rest -> (p = q || disjointb p q) && all_with p rest

let rec pairwise (l: list string) : Tot bool (decreases l) =
  match l with
  | [] -> true
  | p :: rest -> all_with p rest && pairwise rest

let rec all_with_sound (p: string) (qs: list string) (q: string)
  : Lemma (requires all_with p qs = true /\ L.mem q qs /\ p <> q)
          (ensures disjointb p q = true)
          (decreases qs) =
  match qs with
  | [] -> ()
  | h :: rest -> if h = q then () else all_with_sound p rest q

/// A member of a non-empty list that is not the head is a member of the tail.
let mem_cons_elim (x h: string) (tl: list string)
  : Lemma (requires L.mem x (h :: tl) /\ x <> h) (ensures L.mem x tl) = ()

let rec pairwise_sound (l: list string) (p q: string)
  : Lemma (requires pairwise l = true /\ L.mem p l /\ L.mem q l /\ p <> q)
          (ensures disjointb p q = true)
          (decreases l) =
  match l with
  | [] -> ()
  | h :: rest ->
    if h = p then begin
      mem_cons_elim q h rest;
      all_with_sound h rest q
    end else if h = q then begin
      mem_cons_elim p h rest;
      all_with_sound h rest p;
      disjointb_sym h p
    end else begin
      mem_cons_elim p h rest;
      mem_cons_elim q h rest;
      pairwise_sound rest p q
    end

/// `rl:websession:token:` and `rl:websession:token:ip:` are the only
/// prefix-related pair, so the 17-element lists are pairwise separated.
let prefixes_ok () : Lemma (pairwise prefixes_without_token = true) =
  assert_norm (pairwise prefixes_without_token = true)

let prefixes_ip_ok () : Lemma (pairwise prefixes_without_token_ip = true) =
  assert_norm (pairwise prefixes_without_token_ip = true)

// ── The one prefix-related pair, separated by H ────────────────────────────

let token_ip_literal ()
  : Lemma ("rl:websession:token:ip:" == ("rl:websession:token:" ^ "ip:")) =
  S.list_of_concat "rl:websession:token:" "ip:";
  S.string_of_list_of_string "rl:websession:token:ip:";
  S.string_of_list_of_string ("rl:websession:token:" ^ "ip:")

/// `rl:websession:token:{session}` cannot equal
/// `rl:websession:token:ip:{ip}:{session}` when the first session is
/// colon-free.
let token_vs_token_ip (a1 a2: key_args)
  : Lemma (requires key_hypothesis BWebToken a1 /\ key_hypothesis BWebTokenIp a2)
          (ensures key_of BWebToken a1 <> key_of BWebTokenIp a2) =
  key_of_eq BWebToken a1;
  key_of_eq BWebTokenIp a2;
  if key_of BWebToken a1 = key_of BWebTokenIp a2 then begin
    token_ip_literal ();
    concat_assoc "rl:websession:token:" "ip:" (a2.ka_scope._0 ^ (":" ^ a2.ka_id._0));
    concat_assoc "ip:" a2.ka_scope._0 (":" ^ a2.ka_id._0);
    S.concat_injective "rl:websession:token:" "rl:websession:token:"
      a1.ka_id._0 ("ip:" ^ (a2.ka_scope._0 ^ (":" ^ a2.ka_id._0)));
    colon_free_append_colon ("ip:" ^ a2.ka_scope._0) a2.ka_id._0
  end

/// The symmetric direction.
let token_ip_vs_token (a1 a2: key_args)
  : Lemma (requires key_hypothesis BWebTokenIp a1 /\ key_hypothesis BWebToken a2)
          (ensures key_of BWebTokenIp a1 <> key_of BWebToken a2) =
  key_of_eq BWebTokenIp a1;
  key_of_eq BWebToken a2;
  if key_of BWebTokenIp a1 = key_of BWebToken a2 then begin
    token_ip_literal ();
    concat_assoc "rl:websession:token:" "ip:" (a1.ka_scope._0 ^ (":" ^ a1.ka_id._0));
    concat_assoc "ip:" a1.ka_scope._0 (":" ^ a1.ka_id._0);
    S.concat_injective "rl:websession:token:" "rl:websession:token:"
      ("ip:" ^ (a1.ka_scope._0 ^ (":" ^ a1.ka_id._0))) a2.ka_id._0;
    colon_free_append_colon ("ip:" ^ a1.ka_scope._0) a1.ka_id._0
  end

// ── Different builders never collide ───────────────────────────────────────

let key_of_disjoint (b1 b2: builder) (a1 a2: key_args)
  : Lemma (requires b1 <> b2 /\ key_hypothesis b1 a1 /\ key_hypothesis b2 a2)
          (ensures key_of b1 a1 <> key_of b2 a2) =
  key_of_eq b1 a1;
  key_of_eq b2 a2;
  // `rl:websession:token:` is a prefix of `rl:websession:token:ip:`, so the
  // two related prefixes are never in the same pairwise list. Every other
  // pair is handled by `prefixes_without_token` (when neither is
  // `rl:websession:token:ip:`) or by `prefixes_without_token_ip` (when
  // neither is `rl:websession:token:`); the related pair itself is
  // separated by H in `token_vs_token_ip` / `token_ip_vs_token`.
  if b1 = BWebToken then begin
    if b2 = BWebTokenIp then token_vs_token_ip a1 a2
    else begin
      prefix_mem_without_token_ip b1;
      prefix_mem_without_token_ip b2;
      prefixes_ip_ok ();
      if prefix_of b1 = prefix_of b2 then prefix_of_injective b1 b2;
      pairwise_sound prefixes_without_token_ip (prefix_of b1) (prefix_of b2);
      disjointb_sound (prefix_of b1) (prefix_of b2) (suffix_of b1 a1) (suffix_of b2 a2)
    end
  end
  else if b1 = BWebTokenIp then begin
    if b2 = BWebToken then token_ip_vs_token a1 a2
    else begin
      prefix_mem_without_token b1;
      prefix_mem_without_token b2;
      prefixes_ok ();
      if prefix_of b1 = prefix_of b2 then prefix_of_injective b1 b2;
      pairwise_sound prefixes_without_token (prefix_of b1) (prefix_of b2);
      disjointb_sound (prefix_of b1) (prefix_of b2) (suffix_of b1 a1) (suffix_of b2 a2)
    end
  end
  else begin
    if b2 = BWebToken then begin
      prefix_mem_without_token_ip b1;
      prefix_mem_without_token_ip b2;
      prefixes_ip_ok ();
      if prefix_of b1 = prefix_of b2 then prefix_of_injective b1 b2;
      pairwise_sound prefixes_without_token_ip (prefix_of b1) (prefix_of b2);
      disjointb_sound (prefix_of b1) (prefix_of b2) (suffix_of b1 a1) (suffix_of b2 a2)
    end
    else begin
      prefix_mem_without_token b1;
      prefix_mem_without_token b2;
      prefixes_ok ();
      if prefix_of b1 = prefix_of b2 then prefix_of_injective b1 b2;
      pairwise_sound prefixes_without_token (prefix_of b1) (prefix_of b2);
      disjointb_sound (prefix_of b1) (prefix_of b2) (suffix_of b1 a1) (suffix_of b2 a2)
    end
  end

// ── Non-vacuity witnesses ──────────────────────────────────────────────────

let uuid = "3f2b6c1e-8a4d-4c2b-9e7f-1a2b3c4d5e6f"
let uuid2 = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
let challenge = "Q2hhbGxlbmdl+VG9rZW4vPT0="
let ipv4 = "203.0.113.7"
let ipv6 = "2001:db8::1"

let witness_uuid_colon_free () : Lemma (colon_free uuid = true) =
  assert_norm (colon_free uuid = true)

let witness_challenge_colon_free () : Lemma (colon_free challenge = true) =
  assert_norm (colon_free challenge = true)

let witness_ipv4_colon_free () : Lemma (colon_free ipv4 = true) =
  assert_norm (colon_free ipv4 = true)

/// An IPv6 address may contain ':', which is why H constrains only the final
/// identifier (the IP is never last).
let witness_ipv6_not_colon_free () : Lemma (colon_free ipv6 = false) =
  assert_norm (colon_free ipv6 = false)

/// H holds for the real argument alphabets: a UUID session in the one-argument
/// `rl:websession:token:` key, and an IPv6 scope with a UUID session in the
/// two-argument `rl:websession:token:ip:` key.
let witness_H_token () : Lemma (key_hypothesis BWebToken { ka_scope = Alloc.String.String uuid2; ka_id = Alloc.String.String uuid } = true) =
  assert_norm (key_hypothesis BWebToken { ka_scope = Alloc.String.String uuid2; ka_id = Alloc.String.String uuid } = true)

let witness_H_token_ip () : Lemma (key_hypothesis BWebTokenIp { ka_scope = Alloc.String.String ipv6; ka_id = Alloc.String.String uuid } = true) =
  assert_norm (key_hypothesis BWebTokenIp { ka_scope = Alloc.String.String ipv6; ka_id = Alloc.String.String uuid } = true)

/// The builders compute the expected bytes (non-vacuous equality).
let witness_logout_bytes ()
  : Lemma (key1 "jti:revoked:" (Alloc.String.String "abc") ==
           Alloc.String.String "jti:revoked:abc") =
  assert_norm (key1 "jti:revoked:" (Alloc.String.String "abc") ==
               Alloc.String.String "jti:revoked:abc")

/// ... and their keys are distinct for distinct ids.
let witness_logout_distinct ()
  : Lemma (key1 "jti:revoked:" (Alloc.String.String "abc") <>
           key1 "jti:revoked:" (Alloc.String.String "abd")) =
  if key1 "jti:revoked:" (Alloc.String.String "abc") =
     key1 "jti:revoked:" (Alloc.String.String "abd")
  then key1_injective "jti:revoked:" (Alloc.String.String "abc") (Alloc.String.String "abd")

/// Different builders with the same id still differ.
let witness_namespaces_distinct ()
  : Lemma (key_of BLogout { ka_scope = Alloc.String.String uuid; ka_id = Alloc.String.String uuid } <>
           key_of BSentinel { ka_scope = Alloc.String.String uuid; ka_id = Alloc.String.String uuid }) =
  key_of_disjoint BLogout BSentinel
    { ka_scope = Alloc.String.String uuid; ka_id = Alloc.String.String uuid }
    { ka_scope = Alloc.String.String uuid; ka_id = Alloc.String.String uuid }

// ── The extracted plans really build these formats ─────────────────────────
//
// `plan_key` reads the key out of the extracted plan. `plan_key_eq` is the
// link between the two theorems above and `src/store.rs`: it reduces by
// computation, so changing a plan's literal prefix or argument order makes it
// fail (see the `plan-share-token-prefix` mutant).

let stmts_of (p: Alloc.Vec.t_Vec t_StoreStmt Alloc.Alloc.t_Global) : list t_StoreStmt =
  FStar.Seq.seq_to_list p._0

let first_stmt (l: list t_StoreStmt) : t_StoreStmt =
  match l with
  | st :: _ -> st
  | [] -> StoreStmt_RevokeJtis { f_device = Alloc.String.String "" }

let second_stmt (l: list t_StoreStmt) : t_StoreStmt =
  match l with
  | _ :: st :: _ -> st
  | _ -> first_stmt l

let third_stmt (l: list t_StoreStmt) : t_StoreStmt =
  match l with
  | _ :: _ :: st :: _ -> st
  | _ -> first_stmt l

let stmt_key (st: t_StoreStmt) : text =
  match st with
  | StoreStmt_SetEx { f_key = k } -> k
  | StoreStmt_RevokeJtis { f_device = d } -> d
  | StoreStmt_Take { f_key = k } -> k
  | StoreStmt_Incr { f_key = k } -> k
  | StoreStmt_BackoffFailure { f_streak = k } -> k
  | StoreStmt_ResetBackoff { f_streak = k } -> k
  | StoreStmt_AddMember { f_key = k } -> k
  | StoreStmt_SetExNx { f_key = k } -> k
  | StoreStmt_SetExNxByte { f_key = k } -> k
  | StoreStmt_Delete { f_key = k } -> k
  | StoreStmt_Exists { f_key = k } -> k
  | StoreStmt_Ttl { f_key = k } -> k

let plan_key (b: builder) (a: key_args) : text =
  match b with
  | BLogout -> stmt_key (first_stmt (stmts_of (plan_logout a.ka_id)))
  | BSentinel ->
    stmt_key (first_stmt (stmts_of (plan_sentinel a.ka_id (mk_u64 0))))
  | BChallenge ->
    stmt_key (first_stmt (stmts_of (plan_take_challenge a.ka_id)))
  | BStreakVerify ->
    stmt_key (first_stmt (stmts_of (plan_backoff_record a.ka_scope a.ka_id)))
  | BBackoffVerify ->
    stmt_key (second_stmt (stmts_of (plan_login_limits a.ka_scope a.ka_id)))
  | BVerifyFailDev ->
    stmt_key (first_stmt (stmts_of (plan_failure_counter a.ka_scope a.ka_id)))
  | BDeviceJtis ->
    stmt_key (first_stmt (stmts_of (plan_track_jti a.ka_id a.ka_id)))
  | BChallengeIp ->
    stmt_key (first_stmt (stmts_of (plan_challenge_rate_limit a.ka_id)))
  | BRegisterIp ->
    stmt_key (first_stmt (stmts_of (plan_registration_rate_limit a.ka_id)))
  | BVerifyIp ->
    stmt_key (first_stmt (stmts_of (plan_login_limits a.ka_scope a.ka_id)))
  | BWebStartIp ->
    stmt_key (first_stmt (stmts_of (plan_start_limit a.ka_id)))
  | BWebTokenIp ->
    stmt_key (first_stmt (stmts_of (plan_token_limits a.ka_scope a.ka_id)))
  | BWebToken ->
    stmt_key (second_stmt (stmts_of (plan_token_limits a.ka_scope a.ka_id)))
  | BWebBackoff ->
    stmt_key (third_stmt (stmts_of (plan_token_limits a.ka_scope a.ka_id)))
  | BWebStreak ->
    stmt_key (first_stmt (stmts_of (plan_token_backoff_record a.ka_scope a.ka_id)))
  | BWebPollIp ->
    stmt_key (first_stmt (stmts_of (plan_poll_limit a.ka_id)))
  | BWebKeysUser ->
    stmt_key (first_stmt (stmts_of (plan_keys_limit a.ka_id)))
  | BTokenIssued ->
    stmt_key (first_stmt (stmts_of (plan_token_claim a.ka_id)))

/// Each plan's key is exactly the format it was assigned above.
let plan_key_eq (b: builder) (a: key_args) : Lemma (plan_key b a == key_of b a) =
  match b with
  | BLogout -> ()
  | BSentinel -> ()
  | BChallenge -> ()
  | BStreakVerify -> ()
  | BBackoffVerify -> ()
  | BVerifyFailDev -> ()
  | BDeviceJtis -> ()
  | BChallengeIp -> ()
  | BRegisterIp -> ()
  | BVerifyIp -> ()
  | BWebStartIp -> ()
  | BWebTokenIp -> ()
  | BWebToken -> ()
  | BWebBackoff -> ()
  | BWebStreak -> ()
  | BWebPollIp -> ()
  | BWebKeysUser -> ()
  | BTokenIssued -> ()

/// Different plans never produce the same key, under H.
let plan_key_disjoint (b1 b2: builder) (a1 a2: key_args)
  : Lemma (requires b1 <> b2 /\ key_hypothesis b1 a1 /\ key_hypothesis b2 a2)
          (ensures plan_key b1 a1 <> plan_key b2 a2) =
  plan_key_eq b1 a1;
  plan_key_eq b2 a2;
  key_of_disjoint b1 b2 a1 a2
