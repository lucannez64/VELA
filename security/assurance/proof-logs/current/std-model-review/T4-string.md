## T4: String, str, UTF-8 and format!

Reviewed 2026-11-03. Sources: hax 0.3.7 `proof-libs/fstar/core/Alloc.String.fst`,
`Core_models.Str.fsti`, `Alloc.Fmt.fst`, `Core_models.Fmt.fsti`,
`Core_models.Fmt.Rt.fsti`, `Core_models.Hint.fsti`,
`proof-libs/fstar/rust_primitives/Rust_primitives.String.fsti`,
`Rust_primitives.Char.fsti`; the F* ulib `FStar.Char.fsti` and
`FStar.String.fsti`; the local replacement model
`libVELA/vela-crypto/proofs/fstar/models/Alloc.String.fst` (identical to hax's
file plus `impl_String__as_str`, see `diff`); the Rust sources
`libVELA/vela-crypto/src/share_envelope.rs`,
`serverVELA/vela-session-policy/src/{store.rs,challenge.rs}` and the server call
sites. Use counts are from `../model-contract-inventory/inventory.json`.

Two layers must be kept apart before any verdict:

* **F* `string` is a sequence of Unicode scalar values, not bytes.**
  `FStar.Char.char` is a primitive "UTF-8 character" (`FStar.Char.fsti:19-33`)
  whose `char_code` excludes the surrogate block and everything above
  `0x10FFFF` (`FStar.Char.fsti:38`) — exactly Rust's `char` (a Unicode scalar
  value). `FStar.String.length`/`strlen` "counts the number of utf8 values in a
  string. It is not the byte length of a string" (`FStar.String.fsti:49-55`).
* **Rust `String`/`str` are UTF-8 byte buffers.** `.len()` is bytes;
  `&s[a..b]` is a *byte* range that must land on char boundaries; `==` is
  byte equality.

Because UTF-8 is injective, and every F* `string` is a sequence of scalar
values, mapping a Rust `String` to its sequence of chars is a bijection onto F*
`string`. Equality, concatenation, one-char append and emptiness are preserved
by that bijection; **length and indexing are not**. That one fact decides every
verdict below.

| Model (uses) | Definition | Rust semantics | Verdict |
|---|---|---|---|
| `Alloc.String.t_String`, `String` (889, 44) | single constructor `String : string -> t_String` (`models/Alloc.String.fst:6`; hax `core/Alloc.String.fst:6`) | `String`, an owned UTF-8 buffer | Faithful for what the corpus does with it: equality, `new`, `as_str`, and as an opaque table/key type. Capacity, pointers and the `u8` view are absent, and no proof reads them. Content equality is faithful by the UTF-8 bijection. The byte view is deliberately unmodelled (see the `len`/`pop` rows) |
| `impl_String__new` (3) | `let impl_String__new _ = String ""` (`:8`) | `String::new()` — the empty string | Faithful |
| `impl_String__as_str` (14) | `let impl_String__as_str (self: t_String) : string = self._0` (`:47-49`). Local addition: absent from hax's file (`diff` shows it as the only change) | `String::as_str(&self) -> &str`, a `&str` over the same bytes | Faithful. The borrow is erased, the char sequence is the same value. This is what lets the extracted ensures clauses be exactly the Rust ones: `header.sender_user_id.as_str() == share.header.sender_user_id.as_str()` at `libVELA/vela-crypto/src/share_envelope.rs:104-112`, extracted to `impl_String__as_str ... =. impl_String__as_str ...` at `Vela_crypto.Share_envelope.fst:48-57` |
| `impl_String__push_str` (0 outside the model) | `String (str_concat self._0 other)` (`:10-12`) | `push_str(&str)` appends the UTF-8 bytes of `other` | Faithful *if* `str_concat` is `^` (the library does not say so, next row). Unreachable: nothing outside `models/Alloc.String.fst` calls it (`git ls-files '*.fst'` grep) |
| `impl_String__push` (0 outside the model) | `String (str_concat self._0 (str_of_char c))` (`:14-21`) | `push(char)` appends the 1–4 byte UTF-8 encoding of `c` | Faithful under the same caveat. Unreachable |
| `impl_String__pop` (0 outside the model) | `l = impl_str__len self._0`; if `l > 0` then `(str_sub self._0 0 (l-1), Some (str_index self._0 (l-1)))` (`:23-45`) | `pop()` removes and returns the **last `char`** (its whole 1–4 byte encoding); `len()` is **bytes** | **Gap (latent).** The arithmetic is only right if `impl_str__len` counts chars, but the symbol is the model of `str::len`, which counts bytes. For a string ending in a multi-byte char, Rust pops one char while the model slices at a non-boundary byte and returns the final byte as a `char`. `pop` is not reachable from the corpus, so no proof is wrong today |
| `Rust_primitives.String.str_concat` (2) | `val str_concat: string -> string -> string` (`Rust_primitives.String.fsti:5`) — no body, no spec | `push_str` / `&str + &str`: byte concatenation, i.e. `^` on the char-sequence view | **Over-approximate / undefined**: F* knows nothing about it, not even length-addition or associativity. Used only by the unreachable `push`/`push_str` models, so nothing depends on the gap today. This is the symbol O4 needs specified |
| `Rust_primitives.String.str_of_char` (1) | `val str_of_char: FStar.Char.char -> string` (`:7`), undefined | The one-`char` string (`char::encode_utf8`) | Over-approximate / undefined; unreachable outside `push` |
| `Rust_primitives.String.str_sub` (1) | `val str_sub: string -> usize -> usize -> string` (`:9`), total, undefined, unit of the indices unstated | `&s[a..b]`: **byte** range, both ends must be char boundaries, panics otherwise | **Over-approximate**: returns a string for every pair, while Rust panics on a non-boundary or out-of-range pair. The index unit (chars vs bytes) is not fixed by the type. Unreachable outside `pop` |
| `Rust_primitives.String.str_index` (1) | `val str_index: string -> usize -> FStar.Char.char` (`:11`), total | `s.chars().nth(i)` (char index, `None` out of range) or `s.as_bytes()[i]` (byte index, panics) | **Over-approximate**: total, so it silently returns some char past the end. Index unit unstated. Unreachable outside `pop` |
| `Core_models.Str.impl_str__len` (1) | `val impl_str__len: string -> usize` (`Core_models.Str.fsti:4`), undefined | `str::len()`: **bytes** | **Gap as used by `pop`** (which needs a char count); undefined on its own. Nothing else measures a string with it |
| `Core_models.Str.impl_str__as_bytes` (0) | `val impl_str__as_bytes: string -> t_Slice u8` (`:5`) | `str::as_bytes()` | Unused. It is the principled route to a byte model: one could state `impl_str__len s == Slice.impl__len (impl_str__as_bytes s)` |
| `Rust_primitives.Char.char` (1 file) | `type char : eqtype = FStar.Char.char` (`Rust_primitives.Char.fsti:5`) | `char`, a Unicode scalar value | Faithful: both sides exclude surrogates and values above `U+10FFFF` |
| `=` / `=.` on `t_String` and on `string` (used in `admission_facts`, the share/rekey/session store models, `ek_present_b`) | `let (=.) = (=)` (`rust_primitives/Rust_primitives.Integers.fsti:441`), so `=.` on strings is F* equality of char sequences | `String`/`str` `PartialEq`: byte equality | Faithful by the UTF-8 bijection. Note the Rust being modelled is literally `.as_str() == ...` (`share_envelope.rs:104-112`), so the comparison is `str == str`, not `String == String` |

### format!

All 30 `format!` call sites that reach F* are in
`serverVELA/vela-session-policy/src/store.rs`, extracted to
`serverVELA/vela-session-policy/proofs/fstar/extraction-store/Vela_session_policy.Store.fst`.
No other extracted module builds a key with `format!`: the builders in
`vela-enrollment-policy`, `vela-recovery-policy` and `vela-rekey-policy` are
`#[cfg(not(hax))]`, so hax never sees them and their keys arrive as opaque
`text` parameters.

| Model (uses) | Definition | Rust semantics | Verdict |
|---|---|---|---|
| `Core_models.Fmt.t_Arguments` (29) | single constructor `Arguments : Prims.unit -> t_Arguments` (`Core_models.Fmt.fsti:33`) | `fmt::Arguments`: the literal pieces plus the arguments | **Gap**: exactly one inhabitant, so it carries neither pieces nor arguments |
| `Core_models.Fmt.Rt.t_Argument` (29) | `type t_Argument = { f_ty:t_ArgumentType }`, `val t_ArgumentType:eqtype` (`Core_models.Fmt.Rt.fsti:6-8`) | `fmt::Argument`: the value to format, type-erased `&dyn Display` | **Gap**: the value is not in the model, only an abstract type tag |
| `Core_models.Fmt.Rt.impl__new_display` (41), `impl_1__new_v1` (29) | `val impl__new_display (#v_T) (x:v_T) : Prims.Pure t_Argument l_True (fun _ -> l_True)` (`:10-11`); `val impl_1__new_v1 ... : Prims.Pure t_Arguments l_True (fun _ -> l_True)` (`:25-26`) | Wrap one value for `{}`; assemble `Arguments` from the piece array and the argument array | **Gap**: no specification at all, and the result type erases the payload |
| `Alloc.Fmt.format` (29), underlying `format'` | `assume val format': args:Core_models.Fmt.t_Arguments -> Alloc.String.t_String` then `unfold let format = format'` (`core/Alloc.Fmt.fst:6-10`) | `format!` with `{}`: concatenation of the pieces and the `Display` of each argument, and `Display for str/String` is the identity | **Gap**, and sharper than "opaque": because `t_Arguments` has a single inhabitant, `format a == format b` for **every** pair of call sites, by congruence after `a == b == Arguments ()`. Every `format!` in the corpus therefore denotes the *same* F* `String` |
| `Core_models.Hint.must_use` (29) | `val must_use (#v_T) (value:v_T) : Prims.Pure v_T l_True (ensures fun res -> res == value)` (`Core_models.Hint.fsti:14-20`) | `#[must_use]` is a compile-time lint with no runtime effect; `hax_lib` maps it to the identity | Faithful. The `ensures` pins the result to the argument, so the missing body cannot be misread. This is the only abstract symbol of the eight under T4 whose meaning is fully fixed |

The literal pieces *are* visible at each call site — e.g. `["jti:revoked:"]` at
`Vela_session_policy.Store.fst:330-334` and `["rl:streak:verify:"; ":"]` at
`:591-638` — but they are passed to an abstract function whose result type
(`t_Arguments`) erases them, so no information reaches the result.

Consequence already visible in the proofs: `plan_token_release_shape` proves
`(StoreStmt_Delete { f_key = k }) -> k == claim_marker_key sess` by `()` where
`k` is the release plan's `format!("web_session:token_issued:{}", session)` and
`claim_marker_key sess` is the claim plan's `format!` with the same string
(`Vela_session_policy_store_lemmas.fst:1043,1094-1099`). The same happens for
`plan_token_sentinel_shape` versus `sentinel_key`
(`:1087-1091`, `:61-62`). Both statements are **true in Rust**, because the two
Rust keys are byte-identical. But the F* proof does not use the prefixes: it
would prove the same equality if `plan_token_release` used
`format!("jti:revoked:{}", session)`. No lemma in the corpus asserts an
equality across two *different* prefixes, so nothing false is proved today; the
technique just does not transfer.

### Byte length and byte indexing

No proof measures or indexes a string by bytes through a model that counts
characters. Evidence:

* The only uses of `impl_str__len`, `str_index` and `str_sub` are inside
  `impl_String__pop` (`models/Alloc.String.fst:23-45`), which no other tracked
  `.fst` file calls (`git ls-files '*.fst' | xargs grep -n 'impl_String__pop\|str_index\|str_sub\|impl_str__len'`).
  `impl_str__as_bytes` has no uses at all.
* Two proofs do measure a `text`, and both measure **characters**, deliberately:
  * `let text_len (t: text) : nat = FStar.String.length t._0`, comment "`LENGTH(ciphertext)` over the base64 text the handlers store, which is ASCII, so its byte length is its string length" — `serverVELA/vela-rekey-policy/proofs/fstar/executor-lemmas/Vela_rekey_policy_executor_model.fst:741-743`, used by `sum_chunk_len_at` (`:775-780`), `sum_oram_len_at` (`:783-788`) and `sum_oram_len_all` (`:791-795`).
  * `let capsule_text_len (r: inbox_row) : nat = FStar.String.length r.ib_capsule._0`, same comment — `serverVELA/vela-share-policy/proofs/fstar/store-lemmas/Vela_share_policy_store_model.fst:533-536`, used by `sum_capsule_len` (`:549-552`) and `inbox_pair_bytes`/`inbox_total_bytes` (`:560-568`), consumed by `Vela_share_policy_handler_lemmas.fst:228-234,248-296`.
  Both are models of SQL `LENGTH(x)`. The server runs turso/SQLite
  (`serverVELA/vela-server/Cargo.toml:45`), where `LENGTH` of a TEXT value is
  the number of characters, so the F* char count is the faithful reading. The
  stored values are base64 ASCII — conformance schema `capsule TEXT NOT NULL`
  and `TursoValue::Text(...)` at `serverVELA/vela-server/src/share/conformance.rs:157,173,424,436`,
  writes through `db::encode_b64` at `share/mod.rs:233,680`,
  `vault/chunk.rs:266,310`, `vault/oram.rs:286,313` — and the Rust mirror of the
  model computes the same number with `text.chars().count()`
  (`serverVELA/vela-rekey-policy/src/executor_model.rs:940-943`). So the
  character count is the right count in both directions, and the ASCII
  hypothesis that makes chars equal bytes holds at every write site. It is
  stated in a comment, not proved; if a non-ASCII value ever reached those
  columns, the model would under-count bytes (`chars <= bytes`), which would
  make a proved upper bound unsound. Record that as a hypothesis, not a gap:
  no such value exists in the code I read.

### UTF-8 validity (`from_utf8`)

No extracted module calls `String::from_utf8`, `from_utf8_lossy`,
`std::str::from_utf8` or `impl_str__as_bytes`: no tracked `.fst` file contains
`from_utf8` at all, and the only UTF-8 tokens are the observation field
`f_utf8_valid` and the `PairingFailure_PackageNotUtf8` constructor. The
UTF-8-sensitive decisions are:

* `classify_redeem (outcome) (utf8_valid: bool)` copies the flag into
  `RedeemObservation_Present f_utf8_valid`
  (`serverVELA/vela-enrollment-policy/proofs/fstar/extraction-executor/Vela_enrollment_policy.Executor.fst:560-565`)
  and the pairing driver turns it into `PairingFailure_PackageNotUtf8`
  (`extraction-pairing-driver/Vela_enrollment_policy.Pairing_driver.fst:700-703`).
  The boolean is a **parameter**, so the model proves the branch for both
  values; the predicate itself is computed outside the proved fragment by
  `std::str::from_utf8(bytes).is_ok()`
  (`serverVELA/vela-server/src/device/invitation.rs:155-158`). Verdict:
  faithful as a parameterized model, with UTF-8 validation as a trusted
  boundary — the proof says "if the server says valid, the driver completes",
  not "these bytes are valid UTF-8".
* `String::from_utf8` in `libVELA/vela-crypto/src/share_envelope.rs:382`
  (`open_signed_item`) is outside the hax include list
  (`libVELA/vela-crypto/verify-share-facts-fstar.sh:10`), so it never reaches
  F*.
* `String::from_utf8_lossy` in
  `serverVELA/vela-session-policy/src/store.rs:551-553`
  (`challenge_tag_text`) is `#[cfg(not(hax))]`; the tag reaches F* as an
  opaque `text` argument.

**Result: no gap in code any proof can currently reach; one latent gap and one
`format!` gap; the remaining string primitives are unspecified but
unreachable.**

* Faithful: `t_String`, `impl_String__new`, `impl_String__as_str`, the `char`
  type, string equality, and the parameterized `f_utf8_valid` flag. The crypto
  proofs only ever compare strings
  (`share_envelope.rs:104-112`), which the char-sequence model reproduces
  exactly.
* Latent gap: `impl_String__pop` treats `impl_str__len` as a char count while
  the symbol models `str::len` (bytes). It is unreachable; the fix, when it
  becomes reachable, is to model `pop` over `str_index`/`str_sub` on chars and
  keep `impl_str__len` in bytes.
* Over-approximate and undefined: `str_concat`, `str_of_char`, `str_sub`,
  `str_index`, `impl_str__len`, `impl_str__as_bytes` are `val`s with no
  specification. `str_sub`/`str_index` also swallow the panics Rust raises on
  a bad range or index. Sound (more behaviours than Rust) and unreachable.
* Gap: `format!`. `t_Arguments`/`t_Argument` erase both the pieces and the
  argument values, and `format'` is an `assume val`, so every `format!` in the
  corpus denotes one and the same string. Key inequality is unprovable and key
  equality is free, which is why the store key builders are opaque to F* and
  why O4 cannot state injectivity until this is fixed. Two existing lemmas rely
  on the free equality and are true in Rust by coincidence of the prefixes.

`format'` is worth adding to the inventory's trust list: FINDINGS item 1 says no
*used* library symbol is `assume val`, which is true, but `Alloc.Fmt.format` is
defined over the `assume val format'` in the same library, so the corpus does
reach an axiom, through one definition.

T7 differential tests should pin: `String::len` on a multi-byte string
(bytes), `str::chars().count()` (chars), `pop` over `"é"`, the exact bytes
of two `format!` keys, and `from_utf8` on a truncated multi-byte sequence
(where the F* side only ever sees the `f_utf8_valid` boolean).

### O4 input

O4's completion criterion is "every store key builder (`rl:*`, `challenge`,
`grant`, ...) is injective and namespaces are disjoint". This subsection lists
the keys, what an F* `format!` model must provide, and the arithmetic the
injectivity and disjointness proof needs. No Rust was changed.

**The 30 call sites, 18 distinct key formats** (all in
`serverVELA/vela-session-policy/src/store.rs`; all `{}` on `String`, so the
`Display` is the identity and the key is a plain concatenation):

| # | Key format | Builder (`store.rs:line`) | Arguments |
|---|---|---|---|
| 1 | `jti:revoked:{}` | `plan_logout` (:443) | `jti` |
| 2 | `device:revoked:{}` | `plan_sentinel` (:453), `plan_lockout_device` (:467), `plan_lockout_web_session` (:479), `plan_token_sentinel` (:885) | `device` / `session` |
| 3 | `challenge:{}` | `plan_take_challenge` (:559), `plan_store_nonce` (:638) | `challenge` |
| 4 | `rl:streak:verify:{}:{}` | `plan_backoff_record` (:572), `plan_reset_login_streak` (:590) | `ip`, `device` |
| 5 | `rl:backoff:verify:{}:{}` | `plan_backoff_record` (:573), `plan_login_limits` (:790), `plan_reset_login_streak` (:591) | `ip`, `device` |
| 6 | `rl:verify:fail:dev:{}:{}` | `plan_failure_counter` (:581) | `ip`, `device` |
| 7 | `device:jtis:{}` | `plan_track_jti` (:617) | `device` |
| 8 | `rl:challenge:ip:{}` | `plan_challenge_rate_limit` (:628) | `ip` |
| 9 | `rl:register:ip:{}` | `plan_registration_rate_limit` (:647) | `ip` |
| 10 | `rl:verify:ip:{}` | `plan_login_limits` (:785) | `ip` |
| 11 | `rl:websession:start:ip:{}` | `plan_start_limit` (:798) | `ip` |
| 12 | `rl:websession:token:ip:{}:{}` | `plan_token_limits` (:810) | `ip`, `session` |
| 13 | `rl:websession:token:{}` | `plan_token_limits` (:815) | `session` |
| 14 | `rl:backoff:websession:token:{}:{}` | `plan_token_limits` (:820), `plan_token_backoff_record` (:830), `plan_token_backoff_reset` (:838) | `ip`, `session` |
| 15 | `rl:streak:websession:token:{}:{}` | `plan_token_backoff_record` (:829), `plan_token_backoff_reset` (:837) | `ip`, `session` |
| 16 | `rl:websession:poll:ip:{}` | `plan_poll_limit` (:845) | `ip` |
| 17 | `rl:websession:keys:user:{}` | `plan_keys_limit` (:854) | `user` |
| 18 | `web_session:token_issued:{}` | `plan_token_claim` (:875), `plan_token_release` (:894) | `session` |

**What a model of `format!` needs.** Either route gives F* a term it can see
through. (A) leaves `store.rs` and the extraction untouched and replaces the
hax formatting modules with local models; (B) touches only `store.rs` and adds
one small local string model. I recommend (B).

(A) *Model `format!` for the `{}`-only case.* Then:
1. `Core_models.Fmt.t_Arguments` must carry data, e.g.
   `type t_Arguments = | Arguments : pieces:list string -> args:list string -> t_Arguments`
   (every argument in the corpus is a `String`, so `list string` suffices).
2. `impl_1__new_v1` must return the piece array and the argument array;
   `impl__new_display x` must be `x` (Display for `str` is the identity).
3. `Alloc.Fmt.format` must be *defined* (`format'` deleted, not assumed) as the
   piece/argument fold: `format (Arguments [] []) = ""`,
   `format (Arguments [q] []) = q`, and in general
   `format (Arguments ps as) = concat (interleave ps as)`, i.e. exactly what
   `format!` does for `{}`.
4. A lemma that `format` of a singleton piece list and a singleton string
   argument is `piece ^ arg`, so each of the 18 keys reduces to a `str_concat`
   term.

(B) *Replace `format!` with an extracted concatenation* (recommended; smallest
trusted base). In each of the 18 builders, build the key with the two `String`
operations the local model already defines:

```rust
// today:  key: format!("device:revoked:{}", device),
let mut key = String::new();
key.push_str("device:revoked:");   // prefix is a literal
key.push_str(&device);             // exactly one id per `{}`
```

which extracts to `str_concat (str_concat (impl_String__new ()) "device:revoked:") device`
and reduces (once `str_concat` is defined as `^` and `impl_String__new () = ""`)
to `"device:revoked:" ^ device`. The key bytes are unchanged, and the existing
`render_store` unit tests already pin every key
(`store.rs:2041-2060` and following). What the F* side then needs:

* a local replacement for `Rust_primitives.String` (same pattern as
  `libVELA/vela-crypto/proofs/fstar/models/Alloc.String.fst`) that
  *defines* `str_concat s1 s2 = s1 ^ s2` and
  `str_of_char c = FStar.String.string_of_char c`,
  instead of leaving them as bare `val`s;
* no new axiom: `FStar.String.concat_length` and `concat_injective`
  (`FStar.String.fsti:117-121,133-148`) then apply directly, and
  `concat_injective` needs one of the two lengths, which a literal prefix
  supplies.

**What the injectivity proof needs beyond the model.** With keys of the form
`p ^ a` and `p ^ a1 ^ ":" ^ a2`:

* one-argument builders: `p ^ a = p ^ b -> a = b`, immediate for `^`;
* two-argument builders: the split is unique when the **last** argument
  contains no `:` (take the last `:` in the key);
* across builders: compare the 18 literal prefixes. Exactly one pair is
  prefix-related — `rl:websession:token:` (13) is a prefix of
  `rl:websession:token:ip:` (12) — and the bridge case needs
  `session = "ip:" ^ ip ^ ":" ^ session'`, impossible while `session` has no
  `:`.

So O4's injectivity statement should carry the hypothesis **H: every argument
in the final position of a multi-argument key, and the sole argument of builder
13, is colon-free.** H is what the Rust sources actually give:

| Argument | Source | Alphabet |
|---|---|---|
| `jti` | `Uuid::new_v4().to_string()`, `serverVELA/vela-server/src/auth/token.rs:119` | hex + `-`, no `:` |
| `device` / `session` | `Uuid::to_string()`, e.g. `serverVELA/vela-server/src/web_session/mod.rs:1302` | hex + `-`, no `:` |
| `user` | `Uuid` (accounts) | hex + `-`, no `:` |
| `challenge` | standard base64 of 32 random bytes, `serverVELA/vela-server/src/auth/challenge.rs:28,207` | `A-Za-z0-9+/=`, no `:` |
| `ip` | `IpAddr::to_string()`, `serverVELA/vela-server/src/net.rs:62-88` (IPv4 or IPv6) | **may contain `:`** — hence H must be about the final argument only, and `ip` is never last in builders 4, 5, 6, 12, 14, 15 |

Two scope notes for O4:

* Several key builders live **outside** the proved fragment under
  `#[cfg(not(hax))]`: `vela-enrollment-policy/src/executor.rs:40-60` and
  `:543-575`, `vela-recovery-policy/src/rate_store.rs:58-108`,
  `webauthn_store.rs:237,243`, `redemption_store.rs:143`,
  `vela-rekey-policy/src/executor.rs:850`. F* sees only their result as an
  opaque `text` parameter, so it currently proves nothing about them — sound,
  but also nothing about their injectivity. O4 must either lift the
  `cfg(not(hax))` gate so those builders are extracted, or prove their
  injectivity separately.
* `challenge:{}` is built in two crates — `store.rs:559,638` and
  `vela-enrollment-policy/src/executor.rs:58` — over one shared keyspace. Same
  shape, so no new injectivity obligation, but the freshness of the two nonce
  sources is a separate question that the key model does not answer.
