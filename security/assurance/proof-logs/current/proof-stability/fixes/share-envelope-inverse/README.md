# Share-envelope inverse: seed-stable `frame_body_frame` (plan step T8)

Module: `libVELA/vela-crypto/proofs/fstar/share-envelope-inverse/Vela_crypto_share_envelope_inverse.fst`
(O14a). Gate: `libVELA/vela-crypto/verify-share-facts-fstar.sh`. Base commit
`f3e27569`. Every run below went through `vela-heavy` on the build box, cold
(`VELA_FSTAR_CACHE=0`), with `--query_stats`, at the gate's `--z3rlimit 100`.

## Finding

Hosted proof-stability run 41925059881, job "share-facts, seed 2" (as quoted
in the T8 brief; the hosted log itself is not in this directory):

    Vela_crypto_share_envelope_inverse.fst(577,2-584,4) Query-stats
    (Vela_crypto_share_envelope_inverse.frame_body_frame, 3) failed
    {reason-unknown=unknown because canceled} ... rlimit 100 (used rlimit 100.000)

Reproduced locally on the base proof:

- [before-seed2.log](before-seed2.log): the full gate under seed 2 fails the
  same query, `frame_body_frame #3`, 100.000 of 100 used, after 255 s
  (`exit=1`).
- [before-module-seed0.log](before-module-seed0.log),
  [seed 1](before-module-seed1.log), [seed 3](before-module-seed3.log): the
  base module checked alone fails the same query under seeds 0, 1 and 3 too
  (100.000 used; the failing query ran 147 s, 289 s and 376 s). The hosted
  gate passed seeds 0, 1 and 3 (per the brief), so the query was on the edge
  under every seed, not just seed 2. These three runs are a scratch harness,
  not the gate, and their logs do not record the command. It was, from
  `libVELA/vela-crypto` with the tracked extraction files, via `vela-heavy`:

      fstar.exe --z3seed SEED --cmi --query_stats --split_queries always \
        --warn_error -331 --z3rlimit 100 \
        --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
        --cache_dir <empty scratch dir> <the gate's seven --include paths> \
        proofs/fstar/share-envelope-inverse/Vela_crypto_share_envelope_inverse.fst

  i.e. the gate's options with only the inverse module on the command line,
  so F* verifies that module and lax-checks its dependencies (no other module
  issued an SMT query in these runs). (The
  "Unable to load ... checked" warnings at the top of these logs come from the
  empty scratch cache dir.)

## Cause

`frame_body_frame` proved `frame_body (frame_spec f item sig) 4 4699 ==
Some (body_spec f item)` in one query that contained the concrete nine-field
`body_spec` term, `lp sig`, the `.[]` range-index unfolding of `frame_body`,
`usize` subtraction, and the module-wide `append_assoc_smt` SMT pattern
(which fires on every left-nested append, and each `lp x` followed by more
bytes is one). Z3 had to find the slice equation inside that context; how
fast it did depended on the seed.

## Change

Only the `frame_body` part of the proof changed; no statement changed, no
rlimit was raised, nothing was admitted.

- New option scope for the `frame_body` facts:
  `--fuel 1 --ifuel 1 --using_facts_from '* -Vela_crypto_share_envelope_inverse.append_assoc_smt'`.
  None of these proofs re-associates appends. `share_frame_spec_frame` and
  everything after it keep their previous `--fuel 2 --ifuel 2` scope.
- `frame_body_slice`: `frame_body input p t` is `Some (Seq.slice input p (|input| - t))`
  for any input with `p + t <= |input|` (the range-index and `usize`
  subtraction reasoning, done once on an abstract slice; uses `usize_sub_value`).
- `frame_body_append3`: `frame_body (a || (b || c)) |a| |c| == Some b` for
  abstract `a b c` (with `slice_append_right3_mid`).
- `signature_trailer_value`: `v signature_trailer = |lp sig|` for a 4691-byte
  signature.
- `frame_body_marker_trailer`: the marker/trailer instance over an abstract
  `body`.
- `frame_body_frame` is now `frame_len_unfold f item sig;
  frame_body_marker_trailer (body_spec f item) sig`, so the solver never
  unfolds `body_spec` there.

## After: the full gate under five seeds

One run after another, `security/assurance/z3-seed/verify-fstar-seeded.sh
--query-stats SEED libVELA/vela-crypto/verify-share-facts-fstar.sh`:

| Seed | Result | Time | Log |
|---|---|---|---|
| 0 (pass-through) | PASS | 457 s | [after-seed0.log](after-seed0.log) |
| 1 | PASS | 384 s | [after-seed1.log](after-seed1.log) |
| 2 | PASS | 426 s | [after-seed2.log](after-seed2.log) |
| 3 | PASS | 438 s | [after-seed3.log](after-seed3.log) |
| 4 | PASS | 429 s | [after-seed4.log](after-seed4.log) |

Each log ends with `exit=0`, lists all eight modules as verified (including
`Vela_crypto_share_envelope_inverse`), and the seeded runs show the shim's
`exec ... --z3seed <n>` lines. The gate's regenerated extraction files were
byte-identical to the tracked ones after the runs (`git status` clean for
them).

## Used rlimit per query (of 100), this module

Before = the four base runs above (gate seed 2, module-only seeds 0, 1, 3);
after = the five gate runs. Max over the runs; every query not listed used
less than 2.1 after the change.

| Query | Before (max) | After (max) | After, seeds 0/1/2/3/4 |
|---|---|---|---|
| `frame_body_frame #3` | **100.000, failed** (all 4 runs) | 0.036 | |
| `frame_body_frame` (any query) | 100.000 | 0.362 (`#2`) | 0.362 each |
| `frame_body_*` helpers (any query) | n/a (new) | 0.307 (`frame_body_append3 #13`) | |
| `split_lp_append #4` (unchanged) | 40.926 | 40.926 | 40.670 / 40.398 / 40.926 / 38.915 / 40.833 |
| `body_len_unfold #1` (unchanged) | 19.213 | 19.242 | 19.186 / 19.184 / 19.169 / 19.212 / 19.242 |
| `push_share_body_spec #19` (unchanged) | 5.300 | 5.285 | |
| `decode_head8_prefixed #12` (unchanged) | 3.983 | 3.982 | |

After the change no query in the module uses more than 50 (max 40.926,
`split_lp_append #4`), so no other proof needed restructuring. The same holds
for the whole gate: the highest query of any module in the five logs is that
same 40.926.

The before runs stop at the failing query, so the queries after
`frame_body_frame` (`share_frame_spec_frame`, the parser composition and
injectivity lemmas) have no before figure; after, the largest of them is
`share_frame_spec_frame #13` at about 1.6.

Each log also records eight failed first attempts in the unchanged
`first8_list_index` (`incomplete quantifiers` at fuel 2/ifuel 1, then retried
at higher fuel by F*, and then accepted). They are identical in the base log
and are not part of this finding.

## Follow-ups

- `split_lp_append #4` is the module's largest query (about 41 of 100, 40-65 s).
  It is below the 50 target under seeds 0-4, but it is the next candidate if
  more headroom is wanted.
