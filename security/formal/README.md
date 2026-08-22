# Formal models — the decide → unwrap → consume flow

Symbolic (Dolev-Yao) models of VELA's credential-release flow, checked with
[Tamarin](https://tamarin-prover.com/). Eleven theories, `m1`–`m10`, building a
ladder from "in-domain checks are impossible" up to the three-tier deployment
the desktop should implement.

**Read [`password-manager-ipc-tamarin-results.md`](password-manager-ipc-tamarin-results.md) first** — it
states every lemma, its verdict, what each model does and does not certify, and
the corrections made after review.

| File | What it models |
|---|---|
| `m1_indomain.spthy` | in-domain checks only — **falsifies**, the impossibility result |
| `m2_se_alone.spthy` | hardware key storage without a decision escape — **falsifies** |
| `m3_de_se.spthy` | human approval + hardware key: the working-set bound |
| `m4_bool_naive.spthy` | an unbound boolean approval — replayable, worthless |
| `m5_tr_originbound.spthy` | origin-bound signature: zero persistent value |
| `m6_ipc_handshake.spthy` | the real browser↔desktop handshake: pairing, per-client keys, grant lifecycle, browser-spawn gate (no capability file) |
| `m7_oneshot_assertion.spthy` | passkey-shaped one-shot assertion — below the working-set floor |
| `m8_hybrid.spthy` | M7 for passkey origins + M6 for legacy, airtight mode split |
| `m9a_in_core_login.spthy` | in-core login for plain-form sites — credential never enters the domain |
| `m9b_engine_login.spthy` | the same via an embedded browser engine — **falsifies**, don't do this |
| `m9c_inprocess_sandbox.spthy` | the same via a JS runtime inside the core — keeps the credential out of the domain, but an escape takes the whole vault instead of the working set |
| `m10_full_ladder.spthy` | the deployment: M7 → M9a → M6 per origin tier |

`password-manager-ipc-leak-graph.py` produces the quantitative companion
(`.png`): the symbolic models say *which* items can leak, the graph says *how
many*, over time.

## Re-running

Needs `tamarin-prover` 1.12.0+, `maude` 3.x, and a UTF-8 locale.

```bash
export LC_ALL=C.UTF-8 LANG=C.UTF-8
for f in m1_indomain m2_se_alone m3_de_se m4_bool_naive m5_tr_originbound \
         m6_ipc_handshake m7_oneshot_assertion m8_hybrid m9a_in_core_login \
         m9b_engine_login m9c_inprocess_sandbox m10_full_ladder; do
  echo "== $f =="
  tamarin-prover --prove "$f.spthy" 2>/dev/null | grep -E ': (verified|falsified)'
done
```

Expected: **73 verified, 3 falsified**. The three falsifications are intended
results, not failures — `m1`/`m2` secrecy, `m9b`'s and `m9c`'s `credential_never_leaks`,
and `m9c`'s `unused_credentials_stay_secret`
are the negative claims the ladder is built on. Any *other* falsification is a
regression.
