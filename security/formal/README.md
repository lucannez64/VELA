# Formal models — credential release and epoch rotation

Symbolic (Dolev-Yao) models checked with
[Tamarin](https://tamarin-prover.com/). The directory contains two independent
families: thirteen credential-release theories (`m1`–`m10`) and three vault
epoch-rotation theories (`m11`, `m11b`, `m11c`). Together they contain 119
lemmas: 114 verified and five intentionally falsified impossibility claims.

Read the assurance record for the family being changed:

- [`password-manager-ipc-tamarin-results.md`](password-manager-ipc-tamarin-results.md)
  covers credential release.
- [`rekey-tamarin-results.md`](rekey-tamarin-results.md) covers epoch rotation,
  capsule binding, and mutation authority.

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
| `m9d_captcha_artifact.spthy` | the CAPTCHA-artifact tier: browser mints the token + cookie jar, core submits the credential — the artifact is adversary-observable and that changes nothing |
| `m9b_engine_login.spthy` | the same via an embedded browser engine — **falsifies**, don't do this |
| `m9c_inprocess_sandbox.spthy` | the same via a JS runtime inside the core — keeps the credential out of the domain, but an escape takes the whole vault instead of the working set |
| `m10_full_ladder.spthy` | the deployment: M7 → M9a → M6 per origin tier |
| `m11_rekey_epoch_state_machine.spthy` | ACTIVE/FREEZING lifecycle, completeness, commit/abort/timeout, acknowledgements, and epoch invalidation |
| `m11b_rekey_capsule_binding.spthy` | authenticated `{epoch, rotation_id, rms}` capsules over an adversarial transport, including relabel/replay attempts |
| `m11c_rekey_mutation_authority.spthy` | atomic web, recovery, and enrollment authorization at the mutation boundary across epoch commits |

`password-manager-ipc-leak-graph.py` produces the quantitative companion
(`.png`): the symbolic models say *which* items can leak, the graph says *how
many*, over time.

## Re-running credential-release proofs

Needs `tamarin-prover` 1.12.0+, `maude` 3.x, and a UTF-8 locale.

```bash
export LC_ALL=C.UTF-8 LANG=C.UTF-8
for f in m1_indomain m2_se_alone m3_de_se m4_bool_naive m5_tr_originbound \
         m6_ipc_handshake m7_oneshot_assertion m8_hybrid m9a_in_core_login \
         m9b_engine_login m9c_inprocess_sandbox m9d_captcha_artifact \
         m10_full_ladder; do
  echo "== $f =="
  tamarin-prover --prove "$f.spthy" 2>/dev/null | grep -E ': (verified|falsified)'
done
```

Expected: **83 verified, 5 falsified** (88 lemmas total across the thirteen
theories). The five falsifications are intended
results, not failures — `m1`/`m2` secrecy, `m9b`'s and `m9c`'s `credential_never_leaks`,
and `m9c`'s `unused_credentials_stay_secret`
are the negative claims the ladder is built on. Any *other* falsification is a
regression.

## Re-running epoch-rotation proofs

The checked runner rejects tool warnings, incomplete results, unexpected
falsifications, and lemma-count drift:

```bash
./run-rekey-proofs.sh
```

Expected: **31 verified, 0 falsified, 0 warnings** across the three theories.
The same command is a required job in `.github/workflows/security.yml`.
