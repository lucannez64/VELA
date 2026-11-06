# T8 fixes re-checked on the merged tree (parent integration, 2026-11-05)

Both fixes merged onto origin/t3/external-security-assurance (share fix at 44cc290 on 15fc14f; rekey fix on 72b5d52; the later 7fcc698 only adds lld to the proof image), then re-run on the box via vela-heavy with `security/assurance/z3-seed/verify-fstar-seeded.sh`:

```
share-facts seed 0 exit 0
share-facts seed 1 exit 0
share-facts seed 2 exit 0
share-facts seed 3 exit 0
rekey driver seed 0 exit 0 254s
rekey driver seed 1 exit 0 266s
rekey driver seed 2 exit 0 289s
rekey driver seed 3 exit 0 240s
rekey core seed 0 exit 0 2375s
```

share-facts = `libVELA/vela-crypto/verify-share-facts-fstar.sh` (--query-stats); rekey driver = `serverVELA/vela-rekey-policy/verify-fstar-rekey-driver.sh` (--query-stats); rekey core = `serverVELA/vela-rekey-policy/verify-fstar.sh core` (23 modules verified). Per-fix evidence: [share-envelope-inverse](share-envelope-inverse/README.md), [rekey-driver](rekey-driver/README.md).
