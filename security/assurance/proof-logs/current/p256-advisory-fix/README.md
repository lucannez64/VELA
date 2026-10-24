# P-256 dependency repair (local evidence)

Hosted static-scan job [120783995119](https://github.com/lucannez64/VELA/actions/runs/40064237951/job/120783995119)
failed on `915150b` for [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
published on 2026-10-23. Android resolved `p256 0.13.2 -> elliptic-curve
0.13.8 -> crypto-bigint 0.5.5`. The advisory identifies timing variability
in arithmetic intended to be constant-time and lists `crypto-bigint >=0.7.6`
as patched. No advisory exemption was added.

Android and desktop now use P-256 0.14.0, elliptic-curve 0.14.1, crypto-bigint
0.7.6 and ctutils 0.4.5. The dependent fuzz lockfile is updated too. Callers
use the new SEC1 point trait and fallible system key-generation API, returning
an error if OS randomness fails. Existing scalar, COSE, SPKI and DER formats
are preserved by these API changes.

P-256's newer digest/signature dependencies coexist with the versions required
by HKDF/Ed25519. The dependency policy exempts exactly hmac 0.12.1, sha2 0.10.9
and signature 2.2.0 from duplicate detection. Advisory checks remain active
for both versions. These exceptions do not suppress vulnerabilities.

Local commands are serialized through `~/.local/opt/vela-tools/bin/vela-heavy`
under the shared 3 GiB/no-swap/one-worker cap:

```bash
cargo test --manifest-path libVELA/vela-android-bridge/Cargo.toml --lib
cargo test --manifest-path desktopVELA/Cargo.toml -p vela-desktop-core --lib
security/run-scan.sh
```

The desktop suite adds an independent, fixed RFC 6979 A.2.5 P-256/SHA-256
vector: stored private scalar, expected COSE public coordinates, exact
signature DER, successful verification and altered-message rejection. This
checks interoperability across the dependency upgrade. It is not a timing
analysis or a proof of primitive correctness.

Results: 25 Android tests passed; 455 desktop tests passed with 8 ignored.
The Rust source scan and cargo-audit/cargo-deny checks passed across all five
workspaces scanned by `run-scan.sh`. Local semgrep was unavailable, so its
unchanged extension-JavaScript checks were skipped; the complete hosted
static-scan remains pending. The dependent fuzz manifest resolves with
`cargo metadata --locked --no-deps` after refreshing its previously stale
desktop dependency graph.

The local scan uses cargo-audit 0.22.2 and cargo-deny 0.20.2, matching the
failed hosted job's tool versions, with a freshly fetched advisory database.
The cargo-audit release archive was checked against the GitHub release
asset's SHA-256 digest:
`7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428`.

This evidence is from the local working tree. Hosted reproduction of the
repair is pending. No whole-system proof or side-channel assurance is claimed;
cryptographic primitive implementations remain inside the trusted boundary.
