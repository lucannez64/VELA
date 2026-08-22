# VELA extension fuzzing (Jazzer)

Coverage-guided fuzzing for the browser extension's JavaScript, using
[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer) on Node.

## Target: `totp_shim_fuzz.js`

Two attacker-influenced surfaces:

- **`base32ToBytes`** (`src/background/background.js`) — the decode step of
  every TOTP code shown to the user; secrets arrive from sync/import.
- **`toBase64Url` / `fromBase64Url`** (`src/content/webauthn-shim.js`) —
  page-controlled strings cross these on every WebAuthn ceremony.

Oracles: determinism, output-length bound (counted *after* the
implementation's own `toUpperCase()` normalization — `ß`→`SS`, `ﬀ`→`FF`
expand one code point into two letters), URL-safe alphabet, exact byte
round trip.

## Run

```sh
cd fuzz
npm install                      # once (Jazzer)
npx jazzer --sync totp_shim_fuzz.js corpus
```

Crashes land in `./crash-*` and reproduce with
`npx jazzer --sync totp_shim_fuzz.js <file>`.

## Results

~34M executions clean. One earlier crash was a harness artifact (the length
oracle counted pre-normalization characters and under-reported `ß`→`SS`
expansion); fixed in the harness, not the product.

## Scope notes

`generateTOTP` itself is async over WebCrypto and keeps its correctness
coverage in `scripts/totp-test.cjs` (RFC 6238 vectors); its only fuzzer-
reachable input transform is `base32ToBytes`, driven here. The shim's DOM/
browser-dependent paths (`navigator.credentials` override, message bridge)
need a browser-context harness and are out of scope for Jazzer-on-Node.
