# Security Policy

VELA is a local-first, zero-knowledge password vault. Security is the whole
product: the server is designed never to see vault plaintext, the Root Master
Seed (RMS), identity private keys, or browser-extension secrets
(`SPEC.md` §9). We take reports seriously and would rather hear about a
suspected flaw early, even if it turns out to be out of scope.

## Supported versions

VELA is pre-1.0. Every component ships from `main` through CI with a
commit-derived version (`0.1.<commit-count>`), so **only the latest release of
each component receives security fixes**. There is no long-term-support branch
yet; see `ROADMAP.md`.

| Component | Path | Distribution |
| :--- | :--- | :--- |
| Sync/auth server | `serverVELA/` | Docker / source / Nixpacks |
| Desktop app (GPUI + Tauri) | `desktopVELA/` | MSI, NSIS, `.deb`, `.rpm` |
| Android app | `androidVELA/` | signed release APK |
| iOS app | `iosVELA/` | source / Xcode |
| Browser extension + native host | `extension/` | XPI / Chromium zip |
| Shared core & crypto | `libVELA/` | crates |
| Ephemeral web vault | `webVELA/` | served by the server |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a
suspected vulnerability.** Use one of the private channels below.

- **Preferred — GitHub private vulnerability reporting:**
  <https://github.com/lucannez64/VELA/security/advisories/new>
  This opens a private advisory visible only to you and the maintainers.
- **Email:** not yet available — a security mailbox will be published once a
  canonical project domain exists. Until then, use the GitHub advisory link
  above.

> Maintainer note: enable **Settings → Code security → Private vulnerability
> reporting** for the repository so the advisory link above accepts reports.

### What to include

1. The component and version/commit affected (`git rev-parse HEAD` is ideal).
2. A description of the impact — in particular, whether it could expose the
   RMS, vault plaintext, identity private keys, or extension secrets, or let an
   attacker authenticate or enroll a device.
3. Reproduction steps or a proof of concept.
4. Whether it requires local access, a malicious server, a malicious browser
   page, or only the network.
5. Any suggested remediation, if you have one.

### Our commitment

These are targets, not contractual guarantees:

- We will acknowledge your report within **3 business days**.
- We will provide an initial assessment within **10 business days**.
- We will keep you informed of progress and credit you in the release notes and
  advisory unless you ask to remain anonymous.
- Our default disclosure timeline is **90 days** from acknowledgement, or
  sooner once a fix ships. We will coordinate with you before any public
  disclosure.

## Scope

### In scope

Everything tracked in this repository:

- Cryptographic core and protocol (`libVELA/vela-crypto`, `SPEC.md`).
- Sync/auth server, vault storage, ORAM, recovery, sharing, rekeying
  (`serverVELA/`).
- Desktop, Android, iOS, and the browser extension + native-messaging host.
- The extension↔desktop IPC gate and the ephemeral web-access flow.

### Out of scope

These are **documented, deliberate non-goals for v2.0** (`SPEC.md` §9 "Out of
Scope") and are not treated as vulnerabilities:

- Side-channel attacks against client cryptographic implementations.
- Ruthless coercion / rubber-hose attacks.
- Network-layer denial of service.
- Client-side malware, keyloggers, and screen/memory scraping, including
  cold-boot and RAM-readout attacks.
- Anything requiring an already-compromised OS account or root/administrator
  privileges that an attacker could use to read the running app regardless of
  vault design.

Vulnerabilities in **third-party dependencies** should be reported upstream;
we track them with `cargo audit` / `cargo deny` (see `security/run-scan.sh`).

## Safe harbor

We consider security research conducted under this policy to be authorized,
helpful, and in the public interest. As long as your research:

- stays within the scope above,
- affects only accounts and systems you own or have explicit permission to
  test,
- does not exfiltrate, modify, or destroy data that is not yours,
- does not degrade service for other users, and
- is disclosed to us privately and in good faith before any public disclosure,

we will not pursue or support legal action against you, and we will not report
you to law enforcement for the act of research itself.

*This policy is a statement of intent, not a legal contract, and does not
override any applicable law.*

## Assurance artifacts

VELA already carries machine-checked and adversarial assurance. See:

- `SECURITY_AUDIT.md` — white-box audit findings and remediations.
- `SECURITY_REDTEAM.md` — red-team exercise.
- `security/` — semgrep rules, a static Rust scanner, the exploit/regression
  suite that proves audit fixes stay fixed, and ProVerif/Tamarin formal models.
- `libVELA/vela-crypto/SECURITY.md` — crypto review status and primitive pins.
- `security/assurance/` — **start here if you are an external researcher**:
  security claims, formal-model adversaries and assumptions, implementation
  correspondence, reproducibility, and known limitations.

## Contact

- Private vulnerability reports:
  <https://github.com/lucannez64/VELA/security/advisories/new>
- Machine-readable policy: [`.well-known/security.txt`](.well-known/security.txt)
