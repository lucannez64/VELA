# 6. Engaging researchers

This document covers how external researchers can work with VELA: what to
look at first, how to report, and how the project arranges audits.

## Reporting

- **Vulnerabilities:** use GitHub private vulnerability reporting at
  <https://github.com/lucannez64/VELA/security/advisories/new>. Policy, safe
  harbor, and response targets (acknowledgement within 3 business days,
  assessment within 10, 90-day coordinated disclosure) are in
  [`SECURITY.md`](../../SECURITY.md).
- **Assurance defects:** a model that does not match the code, a lemma that
  holds vacuously, an over-claim in this package, or a proof that passes for
  the wrong reason. Report these through the same private channel if they
  imply an exploitable gap. Otherwise open a public issue labelled
  `assurance`.
- Please cite claim and limitation IDs (`CONF-5`, `U-3`, `G-1`, …) and the
  commit you reviewed.

## Priority questions

These are the places where we think the evidence is thinnest. Answers in
either direction are valuable.

| ID | Question | Where to start |
|---|---|---|
| **Q-1** | **Hybrid KEM combiner.** `kem.rs` derives `HKDF-SHA256(salt="vela hybrid kem v1", ikm = ss_mlkem ‖ ss_x25519, info="")`. It does not bind the X25519 ephemeral key, the recipient public key, or the ML-KEM ciphertext. X-Wing binds `ct_X` and `pk_X` for exactly this reason. Is the combiner IND-CCA if ML-KEM fails and X25519 holds? Does COMP-5 hold? | `libVELA/vela-crypto/src/kem.rs`, SPEC §3, G-4 citation |
| **Q-2** | **Sender authenticity of shared items.** `seal_share` is anonymous public-key encryption, and `share_ek` is public. Freshness (INT-2) compares an `updated_at` that whoever seals the capsule chooses. Can a malicious server, or any user, inject an inbox item or a "newer" linked-share update attributed to another sender, for example replacing a shared login's password or URL? M19b assumes an honest relay and does not model this | `kem.rs::seal_share`, `identity.rs::open_share`, `serverVELA/vela-server/src/share/mod.rs`, client accept/apply paths, SPEC §5.4 |
| **Q-3** | **Fact-computing glue.** For each `plan_*` call in [§3.2](03-implementation-correspondence.md#crate-inventory-92-extracted-entry-points), are the boolean facts computed correctly from SQL and crypto results? Hard-coded facts (for example `device_owned_by_caller: true`) deserve particular attention | `serverVELA/vela-server/src/**` |
| **Q-4** | **Model ↔ policy correspondence.** Does each `*_matches_spec` predicate say the same thing as the guard of the corresponding Tamarin rule? | §3, G-5 |
| **Q-5** | **Ordering-only models.** M13, M14, M16, M17, M20, M21, and M26 have no network adversary. Which of their properties fail once you add `In`/`Out`, key compromise, or a deviating server? | `security/formal/` |
| **Q-6** | **M25 freshness ordering.** `timestamp_is_fresher` compares raw bytes. The handler checks only that `signed_at` parses as RFC 3339, then stores the client's string as sent. Clients emit a canonical form, but the server does not enforce one. Can offsets, fractional seconds, or lowercase forms make an older binding look fresher? This needs a device signature, so impact is probably low | `serverVELA/vela-share-policy/src/lib.rs`, `share/mod.rs` |
| **Q-7** | **Mobile sync.** Do the Kotlin and Swift sync engines enforce the same rollback and epoch rules as `vela-sync-policy` (U-8)? | `androidVELA/…/sync/`, `iosVELA/Shared/SyncEngine.swift` |
| **Q-8** | **ORAM abstraction.** Does M22c's transcript match what `oram.rs` actually sends, including stash write-back, padding, tree height, and the `/vault/events` notifications? | `libVELA/vela-crypto/src/oram.rs`, M22, M24 |
| **Q-9** | **Shamir share tags and the possession proof.** Is the share-authentication MAC sound when a share is adversarially chosen? Is the possession commitment hiding and binding? | `libVELA/vela-crypto/src/shamir.rs`, `recovery.rs`, `/recovery/recover/proof` |
| **Q-10** | **hax trust base.** Do the 15 `assume val PartialEq` instances, or any hax translation quirk, let a postcondition pass without being meaningful? | `*/proofs/fstar/extraction/*.fst` |

## Suggested engagement scopes

Audits can be scoped independently:

| Scope | Content | Skills | Rough size |
|---|---|---|---|
| **A. Formal-methods review** | Tamarin and ProVerif models, adversary adequacy, vacuity, hax/F\* specs and trust base, Q-4, Q-5, Q-10 | Tamarin, ProVerif, F\* | 2–3 person-weeks |
| **B. Cryptographic design review** | SPEC §3–§6, KEM and signature combiners, AEAD and AAD encodings, KDF contexts, Shamir tags, link encryption, Q-1, Q-2, Q-9 | Applied cryptography | 2–3 person-weeks |
| **C. Server and core implementation** | Axum handlers, SQL guards, auth and PASETO, rate limiting, glue (Q-3, Q-6), `vela-crypto` | Rust, web security | 3–4 person-weeks |
| **D. Clients** | Desktop IPC and native host, extension, Android (autofill, passkey provider, Keystore), iOS (not covered by the earlier audit), Q-7 | Mobile and desktop security | 3–5 person-weeks |

A and B give the most value for the smallest budget, because they test the
claims this package makes. C and D find bugs in the code.

## Before-outreach checklist

Do these **before** contacting anyone. Each one removes a reason for a
reviewer to stop reading.

- [ ] **Enable private vulnerability reporting** (G-7). It is currently
      disabled, so the advisory link in `SECURITY.md` does not work:
      `gh api -X PUT repos/lucannez64/VELA/private-vulnerability-reporting`
- [ ] Add a security contact email and, ideally, a PGP key to
      `SECURITY.md` and `.well-known/security.txt`.
- [ ] Add hax/F\* and M1–M10 to CI (G-1, G-2) so that every **[REF]** and
      **[SYM-local]** claim is witnessed by a public run.
- [ ] Pin Maude 3.5.1 and ProVerif 2.05 in CI (G-3).
- [ ] Replace or remove the "GL20 (Gong et al., 2020)" citation in SPEC §3 (G-4).
- [ ] Triage Q-2 internally first. If it is a real gap, fix it or state it
      as a known limitation, so the audit does not spend budget re-finding it.
- [ ] Tag the audit baseline (for example `audit-2026-q4`) and refresh
      `MANIFEST.sha256` and `proof-logs/` at that tag.
- [ ] Decide on publication: will audit reports be published in full? (Most
      funders require it.)

## Who to contact

### Funded or brokered audits for open-source projects

| Organization | Fit | How |
|---|---|---|
| **OSTIF** (Open Source Technology Improvement Fund) | Brokers and funds audits for open-source projects, matching them with audit firms. Its 2026 calendar is busy, but it still takes on new projects | Contact form or email via <https://ostif.org> |
| **OTF Security Lab** (formerly Red Team Lab) | Free audits and design reviews for projects relevant to internet freedom. A privacy-preserving, server-blind vault may qualify. Vendors include Cure53, Include Security, Radically Open Security, and Trail of Bits | <https://www.opentech.fund/labs/security-lab/> |
| **NLnet** | The NGI Zero Commons Fund closed its last call on 2026-06-01. Ask NLnet about current programmes before applying | <https://nlnet.nl> |
| **Sovereign Tech Agency** | Has run resilience and bug-bounty programmes for open-source infrastructure. Check its current offerings | <https://www.sovereign.tech> |

### Formal-methods and protocol expertise

| Who | Why |
|---|---|
| **Cryspen** | Authors of hax and libcrux. The obvious reviewers for the hax/F\* layer (scope A) and the KEM combiner (Q-1) |
| **Tamarin community**: CISPA (Cas Cremers' group), ETH Zürich Information Security Group, the Tamarin Prover GitHub discussions and mailing list | Model adequacy and vacuity (Q-4, Q-5). Academic groups sometimes take on interesting open models as student projects |
| **Inria Prosecco** (ProVerif and CryptoVerif authors) | M22 and a possible computational proof of the KEM and AEAD constructions (U-3) |
| **ETH Zürich Applied Cryptography Group** (Kenny Paterson's group) | Has published analyses of end-to-end encrypted cloud storage and password managers against malicious servers. Directly relevant to U-1 and Q-2 |

### Commercial audit firms

All of these have public open-source audit portfolios: **Trail of Bits**
(cryptography, Rust), **NCC Group Cryptography Services**, **Quarkslab**,
**Least Authority**, **Cure53** (web, extension, mobile), **Radically Open
Security** (non-profit), **X41 D-Sec**, **Include Security**. Ask for a
fixed-scope quote for scopes A and B first.

Do not send unsolicited reports or packages to individuals' personal
addresses. Use each organization's published contact route.

## Outreach templates

### Short note (funders, firms, research groups)

> **Subject:** Audit request: VELA, an open-source post-quantum password vault with Tamarin/ProVerif/F\* models
>
> Hello,
>
> I maintain VELA (<https://github.com/lucannez64/VELA>, MIT), a
> local-first password vault. The server is designed never to see vault
> plaintext. It uses hybrid ML-KEM-1024+X25519 and ML-DSA-87+Ed25519, Path
> ORAM, and 2-of-3 Shamir recovery with WebAuthn.
>
> The project ships 30 Tamarin theories (264 lemmas), 3 ProVerif
> equivalence models, and hax/F\* proofs for seven Rust policy crates. We have
> written an assurance package for external reviewers that states our
> claims, the adversary in each model, how the models map to the Rust, and,
> most importantly, what is *not* proved:
> <https://github.com/lucannez64/VELA/tree/main/security/assurance>.
>
> We are looking for an independent review, ideally of [scope A: the formal
> models and proof trust base / scope B: the cryptographic design]. The
> questions we most want answered are listed in §6 (for example the KEM
> combiner's transcript binding, and sender authenticity of shared items
> against a malicious server).
>
> Would you be open to a call, or could you point me to the right person?
> We plan to publish the results.
>
> Thanks,
> [name]

### Longer request for proposal (once a firm or funder responds)

Attach, or link to, this package plus:

1. Baseline tag and commit.
2. Chosen scopes (A–D) and the priority questions in order.
3. Deliverables: a findings report with severity, retest of fixes, and a
   statement of which `CONF-`, `AUTH-`, `INT-`, and `COMP-` claims were
   examined and with what result.
4. Disclosure: findings embargoed until fixed or for 90 days, then published.
5. Logistics: open source, so no NDA is needed for the code. Provide a
   point of contact and a test-server setup (`security/exploits/vela_regtest.py`
   shows an isolated instance).
6. Timeline and budget range, or a request for a quote.

## After an engagement

- Record every finding in `SECURITY_AUDIT.md` with an ID, severity, and
  status, and add an exploit regression where possible (`security/exploits/`).
- Update [§1](01-security-claims.md) and [§5](05-known-limitations.md):
  move claims between evidence levels and add any new limitations.
- Credit researchers in advisories and release notes unless they ask not to
  be named.
