# 6. Engaging researchers

Private vulnerability reports go to
[GitHub advisories](https://github.com/lucannez64/VELA/security/advisories/new)
under [`SECURITY.md`](../../SECURITY.md). Private reporting was confirmed
enabled through the GitHub API on 2026-10-23. Please cite the reviewed commit,
claim/limitation IDs and a minimal trace or reproduction. Model/code mismatches,
vacuity and overstated assurance are welcome findings.

## Priority questions

1. **KEM v2 computational security.** Review `kem.rs::combine_v2`, including
   transcript encoding, key/ciphertext digests, rejection of non-contributory
   X25519 values, and legacy trusted-contact recovery. Binding the transcript
   is implemented; scoped CryptoVerif games are provided under the documented
   random-oracle, correctness and group assumptions. Review the remaining
   concrete scalar/hash/encoding and Rust correspondence bridges.
2. **Share trust bootstrap and persistence.** Review signed envelope parsing,
   fact computation, first-contact TOFU, recipient-key directory trust, and
   persisted pins across crashes/concurrency. M19c proves properties relative
   to a genuine pinned key; it does not authenticate an account at first contact.
3. **Enrollment human comparison.** Check that all client displays and approval
   paths bind both public keys, handle mixed-version clients safely, and that
   joining-device adoption authenticates the intended primary. M13b is a
   focused secrecy/key-substitution proof.
4. **Models versus executed code.** Start with
   [the rule-to-Rust table](../formal/network-boundary-correspondence.md).
   Hash checks detect drift only. Review computed booleans, SQL atomicity,
   revocation races and every caller of the pure policy functions.
5. **Proof trust base and composition.** Review hax library assumptions,
   predicates, fresh extraction, bounded/fuel restrictions, ordering-only
   models and cross-protocol use of keys. Current local proof results and remaining concrete-refinement/CI
   evidence gaps must remain explicit.
6. **Other implementation gaps.** Mobile sync does not use `vela-sync-policy`;
   ORAM transcript adequacy, Shamir tags, possession proofs and share-key
   timestamp canonicalization remain worthwhile targets.

## Suggested scope

Start with a formal-model/code correspondence review and a cryptographic
design review. Request a separate quote for server Rust/SQL and client
integration, including iOS. Deliverables should identify which claims were
examined, assumptions, findings with severity, proof/attack artifacts, and a
retest of fixes. Ask for timeline and cost; this package makes no budget or
publication commitment on the maintainer's behalf.

## Contact routes

Checked against the organizations' own pages on 2026-10-23:

- **hax and implementation proofs:** the [Cryspen site](https://cryspen.com/)
  lists `info@cryspen.com` and its hax project. Ask the team to route a review
  request to the appropriate current organization; the site also announces a
  transition to the name pereq. This is a relevant technical contact, not a
  claim that an audit slot is available.
- **Audit coordination or funding:** [OSTIF's Get an Audit page](https://ostif.org/get-an-audit/)
  provides an intake route and explains its scoping and auditor-selection
  process. Ask about eligibility and sponsorship rather than assuming funding.
- **Protocol-model feedback:** start from the
  [Tamarin project's official site](https://tamarin-prover.com/) and its linked
  community channels. Ask whether anyone is interested in model adequacy or
  a research collaboration; this is distinct from commissioning an audit.

## Outreach templates

These are drafts for the maintainer to adapt and send. No email or contact
form has been submitted as part of preparing this package.

### hax / formal-methods team

**Subject:** VELA: request for Rust/model correspondence and hax proof review

Hello,

I maintain VELA, an MIT-licensed password vault:
https://github.com/lucannez64/VELA.

I am seeking an independent review of our Rust policy proofs and protocol
models. The assurance package documents claims, adversary assumptions,
rule-to-code mappings, reproducible checks and known gaps. The repository
contains Tamarin/ProVerif models and hax/F* specifications for eight policy
crates. Hosted F★ checking covers the 173-postcondition baseline on 5fa4e9f; a local
web-session increment extends the inventory to 183 explicit postconditions with no
local extraction assumptions; imported libraries, defined String/Vec models and proof tools remain trusted.
Composed sharing/journal models have named local verdicts. Concrete whole-system
refinement and updated hosted CI results remain incomplete.

The first priorities are model adequacy, fact-computing Rust glue, the proof
trust base, and whether our exact hybrid KEM v2 has the security properties
we intend. Could you advise whether your team can review this, or route me
to an appropriate reviewer? Please include a proposed scope, availability
and quote.

Reviewed commit: [insert the published commit containing the manifest]
Package: [insert a commit-pinned link to security/assurance]
Contact/name: [maintainer to fill]

### OSTIF intake

**Subject:** Independent audit / sponsorship inquiry for VELA

Hello,

I maintain VELA (https://github.com/lucannez64/VELA), an MIT-licensed vault
with Rust cryptographic core and desktop/mobile clients. I would like help
scoping an independent cryptographic design and implementation review, and
to understand eligibility for audit sponsorship.

We have prepared an external-review package covering explicit security
claims, Tamarin/ProVerif models, Rust correspondence, hax/F* proof boundaries,
reproduction instructions and known limitations. Our highest priorities are
malicious-server protocol behavior, hybrid cryptography and model/code gaps.
This is a request for independent review; our internal results are not a
third-party audit.

Could you advise on the intake process and information needed to assess the
project? I can supply the frozen source revision, manifest and proof logs.

Budget/timeline: [maintainer to fill, or request guidance]
Package/contact: [maintainer to fill]

## Preparing an engagement

Publish the reviewed branch before sending links to it, and use a commit-pinned
URL. Attach the manifest and current logs; label missing CI and refinement
results candidly. Choose scope, budget, maintainer contact, and whether reports
may be published. Do not include vulnerability details in a public community
post. Record findings in the audit log, add regression cases where appropriate,
and update the claim/evidence tables after fixes and retest.
