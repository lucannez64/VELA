# Computational argument for the hybrid signature construction

**Status: machine-checked in CryptoVerif** (`security/formal/cryptoverif/hybrid_sig_mldsa_euf.ocv`,
`hybrid_sig_ed25519_euf.ocv`; local logs retained, CI gate configured), with the modelling choices listed
in that directory's README. It is not a Rust refinement theorem. The F★ AND-gate contract
and the Tamarin M29 proof establish different, narrower statements.

## Exact game and assumptions

Fix a security parameter and one honestly generated, fixed hybrid public key.
Generate the ML-DSA-87 and Ed25519 key pairs independently. The adversary sees
both public keys, adaptively requests signatures on arbitrary byte strings,
and finally outputs a byte string `m` and a hybrid signature. A win requires
both component verifiers to accept `m`, and `m` must never have been submitted
to the hybrid signing oracle. Signing failure aborts that request rather than
returning a partially authenticated message. Verification is the conjunction
of the two component results on exactly the same bytes.

For each component separately, assume EUF-CMA security of the actual scheme
and verification relation: ML-DSA-87 with the fixed context
`vela device identity v1`, or the Ed25519 relation used by `ed25519-dalek`.
The proof does not replace that relation with a stronger verifier. Assume
independent, correctly distributed randomness, correct primitive interfaces,
and a canonical fixed-length projection of a hybrid signature into its two
components. These assumptions require implementation correspondence review.

## Reduction to either component

Choose a component `i`. A reduction `B_i` receives its challenger public key
and signing oracle. It independently generates the other component key pair
and gives the two public keys to the hybrid adversary in the correct order.
For every hybrid signing query `m`, `B_i` asks its oracle to sign `m` and
signs the same bytes with its locally generated other key. It returns their
ordered concatenation. It records every queried byte string.

On adversarial output `(m, sigma)`, parse the two signature components and
output `(m, sigma_i)` to the component challenger. Whenever the hybrid
adversary wins, the selected component accepts by conjunction, and `m` was
never queried to the component oracle: the reduction made exactly the hybrid
signing queries. Thus every hybrid win is a component EUF-CMA win. The
simulation has exactly the honest distribution under the stated independent
key/randomness assumptions. There is no guessing loss for this fixed key.

Consequently, for each `i`,

`Pr[HybridForge(A)] <= Adv_EUF-CMA_i(B_i)`.

Use the bound for whichever component's security assumption remains justified,
including the reduction's time and signing-query overhead. In the common
no-secret-disclosure game, both bounds apply when both assumptions hold, so
their minimum is a valid bound. With one component secret disclosed, use only
the undisclosed component's bound. No
independence between the two *forgery events* is needed, and their
probabilities must not be multiplied.

The same reduction permits disclosure of the *other* secret key: `B_i`
already generated it and can disclose it. This establishes the mathematical
one-component compromise argument for a fixed choice of surviving component.
It does not establish security after disclosure of that surviving component,
or a bound for an adaptive multi-user corruption game without a separate
game definition and reduction.

## Relation to VELA and limits

`signing::sign` signs the same message with both keys; the ML-DSA call uses
the fixed context above. `signing::verify` rejects an invalid ML-DSA component
and passes the two observed results to the verified AND gate. The wire format
has fixed component lengths (4627 and 64 signature bytes). These source facts
support the intended construction; their complete extraction/refinement is
still open. Parser rejection behavior, cryptographic library internals,
randomness, FFI and error paths are not established by the gate theorem.

This is message unforgeability, not strong unforgeability: it does not rule
out a new valid signature on an already signed message. It says nothing about
first-contact identity authentication or maliciously chosen public keys.

At the application layer, an unqueried structured operation must encode to
an unqueried byte string. That requires injective framing, distinct domains,
and an inventory of every use of the same signing key. A collision between
an operation and another signed operation defeats that implication without
breaking either primitive. The [checked byte-frame parser](11-parser-refinement.md)
now establishes a raw grammar boundary. Encoder inverse, UTF-8/transcript
reconstruction and all-domain composition remain open. M29's selected
other-domain abstraction does not close them.

The KEM/HKDF construction requires its own IND-CCA game and reduction. This
signature argument supplies no KEM, confidentiality, KDF, recovery or
whole-system theorem. In particular, transcript binding alone is not a
computational proof of a robust hybrid KEM combiner.
