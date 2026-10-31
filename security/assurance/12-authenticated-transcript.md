# Exact received-byte signature transcript

This increment connects the checked VSE2 byte grammar to the message bytes used
by the production sender and opener. It remains a partial implementation
correspondence result, not a complete authenticated-opening theorem.

## Production behavior

The sender serializes the header and item once, prefixes those bytes with
`SHARE_ITEM_CONTEXT` for signing, and appends the resulting LP signature to the
same frame. The opener parses the frame and prefixes the exact received signed
body with that context for verification. It no longer reconstructs the signed
message from allocated strings and a second encoder.

For an accepted frame of length N, `ShareFrame::signed_body` is precisely
`input[4..N-(8+4691)]`. The four-byte marker is checked separately; the final
signature has a checked eight-byte length and exactly 4691 bytes, with no trailing
input. The functional grammar and stateful parser return the same body and all
nine decoded values. `wire::frame_body` has a complete success/rejection contract
and checks bounds before subtraction.

`wire::domain_message` checks the byte-vector capacity bound before addition.
Its contract states the exact output length, domain prefix and body suffix,
and characterizes rejection. Its bound is `isize::MAX`; allocation failure and
process termination are outside the functional model. Context constants and
field semantics still require specification review. The recorded extraction
targets x86_64 Linux; cross-target layout and native FFI are not verified by
this increment.

Regression checks compare a sender-produced frame's transcript with the
pre-existing reference encoder, open a capsule signed with that encoder,
and reject a modified payload after a valid re-sealing to the recipient.
The payload includes non-UTF-8 and NUL bytes. Separate boundary checks exercise
empty bodies and lengths that would underflow unchecked prefix/trailer slicing.
These finite compatibility checks are not an all-input encoder inverse proof.

## Defined Vec compatibility model

`libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst` supplies only the Vec
operations needed by this extraction: the existing sequence representation,
empty constructor, length, slice view and extension by a slice. It is a local
library model, not extracted VELA code. The pinned hax-lib 0.3.7 extension model
has a Pure postcondition True, which hides the output bytes from callers.
The local model retains its sequence-append definition, exposes the capacity
requirement as an argument refinement and exposes the defined concatenation in
the result type. Explicit length and prefix/suffix refinements follow from
F★ sequence lemmas. F★ checks the definition; no axiom or admitted proof supplies
the result. The upstream representation and these operations' correspondence
to Rust's Vec remain trusted, as do the existing String view and imported
proof libraries. This does not verify allocation or Rust standard-library code.

## Remaining composition work

The extracted contracts do not cover the complete `seal_signed_item` or
`open_signed_item` wrappers. Their primitive calls, early errors, UTF-8/owned
field conversions, verifying-key interpretation and recipient-key provenance
still require correspondence. The checked transcript helpers are actual
production calls, but their placement and composition in these wrappers remain
a manual mapping. The public reference encoder remains available for API
compatibility; its equivalence for every valid header/item is not proved.

The signature's computational reduction remains a written argument in
[the reduction note](10-signature-reduction.md). Handler context origins,
persistent state, concurrency, native callers and full protocol composition
remain open under [the selected target contract](09-target-contract.md).

[Local proof and regression evidence](proof-logs/current/authenticated-transcript/README.md)
records the source snapshot and commands. Hosted reproduction remains pending.
