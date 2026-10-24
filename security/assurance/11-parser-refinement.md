# Concrete share-frame parser refinement

This increment proves a memory-cursor and byte-grammar boundary used directly
by `open_signed_item`. It does not establish the complete authenticated-open,
handler, storage or native-client theorem.

## Checked byte operations

`wire::split_length_prefixed` accepts exactly a complete eight-byte big-endian
length followed by at least that many payload bytes. Success returns precisely
`input[8..8+length]` and `input[8+length..]`. Short headers and oversized lengths
are rejected. The comparison precedes narrowing the length to `usize`.

`wire::split_u64_prefix` returns the exact integer and remaining input, or
rejects an incomplete eight-byte prefix. Its numeric meaning composes with the
previously checked fixed-width decoder.

`take_length_prefixed`, `take_u64` and `take_frame_prefix` are actual mutable
Rust cursor operations. Their postconditions relate the original input, result
and future cursor: a successful read consumes exactly the specified production;
a rejected read preserves the cursor. The pair/four-field readers commit their
cursor only when their entire group succeeds. They refine the corresponding
pure grammar combinators. This is cursor atomicity, not filesystem atomicity.

## Full byte frame

`share_frame_spec` is a functional grammar over the checked splitting operations:

1. Exact `VSE2` marker.
2. Four LP fields: sender account, device, verifying key, recipient account.
3. Fixed 32-byte recipient-key digest.
4. LP lineage, then an eight-byte revision.
5. LP item and signature.
6. Complete input consumption, 2624-byte verifying key and 4691-byte signature.

The actual production `parse_share_frame` uses stateful cursor operations.
Its postcondition equates its complete optional result with this grammar,
using an explicit structural comparator for the signed body and all nine decoded
values. It covers
both successful values and rejection; an implementation that always rejects
does not satisfy the contract. The primitive splitting postconditions give the
grammar its exact byte meaning. The grammar's correspondence to intended VSE2
syntax remains a specification-review obligation.

The production opener now calls this checked parser before UTF-8 conversion,
key/signature decoding, verification and recipient binding. Malformed frame
errors are consolidated; normal VSE2 bytes and the C/JSON bridge format remain
unchanged. A sender-generated capsule regression checks each expected field,
including a fixed endian revision, and rejection of truncation, trailing bytes
and a huge length.

## Read-only authenticated observations

`OpenedShare` fields are private. Safe external Rust code can obtain one only
through the existing opening API (or clone an existing witness). Two compile-fail
doctests reject direct construction and mutation. Read-only `.header()` and
`.item()`, and consuming `.into_item()`, delegate to three checked free-function
kernels that preserve every header field and payload byte. Desktop and Apple/
Android Rust callers use these accessors. Rust consumers that previously accessed
public fields must use the new methods.

Whole-value replacement by another valid witness (including cloning) remains
possible. This constraint preserves the opened-value invariant; it does not
freeze an enclosing AdmittedShare or prove that callers persist a matching pin.

This representation constraint relies on Rust compiler/module privacy. It is
not a cryptographic unforgeability theorem and does not cover unsafe memory
corruption. The opener's crypto calls/recipient binding and the one-call getter
method delegations still need complete implementation correspondence. No new
constructor bypass or mutable accessor is provided.

## Proof/evidence boundary

The subsequent recovery snapshot had 180 directly selected functions and 173 explicit
postconditions. Seven selected specification/comparison functions have no
explicit ensures. All reviewed extracted postconditions have trivial
preconditions; there are zero local assume val declarations. Imported models,
the defined String/Vec models, extraction, compilers and proof tools remain trusted.

All source algorithms are the Rust production algorithms. No generated body
was patched or replaced. The frame function uses scoped `--fuel 2 --ifuel 2`
for definition unfolding, with the existing solver resource limit and 3 GiB
process-tree cap. Early monolithic attempts exhausted solver resources; grouped
readers made the proof compositional. The static boundary checker additionally
rejects `--admit_smt_queries` and `--unsafe_tactic_exec`; negative fixtures cover
those flags and lax mode. That checker detects drift, not logical validity.

[Parser increment evidence](proof-logs/current/frame-parser-refinement/README.md)
is retained; [current transcript evidence](proof-logs/current/authenticated-transcript/README.md)
supersedes its crypto snapshots. Historical hosted success on e690dfc covers the earlier
119-postcondition snapshot; this increment requires a fresh hosted run.

See [the received-byte transcript increment](12-authenticated-transcript.md) for
the new exact-body and domain-concatenation contracts.

Remaining: UTF-8/object conversions; encoder/parser inverse and all-domain
framing composition; complete authenticated-opening composition and recipient-key
provenance;
primitive-wrapper correspondence; context origins; application effects and
failure/concurrency refinement; native callers and computational reductions.
The slice parser allocates no payload buffers; allocation/failure behavior in
the enclosing opener/encoder is outside this proof.
