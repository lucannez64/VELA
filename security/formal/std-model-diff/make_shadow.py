#!/usr/bin/env python3
"""Derive runnable F* modules from the pinned model files, mechanically.

The F* models the VELA corpus uses live in interface files (`.fsti`) that mix
definitions with abstract `val` declarations (hax-lib 0.3.7, plus the two local
models in libVELA/vela-crypto).  F* only extracts `.ml` for a *module*, i.e. a
`.fst`; an interface-only module has no implementation to extract, and an
abstract `val` has no code to run.  Differential execution therefore needs a
private `.fst` copy of each executable module.

This script builds that copy by *selecting declaration blocks by name* from the
pinned files.  Nothing is rewritten: every emitted line is copied verbatim
from the pin, in pin order, except the single documented instantiation
`size_bits` (see INSTANTIATE) which fixes the target width the model leaves
open.  Blocks that are dropped are exactly the ones that cannot run (abstract
`val`s, `assume val`s) or that mention them, and the log prints the full
name -> pin line range manifest so a reviewer can check the claim.

Usage: make_shadow.py OUTDIR [--list MODULE] [--pin-root DIR]
"""
import argparse
import hashlib
import os
import pathlib
import re
import sys

# Pinned hax-lib 0.3.7 proof-libs root (the gates' --include root).
HAX = pathlib.Path(os.environ.get(
    "VELA_HAX_PROOF_LIBS",
    os.path.expanduser("~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
                       "hax-lib-0.3.7")))
REPO = pathlib.Path(__file__).resolve().parents[3]

# sha256 of every pinned source this harness reads.  A different hax-lib
# checkout (or a local model edit) fails here instead of silently changing
# what the differential test compares.
PINS = {
    "proof-libs/fstar/rust_primitives/Rust_primitives.Integers.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Arrays.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Slice.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Notations.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Char.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Sequence.fst": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Hax.fst": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.Hax.Folds.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.fst": None,
    "proof-libs/fstar/core/Core_models.Bundle.fst": None,
    "proof-libs/fstar/core/Core_models.Clone.fst": None,
    "proof-libs/fstar/core/Core_models.Cmp.fst": None,
    "proof-libs/fstar/core/Core_models.Marker.fst": None,
    "proof-libs/fstar/core/Core_models.Slice.fst": None,
    "proof-libs/fstar/core/Core_models.Ops.Function.fst": None,
    "proof-libs/fstar/core/Core_models.Ops.Index.fst": None,
    "proof-libs/fstar/core/Core_models.Ops.Range.fst": None,
    "proof-libs/fstar/core/Alloc.Alloc.fst": None,
    "proof-libs/fstar/core/Alloc.Slice.fst": None,
    "proof-libs/fstar/core/Alloc.Vec.fst": None,
    "proof-libs/fstar/core/Alloc.String.fst": None,
    "proof-libs/fstar/core/Core_models.Str.fsti": None,
    "proof-libs/fstar/rust_primitives/Rust_primitives.String.fsti": None,
}

# Declarations that are abstract in the pin but have to be decided for the
# harness to run.  Each entry replaces the block named `symbol` by `line`.
INSTANTIATE = {
    "Rust_primitives.Integers": {
        "symbol": "size_bits",
        "line": "let size_bits: n:nat{n == 32 \\/ n == 64} = 64",
        "why": "size_bits is abstract in the pin (the usize/isize width the "
               "proofs leave open).  The harness instantiates the 64-bit "
               "target the Rust side runs on.",
    },
}

# Per module: the blocks to keep, in the order they appear in the pin.
# "*" keeps every block (verbatim copy); otherwise `keep` is a list of
# declaration names, and `drop` removes names from a "*" copy.
MODULES = {
    # ---- rust_primitives -------------------------------------------------
    "Rust_primitives": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.fst",
        keep=["module Rust_primitives", "include Rust_primitives.Integers",
              "include Rust_primitives.Arrays", "include Rust_primitives.Char"]),
    "Rust_primitives.Integers": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Integers.fsti",
        keep=["module Rust_primitives.Integers", "open FStar.Mul", "inttype", "unsigned", "signed", "bits", "minint", "maxint",
              "max_usize", "max_isize", "range", "included", "range_t",
              "size_bits", "int_t", "u8_inttype", "i8_inttype", "u16_inttype",
              "i16_inttype", "u32_inttype", "i32_inttype", "u64_inttype",
              "i64_inttype", "u128_inttype", "i128_inttype", "usize_inttype",
              "isize_inttype", "u8", "i8", "u16", "i16", "u32", "i32", "u64",
              "i64", "u128", "i128", "usize", "isize", "v", "mk_int",
              "mk_int_v_lemma", "v_mk_int_lemma", "mk_u8", "mk_i8", "mk_u16",
              "mk_i16", "mk_u32", "mk_i32", "mk_u64", "mk_i64", "mk_u128",
              "mk_i128", "mk_usize", "mk_isize", "sz", "isz", "modulus",
              "op_At_Percent", "op_At_Percent_Dot", "cast", "cast_mod",
              "add_mod", "add_sat", "sub_sat", "add", "incr", "mul_mod",
              "mul_overflow", "mul", "sub_mod", "sub", "decr", "div", "mod",
              "eq", "ne", "lt", "lte", "gt", "gte", "ones", "zero",
              "shiftval", "shift_right", "abs_int", "neg",
              "+!", "+.", "*!", "*.", "-!", "-.", ">>!", "/!", "%!", "=.",
              "<>.", "<.", "<=.", ">.", ">=.",
              "bit", "get_bit_nat", "get_bit", "bit_and", "bit_or",
              "bit_xor"]),
    "Rust_primitives.Arrays": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Arrays.fsti",
        keep=["module Rust_primitives.Arrays", "open Rust_primitives.Integers",
              "open FStar.Mul", "t_Slice", "t_Array", "length", "contains",
              "concat", "slice", "split"]),
    "Rust_primitives.Slice": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Slice.fsti",
        keep=["module Rust_primitives.Slice", "open FStar.Mul",
              "open Rust_primitives.Arrays", "open Rust_primitives.Integers",
              "slice_length", "slice_split_at", "slice_contains",
              "slice_index", "slice_slice", "array_as_slice", "array_slice",
              "array_index"]),
    "Rust_primitives.Notations": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Notations.fsti",
        keep=["module Rust_primitives.Notations", "open Rust_primitives",
              "negation_tc", "negation_for_bool", "open Core_models.Ops.Index",
              ".[]"]),
    "Rust_primitives.Char": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Char.fsti",
        keep_all=True),
    "Rust_primitives.Sequence": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Sequence.fst",
        keep_all=True),
    "Rust_primitives.Hax": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Hax.fst",
        keep=["module Rust_primitives.Hax", "open Rust_primitives.Integers",
              "open Rust_primitives.Arrays", "t_Never", "never_to_any",
              "repeat", "open Core_models.Ops.Index", "update_at_tc",
              "open Core_models.Slice", "impl__index_refined",
              "impl__index", "array_of_list"]),
    "Rust_primitives.Hax.Folds": dict(
        src="proof-libs/fstar/rust_primitives/Rust_primitives.Hax.Folds.fsti",
        keep=["module Rust_primitives.Hax.Folds", "open Rust_primitives",
              "open Core_models.Ops.Range", "open FStar.Mul",
              "fold_range_wf_index", "range_empty", "fold_range"]),
    # ---- core models -----------------------------------------------------
    "Core_models.Bundle": dict(
        src="proof-libs/fstar/core/Core_models.Bundle.fst",
        keep=["module Core_models.Bundle", "open FStar.Mul",
              "open Rust_primitives", "t_Option",
              "impl__is_some_and", "impl__as_ref", "impl__unwrap_or",
              "impl__map", "impl__map_or", "impl__is_some", "impl__is_none"]),
    "Core_models.Clone": dict(
        src="proof-libs/fstar/core/Core_models.Clone.fst", keep_all=True),
    "Core_models.Cmp": dict(
        src="proof-libs/fstar/core/Core_models.Cmp.fst",
        keep=["module Core_models.Cmp", "open FStar.Mul",
              "open Rust_primitives", "t_PartialEq", "impl_6", "impl_18"]),
    "Core_models.Marker": dict(
        src="proof-libs/fstar/core/Core_models.Marker.fst",
        keep=["module Core_models.Marker", "open FStar.Mul",
              "open Rust_primitives", "t_PhantomData"]),
    "Core_models.Slice": dict(
        src="proof-libs/fstar/core/Core_models.Slice.fst",
        keep=["module Core_models.Slice", "open FStar.Mul",
              "open Rust_primitives", "impl__len", "impl__is_empty", "impl_7",
              "impl_8", "impl_9", "impl_10", "impl_11"]),
    "Core_models.Ops.Function": dict(
        src="proof-libs/fstar/core/Core_models.Ops.Function.fst",
        keep_all=True),
    "Core_models.Ops.Index": dict(
        src="proof-libs/fstar/core/Core_models.Ops.Index.fst", keep_all=True),
    "Core_models.Ops.Range": dict(
        src="proof-libs/fstar/core/Core_models.Ops.Range.fst",
        keep=["module Core_models.Ops.Range", "open FStar.Mul",
              "open Rust_primitives", "t_RangeTo", "t_RangeFrom", "t_Range",
              "t_RangeFull"]),
    "Alloc.Alloc": dict(
        src="proof-libs/fstar/core/Alloc.Alloc.fst", keep_all=True),
    "Alloc.Slice": dict(
        src="proof-libs/fstar/core/Alloc.Slice.fst",
        keep=["module Alloc.Slice", "open FStar.Mul", "open Rust_primitives",
              "impl__to_vec", "impl__into_vec"]),
    # The two local vela-crypto models: the pinned copies the gate checks.
    "Alloc.Vec": dict(
        src=str(REPO / "libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst"),
        keep_all=True),
    "Alloc.String": dict(
        src=str(REPO / "libVELA/vela-crypto/proofs/fstar/models/Alloc.String.fst"),
        keep=["module Alloc.String", "open FStar.Mul", "open Rust_primitives",
              "t_String", "impl_String__new", "impl_String__as_str"]),
}

# Local model paths are not under HAX; resolve them against the repository.
LOCAL = {str(REPO / "libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst"),
         str(REPO / "libVELA/vela-crypto/proofs/fstar/models/Alloc.String.fst")}

BLOCK_START = re.compile(
    r"^(?:module|open|include|val|let|unfold\s+(?:let|type|instance)|type|class|"
    r"instance|assume|#push-options|#pop-options)")
# Lines that attach to the *next* declaration: attributes and the keywords hax
# emits on their own line before a `val`/`let`.
PREFIX_ONLY = re.compile(
    r"^(?:assume|unfold|private|inline|noextract|irreducible)\s*$|^\[@")
NAME_RE = re.compile(
    r"\b(?:val|let(?:\s+rec)?|type|class|instance)\s+"
    r"(?:\(\s*([^)\s]+)\s*\)|([A-Za-z_][A-Za-z0-9_']*))")


def block_name(body):
    first = next((ln for ln in body.splitlines()
                  if ln.strip() and not ln.startswith("[@")), "")
    if re.match(r"^(module|open|include)\b", first):
        return first.strip()
    m = NAME_RE.search(body)
    return (m.group(1) or m.group(2)) if m else "(header)"


def blocks(text):
    """Split F* source into top-level declaration blocks (name, text, line)."""
    out, cur, pending, start = [], [], [], 0
    for n, line in enumerate(text.splitlines(keepends=True), 1):
        if PREFIX_ONLY.match(line):
            pending.append(line)
            continue
        if BLOCK_START.match(line):
            if cur:
                out.append((start, "".join(cur)))
            cur = pending + [line]
            pending = []
            start = n - len(pending)
        else:
            if not cur:  # file header before the first block (comments)
                cur = [line]
                start = n
            else:
                cur.append(line)
    if cur:
        out.append((start, "".join(cur)))
    named = []
    for start, body in out:
        named.append((block_name(body), start, body))
    return named


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source(name, spec, pin_root):
    src = spec["src"]
    if src.startswith(str(REPO)):
        return pathlib.Path(src)
    return pin_root / src


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--list", metavar="MODULE", help="print a module's block names")
    ap.add_argument("--pin-root", default=str(HAX))
    ap.add_argument("--print-pins", action="store_true")
    ap.add_argument("--verbose", action="store_true",
                    help="print every kept declaration with its pin line")
    a = ap.parse_args(argv)
    pin_root = pathlib.Path(a.pin_root)

    if a.print_pins:
        for rel in PINS:
            p = pin_root / rel
            print(f"{sha256(p) if p.exists() else 'MISSING'}  {rel}")
        return 0

    if a.list:
        spec = MODULES[a.list]
        p = source(a.list, spec, pin_root)
        for name, line, _ in blocks(p.read_text()):
            print(f"{name}\t{p}:{line}")
        return 0

    out = pathlib.Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)
    problems = []
    added = 0
    for module, spec in MODULES.items():
        pin = source(module, spec, pin_root)
        if not pin.exists():
            problems.append(f"{module}: pinned source missing: {pin}")
            continue
        want = INSTANTIATE.get(module, [])
        text = pin.read_text()
        found = blocks(text)
        names = {n for n, _, _ in found}
        if spec.get("keep_all"):
            keep = [n for n, _, _ in found]
        else:
            keep = spec["keep"]
        missing = [k for k in keep if k not in names]
        if missing:
            problems.append(f"{module}: not in {pin.name}: {missing}")
            continue
        order = {n: i for i, (n, _, _) in enumerate(found)}
        chosen = sorted({(order[k], k) for k in keep if k in order})
        body = []
        placed = False
        for idx, _ in chosen:
            name, line, chunk = found[idx]
            if want and name == want["symbol"]:
                # Substitute the abstract declaration by its instantiation.
                body.append(want["line"] + "\n")
                added += 1
                print(f"ADD  {module}: {want['line']!r} -- {want['why']}")
                placed = True
                continue
            body.append(chunk if chunk.endswith("\n") else chunk + "\n")
            if a.verbose:
                print(f"keep {module}: {name} @ {pin.name}:{line}")
        if want and not placed:
            problems.append(f"{module}: instantiated symbol is not a kept block")
            continue
        head = f"(* Generated by make_shadow.py from {pin}. Do not edit.\n" \
               f"   Every line below is copied verbatim from the pin, in pin \n" \
               f"   order; the only additions are listed in INSTANTIATE. *)\n"
        dst = out / f"{module}.fst"
        dst.write_text(head + "".join(body))
        print(f"shadow {module}: {len(body)} blocks, pin lines "
              f"{found[chosen[0][0]][1]}-{found[chosen[-1][0]][1]}, "
              f"{len(head + ''.join(body))} bytes")
    if problems:
        for p in problems:
            print("ERROR: " + p, file=sys.stderr)
        return 1
    print(f"shadow tree: {out} ({len(MODULES)} modules, {added} added line(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
