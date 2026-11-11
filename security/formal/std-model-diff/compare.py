#!/usr/bin/env python3
"""Compare the Rust reference run with the extracted F* model run.

Two modes:

  hash  RUST MODEL
        Both files hold `H <op> <block> <cases> <hash>` lines produced by
        ../rust/src/main.rs and ../ocaml/driver.ml.  Prints one row per op
        (cases, blocks, mismatching blocks) and exits 1 if any block differs,
        is missing, or reports a different case count.

  demo  NAME RUST MODEL [--expect ...]
        Both files hold `V <op> <i> <input-hex> <result>` lines for the two
        documented hax-lib 0.3.7 bugs (`ne` and `mul_overflow`).  Checks that
        every disagreement matches the bug the review notes describe, and
        exits 1 if the pattern is different (or if the bug does not show).
"""
import argparse
import collections
import sys


def parse_hash(path, notes=None):
    ops = collections.OrderedDict()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        if not line.strip():
            continue
        f = line.rstrip("\n").split("\t")
        if f[0] == "H":
            _, op, block, cases, h = f
            ops.setdefault(op, {})[int(block)] = (int(cases), h)
        elif f[0] == "C":
            ops.setdefault(f[1], {"cases": int(f[2])})
        elif f[0] == "N":
            if notes is not None:
                notes.append((f[1], f[2]))
        else:
            sys.exit(f"{path}:{n}: unexpected line {line[:40]!r}")
    return ops


def hash_main(a):
    notes = []
    rust = parse_hash(a.rust, notes)
    model = parse_hash(a.model)
    only = set(rust) - set(model)
    extra = set(model) - set(rust)
    if only:
        print(f"FAIL: ops missing from the model run: {sorted(only)}")
    if extra:
        print(f"FAIL: ops missing from the Rust run: {sorted(extra)}")
    rows, bad = [], 0
    for op in rust:
        if op not in model:
            continue
        rr, mm = rust[op], model[op]
        blocks = {k: v for k, v in rr.items() if k != "cases"}
        mblocks = {k: v for k, v in mm.items() if k != "cases"}
        cases = sum(c for c, _ in blocks.values())
        mismatch = sum(1 for k in blocks
                       if k not in mblocks or mblocks[k] != blocks[k])
        mismatch += sum(1 for k in mblocks if k not in blocks)
        bad += mismatch
        rows.append((op, cases, len(blocks), mismatch))
    print(f"{'op':32} {'cases':>9} {'blocks':>7} {'mismatches':>10}")
    for op, cases, blocks, mismatch in rows:
        print(f"{op:32} {cases:9d} {blocks:7d} {mismatch:10d}")
    if notes:
        print("\nnotes (from the Rust reference run):")
        for k, v in notes:
            print(f"  {k}\t{v}")
    total = sum(r[1] for r in rows)
    print(f"\n{len(rows)} ops, {total} cases, "
          f"{sum(r[3] for r in rows)} mismatching blocks")
    if bad or only or extra:
        print("RESULT: FAIL")
        return 1
    print("RESULT: OK (0 mismatches)")
    return 0


def parse_verbose(path):
    ops = collections.OrderedDict()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        if not line.strip():
            continue
        f = line.rstrip("\n").split("\t")
        if f[0] != "V":
            continue
        _, op, i, _inp, res = f
        if op.startswith("demo."):
            ops.setdefault(op, []).append(res)
    return ops


def demo_main(a):
    rust = parse_verbose(a.rust)
    model = parse_verbose(a.model)
    if set(rust) != set(model):
        print(f"FAIL: demo op sets differ: {sorted(set(rust) ^ set(model))}")
        return 1
    failed = 0
    for op in rust:
        rr, mm = rust[op], model[op]
        if len(rr) != len(mm):
            print(f"FAIL {op}: {len(rr)} Rust cases but {len(mm)} model cases")
            failed += 1
            continue
        if op == "demo.ne.u64":
            bad = disagree = 0
            for r, m in zip(rr, mm):
                a_s, b_s, rust_ne = r.split(",")
                ma_s, mb_s, model_ne = m.split(",")
                if (a_s, b_s) != (ma_s, mb_s):
                    bad += 1
                    continue
                a, b = int(a_s), int(b_s)
                # F* `ne` is `v b <> v b`, i.e. constant false; Rust's `!=`.
                if model_ne.lower() != "false" or rust_ne.lower() != str(a != b).lower():
                    bad += 1
                if a != b:
                    disagree += 1
            print(f"{op}: {len(rr)} cases, model `ne` always false, "
                  f"Rust `!=` true in {disagree} cases, {bad} unexpected")
            if bad or disagree == 0:
                failed += 1
        elif op.startswith("demo.mul_overflow."):
            ty = op.rsplit(".", 1)[1]
            bits = 64
            umax = (1 << bits) - 1
            if ty.startswith("i"):
                smax, smin = (1 << (bits - 1)) - 1, -(1 << (bits - 1))
            else:
                smax, smin = umax, 0
            bad = overflow_n = nonover_n = model_wrong = 0
            for r, m in zip(rr, mm):
                a_s, b_s, rw, rflag = r.split(",")
                ma_s, mb_s, mw, mflag = m.split(",")
                if (a_s, b_s) != (ma_s, mb_s) or rw != mw:
                    bad += 1
                    continue
                a, b = int(a_s), int(b_s)
                prod = a * b
                overflow = prod < smin or prod > smax
                # Rust's `overflowing_mul` flag is the real overflow flag.
                if rflag.lower() != str(overflow).lower():
                    bad += 1
                # The model flag is `prod > max || prod < max`, i.e.
                # `prod != max`: true for every product that is not exactly
                # `max`, so it is wrong exactly when nothing overflowed.
                want_model = str(prod != smax).lower()
                if mflag.lower() != want_model:
                    bad += 1
                if overflow:
                    overflow_n += 1
                else:
                    nonover_n += 1
                    if mflag.lower() != rflag.lower():
                        model_wrong += 1
            print(f"{op}: {len(rr)} cases ({overflow_n} overflow, {nonover_n} in range); "
                  f"model flag == (prod != MAX) in all cases, so it is wrong in "
                  f"{model_wrong} of the {nonover_n} in-range products; "
                  f"{bad} unexpected")
            if bad or model_wrong == 0:
                failed += 1
        else:
            print(f"FAIL: unknown demo op {op}")
            failed += 1
    if failed:
        print(f"RESULT: FAIL ({failed} checks)")
        return 1
    print("RESULT: OK (documented bugs reproduce exactly)")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    h = sub.add_parser("hash")
    h.add_argument("rust")
    h.add_argument("model")
    d = sub.add_parser("demo")
    d.add_argument("rust")
    d.add_argument("model")
    a = ap.parse_args()
    return hash_main(a) if a.mode == "hash" else demo_main(a)


if __name__ == "__main__":
    sys.exit(main())
