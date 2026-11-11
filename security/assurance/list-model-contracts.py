#!/usr/bin/env python3
"""List every hax/std library model the F* corpus relies on (plan step T1).

Scans the repository's .fst/.fsti files (proof logs and build output excluded)
for symbols from the hax proof libraries (Core_models, Alloc, Rust_primitives,
Hax_lib) and classifies each against the pinned library source:

  assumed   - declared with `assume val` / `assume type`: trusted, unproved
  abstract  - `val` in an interface with no definition in the library: trusted
  defined   - `let`/`type`/constructor with a body in the library
  missing   - not found in the library (needs a look)

Usage:
  python3 -I security/assurance/list-model-contracts.py [--lib DIR] [--out DIR]

Default --lib is $HAX_LIB_ROOT or the pinned hax 0.3.7 hax-lib checkout; the
scanned directories match the gates' F* include roots. Writes
inventory.json and README.md to --out (default:
security/assurance/proof-logs/current/model-contract-inventory).

Qualified names are matched exactly. Names brought in by `open` (mostly
integer operators such as `+!` and `<.`) are matched by token against the
declarations of the opened modules, so their counts are upper bounds.
"""
import argparse
import collections
import json
import os
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_LIB = os.environ.get(
    "HAX_LIB_ROOT", str(pathlib.Path.home() / ".local/opt/vela-tools/src/hax-0.3.7/hax-lib"))
# The same include roots the verify-fstar*.sh gates pass to F*.
LIB_DIRS = ("proof-libs/fstar/core", "proof-libs/fstar/rust_primitives", "proofs/fstar/extraction")
PREFIXES = ("Core_models", "Alloc", "Rust_primitives", "Hax_lib")
QUAL = re.compile(r"\b((?:%s)(?:\.[A-Z][A-Za-z0-9_']*)*)\.([A-Za-z_][A-Za-z0-9_']*)\b" % "|".join(PREFIXES))
OPEN = re.compile(r"^\s*open\s+([A-Z][A-Za-z0-9_.]*)", re.M)
DECL = re.compile(
    r"^\s*(?:\[@[^\]]*\]\s*)*(?:(?:inline_for_extraction|unfold|noextract|irreducible|private)\s+)*"
    r"(assume\s+val|assume\s+type|val|let\s+rec|let|type|and|class|instance)\s+"
    r"(\(\s*[^)\s]+\s*\)|[A-Za-z_][A-Za-z0-9_']*)", re.M)
CTOR = re.compile(r"\|\s*([A-Z][A-Za-z0-9_']*)\s*:")
METHOD_OP = re.compile(r"[{;]\s*\(\s*([^)\s]+)\s*\)\s*:[^:=]")
FIELD = re.compile(r"[{;]\s*([a-z_][A-Za-z0-9_']*)\s*:[^:=]")
SKIP = ("/target/", "/proof-logs/", "/fstar-cache/", "/.cache/", "/node_modules/")


def local_model_dirs():
    """Repository copies of library models (they replace hax's in their crate)."""
    return sorted(d for d in ROOT.glob("*/*/proofs/fstar/models") if "/target/" not in str(d))


def corpus():
    # Local model files stay in the scan: what they build on is trusted too.
    for p in sorted(ROOT.rglob("*.fst*")):
        s = str(p)
        if p.suffix in (".fst", ".fsti") and not any(k in s for k in SKIP):
            yield p


def strip_comments(src):
    src = re.sub(r"\(\*.*?\*\)", " ", src, flags=re.S)
    return re.sub(r"//[^\n]*", " ", src)


INCLUDE = re.compile(r"^\s*include\s+([A-Z][A-Za-z0-9_.]*)\s*(?:\{([^}]*)\})?", re.M)


def library(lib, dirs=None):
    """module -> {name: kind} for every name the module exports, following includes."""
    own, incs, bodies, fields = local_library(lib, dirs)
    memo = {}

    def exports(mod, stack=()):
        if mod in memo:
            return memo[mod]
        if mod in stack:
            return {}
        out = {}
        for inc, sel in incs.get(mod, []):
            sub = exports(inc, stack + (mod,))
            if sel is None:
                out.update(sub)  # a later include shadows an earlier one, as in F*
            else:
                for src, dst in sel:
                    if src in sub:
                        out[dst] = sub[src]
        out.update({k: (v, (mod, k)) for k, v in own.get(mod, {}).items()})
        memo[mod] = out
        return out

    def wraps(origin, depth=0, seen=None):
        """Trusted (abstract/assumed) names a definition reaches in its own module."""
        seen = seen if seen is not None else set()
        mod, _ = origin
        found = set()
        for tok in set(re.findall(r"[A-Za-z_][A-Za-z0-9_']*", bodies.get(origin, ""))):
            k = own.get(mod, {}).get(tok)
            if (mod, tok) in seen or (mod, tok) == origin or k is None:
                continue
            seen.add((mod, tok))
            if k in ("abstract", "assumed"):
                found.add(tok)
            elif depth < 3:
                found |= wraps((mod, tok), depth + 1, seen)
        return found

    return {m: exports(m) for m in set(own) | set(incs)}, wraps, fields


def local_library(lib, dirs=None):
    """Own declarations per module, merging .fsti and .fst, plus include lists."""
    mods = collections.defaultdict(dict)
    incs = collections.defaultdict(list)
    bodies, fields = {}, set()
    roots = dirs if dirs is not None else [pathlib.Path(lib) / d for d in LIB_DIRS]
    for p in sorted(q for d in roots for q in pathlib.Path(d).glob("*.fst*")):
        if p.suffix not in (".fst", ".fsti"):
            continue
        mod = p.stem
        src = strip_comments(p.read_text(errors="replace"))
        ms = list(DECL.finditer(src))
        for i, m in enumerate(ms):
            kind, name = m.group(1), m.group(2)
            name = re.sub(r"\s+", "", name).strip("()") if name.startswith("(") else name
            if kind.startswith("let"):
                bodies[(mod, name)] = src[m.end():ms[i + 1].start() if i + 1 < len(ms) else len(src)]
            kind = kind.split()[0] if not kind.startswith("assume") else "assume"
            k = {"assume": "assumed", "val": "abstract"}.get(kind, "defined")
            old = mods[mod].get(name)
            # A definition anywhere beats an interface val; an assume always wins.
            if old == "assumed" or (old == "defined" and k == "abstract"):
                continue
            mods[mod][name] = k
        for c in CTOR.findall(src) + METHOD_OP.findall(src):
            mods[mod].setdefault(c, "defined")
        for f in FIELD.findall(src):
            mods[mod].setdefault(f, "defined")
            fields.add((mod, f))
        for inc, sel in INCLUDE.findall(src):
            pairs = None
            if sel:
                pairs = []
                for item in sel.split(";"):
                    parts = item.split(" as ")
                    if parts[0].strip():
                        pairs.append((parts[0].strip(), (parts[1] if len(parts) > 1 else parts[0]).strip()))
            if (inc, pairs) not in incs[mod]:
                incs[mod].append((inc, pairs))
    return mods, incs, bodies, fields


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", default=DEFAULT_LIB)
    ap.add_argument("--out", default=str(ROOT / "security/assurance/proof-logs/current/model-contract-inventory"))
    a = ap.parse_args()
    lib, wraps, fields = library(a.lib)
    mdirs = local_model_dirs()
    local, lwraps, _ = library(a.lib, mdirs)
    uses = collections.defaultdict(lambda: {"count": 0, "files": set()})
    opened = collections.defaultdict(set)
    files = list(corpus())
    for p in files:
        src = strip_comments(p.read_text(errors="replace"))
        rel = str(p.relative_to(ROOT))
        for mod, name in QUAL.findall(src):
            u = uses[(mod, name)]
            u["count"] += 1
            u["files"].add(rel)
        for mod in OPEN.findall(src):
            if mod.startswith(PREFIXES):
                opened[mod].add(rel)
    # Unqualified names from opened modules: count operator/identifier tokens.
    for mod, rels in opened.items():
        for name, (_kind, origin) in lib.get(mod, {}).items():
            if origin in fields:  # record fields: too many false matches on locals
                continue
            pat = re.compile(r"(?<![A-Za-z0-9_.'])" + re.escape(name) + r"(?![A-Za-z0-9_'])") \
                if re.match(r"[A-Za-z_]", name) else re.compile(r"(?<![!$%&*+\-./<=>?@^|~:])" + re.escape(name) + r"(?![!$%&*+\-./<=>?@^|~:])")
            for rel in rels:
                n = len(pat.findall(strip_comments((ROOT / rel).read_text(errors="replace"))))
                if not n:
                    continue
                u = uses[(mod, name)]
                if rel in u["files"]:  # already counted through qualified uses
                    continue
                u["count"] += n
                u["files"].add(rel)
                u["via_open"] = True
    rows = []
    for (mod, name), u in uses.items():
        if f"{mod}.{name}" in lib:  # a module reference, not a symbol
            continue
        kind, origin = lib.get(mod, {}).get(name, ("missing", None))
        w = sorted(wraps(origin)) if kind == "defined" and origin else []
        if kind == "missing" and name in local.get(mod, {}):
            lk, origin = local[mod][name]
            kind = "local-" + lk
            w = sorted(lwraps(origin)) if lk == "defined" else []
        rows.append({"module": mod, "name": name, "kind": kind, "uses": u["count"],
                     "defined_in": ".".join(origin) if origin else "", "wraps_trusted": w,
                     "files": len(u["files"]), "via_open": u.get("via_open", False),
                     "file_list": sorted(u["files"])})
    order = {"assumed": 0, "local-assumed": 0, "abstract": 1, "local-abstract": 1, "missing": 2,
             "local-defined": 3, "defined": 4}
    rows.sort(key=lambda r: (order[r["kind"]], -r["uses"], r["module"], r["name"]))
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "inventory.json").write_text(json.dumps(
        {"library": a.lib, "corpus_files": len(files), "symbols": rows}, indent=1) + "\n")
    tally = collections.Counter(r["kind"] for r in rows)
    wrapped = [r for r in rows if r["wraps_trusted"]]
    md = ["# Imported model contracts (plan step T1)", "",
          "Generated by `security/assurance/list-model-contracts.py`; do not edit by hand.", "",
          f"Corpus: {len(files)} F* files outside proof logs. Library: hax 0.3.7 `hax-lib` (the gates' include roots).", "",
          f"{len(rows)} library symbols used: **{tally['assumed']} assumed**, **{tally['abstract']} abstract** "
          f"(interface `val` with no library definition), {tally['missing']} not found, {tally['local-defined']} from local models, {tally['defined']} defined "
          f"({len(wrapped)} of them wrap a trusted symbol of their own module, listed in the last column).", "",
          "Assumed and abstract symbols are trusted: every proof that uses them relies on their stated",
          "types and specifications matching Rust. Steps T3-T7 review them against Rust std semantics.",
          "Rows marked *open* were matched by token through an `open`, so counts are upper bounds.", "",
          "Local models (`local-*` rows) are repository files that replace the hax model in their",
          "crate's gate: " + ", ".join(f"`{d.relative_to(ROOT)}`" for d in mdirs) + ". They are part of",
          "the trusted base until T3/T4 review them.", "",
          "Wrapping is followed only inside the defining module (three levels), so a definition",
          "over another module's abstract symbol is not flagged; see inventory.json for files.", "",
          "| Kind | Module | Symbol | Uses | Files | Defined in | Wraps trusted |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['kind']} | `{r['module']}` | `{r['name']}`{' *open*' if r['via_open'] else ''} | {r['uses']} | {r['files']} | "
                  f"`{r['defined_in']}` | {', '.join('`' + x + '`' for x in r['wraps_trusted']) or ''} |")
    (out / "README.md").write_text("\n".join(md) + "\n")
    print(f"{len(files)} files, {len(rows)} symbols: " + ", ".join(f"{k} {tally[k]}" for k in order))


if __name__ == "__main__":
    main()
