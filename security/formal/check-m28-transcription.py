#!/usr/bin/env python3
"""Drift check between m28_share_journal.spthy and its F* transcription.

The source bridge (m28-trace-equivalence/M28_source_*.fst) proves the M28
lemmas on F* rule schemas written by hand in M28_source_terms.fst.  This
check parses the .spthy independently and rejects any difference in:

  - the declared functions (exactly successor/1; no builtins or equations),
  - the rule set and, per rule, the premises, actions and conclusions with
    their fact names, persistence marks and argument terms (fresh ~x,
    public 'c', variables, successor(...), pairs),
  - the fact inventory (symbol -> arity) in [fact_arity],
  - the single restriction (Increasing, RevisionIncreases(old, next) ==> old << next),
  - the lemma names, which must equal the F* formula names in
    M28_source_bridge.fst, split into eight all-traces lemmas (the
    [m28_universal] conjunction) and two exists-trace lemmas ([m28_exists]
    in M28_source_witness.fst).

It is a syntactic drift check, not a proof that F* and Tamarin agree on
semantics; that remains trusted and is stated in the evidence README.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SPTHY = ROOT / "m28_share_journal.spthy"
FDIR = ROOT / "m28-trace-equivalence"
TERMS = FDIR / "M28_source_terms.fst"
BRIDGE = FDIR / "M28_source_bridge.fst"
WITNESS = FDIR / "M28_source_witness.fst"

EXPECTED_RESTRICTION = ("Increasing", "All old next #i. RevisionIncreases(old, next) @ #i ==> old << next")


class DriftError(Exception):
    pass


# --------------------------------------------------------------------------
# .spthy side
# --------------------------------------------------------------------------

def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def tokenize(s):
    toks = re.findall(r"~?[A-Za-z_][A-Za-z0-9_]*|'[^']*'|[(),<>!]", s)
    rest = re.sub(r"~?[A-Za-z_][A-Za-z0-9_]*|'[^']*'|[(),<>!]|\s+", "", s)
    if rest:
        raise DriftError(f"unexpected characters in .spthy terms: {rest!r}")
    return toks


class Parser:
    def __init__(self, toks):
        self.toks, self.i = toks, 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, want=None):
        t = self.peek()
        if t is None or (want is not None and t != want):
            raise DriftError(f"expected {want!r}, got {t!r}")
        self.i += 1
        return t

    def term(self):
        t = self.take()
        if t == "<":
            a = self.term()
            self.take(",")
            b = self.term()
            if self.peek() == ",":
                raise DriftError("tuples wider than pairs are not transcribed")
            self.take(">")
            return ("pair", a, b)
        if t.startswith("'"):
            return ("pub", t[1:-1])
        if t.startswith("~"):
            return ("fresh", t[1:])
        if self.peek() == "(":
            self.take("(")
            args = [self.term()]
            while self.peek() == ",":
                self.take(",")
                args.append(self.term())
            self.take(")")
            if len(args) != 1:
                raise DriftError(f"function {t} with {len(args)} arguments")
            return ("app", t, args[0])
        return ("var", t)

    def fact(self):
        persistent = False
        if self.peek() == "!":
            self.take("!")
            persistent = True
        name = self.take()
        self.take("(")
        args = []
        if self.peek() != ")":
            args.append(self.term())
            while self.peek() == ",":
                self.take(",")
                args.append(self.term())
        self.take(")")
        return (name, persistent, tuple(args))

    def facts(self):
        out = []
        if self.peek() is None:
            return out
        out.append(self.fact())
        while self.peek() == ",":
            self.take(",")
            out.append(self.fact())
        if self.peek() is not None:
            raise DriftError(f"trailing tokens in fact list: {self.toks[self.i:]}")
        return out


def parse_facts(s):
    return Parser(tokenize(s)).facts()


def parse_spthy(text):
    code = strip_comments(text)
    funcs = re.findall(r"^\s*functions:\s*(.+)$", code, re.M)
    if funcs != ["successor/1"]:
        raise DriftError(f"functions declaration changed: {funcs}")
    if re.search(r"^\s*(builtins|equations)\s*:", code, re.M):
        raise DriftError("builtins/equations declared; the F* term algebra has none")
    rules = {}
    for m in re.finditer(
            r"\brule\s+(\w+)\s*:\s*\[(.*?)\]\s*(?:--\[(.*?)\]->|-->)\s*\[(.*?)\]",
            code, re.S):
        name, prem, act, concl = m.group(1), m.group(2), m.group(3) or "", m.group(4)
        if name in rules:
            raise DriftError(f"duplicate rule {name}")
        rules[name] = (parse_facts(prem), parse_facts(act), parse_facts(concl))
    if len(re.findall(r"\brule\s+\w+", code)) != len(rules):
        raise DriftError("a rule could not be parsed")
    restrictions = [(m.group(1), " ".join(m.group(2).split()))
                    for m in re.finditer(r'\brestriction\s+(\w+)\s*:\s*"(.*?)"', code, re.S)]
    lemmas = {}
    for m in re.finditer(r"\blemma\s+(\w+)\s*(?:\[[^\]]*\])?\s*:\s*(exists-trace|all-traces)?",
                         code):
        lemmas[m.group(1)] = m.group(2) or "all-traces"
    return rules, restrictions, lemmas


# --------------------------------------------------------------------------
# F* side
# --------------------------------------------------------------------------

def strip_fstar_comments(text):
    out, depth, i = [], 0, 0
    while i < len(text):
        if text.startswith("(*", i):
            depth += 1
            i += 2
        elif depth and text.startswith("*)", i):
            depth -= 1
            i += 2
        else:
            if not depth:
                out.append(text[i])
            i += 1
    return "".join(out)


def ftokenize(s):
    return re.findall(r'"[^"]*"|[A-Za-z_][A-Za-z0-9_\']*|[()\[\];]', s)


class FParser:
    def __init__(self, toks):
        self.toks, self.i = toks, 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, want=None):
        t = self.peek()
        if t is None or (want is not None and t != want):
            raise DriftError(f"F*: expected {want!r}, got {t!r}")
        self.i += 1
        return t

    def atom(self):
        t = self.take()
        if t == "(":
            v = self.term()
            self.take(")")
            return v
        if t == "initial":
            return ("pub", "initial")
        if t in ("variable", "fresh_name", "public_name"):
            s = self.take()
            if not s.startswith('"'):
                raise DriftError(f"F*: {t} needs a string literal")
            kind = {"variable": "var", "fresh_name": "fresh", "public_name": "pub"}[t]
            return (kind, s[1:-1])
        if t == "successor":
            return ("app", "successor", self.atom())
        if t == "tuple":
            a = self.atom()
            b = self.atom()
            return ("pair", a, b)
        raise DriftError(f"F*: unknown term head {t!r}")

    def term(self):
        return self.atom()

    def fact(self):
        self.take("mk_fact")
        sym = self.take()
        if not sym.startswith("F_"):
            raise DriftError(f"F*: bad fact symbol {sym}")
        pers = self.take()
        if pers not in ("true", "false"):
            raise DriftError("F*: persistence must be a literal")
        self.take("[")
        args = []
        if self.peek() != "]":
            args.append(self.term())
            while self.peek() == ";":
                self.take(";")
                args.append(self.term())
        self.take("]")
        return (sym[2:], pers == "true", tuple(args))

    def facts(self):
        self.take("[")
        out = []
        if self.peek() != "]":
            out.append(self.fact())
            while self.peek() == ";":
                self.take(";")
                out.append(self.fact())
        self.take("]")
        return out


def parse_fstar_rules(text):
    code = strip_fstar_comments(text)
    names = dict(re.findall(r"\|\s*(R_\w+)\s*->\s*(\w+_rule)\b", code))
    rules = {}
    for rname, fname in names.items():
        m = re.search(r"let\s+" + fname + r"\s*:\s*rule_instance\s*=\s*\{(.*?)\n\}", code, re.S)
        if not m:
            raise DriftError(f"F*: no definition for {fname}")
        body = m.group(1)
        if not re.search(r"r_name\s*=\s*" + rname + r"\s*;", body):
            raise DriftError(f"F*: {fname} has the wrong r_name")
        sides = []
        for field in ("r_premises", "r_actions", "r_conclusions"):
            fm = re.search(field + r"\s*=\s*(\[.*?\])\s*;?\s*(?=r_\w+\s*=|$)", body, re.S)
            if not fm:
                raise DriftError(f"F*: {fname} lacks {field}")
            sides.append(FParser(ftokenize(fm.group(1))).facts())
        rules[rname[2:]] = tuple(sides)
    arities = dict((s, int(n)) for s, n in re.findall(r"\|\s*F_(\w+)\s*->\s*(\d+)", code))
    return rules, arities


def fstar_lets(path):
    code = strip_fstar_comments(path.read_text())
    return set(re.findall(r"^let\s+(?:rec\s+)?(\w+)", code, re.M)), code


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def check(spthy=SPTHY, terms=TERMS, bridge=BRIDGE, witness=WITNESS):
    rules, restrictions, lemmas = parse_spthy(pathlib.Path(spthy).read_text())
    frules, arities = parse_fstar_rules(pathlib.Path(terms).read_text())
    if set(rules) != set(frules):
        raise DriftError(f"rule sets differ: spthy {sorted(rules)} vs F* {sorted(frules)}")
    inventory = {}
    for name, sides in rules.items():
        for side_name, a, b in zip(("premises", "actions", "conclusions"), sides, frules[name]):
            if list(a) != list(b):
                raise DriftError(f"rule {name}: {side_name} differ\n  spthy: {a}\n  F*:    {b}")
            for fname, _, args in a:
                if inventory.setdefault(fname, len(args)) != len(args):
                    raise DriftError(f"fact {fname} used with two arities")
    # Builtin facts of Tamarin's rules.
    for builtin in ("Fr", "In", "Out"):
        inventory.setdefault(builtin, 1)
    if inventory != arities:
        raise DriftError(f"fact inventory differs:\n  spthy: {sorted(inventory.items())}\n"
                         f"  F*:    {sorted(arities.items())}")
    if restrictions != [EXPECTED_RESTRICTION]:
        raise DriftError(f"restrictions changed: {restrictions}")
    blets, bcode = fstar_lets(pathlib.Path(bridge))
    wlets, wcode = fstar_lets(pathlib.Path(witness))
    missing = set(lemmas) - blets
    if missing:
        raise DriftError(f"lemmas without an F* formula: {sorted(missing)}")
    univ = re.search(r"let\s+m28_universal\s*\(h:strace\)\s*:\s*Type0\s*=(.*?)\n\n", bcode, re.S)
    exis = re.search(r"let\s+m28_exists\s*\(h:strace\)\s*:\s*Type0\s*=(.*?)\n\n", wcode, re.S)
    if not univ or not exis:
        raise DriftError("m28_universal / m28_exists not found")
    in_univ = set(re.findall(r"(\w+)\s+h\b", univ.group(1)))
    in_exis = set(re.findall(r"(\w+)\s+h\b", exis.group(1)))
    want_univ = {n for n, k in lemmas.items() if k == "all-traces"}
    want_exis = {n for n, k in lemmas.items() if k == "exists-trace"}
    if in_univ != want_univ:
        raise DriftError(f"m28_universal {sorted(in_univ)} != all-traces lemmas {sorted(want_univ)}")
    if in_exis != want_exis:
        raise DriftError(f"m28_exists {sorted(in_exis)} != exists-trace lemmas {sorted(want_exis)}")
    for name in ("original_universal_lemmas", "instrumented_universal_lemmas"):
        if name not in fstar_lets(FDIR / "M28_source_lemmas.fst")[0]:
            raise DriftError(f"missing theorem {name}")
    for name in ("original_exists_lemmas", "instrumented_exists_lemmas"):
        if name not in wlets:
            raise DriftError(f"missing theorem {name}")
    return len(rules), len(arities), len(lemmas)


def main(argv):
    try:
        if len(argv) not in (1, 5):
            raise DriftError("usage: check-m28-transcription.py [SPTHY TERMS BRIDGE WITNESS]")
        n_rules, n_facts, n_lemmas = check(*argv[1:]) if len(argv) == 5 else check()
    except (OSError, DriftError) as error:
        sys.exit(f"m28 transcription drift: {error}")
    print(f"m28 transcription matches the .spthy: {n_rules} rules, {n_facts} facts, "
          f"{n_lemmas} lemmas")


if __name__ == "__main__":
    main(sys.argv)
