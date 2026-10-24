#!/usr/bin/env python3
"""Reject trace-formula fact atoms that no rule emits as an action.

Tamarin distinguishes state facts from action facts.  A state fact (for
example DiskClean) cannot be observed directly by ``F @ #i``: only actions in
a rule's ``--[ ... ]->`` list can occur in a trace formula.  A lemma that uses
another fact name is unreachable and is therefore vacuous, not a proof.

This is a lightweight source guard, not a soundness proof.  It:
  * strips comments and string literals while scanning,
  * collects (name, arity) from every rule action list,
  * collects fact atoms of the form ``Name(args) @ #i`` (and ``Name @ #i``)
    from every lemma and restriction formula,
  * fails if an atom's name or arity is not emitted by a rule action.

Usage: check-action-atoms.py FILE [FILE ...]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
OPEN = "([{<"
CLOSE = ")]}>"


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments, preserving string literals and newlines."""
    out: list[str] = []
    i = 0
    n = len(text)
    quote: str | None = None
    while i < n:
        c = text[i]
        if quote is not None:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "\"'":
            quote = c
            out.append(c)
            i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise ValueError("unterminated block comment")
            out.append("\n" * text.count("\n", i, end + 2))
            i = end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            if end < 0:
                break
            out.append("\n")
            i = end + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def skip_string(text: str, start: int) -> int:
    """Return the index just past a quoted literal beginning at start."""
    quote = text[start]
    i = start + 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def match_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    """Return the index of the closing delimiter matching text[start]."""
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            i = skip_string(text, i)
            continue
        if c == opening:
            depth += 1
        elif c == closing:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"unbalanced {opening!r} at offset {start}")


def split_top_level(text: str, separator: str = ",") -> list[str]:
    """Split on separator outside (), [], {}, <>, and quoted literals."""
    parts: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    start = 0
    while i < n:
        c = text[i]
        if c in "\"'":
            i = skip_string(text, i)
            continue
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
        elif c == separator and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def arity_of(arg_text: str) -> int:
    if arg_text.strip() == "":
        return 0
    return len(split_top_level(arg_text))


def action_signature(item: str) -> tuple[str, int] | None:
    """Parse one action-list item into (name, arity)."""
    item = item.strip()
    if not item:
        return None
    # Persistent action facts are written with a leading !.
    while item.startswith("!"):
        item = item[1:].lstrip()
    m = re.match(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\((.*)\))?\s*(?:\[[^\]]*\])?\s*$",
        item,
        re.S,
    )
    if not m:
        return None
    name = m.group(1)
    args = m.group(2)
    if args is None:
        return name, 0
    return name, arity_of(args)


def collect_actions(text: str) -> dict[tuple[str, int], list[str]]:
    """Collect action signatures and the rules that emit them."""
    actions: dict[tuple[str, int], list[str]] = {}
    for m in re.finditer(r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", text, re.M):
        rule = m.group(1)
        rest = text[m.end():]
        start = rest.find("--[")
        if start < 0:
            continue
        inside_start = start + 3
        try:
            end = match_delimiter(rest, inside_start - 1, "[", "]")
        except ValueError as exc:
            raise ValueError(f"rule {rule}: {exc}") from exc
        for item in split_top_level(rest[inside_start:end]):
            sig = action_signature(item)
            if sig is not None:
                actions.setdefault(sig, []).append(rule)
    return actions


def read_formula(text: str, start: int) -> tuple[str, int]:
    """Read the double-quoted formula starting at start."""
    if start >= len(text) or text[start] != '"':
        raise ValueError("expected a double-quoted lemma formula")
    i = start + 1
    n = len(text)
    out: list[str] = []
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            out.append(text[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise ValueError("unterminated lemma formula")


def collect_formulas(text: str) -> list[tuple[str, str, str]]:
    """Return (kind, name, formula) for lemmas and restrictions."""
    formulas: list[tuple[str, str, str]] = []
    for m in re.finditer(r"^\s*(lemma|restriction)\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.M):
        kind, name = m.group(1), m.group(2)
        colon = text.find(":", m.end())
        if colon < 0:
            raise ValueError(f"{kind} {name}: missing colon")
        pos = colon + 1
        while pos < len(text) and text[pos].isspace():
            pos += 1
        qualifier = re.match(r"(?:all-traces|exists-trace)\b\s*", text[pos:])
        if qualifier:
            pos += qualifier.end()
        formula, _ = read_formula(text, pos)
        formulas.append((kind, name, formula))
    return formulas


def collect_atoms(formula: str) -> list[tuple[str, int]]:
    """Collect Name(args) @ #i atoms, skipping terms and literals."""
    atoms: list[tuple[str, int]] = []
    i = 0
    n = len(formula)
    while i < n:
        c = formula[i]
        if c in "\"'":
            i = skip_string(formula, i)
            continue
        m = IDENT.match(formula, i)
        if not m or (i > 0 and (formula[i - 1].isalnum() or formula[i - 1] == "_")):
            i += 1
            continue
        name = m.group(0)
        j = m.end()
        k = j
        while k < n and formula[k].isspace():
            k += 1
        arity = 0
        if k < n and formula[k] == "(":
            end = match_delimiter(formula, k, "(", ")")
            arity = arity_of(formula[k + 1:end])
            k = end + 1
            while k < n and formula[k].isspace():
                k += 1
            if k < n and formula[k] == "[":
                end = match_delimiter(formula, k, "[", "]")
                k = end + 1
                while k < n and formula[k].isspace():
                    k += 1
        if k < n and formula[k] == "@":
            atoms.append((name, arity))
            i = k + 1
            continue
        i = m.end()
    return atoms


def check_file(path: Path) -> list[str]:
    text = strip_comments(path.read_text())
    actions = collect_actions(text)
    problems: list[str] = []
    for kind, name, formula in collect_formulas(text):
        for fact, arity in collect_atoms(formula):
            if (fact, arity) not in actions:
                declared = sorted(
                    f"{n}/{a}" for (n, a) in actions if n == fact
                )
                hint = (
                    f"declared arities: {', '.join(declared)}"
                    if declared
                    else "no rule emits this action name"
                )
                problems.append(
                    f"{path}: {kind} {name}: atom {fact}/{arity} @ #i "
                    f"is not a rule action ({hint})"
                )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    failures: list[str] = []
    for arg in argv[1:]:
        path = Path(arg)
        if not path.is_file():
            print(f"{path}: not a file", file=sys.stderr)
            return 2
        try:
            problems = check_file(path)
        except ValueError as exc:
            print(f"{path}: parse error: {exc}", file=sys.stderr)
            return 2
        if problems:
            failures.extend(problems)
        else:
            print(f"{path}: all lemma/restriction action atoms are emitted by rules")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
