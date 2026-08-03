#!/usr/bin/env python3
"""
VELA project-specific security scanner (dependency-free).

Implements the Rust checks that the local semgrep build (osemgrep) cannot run
due to broken `.rs` file targeting. Mirrors the rules in `semgrep/vela-rust.yml`
so a standard Semgrep install can run the same logic in CI.

Checks:
  R1  missing-authsession   Axum route handler (takes State<AppState>) with no
                           AuthSession (or the stricter DeviceSession)
                           parameter. Audit S-2/S-4 class.
  R2  debug-format-crypto   `{:?}` Debug formatting inside crypto/derivation code.
                           Audit crypto M4 (cross-client key divergence).
  R3  panic-across-ffi      expect/unwrap/panic inside `extern "C"`. Audit L2.
  J1  (delegated to semgrep vela-js.yml: unescaped attr interpolation, native
      call without authorization.)

Intentionally-public route handlers (no AuthSession by design) are listed in
`semgrep/public-handlers.txt`, one function name per line (`#` comments allowed).
A handler not in that list that lacks AuthSession is a finding.

Exit code: 0 if clean, 1 if any finding.
"""
from __future__ import annotations
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_SRC = os.path.join(ROOT, "serverVELA", "vela-server", "src")
CRYPTO_DIRS = [
    os.path.join(ROOT, "libVELA", "vela-crypto", "src"),
    os.path.join(ROOT, "libVELA", "vela-core", "src"),
    os.path.join(ROOT, "libVELA", "vela-android-bridge", "src"),
    os.path.join(ROOT, "libVELA", "vela-wasm-bridge", "src"),
]
ALLOWLIST_FILE = os.path.join(ROOT, "security", "semgrep", "public-handlers.txt")

findings = []


def add(check, sev, path, line, msg):
    rel = os.path.relpath(path, ROOT)
    findings.append((check, sev, rel, line, msg))


def load_allowlist():
    names = set()
    if os.path.exists(ALLOWLIST_FILE):
        for raw in open(ALLOWLIST_FILE):
            s = raw.split("#", 1)[0].strip()
            if s:
                names.add(s)
    return names


# ── R1: missing AuthSession ──────────────────────────────────────────────────
def iter_fns(src):
    """Yield (name, param_text, sig_start_line) for every `pub async fn`/`pub fn`
    by paren-depth scanning so multi-line signatures parse correctly."""
    for dirpath, _, files in os.walk(src):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            txt = open(path, encoding="utf-8").read()
            for m in re.finditer(r"\bpub\s+(?:async\s+)?fn\s+(\w+)\s*\(", txt):
                name = m.group(1)
                open_paren = txt.index("(", m.start())
                depth = 0
                i = open_paren
                while i < len(txt):
                    c = txt[i]
                    if c == "(":
                        depth += 1
                    elif c == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                params = txt[open_paren:i + 1]
                line = txt.count("\n", 0, m.start()) + 1
                yield path, name, params, line


def check_missing_authsession():
    allow = load_allowlist()
    allow_unknown = []
    for path, name, params, line in iter_fns(SERVER_SRC):
        is_handler = "State<" in params and "AppState" in params
        if not is_handler:
            continue
        # `DeviceSession` is `AuthSession` plus a scope check — strictly
        # stronger, not weaker (red-team RT-4). Handlers that require a real
        # enrolled device must satisfy R1 too, or the only way to pass the gate
        # would be to whitelist them, which would blind it to someone later
        # dropping the session parameter altogether.
        if "AuthSession" in params or "DeviceSession" in params:
            continue
        if name in allow:
            continue
        add("R1 missing-authsession", "ERROR", path, line,
            f"`{name}` is a route handler (State<AppState>) with no AuthSession "
            f"parameter. Unauthenticated/unscoped endpoint (audit S-2/S-4). "
            f"If intentional, add `{name}` to public-handlers.txt.")


# ── R2: {:?} debug formatting in crypto code ─────────────────────────────────
# Debug formatting inside a format string: `{:?}`, `{:#?}`, `{name:?}`, `{0:?}`.
#
# The previous pattern was `\{:?\}`, where the `?` makes the *colon* optional —
# so it matched `{}` and never `{:?}`. It only ever fired on derivation contexts
# that happened to also contain a `{}`, and `format!("ctx {:?}", id)` — the exact
# thing this rule is named for — was invisible to it.
DEBUG_FMT = re.compile(r'format!\s*\([^;]*?\{[^{}"]*:#?\?\}')

# Debug output only matters where it becomes a *contract*: a KDF context, an
# info/domain-separation string, a salt. In an error message it is fine, and
# flagging those trains people to ignore the rule.
DERIVATION_SITE = re.compile(
    r"let\s+\w*(context|ctx|info|domain|salt)\w*\s*[:=]"
    r"|derive\w*\s*\(|new_keyed\s*\(|update\s*\(",
    re.IGNORECASE,
)
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")


def test_module_span(lines):
    """Line numbers (1-based, inclusive) covered by `#[cfg(test)] mod … { … }`.

    The rule is about *derivation* code: a `{:?}` in a test is usually the
    opposite of a finding — `kdf.rs` compares its explicit context builder
    against the very `format!("{:?}")` it replaced, which is what proves no
    vault gets re-keyed. Flagging that would push someone to delete the check.
    """
    spans = set()
    for index, line in enumerate(lines):
        if not CFG_TEST.match(line):
            continue
        depth, started = 0, False
        for offset in range(index, len(lines)):
            depth += lines[offset].count("{") - lines[offset].count("}")
            started = started or "{" in lines[offset]
            spans.add(offset + 1)
            if started and depth <= 0:
                break
    return spans


def check_debug_format_crypto():
    for d in CRYPTO_DIRS:
        if not os.path.isdir(d):
            continue
        for dirpath, _, files in os.walk(d):
            for fn in files:
                if not fn.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, fn)
                lines = open(path, encoding="utf-8").read().splitlines()
                in_tests = test_module_span(lines)
                for i, raw in enumerate(lines, 1):
                    if i in in_tests:
                        continue
                    if DEBUG_FMT.search(raw) and DERIVATION_SITE.search(raw):
                        add("R2 debug-format-crypto", "WARN", path, i,
                            "Debug formatting (`{:?}`) in crypto/derivation code — "
                            "not a stable serialization contract (audit crypto M4).")


# ── R3: panic operators inside extern "C" ────────────────────────────────────
EXTERN_FN = re.compile(r'extern\s+"C"\s+fn\s+(\w+)\s*\(')
CALL = re.compile(r'\b(\w+)\s*\(')
PANIC_OPS = [r"\.expect\(", r"\.unwrap\(\)", r"panic!\(", r"\.unwrap_or_else\([^)]*\.expect\("]


def _brace_block(txt, open_idx):
    """Return the balanced {..} block starting at open_idx (txt[open_idx]=='{')."""
    bdepth = 0
    j = open_idx
    while j < len(txt):
        if txt[j] == "{":
            bdepth += 1
        elif txt[j] == "}":
            bdepth -= 1
            if bdepth == 0:
                break
        j += 1
    return txt[open_idx:j + 1], j


def _report_panics(txt, body, base, path, label):
    for op in PANIC_OPS:
        for pm in re.finditer(op, body):
            line = txt.count("\n", 0, base + pm.start()) + 1
            add("R3 panic-across-ffi", "WARN", path, line,
                f"Panicking operator inside {label} (audit crypto L2).")


def check_panic_ffi():
    for d in CRYPTO_DIRS + [os.path.join(ROOT, "libVELA", "cyclo")]:
        if not os.path.isdir(d):
            continue
        for dirpath, _, files in os.walk(d):
            for fn in files:
                if not fn.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, fn)
                txt = open(path, encoding="utf-8").read()
                for m in EXTERN_FN.finditer(txt):
                    sig_open = txt.index("(", m.start())
                    depth = 0
                    i = sig_open
                    while i < len(txt):
                        if txt[i] == "(":
                            depth += 1
                        elif txt[i] == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        i += 1
                    try:
                        brace = txt.index("{", i)
                    except ValueError:
                        continue
                    body, end = _brace_block(txt, brace)
                    _report_panics(txt, body, brace, path,
                                   f'`extern "C" fn {m.group(1)}`')
                    # one-hop: panic ops in private helpers this extern fn calls
                    for call in CALL.findall(body):
                        if not (call in ("if", "for", "while", "match", "return",
                                         "let", "Some", "None", "Ok", "Err", "Box",
                                         "Vec", "String", "CString", "self")):
                            # find a private `fn call(` definition in this file
                            for cm in re.finditer(
                                    r"\bfn\s+" + re.escape(call) + r"\s*\(", txt):
                                c_brace = txt.index("{", cm.end())
                                c_body, _ = _brace_block(txt, c_brace)
                                _report_panics(txt, c_body, c_brace, path,
                                               f"helper `fn {call}` called by "
                                               f'extern "C" fn {m.group(1)}')


def main():
    check_missing_authsession()
    check_debug_format_crypto()
    check_panic_ffi()
    if not findings:
        print("VELA security scan: clean (0 findings)")
        return 0
    findings.sort(key=lambda f: (f[0], f[2], f[3]))
    last = None
    for check, sev, rel, line, msg in findings:
        if check != last:
            print(f"\n== {check} ==")
            last = check
        print(f"  [{sev}] {rel}:{line}  {msg}")
    print(f"\nVELA security scan: {len(findings)} finding(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
