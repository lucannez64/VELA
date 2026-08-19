#!/usr/bin/env python3
"""Classify vault login sites by which in-core login path could cover them.

Reads the `LOGIN<TAB>name<TAB>url` lines from `list-sites.sh` on stdin, probes
each distinct site, and prints one row per site:

    SITE<TAB>covered<TAB>detail

`covered` is:
  passkey  — the vault already holds a passkey for this rp_id.
  form     — a server-rendered POST login form; the M9a plain-form path works.
  recipe   — no form in the raw HTML; a candidate for a hand-written recipe
             (clean API login) or the off-by-default JS runtime.
  blocked  — the site refuses a non-browser client (Cloudflare/403/429).
  unknown  — could not be reached or the page did not render a form.

Usage:
    ./security/list-sites.sh | ./security/classify-sites.py
    ./security/list-sites.sh | ./security/classify-sites.py --verbose
"""
from __future__ import annotations

import concurrent.futures as cf
import re
import ssl
import sys
import urllib.error
import urllib.request

TIMEOUT = 12
USER_AGENT = "VELA/classify (password manager site survey; no credentials sent)"

# Multi-part public suffixes that defeat a naive "last two labels" split.
_SUFFIXES = {
    "co.uk", "com.br", "co.jp", "com.au", "com.cn", "com.mx", "com.tr",
    "co.in", "co.za", "com.ar", "co.nz", "co.il", "com.sg", "com.hk",
    "com.tw", "org.uk", "net.au", "com.co",
}


def registrable(host: str) -> str:
    host = host.strip().lower()
    if not host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    tail = ".".join(parts[-2:])
    if tail in _SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail


def fetch(url: str) -> tuple[int | None, str]:
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
            body = r.read(2_000_000).decode("utf-8", "replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(300_000).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, body
    except Exception:
        return None, ""


def classify_one(domain: str, is_passkey: bool) -> tuple[str, str, str]:
    if is_passkey:
        return domain, "passkey", "passkey in the vault"
    if not re.match(r"^[a-z0-9.-]+$", domain):
        return domain, "unknown", f"not a bare domain: {domain!r}"

    # Try the common login paths; first HTTP 200 wins.
    attempts = [f"https://{domain}/login", f"https://{domain}/signin", f"https://{domain}/"]
    for url in attempts:
        status, body = fetch(url)
        if status == 403 or "cf-chl" in body or "cf_chl" in body or "cloudflare" in body[:2000].lower():
            return domain, "blocked", f"{status} bot-challenge"
        if status == 429:
            return domain, "blocked", "429 rate-limited"
        if status is not None and status >= 400:
            continue
        if status is None:
            return domain, "unknown", "unreachable"
        # A real page. Is there a server-rendered password form?
        if re.search(r"<form[^>]*method\s*=\s*[\"']?post", body, re.I) and "type=\"password\"" in body:
            return domain, "form", f"{url} has a POST password form"
        if "type=\"password\"" in body:
            return domain, "form", f"{url} has a password field"
        if re.search(r"<form", body, re.I):
            return domain, "recipe", f"{url} has a form but no password field (JS login?)"
        return domain, "recipe", f"{url} no form in raw HTML (JS/API login)"
    return domain, "unknown", "no reachable login page"


def main() -> None:
    verbose = "--verbose" in sys.argv
    passkeys: set[str] = set()
    logins: list[tuple[str, str]] = []  # (name, url)

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if parts[0] == "PASSKEY":
            passkeys.add(parts[1].strip().lower())
        elif parts[0] == "LOGIN" and len(parts) >= 3:
            logins.append((parts[1].strip(), parts[2].strip()))

    # Distinct registrable domains, remembering the first name seen.
    sites: dict[str, str] = {}
    for name, url in logins:
        host = re.sub(r"^[a-z]+://", "", url.strip()).split("/")[0].split(":")[0].rstrip(".")
        dom = registrable(host)
        sites.setdefault(dom, name)

    if not sites:
        print("No login sites found on stdin; run list-sites.sh first.", file=sys.stderr)
        return 1

    results: list[tuple[str, str, str]] = []
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(classify_one, dom, dom in passkeys): dom for dom in sites}
        for fut in cf.as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: (r[1], r[0]))

    counts: dict[str, int] = {}
    for dom, covered, detail in results:
        counts[covered] = counts.get(covered, 0) + 1
        print(f"{dom}\t{covered}\t{detail}\t#{sites[dom]}")
        if verbose:
            print(f"  -> {detail}", file=sys.stderr)

    print(file=sys.stderr)
    for kind in ("passkey", "form", "recipe", "blocked", "unknown"):
        print(f"{kind:8} {counts.get(kind, 0)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
