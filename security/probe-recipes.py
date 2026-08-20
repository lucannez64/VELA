#!/usr/bin/env python3
"""Probe "recipe" sites for a reachable, clean login API (no bot wall).

Reads `SITE<TAB>...` rows (the "recipe" lines from classify-sites.py) on
stdin, tries the common login-endpoint shapes each site is likely to use, and
prints `SITE<TAB>verdict<TAB>endpoint<TAB>status` where verdict is one of:

  clean    a login endpoint answered 200 with a JSON body (recipe candidate)
  blocked  every reachable attempt was a bot challenge (403/Cloudflare/429)
  none     reachable but no recognisable login endpoint found
  unreach  the site did not answer at all

Usage:
    ./security/list-sites.sh | ./security/classify-sites.py | \\
        grep '^.*\trecipe\t' | ./security/probe-recipes.py
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

TIMEOUT = 12
UA = "VELA/probe (password manager site survey; no credentials sent)"

# (path, method, body) candidates tried for each site.
ATTEMPTS = [
    ("/api/v1/instance", "GET", None),            # Mastodon family
    ("/api/v1/oauth/token", "POST", {"grant_type": "client_credentials"}),  # Mastodon
    ("/api/auth/login", "POST", {}),              # Immich
    ("/api/v1/auth/login", "POST", {}),           # Immich (older) / others
    ("/auth/login", "POST", {}),                  # generic
    ("/api/v1/login", "POST", {}),
    ("/login", "POST", {}),
    ("/api/v1/stats", "GET", None),               # Invidious
    ("/api/v1/login", "GET", None),               # Piped / Invidious instance info
]


def try_url(site: str, path: str, method: str, body) -> tuple[int | None, str, str]:
    url = f"https://{site}{path}"
    data = None
    headers = {"User-Agent": UA, "Accept": "application/json, text/html"}
    if method == "POST":
        if body is None:
            data = b""
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    else:
        req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
            raw = r.read(500_000).decode("utf-8", "replace")
            return r.status, r.headers.get("content-type", ""), raw
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read(200_000).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, e.headers.get("content-type", ""), raw
    except Exception:
        return None, "", ""


def is_challenge(status, ctype, body) -> bool:
    low = body[:3000].lower()
    if status in (403, 429):
        return True
    return any(m in low for m in ("cf-chl", "cf_chl", "cloudflare", "captcha", "challenge"))


def probe_one(site: str) -> tuple[str, str, str, str]:
    if not re.match(r"^[a-z0-9.-]+$", site):
        return site, "none", "", ""
    any_reachable = False
    for path, method, body in ATTEMPTS:
        status, ctype, raw = try_url(site, path, method, body)
        if status is None:
            continue
        any_reachable = True
        if is_challenge(status, ctype, raw):
            return site, "blocked", f"{method} {path}", str(status)
        if 200 <= status < 300 and ("json" in ctype or raw.lstrip().startswith(("{", "["))):
            return site, "clean", f"{method} {path}", str(status)
    return site, ("unreach" if not any_reachable else "none"), "", ""


def main() -> None:
    sites: list[str] = []
    for line in sys.stdin:
        line = line.rstrip("\n")
        parts = line.split("\t")
        if parts and parts[0]:
            sites.append(parts[0])
    if not sites:
        print("No sites on stdin.", file=sys.stderr)
        return 1

    results: list[tuple[str, str, str, str]] = []
    with cf.ThreadPoolExecutor(max_workers=10) as pool:
        for fut in cf.as_completed([pool.submit(probe_one, s) for s in sites]):
            results.append(fut.result())
    results.sort(key=lambda r: (r[1], r[0]))

    counts: dict[str, int] = {}
    for site, verdict, endpoint, status in results:
        counts[verdict] = counts.get(verdict, 0) + 1
        print(f"{site}\t{verdict}\t{endpoint}\t{status}")

    print(file=sys.stderr)
    for kind in ("clean", "blocked", "none", "unreach"):
        print(f"{kind:8} {counts.get(kind, 0)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
