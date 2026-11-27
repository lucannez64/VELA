#!/usr/bin/env python3
"""Check that VELA's crate dependency graph keeps its architectural layers.

The layers below hold today; this guard keeps a new dependency edge, crypto
primitive or ``unsafe`` block from crossing one without review. An agent that
adds such an edge gets the rule and its reason here, at the moment it breaks
it, instead of from a reviewer later.

Rules (each failure names the rule):

  * ``policy-leaf``: a policy crate (``vela-*-policy``, the share journal)
    depends on no other VELA crate. They are the hax/F*-verified cores, so
    their proofs stay closed over their own source.
  * ``core-leaf``: ``vela-core`` and ``vela-import`` depend on no VELA crate.
  * ``crypto-deps``: ``vela-crypto`` depends only on client policy crates.
  * ``no-bridge-deps``: no crate depends on a platform bridge; bridges are the
    outer FFI shell (see check-bridge-thinness.py).
  * ``server-client``: server crates do not depend on client-only crates, and
    client crates do not depend on server crates. ``vela-crypto`` is shared.
  * ``vault-primitives``: only ``vela-crypto`` depends on the vault's
    cryptographic primitives (KEM, key agreement, KDF, AEAD, signatures,
    password hashing). Other uses are listed in PRIMITIVE_EXCEPTIONS with a
    reason.
  * ``unsafe``: a library or server crate not in UNSAFE_ALLOWED contains no
    ``unsafe`` token. (A crate attribute would be stronger, but the policy
    crates' sources and manifests are hash-pinned by reviewed proofs.)

What it does NOT check: dependencies pulled in transitively by a third-party
crate, ``unsafe`` produced by macros, or vendored and experimental crates.

Usage: python3 -I security/formal/check-crate-boundaries.py [--root DIR]
Exit status 0 when every rule holds, 1 with findings otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[2]

# Directories whose crates are VELA's own. Vendored, fuzz, exploit and
# experiment crates are outside the product graph.
PRODUCT_DIRS = ("libVELA", "serverVELA", "desktopVELA")
SKIP_PARTS = {"vendor", "fuzz", "experiments", "target", "node_modules"}

POLICY_RE = re.compile(r"^vela-(?:[a-z-]+-policy|client-share-journal)$")
CORE_LEAVES = {"vela-core", "vela-import"}
CRYPTO = "vela-crypto"
CLIENT_POLICIES = {
    "vela-client-recovery-policy",
    "vela-client-share-policy",
    "vela-sync-policy",
}

VAULT_PRIMITIVES = {
    "ml-kem", "ml-dsa", "fips203", "fips204", "x25519-dalek", "curve25519-dalek",
    "hkdf", "chacha20poly1305", "aes", "aes-gcm", "aes-gcm-siv", "argon2",
    "pbkdf2", "scrypt", "blake3", "ed25519-dalek", "ring", "aws-lc-rs", "openssl",
}
PRIMITIVE_EXCEPTIONS = {
    ("vela-server", "argon2"): "migration.rs stretches migration verifiers",
    ("vela-server", "blake3"): "migration.rs content-hashes migration bundles",
    ("vela-cli", "ed25519-dalek"): "the SSH agent signs with the user's own SSH keys",
}

UNSAFE_ALLOWED = {
    "vela-android-bridge": "JNI exports",
    "vela-apple-bridge": "C ABI exports",
    "vela-crypto": "volatile zeroing in kem.rs and field moves in signing.rs",
    "vela-server": "reviewed separately in SECURITY_AUDIT.md",
}
UNSAFE_RE = re.compile(r"\bunsafe\b")
COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')


@dataclass
class Crate:
    name: str
    manifest: str
    side: str  # "server" or "client"
    deps: set[str] = field(default_factory=set)  # path dependencies (VELA crates)
    external: set[str] = field(default_factory=set)


def _dep_tables(data: dict):
    # Normal and build dependencies define the shipped graph; dev-dependencies
    # are test harness wiring and may cross layers.
    for sec in ("dependencies", "build-dependencies"):
        yield data.get(sec, {})
    for target in data.get("target", {}).values():
        for sec in ("dependencies", "build-dependencies"):
            yield target.get(sec, {})


def load_crates(root: Path) -> dict[str, Crate]:
    crates: dict[str, Crate] = {}
    for top in PRODUCT_DIRS:
        for manifest in sorted((root / top).rglob("Cargo.toml")):
            rel = manifest.relative_to(root)
            if SKIP_PARTS & set(rel.parts):
                continue
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            name = data.get("package", {}).get("name")
            if not name:
                continue
            crate = Crate(name, str(rel), "server" if top == "serverVELA" else "client")
            for table in _dep_tables(data):
                for dep, spec in table.items():
                    real = spec.get("package", dep) if isinstance(spec, dict) else dep
                    if isinstance(spec, dict) and "path" in spec:
                        crate.deps.add(real)
                    else:
                        crate.external.add(real)
            crates[name] = crate
    return crates


def rust_sources(root: Path, manifest: str):
    src = (root / manifest).parent / "src"
    return sorted(src.rglob("*.rs")) if src.is_dir() else []


def check_repo(root: Path) -> list[str]:
    crates = load_crates(root)
    findings: list[str] = []

    def fail(rule: str, crate: Crate, message: str) -> None:
        findings.append(f"{crate.manifest}: [{rule}] {message}")

    for c in crates.values():
        vela_deps = {d for d in c.deps if d in crates}
        if POLICY_RE.match(c.name) and vela_deps:
            fail("policy-leaf", c, f"policy crate depends on {sorted(vela_deps)}; "
                 "keep verified policy crates free of VELA dependencies")
        if c.name in CORE_LEAVES and vela_deps:
            fail("core-leaf", c, f"depends on {sorted(vela_deps)}; it must stay a leaf")
        if c.name == CRYPTO and vela_deps - CLIENT_POLICIES:
            fail("crypto-deps", c, f"depends on {sorted(vela_deps - CLIENT_POLICIES)}; "
                 f"vela-crypto may only use {sorted(CLIENT_POLICIES)}")
        for d in sorted(vela_deps):
            if d.endswith("-bridge"):
                fail("no-bridge-deps", c, f"depends on bridge {d}; move the shared "
                     "code into vela-core or vela-crypto")
            other = crates[d]
            if d != CRYPTO and other.side != c.side:
                fail("server-client", c, f"{c.side} crate depends on {other.side} "
                     f"crate {d}; share it through vela-crypto or a policy crate")
        if c.name != CRYPTO:
            for prim in sorted(c.external & VAULT_PRIMITIVES):
                if (c.name, prim) not in PRIMITIVE_EXCEPTIONS:
                    fail("vault-primitives", c, f"uses {prim} directly; call "
                         "vela-crypto instead, or add a reviewed entry to "
                         "PRIMITIVE_EXCEPTIONS with the reason")
        if c.name not in UNSAFE_ALLOWED and (
                c.manifest.startswith(("libVELA/", "serverVELA/"))):
            for path in rust_sources(root, c.manifest):
                code = STRING_RE.sub('""', COMMENT_RE.sub("", path.read_text(encoding="utf-8")))
                if UNSAFE_RE.search(code):
                    fail("unsafe", c, f"{path.relative_to(root)} uses unsafe; keep "
                         "unsafe in the crates listed in UNSAFE_ALLOWED")
    for name, _ in PRIMITIVE_EXCEPTIONS:
        if name not in crates:
            findings.append(f"PRIMITIVE_EXCEPTIONS lists unknown crate {name}; remove the entry")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check VELA crate boundaries.")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    findings = check_repo(args.root)
    if findings:
        print("\n".join(findings))
        return 1
    print(f"Crate boundaries hold for {len(load_crates(args.root))} crates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
