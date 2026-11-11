#!/usr/bin/env python3
"""Check zeroization of VELA's secret-bearing Rust types (plan step C16).

This is a *targeted static check*, not a proof about the compiler or the OS.
The allowlist below is the reviewed inventory of types that hold symmetric
keys, KEM/DH/signature secret keys, seeds, recovery shares, KDF outputs,
passwords, or decrypted vault plaintext. For every entry the declaration must:

  * carry a `Zeroize`/`ZeroizeOnDrop` derive or impl, a manual `Drop` that
    wipes the secret fields, or wrap them in `Zeroizing<_>`; and
  * not derive `Copy` (a bitwise copy defeats every destructor); and
  * not derive `Debug` unless a hand-written `Debug` impl redacts the secret
    (the inventory's `REDACTED` convention), because a derived `Debug` prints
    keys into logs.

Adding a new secret-bearing type is a deliberate act: add it here after
reviewing its drop path. Removing a derive or adding `Copy`/`Debug` fails the
check. The companion test mutates real source to prove the failure is live.

Run from the repository root: `python3 -I security/formal/check-secret-erasure.py`
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# (relative path, declaration kind, type name)
ALLOWLIST = (
    # vela-crypto: keys, seeds, shares, KDF output, decrypted plaintext
    ("libVELA/vela-crypto/src/kdf.rs", "struct", "DerivedKey"),
    ("libVELA/vela-crypto/src/kem.rs", "struct", "HybridSecretKey"),
    ("libVELA/vela-crypto/src/kem.rs", "struct", "SharedSecret"),
    ("libVELA/vela-crypto/src/signing.rs", "struct", "HybridSigningKey"),
    ("libVELA/vela-crypto/src/identity.rs", "struct", "DeviceIdentity"),
    ("libVELA/vela-crypto/src/shamir.rs", "struct", "Share"),
    ("libVELA/vela-crypto/src/recovery.rs", "struct", "ReconstructedRms"),
    ("libVELA/vela-crypto/src/recovery.rs", "struct", "KdfStreamRng"),
    ("libVELA/vela-crypto/src/share_envelope.rs", "struct", "OpenedShare"),
    ("libVELA/vela-crypto/src/oram.rs", "enum", "OramBlock"),
    # vela-core: vault plaintext and richer-item secrets
    ("libVELA/vela-core/src/vault.rs", "enum", "VaultItem"),
    ("libVELA/vela-core/src/rich_items.rs", "struct", "SensitiveValue"),
    ("libVELA/vela-core/src/rich_items.rs", "struct", "AdditionalUrl"),
    ("libVELA/vela-core/src/rich_items.rs", "struct", "IdentityDetails"),
    ("libVELA/vela-core/src/rich_items.rs", "struct", "PostalAddress"),
    # Desktop key file + Android JNI byte-array wrapper
    (
        "desktopVELA/vela-desktop-core/src/store.rs",
        "struct",
        "IdentityKeysStore",
    ),
    ("libVELA/vela-android-bridge/src/lib.rs", "struct", "SecretBytes"),
)

# A declaration such as `pub struct Foo`, `pub(crate) enum Foo`, `struct Foo`.
_DECL = r"\b(?:pub(?:\s*\([^)]*\))?\s+)?%s\s+%s\b"


def _declaration_line(lines, kind, name):
    pattern = re.compile(_DECL % (kind, re.escape(name)))
    for index, line in enumerate(lines):
        if pattern.search(line):
            return index
    return None


def _attributes(lines, index):
    """Attributes directly above a declaration (doc comments are skipped)."""
    attrs = []
    i = index - 1
    while i >= 0:
        text = lines[i].strip()
        if text.startswith("#["):
            attrs.append(text)
        elif text.startswith("///") or text.startswith("//") or text.startswith("#!["):
            pass
        else:
            break
        i -= 1
    return attrs


def _impl_body(source, trait, name):
    """Return the braced body of `impl <trait> for <name>`, if any."""
    pattern = re.compile(
        r"impl(?:\s*<[^>]*>)?\s+%s\s+for\s+%s\b" % (trait, re.escape(name))
    )
    match = pattern.search(source)
    if not match:
        return None
    brace = source.find("{", match.end())
    if brace < 0:
        return ""
    depth = 0
    for i in range(brace, len(source)):
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace : i + 1]
    return source[brace:]


def _macro_redacts(source, name):
    """The repo's `redact_debug!(Type, ...)` review macro counts as redacting."""
    for match in re.finditer(r"redact_debug!\(([^)]*)\)", source):
        if re.search(r"\b%s\b" % re.escape(name), match.group(1)) and re.search(
            r"REDACTED|redact", source, re.IGNORECASE
        ):
            return True
    return False


def audit_source(relpath, source):
    """Findings for the allowlisted types declared in `relpath`."""
    lines = source.splitlines()
    findings = []
    for path, kind, name in ALLOWLIST:
        if path != relpath:
            continue
        index = _declaration_line(lines, kind, name)
        if index is None:
            findings.append(
                "%s: allowlisted secret type `%s` not found (renamed or removed?)"
                % (relpath, name)
            )
            continue
        line = index + 1
        attrs = _attributes(lines, index)
        derives = "\n".join(attrs)
        prefix = "%s:%d: %s `%s`" % (relpath, line, kind, name)

        has_copy = re.search(r"\bCopy\b", derives) is not None
        if has_copy:
            findings.append(prefix + " derives Copy, which defeats zeroization")

        derives_debug = re.search(r"\bDebug\b", derives) is not None
        debug_body = _impl_body(source, r"(?:std::fmt::)?Debug", name)
        redacts = (
            debug_body is not None
            and re.search(r"REDACTED|redact", debug_body, re.IGNORECASE) is not None
        )
        if derives_debug:
            findings.append(prefix + " derives Debug (secrets can reach logs)")
        elif debug_body is not None and not redacts:
            findings.append(prefix + " has a Debug impl that does not redact")
        elif debug_body is None and not _macro_redacts(source, name):
            # No Debug at all is fine; record nothing.
            pass

        zeroize_derive = re.search(r"\bZeroize(?:OnDrop)?\b", derives) is not None
        zeroize_impl = (
            _impl_body(source, r"(?:zeroize::)?ZeroizeOnDrop", name) is not None
            or _impl_body(source, r"(?:zeroize::)?Zeroize\b", name) is not None
        )
        drop_body = _impl_body(source, "Drop", name)
        drop_wipes = drop_body is not None and (
            re.search(r"zeroize", drop_body, re.IGNORECASE) is not None
            or "write_volatile" in drop_body
        )
        # A type-level `Zeroizing<_>` field is the wrapping form. Look at the
        # declaration body rather than the whole file so comments do not count.
        end = index
        depth = 0
        started = False
        for i in range(index, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if "{" in lines[i]:
                started = True
            end = i
            if started and depth <= 0:
                break
        body = "\n".join(lines[index : end + 1])
        wrapped = re.search(r"\bZeroizing\s*<", body) is not None

        if not (zeroize_derive or zeroize_impl or drop_wipes or wrapped):
            findings.append(
                prefix
                + " has no Zeroize derive/impl, wiping Drop, or Zeroizing field"
            )
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("root", nargs="?", default=str(ROOT))
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root).resolve()

    findings = []
    seen = set()
    for relpath, _kind, _name in ALLOWLIST:
        if relpath in seen:
            continue
        seen.add(relpath)
        path = root / relpath
        if not path.exists():
            findings.append("%s: allowlisted secret-bearing file is missing" % relpath)
            continue
        findings.extend(audit_source(relpath, path.read_text(encoding="utf-8")))

    for finding in findings:
        print(finding)
    if findings:
        print(
            "%d secret-erasure finding(s) across %d listed files"
            % (len(findings), len(seen)),
            file=sys.stderr,
        )
        return 1
    print(
        "%d secret-bearing types in %d files: zeroized, not Copy, not Debug-leaking."
        % (len(ALLOWLIST), len(seen))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
