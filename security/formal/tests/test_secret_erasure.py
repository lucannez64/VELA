#!/usr/bin/env python3
"""Regression cases for the secret-erasure guard (plan step C16).

The repository must pass, and a mutation that removes a real zeroization
derive/impl, adds `Copy`, or lets `Debug` print a secret must fail. The tests
mutate the checked-in source text in memory, so they fail if the guard becomes
a no-op.
"""
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "secret_erasure", HERE.parent / "check-secret-erasure.py"
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

SHAMIR = "libVELA/vela-crypto/src/shamir.rs"
KDF = "libVELA/vela-crypto/src/kdf.rs"
ORAM = "libVELA/vela-crypto/src/oram.rs"


def source(relpath):
    return (guard.ROOT / relpath).read_text(encoding="utf-8")


def findings(relpath, text):
    return guard.audit_source(relpath, text)


class SecretErasure(unittest.TestCase):
    def test_repository_is_clean(self):
        self.assertEqual(guard.main([]), 0)

    def test_removing_a_zeroize_derive_fails(self):
        text = source(SHAMIR)
        mutant = text.replace(
            "#[derive(Clone, Zeroize, ZeroizeOnDrop)]", "#[derive(Clone)]", 1
        )
        self.assertNotEqual(mutant, text, "fixture drifted: derive line missing")
        out = findings(SHAMIR, mutant)
        self.assertTrue(
            any("Share" in line and "no Zeroize" in line for line in out), out
        )

    def test_deriving_copy_fails(self):
        text = source(KDF)
        mutant = text.replace(
            "#[derive(Clone, ZeroizeOnDrop)]",
            "#[derive(Clone, Copy, ZeroizeOnDrop)]",
            1,
        )
        self.assertNotEqual(mutant, text, "fixture drifted: derive line missing")
        out = findings(KDF, mutant)
        self.assertTrue(any("DerivedKey" in line and "Copy" in line for line in out), out)

    def test_deriving_debug_fails(self):
        text = source(KDF)
        mutant = text.replace(
            "#[derive(Clone, ZeroizeOnDrop)]",
            "#[derive(Clone, Debug, ZeroizeOnDrop)]",
            1,
        )
        self.assertNotEqual(mutant, text, "fixture drifted: derive line missing")
        out = findings(KDF, mutant)
        self.assertTrue(
            any("DerivedKey" in line and "Debug" in line for line in out), out
        )

    def test_non_redacting_debug_fails(self):
        text = source(SHAMIR)
        # The custom Debug impl for Share currently redacts both secret fields.
        mutant = text.replace(
            '.field("y", &"[REDACTED]")', '.field("y", &self.y)', 1
        )
        mutant = mutant.replace(
            '.field("mac", &self.mac.as_ref().map(|_| "[REDACTED]"))',
            '.field("mac", &self.mac)',
            1,
        )
        self.assertNotEqual(mutant, text, "fixture drifted: redaction missing")
        out = findings(SHAMIR, mutant)
        self.assertTrue(
            any("Share" in line and "Debug impl" in line for line in out), out
        )

    def test_removing_a_wiping_drop_fails(self):
        text = source(ORAM)
        mutant = text.replace("impl Drop for OramBlock", "impl Drop for OldOramBlock", 1)
        self.assertNotEqual(mutant, text, "fixture drifted: Drop impl missing")
        out = findings(ORAM, mutant)
        self.assertTrue(
            any("OramBlock" in line and "no Zeroize" in line for line in out), out
        )

    def test_renamed_secret_type_fails(self):
        text = source(KDF)
        mutant = text.replace("pub struct DerivedKey", "pub struct RenamedKey", 1)
        self.assertNotEqual(mutant, text, "fixture drifted: declaration missing")
        out = findings(KDF, mutant)
        self.assertTrue(
            any("DerivedKey" in line and "not found" in line for line in out), out
        )


if __name__ == "__main__":
    unittest.main()
