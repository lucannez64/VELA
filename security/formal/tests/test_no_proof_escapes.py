#!/usr/bin/env python3
"""Regression cases for the repository-wide proof-escape check (plan step T2)."""
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("escapes", HERE.parent / "check-no-proof-escapes.py")
escapes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(escapes)


def found(source, name="M.fst", siblings=()):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / name
        p.write_text(source)
        for s in siblings:
            (pathlib.Path(d) / s).write_text("module X\n")
        return escapes.problems(p, source)


class NoProofEscapes(unittest.TestCase):
    def test_repository_is_clean(self):
        self.assertEqual(escapes.main([]), 0)

    def test_escapes_in_code_are_rejected(self):
        for word in ("admit ()", "assume (False)", "assume val x : int", "Admitted", "magic ()",
                     "unsafe_coerce x", "[@@expect_failure] let x = 1", "admit1 ()"):
            with self.subTest(word=word):
                self.assertTrue(found(f"module M\nlet f () = {word}\n"))

    def test_comments_and_strings_are_masked(self):
        self.assertEqual(found("module M\n(* admit () *)\n// assume\nlet s = \"admit\"\n"), [])

    def test_nested_comment_cannot_hide_code(self):
        self.assertTrue(found("module M\n(* (* *) *) let x = admit ()\n"))
        self.assertTrue(found("module M\n(* (* *) admit *) *) let y = 1\nlet z = admit ()\n"))

    def test_identifiers_containing_the_words_pass(self):
        self.assertEqual(found("module M\nlet assumed_ok = 1\nlet readmit = 2\nlet magic_number = 3\n"), [])

    def test_interface_without_implementation_is_rejected(self):
        self.assertTrue(found("module M\nval f : int -> int\n", name="M.fsti"))
        self.assertEqual(found("module M\nval f : int -> int\n", name="M.fsti", siblings=("M.fst",)), [])

    def test_tracked_mode_matches_git(self):
        out = subprocess.run(["git", "-C", str(escapes.ROOT), "ls-files", "--", "*.fst", "*.fsti"],
                             capture_output=True, text=True, check=True).stdout.split()
        scanned = {str(p.relative_to(escapes.ROOT)) for p in escapes.corpus()}
        self.assertTrue(scanned)
        self.assertTrue(scanned <= set(out))


if __name__ == "__main__":
    unittest.main()
