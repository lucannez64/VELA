#!/usr/bin/env python3
"""Adversarial regression cases for the driver source-policy guard."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('driver_guard', Path(__file__).resolve().parents[1] / 'check-driver-proof-sources.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DriverGuardTests(unittest.TestCase):
    def test_real_modules_pass(self):
        root = Path(__file__).resolve().parents[3]
        for crate, suffix in [('vela-recovery-policy', 'driver'), ('vela-recovery-policy', 'possession-driver'), ('vela-share-policy', 'driver')]:
            base = root / 'serverVELA' / crate / 'proofs/fstar'
            for path in (base / ('extraction-' + suffix)).glob('*.fst'):
                guard.check_source(path.read_text(), generated=True)
            for folder in [suffix + '-lemmas', suffix + '-composition']:
                for path in (base / folder).glob('*.fst'):
                    guard.check_source(path.read_text())

    def test_nested_comments_and_strings(self):
        guard.check_source('(* assume (* axiom *) admit *)\nlet text = "admit // (*"\nlet ok : Lemma True = ()')

    def test_line_comment_cannot_hide_escape_after_block_comment(self):
        with self.assertRaises(ValueError):
            guard.check_source('let bad : Lemma False = (* // *) admit()')

    def test_all_escapes_refused(self):
        for escape in ['assume val bad: False', 'axiom bad: False', 'let bad = admit()', 'let bad = unsafe_coerce ()', '[@@expect_failure] let bad : Lemma False = ()', 'val bad: False']:
            with self.subTest(escape=escape), self.assertRaises(ValueError):
                guard.check_source(escape)

    def test_option_admission_refused(self):
        for pragma in ['#set-options "--lax"', '#push-options "--admit_smt_queries true"', '#reset-options', '#push-options "--fuel 4 --ifuel 2 --lax"']:
            with self.subTest(pragma=pragma), self.assertRaises(ValueError):
                guard.check_source(pragma)

    def test_reviewed_headers_only_in_generated_modules(self):
        header = '#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"'
        guard.check_source(header, generated=True)
        for source, generated in [(header, False), (header + '\n' + header, True), ('#set-options "--fuel 0 --ifuel 1 --z3rlimit 500 --lax"', True)]:
            with self.assertRaises(ValueError):
                guard.check_source(source, generated=generated)

    def test_budget_scopes_are_balanced(self):
        push = '#push-options "--fuel 4 --ifuel 2"'
        guard.check_source(push + '\nlet ok : Lemma True = ()\n#pop-options')
        for source in [push, '#pop-options', push + '\n' + push + '\n#pop-options\n#pop-options']:
            with self.assertRaises(ValueError):
                guard.check_source(source)

    def test_unterminated_comment_or_string_refused(self):
        for source in ['(* never ends', 'let text = "never ends']:
            with self.assertRaises(ValueError):
                guard.check_source(source)


if __name__ == '__main__':
    unittest.main()
