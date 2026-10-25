#!/usr/bin/env python3
"""Adversarial regression cases for the driver source-policy guard."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import subprocess
import sys
import os

spec = importlib.util.spec_from_file_location('driver_guard', Path(__file__).resolve().parents[1] / 'check-driver-proof-sources.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DriverGuardTests(unittest.TestCase):
    def test_real_modules_pass(self):
        root = Path(__file__).resolve().parents[3]
        directories = list(root.glob('serverVELA/vela-*-policy/proofs/fstar/extraction-*driver'))
        self.assertTrue(directories)
        for directory in directories:
            suffix = directory.name.removeprefix('extraction-')
            base = directory.parent
            proof_files = list((base / (suffix + '-lemmas')).glob('*.fst'))
            proof_files += list((base / (suffix + '-composition')).glob('*.fst'))
            if suffix == 'login-driver':
                proof_files += list((base / 'challenge-lemmas').glob('*.fst'))
                proof_files += list((base / 'login-raw-nonce-lemmas').glob('*.fst'))
            self.assertTrue(proof_files)
            guard.check_files(list(directory.glob('*.fst')), proof_files, [base.parents[1]])

    def test_focused_driver_runners_are_executable_in_git(self):
        root = Path(__file__).resolve().parents[3]
        runners = list(root.glob('serverVELA/vela-*-policy/verify-fstar*.sh'))
        self.assertGreaterEqual(len(runners), 4)
        for runner in runners:
            relative = str(runner.relative_to(root))
            with self.subTest(runner=relative):
                entry = subprocess.check_output(
                    ['git', 'ls-files', '--stage', '--', relative],
                    cwd=root, text=True,
                )
                self.assertTrue(entry.startswith('100755 '), entry)

    def test_nested_comments_and_strings(self):
        guard.check_source('(* assume (* axiom *) admit *)\nlet text = "admit // (*"\nlet ok : Lemma True = ()')

    def test_line_comment_cannot_hide_escape_after_block_comment(self):
        with self.assertRaises(ValueError):
            guard.check_source('let bad : Lemma False = (* // *) admit()')

    def test_all_escapes_refused(self):
        for escape in ['assume val bad: False', 'axiom bad: False', 'let bad = admit()', 'let bad = unsafe_coerce ()', '[@@expect_failure] let bad : Lemma False = ()', 'val bad: False', 'let bad = magic()', 'let bad = sorry()', 'let bad = Admitted', 'let bad = admit1()', '[@@expect_lax_failure] let bad : Lemma False = ()']:
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

    def test_char_literals_do_not_hide_escape(self):
        source = """let c = '"' let s = "x" admit() let t = "y" let u = '"'"""
        with self.assertRaises(ValueError):
            guard.check_source(source)
        guard.check_source("""let c = '"' let text = "safe" let ok : Lemma True = ()""")
        guard.check_source("let identity (#a:Type) (x:'a) = x")

    def test_unlisted_modules_and_interfaces_are_rejected(self):
        for suffix in ['.fst', '.fsti']:
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                generated, proof = root / 'Extracted.fst', root / 'Proof.fst'
                generated.write_text('module Extracted', encoding='utf-8')
                proof.write_text('module Proof', encoding='utf-8')
                (root / ('Evil' + suffix)).write_text('assume val bad: False', encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'unlisted proof sources'):
                    guard.check_files([generated], [proof])

    def test_extra_cwd_include_is_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = root / 'sources'
            sources.mkdir()
            generated, proof = sources / 'Extracted.fst', sources / 'Proof.fst'
            generated.write_text('module Extracted', encoding='utf-8')
            proof.write_text('module Proof', encoding='utf-8')
            (root / 'Evil.fst').write_text('assume val bad: False', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unlisted proof sources'):
                guard.check_files([generated], [proof], [root])

    def test_cli_reads_utf8_under_c_locale_and_fails_on_missing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generated, proof = root / 'Extracted.fst', root / 'Proof.fst'
            generated.write_text('module Extracted', encoding='utf-8')
            proof.write_text('module Proof\n(* Unicode ── checked *)', encoding='utf-8')
            argv = [sys.executable, str(Path(guard.__file__)), '--generated', str(generated), '--proof', str(proof)]
            env = dict(os.environ, LC_ALL='C', PYTHONCOERCECLOCALE='0', PYTHONUTF8='0')
            result = subprocess.run(argv, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            proof.unlink()
            self.assertNotEqual(subprocess.run(argv, capture_output=True, env=env).returncode, 0)


if __name__ == '__main__':
    unittest.main()
