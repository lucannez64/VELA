"""Exercise the source guard, independently of F* theorem checking."""
import importlib.util
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard', ROOT / 'check-m28-semantic-proof.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
SOURCE = (ROOT / 'm28-trace-equivalence/M28TraceEquivalence.fst').read_text()


class SemanticGuardTests(unittest.TestCase):
    def check(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Proof.fst'
            path.write_text(text)
            guard.check(path)

    def test_scripts_are_executable_in_git(self):
        for name in ('security/formal/fstar-bounded.sh',
                     'security/formal/m28-trace-equivalence/verify.sh',
                     'security/assurance/install-formal-fstar.sh'):
            with self.subTest(name=name):
                result = subprocess.check_output(
                    ['git', 'ls-files', '--stage', name], cwd=ROOT.parents[1], text=True)
                self.assertTrue(result.startswith('100755 '), result)
                self.assertTrue(os.access(ROOT.parents[1] / name, os.X_OK))

    def test_actual_source_passes(self):
        self.check(SOURCE)

    def test_nested_comments_are_not_declarations(self):
        self.check(SOURCE + '(* assume (* admit --lax *) #set-options *)')

    def test_escapes_and_lax_options_fail(self):
        for added in ('assume val bad: False', 'let bad () = admit ()',
                      '#set-options "--lax"',
                      '#push-options "--admit_smt_queries true"',
                      'let bad () = unsafe_coerce ()'):
            with self.subTest(added=added), self.assertRaises(ValueError):
                self.check(SOURCE + '\n' + added)

    def test_missing_transfer_fails(self):
        with self.assertRaisesRegex(ValueError, 'missing proof definitions'):
            self.check(SOURCE.replace('let transfer_lifted_to_original', 'let renamed_transfer'))

    def test_unterminated_comment_fails(self):
        with self.assertRaises(ValueError):
            self.check(SOURCE + '(* unfinished')


if __name__ == '__main__':
    unittest.main()
