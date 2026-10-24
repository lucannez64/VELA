"""Exercise the real gate with a fake verifier; these are not proof verdicts."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / 'security/formal/run-cryptoverif-proofs.sh'
FAKE = '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
model = Path(sys.argv[-1]).stem
mode = os.environ['FIXTURE_MODE']
if mode == 'crash_after_proved':
    print('All queries proved.')
    sys.exit(137)
if model == 'kem_v1_x25519_baseline':
    if mode == 'missing_verdict':
        sys.exit(0)
    if mode == 'error_banner':
        print('Error: invalid model')
    print('RESULT Could not prove bit secrecy of b.')
    sys.exit(124 if mode == 'baseline_timeout' else 0)
if mode != 'missing_query_witness':
    query = 'event(forge) ==> false' if model.startswith('hybrid_sig_') else 'bit secrecy of b'
    print('RESULT Proved ' + query + ' up to probability 0')
print('All queries proved.')
'''


class RunnerTests(unittest.TestCase):
    def invoke(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            verifier = folder / 'cryptoverif'
            verifier.write_text(FAKE)
            verifier.chmod(0o755)
            return subprocess.run(
                [str(RUNNER)], cwd=ROOT, text=True, capture_output=True,
                env={**os.environ, 'CRYPTOVERIF': str(verifier),
                     'CRYPTOVERIF_LIB': str(folder / 'unused'),
                     'VELA_PROOF_OUT': str(folder / 'logs'),
                     # Only fake, tiny verifier processes run in these fixtures.
                     'VELA_BOUNDED': '1', 'FIXTURE_MODE': mode},
                timeout=15,
            )

    def test_git_records_an_executable_runner(self):
        entry = subprocess.check_output(
            ['git', 'ls-files', '--stage', str(RUNNER.relative_to(ROOT))],
            cwd=ROOT, text=True,
        )
        self.assertTrue(entry.startswith('100755 '), entry)
        self.assertTrue(os.access(RUNNER, os.X_OK))

    def test_complete_expected_verdicts_pass(self):
        result = self.invoke('complete')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('kem_v1_x25519_baseline: unproved (as expected)', result.stdout)
        self.assertEqual(result.stdout.count('(as expected)'), 6)

    def test_baseline_timeout_is_not_an_expected_nonproof(self):
        result = self.invoke('baseline_timeout')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('proof process failed (exit 124)', result.stderr)

    def test_baseline_requires_a_recognized_verdict(self):
        result = self.invoke('missing_verdict')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no recognized proof verdict', result.stderr)

    def test_proved_banner_cannot_hide_a_process_failure(self):
        result = self.invoke('crash_after_proved')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('proof process failed (exit 137)', result.stderr)

    def test_success_banner_requires_expected_query_witness(self):
        result = self.invoke('missing_query_witness')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing expected query result', result.stderr)

    def test_error_banner_cannot_count_as_expected_nonproof(self):
        result = self.invoke('error_banner')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CryptoVerif error', result.stderr)


class SourceBoundaryTests(unittest.TestCase):
    def invoke(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.ocv'
            path.write_text(source)
            return subprocess.run(
                ['python3', str(ROOT / 'security/formal/check-cryptoverif-boundary.py'), str(path)],
                capture_output=True, text=True, timeout=5,
            )

    def test_manual_hypothesis_is_rejected(self):
        self.assertNotEqual(self.invoke('equiv(x) [manual] left right.').returncode, 0)

    def test_admitted_declaration_is_rejected(self):
        self.assertNotEqual(self.invoke('assume secret.').returncode, 0)

    def test_nested_comment_is_not_a_declaration(self):
        result = self.invoke('(* [manual] (* assume *) *) param Q.')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unterminated_comment_is_rejected(self):
        self.assertNotEqual(self.invoke('(* comment').returncode, 0)


if __name__ == '__main__':
    unittest.main()
