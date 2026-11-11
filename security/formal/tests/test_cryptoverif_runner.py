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
if model == 'x25519_cofactor_projection' and mode != 'missing_query_witness':
    if mode == 'projection_wrong_result':
        print('RESULT Proved indistinguishability between game 2 and game 1')
    elif mode != 'projection_missing_result':
        print('RESULT Proved indistinguishability between game 1 and game 2')
    print('All queries proved.')
    sys.exit(0)
if mode != 'missing_query_witness':
    if model.startswith(('hybrid_sig_', 'possession_proof_')):
        query = 'event(forge) ==> false'
    elif model == 'shamir_share_tags':
        query = 'event(accepted_wrong_secret) ==> false'
    else:
        query = 'bit secrecy of b'
    bound = '0'
    if model == 'kem_v2_x25519_gdh_nonuniform':
        bound = '4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH) + (2 * Qd + 2 * qH) * PCollKey'
        if mode == 'nonuniform_zero_bound':
            bound = '0'
        elif mode == 'nonuniform_uniform_bound':
            bound = bound.replace('* PCollKey', '/ |Z|')
        elif mode == 'nonuniform_extra_collision':
            bound += ' + Pcoll1rand(Z)'
        elif mode == 'nonuniform_changed_coefficient':
            bound = bound.replace('2 * Qd', 'Qd')
        elif mode == 'nonuniform_missing_rerandomization':
            bound = bound.replace('4 * pDistRerandom + ', '')
    elif model == 'kem_v2_x25519_gdh_sha256':
        bound = ('4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH) + '
                 '(2 * Qd + 2 * qH) / |Z| + 6 * PhashCt')
    elif model == 'kem_v2_x25519_gdh_nonuniform_sha256':
        bound = ('4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH) + '
                 '(2 * Qd + 2 * qH) * PCollKey + 6 * PhashCt')
    elif model == 'kem_v2_x25519_cofactor_sha256':
        bound = ('4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH) + '
                 '(2 * Qd + 2 * qH) * PCollKey + 6 * PhashCt')
        if mode == 'cofactor_zero_bound':
            bound = '0'
        elif mode == 'cofactor_uniform_bound':
            bound = bound.replace('* PCollKey', '/ |Z|')
        elif mode == 'cofactor_changed_coefficient':
            bound = bound.replace('2 * Qd', 'Qd')
        elif mode == 'cofactor_missing_hash':
            bound = bound.replace(' + 6 * PhashCt', '')
        elif mode == 'cofactor_missing_collision':
            bound = bound.replace(' + (2 * Qd + 2 * qH) * PCollKey', '')
    elif model == 'kem_v2_mlkem_cca_sha256':
        bound = ('2 * qH / |mlss| + 2 * Penc(time_1, 1, 1, Qd) + '
                 '(8 * Qd + 2 * qH) / |Z| + 4 * PhashCt + 6 * Qd * Pctxtcoll')
    elif model == 'kem_v2_x25519_gdh_multi_sha256':
        bound = ('(2 * N + 2 * Qc) * pDistRerandom + 2 * N * Qc * pGDH(time_1, 2 * qH) + '
                 '(2 * N^2 * Qc^2 + 4 * N^2 + 2 * Qc^2 + 2 * #Odecap * Qc + '
                 '2 * N^2 * Qc + 2 * qH * Qc) / |Z| + 8 * PhashCt + 6 * PhashEk')
        if mode == 'sha256_multi_changed_coefficient':
            bound = bound.replace('2 * N * Qc * pGDH', 'N * Qc * pGDH')
        elif mode == 'sha256_multi_missing_phashEk':
            bound = bound.replace(' + 6 * PhashEk', '')
    elif model == 'kem_v2_x25519_gdh_nonuniform_multi_sha256':
        bound = ('(2 * N + 2 * Qc) * pDistRerandom + 2 * pGDH(time_1, 2 * qH) + '
                 '(8 * N^2 + 4 * Qc^2 + 2 * #Odecap * Qc + 2 * Qc * qH) * PCollKey + '
                 '8 * PhashCt + 6 * PhashEk')
    elif model == 'kem_v2_mlkem_cca_multi_sha256':
        bound = ('2 * qH * Qc / |mlss| + 2 * Penc(time_1, N, Qc, #Odecap) + '
                 '(2 * N^2 * Qc^2 + 3 * N^2 + 8 * #Odecap * Qc + 2 * N^2 * Qc + '
                 '2 * qH * Qc) / |Z| + (2 * Qc^2 * N^2 + 6 * #Odecap * Qc * N) * Pctxtcoll + '
                 '6 * PhashCt + 4 * PhashEk + 8 * N^2 * Pkeycoll')
    if mode == 'sha256_changed_coefficient' and model.endswith('_sha256'):
        bound = bound.replace('2 * Qd', 'Qd')
    print('RESULT Proved ' + query + ' up to probability ' + bound)
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
        self.assertIn('kem_v2_x25519_gdh_nonuniform: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_x25519_gdh_sha256: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_x25519_gdh_nonuniform_sha256: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_mlkem_cca_sha256: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_x25519_gdh_multi_sha256: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_x25519_gdh_nonuniform_multi_sha256: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_mlkem_cca_multi_sha256: proved (as expected)', result.stdout)
        self.assertIn('kem_v2_x25519_cofactor_sha256: proved (as expected)', result.stdout)
        self.assertIn('x25519_cofactor_projection: proved (as expected)', result.stdout)
        self.assertEqual(result.stdout.count('(as expected)'), 18)

    def test_sha256_bridge_bound_drift_is_rejected(self):
        result = self.invoke('sha256_changed_coefficient')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kem_v2_x25519_gdh_sha256: SHA-256 bridge bound changed',
                      result.stderr)

    def test_multi_user_bound_drift_is_rejected(self):
        result = self.invoke('sha256_multi_changed_coefficient')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kem_v2_x25519_gdh_multi_sha256: SHA-256 bridge bound changed',
                      result.stderr)

    def test_missing_multi_user_phash_ek_term_is_rejected(self):
        result = self.invoke('sha256_multi_missing_phashEk')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('kem_v2_x25519_gdh_multi_sha256: SHA-256 bridge bound changed',
                      result.stderr)

    def test_retained_sha256_bridge_proof_bounds_pass(self):
        cases = [
            ('cryptoverif-sha256-bridge', 'kem_v2_x25519_gdh_sha256'),
            ('cryptoverif-sha256-bridge', 'kem_v2_x25519_gdh_nonuniform_sha256'),
            ('cryptoverif-sha256-bridge', 'kem_v2_mlkem_cca_sha256'),
            ('cryptoverif-multi-user', 'kem_v2_x25519_gdh_multi_sha256'),
            ('cryptoverif-multi-user', 'kem_v2_x25519_gdh_nonuniform_multi_sha256'),
            ('cryptoverif-multi-user', 'kem_v2_mlkem_cca_multi_sha256'),
        ]
        for folder, model in cases:
            with self.subTest(model=model):
                result = subprocess.run([
                    'python3', str(ROOT / 'security/formal/check-cryptoverif-sha256-bound.py'),
                    model, str(ROOT / 'security/assurance/proof-logs/current' / folder / f'{model}.log'),
                ], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonuniform_bound_drift_is_rejected(self):
        for mode in ('nonuniform_zero_bound', 'nonuniform_uniform_bound',
                     'nonuniform_extra_collision', 'nonuniform_changed_coefficient',
                     'nonuniform_missing_rerandomization'):
            with self.subTest(mode=mode):
                result = self.invoke(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('nonuniform bound changed', result.stderr)

    def test_retained_nonuniform_proof_bound_passes(self):
        result = subprocess.run([
            'python3', str(ROOT / 'security/formal/check-cryptoverif-bound.py'),
            str(ROOT / 'security/assurance/proof-logs/current/x25519-nonuniform-gdh/kem_v2_x25519_gdh_nonuniform.log'),
        ], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cofactor_bound_drift_is_rejected(self):
        for mode in ('cofactor_zero_bound', 'cofactor_uniform_bound',
                     'cofactor_changed_coefficient', 'cofactor_missing_hash',
                     'cofactor_missing_collision'):
            with self.subTest(mode=mode):
                result = self.invoke(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('cofactor IND-CCA2 bound changed', result.stderr)

    def test_cofactor_projection_result_drift_is_rejected(self):
        for mode in ('projection_missing_result', 'projection_wrong_result'):
            with self.subTest(mode=mode):
                result = self.invoke(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('cofactor projection equivalence', result.stderr)

    def test_retained_cofactor_proof_results_pass(self):
        folder = ROOT / 'security/assurance/proof-logs/current/cryptoverif-x25519-cofactor'
        for mode, model in (('bound', 'kem_v2_x25519_cofactor_sha256'),
                            ('projection', 'x25519_cofactor_projection')):
            with self.subTest(model=model):
                result = subprocess.run([
                    'python3', str(ROOT / 'security/formal/check-cryptoverif-cofactor.py'),
                    mode, str(folder / f'{model}.log'),
                ], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

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
