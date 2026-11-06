"""Source-escape/count regressions; F* separately checks the theorems."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('guard', ROOT / 'security/formal/check-sync-chunk-proof.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
ARTIFACT = (ROOT / 'libVELA/vela-sync-policy/proofs/fstar/extraction/Vela_sync_policy.fst').read_text()
PROOF = (ROOT / 'libVELA/vela-sync-policy/proofs/fstar/chunk-lemmas/Vela_sync_policy_chunk_lemmas.fst').read_text()


class ChunkGuardTests(unittest.TestCase):
    def check(self, proof=PROOF, artifact=ARTIFACT):
        with tempfile.TemporaryDirectory() as folder:
            a, p = Path(folder) / 'Artifact.fst', Path(folder) / 'Proof.fst'
            a.write_text(artifact)
            p.write_text(proof)
            guard.check(a, p)

    def test_current_source(self):
        self.check()

    def test_comments_do_not_add_declarations(self):
        self.check(PROOF + '\n// assume --lax\n(* admit (* axiom *) #set-options *)')

    def test_escapes_and_source_options_fail(self):
        for added in ('assume val unsound: False', 'let unsound () = admit ()',
                      'axiom unsound: False', 'let bad : Lemma False = (* // *) admit ()', '#set-options "--lax"',
                      '#push-options "--admit_smt_queries true"',
                      'let unsound () = unsafe_coerce ()'):
            with self.subTest(added=added), self.assertRaises(ValueError):
                self.check(PROOF + '\n' + added)

    def test_count_name_and_import_drift_fail(self):
        for proof in (PROOF.replace(': Lemma', ': Tot', 1),
                      PROOF.replace('let accept_iff_admissible', 'let renamed'),
                      PROOF.replace('open Vela_sync_policy\n', 'open Wrong_module\n')):
            with self.subTest(proof=proof[:40]), self.assertRaises(ValueError):
                self.check(proof)
        with self.assertRaises(ValueError):
            self.check(artifact=ARTIFACT.replace('(ensures', '(requires', 1))

    def test_extraction_options_are_exactly_allowlisted(self):
        with self.assertRaises(ValueError):
            self.check(artifact=ARTIFACT.replace('--fuel 0', '--lax --fuel 0'))
        with self.assertRaises(ValueError):
            self.check(artifact=ARTIFACT + '\n#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"')

    def test_unterminated_comment_fails(self):
        with self.assertRaises(ValueError):
            self.check(PROOF + '(* unfinished')


class EpochGuardTests(unittest.TestCase):
    def test_focused_epoch_module_passes(self):
        guard.check_epoch(
            ROOT / 'libVELA/vela-sync-policy/proofs/fstar/extraction-epoch/Vela_sync_policy.fst',
            ROOT / 'libVELA/vela-sync-policy/proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst')

    def test_historical_module_cannot_shadow_focused_module(self):
        with self.assertRaisesRegex(ValueError, '4 epoch postconditions'):
            guard.check_epoch(
                ROOT / 'libVELA/vela-sync-policy/proofs/fstar/extraction/Vela_sync_policy.fst',
                ROOT / 'libVELA/vela-sync-policy/proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst')

    def test_epoch_escape_and_theorem_drift_fail(self):
        source = (ROOT / 'libVELA/vela-sync-policy/proofs/fstar/epoch-lemmas/Vela_sync_policy_epoch_lemmas.fst').read_text()
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'Epoch.fst'
            for modified in (source + '\naxiom unsound: False',
                             source.replace('let plan_matches_independent_predicate', 'let renamed')):
                p.write_text(modified)
                with self.assertRaises(ValueError):
                    guard.check_epoch(
                        ROOT / 'libVELA/vela-sync-policy/proofs/fstar/extraction-epoch/Vela_sync_policy.fst', p)


if __name__ == '__main__':
    unittest.main()
