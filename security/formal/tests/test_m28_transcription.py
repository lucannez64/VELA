"""Mutation tests for check-m28-transcription.py (a drift check, not a proof)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('drift', ROOT / 'check-m28-transcription.py')
drift = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drift)
SPTHY = drift.SPTHY.read_text()
TERMS = drift.TERMS.read_text()
BRIDGE = drift.BRIDGE.read_text()
WITNESS = drift.WITNESS.read_text()


class TranscriptionDriftTests(unittest.TestCase):
    def run_check(self, spthy=SPTHY, terms=TERMS, bridge=BRIDGE, witness=WITNESS):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for name, text in (('m.spthy', spthy), ('T.fst', terms),
                               ('B.fst', bridge), ('W.fst', witness)):
                p = Path(d) / name
                p.write_text(text)
                paths.append(p)
            return drift.check(*paths)

    def mutate(self, text, old, new):
        self.assertIn(old, text)
        return text.replace(old, new, 1)

    def assert_drift(self, **kw):
        with self.assertRaises(drift.DriftError):
            self.run_check(**kw)

    def test_real_sources_match(self):
        self.assertEqual(self.run_check(), (7, 18, 10))

    def test_spthy_premise_change(self):
        self.assert_drift(spthy=self.mutate(
            SPTHY, 'Snapshot(slot, tx, gen, pinned), In(', 'Snapshot(slot, tx, gen, vrev), In('))

    def test_spthy_dropped_chain(self):
        self.assert_drift(spthy=self.mutate(
            SPTHY, '      Chain(~slot, \'initial\', \'initial\'), Out(~slot) ]',
            '      Out(~slot) ]'))

    def test_spthy_persistence_change(self):
        self.assert_drift(spthy=self.mutate(SPTHY, '[ !Profile(slot) ]', '[ Profile(slot) ]'))

    def test_spthy_fresh_vs_message_variable(self):
        self.assert_drift(spthy=self.mutate(SPTHY, 'Fr(~tx) ]', 'Fr(tx) ]'))

    def test_spthy_new_rule(self):
        self.assert_drift(spthy=self.mutate(
            SPTHY, 'rule Crash:', 'rule Leak:\n    [ DiskClean(s, g, p, r, v) ] --> [ Out(v) ]\n\nrule Crash:'))

    def test_spthy_new_function(self):
        self.assert_drift(spthy=self.mutate(SPTHY, 'functions: successor/1', 'functions: successor/1, h/1'))

    def test_spthy_builtins(self):
        self.assert_drift(spthy=self.mutate(SPTHY, 'functions: successor/1',
                                            'functions: successor/1\nbuiltins: hashing'))

    def test_spthy_restriction_change(self):
        self.assert_drift(spthy=self.mutate(SPTHY, '==> old << next"', '==> not (old = next)"'))

    def test_spthy_new_lemma(self):
        self.assert_drift(spthy=self.mutate(
            SPTHY, '\nend', '\nlemma extra:\n    "All s #i. Crash(s) @ #i ==> F"\n\nend'))

    def test_spthy_lemma_kind_change(self):
        self.assert_drift(spthy=self.mutate(
            SPTHY, 'lemma recovery_is_reachable:\n    exists-trace', 'lemma recovery_is_reachable:\n    all-traces'))

    def test_fstar_argument_change(self):
        self.assert_drift(terms=self.mutate(
            TERMS, '[variable "slot"; variable "tx"; variable "gen"; variable "next";\n       variable "payload"; variable "next"; variable "payload"]',
            '[variable "slot"; variable "tx"; variable "gen"; variable "next";\n       variable "payload"; variable "next"; variable "vpayload"]'))

    def test_fstar_arity_change(self):
        self.assert_drift(terms=self.mutate(TERMS, '| F_Chain -> 3', '| F_Chain -> 4'))

    def test_fstar_missing_formula(self):
        self.assert_drift(bridge=BRIDGE.replace('let pins_advance_on_every_commit', 'let pins_advance_renamed'))

    def test_fstar_universal_conjunction(self):
        self.assert_drift(bridge=self.mutate(BRIDGE, '  /\\ each_transaction_applies_at_most_once h\n', ''))


if __name__ == '__main__':
    unittest.main()
