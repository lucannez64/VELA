"""Regression checks for emitted-action coverage, including trace qualifiers."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "action_atoms", Path(__file__).resolve().parents[1] / "check-action-atoms.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class ActionAtoms(unittest.TestCase):
    def check(self, formula, qualifier="", prefix=""):
        source = prefix + '''theory Example
begin
rule Emit:
 [ Fr(~x) ] --[ Actual(~x), Pair(<~x,~x>, f(~x)), Empty() ]-> []
lemma goal:
 ''' + qualifier + '\n "' + formula + '"\nend\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.spthy"
            path.write_text(source)
            return guard.check_file(path)

    def test_emitted_nested_and_zero_arity(self):
        self.assertEqual(self.check(
            "All x #i. Pair(<x,x>, f(x)) @ #i & Empty() @ #i ==> Actual(x) @ #i"), [])

    def test_both_trace_qualifiers_are_checked(self):
        for qualifier in ("all-traces", "exists-trace", ""):
            with self.subTest(qualifier=qualifier):
                self.assertIn("Missing/1", self.check(
                    "Ex x #i. Missing(x) @ #i", qualifier)[0])

    def test_wrong_arity(self):
        self.assertIn("Actual/2", self.check("Ex x #i. Actual(x,x) @ #i")[0])

    def test_comments_do_not_declare_actions(self):
        self.assertIn("Missing/1", self.check("Ex x #i. Missing(x) @ #i", prefix='''
/* rule Fake: [] --[ Missing(x) ]-> [] */
// rule Fake: [] --[ Missing(x) ]-> []
''')[0])

    def test_unterminated_comment_fails_closed(self):
        with self.assertRaises(ValueError):
            guard.strip_comments("/* unfinished")

    def test_invalid_formula_fails_closed(self):
        with self.assertRaises(ValueError):
            guard.collect_formulas("lemma broken: exists-trace NoQuote")


if __name__ == "__main__":
    unittest.main()
