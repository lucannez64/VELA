"""Regression tests for the bridge-thinness guard.

The first test is the real repository: all 91 exports must be conversions
around reviewed core calls. The rest are mutants that must be rejected: an
added ``if``, an added numeric default (in a body and behind ``serde``), an
``unwrap_or_default`` fallback, a call to a function that is neither core nor a
reviewed helper, an unreviewed local helper, and a renamed export.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
GUARD_PATH = HERE.parents[1] / "check-bridge-thinness.py"
REPO_ROOT = HERE.parents[3]
spec = importlib.util.spec_from_file_location("bridge_thinness_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)

WASM = "libVELA/vela-wasm-bridge/src/lib.rs"


class BridgeThinness(unittest.TestCase):
    def test_real_repository_is_thin(self):
        self.assertEqual(guard.check_repo(REPO_ROOT), [])

    def test_every_export_is_classified(self):
        for bridge in guard.BRIDGES:
            _, exports = guard.check_bridge(REPO_ROOT, bridge)
            self.assertEqual(exports, set(guard.ALLOW[bridge]["exports"]))
        total = sum(len(guard.ALLOW[b]["exports"]) for b in guard.BRIDGES)
        self.assertEqual(total, 91)

    def _mutant(self, mutate):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for bridge in guard.BRIDGES:
            target = root / bridge
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / bridge, target)
        path = root / WASM
        path.write_text(mutate(path.read_text(encoding="utf-8")), encoding="utf-8")
        return guard.check_repo(root)

    def test_added_if_is_rejected(self):
        def mutate(source):
            return source.replace(
                "pub fn password_strength_json(request_json: &str) -> String {\n"
                "    respond(password_strength_impl(request_json))\n"
                "}",
                "pub fn password_strength_json(request_json: &str) -> String {\n"
                "    if request_json.is_empty() {\n"
                "        return respond(Err(\"empty\".to_string()));\n"
                "    }\n"
                "    respond(password_strength_impl(request_json))\n"
                "}",
            )

        findings = self._mutant(mutate)
        self.assertTrue(
            any("`password_strength_json` has 1 decision(s) `if`" in f for f in findings),
            findings,
        )

    def test_added_default_is_rejected(self):
        def mutate(source):
            return source.replace(
                "        req.epoch,\n",
                "        Some(req.epoch.unwrap_or(1)),\n",
                1,
            )

        findings = self._mutant(mutate)
        self.assertTrue(
            any("1 default(s) `1`" in f for f in findings), findings
        )

    def test_unwrap_or_default_is_rejected(self):
        def mutate(source):
            return source.replace(
                "        req.epoch,\n",
                "        Some(req.epoch.unwrap_or_default()),\n",
                1,
            )

        findings = self._mutant(mutate)
        self.assertTrue(
            any("default(s) `unwrap_or`" in f for f in findings), findings
        )

    def test_serde_default_is_rejected(self):
        def mutate(source):
            source = source.replace(
                "    #[serde(default)]\n    epoch: Option<i64>,",
                '    #[serde(default = "default_epoch")]\n    epoch: Option<i64>,',
            )
            return source.replace(
                "#[derive(Serialize)]\nstruct EncryptChunkResponse {",
                "fn default_epoch() -> Option<i64> {\n    Some(1)\n}\n\n"
                "#[derive(Serialize)]\nstruct EncryptChunkResponse {",
            )

        findings = self._mutant(mutate)
        self.assertTrue(any("serde default `default_epoch`" in f for f in findings), findings)

    def test_non_core_call_is_rejected(self):
        def mutate(source):
            return source.replace(
                "pub fn vela_wasm_version() -> String {\n"
                '    concat!("vela-wasm-bridge/", env!("CARGO_PKG_VERSION")).to_string()\n'
                "}",
                "pub fn vela_wasm_version() -> String {\n"
                "    std::process::abort();\n"
                '    concat!("vela-wasm-bridge/", env!("CARGO_PKG_VERSION")).to_string()\n'
                "}",
            )

        findings = self._mutant(mutate)
        self.assertTrue(
            any("calls `std::process::abort`" in f for f in findings), findings
        )

    def test_unreviewed_local_helper_is_rejected(self):
        def mutate(source):
            source = source.replace(
                "/// Bridge version string.\n#[wasm_bindgen]\n"
                "pub fn vela_wasm_version() -> String {",
                "fn local_policy_decision() -> bool {\n    true\n}\n\n"
                "/// Bridge version string.\n#[wasm_bindgen]\n"
                "pub fn vela_wasm_version() -> String {\n"
                "    let _ = local_policy_decision();",
            )
            return source

        findings = self._mutant(mutate)
        self.assertTrue(
            any("unreviewed local helper `local_policy_decision`" in f for f in findings),
            findings,
        )

    def test_renamed_export_is_rejected(self):
        def mutate(source):
            return source.replace(
                "pub fn vela_wasm_version() -> String {",
                "pub fn vela_wasm_version_renamed() -> String {",
            )

        findings = self._mutant(mutate)
        self.assertTrue(
            any("manifest lists missing export `vela_wasm_version`" in f for f in findings),
            findings,
        )
        self.assertTrue(
            any(
                "export `vela_wasm_version_renamed` is not in the reviewed manifest" in f
                for f in findings
            ),
            findings,
        )


if __name__ == "__main__":
    unittest.main()
