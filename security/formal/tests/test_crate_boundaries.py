"""Regression tests for the crate-boundary guard.

The first test is the real repository. The rest copy every product manifest
and source tree into a temporary root, add one forbidden edge, primitive or
``unsafe`` block, and check that the guard names the rule it breaks.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
GUARD_PATH = HERE.parents[1] / "check-crate-boundaries.py"
REPO_ROOT = HERE.parents[3]
spec = importlib.util.spec_from_file_location("crate_boundaries_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


class CrateBoundaries(unittest.TestCase):
    def test_real_repository_holds(self):
        self.assertEqual(guard.check_repo(REPO_ROOT), [])

    def test_graph_is_discovered(self):
        crates = guard.load_crates(REPO_ROOT)
        for name in ("vela-core", "vela-crypto", "vela-server", "vela-desktop-core",
                     "vela-sync-policy", "vela-wasm-bridge"):
            self.assertIn(name, crates)
        self.assertEqual(crates["vela-server"].side, "server")
        self.assertIn("vela-crypto", crates["vela-server"].deps)

    def _mutant(self, manifest, add_dep=None, source=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for crate in guard.load_crates(REPO_ROOT).values():
            src_dir = (REPO_ROOT / crate.manifest).parent
            dst_dir = root / crate.manifest
            dst_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / crate.manifest, dst_dir)
            if (src_dir / "src").is_dir():
                shutil.copytree(src_dir / "src", dst_dir.parent / "src")
        target = root / manifest
        if add_dep:
            text = target.read_text(encoding="utf-8")
            if "\n[dependencies]\n" not in text:
                text += "\n[dependencies]\n"
            text = text.replace("\n[dependencies]\n", f"\n[dependencies]\n{add_dep}\n", 1)
            target.write_text(text, encoding="utf-8")
        if source:
            (target.parent / "src" / "mutant.rs").write_text(source, encoding="utf-8")
        return guard.check_repo(root)

    def assertRule(self, findings, rule):
        self.assertTrue(any(f"[{rule}]" in f for f in findings), findings)

    def test_policy_crate_gaining_a_vela_dependency_is_rejected(self):
        self.assertRule(self._mutant("libVELA/vela-sync-policy/Cargo.toml",
                                     'vela-core = { path = "../vela-core" }'), "policy-leaf")

    def test_core_gaining_a_vela_dependency_is_rejected(self):
        self.assertRule(self._mutant("libVELA/vela-core/Cargo.toml",
                                     'vela-crypto = { path = "../vela-crypto" }'), "core-leaf")

    def test_crypto_depending_on_core_is_rejected(self):
        self.assertRule(self._mutant("libVELA/vela-crypto/Cargo.toml",
                                     'vela-core = { path = "../vela-core" }'), "crypto-deps")

    def test_depending_on_a_bridge_is_rejected(self):
        self.assertRule(self._mutant("desktopVELA/vela-desktop-core/Cargo.toml",
                                     'vela-wasm-bridge = { path = "../../libVELA/vela-wasm-bridge" }'),
                        "no-bridge-deps")

    def test_server_depending_on_client_crate_is_rejected(self):
        self.assertRule(self._mutant("serverVELA/vela-server/Cargo.toml",
                                     'vela-core = { path = "../../libVELA/vela-core" }'),
                        "server-client")

    def test_client_depending_on_server_policy_is_rejected(self):
        self.assertRule(self._mutant("desktopVELA/vela-desktop-core/Cargo.toml",
                                     'vela-share-policy = { path = "../../serverVELA/vela-share-policy" }'),
                        "server-client")

    def test_vault_primitive_outside_crypto_is_rejected(self):
        self.assertRule(self._mutant("libVELA/vela-core/Cargo.toml",
                                     'chacha20poly1305 = "0.10"'), "vault-primitives")

    def test_renamed_vault_primitive_is_rejected(self):
        self.assertRule(self._mutant("desktopVELA/vela-desktop-core/Cargo.toml",
                                     'aead = { package = "aes-gcm", version = "0.10" }'),
                        "vault-primitives")

    def test_listed_primitive_exception_is_accepted(self):
        findings = guard.check_repo(REPO_ROOT)
        self.assertFalse(any("vela-cli" in f for f in findings), findings)

    def test_unsafe_outside_allowed_crates_is_rejected(self):
        self.assertRule(self._mutant("libVELA/vela-import/Cargo.toml",
                                     source="pub fn f(p: *const u8) -> u8 { unsafe { *p } }\n"),
                        "unsafe")

    def test_unsafe_in_comments_and_strings_is_ignored(self):
        findings = self._mutant("libVELA/vela-import/Cargo.toml",
                                source='// unsafe here is prose\npub const S: &str = "unsafe";\n')
        self.assertEqual(findings, [])

    def test_dev_dependencies_may_cross_layers(self):
        findings = self._mutant("libVELA/vela-core/Cargo.toml")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
