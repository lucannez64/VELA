"""Handlers reach their drivers only through the proved interpreter macro.

Each listed handler must expand its policy crate's interpreter macro with
`await` (the same macro text the policy crate expands into the function hax
extracts and F* checks), and must not call the driver's transition functions
itself: a direct call would perform effects outside the proved loop.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

# (handler, macro, driver module path, interpreter source, expansions)
WIRED = [
    (
        'serverVELA/vela-server/src/account/delete.rs',
        'deletion_interpreter',
        'deletion_driver',
        'serverVELA/vela-session-policy/src/deletion_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/device/invitation.rs',
        'pairing_interpreter',
        'pairing_driver',
        'serverVELA/vela-enrollment-policy/src/pairing_interpreter.rs',
        2,
    ),
    (
        'serverVELA/vela-server/src/device/rendezvous.rs',
        'pairing_interpreter',
        'pairing_driver',
        'serverVELA/vela-enrollment-policy/src/pairing_interpreter.rs',
        4,
    ),
    (
        'serverVELA/vela-server/src/share/mod.rs',
        'share_interpreter',
        'driver',
        'serverVELA/vela-share-policy/src/interpreter.rs',
        5,
    ),
    (
        'serverVELA/vela-server/src/auth/verify.rs',
        'login_interpreter',
        'login_driver',
        'serverVELA/vela-session-policy/src/login_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/device/revoke.rs',
        'revocation_interpreter',
        'revocation_driver',
        'serverVELA/vela-session-policy/src/revocation_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/auth/logout.rs',
        'logout_interpreter',
        'revocation_driver',
        'serverVELA/vela-session-policy/src/revocation_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/vault/chunk.rs',
        'upload_interpreter',
        'vault_upload_driver',
        'serverVELA/vela-rekey-policy/src/vault_upload_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/vault/chunk.rs',
        'read_interpreter',
        'vault_upload_driver',
        'serverVELA/vela-rekey-policy/src/vault_upload_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/enroll_device.rs',
        'redemption_interpreter',
        'driver',
        'serverVELA/vela-recovery-policy/src/redemption_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/possess.rs',
        'possession_initiation_interpreter',
        'possession_driver',
        'serverVELA/vela-recovery-policy/src/possession_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/possess.rs',
        'possession_recover_interpreter',
        'possession_driver',
        'serverVELA/vela-recovery-policy/src/possession_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/initiate.rs',
        'auth_start_interpreter',
        'webauthn_driver',
        'serverVELA/vela-recovery-policy/src/webauthn_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/webauthn.rs',
        'registration_start_interpreter',
        'webauthn_driver',
        'serverVELA/vela-recovery-policy/src/webauthn_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/webauthn.rs',
        'registration_interpreter',
        'webauthn_driver',
        'serverVELA/vela-recovery-policy/src/webauthn_interpreter.rs',
        1,
    ),
    (
        'serverVELA/vela-server/src/recovery/recover.rs',
        'auth_finish_interpreter',
        'webauthn_driver',
        'serverVELA/vela-recovery-policy/src/webauthn_interpreter.rs',
        1,
    ),
]

TRANSITIONS = re.compile(r'\b(?:begin_\w+|step|on_\w+_event|on_\w+)\s*\(')


def code_only(text):
    """Drop comments and string literals."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


class HandlerInterpreterTest(unittest.TestCase):
    def test_handlers_expand_the_proved_macro_only_from_the_loop(self):
        for handler, macro, _, _, expected in WIRED:
            code = code_only((ROOT / handler).read_text(encoding='utf-8'))
            calls = re.findall(r'\b' + macro + r'!\s*\(([^)]*)\)', code)
            self.assertEqual(len(calls), expected,
                             f'{handler}: expected {expected} {macro}! expansions')
            for call in calls:
                self.assertTrue(call.rstrip().endswith('await'),
                                f'{handler}: {macro}! must be expanded with await')

    def test_handlers_never_call_driver_transitions(self):
        for handler, _, driver, _, _ in WIRED:
            code = code_only((ROOT / handler).read_text(encoding='utf-8'))
            imported = re.findall(r'use\s+vela_\w+::' + driver + r'::\{([^}]*)\}', code, flags=re.S)
            names = {n.strip() for group in imported for n in group.split(',') if n.strip()}
            offending = sorted(n for n in names if TRANSITIONS.match(n + '('))
            self.assertEqual(offending, [], f'{handler} imports driver transitions')
            self.assertNotRegex(code, driver + r'::(?:begin_\w+|step|on_\w+)\s*\(',
                                f'{handler} calls a driver transition directly')

    def test_interpreters_define_one_macro_and_its_sync_expansion(self):
        by_source = {}
        for _, macro, _, source, _ in WIRED:
            by_source.setdefault(source, set()).add(macro)
        for source, macros in by_source.items():
            code = code_only((ROOT / source).read_text(encoding='utf-8'))
            for macro in macros:
                self.assertEqual(len(re.findall(r'macro_rules!\s*' + macro + r'\b', code)), 1,
                                 f'{source}: {macro} must be defined once')
                self.assertEqual(len(re.findall(r'\b' + macro + r'!\s*\(', code)), 1,
                                 f'{source}: {macro} must be expanded exactly once')
            declared = set(re.findall(r'macro_rules!\s*(\w+)', code))
            self.assertEqual(declared - {'executor_trait'}, macros,
                             f'{source}: unexpected interpreter macro set')


if __name__ == '__main__':
    unittest.main()
