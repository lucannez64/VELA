"""Fail closed on missing, unexpected, incomplete, or warning-bearing verdicts."""
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding='utf-8')
expected = {
    'same_user_required': 'verified',
    'other_user_rejected': 'verified',
    'honest_reachable': 'verified',
    'basename_impostor_reachable': 'verified',
    'provider_without_browser_reachable': 'verified',
    'authentic_browser_required': 'falsified',
}
if re.search(r'warning|analysis incomplete|wellformedness check failed', text, re.I):
    raise SystemExit('Tamarin warning or incomplete analysis')
summary = text.split('summary of summaries:')[-1]
verdicts = re.findall(r'^\s*(\w+)\s+\([^\n]*?\):\s*(verified|falsified)', summary, re.M)
if len(verdicts) != len(expected) or dict(verdicts) != expected:
    raise SystemExit(f'Unexpected verdicts: {verdicts}')
print('M27: 5 verified; exact expected authenticity claim falsified')
