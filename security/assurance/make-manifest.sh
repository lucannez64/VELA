#!/usr/bin/env bash
# Include new working-tree artifacts as well as tracked files; exclude self.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
python3 - <<'PYTHON'
import hashlib, json, subprocess
from pathlib import Path
patterns = [
    'security/formal/*.spthy', 'security/formal/*.pv', 'security/formal/*.pvl',
    'security/formal/*.sh', 'security/formal/*.py', 'security/formal/*.json',
    'security/formal/network-boundary-correspondence.md',
    'security/assurance/*.patch', 'security/assurance/*.md', 'security/assurance/*.sh',
    'security/assurance/*.py', 'security/assurance/*.json',
    'security/assurance/proof-logs/**/*.txt', 'security/assurance/proof-logs/**/*.out', 'security/assurance/proof-logs/**/*.log',
    'security/assurance/proof-logs/**/*.md', 'security/assurance/proof-logs/**/*.fst',
    'security/assurance/proof-logs/**/*.fsti',
    '*/vela-*-policy/src/*.rs', '*/vela-*-policy/verify-fstar.sh',
    '*/vela-*-policy/README.md', '*/vela-*-policy/Cargo.toml', '*/vela-*-policy/Cargo.lock',
    '*/vela-*-policy/proofs/fstar/extraction/*.fst',
    'libVELA/vela-crypto/proofs/proverif/extraction/*.pvl',
    'libVELA/vela-crypto/proofs/fstar/extraction/*.fst',
    'libVELA/vela-crypto/proofs/fstar/models/*.fst',
    'libVELA/vela-crypto/proofs/fstar/*.md',
    'libVELA/vela-crypto/verify-share-facts-fstar.sh',
    '.gitignore', 'SPEC.md', 'SECURITY.md', '.cargo/config.toml', 'serverVELA/Cargo.lock',
    '*/vela-*-policy/rust-toolchain.toml',
    'libVELA/vela-crypto/SECURITY.md', 'libVELA/vela-crypto/Cargo.toml', 'libVELA/vela-crypto/Cargo.lock',
    'libVELA/vela-crypto/src/oram.rs', 'libVELA/vela-crypto/tests/oram_stash_bounds.rs',
    'serverVELA/vela-server/tests/*_model.rs',
    'libVELA/vela-client-recovery-policy/tests/*.rs',
    'libVELA/vela-client-share-policy/tests/*.rs', '.github/workflows/security.yml',
]
files = {p for pattern in patterns for p in Path('.').glob(pattern) if p.is_file()}
for pair in json.loads(Path('security/formal/correspondence.json').read_text())['pairs']:
    files.update(map(Path, pair['artifacts']))
ignored = subprocess.run(['git', 'check-ignore', '--stdin'],
    input=''.join(str(p)+'\n' for p in sorted(files)), text=True, capture_output=True)
if ignored.returncode not in (0, 1):
    raise SystemExit(ignored.stderr)
files.difference_update(map(Path, ignored.stdout.splitlines()))
for p in sorted(files):
    print(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p}')
PYTHON
