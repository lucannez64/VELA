"""The CI proof jobs skip a proof whose inputs match a run that already
passed. That is only sound if each job's input key covers every file its
scripts read. This test finds the outside paths each crate's scripts mention
and fails if the job's key in security.yml does not cover them."""

import os
import re
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'security.yml')

# Covered for every job by the "Compute proof input key" step.
SHARED = [
    'security/formal',
    'security/assurance/bounded.sh',
    'security/assurance/install-hax.sh',
    'security/assurance/check-proof-boundary.py',
    '.github/workflows/security.yml',
]

RELATIVE = re.compile(r'(?<![\w.])((?:\.\./)+[A-Za-z0-9_.\-/]+)')
ROOTED = re.compile(r'(?<![\w./-])((?:security|serverVELA|libVELA)/[A-Za-z0-9_.\-/]+)')


def matrix():
    with open(WORKFLOW) as f:
        doc = yaml.safe_load(f)
    return doc['jobs']['refinement']['strategy']['matrix']['include']


def scripts(crate_dir):
    base = os.path.join(ROOT, crate_dir)
    for name in sorted(os.listdir(base)):
        if name.endswith(('.sh', '.py')):
            yield os.path.join(base, name)


def outside_paths(crate_dir):
    found = set()
    for path in scripts(crate_dir):
        with open(path) as f:
            text = f.read()
        for m in RELATIVE.finditer(text):
            rel = os.path.normpath(os.path.join(crate_dir, m.group(1).rstrip('/.')))
            found.add((os.path.basename(path), rel))
        for m in ROOTED.finditer(text):
            found.add((os.path.basename(path), os.path.normpath(m.group(1).rstrip('/.'))))
    return found


def covered(path, covers):
    return any(path == c or path.startswith(c.rstrip('/') + '/') for c in covers)


class ProofInputKeyTest(unittest.TestCase):
    def test_every_outside_input_is_in_the_key(self):
        missing = []
        for entry in matrix():
            crate = entry['dir']
            root = crate.split('/')[0]
            covers = [crate, f'{root}/Cargo.toml', f'{root}/Cargo.lock', *SHARED]
            covers += (entry.get('deps') or '').split()
            for script, path in sorted(outside_paths(crate)):
                if not covered(path, covers):
                    missing.append(f"{entry['name']}: {script} reads {path}")
        self.assertEqual(missing, [], 'add these to the matrix entry\'s deps:\n' + '\n'.join(missing))

    def test_every_local_crate_dependency_is_in_the_key(self):
        missing = []
        for entry in matrix():
            crate = entry['dir']
            with open(os.path.join(ROOT, crate, 'Cargo.toml')) as f:
                text = f.read()
            covers = (entry.get('deps') or '').split()
            for name in re.findall(r'(?m)^(vela[\w-]*)\s*=', text):
                sibling = os.path.join(os.path.dirname(crate), name)
                if os.path.isdir(os.path.join(ROOT, sibling)) and not covered(sibling, covers):
                    missing.append(f"{entry['name']}: depends on {sibling}")
        self.assertEqual(missing, [], '\n'.join(missing))

    def test_every_dep_exists(self):
        for entry in matrix():
            for dep in (entry.get('deps') or '').split():
                self.assertTrue(os.path.exists(os.path.join(ROOT, dep)), f"{entry['name']}: {dep}")


if __name__ == '__main__':
    unittest.main()
