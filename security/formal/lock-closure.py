#!/usr/bin/env python3
"""Print the part of a workspace Cargo.lock that one crate resolves to.

usage: lock-closure.py <workspace Cargo.lock> <crate dir>

The CI proof jobs key their reuse on this instead of the whole lockfile, so a
dependency bump elsewhere in the workspace (a server-only crate) does not rerun
proofs whose crate never reaches it. Every package reachable from the crate
through the lockfile's dependency lists (normal, build and dev, all targets) is
printed as `name version source checksum`, sorted. A crate missing from the
lockfile is an error, never an empty closure.
"""
import sys
import tomllib
from pathlib import Path


def closure(lock: dict, root_name: str) -> list[str]:
    packages = lock.get('package', [])
    by_name: dict[str, list[dict]] = {}
    for p in packages:
        by_name.setdefault(p['name'], []).append(p)

    def resolve(spec: str) -> dict:
        # "name", "name version" or "name version (source)"
        parts = spec.split(' ', 2)
        candidates = by_name.get(parts[0], [])
        if len(parts) > 1:
            candidates = [p for p in candidates if p['version'] == parts[1]]
        if len(parts) > 2:
            source = parts[2].strip('()')
            candidates = [p for p in candidates if p.get('source') == source]
        if len(candidates) != 1:
            raise SystemExit(f'lock-closure: cannot resolve {spec!r} ({len(candidates)} matches)')
        return candidates[0]

    roots = [p for p in by_name.get(root_name, []) if 'source' not in p]
    if len(roots) != 1:
        raise SystemExit(f'lock-closure: {root_name} is not a workspace member of this lockfile')
    seen: dict[tuple, dict] = {}
    stack = roots
    while stack:
        p = stack.pop()
        key = (p['name'], p['version'], p.get('source', ''))
        if key in seen:
            continue
        seen[key] = p
        stack.extend(resolve(d) for d in p.get('dependencies', []))
    return sorted(
        f"{p['name']} {p['version']} {p.get('source', 'local')} {p.get('checksum', '-')}"
        for p in seen.values()
    )


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    lock = tomllib.loads(Path(sys.argv[1]).read_text())
    manifest = tomllib.loads((Path(sys.argv[2]) / 'Cargo.toml').read_text())
    print('\n'.join(closure(lock, manifest['package']['name'])))


if __name__ == '__main__':
    main()
