#!/usr/bin/env python3
"""Pin the reviewed X25519-cofactor results; output drift detection."""
from pathlib import Path
import re
import sys

BOUND_PREFIX = 'RESULT Proved bit secrecy of b up to probability '
EXPECTED_BOUND = re.compile(
    r'4 \* pDistRerandom \+ 2 \* pGDH\(time(?:_[0-9]+)?, 2 \* qH\) '
    r'\+ \(2 \* Qd \+ 2 \* qH\) \* PCollKey \+ 6 \* PhashCt'
)
PROJECTION_RESULT = 'RESULT Proved indistinguishability between game 1 and game 2'


def check_bound(path):
    results = [line[len(BOUND_PREFIX):] for line in path.read_text().splitlines()
               if line.startswith(BOUND_PREFIX)]
    if not results or any(not EXPECTED_BOUND.fullmatch(' '.join(line.split()))
                          for line in results):
        raise ValueError('cofactor IND-CCA2 bound changed; '
                         'review the model, assumptions, and claimed bound')


def check_projection(path):
    lines = path.read_text().splitlines()
    if lines.count(PROJECTION_RESULT) != 1:
        raise ValueError('cofactor projection equivalence result missing or changed')
    if 'All queries proved.' not in lines:
        raise ValueError('cofactor projection equivalence was not proved')


def main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ('bound', 'projection'):
            raise ValueError('usage: check-cryptoverif-cofactor.py '
                             '{bound|projection} LOG')
        log = Path(sys.argv[2])
        if sys.argv[1] == 'bound':
            check_bound(log)
        else:
            check_projection(log)
    except (ValueError, OSError) as error:
        sys.exit(str(error))


if __name__ == '__main__':
    main()
