#!/usr/bin/env python3
"""Pin the reviewed nonuniform-game result; this is output drift detection."""
from pathlib import Path
import re
import sys

PREFIX = 'RESULT Proved bit secrecy of b up to probability '
EXPECTED = re.compile(
    r'4 \* pDistRerandom \+ 2 \* pGDH\(time(?:_[0-9]+)?, 2 \* qH\) '
    r'\+ \(2 \* Qd \+ 2 \* qH\) \* PCollKey'
)


def check(path):
    results = [line[len(PREFIX):] for line in path.read_text().splitlines()
               if line.startswith(PREFIX)]
    if not results or any(not EXPECTED.fullmatch(' '.join(line.split()))
                          for line in results):
        raise ValueError('nonuniform bound changed; review the model, assumptions, and claimed bound')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: check-cryptoverif-bound.py LOG')
        check(Path(sys.argv[1]))
    except (ValueError, OSError) as error:
        sys.exit(str(error))
