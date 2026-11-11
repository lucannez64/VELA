#!/usr/bin/env python3
"""Reject local manual/admitted proof syntax; not an assumption-adequacy proof."""
from pathlib import Path
import re
import sys


def uncomment(source):
    """CryptoVerif comments use OCaml's nested (* ... *) syntax."""
    output = []
    depth = 0
    index = 0
    while index < len(source):
        pair = source[index:index + 2]
        if pair == '(*':
            depth += 1
            output.append(' ')
            index += 2
        elif pair == '*)' and depth:
            depth -= 1
            output.append(' ')
            index += 2
        else:
            output.append(source[index] if not depth or source[index] == '\n' else ' ')
            index += 1
    if depth:
        raise ValueError('unterminated model comment')
    return ''.join(output)


def check(path):
    code = uncomment(path.read_text())
    if re.search(r'\[[^\]]*\bmanual\b[^\]]*\]|\b(?:assume|admit|sorry)\b', code):
        raise ValueError(f'{path}: manual/admitted proof syntax requires review')


def main():
    files = [Path(arg) for arg in sys.argv[1:]] if len(sys.argv) > 1 else sorted(
        (Path(__file__).parent / 'cryptoverif').glob('*.ocv'))
    if not files:
        raise ValueError('no computational models selected')
    for path in files:
        check(path)
    print(f'{len(files)} local CryptoVerif models contain no manual/admitted proof syntax; '
          'primitive assumptions and model correspondence still require review.')


if __name__ == '__main__':
    main()
