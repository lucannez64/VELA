#!/usr/bin/env python3
"""Reject unreviewed proof escapes in focused drivers; not a proof checker.

F* remains the proof checker. This gate only enforces a reviewed source policy,
including exact solver-budget pragmas. Imported libraries remain trusted.
"""
import argparse
import re
from pathlib import Path


def uncomment(source):
    output, index, depth, quoted = [], 0, 0, False
    while index < len(source):
        pair, char = source[index:index + 2], source[index]
        if quoted:
            output.append(char)
            if char == '\\' and index + 1 < len(source):
                output.append(source[index + 1])
                index += 2
                continue
            quoted = char != '"'
        elif not depth and char == "'" and (literal := re.match(
            r"'(?:[^'\\\r\n]|\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-9]{3}|.))'",
            source[index:],
        )):
            # F* type variables such as 'a do not match a closed character
            # literal. A quote character must not shift string-lexer parity.
            output.append('0')
            index += len(literal.group())
            continue
        elif depth:
            if pair == '(*':
                depth += 1
                index += 2
                continue
            if pair == '*)':
                depth -= 1
                index += 2
                continue
            output.append('\n' if char == '\n' else ' ')
        elif pair == '(*':
            output.append(' ')
            depth = 1
            index += 2
            continue
        elif pair == '//':
            end = source.find('\n', index)
            if end < 0:
                break
            output.append('\n')
            index = end + 1
            continue
        else:
            output.append(char)
            quoted = char == '"'
        index += 1
    if depth or quoted:
        raise ValueError('unterminated comment or string')
    return ''.join(output)


def check_source(source, *, generated=False):
    code = uncomment(source)
    budget_header = '#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"'
    push = '#push-options "--fuel 4 --ifuel 2"'
    pop = '#pop-options'
    header_count, option_depth = 0, 0
    checked = []
    for line in code.splitlines():
        stripped = line.strip()
        if generated and stripped == budget_header:
            header_count += 1
            if header_count > 1:
                raise ValueError('repeated extraction budget header')
            continue
        if not generated and stripped == push:
            if option_depth:
                raise ValueError('nested proof budget scopes are unreviewed')
            option_depth = 1
            continue
        if not generated and stripped == pop:
            if not option_depth:
                raise ValueError('unmatched proof budget pop')
            option_depth = 0
            continue
        checked.append(line)
    if option_depth:
        raise ValueError('unclosed proof budget scope')
    code = '\n'.join(checked)
    # Examine directives before masking strings: an arbitrary source option
    # cannot hide behind an otherwise legitimate string literal.
    if re.search(r'#\s*(?:set|push|pop|reset)-options\b', code):
        raise ValueError('unreviewed source options')
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code, flags=re.S)
    if re.search(r'\b(?:assume|admit|admit1|axiom|Admitted|sorry|magic|unsafe_coerce|expect_failure|expect_lax_failure)\b', code):
        raise ValueError('unreviewed proof escape')
    if re.search(r'^\s*val\s', code, re.M):
        raise ValueError('unreviewed bare declaration')


def check_files(generated, proofs, include_dirs=()):
    declared = {path.resolve() for path in [*generated, *proofs]}
    directories = {path.parent for path in declared}
    directories.update(path.resolve() for path in include_dirs)
    # All local source-resolution directories must be covered, including the
    # verifier cwd. Extra modules/interfaces cannot silently add assumptions.
    for directory in directories:
        siblings = set(directory.glob('*.fst')) | set(directory.glob('*.fsti'))
        unlisted = siblings - declared
        if unlisted:
            raise ValueError('unlisted proof sources in include directory: ' +
                             ', '.join(str(path) for path in sorted(unlisted)))
    for extracted, paths in [(True, generated), (False, proofs)]:
        for path in paths:
            try:
                check_source(path.read_text(encoding='utf-8'), generated=extracted)
            except ValueError as error:
                raise ValueError(f'{path}: {error}') from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generated', nargs='+', type=Path, required=True)
    parser.add_argument('--proof', nargs='+', type=Path, required=True)
    parser.add_argument('--include-dir', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        check_files(args.generated, args.proof, args.include_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')
    print(f'Driver source policy: {len(args.generated)} extracted modules, {len(args.proof)} proof modules; no unreviewed escapes/options')


if __name__ == '__main__':
    main()
