#!/usr/bin/env python3
"""Source drift guard for the handwritten model proof; not a semantics proof."""
from pathlib import Path
import re
import sys

REQUIRED = {
    'step_core_to_lift', 'step_lift_projects', 'reach_core_lifts',
    'reach_lift_projects', 'reach_lift_wf', 'transfer_lifted_to_original',
    'transfer_original_to_lifted',
}


def uncomment(text):
    output, depth, quoted, index = [], 0, False, 0
    while index < len(text):
        pair = text[index:index + 2]
        char = text[index]
        if not depth and quoted:
            output.append(char)
            if char == '\\' and index + 1 < len(text):
                output.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                quoted = False
        elif not depth and char == '"':
            quoted = True
            output.append(char)
        elif pair == '(*':
            depth += 1
            output.append(' ')
            index += 2
            continue
        elif depth and pair == '*)':
            depth -= 1
            output.append(' ')
            index += 2
            continue
        else:
            output.append(char if not depth or char == '\n' else ' ')
        index += 1
    if depth:
        raise ValueError('unterminated proof comment')
    return ''.join(output)


def check(path):
    code = uncomment(path.read_text())
    if re.search(r'\b(?:assume|admit|admit1|axiom|sorry|magic|unsafe_coerce)\b'
                 r'|--(?:lax|admit_smt_queries|unsafe_tactic_exec|load)\b'
                 r'|#\s*(?:set|push|pop|reset)-options\b', code):
        raise ValueError('unchecked proof syntax or source options require review')
    names = set(re.findall(r'^\s*let\s+(?:rec\s+)?(\w+)\b', code, re.M))
    missing = REQUIRED - names
    if missing:
        raise ValueError('missing proof definitions: ' + ', '.join(sorted(missing)))


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: check-m28-semantic-proof.py FILE')
        check(Path(sys.argv[1]))
    except (OSError, ValueError) as error:
        sys.exit(str(error))
    print('semantic proof source guard passed')
