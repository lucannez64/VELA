#!/usr/bin/env python3
"""Source drift guard for the handwritten model proof; not a semantics proof."""
from pathlib import Path
import re
import sys

REQUIRED = {
    'step_core_to_lift', 'step_lift_projects', 'reach_core_lifts',
    'reach_lift_projects', 'reach_lift_wf', 'transfer_lifted_to_original',
    'transfer_original_to_lifted',
    # Encoded all-pairs goals and their core/lift proofs.
    'journal_generation_at_most_once', 'clear_pins_strictly_increase',
    'reach_core_journal_unique', 'reach_lift_journal_unique',
    'reach_core_clear_pins_strict', 'reach_lift_clear_pins_strict',
    # Concrete order instance and the two-commit non-vacuity witness.
    'term_order', 'subterm_trans', 'subterm_irrefl',
    'two_commits_reach', 'two_commits_reach_lift',
    'two_commits_clear_goal', 'two_commits_journal_goal',
    'two_commits_lift_clear_goal', 'two_commits_lift_journal_goal',
    'two_commits_ordered',
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
