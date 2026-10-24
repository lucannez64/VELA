#!/usr/bin/env python3
"""Drift/escape guard for the sync chunk proof; not a soundness certificate."""
from pathlib import Path
import re
import sys


def uncomment(text):
    result, i, depth, quoted = [], 0, 0, False
    while i < len(text):
        pair, char = text[i:i + 2], text[i]
        if quoted:
            result.append(char)
            if char == '\\' and i + 1 < len(text):
                result.append(text[i + 1])
                i += 2
                continue
            if char == '"':
                quoted = False
        elif depth:
            if pair == '(*':
                depth += 1
                i += 2
                continue
            if pair == '*)':
                depth -= 1
                i += 2
                continue
            result.append('\n' if char == '\n' else ' ')
        elif pair == '(*':
            depth = 1
            result.append(' ')
            i += 2
            continue
        elif pair == '//':
            end = text.find('\n', i)
            if end == -1:
                break
            result.append('\n')
            i = end + 1
            continue
        else:
            result.append(char)
            quoted = char == '"'
        i += 1
    if depth or quoted:
        raise ValueError('unterminated proof comment or string')
    return ''.join(result)


def checked_code(path, extracted=False):
    code = uncomment(path.read_text())
    if extracted:
        # Exact hax 0.3.7 boilerplate: fuel/solver budget, no admission flags.
        code = code.replace('#set-options "--fuel 0 --ifuel 1 --z3rlimit 500"', '', 1)
    if re.search(r'\b(?:assume|admit|admit1|axiom|Admitted|sorry|magic|unsafe_coerce)\b'
                 r'|--(?:lax|admit_smt_queries|unsafe_tactic_exec|load)\b'
                 r'|#\s*(?:set|push|pop|reset)-options\b', code):
        raise ValueError(f'{path}: unreviewed proof escape or source options')
    return code


def check(artifact, lemmas):
    extraction = checked_code(artifact, extracted=True)
    proof = checked_code(lemmas)
    if not re.search(r'^module Vela_sync_policy\s*$', extraction, re.M):
        raise ValueError('unexpected extraction module')
    if len(re.findall(r'\(ensures\b', extraction)) != 11:
        raise ValueError('expected 11 extracted postconditions')
    if not re.search(r'^module Vela_sync_policy_chunk_lemmas\s*$', proof, re.M):
        raise ValueError('unexpected chunk lemma module')
    if not re.search(r'^open Vela_sync_policy\s*$', proof, re.M):
        raise ValueError('chunk lemmas must import the actual extraction')
    if len(re.findall(r':\s*Lemma\b', proof)) != 20:
        raise ValueError('expected 20 handwritten lemmas')
    required = {'accept_iff_admissible', 'reject_iff_not_admissible',
                'accepted_permit_is_exact', 'stale_clock_rejected_for_any_baseline',
                'accept_witness_first_contact', 'reject_witness_rolled_back'}
    names = set(re.findall(r'^let\s+(?:rec\s+)?(\w+)\b', proof, re.M))
    if not required <= names:
        raise ValueError('missing required admission theorem or witness')


def check_epoch(artifact, lemmas):
    extraction, proof = checked_code(artifact, extracted=True), checked_code(lemmas)
    if not re.search(r'^module Vela_sync_policy\s*$', extraction, re.M):
        raise ValueError('unexpected epoch extraction module')
    if len(re.findall(r'\(ensures\b', extraction)) != 4:
        raise ValueError('expected 4 epoch postconditions')
    if not re.search(r'^module Vela_sync_policy_epoch_lemmas\s*$', proof, re.M):
        raise ValueError('unexpected epoch lemma module')
    if not re.search(r'^open Vela_sync_policy\s*$', proof, re.M):
        raise ValueError('epoch lemmas must import the focused extraction')
    if len(re.findall(r':\s*Lemma\b', proof)) != 6:
        raise ValueError('expected 6 handwritten epoch lemmas')
    required = {'accepted_implies_positive_and_equal', 'positive_and_equal_admits',
                'plan_matches_independent_predicate', 'rejected_implies_not_admissible',
                'equal_positive_pair_admits', 'mismatched_or_nonpositive_pair_refuses'}
    names = set(re.findall(r'^let\s+(?:rec\s+)?(\w+)\b', proof, re.M))
    if not required <= names:
        raise ValueError('missing required epoch theorem')


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--epoch':
            check_epoch(Path(sys.argv[2]), Path(sys.argv[3]))
            print('Epoch source guard: 4 extracted postconditions, 6 handwritten lemmas')
        elif len(sys.argv) == 3:
            check(Path(sys.argv[1]), Path(sys.argv[2]))
            print('Chunk source guard: 11 extracted postconditions, 20 handwritten lemmas')
        else:
            raise ValueError('usage: check-sync-chunk-proof.py [--epoch] EXTRACTION LEMMAS')
    except (OSError, ValueError) as error:
        sys.exit(str(error))
