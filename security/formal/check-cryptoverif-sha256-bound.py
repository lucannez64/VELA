#!/usr/bin/env python3
"""Pin the reviewed SHA-256 bridge results; this is output drift detection."""
from pathlib import Path
import re
import sys

PREFIX = 'RESULT Proved bit secrecy of b up to probability '
TIME = r'time(?:_[0-9]+)?'
TOKEN = '@TIME@'

# Each pattern is the complete probability expression printed by CryptoVerif,
# except that the proof-step time indices are not pinned.
EXPECTED = {
    'kem_v2_x25519_gdh_sha256': (
        f'4 * pDistRerandom + 2 * pGDH({TOKEN}, 2 * qH) + '
        f'(2 * Qd + 2 * qH) / |Z| + 6 * PhashCt'
    ),
    'kem_v2_x25519_gdh_nonuniform_sha256': (
        f'4 * pDistRerandom + 2 * pGDH({TOKEN}, 2 * qH) + '
        f'(2 * Qd + 2 * qH) * PCollKey + 6 * PhashCt'
    ),
    'kem_v2_mlkem_cca_sha256': (
        f'2 * qH / |mlss| + 2 * Penc({TOKEN}, 1, 1, Qd) + '
        f'(8 * Qd + 2 * qH) / |Z| + 4 * PhashCt + 6 * Qd * Pctxtcoll'
    ),
    # Multi-recipient / multi-challenge variants (N users, Qc challenges,
    # #Odecap <= N * Qd total decapsulation calls).  The PhashEk term is
    # charged because distinct recipient public keys meet in the ROM input.
    'kem_v2_x25519_gdh_multi_sha256': (
        f'(2 * N + 2 * Qc) * pDistRerandom + 2 * N * Qc * pGDH({TOKEN}, 2 * qH) + '
        f'(2 * N^2 * Qc^2 + 4 * N^2 + 2 * Qc^2 + 2 * #Odecap * Qc + 2 * N^2 * Qc + '
        f'2 * qH * Qc) / |Z| + 8 * PhashCt + 6 * PhashEk'
    ),
    'kem_v2_x25519_gdh_nonuniform_multi_sha256': (
        f'(2 * N + 2 * Qc) * pDistRerandom + 2 * pGDH({TOKEN}, 2 * qH) + '
        f'(8 * N^2 + 4 * Qc^2 + 2 * #Odecap * Qc + 2 * Qc * qH) * PCollKey + '
        f'8 * PhashCt + 6 * PhashEk'
    ),
    'kem_v2_mlkem_cca_multi_sha256': (
        f'2 * qH * Qc / |mlss| + 2 * Penc({TOKEN}, N, Qc, #Odecap) + '
        f'(2 * N^2 * Qc^2 + 3 * N^2 + 8 * #Odecap * Qc + 2 * N^2 * Qc + '
        f'2 * qH * Qc) / |Z| + (2 * Qc^2 * N^2 + 6 * #Odecap * Qc * N) * Pctxtcoll + '
        f'6 * PhashCt + 4 * PhashEk + 8 * N^2 * Pkeycoll'
    ),
}


def compile_expected(text):
    escaped = re.escape(text)
    return re.compile(escaped.replace(re.escape(TOKEN), TIME))


def check(model, path):
    if model not in EXPECTED:
        raise ValueError(f'unknown SHA-256 bridge model: {model}')
    expected = compile_expected(EXPECTED[model])
    results = [line[len(PREFIX):] for line in path.read_text().splitlines()
               if line.startswith(PREFIX)]
    if not results or any(not expected.fullmatch(' '.join(line.split()))
                          for line in results):
        raise ValueError(f'{model}: SHA-256 bridge bound changed; '
                         'review the model, assumptions, and claimed bound')


def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError('usage: check-cryptoverif-sha256-bound.py MODEL LOG')
        check(sys.argv[1], Path(sys.argv[2]))
    except (ValueError, OSError) as error:
        sys.exit(str(error))


if __name__ == '__main__':
    main()
