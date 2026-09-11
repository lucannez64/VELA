"""Measure paired external adapters; JSON config contains argv arrays, never shell text.

Adapters must perform one completed operation, exit nonzero on failure, and
reset fixtures themselves. Elapsed time includes process startup. No secrets
or adapter stdout are persisted. Use dedicated disposable vaults.
"""
import argparse
import json
import platform
import random
import statistics
import subprocess
import time
from pathlib import Path


def run(config, samples, output):
    if samples < 2 or len(config) < 2:
        raise ValueError('require >=2 samples and >=2 labeled adapters')
    for argv in config.values():
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            raise ValueError('adapters must be nonempty argv arrays')
    rng = random.Random(27)
    rows = []
    for trial in range(-1, samples):
        labels = list(config)
        rng.shuffle(labels)
        for label in labels:
            start = time.perf_counter_ns()
            subprocess.run(config[label], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=300)
            elapsed = time.perf_counter_ns() - start
            if trial >= 0:
                rows.append(dict(case=label, sample=trial, elapsed_ns=elapsed))
    summary = {}
    for label in config:
        values = sorted(r['elapsed_ns'] for r in rows if r['case'] == label)
        summary[label] = dict(n=len(values), median_ns=statistics.median(values),
                              p95_ns=values[min(len(values)-1, int(.95*len(values)))])
    Path(output).write_text(json.dumps(dict(platform=platform.platform(),
        clock='perf_counter_ns', includes_process_startup=True, samples=rows,
        summary=summary), indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', help='JSON object mapping case labels to argv arrays')
    parser.add_argument('output')
    parser.add_argument('--samples', type=int, default=100)
    args = parser.parse_args()
    run(json.loads(Path(args.config).read_text(encoding='utf-8')), args.samples, args.output)
