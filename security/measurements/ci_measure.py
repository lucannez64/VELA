"""Collect production microbenchmark samples and provenance on hosted runners."""
import csv
import io
import json
import os
import platform
import statistics
import subprocess
from pathlib import Path


def capture(*argv):
    return subprocess.check_output(argv, text=True).strip()


def main():
    output = Path('measurement-results')
    output.mkdir(exist_ok=True)
    metadata = {
        'commit': capture('git', 'rev-parse', 'HEAD'),
        'rust': capture('rustc', '-Vv'),
        'platform': platform.platform(),
        'processor': platform.processor(),
        'cpu_count': os.cpu_count(),
        'runner': {key: os.environ.get(key) for key in (
            'RUNNER_OS', 'RUNNER_ARCH', 'ImageOS', 'ImageVersion',
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
        'profile': 'release; repository Cargo config; --locked',
        'scope': 'CPU microbenchmarks; modeled bytes; no product baseline or network',
    }
    if platform.system() == 'Linux':
        metadata['cpu_details'] = capture('lscpu')
    elif platform.system() == 'Darwin':
        metadata['cpu_details'] = capture('sysctl', '-n', 'machdep.cpu.brand_string')
    else:
        metadata['cpu_details'] = capture('powershell', '-NoProfile', '-Command',
            'Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores | ConvertTo-Json')
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    exe = Path('target/release/examples/assurance_measure' + ('.exe' if os.name == 'nt' else '')).resolve()
    summary = ['# CPU microbenchmarks', '',
               'Hosted-runner measurements; copies are proxies, bytes are modeled.', '',
               '| Payload | Repeat | Chunks | Case | Median ns | p95 ns |',
               '|---|---|---|---|---|---|']
    for size in (4096, 1048576):
        for repeat in range(3):
            raw = capture(str(exe), '100', str(size))
            (output / f'samples-{size}-{repeat}.csv').write_text(raw + '\n', encoding='utf-8')
            rows = list(csv.DictReader(io.StringIO(raw)))
            if len(rows) != 2400:
                raise ValueError(f'incomplete benchmark: {len(rows)} rows')
            groups = {}
            for row in rows:
                groups.setdefault((int(row['chunks']), row['case']), []).append(int(row['elapsed_ns']))
            if len(groups) != 24 or any(len(v) != 100 for v in groups.values()):
                raise ValueError('unexpected sample groups')
            for (chunks, case), values in sorted(groups.items()):
                summary.append(f'| {size} | {repeat} | {chunks} | {case} | {statistics.median(values)} | {sorted(values)[94]} |')
    report = '\n'.join(summary) + '\n'
    (output / 'summary.md').write_text(report, encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
            stream.write(report)


if __name__ == '__main__':
    main()
