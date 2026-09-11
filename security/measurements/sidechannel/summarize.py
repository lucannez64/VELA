"""Validate artifacts and report exploratory timing contrasts; no security gate."""
import csv
import hashlib
import json
import math
import statistics as st
import sys
from pathlib import Path

root, destination = map(Path, sys.argv[1:])
lines = ['# Assurance boundary timing results', '',
         'All timings below are microseconds. Gate values are per 100-check batch.',
         'Welch t is descriptive only: evolving state and adjacent samples violate IID assumptions.',
         'No p-value, constant-time verdict, or real transport/biometric claim is inferred.', '']
hashes = {}
for directory in sorted(root.glob('timing-*')):
    meta = json.loads((directory/'metadata.json').read_text())
    lines += [f"## {directory.name}", '', f"Commit: `{meta['commit']}`. Platform: {meta['platform']}.",
              f"Boundary: {meta['boundaries']}.", '',
              '| Seed | Contrast | A median / p95 | B median / p95 | Welch t |',
              '|---|---|---:|---:|---:|']
    for seed in [27,91,163]:
        f = directory/f'timing-{seed}.csv'
        rows = list(csv.DictReader(f.open()))
        expected = {(f'approval_{a}_{delay}ms',0,i) for a in ['yes','no'] for delay in [0,2] for i in range(200)}
        expected |= {(f'gate_depth_{d}_batch100',0,i) for d in [2,8,9] for i in range(200)}
        expected |= {(f'path_target_{a}',n,i) for a in ['a','b'] for n in [4,5,16,64,256] for i in range(1000)}
        assert len(rows)==11400 and {(r['case'],int(r['chunks']),int(r['sample'])) for r in rows}==expected
        assert all(int(r['elapsed_ns'])>0 for r in rows)
        for r in rows:
            if r['case'].startswith('path_'):
                assert int(r['path_slots'])==4*(math.ceil(math.log2(2*int(r['chunks'])))+1)
        def get(case,n=0):
            return [int(r['elapsed_ns'])/1000 for r in rows if r['case']==case and int(r['chunks'])==n]
        pairs = [('approve/deny; no delay',get('approval_yes_0ms'),get('approval_no_0ms')),
                 ('approve/deny; 2 ms delay',get('approval_yes_2ms'),get('approval_no_2ms')),
                 ('gate depth 2/8',get('gate_depth_2_batch100'),get('gate_depth_8_batch100')),
                 ('gate depth 8/9',get('gate_depth_8_batch100'),get('gate_depth_9_batch100'))]
        pairs += [(f'target A/B; N={n}',get('path_target_a',n),get('path_target_b',n)) for n in [4,5,16,64,256]]
        pairs += [('capacity 4/256; target A',get('path_target_a',4),get('path_target_a',256))]
        for label,a,b in pairs:
            def stats(v): return f'{st.median(v):.3f} / {sorted(v)[math.ceil(.95*len(v))-1]:.3f}'
            denominator = math.sqrt(st.variance(a)/len(a)+st.variance(b)/len(b))
            t = (st.mean(a)-st.mean(b))/denominator if denominator else float('nan')
            lines.append(f'| {seed} | {label} | {stats(a)} | {stats(b)} | {t:.2f} |')
    for f in directory.iterdir():
        hashes[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    lines.append('')
assert hashes, 'No timing artifacts found'
destination.write_text('\n'.join(lines)+'\n', encoding='utf-8')
destination.with_suffix('.sha256.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8')
print(f'Validated {len(hashes)//4} platforms; wrote {destination}')
