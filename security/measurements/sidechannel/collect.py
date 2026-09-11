import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

out = Path('boundary-results')
out.mkdir(exist_ok=True)
sources = ['desktopVELA/vela-desktop-core/src/ipc_gate.rs',
           'desktopVELA/vela-desktop-core/src/presence.rs',
           'libVELA/vela-crypto/src/oram.rs']
meta = dict(commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            platform=platform.platform(), processor=platform.processor(),
            rust=subprocess.check_output(['rustc', '-Vv'], text=True),
            runner={k: os.getenv(k) for k in ['RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion','GITHUB_RUN_ID']},
            sources={p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sources},
            boundaries='synthetic process table, user identity and UI; unavailable biometric; no socket or real human')
(out/'metadata.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
exe = Path('target/release/vela-sidechannel-measure' + ('.exe' if os.name == 'nt' else '')).resolve()
for seed in [27,91,163]:
    with (out/f'timing-{seed}.csv').open('w', encoding='utf-8') as f:
        subprocess.run([str(exe),str(seed)], stdout=f, check=True, timeout=180)
