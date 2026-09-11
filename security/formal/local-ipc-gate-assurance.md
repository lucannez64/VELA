# Local IPC admission: M27

Verified in [CI run 34584794710](https://github.com/lucannez64/VELA/actions/runs/34584794710)
at commit `720c76a7f6ec3c84665829511607de95814ddcc4`, using Tamarin 1.12.0
and Maude 3.5.1: **five verified lemmas, one expected falsification, zero
warnings**. The falsification is `authentic_browser_required`; the solver
constructs the LocalImpostorSnapshot -> AdmitHost counterexample.

[Full solver output](m27-verified-output.txt) is retained in the repository.
The CI gate checks the exact named verdicts and rejects missing results,
unexpected falsifications, unsupported-tool warnings and incomplete analysis.
The initial run using Ubuntu Maude 3.2 was rejected for a tool-version warning;
only the supported-version rerun is accepted as the assurance result.

```
tamarin-prover --prove security/formal/m27_local_ipc_gate.spthy > m27.txt 2>&1
python security/formal/check-local-ipc-proof.py m27.txt
```

M6 already models credential release with a browser-channel assumption. M27
examines that assumption separately; these are not a composed proof.
The public network is Dolev–Yao controlled. The kernel is trusted to report
user/process facts; the attacker cannot inject Snapshot facts through In.
However, same-user attackers can launch files with chosen basenames. The
LocalImpostorSnapshot rule represents a host-named process descended from a
browser-named executable, both under attacker control. This requires no
browser compromise. The resulting trace admits the impostor.

Implementation mapping: `ipc_gate.rs::authorize_host` checks same user,
requires a PID, compares the executable **basename**, then walks at most eight
process-table entries (including the peer). `is_browser_process` compares
basenames plus `VELA_NM_BROWSER_NAMES`. There is no hash, signature, or trusted
installation-path check. The provider basename bypasses ancestry entirely;
its separate presence checks are outside this admission model.

Snapshot abstracts a successful bounded walk. Missing identity, missing table
entries, unrecognized names, and exhausted walks have no admission rule.
PID reuse, non-atomic lookups, process injection, kernel compromise, environment
configuration changes, and approval timing are not proved safe. No claim of
credential theft follows from admission alone. No claim of exact-binary or
authentic-browser provenance follows from this implementation either.
