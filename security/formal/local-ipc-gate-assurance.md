# Local IPC admission: M27

Status: model supplied; Tamarin has not been run for this revision. Expected:
five verified lemmas (including three reachability witnesses), one intentional
falsification (`authentic_browser_required`). Run:

```
tamarin-prover --prove security/formal/m27_local_ipc_gate.spthy
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
