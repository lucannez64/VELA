# Web-session constructors: local reproduction

This is parent working-tree evidence after baseline `5fa4e9f`, not hosted CI
or independent review. It uses pinned hax 0.3.7, Rust nightly 2025-11-08,
F★ 2025.10.06 and Z3 4.13.3. All heavy work was serialized through
`~/.local/opt/vela-tools/bin/vela-heavy`, under 3 GiB/no swap/one worker.

```bash
vela-heavy env CARGO_HOME=/tmp/vela-hax-cargo \
  OPAMROOT="$HOME/.local/opt/vela-tools/opam" \
  PATH="/tmp/vela-fstar-prebuilt/fstar/bin:$HOME/.local/opt/vela-tools/bin:$HOME/.local/opt/vela-tools/opam/vela-hax/bin:$PATH" \
  serverVELA/vela-session-policy/verify-fstar.sh
vela-heavy env CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-fbd571eb/target \
  cargo test --manifest-path serverVELA/Cargo.toml -p vela-server \
  --test integration web_session_
```

`fstar.log` records eight policy tests, fresh hax extraction and successful
checking of the entire resulting module (19 postconditions, 21 selected
functions). The exact generated module is retained unchanged. Imported
libraries and proof tools remain trusted; library warnings are preserved.
`integration-tests.log` records thirteen passing server tests, 46 filtered.
The existing completed target directory was reused for dependency artifacts.

See [the boundary](../../../14-session-observation-refinement.md) for supplied
observations, UUID/source decoding and concrete effect gaps. Neither the
constructors nor these tests establish complete handler/database refinement.
