# Build performance

Measurements on the reference dev machine (Linux, 12 cores, 30 GB RAM,
nightly rustc 1.100.0-nightly), building `vela-server` with tests.

## What is configured

`.cargo/config.toml` (repo root) applies to every workspace:

- **Shared `target/`** — all workspaces (libVELA, serverVELA, desktopVELA, …)
  build into one `VELA/target/`, so shared dependencies compile once and
  disk usage drops by roughly half. Previously each workspace held its own
  9–11 GB target dir with near-identical contents.
- **lld linker** (Linux x86_64) — clang + `-fuse-ld=lld`. Linking dominates
  incremental test builds, and lld cuts those links ~4x vs GNU ld.

`cargo-nextest` (install: `cargo install cargo-nextest --locked`) runs the
test suites in parallel; `cargo nextest run` per workspace.

## Measured results (vela-server)

| Scenario                          | before | after        | delta |
|-----------------------------------|--------|--------------|-------|
| incremental test rebuild          | 37.7 s | **7.1 s**    | −81 % |
| clean build with tests            | 169 s  | 160 s        | −5 %  |
| disk for a lib build              | 5.4 GB | 3.5 GB       | −35 % |

("after" = cranelift + lld; lld alone already gives the 9.3 s row below.)

## Debuginfo tuning (biggest disk win)

Dev profiles now use `debug = "line-tables-only"` for local crates and
`debug = false, opt-level = 1` for dependencies (serverVELA previously used
cargo defaults = full `debuginfo=2` everywhere; desktopVELA already tuned
its deps). Backtraces keep file names and line numbers; variable and type
information is dropped — use a debug build with `debug = true` if you need
to inspect variables in a debugger.

Measured with the shared target dir: `vela-server` with all test binaries
plus a `vela-desktop-core` check **shrank from ~7.4 GB to 2.3 GB (−69 %)**.
The one-time cost is a slower cold build (~2x for the server), because
dependencies now compile at opt-level 1; incremental rebuilds are unchanged.

Housekeeping: invalidated artifacts are not garbage-collected by cargo, so
after profile changes run `rm -rf target` once, and periodically after big
dependency upgrades.

Breakdown by technique:

| Technique                                   | incremental tests | clean  | disk |
|---------------------------------------------|-------------------|--------|------|
| baseline (GNU ld, LLVM)                     | 37.7 s            | 169 s  | 5.4 GB |
| cranelift codegen (`-Zcodegen-backend`)     | 30.4 s            | 155 s  | 3.5 GB |
| lld linker only                             | 9.3 s             | 174 s  | —    |
| cranelift + lld                             | **7.1 s**         | 160 s  | —    |
| mold instead of lld                         | 11.8 s            | 160 s  | —    |

mold loses to lld here (12 cores / 30 GB); revisit only if the machine
changes. The linker, not codegen, is the dominant lever for test builds.

## Cranelift (nightly-only, opt-in)

The Cranelift backend makes `cargo check`-grade builds ~10–20 % faster and
output ~35 % smaller. It produces slower machine code than LLVM, so use it
for development iteration only — **never** for release artifacts or CI
(both stay on stable + LLVM).

```sh
rustup component add rustc-codegen-cranelift-preview --toolchain nightly

# Dev iteration (note: RUSTFLAGS overrides the repo config, so the lld
# flags and the reqwest_unstable cfg must be repeated here):
RUSTFLAGS="-Zcodegen-backend=cranelift -Clinker=clang -Clink-arg=-fuse-ld=lld --cfg reqwest_unstable" \
  cargo build -p vela-server
```

Everything currently in the workspace builds clean under Cranelift
(all 12 fuzz targets under ASan included). If a crate ever fails with
`-Zcodegen-backend=cranelift`, build that crate without the flag — the
flag is per-invocation, so this is always possible without config edits.

## Housekeeping

- `fuzz` builds (`cargo fuzz`) use ASan and generate multi-GB `target`
  dirs under `libVELA/vela-core/fuzz/target`; delete it after local fuzz
  sessions. CI builds it fresh each night.
- `cargo report future-incompatibilities` warnings are tracked upstream
  (see the `get_sync` recursion-depth note in
  `serverVELA/vela-server/src/routes.rs`); they are pre-existing and not
  caused by this config.
