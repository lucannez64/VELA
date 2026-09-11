# Assurance measurements

Local production ORAM state machine and blob rekey microbenchmarks:

```
cargo run --release --manifest-path libVELA/vela-crypto/Cargo.toml --example assurance_measure -- 100 4096
```

Redirect stdout to a CSV file. Repeat with 1048576-byte chunks for SPEC-sized
payloads. Records include raw samples, platform, architecture, chunk count,
payload size, and stash occupancy. Initialization and one warmup per case are
excluded. ORAM remapping uses production OS randomness; preserve raw results.
Path timings include fake-server copies but exclude encryption and network.
Whole-vault and single-blob copies are explicitly proxies, not full trivial
ORAM or Bitwarden benchmarks. Modeled bytes assume fixed padded slots plus
AEAD overhead, exclude framing, and must not be described as captured traffic.
Compare both time and bytes; the deployed threshold of four is not a measured
crossover. This harness does not justify changing it.

For installed clients, use `measure_commands.py config.json output.json` with
JSON mapping labels to argv arrays. Each adapter must complete one operation,
check success, and restore a disposable fixture. Failed commands abort the
run; randomized interleaving and one warmup reduce order/startup bias.
The timer includes command startup; use equivalent adapters and measure an
empty adapter to quantify that overhead. Never subtract it blindly.

Required experiment matrix (currently pending device/application runs):

| Experiment | Paired cases | Controls |
|---|---|---|
| Unlock | VELA / installed Bitwarden-class client | Windows, Linux, macOS, Android; same item count; record version, KDF, hardware-backed policy, cold/warm state |
| Sync | trivial / Path / baseline client | 1,4,5,16,64,256 chunks; same logical edit; capture actual request/response bytes externally |
| Rekey | VELA / baseline supported rotation | same vault; time through durable commit; include uploads, recovery shares and device capsules |
| IPC timing | deny / approve; registered / unregistered | synthetic vault; separate gate response from human approval; fixed scripted approval delay; no credential logs |
| Path timing | same-size different targets / different tree heights | separate target leakage from public capacity leakage; fixed network conditions and payload padding |

Preserve commit, build flags, OS, CPU, power mode, client versions, adapter
revision, fixture recipe and network setup alongside results. Report medians,
p95, raw distributions and repeated independent runs. A timing difference is
evidence of distinguishability under that setup; its absence is not a
constant-time proof. No measured cross-platform or competitor result is claimed
until the relevant adapter/device run exists. SPEC §9 remains out of scope.

## GitHub Actions

`assurance-measurements.yml` runs on Ubuntu 24.04, Windows 2022, and macOS 14.
Each job builds with `--locked --release` and collects three independent
process runs at 4 KiB and 1 MiB, with 100 samples per case and vault size.
Artifacts contain all 14,400 raw samples per OS, compiler/runner/CPU metadata,
and per-run median/p95 summaries. Build time is excluded. Runner hardware and
background load differ, so cross-OS results are descriptive, not causal OS
comparisons. Timings are not pass/fail security gates.

The dedicated `assurance/measurements` branch triggers runs on push; manual
workflow dispatch is available once the workflow exists on the default branch.
No deployment or release is performed. Physical-device unlock, browser approval,
actual wire bytes and installed competitor measurements still need adapters.
