# Cold toolchain installation exceeded its time budget

Failed baseline: fb6fc35, refinement job 120519697969 in
https://github.com/lucannez64/VELA/actions/runs/39984396642.

The installed-tool cache missed. Source compilation proceeded successfully:
Rust frontend/driver and name extractor built, both OCaml 5.1.1 switches built,
and hax-engine 0.3.7 was installed at 17:02:36 UTC. F★ installation began at
17:07:33 UTC. The enclosing installer hit its exact 3600-second limit at
17:15:47 UTC and exited 124 while F★ was still building. There was no VELA
proof verdict; this is a setup timeout, not a proved result or counterexample.
The timing excerpts preserve relevant timestamped job lines, not a full log.

The cold-install limit is now 5400 seconds (90 minutes), inside a 120-minute
job limit. The prerequisite step retains its 15-minute limit. Memory remains
6 GiB for tool installation, no swap, one worker; application proof commands
retain their existing 3 GiB bound. No tool version, proof obligation or
cryptographic/model assumption changed.

The exact toolchain cache key is unchanged: the installer script did not
change. Only a fully installed, activated toolchain is saved. This first cache
population still requires a cold rebuild; later exact hits skip installation
and retain fresh VELA extraction/checking.

Validation: workflow YAML and all shell blocks parse; the configured installer
budget is 5400 seconds and the job budget is 120 minutes, with the same 6 GiB
install cap. Correspondence and proof-boundary gates still pass. No complete
new hosted proof result is claimed. The next run must finish installation and
execute the proofs before this job can be considered successful.
