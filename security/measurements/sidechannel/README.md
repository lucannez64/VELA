# Timing boundary probes

Run `cargo build --locked --release --manifest-path security/measurements/sidechannel/Cargo.toml`
then `python security/measurements/sidechannel/collect.py` from the repository
root. CI runs these commands on Linux, Windows, and macOS. Raw samples and
source hashes are preserved in artifacts. Three public order seeds vary
paired-case order; production ORAM leaf remapping still uses OS randomness.

## Precisely what is measured

- `approval_yes/no_0ms`: production `presence.rs::confirm`, prompt formatting,
  and approval/error result handling. Imported source is compiled directly.
  The biometric boundary returns unavailable; a scripted Host supplies the
  answer. Token construction is a stub. This is software approval handling,
  not biometric or human-response latency, socket latency, or a full ceremony.
- `approval_yes/no_2ms`: the same, with an equal requested 2 ms UI delay on both
  outcomes. OS sleep scheduling can overshoot. No claim is made that 2 ms
  resembles human reaction time. This checks how delay masks handler costs.
- `gate_depth_2/8/9_batch100`: production `authorize_host`, with a synthetic
  process table and fixed same-user identity. The first two admit; depth nine
  is beyond the eight-entry search and refuses. Timings are for 100 checks,
  including result assertions. The peer path is deliberately untrusted and
  has an allowed basename, exercising M27's impostor premise. This measures
  policy traversal/allocation, not OS process-table calls or PID-race safety.
- `path_target_a/b`: real PathOram prepare/access and shared fake-tree read/
  writeback, fixed 4 KiB real payloads, different targets at equal capacity.
  Each capacity (4,5,16,64,256) gets 1,000 paired observations after warmup.
  Path mode is forced at every size to separate height from mode selection.
  `path_slots` counts one direction's slots, including empty dummies; it is
  not ciphertext bytes. Dummies contain no fixed-size in-memory payload.

Plain autofill has no per-fill presence prompt. The approval cases represent
the presence code used by passkey and in-core login requests, not all IPC.
Host/biometric/token/peer shims are explicitly visible in the probe; changing
them must not be described as testing native transport or hardware.

## Interpretation

Report each run separately: medians, p95, and Welch t statistic for paired
case distributions (an exploratory indicator, not a security pass/fail test).
Samples share evolving cache, stash and RNG state and are not IID. A small
statistic does not prove constant time; a large statistic needs replication
and an observer/threat-model argument before it implies secret leakage.
Depth and capacity are deliberately different public inputs. Target A/B at
fixed capacity is a different question and must not be pooled across sizes.
Outcomes already reveal approval/denial, so distinguishing those alone is not
a new confidentiality break. Gate error strings also disclose branch results.

These measurements narrow SPEC's unevaluated boundary. Actual native-pipe/
socket observations, real human/biometric approvals, and encrypted server path
responses still require deployment-level experiments. The symbolic M22 model
does not include any of these measured runtimes.
