# Node prerequisite and installed-toolchain cache

Failed baseline: f9b20c4, refinement job 120488775909 in
https://github.com/lucannez64/VELA/actions/runs/39975465288.

The tool installer reached the pinned hax-engine opam package, then exited 10
because system package nodejs was missing. No VELA proof verdict was produced.
The pinned hax source explicitly declares `depexts: [["nodejs"] {}]`.

The earlier slow prerequisite step downloaded 142 MB, including the distro
OCaml compiler/library packages. The log shows multi-minute download gaps on
azure.archive.ubuntu.com, including about 13 minutes for libcompiler-libs and
16 minutes for the OCaml archive. This was package download time, not solver
work. Ubuntu noble's opam package recommends OCaml:
https://packages.ubuntu.com/noble/opam.

Changes:

- Install nodejs explicitly; use apt --no-install-recommends so the otherwise
  unused distro OCaml does not accompany opam. The selected compiler remains
  OCaml 5.1.1 inside opam switches. Apt retries/network timeouts and a 15-minute
  prerequisite limit bound stalled setup.
- Restore/cache completed installed tools and pinned Rust nightly using an
  exact OS/architecture/Ubuntu/installer-hash key, without fallback keys.
  Save after successful installation and activation, before application proofs,
  so a later application proof failure does not discard a valid tool build.
- Restore environment paths on both cache hits and misses. Require installed
  hax frontend/engine 0.3.7 and F★ 2025.10.06, and log Z3/Rust versions.
- Clean disposable opam build/download directories before caching. Installed
  tools and their libraries are retained. No VELA proof output is cached;
  the existing fresh extraction/check steps remain unconditional.

Local validation:

- The actual activation shell block passed against the installed pinned tool
  prefix (only the local prefix and temporary GITHUB_ENV/GITHUB_PATH outputs
  were substituted). activation.log records the probes. Deliberately changing
  the expected frontend version to 0.3.8 correctly rejected activation.
  Cache hits also retain the activation/version log in the CI artifact.
- The pinned hax opam external-dependency check passed against the existing
  local installation with Node present; depext-check.log records this. This is
  not a clean Ubuntu installation test.
- Fresh bounded extraction and F★ checking of all 19 share-policy contracts
  passed; share-policy-fstar.log contains the full output. The extraction
  remained byte-identical to the existing tracked artifact.
- Workflow YAML/all shell blocks parse; restore/save paths agree. An opam
  clean dry run confirms it targets disposable build/download data. The dry
  run made no local cleanup changes.

GitHub cache restoration, apt package selection and a complete cold hosted
installation still require the next CI run. Installed tool binaries/cache are
part of trusted CI infrastructure. No formal obligation, selected primitive
assumption, compiler version or memory limit is relaxed by these changes.
