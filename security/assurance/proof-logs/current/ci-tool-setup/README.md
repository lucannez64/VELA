# CI tool setup failures and reproductions

PR #175 at f1225d5 failed these two jobs in hosted run
https://github.com/lucannez64/VELA/actions/runs/39971344783:

- formal-rekey, job 120474534241: Maude 3.5.1 launched through a symlink
  could not find prelude.maude. The archived network proof log reported a
  Maude parse error before proving the first model. This is not a counterexample
  or successful proof run.
- refinement, job 120474534602: cargo-hax installation failed because the
  requested LLVM backend setting needs the unstable codegen-backend Cargo
  feature on pinned nightly-2025-11-08. Local global Cargo configuration had
  previously enabled it implicitly, hiding the clean-host failure.

The workflow now installs a Maude wrapper with an explicit MAUDE_LIB resource
location, and rejects Tamarin installation warnings before proof execution.
The hax installer explicitly exports CARGO_UNSTABLE_CODEGEN_BACKEND=true.
No proof obligations, tool versions or resource limits were weakened.

Local reproductions and validation:

- maude-before.log: bare symlink to the installed 3.5.1 binary, no MAUDE_LIB,
  reproduces the missing prelude warning. maude-after.log: the wrapper fixes it.
- network/*.log and network-summary.log: the actual bounded network runner
  with the wrapper resolves the issue: 17 verified, zero falsifications or
  warnings across all five theories. Wrapper installation was under a temporary
  local directory, using the existing pinned Maude distribution; CI installs
  the same form of wrapper against /opt/maude-3.5.1.
- backend-before.log: building a minimal dependency-free crate from /tmp with
  a fresh CARGO_HOME and CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm reproduces
  Cargo's feature error. backend-after.log: the same pinned nightly build with
  CARGO_UNSTABLE_CODEGEN_BACKEND=true succeeds. This validates Cargo setup;
  it is not a completed rebuild or verification of hax/F★.
- Workflow YAML and all run blocks pass parsing (PyYAML and bash -n).

All builds/proof executions used the existing 3 GiB bounded runner. A new
hosted installation/proof run remains required; successful hosted refinement
and full-system formalization are not claimed by these local setup checks.
