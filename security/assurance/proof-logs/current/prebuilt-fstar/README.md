# Official prebuilt F★ validation

CI now downloads F★ 2025.10.06 and its matching standard libraries from the
[official release](https://github.com/FStarLang/FStar/releases/tag/v2025.10.06),
instead of building a second OCaml switch and F★ from source.

Archive: fstar-v2025.10.06-Linux-x86_64.tar.gz
SHA-256: 940c187d7a6dc3e95d17fd5159b5eaec17d62981c7f135a7e6c531ce3b59442d
Release commit: 7b347386330d0e5a331a220535b6f15288903234
The release binary reports OCaml 4.14.2. This is its build compiler, not a
new system OCaml prerequisite. hax still uses its pinned OCaml 5.1.1 switch.

The archive digest was checked before extraction/execution. It is downloaded
and version-checked before the long hax build to surface download failures
early. Installer-hash cache keys automatically invalidate older layouts.

Validation against this exact downloaded executable:

- Fresh hax extraction and F★ checking passed for all eight policy crates and
  all eleven crypto contracts: 122 selected functions / 119 postconditions.
- All commands ran sequentially under the 3 GiB bounded runner with pinned
  hax 0.3.7, Rust nightly-2025-11-08 and Z3 4.13.3. Logs for each crate and the
  crypto runner are retained here. The crypto command completed successfully
  in about 57 seconds after its preceding policy/test/extraction work.
- The extracted artifacts remained byte-identical to the existing source-tree
  artifacts. The twelve snapshots include eleven Rust modules and the String
  compatibility view. The proof-boundary gate still reports no local assume
  val declarations; imported models and compiler/proof tools remain trusted.
- The actual CI activation block passed with local installation prefixes and
  temporary GITHUB_ENV/GITHUB_PATH files substituted. activation.log records
  the official release version and unchanged hax/Rust/Z3 pins.
- Workflow YAML/all shell blocks parse. The complete new hosted installer and
  cache restore are pending CI; local proof success is not hosted CI success.

Why some cold-build time remains: the pinned hax 0.3.7 release has no standalone
binary assets. The [current upstream manual](https://hax.cryspen.com/manual/)
states binary releases begin with 0.4.0, and also documents a Nix binary cache.
This change preserves hax 0.3.7 and its existing proof/extraction correspondence.
It does not claim to have validated a cache hit for the pinned upstream Nix
package. Our completed-toolchain cache reuses the installed hax after the first
successful build. No VELA extraction/proof result is reused by that cache.

Prebuilt compilers and GitHub cache contents are trusted tooling under the
selected boundary. This installation change supplies no full-system refinement
or computational-construction theorem.
