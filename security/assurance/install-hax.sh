#!/usr/bin/env bash
# Run in a clean Linux environment. No global Cargo flags: nested hax needs --cfg hax.
set -euo pipefail
export CARGO_BUILD_JOBS=1 OPAMJOBS=1 MAKEFLAGS=-j1 CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm
root=${VELA_HAX_ROOT:-$HOME/.local/opt/vela-hax-0.3.7}
mkdir -p "$root/bin" "$root/cargo-home"
export CARGO_HOME="$root/cargo-home"
export PATH="$root/bin:$HOME/.cargo/bin:$PATH"
export OPAMROOT="$root/opam"
opam init --bare --disable-sandboxing --no-setup --yes
rustup toolchain install nightly-2025-11-08 --profile minimal \
  --component rustc-dev --component llvm-tools-preview --component rust-analysis \
  --component rust-src --component rustfmt
cargo +nightly-2025-11-08 install cargo-hax --version 0.3.7 --locked --root "$root"
cargo +nightly-2025-11-08 install hax-driver --version 0.3.7 --locked --root "$root"
if [[ ! -d "$root/hax/.git" ]]; then
  git clone https://github.com/cryspen/hax.git "$root/hax"
fi
git -C "$root/hax" checkout d8b5b3d3b666fee8943a351445d2b680105e8ea3
(cd "$root/hax" && RUSTFLAGS="--cfg hax" cargo +nightly-2025-11-08 install --locked --path engine/names/extract --root "$root")
opam switch create vela-hax ocaml-base-compiler.5.1.1 --yes
# Reduce heap slack for the large generated OCaml AST module. Native engine
# installation exceeded 3 GiB; the successful local run used a 6 GiB cap.
OCAMLRUNPARAM="o=10,s=256k" opam install --switch vela-hax --yes "$root/hax/engine"
opam switch create vela-fstar ocaml-base-compiler.5.1.1 --yes
opam install --switch vela-fstar --yes fstar.2025.10.06
curl -fL -o "$root/z3.zip" https://github.com/Z3Prover/z3/releases/download/z3-4.13.3/z3-4.13.3-x64-glibc-2.35.zip
echo "32c7377026733c9d7b33c21cd77a68f50ba682367207b031a6bfd80140a8722f  $root/z3.zip" | sha256sum -c
unzip -oq "$root/z3.zip" -d "$root"
install -m755 "$root/z3-4.13.3-x64-glibc-2.35/bin/z3" "$root/bin/z3-4.13.3"
# GITHUB_PATH is optional: this script also works outside Actions.
if [[ -n ${GITHUB_PATH:-} ]]; then
  printf 'CARGO_HOME=%s\n' "$CARGO_HOME" >> "$GITHUB_ENV"
  printf '%s\n' "$root/bin" "$OPAMROOT/vela-hax/bin" "$OPAMROOT/vela-fstar/bin" >> "$GITHUB_PATH"
fi
