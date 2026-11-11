#!/usr/bin/env bash
# Differential test of the hax 0.3.7 F* std models against Rust (plan step T7).
#
# Heavy pipeline: it is named verify-fstar*.sh so that vela-heavy offloads the
# whole run (F* extraction, OCaml build, Rust build) to the build box in one
# slot. run.sh is the entry point; it calls this script through vela-heavy when
# that wrapper is available.
#
#   ./verify-fstar-std-model-diff.sh [--cases N] [--seed S] [--block B]
#
# Exit status 0 means: every runnable model operation produced the same value
# as Rust on every generated case, and the two documented hax-lib bugs
# reproduce exactly as the T5 review describes.
set -uo pipefail   # not -e: every step is checked explicitly
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../../.." && pwd)
cd "$here"

CASES=1000000
SEED=0x5EED1234ABCD0001
BLOCK=1024
while [[ $# -gt 0 ]]; do
  case $1 in
    --cases) CASES=$2; shift 2 ;;
    --seed) SEED=$2; shift 2 ;;
    --block) BLOCK=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
DECSEED=$((SEED))
rc_ok() { [[ $1 -eq 0 ]] || { echo "step failed (exit $1): $2" >&2; exit "$1"; }; }

WORK=${T7_WORK:-${TMPDIR:-/tmp}/vela-t7-std-model-diff}
rm -rf "$WORK"
mkdir -p "$WORK/shadow" "$WORK/ml" "$WORK/logs" "$WORK/target"

# --- tools -----------------------------------------------------------------
# F*: the release the corpus' gates pin (see install-formal-fstar.sh).
fstar=${VELA_FSTAR:-}
if [[ -z $fstar ]]; then
  for c in "$HOME/.local/opt/vela-formal-fstar-2025.10.06/fstar/bin/fstar.exe" \
           /tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe \
           "${VELA_PROOF_TOOLS:-$HOME/.local/opt/vela-hax-0.3.7}/fstar/bin/fstar.exe"; do
    [[ -x $c ]] && { fstar=$c; break; }
  done
fi
[[ -x ${fstar:-} ]] || { echo "F* not found (set VELA_FSTAR)" >&2; exit 2; }
fstar_root=$(cd -- "$(dirname -- "$fstar")/.." && pwd)

# ocamlfind: a switch with zarith + batteries for the extracted ulib.
ocamlfind=${OCAMLFIND:-}
if [[ -z $ocamlfind ]]; then
  for c in "$HOME/.local/opt/vela-tools/opam/vela-fstar/bin/ocamlfind" \
           "${VELA_PROOF_TOOLS:-$HOME/.local/opt/vela-hax-0.3.7}/opam/vela-hax/bin/ocamlfind" \
           "$HOME/.opam/vela-ocaml/bin/ocamlfind"; do
    [[ -x $c ]] && { ocamlfind=$c; break; }
  done
fi
[[ -n ${ocamlfind:-} ]] || ocamlfind=$(command -v ocamlfind || true)
[[ -n ${ocamlfind:-} ]] || { echo "ocamlfind not found (set OCAMLFIND)" >&2; exit 2; }
ocamlbin=$(dirname -- "$ocamlfind")
ocamldep=$ocamlbin/ocamldep
export PATH="$ocamlbin:$PATH"

# The F* release ships its extracted ulib as the `fstar.lib` findlib package.
# Prefer an installed one and fall back to the release tree.
if ! "$ocamlfind" query fstar.lib >/dev/null 2>&1; then
  export OCAMLPATH="$fstar_root/lib${OCAMLPATH:+:$OCAMLPATH}"
fi

# --- pinned models ---------------------------------------------------------
# hax-lib is a crates.io dependency; every file this harness reads is pinned by
# sha256 so a different checkout cannot silently change what is compared.
hax=${VELA_HAX_PROOF_LIBS:-}
if [[ -z $hax ]]; then
  hax=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -type d \
          -name 'hax-lib-0.3.7' 2>/dev/null | head -n1)
fi
[[ -d ${hax:-}/proof-libs/fstar ]] || { echo "hax-lib 0.3.7 proof-libs not found (set VELA_HAX_PROOF_LIBS)" >&2; exit 2; }
( cd "$hax" && sha256sum -c --quiet "$here/pins.sha256" )
rc_ok $? "pinned hax-lib 0.3.7 model files changed; update pins.sha256 only with a re-run"
echo "pinned models: $(grep -c . "$here/pins.sha256") hax-lib files verified in $hax"

# The two local vela-crypto models are part of this repository; print their
# hashes for the record (the shadow is re-derived from them on every run).
echo "local models:"
local_models=("$repo/libVELA/vela-crypto/proofs/fstar/models/Alloc.Vec.fst"
              "$repo/libVELA/vela-crypto/proofs/fstar/models/Alloc.String.fst")
for m in "${local_models[@]}"; do [[ -f $m ]] || { echo "missing local model: $m" >&2; exit 1; }; done
sha256sum "${local_models[@]}" | sed 's/^/  /'
sha256sum "${local_models[@]}" > "$WORK/logs/local-models.sha256"

# --- guards ---------------------------------------------------------------
# The two hax-lib bugs and signed division must stay out of the corpus.  The
# guard is proven to bite by injecting one use of each and expecting a failure.
python3 check-model-guards.py
rc_ok $? "corpus guard (ne / mul_overflow / signed division)"
selftest="$here/.guard-selftest"
trap 'rm -rf "$selftest"' EXIT
guard_fail=0
try_injection() {  # name, file content, expected guard message fragment
  rm -rf "$selftest"; mkdir -p "$selftest"
  printf '%s\n' "$2" > "$selftest/injected-$1.fst"
  out=$(python3 check-model-guards.py 2>&1); status=$?
  if [[ $status -eq 1 ]] && grep -q "$3" <<<"$out"; then
    echo "guard self-test: injected $1 -> rejected: $(grep -m1 "$3" <<<"$out")"
  else
    echo "guard self-test: injected $1 was NOT rejected (exit $status)" >&2
    echo "$out" | sed 's/^/    /' >&2
    guard_fail=1
  fi
}
try_injection ne \
  'module Injected_ne
let f (a b: Rust_primitives.Integers.u64) : bool = Rust_primitives.Integers.ne a b' \
  'constant false'
try_injection mul_overflow \
  'module Injected_mul_overflow
let g (a b: Rust_primitives.Integers.u64) = Rust_primitives.Integers.mul_overflow a b' \
  'flag is wrong'
try_injection signed_div \
  'module Injected_signed_div
let h (a b: Rust_primitives.Integers.i64) : Rust_primitives.Integers.i64 = a /! b' \
  'disagree on signed division'
rm -rf "$selftest"
[[ $guard_fail -eq 0 ]]; rc_ok $? "guard self-test"

# --- shadow modules -------------------------------------------------------
# F* only extracts `.ml` for a module, and every abstract `val` has no code to
# run, so the harness derives executable `.fst` copies from the pinned files by
# selecting declaration blocks. make_shadow.py prints the manifest.
python3 make_shadow.py "$WORK/shadow" >"$WORK/logs/shadow.txt" 2>&1
rc_ok $? "shadow module derivation"
sed 's/^/shadow: /' "$WORK/logs/shadow.txt"
echo "shadow: $(ls "$WORK/shadow" | wc -l) modules, $(grep -c '^ADD' "$WORK/logs/shadow.txt") line(s) added to the pins"

# --- extraction -----------------------------------------------------------
# --lax: this harness runs the definitions, it does not re-prove them (the
# crate gates do). F* still typechecks every term; only SMT obligations are
# skipped, and the checked-arithmetic protocol evaluates the same `range`
# predicate at run time instead.
"$fstar" --lax --codegen OCaml --odir "$WORK/ml" \
  --already_cached '+Prims+FStar+LowStar+C+Spec.Loops+TestLib' \
  --warn_error -331 \
  --include "$WORK/shadow" --include "$here/fstar" \
  "$WORK"/shadow/*.fst "$here/fstar/T7_phase.fst" >"$WORK/logs/extract.txt" 2>&1
rc_ok $? "F* extraction (log: $WORK/logs/extract.txt)"
tail -n 3 "$WORK/logs/extract.txt" | sed 's/^/fstar: /'
test -f "$WORK/ml/Rust_primitives_Integers.ml"
rc_ok $? "extraction produced no OCaml"
test -f "$WORK/ml/T7_phase.ml"
rc_ok $? "the hand-written driver module was not extracted"
echo "extracted: $(ls "$WORK/ml"/*.ml | wc -l) modules"

# --- normalizer facts (no extraction) -------------------------------------
# F* integer division is Euclidean and Rust truncates, so the quotient differs
# on negative dividends.  The extracted OCaml truncates like Rust, so this can
# only be checked against the F* specification: without --lax, every assertion
# is a real proof obligation about `Prims` division.
"$fstar" --warn_error -331 --include "$here/semantics" \
  "$here/semantics/T7_semantics.fst" >"$WORK/logs/semantics.txt" 2>&1
rc_ok $? "F* normalizer facts (log: $WORK/logs/semantics.txt)"
echo "normalizer: $(grep -c '^let _ = assert' "$here/semantics/T7_semantics.fst") integer-division facts verified without --lax"

# --- build the model driver ----------------------------------------------
cp "$here/ocaml/driver.ml" "$WORK/ml/"
(
  cd "$WORK/ml"
  for f in $("$ocamldep" -sort *.ml); do
    "$ocamlfind" ocamlopt -package fstar.lib -c "$f" >>"$WORK/logs/ocaml.txt" 2>&1
    rc_ok $? "ocamlopt -c $f (log: $WORK/logs/ocaml.txt)"
  done
  "$ocamlfind" ocamlopt -package fstar.lib,zarith -linkpkg -o t7driver \
    $("$ocamldep" -sort *.ml) >>"$WORK/logs/ocaml.txt" 2>&1
  rc_ok $? "ocamlopt link (log: $WORK/logs/ocaml.txt)"
)
rc_ok $? "OCaml build of the model driver (log: $WORK/logs/ocaml.txt)"
echo "model driver: $WORK/ml/t7driver"

# --- build the Rust reference --------------------------------------------
cargo build --release --locked \
  --manifest-path rust/Cargo.toml --target-dir "$WORK/target" >"$WORK/logs/rust.txt" 2>&1
rc_ok $? "cargo build (log: $WORK/logs/rust.txt)"
rust="$WORK/target/release/std-model-diff"
test -x "$rust"; rc_ok $? "Rust reference binary missing"

# --- hash run: >= 10^6 cases per operation -------------------------------
echo
echo "== differential run: cases=$CASES seed=$DECSEED block=$BLOCK =="
"$rust" --seed "$DECSEED" --cases "$CASES" --block "$BLOCK" >"$WORK/rust.hash"
rc_ok $? "Rust reference run"
"$WORK/ml/t7driver" --seed "$DECSEED" --cases "$CASES" --block "$BLOCK" >"$WORK/model.hash"
rc_ok $? "model run"
python3 compare.py hash "$WORK/rust.hash" "$WORK/model.hash" >"$WORK/logs/hash.log" 2>&1
hash_rc=$?
cat "$WORK/logs/hash.log"

# --- documented-bug demonstrations ---------------------------------------
echo
echo "== documented hax-lib 0.3.7 bugs (ne, mul_overflow) =="
demo_cases=$(( CASES < 10000 ? CASES : 10000 ))
"$rust" --seed "$DECSEED" --cases "$demo_cases" --mode demo >"$WORK/rust.demo"
rc_ok $? "Rust demo run"
"$WORK/ml/t7driver" --seed "$DECSEED" --cases "$demo_cases" --mode demo >"$WORK/model.demo"
rc_ok $? "model demo run"
python3 compare.py demo "$WORK/rust.demo" "$WORK/model.demo" >"$WORK/logs/demo.log" 2>&1
demo_rc=$?
cat "$WORK/logs/demo.log"

# --- versions -------------------------------------------------------------
echo
echo "== versions =="
echo "fstar: $("$fstar" --version)"
echo "z3: $("$fstar_root/lib/fstar/z3-4.13.3/bin/z3" --version 2>/dev/null | head -1)"
"$ocamlfind" ocamlopt -version | sed 's/^/ocaml: /'
"$ocamlfind" list 2>/dev/null | grep -E '^(zarith|batteries|fstar\.lib) ' | sed 's/^/  /'
echo "rustc: $(rustc --version)"
echo "cargo: $(cargo --version)"
echo "hax-lib: 0.3.7 ($hax)"
echo "work: $WORK"

if [[ $hash_rc -ne 0 || $demo_rc -ne 0 ]]; then
  echo "RESULT: FAIL (hash=$hash_rc demo=$demo_rc)" >&2
  exit 1
fi
echo "RESULT: OK"
