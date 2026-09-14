#!/usr/bin/env bash
# Build the THREADED browser prover.
#
#   ./scripts/build-threaded-wasm.sh
#
# This is not a flag flip on `build-wasm.sh`. Four things have to line up and
# each of them fails differently:
#
#   1. `+atomics,+bulk-memory,+mutable-globals`. Without them there is no
#      shared memory and no atomic primitives, and rayon-core's `std::thread`
#      traps at runtime rather than failing to compile.
#   2. A `std` rebuilt with those features. The shipped `wasm32-unknown-unknown`
#      std is compiled without them, so `-Z build-std=std,panic_abort` on a
#      nightly toolchain with `rust-src` is mandatory. This is the reason the
#      threaded module needs nightly and the default one does not.
#   3. `--shared-memory --import-memory` through the linker, so the module
#      imports a `SharedArrayBuffer`-backed memory instead of defining a
#      private one. `--max-memory` has to be stated: a shared memory must
#      declare a maximum, and every worker reserves it.
#   3b. The four TLS symbols, exported by name. This is the one that is not in
#      any published recipe and it cost an afternoon: wasm-bindgen's threading
#      transform reads `__wasm_init_tls`, `__tls_size`, `__tls_align` and
#      `__tls_base` out of the module's *exports*, and current wasm-ld creates
#      all four and exports none of them. The failure is
#      `failed to prepare module for threading / failed to find
#      __wasm_init_tls`, which reads as "your build has no thread-local
#      storage" when the truth is that it has it and did not publish it. The
#      symbols appear one at a time as each is exported, so the error names
#      only the first one missing.
#   4. The serving origin has to be cross-origin isolated (COOP `same-origin`
#      plus COEP `require-corp`) or `SharedArrayBuffer` does not exist in the
#      page at all. `wallet-web/vite.config.ts` sends those headers for the dev
#      server and the preview; a production host has to send them itself.
#
# `RUSTFLAGS` replaces `.cargo/config.toml`'s `[target.wasm32-unknown-unknown]`
# rustflags wholesale rather than adding to them, so the two flags that file
# sets are repeated here. Dropping either is silent: without the getrandom cfg
# the build stops at a `compile_error!`, and without the stack size plonky2
# overflows the 1 MiB default as a trap shaped like memory corruption.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_dir="$(cd "${crate_dir}/../.." && pwd)"
out_dir="${crate_dir}/www/pkg-threaded"
target=wasm32-unknown-unknown
package=qnero-prover-wasm
toolchain="${QNERO_NIGHTLY:-nightly}"

# 8 MiB of stack, and a 4 GiB ceiling on the memory. The single-threaded module
# measured a 910.4 MiB peak at N = 6 and 1765.4 MiB at N = 7, so the maximum is
# set above both: a shared memory cannot grow past its declared maximum, and
# hitting it is an allocation failure inside a proof.
stack_bytes=8388608
max_memory=4294967296

cd "${workspace_dir}"

if ! rustup toolchain list | grep -q "^${toolchain}"; then
    echo "the ${toolchain} toolchain is not installed: rustup toolchain install ${toolchain}" >&2
    exit 1
fi
if ! rustup component list --toolchain "${toolchain}" --installed | grep -qx "rust-src"; then
    echo "rust-src is not installed on ${toolchain}: rustup component add rust-src --toolchain ${toolchain}" >&2
    exit 1
fi
if ! command -v wasm-bindgen >/dev/null 2>&1; then
    echo "wasm-bindgen is not on PATH; see scripts/build-wasm.sh for the install line" >&2
    exit 1
fi

echo "building ${package} for ${target} with atomics, on ${toolchain}"
RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals \
    -C link-arg=--shared-memory \
    -C link-arg=--import-memory \
    -C link-arg=--max-memory=${max_memory} \
    -C link-arg=-zstack-size=${stack_bytes} \
    -C link-arg=--export=__wasm_init_tls \
    -C link-arg=--export=__tls_size \
    -C link-arg=--export=__tls_align \
    -C link-arg=--export=__tls_base \
    --cfg getrandom_backend=\"wasm_js\"" \
    nice -n 19 cargo "+${toolchain}" build -j 2 --release \
        -Z build-std=std,panic_abort \
        --target "${target}" \
        -p "${package}" \
        --features threads


# `wasm-opt -O`, when binaryen is installed.
#
# It is a real saving and it is not the same saving on both modules: the
# single-threaded one loses about 18% of its raw bytes and 3% of its
# compressed bytes, and the threaded one loses about 49% raw and 10%
# compressed, because `-Z build-std` emits a std that has never been through
# an optimiser. `docs/BENCH.md` carries the measured numbers.
#
# Optional, because it is a size pass rather than a correctness one and a
# clone without binaryen should still produce a working module. The acceptance
# gate is what proves the optimised module still proves:
#   QNERO_WASM_PROOF=<...>.proof QNERO_ARTIFACT_DIR=www/artifacts \
#     cargo test -p qnero-prover-wasm --release --test wasm_proof -- --ignored
run_wasm_opt() {
    local module="$1"
    shift
    if ! command -v wasm-opt >/dev/null 2>&1; then
        echo "wasm-opt is not on PATH, so the module ships unoptimised (install binaryen)"
        return
    fi
    local before
    before="$(stat -c%s "${module}")"
    nice -n 19 wasm-opt -O "$@" "${module}" -o "${module}.opt"
    mv "${module}.opt" "${module}"
    local after
    after="$(stat -c%s "${module}")"
    echo "wasm-opt -O: ${before} -> ${after} bytes"
}

echo "running wasm-bindgen into ${out_dir#"${workspace_dir}"/}"
rm -rf "${out_dir}"
wasm-bindgen --target web --no-typescript \
    --out-dir "${out_dir}" \
    "target/${target}/release/qnero_prover_wasm.wasm"

# The three features the module was built with have to be named, or the
# optimiser refuses a module it considers invalid.
run_wasm_opt "${out_dir}/qnero_prover_wasm_bg.wasm" \
    --enable-threads --enable-bulk-memory --enable-mutable-globals

# wasm-bindgen-rayon's worker helper imports its own package as a DIRECTORY
# (`import('../../..')`), which only resolves under a bundler that knows the
# package's entry point. This module is loaded by URL with no bundler, so the
# browser asks for `.../threaded/` and gets whatever a static host says about a
# directory, which is a 404 here. The failure is a page that loads the threaded
# module, starts its pool, and then stalls with every spawned worker dead.
#
# The fix is to name the file the directory stood for. It is a generated file
# and the substitution is exact, so a version of wasm-bindgen-rayon that stops
# emitting this line makes the loop below a no-op rather than a wrong edit.
for helper in "${out_dir}"/snippets/wasm-bindgen-rayon-*/src/workerHelpers.js; do
    [[ -f "${helper}" ]] || continue
    sed -i "s|await import('../../..')|await import('../../../qnero_prover_wasm.js')|" "${helper}"
    echo "pointed $(basename "${helper}") at the module file rather than its directory"
done

ls -l "${out_dir}"
