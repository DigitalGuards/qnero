#!/usr/bin/env bash
# Stage the browser prover into this app's `public/` so Vite serves it as a
# plain asset.
#
#   ./scripts/stage-wasm.sh              the single-threaded module
#   ./scripts/stage-wasm.sh --threaded   that, plus the threaded one if it exists
#
# The module is not imported by the bundle. It is three megabytes of wasm with
# a generated ES-module wrapper, and the worker fetches it at runtime from
# `config.json`'s `wasmBase`, so the same build serves either module and Vite
# never parses any of it.
#
# Nothing here is absolute: every path derives from this script's location.
set -euo pipefail

app_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd "${app_dir}/.." && pwd)"
crate_dir="${repo_dir}/crates/qnero-prover-wasm"
out_dir="${app_dir}/public/wasm"

want_threaded=0
[[ "${1:-}" == "--threaded" ]] && want_threaded=1

if [[ ! -f "${crate_dir}/www/pkg/qnero_prover_wasm.js" ]]; then
    echo "the prover has not been built: run ${crate_dir#"${repo_dir}"/}/scripts/build-wasm.sh" >&2
    exit 1
fi

mkdir -p "${out_dir}"
cp "${crate_dir}/www/pkg/qnero_prover_wasm.js" "${out_dir}/"
cp "${crate_dir}/www/pkg/qnero_prover_wasm_bg.wasm" "${out_dir}/"
echo "staged the single-threaded prover into public/wasm/"

if [[ "${want_threaded}" == "1" ]]; then
    threaded_pkg="${crate_dir}/www/pkg-threaded"
    if [[ -f "${threaded_pkg}/qnero_prover_wasm.js" ]]; then
        rm -rf "${out_dir}/threaded"
        mkdir -p "${out_dir}/threaded"
        # Recursive: wasm-bindgen-rayon emits a `snippets/` directory beside
        # the module holding the worker entry point, and `initThreadPool`
        # resolves it relative to the module's own URL. Copying only the two
        # top-level files leaves a module whose pool starter 404s.
        cp -r "${threaded_pkg}"/. "${out_dir}/threaded/"
        echo "staged the threaded prover into public/wasm/threaded/"
    else
        echo "no threaded build at ${threaded_pkg#"${repo_dir}"/}: the app will use the single-threaded module"
    fi
fi

ls -l "${out_dir}"
