#!/usr/bin/env bash
# Stage the browser prover into this app's `public/` so Vite serves it as a
# plain asset.
#
#   ./scripts/stage-wasm.sh              the single-threaded module
#   ./scripts/stage-wasm.sh --threaded   that, plus the threaded one if it exists
#
# QNERO_WASM_PREBUILT=1 says the modules were built on another machine and
# copied in. Both packages must be present and authenticated by an ML-DSA-87
# release manifest, a separately trusted public key and an expected revision.
# Copies come from the verifier's authenticated snapshot.
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

prebuilt="${QNERO_WASM_PREBUILT:-0}"
if [[ "${prebuilt}" != "0" && "${prebuilt}" != "1" ]]; then
    echo "QNERO_WASM_PREBUILT must be 0 or 1. Nothing has been staged." >&2
    exit 1
fi
source_dir="${crate_dir}/www"
verified_parent=""

cleanup_verified() {
    if [[ -n "${verified_parent}" ]]; then
        rm -rf -- "${verified_parent}"
    fi
}
trap cleanup_verified EXIT

verify_manifest() {
    local verifier="${QNERO_RELEASE_VERIFIER:-${repo_dir}/target/release/qnero-release}"
    local manifest="${QNERO_RELEASE_MANIFEST:-${source_dir}/wasm-prebuilt.release.json}"
    local signature="${QNERO_RELEASE_SIGNATURE:-${manifest}.sig}"
    local public_key="${QNERO_RELEASE_PUBLIC_KEY:-}"
    local revision="${QNERO_RELEASE_REVISION:-}"
    if [[ -z "${public_key}" || ! -r "${public_key}" || ! -x "${verifier}" ]]; then
        cat >&2 <<MSG
prebuilt prover packages require qnero-release and a separately trusted public
release key. Build the verifier with cargo build --locked --release -p
qnero-release and set QNERO_RELEASE_PUBLIC_KEY to your trusted key file.
See docs/RELEASE-AUTH.md. Nothing has been staged.
MSG
        exit 1
    fi
    if [[ -z "${revision}" ]]; then
        revision="$(git -C "${repo_dir}" rev-parse HEAD)" || exit 1
    fi
    verified_parent="$(mktemp -d)"
    if ! "${verifier}" verify --root "${source_dir}" --public-key "${public_key}" \
        --revision "${revision}" --manifest "${manifest}" --signature "${signature}" \
        --require-path pkg --require-path pkg-threaded \
        --output-dir "${verified_parent}/bundle"; then
        echo "prebuilt release authentication failed. Nothing has been staged." >&2
        exit 1
    fi
    source_dir="${verified_parent}/bundle"
}

if [[ ! -f "${crate_dir}/www/pkg/qnero_prover_wasm.js" ]]; then
    echo "the prover has not been built: run ${crate_dir#"${repo_dir}"/}/scripts/build-wasm.sh" >&2
    exit 1
fi

# The built module has to be as new as the crate's surface, or the bundle
# ships calling exports that are not there. That happened on 2026-09-17: the
# crate gained `readStateProof`, the deploy staged a module built three days
# earlier, and every wallet screen that read state died with "readStateProof
# is not a function". Nothing in the build catches it, because the module is
# fetched at runtime and never typed against. So it is checked here: every
# top-level `js_name` the crate declares must appear in the generated glue.
check_exports() {
    local glue="$1" label="$2" missing=""
    local name
    while read -r name; do
        if ! grep -qw "${name}" "${glue}"; then
            missing="${missing} ${name}"
        fi
    done < <(grep -oE '^#\[wasm_bindgen\(js_name = [A-Za-z0-9_]+' "${crate_dir}/src/lib.rs" \
        | sed 's/.*= //' | sort -u)
    if [[ -n "${missing}" ]]; then
        cat >&2 <<MSG
the ${label} prover is stale: the crate exports${missing} and the built module
does not. Rebuild it before staging:

    ${crate_dir#"${repo_dir}"/}/scripts/build-wasm.sh
    ${crate_dir#"${repo_dir}"/}/scripts/build-threaded-wasm.sh
MSG
        exit 1
    fi
}

if [[ "${prebuilt}" == "1" ]]; then
    if [[ ! -f "${crate_dir}/www/pkg-threaded/qnero_prover_wasm.js" ]]; then
        cat >&2 <<MSG
QNERO_WASM_PREBUILT=1 and no threaded module at
${crate_dir}/www/pkg-threaded

Under this flag the modules are copied in and neither is built, so a missing
threaded package is a copy that did not finish, and staging it as a
single-threaded deploy would silently ship a wallet proving a payment in 37.6 s
where it takes 11.2 s. Copy it in, or build here without the flag. Nothing has
been staged.
MSG
        exit 1
    fi
    if [[ "${want_threaded}" != "1" ]]; then
        echo "QNERO_WASM_PREBUILT=1 needs --threaded: both modules are staged or neither" >&2
        exit 1
    fi
    verify_manifest
fi

# Validate both export surfaces before changing public/wasm/. Prebuilt checks
# read the verified snapshot, which is also the source of every later copy.
check_exports "${source_dir}/pkg/qnero_prover_wasm.js" single-threaded
if [[ ! -f "${source_dir}/pkg/qnero_prover_wasm_bg.wasm" ]]; then
    echo "the single-threaded prover wasm is missing. Nothing has been staged." >&2
    exit 1
fi
if [[ "${want_threaded}" == "1" && -f "${source_dir}/pkg-threaded/qnero_prover_wasm.js" ]]; then
    check_exports "${source_dir}/pkg-threaded/qnero_prover_wasm.js" threaded
    if [[ ! -f "${source_dir}/pkg-threaded/qnero_prover_wasm_bg.wasm" ]]; then
        echo "the threaded prover wasm is missing. Nothing has been staged." >&2
        exit 1
    fi
fi

mkdir -p "${out_dir}"
cp "${source_dir}/pkg/qnero_prover_wasm.js" "${out_dir}/"
cp "${source_dir}/pkg/qnero_prover_wasm_bg.wasm" "${out_dir}/"
echo "staged the single-threaded prover into public/wasm/"

if [[ "${want_threaded}" == "1" ]]; then
    threaded_pkg="${source_dir}/pkg-threaded"
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
