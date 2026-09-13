#!/usr/bin/env bash
# Build the browser prover and stage everything the harness serves.
#
#   ./scripts/build-wasm.sh            build the module and generate artifacts
#   ./scripts/build-wasm.sh --no-artifacts   module only
#
# Nothing here is absolute: every path is derived from the script's own
# location, so the repository can live anywhere.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_dir="$(cd "${crate_dir}/../.." && pwd)"
out_dir="${crate_dir}/www/pkg"
artifact_dir="${crate_dir}/www/artifacts"
target=wasm32-unknown-unknown
package=qnero-prover-wasm

want_artifacts=1
[[ "${1:-}" == "--no-artifacts" ]] && want_artifacts=0

cd "${workspace_dir}"

if ! rustup target list --installed | grep -qx "${target}"; then
    echo "the ${target} target is not installed: rustup target add ${target}" >&2
    exit 1
fi

if ! command -v wasm-bindgen >/dev/null 2>&1; then
    cat >&2 <<'MSG'
wasm-bindgen is not on PATH. Install the CLI at the exact version the
wasm-bindgen crate resolves to (a mismatch is a hard refusal, not a subtle
bug):

    version=$(cargo tree -p qnero-prover-wasm -e normal \
        | sed -n 's/.*wasm-bindgen v\([0-9.]*\).*/\1/p' | head -1)
    cargo install wasm-bindgen-cli --version "${version}" -j 4
MSG
    exit 1
fi

# The threading guard. rayon-core spawns `std::thread`, which on this target
# without the atomics target feature fails at runtime, so its presence in the
# tree is a build failure rather than something to discover in a browser.
echo "checking the ${target} dependency tree for rayon"
# `cargo tree` takes no -j, and a pipeline whose left side fails inside an `if`
# would report a clean tree because grep found nothing in an empty stream. So
# the tree is captured first and its exit status is the gate.
tree="$(nice -n 19 cargo tree --target "${target}" -p "${package}" -e normal)"
# Match the crate name, not the substring: `plonky2_maybe_rayon` is always in
# the tree and takes its serial path. `rayon` and `rayon-core` are the ones that
# spawn threads.
if sed -E 's/^[^a-zA-Z]*//' <<<"${tree}" | awk '{print $1}' | grep -qxE 'rayon|rayon-core'; then
    echo "rayon is in the ${target} dependency tree: some crate turned on a parallel feature" >&2
    exit 1
fi

echo "building ${package} for ${target}"
nice -n 19 cargo build -j 2 --release -p "${package}" --target "${target}"

echo "running wasm-bindgen into ${out_dir#"${workspace_dir}"/}"
rm -rf "${out_dir}"
wasm-bindgen --target web --no-typescript \
    --out-dir "${out_dir}" \
    "target/${target}/release/qnero_prover_wasm.wasm"

if [[ "${want_artifacts}" == "1" ]]; then
    if [[ -f "${artifact_dir}/config.json" ]]; then
        echo "artifact set already present in ${artifact_dir#"${workspace_dir}"/}"
    else
        echo "generating the artifact set (leaf verifier, padding leaf proof, batch verifier)"
        nice -n 19 cargo run -j 2 --release -p qnero-circuit-builder -- \
            --output "${artifact_dir}" --no-public-batch --skip-padding-batch
    fi
fi

ls -l "${out_dir}"
