#!/usr/bin/env bash
# Stage the browser prover into this app's `public/` so Vite serves it as a
# plain asset.
#
#   ./scripts/stage-wasm.sh              the single-threaded module
#   ./scripts/stage-wasm.sh --threaded   that, plus the threaded one if it exists
#
# QNERO_WASM_PREBUILT=1 says the modules were built on another machine and
# copied in, which this script then holds to a stronger standard than a local
# build: both modules must be present, and every file the stage copies must
# match a SHA-256 manifest. See "the prebuilt gate" below.
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
manifest="${QNERO_WASM_SHA256:-${app_dir}/wasm-prebuilt.sha256}"

# The prebuilt gate.
#
# A module built here comes out of the crate this script reads, so what it
# exports and what is in it are both decided by the source tree. A module built
# elsewhere is a file somebody copied in, and the export check below says only
# that the names the crate declares appear in the generated glue: a module with
# every export and other bytes in it passes that, and the glue is text anybody
# can edit. So under this flag every file this script copies is pinned by
# digest against a manifest the operator brings, and a manifest that is
# missing, unreadable, incomplete or disagreeing refuses the stage.
#
# Every file, because the glue is what the seed goes through. `deriveAccount`
# takes the seed as a JS string and hands it to the module through
# `qnero_prover_wasm.js`, and the threaded package carries a `snippets/`
# directory whose worker entry point the pool starter fetches at run time. A
# gate that pinned the two `.wasm` files and let the JS beside them through
# pinned the part that is hard to edit and left the part that is easy.
#
# The manifest is `sha256sum` output with paths relative to the crate's `www/`
# directory. On the machine that built the modules:
#
#     cd crates/qnero-prover-wasm/www
#     find pkg pkg-threaded -type f -print0 | sort -z \
#         | xargs -0 sha256sum > wasm-prebuilt.sha256
#
# Point QNERO_WASM_SHA256 at it, or leave it at wallet-web/wasm-prebuilt.sha256.
# A manifest listing more than the stage copies is fine and is checked as well;
# a manifest missing one file the stage copies is refused by name.

# The paths, relative to `www/`, that this script copies into `public/wasm/`.
# The threaded tree is walked, because `cp -r` copies all of it, `snippets/`
# included.
staged_files() {
    printf '%s\n' pkg/qnero_prover_wasm.js pkg/qnero_prover_wasm_bg.wasm
    (cd "${crate_dir}/www" && find pkg-threaded -type f) | sed 's#^\./##'
}

# The paths a `sha256sum` manifest covers. A line is 64 hex characters, two
# separator characters (the second is `*` in binary mode), then the path.
manifest_files() {
    grep -E '^[0-9a-fA-F]{64}[ \t]' "${manifest}" | cut -c67- | sed 's#^\./##'
}

verify_manifest() {
    if [[ ! -r "${manifest}" ]]; then
        cat >&2 <<MSG
QNERO_WASM_PREBUILT=1 and no readable SHA-256 manifest at
${manifest}

The modules were built on another machine, so the only thing tying these bytes
to that build is their digest. Write the manifest on the machine that built
them and bring it with them:

    cd crates/qnero-prover-wasm/www
    find pkg pkg-threaded -type f -print0 | sort -z \\
        | xargs -0 sha256sum > wasm-prebuilt.sha256

then point QNERO_WASM_SHA256 at it. Nothing has been staged.
MSG
        exit 1
    fi
    local missing
    missing="$(comm -23 <(staged_files | sort -u) <(manifest_files | sort -u))"
    if [[ -n "${missing}" ]]; then
        {
            echo "${manifest} leaves out files this script copies:"
            echo
            while IFS= read -r path; do
                printf '    %s\n' "${path}"
            done <<<"${missing}"
            cat <<MSG

The glue carries the seed and the worker snippets start the thread pool, so a
manifest that pins the two modules and lets the JS beside them through pins the
half that is hard to edit. Write it over the whole tree on the machine that
built it:

    cd crates/qnero-prover-wasm/www
    find pkg pkg-threaded -type f -print0 | sort -z \\
        | xargs -0 sha256sum > wasm-prebuilt.sha256

Nothing has been staged.
MSG
        } >&2
        exit 1
    fi
    if ! (cd "${crate_dir}/www" && sha256sum --check --strict --quiet "${manifest}"); then
        cat >&2 <<MSG
a prebuilt prover file does not match ${manifest}. These are bytes this deploy
did not build and cannot check any other way, so the stage is refused. Nothing
has been staged.
MSG
        exit 1
    fi
    echo "every staged prover file matches ${manifest}"
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

check_exports "${crate_dir}/www/pkg/qnero_prover_wasm.js" single-threaded

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

mkdir -p "${out_dir}"
cp "${crate_dir}/www/pkg/qnero_prover_wasm.js" "${out_dir}/"
cp "${crate_dir}/www/pkg/qnero_prover_wasm_bg.wasm" "${out_dir}/"
echo "staged the single-threaded prover into public/wasm/"

if [[ "${want_threaded}" == "1" ]]; then
    threaded_pkg="${crate_dir}/www/pkg-threaded"
    if [[ -f "${threaded_pkg}/qnero_prover_wasm.js" ]]; then
        check_exports "${threaded_pkg}/qnero_prover_wasm.js" threaded
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
