#!/usr/bin/env bash
#
# Build qnero-node from the one path the committed chain spec is reproducible at.
#
# The runtime wasm is not reproducible across checkout locations. When
# `substrate-wasm-builder` compiles the runtime it writes a throwaway cargo
# project under `target/release/wbuild` whose manifest names every chain crate
# by absolute path, and cargo mixes a path dependency's absolute location into
# its `-C metadata` hash. Symbol hashes move with the checkout directory, the
# optimiser lays the module out differently, and the compressed `:code` in
# genesis, and with it the genesis hash, changes with the directory the build
# ran in. `--remap-path-prefix` in chain/runtime/build.rs keeps paths out of the
# bytes and has no effect on that hash.
#
# So the spec is built at a fixed path, the way srtool builds Polkadot runtimes
# at `/build`: a detached git worktree of HEAD at QNERO_CANONICAL_DIR. The same
# committed tree built there on any Linux machine with the pinned toolchain
# exports the same genesis. CI builds there, `scripts/build-testnet-spec.sh`
# exports from the binary built there, and `chain/node/tests/testnet_spec.rs`
# refuses to compare the committed spec from anywhere else.
#
#   ./scripts/build-canonical-node.sh             # refresh the worktree to HEAD and build
#   ./scripts/build-canonical-node.sh --no-build  # refresh the worktree only (CI restores
#                                                 # its cache into it before building)
#
# The worktree holds HEAD. Uncommitted edits in this checkout are not in it, so
# commit before building a spec that is meant to be committed.

set -euo pipefail

canonical="/tmp/qnero-spec-build"
if [ "${QNERO_CANONICAL_DIR:-$canonical}" != "$canonical" ]; then
  echo "QNERO_CANONICAL_DIR is fixed at $canonical: the path is part of what is reproduced." >&2
  exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
head="$(git -C "$here" rev-parse HEAD)"

if ! git -C "$here" diff --quiet HEAD -- chain crates; then
  echo "note: this checkout has uncommitted changes under chain/ or crates/; the" >&2
  echo "      canonical build uses HEAD ($head) and does not include them." >&2
fi

if [ -e "$canonical/.git" ]; then
  git -C "$canonical" checkout --quiet --detach "$head"
elif [ -e "$canonical" ] && [ -n "$(ls -A "$canonical")" ]; then
  echo "$canonical exists and is not a worktree of this repository; move it aside." >&2
  exit 1
else
  git -C "$here" worktree add --quiet --detach "$canonical" "$head"
fi
echo "canonical worktree at $canonical, HEAD $head"

if [ "${1:-}" = "--no-build" ]; then
  exit 0
fi

cd "$canonical/chain"
nice -n 19 cargo build --locked --release -p qnero-node
echo "built $canonical/chain/target/release/qnero-node"
