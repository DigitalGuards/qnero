#!/usr/bin/env bash
#
# Regenerate the committed raw chain spec for the Qnero public testnet.
#
# The spec is generated, never hand-edited. Its genesis is the `qnero-testnet`
# runtime preset compiled into the node binary, and `.genesis.raw.top` carries
# the whole compressed runtime wasm, so the file is megabytes and is
# reproducible exactly as far as the binary that produced it is. That is the
# point: `chain/node/tests/testnet_spec.rs` regenerates it and compares the
# bytes, so a preset edit that was never re-exported fails a test rather than
# shipping a spec whose genesis nobody can rebuild.
#
#   ./scripts/build-testnet-spec.sh          # write the committed spec
#   ./scripts/build-testnet-spec.sh --check  # regenerate to a temporary file
#                                            # and diff, changing nothing
#
# `--disable-default-bootnode` is not optional. Without it, a spec that names
# no bootnode gets a throwaway /ip4/127.0.0.1 one injected
# (chain/docs/CHAINSPEC_CREATION.md), which would then be in the file every
# operator is handed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
node="$here/chain/target/release/qnero-node"
out="$here/chain/node/chain-specs/qnero-testnet.json"

check=0
if [ "${1:-}" = "--check" ]; then
  check=1
fi

if [ ! -x "$node" ]; then
  cat >&2 <<MSG
$node is missing.

The node is built on a workstation and copied to the host, never built there,
so this script does not build it for you:

  cd chain
  LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node

Do not build it with SKIP_WASM_BUILD set. That produces a binary with a stub
runtime wasm, and every genesis it exports is that stub's.
MSG
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# One step, not two. The two-step form in chain/docs/CHAINSPEC_CREATION.md
# exists so the plain spec can be edited before it is rawified; nothing here
# edits it, because the one field a deployment fills in, `bootNodes`, sits
# outside genesis and is edited in the raw file directly.
"$node" build-spec --chain qnero-testnet --raw --disable-default-bootnode > "$tmp"

if [ "$check" = "1" ]; then
  if diff -q "$out" "$tmp" > /dev/null 2>&1; then
    echo "the committed spec matches what this binary exports"
    exit 0
  fi
  echo "the committed spec does NOT match what this binary exports:" >&2
  # The file is megabytes of hex, so report the shape of the difference
  # rather than the difference itself.
  echo "  committed: $(wc -c < "$out") bytes" >&2
  echo "  exported:  $(wc -c < "$tmp") bytes" >&2
  exit 1
fi

mkdir -p "$(dirname "$out")"
mv "$tmp" "$out"
# mktemp creates 0600 and mv keeps it. This file is a public artifact every
# operator is handed, so it is 0644 like the rest of the tree.
chmod 644 "$out"
trap - EXIT

echo "wrote $out ($(wc -c < "$out") bytes)"
echo
echo "The genesis hash this spec produces:"
echo "  $node --chain $out --tmp 2>&1 | grep 'Genesis'"
echo
echo "bootNodes is empty and stays empty here. The seed node's peer id is"
echo "written into the copy installed on the host; see docs/TESTNET.md."
