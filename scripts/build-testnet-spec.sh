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
# `bootNodes` is the one field a deployment writes into the file after it is
# generated. It sits outside genesis, so it does not move the genesis hash, and
# a peer id is public. It is fed through here rather than edited in afterwards,
# because a regeneration that silently dropped the launched network's entry
# point is the failure this script exists to prevent:
#
#   QNERO_BOOTNODES=/dns/node.<domain>/tcp/30333/p2p/<peer id> \
#     ./scripts/build-testnet-spec.sh
#
# With the variable unset, whatever the committed file already carries is
# preserved, so an ordinary re-export after a preset edit keeps the bootnode.
# Pass `QNERO_BOOTNODES=` explicitly, as an empty value, to clear the list.
#
# `--disable-default-bootnode` is not optional. Without it, a spec that names
# no bootnode gets a throwaway /ip4/127.0.0.1 one injected
# (chain/docs/CHAINSPEC_CREATION.md), which would then be in the file every
# operator is handed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The binary built at the canonical path. A node built in any other directory
# carries a different runtime wasm; scripts/build-canonical-node.sh says why.
node="/tmp/qnero-spec-build/chain/target/release/qnero-node"
out="$here/chain/node/chain-specs/qnero-testnet.json"

check=0
if [ "${1:-}" = "--check" ]; then
  check=1
fi

if [ ! -x "$node" ]; then
  cat >&2 <<MSG
$node is missing.

The node is built on a workstation and copied to the host, never built there,
and the spec is exported from the build at the canonical path, so this script
does not build it for you:

  LIBCLANG_PATH=/usr/lib/llvm-18/lib ./scripts/build-canonical-node.sh

Do not build it with SKIP_WASM_BUILD set. That produces a binary with a stub
runtime wasm, and every genesis it exports is that stub's.
MSG
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# One step. The two-step form in chain/docs/CHAINSPEC_CREATION.md exists so the
# plain spec can be edited before it is rawified; nothing here edits it, because
# the one field a deployment fills in, `bootNodes`, sits outside genesis and is
# edited in the raw file directly.
"$node" build-spec --chain qnero-testnet --raw --disable-default-bootnode > "$tmp"

# The bootnode list, either the one given or the one already committed.
#
# `${VAR+set}` rather than `${VAR:-}`: an empty QNERO_BOOTNODES is how a list is
# deliberately cleared, and it has to be distinguishable from the variable not
# being there at all, which is how a list is preserved.
if [ -n "${QNERO_BOOTNODES+set}" ]; then
  bootnodes="$QNERO_BOOTNODES"
elif [ -f "$out" ]; then
  bootnodes="$(jq -r '(.bootNodes // []) | join(",")' "$out")"
else
  bootnodes=""
fi

if [ -n "$bootnodes" ]; then
  # The same shape chain/node/tests/testnet_spec.rs asserts, checked here so a
  # typo fails at the machine that made it rather than in CI. A bare hostname,
  # a missing /p2p segment or an apex name each produce a spec whose bootnode
  # nobody can dial, and the symptom turns up days later on somebody else's
  # machine.
  old_ifs="$IFS"
  IFS=,
  for address in $bootnodes; do
    case "$address" in
      /dns/*/tcp/*/p2p/*|/dns4/*/tcp/*/p2p/*|/dns6/*/tcp/*/p2p/*|/ip4/*/tcp/*/p2p/*) ;;
      *)
        IFS="$old_ifs"
        echo "$address is not a /dns/<host>/tcp/<port>/p2p/<peer id> multiaddr." >&2
        echo "Nothing was written. Read the peer id off the seed node's key with" >&2
        echo "  qnero-node key inspect-node-key --file /etc/qnero/node-key" >&2
        exit 1
        ;;
    esac
  done
  IFS="$old_ifs"

  # jq rather than a text edit, and the whole file through jq rather than only
  # when a list is present: the committed bytes have to be reproducible, and
  # `--check` below compares them. A file written by jq and re-exported without
  # it differs everywhere, so the two paths have to agree. With no bootnode the
  # node's own output is committed untouched, which is what keeps the byte
  # comparison in chain/node/tests/testnet_spec.rs live for an empty list.
  boot_json="$(printf '%s' "$bootnodes" | jq -R 'split(",")')"
  jq --argjson list "$boot_json" '.bootNodes = $list' "$tmp" > "$tmp.boot"
  mv "$tmp.boot" "$tmp"
fi

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
if [ -n "$bootnodes" ]; then
  echo "bootNodes carries:"
  printf '%s\n' "$bootnodes" | tr ',' '\n' | sed 's/^/  /'
  echo
  echo "That list is outside genesis, so it did not move the genesis hash."
else
  echo "bootNodes is empty. Pass QNERO_BOOTNODES once the seed node's key"
  echo "exists; see docs/TESTNET.md."
fi
