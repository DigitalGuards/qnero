#!/usr/bin/env bash
#
# Generate the seed node's network identity and print the multiaddr other
# nodes dial it at.
#
#   ./scripts/generate-bootnode-key.sh /etc/qnero/node-key [host]
#
# Three things about this that break a copied Substrate runbook:
#
#  1. The key is Dilithium. This tree's `sc-cli` generates a litep2p dilithium
#     keypair and the on-disk file the node writes for itself is
#     `network/secret_dilithium`. Anything that says ed25519 is describing
#     upstream.
#  2. The peer id is printed on STDERR, so `> file` loses it. This script
#     captures both streams. `key inspect-node-key --file <path>` prints it
#     again from an existing key, which is how you recover it later.
#  3. A bootnode's identity must never rotate. Its peer id is published in
#     other people's spec files, so `--unsafe-force-node-key-generation` and
#     letting the node generate one into its base path are both wrong here:
#     a base-path wipe would silently change the address of the network's
#     entry point.
#
# The key goes on the host and never into the repository. Pass it to the node
# as `--node-key-file`, never as `--node-key <hex>`, which puts the secret in
# argv where every process listing can read it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
node="${QNERO_NODE:-$here/chain/target/release/qnero-node}"
key_file="${1:-}"
host="${2:-<host>}"
port="${QNERO_P2P_PORT:-30333}"
# `key generate-node-key` resolves a chain before it does anything, even with
# --file given and even though the id is then unused, and this tree refuses an
# empty --chain by naming its chains. So one has to be passed. Any of them
# would do; the testnet is passed because that is the network this key is for.
chain="${QNERO_CHAIN:-qnero-testnet}"

if [ -z "$key_file" ]; then
  echo "usage: $0 <key-file> [host]" >&2
  echo "  e.g. $0 /etc/qnero/node-key node.example" >&2
  exit 2
fi

if [ ! -x "$node" ]; then
  echo "$node is missing. Build it first, or set QNERO_NODE." >&2
  exit 1
fi

# The node's own diagnostics go here rather than into the command substitution
# that captures the peer id. Folding stderr into that capture is what makes a
# failure silent: the message becomes part of $peer_id, `set -e` aborts on the
# failing command before the assignment finishes, and the operator sees a
# script that exits 1 having printed nothing at all. Which is exactly what an
# unwritable /etc/qnero looks like, on the first command of a deployment.
diagnostics="$(mktemp "${TMPDIR:-/tmp}/qnero-nodekey.XXXXXX")"
trap 'rm -f "$diagnostics"' EXIT

fail() {
  echo "$1" >&2
  if [ -s "$diagnostics" ]; then
    echo "--- what the node said ---" >&2
    cat "$diagnostics" >&2
  fi
  exit 1
}

if [ -e "$key_file" ]; then
  echo "$key_file already exists, so this prints its peer id rather than" >&2
  echo "replacing it. A bootnode that rotates its identity is a bootnode" >&2
  echo "nobody can reach." >&2
  # `inspect-node-key` prints the peer id on STDOUT, and `generate-node-key`
  # prints it on STDERR. They really do differ, so each branch reads the
  # stream its own command writes.
  if ! peer_id="$("$node" key inspect-node-key --file "$key_file" 2>"$diagnostics")"; then
    fail "reading the peer id out of $key_file failed. A truncated or non-hex key reads like this."
  fi
  peer_id="$(printf '%s' "$peer_id" | tr -d '[:space:]')"
else
  umask 077
  mkdir -p "$(dirname "$key_file")" || fail "$(dirname "$key_file") could not be created. Root-owned? Run this under sudo."
  # The seed goes to the file and the peer id to stderr, so the seed is never
  # echoed and the peer id is read back out of the diagnostics.
  if ! "$node" key generate-node-key --chain "$chain" --file "$key_file" >/dev/null 2>"$diagnostics"; then
    fail "generating the node key failed and $key_file was not written."
  fi
  peer_id="$(grep -v '^[[:space:]]*$' "$diagnostics" | tail -1 | tr -d '[:space:]')"
  chmod 600 "$key_file"
  echo "wrote $key_file (mode 600, 64 hex characters of seed)"
fi

if [ -z "$peer_id" ]; then
  fail "the node printed no peer id. The key file is not trustworthy until one does."
fi

echo "peer id     $peer_id"
echo "multiaddr   /dns/$host/tcp/$port/p2p/$peer_id"
echo
cat <<MSG
Put that multiaddr in the "bootNodes" array of the raw chain spec. It sits
outside genesis, so adding it does not move the genesis hash and nothing has
to be regenerated:

  jq '.bootNodes = ["/dns/$host/tcp/$port/p2p/$peer_id"]' \\
     /etc/qnero/qnero-testnet.json > /tmp/spec.json \\
     && sudo install -m 0644 /tmp/spec.json /etc/qnero/qnero-testnet.json

Keep that hostname DNS-only at the CDN. p2p is raw TCP under a post-quantum
Noise handshake, so a proxied record blackholes it.
MSG
