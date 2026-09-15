#!/usr/bin/env bash
#
# The node's health check, which the node itself does not have.
#
# There is no /health on a Substrate node. What there is, is a handful of safe
# JSON-RPC calls that work under `--rpc-methods safe`, plus one TCP check.
# This runs them and prints one line per check, then exits non-zero if any
# failed. The on-box monitor calls it every minute; the runbook calls it once
# by hand after a deploy.
#
#   ./scripts/probe-node.sh                            # 127.0.0.1:9944
#   QNERO_RPC=http://127.0.0.1:9944 \
#   QNERO_STRATUM_PORT=3333 \
#   QNERO_MIN_PEERS=0 \
#   QNERO_MIN_HEIGHT=1 \
#   QNERO_GENESIS=0x... \
#   ./scripts/probe-node.sh
#
# Two failure shapes the generic checks miss, both checked here:
#
#  - **Authoring paused.** The node stops handing out the stratum template when
#    the tip is stale, when it has no peers, or during an initial sync. A rig
#    sees "Node is not authoring" and then EOF. From the box it reads as a
#    height that is not moving while peers is 0 or isSyncing is true, which is
#    why those are reported together rather than one at a time.
#  - **A node answering from an empty chain.** One that lost its database and
#    restarted from the spec answers every call happily: the genesis hash still
#    matches, the RPC is up, and both wallets are handed an empty tree. Only a
#    height floor catches it, which is what QNERO_MIN_HEIGHT is.
set -uo pipefail

rpc="${QNERO_RPC:-http://127.0.0.1:9944}"
stratum_host="${QNERO_STRATUM_HOST:-127.0.0.1}"
stratum_port="${QNERO_STRATUM_PORT:-3333}"
min_peers="${QNERO_MIN_PEERS:-0}"
min_height="${QNERO_MIN_HEIGHT:-1}"
expect_genesis="${QNERO_GENESIS:-}"
expect_target_ms="${QNERO_TARGET_BLOCK_TIME_MS:-120000}"
timeout_s="${QNERO_RPC_TIMEOUT:-6}"

failures=0

say() {
  printf '%-22s %s\n' "$1" "$2"
}

fail() {
  say "$1" "FAIL $2"
  failures=$((failures + 1))
}

call() {
  local method="$1" params="${2:-[]}"
  curl -s -m "$timeout_s" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$rpc"
}

jqr() {
  printf '%s' "$1" | jq -r "$2" 2>/dev/null
}

health="$(call system_health)"
peers="$(jqr "$health" '.result.peers')"
syncing="$(jqr "$health" '.result.isSyncing')"
if [ -z "$peers" ] || [ "$peers" = "null" ]; then
  fail "system_health" "the node did not answer at $rpc"
else
  say "peers" "$peers"
  say "isSyncing" "$syncing"
  if [ "$peers" -lt "$min_peers" ]; then
    fail "peers" "$peers is below the configured floor of $min_peers"
  fi
fi

header="$(call chain_getHeader)"
height_hex="$(jqr "$header" '.result.number')"
if [ -z "$height_hex" ] || [ "$height_hex" = "null" ]; then
  fail "chain_getHeader" "no header came back"
else
  height=$((height_hex))
  say "height" "$height"
  if [ "$height" -lt "$min_height" ]; then
    fail "height" "$height is below the floor of $min_height, which is what a node that \
resynced from the spec looks like"
  fi
fi

genesis="$(jqr "$(call chain_getBlockHash '[0]')" '.result')"
say "genesis" "${genesis:-none}"
if [ -n "$expect_genesis" ] && [ "$genesis" != "$expect_genesis" ]; then
  fail "genesis" "this node serves $genesis and the deployment expects $expect_genesis"
fi

# QPoWApi_get_target_block_time returns a SCALE u64, little endian. 120 000 ms
# is 0xc0d4010000000000. A chain whose spec set another target retargets
# against that other number, and every client that reads the interval, both
# wallets and the explorer, would be quoting it.
target_hex="$(jqr "$(call state_call '["QPoWApi_get_target_block_time","0x"]')" '.result')"
if [ -z "$target_hex" ] || [ "$target_hex" = "null" ]; then
  fail "target block time" "the runtime API did not answer"
else
  clean="${target_hex#0x}"
  target_ms=0
  for i in 7 6 5 4 3 2 1 0; do
    byte="${clean:$((i * 2)):2}"
    target_ms=$(((target_ms << 8) + 0x$byte))
  done
  say "target block time" "${target_ms} ms"
  if [ "$target_ms" != "$expect_target_ms" ]; then
    fail "target block time" "$target_ms ms, and this deployment expects $expect_target_ms"
  fi
fi

if command -v nc > /dev/null 2>&1; then
  if nc -z -w 3 "$stratum_host" "$stratum_port" > /dev/null 2>&1; then
    say "stratum" "$stratum_host:$stratum_port open"
  else
    fail "stratum" "$stratum_host:$stratum_port is not accepting connections"
  fi
else
  say "stratum" "skipped, nc is not installed"
fi

if [ "$failures" -gt 0 ]; then
  echo
  echo "$failures check(s) failed"
  exit 1
fi
echo
echo "all checks passed"
