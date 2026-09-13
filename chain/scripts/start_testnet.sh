#!/bin/bash

# Start a single Qnero node with a persistent base path and an open RPC port.
#
# USAGE:
#   ./start_testnet.sh
#
# The chain is `dev`, which is the only preset Qnero runs. This script used to
# pass `--chain planck`, an upstream network identity: the node built this
# tree's genesis, so upstream's peers refused it on genesis hash, and it
# published its name, version and height to a telemetry server run by somebody
# else. Point this at a Qnero testnet spec once Qnero has one.
#

rm -rf /tmp/validator1

./target/release/qnero-node \
  --base-path /tmp/validator1 \
  --chain dev \
  --port 30333 \
  --prometheus-port 9616 \
  --name QneroDevNode \
  --experimental-rpc-endpoint "listen-addr=127.0.0.1:9944,methods=unsafe,cors=all" \
  --node-key cffac33ca656d18f3ae94393d01fe03d6f9e8bf04106870f489acc028b214b15 \
  --validator
