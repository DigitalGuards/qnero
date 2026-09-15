#!/usr/bin/env bash
#
# Build the testnet artifacts here and copy them to the host.
#
#   QNERO_HOST=<user>@<host> QNERO_DOMAIN=<domain> ./scripts/deploy-testnet.sh [stage...]
#
# Stages, in the order they run when none is named:
#
#   node      build qnero-node and qnero-faucet, copy both, restart the units
#   spec      copy the committed raw chain spec (does NOT restart anything)
#   site      build nothing, rsync site/
#   wallet    build Qloak against wss://rpc.<domain>, rsync wallet-web/dist/
#   explorer  build silQ Road, rsync explorer/dist/
#   config    write the two runtime config.json files
#
# **Nothing is built on the host.** The build wants cmake and a C++17 compiler
# for randomx-rs, libclang for the rocksdb bindings, and a pallet build script
# that generates the circuit artifact set before the pallet compiles; on a
# 2 vCPU, 8 GB box that is hours or an out-of-memory kill. The host runs the
# same glibc as this workstation, which is the whole reason a container is not
# needed.
#
# This script copies. It does not install units, write nginx configuration,
# open ports, generate keys or fund anything: those are one-time steps and they
# are in docs/TESTNET.md where they can be read before they are run.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
host="${QNERO_HOST:-}"
domain="${QNERO_DOMAIN:-}"
jobs="${QNERO_JOBS:-4}"

if [ -z "$host" ] || [ -z "$domain" ]; then
  echo "usage: QNERO_HOST=user@host QNERO_DOMAIN=example.invalid $0 [stage...]" >&2
  exit 2
fi

rpc_endpoint="wss://rpc.$domain"
stages=("$@")
if [ ${#stages[@]} -eq 0 ]; then
  stages=(node spec site wallet explorer config)
fi

has_stage() {
  local wanted="$1"
  for stage in "${stages[@]}"; do
    [ "$stage" = "$wanted" ] && return 0
  done
  return 1
}

step() {
  printf '\n=== %s ===\n' "$1"
}

# Copy a built directory into a root-owned webroot.
#
# The webroots are created by the runbook's nginx step and are owned by root,
# so the deploy account cannot write into them and a plain `rsync` to
# `$host:/var/www/...` fails with permission denied on every file: binaries and
# spec installed, every static asset rejected, nginx serving empty roots. The
# fix is to stage into a directory of the deploy account's own and let one
# sudo'd rsync do the replace, rather than chowning three webroots to the
# deploy account and handing whoever holds it write access to everything nginx
# serves.
#
# Two details make that true rather than merely intended:
#
#  - **--chown=root:root on the second hop.** `-a` implies `-o -g`, and running under sudo
#    they take effect, so without this the replace writes every file, and the webroot
#    itself, owned by the deploy account. Which is the thing this function is shaped to
#    avoid: anything running as that account could then rewrite the wallet's JavaScript
#    with no sudo at all, on the one host where a page handles seeds.
#  - **The stage is an mktemp -d.** A fixed `/tmp/qnero-deploy/var/www/...` is
#    predictable and /tmp is world-writable, so another local account could create the
#    path first, keep it writable, and have the sudo'd hop copy its contents into a
#    webroot as root.
#
# Any extra arguments are excludes, and they are applied to BOTH hops: the
# second rsync also carries --delete, so an exclude the first hop honoured and
# the second did not would delete the very file it was protecting.
deploy_tree() {
  local source="$1" webroot="$2"
  shift 2
  local stage
  stage="$(ssh "$host" 'mktemp -d')"
  if [ -z "$stage" ]; then
    echo "the host would not make a staging directory" >&2
    exit 1
  fi
  local extra=""
  local argument
  for argument in "$@"; do
    extra="$extra $(printf '%q' "$argument")"
  done
  rsync -a --delete "$@" "$source" "$host:$stage/"
  ssh "$host" "sudo rsync -a --delete --chown=root:root$extra $(printf '%q' "$stage/") \
    $(printf '%q' "$webroot/") && rm -rf $(printf '%q' "$stage")"
}

if has_stage node; then
  step "building qnero-node"
  (
    cd "$here/chain"
    # Never with SKIP_WASM_BUILD set: that produces a binary whose runtime wasm
    # is a stub, and every genesis it exports and every block it executes is
    # that stub's.
    LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-18/lib}" \
      nice -n 19 cargo build -j "$jobs" --release -p qnero-node
  )

  step "building qnero-faucet"
  (
    cd "$here"
    nice -n 19 cargo build -j 2 --release -p qnero-faucet
  )

  step "copying the binaries"
  scp "$here/chain/target/release/qnero-node" "$host:/tmp/qnero-node"
  scp "$here/target/release/qnero-faucet" "$host:/tmp/qnero-faucet"
  # The binary that is about to be replaced is kept as `.previous`, here,
  # because this is the only moment it still exists. Rolling a bad node back
  # otherwise means rebuilding a release binary on the workstation, which is
  # the wrong thing to be doing while the chain is stopped. It is taken
  # automatically rather than asked of the operator as a pre-step, since a
  # rollback that depends on somebody having remembered is not a rollback.
  #
  # `install` rather than `cp` for the new one: the mode is set in the same
  # operation and the replace is atomic, so a running node is never reading a
  # half-written file.
  ssh "$host" 'for binary in qnero-node qnero-faucet; do \
      if sudo test -x "/usr/local/bin/$binary"; then \
        sudo cp -a "/usr/local/bin/$binary" "/usr/local/bin/$binary.previous"; \
        echo "kept /usr/local/bin/$binary.previous"; \
      fi; \
    done \
    && sudo install -m 0755 /tmp/qnero-node /usr/local/bin/qnero-node \
    && sudo install -m 0755 /tmp/qnero-faucet /usr/local/bin/qnero-faucet \
    && rm -f /tmp/qnero-node /tmp/qnero-faucet \
    && sudo systemctl restart qnero-node \
    && sleep 5 \
    && sudo systemctl restart qnero-faucet \
    && systemctl is-active qnero-node qnero-faucet'
fi

if has_stage spec; then
  step "copying the chain spec"
  echo "The spec is copied and NOTHING is restarted. A node already running on"
  echo "this genesis does not need it, and a node restarted onto a different"
  echo "genesis resyncs from block zero. Restart deliberately."
  scp "$here/chain/node/chain-specs/qnero-testnet.json" "$host:/tmp/qnero-testnet.json"
  ssh "$host" 'sudo install -m 0644 -o root -g root /tmp/qnero-testnet.json \
    /etc/qnero/qnero-testnet.json && rm -f /tmp/qnero-testnet.json'
  cat <<MSG

The committed spec carries an empty "bootNodes", so the installed copy has just
lost its entry. Put it back ON THE HOST. This reads the peer id out of the key
that is already there; it does not generate anything, and it must not, because
a bootnode that rotates its identity is one nobody can reach:

  ssh $host
  PEER_ID=\$(qnero-node key inspect-node-key --file /etc/qnero/node-key)
  spec=\$(mktemp)
  jq --arg addr "/dns/node.$domain/tcp/30333/p2p/\$PEER_ID" '.bootNodes = [\$addr]' \\
     /etc/qnero/qnero-testnet.json > "\$spec" \\
     && sudo install -m 0644 -o root -g root "\$spec" /etc/qnero/qnero-testnet.json
  rm -f "\$spec"

The hostname is node.$domain and not $domain: p2p is raw TCP under a
post-quantum Noise handshake, and the apex is proxied by the CDN, which
blackholes it.
MSG
fi

if has_stage site; then
  step "deploying the site"
  # --delete is what stops a removed page lingering. The excludes are the
  # site's own build tools and its two repository-facing files.
  deploy_tree "$here/site/" "/var/www/$domain" \
    --exclude tools/ --exclude README.md --exclude NOTICE
fi

if has_stage wallet; then
  step "building Qloak against $rpc_endpoint"
  (
    cd "$here/wallet-web"
    nice -n 19 npm ci
    ./scripts/stage-wasm.sh --threaded
    # Pinning the endpoint at build time narrows the bundle's own
    # content-security-policy from `connect-src 'self' ws: wss:` to this one
    # origin. The wide form permits a WebSocket to any host, which is the
    # residual exfiltration path wallet-web/README.md names. The trade is that
    # repointing the wallet needs a rebuild.
    QNERO_ENDPOINT="$rpc_endpoint" nice -n 19 npm run build
  )
  # config.json is excluded rather than deleted and rewritten, because
  # --delete would otherwise remove it for however long the next step takes
  # and a wallet loading in that window starts against nothing.
  deploy_tree "$here/wallet-web/dist/" "/var/www/wallet.$domain" --exclude config.json
fi

if has_stage explorer; then
  step "building silQ Road"
  (
    cd "$here/explorer"
    nice -n 19 npm ci
    nice -n 19 npm run build
  )
  deploy_tree "$here/explorer/dist/" "/var/www/explorer.$domain" --exclude config.json
fi

if has_stage config; then
  step "writing the runtime configs"
  # Both apps read config.json at startup, so it is how one build serves two
  # chains. numLeaves must match the runtime's embedded verifier: a mismatch is
  # every proof refused after the whole proving cost has been paid.
  leaves="${QNERO_NUM_LEAVES:-6}"
  wallet_config=$(cat <<JSON
{
  "rpcEndpoint": "$rpc_endpoint",
  "chainName": "Qnero testnet",
  "wasmBase": "wasm/",
  "numLeaves": $leaves,
  "expectedProvingSeconds": { "threaded": 12, "single": 36 }
}
JSON
)
  explorer_config=$(cat <<JSON
{
  "rpcEndpoint": "$rpc_endpoint",
  "chainName": "Qnero testnet",
  "recentBlocks": 12,
  "searchWindowBlocks": 512,
  "nullifierPageLimit": 25
}
JSON
)
  printf '%s\n' "$wallet_config" | ssh "$host" "cat > /tmp/wallet-config.json \
    && sudo install -m 0644 /tmp/wallet-config.json /var/www/wallet.$domain/config.json \
    && rm -f /tmp/wallet-config.json"
  printf '%s\n' "$explorer_config" | ssh "$host" "cat > /tmp/explorer-config.json \
    && sudo install -m 0644 /tmp/explorer-config.json /var/www/explorer.$domain/config.json \
    && rm -f /tmp/explorer-config.json"
  echo "wallet and explorer config.json written, both pointing at $rpc_endpoint"
fi

step "done"
cat <<MSG
Verify from off the box, because a check that runs on the host cannot tell you
the host is unreachable:

  curl -sS -o /dev/null -w '%{http_code}\\n' https://$domain/
  curl -sS https://wallet.$domain/config.json
  curl -sS https://explorer.$domain/config.json
  curl -sS https://faucet.$domain/status
  curl -sS -H 'content-type: application/json' \\
    -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' \\
    https://rpc.$domain
MSG
