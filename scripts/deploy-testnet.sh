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
#   wallet    rebuild the wasm prover, build Qloak against wss://rpc.<domain>,
#             rsync wallet-web/dist/
#             QNERO_WASM_PREBUILT=1 skips the two prover builds and stages the
#             modules already in crates/qnero-prover-wasm/www/pkg and
#             www/pkg-threaded. It is for a workstation that does not build
#             wasm: build the modules elsewhere, rsync them into those two
#             directories, and deploy with the flag set. What it does not skip
#             is stage-wasm.sh's export check, so a module older than the
#             crate's surface still refuses the deploy.
#   explorer  build silQ Road, rsync explorer/dist/
#   config    write the two runtime config.json files
#
# And one stage that is never run unless it is named:
#
#   faucet    build qnero-faucet, copy it, restart qnero-faucet and nothing else
#
# The faucet page is the surface that changes most often and the chain is the
# thing least worth restarting, so a faucet edit had the worst deploy in this
# repository: the node stage was the only path to the binary and it restarts
# the chain mid-block to deliver it. `faucet` is that path without the chain.
# It stays out of the default run because `node` already builds and installs
# the same binary, and running both would build it twice and restart it twice.
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

# Release builds run niced, and on at most eight of this workstation's cores,
# so a deploy never takes the machine away from whoever is using it. taskset is
# Linux only and the mask is clamped to the cores that actually exist, because
# asking for 0-7 on a four-core machine fails the whole build.
build_nice=(nice -n 19)
if command -v taskset > /dev/null 2>&1; then
  cores="$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo 1)"
  build_nice=(taskset -c "0-$((cores > 8 ? 7 : cores - 1))" nice -n 19)
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
      "${build_nice[@]}" cargo build -j "$jobs" --release -p qnero-node
  )

  step "building qnero-faucet"
  (
    cd "$here"
    "${build_nice[@]}" cargo build -j 2 --release -p qnero-faucet
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

# The faucet alone. Same build, same keep-the-previous-binary rule, and one
# unit restarted: the chain is not touched, no block is missed and no peer is
# dropped for a change to a page.
if has_stage faucet; then
  step "building qnero-faucet"
  (
    cd "$here"
    "${build_nice[@]}" cargo build -j 2 --release -p qnero-faucet
  )

  step "copying the faucet binary"
  scp "$here/target/release/qnero-faucet" "$host:/tmp/qnero-faucet"
  ssh "$host" 'if sudo test -x /usr/local/bin/qnero-faucet; then \
      sudo cp -a /usr/local/bin/qnero-faucet /usr/local/bin/qnero-faucet.previous; \
      echo "kept /usr/local/bin/qnero-faucet.previous"; \
    fi \
    && sudo install -m 0755 /tmp/qnero-faucet /usr/local/bin/qnero-faucet \
    && rm -f /tmp/qnero-faucet \
    && sudo systemctl restart qnero-faucet \
    && systemctl is-active qnero-faucet'

  cat <<'MSG'

The faucet answers 502 for about 20 s after this restart. Its worker opens the
wallet, asks the node for runtime metadata and builds the proving circuits
before the listener binds, on purpose: a faucet that cannot pay should fail at
startup rather than serve a page and refuse every claim. Nothing else was
restarted, and the chain did not miss a block.
MSG
fi

if has_stage spec; then
  step "copying the chain spec"
  echo "The spec is copied and NOTHING is restarted. A node already running on"
  echo "this genesis does not need it, and a node restarted onto a different"
  echo "genesis resyncs from block zero. Restart deliberately."
  scp "$here/chain/node/chain-specs/qnero-testnet.json" "$host:/tmp/qnero-testnet.json"
  ssh "$host" 'sudo install -m 0644 -o root -g root /tmp/qnero-testnet.json \
    /etc/qnero/qnero-testnet.json && rm -f /tmp/qnero-testnet.json'
  # What the copy just installed says about the network's entry point. The
  # committed spec carries the bootnode once a deployment has fed it through
  # build-testnet-spec.sh, and carries an empty list before that, so this
  # reports which of the two was copied rather than assuming either.
  committed_boot="$(jq -r '(.bootNodes // []) | join(" ")' \
    "$here/chain/node/chain-specs/qnero-testnet.json")"
  if [ -n "$committed_boot" ]; then
    cat <<MSG

The copy on the host carries its bootnode:

  $committed_boot

Check it against the key that is actually on the host, because a spec naming
somebody else's peer id is a network nobody can join:

  ssh $host qnero-node key inspect-node-key --file /etc/qnero/node-key
MSG
  else
    cat <<MSG

The committed spec carries an empty "bootNodes", so the installed copy has no
entry. Put one in ON THE HOST, then feed the same multiaddr through
scripts/build-testnet-spec.sh and commit it, so the next copy does not drop it
again. This reads the peer id out of the key that is already there; it does not
generate anything, and it must not, because a bootnode that rotates its
identity is one nobody can reach:

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
    # The prover is rebuilt here rather than staged from whatever build is
    # lying in the crate. A stale module is a wallet whose screens die on an
    # export that is not there, and the bundle cannot know: the module is
    # fetched at runtime, never imported, never typed. stage-wasm.sh also
    # refuses a module missing an export the crate declares, as the backstop.
    #
    # QNERO_WASM_PREBUILT=1 is the escape hatch for a machine that is not
    # allowed to build wasm: the two modules are built elsewhere and rsynced
    # into www/pkg and www/pkg-threaded, and this stage only stages them.
    #
    # What keeps that honest is the digest. The export check says the names the
    # crate declares appear in the generated glue, which a module with every
    # export and other bytes in it also passes, and the glue is text. So
    # stage-wasm.sh pins both `.wasm` files against a SHA-256 manifest under
    # this flag and refuses a manifest that is missing or disagrees, and it
    # refuses a missing threaded package, which would otherwise ship a wallet
    # that proves a payment in 37.6 s where it takes 11.2 s. Write the manifest on
    # the machine that built the modules and bring it with them; point
    # QNERO_WASM_SHA256 at it, or put it at wallet-web/wasm-prebuilt.sha256.
    if [ "${QNERO_WASM_PREBUILT:-0}" = "1" ]; then
      echo "QNERO_WASM_PREBUILT=1: staging the prover modules already in the crate, building neither"
      export QNERO_WASM_PREBUILT QNERO_WASM_SHA256
    else
      (
        cd "$here/crates/qnero-prover-wasm"
        "${build_nice[@]}" ./scripts/build-wasm.sh
        "${build_nice[@]}" ./scripts/build-threaded-wasm.sh
      )
    fi
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
