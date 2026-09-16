#!/usr/bin/env bash
#
# The on-box monitor for the Qnero testnet host. One ops crontab entry, every
# minute:
#
#   * * * * * $HOME/monitor.sh >> $HOME/monitor.log 2>&1
#
# Every path below is relative to the home directory of the account it runs as,
# so nothing in this file has to be hand-patched for a particular host. Set
# MONITOR_HOME to override that, and the rest individually if the layout
# differs. Secrets go in ~/.monitor.env at mode 0600 (DISCORD_WEBHOOK_URL and
# the expected genesis hash), which this sources.
#
# Two things about the shape, both learned the hard way on a sibling
# deployment:
#
#  - **Alerts are edge-triggered and debounced.** An alert fires once when a check starts
#    failing and once more when it recovers, and only after two consecutive failing ticks,
#    so a deploy restart or a garbage-collection pause stays quiet.
#  - **The state file is NOT in /tmp.** A reboot wipes /tmp, and every active alert then
#    re-fires as new, which is exactly the moment an operator is least able to tell a real
#    problem from an artefact of the reboot.
#
# And the limit of this script, said plainly: it runs on the box it watches, so
# it cannot report that box being down, and every check below except the TLS
# one probes loopback. A nine-hour outage on a sibling host was nginx dead with
# every application behind it healthy, and a monitor exactly like this one
# stayed green throughout. The external watchdog is the other half and is not
# optional.
set -uo pipefail

OPS_HOME="${MONITOR_HOME:-$HOME}"
ENV_FILE="${MONITOR_ENV:-$OPS_HOME/.monitor.env}"

# The operator's file is sourced HERE, before a single default below is
# resolved. Sourcing it after them reads as a detail and is not one: every
# default is `${MONITOR_X:-...}` expanded once, so a later source sets
# MONITOR_DOMAIN to no effect, DOMAIN stays at the literal `<domain>`, curl
# cannot resolve a host with angle brackets, and the one check written to catch
# a dead proxy latches a red alert on its first tick that never clears.
#
# A failed source is fatal, and it has to be, because the failure is silent
# otherwise. The file is shell, so a value carrying `<` or `>` unquoted is a
# syntax error, bash stops reading the file at that line, and every setting
# below it never arrives: the monitor then runs with defaults it was never
# meant to have and skips MONITOR_EXPECT_GENESIS entirely, which is the one
# check that catches a node that lost its database and resynced from the spec.
# shellcheck source=/dev/null
if [ -f "$ENV_FILE" ]; then
    if ! . "$ENV_FILE"; then
        echo "[$(date -Is)] $ENV_FILE could not be sourced. It is shell: a value" >&2
        echo "containing < or > has to be quoted, and everything after the failing" >&2
        echo "line never reached this script." >&2
        exit 2
    fi
fi

STATE_DIR="${MONITOR_STATE_DIR:-$OPS_HOME/monitor-state}"
ALERT_STATE="$STATE_DIR/alerts"
FAIL_COUNTS="$STATE_DIR/fails"
HEIGHT_FILE="$STATE_DIR/height"
DEBOUNCE="${MONITOR_DEBOUNCE:-2}"

# Filled in by the operator. <domain> is the only placeholder here.
DOMAIN="${MONITOR_DOMAIN:-<domain>}"
SSL_DIR="${MONITOR_SSL_DIR:-$OPS_HOME/ssl/$DOMAIN}"
RPC="${MONITOR_RPC:-http://127.0.0.1:9944}"
FAUCET="${MONITOR_FAUCET:-http://127.0.0.1:8080}"
STRATUM_PORT="${MONITOR_STRATUM_PORT:-3333}"
# An optional extra floor, and no longer the check that catches a node which
# lost its database: this script remembers the best height it has seen and
# alerts on a fall from it, which needs no hand-editing as the chain grows.
# Leave this at 1, or set it to a height this deployment is known to be past if
# an absolute floor is wanted as well.
MIN_HEIGHT="${MONITOR_MIN_HEIGHT:-1}"
# How far the head may fall below the best height this monitor has seen before
# it is a fall rather than a reorg. A node that resynced from the spec goes to
# zero; a reorg on this chain is a block or two.
HEIGHT_DROP="${MONITOR_HEIGHT_DROP:-100}"
# At 120 s blocks and a 60 s tick the height moves on roughly every other tick,
# so staleness is wall clock rather than a per-tick comparison. Thirty minutes
# is fifteen block intervals: long enough that a slow stretch of difficulty
# retarget is not an alert, short enough to catch a node that stopped.
STALE_SECS="${MONITOR_STALE_SECS:-1800}"
DISK_MIN_PCT="${MONITOR_DISK_MIN_PCT:-10}"
CERT_WARN_DAYS="${MONITOR_CERT_WARN_DAYS:-30}"

# A placeholder is never probed. Without this the TLS check asks curl for
# `wallet.<domain>`, gets 000 every tick, and alerts on a name that does not
# exist instead of on nginx.
case "$DOMAIN" in
    *'<'*|*'>'*|'')
        echo "[$(date -Is)] MONITOR_DOMAIN is still the placeholder ($DOMAIN). Set it in $ENV_FILE." >&2
        exit 2
        ;;
esac
case "$SSL_DIR" in
    *'<'*|*'>'*)
        echo "[$(date -Is)] MONITOR_SSL_DIR is still a placeholder ($SSL_DIR). Set it in $ENV_FILE." >&2
        exit 2
        ;;
esac

mkdir -p "$STATE_DIR"
touch "$ALERT_STATE" "$FAIL_COUNTS"

now=$(date +%s)

notify() {
    local text="$1"
    if [ -z "${DISCORD_WEBHOOK_URL:-}" ]; then
        echo "[$(date -Is)] (no webhook configured) $text"
        return
    fi
    # Discord answers 204 on success. Capture it: a revoked or mistyped webhook
    # fails silently and the first anyone knows is an outage nobody was paged
    # for.
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
        -H 'content-type: application/json' \
        -d "$(printf '{"content":%s}' "$(printf '%s' "$text" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")" \
        "$DISCORD_WEBHOOK_URL")
    if [ "$code" != "204" ]; then
        echo "[$(date -Is)] the webhook answered $code, not 204: $text"
    fi
}

is_alerting() {
    grep -qxF "$1" "$ALERT_STATE"
}

alert() {
    local key="$1" message="$2"
    is_alerting "$key" && return
    printf '%s\n' "$key" >> "$ALERT_STATE"
    notify ":red_circle: **qnero testnet** $message"
}

resolve() {
    local key="$1" message="$2"
    is_alerting "$key" || return
    # `|| true` and an unconditional mv, because grep exits 1 when it matches
    # nothing, which is exactly the case where this key was the only one in the
    # file. Guarding the mv on grep's status there leaves the key behind for
    # ever: the next alert() returns early on `is_alerting` and the check is
    # silently dead from its first recovery onward.
    { grep -vxF "$key" "$ALERT_STATE" || true; } > "$ALERT_STATE.new"
    mv "$ALERT_STATE.new" "$ALERT_STATE"
    notify ":green_circle: **qnero testnet** $message"
}

fail_count() {
    awk -v k="$1" '$1 == k { print $2 }' "$FAIL_COUNTS" | tail -1
}

set_fail_count() {
    local key="$1" count="$2"
    grep -v "^$key " "$FAIL_COUNTS" > "$FAIL_COUNTS.new" 2>/dev/null
    printf '%s %s\n' "$key" "$count" >> "$FAIL_COUNTS.new"
    mv "$FAIL_COUNTS.new" "$FAIL_COUNTS"
}

# A state field read back as a number. A file written by a different version of
# this script, or a write that was cut short by a reboot, holds something that
# is not one, and `$(( ))` reads an unparseable value as a variable name and
# calls it zero. A zero best height is no memory at all, and a zero timestamp
# would read as thirty minutes of stall on the next tick, so an unreadable
# field starts again from this tick instead.
number_or_zero() {
    case "$1" in
        '' | *[!0-9]*) printf '0' ;;
        *) printf '%s' "$1" ;;
    esac
}

# check_debounced <key> <ok|fail> <alert message> <resolve message>
check_debounced() {
    local key="$1" verdict="$2" bad="$3" good="$4"
    local count
    count="$(fail_count "$key")"
    count="${count:-0}"
    if [ "$verdict" = "ok" ]; then
        set_fail_count "$key" 0
        resolve "$key" "$good"
        return
    fi
    count=$((count + 1))
    set_fail_count "$key" "$count"
    if [ "$count" -ge "$DEBOUNCE" ]; then
        alert "$key" "$bad"
    fi
}

rpc_call() {
    curl -s -m 6 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "$RPC"
}

# ---------------------------------------------------------------- units

for unit in qnero-node qnero-faucet nginx; do
    if systemctl is-active --quiet "$unit"; then
        check_debounced "unit-$unit" ok "" "$unit is running again"
    else
        check_debounced "unit-$unit" fail "$unit is not active" ""
    fi

    # A unit that is flapping reads as active on every tick. This is the gap
    # that let a sibling deployment's backend sit at 32 restarts unnoticed.
    restarts=$(systemctl show -p NRestarts --value "$unit" 2>/dev/null || echo 0)
    previous=$(fail_count "restarts-$unit")
    previous="${previous:-0}"
    set_fail_count "restarts-$unit" "$restarts"
    if [ "$restarts" -gt "$previous" ] && [ "$previous" -gt 0 ]; then
        notify ":warning: **qnero testnet** $unit restarted ($previous -> $restarts)"
    fi
done

# ---------------------------------------------------------------- the node

health="$(rpc_call system_health)"
peers="$(printf '%s' "$health" | jq -r '.result.peers // empty' 2>/dev/null)"
syncing="$(printf '%s' "$health" | jq -r '.result.isSyncing // empty' 2>/dev/null)"

if [ -z "$peers" ]; then
    check_debounced "rpc" fail "the node's RPC did not answer on loopback" ""
else
    check_debounced "rpc" ok "" "the node's RPC is answering again"
fi

header="$(rpc_call chain_getHeader)"
height_hex="$(printf '%s' "$header" | jq -r '.result.number // empty' 2>/dev/null)"
# Anything that is not hex is treated as no header at all, for the same reason
# as number_or_zero: $(( )) would call it zero, and a zero here is exactly what
# a node that lost its database looks like.
if ! printf '%s' "$height_hex" | grep -qE '^0x[0-9a-fA-F]+$'; then
    height_hex=''
fi
if [ -n "$height_hex" ]; then
    height=$((height_hex))

    # An absolute floor, kept because it is free and it catches the one case
    # the memory below cannot: a monitor whose state directory is as new as the
    # resynced node it is watching. It is optional and it no longer has to be
    # raised by hand.
    if [ "$height" -lt "$MIN_HEIGHT" ]; then
        check_debounced "height-floor" fail \
            "the node is at block $height, below the floor of $MIN_HEIGHT" ""
    else
        check_debounced "height-floor" ok "" "the node is back above the height floor"
    fi

    # What the monitor remembers about the chain: the best height it has ever
    # seen, the height it saw last, and when that last changed.
    #
    # The best height is the check that used to be MONITOR_MIN_HEIGHT's job and
    # was only ever as good as the last time somebody edited it. A node that
    # lost its database and restarted from the spec answers every call happily
    # and serves both wallets an empty tree; against a remembered high-water
    # mark it is unmistakable, and nothing has to be maintained for that to
    # stay true as the chain grows.
    #
    # Three fields. A state file written by an older copy of this script holds
    # two, height and the time it was seen, and is read as that.
    previous_best=0
    previous_height=0
    previous_at=0
    if [ -f "$HEIGHT_FILE" ]; then
        read -r previous_best previous_height previous_at < "$HEIGHT_FILE" || true
        if [ -z "${previous_at:-}" ]; then
            previous_at="${previous_height:-0}"
            previous_height="${previous_best:-0}"
        fi
    fi
    previous_best="$(number_or_zero "${previous_best:-0}")"
    previous_height="$(number_or_zero "${previous_height:-0}")"
    previous_at="$(number_or_zero "${previous_at:-0}")"

    best="$previous_best"
    [ "$height" -gt "$best" ] && best="$height"
    # The tip moving at all is the node working, in either direction: a reorg
    # is not a stall.
    if [ "$height" != "$previous_height" ] || [ "$previous_at" = "0" ]; then
        changed_at="$now"
    else
        changed_at="$previous_at"
    fi
    printf '%s %s %s\n' "$best" "$height" "$changed_at" > "$HEIGHT_FILE"

    dropped=$((best - height))
    if [ "$dropped" -gt "$HEIGHT_DROP" ]; then
        check_debounced "height-drop" fail \
            "the node is at block $height, $dropped blocks below the $best this monitor has seen. A node that lost its database and resynced from the spec looks exactly like this: it answers every call and serves an empty tree. If this chain was replaced on purpose, delete $HEIGHT_FILE and update MONITOR_EXPECT_GENESIS" ""
    else
        check_debounced "height-drop" ok "" "the node is back up at block $height"
    fi

    stalled=$((now - changed_at))
    if [ "$stalled" -gt "$STALE_SECS" ]; then
        # Peers and syncing are reported with it rather than alerted on
        # separately, because authoring pauses on a stale tip, on no peers or
        # during an initial sync, and a stalled height with peers is a
        # different problem from a stalled height with zero peers.
        check_debounced "height-stall" fail \
            "the node has been at block $height for ${stalled}s (peers $peers, syncing $syncing)" ""
    else
        check_debounced "height-stall" ok "" "the node is authoring again, at block $height"
    fi
else
    check_debounced "height-stall" fail "chain_getHeader returned no usable height" ""
fi

genesis="$(rpc_call chain_getBlockHash '[0]' | jq -r '.result // empty' 2>/dev/null)"
if [ -n "${MONITOR_EXPECT_GENESIS:-}" ]; then
    if [ "$genesis" = "$MONITOR_EXPECT_GENESIS" ]; then
        check_debounced "genesis" ok "" "the node is back on the expected genesis"
    else
        check_debounced "genesis" fail \
            "the node serves genesis $genesis and this deployment is $MONITOR_EXPECT_GENESIS" ""
    fi
fi

if nc -z -w 3 127.0.0.1 "$STRATUM_PORT" > /dev/null 2>&1; then
    check_debounced "stratum" ok "" "the stratum port is listening again"
else
    check_debounced "stratum" fail "the stratum port $STRATUM_PORT is not listening" ""
fi

# ---------------------------------------------------------------- the faucet

faucet_code="$(curl -s -o /dev/null -w '%{http_code}' -m 6 "$FAUCET/health")"
if [ "$faucet_code" = "200" ]; then
    check_debounced "faucet" ok "" "the faucet is healthy again"
else
    # `balanceQnr` is the same figure with a unit a person reads: a bare
    # 48992 in a page reads as a hundred times what the faucet holds. It is
    # null against a faucet older than this field, which costs the reason
    # nothing, so `balanceQuanta` stays selected beside it.
    reason="$(curl -s -m 6 "$FAUCET/health" \
        | jq -c '{ready, nodeFresh, funded, balanceQuanta, balanceQnr}' 2>/dev/null)"
    check_debounced "faucet" fail "the faucet answered $faucet_code on /health ${reason:-}" ""
fi

# ---------------------------------------------------------------- nginx

# On loopback with the Host header forced, because `systemctl is-active nginx`
# is exactly what stayed green through a nine-hour outage: every application
# behind the proxy was healthy and the proxy was dead.
tls_code="$(curl -sk -o /dev/null -w '%{http_code}' -m 8 \
    --resolve "wallet.$DOMAIN:443:127.0.0.1" "https://wallet.$DOMAIN/")"
if [ "$tls_code" = "200" ]; then
    check_debounced "nginx-tls" ok "" "nginx is serving TLS again"
else
    check_debounced "nginx-tls" fail "nginx answered $tls_code for wallet.$DOMAIN on loopback" ""
fi

# The origin certificate. It is a 15-year certificate with no renewal timer,
# which is exactly why something has to watch it: nothing else will notice.
if [ -f "$SSL_DIR/cert.pub" ]; then
    expiry="$(openssl x509 -enddate -noout -in "$SSL_DIR/cert.pub" 2>/dev/null | cut -d= -f2)"
    if [ -n "$expiry" ]; then
        expiry_at="$(date -d "$expiry" +%s 2>/dev/null || echo 0)"
        days=$(((expiry_at - now) / 86400))
        if [ "$days" -lt "$CERT_WARN_DAYS" ]; then
            check_debounced "cert" fail "the origin certificate expires in $days days" ""
        else
            check_debounced "cert" ok "" "the origin certificate is valid again"
        fi
    fi
fi

# ---------------------------------------------------------------- disk

free_pct="$(df --output=pcent /var/lib/qnero 2>/dev/null | tail -1 | tr -dc '0-9')"
if [ -n "$free_pct" ]; then
    remaining=$((100 - free_pct))
    if [ "$remaining" -lt "$DISK_MIN_PCT" ]; then
        check_debounced "disk" fail \
            "only ${remaining}% of the node's filesystem is free. --state-pruning archive is what fills a small box" ""
    else
        check_debounced "disk" ok "" "the node's filesystem has room again"
    fi
fi

# An empty alert state file is the all-clear.
exit 0
