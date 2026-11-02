# Shared by start-site.sh and start-mirror.sh: builds Anathemic and runs a private i2pd router
# for one script, in its own data folder and on its own ports, so it never touches another
# router on this computer (rynx's, or the system's).

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/release"
# Processes that must keep running, and helpers that may finish on their own
CHILDREN=()
HELPERS=()

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

build() {
    command -v cargo >/dev/null || die "Rust isn't installed; get it from https://rustup.rs"
    say "Building Anathemic (the first build takes a few minutes)..."
    (cd "$REPO" && cargo build --release --quiet -p anathemic-server -p anathemic-client -p anathemic-node) || die "the build failed"
}

find_i2pd() {
    I2PD="${I2PD:-$(command -v i2pd || true)}"
    [ -n "$I2PD" ] || die "i2pd isn't installed: brew install i2pd (macOS) or sudo apt install i2pd (Debian, Ubuntu)"
    # A fresh data folder has no reseed certificates; use the ones i2pd was installed with
    for dir in "${I2PD_CERTS:-}" "$(dirname "$I2PD")/../share/i2pd/certificates" /usr/share/i2pd/certificates /var/lib/i2pd/certificates; do
        if [ -n "$dir" ] && [ -d "$dir/reseed" ]; then
            I2PD_CERTS="$(cd "$dir" && pwd)"
            return
        fi
    done
    die "can't find i2pd's certificates folder; set I2PD_CERTS to it"
}

# start_router <data folder> <port base> <sam: 0 or 1>
# The router console is on the base port, the HTTP proxy on base+1 and SAM on base+2.
start_router() {
    local dir="$1" base="$2" sam="$3"
    ROUTER_CONSOLE=$base
    ROUTER_PROXY=$((base + 1))
    ROUTER_SAM=$((base + 2))
    mkdir -p "$dir/tunnels.d"
    if [ ! -f "$dir/i2pd.conf" ]; then
        cat > "$dir/i2pd.conf" <<'EOF'
# This router's own settings; the start script sets its ports on the command line.
# Relaying for others keeps I2P fast for everyone. Raise these if you have bandwidth to spare.
bandwidth = L
share = 50
EOF
    fi
    touch "$dir/tunnels.conf"
    # A router left behind by an earlier run that didn't exit cleanly
    if [ -f "$dir/i2pd.pid" ] && kill -0 "$(cat "$dir/i2pd.pid")" 2>/dev/null; then
        kill "$(cat "$dir/i2pd.pid")" 2>/dev/null || true
        sleep 2
    fi
    for port in $ROUTER_CONSOLE $ROUTER_PROXY $( [ "$sam" = 1 ] && echo $ROUTER_SAM ); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            die "port $port is taken; pick other ports with --port-base"
        fi
    done
    "$I2PD" --datadir="$dir" --conf="$dir/i2pd.conf" --tunconf="$dir/tunnels.conf" --tunnelsdir="$dir/tunnels.d" \
        --certsdir="$I2PD_CERTS" --pidfile="$dir/i2pd.pid" --log=file --logfile="$dir/i2pd.log" --loglevel=warn \
        --http.address=127.0.0.1 --http.port="$ROUTER_CONSOLE" \
        --httpproxy.address=127.0.0.1 --httpproxy.port="$ROUTER_PROXY" \
        --sam.enabled="$sam" --sam.address=127.0.0.1 --sam.port="$ROUTER_SAM" \
        --socksproxy.enabled=0 --bob.enabled=0 --i2cp.enabled=0 --i2pcontrol.enabled=0 \
        >/dev/null 2>&1 &
    CHILDREN+=($!)
    ROUTER_PID=$!
    sleep 1
    kill -0 "$ROUTER_PID" 2>/dev/null || die "i2pd didn't start; see $dir/i2pd.log"
}

# Stops everything this script started
cleanup() {
    trap - EXIT INT TERM
    if [ ${#HELPERS[@]} -gt 0 ]; then
        kill "${HELPERS[@]}" 2>/dev/null || true
    fi
    if [ ${#CHILDREN[@]} -gt 0 ]; then
        say "Stopping..."
        kill "${CHILDREN[@]}" 2>/dev/null || true
        wait 2>/dev/null || true
    fi
}

# wait_for <seconds> <command...>: retries the command once a second
wait_for() {
    local seconds="$1"
    shift
    for _ in $(seq "$seconds"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

# Waits until the background processes exit, stopping them all if one does
wait_all() {
    while :; do
        for pid in "${CHILDREN[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                say "A process stopped (pid $pid); shutting down."
                exit 1
            fi
        done
        sleep 2
    done
}
