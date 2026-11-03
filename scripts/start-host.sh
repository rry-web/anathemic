#!/usr/bin/env bash
# Starts a trusted host for an Anathemic site: a standby server that copies the site from its
# writer, passes posts on to it, and takes over (taking posts in the site's name) if the
# operator's server is out of reach for long enough. It runs beside a private i2pd router.
#
#   scripts/start-host.sh --name alice 'anathemic:….b32.i2p?root=…'    # the first time
#   scripts/start-host.sh                                              # again later
#
# The first run prints a command for the site's operator, who adds the host with the site's
# root key. Until then the standby waits. Ctrl-C stops the server and the router.

usage() {
    cat <<EOF
Usage: $0 [options] [share link]

  --data DIR              Where the standby, its I2P keys and its router live [default: ./host-data]
  --name NAME             Who runs this host, for the operator's records (first run) [default: \$USER]
  --site-keys FILE        A copy of the site's tunnel keys (site-data/i2pd/site.dat on the
                          operator's computer), so this host also answers at the site's own
                          address while it's up. Optional: readers find hosts through the site's
                          host list anyway. Sharing one address between two routers is untested.
  --takeover-minutes N    Take over after the writer has been out of reach this long; 0 only
                          when told to with promote [default: 30]
  --quick                 Take over after 2 minutes, and seal epochs as start-site.sh --quick
                          does once it's the writer (for testing)
  --listen PORT           The server's port on this computer [default: 8471]
  --port-base N           The router's ports: console N, HTTP proxy N+1 [default: 7490]
  -h, --help              Show this
EOF
}

source "$(dirname "${BASH_SOURCE[0]}")/router.sh"

DATA="$PWD/host-data"
NAME="${USER:-}"
SITE_KEYS=""
TAKEOVER=""
QUICK=0
LISTEN=8471
PORT_BASE=7490
TARGET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --data) DATA="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --site-keys) SITE_KEYS="$2"; shift 2 ;;
        --takeover-minutes) TAKEOVER="$2"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --listen) LISTEN="$2"; shift 2 ;;
        --port-base) PORT_BASE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) usage; die "unknown option $1" ;;
        *) TARGET="$1"; shift ;;
    esac
done
mkdir -p "$DATA"
DATA="$(cd "$DATA" && pwd)"
SITE="$DATA/site"
ROUTER="$DATA/i2pd"

build
find_i2pd
server() { "$BIN/anathemic-server" --data "$SITE" "$@"; }

# The standby
if [ ! -d "$SITE" ]; then
    [ -n "$TARGET" ] || { usage; die "give the site's share link (the footer of its pages shows one) the first time"; }
    say "Setting up a standby in $SITE"
    KEY="$(server init-standby "$TARGET" | sed -n 's/^Its key: //p')"
    [ -n "$KEY" ] || die "couldn't set up the standby"
    echo "$KEY" > "$DATA/key"
elif [ -n "$TARGET" ]; then
    say "This folder already holds a standby, so the share link is ignored."
fi
KEY="$(cat "$DATA/key")"

# Its own address, and the site's if the operator shared its keys
mkdir -p "$ROUTER"
if [ -n "$SITE_KEYS" ]; then
    [ -s "$SITE_KEYS" ] || die "can't read $SITE_KEYS"
    cp "$SITE_KEYS" "$ROUTER/site.dat"
    chmod 600 "$ROUTER/site.dat"
fi
{
    echo "# Written by start-host.sh. This host's own address, where the other hosts reach it:"
    printf '[anathemic-host]\ntype = http\nhost = 127.0.0.1\nport = %s\nkeys = host.dat\n' "$LISTEN"
    if [ -s "$ROUTER/site.dat" ]; then
        echo
        echo "# The site's own address, from the operator's copy of its keys"
        printf '[anathemic]\ntype = http\nhost = 127.0.0.1\nport = %s\nkeys = site.dat\n' "$LISTEN"
    fi
} > "$ROUTER/tunnels.conf"
say "Starting a private I2P router in $ROUTER"
start_router "$ROUTER" "$PORT_BASE" 0
wait_for 60 test -s "$ROUTER/host.dat" || die "i2pd didn't make this host's keys; see $ROUTER/i2pd.log"
ADDRESS="$(server i2p-address "$ROUTER/host.dat")" || die "couldn't read this host's I2P address"

# The server, reaching the other hosts through this router
SERVE=(serve --listen "127.0.0.1:$LISTEN" --proxy "http://127.0.0.1:$ROUTER_PROXY")
if [ "$QUICK" = 1 ]; then
    SERVE+=(--takeover-minutes 2 --stagger-minutes 1 --epoch-posts 5 --epoch-seconds 300 --window-seconds 60 --tick-seconds 10)
fi
[ -n "$TAKEOVER" ] && SERVE+=(--takeover-minutes "$TAKEOVER")
nc -z 127.0.0.1 "$LISTEN" 2>/dev/null && die "port $LISTEN is taken; pick another with --listen"
"$BIN/anathemic-server" --data "$SITE" "${SERVE[@]}" > "$DATA/server.log" 2>&1 &
CHILDREN+=($!)
wait_for 30 nc -z 127.0.0.1 "$LISTEN" || die "the server didn't start; see $DATA/server.log"

cat <<EOF

$(say "The standby is running.")
  This host's own I2P address: $ADDRESS
  Its key: $KEY

  If the operator hasn't added this host yet, send them that address and key. They run, in
  the folder they ran start-site.sh from:

    target/release/anathemic-server --data site-data/site add-host $KEY --address $ADDRESS --name '${NAME}'

  (or from wherever their site's data folder is). Until then this standby waits.

  Once added, it copies the site from the writer, and passes on posts and moderation sent to
  it. If the writer is out of reach for ${TAKEOVER:-$([ "$QUICK" = 1 ] && echo 2 || echo 30)} minutes, it takes over the site.
  To take over now: $BIN/anathemic-server --data $SITE promote

  Logs: $DATA/server.log and $ROUTER/i2pd.log. Router console: http://127.0.0.1:$ROUTER_CONSOLE/
  Press Ctrl-C to stop.

EOF

# Reports what the standby is doing as it changes: waiting to be added, copying, writing
(
    last=""
    while :; do
        now="$(server hosts 2>/dev/null)"
        role="$(echo "$now" | sed -nE 's/.* is (the writer|a standby), in term ([0-9]+).*/\1 in term \2/p')"
        listed=no
        echo "$now" | grep -q "$ADDRESS" && listed=yes
        state="$role, on the host list: $listed"
        if [ "$state" != "$last" ]; then
            case "$listed:$role" in
                no:*) say "Waiting for the operator to add this host." ;;
                yes:a\ standby*) say "On the site's host list: copying the site, and standing by ($role)." ;;
                yes:the\ writer*) say "This host is now running the site ($role)." ;;
            esac
            last="$state"
        fi
        sleep 15
    done
) &
HELPERS+=($!)

wait_all
