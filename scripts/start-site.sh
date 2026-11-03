#!/usr/bin/env bash
# Starts an Anathemic site: the operator's server, published over I2P by a private i2pd router.
# The first run creates the site; later runs start it again from the same folder.
#
#   scripts/start-site.sh --name "My Forum" --board general:General --web-posting
#   scripts/start-site.sh                      # again later
#   scripts/start-site.sh --quick              # small epochs that seal in minutes, for testing
#
# Ctrl-C stops the server and the router.

usage() {
    cat <<EOF
Usage: $0 [options]

  --data DIR          Where the site, its I2P keys and its router live [default: ./site-data]
  --name NAME         What to call the site (first run)
  --board NAME:TITLE  A board to create (first run); repeat for more [default: general:General]
  --web-posting       Let the boards take anonymous posts from the web pages (first run)
  --quick             Close epochs after 5 posts and seal them a minute later, so mirrors have
                      something to fetch soon (for testing; the defaults are 500 posts or a
                      week, then 3 days)
  --listen PORT       The server's port on this computer [default: 8470]
  --port-base N       The router's ports: console N, HTTP proxy N+1 [default: 7470]
  -h, --help          Show this
EOF
}

source "$(dirname "${BASH_SOURCE[0]}")/router.sh"

DATA="$PWD/site-data"
NAME=""
BOARDS=()
WEB=0
QUICK=0
LISTEN=8470
PORT_BASE=7470
while [ $# -gt 0 ]; do
    case "$1" in
        --data) DATA="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --board) BOARDS+=("$2"); shift 2 ;;
        --web-posting) WEB=1; shift ;;
        --quick) QUICK=1; shift ;;
        --listen) LISTEN="$2"; shift 2 ;;
        --port-base) PORT_BASE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown option $1" ;;
    esac
done
mkdir -p "$DATA"
DATA="$(cd "$DATA" && pwd)"
SITE="$DATA/site"
LOCAL="http://127.0.0.1:$LISTEN"
OPERATOR="$DATA/operator"

build
find_i2pd
server() { "$BIN/anathemic-server" --data "$SITE" "$@"; }
operator() { "$BIN/anathemic-client" --home "$OPERATOR" --direct "$@"; }

# The site
FIRST=0
if [ ! -d "$SITE" ]; then
    FIRST=1
    say "Creating the site in $SITE"
    server init --name "$NAME" || die "couldn't create the site"
    [ ${#BOARDS[@]} -gt 0 ] || BOARDS=("general:General")
    for board in "${BOARDS[@]}"; do
        name="${board%%:*}"
        title="${board#*:}"
        [ "$title" != "$board" ] || title="$name"
        if [ "$WEB" = 1 ]; then
            server add-board "$name" --title "$title" --web-posting || die "couldn't add /$name/"
        else
            server add-board "$name" --title "$title" || die "couldn't add /$name/"
        fi
    done
elif [ -n "$NAME" ] || [ ${#BOARDS[@]} -gt 0 ] || [ "$WEB" = 1 ]; then
    say "The site already exists, so --name, --board and --web-posting are ignored."
    echo "Change it with $BIN/anathemic-server --data $SITE set-site, add-board or set-board."
fi

# Its I2P address: a server tunnel to the server, whose keys i2pd makes on first start
ROUTER="$DATA/i2pd"
mkdir -p "$ROUTER"
cat > "$ROUTER/tunnels.conf" <<EOF
# Written by start-site.sh. The site's address, which readers use:
[anathemic]
type = http
host = 127.0.0.1
port = $LISTEN
keys = site.dat

# This server's own address, where trusted hosts reach it (see start-host.sh)
[anathemic-host]
type = http
host = 127.0.0.1
port = $LISTEN
keys = host.dat
EOF
say "Starting a private I2P router in $ROUTER"
start_router "$ROUTER" "$PORT_BASE" 0
wait_for 60 test -s "$ROUTER/site.dat" || die "i2pd didn't make the site's keys; see $ROUTER/i2pd.log"
ADDRESS="$(server i2p-address "$ROUTER/site.dat")" || die "couldn't read the site's I2P address"
if [ "$(cat "$DATA/address" 2>/dev/null)" != "$ADDRESS" ]; then
    server set-site --address "$ADDRESS" >/dev/null || die "couldn't set the site's address"
    echo "$ADDRESS" > "$DATA/address"
fi
wait_for 60 test -s "$ROUTER/host.dat" || die "i2pd didn't make this server's own keys; see $ROUTER/i2pd.log"
HOST_ADDRESS="$(server i2p-address "$ROUTER/host.dat")" || die "couldn't read this server's own I2P address"
if [ "$(cat "$DATA/host-address" 2>/dev/null)" != "$HOST_ADDRESS" ]; then
    server set-site --host-address "$HOST_ADDRESS" >/dev/null || die "couldn't set this server's own address"
    echo "$HOST_ADDRESS" > "$DATA/host-address"
fi

# The server
SERVE=(serve --listen "127.0.0.1:$LISTEN")
[ "$QUICK" = 1 ] && SERVE+=(--epoch-posts 5 --epoch-seconds 300 --window-seconds 60 --tick-seconds 10)
nc -z 127.0.0.1 "$LISTEN" 2>/dev/null && die "port $LISTEN is taken; pick another with --listen"
"$BIN/anathemic-server" --data "$SITE" "${SERVE[@]}" > "$DATA/server.log" 2>&1 &
CHILDREN+=($!)
wait_for 30 curl -sf "$LOCAL/manifest" -o /dev/null || die "the server didn't start; see $DATA/server.log"

# On the first run the operator becomes a moderator, with a member key of their own
if [ "$FIRST" = 1 ]; then
    KEY="$(operator key "$LOCAL" | tail -1 | cut -d' ' -f1)"
    server add-moderator "$KEY" --name operator --power hide --power purge --power ban >/dev/null \
        || say "Couldn't make you a moderator; do it later with anathemic-server add-moderator"
fi
LINK="$(operator share "$LOCAL" 2>/dev/null | head -1)"
BOARD="$(operator boards "$LOCAL" 2>/dev/null | sed -n 's|^/\([^/]*\)/.*|\1|p' | head -1)"
BOARD="${BOARD:-general}"

CLIENT="$BIN/anathemic-client --home $OPERATOR"
cat <<EOF

$(say "The site is running.")
  I2P address:  http://$ADDRESS/
  On this computer: $LOCAL/
  Share link (for mirrors and readers):
    $LINK

  A new router takes a few minutes to join I2P before the address works; this script says
  when it does. Then open the address in rynx, or any I2P browser.

  Mirror it, from this computer or another:
    scripts/start-mirror.sh '$LINK'

  Let someone you trust keep it taking posts while this server is down:
    scripts/start-host.sh '$LINK'
  It prints the command to run here to add them. Hosts: $BIN/anathemic-server --data $SITE hosts

  Post and moderate as the operator (with the moderator key this script made):
    $CLIENT --direct post $LOCAL $BOARD --title "Hello" "First post"
    $CLIENT --direct moderate $LOCAL hide $BOARD 1 --reason "test"
    $CLIENT --direct log $LOCAL

  Logs: $DATA/server.log and $ROUTER/i2pd.log. Router console: http://127.0.0.1:$ROUTER_CONSOLE/
  Press Ctrl-C to stop.

EOF

# Says when the site answers over I2P, through this router's own proxy
(
    for _ in $(seq 180); do
        if curl -sf -x "http://127.0.0.1:$ROUTER_PROXY" --max-time 60 "http://$ADDRESS/manifest" -o /dev/null; then
            say "The site is reachable over I2P at http://$ADDRESS/"
            exit 0
        fi
        sleep 10
    done
    say "The site still isn't reachable over I2P after 30 minutes; see $ROUTER/i2pd.log"
) &
HELPERS+=($!)

wait_all
