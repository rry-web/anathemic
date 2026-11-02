#!/usr/bin/env bash
# Starts a mirror of an Anathemic site: anathemic-node beside a private i2pd router with SAM on.
# It keeps a copy of the site, shares its epochs with other mirrors, and serves the site
# read-only at an I2P address of its own.
#
#   scripts/start-mirror.sh 'anathemic:….b32.i2p?root=…'    # the first time
#   scripts/start-mirror.sh                                 # again later, from the same folder
#
# Several mirrors on one computer need their own folders and ports:
#   scripts/start-mirror.sh --data mirror2 --port-base 7490 '<share link>'
#
# Ctrl-C stops the node and the router.

usage() {
    cat <<EOF
Usage: $0 [options] [share link or site address] [-- anathemic-node options]

  --data DIR       Where the copy, the node's I2P keys and the router live [default: ./mirror-data]
  --port-base N    The router's ports: console N, HTTP proxy N+1, SAM N+2 [default: 7480]
  --router         Use an I2P router that's already running instead of starting one; give its
                   ports with --sam and --proxy
  --sam PORT       With --router: its SAM port [default: 7656]
  --proxy URL      With --router: its HTTP proxy [default: http://127.0.0.1:4444]
  -h, --help       Show this

Options after -- go to anathemic-node, such as --board general, -v, or --peer-seconds 60.
EOF
}

source "$(dirname "${BASH_SOURCE[0]}")/router.sh"

DATA="$PWD/mirror-data"
PORT_BASE=7480
OWN_ROUTER=1
SAM=7656
PROXY="http://127.0.0.1:4444"
TARGET=""
NODE_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --data) DATA="$2"; shift 2 ;;
        --port-base) PORT_BASE="$2"; shift 2 ;;
        --router) OWN_ROUTER=0; shift ;;
        --sam) SAM="$2"; shift 2 ;;
        --proxy) PROXY="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; NODE_ARGS=("$@"); break ;;
        -*) usage; die "unknown option $1" ;;
        *) TARGET="$1"; shift ;;
    esac
done
mkdir -p "$DATA"
DATA="$(cd "$DATA" && pwd)"

# The site to mirror, remembered for later runs
if [ -n "$TARGET" ]; then
    echo "$TARGET" > "$DATA/site"
elif [ -s "$DATA/site" ]; then
    TARGET="$(cat "$DATA/site")"
else
    usage
    die "give the site's share link (the footer of its pages shows one) the first time"
fi

build
if [ "$OWN_ROUTER" = 1 ]; then
    find_i2pd
    say "Starting a private I2P router with SAM in $DATA/i2pd"
    start_router "$DATA/i2pd" "$PORT_BASE" 1
    SAM=$ROUTER_SAM
    PROXY="http://127.0.0.1:$ROUTER_PROXY"
    wait_for 30 nc -z 127.0.0.1 "$SAM" || die "the router's SAM didn't come up; see $DATA/i2pd/i2pd.log"
fi

say "Mirroring $TARGET"
echo "A new router takes a few minutes to join I2P; until then the node keeps retrying."
[ "$OWN_ROUTER" = 1 ] && echo "Router log: $DATA/i2pd/i2pd.log. Router console: http://127.0.0.1:$ROUTER_CONSOLE/"
echo "Press Ctrl-C to stop."
echo
"$BIN/anathemic-node" --home "$DATA/anathemic" --sam "$SAM" --proxy "$PROXY" "${NODE_ARGS[@]}" "$TARGET" &
CHILDREN+=($!)

wait_all
