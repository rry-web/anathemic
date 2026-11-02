# BitTorrent over I2P: which library?

Tests run on 2026-11-02 to choose how Anathemic shares sealed epochs between mirrors (build
phase 2). Each one moves an 8 MB file (a stand-in for a sealed epoch) between two I2P
destinations on one i2pd 3.0.0 router, with 3-hop tunnels, through its SAM bridge.

## What was tried

| Route | Language | How peers find each other | Result |
|---|---|---|---|
| **libtorrent 2.1** (what qBittorrent uses), its own I2P support | C++ (tested through its Python bindings) | I2P trackers only: no I2P DHT or PEX yet ([libtorrent#7408](https://github.com/arvidn/libtorrent/issues/7408)) | Works |
| **librqbit 9.1**, through a SAM bridge written with `yosemite` | Rust | Our code announces to the tracker and gives librqbit a local port for each I2P peer | Works, with tuning needed |
| **Plain SAM streams** (`yosemite`), no BitTorrent | Rust | The other side's destination | The baseline: what one I2P stream can carry |

Public I2P trackers were unreliable from a fresh router: tracker2.postman.i2p accepts only
torrents registered with it, opentracker.skank.i2p timed out, and opentracker.dg2.i2p closed
connections. A tracker of our own, about 50 lines of Python behind an i2pd HTTP server tunnel
(`tracker.py`), worked on its first announce. It takes each peer's destination from the
tunnel's `X-I2P-DestB64` header, so nobody can announce someone else. libtorrent wants I2P
peers in compact form: the SHA-256 of each destination, which is the 32 bytes behind its
`.b32.i2p` address.

## Results

Rates are after the first byte arrived; the start is how long that took. One seeder each time,
over about an hour as the router warmed up.

| Route | Runs | Rate (KB/s) | Start |
|---|---|---|---|
| libtorrent → libtorrent | 4 | 215, 31, 100, 36 | 29–82 s (new sessions, then the first announce) |
| librqbit (bridge) ← libtorrent | 3 of 4 (one stalled) | 454, 160, 215 | 12 s, then 148 s and 131 s |
| Plain SAM stream, one | 3 | 120, 129, 111 | first connect 0.6–17 s; round trips 1.1–2.5 s |
| Plain SAM streams, four at once to one peer | 3 | 80, 99, 76 (together) | |

What they show:

- **Speeds match DESIGN.md's estimates:** 100–300 KB/s from one peer, varying a lot from
  minute to minute. An 8 MB epoch takes 20 s to 4 minutes from a single seeder.
- **More streams to one peer don't help** (four streams together were slower than one), so
  speed has to come from more peers. That is what the seeding quota buys.
- **Starting is slow:** new SAM sessions take 10–60 s to build tunnels. Nodes should keep one
  long-lived session with a saved destination key, not start one per download.
- **librqbit's slow starts were the bridge's fault, not librqbit's.** The test bridge connects to
  one peer at a time under a lock, so a dead peer the tracker still lists (left over from an
  earlier run) holds up the live one until SAM gives up on it. The stalled run was librqbit's
  clearnet timeouts closing slow I2P connections. Both are fixable: connect in parallel, and set
  librqbit's `PeerConnectionOptions` timeouts to I2P's pace.
- Both ends ran on one router, but traffic still went through full tunnels (the 1–2 s round
  trips show it), so this is close to two routers.

## Recommendation

1. **The operator's server is the tracker.** It already serves HTTP inside I2P; the tunnel's
   `X-I2P-DestB64` header tells it each peer's destination, and the compact reply is what
   libtorrent, I2PSnark and qBittorrent expect. Trackers are needed anyway while libtorrent has
   no I2P DHT, and public ones can't be relied on. Mirrors could run trackers too, for when the
   server is down.
2. **Each sealed epoch is a standard v1 torrent,** its info hash listed in the manifest beside
   the bundle's SHA-256. Members can then seed with clients they already have (qBittorrent,
   I2PSnark, BiglyBT), not only Anathemic's.
3. **`anathemic-node` uses librqbit with a SAM bridge built on `yosemite`.** That keeps
   everything in Rust, so it builds for the Pi and the glasses like rynx does, and it was the
   fastest here once data flowed. The bridge needs parallel connects, a way in for seeding (SAM
   accepts forwarded to librqbit's listening port), I2P-paced timeouts, and DHT and local
   discovery switched off. [rqbit#361](https://github.com/ikatson/rqbit/issues/361) asks for
   I2P upstream, and someone has done the same bridge in
   [YGGverse/btracker](https://github.com/YGGverse/btracker/tree/main/crates/crawler), so it
   could become a contribution to librqbit.
4. **libtorrent stays the reference** to test against, because qBittorrent members will use
   it. It isn't the node's library: its Rust bindings are thin and it's a large C++ build.

## Running them

```sh
i2pd --datadir=<dir> --conf=i2pd.conf   # SAM on 7666; tunnels.conf in <dir> publishes the tracker
python3 tracker.py 8475                 # then read the tracker's .b32.i2p address off the console
python3 -m venv venv && venv/bin/pip install libtorrent==2.1.1
TRACKERS="http://<tracker>.b32.i2p/announce" venv/bin/python lt_test.py 7666 8388608 3
venv/bin/python lt_seed.py 7666 8388608 http://<tracker>.b32.i2p/announce   # writes seed.torrent
(cd rqtest && cargo run --release -- 7666 ../seed.torrent <tracker>.b32.i2p <output dir>)
(cd samtest && cargo run --release -- 7666 3 4 4)
```
