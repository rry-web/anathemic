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
| librqbit (bridge, connecting one peer at a time) ← libtorrent | 3 of 4 (one stalled) | 454, 160, 215 | 12 s, then 148 s and 131 s |
| librqbit (bridge, connecting in parallel) ← libtorrent | 4 of 4 | 108, 182, 46, 303 | 43 s, then 17, 14, 14 s, with 1–3 dead peers listed |
| librqbit (bridge in parallel, I2P-paced timeouts) ← libtorrent | 4 of 4 | 282, 409, 327, 170 | 24 s, then 9, 11, 11 s, with 1–3 dead peers listed |
| Plain SAM stream, one | 3 | 120, 129, 111 | first connect 0.6–17 s; round trips 1.1–2.5 s |
| Plain SAM streams, four at once to one peer | 3 | 80, 99, 76 (together) | |

What they show:

- **Speeds match DESIGN.md's estimates:** 100–300 KB/s from one peer, varying a lot from
  minute to minute. An 8 MB epoch takes 20 s to 4 minutes from a single seeder.
- **More streams to one peer don't help** (four streams together were slower than one), so
  speed has to come from more peers. That is what the seeding quota buys.
- **Starting is slow:** new SAM sessions take 10–60 s to build tunnels. Nodes should keep one
  long-lived session with a saved destination key, not start one per download.
- **librqbit's slow starts were the bridge's fault, not librqbit's.** The first bridge connected
  to one peer at a time under a lock, so a dead peer the tracker still listed (left over from an
  earlier run) held up the live one until SAM gave up on it. With connects in parallel
  (yosemite's `connect_detached`, holding the lock only to start each one, and a 60 s limit),
  the first byte came 14–17 s after the tracker replied, even with up to three dead peers
  listed. (Run 1's 43 s was the seeder's first connection on a newly started router.) Speed
  once data flowed didn't change: it is still whatever the tunnels give. - **librqbit's clearnet timeouts drop I2P peers.** By default it allows 10 s to connect and
  handshake and 10 s for each message, and sends keep-alives every 120 s, so a live I2P peer that
  pauses for a few seconds gets dropped. That caused the earlier stalled run. `rqtest` now sets
  `PeerConnectionOptions` on the torrent: 90 s to connect (longer than the bridge's 60 s SAM
  connect, which happens inside librqbit's handshake), 120 s per message, and keep-alives every
  30 s. With those settings the bridge opened each peer once per run. Before, it reopened the
  seeder two or three times per run as librqbit dropped it. All four runs finished, at an
  average of 297 KB/s against 160 KB/s before. That is only four runs on one router, and
  I2P speeds vary a lot, so treat the gain as likely rather than measured.
- i2pd's SAM can say a stream is open before the far end has answered, so "open" in the bridge
  log doesn't prove a peer is alive; dead peers either fail later (`CantReachPeer`) or just
  never send data.
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
   fastest here once data flowed. The bridge needs parallel connects and I2P-paced timeouts
   (both now in `rqtest`), a way in for seeding (SAM accepts forwarded to librqbit's listening
   port), and DHT and local discovery switched off. [rqbit#361](https://github.com/ikatson/rqbit/issues/361) asks for
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
