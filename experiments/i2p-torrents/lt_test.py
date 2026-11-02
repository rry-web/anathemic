"""Seed a random file from one libtorrent session and fetch it from another, both I2P-only via SAM."""
import os, sys, time, shutil
import libtorrent as lt

SAM_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7666
SIZE = int(sys.argv[2]) if len(sys.argv) > 2 else 8 << 20
HOPS = int(sys.argv[3]) if len(sys.argv) > 3 else 3
base = os.path.dirname(os.path.abspath(__file__))
seed_dir, leech_dir = os.path.join(base, "seed"), os.path.join(base, "leech")
for d in (seed_dir, leech_dir):
    shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
with open(os.path.join(seed_dir, "epoch.bin"), "wb") as f:
    f.write(os.urandom(SIZE))

TRACKERS = os.environ["TRACKERS"].split() if os.environ.get("TRACKERS") else [
    "http://w7tpbzncbcocrqtwwm3nezhnnsw4ozadvi2hmvzdhrqzfxfum7wa.b32.i2p/a",   # opentracker.dg2.i2p
    "http://by7luzwhx733fhc5ug2o75dcaunblq2ztlshzd7qvptaoa73nqua.b32.i2p/a",   # opentracker.skank.i2p
    "http://6a4kxkg5wp33p25qqhgwl6sj4yh4xuf5b3p3qldwgclebchm3eea.b32.i2p/announce.php",  # tracker2.postman.i2p
]
fs = lt.file_storage(); lt.add_files(fs, os.path.join(seed_dir, "epoch.bin"))
ct = lt.create_torrent(fs, 256 << 10)
for i, t in enumerate(TRACKERS): ct.add_tracker(t, i)
lt.set_piece_hashes(ct, seed_dir)
info = lt.torrent_info(ct.generate())

def session(name):
    return lt.session({
        "i2p_hostname": "127.0.0.1", "i2p_port": SAM_PORT,
        "i2p_inbound_length": HOPS, "i2p_outbound_length": HOPS,
        "allow_i2p_mixed": False, "listen_interfaces": "", "enable_dht": False,
        "enable_lsd": False, "enable_upnp": False, "enable_natpmp": False,
        "anonymous_mode": True, "peer_fingerprint": name.encode(),
        "alert_mask": lt.alert.category_t.error_notification | lt.alert.category_t.tracker_notification
                      | lt.alert.category_t.status_notification | lt.alert.category_t.peer_notification,
    })

t0 = time.time()
def log(who, msg): print(f"{time.time()-t0:7.1f}s {who}: {msg}", flush=True)
seeder, leecher = session("seed"), session("leech")
hs = seeder.add_torrent({"ti": info, "save_path": seed_dir})
hl = leecher.add_torrent({"ti": lt.torrent_info(info), "save_path": leech_dir})
done_at = first_peer = None
while time.time() - t0 < 1200:
    for who, ses in (("seed", seeder), ("leech", leecher)):
        for a in ses.pop_alerts():
            if isinstance(a, (lt.tracker_error_alert, lt.tracker_reply_alert, lt.i2p_alert, lt.peer_connect_alert, lt.peer_error_alert, lt.torrent_error_alert)):
                log(who, a.message())
    st = hl.status()
    if first_peer is None and st.num_peers > 0:
        first_peer = time.time() - t0; log("leech", "first peer connected")
    if int(time.time() - t0) % 30 == 0:
        log("leech", f"{st.progress*100:5.1f}%  {st.download_rate/1024:6.1f} KB/s  peers {st.num_peers}  seeder state {hs.status().state}")
    if st.is_seeding:
        done_at = time.time() - t0; break
    time.sleep(1)
if done_at:
    xfer = done_at - first_peer
    print(f"RESULT size={SIZE} hops={HOPS} first_peer={first_peer:.1f}s complete={done_at:.1f}s transfer={xfer:.1f}s avg={SIZE/1024/max(xfer,0.1):.1f} KB/s")
else:
    print(f"RESULT timed out; progress {hl.status().progress*100:.1f}%")
