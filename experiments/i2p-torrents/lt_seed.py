"""Seed a random file over I2P with libtorrent until killed; writes seed.torrent."""
import os, sys, time, shutil
import libtorrent as lt
SAM_PORT, SIZE, TRACKER = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
base = os.path.dirname(os.path.abspath(__file__)); d = os.path.join(base, "seed2")
shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
with open(os.path.join(d, "epoch.bin"), "wb") as f: f.write(os.urandom(SIZE))
fs = lt.file_storage(); lt.add_files(fs, os.path.join(d, "epoch.bin"))
ct = lt.create_torrent(fs, 256 << 10, flags=lt.create_torrent.v1_only); ct.add_tracker(TRACKER)
lt.set_piece_hashes(ct, d)
data = lt.bencode(ct.generate()); open(os.path.join(base, "seed.torrent"), "wb").write(data)
ses = lt.session({"i2p_hostname": "127.0.0.1", "i2p_port": SAM_PORT, "listen_interfaces": "", "enable_dht": False,
                  "enable_lsd": False, "enable_upnp": False, "enable_natpmp": False, "anonymous_mode": True})
h = ses.add_torrent({"ti": lt.torrent_info(data), "save_path": d})
t0 = time.time()
while True:
    st = h.status()
    print(f"{time.time()-t0:6.0f}s {st.state} peers {st.num_peers} up {st.upload_rate/1024:.0f} KB/s total {st.total_upload>>10} KB", flush=True)
    time.sleep(15)
