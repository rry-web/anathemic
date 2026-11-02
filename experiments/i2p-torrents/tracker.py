"""A minimal I2P BitTorrent tracker, as the operator's server could run: peers are I2P
destinations, taken from the i2pd tunnel's X-I2P-DestB64 header when present."""
import http.server, urllib.parse, time, sys, base64, hashlib

peers = {}  # info_hash -> {dest: last_seen}

def bencode(v):
    if isinstance(v, int): return b"i%de" % v
    if isinstance(v, str): v = v.encode()
    if isinstance(v, bytes): return b"%d:%s" % (len(v), v)
    if isinstance(v, list): return b"l" + b"".join(map(bencode, v)) + b"e"
    if isinstance(v, dict): return b"d" + b"".join(bencode(k) + bencode(v[k]) for k in sorted(v)) + b"e"

class Tracker(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query, keep_blank_values=True, encoding="latin-1")
        ih = q.get("info_hash", [""])[0].encode("latin-1")
        dest = self.headers.get("X-I2P-DestB64")
        dest = dest + ".i2p" if dest else q.get("ip", [""])[0]
        now = time.time()
        swarm = peers.setdefault(ih, {})
        if q.get("event", [""])[0] == "stopped": swarm.pop(dest, None)
        elif dest: swarm[dest] = now
        for d in [d for d, t in swarm.items() if now - t > 3600]: del swarm[d]
        others = [d for d in swarm if d != dest]
        if q.get("compact", ["0"])[0] == "1":
            # I2P's compact form: the SHA-256 of each destination, which is its .b32.i2p address
            raw = lambda d: base64.b64decode(d[:-4].replace("-", "+").replace("~", "/") + "==")
            peers_value = b"".join(hashlib.sha256(raw(d)).digest() for d in others)
        else:
            peers_value = [{"ip": d, "port": 6881} for d in others]
        print(f"announce {ih.hex()[:12]} from {dest[:16]}… -> {len(others)} peers", flush=True)
        body = bencode({"interval": 120, "peers": peers_value})
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Tracker).serve_forever()
