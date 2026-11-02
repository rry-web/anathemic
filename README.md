# Anathemic

Software for running **swarmboards**: forums on I2P where one operator runs the site and its
members mirror it. Text goes over I2P only. Media goes over I2P or clearnet BitTorrent, as each
board allows. Old pages are frozen, hashed and signed, so they survive the server going down.
No JavaScript, anywhere.

The plan is in [DESIGN.md](DESIGN.md). This is an early prototype of its first phase, the text
core:

- **The server** accepts signed posts and closes each board's epochs after a number of posts or
  a length of time. Once an epoch's moderation window is over, the server seals it into a hashed,
  signed bundle. It serves a signed manifest, the bundles and the posts over plain HTTP.
- **The client** checks every signature and the hash chain, keeps a separate member key for each
  site, pins each site's root key on first contact, caches sealed epochs, and posts. Boards show
  authors, hide them, or let posters choose.
- **Web pages** for reading a site in rynx or any other browser: the boards, each board's threads
  and each thread, in plain HTML with no JavaScript. The server draws them from its own records,
  so unlike the client they don't check signatures. Boards can also take anonymous posts from
  these pages, if the operator turns it on. No member signs those posts, so they're rate limited
  instead.

Not yet: mirroring between members, moderation, media, tags, a full
client UI.

## Trying it

```sh
cargo build --release

# A site, with one board where posters choose whether to show their key and browsers can post
target/release/anathemic-server --data mysite init --name "My Site"
target/release/anathemic-server --data mysite add-board general --title "General" --authors choice --web-posting
target/release/anathemic-server --data mysite serve      # on 127.0.0.1:8470

# On this computer, without I2P
target/release/anathemic-client --direct post http://127.0.0.1:8470 general --title "Hello" "First post"
target/release/anathemic-client --direct post http://127.0.0.1:8470 general --thread 1 --anonymous "A reply"
target/release/anathemic-client --direct read http://127.0.0.1:8470 general
target/release/anathemic-client --direct read http://127.0.0.1:8470 general --thread 1
```

Then open `http://127.0.0.1:8470/` in rynx (or any browser) to read the site.

For quick tests, `serve --epoch-posts 2 --window-seconds 10 --tick-seconds 1` seals epochs
within seconds. By default epochs close at 500 posts or 7 days, and seal 72 hours later.

`set-site` changes the site's name, its description (post markup, shown on the front page) and
the I2P addresses it answers at; `set-board general --web-posting off` stops browser posts. Both
work while the server runs. Web posts are limited to 30 an hour per board, and 6 from each I2P
destination (`serve --web-posts-per-hour`, `--web-posts-per-hour-each`).

`init` writes `root.key`, the site's identity. `serve` never reads it, so keep a copy offline.

### Over I2P

Publish the server with an i2pd server tunnel (in `tunnels.conf`):

```ini
[anathemic]
type = http
host = 127.0.0.1
port = 8470
keys = anathemic.dat
```

Clients reach it through the router's HTTP proxy, which they use by default
(`--proxy http://127.0.0.1:4444`):

```sh
anathemic-client read http://<the tunnel's address>.b32.i2p general
```

The site's address is that tunnel's `.b32.i2p` address (the router console lists it under
server tunnels), or a name such as `mysite.i2p` once registered with an address book such as
reg.i2p or stats.i2p. Put it in the manifest so clients and pages show it:

```sh
anathemic-server --data mysite set-site --address mysite.i2p --address <the tunnel's address>.b32.i2p
```

The web pages make the site an ordinary eepsite: rynx reads the same address through the router,
in I2P mode, and can post on boards with web posting on.

## License

AGPL-3.0-or-later.
