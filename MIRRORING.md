# Mirroring a site

A mirror keeps a full copy of an Anathemic site and shares it, so the site stays readable while
its operator is offline. Mirrors can't change anything: every post is signed by the site, and
readers check those signatures themselves, so a mirror can at worst be out of date.

What a mirror does:

- keeps every sealed epoch of the site, and shares them with other mirrors as torrents inside I2P;
- serves the site read-only at its own I2P address, as web pages (for rynx and other browsers)
  and as data for the anathemic client, which falls back on mirrors when the server is down;
- takes the server's copy of an epoch only if no other mirror has it.

It needs very little: a few MB of disk for a small site, a little bandwidth, and a computer that
stays on. A Raspberry Pi is plenty.

## What you need

1. **An I2P router with SAM on.** i2pd is the one tested:

   ```sh
   brew install i2pd          # macOS
   sudo apt install i2pd      # Debian, Ubuntu, Raspberry Pi OS
   ```

   In `i2pd.conf` (`/etc/i2pd/i2pd.conf` on Linux, or the data folder i2pd prints at start),
   make sure SAM is on, and while you're there, let it relay for others, which keeps I2P fast:

   ```ini
   bandwidth = O    # or a number in KB/s
   share = 80
   [sam]
   enabled = true
   ```

   Then start it (`brew services start i2pd`, or `sudo systemctl enable --now i2pd`). A new
   router needs a few minutes to join the network.

2. **The node**, built with Rust (from [rustup.rs](https://rustup.rs)):

   ```sh
   cargo install --path node     # in a copy of this repository; installs anathemic-node
   ```

3. **The site's share link**, from the operator or any member. It looks like
   `anathemic:forum.i2p?root=…&mirror=….b32.i2p`. The footer of every page of the site shows
   one, and `anathemic-client share <site address>` prints one.

   The link names the site's root key, its identity. Get it from someone you trust, or check
   the key's fingerprint with the operator: everything the node accepts is checked against it.

## Running it

```sh
anathemic-node 'anathemic:forum.i2p?root=…&mirror=…'
```

It prints its own I2P address. The site's pages are readable there right away, in rynx or any
I2P browser, and the site's server lists the node as a mirror once it seeds. For example:

```
Mirroring Forum (root key 3875-df5c-e750)
This node's I2P address for the site, where it also serves it read-only: jmov….b32.i2p
Read the mirror in a browser such as rynx at http://jmov….b32.i2p/
general-0.zst: looking for other nodes that have it
general-0.zst: got it from other nodes in 44s (12 KB/s); seeding it
```

The node keeps everything in `~/.anathemic` (`--home` to change it): the copy of the site, its
I2P key for the site, and the mirrors it knows of. Stop and start it as you like; it picks up
where it left off. If it can't reach the server or any mirror at first, it keeps trying.

Useful options: `--sam` if SAM isn't on port 7656, `--board` to mirror only some boards, and
`-v` to see each connection.

### Keeping it running

On Linux, a systemd unit (`/etc/systemd/system/anathemic-node.service`):

```ini
[Unit]
Description=Anathemic mirror
After=i2pd.service
Wants=i2pd.service

[Service]
User=anathemic
ExecStart=/usr/local/bin/anathemic-node 'anathemic:forum.i2p?root=…'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Then `sudo systemctl enable --now anathemic-node` and `journalctl -u anathemic-node -f` to
watch it.

On macOS, `brew services` doesn't run your own programs, so the simplest way is a terminal left
open, or a launchd agent in `~/Library/LaunchAgents` running the same command with
`KeepAlive` set.

## Privacy

- Everything goes over I2P. The node never opens a clearnet connection, even to peers other
  BitTorrent clients suggest.
- The node uses its own I2P address for each site it mirrors, so sites can't tell that the same
  person mirrors both.
- The site's tracker, and anyone who asks it, can see that the node's address holds the site.
  That address isn't linked to your computer or to any member key.

## When the operator is away

Nothing changes for a mirror. Readers who have used the site before (or who have a share link)
fall back on mirrors when the server doesn't answer, and see the site as it was when the server
last published. New posts wait for the server to come back: mirrors are read-only.

If the operator trusts you to keep the site taking posts too, they can make you a trusted
host instead: see "Trusted hosts" in the README. A host runs `anathemic-server`, not the node.

Pass the share link on: the more mirrors, the safer the site.
