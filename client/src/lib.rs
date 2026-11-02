//! Fetching and checking a swarmboard, and posting to it.
//!
//! Every manifest, epoch and post is verified before it's used. The site's root key is pinned
//! on first contact, like an SSH host key. What the client reads is kept in a local cache (the
//! signed manifest, sealed epochs, and the posts of epochs still open), which a node serves to
//! others as a mirror. When the server can't be reached, the client reads from the site's
//! mirrors instead, trusting nothing they send that doesn't check out.

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime},
};

use anathemic_core::{
    Content, Context, Manifest, Post, PublicKey, SecretKey, Signed, Submission, cbor,
    epoch::{check_epoch, check_order, check_post, link, open_bundle},
    i2p,
    link::{Link, MAX_LINK_MIRRORS},
    moderation::{self, Logged, Moderation, Revocation},
    now, valid_board_name,
    verify::{self, Verified},
};
use anyhow::{Context as _, anyhow, bail};

const SITES: &str = "sites.txt";
/// The signed manifest last read, in a site's cache folder
pub const MANIFEST_FILE: &str = "manifest.cbor";
/// The site's revocation log, as far as it's been read
pub const LOG_FILE: &str = "revocations.cbor";
/// A site's mirrors are asked for at most this often
const MIRRORS_REFRESH: Duration = Duration::from_secs(60 * 60);
const MAX_MIRRORS: usize = 50;
/// When the server is down, the newest manifest of this many mirrors is taken
const MIRRORS_ASKED: usize = 3;
/// Larger responses are refused
const MAX_RESPONSE: u64 = 300 << 20;

/// Your member key for the site with this root key, made on first use. Each site gets its own,
/// so sites can't link your posts to each other.
pub fn member_key(home: &Path, root: &PublicKey) -> anyhow::Result<(SecretKey, bool)> {
    let path = home.join("keys").join(format!("{}.key", root.to_hex()));
    if path.exists() {
        return Ok((SecretKey::from_bytes(&fs::read(&path)?)?, false));
    }
    fs::create_dir_all(path.parent().expect("key files are in a folder"))?;
    let key = SecretKey::generate();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(&path)?, &key.to_bytes())?;
    Ok((key, true))
}

/// The folder a site's sealed epochs are kept in, which a node seeds from
pub fn cache_dir(home: &Path, root: &PublicKey) -> PathBuf {
    home.join("cache").join(root.to_hex())
}

/// Where a sealed epoch is kept: named as in its torrent, so a node can seed the same file
pub fn cache_path(home: &Path, root: &PublicKey, board: &str, epoch: u64) -> PathBuf {
    debug_assert!(valid_board_name(board));
    cache_dir(home, root).join(anathemic_core::torrent::file_name(board, epoch))
}

/// Where the posts of an epoch that isn't sealed yet are kept, as the server signed them
pub fn posts_path(home: &Path, root: &PublicKey, board: &str, epoch: u64) -> PathBuf {
    debug_assert!(valid_board_name(board));
    cache_dir(home, root).join(format!("{board}-{epoch}.posts"))
}

/// The site's mirrors this client knows of, as base URLs
pub fn mirrors_path(home: &Path, root: &PublicKey) -> PathBuf {
    home.join("mirrors").join(format!("{}.txt", root.to_hex()))
}

pub fn load_mirrors(home: &Path, root: &PublicKey) -> Vec<String> {
    fs::read_to_string(mirrors_path(home, root))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// A site as this computer holds it, every signature checked
pub struct Cached {
    pub site: Verified,
    pub boards: Vec<CachedBoard>,
    /// From the log held, if it matches the manifest
    pub moderation: Moderation,
}

pub struct CachedBoard {
    pub name: String,
    /// Oldest first
    pub posts: Vec<Post>,
    /// Epochs not held, or held but not matching the manifest
    pub missing: Vec<u64>,
}

/// Reads a site from the cache alone: the last manifest read, and whatever epochs are held
pub fn read_cache(home: &Path, root: &PublicKey) -> anyhow::Result<Cached> {
    let bytes = fs::read(cache_dir(home, root).join(MANIFEST_FILE)).context("no copy of this site's manifest is held")?;
    let site = verify::manifest(&cbor::from_slice(&bytes)?, Some(root))?;
    let moderation = read_log(home, &site).unwrap_or_default();
    let mut boards = Vec::new();
    for board in &site.manifest.boards {
        let mut posts = Vec::new();
        let mut missing = Vec::new();
        let mut prev = None;
        for sealed in &board.sealed {
            let checked = fs::read(cache_path(home, root, &board.name, sealed.epoch))
                .ok()
                .and_then(|bundle| open_bundle(&bundle, sealed).ok())
                .and_then(|epoch| check_epoch(&epoch, &board.name, sealed.epoch, prev, sealed.index, &site.keys).ok());
            match checked {
                Some(checked) => posts.extend(checked),
                None => missing.push(sealed.epoch),
            }
            prev = Some(link(sealed));
        }
        for &number in &board.unsealed {
            let checked = fs::read(posts_path(home, root, &board.name, number))
                .ok()
                .and_then(|bytes| cbor::from_slice::<Vec<Signed<Post>>>(&bytes).ok())
                .and_then(|signed| {
                    signed.iter().map(|post| check_post(post, &site.keys, &board.name, number)).collect::<Result<Vec<_>, _>>().ok()
                });
            match checked {
                Some(checked) => posts.extend(checked),
                None => missing.push(number),
            }
        }
        posts.sort_by_key(|post| post.number);
        posts.dedup_by_key(|post| post.number);
        // Posts purged since they were cached
        posts.retain(|post| !moderation.is_purged(&board.name, post.number));
        boards.push(CachedBoard { name: board.name.clone(), posts, missing });
    }
    Ok(Cached { site, boards, moderation })
}

/// The cached log, added up, if it's the whole log the manifest names
fn read_log(home: &Path, site: &Verified) -> anyhow::Result<Moderation> {
    let bytes = fs::read(cache_dir(home, &site.manifest.root).join(LOG_FILE))?;
    let log: Vec<Signed<Logged>> = cbor::from_slice(&bytes)?;
    Ok(moderation::replay(&log, &site.manifest.revocations, &site.keys, &site.moderators)?)
}

pub struct Client {
    agent: ureq::Agent,
    base: String,
    home: PathBuf,
    /// The mirror being read from, while the server can't be reached
    mirror: Mutex<Option<String>>,
}

enum Got {
    Body(Vec<u8>),
    /// The server (or mirror) couldn't be reached, as opposed to refusing
    Unreachable(String),
}

/// Why the site couldn't be reached at all, as opposed to refusing a request. i2pd's HTTP proxy
/// answers with a page headed "Proxy error" (status 500 for "Host is down") when it can't reach
/// a destination; the server's own errors have no such page.
fn unreachable(error: ureq::Error) -> Result<String, anyhow::Error> {
    match error {
        ureq::Error::Transport(transport) => Ok(transport.to_string()),
        ureq::Error::Status(code, response) => {
            let body = response.into_string().unwrap_or_default();
            let proxy_error = body.split("<h1>").nth(1).and_then(|h| h.split("</h1>").next()).filter(|h| h.starts_with("Proxy error"));
            match proxy_error {
                Some(heading) => Ok(heading.to_string()),
                None if (502..=504).contains(&code) => Ok(format!("status {code}")),
                None => Err(refusal(code, &body)),
            }
        }
    }
}

impl Client {
    /// `server` is the site's address as a URL, or a share link (`anathemic:…`), which pins
    /// its root key and remembers its mirrors. `proxy` is the I2P router's HTTP proxy, such as
    /// `http://127.0.0.1:4444`.
    pub fn new(server: &str, proxy: Option<&str>, home: PathBuf) -> anyhow::Result<Client> {
        let mut builder = ureq::AgentBuilder::new().user_agent("anathemic");
        if let Some(proxy) = proxy {
            builder = builder.proxy(ureq::Proxy::new(proxy)?);
        }
        let mut client =
            Client { agent: builder.build(), base: server.trim_end_matches('/').to_string(), home, mirror: Mutex::new(None) };
        if server.starts_with(anathemic_core::link::SCHEME) {
            client.join(&Link::parse(server)?)?;
        }
        Ok(client)
    }

    /// Takes on a share link: its address, its root key pinned (unless a different one already
    /// is), and its mirrors remembered
    fn join(&mut self, link: &Link) -> anyhow::Result<()> {
        self.base = link.base();
        let mut sites = self.load_sites()?;
        match sites.get(&self.base) {
            Some(pin) if pin.root != link.root => bail!(
                "{} is pinned to root key {}, not the link's {}",
                self.base,
                pin.root.fingerprint(),
                link.root.fingerprint()
            ),
            Some(_) => {}
            None => {
                sites.insert(self.base.clone(), Pin { root: link.root, sequence: 0, term: 0, hosts: 0 });
                self.save_sites(&sites)?;
            }
        }
        let mut mirrors: Vec<String> = link.mirrors.iter().map(|host| format!("http://{host}")).collect();
        for old in load_mirrors(&self.home, &link.root) {
            if !mirrors.contains(&old) {
                mirrors.push(old);
            }
        }
        mirrors.truncate(MAX_MIRRORS);
        let path = mirrors_path(&self.home, &link.root);
        fs::create_dir_all(path.parent().expect("in a folder"))?;
        // Written fresh only if new; an untouched file still tells when mirrors were last asked for
        if load_mirrors(&self.home, &link.root) != mirrors {
            fs::write(&path, mirrors.iter().map(|m| format!("{m}\n")).collect::<String>())?;
        }
        Ok(())
    }

    /// A link to pass on, so someone else can read or mirror the site: its preferred address,
    /// root key, and the mirrors this client knows of
    pub fn share_link(&self, site: &Verified) -> Link {
        let address = site.manifest.addresses.first().cloned().unwrap_or_else(|| self.base.trim_start_matches("http://").to_string());
        let mirrors = load_mirrors(&self.home, &site.manifest.root)
            .iter()
            .map(|m| m.trim_start_matches("http://").to_string())
            .filter(|host| i2p::b32_hash(host).is_some())
            .take(MAX_LINK_MIRRORS)
            .collect();
        Link { address, root: site.manifest.root, mirrors }
    }

    fn fetch(&self, base: &str, path: &str) -> anyhow::Result<Got> {
        match self.agent.get(&format!("{base}{path}")).call() {
            Ok(response) => Ok(Got::Body(read_body(response)?)),
            Err(e) => unreachable(e).map(Got::Unreachable),
        }
    }

    /// From the server, or from the mirror the manifest came from while the server is down
    fn get(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let base = self.source().unwrap_or_else(|| self.base.clone());
        match self.fetch(&base, path)? {
            Got::Body(body) => Ok(body),
            Got::Unreachable(why) => bail!("can't reach {base}: {why}"),
        }
    }

    /// The mirror being read from, if the server couldn't be reached
    pub fn source(&self) -> Option<String> {
        self.mirror.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// The site's manifest, verified, checked against the pinned root key and never older
    /// than one seen before. If the server can't be reached, the newest of its mirrors'.
    pub fn manifest(&self) -> anyhow::Result<Verified> {
        let mut sites = self.load_sites()?;
        let pinned = sites.get(&self.base).copied();
        let (verified, bytes, mirror) = match self.fetch(&self.base, "/manifest")? {
            Got::Body(bytes) => {
                let verified = check_manifest(&bytes, pinned).with_context(|| format!("checking {}'s manifest", self.base))?;
                (verified, bytes, None)
            }
            Got::Unreachable(why) => {
                let Some(Pin { root, .. }) = pinned else {
                    bail!("can't reach {} ({why}), and as it's never been reached, no mirrors are known", self.base);
                };
                self.manifest_from_mirrors(&root, pinned)
                    .with_context(|| format!("can't reach {} ({why})", self.base))?
            }
        };
        let root = verified.manifest.root;
        sites.insert(self.base.clone(), Pin::of(&verified));
        self.save_sites(&sites)?;
        let folder = cache_dir(&self.home, &root);
        fs::create_dir_all(&folder)?;
        fs::write(folder.join(MANIFEST_FILE), &bytes)?;
        let from_server = mirror.is_none();
        *self.mirror.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = mirror;
        if from_server {
            // Mirrors are only a fallback; not hearing of new ones isn't an error
            let _ = self.refresh_mirrors(&root, false);
        }
        Ok(verified)
    }

    /// Where to turn when the server doesn't answer: the site's trusted hosts at their own
    /// addresses (from the last manifest held), which can take posts too, then its mirrors
    fn fallbacks(&self, root: &PublicKey) -> Vec<String> {
        let held = fs::read(cache_dir(&self.home, root).join(MANIFEST_FILE))
            .ok()
            .and_then(|bytes| cbor::from_slice::<Signed<Manifest>>(&bytes).ok())
            .and_then(|signed| signed.peek().ok())
            .and_then(|manifest| manifest.hosts)
            .and_then(|hosts| hosts.peek().ok());
        let mut out: Vec<String> = held
            .map(|hosts| hosts.hosts.into_iter().filter(|host| !host.retired).map(|host| format!("http://{}", host.address)).collect())
            .unwrap_or_default();
        out.retain(|base| *base != self.base);
        for mirror in load_mirrors(&self.home, root) {
            if !out.contains(&mirror) {
                out.push(mirror);
            }
        }
        out
    }

    /// The newest manifest from the first few hosts or mirrors that answer with a good one
    fn manifest_from_mirrors(&self, root: &PublicKey, pinned: Option<Pin>) -> anyhow::Result<(Verified, Vec<u8>, Option<String>)> {
        let mirrors = self.fallbacks(root);
        let mut best: Option<(Verified, Vec<u8>, String)> = None;
        let mut answered = 0;
        for mirror in &mirrors {
            let Ok(Got::Body(bytes)) = self.fetch(mirror, "/manifest") else { continue };
            let Ok(verified) = check_manifest(&bytes, pinned) else { continue };
            answered += 1;
            if best.as_ref().is_none_or(|(b, _, _)| newer(&verified, b)) {
                best = Some((verified, bytes, mirror.clone()));
            }
            if answered >= MIRRORS_ASKED {
                break;
            }
        }
        match best {
            Some((verified, bytes, mirror)) => Ok((verified, bytes, Some(mirror))),
            None if mirrors.is_empty() => bail!("no mirrors or other hosts of it are known"),
            None => bail!("none of its {} known hosts and mirrors gave a good manifest", mirrors.len()),
        }
    }

    /// Asks the server which nodes mirror the site, and remembers them: at most hourly, unless
    /// `now`, and until it has heard of some
    pub fn refresh_mirrors(&self, root: &PublicKey, now: bool) -> anyhow::Result<()> {
        let path = mirrors_path(&self.home, root);
        let fresh = fs::metadata(&path)
            .and_then(|meta| meta.modified())
            .is_ok_and(|modified| SystemTime::now().duration_since(modified).unwrap_or_default() < MIRRORS_REFRESH);
        if (fresh && !now) || self.source().is_some() {
            return Ok(());
        }
        let Got::Body(body) = self.fetch(&self.base, "/mirrors")? else { return Ok(()) };
        let listed = String::from_utf8_lossy(&body)
            .lines()
            .map(str::trim)
            .filter(|host| i2p::b32_hash(host).is_some())
            .map(|host| format!("http://{host}"))
            .collect::<Vec<_>>();
        // Newly listed first, then ones heard of before, which may only be offline for now
        let mut mirrors = listed;
        for old in load_mirrors(&self.home, root) {
            if !mirrors.contains(&old) {
                mirrors.push(old);
            }
        }
        mirrors.truncate(MAX_MIRRORS);
        // Hearing of none isn't worth waiting an hour to ask again
        if mirrors.is_empty() {
            return Ok(());
        }
        fs::create_dir_all(path.parent().expect("in a folder"))?;
        fs::write(&path, mirrors.iter().map(|m| format!("{m}\n")).collect::<String>())?;
        Ok(())
    }

    /// Every post on a board, oldest first, with sealed epochs read from the cache when it has them
    pub fn board_posts(&self, site: &Verified, board: &str) -> anyhow::Result<Vec<Post>> {
        let entry = site.manifest.board(board).ok_or_else(|| anyhow!("there's no board /{board}/"))?;
        let mut posts = Vec::new();
        let mut prev = None;
        for sealed in &entry.sealed {
            let cached = self.cache_path(&site.manifest.root, board, sealed.epoch);
            let bundle = match fs::read(&cached) {
                Ok(bundle) if open_bundle(&bundle, sealed).is_ok() => bundle,
                _ => {
                    let bundle = self.fetch_bundle(board, sealed.epoch)?;
                    fs::create_dir_all(cached.parent().expect("cache files are in a folder"))?;
                    fs::write(&cached, &bundle)?;
                    bundle
                }
            };
            let epoch = open_bundle(&bundle, sealed)?;
            posts.extend(check_epoch(&epoch, board, sealed.epoch, prev, sealed.index, &site.keys)?);
            prev = Some(link(sealed));
        }
        posts.extend(self.unsealed_posts(site, board)?);
        check_order(&posts)?;
        Ok(posts)
    }

    /// The posts of a board's epochs that aren't sealed yet, checked and kept for mirroring
    pub fn unsealed_posts(&self, site: &Verified, board: &str) -> anyhow::Result<Vec<Post>> {
        let entry = site.manifest.board(board).ok_or_else(|| anyhow!("there's no board /{board}/"))?;
        let mut posts = Vec::new();
        for &number in &entry.unsealed {
            let bytes = self.get(&format!("/boards/{board}/epochs/{number}/posts"))?;
            let signed: Vec<Signed<Post>> = cbor::from_slice(&bytes)?;
            for post in &signed {
                posts.push(check_post(post, &site.keys, board, number)?);
            }
            fs::write(posts_path(&self.home, &site.manifest.root, board, number), &bytes)?;
        }
        Ok(posts)
    }

    pub fn submit(&self, key: &SecretKey, board: &str, content: Content, anonymous: bool) -> anyhow::Result<Post> {
        let site = self.manifest()?;
        content.check()?;
        let submission = Submission { board: board.to_string(), content, anonymous, time: now() };
        let signed = key.sign(Context::Submission, &submission);
        let response = self
            .agent
            .post(&format!("{}/boards/{board}/posts", self.source().unwrap_or_else(|| self.base.clone())))
            .set("Content-Type", "application/cbor")
            .send_bytes(&cbor::to_vec(&signed))
            .map_err(describe)?;
        let record: Signed<Post> = cbor::from_slice(&read_body(response)?)?;
        let post = check_post(&record, &site.keys, board, record.peek()?.epoch)?;
        if post.content != submission.content {
            bail!("the server changed the post");
        }
        Ok(post)
    }

    pub fn cache_path(&self, root: &PublicKey, board: &str, epoch: u64) -> PathBuf {
        cache_path(&self.home, root, board, epoch)
    }

    /// The server's address, as given
    pub fn base(&self) -> &str {
        &self.base
    }

    /// What moderators have hidden, purged and banned: the site's revocation log, read on from
    /// where the cached copy ends and checked against the manifest
    pub fn moderation(&self, site: &Verified) -> anyhow::Result<Moderation> {
        let path = cache_dir(&self.home, &site.manifest.root).join(LOG_FILE);
        let mut log: Vec<Signed<Logged>> = fs::read(&path).ok().and_then(|bytes| cbor::from_slice(&bytes).ok()).unwrap_or_default();
        let wanted = site.manifest.revocations.count;
        // A longer copy than the manifest names came from an older log
        if log.len() as u64 > wanted {
            log.clear();
        }
        self.read_rest_of_log(&mut log, wanted)?;
        let moderation = match moderation::replay(&log, &site.manifest.revocations, &site.keys, &site.moderators) {
            Ok(moderation) => moderation,
            Err(_) => {
                // The cached part may be from an older log too; read the whole of it again
                log.clear();
                self.read_rest_of_log(&mut log, wanted)?;
                moderation::replay(&log, &site.manifest.revocations, &site.keys, &site.moderators)?
            }
        };
        fs::write(&path, cbor::to_vec(&log))?;
        Ok(moderation)
    }

    fn read_rest_of_log(&self, log: &mut Vec<Signed<Logged>>, wanted: u64) -> anyhow::Result<()> {
        while (log.len() as u64) < wanted {
            let page: Vec<Signed<Logged>> = cbor::from_slice(&self.get(&format!("/revocations?from={}", log.len()))?)?;
            if page.is_empty() {
                bail!("the revocation log ends early");
            }
            log.extend(page);
        }
        log.truncate(wanted as usize);
        Ok(())
    }

    /// Sends a moderator's decision, signed with their member key; returns it as logged
    pub fn moderate(&self, key: &SecretKey, revocation: Revocation) -> anyhow::Result<Logged> {
        let site = self.manifest()?;
        let signed = key.sign(Context::Revocation, &revocation);
        let base = self.source().unwrap_or_else(|| self.base.clone());
        let response = self
            .agent
            .post(&format!("{base}/revocations"))
            .set("Content-Type", "application/cbor")
            .send_bytes(&cbor::to_vec(&signed))
            .map_err(describe)?;
        let logged: Signed<Logged> = cbor::from_slice(&read_body(response)?)?;
        if !site.keys.contains(&logged.signer) {
            bail!("the entry came back signed by a key that isn't the site's");
        }
        Ok(logged.open(Context::Logged, None)?)
    }

    /// A sealed epoch's torrent file, from the server
    pub fn fetch_torrent(&self, board: &str, epoch: u64) -> anyhow::Result<Vec<u8>> {
        self.get(&format!("/boards/{board}/epochs/{epoch}/torrent"))
    }

    /// A sealed epoch's bundle, from the server
    pub fn fetch_bundle(&self, board: &str, epoch: u64) -> anyhow::Result<Vec<u8>> {
        self.get(&format!("/boards/{board}/epochs/{epoch}"))
    }

    /// Server address → what's pinned for it
    fn load_sites(&self) -> anyhow::Result<HashMap<String, Pin>> {
        let text = match fs::read_to_string(self.home.join(SITES)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e.into()),
        };
        let mut sites = HashMap::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let mut fields = line.split_whitespace();
            let (Some(base), Some(root), Some(sequence)) = (fields.next(), fields.next(), fields.next()) else {
                bail!("{} has a line it can't read: {line}", SITES);
            };
            // Term and host list sequence came later; lines written before have neither
            let term = fields.next().map(str::parse).transpose()?.unwrap_or(0);
            let hosts = fields.next().map(str::parse).transpose()?.unwrap_or(0);
            sites.insert(base.to_string(), Pin { root: PublicKey::from_hex(root)?, sequence: sequence.parse()?, term, hosts });
        }
        Ok(sites)
    }

    fn save_sites(&self, sites: &HashMap<String, Pin>) -> anyhow::Result<()> {
        let mut lines: Vec<String> = sites
            .iter()
            .map(|(base, pin)| format!("{base} {} {} {} {}\n", pin.root.to_hex(), pin.sequence, pin.term, pin.hosts))
            .collect();
        lines.sort();
        fs::create_dir_all(&self.home)?;
        fs::write(self.home.join(SITES), lines.concat())?;
        Ok(())
    }
}

/// What a client holds to for a site: its root key, and how new a manifest it has seen
#[derive(Clone, Copy, Debug)]
pub struct Pin {
    pub root: PublicKey,
    pub sequence: u64,
    pub term: u64,
    /// The sequence of the newest host list seen
    pub hosts: u64,
}

impl Pin {
    fn of(verified: &Verified) -> Pin {
        let manifest = &verified.manifest;
        Pin { root: manifest.root, sequence: manifest.sequence, term: manifest.term, hosts: verified.hosts_sequence }
    }
}

/// Whether one manifest is newer than another: a later term wins, then a higher sequence
fn newer(a: &Verified, b: &Verified) -> bool {
    (a.manifest.term, a.manifest.sequence) > (b.manifest.term, b.manifest.sequence)
}

/// A manifest's signatures, its root key against the pinned one, and how new it is against the
/// newest seen. An older host list is refused too, so a retired host can't carry on with one.
fn check_manifest(bytes: &[u8], pinned: Option<Pin>) -> anyhow::Result<Verified> {
    let signed: Signed<Manifest> = cbor::from_slice(bytes)?;
    let verified = verify::manifest(&signed, pinned.as_ref().map(|pin| &pin.root))?;
    if let Some(pin) = pinned {
        if (verified.manifest.term, verified.manifest.sequence) < (pin.term, pin.sequence) {
            bail!("it's older than a manifest already seen");
        }
        if verified.hosts_sequence < pin.hosts {
            bail!("its list of the site's servers is older than one already seen");
        }
    }
    Ok(verified)
}

fn read_body(response: ureq::Response) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    response.into_reader().take(MAX_RESPONSE + 1).read_to_end(&mut body)?;
    if body.len() as u64 > MAX_RESPONSE {
        bail!("the server's response is too large");
    }
    Ok(body)
}

/// Turns a refusal into the server's reason
fn describe(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(code, response) => refusal(code, &response.into_string().unwrap_or_default()),
        other => anyhow!(other),
    }
}

fn refusal(code: u16, reason: &str) -> anyhow::Error {
    match code {
        404 => anyhow!("not found"),
        _ => anyhow!("the server refused ({code}): {}", reason.trim()),
    }
}
