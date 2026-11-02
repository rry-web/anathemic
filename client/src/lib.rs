//! Fetching and checking a swarmboard, and posting to it.
//!
//! Every manifest, epoch and post is verified before it's used. The site's root key is pinned
//! on first contact, like an SSH host key, and sealed epochs are kept in a local cache, which
//! is the start of mirroring.

use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anathemic_core::{
    Content, Context, Manifest, Post, PublicKey, SecretKey, Signed, Submission, cbor,
    epoch::{check_epoch, check_order, check_post, open_bundle},
    now, valid_board_name,
    verify::{self, Verified},
};
use anyhow::{Context as _, anyhow, bail};

const SITES: &str = "sites.txt";
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

pub struct Client {
    agent: ureq::Agent,
    base: String,
    home: PathBuf,
}

impl Client {
    /// `proxy` is the I2P router's HTTP proxy, such as `http://127.0.0.1:4444`
    pub fn new(server: &str, proxy: Option<&str>, home: PathBuf) -> anyhow::Result<Client> {
        let mut builder = ureq::AgentBuilder::new().user_agent("anathemic");
        if let Some(proxy) = proxy {
            builder = builder.proxy(ureq::Proxy::new(proxy)?);
        }
        Ok(Client { agent: builder.build(), base: server.trim_end_matches('/').to_string(), home })
    }

    fn get(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let response = self.agent.get(&format!("{}{path}", self.base)).call().map_err(describe)?;
        read_body(response)
    }

    /// The site's manifest, verified, checked against the pinned root key and never older
    /// than one seen before
    pub fn manifest(&self) -> anyhow::Result<Verified> {
        let signed: Signed<Manifest> = cbor::from_slice(&self.get("/manifest")?)?;
        let mut sites = self.load_sites()?;
        let pinned = sites.get(&self.base).copied();
        let verified = verify::manifest(&signed, pinned.as_ref().map(|(root, _)| root))
            .with_context(|| format!("checking {}'s manifest", self.base))?;
        if let Some((_, sequence)) = pinned
            && verified.manifest.sequence < sequence
        {
            bail!("{} sent an older manifest than one already seen", self.base);
        }
        sites.insert(self.base.clone(), (verified.manifest.root, verified.manifest.sequence));
        self.save_sites(&sites)?;
        Ok(verified)
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
            posts.extend(check_epoch(&epoch, board, sealed.epoch, prev, &site.site_key)?);
            prev = Some(sealed.sha256);
        }
        for &number in &entry.unsealed {
            let signed: Vec<Signed<Post>> =
                cbor::from_slice(&self.get(&format!("/boards/{board}/epochs/{number}/posts"))?)?;
            for post in &signed {
                posts.push(check_post(post, &site.site_key, board, number)?);
            }
        }
        check_order(&posts)?;
        Ok(posts)
    }

    pub fn submit(&self, key: &SecretKey, board: &str, content: Content, anonymous: bool) -> anyhow::Result<Post> {
        let site = self.manifest()?;
        content.check()?;
        let submission = Submission { board: board.to_string(), content, anonymous, time: now() };
        let signed = key.sign(Context::Submission, &submission);
        let response = self
            .agent
            .post(&format!("{}/boards/{board}/posts", self.base))
            .set("Content-Type", "application/cbor")
            .send_bytes(&cbor::to_vec(&signed))
            .map_err(describe)?;
        let record: Signed<Post> = cbor::from_slice(&read_body(response)?)?;
        let post = check_post(&record, &site.site_key, board, record.peek()?.epoch)?;
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

    /// A sealed epoch's torrent file, from the server
    pub fn fetch_torrent(&self, board: &str, epoch: u64) -> anyhow::Result<Vec<u8>> {
        self.get(&format!("/boards/{board}/epochs/{epoch}/torrent"))
    }

    /// A sealed epoch's bundle, from the server
    pub fn fetch_bundle(&self, board: &str, epoch: u64) -> anyhow::Result<Vec<u8>> {
        self.get(&format!("/boards/{board}/epochs/{epoch}"))
    }

    /// Server address → (pinned root key, highest manifest sequence seen)
    fn load_sites(&self) -> anyhow::Result<HashMap<String, (PublicKey, u64)>> {
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
            sites.insert(base.to_string(), (PublicKey::from_hex(root)?, sequence.parse()?));
        }
        Ok(sites)
    }

    fn save_sites(&self, sites: &HashMap<String, (PublicKey, u64)>) -> anyhow::Result<()> {
        let mut lines: Vec<String> = sites
            .iter()
            .map(|(base, (root, sequence))| format!("{base} {} {sequence}\n", root.to_hex()))
            .collect();
        lines.sort();
        fs::create_dir_all(&self.home)?;
        fs::write(self.home.join(SITES), lines.concat())?;
        Ok(())
    }
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
        ureq::Error::Status(404, _) => anyhow!("not found"),
        ureq::Error::Status(code, response) => {
            let reason = response.into_string().unwrap_or_default();
            anyhow!("the server refused ({code}): {}", reason.trim())
        }
        other => anyhow!(other),
    }
}
