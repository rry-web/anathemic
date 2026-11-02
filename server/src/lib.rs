//! The operator's server: accepts posts, closes and seals epochs, and serves the signed
//! manifest, epochs and posts over plain HTTP (inside I2P, through an i2pd server tunnel).

use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anathemic_core::{
    Authors, BoardEntry, Content, Context, Epoch, FORMAT, Hash20, Hash32, Manifest, Post, PublicKey, SealedRef,
    SecretKey, Signed, SiteCert, Submission, Time, cbor, check_site_text, epoch, now, torrent, valid_address,
    valid_board_name,
};
use anyhow::{Context as _, bail};
use axum::{
    Router,
    body::Bytes,
    extract::{Path as UrlPath, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub mod hosts;
pub mod snapshot;
pub mod tracker;
pub mod web;

const ROOT_KEY: &str = "root.key";
const SITE_KEY: &str = "site.key";
const DATABASE: &str = "site.db";
/// How far a submission's clock may be from the server's
const CLOCK_SLACK: u64 = 24 * 60 * 60;

pub struct Config {
    /// Anonymous web posts each board takes in an hour, from everyone together
    pub web_posts_per_hour: u32,
    /// …and from each I2P destination, when the tunnel says which one is asking
    pub web_posts_per_hour_each: u32,
    /// An open epoch closes after this many posts…
    pub epoch_posts: u64,
    /// …or this long after it opened, if it has any posts
    pub epoch_seconds: u64,
    /// How long a closed epoch stays open to moderation before it's sealed
    pub window_seconds: u64,
    /// The I2P router's HTTP proxy, for reaching the site's other hosts
    pub proxy: Option<String>,
    /// A standby takes over after the writer has been out of reach this long (0: never by itself)…
    pub takeover_seconds: u64,
    /// …plus this long for each host ranked above it, so they don't all take over at once
    pub stagger_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            web_posts_per_hour: 30,
            web_posts_per_hour_each: 6,
            epoch_posts: 500, epoch_seconds: 7 * 24 * 60 * 60, window_seconds: 72 * 60 * 60,
            proxy: None,
            takeover_seconds: 30 * 60,
            stagger_seconds: 10 * 60,
        }
    }
}

/// Creates a site's keys and database in `dir`; returns the root key, the site's identity
pub fn init(dir: &Path) -> anyhow::Result<PublicKey> {
    fs::create_dir_all(dir)?;
    if dir.join(ROOT_KEY).exists() || dir.join(DATABASE).exists() {
        bail!("{} already holds a site", dir.display());
    }
    let root = SecretKey::generate();
    let site = SecretKey::generate();
    write_secret(&dir.join(ROOT_KEY), &root.to_bytes())?;
    write_secret(&dir.join(SITE_KEY), &site.to_bytes())?;
    let cert = root.sign(Context::SiteCert, &SiteCert { site_key: site.public(), issued: now() });

    let db = Connection::open(dir.join(DATABASE))?;
    create_tables(&db)?;
    db.execute("insert into meta values('root', ?1)", [root.public().0.to_vec()])?;
    db.execute("insert into meta values('site_cert', ?1)", [cbor::to_vec(&cert)])?;
    db.execute("insert into meta values('sequence', 0)", [])?;
    migrate(&db)?;
    Ok(root.public())
}

fn create_tables(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "create table meta(key text primary key, value blob not null);
         create table boards(name text primary key, title text not null, authors text not null,
                             tier integer not null, position integer not null);
         create table epochs(board text not null, number integer not null, state text not null,
                             opened integer not null, closed integer, sha256 blob, bundle blob,
                             primary key(board, number));
         create table posts(board text not null, number integer not null, epoch integer not null,
                            thread integer, record blob not null, author blob not null,
                            submission blob not null unique, primary key(board, number));",
    )
}

/// Brings a database made by an older version up to date
fn migrate(db: &Connection) -> rusqlite::Result<()> {
    let has_web: i64 =
        db.query_row("select count(*) from pragma_table_info('boards') where name = 'web'", [], |r| r.get(0))?;
    if has_web == 0 {
        db.execute_batch("alter table boards add column web integer not null default 0;")?;
    }
    let has_infohash: i64 =
        db.query_row("select count(*) from pragma_table_info('epochs') where name = 'infohash'", [], |r| r.get(0))?;
    if has_infohash == 0 {
        db.execute_batch("alter table epochs add column infohash blob;")?;
    }
    db.execute_batch(
        "insert or ignore into meta values('name', '');
         insert or ignore into meta values('description', '');
         insert or ignore into meta values('addresses', '');
         insert or ignore into meta values('term', 0);
         insert or ignore into meta values('role', 'writer');
         insert or ignore into meta values('host_address', '');
         insert or ignore into meta values('hosts', x'');
         insert or ignore into meta values('relayed', x'');
         insert or ignore into meta values('promote', 0);
         insert or ignore into meta values('follow', '');
         create table if not exists orphans(board text not null, number integer not null, record blob not null,
                                            author blob not null, submission blob not null, orphaned integer not null);
         create index if not exists posts_by_thread on posts(board, thread, number);
         create index if not exists epochs_by_infohash on epochs(infohash);",
    )?;
    // Epochs sealed before mirroring get their torrents now
    let unhashed: Vec<(String, i64, Vec<u8>)> = db
        .prepare("select board, number, bundle from epochs where state = 'sealed' and infohash is null")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (board, number, bundle) in &unhashed {
        let hash = torrent::bundle_hash(bundle, board, *number as u64);
        db.execute("update epochs set infohash = ?3 where board = ?1 and number = ?2", params![board, number, hash.0.to_vec()])?;
    }
    if !unhashed.is_empty() {
        bump(db)?;
    }
    Ok(())
}

/// What `set-site` changes; `None` leaves a field as it is
#[derive(Default)]
pub struct SiteSettings {
    pub name: Option<String>,
    pub description: Option<String>,
    pub addresses: Option<Vec<String>>,
}

pub fn set_site(dir: &Path, settings: SiteSettings) -> anyhow::Result<()> {
    let db = open_db(dir)?;
    let text = |key: &str| -> rusqlite::Result<String> {
        db.query_row("select value from meta where key = ?1", [key], |r| r.get(0))
    };
    let name = settings.name.map_or_else(|| text("name"), Ok)?;
    let description = settings.description.map_or_else(|| text("description"), Ok)?;
    check_site_text(&name, &description)?;
    if let Some(addresses) = &settings.addresses {
        if let Some(bad) = addresses.iter().find(|a| !valid_address(a)) {
            bail!("{bad:?} isn't an I2P address, like forum.i2p or <52 characters>.b32.i2p");
        }
        db.execute("update meta set value = ?1 where key = 'addresses'", [addresses.join("\n")])?;
    }
    db.execute("update meta set value = ?1 where key = 'name'", [name.trim()])?;
    db.execute("update meta set value = ?1 where key = 'description'", [description])?;
    bump(&db)?;
    Ok(())
}

/// Turns anonymous posting from the web pages on or off for a board
pub fn set_web_posting(dir: &Path, board: &str, on: bool) -> anyhow::Result<()> {
    let db = open_db(dir)?;
    let authors: Option<String> =
        db.query_row("select authors from boards where name = ?1", [board], |r| r.get(0)).optional()?;
    match authors.as_deref() {
        None => bail!("there's no board /{board}/"),
        Some("shown") if on => bail!("/{board}/ shows every post's author, so it can't take anonymous web posts"),
        _ => {}
    }
    db.execute("update boards set web = ?2 where name = ?1", params![board, on])?;
    bump(&db)?;
    Ok(())
}

fn open_db(dir: &Path) -> anyhow::Result<Connection> {
    let path = dir.join(DATABASE);
    if !path.exists() {
        bail!("{} holds no site; run init first", dir.display());
    }
    let db = Connection::open(path)?;
    migrate(&db)?;
    Ok(db)
}

pub fn add_board(dir: &Path, name: &str, title: &str, authors: Authors) -> anyhow::Result<()> {
    if !valid_board_name(name) {
        bail!("board names are 1 to 32 of a-z, 0-9 and '-'");
    }
    if web::RESERVED.contains(&name) {
        bail!("/{name}/ is one of the server's own addresses");
    }
    let db = open_db(dir)?;
    let position: i64 = db.query_row("select count(*) from boards", [], |r| r.get(0))?;
    db.execute(
        "insert into boards(name, title, authors, tier, position) values(?1, ?2, ?3, 0, ?4)",
        params![name, title, authors.name(), position],
    )
    .with_context(|| format!("adding board {name}"))?;
    db.execute("insert into epochs(board, number, state, opened) values(?1, 0, 'open', ?2)", params![name, now() as i64])?;
    bump(&db)?;
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

/// Why a request failed
#[derive(Debug)]
pub enum Fail {
    Refused(String),
    NotFound,
    Internal(String),
    /// Can't answer now, as when a standby can't reach the writer
    Unavailable(String),
    /// A host-only request without a good signature
    Forbidden,
}

impl From<anathemic_core::Error> for Fail {
    fn from(error: anathemic_core::Error) -> Self {
        Fail::Refused(error.to_string())
    }
}

impl From<rusqlite::Error> for Fail {
    fn from(error: rusqlite::Error) -> Self {
        Fail::Internal(error.to_string())
    }
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        match self {
            Fail::Refused(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            Fail::NotFound => StatusCode::NOT_FOUND.into_response(),
            Fail::Unavailable(message) => (StatusCode::SERVICE_UNAVAILABLE, message).into_response(),
            Fail::Forbidden => StatusCode::FORBIDDEN.into_response(),
            Fail::Internal(message) => {
                eprintln!("internal error: {message}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

fn refuse<T>(message: &str) -> Result<T, Fail> {
    Err(Fail::Refused(message.to_string()))
}

pub struct Site {
    db: Mutex<Connection>,
    key: SecretKey,
    root: PublicKey,
    config: Config,
    /// When a standby last copied the writer
    last_contact: Mutex<Time>,
    /// When recent web posts were made, by board and by board and destination
    web_posts: Mutex<HashMap<String, Vec<Time>>>,
    /// Who holds which sealed epochs
    pub tracker: tracker::Tracker,
}

impl Site {
    pub fn open(dir: &Path, config: Config) -> anyhow::Result<Site> {
        let key = SecretKey::from_bytes(&fs::read(dir.join(SITE_KEY))?)?;
        let db = open_db(dir)?;
        let meta = |name: &str| -> anyhow::Result<Vec<u8>> {
            Ok(db.query_row("select value from meta where key = ?1", [name], |r| r.get(0))?)
        };
        let root = PublicKey(meta("root")?.try_into().map_err(|_| anyhow::anyhow!("bad root key"))?);
        // The operator's server holds the key the site certificate names; other hosts are on
        // the root key's host list, or are standbys waiting to be added to it
        let certified = match cbor::from_slice::<Signed<SiteCert>>(&meta("site_cert")?) {
            Ok(cert) => cert.open(Context::SiteCert, Some(&root))?.site_key == key.public(),
            Err(_) => false,
        };
        let listed = hosts::load_hosts(&db)
            .map_err(|f| anyhow::anyhow!("{f:?}"))?
            .map(|signed| signed.open(Context::Hosts, Some(&root)))
            .transpose()?
            .is_some_and(|list| list.get(&key.public()).is_some());
        if !certified && !listed && hosts::role(&db)? == hosts::Role::Writer {
            bail!("{SITE_KEY} isn't the key the root key certified");
        }
        Ok(Site {
            db: Mutex::new(db),
            key,
            root,
            config,
            last_contact: Mutex::new(now()),
            web_posts: Mutex::new(HashMap::new()),
            tracker: Default::default(),
        })
    }

    pub fn root(&self) -> PublicKey {
        self.root
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn manifest(&self, now: u64) -> Result<Signed<Manifest>, Fail> {
        let db = self.db();
        let sequence: i64 = db.query_row("select value from meta where key = 'sequence'", [], |r| r.get(0))?;
        let mut boards = Vec::new();
        let mut statement = db.prepare("select name, title, authors, tier, web from boards order by position")?;
        let rows = statement.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, u8>(3)?, r.get::<_, bool>(4)?))
        })?;
        for row in rows {
            let (name, title, authors, tier, web_posting) = row?;
            let mut sealed = Vec::new();
            let mut unsealed = Vec::new();
            let mut epochs = db.prepare(
                "select number, state, sha256, length(bundle), infohash from epochs where board = ?1 order by number",
            )?;
            let mut rows = epochs.query([&name])?;
            while let Some(r) = rows.next()? {
                let number: i64 = r.get(0)?;
                if r.get::<_, String>(1)? == "sealed" {
                    let sha256: Vec<u8> = r.get(2)?;
                    let sha256 = Hash32(sha256.try_into().map_err(|_| Fail::Internal("bad epoch hash".into()))?);
                    let infohash: Option<Vec<u8>> = r.get(4)?;
                    let infohash = infohash.and_then(|hash| hash.try_into().ok()).map(Hash20);
                    sealed.push(SealedRef { epoch: number as u64, sha256, size: r.get::<_, i64>(3)? as u64, infohash });
                } else {
                    unsealed.push(number as u64);
                }
            }
            let authors = Authors::parse(&authors).ok_or_else(|| Fail::Internal(format!("bad authors {authors}")))?;
            boards.push(BoardEntry { name, title, authors, tier, sealed, unsealed, web_posting });
        }
        let text = |key: &str| -> rusqlite::Result<String> {
            db.query_row("select value from meta where key = ?1", [key], |r| r.get(0))
        };
        let term: i64 = db.query_row("select value from meta where key = 'term'", [], |r| r.get(0))?;
        let manifest = Manifest {
            format: FORMAT,
            root: self.root,
            site_cert: hosts::load_cert(&db)?,
            term: term as u64,
            hosts: hosts::load_hosts(&db)?,
            sequence: sequence as u64,
            published: now,
            name: text("name")?,
            description: text("description")?,
            addresses: text("addresses")?.lines().map(str::to_string).collect(),
            boards,
        };
        Ok(self.key.sign(Context::Manifest, &manifest))
    }

    /// A sealed epoch's bundle
    pub fn bundle(&self, board: &str, number: u64) -> Result<Vec<u8>, Fail> {
        self.db()
            .query_row(
                "select bundle from epochs where board = ?1 and number = ?2 and state = 'sealed'",
                params![board, number as i64],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Fail::NotFound)
    }

    /// A sealed epoch's torrent file, announcing to the site's tracker at each of its addresses
    pub fn torrent(&self, board: &str, number: u64) -> Result<Vec<u8>, Fail> {
        let bundle = self.bundle(board, number)?;
        let (_, _, addresses) = self.about()?;
        let trackers: Vec<String> = addresses.iter().map(|address| format!("http://{address}/announce")).collect();
        Ok(torrent::file(&torrent::info(&bundle, board, number), &trackers))
    }

    /// Whether an info hash is one of the site's sealed epochs, which are all its tracker tracks
    pub fn has_torrent(&self, infohash: &Hash20) -> Result<bool, Fail> {
        let count: i64 =
            self.db().query_row("select count(*) from epochs where infohash = ?1", [infohash.0.to_vec()], |r| r.get(0))?;
        Ok(count > 0)
    }

    /// An epoch's posts, as the server signed them
    pub fn posts(&self, board: &str, number: u64) -> Result<Vec<Signed<Post>>, Fail> {
        let db = self.db();
        let known: i64 = db.query_row(
            "select count(*) from epochs where board = ?1 and number = ?2",
            params![board, number as i64],
            |r| r.get(0),
        )?;
        if known == 0 {
            return Err(Fail::NotFound);
        }
        load_posts(&db, board, number)
    }

    pub fn submit(&self, board: &str, signed: &Signed<Submission>, now: u64) -> Result<Signed<Post>, Fail> {
        let submission = signed.open(Context::Submission, None)?;
        if submission.board != board {
            return refuse("the post names a different board");
        }
        submission.content.check()?;
        if submission.time.abs_diff(now) > CLOCK_SLACK {
            return refuse("the post's clock is more than a day off");
        }

        let db = self.db();
        let authors: String = db
            .query_row("select authors from boards where name = ?1", [board], |r| r.get(0))
            .optional()?
            .ok_or(Fail::NotFound)?;
        let shown = match (Authors::parse(&authors), submission.anonymous) {
            (Some(Authors::Shown), true) => return refuse("this board shows every post's author"),
            (Some(Authors::Shown), false) => true,
            (Some(Authors::Choice), anonymous) => !anonymous,
            _ => false,
        };
        check_thread(&db, board, &submission.content)?;
        let fingerprint = Sha256::digest(&signed.body).to_vec();
        let seen: i64 = db.query_row("select count(*) from posts where submission = ?1", [&fingerprint], |r| r.get(0))?;
        if seen > 0 {
            return refuse("this post was already made");
        }

        self.insert_post(&db, board, submission.content, shown.then(|| signed.clone()), &signed.signer.0, fingerprint, now)
    }

    /// Takes an anonymous post from the web pages, on boards that allow them. `from` is the
    /// poster's I2P destination, when the tunnel says.
    pub fn submit_web(&self, board: &str, content: Content, from: Option<&str>, now: u64) -> Result<Signed<Post>, Fail> {
        content.check()?;
        if self.role()? == hosts::Role::Standby {
            return self.forward_web(board, content, from);
        }
        let db = self.db();
        let web: bool = db
            .query_row("select web from boards where name = ?1", [board], |r| r.get(0))
            .optional()?
            .ok_or(Fail::NotFound)?;
        if !web {
            return refuse("this board takes posts only from the anathemic client");
        }
        check_thread(&db, board, &content)?;
        {
            let mut recent = self.web_posts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            recent.retain(|_, times| {
                times.retain(|&t| now < t + 3600);
                !times.is_empty()
            });
            let everyone = recent.get(board).map_or(0, Vec::len);
            let each_key = from.map(|from| format!("{board} {from}"));
            let each = each_key.as_ref().and_then(|key| recent.get(key)).map_or(0, Vec::len);
            if everyone >= self.config.web_posts_per_hour as usize || each >= self.config.web_posts_per_hour_each as usize {
                return refuse("this board has taken all the web posts it takes in an hour; try again later");
            }
            recent.entry(board.to_string()).or_default().push(now);
            if let Some(key) = each_key {
                recent.entry(key).or_default().push(now);
            }
        }
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        self.insert_post(&db, board, content, None, &[], nonce.to_vec(), now)
    }

    /// Numbers, signs and stores a post, closing its epoch if that fills it
    #[allow(clippy::too_many_arguments)]
    fn insert_post(
        &self,
        db: &Connection,
        board: &str,
        content: Content,
        author: Option<Signed<Submission>>,
        author_key: &[u8],
        fingerprint: Vec<u8>,
        now: u64,
    ) -> Result<Signed<Post>, Fail> {
        let web = author_key.is_empty();
        let number: i64 = db.query_row("select coalesce(max(number), 0) + 1 from posts where board = ?1", [board], |r| r.get(0))?;
        let epoch: i64 = db.query_row("select number from epochs where board = ?1 and state = 'open'", [board], |r| r.get(0))?;
        let post = Post {
            board: board.to_string(),
            number: number as u64,
            epoch: epoch as u64,
            accepted: now,
            content,
            author,
            web,
        };
        let record = self.key.sign(Context::Post, &post);
        db.execute(
            "insert into posts values(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![board, number, epoch, post.content.thread.map(|t| t as i64), cbor::to_vec(&record), author_key, fingerprint],
        )?;
        let count: i64 = db.query_row(
            "select count(*) from posts where board = ?1 and epoch = ?2",
            params![board, epoch],
            |r| r.get(0),
        )?;
        if count as u64 >= self.config.epoch_posts {
            close_epoch(db, board, epoch, now)?;
        }
        Ok(record)
    }

    /// Closes open epochs that are old enough and seals those whose moderation window is over
    pub fn tick(&self, now: u64) -> Result<(), Fail> {
        // Only the writer closes and seals; standbys copy what it did
        if self.role()? == hosts::Role::Standby {
            return Ok(());
        }
        let db = self.db();
        let open: Vec<(String, i64, i64)> = db
            .prepare("select board, number, opened from epochs where state = 'open'")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (board, number, opened) in open {
            let posts: i64 = db.query_row(
                "select count(*) from posts where board = ?1 and epoch = ?2",
                params![board, number],
                |r| r.get(0),
            )?;
            if posts > 0 && now >= opened as u64 + self.config.epoch_seconds {
                close_epoch(&db, &board, number, now)?;
            }
        }
        let settling: Vec<(String, i64, i64)> = db
            .prepare("select board, number, closed from epochs where state = 'settling' order by board, number")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (board, number, closed) in settling {
            if now >= closed as u64 + self.config.window_seconds {
                seal_epoch(&db, &board, number)?;
            }
        }
        Ok(())
    }
}

/// A board as the web pages list it
pub struct BoardSummary {
    pub name: String,
    pub title: String,
    pub authors: Authors,
    pub threads: u64,
    pub posts: u64,
    /// When its newest post was accepted
    pub last: Option<Time>,
}

/// A thread as a board's page lists it
pub struct ThreadSummary {
    pub start: Post,
    pub replies: u64,
    /// When its newest post was accepted
    pub last: Time,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochState {
    Open,
    Settling,
    Sealed,
}

/// Reading the site for its web pages. The server's own records are trusted, so these don't
/// check signatures.
impl Site {
    pub fn boards(&self) -> Result<Vec<BoardSummary>, Fail> {
        let db = self.db();
        let rows: Vec<(String, String, String, i64, i64)> = db
            .prepare(
                "select name, title, authors,
                        (select count(*) from posts where board = name and thread is null),
                        (select count(*) from posts where board = name)
                 from boards order by position",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(name, title, authors, threads, posts)| {
                let last = latest(&db, &name, None)?.map(|post| post.accepted);
                Ok(BoardSummary { authors: parse_authors(&authors)?, name, title, threads: threads as u64, posts: posts as u64, last })
            })
            .collect()
    }

    /// A board's title, author rule, and whether it takes web posts
    pub fn board(&self, board: &str) -> Result<(String, Authors, bool), Fail> {
        let (title, authors, web): (String, String, bool) = self
            .db()
            .query_row("select title, authors, web from boards where name = ?1", [board], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?
            .ok_or(Fail::NotFound)?;
        Ok((title, parse_authors(&authors)?, web))
    }

    /// The site's name, description and addresses, as the manifest gives them
    pub fn about(&self) -> Result<(String, String, Vec<String>), Fail> {
        let db = self.db();
        let text = |key: &str| -> rusqlite::Result<String> {
            db.query_row("select value from meta where key = ?1", [key], |r| r.get(0))
        };
        Ok((text("name")?, text("description")?, text("addresses")?.lines().map(str::to_string).collect()))
    }

    /// A page of a board's threads, the most recently active first, and how many there are
    pub fn threads(&self, board: &str, skip: u64, take: u64) -> Result<(Vec<ThreadSummary>, u64), Fail> {
        self.board(board)?;
        let db = self.db();
        let total: i64 =
            db.query_row("select count(*) from posts where board = ?1 and thread is null", [board], |r| r.get(0))?;
        // Post numbers rise with time, so the highest number is the newest post
        let rows: Vec<(Vec<u8>, i64, i64)> = db
            .prepare(
                "select s.record, count(r.number), coalesce(max(r.number), s.number) as last
                 from posts s left join posts r on r.board = s.board and r.thread = s.number
                 where s.board = ?1 and s.thread is null
                 group by s.number order by last desc limit ?2 offset ?3",
            )?
            .query_map(params![board, take as i64, skip as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        let mut threads = Vec::new();
        for (record, replies, last) in rows {
            let start = decode(&record)?;
            let last = if last as u64 == start.number {
                start.accepted
            } else {
                latest(&db, board, Some(last as u64))?.map_or(start.accepted, |post| post.accepted)
            };
            threads.push(ThreadSummary { start, replies: replies as u64, last });
        }
        Ok((threads, total as u64))
    }

    /// A thread's posts in order, its first post first
    pub fn thread(&self, board: &str, number: u64) -> Result<Vec<Post>, Fail> {
        let db = self.db();
        let records: Vec<Vec<u8>> = db
            .prepare(
                "select record from posts where board = ?1 and (number = ?2 and thread is null or thread = ?2)
                 order by number",
            )?
            .query_map(params![board, number as i64], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        if records.is_empty() {
            return Err(Fail::NotFound);
        }
        records.iter().map(|record| decode(record)).collect()
    }

    /// The thread a post belongs to
    pub fn thread_of(&self, board: &str, number: u64) -> Result<u64, Fail> {
        let thread: i64 = self
            .db()
            .query_row(
                "select coalesce(thread, number) from posts where board = ?1 and number = ?2",
                params![board, number as i64],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Fail::NotFound)?;
        Ok(thread as u64)
    }

    pub fn epoch_states(&self, board: &str) -> Result<HashMap<u64, EpochState>, Fail> {
        let db = self.db();
        let rows: Vec<(i64, String)> = db
            .prepare("select number, state from epochs where board = ?1")?
            .query_map([board], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(number, state)| {
                let state = match state.as_str() {
                    "sealed" => EpochState::Sealed,
                    "settling" => EpochState::Settling,
                    _ => EpochState::Open,
                };
                (number as u64, state)
            })
            .collect())
    }
}

/// A reply's thread exists
fn check_thread(db: &Connection, board: &str, content: &Content) -> Result<(), Fail> {
    if let Some(thread) = content.thread {
        let starts: i64 = db.query_row(
            "select count(*) from posts where board = ?1 and number = ?2 and thread is null",
            params![board, thread as i64],
            |r| r.get(0),
        )?;
        if starts == 0 {
            return refuse("there's no such thread");
        }
    }
    Ok(())
}

fn parse_authors(name: &str) -> Result<Authors, Fail> {
    Authors::parse(name).ok_or_else(|| Fail::Internal(format!("bad authors {name}")))
}

fn decode(record: &[u8]) -> Result<Post, Fail> {
    let signed: Signed<Post> = cbor::from_slice(record).map_err(|e| Fail::Internal(e.to_string()))?;
    signed.peek().map_err(|e| Fail::Internal(e.to_string()))
}

/// A board's newest post, or a given one
fn latest(db: &Connection, board: &str, number: Option<u64>) -> Result<Option<Post>, Fail> {
    let record: Option<Vec<u8>> = db
        .query_row(
            "select record from posts where board = ?1 and (?2 is null or number = ?2) order by number desc limit 1",
            params![board, number.map(|n| n as i64)],
            |r| r.get(0),
        )
        .optional()?;
    record.map(|record| decode(&record)).transpose()
}

fn load_posts(db: &Connection, board: &str, epoch: u64) -> Result<Vec<Signed<Post>>, Fail> {
    let records: Vec<Vec<u8>> = db
        .prepare("select record from posts where board = ?1 and epoch = ?2 order by number")?
        .query_map(params![board, epoch as i64], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    records
        .iter()
        .map(|record| cbor::from_slice(record).map_err(|e| Fail::Internal(e.to_string())))
        .collect()
}

fn bump(db: &Connection) -> rusqlite::Result<()> {
    db.execute("update meta set value = value + 1 where key = 'sequence'", [])?;
    Ok(())
}

fn close_epoch(db: &Connection, board: &str, number: i64, now: u64) -> rusqlite::Result<()> {
    db.execute(
        "update epochs set state = 'settling', closed = ?3 where board = ?1 and number = ?2",
        params![board, number, now as i64],
    )?;
    db.execute(
        "insert into epochs(board, number, state, opened) values(?1, ?2, 'open', ?3)",
        params![board, number + 1, now as i64],
    )?;
    bump(db)
}

fn seal_epoch(db: &Connection, board: &str, number: i64) -> Result<(), Fail> {
    let prev = if number == 0 {
        None
    } else {
        let hash: Option<Vec<u8>> = db
            .query_row(
                "select sha256 from epochs where board = ?1 and number = ?2 and state = 'sealed'",
                params![board, number - 1],
                |r| r.get(0),
            )
            .optional()?;
        // Epochs seal in order; the previous one goes first
        let Some(hash) = hash else { return Ok(()) };
        Some(Hash32(hash.try_into().map_err(|_| Fail::Internal("bad epoch hash".into()))?))
    };
    let posts = load_posts(db, board, number as u64)?;
    let epoch = Epoch { format: FORMAT, board: board.to_string(), number: number as u64, prev, posts };
    let (bundle, hash) = epoch::seal(&epoch);
    let infohash = torrent::bundle_hash(&bundle, board, number as u64);
    db.execute(
        "update epochs set state = 'sealed', sha256 = ?3, bundle = ?4, infohash = ?5 where board = ?1 and number = ?2",
        params![board, number, hash.0.to_vec(), bundle, infohash.0.to_vec()],
    )?;
    bump(db)?;
    Ok(())
}

fn cbor_response<T: anathemic_core::serde::Serialize>(value: &T) -> Response {
    ([(header::CONTENT_TYPE, "application/cbor")], cbor::to_vec(value)).into_response()
}

async fn get_manifest(State(site): State<Arc<Site>>) -> Result<Response, Fail> {
    if site.role()? == hosts::Role::Standby {
        return Ok(([(header::CONTENT_TYPE, "application/cbor")], site.relayed()?).into_response());
    }
    Ok(cbor_response(&site.manifest(now())?))
}

async fn get_bundle(State(site): State<Arc<Site>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Result<Response, Fail> {
    let bundle = site.bundle(&board, number)?;
    Ok(([(header::CONTENT_TYPE, "application/zstd")], bundle).into_response())
}

async fn get_torrent(State(site): State<Arc<Site>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Result<Response, Fail> {
    let torrent = site.torrent(&board, number)?;
    let name = format!("attachment; filename=\"{}.torrent\"", torrent::file_name(&board, number));
    Ok(([(header::CONTENT_TYPE, "application/x-bittorrent".to_string()), (header::CONTENT_DISPOSITION, name)], torrent).into_response())
}

async fn get_posts(State(site): State<Arc<Site>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Result<Response, Fail> {
    Ok(cbor_response(&site.posts(&board, number)?))
}

async fn post_submission(State(site): State<Arc<Site>>, UrlPath(board): UrlPath<String>, body: Bytes) -> Result<Response, Fail> {
    let signed: Signed<Submission> = cbor::from_slice(&body)?;
    tokio::task::spawn_blocking(move || {
        if site.role()? == hosts::Role::Standby {
            // Posts reach whichever host answers at the site's address; only the writer takes them
            return site.forward_submission(&board, &body);
        }
        Ok(cbor_response(&site.submit(&board, &signed, now())?))
    })
    .await
    .map_err(|e| Fail::Internal(e.to_string()))?
}

pub fn router(site: Arc<Site>) -> Router {
    Router::new()
        .route("/manifest", get(get_manifest))
        .route("/boards/{board}/epochs/{number}", get(get_bundle))
        .route("/boards/{board}/epochs/{number}/posts", get(get_posts))
        .route("/boards/{board}/epochs/{number}/torrent", get(get_torrent))
        .route("/announce", get(tracker::announce))
        .route("/mirrors", get(tracker::mirrors))
        .route("/hosts/state", get(hosts::get_state))
        .route("/hosts/posts", get(hosts::get_posts))
        .route("/hosts/web", post(hosts::post_web))
        .route("/boards/{board}/posts", post(post_submission))
        .merge(web::routes())
        .with_state(site)
}

/// Serves the site, closing and sealing epochs every `tick` in the background
pub async fn serve(site: Arc<Site>, listen: SocketAddr, tick: Duration) -> anyhow::Result<()> {
    let ticker = site.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        loop {
            interval.tick().await;
            if let Err(fail) = ticker.tick(now()) {
                eprintln!("closing or sealing epochs failed: {fail:?}");
            }
            let hosts = ticker.clone();
            match tokio::task::spawn_blocking(move || hosts.host_tick(now())).await {
                Ok(Err(fail)) => eprintln!("keeping up with the site's other hosts failed: {fail:?}"),
                Err(e) => eprintln!("keeping up with the site's other hosts failed: {e}"),
                Ok(Ok(())) => {}
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router(site)).await?;
    Ok(())
}
