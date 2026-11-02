//! The operator's server: accepts posts, closes and seals epochs, and serves the signed
//! manifest, epochs and posts over plain HTTP (inside I2P, through an i2pd server tunnel).

use std::{
    fs,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anathemic_core::{
    Authors, BoardEntry, Context, Epoch, FORMAT, Hash32, Manifest, Post, PublicKey, SealedRef,
    SecretKey, Signed, SiteCert, Submission, cbor, epoch, now, valid_board_name,
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

const ROOT_KEY: &str = "root.key";
const SITE_KEY: &str = "site.key";
const DATABASE: &str = "site.db";
/// How far a submission's clock may be from the server's
const CLOCK_SLACK: u64 = 24 * 60 * 60;

pub struct Config {
    /// An open epoch closes after this many posts…
    pub epoch_posts: u64,
    /// …or this long after it opened, if it has any posts
    pub epoch_seconds: u64,
    /// How long a closed epoch stays open to moderation before it's sealed
    pub window_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self { epoch_posts: 500, epoch_seconds: 7 * 24 * 60 * 60, window_seconds: 72 * 60 * 60 }
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
    )?;
    db.execute("insert into meta values('root', ?1)", [root.public().0.to_vec()])?;
    db.execute("insert into meta values('site_cert', ?1)", [cbor::to_vec(&cert)])?;
    db.execute("insert into meta values('sequence', 0)", [])?;
    Ok(root.public())
}

pub fn add_board(dir: &Path, name: &str, title: &str, authors: Authors) -> anyhow::Result<()> {
    if !valid_board_name(name) {
        bail!("board names are 1 to 32 of a-z, 0-9 and '-'");
    }
    let db = Connection::open(dir.join(DATABASE))?;
    let position: i64 = db.query_row("select count(*) from boards", [], |r| r.get(0))?;
    db.execute(
        "insert into boards values(?1, ?2, ?3, 0, ?4)",
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
    cert: Signed<SiteCert>,
    config: Config,
}

impl Site {
    pub fn open(dir: &Path, config: Config) -> anyhow::Result<Site> {
        let key = SecretKey::from_bytes(&fs::read(dir.join(SITE_KEY))?)?;
        let db = Connection::open(dir.join(DATABASE))?;
        let meta = |name: &str| -> anyhow::Result<Vec<u8>> {
            Ok(db.query_row("select value from meta where key = ?1", [name], |r| r.get(0))?)
        };
        let root = PublicKey(meta("root")?.try_into().map_err(|_| anyhow::anyhow!("bad root key"))?);
        let cert: Signed<SiteCert> = cbor::from_slice(&meta("site_cert")?)?;
        if cert.open(Context::SiteCert, Some(&root))?.site_key != key.public() {
            bail!("{SITE_KEY} isn't the key the root key certified");
        }
        Ok(Site { db: Mutex::new(db), key, root, cert, config })
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
        let mut statement = db.prepare("select name, title, authors, tier from boards order by position")?;
        let rows = statement.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, u8>(3)?))
        })?;
        for row in rows {
            let (name, title, authors, tier) = row?;
            let mut sealed = Vec::new();
            let mut unsealed = Vec::new();
            let mut epochs = db.prepare(
                "select number, state, sha256, length(bundle) from epochs where board = ?1 order by number",
            )?;
            let mut rows = epochs.query([&name])?;
            while let Some(r) = rows.next()? {
                let number: i64 = r.get(0)?;
                if r.get::<_, String>(1)? == "sealed" {
                    let sha256: Vec<u8> = r.get(2)?;
                    let sha256 = Hash32(sha256.try_into().map_err(|_| Fail::Internal("bad epoch hash".into()))?);
                    sealed.push(SealedRef { epoch: number as u64, sha256, size: r.get::<_, i64>(3)? as u64 });
                } else {
                    unsealed.push(number as u64);
                }
            }
            let authors = Authors::parse(&authors).ok_or_else(|| Fail::Internal(format!("bad authors {authors}")))?;
            boards.push(BoardEntry { name, title, authors, tier, sealed, unsealed });
        }
        let manifest = Manifest {
            format: FORMAT,
            root: self.root,
            site_cert: self.cert.clone(),
            sequence: sequence as u64,
            published: now,
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
        if let Some(thread) = submission.content.thread {
            let starts: i64 = db.query_row(
                "select count(*) from posts where board = ?1 and number = ?2 and thread is null",
                params![board, thread as i64],
                |r| r.get(0),
            )?;
            if starts == 0 {
                return refuse("there's no such thread");
            }
        }
        let fingerprint = Sha256::digest(&signed.body).to_vec();
        let seen: i64 = db.query_row("select count(*) from posts where submission = ?1", [&fingerprint], |r| r.get(0))?;
        if seen > 0 {
            return refuse("this post was already made");
        }

        let number: i64 = db.query_row("select coalesce(max(number), 0) + 1 from posts where board = ?1", [board], |r| r.get(0))?;
        let epoch: i64 = db.query_row("select number from epochs where board = ?1 and state = 'open'", [board], |r| r.get(0))?;
        let post = Post {
            board: board.to_string(),
            number: number as u64,
            epoch: epoch as u64,
            accepted: now,
            content: submission.content,
            author: shown.then(|| signed.clone()),
        };
        let record = self.key.sign(Context::Post, &post);
        db.execute(
            "insert into posts values(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                board,
                number,
                epoch,
                post.content.thread.map(|t| t as i64),
                cbor::to_vec(&record),
                signed.signer.0.to_vec(),
                fingerprint
            ],
        )?;
        let count: i64 = db.query_row(
            "select count(*) from posts where board = ?1 and epoch = ?2",
            params![board, epoch],
            |r| r.get(0),
        )?;
        if count as u64 >= self.config.epoch_posts {
            close_epoch(&db, board, epoch, now)?;
        }
        Ok(record)
    }

    /// Closes open epochs that are old enough and seals those whose moderation window is over
    pub fn tick(&self, now: u64) -> Result<(), Fail> {
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
    db.execute(
        "update epochs set state = 'sealed', sha256 = ?3, bundle = ?4 where board = ?1 and number = ?2",
        params![board, number, hash.0.to_vec(), bundle],
    )?;
    bump(db)?;
    Ok(())
}

fn cbor_response<T: anathemic_core::serde::Serialize>(value: &T) -> Response {
    ([(header::CONTENT_TYPE, "application/cbor")], cbor::to_vec(value)).into_response()
}

async fn get_manifest(State(site): State<Arc<Site>>) -> Result<Response, Fail> {
    Ok(cbor_response(&site.manifest(now())?))
}

async fn get_bundle(State(site): State<Arc<Site>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Result<Response, Fail> {
    let bundle = site.bundle(&board, number)?;
    Ok(([(header::CONTENT_TYPE, "application/zstd")], bundle).into_response())
}

async fn get_posts(State(site): State<Arc<Site>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Result<Response, Fail> {
    Ok(cbor_response(&site.posts(&board, number)?))
}

async fn post_submission(State(site): State<Arc<Site>>, UrlPath(board): UrlPath<String>, body: Bytes) -> Result<Response, Fail> {
    let signed: Signed<Submission> = cbor::from_slice(&body)?;
    Ok(cbor_response(&site.submit(&board, &signed, now())?))
}

pub fn router(site: Arc<Site>) -> Router {
    Router::new()
        .route("/manifest", get(get_manifest))
        .route("/boards/{board}/epochs/{number}", get(get_bundle))
        .route("/boards/{board}/epochs/{number}/posts", get(get_posts))
        .route("/boards/{board}/posts", post(post_submission))
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
        }
    });
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router(site)).await?;
    Ok(())
}
