//! Trusted hosts: servers besides the operator's that can run the site while it's down.
//!
//! The root key lists the hosts, each with its own key, its own I2P address and a rank. One host
//! at a time is the writer: it takes posts, closes and seals epochs, and signs the manifest.
//! The others are standbys. They copy everything from the writer every tick, pass on posts
//! people send them, and serve the writer's manifest as it is. All the hosts can publish the
//! site's shared I2P address, so readers reach whichever is up.
//!
//! When a standby can't reach the writer for long enough (longer for lower ranks, so they don't
//! all take over at once), it takes over: it signs a manifest with the next term, which clients
//! prefer to any manifest from an earlier term. A writer that sees a later term elsewhere steps
//! down and copies the new writer's state. Posts it took that the new writer never got are set
//! aside as orphans for the operator to look at, rather than forking the site.

use std::{fs, path::Path, sync::Arc};

use anathemic_core::{
    Content, Context, Host, HostRequest, Hosts, Manifest, Post, PublicKey, SecretKey, Signed, Time, cbor,
    epoch,
    link::{Link, valid_host},
    now, torrent,
    verify::{self, Verified},
};
use anyhow::{Context as _, bail};
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{DATABASE, Fail, ROOT_KEY, SITE_KEY, Site, bump, cbor_response, open_db, write_secret};

/// How far a host request's clock may be from ours
const REQUEST_SLACK: u64 = 5 * 60;
/// Posts copied per request
const POSTS_PAGE: u64 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Writer,
    Standby,
}

/// A board's settings, as hosts copy them
#[derive(Serialize, Deserialize)]
pub struct BoardRow {
    pub name: String,
    pub title: String,
    pub authors: String,
    pub tier: u8,
    pub position: i64,
    pub web: bool,
}

#[derive(Serialize, Deserialize)]
pub struct EpochRow {
    pub board: String,
    pub number: i64,
    pub state: String,
    pub opened: i64,
    pub closed: Option<i64>,
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
}

/// Everything about the site but its posts and bundles
#[derive(Serialize, Deserialize)]
pub struct HostState {
    pub manifest: Signed<Manifest>,
    pub boards: Vec<BoardRow>,
    pub epochs: Vec<EpochRow>,
}

/// A post as the writer stores it, with what only hosts know: who wrote it, and the
/// fingerprint that stops a submission being posted twice
#[derive(Serialize, Deserialize)]
pub struct PostRow {
    pub board: String,
    pub number: i64,
    pub epoch: i64,
    pub thread: Option<i64>,
    #[serde(with = "serde_bytes")]
    pub record: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub author: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub submission: Vec<u8>,
}

/// An anonymous post from a standby's web pages, passed on to the writer
#[derive(Serialize, Deserialize)]
pub struct WebPost {
    pub board: String,
    pub content: Content,
    pub from: Option<String>,
}

fn meta_text(db: &Connection, key: &str) -> rusqlite::Result<String> {
    db.query_row("select value from meta where key = ?1", [key], |r| r.get(0))
}

fn set_meta(db: &Connection, key: &str, value: impl rusqlite::ToSql) -> rusqlite::Result<()> {
    db.execute("insert or replace into meta values(?1, ?2)", params![key, value])?;
    Ok(())
}

/// The root key's host list, if the site has one
pub(crate) fn load_hosts(db: &Connection) -> Result<Option<Signed<Hosts>>, Fail> {
    let bytes: Vec<u8> = db.query_row("select value from meta where key = 'hosts'", [], |r| r.get(0)).optional()?.unwrap_or_default();
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(cbor::from_slice(&bytes).map_err(|e| Fail::Internal(e.to_string()))?))
}

pub(crate) fn role(db: &Connection) -> rusqlite::Result<Role> {
    Ok(if meta_text(db, "role")? == "standby" { Role::Standby } else { Role::Writer })
}

/// This server's own I2P address, where the other hosts reach it
pub fn set_host_address(dir: &Path, address: &str) -> anyhow::Result<()> {
    if !valid_host(address) {
        bail!("{address:?} isn't an I2P address");
    }
    set_meta(&open_db(dir)?, "host_address", address)?;
    Ok(())
}

fn root_key(dir: &Path, root_key: Option<&Path>) -> anyhow::Result<SecretKey> {
    let path = root_key.map_or_else(|| dir.join(ROOT_KEY), Path::to_path_buf);
    let bytes = fs::read(&path).with_context(|| format!("reading the root key from {}; pass --root-key", path.display()))?;
    Ok(SecretKey::from_bytes(&bytes)?)
}

/// Signs a new host list with the root key, after `change` edits the current one
fn change_hosts(dir: &Path, root_key_path: Option<&Path>, change: impl FnOnce(&mut Vec<Host>) -> anyhow::Result<()>) -> anyhow::Result<Hosts> {
    let db = open_db(dir)?;
    let root = root_key(dir, root_key_path)?;
    let stored: Vec<u8> = db.query_row("select value from meta where key = 'root'", [], |r| r.get(0))?;
    if root.public().0.to_vec() != stored {
        bail!("that isn't this site's root key");
    }
    let current = load_hosts(&db).map_err(|f| anyhow::anyhow!("{f:?}"))?;
    let (sequence, mut hosts) = match current {
        Some(signed) => {
            let hosts = signed.open(Context::Hosts, Some(&root.public()))?;
            (hosts.sequence, hosts.hosts)
        }
        None => {
            // The first list starts with this server, at rank 0
            let address = meta_text(&db, "host_address")?;
            if address.is_empty() {
                bail!("first give this server's own I2P address: set-site --host-address <its .b32.i2p>");
            }
            let key = SecretKey::from_bytes(&fs::read(dir.join(SITE_KEY))?)?;
            (0, vec![Host { key: key.public(), rank: 0, address, name: "operator".into(), retired: false }])
        }
    };
    change(&mut hosts)?;
    let list = Hosts { sequence: sequence + 1, issued: now(), hosts };
    set_meta(&db, "hosts", cbor::to_vec(&root.sign(Context::Hosts, &list)))?;
    bump(&db)?;
    Ok(list)
}

/// Adds a trusted host, after the others in rank; returns its rank
pub fn add_host(dir: &Path, root_key: Option<&Path>, key: PublicKey, address: &str, name: &str) -> anyhow::Result<u8> {
    if !valid_host(address) {
        bail!("{address:?} isn't an I2P address");
    }
    let mut rank = 0;
    change_hosts(dir, root_key, |hosts| {
        if hosts.iter().any(|host| host.key == key) {
            bail!("{} is already a host", key.fingerprint());
        }
        rank = hosts.iter().map(|host| host.rank).max().unwrap_or(0) + 1;
        hosts.push(Host { key, rank, address: address.to_string(), name: name.to_string(), retired: false });
        Ok(())
    })?;
    Ok(rank)
}

/// Stops a host from running the site. The posts it signed still count.
pub fn retire_host(dir: &Path, root_key: Option<&Path>, key: PublicKey) -> anyhow::Result<()> {
    change_hosts(dir, root_key, |hosts| {
        let host = hosts.iter_mut().find(|host| host.key == key).ok_or_else(|| anyhow::anyhow!("{} isn't a host", key.fingerprint()))?;
        host.retired = true;
        Ok(())
    })?;
    Ok(())
}

/// The host list, this server's role, and the term
pub fn describe(dir: &Path) -> anyhow::Result<(Option<Hosts>, Role, u64, PublicKey)> {
    let db = open_db(dir)?;
    let hosts = load_hosts(&db).map_err(|f| anyhow::anyhow!("{f:?}"))?.map(|signed| signed.peek()).transpose()?;
    let term: i64 = db.query_row("select value from meta where key = 'term'", [], |r| r.get(0))?;
    let key = SecretKey::from_bytes(&fs::read(dir.join(SITE_KEY))?)?;
    Ok((hosts, role(&db)?, term as u64, key.public()))
}

/// Makes a standby in `dir` for the site a share link names; returns its key, for the operator
/// to add with add-host
pub fn init_standby(dir: &Path, link: &Link) -> anyhow::Result<PublicKey> {
    fs::create_dir_all(dir)?;
    if dir.join(SITE_KEY).exists() || dir.join(DATABASE).exists() {
        bail!("{} already holds a site", dir.display());
    }
    let key = SecretKey::generate();
    write_secret(&dir.join(SITE_KEY), &key.to_bytes())?;
    let db = Connection::open(dir.join(DATABASE))?;
    crate::create_tables(&db)?;
    db.execute("insert into meta values('root', ?1)", [link.root.0.to_vec()])?;
    db.execute("insert into meta values('site_cert', x'')", [])?;
    db.execute("insert into meta values('sequence', 0)", [])?;
    crate::migrate(&db)?;
    set_meta(&db, "role", "standby")?;
    set_meta(&db, "follow", link.address.as_str())?;
    Ok(key.public())
}

/// Asks a running standby to take over at its next tick
pub fn promote(dir: &Path) -> anyhow::Result<()> {
    set_meta(&open_db(dir)?, "promote", 1)?;
    Ok(())
}

/// Posts set aside when this server stepped down: (board, number, record)
pub fn orphans(dir: &Path) -> anyhow::Result<Vec<(String, u64, Signed<Post>)>> {
    let db = open_db(dir)?;
    let rows: Vec<(String, i64, Vec<u8>)> = db
        .prepare("select board, number, record from orphans order by orphaned, board, number")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    rows.into_iter().map(|(board, number, record)| Ok((board, number as u64, cbor::from_slice(&record)?))).collect()
}

impl Site {
    pub fn role(&self) -> Result<Role, Fail> {
        Ok(role(&self.db())?)
    }

    fn agent(&self) -> ureq::Agent {
        let mut builder = ureq::AgentBuilder::new().user_agent("anathemic-host").timeout(std::time::Duration::from_secs(120));
        if let Some(proxy) = &self.config.proxy
            && let Ok(proxy) = ureq::Proxy::new(proxy)
        {
            builder = builder.proxy(proxy);
        }
        builder.build()
    }

    fn fetch(&self, address: &str, path: &str) -> anyhow::Result<Vec<u8>> {
        let response = self.agent().get(&format!("http://{address}{path}")).call()?;
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(response.into_reader(), 300 << 20), &mut body)?;
        Ok(body)
    }

    /// `path` with a signed request appended, so another host knows it's us
    fn signed(&self, path: &str) -> String {
        let request = self.key.sign(Context::HostRequest, &HostRequest { path: path.to_string(), time: now() });
        let sep = if path.contains('?') { '&' } else { '?' };
        format!("{path}{sep}auth={}", hex::encode(cbor::to_vec(&request)))
    }

    /// The hosts on the list other than this one, with their keys
    fn other_hosts(&self) -> Result<Vec<Host>, Fail> {
        let Some(signed) = load_hosts(&self.db())? else { return Ok(Vec::new()) };
        let hosts = signed.peek()?;
        Ok(hosts.hosts.into_iter().filter(|host| host.key != self.key.public() && !host.retired).collect())
    }

    /// This server's place on the host list, if it's on it and not retired
    fn own_rank(&self) -> Result<Option<u8>, Fail> {
        let Some(signed) = load_hosts(&self.db())? else { return Ok(None) };
        Ok(signed.peek()?.get(&self.key.public()).filter(|host| !host.retired).map(|host| host.rank))
    }

    fn term(&self) -> Result<u64, Fail> {
        let term: i64 = self.db().query_row("select value from meta where key = 'term'", [], |r| r.get(0))?;
        Ok(term as u64)
    }

    /// A manifest from another host, checked against the root key and its host list
    fn manifest_at(&self, address: &str) -> Option<(Verified, Vec<u8>)> {
        let bytes = self.fetch(address, "/manifest").ok()?;
        let signed: Signed<Manifest> = cbor::from_slice(&bytes).ok()?;
        let verified = verify::manifest(&signed, Some(&self.root)).ok()?;
        Some((verified, bytes))
    }

    /// The manifest a standby serves: the writer's, exactly as signed
    pub fn relayed(&self) -> Result<Vec<u8>, Fail> {
        let bytes: Vec<u8> = self.db().query_row("select value from meta where key = 'relayed'", [], |r| r.get(0))?;
        if bytes.is_empty() {
            return Err(Fail::Unavailable("this standby hasn't reached the site's writer yet".into()));
        }
        Ok(bytes)
    }

    /// The hosts' side of a tick: a writer looks for a later term elsewhere and steps down if
    /// there is one; a standby copies the writer, or takes over once it's been out of reach for
    /// long enough. Blocking: it makes requests over I2P.
    pub fn host_tick(&self, now: Time) -> Result<(), Fail> {
        match self.role()? {
            Role::Writer => {
                let term = self.term()?;
                let rank = self.own_rank()?.unwrap_or(u8::MAX);
                for host in self.other_hosts()? {
                    // A later term wins; in the same term (two standbys that couldn't see each
                    // other both took over), the better rank does
                    if let Some((verified, bytes)) = self.manifest_at(&host.address)
                        && verified.site_key == host.key
                        && (verified.manifest.term > term || (verified.manifest.term == term && host.rank < rank))
                    {
                        let set_aside = self.step_down(&host.address, &bytes)?;
                        eprintln!(
                            "{} took over the site in term {}, so this server is a standby now{}",
                            host.name,
                            verified.manifest.term,
                            if set_aside > 0 { format!("; {set_aside} posts only it had were set aside (see `orphans`)") } else { String::new() }
                        );
                        return Ok(());
                    }
                }
                Ok(())
            }
            Role::Standby => {
                let promote: i64 = self.db().query_row("select value from meta where key = 'promote'", [], |r| r.get(0))?;
                if promote != 0 {
                    self.db().execute("update meta set value = 0 where key = 'promote'", [])?;
                    return self.take_over("asked to");
                }
                if self.follow(now)? {
                    return Ok(());
                }
                let Some(rank) = self.own_rank()? else { return Ok(()) };
                let last = *self.last_contact.lock().unwrap_or_else(|p| p.into_inner());
                let wait = self.config.takeover_seconds + u64::from(rank.saturating_sub(1)) * self.config.stagger_seconds;
                if self.config.takeover_seconds > 0 && now >= last + wait {
                    return self.take_over(&format!("the writer has been out of reach for {} minutes", (now - last) / 60));
                }
                Ok(())
            }
        }
    }

    /// Finds the newest manifest among the other hosts and copies its writer; whether that worked
    fn follow(&self, now: Time) -> Result<bool, Fail> {
        let mut addresses: Vec<String> = self.other_hosts()?.into_iter().map(|host| host.address).collect();
        let follow = meta_text(&self.db(), "follow")?;
        if !follow.is_empty() && !addresses.contains(&follow) {
            addresses.push(follow);
        }
        let own = self.key.public();
        let newest = addresses
            .iter()
            .filter_map(|address| self.manifest_at(address))
            .filter(|(verified, _)| verified.site_key != own)
            .max_by_key(|(verified, _)| (verified.manifest.term, verified.manifest.sequence));
        let Some((verified, bytes)) = newest else { return Ok(false) };
        if verified.manifest.term < self.term()? {
            return Ok(false);
        }
        // The writer's own address, from the list; or wherever the manifest came from
        let writer = verified
            .manifest
            .hosts
            .as_ref()
            .and_then(|hosts| hosts.peek().ok())
            .and_then(|hosts| hosts.get(&verified.site_key).map(|host| host.address.clone()));
        let Some(writer) = writer else {
            // Not on a host list yet: keep the manifest so the site's details are known
            self.adopt(&bytes)?;
            return Ok(false);
        };
        match self.copy_from(&writer, &bytes) {
            Ok(_) => {
                *self.last_contact.lock().unwrap_or_else(|p| p.into_inner()) = now;
                Ok(true)
            }
            Err(fail) => {
                eprintln!("couldn't copy the site from its writer: {fail:?}");
                Ok(false)
            }
        }
    }

    /// Takes the writer's manifest as the one to serve, with the details it carries
    fn adopt(&self, bytes: &[u8]) -> Result<(), Fail> {
        let signed: Signed<Manifest> = cbor::from_slice(bytes)?;
        let manifest = signed.peek()?;
        let db = self.db();
        set_meta(&db, "relayed", bytes)?;
        set_meta(&db, "site_cert", cbor::to_vec(&manifest.site_cert))?;
        if let Some(hosts) = &manifest.hosts {
            let newer = match load_hosts(&db)? {
                Some(current) => hosts.peek()?.sequence >= current.peek()?.sequence,
                None => true,
            };
            if newer {
                set_meta(&db, "hosts", cbor::to_vec(hosts))?;
            }
        }
        set_meta(&db, "term", manifest.term as i64)?;
        set_meta(&db, "sequence", manifest.sequence as i64)?;
        set_meta(&db, "name", manifest.name.as_str())?;
        set_meta(&db, "description", manifest.description.as_str())?;
        set_meta(&db, "addresses", manifest.addresses.join("\n"))?;
        Ok(())
    }

    /// Copies the site from the writer at `address`; returns how many posts of ours it didn't
    /// have, which are set aside
    fn copy_from(&self, address: &str, manifest: &[u8]) -> Result<usize, Fail> {
        let fail = |e: anyhow::Error| Fail::Internal(format!("{e:#}"));
        let state: HostState = cbor::from_slice(&self.fetch(address, &self.signed("/hosts/state")).map_err(fail)?)?;
        let mut set_aside = 0;
        for board in &state.boards {
            {
                let db = self.db();
                db.execute(
                    "insert into boards(name, title, authors, tier, position, web) values(?1, ?2, ?3, ?4, ?5, ?6)
                     on conflict(name) do update set title = ?2, authors = ?3, tier = ?4, position = ?5, web = ?6",
                    params![board.name, board.title, board.authors, board.tier, board.position, board.web],
                )?;
            }
            set_aside += self.copy_posts(address, &board.name)?;
        }
        // Epochs last, so a sealed one's bundle matches the posts copied
        for row in &state.epochs {
            let ours: Option<Vec<u8>> = self
                .db()
                .query_row("select sha256 from epochs where board = ?1 and number = ?2 and state = 'sealed'", params![row.board, row.number], |r| r.get(0))
                .optional()?
                .flatten();
            if row.state == "sealed" && ours.as_deref() != Some(&row.sha256[..]) {
                let bundle = self.fetch(address, &format!("/boards/{}/epochs/{}", row.board, row.number)).map_err(fail)?;
                if epoch::hash(&bundle).0[..] != row.sha256[..] {
                    return Err(Fail::Internal(format!("the writer's bundle for /{}/ epoch {} doesn't match its hash", row.board, row.number)));
                }
                let infohash = torrent::bundle_hash(&bundle, &row.board, row.number as u64);
                self.db().execute(
                    "insert or replace into epochs(board, number, state, opened, closed, sha256, bundle, infohash)
                     values(?1, ?2, 'sealed', ?3, ?4, ?5, ?6, ?7)",
                    params![row.board, row.number, row.opened, row.closed, row.sha256, bundle, infohash.0.to_vec()],
                )?;
            } else if row.state != "sealed" {
                self.db().execute(
                    "insert or replace into epochs(board, number, state, opened, closed) values(?1, ?2, ?3, ?4, ?5)",
                    params![row.board, row.number, row.state, row.opened, row.closed],
                )?;
            }
        }
        let db = self.db();
        let mut keep = db.prepare("select board, number from epochs")?;
        let ours: Vec<(String, i64)> = keep.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        for (board, number) in ours {
            if !state.epochs.iter().any(|row| row.board == board && row.number == number) {
                db.execute("delete from epochs where board = ?1 and number = ?2", params![board, number])?;
            }
        }
        drop(keep);
        drop(db);
        // Last, so nobody is sent a manifest naming epochs this server doesn't hold yet
        self.adopt(manifest)?;
        Ok(set_aside)
    }

    /// Copies a board's posts from the writer. Ours that differ from the writer's, or that it
    /// doesn't have, are moved to the orphans.
    fn copy_posts(&self, address: &str, board: &str) -> Result<usize, Fail> {
        let fail = |e: anyhow::Error| Fail::Internal(format!("{e:#}"));
        let ours: i64 = self.db().query_row("select coalesce(max(number), 0) from posts where board = ?1", [board], |r| r.get(0))?;
        // From our newest post, to see whether it's the writer's too
        let mut after = (ours - 1).max(0);
        let mut set_aside = 0;
        let mut checked = ours == 0;
        loop {
            let path = self.signed(&format!("/hosts/posts?board={board}&after={after}"));
            let rows: Vec<PostRow> = cbor::from_slice(&self.fetch(address, &path).map_err(fail)?)?;
            if !checked {
                checked = true;
                let same = rows.first().is_some_and(|row| {
                    row.number == ours
                        && self
                            .db()
                            .query_row("select record from posts where board = ?1 and number = ?2", params![board, ours], |r| r.get::<_, Vec<u8>>(0))
                            .is_ok_and(|record| record == row.record)
                });
                if !same {
                    // We've diverged: compare everything from the start
                    set_aside += self.set_aside_from(address, board)?;
                    return Ok(set_aside);
                }
            }
            let Some(last) = rows.last().map(|row| row.number) else { break };
            let full = rows.len() as u64 == POSTS_PAGE;
            self.insert_rows(&rows)?;
            after = last;
            if !full {
                break;
            }
        }
        Ok(set_aside)
    }

    fn insert_rows(&self, rows: &[PostRow]) -> Result<(), Fail> {
        let db = self.db();
        for row in rows {
            db.execute(
                "insert or ignore into posts(board, number, epoch, thread, record, author, submission) values(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![row.board, row.number, row.epoch, row.thread, row.record, row.author, row.submission],
            )?;
        }
        Ok(())
    }

    /// Compares a whole board with the writer's, setting aside every post of ours it lacks or
    /// has differently, then copies the writer's
    fn set_aside_from(&self, address: &str, board: &str) -> Result<usize, Fail> {
        let fail = |e: anyhow::Error| Fail::Internal(format!("{e:#}"));
        let mut theirs: Vec<PostRow> = Vec::new();
        loop {
            let after = theirs.last().map_or(0, |row| row.number);
            let rows: Vec<PostRow> =
                cbor::from_slice(&self.fetch(address, &self.signed(&format!("/hosts/posts?board={board}&after={after}"))).map_err(fail)?)?;
            let full = rows.len() as u64 == POSTS_PAGE;
            theirs.extend(rows);
            if !full {
                break;
            }
        }
        let db = self.db();
        let ours: Vec<(i64, Vec<u8>)> = db
            .prepare("select number, record from posts where board = ?1 order by number")?
            .query_map([board], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut set_aside = 0;
        for (number, record) in ours {
            if !theirs.iter().any(|row| row.number == number && row.record == record) {
                db.execute(
                    "insert into orphans select board, number, record, author, submission, ?3 from posts where board = ?1 and number = ?2",
                    params![board, number, now() as i64],
                )?;
                db.execute("delete from posts where board = ?1 and number = ?2", params![board, number])?;
                set_aside += 1;
            }
        }
        drop(db);
        self.insert_rows(&theirs)?;
        Ok(set_aside)
    }

    /// Becomes a standby following the writer at `address`, whose manifest is `manifest`
    fn step_down(&self, address: &str, manifest: &[u8]) -> Result<usize, Fail> {
        set_meta(&self.db(), "role", "standby")?;
        let set_aside = self.copy_from(address, manifest)?;
        *self.last_contact.lock().unwrap_or_else(|p| p.into_inner()) = now();
        Ok(set_aside)
    }

    /// Becomes the writer, in the next term
    fn take_over(&self, why: &str) -> Result<(), Fail> {
        if self.own_rank()?.is_none() {
            eprintln!("can't take over: this server isn't on the site's host list");
            return Ok(());
        }
        let site_cert: Vec<u8> = self.db().query_row("select value from meta where key = 'site_cert'", [], |r| r.get(0))?;
        if site_cert.is_empty() {
            eprintln!("can't take over: this standby has never copied the site");
            return Ok(());
        }
        let term = self.term()? + 1;
        let db = self.db();
        set_meta(&db, "term", term as i64)?;
        set_meta(&db, "role", "writer")?;
        bump(&db)?;
        eprintln!("Took over the site as its writer, in term {term}: {why}");
        Ok(())
    }

    /// Passes a member's post on to the writer, returning its answer
    pub fn forward_submission(&self, board: &str, body: &[u8]) -> Result<Response, Fail> {
        let writer = self.writer_address()?;
        let response = self
            .agent()
            .post(&format!("http://{writer}/boards/{board}/posts"))
            .set("Content-Type", "application/cbor")
            .send_bytes(body);
        match response {
            Ok(response) => {
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes).map_err(|e| Fail::Internal(e.to_string()))?;
                Ok(([(header::CONTENT_TYPE, "application/cbor")], bytes).into_response())
            }
            Err(ureq::Error::Status(code, response)) => {
                let text = response.into_string().unwrap_or_default();
                Ok((StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY), text).into_response())
            }
            Err(e) => Err(Fail::Unavailable(format!("can't reach the site's writer: {e}"))),
        }
    }

    /// Passes an anonymous web post on to the writer, then copies the result back
    pub(crate) fn forward_web(&self, board: &str, content: Content, from: Option<&str>) -> Result<Signed<Post>, Fail> {
        let writer = self.writer_address()?;
        let post = WebPost { board: board.to_string(), content, from: from.map(str::to_string) };
        let response = self.agent().post(&format!("http://{writer}{}", self.signed("/hosts/web"))).send_bytes(&cbor::to_vec(&post));
        let record: Signed<Post> = match response {
            Ok(response) => {
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes).map_err(|e| Fail::Internal(e.to_string()))?;
                cbor::from_slice(&bytes)?
            }
            Err(ureq::Error::Status(400, response)) => return Err(Fail::Refused(response.into_string().unwrap_or_default())),
            Err(e) => return Err(Fail::Unavailable(format!("can't reach the site's writer: {e}"))),
        };
        // So the page it's sent on to shows it
        let _ = self.copy_posts(&writer, board);
        Ok(record)
    }

    fn writer_address(&self) -> Result<String, Fail> {
        let relayed = self.relayed()?;
        let signed: Signed<Manifest> = cbor::from_slice(&relayed)?;
        let hosts = signed.peek()?.hosts.ok_or_else(|| Fail::Unavailable("the site has no host list".into()))?;
        let hosts = hosts.peek()?;
        hosts.get(&signed.signer).map(|host| host.address.clone()).ok_or_else(|| Fail::Unavailable("the writer isn't on the host list".into()))
    }

    /// Checks a request from another host: signed by a key on the list, recently, for this path
    fn check_request(&self, path: &str, query: Option<&str>) -> Result<PublicKey, Fail> {
        let query = query.unwrap_or("");
        let (rest, auth) = match query.rsplit_once("auth=") {
            Some((rest, auth)) => (rest.trim_end_matches('&'), auth),
            None => return Err(Fail::Forbidden),
        };
        let asked = if rest.is_empty() { path.to_string() } else { format!("{path}?{rest}") };
        let bytes = hex::decode(auth).map_err(|_| Fail::Forbidden)?;
        let signed: Signed<HostRequest> = cbor::from_slice(&bytes).map_err(|_| Fail::Forbidden)?;
        let request = signed.open(Context::HostRequest, None).map_err(|_| Fail::Forbidden)?;
        let listed = self.other_hosts()?.iter().any(|host| host.key == signed.signer);
        if !listed || request.path != asked || request.time.abs_diff(now()) > REQUEST_SLACK {
            return Err(Fail::Forbidden);
        }
        Ok(signed.signer)
    }

    fn host_state(&self) -> Result<HostState, Fail> {
        let manifest = self.manifest(now())?;
        let db = self.db();
        let boards = db
            .prepare("select name, title, authors, tier, position, web from boards order by position")?
            .query_map([], |r| Ok(BoardRow { name: r.get(0)?, title: r.get(1)?, authors: r.get(2)?, tier: r.get(3)?, position: r.get(4)?, web: r.get(5)? }))?
            .collect::<Result<_, _>>()?;
        let epochs = db
            .prepare("select board, number, state, opened, closed, coalesce(sha256, x'') from epochs order by board, number")?
            .query_map([], |r| {
                Ok(EpochRow { board: r.get(0)?, number: r.get(1)?, state: r.get(2)?, opened: r.get(3)?, closed: r.get(4)?, sha256: r.get(5)? })
            })?
            .collect::<Result<_, _>>()?;
        Ok(HostState { manifest, boards, epochs })
    }

    fn host_posts(&self, board: &str, after: i64) -> Result<Vec<PostRow>, Fail> {
        let db = self.db();
        let rows = db
            .prepare("select board, number, epoch, thread, record, author, submission from posts where board = ?1 and number > ?2 order by number limit ?3")?
            .query_map(params![board, after, POSTS_PAGE as i64], |r| {
                Ok(PostRow {
                    board: r.get(0)?,
                    number: r.get(1)?,
                    epoch: r.get(2)?,
                    thread: r.get(3)?,
                    record: r.get(4)?,
                    author: r.get(5)?,
                    submission: r.get(6)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}

pub(crate) async fn get_state(State(site): State<Arc<Site>>, RawQuery(query): RawQuery) -> Result<Response, Fail> {
    site.check_request("/hosts/state", query.as_deref())?;
    if site.role()? != Role::Writer {
        return Err(Fail::Unavailable("this server is a standby".into()));
    }
    Ok(cbor_response(&site.host_state()?))
}

pub(crate) async fn get_posts(State(site): State<Arc<Site>>, RawQuery(query): RawQuery) -> Result<Response, Fail> {
    site.check_request("/hosts/posts", query.as_deref())?;
    let query = query.unwrap_or_default();
    let field = |name: &str| query.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}="))).map(str::to_string);
    let board = field("board").ok_or(Fail::NotFound)?;
    let after: i64 = field("after").and_then(|a| a.parse().ok()).unwrap_or(0);
    Ok(cbor_response(&site.host_posts(&board, after)?))
}

pub(crate) async fn post_web(State(site): State<Arc<Site>>, RawQuery(query): RawQuery, body: Bytes) -> Result<Response, Fail> {
    site.check_request("/hosts/web", query.as_deref())?;
    let post: WebPost = cbor::from_slice(&body)?;
    let record = tokio::task::spawn_blocking(move || site.submit_web(&post.board, post.content, post.from.as_deref(), now()))
        .await
        .map_err(|e| Fail::Internal(e.to_string()))??;
    Ok(cbor_response(&record))
}

pub(crate) fn load_cert(db: &Connection) -> Result<Signed<anathemic_core::SiteCert>, Fail> {
    let bytes: Vec<u8> = db.query_row("select value from meta where key = 'site_cert'", [], |r| r.get(0))?;
    cbor::from_slice(&bytes).map_err(|_| Fail::Unavailable("this standby hasn't copied the site yet".into()))
}
