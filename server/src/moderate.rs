//! Moderation on the server: moderators the root key appoints, the revocation log, and what
//! its entries do here. Hides and bans are worked out from the log whenever they're needed
//! ([`Site::moderation`]); a purge also deletes the post's bytes, re-sealing its epoch around a
//! tombstone if it's already sealed.

use std::{path::Path, sync::Arc};

use anathemic_core::{
    Context, EPOCH_FORMAT, Epoch, Hash32, Post, PublicKey, Signed, Time, Tombstone, cbor, epoch,
    moderation::{self, Action, Logged, ModCert, Moderation, Power, Revocation, RevocationHead, Target},
    now, torrent,
};
use anyhow::bail;
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    response::Response,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{Fail, Site, bump, cbor_response, hosts, load_posts, open_db, refuse};

/// Log entries sent per request
const LOG_PAGE: u64 = 1000;

pub(crate) fn load_moderators(db: &Connection) -> Result<Vec<Signed<ModCert>>, Fail> {
    let bytes: Vec<u8> = db.query_row("select value from meta where key = 'moderators'", [], |r| r.get(0))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(cbor::from_slice(&bytes)?)
}

/// Appoints a moderator, or changes an appointment: a new certificate signed by the root key,
/// in force from now
pub fn add_moderator(
    dir: &Path,
    root_key: Option<&Path>,
    key: PublicKey,
    name: &str,
    boards: Vec<String>,
    powers: Vec<Power>,
    expires: Option<Time>,
) -> anyhow::Result<()> {
    if powers.is_empty() {
        bail!("give at least one power: hide, purge or ban");
    }
    issue(dir, root_key, ModCert { key, name: name.to_string(), boards, powers, issued: now(), expires })
}

/// Ends an appointment: what they did before still counts
pub fn end_moderator(dir: &Path, root_key: Option<&Path>, key: PublicKey) -> anyhow::Result<()> {
    let at = now();
    issue(dir, root_key, ModCert { key, name: String::new(), boards: vec![], powers: vec![], issued: at, expires: Some(at) })
}

fn issue(dir: &Path, root_key: Option<&Path>, cert: ModCert) -> anyhow::Result<()> {
    let db = open_db(dir)?;
    let root = hosts::root_key(dir, root_key)?;
    let stored: Vec<u8> = db.query_row("select value from meta where key = 'root'", [], |r| r.get(0))?;
    if root.public().0.to_vec() != stored {
        bail!("that isn't this site's root key");
    }
    let mut certs = load_moderators(&db).map_err(|f| anyhow::anyhow!("{f:?}"))?;
    certs.push(root.sign(Context::ModCert, &cert));
    db.execute("insert or replace into meta values('moderators', ?1)", [cbor::to_vec(&certs)])?;
    bump(&db)?;
    Ok(())
}

/// The appointments in force, as of now
pub fn moderators(dir: &Path) -> anyhow::Result<Vec<ModCert>> {
    let db = open_db(dir)?;
    let root: Vec<u8> = db.query_row("select value from meta where key = 'root'", [], |r| r.get(0))?;
    let root = PublicKey(root.try_into().map_err(|_| anyhow::anyhow!("bad root key"))?);
    let certs = moderation::open_certs(&load_moderators(&db).map_err(|f| anyhow::anyhow!("{f:?}"))?, &root)?;
    let at = now();
    Ok(certs.into_iter().filter(|cert| !cert.powers.is_empty() && cert.expires.is_none_or(|end| at < end)).collect())
}

fn load_log(db: &Connection, from: u64, take: u64) -> Result<Vec<Signed<Logged>>, Fail> {
    let rows: Vec<Vec<u8>> = db
        .prepare("select entry from revocations where number >= ?1 order by number limit ?2")?
        .query_map(params![from as i64, take as i64], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    rows.iter().map(|row| Ok(cbor::from_slice(row)?)).collect()
}

pub(crate) fn log_head(db: &Connection) -> Result<RevocationHead, Fail> {
    Ok(moderation::head(&load_log(db, 0, u64::MAX >> 1)?))
}

/// Empties a post's stored copy, keeping its hash; re-seals its epoch if it's sealed and
/// `reseal`. Standbys don't re-seal: they copy the writer's new bundle.
fn purge_post(db: &Connection, board: &str, number: u64, reseal: bool) -> Result<(), Fail> {
    let row: Option<(Vec<u8>, i64)> = db
        .query_row("select record, epoch from posts where board = ?1 and number = ?2", params![board, number as i64], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((record, epoch_number)) = row else { return Ok(()) };
    if record.is_empty() {
        return Ok(());
    }
    let signed: Signed<Post> = cbor::from_slice(&record)?;
    let hash = epoch::post_hash(&signed);
    db.execute(
        "update posts set record = x'', purged = ?3 where board = ?1 and number = ?2",
        params![board, number as i64, hash.0.to_vec()],
    )?;
    let sealed: Option<String> =
        db.query_row("select state from epochs where board = ?1 and number = ?2", params![board, epoch_number], |r| r.get(0)).optional()?;
    if reseal && sealed.as_deref() == Some("sealed") {
        reseal_epoch(db, board, epoch_number)?;
    }
    Ok(())
}

/// Tombstones for an epoch's purged posts
pub(crate) fn tombstones(db: &Connection, board: &str, number: i64) -> Result<Vec<Tombstone>, Fail> {
    let rows: Vec<(i64, Vec<u8>)> = db
        .prepare("select number, purged from posts where board = ?1 and epoch = ?2 and record = x'' order by number")?
        .query_map(params![board, number], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|(number, hash)| {
            let hash = Hash32(hash.try_into().map_err(|_| Fail::Internal("bad purged hash".into()))?);
            Ok(Tombstone { number: number as u64, hash })
        })
        .collect()
}

/// Remakes a sealed epoch's bundle without its purged posts. Its index, and so the board's
/// chain, stays the same; its hash and torrent change.
fn reseal_epoch(db: &Connection, board: &str, number: i64) -> Result<(), Fail> {
    let (old, index): (Vec<u8>, Option<Vec<u8>>) = db.query_row(
        "select bundle, idx from epochs where board = ?1 and number = ?2",
        params![board, number],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let Some(index) = index else {
        return Err(Fail::Internal(format!("/{board}/ epoch {number} was sealed before purging was possible")));
    };
    let mut decoded = Vec::new();
    std::io::Read::read_to_end(&mut zstd_decoder(&old)?, &mut decoded).map_err(|e| Fail::Internal(e.to_string()))?;
    let previous: Epoch = cbor::from_slice(&decoded)?;
    let remade = Epoch {
        format: EPOCH_FORMAT,
        board: board.to_string(),
        number: number as u64,
        prev: previous.prev,
        posts: load_posts(db, board, number as u64)?,
        purged: tombstones(db, board, number)?,
    };
    if epoch::index(&remade).0[..] != index[..] {
        return Err(Fail::Internal(format!("re-sealing /{board}/ epoch {number} would change its index")));
    }
    let (bundle, hash) = epoch::seal(&remade);
    let infohash = torrent::bundle_hash(&bundle, board, number as u64);
    db.execute(
        "update epochs set sha256 = ?3, bundle = ?4, infohash = ?5 where board = ?1 and number = ?2",
        params![board, number, hash.0.to_vec(), bundle, infohash.0.to_vec()],
    )?;
    Ok(())
}

fn zstd_decoder(bundle: &[u8]) -> Result<impl std::io::Read + '_, Fail> {
    epoch::decoder(bundle).map_err(|e| Fail::Internal(e.to_string()))
}

impl Site {
    /// The keys whose entries and posts count: the host list's, or the site key alone
    fn site_keys(&self, db: &Connection) -> Result<Vec<PublicKey>, Fail> {
        Ok(match hosts::load_hosts(db)? {
            Some(signed) => signed.peek()?.hosts.into_iter().map(|host| host.key).collect(),
            None => vec![hosts::load_cert(db)?.peek()?.site_key],
        })
    }

    /// What the log adds up to now
    pub fn moderation(&self) -> Result<Arc<Moderation>, Fail> {
        let db = self.db();
        let count: i64 = db.query_row("select count(*) from revocations", [], |r| r.get(0))?;
        let certs = load_moderators(&db)?;
        // New appointments change the page of moderators, not the log
        let version = (count as u64, certs.len());
        let mut cache = self.moderation.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((cached, moderation)) = cache.as_ref()
            && *cached == version
        {
            return Ok(moderation.clone());
        }
        let log = load_log(&db, 0, u64::MAX >> 1)?;
        let moderators = moderation::open_certs(&certs, &self.root)?;
        let keys = if log.is_empty() { Vec::new() } else { self.site_keys(&db)? };
        let moderation = Arc::new(moderation::replay(&log, &moderation::head(&log), &keys, &moderators)?);
        *cache = Some((version, moderation.clone()));
        Ok(moderation)
    }

    /// Logs a moderator's decision, and carries it out. A standby passes it on to the writer.
    pub fn moderate(&self, entry: Signed<Revocation>, now: Time) -> Result<Signed<Logged>, Fail> {
        if self.role()? == hosts::Role::Standby {
            return self.forward_revocation(&entry);
        }
        let current = self.moderation()?;
        let db = self.db();
        let moderators = moderation::open_certs(&load_moderators(&db)?, &self.root)?;
        let revocation = moderation::check_entry(&entry, &moderators, now)?;
        match (&revocation.target, &revocation.action) {
            (Target::Post { board, number }, action) => {
                let row: Option<(Vec<u8>, String, Option<Vec<u8>>)> = db
                    .query_row(
                        "select p.record, e.state, e.idx from posts p join epochs e on e.board = p.board and e.number = p.epoch
                         where p.board = ?1 and p.number = ?2",
                        params![board, *number as i64],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((record, state, index)) = row else { return refuse("there's no such post") };
                if record.is_empty() {
                    return refuse("that post was purged");
                }
                match action {
                    Action::Restore if !current.hidden.contains_key(&(board.clone(), *number)) => return refuse("that post isn't hidden"),
                    Action::Hide if current.hidden.contains_key(&(board.clone(), *number)) => return refuse("that post is already hidden"),
                    Action::Purge if state == "sealed" && index.is_none() => {
                        return refuse("that post's epoch was sealed before purging was possible; hide it instead");
                    }
                    _ => {}
                }
            }
            (Target::Member { key, board }, Action::Restore) if !current.bans.contains_key(&(*key, board.clone())) => {
                return refuse("that member isn't banned there");
            }
            _ => {}
        }
        let count: i64 = db.query_row("select count(*) from revocations", [], |r| r.get(0))?;
        let logged = self.key.sign(Context::Logged, &Logged { number: count as u64, accepted: now, entry });
        db.execute("insert into revocations values(?1, ?2)", params![count, cbor::to_vec(&logged)])?;
        if let (Target::Post { board, number }, Action::Purge) = (&revocation.target, &revocation.action) {
            purge_post(&db, board, *number, true)?;
        }
        bump(&db)?;
        Ok(logged)
    }

    fn forward_revocation(&self, entry: &Signed<Revocation>) -> Result<Signed<Logged>, Fail> {
        let bytes = self.forward_to_writer("/revocations", &cbor::to_vec(entry))?;
        Ok(cbor::from_slice(&bytes)?)
    }

    /// Copies the writer's log past what this host has, purging as it goes; the writer's new
    /// bundles come with its epochs
    pub(crate) fn copy_log(&self, address: &str, keys: &[PublicKey]) -> Result<(), Fail> {
        loop {
            let ours: i64 = self.db().query_row("select count(*) from revocations", [], |r| r.get(0))?;
            let body = self
                .fetch(address, &format!("/revocations?from={ours}"))
                .map_err(|e| Fail::Internal(format!("{e:#}")))?;
            let entries: Vec<Signed<Logged>> = cbor::from_slice(&body)?;
            let db = self.db();
            for (i, signed) in entries.iter().enumerate() {
                let logged = signed.open(Context::Logged, None)?;
                if !keys.contains(&signed.signer) || logged.number != ours as u64 + i as u64 {
                    return Err(Fail::Internal("the writer's revocation log doesn't follow ours".into()));
                }
                db.execute("insert into revocations values(?1, ?2)", params![logged.number as i64, cbor::to_vec(signed)])?;
                let revocation = logged.entry.peek()?;
                if let (Target::Post { board, number }, Action::Purge) = (&revocation.target, &revocation.action) {
                    purge_post(&db, board, *number, false)?;
                }
            }
            if (entries.len() as u64) < LOG_PAGE {
                return Ok(());
            }
        }
    }
}

pub(crate) async fn post_revocation(State(site): State<Arc<Site>>, body: Bytes) -> Result<Response, Fail> {
    let entry: Signed<Revocation> = cbor::from_slice(&body)?;
    let logged = tokio::task::spawn_blocking(move || site.moderate(entry, now()))
        .await
        .map_err(|e| Fail::Internal(e.to_string()))??;
    Ok(cbor_response(&logged))
}

pub(crate) async fn get_revocations(State(site): State<Arc<Site>>, RawQuery(query): RawQuery) -> Result<Response, Fail> {
    let from = query
        .as_deref()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("from=")))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let log = load_log(&site.db(), from, LOG_PAGE)?;
    Ok(cbor_response(&log))
}
