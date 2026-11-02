//! Moderation: moderators the root key appoints, and the site's revocation log.
//!
//! A moderator signs a [`Revocation`]; the site's writer numbers it, stamps the time and
//! countersigns it as a [`Logged`] entry. The log only grows, and each entry's hash folds into the
//! next ([`chain`]), so the manifest's [`RevocationHead`] pins the whole log: a mirror can relay
//! it but can't drop or change an entry. Clients replay the log ([`replay`]) to learn what's
//! hidden, purged and banned.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Context, Error, Hash32, PublicKey, Signed, Time, invalid};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Power {
    /// Hide posts, and restore them
    Hide,
    /// Delete posts' bytes everywhere, for good
    Purge,
    /// Refuse a member's posts, and lift that
    Ban,
}

impl Power {
    pub fn parse(name: &str) -> Option<Power> {
        match name {
            "hide" => Some(Power::Hide),
            "purge" => Some(Power::Purge),
            "ban" => Some(Power::Ban),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Power::Hide => "hide",
            Power::Purge => "purge",
            Power::Ban => "ban",
        }
    }
}

/// The root key's appointment of a moderator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModCert {
    /// The moderator's member key for the site
    pub key: PublicKey,
    pub name: String,
    /// The boards they moderate; empty for all of them
    pub boards: Vec<String>,
    pub powers: Vec<Power>,
    pub issued: Time,
    /// After this, their new entries don't count. Ending an appointment is a new certificate
    /// for the same key that expires at once.
    pub expires: Option<Time>,
}

impl ModCert {
    /// `logged` allows an entry in the very second the appointment ended: the writer checked it
    /// when it logged it, and times are only to the second
    fn covers(&self, board: Option<&str>, power: Power, at: Time, logged: bool) -> bool {
        let board_ok = self.boards.is_empty() || board.is_some_and(|b| self.boards.iter().any(|mine| mine == b));
        let in_force = at >= self.issued && self.expires.is_none_or(|end| at < end || (logged && at == end));
        board_ok && self.powers.contains(&power) && in_force
    }

    pub fn in_force(&self, now: Time) -> bool {
        !self.powers.is_empty() && now >= self.issued && self.expires.is_none_or(|end| now < end)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Post { board: String, number: u64 },
    /// A member, on one board or (with none) the whole site
    Member { key: PublicKey, board: Option<String> },
}

impl Target {
    fn board(&self) -> Option<&str> {
        match self {
            Target::Post { board, .. } => Some(board),
            Target::Member { board, .. } => board.as_deref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Honest clients don't show the post; it stays in its epoch, and can be restored
    Hide,
    /// The post's bytes are deleted everywhere; its epoch keeps only its hash
    Purge,
    /// The member's posts are refused, until a time or for good
    Ban { until: Option<Time> },
    /// Undoes a hide or a ban of the same target
    Restore,
}

/// What a moderator decides
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocation {
    pub target: Target,
    pub action: Action,
    /// Shown to readers in place of what was removed
    pub reason: String,
    /// The moderator's clock
    pub time: Time,
}

pub const MAX_REASON: usize = 200;

/// A revocation as the site logged it, countersigned by the writer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Logged {
    /// From 0, with no gaps
    pub number: u64,
    /// The writer's clock: the time the entry counts from
    pub accepted: Time,
    pub entry: Signed<Revocation>,
}

/// The log's length and its chained hash, as the manifest gives them
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationHead {
    pub count: u64,
    pub hash: Hash32,
}

/// The chained hash after one more entry
pub fn chain(prev: &Hash32, entry: &Signed<Logged>) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(prev.0);
    hasher.update(entry.body.as_slice());
    hasher.update(entry.signer.0);
    hasher.update(entry.signature);
    Hash32(hasher.finalize().into())
}

/// The head of a whole log
pub fn head(log: &[Signed<Logged>]) -> RevocationHead {
    let hash = log.iter().fold(Hash32([0; 32]), |hash, entry| chain(&hash, entry));
    RevocationHead { count: log.len() as u64, hash }
}

/// One checked entry of the log, for showing it to readers
#[derive(Clone, Debug)]
pub struct Entry {
    pub number: u64,
    /// When the site logged it
    pub accepted: Time,
    pub moderator: PublicKey,
    pub revocation: Revocation,
}

impl Entry {
    /// What the moderator did, as a verb for the target that follows
    pub fn verb(&self) -> String {
        match (&self.revocation.target, &self.revocation.action) {
            (_, Action::Hide) => "Hid".into(),
            (_, Action::Purge) => "Purged".into(),
            (_, Action::Ban { until: None }) => "Banned for good".into(),
            (_, Action::Ban { until: Some(end) }) => format!("Banned until {}", crate::utc(*end)),
            (Target::Post { .. }, Action::Restore) => "Restored".into(),
            (Target::Member { .. }, Action::Restore) => "Lifted the ban on".into(),
        }
    }
}

/// What the log adds up to, and the checked log itself, so anyone can see who did what and why
#[derive(Clone, Debug, Default)]
pub struct Moderation {
    /// Hidden posts, with the reason
    pub hidden: HashMap<(String, u64), String>,
    pub purged: HashMap<(String, u64), String>,
    /// Banned members, by key and board (none for site-wide): until when, if not for good
    pub bans: HashMap<(PublicKey, Option<String>), Option<Time>>,
    /// Every entry, oldest first
    pub log: Vec<Entry>,
    /// Every appointment the root key has made, ended ones too, as [`open_certs`] gives them
    pub moderators: Vec<ModCert>,
}

impl Moderation {
    /// Why a post isn't shown, if it isn't
    pub fn removed(&self, board: &str, number: u64) -> Option<&str> {
        let key = (board.to_string(), number);
        self.purged.get(&key).or_else(|| self.hidden.get(&key)).map(String::as_str)
    }

    pub fn is_purged(&self, board: &str, number: u64) -> bool {
        self.purged.contains_key(&(board.to_string(), number))
    }

    /// Whether `key` may post on `board` at `now`
    pub fn banned(&self, key: &PublicKey, board: &str, now: Time) -> bool {
        [None, Some(board.to_string())].into_iter().any(|scope| {
            self.bans.get(&(*key, scope)).is_some_and(|until| until.is_none_or(|end| now < end))
        })
    }

    /// The name a moderator went by when they made an entry at `at`
    pub fn moderator_name(&self, key: &PublicKey, at: Time) -> Option<&str> {
        self.moderators
            .iter()
            .filter(|cert| cert.key == *key && cert.issued <= at && !cert.name.is_empty())
            .max_by_key(|cert| cert.issued)
            .map(|cert| cert.name.as_str())
    }

    /// Each moderator's latest appointment with any powers, those in force at `now` first, then
    /// the most recent. An ended one's `expires` says when it ended.
    pub fn appointments(&self, now: Time) -> Vec<&ModCert> {
        let mut latest: HashMap<PublicKey, &ModCert> = HashMap::new();
        for cert in self.moderators.iter().filter(|cert| !cert.powers.is_empty()) {
            let entry = latest.entry(cert.key).or_insert(cert);
            if cert.issued >= entry.issued {
                *entry = cert;
            }
        }
        let mut appointments: Vec<&ModCert> = latest.into_values().collect();
        appointments.sort_by_key(|cert| (!cert.in_force(now), std::cmp::Reverse(cert.issued), cert.key.0));
        appointments
    }

    fn apply(&mut self, target: &Target, action: &Action, reason: &str) {
        match (target, action) {
            (Target::Post { board, number }, Action::Hide) => {
                self.hidden.insert((board.clone(), *number), reason.to_string());
            }
            (Target::Post { board, number }, Action::Purge) => {
                self.purged.insert((board.clone(), *number), reason.to_string());
            }
            (Target::Post { board, number }, Action::Restore) => {
                self.hidden.remove(&(board.clone(), *number));
            }
            (Target::Member { key, board }, Action::Ban { until }) => {
                self.bans.insert((*key, board.clone()), *until);
            }
            (Target::Member { key, board }, Action::Restore) => {
                self.bans.remove(&(*key, board.clone()));
            }
            _ => {}
        }
    }
}

/// The power an action needs
pub fn power(target: &Target, action: &Action) -> Result<Power, Error> {
    match (target, action) {
        (Target::Post { .. }, Action::Hide | Action::Restore) => Ok(Power::Hide),
        (Target::Post { .. }, Action::Purge) => Ok(Power::Purge),
        (Target::Member { .. }, Action::Ban { .. } | Action::Restore) => Ok(Power::Ban),
        _ => Err(invalid("that action doesn't apply to that target")),
    }
}

/// Checks a new moderator's entry against the certificates, as of `at`
pub fn check_entry(entry: &Signed<Revocation>, moderators: &[ModCert], at: Time) -> Result<Revocation, Error> {
    check(entry, moderators, at, false)
}

fn check(entry: &Signed<Revocation>, moderators: &[ModCert], at: Time, logged: bool) -> Result<Revocation, Error> {
    let revocation = entry.open(Context::Revocation, None)?;
    if revocation.reason.chars().count() > MAX_REASON {
        return Err(invalid(format!("reasons are at most {MAX_REASON} characters")));
    }
    let needed = power(&revocation.target, &revocation.action)?;
    let board = revocation.target.board();
    if !moderators.iter().any(|cert| cert.key == entry.signer && cert.covers(board, needed, at, logged)) {
        return Err(invalid("the moderator has no such power here"));
    }
    Ok(revocation)
}

/// Checks a whole log, signed by the site's `keys` and its `moderators`, against the head the
/// manifest gives, and adds it up
pub fn replay(
    log: &[Signed<Logged>],
    expected: &RevocationHead,
    keys: &[PublicKey],
    moderators: &[ModCert],
) -> Result<Moderation, Error> {
    if head(log) != *expected {
        return Err(invalid("the revocation log doesn't match the manifest"));
    }
    let mut moderation = Moderation::default();
    for (i, signed) in log.iter().enumerate() {
        if !keys.contains(&signed.signer) {
            return Err(Error::WrongSigner);
        }
        let logged = signed.open(Context::Logged, None)?;
        if logged.number != i as u64 {
            return Err(invalid("the revocation log is out of order"));
        }
        let revocation = check(&logged.entry, moderators, logged.accepted, true)?;
        moderation.apply(&revocation.target, &revocation.action, &revocation.reason);
        moderation.log.push(Entry { number: logged.number, accepted: logged.accepted, moderator: logged.entry.signer, revocation });
    }
    moderation.moderators = moderators.to_vec();
    Ok(moderation)
}

/// The moderators' certificates in a manifest, checked against the root key. A later
/// certificate for a key replaces an earlier one only for entries after it was issued, so
/// what a moderator did while appointed still counts.
pub fn open_certs(certs: &[Signed<ModCert>], root: &PublicKey) -> Result<Vec<ModCert>, Error> {
    let mut opened: Vec<ModCert> = certs.iter().map(|cert| cert.open(Context::ModCert, Some(root))).collect::<Result<_, _>>()?;
    // Each certificate counts until the next one for the same key is issued
    opened.sort_by_key(|cert| (cert.key.0, cert.issued));
    for i in 0..opened.len().saturating_sub(1) {
        if opened[i].key == opened[i + 1].key {
            let next = opened[i + 1].issued;
            opened[i].expires = Some(opened[i].expires.map_or(next, |end| end.min(next)));
        }
    }
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    fn cert(key: &SecretKey, boards: &[&str], powers: &[Power], issued: Time, expires: Option<Time>) -> ModCert {
        ModCert {
            key: key.public(),
            name: "mod".into(),
            boards: boards.iter().map(|b| b.to_string()).collect(),
            powers: powers.to_vec(),
            issued,
            expires,
        }
    }

    fn log_entry(site: &SecretKey, number: u64, accepted: Time, entry: Signed<Revocation>) -> Signed<Logged> {
        site.sign(Context::Logged, &Logged { number, accepted, entry })
    }

    fn revocation(target: Target, action: Action) -> Revocation {
        Revocation { target, action, reason: "spam".into(), time: 0 }
    }

    #[test]
    fn logs_replay_into_what_is_hidden_purged_and_banned() {
        let site = SecretKey::generate();
        let moderator = SecretKey::generate();
        let member = SecretKey::generate().public();
        let certs = [cert(&moderator, &["general"], &[Power::Hide, Power::Purge, Power::Ban], 0, None)];
        let post = |n| Target::Post { board: "general".into(), number: n };
        let entries = [
            revocation(post(3), Action::Hide),
            revocation(post(4), Action::Purge),
            revocation(Target::Member { key: member, board: Some("general".into()) }, Action::Ban { until: Some(500) }),
            revocation(post(3), Action::Restore),
            revocation(post(5), Action::Hide),
        ];
        let log: Vec<_> = entries
            .iter()
            .enumerate()
            .map(|(i, r)| log_entry(&site, i as u64, 10, moderator.sign(Context::Revocation, r)))
            .collect();
        let moderation = replay(&log, &head(&log), &[site.public()], &certs).unwrap();
        assert_eq!(moderation.removed("general", 3), None);
        assert_eq!(moderation.removed("general", 4), Some("spam"));
        assert!(moderation.is_purged("general", 4));
        assert!(moderation.removed("general", 5).is_some());
        assert!(moderation.banned(&member, "general", 100));
        assert!(!moderation.banned(&member, "general", 500));
        assert!(!moderation.banned(&member, "other", 100));
        assert_eq!(moderation.log.len(), 5);
        assert_eq!(moderation.log[3].verb(), "Restored");
        assert_eq!(moderation.moderator_name(&moderator.public(), 10), Some("mod"));

        // A dropped or changed entry no longer matches the head
        assert!(replay(&log[..4], &head(&log), &[site.public()], &certs).is_err());
        // Entries the writer didn't countersign, or a moderator made outside their board,
        // don't count
        assert!(replay(&log, &head(&log), &[SecretKey::generate().public()], &certs).is_err());
        let elsewhere = vec![log_entry(&site, 0, 10, moderator.sign(Context::Revocation, &revocation(
            Target::Post { board: "other".into(), number: 1 },
            Action::Hide,
        )))];
        assert!(replay(&elsewhere, &head(&elsewhere), &[site.public()], &certs).is_err());
    }

    #[test]
    fn appointments_end_with_a_newer_certificate() {
        let root = SecretKey::generate();
        let moderator = SecretKey::generate();
        let first = cert(&moderator, &[], &[Power::Hide], 0, None);
        let ended = cert(&moderator, &[], &[], 100, Some(100));
        let certs = open_certs(&[root.sign(Context::ModCert, &first), root.sign(Context::ModCert, &ended)], &root.public()).unwrap();
        let hide = moderator.sign(Context::Revocation, &revocation(Target::Post { board: "general".into(), number: 1 }, Action::Hide));
        assert!(check_entry(&hide, &certs, 50).is_ok());
        assert!(check_entry(&hide, &certs, 150).is_err());
        assert!(open_certs(&[moderator.sign(Context::ModCert, &first)], &root.public()).is_err());

        // The ended appointment still shows, with when it ended, and keeps its name
        let moderation = Moderation { moderators: certs, ..Default::default() };
        let appointments = moderation.appointments(150);
        assert_eq!(appointments.len(), 1);
        assert!(!appointments[0].in_force(150) && appointments[0].expires == Some(100));
        assert_eq!(moderation.moderator_name(&moderator.public(), 150), Some("mod"));
    }
}
