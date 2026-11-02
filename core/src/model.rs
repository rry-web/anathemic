use serde::{Deserialize, Serialize};

use crate::{
    Error, PublicKey, Signed, invalid,
    moderation::{ModCert, RevocationHead},
};

/// Seconds since the Unix epoch
pub type Time = u64;

/// The format version written into manifests
pub const FORMAT: u32 = 1;
/// The format of epochs sealed now: 2 adds the index and tombstones for purged posts
pub const EPOCH_FORMAT: u32 = 2;
pub const MAX_TITLE: usize = 200;
pub const MAX_BODY: usize = 20_000;
pub const MAX_SITE_NAME: usize = 100;
pub const MAX_DESCRIPTION: usize = 2_000;

/// Whether a board's posts show who wrote them
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Authors {
    /// Every post shows its author's key
    Shown,
    /// No post does; the server still knows, for bans and quotas
    Hidden,
    /// Each poster chooses
    Choice,
}

impl Authors {
    pub fn name(self) -> &'static str {
        match self {
            Authors::Shown => "shown",
            Authors::Hidden => "hidden",
            Authors::Choice => "choice",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "shown" => Some(Authors::Shown),
            "hidden" => Some(Authors::Hidden),
            "choice" => Some(Authors::Choice),
            _ => None,
        }
    }
}

/// Board names go into links and file names: 1 to 32 of a-z, 0-9 and '-'
pub fn valid_board_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A site's I2P address, as people type it: `<52 characters>.b32.i2p` or a registered name
/// such as `forum.i2p`
pub fn valid_address(address: &str) -> bool {
    let Some(name) = address.strip_suffix(".i2p") else { return false };
    address.len() <= 255
        && !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The site's name and description: one line of at most [`MAX_SITE_NAME`] characters, and at
/// most [`MAX_DESCRIPTION`] characters of post markup
pub fn check_site_text(name: &str, description: &str) -> Result<(), Error> {
    if name.contains(['\n', '\r']) || name.chars().count() > MAX_SITE_NAME {
        return Err(invalid(format!("a site's name is one line of at most {MAX_SITE_NAME} characters")));
    }
    if description.chars().count() > MAX_DESCRIPTION {
        return Err(invalid(format!("a site's description is at most {MAX_DESCRIPTION} characters")));
    }
    Ok(())
}

/// The root key's statement that a site key speaks for the site
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteCert {
    pub site_key: PublicKey,
    pub issued: Time,
}

/// What a person writes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Content {
    /// The number of the thread's first post, for a reply; none for a new thread
    pub thread: Option<u64>,
    /// A new thread's title; none for a reply
    pub title: Option<String>,
    /// A small Markdown subset, rendered by the client
    pub body: String,
}

impl Content {
    pub fn check(&self) -> Result<(), Error> {
        match (&self.thread, &self.title) {
            (None, None) => return Err(invalid("a new thread needs a title")),
            (Some(_), Some(_)) => return Err(invalid("a reply has no title")),
            _ => {}
        }
        if let Some(title) = &self.title {
            if title.trim().is_empty() || title.contains(['\n', '\r']) {
                return Err(invalid("a title is one line of text"));
            }
            if title.chars().count() > MAX_TITLE {
                return Err(invalid(format!("titles are at most {MAX_TITLE} characters")));
            }
        }
        if self.body.trim().is_empty() {
            return Err(invalid("the post is empty"));
        }
        if self.body.chars().count() > MAX_BODY {
            return Err(invalid(format!("posts are at most {MAX_BODY} characters")));
        }
        Ok(())
    }
}

/// A post as its author signs it and sends it to the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Submission {
    pub board: String,
    pub content: Content,
    /// Asks for the author to be left out, on boards where posters choose
    pub anonymous: bool,
    /// The author's clock, so an old submission can't be replayed much later
    pub time: Time,
}

/// A post as the server accepted it; travels signed by the site key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Post {
    pub board: String,
    pub number: u64,
    pub epoch: u64,
    pub accepted: Time,
    pub content: Content,
    /// The author's signed submission, when the post shows its author
    pub author: Option<Signed<Submission>>,
    /// Sent from a web page, so no member signed it: the site key is all that vouches for it
    #[serde(default, skip_serializing_if = "is_false")]
    pub web: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Post {
    pub fn author_key(&self) -> Option<PublicKey> {
        self.author.as_ref().map(|signed| signed.signer)
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash32(#[serde(with = "serde_bytes")] pub [u8; 32]);

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// A BitTorrent v1 info hash
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash20(#[serde(with = "serde_bytes")] pub [u8; 20]);

impl std::fmt::Debug for Hash20 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// A sealed epoch, as the manifest lists it
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedRef {
    pub epoch: u64,
    /// Of the compressed bundle, which is what mirrors hold
    pub sha256: Hash32,
    pub size: u64,
    /// The bundle's torrent (see [`crate::torrent`]), which mirrors share over I2P. Missing
    /// only from manifests made before mirroring
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infohash: Option<Hash20>,
    /// The hash of the epoch's posts, each by its own hash (see [`crate::epoch::index`]). It
    /// stays the same when a post is purged and the bundle remade without it, so it's what the
    /// next epoch chains to. Missing from epochs sealed before format 2, which chain to `sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<Hash32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoardEntry {
    pub name: String,
    pub title: String,
    pub authors: Authors,
    pub tier: u8,
    /// Oldest first, numbered from 0 with no gaps
    pub sealed: Vec<SealedRef>,
    /// The epochs after the sealed ones: settling, then the open one last
    pub unsealed: Vec<u64>,
    /// Whether the site's web pages take anonymous posts from browsers, which no member signs
    #[serde(default)]
    pub web_posting: bool,
}

/// One of the servers the root key allows to run the site
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub key: PublicKey,
    /// 0 for the operator's own server; standbys take over in order of rank
    pub rank: u8,
    /// The host's own I2P address, where the site's servers reach each other (each also
    /// answers at the site's shared address)
    pub address: String,
    /// Who runs it, for the operator's records
    pub name: String,
    /// No longer allowed to publish the site; the posts it signed still count
    #[serde(default)]
    pub retired: bool,
}

/// The servers allowed to run the site, signed by the root key. While one is down, the next by
/// rank takes over, so the site keeps taking posts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hosts {
    /// Rises with every change; clients never accept a lower one than they've seen
    pub sequence: u64,
    pub issued: Time,
    pub hosts: Vec<Host>,
}

impl Hosts {
    pub fn get(&self, key: &PublicKey) -> Option<&Host> {
        self.hosts.iter().find(|host| host.key == *key)
    }
}

/// What one of a site's servers asks another for; signed with its host key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostRequest {
    /// The path and query asked for, without this request
    pub path: String,
    pub time: Time,
}

/// The site's current state; travels signed by the site key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub root: PublicKey,
    pub site_cert: Signed<SiteCert>,
    /// Rises with every change; clients never accept a lower one than they've seen
    pub sequence: u64,
    pub published: Time,
    /// What the operator calls the site; may be empty. The root key is still its identity
    #[serde(default)]
    pub name: String,
    /// Post markup, shown on the site's front page
    #[serde(default)]
    pub description: String,
    /// The I2P addresses the site answers at, the preferred one first
    #[serde(default)]
    pub addresses: Vec<String>,
    pub boards: Vec<BoardEntry>,
    /// Rises each time a different server takes over the site. A manifest from a higher term
    /// wins over any from a lower one, whatever their sequence numbers.
    #[serde(default)]
    pub term: u64,
    /// The servers allowed to run the site, when there's more than the first. With a list,
    /// only the keys on it count; without one, only the site key in `site_cert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Signed<Hosts>>,
    /// The root key's appointments of moderators, each in force until the next for its key
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub moderators: Vec<Signed<ModCert>>,
    /// The revocation log's length and hash
    #[serde(default, skip_serializing_if = "is_empty_log")]
    pub revocations: RevocationHead,
}

fn is_empty_log(head: &RevocationHead) -> bool {
    head.count == 0
}

impl Manifest {
    pub fn board(&self, name: &str) -> Option<&BoardEntry> {
        self.boards.iter().find(|board| board.name == name)
    }

    /// The site's name, or its root key's fingerprint if it has none
    pub fn title(&self) -> String {
        if self.name.trim().is_empty() { format!("Site {}", self.root.fingerprint()) } else { self.name.clone() }
    }
}

/// A board's posts for one epoch; sealed, it is the bundle mirrors hold
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Epoch {
    pub format: u32,
    pub board: String,
    pub number: u64,
    /// The previous sealed epoch's link (its index, or its hash before format 2), chaining
    /// the board's history
    pub prev: Option<Hash32>,
    pub posts: Vec<Signed<Post>>,
    /// Posts purged by moderators, by number and hash, so the index still adds up
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purged: Vec<Tombstone>,
}

/// What's left of a purged post in its sealed epoch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tombstone {
    pub number: u64,
    /// The post's hash (see [`crate::epoch::post_hash`])
    pub hash: Hash32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert!(valid_address("forum.i2p"));
        assert!(valid_address("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"));
        for bad in ["i2p", ".i2p", "forum.com", "Forum.i2p", "a..i2p", "-a.i2p", "http://forum.i2p", "fo rum.i2p"] {
            assert!(!valid_address(bad), "{bad}");
        }
    }
}
