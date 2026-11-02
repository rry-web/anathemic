use serde::{Deserialize, Serialize};

use crate::{Error, PublicKey, Signed, invalid};

/// Seconds since the Unix epoch
pub type Time = u64;

/// The format version written into manifests and sealed epochs
pub const FORMAT: u32 = 1;
pub const MAX_TITLE: usize = 200;
pub const MAX_BODY: usize = 20_000;

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
}

impl Post {
    pub fn author_key(&self) -> Option<PublicKey> {
        self.author.as_ref().map(|signed| signed.signer)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash32(#[serde(with = "serde_bytes")] pub [u8; 32]);

impl std::fmt::Debug for Hash32 {
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
    pub boards: Vec<BoardEntry>,
}

impl Manifest {
    pub fn board(&self, name: &str) -> Option<&BoardEntry> {
        self.boards.iter().find(|board| board.name == name)
    }
}

/// A board's posts for one epoch; sealed, it is the bundle mirrors hold
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Epoch {
    pub format: u32,
    pub board: String,
    pub number: u64,
    /// The previous sealed epoch's hash, chaining the board's history
    pub prev: Option<Hash32>,
    pub posts: Vec<Signed<Post>>,
}
