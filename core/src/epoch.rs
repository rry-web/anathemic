//! Sealing epochs into bundles, and checking bundles and posts from anywhere

use std::io::Read;

use sha2::{Digest, Sha256};

use crate::{Context, Epoch, Error, Hash32, Post, PublicKey, SealedRef, Signed, cbor, invalid};

/// A post's hash: of exactly what was signed, the signer and the signature
pub fn post_hash(signed: &Signed<Post>) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(signed.body.as_slice());
    hasher.update(signed.signer.0);
    hasher.update(signed.signature);
    Hash32(hasher.finalize().into())
}

/// An epoch's index: the hash of its place in the board's chain and each post's hash, in
/// order. Purging a post swaps it for its hash, which leaves the index as it was.
pub fn index(epoch: &Epoch) -> Hash32 {
    let mut entries: Vec<(u64, Hash32)> = epoch.posts.iter().map(|signed| {
        let number = signed.peek().map_or(0, |post| post.number);
        (number, post_hash(signed))
    }).collect();
    entries.extend(epoch.purged.iter().map(|tomb| (tomb.number, tomb.hash)));
    entries.sort_by_key(|(number, _)| *number);
    hash(&cbor::to_vec(&(&epoch.board, epoch.number, &epoch.prev, entries)))
}

/// What the next epoch's `prev` holds for this one
pub fn link(sealed: &SealedRef) -> Hash32 {
    sealed.index.unwrap_or(sealed.sha256)
}

const ZSTD_LEVEL: i32 = 10;
/// Larger bundles are refused before they're fully decompressed
const MAX_EPOCH_BYTES: u64 = 256 << 20;

/// The compressed bundle and its hash
pub fn seal(epoch: &Epoch) -> (Vec<u8>, Hash32) {
    let bundle = zstd::encode_all(&cbor::to_vec(epoch)[..], ZSTD_LEVEL)
        .expect("compressing in memory can't fail");
    let hash = hash(&bundle);
    (bundle, hash)
}

pub fn hash(bytes: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(bytes).into())
}

/// Reads a bundle's contents
pub fn decoder(bundle: &[u8]) -> std::io::Result<impl Read + '_> {
    zstd::Decoder::new(bundle)
}

/// Checks a bundle against the manifest's entry for it, then decodes it
pub fn open_bundle(bundle: &[u8], expected: &SealedRef) -> Result<Epoch, Error> {
    if bundle.len() as u64 != expected.size || hash(bundle) != expected.sha256 {
        return Err(invalid(format!("epoch {} doesn't match its hash", expected.epoch)));
    }
    let mut decoded = Vec::new();
    zstd::Decoder::new(bundle)
        .map_err(|e| Error::Decode(e.to_string()))?
        .take(MAX_EPOCH_BYTES + 1)
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decode(e.to_string()))?;
    if decoded.len() as u64 > MAX_EPOCH_BYTES {
        return Err(invalid("epoch is too large"));
    }
    cbor::from_slice(&decoded)
}

/// Checks a post one of the site's `keys` signed, and the author's signature if it shows one
pub fn check_post(
    signed: &Signed<Post>,
    keys: &[PublicKey],
    board: &str,
    epoch: u64,
) -> Result<Post, Error> {
    if !keys.contains(&signed.signer) {
        return Err(Error::WrongSigner);
    }
    let post = signed.open(Context::Post, None)?;
    if post.board != board || post.epoch != epoch {
        return Err(invalid(format!("post {} is filed in the wrong place", post.number)));
    }
    post.content.check()?;
    if post.web && post.author.is_some() {
        return Err(invalid(format!("post {} came from the web but names an author", post.number)));
    }
    if let Some(author) = &post.author {
        let submission = author.open(Context::Submission, None)?;
        if submission.board != board || submission.content != post.content {
            return Err(invalid(format!("post {} differs from what its author signed", post.number)));
        }
    }
    Ok(post)
}

/// Checks a sealed epoch's place in its board's chain, its index if it has one, and every post
/// in it
pub fn check_epoch(
    epoch: &Epoch,
    board: &str,
    number: u64,
    prev: Option<Hash32>,
    expected_index: Option<Hash32>,
    keys: &[PublicKey],
) -> Result<Vec<Post>, Error> {
    if epoch.board != board || epoch.number != number {
        return Err(invalid(format!("epoch {number} is filed in the wrong place")));
    }
    if epoch.prev != prev {
        return Err(invalid(format!("epoch {number} doesn't follow the previous one")));
    }
    if expected_index.is_some_and(|expected| index(epoch) != expected) {
        return Err(invalid(format!("epoch {number} doesn't match its index")));
    }
    let posts = epoch
        .posts
        .iter()
        .map(|signed| check_post(signed, keys, board, number))
        .collect::<Result<Vec<_>, _>>()?;
    check_order(&posts)?;
    Ok(posts)
}

/// Post numbers only rise
pub fn check_order(posts: &[Post]) -> Result<(), Error> {
    if posts.windows(2).any(|pair| pair[0].number >= pair[1].number) {
        return Err(invalid("posts are out of order"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Content, FORMAT, SecretKey, Submission};

    fn post(site: &SecretKey, author: &SecretKey, number: u64, epoch: u64) -> Signed<Post> {
        let content = Content {
            thread: (number > 1).then_some(1),
            title: (number == 1).then(|| "A thread".to_string()),
            body: format!("post {number}"),
        };
        let submission = Submission {
            board: "general".into(),
            content: content.clone(),
            anonymous: false,
            time: 0,
        };
        let post = Post {
            board: "general".into(),
            number,
            epoch,
            accepted: 0,
            content,
            author: Some(author.sign(Context::Submission, &submission)),
            web: false,
        };
        site.sign(Context::Post, &post)
    }

    fn epoch(site: &SecretKey, number: u64, prev: Option<Hash32>, posts: &[u64]) -> Epoch {
        let author = SecretKey::generate();
        Epoch {
            format: FORMAT,
            board: "general".into(),
            number,
            prev,
            posts: posts.iter().map(|&n| post(site, &author, n, number)).collect(),
            purged: vec![],
        }
    }

    #[test]
    fn sealed_epochs_open_and_chain() {
        let site = SecretKey::generate();
        let first = epoch(&site, 0, None, &[1, 2]);
        let (bundle, hash) = seal(&first);
        let entry = SealedRef { epoch: 0, sha256: hash, size: bundle.len() as u64, infohash: None, index: None };
        let opened = open_bundle(&bundle, &entry).unwrap();
        assert_eq!(check_epoch(&opened, "general", 0, None, None, &[site.public()]).unwrap().len(), 2);

        let second = epoch(&site, 1, Some(hash), &[3]);
        assert!(check_epoch(&second, "general", 1, Some(hash), None, &[site.public()]).is_ok());
        assert!(check_epoch(&second, "general", 1, None, None, &[site.public()]).is_err());
    }

    #[test]
    fn altered_bundles_and_strangers_posts_are_refused() {
        let site = SecretKey::generate();
        let (mut bundle, hash) = seal(&epoch(&site, 0, None, &[1]));
        let entry = SealedRef { epoch: 0, sha256: hash, size: bundle.len() as u64, infohash: None, index: None };
        bundle[10] ^= 1;
        assert!(open_bundle(&bundle, &entry).is_err());

        let stranger = SecretKey::generate();
        let forged = epoch(&stranger, 0, None, &[1]);
        assert!(check_epoch(&forged, "general", 0, None, None, &[site.public()]).is_err());

        let shuffled = epoch(&site, 0, None, &[2, 1]);
        assert!(check_epoch(&shuffled, "general", 0, None, None, &[site.public()]).is_err());
    }

    #[test]
    fn posts_must_match_what_their_author_signed() {
        let site = SecretKey::generate();
        let author = SecretKey::generate();
        let mut post = post(&site, &author, 1, 0).peek().unwrap();
        post.content.body = "words the author never wrote".into();
        let resigned = site.sign(Context::Post, &post);
        assert!(check_post(&resigned, &[site.public()], "general", 0).is_err());
    }

    #[test]
    fn purging_a_post_keeps_the_index() {
        let site = SecretKey::generate();
        let mut sealed = epoch(&site, 0, None, &[1, 2, 3]);
        let before = index(&sealed);
        let removed = sealed.posts.remove(1);
        sealed.purged.push(crate::Tombstone { number: 2, hash: post_hash(&removed) });
        assert_eq!(index(&sealed), before);
        assert_eq!(check_epoch(&sealed, "general", 0, None, Some(before), &[site.public()]).unwrap().len(), 2);

        // A tombstone with any other hash changes it
        sealed.purged[0].hash = Hash32([1; 32]);
        assert!(check_epoch(&sealed, "general", 0, None, Some(before), &[site.public()]).is_err());
    }
}
