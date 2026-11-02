//! Sealing epochs into bundles, and checking bundles and posts from anywhere

use std::io::Read;

use sha2::{Digest, Sha256};

use crate::{Context, Epoch, Error, Hash32, Post, PublicKey, SealedRef, Signed, cbor, invalid};

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

/// Checks a post the site key signed, and the author's signature if it shows one
pub fn check_post(
    signed: &Signed<Post>,
    site_key: &PublicKey,
    board: &str,
    epoch: u64,
) -> Result<Post, Error> {
    let post = signed.open(Context::Post, Some(site_key))?;
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

/// Checks a sealed epoch's place in its board's chain, and every post in it
pub fn check_epoch(
    epoch: &Epoch,
    board: &str,
    number: u64,
    prev: Option<Hash32>,
    site_key: &PublicKey,
) -> Result<Vec<Post>, Error> {
    if epoch.board != board || epoch.number != number {
        return Err(invalid(format!("epoch {number} is filed in the wrong place")));
    }
    if epoch.prev != prev {
        return Err(invalid(format!("epoch {number} doesn't follow the previous one")));
    }
    let posts = epoch
        .posts
        .iter()
        .map(|signed| check_post(signed, site_key, board, number))
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
        }
    }

    #[test]
    fn sealed_epochs_open_and_chain() {
        let site = SecretKey::generate();
        let first = epoch(&site, 0, None, &[1, 2]);
        let (bundle, hash) = seal(&first);
        let entry = SealedRef { epoch: 0, sha256: hash, size: bundle.len() as u64, infohash: None };
        let opened = open_bundle(&bundle, &entry).unwrap();
        assert_eq!(check_epoch(&opened, "general", 0, None, &site.public()).unwrap().len(), 2);

        let second = epoch(&site, 1, Some(hash), &[3]);
        assert!(check_epoch(&second, "general", 1, Some(hash), &site.public()).is_ok());
        assert!(check_epoch(&second, "general", 1, None, &site.public()).is_err());
    }

    #[test]
    fn altered_bundles_and_strangers_posts_are_refused() {
        let site = SecretKey::generate();
        let (mut bundle, hash) = seal(&epoch(&site, 0, None, &[1]));
        let entry = SealedRef { epoch: 0, sha256: hash, size: bundle.len() as u64, infohash: None };
        bundle[10] ^= 1;
        assert!(open_bundle(&bundle, &entry).is_err());

        let stranger = SecretKey::generate();
        let forged = epoch(&stranger, 0, None, &[1]);
        assert!(check_epoch(&forged, "general", 0, None, &site.public()).is_err());

        let shuffled = epoch(&site, 0, None, &[2, 1]);
        assert!(check_epoch(&shuffled, "general", 0, None, &site.public()).is_err());
    }

    #[test]
    fn posts_must_match_what_their_author_signed() {
        let site = SecretKey::generate();
        let author = SecretKey::generate();
        let mut post = post(&site, &author, 1, 0).peek().unwrap();
        post.content.body = "words the author never wrote".into();
        let resigned = site.sign(Context::Post, &post);
        assert!(check_post(&resigned, &site.public(), "general", 0).is_err());
    }
}
