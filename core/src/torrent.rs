//! Sealed epochs as BitTorrent v1 torrents, made the same way by everyone who holds the bundle,
//! so the info hash the manifest lists can be checked by anyone and seeded with any client
//! (qBittorrent, I2PSnark, BiglyBT) as well as Anathemic's node.

use sha1::{Digest, Sha1};

use crate::{
    Error, Hash20,
    bencode::{self, Value},
    invalid,
};

/// Bundles are at most a few hundred MB, so a fixed size keeps the piece count reasonable
/// without making the torrent depend on any choice of the sealer's
pub const PIECE_LENGTH: usize = 256 << 10;

/// The bundle's file name in its torrent, which is also where clients and nodes keep it
pub fn file_name(board: &str, epoch: u64) -> String {
    format!("{board}-{epoch}.zst")
}

/// The bencoded info dictionary for a bundle
pub fn info(bundle: &[u8], board: &str, epoch: u64) -> Vec<u8> {
    let pieces: Vec<u8> = bundle.chunks(PIECE_LENGTH).flat_map(Sha1::digest).collect();
    bencode::encode(&Value::dict([
        ("length", Value::Int(bundle.len() as i64)),
        ("name", file_name(board, epoch).as_str().into()),
        ("piece length", Value::Int(PIECE_LENGTH as i64)),
        ("pieces", Value::Bytes(pieces)),
    ]))
}

pub fn info_hash(info: &[u8]) -> Hash20 {
    Hash20(Sha1::digest(info).into())
}

/// A bundle's info hash, as the manifest lists it
pub fn bundle_hash(bundle: &[u8], board: &str, epoch: u64) -> Hash20 {
    info_hash(&info(bundle, board, epoch))
}

/// A .torrent file around an info dictionary, announcing to `trackers` in order
pub fn file(info: &[u8], trackers: &[String]) -> Vec<u8> {
    // Written by hand so the info dictionary goes in byte for byte; keys in sorted order
    let mut out = b"d".to_vec();
    if let Some(first) = trackers.first() {
        out.extend(bencode::encode(&"announce".into()));
        out.extend(bencode::encode(&first.as_str().into()));
        out.extend(bencode::encode(&"announce-list".into()));
        let tier = Value::List(trackers.iter().map(|t| t.as_str().into()).collect());
        out.extend(bencode::encode(&Value::List(vec![tier])));
    }
    out.extend(bencode::encode(&"info".into()));
    out.extend(info);
    out.push(b'e');
    out
}

/// The info dictionary of a .torrent file, checked against the info hash expected
pub fn info_of<'a>(torrent: &'a [u8], expected: &Hash20) -> Result<&'a [u8], Error> {
    let info = bencode::raw_value(torrent, "info")?.ok_or_else(|| invalid("the torrent has no info"))?;
    if info_hash(info) != *expected {
        return Err(invalid("the torrent isn't the one the manifest lists"));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torrents_are_deterministic_and_checkable() {
        let bundle: Vec<u8> = (0..PIECE_LENGTH * 2 + 5).map(|i| i as u8).collect();
        let info = info(&bundle, "general", 3);
        let decoded = bencode::decode(&info).unwrap();
        assert_eq!(decoded.get("pieces").unwrap().bytes().unwrap().len(), 3 * 20);
        assert_eq!(decoded.get("name").unwrap().bytes().unwrap(), b"general-3.zst");
        assert_eq!(decoded.get("length").unwrap().int(), Some(bundle.len() as i64));

        let hash = bundle_hash(&bundle, "general", 3);
        assert_ne!(hash, bundle_hash(&bundle, "general", 4));
        let torrent = file(&info, &["http://forum.i2p/announce".into(), "http://b.i2p/announce".into()]);
        assert_eq!(info_of(&torrent, &hash).unwrap(), &info[..]);
        let parsed = bencode::decode(&torrent).unwrap();
        assert_eq!(parsed.get("announce").unwrap().bytes().unwrap(), b"http://forum.i2p/announce");
        assert!(info_of(&torrent, &bundle_hash(&bundle, "other", 3)).is_err());
        assert!(info_of(&file(&info, &[]), &hash).is_ok());
    }
}
