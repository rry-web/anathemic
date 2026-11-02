//! The site's BitTorrent tracker, for its sealed epochs only. Peers are I2P destinations, and
//! each one is taken from the `X-I2P-DestB64` header the i2pd server tunnel adds, never from the
//! request, so nobody can announce someone else. Replies are in I2P's compact form (the SHA-256
//! of each destination, the bytes behind its `.b32.i2p` address), which libtorrent, I2PSnark
//! and Anathemic's node read, or as a list of full destinations for clients that ask for that.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anathemic_core::{
    Hash20, Time,
    bencode::{self, Value},
    i2p, now,
};
use axum::{
    extract::{RawQuery, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};

use crate::Site;

pub const DESTINATION_HEADER: &str = "x-i2p-destb64";
/// Seconds peers are asked to wait between announces
pub const INTERVAL: u64 = 20 * 60;
/// Peers that haven't announced for this long are forgotten
const EXPIRY: u64 = 2 * INTERVAL + 5 * 60;
const MAX_REPLY_PEERS: usize = 50;
/// The most peers remembered for one epoch
const MAX_SWARM: usize = 2000;

#[derive(Default)]
pub struct Tracker {
    swarms: Mutex<HashMap<Hash20, HashMap<[u8; 32], Peer>>>,
}

struct Peer {
    /// In I2P's base64, as the tunnel gave it
    destination: String,
    seen: Time,
    seeding: bool,
}

/// One announce, as the request's query gives it
pub struct Announce {
    pub infohash: Hash20,
    pub stopped: bool,
    pub seeding: bool,
    pub compact: bool,
    pub wanted: usize,
}

impl Tracker {
    /// Records an announce from `destination` and returns the reply's peers and counts
    fn announce(&self, destination: &str, hash: [u8; 32], request: &Announce, now: Time) -> (Vec<(String, [u8; 32])>, usize, usize) {
        let mut swarms = self.swarms.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let swarm = swarms.entry(request.infohash).or_default();
        swarm.retain(|_, peer| now < peer.seen + EXPIRY);
        if request.stopped {
            swarm.remove(&hash);
        } else if swarm.len() < MAX_SWARM || swarm.contains_key(&hash) {
            swarm.insert(hash, Peer { destination: destination.to_string(), seen: now, seeding: request.seeding });
        }
        let seeders = swarm.values().filter(|peer| peer.seeding).count();
        let leechers = swarm.len() - seeders;
        // Seeders are no use to each other
        let peers = swarm
            .iter()
            .filter(|(other, peer)| **other != hash && !(request.seeding && peer.seeding))
            .take(request.wanted.min(MAX_REPLY_PEERS))
            .map(|(other, peer)| (peer.destination.clone(), *other))
            .collect();
        if swarm.is_empty() {
            swarms.remove(&request.infohash);
        }
        (peers, seeders, leechers)
    }
}

/// The fields of an announce's query that matter here
pub fn parse_query(query: &str) -> Result<Announce, &'static str> {
    let mut infohash = None;
    let mut announce = Announce { infohash: Hash20([0; 20]), stopped: false, seeding: false, compact: false, wanted: MAX_REPLY_PEERS };
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value).ok_or("the query is badly escaped")?;
        let text = || String::from_utf8_lossy(&value).into_owned();
        match key {
            "info_hash" => infohash = Some(Hash20(value.try_into().map_err(|_| "info_hash isn't 20 bytes")?)),
            "event" => announce.stopped = text() == "stopped",
            "left" => announce.seeding = text() == "0",
            "compact" => announce.compact = text() == "1",
            "numwant" => announce.wanted = text().parse().unwrap_or(MAX_REPLY_PEERS),
            _ => {}
        }
    }
    announce.infohash = infohash.ok_or("there's no info_hash")?;
    Ok(announce)
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Some(out)
}

fn reply(value: Value) -> Response {
    ([(header::CONTENT_TYPE, "text/plain")], bencode::encode(&value)).into_response()
}

/// Trackers answer failures with a reason in the body, not an HTTP error
fn failure(reason: &str) -> Response {
    reply(Value::dict([("failure reason", reason.into())]))
}

pub async fn announce(State(site): State<Arc<Site>>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    let Some(destination) = headers.get(DESTINATION_HEADER).and_then(|value| value.to_str().ok()) else {
        return failure("announce through the site's I2P address");
    };
    let Some(bytes) = i2p::decode_destination(destination) else {
        return failure("the tunnel gave a destination that can't be read");
    };
    let request = match parse_query(query.as_deref().unwrap_or("")) {
        Ok(request) => request,
        Err(reason) => return failure(reason),
    };
    match site.has_torrent(&request.infohash) {
        Ok(true) => {}
        Ok(false) => return failure("this tracker tracks only this site's sealed epochs"),
        Err(fail) => return fail.into_response(),
    }
    let (peers, seeders, leechers) = site.tracker.announce(destination, i2p::destination_hash(&bytes), &request, now());
    let peers = if request.compact {
        Value::Bytes(peers.iter().flat_map(|(_, hash)| *hash).collect())
    } else {
        // I2PSnark's form: the full destination as the "ip", and a port it ignores
        Value::List(
            peers
                .iter()
                .map(|(destination, _)| {
                    Value::dict([("ip", format!("{destination}.i2p").as_str().into()), ("port", Value::Int(6881))])
                })
                .collect(),
        )
    };
    reply(Value::dict([
        ("interval", Value::Int(INTERVAL as i64)),
        ("complete", Value::Int(seeders as i64)),
        ("incomplete", Value::Int(leechers as i64)),
        ("peers", peers),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        let request = parse_query("info_hash=%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14&peer_id=x&left=0&compact=1&event=started").unwrap();
        assert_eq!(request.infohash.0[19], 0x14);
        assert!(request.seeding && request.compact && !request.stopped);
        assert!(parse_query("info_hash=%01").is_err());
        assert!(parse_query("left=5").is_err());
        assert!(parse_query("info_hash=%zz").is_err());
    }

    #[test]
    fn swarms() {
        let tracker = Tracker::default();
        let mut request = Announce { infohash: Hash20([7; 20]), stopped: false, seeding: true, compact: true, wanted: 50 };
        let (peers, seeders, _) = tracker.announce("seed", [1; 32], &request, 100);
        assert!(peers.is_empty());
        assert_eq!(seeders, 1);

        request.seeding = false;
        let (peers, seeders, leechers) = tracker.announce("leech", [2; 32], &request, 110);
        assert_eq!(peers, vec![("seed".to_string(), [1; 32])]);
        assert_eq!((seeders, leechers), (1, 1));

        // The seeder hears of the leecher; long after, the seeder is forgotten
        request.seeding = true;
        assert_eq!(tracker.announce("seed", [1; 32], &request, 120).0.len(), 1);
        request.seeding = false;
        assert!(tracker.announce("leech", [2; 32], &request, 120 + EXPIRY).0.is_empty());

        request.stopped = true;
        tracker.announce("leech", [2; 32], &request, 130 + EXPIRY);
        assert!(tracker.swarms.lock().unwrap().is_empty());
    }
}
