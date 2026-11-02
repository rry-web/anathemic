//! A tracker on localhost that librqbit announces to. Each announce goes on over SAM to the
//! site's real tracker, so the tracker sees this node's destination, and each I2P peer in the
//! reply comes back as a local bridge port. librqbit then re-announces on its own schedule,
//! and never sees an `.i2p` address it would try to look up on the clearnet.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anathemic_core::{
    bencode::{self, Value},
    i2p,
};
use axum::{
    Router,
    extract::{Path, RawQuery, State},
    response::{IntoResponse, Response},
    routing::get,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::sam::{Sam, short};

/// Tracker replies are small; a larger one is refused
const MAX_REPLY: u64 = 1 << 20;
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Proxy {
    sam: Arc<Sam>,
    /// The I2P trackers' hosts, by the index in their local address
    hosts: Mutex<Vec<String>>,
    addr: SocketAddr,
    verbose: bool,
}

impl Proxy {
    pub async fn start(sam: Arc<Sam>, verbose: bool) -> anyhow::Result<Arc<Proxy>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy = Arc::new(Proxy { sam, hosts: Mutex::new(Vec::new()), addr: listener.local_addr()?, verbose });
        let app = Router::new().route("/{index}/announce", get(announce)).with_state(proxy.clone());
        tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(proxy)
    }

    /// The local address librqbit announces to, for the tracker at an I2P host
    pub fn url_for(&self, host: &str) -> String {
        let mut hosts = self.hosts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let index = hosts.iter().position(|h| h == host).unwrap_or_else(|| {
            hosts.push(host.to_string());
            hosts.len() - 1
        });
        format!("http://{}/{index}/announce", self.addr)
    }

    fn host(&self, index: usize) -> Option<String> {
        self.hosts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(index).cloned()
    }

    /// Sends an announce to the I2P tracker and returns its bencoded reply
    async fn forward(&self, host: &str, query: &str) -> anyhow::Result<Value> {
        let mut stream = self.sam.connect(host).await?;
        let request = format!(
            "GET /announce?{query} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: anathemic-node\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        (&mut stream).take(MAX_REPLY).read_to_end(&mut response).await?;
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow::anyhow!("not an HTTP reply"))?;
        let status = String::from_utf8_lossy(&response[..split]);
        anyhow::ensure!(status.split_whitespace().nth(1) == Some("200"), "the tracker answered {}", status.lines().next().unwrap_or(""));
        Ok(bencode::decode(&response[split + 4..])?)
    }

    /// The reply with each I2P peer swapped for its local bridge, in compact IPv4 form
    async fn translate(&self, reply: Value) -> anyhow::Result<Value> {
        if reply.get("failure reason").is_some() {
            return Ok(reply);
        }
        let mut hashes = Vec::new();
        match reply.get("peers") {
            Some(Value::Bytes(compact)) => hashes.extend(compact.as_chunks::<32>().0.iter().copied()),
            Some(Value::List(peers)) => {
                for peer in peers {
                    let destination = peer.get("ip").and_then(Value::bytes).map(String::from_utf8_lossy);
                    let bytes = destination.as_deref().and_then(|d| i2p::decode_destination(d.trim_end_matches(".i2p")));
                    hashes.extend(bytes.map(|bytes| i2p::destination_hash(&bytes)));
                }
            }
            _ => {}
        }
        let mut peers = Vec::new();
        for hash in hashes {
            let addr = self.sam.bridge(hash).await?;
            let IpAddr::V4(ip) = addr.ip() else { continue };
            peers.extend(ip.octets());
            peers.extend(addr.port().to_be_bytes());
        }
        let count = |key| reply.get(key).and_then(Value::int).unwrap_or(0);
        Ok(Value::dict([
            ("interval", Value::Int(reply.get("interval").and_then(Value::int).unwrap_or(1200))),
            ("complete", Value::Int(count("complete"))),
            ("incomplete", Value::Int(count("incomplete"))),
            ("peers", Value::Bytes(peers)),
        ]))
    }
}

/// librqbit's query, asking the I2P tracker for the compact form
fn compact(query: &str) -> String {
    let mut pairs: Vec<&str> = query.split('&').filter(|pair| !pair.is_empty() && !pair.starts_with("compact=")).collect();
    pairs.push("compact=1");
    pairs.join("&")
}

async fn announce(State(proxy): State<Arc<Proxy>>, Path(index): Path<usize>, RawQuery(query): RawQuery) -> Response {
    let Some(host) = proxy.host(index) else {
        return failure("unknown tracker");
    };
    let query = compact(query.as_deref().unwrap_or(""));
    let result = match tokio::time::timeout(ANNOUNCE_TIMEOUT, proxy.forward(&host, &query)).await {
        Ok(Ok(reply)) => proxy.translate(reply).await,
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow::anyhow!("timed out")),
    };
    match result {
        Ok(reply) => {
            if proxy.verbose {
                let peers = reply.get("peers").and_then(Value::bytes).map_or(0, |p| p.len() / 6);
                match reply.get("failure reason").and_then(Value::bytes) {
                    Some(reason) => println!("  tracker {} refused: {}", short(&host), String::from_utf8_lossy(reason)),
                    None => println!("  tracker {} gave {peers} peers", short(&host)),
                }
            }
            bencode::encode(&reply).into_response()
        }
        Err(e) => {
            if proxy.verbose {
                println!("  announcing to {} failed: {e}", short(&host));
            }
            failure(&format!("announcing over I2P failed: {e}"))
        }
    }
}

fn failure(reason: &str) -> Response {
    bencode::encode(&Value::dict([("failure reason", reason.into())])).into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn asks_for_compact_replies() {
        assert_eq!(super::compact("info_hash=x&compact=0&left=1"), "info_hash=x&left=1&compact=1");
        assert_eq!(super::compact(""), "compact=1");
    }
}
