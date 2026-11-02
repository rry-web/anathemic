//! librqbit over I2P through a SAM bridge: announce our destination to an I2P tracker over a
//! SAM stream, then give librqbit a local TCP port for each I2P peer, each forwarded to a SAM
//! stream. Usage: rqtest <sam port> <torrent file> <tracker b32 host> <output dir>
use std::{sync::Arc, time::{Duration, Instant}};
use librqbit::{AddTorrent, AddTorrentOptions, AddTorrentResponse, Session as Rq, SessionOptions as RqOptions};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, sync::Mutex};
use yosemite::{style::Stream, Session, SessionOptions};

fn escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("%{b:02X}")).collect()
}

/// The bytes of the bencoded string after `key`
fn bstring<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let at = data.windows(key.len()).position(|w| w == key)? + key.len();
    let colon = at + data[at..].iter().position(|&b| b == b':')?;
    let len: usize = std::str::from_utf8(&data[at..colon]).ok()?.parse().ok()?;
    data.get(colon + 1..colon + 1 + len)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (port, torrent, tracker, out) = (args[1].parse::<u16>()?, std::fs::read(&args[2])?, args[3].clone(), args[4].clone());
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let t0 = Instant::now();
    let log = move |msg: String| println!("{:7.1}s {msg}", t0.elapsed().as_secs_f64());

    // The info dict runs from after "4:info" to the torrent's last byte but one
    let start = torrent.windows(6).position(|w| w == b"4:info").unwrap() + 6;
    let info_hash: [u8; 20] = sha1(&torrent[start..torrent.len() - 1]);

    let options = SessionOptions { samv3_tcp_port: port, nickname: "rqbit-bridge".into(), ..Default::default() };
    let sam = Arc::new(Mutex::new(Session::<Stream>::new(options).await?));
    log("SAM session up".into());

    // Announce, over a SAM stream; the tracker learns our destination from the tunnel
    let peers = loop {
        let attempt = async {
            let mut stream = sam.lock().await.connect(&tracker).await?;
            let request = format!(
                "GET /announce?info_hash={}&peer_id=-RQ0001-anathemic01&port=6881&uploaded=0&downloaded=0&left=1&compact=1&event=started HTTP/1.0\r\nHost: {tracker}\r\nConnection: close\r\n\r\n",
                escape(&info_hash)
            );
            stream.write_all(request.as_bytes()).await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            anyhow::Ok(response)
        };
        match tokio::time::timeout(Duration::from_secs(90), attempt).await {
            Ok(Ok(response)) => {
                let peers = bstring(&response, b"5:peers").unwrap_or_default();
                let b32: Vec<String> = peers
                    .chunks_exact(32)
                    .map(|h| format!("{}.b32.i2p", data_encoding::BASE32_NOPAD.encode(h).to_lowercase()))
                    .collect();
                if !b32.is_empty() { break b32; }
                log("tracker has no peers yet".into());
            }
            other => log(format!("announce failed: {:?}", other.map(|r| r.err().map(|e| e.to_string())))),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    };
    log(format!("tracker gave {} peers", peers.len()));

    // A local port per I2P peer, forwarded over SAM
    let mut initial = Vec::new();
    for peer in peers {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        initial.push(listener.local_addr()?);
        let sam = sam.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let sam = sam.clone();
                let peer = peer.clone();
                tokio::spawn(async move {
                    let started = Instant::now();
                    let stream = sam.lock().await.connect(&peer).await;
                    match stream {
                        Ok(mut i2p) => {
                            println!("  bridge to {}… open after {:.1}s", &peer[..10], started.elapsed().as_secs_f64());
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut i2p).await;
                        }
                        Err(e) => println!("  bridge to {}… failed: {e}", &peer[..10]),
                    }
                });
            }
        });
    }

    let rq = Rq::new_with_opts(out.clone().into(), RqOptions {
        dht: None, disable_trackers: true, disable_local_service_discovery: true, listen: None, ..Default::default()
    }).await?;
    let opts = AddTorrentOptions {
        initial_peers: Some(initial), disable_trackers: true, overwrite: true, output_folder: Some(out), ..Default::default()
    };
    let handle = match rq.add_torrent(AddTorrent::from_bytes(torrent.clone()), Some(opts)).await? {
        AddTorrentResponse::Added(_, handle) => handle,
        _ => anyhow::bail!("not added"),
    };
    let started = Instant::now();
    let mut first_byte = None;
    loop {
        let stats = handle.stats();
        if first_byte.is_none() && stats.progress_bytes > 0 { first_byte = Some(started.elapsed().as_secs_f64()); }
        if stats.finished { break; }
        if started.elapsed().as_secs() % 10 == 0 { log(format!("{} / {} bytes", stats.progress_bytes, stats.total_bytes)); }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let total = handle.stats().total_bytes as f64;
    let secs = started.elapsed().as_secs_f64();
    let first = first_byte.unwrap_or(0.0);
    log(format!("RESULT librqbit over SAM: {:.0} KB in {secs:.1}s (first byte after {first:.1}s) = {:.0} KB/s after the first byte",
        total / 1024.0, total / 1024.0 / (secs - first).max(0.1)));
    Ok(())
}

fn sha1(data: &[u8]) -> [u8; 20] {
    // librqbit computes the info hash too, but we need it before adding the torrent
    use sha1_smol::Sha1;
    Sha1::from(data).digest().bytes()
}
