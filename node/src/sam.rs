//! The node's I2P side, through the router's SAM bridge: one long-lived session per site with a
//! saved destination, a local TCP port for each peer (which librqbit dials as if it were an
//! ordinary peer), and inbound streams forwarded to librqbit's listening port.

use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anathemic_core::i2p;
use anyhow::Context as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use yosemite::{DestinationKind, RouterApi, Session, SessionOptions, style::Stream};

/// How long to wait for SAM to reach a peer before giving up on it. librqbit's own connect
/// timeout is longer, so this decides when a peer is dead.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// The line a forwarded stream starts with, naming its destination
const MAX_FORWARD_LINE: usize = 4096;

pub struct Sam {
    /// This session's `.b32.i2p` address
    pub address: String,
    session: Mutex<Session<Stream>>,
    /// The local port standing in for each peer, by the hash of its destination
    bridges: Mutex<HashMap<[u8; 32], SocketAddr>>,
    verbose: bool,
}

impl Sam {
    /// Opens a session with the destination saved at `key_path`, making one the first time
    pub async fn open(sam_port: u16, key_path: &Path, verbose: bool) -> anyhow::Result<Arc<Sam>> {
        let private_key = match fs::read_to_string(key_path) {
            Ok(key) => key.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (_, key) = RouterApi::new(sam_port)
                    .generate_destination()
                    .await
                    .context("making an I2P destination; is the router's SAM bridge on?")?;
                write_secret(key_path, key.as_bytes())?;
                key
            }
            Err(e) => return Err(e.into()),
        };
        let options = SessionOptions {
            samv3_tcp_port: sam_port,
            nickname: format!("anathemic-node-{}", std::process::id()),
            destination: DestinationKind::Persistent { private_key },
            silent_forward: false,
            ..Default::default()
        };
        // After a node stops, the router holds its destination for a few seconds and refuses
        // a new session for it, so a quick restart has to wait
        let mut tries = 0;
        let session = loop {
            match Session::<Stream>::new(options.clone()).await {
                Ok(session) => break session,
                Err(_) if tries < 6 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => return Err(e).context("opening a SAM session"),
            }
        };
        let address = i2p::decode_destination(session.destination())
            .map(|bytes| i2p::b32_address(&i2p::destination_hash(&bytes)))
            .unwrap_or_default();
        Ok(Arc::new(Sam { address, session: Mutex::new(session), bridges: Mutex::new(HashMap::new()), verbose }))
    }

    /// A stream to an I2P address. The session is locked only to start the connect, so slow
    /// and dead peers don't hold up the others.
    pub async fn connect(&self, address: &str) -> anyhow::Result<yosemite::Stream> {
        let connect = self.session.lock().await.connect_detached(address);
        match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(stream) => Ok(stream?),
            Err(_) => anyhow::bail!("timed out"),
        }
    }

    /// The local port librqbit dials to reach the peer with this destination hash
    pub async fn bridge(self: &Arc<Self>, hash: [u8; 32]) -> anyhow::Result<SocketAddr> {
        let mut bridges = self.bridges.lock().await;
        if let Some(addr) = bridges.get(&hash) {
            return Ok(*addr);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        bridges.insert(hash, addr);
        let sam = self.clone();
        let address = i2p::b32_address(&hash);
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let sam = sam.clone();
                let address = address.clone();
                tokio::spawn(async move {
                    let started = Instant::now();
                    match sam.connect(&address).await {
                        Ok(mut stream) => {
                            if sam.verbose {
                                println!("  connected to {} in {:.1}s", short(&address), started.elapsed().as_secs_f64());
                            }
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                        }
                        Err(e) if sam.verbose => println!("  couldn't reach {}: {e}", short(&address)),
                        Err(_) => {}
                    }
                });
            }
        });
        Ok(addr)
    }

    /// Hands every stream others open to us to librqbit, listening at `torrents`, or to the
    /// HTTP mirror at `http`. BitTorrent's handshake starts with the byte 19; HTTP with a
    /// method name.
    pub async fn forward_inbound(self: &Arc<Self>, torrents: SocketAddr, http: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        self.session.lock().await.forward(port).await.context("asking SAM to forward inbound streams")?;
        let verbose = self.verbose;
        tokio::spawn(async move {
            while let Ok((mut from_router, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // The router first sends a line naming the peer's destination
                    let Ok(line) = read_line(&mut from_router).await else { return };
                    if verbose {
                        let address = line
                            .split_whitespace()
                            .next()
                            .and_then(i2p::decode_destination)
                            .map(|d| i2p::b32_address(&i2p::destination_hash(&d)))
                            .unwrap_or_default();
                        println!("  {} connected to us", short(&address));
                    }
                    let Ok(first) = from_router.read_u8().await else { return };
                    let to = if first == 19 { torrents } else { http };
                    if let Ok(mut local) = TcpStream::connect(to).await
                        && local.write_all(&[first]).await.is_ok()
                    {
                        let _ = tokio::io::copy_bidirectional(&mut from_router, &mut local).await;
                    }
                });
            }
        });
        Ok(())
    }
}

async fn read_line(stream: &mut TcpStream) -> anyhow::Result<String> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(byte);
        anyhow::ensure!(line.len() <= MAX_FORWARD_LINE, "the router's first line is too long");
    }
}

/// The start of an address, for logs
pub fn short(address: &str) -> &str {
    &address[..address.len().min(10)]
}

fn write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    fs::create_dir_all(path.parent().expect("key files are in a folder"))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)?;
    Ok(())
}
