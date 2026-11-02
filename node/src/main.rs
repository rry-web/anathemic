//! anathemic-node: keeps a copy of a site's sealed epochs and shares them with other nodes as
//! torrents inside I2P. It reads the site's signed manifest, seeds the epochs it already holds,
//! and fetches the rest from other nodes, taking the server's copy only if no node has one.
//!
//! BitTorrent is librqbit's. Everything it sends goes through the router's SAM bridge: librqbit
//! announces to a tracker on localhost that passes announces on over I2P
//! ([`tracker_proxy`]), dials a local port for each I2P peer, and is reached through SAM
//! forwarding ([`sam`]). An allowlist of 127.0.0.1 stops it dialing anything else, even
//! addresses other peers suggest.

mod sam;
mod tracker_proxy;

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anathemic_client::{Client, cache_dir};
use anathemic_core::{Hash20, SealedRef, epoch::open_bundle, torrent, verify::Verified};
use anyhow::Context as _;
use clap::Parser;
use librqbit::{
    AddTorrent, AddTorrentOptions, AddTorrentResponse, ConnectionOptions, ListenerMode, ListenerOptions,
    ManagedTorrent, PeerConnectionOptions, Session, SessionOptions, api::TorrentIdOrHash,
};

type ManagedTorrentHandle = Arc<ManagedTorrent>;

/// librqbit's defaults suit the clearnet: 10 s to connect and handshake, 10 s for each
/// message, keep-alives every 120 s. Over I2P a round trip takes 1–2.5 s and tunnels stall for
/// seconds at a time, and the SAM connect (up to 60 s) happens inside librqbit's handshake.
/// Measured in experiments/i2p-torrents: these keep live peers instead of dropping them.
const I2P_PACE: PeerConnectionOptions = PeerConnectionOptions {
    connect_timeout: Some(Duration::from_secs(90)),
    read_write_timeout: Some(Duration::from_secs(120)),
    keep_alive_interval: Some(Duration::from_secs(30)),
    max_request_window: None,
};

/// Mirror an Anathemic swarmboard's sealed epochs over I2P torrents
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The site, as for anathemic-client
    server: String,
    /// Where member keys, pinned sites and cached epochs live, shared with anathemic-client
    /// [default: ~/.anathemic]
    #[arg(long)]
    home: Option<PathBuf>,
    /// The I2P router's HTTP proxy, for fetching the manifest
    #[arg(long, default_value = "http://127.0.0.1:4444")]
    proxy: String,
    /// Fetch the manifest directly, without the proxy (for a server on this computer)
    #[arg(long)]
    direct: bool,
    /// The I2P router's SAM port
    #[arg(long, default_value_t = 7656)]
    sam: u16,
    /// Mirror only these boards; repeat for more [default: all]
    #[arg(long = "board")]
    boards: Vec<String>,
    /// Seconds to look for other nodes before taking the server's copy of an epoch
    #[arg(long, default_value_t = 300)]
    peer_seconds: u64,
    /// Never take the server's copy; wait for other nodes (for testing mirrors)
    #[arg(long)]
    peers_only: bool,
    /// Seconds between checks of the manifest for newly sealed epochs
    #[arg(long, default_value_t = 600)]
    check_seconds: u64,
    /// Seconds between progress reports
    #[arg(long, default_value_t = 300)]
    status_seconds: u64,
    /// Report each connection and announce
    #[arg(short, long)]
    verbose: bool,
}

struct Node {
    cli: Cli,
    client: Arc<Client>,
    rq: Arc<Session>,
    proxy: Arc<tracker_proxy::Proxy>,
    folder: PathBuf,
    /// The epochs being fetched or seeded, by info hash
    held: tokio::sync::Mutex<HashMap<Hash20, (String, ManagedTorrentHandle)>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = match &cli.home {
        Some(home) => home.clone(),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME isn't set; pass --home")?).join(".anathemic"),
    };
    let proxy = (!cli.direct).then_some(cli.proxy.as_str());
    let client = Arc::new(Client::new(&cli.server, proxy, home.clone())?);
    let site = manifest(&client).await?;
    let root = site.manifest.root;

    // One destination per site, so sites' trackers can't link the nodes that mirror them
    let node_dir = home.join("node");
    let key_path = node_dir.join(format!("{}.dest", root.to_hex()));
    let sam = sam::Sam::open(cli.sam, &key_path, cli.verbose).await?;
    let proxy = tracker_proxy::Proxy::start(sam.clone(), cli.verbose).await?;

    let folder = cache_dir(&home, &root);
    fs::create_dir_all(&folder)?;
    let allowlist = node_dir.join("allowlist.txt");
    fs::write(&allowlist, "bridges:127.0.0.1-127.0.0.1\n")?;
    let rq = Session::new_with_opts(
        folder.clone(),
        SessionOptions {
            dht: None,
            disable_local_service_discovery: true,
            listen: Some(ListenerOptions {
                mode: ListenerMode::TcpOnly,
                listen_addr: "127.0.0.1:0".parse().expect("an address"),
                ..Default::default()
            }),
            connect: Some(ConnectionOptions { peer_opts: Some(I2P_PACE), ..Default::default() }),
            allowlist_url: Some(format!("file://{}", allowlist.canonicalize()?.display())),
            ..Default::default()
        },
    )
    .await?;
    sam.forward_inbound(rq.listen_addr().context("librqbit isn't listening")?).await?;
    println!("Mirroring {} (root key {})", site.manifest.title(), root.fingerprint());
    println!("This node's I2P address for the site: {}", sam.address);

    let node = Arc::new(Node { cli, client, rq, proxy, folder, held: Default::default() });
    let mut status = tokio::time::interval(Duration::from_secs(node.cli.status_seconds.max(1)));
    let mut check = tokio::time::interval(Duration::from_secs(node.cli.check_seconds.max(1)));
    status.tick().await;
    let mut site = Some(site);
    loop {
        tokio::select! {
            _ = check.tick() => {
                let current = match site.take() {
                    Some(site) => Ok(site),
                    None => manifest(&node.client).await,
                };
                match current {
                    Ok(site) => node.sync(&site).await,
                    Err(e) => println!("Couldn't fetch the manifest: {e:#}"),
                }
            }
            _ = status.tick() => node.report().await,
        }
    }
}

async fn manifest(client: &Arc<Client>) -> anyhow::Result<Verified> {
    let client = client.clone();
    tokio::task::spawn_blocking(move || client.manifest()).await?
}

impl Node {
    /// The local tracker addresses for the site's trackers: its server at each I2P address
    fn trackers(&self, site: &Verified) -> Vec<String> {
        let mut hosts = site.manifest.addresses.clone();
        if hosts.is_empty() {
            let host = self.cli.server.split("://").last().unwrap_or("").split(['/', ':']).next().unwrap_or("");
            if host.ends_with(".i2p") {
                hosts.push(host.to_string());
            }
        }
        hosts.iter().map(|host| self.proxy.url_for(host)).collect()
    }

    /// Starts seeding or fetching every sealed epoch the node doesn't have in hand yet
    async fn sync(self: &Arc<Self>, site: &Verified) {
        let trackers = self.trackers(site);
        if trackers.is_empty() {
            println!("The site lists no I2P address, so there's no tracker to find other nodes through");
        }
        for board in &site.manifest.boards {
            if !self.cli.boards.is_empty() && !self.cli.boards.contains(&board.name) {
                continue;
            }
            for sealed in &board.sealed {
                let Some(infohash) = sealed.infohash else { continue };
                if self.held.lock().await.contains_key(&infohash) {
                    continue;
                }
                let name = torrent::file_name(&board.name, sealed.epoch);
                if let Err(e) = self.start(&board.name, sealed, infohash, &trackers).await {
                    println!("{name}: {e:#}");
                }
            }
        }
    }

    async fn start(self: &Arc<Self>, board: &str, sealed: &SealedRef, infohash: Hash20, trackers: &[String]) -> anyhow::Result<()> {
        let name = torrent::file_name(board, sealed.epoch);
        let path = self.folder.join(&name);
        if let Ok(bundle) = fs::read(&path)
            && open_bundle(&bundle, sealed).is_ok()
        {
            return self.seed(board, sealed, infohash, &bundle, trackers).await;
        }

        // The torrent's info from the server, checked against the manifest; without the server,
        // a magnet link, and the info comes from peers
        let client = self.client.clone();
        let (b, e) = (board.to_string(), sealed.epoch);
        let file = tokio::task::spawn_blocking(move || client.fetch_torrent(&b, e)).await?;
        let add = match file.as_deref().map(|file| torrent::info_of(file, &infohash)) {
            Ok(Ok(info)) => AddTorrent::from_bytes(torrent::file(info, trackers)),
            _ => {
                let tr: String = trackers.iter().map(|t| format!("&tr={}", escape(t))).collect();
                AddTorrent::from_url(format!("magnet:?xt=urn:btih:{}&dn={name}{tr}", hex::encode(infohash.0)))
            }
        };
        let handle = self.add(add).await?;
        println!("{name}: looking for other nodes that have it");
        self.held.lock().await.insert(infohash, (name.clone(), handle.clone()));

        let node = self.clone();
        let (board, sealed, trackers) = (board.to_string(), sealed.clone(), trackers.to_vec());
        tokio::spawn(async move {
            if let Err(e) = node.fetch(&board, &sealed, infohash, handle, &trackers).await {
                println!("{}: {e:#}", torrent::file_name(&board, sealed.epoch));
            }
        });
        Ok(())
    }

    /// Waits for peers to deliver an epoch, or takes the server's copy after a while
    async fn fetch(&self, board: &str, sealed: &SealedRef, infohash: Hash20, handle: ManagedTorrentHandle, trackers: &[String]) -> anyhow::Result<()> {
        let name = torrent::file_name(board, sealed.epoch);
        let started = Instant::now();
        let patience = Duration::from_secs(self.cli.peer_seconds);
        let done = if self.cli.peers_only {
            handle.wait_until_completed().await.map(|_| true)?
        } else {
            match tokio::time::timeout(patience, handle.wait_until_completed()).await {
                Ok(result) => result.map(|_| true)?,
                Err(_) => false,
            }
        };
        if done {
            let bundle = fs::read(self.folder.join(&name))?;
            open_bundle(&bundle, sealed).context("the copy from other nodes doesn't match the manifest")?;
            let secs = started.elapsed().as_secs_f64();
            println!(
                "{name}: got it from other nodes in {secs:.0}s ({:.0} KB/s); seeding it",
                bundle.len() as f64 / 1024.0 / secs.max(0.1)
            );
            return Ok(());
        }

        // Nobody had it in time: the server's copy, then seed that
        let got = handle.stats().progress_bytes;
        self.rq.delete(TorrentIdOrHash::Id(handle.id()), true).await?;
        self.held.lock().await.remove(&infohash);
        let client = self.client.clone();
        let b = board.to_string();
        let epoch = sealed.epoch;
        let bundle = tokio::task::spawn_blocking(move || client.fetch_bundle(&b, epoch)).await??;
        open_bundle(&bundle, sealed).context("the server's copy doesn't match the manifest")?;
        fs::write(self.folder.join(&name), &bundle)?;
        println!("{name}: other nodes sent {got} bytes in {}s, so took the server's copy", patience.as_secs());
        self.seed(board, sealed, infohash, &bundle, trackers).await
    }

    async fn seed(&self, board: &str, sealed: &SealedRef, infohash: Hash20, bundle: &[u8], trackers: &[String]) -> anyhow::Result<()> {
        let name = torrent::file_name(board, sealed.epoch);
        let info = torrent::info(bundle, board, sealed.epoch);
        anyhow::ensure!(torrent::info_hash(&info) == infohash, "the manifest's info hash isn't this epoch's");
        let handle = self.add(AddTorrent::from_bytes(torrent::file(&info, trackers))).await?;
        self.held.lock().await.insert(infohash, (name.clone(), handle));
        println!("{name}: seeding");
        Ok(())
    }

    async fn add(&self, add: AddTorrent<'_>) -> anyhow::Result<ManagedTorrentHandle> {
        let options = AddTorrentOptions {
            output_folder: Some(self.folder.display().to_string()),
            overwrite: true,
            peer_opts: Some(I2P_PACE),
            ..Default::default()
        };
        match self.rq.add_torrent(add, Some(options)).await? {
            AddTorrentResponse::Added(_, handle) | AddTorrentResponse::AlreadyManaged(_, handle) => Ok(handle),
            AddTorrentResponse::ListOnly(_) => anyhow::bail!("librqbit only listed the torrent"),
        }
    }

    async fn report(&self) {
        let held = self.held.lock().await;
        let mut lines: Vec<String> = held
            .values()
            .map(|(name, handle)| {
                let stats = handle.stats();
                let peers = stats.live.as_ref().map_or(0, |live| live.snapshot.peer_stats.live);
                let state = if stats.finished {
                    "seeding".to_string()
                } else {
                    format!("{:.0}%", 100.0 * stats.progress_bytes as f64 / stats.total_bytes.max(1) as f64)
                };
                format!("  {name}: {state}, {peers} peers, {} KB sent", stats.uploaded_bytes / 1024)
            })
            .collect();
        lines.sort();
        if !lines.is_empty() {
            println!("Status:\n{}", lines.join("\n"));
        }
    }
}

fn escape(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}
