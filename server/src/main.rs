use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anathemic_core::Authors;
use anathemic_server::{Config, Site, add_board, init, serve};
use clap::{Parser, Subcommand};

/// The operator's server for an Anathemic swarmboard
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Where the site's keys and database live
    #[arg(long, default_value = "site")]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new site: its root key, site key and database
    Init,
    /// Add a board
    AddBoard {
        name: String,
        #[arg(long)]
        title: String,
        /// Whether posts show their author: shown, hidden or choice
        #[arg(long, default_value = "choice", value_parser = parse_authors)]
        authors: Authors,
    },
    /// Serve the site over HTTP, for an i2pd server tunnel to publish
    Serve {
        #[arg(long, default_value = "127.0.0.1:8470")]
        listen: SocketAddr,
        /// An open epoch closes after this many posts
        #[arg(long, default_value_t = Config::default().epoch_posts)]
        epoch_posts: u64,
        /// …or after this many seconds, if it has posts
        #[arg(long, default_value_t = Config::default().epoch_seconds)]
        epoch_seconds: u64,
        /// Seconds a closed epoch stays open to moderation before it's sealed
        #[arg(long, default_value_t = Config::default().window_seconds)]
        window_seconds: u64,
        /// Seconds between checks for epochs to close or seal
        #[arg(long, default_value_t = 60)]
        tick_seconds: u64,
    },
}

fn parse_authors(name: &str) -> Result<Authors, String> {
    Authors::parse(name).ok_or_else(|| "expected shown, hidden or choice".to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => {
            let root = init(&cli.data)?;
            println!("Created a site in {}", cli.data.display());
            println!("Root key: {} ({})", root.to_hex(), root.fingerprint());
            println!(
                "root.key is the site's identity. Nothing in `serve` needs it, so keep a copy \
                 somewhere safe and offline."
            );
        }
        Command::AddBoard { name, title, authors } => {
            add_board(&cli.data, &name, &title, authors)?;
            println!("Added /{name}/");
        }
        Command::Serve { listen, epoch_posts, epoch_seconds, window_seconds, tick_seconds } => {
            let config = Config { epoch_posts, epoch_seconds, window_seconds };
            let site = Arc::new(Site::open(&cli.data, config)?);
            println!("Serving {} on http://{listen}", site.root().fingerprint());
            serve(site, listen, Duration::from_secs(tick_seconds.max(1))).await?;
        }
    }
    Ok(())
}
