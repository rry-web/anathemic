use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anathemic_core::Authors;
use anathemic_server::{Config, Site, SiteSettings, add_board, init, serve, set_site, set_web_posting};
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
    Init {
        /// What to call the site
        #[arg(long, default_value = "")]
        name: String,
    },
    /// Change the site's name, description or I2P addresses
    SetSite {
        #[arg(long)]
        name: Option<String>,
        /// Post markup shown on the front page; `-` reads it from standard input
        #[arg(long)]
        description: Option<String>,
        /// An I2P address the site answers at, like forum.i2p or the tunnel's .b32.i2p
        /// address; repeat for more, the preferred one first. Replaces the ones set before
        #[arg(long = "address")]
        addresses: Vec<String>,
        /// Forget the addresses set before
        #[arg(long, conflicts_with = "addresses")]
        no_addresses: bool,
    },
    /// Add a board
    AddBoard {
        name: String,
        #[arg(long)]
        title: String,
        /// Whether posts show their author: shown, hidden or choice
        #[arg(long, default_value = "choice", value_parser = parse_authors)]
        authors: Authors,
        /// Take anonymous posts from the web pages (not on boards that show authors)
        #[arg(long)]
        web_posting: bool,
    },
    /// Change a board's settings
    SetBoard {
        name: String,
        /// Take anonymous posts from the web pages: on or off
        #[arg(long, value_parser = parse_on_off)]
        web_posting: Option<bool>,
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
        /// Anonymous web posts a board takes in an hour, from everyone together
        #[arg(long, default_value_t = Config::default().web_posts_per_hour)]
        web_posts_per_hour: u32,
        /// …and from each I2P destination
        #[arg(long, default_value_t = Config::default().web_posts_per_hour_each)]
        web_posts_per_hour_each: u32,
    },
}

fn parse_on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("expected on or off".to_string()),
    }
}

fn parse_authors(name: &str) -> Result<Authors, String> {
    Authors::parse(name).ok_or_else(|| "expected shown, hidden or choice".to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { name } => {
            let root = init(&cli.data)?;
            if !name.is_empty() {
                set_site(&cli.data, SiteSettings { name: Some(name), ..Default::default() })?;
            }
            println!("Created a site in {}", cli.data.display());
            println!("Root key: {} ({})", root.to_hex(), root.fingerprint());
            println!(
                "root.key is the site's identity. Nothing in `serve` needs it, so keep a copy \
                 somewhere safe and offline."
            );
        }
        Command::SetSite { name, description, addresses, no_addresses } => {
            let description = match description.as_deref() {
                Some("-") => {
                    let mut text = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)?;
                    Some(text)
                }
                _ => description,
            };
            let addresses = (no_addresses || !addresses.is_empty()).then_some(addresses);
            set_site(&cli.data, SiteSettings { name, description, addresses })?;
            println!("Updated the site");
        }
        Command::AddBoard { name, title, authors, web_posting } => {
            if web_posting && authors == Authors::Shown {
                anyhow::bail!("a board that shows every post's author can't take anonymous web posts");
            }
            add_board(&cli.data, &name, &title, authors)?;
            if web_posting {
                set_web_posting(&cli.data, &name, true)?;
            }
            println!("Added /{name}/");
        }
        Command::SetBoard { name, web_posting } => {
            if let Some(on) = web_posting {
                set_web_posting(&cli.data, &name, on)?;
            }
            println!("Updated /{name}/");
        }
        Command::Serve {
            listen,
            epoch_posts,
            epoch_seconds,
            window_seconds,
            tick_seconds,
            web_posts_per_hour,
            web_posts_per_hour_each,
        } => {
            let config = Config { web_posts_per_hour, web_posts_per_hour_each, epoch_posts, epoch_seconds, window_seconds };
            let site = Arc::new(Site::open(&cli.data, config)?);
            println!("Serving {} on http://{listen}", site.root().fingerprint());
            serve(site, listen, Duration::from_secs(tick_seconds.max(1))).await?;
        }
    }
    Ok(())
}
