use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anathemic_core::{Authors, PublicKey, link::Link, moderation::Power, now, utc};
use anathemic_server::{
    Config, Site, SiteSettings, add_board,
    hosts::{self, Role},
    init, moderate, serve, set_site, set_web_posting,
};
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
        /// This server's own I2P address, where the site's other hosts reach it: the .b32.i2p
        /// address of a second server tunnel, not the site's shared one
        #[arg(long)]
        host_address: Option<String>,
    },
    /// Let someone you trust run the site while this server is down: adds their standby to the
    /// root key's list of hosts, after any already on it
    AddHost {
        /// The standby's key, as init-standby printed it
        key: String,
        /// The standby's own I2P address
        #[arg(long)]
        address: String,
        /// Who runs it, for your records
        #[arg(long, default_value = "")]
        name: String,
        /// The root key, if it isn't kept in the data folder
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// Stop a host from running the site
    RetireHost {
        key: String,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// List the site's hosts, and whether this server is the writer
    Hosts,
    /// Set up a standby for a site, from its share link; then the site's operator adds it with
    /// add-host
    InitStandby { link: String },
    /// Make a running standby take over the site now
    Promote,
    /// Show posts set aside when this server stepped down, which the new writer never got
    Orphans,
    /// Appoint a moderator, or change an appointment. Moderators act with
    /// `anathemic-client moderate`, using the member key named here (yours too, if you
    /// moderate yourself)
    AddModerator {
        /// Their member key for this site, as `anathemic-client key` shows it
        key: String,
        #[arg(long, default_value = "")]
        name: String,
        /// The boards they moderate; repeat for more [default: all]
        #[arg(long = "board")]
        boards: Vec<String>,
        /// hide, purge or ban; repeat for more
        #[arg(long = "power", required = true, value_parser = parse_power)]
        powers: Vec<Power>,
        /// End the appointment after this many days [default: never]
        #[arg(long)]
        days: Option<u64>,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// End a moderator's appointment; what they did still counts
    EndModerator {
        key: String,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// List the moderators
    Moderators,
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
        /// The I2P router's HTTP proxy, for reaching the site's other hosts
        #[arg(long, default_value = "http://127.0.0.1:4444")]
        proxy: String,
        /// Reach the other hosts directly, not through the proxy (for hosts on this computer)
        #[arg(long)]
        direct: bool,
        /// A standby takes over after the writer has been out of reach this many minutes
        /// (0: only when told to, with promote)
        #[arg(long, default_value_t = Config::default().takeover_seconds / 60)]
        takeover_minutes: u64,
        /// …plus this many for each host ranked above it
        #[arg(long, default_value_t = Config::default().stagger_seconds / 60)]
        stagger_minutes: u64,
    },
}

fn parse_on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("expected on or off".to_string()),
    }
}

fn parse_power(name: &str) -> Result<Power, String> {
    Power::parse(name).ok_or_else(|| "expected hide, purge or ban".to_string())
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
        Command::SetSite { name, description, addresses, no_addresses, host_address } => {
            if let Some(address) = host_address {
                hosts::set_host_address(&cli.data, &address)?;
            }
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
            proxy,
            direct,
            takeover_minutes,
            stagger_minutes,
        } => {
            let config = Config {
                web_posts_per_hour,
                web_posts_per_hour_each,
                epoch_posts,
                epoch_seconds,
                window_seconds,
                proxy: (!direct).then_some(proxy),
                takeover_seconds: takeover_minutes * 60,
                stagger_seconds: stagger_minutes * 60,
            };
            let site = Arc::new(Site::open(&cli.data, config)?);
            println!("Serving {} on http://{listen}", site.root().fingerprint());
            serve(site, listen, Duration::from_secs(tick_seconds.max(1))).await?;
        }
        Command::AddHost { key, address, name, root_key } => {
            let key = PublicKey::from_hex(&key)?;
            let rank = hosts::add_host(&cli.data, root_key.as_deref(), key, &address, &name)?;
            println!("Added {} as host {rank}. It takes over by itself if the site's writer is out of reach.", key.fingerprint());
            println!("Give it the site's tunnel keys too, so it answers at the site's address.");
        }
        Command::RetireHost { key, root_key } => {
            let key = PublicKey::from_hex(&key)?;
            hosts::retire_host(&cli.data, root_key.as_deref(), key)?;
            println!("Retired {}", key.fingerprint());
        }
        Command::Hosts => {
            let (list, role, term, own) = hosts::describe(&cli.data)?;
            let role = match role {
                Role::Writer => "the writer",
                Role::Standby => "a standby",
            };
            println!("This server ({}) is {role}, in term {term}.", own.fingerprint());
            match list {
                None => println!("The site has no other hosts. Add one with add-host."),
                Some(list) => {
                    println!("Host list {} (signed {}):", list.sequence, utc(list.issued));
                    for host in &list.hosts {
                        println!(
                            "  {}  {}  {}  {}{}",
                            host.rank,
                            host.key.fingerprint(),
                            host.address,
                            host.name,
                            if host.retired { "  (retired)" } else { "" }
                        );
                    }
                }
            }
        }
        Command::InitStandby { link } => {
            let link = Link::parse(&link)?;
            let key = hosts::init_standby(&cli.data, &link)?;
            println!("Made a standby in {} for the site with root key {}.", cli.data.display(), link.root.fingerprint());
            println!("Its key: {}", key.to_hex());
            println!("Next:");
            println!("  1. Give it its own I2P address: a server tunnel to `serve`'s port, with its own keys.");
            println!("  2. Send the operator its key and that address, for:");
            println!("       anathemic-server add-host {} --address <its .b32.i2p> --name <you>", key.to_hex());
            println!("  3. Run `anathemic-server --data {} serve`. It copies the site until it's needed.", cli.data.display());
        }
        Command::Promote => {
            hosts::promote(&cli.data)?;
            println!("The standby takes over at its next tick, if it's on the host list.");
        }
        Command::AddModerator { key, name, boards, powers, days, root_key } => {
            let key = PublicKey::from_hex(&key)?;
            let expires = days.map(|days| now() + days * 24 * 60 * 60);
            moderate::add_moderator(&cli.data, root_key.as_deref(), key, &name, boards, powers, expires)?;
            println!("Appointed {}", key.fingerprint());
        }
        Command::EndModerator { key, root_key } => {
            let key = PublicKey::from_hex(&key)?;
            moderate::end_moderator(&cli.data, root_key.as_deref(), key)?;
            println!("Ended {}'s appointment", key.fingerprint());
        }
        Command::Moderators => {
            let list = moderate::moderators(&cli.data)?;
            if list.is_empty() {
                println!("No moderators. Appoint one with add-moderator.");
            }
            for cert in list {
                let powers: Vec<&str> = cert
                    .powers
                    .iter()
                    .map(|p| match p {
                        Power::Hide => "hide",
                        Power::Purge => "purge",
                        Power::Ban => "ban",
                    })
                    .collect();
                let boards = if cert.boards.is_empty() { "all boards".to_string() } else { cert.boards.iter().map(|b| format!("/{b}/")).collect::<Vec<_>>().join(" ") };
                let until = cert.expires.map_or_else(String::new, |end| format!(", until {}", utc(end)));
                println!("{}  {}  {}: {}{until}", cert.key.fingerprint(), cert.name, boards, powers.join(", "));
            }
        }
        Command::Orphans => {
            let orphans = hosts::orphans(&cli.data)?;
            if orphans.is_empty() {
                println!("No posts were set aside.");
            }
            for (board, number, record) in orphans {
                let post = record.peek()?;
                println!("/{board}/ #{number}  {}\n{}\n", utc(post.accepted), post.content.body.trim_end());
            }
        }
    }
    Ok(())
}
