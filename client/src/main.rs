use std::{collections::HashMap, io::Read, path::PathBuf};

use anathemic_client::{Client, member_key};
use anathemic_core::{Content, Post, utc};
use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};

/// Read and post to Anathemic swarmboards
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Where your member keys, pinned sites and cached epochs live [default: ~/.anathemic]
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// The I2P router's HTTP proxy, needed for .i2p sites
    #[arg(long, global = true, default_value = "http://127.0.0.1:4444")]
    proxy: String,
    /// Connect directly, without the proxy (for a server on this computer)
    #[arg(long, global = true)]
    direct: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show your member key for a site, making one if you have none
    Key { server: String },
    /// List a site's boards
    Boards { server: String },
    /// List a board's threads, or show one thread
    Read {
        server: String,
        board: String,
        /// The number of the thread's first post
        #[arg(long)]
        thread: Option<u64>,
    },
    /// Start a thread, or reply to one
    Post {
        server: String,
        board: String,
        /// The post's text; `-` reads it from standard input
        body: String,
        /// Reply to this thread (the number of its first post)
        #[arg(long, conflicts_with = "title")]
        thread: Option<u64>,
        /// Start a new thread with this title
        #[arg(long, required_unless_present = "thread")]
        title: Option<String>,
        /// Leave your key off the post, on boards where posters choose
        #[arg(long)]
        anonymous: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = match cli.home {
        Some(home) => home,
        None => PathBuf::from(std::env::var_os("HOME").context("HOME isn't set; pass --home")?).join(".anathemic"),
    };
    let proxy = (!cli.direct).then_some(cli.proxy.as_str());
    match cli.command {
        Command::Key { server } => {
            let site = Client::new(&server, proxy, home.clone())?.manifest()?;
            let (key, made) = member_key(&home, &site.manifest.root)?;
            if made {
                println!("Made a new member key for this site");
            }
            println!("{} ({})", key.public().to_hex(), key.public().fingerprint());
        }
        Command::Boards { server } => {
            let site = Client::new(&server, proxy, home)?.manifest()?;
            let manifest = &site.manifest;
            println!("{} (root key {})", manifest.title(), manifest.root.fingerprint());
            if !manifest.addresses.is_empty() {
                println!("At {}", manifest.addresses.join(", "));
            }
            if !manifest.description.trim().is_empty() {
                println!("\n{}\n", manifest.description.trim_end());
            }
            for board in &manifest.boards {
                println!(
                    "/{}/  {}  (authors {}{}, {} sealed epochs)",
                    board.name,
                    board.title,
                    board.authors.name(),
                    if board.web_posting { ", anonymous web posts" } else { "" },
                    board.sealed.len()
                );
            }
        }
        Command::Read { server, board, thread } => {
            let client = Client::new(&server, proxy, home)?;
            let site = client.manifest()?;
            let posts = client.board_posts(&site, &board)?;
            match thread {
                Some(thread) => show_thread(&posts, thread)?,
                None => list_threads(&posts),
            }
        }
        Command::Post { server, board, body, thread, title, anonymous } => {
            let body = if body == "-" {
                let mut text = String::new();
                std::io::stdin().read_to_string(&mut text)?;
                text
            } else {
                body
            };
            let client = Client::new(&server, proxy, home.clone())?;
            let site = client.manifest()?;
            let (key, made) = member_key(&home, &site.manifest.root)?;
            if made {
                println!("Made a new member key for this site");
            }
            let post = client.submit(&key, &board, Content { thread, title, body }, anonymous)?;
            println!("Posted #{} in epoch {}", post.number, post.epoch);
        }
    }
    Ok(())
}

fn author(post: &Post) -> String {
    match post.author_key() {
        Some(key) => key.fingerprint(),
        None if post.web => "Anonymous (web)".to_string(),
        None => "Anonymous".to_string(),
    }
}

fn list_threads(posts: &[Post]) {
    let mut replies: HashMap<u64, (usize, u64)> = HashMap::new();
    for post in posts {
        if let Some(thread) = post.content.thread {
            let entry = replies.entry(thread).or_default();
            entry.0 += 1;
            entry.1 = entry.1.max(post.accepted);
        }
    }
    let mut threads: Vec<(&Post, usize, u64)> = posts
        .iter()
        .filter(|post| post.content.thread.is_none())
        .map(|post| {
            let (count, last) = replies.get(&post.number).copied().unwrap_or_default();
            (post, count, last.max(post.accepted))
        })
        .collect();
    threads.sort_by_key(|thread| std::cmp::Reverse(thread.2));
    if threads.is_empty() {
        println!("No threads yet.");
    }
    for (post, count, last) in threads {
        println!(
            "#{:<6} {}  ({count} {}, last {})",
            post.number,
            post.content.title.as_deref().unwrap_or(""),
            if count == 1 { "reply" } else { "replies" },
            utc(last)
        );
    }
}

fn show_thread(posts: &[Post], thread: u64) -> anyhow::Result<()> {
    let Some(start) = posts.iter().find(|p| p.number == thread && p.content.thread.is_none()) else {
        bail!("there's no thread #{thread}");
    };
    println!("{}\n", start.content.title.as_deref().unwrap_or(""));
    for post in posts.iter().filter(|p| p.number == thread || p.content.thread == Some(thread)) {
        println!("#{}  {}  {}", post.number, author(post), utc(post.accepted));
        println!("{}\n", post.content.body.trim_end());
    }
    Ok(())
}
