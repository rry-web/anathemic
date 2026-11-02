use std::{collections::HashMap, io::Read, path::PathBuf};

use anathemic_client::{Client, member_key};
use anathemic_core::{
    Content, Post, PublicKey, now,
    moderation::{Action, ModCert, Moderation, Revocation, Target},
    utc,
};
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
    /// Print a link to pass on, so someone else can read or mirror the site. Anything that
    /// takes a site's address takes the link too
    Share { server: String },
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
    /// Show the site's moderators and every moderator action, checked against the site's root
    /// key: who did what, to which post or member, when, and why
    Log {
        server: String,
        /// Show at most this many entries, the newest [default: all]
        #[arg(long)]
        last: Option<usize>,
    },
    /// Act as a moderator, with your member key for the site (the operator appoints
    /// moderators with `anathemic-server add-moderator`)
    Moderate {
        server: String,
        #[command(subcommand)]
        action: ModAction,
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

#[derive(Subcommand)]
enum ModAction {
    /// Hide a post: honest clients and mirrors stop showing it, and it can be restored
    Hide {
        board: String,
        number: u64,
        /// Shown in the post's place
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Delete a post's text everywhere, for good. Its sealed epoch keeps only its hash.
    Purge {
        board: String,
        number: u64,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Show a hidden post again
    Restore { board: String, number: u64 },
    /// Refuse a member's posts
    Ban {
        /// Their member key, as the posts show it in full on boards that show authors
        member: String,
        /// Only on this board [default: the whole site]
        #[arg(long)]
        board: Option<String>,
        /// For this many days [default: for good]
        #[arg(long)]
        days: Option<u64>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Lift a ban
    Unban {
        member: String,
        #[arg(long)]
        board: Option<String>,
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
        Command::Share { server } => {
            let client = Client::new(&server, proxy, home)?;
            let site = client.manifest()?;
            note_mirror(&client);
            let link = client.share_link(&site);
            println!("{link}\n");
            println!(
                "It names {}'s root key, so whoever uses it checks everything against that, and {} {}.",
                site.manifest.title(),
                link.mirrors.len(),
                if link.mirrors.len() == 1 { "mirror to fall back on" } else { "mirrors to fall back on" }
            );
            println!("To mirror the site: anathemic-node '{link}'");
            println!("To read it:         anathemic-client read '{link}' <board>");
        }
        Command::Boards { server } => {
            let client = Client::new(&server, proxy, home)?;
            let site = client.manifest()?;
            note_mirror(&client);
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
            note_mirror(&client);
            let posts = client.board_posts(&site, &board)?;
            let moderation = client.moderation(&site)?;
            match thread {
                Some(thread) => show_thread(&posts, &board, &moderation, thread)?,
                None => list_threads(&posts, &board, &moderation),
            }
        }
        Command::Log { server, last } => {
            let client = Client::new(&server, proxy, home)?;
            let site = client.manifest()?;
            note_mirror(&client);
            let moderation = client.moderation(&site)?;
            show_log(&moderation, &site.manifest.title(), last);
        }
        Command::Moderate { server, action } => {
            let client = Client::new(&server, proxy, home.clone())?;
            let site = client.manifest()?;
            let (key, _) = member_key(&home, &site.manifest.root)?;
            let post = |board: String, number| Target::Post { board, number };
            let member = |hex: &str, board| -> anyhow::Result<Target> { Ok(Target::Member { key: PublicKey::from_hex(hex)?, board }) };
            let (target, action, reason) = match action {
                ModAction::Hide { board, number, reason } => (post(board, number), Action::Hide, reason),
                ModAction::Purge { board, number, reason } => (post(board, number), Action::Purge, reason),
                ModAction::Restore { board, number } => (post(board, number), Action::Restore, String::new()),
                ModAction::Ban { member: hex, board, days, reason } => {
                    (member(&hex, board)?, Action::Ban { until: days.map(|d| now() + d * 24 * 60 * 60) }, reason)
                }
                ModAction::Unban { member: hex, board } => (member(&hex, board)?, Action::Restore, String::new()),
            };
            let logged = client.moderate(&key, Revocation { target, action, reason, time: now() })?;
            println!("Logged as revocation #{}", logged.number);
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

fn note_mirror(client: &Client) {
    if let Some(mirror) = client.source() {
        eprintln!("{} can't be reached, so this is from {mirror}, one of the site's other hosts or mirrors\n", client.base());
    }
}

fn author(post: &Post) -> String {
    match post.author_key() {
        Some(key) => key.fingerprint(),
        None if post.web => "Anonymous (web)".to_string(),
        None => "Anonymous".to_string(),
    }
}

fn list_threads(posts: &[Post], board: &str, moderation: &Moderation) {
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
            if moderation.removed(board, post.number).is_some() { "[hidden by a moderator]" } else { post.content.title.as_deref().unwrap_or("") },
            if count == 1 { "reply" } else { "replies" },
            utc(last)
        );
    }
}

fn show_thread(posts: &[Post], board: &str, moderation: &Moderation, thread: u64) -> anyhow::Result<()> {
    let Some(start) = posts.iter().find(|p| p.number == thread && p.content.thread.is_none()) else {
        bail!("there's no thread #{thread}");
    };
    let title = if moderation.removed(board, start.number).is_some() { "[hidden by a moderator]" } else { start.content.title.as_deref().unwrap_or("") };
    println!("{title}\n");
    for post in posts.iter().filter(|p| p.number == thread || p.content.thread == Some(thread)) {
        println!("#{}  {}  {}", post.number, author(post), utc(post.accepted));
        match moderation.removed(board, post.number) {
            Some(reason) => println!("[hidden by a moderator: {reason}]\n"),
            None => println!("{}\n", post.content.body.trim_end()),
        }
    }
    Ok(())
}

fn show_log(moderation: &Moderation, title: &str, last: Option<usize>) {
    let at = now();
    let appointment = |cert: &ModCert| {
        let boards = if cert.boards.is_empty() { "all boards".to_string() } else { cert.boards.iter().map(|b| format!("/{b}/")).collect::<Vec<_>>().join(" ") };
        let powers = cert.powers.iter().map(|p| p.name()).collect::<Vec<_>>().join(", ");
        format!("{} ({})  {boards}: {powers}, from {}", cert.name, cert.key.fingerprint(), utc(cert.issued))
    };
    let (current, former): (Vec<&ModCert>, Vec<&ModCert>) = moderation.appointments(at).into_iter().partition(|cert| cert.in_force(at));
    println!("Moderators of {title}");
    if current.is_empty() {
        println!("  none appointed");
    }
    for cert in current {
        let until = cert.expires.map_or_else(String::new, |end| format!(" until {}", utc(end)));
        println!("  {}{until}", appointment(cert));
    }
    for cert in former {
        let ended = cert.expires.map_or_else(String::new, |end| format!(", ended {}", utc(end)));
        println!("  former: {}{ended}", appointment(cert));
    }

    let total = moderation.log.len();
    let shown = last.unwrap_or(total).min(total);
    println!("\n{total} {} in the log, checked against the site's root key{}", if total == 1 { "entry" } else { "entries" }, if shown < total { format!("; the last {shown}") } else { String::new() });
    for entry in &moderation.log[total - shown..] {
        let who = match moderation.moderator_name(&entry.moderator, entry.accepted) {
            Some(name) => format!("{name} ({})", entry.moderator.fingerprint()),
            None => entry.moderator.fingerprint(),
        };
        let target = match &entry.revocation.target {
            Target::Post { board, number } if moderation.is_purged(board, *number) => format!("post #{number} on /{board}/ (purged)"),
            Target::Post { board, number } => format!("post #{number} on /{board}/"),
            Target::Member { key, board: Some(board) } => format!("member {} on /{board}/", key.to_hex()),
            Target::Member { key, board: None } => format!("member {} across the site", key.to_hex()),
        };
        let reason = entry.revocation.reason.trim();
        println!("#{:<5} {}  {who}: {} {target}", entry.number, utc(entry.accepted), entry.verb());
        println!("       reason: {}", if reason.is_empty() { "none given" } else { reason });
    }
}
