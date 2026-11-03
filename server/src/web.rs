//! Web pages for reading a site in any browser, rynx and other text browsers first: plain HTML
//! with a little CSS, and never JavaScript (the pages' Content-Security-Policy forbids it).
//!
//! The server renders these from its own records, so a reader trusts the server for what they
//! show. The dedicated client verifies every signature instead. Boards can also take anonymous
//! posts from these pages, which no member signs.
//!
//! Mirrors draw the same pages, read-only, from their checked copy of the site ([`Source`]), so
//! the site stays readable in a browser while its server is down.

use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    sync::Arc,
};

use anathemic_core::{
    Authors, Content, Post, PublicKey, Signed, Time,
    link::Link,
    moderation::{Entry, ModCert, Moderation, Target},
    now, utc, valid_board_name,
    markup::{self, Block, Inline},
};
use axum::{
    Form, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{BoardSummary, EpochState, Fail, Site, ThreadSummary, refuse};

/// Board names the server's own addresses use
pub const RESERVED: &[&str] = &["announce", "boards", "hosts", "manifest", "mirrors", "moderation", "revocations", "static"];
const THREADS_PER_PAGE: u64 = 50;
const LOG_ENTRIES_PER_PAGE: u64 = 100;
/// The header an i2pd HTTP server tunnel adds, naming the visitor's destination
const DESTINATION_HEADER: &str = "x-i2p-desthash";

/// What the pages are drawn from: the server's own records, or a mirror's checked copy
pub trait Source: Send + Sync + 'static {
    fn root(&self) -> PublicKey;
    /// The site's name, description and addresses
    fn about(&self) -> Result<(String, String, Vec<String>), Fail>;
    fn boards(&self) -> Result<Vec<BoardSummary>, Fail>;
    /// A board's title, author rule, and whether these pages take posts for it
    fn board(&self, board: &str) -> Result<(String, Authors, bool), Fail>;
    /// A page of a board's threads, the most recently active first, and how many there are
    fn threads(&self, board: &str, skip: u64, take: u64) -> Result<(Vec<ThreadSummary>, u64), Fail>;
    /// A thread's posts in order, its first post first
    fn thread(&self, board: &str, number: u64) -> Result<Vec<Post>, Fail>;
    /// The thread a post belongs to
    fn thread_of(&self, board: &str, number: u64) -> Result<u64, Fail>;
    fn epoch_states(&self, board: &str) -> Result<HashMap<u64, EpochState>, Fail>;
    /// For a mirror, when the manifest its copy follows was published
    fn mirrored(&self) -> Option<Time> {
        None
    }
    /// Mirrors' addresses to put in the share link
    fn mirrors(&self) -> Vec<String> {
        Vec::new()
    }
    /// What moderators have hidden and purged
    fn moderation(&self) -> Result<Arc<Moderation>, Fail>;
    fn submit_web(&self, _board: &str, _content: Content, _from: Option<&str>, _now: u64) -> Result<Signed<Post>, Fail> {
        refuse("this is a read-only mirror; post on the site itself")
    }
}

impl Source for Site {
    fn root(&self) -> PublicKey {
        Site::root(self)
    }
    fn about(&self) -> Result<(String, String, Vec<String>), Fail> {
        Site::about(self)
    }
    fn boards(&self) -> Result<Vec<BoardSummary>, Fail> {
        Site::boards(self)
    }
    fn board(&self, board: &str) -> Result<(String, Authors, bool), Fail> {
        Site::board(self, board)
    }
    fn threads(&self, board: &str, skip: u64, take: u64) -> Result<(Vec<ThreadSummary>, u64), Fail> {
        Site::threads(self, board, skip, take)
    }
    fn thread(&self, board: &str, number: u64) -> Result<Vec<Post>, Fail> {
        Site::thread(self, board, number)
    }
    fn thread_of(&self, board: &str, number: u64) -> Result<u64, Fail> {
        Site::thread_of(self, board, number)
    }
    fn epoch_states(&self, board: &str) -> Result<HashMap<u64, EpochState>, Fail> {
        Site::epoch_states(self, board)
    }
    fn submit_web(&self, board: &str, content: Content, from: Option<&str>, now: u64) -> Result<Signed<Post>, Fail> {
        Site::submit_web(self, board, content, from, now)
    }
    /// The site's other hosts first, then mirrors seeding through its tracker
    fn mirrors(&self) -> Vec<String> {
        let mut addresses = self.host_addresses().unwrap_or_default();
        addresses.extend(self.tracker.mirrors(now(), 3).iter().map(anathemic_core::i2p::b32_address));
        addresses.truncate(anathemic_core::link::MAX_LINK_MIRRORS);
        addresses
    }
    fn moderation(&self) -> Result<Arc<Moderation>, Fail> {
        Site::moderation(self)
    }
}

pub fn routes<S: Source>() -> Router<Arc<S>> {
    Router::new()
        .route("/", get(index::<S>))
        .route("/moderation", get(moderation_log::<S>))
        .route("/{board}", get(to_board))
        .route("/{board}/", get(board::<S>).post(new_thread::<S>))
        .route("/{board}/{thread}", get(thread::<S>).post(new_reply::<S>))
        .route("/{board}/post/{number}", get(post::<S>))
}

/// Text made safe for HTML, inside elements and in quoted attributes
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "body{max-width:48em;margin:1em auto;padding:0 1em;font-family:sans-serif;line-height:1.45}\
    .meta{color:#666;font-size:.9em;margin-bottom:.3em}\
    .post{border-top:1px solid #ccc;padding:.6em 0}\
    .refused{border:1px solid #c66;padding:.4em .8em}\
    blockquote{color:#363;margin:.4em 0 .4em .8em;padding-left:.6em;border-left:3px solid #9c9}\
    pre{background:#f4f4f4;padding:.5em;overflow-x:auto}\
    td,th{padding:.2em .6em;text-align:left}\
    input[type=text],textarea{width:100%;box-sizing:border-box}\
    footer{color:#666;font-size:.85em;margin-top:2em}\
    @media(prefers-color-scheme:dark){body{background:#111;color:#ddd}a{color:#8bf}pre{background:#222}.meta,footer{color:#999}}";

/// What every page shows of the site
struct About {
    title: String,
    description: String,
    address: Option<String>,
}

fn about(site: &impl Source) -> Result<About, Fail> {
    let (name, description, addresses) = site.about()?;
    let title = if name.is_empty() { format!("Site {}", site.root().fingerprint()) } else { name };
    Ok(About { title, description, address: addresses.into_iter().next() })
}

fn page(site: &impl Source, about: &About, title: &str, crumbs: &[(&str, &str)], body: &str) -> Response {
    let mut nav = format!("<a href=\"/\">{}</a>", escape(&about.title));
    let (banner, drawn) = match site.mirrored() {
        Some(published) => {
            let at = about.address.as_ref().map_or_else(String::new, |a| format!(" at <a href=\"http://{a}/\">{a}</a>", a = escape(a)));
            (
                format!(
                    "<p class=\"refused\">This is a read-only mirror of {}, kept by one of its members. \
                     It follows the site as it was at {}, so newer posts may be missing. \
                     To post, use the site itself{at}.</p>\n",
                    escape(&about.title),
                    utc(published)
                ),
                "These pages are drawn by a mirror, from a copy whose signatures it checked",
            )
        }
        None => (String::new(), "These pages are drawn by the server"),
    };
    for (href, label) in crumbs {
        let _ = write!(nav, " · <a href=\"{}\">{}</a>", escape(href), escape(label));
    }
    let title = if title == about.title { escape(title) } else { format!("{} – {}", escape(title), escape(&about.title)) };
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body>\
         <nav>{nav}</nav>\n{banner}{body}\n<footer><p>An Anathemic swarmboard. Root key {fingerprint} \
         (<code>{root}</code>). {drawn}; the anathemic client checks every signature \
         itself. <a href=\"/moderation\">Moderation log</a>: every moderator action, and who took it.</p>{share}</footer></body></html>\n",
        fingerprint = site.root().fingerprint(),
        root = site.root().to_hex(),
        share = share(site, about),
    );
    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"),
    );
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// The site's share link, for anyone who wants to help keep it up
fn share(site: &impl Source, about: &About) -> String {
    let Some(address) = &about.address else { return String::new() };
    let link = Link { address: address.clone(), root: site.root(), mirrors: site.mirrors() };
    format!(
        "<p>To help keep this site up by mirroring it, run <code>anathemic-node '{}'</code> \
         beside an I2P router with SAM on.</p>",
        escape(&link.to_string())
    )
}

fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// How to post with the client, using the site's address when it has one
fn client_hint(about: &About, action: &str, args: &str) -> String {
    let address = about.address.as_ref().map_or_else(|| "&lt;this site&#39;s address&gt;".to_string(), |a| format!("http://{}", escape(a)));
    format!("<p class=\"meta\">To {action}, use the anathemic client: <code>anathemic-client post {address} {args}</code></p>\n")
}

async fn to_board(Path(name): Path<String>) -> Result<Response, Fail> {
    if !valid_board_name(&name) {
        return Err(Fail::NotFound);
    }
    Ok(Redirect::permanent(&format!("/{name}/")).into_response())
}

async fn index<S: Source>(State(site): State<Arc<S>>) -> Result<Response, Fail> {
    let about = about(&*site)?;
    let boards = site.boards()?;
    let mut body = format!("<h1>{}</h1>\n", escape(&about.title));
    body.push_str(&render_markup(&about.description, "", &|_| false));
    if boards.is_empty() {
        body.push_str("<p>No boards yet.</p>");
    } else {
        body.push_str("<table><tr><th>Board</th><th>Threads</th><th>Posts</th><th>Last post</th></tr>\n");
        for board in &boards {
            let _ = writeln!(
                body,
                "<tr><td><a href=\"/{name}/\">/{name}/</a> {title}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                board.threads,
                board.posts,
                board.last.map_or_else(|| "none".to_string(), utc),
                name = board.name,
                title = escape(&board.title),
            );
        }
        body.push_str("</table>");
    }
    Ok(page(&*site, &about, &about.title, &[], &body))
}

/// The public record of moderation: who may moderate, and every entry of the log, newest first
async fn moderation_log<S: Source>(State(site): State<Arc<S>>, Query(query): Query<PageQuery>) -> Result<Response, Fail> {
    let about = about(&*site)?;
    let moderation = site.moderation()?;
    let at = now();
    let mut body = String::from(
        "<h1>Moderation log</h1>\n<p>Every action a moderator takes is signed by them, countersigned by the site, \
         and chained into this log, which every mirror keeps a copy of. Nothing can be taken out of it or \
         changed without readers&#39; clients noticing. Purged posts&#39; text is gone; the entry stays.</p>\n",
    );

    let appointments = moderation.appointments(at);
    let (current, former): (Vec<&ModCert>, Vec<&ModCert>) = appointments.into_iter().partition(|cert| cert.in_force(at));
    body.push_str("<h2 id=\"moderators\">Moderators</h2>\n");
    if current.is_empty() {
        body.push_str("<p>None appointed.</p>\n");
    } else {
        body.push_str(&appointment_table(&current, "Until"));
    }
    if !former.is_empty() {
        body.push_str("<h3>Former moderators</h3>\n");
        body.push_str(&appointment_table(&former, "Ended"));
    }

    let total = moderation.log.len() as u64;
    let pages = total.div_ceil(LOG_ENTRIES_PER_PAGE).max(1);
    let number = query.page.unwrap_or(1).max(1);
    if number > pages {
        return Err(Fail::NotFound);
    }
    let _ = writeln!(body, "<h2 id=\"log\">Actions</h2>\n<p class=\"meta\">{}, newest first.</p>", plural(total, "entry", "entries"));
    if total > 0 {
        body.push_str("<table><tr><th>#</th><th>Logged</th><th>Moderator</th><th>Action</th><th>Reason</th></tr>\n");
        let entries = moderation.log.iter().rev().skip(((number - 1) * LOG_ENTRIES_PER_PAGE) as usize).take(LOG_ENTRIES_PER_PAGE as usize);
        for entry in entries {
            let reason = entry.revocation.reason.trim();
            let _ = writeln!(
                body,
                "<tr id=\"r{n}\"><td>{n}</td><td>{}</td><td>{}</td><td>{} {}</td><td>{}</td></tr>",
                utc(entry.accepted),
                moderator(&moderation, entry),
                escape(&entry.verb()),
                target(&moderation, &entry.revocation.target),
                if reason.is_empty() { "<em>none given</em>".to_string() } else { escape(reason) },
                n = entry.number,
            );
        }
        body.push_str("</table>\n");
    }
    if pages > 1 {
        let mut links = Vec::new();
        if number > 1 {
            links.push(format!("<a href=\"/moderation?page={}#log\">Newer</a>", number - 1));
        }
        links.push(format!("Page {number} of {pages}"));
        if number < pages {
            links.push(format!("<a href=\"/moderation?page={}#log\">Older</a>", number + 1));
        }
        let _ = writeln!(body, "<nav class=\"pagination\">{}</nav>", links.join(" · "));
    }
    body.push_str(
        "<p class=\"meta\">To check the log yourself rather than trust whoever drew this page: \
         <code>anathemic-client log &lt;this site&#39;s address&gt;</code></p>\n",
    );
    Ok(page(&*site, &about, "Moderation log", &[("/moderation", "Moderation log")], &body))
}

fn appointment_table(certs: &[&ModCert], until: &str) -> String {
    let mut out = format!("<table><tr><th>Name</th><th>Key</th><th>Boards</th><th>Powers</th><th>Appointed</th><th>{until}</th></tr>\n");
    for cert in certs {
        let boards = if cert.boards.is_empty() {
            "all".to_string()
        } else {
            cert.boards.iter().map(|b| format!("<a href=\"/{b}/\">/{b}/</a>", b = escape(b))).collect::<Vec<_>>().join(" ")
        };
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td><code>{}</code></td><td>{boards}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&cert.name),
            cert.key.fingerprint(),
            cert.powers.iter().map(|p| p.name()).collect::<Vec<_>>().join(", "),
            utc(cert.issued),
            cert.expires.map_or_else(|| "—".to_string(), utc),
        );
    }
    out.push_str("</table>\n");
    out
}

fn moderator(moderation: &Moderation, entry: &Entry) -> String {
    let key = format!("<code>{}</code>", entry.moderator.fingerprint());
    match moderation.moderator_name(&entry.moderator, entry.accepted) {
        Some(name) => format!("{} {key}", escape(name)),
        None => key,
    }
}

fn target(moderation: &Moderation, target: &Target) -> String {
    match target {
        // A purged post is gone, so there's nothing to link to
        Target::Post { board, number } if moderation.is_purged(board, *number) => {
            format!("post #{number} on <a href=\"/{board}/\">/{board}/</a>", board = escape(board))
        }
        Target::Post { board, number } => {
            format!("<a href=\"/{board}/post/{number}\">post #{number}</a> on <a href=\"/{board}/\">/{board}/</a>", board = escape(board))
        }
        Target::Member { key, board: Some(board) } => {
            format!("member <code>{}</code> on <a href=\"/{board}/\">/{board}/</a>", key.fingerprint(), board = escape(board))
        }
        Target::Member { key, board: None } => format!("member <code>{}</code> across the site", key.fingerprint()),
    }
}

#[derive(Deserialize)]
struct PageQuery {
    page: Option<u64>,
}

/// What a web form sends
#[derive(Deserialize, Default)]
struct Draft {
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
}

async fn board<S: Source>(State(site): State<Arc<S>>, Path(name): Path<String>, Query(query): Query<PageQuery>) -> Result<Response, Fail> {
    board_page(&*site, &name, query.page.unwrap_or(1), None, &Draft::default())
}

fn board_page(site: &impl Source, name: &str, number: u64, refused: Option<&str>, draft: &Draft) -> Result<Response, Fail> {
    let about = about(site)?;
    let (title, authors, web) = site.board(name)?;
    let number = number.max(1);
    let (threads, total) = site.threads(name, (number - 1) * THREADS_PER_PAGE, THREADS_PER_PAGE)?;
    let moderation = site.moderation()?;
    let pages = total.div_ceil(THREADS_PER_PAGE).max(1);
    if number > pages {
        return Err(Fail::NotFound);
    }

    let mut body = format!(
        "<h1>/{name}/ {}</h1>\n<p class=\"meta\">{}. {}.</p>\n",
        escape(&title),
        plural(total, "thread", "threads"),
        authors_rule(authors)
    );
    if threads.is_empty() {
        body.push_str("<p>No threads yet.</p>\n");
    } else {
        body.push_str("<table><tr><th>Thread</th><th>Replies</th><th>Last post</th></tr>\n");
        for thread in &threads {
            let _ = writeln!(
                body,
                "<tr><td><a href=\"/{name}/{number}\">{title}</a></td><td>{}</td><td>{}</td></tr>",
                thread.replies,
                utc(thread.last),
                number = thread.start.number,
                title = match moderation.removed(name, thread.start.number) {
                    Some(_) => "[hidden by a moderator]".to_string(),
                    None => escape(thread.start.content.title.as_deref().unwrap_or("")),
                },
            );
        }
        body.push_str("</table>\n");
    }
    if pages > 1 {
        let mut links = Vec::new();
        if number > 1 {
            links.push(format!("<a href=\"/{name}/?page={}\">Newer</a>", number - 1));
        }
        links.push(format!("Page {number} of {pages}"));
        if number < pages {
            links.push(format!("<a href=\"/{name}/?page={}\">Older</a>", number + 1));
        }
        let _ = writeln!(body, "<nav class=\"pagination\">{}</nav>", links.join(" · "));
    }
    if web {
        body.push_str("<h2 id=\"post\">Start a thread</h2>\n");
        body.push_str(&refusal(refused));
        body.push_str(&form(&format!("/{name}/"), true, draft));
    } else {
        body.push_str(&refusal(refused));
    }
    body.push_str(&client_hint(&about, if web { "post with your own key" } else { "post" }, &format!("{name} --title &quot;…&quot; &quot;…&quot;")));
    let label = format!("/{name}/");
    Ok(page(site, &about, &format!("/{name}/ {title}"), &[(&label, &label)], &body))
}

fn refusal(reason: Option<&str>) -> String {
    reason.map_or_else(String::new, |reason| format!("<p class=\"refused\"><strong>Not posted:</strong> {}</p>\n", escape(reason)))
}

/// A form for a new thread or a reply, holding the text sent if it was refused
fn form(action: &str, with_title: bool, draft: &Draft) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "<form method=\"post\" action=\"{}\">", escape(action));
    if with_title {
        let _ = writeln!(
            out,
            "<p><label>Title<br><input type=\"text\" name=\"title\" maxlength=\"{}\" value=\"{}\"></label></p>",
            anathemic_core::MAX_TITLE,
            escape(&draft.title)
        );
    }
    let _ = writeln!(
        out,
        "<p><label>Text<br><textarea name=\"body\" rows=\"6\" cols=\"60\">{}</textarea></label></p>\n\
         <p><button type=\"submit\">Post anonymously</button></p>\n</form>\n\
         <p class=\"meta\">Posts from this page carry no key: anyone could have sent them. \
         Markup: *emphasis*, **strong**, `code`, &gt; quotes, - lists, &gt;&gt;12 links to post 12.</p>",
        escape(&draft.body)
    );
    out
}

fn authors_rule(authors: Authors) -> &'static str {
    match authors {
        Authors::Shown => "Every post shows its author's key",
        Authors::Hidden => "Posts don't show their authors",
        Authors::Choice => "Posters choose whether to show their key",
    }
}

async fn thread<S: Source>(State(site): State<Arc<S>>, Path((name, number)): Path<(String, u64)>) -> Result<Response, Fail> {
    thread_page(&*site, &name, number, None, &Draft::default())
}

fn thread_page(site: &impl Source, name: &str, number: u64, refused: Option<&str>, draft: &Draft) -> Result<Response, Fail> {
    let about = about(site)?;
    let (board_title, _, web) = site.board(name)?;
    let posts = match site.thread(name, number) {
        // A reply's number goes to its place in its thread
        Err(Fail::NotFound) => return to_post(site, name, number),
        result => result?,
    };
    let states = site.epoch_states(name)?;
    let moderation = site.moderation()?;
    let title = match moderation.removed(name, posts[0].number) {
        Some(_) => "[hidden by a moderator]".to_string(),
        None => posts[0].content.title.clone().unwrap_or_default(),
    };
    let here: HashSet<u64> = posts.iter().map(|post| post.number).collect();

    let mut body = format!("<h1>{}</h1>\n", escape(&title));
    for post in &posts {
        let state = match states.get(&post.epoch) {
            Some(EpochState::Sealed) => "sealed",
            Some(EpochState::Settling) => "settling",
            _ => "open",
        };
        let author = match post.author_key() {
            Some(key) => format!("<code>{}</code>", key.fingerprint()),
            None if post.web => "Anonymous (web)".to_string(),
            None => "Anonymous".to_string(),
        };
        let _ = writeln!(
            body,
            "<div class=\"post\" id=\"p{n}\"><div class=\"meta\"><a href=\"#p{n}\">#{n}</a> · {author} · {} · epoch {} ({state})</div>\n{}</div>",
            utc(post.accepted),
            post.epoch,
            match moderation.removed(name, post.number) {
                Some(reason) => format!("<p class=\"meta\"><em>Hidden by a moderator: {}</em></p>", escape(reason)),
                None => render(post, name, &|n| here.contains(&n)),
            },
            n = post.number,
        );
    }
    if web {
        body.push_str("<h2 id=\"reply\">Reply</h2>\n");
        body.push_str(&refusal(refused));
        body.push_str(&form(&format!("/{name}/{number}"), false, draft));
    } else {
        body.push_str(&refusal(refused));
    }
    body.push_str(&client_hint(&about, if web { "reply with your own key" } else { "reply" }, &format!("{name} --thread {number} &quot;…&quot;")));
    let board_link = format!("/{name}/");
    let board_label = format!("/{name}/ {board_title}");
    Ok(page(site, &about, &title, &[(&board_link, &board_label)], &body))
}

/// Sends a link to a post on to its place in its thread
async fn post<S: Source>(State(site): State<Arc<S>>, Path((name, number)): Path<(String, u64)>) -> Result<Response, Fail> {
    to_post(&*site, &name, number)
}

fn to_post(site: &impl Source, name: &str, number: u64) -> Result<Response, Fail> {
    let thread = site.thread_of(name, number)?;
    Ok(Redirect::to(&format!("/{name}/{thread}#p{number}")).into_response())
}

fn destination(headers: &HeaderMap) -> Option<String> {
    headers.get(DESTINATION_HEADER).and_then(|value| value.to_str().ok()).map(str::to_string)
}

/// Text from a browser, with its line endings made plain
fn tidy(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

async fn new_thread<S: Source>(
    State(site): State<Arc<S>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Form(draft): Form<Draft>,
) -> Result<Response, Fail> {
    let content = Content { thread: None, title: Some(draft.title.trim().to_string()), body: tidy(&draft.body) };
    match submit(&site, &name, content, destination(&headers)).await {
        Ok(record) => posted(&name, record),
        Err(Fail::Refused(reason)) => refused(board_page(&*site, &name, 1, Some(&reason), &draft)),
        Err(other) => Err(other),
    }
}

async fn new_reply<S: Source>(
    State(site): State<Arc<S>>,
    Path((name, thread)): Path<(String, u64)>,
    headers: HeaderMap,
    Form(draft): Form<Draft>,
) -> Result<Response, Fail> {
    let content = Content { thread: Some(thread), title: None, body: tidy(&draft.body) };
    match submit(&site, &name, content, destination(&headers)).await {
        Ok(record) => posted(&name, record),
        Err(Fail::Refused(reason)) => refused(thread_page(&*site, &name, thread, Some(&reason), &draft)),
        Err(other) => Err(other),
    }
}

/// Posts off the async threads: a standby passes the post on to the writer over I2P
async fn submit<S: Source>(site: &Arc<S>, board: &str, content: Content, from: Option<String>) -> Result<Signed<Post>, Fail> {
    let (site, board) = (site.clone(), board.to_string());
    tokio::task::spawn_blocking(move || site.submit_web(&board, content, from.as_deref(), now()))
        .await
        .map_err(|e| Fail::Internal(e.to_string()))?
}

/// On to the new post, as a GET, so reloading doesn't post again
fn posted(name: &str, record: anathemic_core::Signed<Post>) -> Result<Response, Fail> {
    let post = record.peek()?;
    let thread = post.content.thread.unwrap_or(post.number);
    Ok(Redirect::to(&format!("/{name}/{thread}#p{}", post.number)).into_response())
}

/// The page again with the reason and the text that was sent, so nothing typed is lost
fn refused(page: Result<Response, Fail>) -> Result<Response, Fail> {
    let mut response = page?;
    *response.status_mut() = StatusCode::BAD_REQUEST;
    Ok(response)
}

/// A post's body as HTML. `in_thread` says whether a post number is on the same page.
pub fn render(post: &Post, board: &str, in_thread: &dyn Fn(u64) -> bool) -> String {
    render_markup(&post.content.body, board, in_thread)
}

/// Post markup as HTML. Post links go to `board`.
pub fn render_markup(text: &str, board: &str, in_thread: &dyn Fn(u64) -> bool) -> String {
    let mut out = String::new();
    for block in markup::parse(text) {
        match block {
            Block::Paragraph(inlines) => {
                let _ = writeln!(out, "<p>{}</p>", render_inlines(&inlines, board, in_thread));
            }
            Block::Quote(inlines) => {
                let _ = writeln!(out, "<blockquote>{}</blockquote>", render_inlines(&inlines, board, in_thread));
            }
            Block::List(items) => {
                out.push_str("<ul>");
                for item in items {
                    let _ = write!(out, "<li>{}</li>", render_inlines(&item, board, in_thread));
                }
                out.push_str("</ul>\n");
            }
            Block::Code(code) => {
                let _ = writeln!(out, "<pre><code>{}</code></pre>", escape(&code));
            }
        }
    }
    out
}

fn render_inlines(inlines: &[Inline], board: &str, in_thread: &dyn Fn(u64) -> bool) -> String {
    let mut out = String::new();
    for inline in inlines {
        match inline {
            Inline::Text(text) => out.push_str(&escape(text)),
            Inline::Code(code) => {
                let _ = write!(out, "<code>{}</code>", escape(code));
            }
            Inline::Strong(text) => {
                let _ = write!(out, "<strong>{}</strong>", escape(text));
            }
            Inline::Emphasis(text) => {
                let _ = write!(out, "<em>{}</em>", escape(text));
            }
            Inline::PostRef(n) if in_thread(*n) => {
                let _ = write!(out, "<a href=\"#p{n}\">&gt;&gt;{n}</a>");
            }
            // Outside a board (the site's description) a post number links nowhere
            Inline::PostRef(n) if board.is_empty() => {
                let _ = write!(out, "&gt;&gt;{n}");
            }
            Inline::PostRef(n) => {
                let _ = write!(out, "<a href=\"/{board}/post/{n}\">&gt;&gt;{n}</a>");
            }
            Inline::Link(url) => {
                let url = escape(url);
                let _ = write!(out, "<a href=\"{url}\" rel=\"nofollow noreferrer\">{url}</a>");
            }
            Inline::LineBreak => out.push_str("<br>\n"),
        }
    }
    out
}
