//! Web pages for reading a site in any browser, rynx and other text browsers first: plain HTML
//! with a little CSS, and never JavaScript (the pages' Content-Security-Policy forbids it).
//!
//! The server renders these from its own records, so a reader trusts the server for what they
//! show. The dedicated client verifies every signature instead. Boards can also take anonymous
//! posts from these pages, which no member signs.

use std::{collections::HashSet, fmt::Write, sync::Arc};

use anathemic_core::{
    Authors, Content, Post, now, utc, valid_board_name,
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

use crate::{EpochState, Fail, Site};

/// Board names the server's own addresses use
pub const RESERVED: &[&str] = &["boards", "manifest", "static"];
const THREADS_PER_PAGE: u64 = 50;
/// The header an i2pd HTTP server tunnel adds, naming the visitor's destination
const DESTINATION_HEADER: &str = "x-i2p-desthash";

pub fn routes() -> Router<Arc<Site>> {
    Router::new()
        .route("/", get(index))
        .route("/{board}", get(to_board))
        .route("/{board}/", get(board).post(new_thread))
        .route("/{board}/{thread}", get(thread).post(new_reply))
        .route("/{board}/post/{number}", get(post))
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

fn about(site: &Site) -> Result<About, Fail> {
    let (name, description, addresses) = site.about()?;
    let title = if name.is_empty() { format!("Site {}", site.root().fingerprint()) } else { name };
    Ok(About { title, description, address: addresses.into_iter().next() })
}

fn page(site: &Site, about: &About, title: &str, crumbs: &[(&str, &str)], body: &str) -> Response {
    let mut nav = format!("<a href=\"/\">{}</a>", escape(&about.title));
    for (href, label) in crumbs {
        let _ = write!(nav, " · <a href=\"{}\">{}</a>", escape(href), escape(label));
    }
    let title = if title == about.title { escape(title) } else { format!("{} – {}", escape(title), escape(&about.title)) };
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body>\
         <nav>{nav}</nav>\n{body}\n<footer><p>An Anathemic swarmboard. Root key {fingerprint} \
         (<code>{root}</code>). These pages are drawn by the server; the anathemic client checks \
         every signature itself.</p></footer></body></html>\n",
        fingerprint = site.root().fingerprint(),
        root = site.root().to_hex(),
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

async fn index(State(site): State<Arc<Site>>) -> Result<Response, Fail> {
    let about = about(&site)?;
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
    Ok(page(&site, &about, &about.title, &[], &body))
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

async fn board(State(site): State<Arc<Site>>, Path(name): Path<String>, Query(query): Query<PageQuery>) -> Result<Response, Fail> {
    board_page(&site, &name, query.page.unwrap_or(1), None, &Draft::default())
}

fn board_page(site: &Site, name: &str, number: u64, refused: Option<&str>, draft: &Draft) -> Result<Response, Fail> {
    let about = about(site)?;
    let (title, authors, web) = site.board(name)?;
    let number = number.max(1);
    let (threads, total) = site.threads(name, (number - 1) * THREADS_PER_PAGE, THREADS_PER_PAGE)?;
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
                title = escape(thread.start.content.title.as_deref().unwrap_or("")),
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

async fn thread(State(site): State<Arc<Site>>, Path((name, number)): Path<(String, u64)>) -> Result<Response, Fail> {
    thread_page(&site, &name, number, None, &Draft::default())
}

fn thread_page(site: &Arc<Site>, name: &str, number: u64, refused: Option<&str>, draft: &Draft) -> Result<Response, Fail> {
    let about = about(site)?;
    let (board_title, _, web) = site.board(name)?;
    let posts = match site.thread(name, number) {
        // A reply's number goes to its place in its thread
        Err(Fail::NotFound) => return to_post(site, name, number),
        result => result?,
    };
    let states = site.epoch_states(name)?;
    let title = posts[0].content.title.clone().unwrap_or_default();
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
            render(post, name, &|n| here.contains(&n)),
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
async fn post(State(site): State<Arc<Site>>, Path((name, number)): Path<(String, u64)>) -> Result<Response, Fail> {
    to_post(&site, &name, number)
}

fn to_post(site: &Site, name: &str, number: u64) -> Result<Response, Fail> {
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

async fn new_thread(
    State(site): State<Arc<Site>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Form(draft): Form<Draft>,
) -> Result<Response, Fail> {
    let content = Content { thread: None, title: Some(draft.title.trim().to_string()), body: tidy(&draft.body) };
    match site.submit_web(&name, content, destination(&headers).as_deref(), now()) {
        Ok(record) => posted(&name, record),
        Err(Fail::Refused(reason)) => refused(board_page(&site, &name, 1, Some(&reason), &draft)),
        Err(other) => Err(other),
    }
}

async fn new_reply(
    State(site): State<Arc<Site>>,
    Path((name, thread)): Path<(String, u64)>,
    headers: HeaderMap,
    Form(draft): Form<Draft>,
) -> Result<Response, Fail> {
    let content = Content { thread: Some(thread), title: None, body: tidy(&draft.body) };
    match site.submit_web(&name, content, destination(&headers).as_deref(), now()) {
        Ok(record) => posted(&name, record),
        Err(Fail::Refused(reason)) => refused(thread_page(&site, &name, thread, Some(&reason), &draft)),
        Err(other) => Err(other),
    }
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
