//! Web pages for reading a site in any browser, rynx and other text browsers first: plain HTML
//! with a little CSS, and never JavaScript (the pages' Content-Security-Policy forbids it).
//!
//! The server renders these from its own records, so a reader trusts the server for what they
//! show. The dedicated client verifies every signature instead.

use std::{collections::HashSet, fmt::Write, sync::Arc};

use anathemic_core::{
    Authors, Post, utc, valid_board_name,
    markup::{self, Block, Inline},
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{EpochState, Fail, Site};

/// Board names the server's own addresses use
pub const RESERVED: &[&str] = &["boards", "manifest", "static"];
const THREADS_PER_PAGE: u64 = 50;

pub fn routes() -> Router<Arc<Site>> {
    Router::new()
        .route("/", get(index))
        .route("/{board}", get(to_board))
        .route("/{board}/", get(board))
        .route("/{board}/{thread}", get(thread))
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
    blockquote{color:#363;margin:.4em 0 .4em .8em;padding-left:.6em;border-left:3px solid #9c9}\
    pre{background:#f4f4f4;padding:.5em;overflow-x:auto}\
    td,th{padding:.2em .6em;text-align:left}\
    footer{color:#666;font-size:.85em;margin-top:2em}\
    @media(prefers-color-scheme:dark){body{background:#111;color:#ddd}a{color:#8bf}pre{background:#222}.meta,footer{color:#999}}";

fn page(site: &Site, title: &str, crumbs: &[(&str, &str)], body: &str) -> Response {
    let fingerprint = site.root().fingerprint();
    let mut nav = format!("<a href=\"/\">Site {fingerprint}</a>");
    for (href, label) in crumbs {
        let _ = write!(nav, " · <a href=\"{}\">{}</a>", escape(href), escape(label));
    }
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head><body>\
         <nav>{nav}</nav>\n{body}\n<footer><p>An Anathemic swarmboard. Site {fingerprint}, root key \
         <code>{root}</code>. These pages are drawn by the server; the anathemic client checks \
         every signature itself.</p></footer></body></html>\n",
        title = escape(title),
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

async fn to_board(Path(name): Path<String>) -> Result<Response, Fail> {
    if !valid_board_name(&name) {
        return Err(Fail::NotFound);
    }
    Ok(Redirect::permanent(&format!("/{name}/")).into_response())
}

async fn index(State(site): State<Arc<Site>>) -> Result<Response, Fail> {
    let boards = site.boards()?;
    let mut body = format!("<h1>Site {}</h1>\n", site.root().fingerprint());
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
    Ok(page(&site, &format!("Site {}", site.root().fingerprint()), &[], &body))
}

#[derive(Deserialize)]
struct PageQuery {
    page: Option<u64>,
}

async fn board(State(site): State<Arc<Site>>, Path(name): Path<String>, Query(query): Query<PageQuery>) -> Result<Response, Fail> {
    let (title, authors) = site.board(&name)?;
    let number = query.page.unwrap_or(1).max(1);
    let (threads, total) = site.threads(&name, (number - 1) * THREADS_PER_PAGE, THREADS_PER_PAGE)?;
    let pages = total.div_ceil(THREADS_PER_PAGE).max(1);
    if number > pages {
        return Err(Fail::NotFound);
    }

    let mut body = format!("<h1>/{name}/ {}</h1>\n<p class=\"meta\">{}. {}.</p>\n", escape(&title), plural(total, "thread", "threads"), authors_rule(authors));
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
    let _ = write!(
        body,
        "<p class=\"meta\">To post, use the anathemic client: \
         <code>anathemic-client post &lt;this site&#39;s address&gt; {name} --title &quot;…&quot; &quot;…&quot;</code></p>"
    );
    Ok(page(&site, &format!("/{name}/ {title}"), &[(&format!("/{name}/"), &format!("/{name}/"))], &body))
}

fn authors_rule(authors: Authors) -> &'static str {
    match authors {
        Authors::Shown => "Every post shows its author's key",
        Authors::Hidden => "Posts don't show their authors",
        Authors::Choice => "Posters choose whether to show their key",
    }
}

async fn thread(State(site): State<Arc<Site>>, Path((name, number)): Path<(String, u64)>) -> Result<Response, Fail> {
    let (board_title, _) = site.board(&name)?;
    let posts = match site.thread(&name, number) {
        // A reply's number goes to its place in its thread
        Err(Fail::NotFound) => return post(State(site), Path((name, number))).await,
        result => result?,
    };
    let states = site.epoch_states(&name)?;
    let title = posts[0].content.title.clone().unwrap_or_default();
    let here: HashSet<u64> = posts.iter().map(|post| post.number).collect();

    let mut body = format!("<h1>{}</h1>\n", escape(&title));
    for post in &posts {
        let state = match states.get(&post.epoch) {
            Some(EpochState::Sealed) => "sealed",
            Some(EpochState::Settling) => "settling",
            _ => "open",
        };
        let author = post.author_key().map_or_else(|| "Anonymous".to_string(), |key| format!("<code>{}</code>", key.fingerprint()));
        let _ = writeln!(
            body,
            "<div class=\"post\" id=\"p{n}\"><div class=\"meta\"><a href=\"#p{n}\">#{n}</a> · {author} · {} · epoch {} ({state})</div>\n{}</div>",
            utc(post.accepted),
            post.epoch,
            render(post, &name, &|n| here.contains(&n)),
            n = post.number,
        );
    }
    let _ = write!(
        body,
        "<p class=\"meta\">To reply, use the anathemic client: \
         <code>anathemic-client post &lt;this site&#39;s address&gt; {name} --thread {number} &quot;…&quot;</code></p>"
    );
    let board_link = format!("/{name}/");
    let board_label = format!("/{name}/ {board_title}");
    Ok(page(&site, &title, &[(&board_link, &board_label)], &body))
}

/// Sends a link to a post on to its place in its thread
async fn post(State(site): State<Arc<Site>>, Path((name, number)): Path<(String, u64)>) -> Result<Response, Fail> {
    let thread = site.thread_of(&name, number)?;
    Ok(Redirect::to(&format!("/{name}/{thread}#p{number}")).into_response())
}

/// A post's body as HTML. `in_thread` says whether a post number is on the same page.
pub fn render(post: &Post, board: &str, in_thread: &dyn Fn(u64) -> bool) -> String {
    let mut out = String::new();
    for block in markup::parse(&post.content.body) {
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
