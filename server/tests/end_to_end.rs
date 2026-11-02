//! A real server on localhost and the client library: posting, closing and sealing epochs,
//! reading everything back verified, and the cache

use std::{fs, sync::Arc};

use anathemic_client::Client;
use anathemic_core::{Authors, Content, SecretKey, bencode, i2p, now, torrent};
use anathemic_server::{Config, Site, SiteSettings, add_board, init, router, set_site, set_web_posting};

struct Running {
    dir: std::path::PathBuf,
    site: Arc<Site>,
    url: String,
    _runtime: tokio::runtime::Runtime,
}

fn start(dir: &std::path::Path) -> Running {
    init(dir).unwrap();
    add_board(dir, "general", "General", Authors::Choice).unwrap();
    add_board(dir, "named", "Names shown", Authors::Shown).unwrap();
    add_board(dir, "masks", "Names hidden", Authors::Hidden).unwrap();
    let config = Config { epoch_posts: 3, epoch_seconds: 3600, window_seconds: 60, web_posts_per_hour: 5, web_posts_per_hour_each: 2 };
    let site = Arc::new(Site::open(dir, config).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(site.clone());
    runtime.spawn(async move { axum_serve(listener, app).await });
    Running { dir: dir.to_path_buf(), site, url, _runtime: runtime }
}

async fn axum_serve(listener: tokio::net::TcpListener, app: axum::Router) {
    axum::serve(listener, app).await.unwrap();
}

fn thread(title: &str, body: &str) -> Content {
    Content { thread: None, title: Some(title.into()), body: body.into() }
}

fn reply(thread: u64, body: &str) -> Content {
    Content { thread: Some(thread), title: None, body: body.into() }
}

#[test]
fn posts_seal_into_a_verified_chain() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(&dir.path().join("site"));
    let client = Client::new(&server.url, None, dir.path().join("home")).unwrap();
    let key = SecretKey::generate();

    let first = client.submit(&key, "general", thread("Hello", "first post"), false).unwrap();
    assert_eq!((first.number, first.epoch), (1, 0));
    assert_eq!(first.author_key(), Some(key.public()));
    client.submit(&key, "general", reply(1, "second"), false).unwrap();
    let hidden = client.submit(&key, "general", reply(1, "third, anonymously"), true).unwrap();
    assert_eq!(hidden.author_key(), None);
    // Three posts closed epoch 0; the fourth opens epoch 1
    let fourth = client.submit(&key, "general", reply(1, "fourth"), false).unwrap();
    assert_eq!(fourth.epoch, 1);

    let before = client.manifest().unwrap();
    let general = before.manifest.board("general").unwrap();
    assert!(general.sealed.is_empty());
    assert_eq!(general.unsealed, vec![0, 1]);

    // Still settling inside the window; sealed after it
    server.site.tick(now() + 30).unwrap();
    assert!(client.manifest().unwrap().manifest.board("general").unwrap().sealed.is_empty());
    server.site.tick(now() + 61).unwrap();
    let after = client.manifest().unwrap();
    assert!(after.manifest.sequence > before.manifest.sequence);
    let general = after.manifest.board("general").unwrap();
    assert_eq!(general.sealed.len(), 1);
    assert_eq!(general.unsealed, vec![1]);

    let posts = client.board_posts(&after, "general").unwrap();
    let numbers: Vec<u64> = posts.iter().map(|p| p.number).collect();
    assert_eq!(numbers, vec![1, 2, 3, 4]);
    assert_eq!(posts[2].author_key(), None);
    assert_eq!(posts[3].author_key(), Some(key.public()));

    // The sealed epoch is cached, and a damaged copy is fetched again
    let cached = client.cache_path(&after.manifest.root, "general", 0);
    assert!(cached.exists());
    fs::write(&cached, b"damaged").unwrap();
    assert_eq!(client.board_posts(&after, "general").unwrap().len(), 4);
    assert_ne!(fs::read(&cached).unwrap(), b"damaged");
}

#[test]
fn boards_enforce_their_rules() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(&dir.path().join("site"));
    let client = Client::new(&server.url, None, dir.path().join("home")).unwrap();
    let key = SecretKey::generate();

    let error = client.submit(&key, "named", thread("Hi", "hiding"), true).unwrap_err();
    assert!(error.to_string().contains("shows every post's author"), "{error}");
    assert!(client.submit(&key, "named", thread("Hi", "named"), false).unwrap().author_key().is_some());

    assert!(client.submit(&key, "masks", thread("Hi", "masked"), false).unwrap().author_key().is_none());

    let error = client.submit(&key, "general", reply(42, "to nothing"), false).unwrap_err();
    assert!(error.to_string().contains("no such thread"), "{error}");
    let error = client.submit(&key, "nowhere", thread("Hi", "lost"), false).unwrap_err();
    assert!(error.to_string().contains("not found"), "{error}");
}

#[test]
fn a_different_root_key_at_the_same_address_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let first = start(&dir.path().join("first"));
    Client::new(&first.url, None, home.clone()).unwrap().manifest().unwrap();

    // Another site answers at the address the client pinned
    let second = start(&dir.path().join("second"));
    let pins = fs::read_to_string(home.join("sites.txt")).unwrap();
    fs::write(home.join("sites.txt"), pins.replace(&first.url, &second.url)).unwrap();
    let error = Client::new(&second.url, None, home).unwrap().manifest().unwrap_err();
    assert!(format!("{error:#}").contains("root key"), "{error:#}");
}

#[test]
fn members_have_a_key_per_site() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let first = start(&dir.path().join("first"));
    let second = start(&dir.path().join("second"));
    let (one, made) = anathemic_client::member_key(&home, &first.site.root()).unwrap();
    assert!(made);
    let (again, made) = anathemic_client::member_key(&home, &first.site.root()).unwrap();
    assert!(!made);
    assert_eq!(again.public(), one.public());
    let (other, _) = anathemic_client::member_key(&home, &second.site.root()).unwrap();
    assert_ne!(other.public(), one.public());
}

fn get_page(url: &str) -> (u16, String, Option<String>) {
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(e) => panic!("{e}"),
    };
    let status = response.status();
    let csp = response.header("content-security-policy").map(str::to_string);
    let location = response.header("location").map(str::to_string);
    let body = response.into_string().unwrap();
    (status, if status / 100 == 3 { location.unwrap_or_default() } else { body }, csp)
}

#[test]
fn web_pages_show_the_site_without_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(&dir.path().join("site"));
    let client = Client::new(&server.url, None, dir.path().join("home")).unwrap();
    let key = SecretKey::generate();
    client.submit(&key, "general", thread("Tags & <things>", "Hello **world**"), false).unwrap();
    client.submit(&key, "general", reply(1, "<script>alert(1)</script>\n> quoted\n\nsee >>1"), true).unwrap();
    client.submit(&key, "general", thread("Second", "a reply to >>2 from elsewhere"), false).unwrap();

    let (status, index, csp) = get_page(&server.url);
    assert_eq!(status, 200);
    assert!(csp.unwrap().contains("default-src 'none'"));
    assert!(index.contains("<a href=\"/general/\">/general/</a> General"), "{index}");

    let (status, board, _) = get_page(&format!("{}/general/", server.url));
    assert_eq!(status, 200);
    assert!(board.contains("Tags &amp; &lt;things&gt;"), "{board}");
    // The most recently active thread comes first
    assert!(board.find("Second").unwrap() < board.find("Tags &amp;").unwrap());

    let (status, page, _) = get_page(&format!("{}/general/1", server.url));
    assert_eq!(status, 200);
    assert!(page.contains("Hello <strong>world</strong>"), "{page}");
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{page}");
    assert!(!page.contains("<script"), "{page}");
    assert!(page.contains("<blockquote>quoted</blockquote>"), "{page}");
    assert!(page.contains("<a href=\"#p1\">&gt;&gt;1</a>"), "{page}");
    assert!(page.contains("Anonymous"), "{page}");
    assert!(page.contains(&key.public().fingerprint()), "{page}");

    let (_, other, _) = get_page(&format!("{}/general/3", server.url));
    assert!(other.contains("<a href=\"/general/post/2\">&gt;&gt;2</a>"), "{other}");
    assert_eq!(get_page(&format!("{}/general/post/2", server.url)).1, "/general/1#p2");
    assert_eq!(get_page(&format!("{}/general/2", server.url)).1, "/general/1#p2");
    assert_eq!(get_page(&format!("{}/general", server.url)).1, "/general/");

    assert_eq!(get_page(&format!("{}/general/99", server.url)).0, 404);
    assert_eq!(get_page(&format!("{}/nowhere/", server.url)).0, 404);
    assert_eq!(get_page(&format!("{}/general/?page=5", server.url)).0, 404);
    assert_eq!(get_page(&format!("{}/bad%0Aname", server.url)).0, 404);
}

#[test]
fn reserved_board_names_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path()).unwrap();
    assert!(add_board(dir.path(), "manifest", "Clash", Authors::Choice).is_err());
}

/// Posts a web form; the status and where it sent the browser, or the page
fn post_form(url: &str, fields: &[(&str, &str)], from: Option<&str>) -> (u16, String) {
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut request = agent.post(url);
    if let Some(from) = from {
        request = request.set("X-I2P-DestHash", from);
    }
    let response = match request.send_form(fields) {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(e) => panic!("{e}"),
    };
    let status = response.status();
    let location = response.header("location").map(str::to_string);
    (status, if status == 303 { location.unwrap() } else { response.into_string().unwrap() })
}

#[test]
fn boards_can_take_anonymous_posts_from_the_web() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(&dir.path().join("site"));
    let client = Client::new(&server.url, None, dir.path().join("home")).unwrap();
    let board = format!("{}/general/", server.url);

    // Off until the operator turns it on
    assert!(!get_page(&board).1.contains("<form"));
    let (status, page) = post_form(&board, &[("title", "Hi"), ("body", "from rynx")], None);
    assert_eq!(status, 400);
    assert!(page.contains("only from the anathemic client"), "{page}");

    assert!(set_web_posting(&server.dir, "named", true).is_err());
    set_web_posting(&server.dir, "general", true).unwrap();
    assert!(client.manifest().unwrap().manifest.board("general").unwrap().web_posting);
    assert!(get_page(&board).1.contains("<form method=\"post\" action=\"/general/\">"));

    assert_eq!(post_form(&board, &[("title", "From a browser"), ("body", "line one\r\nline two")], Some("aaa")).1, "/general/1#p1");
    assert_eq!(post_form(&format!("{board}1"), &[("body", "a reply")], Some("aaa")).1, "/general/1#p2");

    // The client verifies them like any other post
    let site = client.manifest().unwrap();
    let posts = client.board_posts(&site, "general").unwrap();
    assert_eq!(posts.len(), 2);
    assert!(posts.iter().all(|post| post.web && post.author_key().is_none()));
    assert_eq!(posts[0].content.body, "line one\nline two");
    assert!(get_page(&format!("{board}1")).1.contains("Anonymous (web)"));

    // Refused posts come back with the reason and what was typed
    let (status, page) = post_form(&board, &[("title", ""), ("body", "kept <text>")], Some("bbb"));
    assert_eq!(status, 400);
    assert!(page.contains("a title is one line of text") && page.contains("kept &lt;text&gt;</textarea>"), "{page}");

    // Two an hour from each destination, five from everyone
    let (status, page) = post_form(&format!("{board}1"), &[("body", "third")], Some("aaa"));
    assert_eq!(status, 400);
    assert!(page.contains("try again later"), "{page}");
    for i in 0..3 {
        assert_eq!(post_form(&format!("{board}1"), &[("body", &format!("other {i}"))], None).0, 303);
    }
    assert_eq!(post_form(&format!("{board}1"), &[("body", "one too many")], Some("ccc")).0, 400);
}

#[test]
fn the_site_has_a_name_description_and_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(&dir.path().join("site"));
    let client = Client::new(&server.url, None, dir.path().join("home")).unwrap();
    let before = client.manifest().unwrap().manifest;
    assert_eq!(before.title(), format!("Site {}", server.site.root().fingerprint()));

    let bad = SiteSettings { addresses: Some(vec!["forum.com".into()]), ..Default::default() };
    assert!(set_site(&server.dir, bad).is_err());
    set_site(
        &server.dir,
        SiteSettings {
            name: Some("The <Forum>".into()),
            description: Some("Talk about **anything**.".into()),
            addresses: Some(vec!["forum.i2p".into()]),
        },
    )
    .unwrap();
    let after = client.manifest().unwrap().manifest;
    assert!(after.sequence > before.sequence);
    assert_eq!((after.name.as_str(), after.addresses.as_slice()), ("The <Forum>", &["forum.i2p".to_string()][..]));

    let index = get_page(&server.url).1;
    assert!(index.contains("<h1>The &lt;Forum&gt;</h1>"), "{index}");
    assert!(index.contains("Talk about <strong>anything</strong>."), "{index}");
    assert!(get_page(&format!("{}/general/", server.url)).1.contains("anathemic-client post http://forum.i2p general"));
}

#[test]
fn sites_made_by_the_first_prototype_still_open() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path()).unwrap();
    add_board(dir.path(), "general", "General", Authors::Choice).unwrap();
    let db = rusqlite::Connection::open(dir.path().join("site.db")).unwrap();
    db.execute_batch("alter table boards drop column web; delete from meta where key in ('name', 'description', 'addresses');").unwrap();
    drop(db);
    let site = Site::open(dir.path(), Config::default()).unwrap();
    assert!(!site.manifest(now()).unwrap().peek().unwrap().boards[0].web_posting);
}

/// An announce to the site's tracker, as if through the I2P tunnel from `destination`
fn announce(url: &str, infohash: &[u8; 20], destination: Option<&str>, seeding: bool) -> bencode::Value {
    let escaped: String = infohash.iter().map(|b| format!("%{b:02X}")).collect();
    let left = if seeding { 0 } else { 1000 };
    let mut request = ureq::get(&format!("{url}/announce?info_hash={escaped}&peer_id=-XX0001-000000000000&port=6881&uploaded=0&downloaded=0&left={left}&compact=1"));
    if let Some(destination) = destination {
        request = request.set("X-I2P-DestB64", destination);
    }
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut request.call().unwrap().into_reader(), &mut body).unwrap();
    bencode::decode(&body).unwrap()
}

#[test]
fn sealed_epochs_are_torrents_the_site_tracks() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(&dir.path().join("site"));
    set_site(&server.dir, SiteSettings { addresses: Some(vec!["forum.i2p".into()]), ..Default::default() }).unwrap();
    let client = Client::new(&server.url, None, dir.path().join("home")).unwrap();
    let key = SecretKey::generate();
    client.submit(&key, "general", thread("Hello", "first post"), false).unwrap();
    client.submit(&key, "general", reply(1, "second"), false).unwrap();
    client.submit(&key, "general", reply(1, "third"), false).unwrap();
    server.site.tick(now() + 61).unwrap();

    let site = client.manifest().unwrap();
    let sealed = &site.manifest.board("general").unwrap().sealed[0];
    let infohash = sealed.infohash.expect("sealed epochs list their torrent");
    let bundle = ureq::get(&format!("{}/boards/general/epochs/0", server.url)).call().unwrap();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut bundle.into_reader(), &mut bytes).unwrap();
    assert_eq!(torrent::bundle_hash(&bytes, "general", 0), infohash);

    // The torrent file holds the same info, and announces to the site's tracker
    let file = ureq::get(&format!("{}/boards/general/epochs/0/torrent", server.url)).call().unwrap();
    let mut file_bytes = Vec::new();
    std::io::Read::read_to_end(&mut file.into_reader(), &mut file_bytes).unwrap();
    torrent::info_of(&file_bytes, &infohash).unwrap();
    let parsed = bencode::decode(&file_bytes).unwrap();
    assert_eq!(parsed.get("announce").unwrap().bytes().unwrap(), b"http://forum.i2p/announce");

    // Announces count only through the tunnel, and only for the site's own epochs
    let seeder = format!("B{}", "A".repeat(519));
    let leecher = format!("C{}", "A".repeat(519));
    let refused = announce(&server.url, &infohash.0, None, false);
    assert!(refused.get("failure reason").is_some());
    let stranger = announce(&server.url, &[9; 20], Some(&seeder), true);
    assert!(stranger.get("failure reason").is_some());

    let first = announce(&server.url, &infohash.0, Some(&seeder), true);
    assert_eq!(first.get("peers").unwrap().bytes().unwrap(), b"");
    let second = announce(&server.url, &infohash.0, Some(&leecher), false);
    let seeder_hash = i2p::destination_hash(&i2p::decode_destination(&seeder).unwrap());
    assert_eq!(second.get("peers").unwrap().bytes().unwrap(), seeder_hash);
    assert_eq!(second.get("complete").unwrap().int(), Some(1));

    // Epochs sealed before mirroring get their info hashes when the site is next opened
    let db = rusqlite::Connection::open(server.dir.join("site.db")).unwrap();
    db.execute("update epochs set infohash = null", []).unwrap();
    drop(db);
    let reopened = Site::open(&server.dir, Config::default()).unwrap();
    let manifest = reopened.manifest(now()).unwrap().peek().unwrap();
    assert_eq!(manifest.board("general").unwrap().sealed[0].infohash, Some(infohash));
}
