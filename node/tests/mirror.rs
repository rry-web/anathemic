//! A node's read-only mirror standing in for a server that's gone: clients that have read the
//! site before read all of it from the mirror, checked as if it came from the server

use std::{fs, sync::Arc};

use anathemic_client::{Client, cache_dir, member_key, mirrors_path};
use anathemic_core::{
    Authors, Content, SecretKey,
    moderation::{Action, Power, Revocation, Target},
    now,
};
use anathemic_node::mirror;
use anathemic_core::link::Link;
use anathemic_server::{Config, Site, SiteSettings, add_board, init, moderate::add_moderator, router, set_site, snapshot::Mirrored};

fn post(thread: Option<u64>, body: &str) -> Content {
    Content { thread, title: thread.is_none().then(|| "A thread".to_string()), body: body.into() }
}

#[test]
fn clients_read_from_a_mirror_while_the_server_is_down() {
    let dir = tempfile::tempdir().unwrap();
    let site_dir = dir.path().join("site");
    init(&site_dir).unwrap();
    add_board(&site_dir, "general", "General", Authors::Choice).unwrap();
    set_site(&site_dir, SiteSettings { addresses: Some(vec!["forum.i2p".into()]), ..Default::default() }).unwrap();
    let config = Config { epoch_posts: 3, window_seconds: 60, ..Default::default() };
    let site = Arc::new(Site::open(&site_dir, config).unwrap());
    let server = tokio::runtime::Runtime::new().unwrap();
    let listener = server.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(site.clone());
    server.spawn(async move { axum::serve(listener, app).await });

    // Epoch 0 sealed, and a post in epoch 1, still open
    let key = SecretKey::generate();
    let node_home = dir.path().join("node");
    let node = Client::new(&url, None, node_home.clone()).unwrap();
    node.submit(&key, "general", post(None, "first"), false).unwrap();
    node.submit(&key, "general", post(Some(1), "second"), false).unwrap();
    node.submit(&key, "general", post(Some(1), "third"), false).unwrap();
    node.submit(&key, "general", post(Some(1), "fourth, not sealed yet"), false).unwrap();
    site.tick(now() + 61).unwrap();

    // A moderator hides the second post
    let root = site.root();
    let moderator_home = dir.path().join("moderator");
    let (moderator_key, _) = member_key(&moderator_home, &root).unwrap();
    add_moderator(&site_dir, None, moderator_key.public(), "mod", vec![], vec![Power::Hide], None).unwrap();
    let hide = Revocation { target: Target::Post { board: "general".into(), number: 2 }, action: Action::Hide, reason: "off topic".into(), time: now() };
    Client::new(&url, None, moderator_home).unwrap().moderate(&moderator_key, hide).unwrap();

    // The node reads the whole site, which leaves its cache ready to serve
    let verified = node.manifest().unwrap();
    assert_eq!(node.board_posts(&verified, "general").unwrap().len(), 4);
    node.moderation(&verified).unwrap();
    let root = verified.manifest.root;
    let mirrors = tokio::runtime::Runtime::new().unwrap();
    let pages = Arc::new(Mirrored::new(mirror::snapshot(&node_home, &root, vec![]).unwrap()));
    let addr = mirrors.block_on(mirror::serve(cache_dir(&node_home, &root), pages)).unwrap();

    // The server's pages give a link for mirroring it
    let page = ureq::get(&format!("{url}/")).call().unwrap().into_string().unwrap();
    assert!(page.contains(&format!("anathemic-node 'anathemic:forum.i2p?root={}'", root.to_hex())), "{page}");

    // A reader who has seen the site before, and knows of the mirror
    let reader_home = dir.path().join("reader");
    Client::new(&url, None, reader_home.clone()).unwrap().manifest().unwrap();
    fs::create_dir_all(mirrors_path(&reader_home, &root).parent().unwrap()).unwrap();
    fs::write(mirrors_path(&reader_home, &root), format!("http://127.0.0.1:1\nhttp://{addr}\n")).unwrap();

    drop(server);
    let reader = Client::new(&url, None, reader_home).unwrap();
    let verified = reader.manifest().unwrap();
    assert_eq!(reader.source(), Some(format!("http://{addr}")));
    let posts = reader.board_posts(&verified, "general").unwrap();
    let bodies: Vec<&str> = posts.iter().map(|p| p.content.body.as_str()).collect();
    assert_eq!(bodies, ["first", "second", "third", "fourth, not sealed yet"]);
    assert_eq!(reader.moderation(&verified).unwrap().removed("general", 2), Some("off topic"));

    // Browsers read the same pages from the mirror, read-only and labelled as a mirror
    let get = |path: &str| ureq::get(&format!("http://{addr}{path}")).call().unwrap().into_string().unwrap();
    let index = get("/");
    assert!(index.contains("read-only mirror") && index.contains("/general/"), "{index}");
    assert!(index.contains("anathemic-node 'anathemic:forum.i2p?root="));
    let thread = get("/general/1");
    assert!(thread.contains("fourth, not sealed yet") && thread.contains("(sealed)") && thread.contains("(open)"));
    assert!(!thread.contains("<form"));
    assert!(thread.contains("Hidden by a moderator: off topic") && !thread.contains(">second<"));
    let log = get("/moderation");
    assert!(log.contains("Hid <a href=\"/general/post/2\">post #2</a>") && log.contains("<td>off topic</td>"), "{log}");
    let refused = ureq::post(&format!("http://{addr}/general/1")).send_form(&[("body", "hi")]);
    assert!(matches!(refused, Err(ureq::Error::Status(400, _))));

    // Mirrors are only for sites a client has already met, whose root key it pinned…
    let stranger = Client::new(&url, None, dir.path().join("stranger")).unwrap();
    let error = stranger.manifest().unwrap_err().to_string();
    assert!(error.contains("no mirrors are known"), "{error}");

    // …or that someone shared a link to: it carries the root key and mirrors, so a friend can
    // start mirroring while the server is down
    let address = url.trim_start_matches("http://").to_string();
    let link = Link { address: address.clone(), root, mirrors: vec![addr.to_string()] };
    let friend = Client::new(&link.to_string(), None, dir.path().join("friend")).unwrap();
    let verified = friend.manifest().unwrap();
    assert_eq!(friend.board_posts(&verified, "general").unwrap().len(), 4);

    // A link naming a different root key than the one pinned is refused
    let forged = Link { address, root: SecretKey::generate().public(), mirrors: vec![addr.to_string()] };
    assert!(Client::new(&forged.to_string(), None, dir.path().join("friend")).is_err());
}
