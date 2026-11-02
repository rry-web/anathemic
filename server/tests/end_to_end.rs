//! A real server on localhost and the client library: posting, closing and sealing epochs,
//! reading everything back verified, and the cache

use std::{fs, sync::Arc};

use anathemic_client::Client;
use anathemic_core::{Authors, Content, SecretKey, now};
use anathemic_server::{Config, Site, add_board, init, router};

struct Running {
    site: Arc<Site>,
    url: String,
    _runtime: tokio::runtime::Runtime,
}

fn start(dir: &std::path::Path) -> Running {
    init(dir).unwrap();
    add_board(dir, "general", "General", Authors::Choice).unwrap();
    add_board(dir, "named", "Names shown", Authors::Shown).unwrap();
    add_board(dir, "masks", "Names hidden", Authors::Hidden).unwrap();
    let config = Config { epoch_posts: 3, epoch_seconds: 3600, window_seconds: 60 };
    let site = Arc::new(Site::open(dir, config).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(site.clone());
    runtime.spawn(async move { axum_serve(listener, app).await });
    Running { site, url, _runtime: runtime }
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
