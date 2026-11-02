//! Trusted hosts on localhost: a standby copies the site and passes posts on, takes over when the
//! operator's server goes down, and the operator's server steps down when it's back

use std::sync::Arc;

use anathemic_client::Client;
use anathemic_core::{Authors, Content, SecretKey, link::Link, now};
use anathemic_server::{
    Config, Site, add_board,
    hosts::{Role, add_host, init_standby, orphans, set_host_address},
    init, router, set_web_posting,
};

fn serve_on(site: Arc<Site>, listener: std::net::TcpListener) -> tokio::runtime::Runtime {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    listener.set_nonblocking(true).unwrap();
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router(site)).await
    });
    runtime
}

fn reply(thread: u64, body: &str) -> Content {
    Content { thread: Some(thread), title: None, body: body.into() }
}

fn bodies(site: &Site) -> Vec<String> {
    site.thread("general", 1).unwrap().into_iter().map(|post| post.content.body).collect()
}

#[test]
fn a_trusted_host_takes_over_and_the_old_writer_steps_down() {
    let dir = tempfile::tempdir().unwrap();
    let (primary_dir, standby_dir) = (dir.path().join("primary"), dir.path().join("standby"));
    let primary_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let standby_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let primary_address = primary_listener.local_addr().unwrap().to_string();
    let standby_address = standby_listener.local_addr().unwrap().to_string();
    let config = || Config { epoch_posts: 3, window_seconds: 60, takeover_seconds: 600, stagger_seconds: 300, ..Default::default() };

    let root = init(&primary_dir).unwrap();
    add_board(&primary_dir, "general", "General", Authors::Choice).unwrap();
    set_web_posting(&primary_dir, "general", true).unwrap();
    set_host_address(&primary_dir, &primary_address).unwrap();
    let primary = Arc::new(Site::open(&primary_dir, config()).unwrap());
    let primary_runtime = serve_on(primary.clone(), primary_listener);

    // A friend sets up a standby from the site's share link; the operator adds it
    let standby_key = init_standby(&standby_dir, &Link { address: primary_address.clone(), root, mirrors: vec![] }).unwrap();
    assert_eq!(add_host(&primary_dir, None, standby_key, &standby_address, "friend").unwrap(), 1);
    let standby = Arc::new(Site::open(&standby_dir, config()).unwrap());
    let _standby_runtime = serve_on(standby.clone(), standby_listener);

    // Posts on the operator's server, sealing an epoch; the standby copies them
    let key = SecretKey::generate();
    let direct = Client::new(&format!("http://{primary_address}"), None, dir.path().join("member")).unwrap();
    direct.submit(&key, "general", Content { thread: None, title: Some("Hello".into()), body: "first".into() }, false).unwrap();
    direct.submit(&key, "general", reply(1, "second"), false).unwrap();
    direct.submit(&key, "general", reply(1, "third"), false).unwrap();
    direct.submit(&key, "general", reply(1, "fourth"), false).unwrap();
    primary.tick(now() + 61).unwrap();
    standby.host_tick(now()).unwrap();
    assert_eq!(standby.role().unwrap(), Role::Standby);
    assert_eq!(bodies(&standby), ["first", "second", "third", "fourth"]);

    // Readers at the standby get the writer's manifest, and their posts reach the writer
    let reader_link = Link { address: standby_address.clone(), root, mirrors: vec![] };
    let reader = Client::new(&reader_link.to_string(), None, dir.path().join("reader")).unwrap();
    let site = reader.manifest().unwrap();
    assert_eq!((site.manifest.term, reader.board_posts(&site, "general").unwrap().len()), (0, 4));
    assert_eq!(reader.submit(&key, "general", reply(1, "sent to the standby"), false).unwrap().number, 5);
    let page = ureq::post(&format!("http://{standby_address}/general/1")).send_form(&[("body", "from a browser at the standby")]);
    assert!(page.unwrap().into_string().unwrap().contains("from a browser at the standby"));
    assert_eq!(bodies(&primary).len(), 6);

    // The operator's server goes down. The standby waits, then takes over in term 1.
    drop(primary_runtime);
    standby.host_tick(now() + 30).unwrap();
    assert_eq!(standby.role().unwrap(), Role::Standby);
    standby.host_tick(now() + 700).unwrap();
    assert_eq!(standby.role().unwrap(), Role::Writer);
    let site = reader.manifest().unwrap();
    assert_eq!(site.manifest.term, 1);
    assert_eq!(site.site_key, standby_key);
    assert_eq!(reader.submit(&key, "general", reply(1, "after the takeover"), false).unwrap().number, 7);
    assert_eq!(reader.board_posts(&reader.manifest().unwrap(), "general").unwrap().len(), 7);

    // A member who only knows the operator's address finds the standby on the host list, and
    // posts there
    let site = direct.manifest().unwrap();
    assert_eq!(direct.source(), Some(format!("http://{standby_address}")));
    assert_eq!(site.manifest.term, 1);
    assert_eq!(direct.submit(&key, "general", reply(1, "found the new writer"), false).unwrap().number, 8);

    // Cut off, the operator's server took a post of its own meanwhile
    let lone = primary.submit_web("general", reply(1, "only the old writer got this"), None, now()).unwrap();
    assert_eq!(lone.peek().unwrap().number, 7);

    // Back, it sees the later term, steps down, and sets its own post aside
    primary.host_tick(now()).unwrap();
    assert_eq!(primary.role().unwrap(), Role::Standby);
    let set_aside = orphans(&primary_dir).unwrap();
    assert_eq!(set_aside.len(), 1);
    assert_eq!(set_aside[0].2.peek().unwrap().content.body, "only the old writer got this");
    assert_eq!(bodies(&primary), bodies(&standby));
    assert_eq!(bodies(&primary).last().unwrap(), "found the new writer");
}
