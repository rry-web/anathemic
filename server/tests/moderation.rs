//! Moderators on a real server: hiding and restoring, purging before and after sealing, bans,
//! and appointments ending

use std::sync::Arc;

use anathemic_client::{Client, member_key};
use anathemic_core::{
    Authors, Content, SecretKey, now,
    moderation::{Action, Power, Revocation, Target},
};
use anathemic_server::{
    Config, Site, add_board, init,
    moderate::{add_moderator, end_moderator},
    router,
};

fn reply(thread: u64, body: &str) -> Content {
    Content { thread: Some(thread), title: None, body: body.into() }
}

fn revocation(target: Target, action: Action) -> Revocation {
    Revocation { target, action, reason: "spam".into(), time: now() }
}

fn post(number: u64) -> Target {
    Target::Post { board: "general".into(), number }
}

#[test]
fn moderators_hide_purge_and_ban() {
    let dir = tempfile::tempdir().unwrap();
    let site_dir = dir.path().join("site");
    let root = init(&site_dir).unwrap();
    add_board(&site_dir, "general", "General", Authors::Choice).unwrap();
    let site = Arc::new(Site::open(&site_dir, Config { epoch_posts: 3, window_seconds: 60, ..Default::default() }).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(site.clone());
    runtime.spawn(async move { axum::serve(listener, app).await });

    // The operator appoints a moderator by their member key for the site
    let moderator_home = dir.path().join("moderator");
    let (moderator_key, _) = member_key(&moderator_home, &root).unwrap();
    add_moderator(&site_dir, None, moderator_key.public(), "mod", vec!["general".into()], vec![Power::Hide, Power::Purge, Power::Ban], None).unwrap();
    let moderator = Client::new(&url, None, moderator_home).unwrap();

    let member = SecretKey::generate();
    let reader = Client::new(&url, None, dir.path().join("reader")).unwrap();
    reader.submit(&member, "general", Content { thread: None, title: Some("Hello".into()), body: "first".into() }, false).unwrap();
    reader.submit(&member, "general", reply(1, "second, spam"), false).unwrap();
    reader.submit(&member, "general", reply(1, "third"), false).unwrap();
    site.tick(now() + 61).unwrap();

    // Hiding: the post stays, readers and pages show the reason instead
    moderator.moderate(&moderator_key, revocation(post(2), Action::Hide)).unwrap();
    let verified = reader.manifest().unwrap();
    assert_eq!(reader.moderation(&verified).unwrap().removed("general", 2), Some("spam"));
    assert_eq!(reader.board_posts(&verified, "general").unwrap().len(), 3);
    let page = ureq::get(&format!("{url}/general/1")).call().unwrap().into_string().unwrap();
    assert!(page.contains("Hidden by a moderator: spam") && !page.contains("second, spam"));

    // Nobody else can, and a moderator can't act outside their boards
    let stranger = SecretKey::generate();
    assert!(reader.moderate(&stranger, revocation(post(3), Action::Hide)).is_err());
    let elsewhere = Target::Post { board: "other".into(), number: 1 };
    assert!(moderator.moderate(&moderator_key, revocation(elsewhere, Action::Hide)).is_err());

    // Restoring brings it back
    moderator.moderate(&moderator_key, revocation(post(2), Action::Restore)).unwrap();
    assert_eq!(reader.moderation(&reader.manifest().unwrap()).unwrap().removed("general", 2), None);

    // Purging in the moderation window: the post never reaches a sealed epoch
    reader.submit(&member, "general", reply(1, "fourth, purged before sealing"), false).unwrap();
    reader.submit(&member, "general", reply(1, "fifth"), false).unwrap();
    moderator.moderate(&moderator_key, revocation(post(4), Action::Purge)).unwrap();
    reader.submit(&member, "general", reply(1, "sixth"), false).unwrap();
    site.tick(now() + 61).unwrap();
    let verified = reader.manifest().unwrap();
    let numbers = |posts: Vec<anathemic_core::Post>| posts.iter().map(|p| p.number).collect::<Vec<_>>();
    assert_eq!(numbers(reader.board_posts(&verified, "general").unwrap()), [1, 2, 3, 5, 6]);

    // Purging from a sealed epoch re-seals it: a new bundle and torrent, the same index, and
    // the chain still checks out for a reader holding the old copy
    let before = verified.manifest.board("general").unwrap().sealed[0].clone();
    moderator.moderate(&moderator_key, revocation(post(3), Action::Purge)).unwrap();
    let verified = reader.manifest().unwrap();
    let after = &verified.manifest.board("general").unwrap().sealed[0];
    assert_ne!(after.sha256, before.sha256);
    assert_ne!(after.infohash, before.infohash);
    assert_eq!(after.index, before.index);
    assert!(after.index.is_some());
    assert_eq!(numbers(reader.board_posts(&verified, "general").unwrap()), [1, 2, 5, 6]);
    assert!(reader.moderate(&stranger, revocation(post(3), Action::Restore)).is_err());

    // Bans refuse the member's posts until lifted
    let banned = Target::Member { key: member.public(), board: None };
    moderator.moderate(&moderator_key, revocation(banned.clone(), Action::Ban { until: None })).unwrap_err();
    let on_board = Target::Member { key: member.public(), board: Some("general".into()) };
    moderator.moderate(&moderator_key, revocation(on_board.clone(), Action::Ban { until: None })).unwrap();
    let refused = reader.submit(&member, "general", reply(1, "while banned"), false).unwrap_err();
    assert!(refused.to_string().contains("banned"), "{refused}");
    moderator.moderate(&moderator_key, revocation(on_board, Action::Restore)).unwrap();
    reader.submit(&member, "general", reply(1, "after the ban"), false).unwrap();

    // An ended appointment stops new entries; the old ones still count
    end_moderator(&site_dir, None, moderator_key.public()).unwrap();
    assert!(moderator.moderate(&moderator_key, revocation(post(5), Action::Hide)).is_err());
    let verified = reader.manifest().unwrap();
    let moderation = reader.moderation(&verified).unwrap();
    assert!(moderation.is_purged("general", 3));

    // The whole record is public: the client gets every entry, checked, with who made it
    assert_eq!(moderation.log.len(), 6);
    assert!(moderation.log.iter().all(|entry| entry.moderator == moderator_key.public()));
    assert_eq!(moderation.moderator_name(&moderator_key.public(), now()), Some("mod"));
    assert_eq!(moderation.log[5].verb(), "Lifted the ban on");

    // ...and so does anyone with a browser, at /moderation
    let page = ureq::get(&format!("{url}/moderation")).call().unwrap().into_string().unwrap();
    assert!(page.contains("6 entries, newest first"), "{page}");
    assert!(page.contains("Former moderators") && page.contains("None appointed."));
    assert!(page.contains("Hid <a href=\"/general/post/2\">post #2</a>"));
    assert!(page.contains("Purged post #3 on <a href=\"/general/\">/general/</a>"));
    assert!(page.contains(&format!("Banned for good member <code>{}</code> on", member.public().fingerprint())));
    assert!(page.contains("<td>spam</td>"));
    assert!(page.find("id=\"r5\"").unwrap() < page.find("id=\"r0\"").unwrap());
    let home = ureq::get(&format!("{url}/")).call().unwrap().into_string().unwrap();
    assert!(home.contains("<a href=\"/moderation\">Moderation log</a>"));
}
