//! The read-only copy of a site each node serves over HTTP on its I2P address, at the same paths
//! as the server: the signed manifest it last read, sealed epochs, and the posts of epochs not
//! sealed yet. Clients fall back on mirrors when the server is down. They check everything
//! against signatures and hashes, so a mirror can at worst be out of date, not lie.
//!
//! It also draws the server's web pages, read-only, from its checked copy, so browsers such as
//! rynx can read the site at the mirror's address.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anathemic_client::{MANIFEST_FILE, read_cache};
use anathemic_core::{Manifest, PublicKey, Signed, cbor, torrent, valid_board_name};
use anathemic_server::{
    EpochState,
    snapshot::{Mirrored, Snapshot, SnapshotBoard},
    web,
};
use axum::{
    Router,
    extract::{Path as UrlPath, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

/// Serves the site's cache folder, and pages drawn from `pages`, on localhost; returns where
pub async fn serve(folder: PathBuf, pages: Arc<Mirrored>) -> anyhow::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = router(folder, pages);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(addr)
}

pub fn router(folder: PathBuf, pages: Arc<Mirrored>) -> Router {
    Router::new()
        .route("/manifest", get(manifest))
        .route("/boards/{board}/epochs/{number}", get(bundle))
        .route("/boards/{board}/epochs/{number}/posts", get(posts))
        .route("/boards/{board}/epochs/{number}/torrent", get(torrent_file))
        .with_state(Arc::new(folder))
        .merge(web::routes::<Mirrored>().with_state(pages))
}

/// The site as held in `home`'s cache, for the pages. `mirrors` go in their share link.
pub fn snapshot(home: &Path, root: &PublicKey, mirrors: Vec<String>) -> anyhow::Result<Snapshot> {
    let cached = read_cache(home, root)?;
    let manifest = &cached.site.manifest;
    let boards = manifest
        .boards
        .iter()
        .zip(cached.boards)
        .map(|(entry, held)| {
            let mut states: std::collections::HashMap<u64, EpochState> =
                entry.sealed.iter().map(|s| (s.epoch, EpochState::Sealed)).collect();
            let last = entry.unsealed.last().copied();
            states.extend(entry.unsealed.iter().map(|&n| (n, if Some(n) == last { EpochState::Open } else { EpochState::Settling })));
            SnapshotBoard { name: held.name, title: entry.title.clone(), authors: entry.authors, posts: held.posts, states }
        })
        .collect();
    Ok(Snapshot {
        root: manifest.root,
        name: manifest.name.clone(),
        description: manifest.description.clone(),
        addresses: manifest.addresses.clone(),
        published: manifest.published,
        boards,
        mirrors,
    })
}

fn file(path: &Path, content_type: &'static str) -> Response {
    match std::fs::read(path) {
        Ok(bytes) => ([(header::CONTENT_TYPE, content_type)], bytes).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn manifest(State(folder): State<Arc<PathBuf>>) -> Response {
    file(&folder.join(MANIFEST_FILE), "application/cbor")
}

async fn bundle(State(folder): State<Arc<PathBuf>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Response {
    if !valid_board_name(&board) {
        return StatusCode::NOT_FOUND.into_response();
    }
    file(&folder.join(torrent::file_name(&board, number)), "application/zstd")
}

async fn posts(State(folder): State<Arc<PathBuf>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Response {
    if !valid_board_name(&board) {
        return StatusCode::NOT_FOUND.into_response();
    }
    file(&folder.join(format!("{board}-{number}.posts")), "application/cbor")
}

/// The epoch's torrent, made from the bundle, announcing to the site's trackers as the
/// manifest names them
async fn torrent_file(State(folder): State<Arc<PathBuf>>, UrlPath((board, number)): UrlPath<(String, u64)>) -> Response {
    if !valid_board_name(&board) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(bundle) = std::fs::read(folder.join(torrent::file_name(&board, number))) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let addresses = std::fs::read(folder.join(MANIFEST_FILE))
        .ok()
        .and_then(|bytes| cbor::from_slice::<Signed<Manifest>>(&bytes).ok())
        .and_then(|signed| signed.peek().ok())
        .map(|manifest| manifest.addresses)
        .unwrap_or_default();
    let trackers: Vec<String> = addresses.iter().map(|address| format!("http://{address}/announce")).collect();
    let torrent = torrent::file(&torrent::info(&bundle, &board, number), &trackers);
    ([(header::CONTENT_TYPE, "application/x-bittorrent")], torrent).into_response()
}
