//! A site held in memory, for a mirror to draw the web pages from: built from a copy whose
//! signatures were checked, and swapped for a newer one whenever the mirror reads the site again.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anathemic_core::{Authors, Post, PublicKey, Time, moderation::Moderation};

use crate::{BoardSummary, EpochState, Fail, ThreadSummary, web::Source};

pub struct Snapshot {
    pub root: PublicKey,
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
    /// When the manifest this copy follows was published
    pub published: Time,
    pub boards: Vec<SnapshotBoard>,
    /// Mirrors' addresses for the share link, this one first
    pub mirrors: Vec<String>,
    pub moderation: Arc<Moderation>,
}

pub struct SnapshotBoard {
    pub name: String,
    pub title: String,
    pub authors: Authors,
    /// Oldest first
    pub posts: Vec<Post>,
    pub states: HashMap<u64, EpochState>,
}

impl Snapshot {
    fn find(&self, board: &str) -> Result<&SnapshotBoard, Fail> {
        self.boards.iter().find(|b| b.name == board).ok_or(Fail::NotFound)
    }
}

/// A snapshot that can be replaced while pages are being drawn from it
pub struct Mirrored(RwLock<Arc<Snapshot>>);

impl Mirrored {
    pub fn new(snapshot: Snapshot) -> Self {
        Mirrored(RwLock::new(Arc::new(snapshot)))
    }

    pub fn replace(&self, snapshot: Snapshot) {
        *self.0.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(snapshot);
    }

    fn current(&self) -> Arc<Snapshot> {
        self.0.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }
}

impl Source for Mirrored {
    fn root(&self) -> PublicKey {
        self.current().root
    }

    fn about(&self) -> Result<(String, String, Vec<String>), Fail> {
        let site = self.current();
        Ok((site.name.clone(), site.description.clone(), site.addresses.clone()))
    }

    fn boards(&self) -> Result<Vec<BoardSummary>, Fail> {
        Ok(self
            .current()
            .boards
            .iter()
            .map(|board| BoardSummary {
                name: board.name.clone(),
                title: board.title.clone(),
                authors: board.authors,
                threads: board.posts.iter().filter(|p| p.content.thread.is_none()).count() as u64,
                posts: board.posts.len() as u64,
                last: board.posts.last().map(|p| p.accepted),
            })
            .collect())
    }

    fn board(&self, board: &str) -> Result<(String, Authors, bool), Fail> {
        let site = self.current();
        let board = site.find(board)?;
        Ok((board.title.clone(), board.authors, false))
    }

    fn threads(&self, board: &str, skip: u64, take: u64) -> Result<(Vec<ThreadSummary>, u64), Fail> {
        let site = self.current();
        let board = site.find(board)?;
        // Each thread's reply count and newest post
        let mut replies: HashMap<u64, (u64, &Post)> = HashMap::new();
        for post in &board.posts {
            if let Some(thread) = post.content.thread {
                let entry = replies.entry(thread).or_insert((0, post));
                entry.0 += 1;
                entry.1 = post;
            }
        }
        let mut threads: Vec<(&Post, u64, &Post)> = board
            .posts
            .iter()
            .filter(|p| p.content.thread.is_none())
            .map(|start| {
                let (count, last) = replies.get(&start.number).copied().unwrap_or((0, start));
                (start, count, last)
            })
            .collect();
        threads.sort_by_key(|(_, _, last)| std::cmp::Reverse(last.number));
        let total = threads.len() as u64;
        let page = threads
            .into_iter()
            .skip(skip as usize)
            .take(take as usize)
            .map(|(start, replies, last)| ThreadSummary { start: start.clone(), replies, last: last.accepted })
            .collect();
        Ok((page, total))
    }

    fn thread(&self, board: &str, number: u64) -> Result<Vec<Post>, Fail> {
        let site = self.current();
        let posts: Vec<Post> = site
            .find(board)?
            .posts
            .iter()
            .filter(|p| (p.number == number && p.content.thread.is_none()) || p.content.thread == Some(number))
            .cloned()
            .collect();
        if posts.is_empty() { Err(Fail::NotFound) } else { Ok(posts) }
    }

    fn thread_of(&self, board: &str, number: u64) -> Result<u64, Fail> {
        let site = self.current();
        let post = site.find(board)?.posts.iter().find(|p| p.number == number).ok_or(Fail::NotFound)?;
        Ok(post.content.thread.unwrap_or(post.number))
    }

    fn epoch_states(&self, board: &str) -> Result<HashMap<u64, EpochState>, Fail> {
        Ok(self.current().find(board)?.states.clone())
    }

    fn mirrored(&self) -> Option<Time> {
        Some(self.current().published)
    }

    fn mirrors(&self) -> Vec<String> {
        self.current().mirrors.clone()
    }

    fn moderation(&self) -> Result<Arc<Moderation>, Fail> {
        Ok(self.current().moderation.clone())
    }
}
