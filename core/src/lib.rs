//! Anathemic's formats, signatures and verification, shared by the server and clients.
//!
//! Everything that travels is CBOR. Anything signed travels as [`Signed`]: the exact bytes that
//! were signed, so verifying never depends on encoding a value the same way twice.

pub mod cbor;
pub mod epoch;
pub mod keys;
pub mod model;
pub mod verify;

pub use keys::{Context, PublicKey, SecretKey, Signed};
pub use model::*;
pub use serde;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can't decode: {0}")]
    Decode(String),
    #[error("bad signature")]
    BadSignature,
    #[error("signed by the wrong key")]
    WrongSigner,
    #[error("{0}")]
    Invalid(String),
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

/// Seconds since the Unix epoch
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
