//! Anathemic's formats, signatures and verification, shared by the server and clients.
//!
//! Everything that travels is CBOR. Anything signed travels as [`Signed`]: the exact bytes that
//! were signed, so verifying never depends on encoding a value the same way twice.

pub mod bencode;
pub mod cbor;
pub mod epoch;
pub mod i2p;
pub mod keys;
pub mod link;
pub mod markup;
pub mod model;
pub mod torrent;
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

/// `2026-11-02 14:03 UTC`
pub fn utc(time: u64) -> String {
    let days = (time / 86_400) as i64;
    let (hour, minute) = (time % 86_400 / 3600, time % 3600 / 60);
    // Howard Hinnant's days-to-civil
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_dates() {
        assert_eq!(super::utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::utc(1_793_621_000), "2026-11-02 12:03 UTC");
        assert_eq!(super::utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
