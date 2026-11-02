//! I2P destinations and addresses: a destination is written in I2P's base64 (with `-` and `~`
//! for `+` and `/`), and its `.b32.i2p` address is the base32 of its SHA-256, which is also
//! the 32 bytes an I2P tracker's compact reply gives for each peer.

use sha2::{Digest, Sha256};

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Real destinations are 387 bytes or a little more, with certificates
const MAX_DESTINATION: usize = 1024;

/// A destination's bytes, from I2P's base64 (as the `X-I2P-DestB64` header gives it)
pub fn decode_destination(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() < 387 * 4 / 3 || text.len() > MAX_DESTINATION * 4 / 3 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0;
    for c in text.bytes() {
        let value = BASE64.iter().position(|&b| b == c)? as u32;
        bits = bits << 6 | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// The hash naming a destination. `destination` may run on into private keys, as a saved
/// key does; only the destination itself (387 bytes and its certificate's payload) counts.
pub fn destination_hash(destination: &[u8]) -> [u8; 32] {
    let certificate = destination.get(385..387).map_or(0, |len| u16::from_be_bytes([len[0], len[1]]) as usize);
    let end = (387 + certificate).min(destination.len());
    Sha256::digest(&destination[..end]).into()
}

/// `<52 characters>.b32.i2p` for a destination's hash
pub fn b32_address(hash: &[u8; 32]) -> String {
    let mut out = String::with_capacity(60);
    let mut bits = 0u32;
    let mut count = 0;
    for &byte in hash {
        bits = bits << 8 | byte as u32;
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(BASE32[(bits >> count & 31) as usize] as char);
        }
    }
    if count > 0 {
        out.push(BASE32[(bits << (5 - count) & 31) as usize] as char);
    }
    out + ".b32.i2p"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_from_destinations() {
        // An all-zero hash and the start of the base32 alphabet
        assert_eq!(b32_address(&[0; 32]), format!("{}.b32.i2p", "a".repeat(52)));
        let mut hash = [0u8; 32];
        hash[0] = 0b0000_1000;
        assert!(b32_address(&hash).starts_with("baaa"));

        // 387 bytes of 0xff, then two zero bytes: I2P's base64 uses ~ for 63
        let destination: Vec<u8> = [vec![0xff; 387], vec![0, 0]].concat();
        let text = format!("{}{}", "~".repeat(516), "AAA");
        assert_eq!(decode_destination(&text).unwrap(), destination);
        assert!(decode_destination("short").is_none());

        // A saved key: the destination (with a 4-byte certificate), then private keys
        let mut destination = vec![7u8; 384];
        destination.extend([5, 0, 4, 0, 7, 0, 0]);
        let key = [destination.clone(), vec![9; 300]].concat();
        assert_eq!(destination_hash(&key), destination_hash(&destination));
        assert_eq!(destination_hash(&destination), <[u8; 32]>::from(Sha256::digest(&destination)));
        assert!(decode_destination(&format!("{}+", "A".repeat(520))).is_none());
    }
}
