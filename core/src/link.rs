//! Share links: everything someone needs to read or mirror a site, in one line to pass on.
//!
//! `anathemic:forum.i2p?root=<64 hex digits>&mirror=<52 characters>.b32.i2p&mirror=…`
//!
//! The root key is the site's identity, so whoever uses the link checks everything against it
//! from the first contact, instead of trusting whatever answers at the address. The mirrors let
//! them start even while the server is down.

use crate::{Error, PublicKey, invalid, valid_address};

pub const SCHEME: &str = "anathemic:";
/// More than this many mirrors in one link are left out
pub const MAX_LINK_MIRRORS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// Where the server answers: an I2P address, or `host:port` on this computer for testing
    pub address: String,
    pub root: PublicKey,
    /// Mirrors' addresses, in the same forms
    pub mirrors: Vec<String>,
}

/// An I2P address, or a local `host:port` (`127.0.0.1:8470`, `localhost:8470`) for testing
pub fn valid_host(host: &str) -> bool {
    if valid_address(host) {
        return true;
    }
    let Some((name, port)) = host.rsplit_once(':') else { return false };
    port.parse::<u16>().is_ok() && (name == "localhost" || name.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_loopback()))
}

impl Link {
    /// The address as a base URL
    pub fn base(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn parse(text: &str) -> Result<Link, Error> {
        let rest = text.trim().strip_prefix(SCHEME).ok_or_else(|| invalid("a share link starts with anathemic:"))?;
        let (address, query) = rest.split_once('?').ok_or_else(|| invalid("the link names no root key"))?;
        if !valid_host(address) {
            return Err(invalid(format!("{address:?} isn't an I2P address")));
        }
        let mut root = None;
        let mut mirrors = Vec::new();
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("root", hex)) => root = Some(PublicKey::from_hex(hex)?),
                Some(("mirror", host)) if valid_host(host) => {
                    if mirrors.len() < MAX_LINK_MIRRORS && !mirrors.iter().any(|m| m == host) {
                        mirrors.push(host.to_string());
                    }
                }
                Some(("mirror", host)) => return Err(invalid(format!("mirror {host:?} isn't an I2P address"))),
                _ => {}
            }
        }
        let root = root.ok_or_else(|| invalid("the link names no root key"))?;
        Ok(Link { address: address.to_string(), root, mirrors })
    }
}

impl std::fmt::Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{SCHEME}{}?root={}", self.address, self.root.to_hex())?;
        for mirror in self.mirrors.iter().take(MAX_LINK_MIRRORS) {
            write!(f, "&mirror={mirror}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    #[test]
    fn links_round_trip_and_refuse_strangers() {
        let root = SecretKey::generate().public();
        let mirror = format!("{}.b32.i2p", "a".repeat(52));
        let link = Link { address: "forum.i2p".into(), root, mirrors: vec![mirror.clone(), "127.0.0.1:9000".into()] };
        let text = link.to_string();
        assert_eq!(Link::parse(&text).unwrap(), link);
        assert_eq!(link.base(), "http://forum.i2p");

        assert!(Link::parse("anathemic:forum.i2p").is_err());
        assert!(Link::parse(&format!("anathemic:example.com?root={}", root.to_hex())).is_err());
        assert!(Link::parse(&format!("anathemic:10.0.0.1:80?root={}", root.to_hex())).is_err());
        assert!(Link::parse(&format!("anathemic:forum.i2p?root={}&mirror=evil.com", root.to_hex())).is_err());
        assert!(Link::parse("anathemic:forum.i2p?root=zz").is_err());
    }
}
