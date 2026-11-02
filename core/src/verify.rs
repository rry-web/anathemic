use crate::{Context, Error, Manifest, PublicKey, Signed, check_site_text, invalid, link::valid_host, valid_address, valid_board_name};

/// A manifest whose signatures check out, with the keys it vouches for
#[derive(Clone, Debug)]
pub struct Verified {
    pub manifest: Manifest,
    /// The server that published it
    pub site_key: PublicKey,
    /// The keys whose posts count: every host on the root key's list, or the site key alone
    pub keys: Vec<PublicKey>,
    /// The sequence of the host list it carries, 0 if none
    pub hosts_sequence: u64,
}

/// Checks the root key's certificate for the site key, then the site key's signature.
/// `pinned` is the root key a client saw first for this site, if any.
pub fn manifest(signed: &Signed<Manifest>, pinned: Option<&PublicKey>) -> Result<Verified, Error> {
    let claimed = signed.peek()?;
    if pinned.is_some_and(|root| *root != claimed.root) {
        return Err(invalid(format!(
            "this site's root key is {}, not the {} seen before",
            claimed.root.fingerprint(),
            pinned.unwrap().fingerprint()
        )));
    }
    let cert = claimed.site_cert.open(Context::SiteCert, Some(&claimed.root))?;
    let (keys, publishers, hosts_sequence) = match &claimed.hosts {
        Some(hosts) => {
            let hosts = hosts.open(Context::Hosts, Some(&claimed.root))?;
            if let Some(host) = hosts.hosts.iter().find(|host| !valid_host(&host.address)) {
                return Err(invalid(format!("host {:?} isn't an I2P address", host.address)));
            }
            let keys = hosts.hosts.iter().map(|host| host.key).collect();
            let publishers = hosts.hosts.iter().filter(|host| !host.retired).map(|host| host.key).collect();
            (keys, publishers, hosts.sequence)
        }
        None => (vec![cert.site_key], vec![cert.site_key], 0),
    };
    if !publishers.contains(&signed.signer) {
        return Err(Error::WrongSigner);
    }
    let manifest = signed.open(Context::Manifest, None)?;
    check_site_text(&manifest.name, &manifest.description)?;
    if let Some(address) = manifest.addresses.iter().find(|a| !valid_address(a)) {
        return Err(invalid(format!("{address:?} isn't an I2P address")));
    }
    for board in &manifest.boards {
        if !valid_board_name(&board.name) {
            return Err(invalid(format!("board name {:?} isn't allowed", board.name)));
        }
        let sealed_in_order = board.sealed.iter().enumerate().all(|(i, s)| s.epoch == i as u64);
        let next = board.sealed.len() as u64;
        let unsealed_follow = board.unsealed.iter().enumerate().all(|(i, &n)| n == next + i as u64);
        if !sealed_in_order || !unsealed_follow {
            return Err(invalid(format!("board {}'s epochs have gaps", board.name)));
        }
    }
    Ok(Verified { manifest, site_key: signed.signer, keys, hosts_sequence })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FORMAT, SecretKey, SiteCert};

    fn signed(root: &SecretKey, site: &SecretKey) -> Signed<Manifest> {
        let cert = root.sign(Context::SiteCert, &SiteCert { site_key: site.public(), issued: 0 });
        let manifest = Manifest {
            format: FORMAT,
            root: root.public(),
            site_cert: cert,
            sequence: 1,
            published: 0,
            name: String::new(),
            description: String::new(),
            addresses: vec![],
            boards: vec![],
            term: 0,
            hosts: None,
        };
        site.sign(Context::Manifest, &manifest)
    }

    #[test]
    fn manifests_need_a_certified_site_key_and_the_pinned_root() {
        let root = SecretKey::generate();
        let site = SecretKey::generate();
        let good = signed(&root, &site);
        assert_eq!(manifest(&good, Some(&root.public())).unwrap().site_key, site.public());

        let impostor = SecretKey::generate();
        assert!(manifest(&signed(&impostor, &site), Some(&root.public())).is_err());

        // A real certificate, but the manifest is signed by a key it doesn't name
        let mut stolen = good.peek().unwrap();
        stolen.sequence = 99;
        let resigned = impostor.sign(Context::Manifest, &stolen);
        assert!(manifest(&resigned, None).is_err());
    }

    #[test]
    fn addresses_must_be_i2p() {
        let root = SecretKey::generate();
        let site = SecretKey::generate();
        let mut fields = signed(&root, &site).peek().unwrap();
        fields.addresses = vec!["forum.i2p".into(), "example.com".into()];
        assert!(manifest(&site.sign(Context::Manifest, &fields), None).is_err());
        fields.addresses.pop();
        assert!(manifest(&site.sign(Context::Manifest, &fields), None).is_ok());
    }

    #[test]
    fn hosts_on_the_root_keys_list_can_publish() {
        use crate::{Host, Hosts};
        let root = SecretKey::generate();
        let site = SecretKey::generate();
        let standby = SecretKey::generate();
        let retired = SecretKey::generate();
        let host = |key: &SecretKey, rank, retired| Host {
            key: key.public(),
            rank,
            address: format!("{}.b32.i2p", "a".repeat(52)),
            name: String::new(),
            retired,
        };
        let hosts = Hosts { sequence: 2, issued: 0, hosts: vec![host(&site, 0, false), host(&standby, 1, false), host(&retired, 2, true)] };
        let mut fields = signed(&root, &site).peek().unwrap();
        fields.hosts = Some(root.sign(Context::Hosts, &hosts));
        fields.term = 1;

        let verified = manifest(&standby.sign(Context::Manifest, &fields), Some(&root.public())).unwrap();
        assert_eq!(verified.site_key, standby.public());
        assert_eq!((verified.keys.len(), verified.hosts_sequence), (3, 2));
        assert!(manifest(&retired.sign(Context::Manifest, &fields), None).is_err());
        assert!(manifest(&SecretKey::generate().sign(Context::Manifest, &fields), None).is_err());

        // A host list signed by anyone but the root key counts for nothing
        fields.hosts = Some(standby.sign(Context::Hosts, &hosts));
        assert!(manifest(&standby.sign(Context::Manifest, &fields), None).is_err());
    }
}
