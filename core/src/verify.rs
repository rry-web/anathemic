use crate::{Context, Error, Manifest, PublicKey, Signed, invalid, valid_board_name};

/// A manifest whose signatures check out, with the site key it vouches for
#[derive(Clone, Debug)]
pub struct Verified {
    pub manifest: Manifest,
    pub site_key: PublicKey,
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
    let manifest = signed.open(Context::Manifest, Some(&cert.site_key))?;
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
    Ok(Verified { manifest, site_key: cert.site_key })
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
            boards: vec![],
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
}
