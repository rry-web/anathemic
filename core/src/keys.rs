use std::{fmt, marker::PhantomData};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{Error, cbor};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "serde_bytes")] pub [u8; 32]);

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let bytes = hex::decode(text.trim()).map_err(|_| Error::Decode("key isn't hex".into()))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Decode("key isn't 32 bytes".into()))?;
        Ok(Self(bytes))
    }

    /// A short form for people to compare by eye, like `3fa2-91c0-7d4e`
    pub fn fingerprint(&self) -> String {
        let hash = Sha256::digest(self.0);
        hash[..6].chunks(2).map(hex::encode).collect::<Vec<_>>().join("-")
    }

    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| Error::BadSignature)?;
        key.verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| Error::BadSignature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Decode("secret key isn't 32 bytes".into()))?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign<T: Serialize>(&self, context: Context, value: &T) -> Signed<T> {
        let body = cbor::to_vec(value);
        let signature = self.0.sign(&context.message(&body)).to_bytes();
        Signed { body, signer: self.public(), signature, kind: PhantomData }
    }
}

/// What a signature is for, so one made for a post can never pass as a manifest
#[derive(Clone, Copy, Debug)]
pub enum Context {
    SiteCert,
    Manifest,
    Submission,
    Post,
    /// The root key's list of the servers allowed to run a site
    Hosts,
    /// A request from one of a site's servers to another
    HostRequest,
    /// The root key's appointment of a moderator
    ModCert,
    /// A moderator's decision
    Revocation,
    /// A revocation as the site's writer logged it
    Logged,
}

impl Context {
    fn label(self) -> &'static [u8] {
        match self {
            Context::SiteCert => b"anathemic/1/site-cert",
            Context::Manifest => b"anathemic/1/manifest",
            Context::Submission => b"anathemic/1/submission",
            Context::Post => b"anathemic/1/post",
            Context::Hosts => b"anathemic/1/hosts",
            Context::HostRequest => b"anathemic/1/host-request",
            Context::ModCert => b"anathemic/1/mod-cert",
            Context::Revocation => b"anathemic/1/revocation",
            Context::Logged => b"anathemic/1/logged",
        }
    }

    fn message(self, body: &[u8]) -> Vec<u8> {
        let mut message = self.label().to_vec();
        message.push(0);
        message.extend_from_slice(body);
        message
    }
}

/// A value as the bytes that were signed, with the signer and signature
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Signed<T> {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub signer: PublicKey,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    #[serde(skip)]
    kind: PhantomData<fn() -> T>,
}

impl<T: DeserializeOwned> Signed<T> {
    /// Checks the signature, and the signer if one is expected, then decodes the value
    pub fn open(&self, context: Context, signer: Option<&PublicKey>) -> Result<T, Error> {
        if signer.is_some_and(|expected| *expected != self.signer) {
            return Err(Error::WrongSigner);
        }
        self.signer.verify(&context.message(&self.body), &self.signature)?;
        cbor::from_slice(&self.body)
    }

    /// Decodes the value without checking the signature, to learn which key should have signed it
    pub fn peek(&self) -> Result<T, Error> {
        cbor::from_slice(&self.body)
    }
}

impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            body: self.body.clone(),
            signer: self.signer,
            signature: self.signature,
            kind: PhantomData,
        }
    }
}

impl<T> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signed({} bytes by {})", self.body.len(), self.signer.fingerprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_values_open_only_with_their_context_and_signer() {
        let key = SecretKey::generate();
        let other = SecretKey::generate();
        let signed = key.sign(Context::Post, &"hello".to_string());

        assert_eq!(signed.open(Context::Post, Some(&key.public())).unwrap(), "hello");
        assert!(matches!(signed.open(Context::Manifest, None), Err(Error::BadSignature)));
        assert!(matches!(
            signed.open(Context::Post, Some(&other.public())),
            Err(Error::WrongSigner)
        ));

        let mut tampered = signed.clone();
        tampered.body = cbor::to_vec(&"goodbye".to_string());
        assert!(matches!(tampered.open(Context::Post, None), Err(Error::BadSignature)));
    }

    #[test]
    fn signed_values_survive_encoding() {
        let key = SecretKey::generate();
        let signed = key.sign(Context::Submission, &vec![1u32, 2, 3]);
        let decoded: Signed<Vec<u32>> = cbor::from_slice(&cbor::to_vec(&signed)).unwrap();
        assert_eq!(decoded.open(Context::Submission, None).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn keys_round_trip() {
        let key = SecretKey::generate();
        let again = SecretKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(again.public(), key.public());
        assert_eq!(PublicKey::from_hex(&key.public().to_hex()).unwrap(), key.public());
        assert_eq!(key.public().fingerprint().len(), 14);
    }
}
