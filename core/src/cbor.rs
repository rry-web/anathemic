use serde::{Serialize, de::DeserializeOwned};

use crate::Error;

pub fn to_vec<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing CBOR to a Vec can't fail");
    out
}

pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
}
