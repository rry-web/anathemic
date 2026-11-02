//! Bencoding, BitTorrent's format: enough for torrent files and tracker replies

use std::collections::BTreeMap;

use crate::{Error, invalid};

/// Nesting deeper than this is refused, so hostile input can't exhaust the stack
const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    /// Keys sorted, as bencoding requires
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(dict) => dict.get(key.as_bytes()),
            _ => None,
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn dict<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Value {
        Value::Dict(entries.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect())
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Value::Bytes(text.as_bytes().to_vec())
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(n) => out.extend(format!("i{n}e").as_bytes()),
        Value::Bytes(bytes) => {
            out.extend(format!("{}:", bytes.len()).as_bytes());
            out.extend(bytes);
        }
        Value::List(items) => {
            out.push(b'l');
            items.iter().for_each(|item| write(item, out));
            out.push(b'e');
        }
        Value::Dict(entries) => {
            out.push(b'd');
            for (key, value) in entries {
                write(&Value::Bytes(key.clone()), out);
                write(value, out);
            }
            out.push(b'e');
        }
    }
}

/// Decodes `data`, which must hold exactly one value
pub fn decode(data: &[u8]) -> Result<Value, Error> {
    let (value, end) = read(data, 0, 0)?;
    if end != data.len() {
        return Err(invalid("bencoded data has bytes after its end"));
    }
    Ok(value)
}

/// The bytes of the value under `key` in the dictionary that is `data`, exactly as written:
/// a torrent's info dictionary, whose hash names the torrent
pub fn raw_value<'a>(data: &'a [u8], key: &str) -> Result<Option<&'a [u8]>, Error> {
    if data.first() != Some(&b'd') {
        return Err(invalid("not a bencoded dictionary"));
    }
    let mut at = 1;
    while data.get(at) != Some(&b'e') {
        let (name, after_key) = read(data, at, 1)?;
        let (_, after_value) = read(data, after_key, 1)?;
        if name.bytes() == Some(key.as_bytes()) {
            return Ok(Some(&data[after_key..after_value]));
        }
        at = after_value;
    }
    Ok(None)
}

fn read(data: &[u8], at: usize, depth: usize) -> Result<(Value, usize), Error> {
    let truncated = || invalid("bencoded data ends early");
    if depth > MAX_DEPTH {
        return Err(invalid("bencoded data is nested too deeply"));
    }
    match *data.get(at).ok_or_else(truncated)? {
        b'i' => {
            let end = at + data[at..].iter().position(|&b| b == b'e').ok_or_else(truncated)?;
            let digits = std::str::from_utf8(&data[at + 1..end]).map_err(|_| invalid("bad bencoded number"))?;
            let canonical = !digits.starts_with("-0") && !(digits.starts_with('0') && digits.len() > 1);
            let n = digits.parse().ok().filter(|_| canonical).ok_or_else(|| invalid("bad bencoded number"))?;
            Ok((Value::Int(n), end + 1))
        }
        b'0'..=b'9' => {
            let colon = at + data[at..].iter().position(|&b| b == b':').ok_or_else(truncated)?;
            let len: usize = std::str::from_utf8(&data[at..colon])
                .ok()
                .and_then(|digits| digits.parse().ok())
                .ok_or_else(|| invalid("bad bencoded length"))?;
            let start = colon + 1;
            let end = start.checked_add(len).filter(|&end| end <= data.len()).ok_or_else(truncated)?;
            Ok((Value::Bytes(data[start..end].to_vec()), end))
        }
        b'l' => {
            let mut items = Vec::new();
            let mut at = at + 1;
            while *data.get(at).ok_or_else(truncated)? != b'e' {
                let (item, next) = read(data, at, depth + 1)?;
                items.push(item);
                at = next;
            }
            Ok((Value::List(items), at + 1))
        }
        b'd' => {
            let mut entries = BTreeMap::new();
            let mut at = at + 1;
            while *data.get(at).ok_or_else(truncated)? != b'e' {
                let (key, next) = read(data, at, depth + 1)?;
                let Value::Bytes(key) = key else { return Err(invalid("a bencoded key isn't a string")) };
                let (value, next) = read(data, next, depth + 1)?;
                entries.insert(key, value);
                at = next;
            }
            Ok((Value::Dict(entries), at + 1))
        }
        _ => Err(invalid("not bencoded data")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let value = Value::dict([
            ("peers", Value::Bytes(vec![0, 1, 2])),
            ("interval", Value::Int(1800)),
            ("list", Value::List(vec!["a".into(), Value::Int(-3)])),
        ]);
        let bytes = encode(&value);
        assert_eq!(bytes, b"d8:intervali1800e4:listl1:ai-3ee5:peers3:\x00\x01\x02e");
        assert_eq!(decode(&bytes).unwrap(), value);
        assert_eq!(raw_value(&bytes, "list").unwrap(), Some(&b"l1:ai-3ee"[..]));
        assert_eq!(raw_value(&bytes, "info").unwrap(), None);
    }

    #[test]
    fn bad_input_is_refused() {
        for bad in [&b"i01e"[..], b"i-0e", b"5:abc", b"l", b"d1:ai1e", b"i1ei2e", b"x", b"99999999999999999999:"] {
            assert!(decode(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(decode(&[b'l'; 100]).is_err());
    }
}
