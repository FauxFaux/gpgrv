use std::io;
use std::io::Read;

use failure::Error;
use failure::ResultExt;
use iowrap;

use hash_multimap::HashMultiMap;
use packets;
use PubKey;

pub struct Keyring {
    /// Allows a (mathematical) key to have multiple ids.
    /// This is the exact opposite to what all the users want, but is
    /// the canonical way to store this data; we're deduplicating the
    /// mathematical keys, and keeping all the ids around.
    keys: HashMultiMap<PubKey, u64>,
}

impl Keyring {
    pub fn new() -> Self {
        Keyring {
            keys: HashMultiMap::new(),
        }
    }

    pub fn append_keys_from<R: Read>(&mut self, reader: R) -> Result<usize, Error> {
        let mut reader = iowrap::Pos::new(io::BufReader::new(reader));
        let mut read = 0;
        let mut last = None;
        loop {
            match packets::parse_packet(&mut reader).with_context(|_| {
                format_err!(
                    "parsing after after {:?} at around {}",
                    last,
                    reader.position()
                )
            })? {
                Some(packets::Packet::PubKey(key)) => {
                    last = Some(key.identity_hex());
                    let identity = key.identity().unwrap_or(0);
                    self.keys.insert(key.math, identity);
                }
                Some(packets::Packet::IgnoredJunk) | Some(packets::Packet::Signature(_)) => {
                    continue
                }
                None => break,
            }

            read += 1;
        }

        Ok(read)
    }

    pub fn keys_with_id(&self, id: u64) -> Vec<&PubKey> {
        let mut ret = Vec::new();
        for (key, key_id) in self.keys.entries() {
            if id == *key_id {
                ret.push(key);
            }
        }

        ret
    }
}

impl Default for Keyring {
    fn default() -> Self {
        Keyring::new()
    }
}
