use std::collections::HashSet;
use std::fmt;
use std::io;
use std::io::BufRead;
use std::io::Read;

use failure::bail;
use failure::err_msg;
use failure::format_err;
use failure::Error;
use failure::ResultExt;
use iowrap;

use crate::armour;
use crate::hash_multimap::HashMultiMap;
use crate::packets;
use crate::short_string::ShortLine;
use crate::PubKey;

#[derive(Clone)]
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

    pub fn append_keys_from_armoured<R: BufRead>(&mut self, mut reader: R) -> Result<usize, Error> {
        let first_line = reader
            .read_short_line()
            .with_context(|_| err_msg("reading first line of key file"))?;

        let as_string = String::from_utf8(first_line)
            .with_context(|_| err_msg("non-textual data at start of key file"))?;

        if as_string.trim() != armour::BEGIN_PUBLIC_KEY {
            bail!("not a public key, invalid header: {:?}", as_string);
        }

        let key_data = armour::unarmour(reader, armour::END_PUBLIC_KEY)
            .with_context(|_| err_msg("unpacking key armour"))?;

        self.append_keys_from(io::Cursor::new(key_data))
    }

    pub fn append_keys_from<R: Read>(&mut self, reader: R) -> Result<usize, Error> {
        let mut reader = iowrap::Pos::new(io::BufReader::new(reader));
        let mut read = 0;
        let mut last = None;
        use packets::Event;
        use packets::Packet;

        packets::parse_packets(&mut reader, &mut |ev| match ev {
            Event::Packet(Packet::PubKey(key)) => {
                last = Some(key.identity_hex());
                let identity = key.identity().unwrap_or(0);
                self.keys.insert(key.math, identity);
                read += 1;
                Ok(())
            }
            Event::Packet(Packet::IgnoredJunk)
            | Event::Packet(Packet::Signature(_))
            | Event::Packet(Packet::OnePassHelper(_)) => Ok(()),
            Event::PlainData(_, _) => Err(err_msg("unsupported: message data in keyring")),
        })
        .with_context(|_| {
            format_err!(
                "parsing after after {:?} at around {}",
                last,
                reader.position()
            )
        })?;

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

    pub fn key_ids(&self) -> HashSet<&u64> {
        self.keys.values()
    }
}

impl Default for Keyring {
    fn default() -> Self {
        Keyring::new()
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keyring[")?;
        for &id in self.key_ids() {
            write!(f, "0x{:016},", id)?;
        }
        write!(f, "]")
    }
}
