use std::io;
use std::io::Read;

use errors::*;
use packets;

use PubKey;

pub struct Keyring {
    keys: Vec<PubKey>,
}

impl Keyring {
    pub fn new() -> Self {
        Keyring { keys: Vec::new() }
    }

    pub fn append_keys_from<R: Read>(&mut self, reader: R) -> Result<usize> {
        let mut reader = io::BufReader::new(reader);
        let mut read = 0;
        loop {
            match packets::parse_packet(&mut reader)? {
                Some(packets::Packet::PubKey(key)) => self.keys.push(key),
                None => break,
                other => bail!("unexpected packet in keyring: {:?}", other),
            }

            read += 1;
        }

        Ok(read)
    }

    pub fn as_slice(&self) -> &[PubKey] {
        &self.keys
    }
}
