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
        let mut reader = IoPos::new(io::BufReader::new(reader));
        let mut read = 0;
        let mut last = None;
        loop {
            match packets::parse_packet(&mut reader).chain_err(|| {
                format!("parsing after after {:?} at around {}", last, reader.count)
            })? {
                Some(packets::Packet::PubKey(key)) => {
                    last = Some(key.identity());
                    self.keys.push(key.math);
                }
                Some(packets::Packet::IgnoredJunk) => continue,
                Some(packets::Packet::Signature(_)) => continue,
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

struct IoPos<R: Read> {
    inner: R,
    count: u64,
}

impl<R: Read> Read for IoPos<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(count) => {
                self.count += count as u64;
                Ok(count)
            }
            Err(e) => Err(e),
        }
    }
}

impl<R: Read> IoPos<R> {
    fn new(inner: R) -> Self {
        IoPos { inner, count: 0 }
    }
}
