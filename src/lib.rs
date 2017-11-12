extern crate base64;
extern crate byteorder;
extern crate digest;

#[macro_use]
extern crate error_chain;
extern crate hex;
extern crate gmp;
extern crate sha_1;
extern crate sha2;

mod armour;
mod digestable;
mod errors;
mod high;
mod keyring;
mod mpi;
mod packets;
mod rsa;

pub use armour::parse_clearsign_armour;
pub use high::verify_clearsign_armour;
pub use keyring::Keyring;
pub use packets::parse_packet;
pub use packets::Packet;
pub use errors::*;

#[derive(Debug)]
pub enum PublicKeySig {
    Rsa(Vec<u8>),
    Dsa { r: Vec<u8>, s: Vec<u8> },
}

#[derive(Debug)]
pub enum PubKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

pub fn verify(key: &PubKey, sig: &PublicKeySig, padded_hash: &[u8]) -> Result<()> {
    match key {
        &PubKey::Rsa { ref n, ref e } => {
            match sig {
                &PublicKeySig::Rsa(ref sig) => rsa::verify(sig, (n, e), padded_hash),
                _ => bail!("key/signature type mismatch"),
            }
        }
    }
}

/// https://github.com/rust-lang/rust/issues/44290
fn usize_from(val: u16) -> usize {
    val as usize
}

fn usize_from_u32(val: u32) -> usize {
    assert!((val as u64) <= (std::usize::MAX as u64));
    val as usize
}

fn to_u32(val: usize) -> u32 {
    assert!((val as u64) <= (std::u32::MAX as u64));
    val as u32
}
