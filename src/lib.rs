extern crate base64;
extern crate byteorder;
extern crate digest;

#[macro_use]
extern crate error_chain;
extern crate hex;
extern crate iowrap;
extern crate num;
extern crate sha2;
extern crate sha_1;

mod armour;
mod digestable;
mod errors;
mod hash_multimap;
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum PubKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ecdsa { oid: Vec<u8>, point: Vec<u8> },
    Ed25519 { oid: Vec<u8>, point: Vec<u8> },
    Elgaml { p: Vec<u8>, g: Vec<u8>, y: Vec<u8> },
    Dsa {
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,

    Md5,
    RipeMd,
}

pub fn verify(key: &PubKey, sig: &PublicKeySig, padded_hash: &[u8]) -> Result<()> {
    match *key {
        PubKey::Rsa { ref n, ref e } => match *sig {
            PublicKeySig::Rsa(ref sig) => rsa::verify(sig, (n, e), padded_hash),
            _ => bail!("key/signature type mismatch"),
        },
        PubKey::Ecdsa { .. } => bail!("not implemented: verify ecdsa signatures"),
        PubKey::Ed25519 { .. } => bail!("not implemented: verify ed25519 signatures"),
        PubKey::Dsa { .. } => bail!("not implemented: verify dsa signatures"),
        PubKey::Elgaml { .. } => bail!("elgaml may not have signatures"),
    }
}

/// <https://github.com/rust-lang/rust/issues/44290>
fn usize_from(val: u16) -> usize {
    val as usize
}

fn usize_from_u32(val: u32) -> usize {
    assert!(u64::from(val) <= (std::usize::MAX as u64));
    val as usize
}

fn to_u32(val: usize) -> u32 {
    assert!((val as u64) <= u64::from(std::u32::MAX));
    val as u32
}
