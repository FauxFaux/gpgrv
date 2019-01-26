extern crate base64;
extern crate byteorder;
extern crate digest;

#[macro_use]
extern crate failure;
extern crate hex;
extern crate iowrap;
extern crate num;
extern crate sha1;
extern crate sha2;

mod armour;
mod digestable;
mod hash_multimap;
mod high;
mod keyring;
mod load;
mod mpi;
mod packets;
mod rsa;

use byteorder::ByteOrder;
use cast::u32;
use byteorder::BigEndian;
use failure::Error;

pub use crate::high::verify_message;
pub use crate::keyring::Keyring;
pub use crate::load::read_doc;
pub use crate::packets::parse_packet;
pub use crate::packets::parse_packets;
pub use crate::packets::Event;
pub use crate::packets::Packet;
pub use crate::packets::Signature;

#[derive(Clone, Debug)]
pub enum PublicKeySig {
    Rsa(Vec<u8>),
    Dsa { r: Vec<u8>, s: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PubKey {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ecdsa {
        oid: Vec<u8>,
        point: Vec<u8>,
    },
    Ed25519 {
        oid: Vec<u8>,
        point: Vec<u8>,
    },
    Elgaml {
        p: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
    Dsa {
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,

    Md5,
    RipeMd,
}

pub fn verify(key: &PubKey, sig: &Signature, mut digest: digestable::Digestable) -> Result<(), Error> {

    digest.process(&sig.authenticated_data);
    digest.process(&make_tail(sig.authenticated_data.len())?);

    let hash = digest.clone().hash();

    {
        let actual = BigEndian::read_u16(&hash);
        ensure!(
            actual == sig.hash_hint,
            "digest hint doesn't match; digest is probably wrong, exp: {:04x}, act: {:04x}",
            sig.hash_hint,
            actual,
        );
    }

    let padded = match sig.sig {
        PublicKeySig::Rsa(ref sig) => digest.emsa_pkcs1_v1_5(&hash, sig.len())?,
        _ => bail!("unsupported signature"),
    };

    match *key {
        PubKey::Rsa { ref n, ref e } => match sig.sig {
            PublicKeySig::Rsa(ref sig) => rsa::verify(sig, (n, e), &padded),
            _ => bail!("key/signature type mismatch"),
        },
        PubKey::Ecdsa { .. } => bail!("not implemented: verify ecdsa signatures"),
        PubKey::Ed25519 { .. } => bail!("not implemented: verify ed25519 signatures"),
        PubKey::Dsa { .. } => bail!("not implemented: verify dsa signatures"),
        PubKey::Elgaml { .. } => bail!("elgaml may not have signatures"),
    }
}

fn make_tail(len: usize) -> Result<[u8; 6], Error> {
    let mut tail = [0u8; 6];
    tail[0] = 0x04;
    tail[1] = 0xff;
    BigEndian::write_u32(&mut tail[2..], u32(len)?);
    Ok(tail)
}
