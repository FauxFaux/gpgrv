mod armour;
mod digestable;
mod hash_multimap;
mod high;
mod keyring;
mod load;
mod mpi;
mod packets;
mod rsa;
mod verify;

pub use crate::digestable::Digestable;
pub use crate::high::verify_detached;
pub use crate::high::verify_message;
pub use crate::keyring::Keyring;
pub use crate::load::read_doc;
pub use crate::verify::any_signature_valid;
pub use crate::verify::is_any_signature_valid;


// Testing.
pub use crate::packets::parse_packets;
pub use crate::packets::Event;
pub use crate::packets::Packet;
pub use crate::packets::Signature;
//pub use crate::packets::parse_packet;
//pub use crate::verify::single_signature_valid;

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
