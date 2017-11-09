extern crate base64;
extern crate digest;

#[macro_use]
extern crate error_chain;

extern crate sha_1;
extern crate sha2;

mod armour;
mod errors;

pub use armour::parse_clearsign_armour;
pub use errors::*;

#[derive(Copy, Clone)]
struct Digests {
    sha1: [u8; 20],
    sha256: [u8; 32],
    sha512: [u8; 64],
}

impl Default for Digests {
    fn default() -> Self {
        Digests {
            sha1: [0u8; 20],
            sha256: [0u8; 32],
            sha512: [0u8; 64],
        }
    }
}
