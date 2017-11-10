extern crate base64;
extern crate byteorder;
extern crate digest;

#[macro_use]
extern crate error_chain;

extern crate sha_1;
extern crate sha2;

mod armour;
mod errors;
mod packets;

pub use armour::parse_clearsign_armour;
pub use packets::parse_packet;
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

/// https://github.com/rust-lang/rust/issues/44290
fn usize_from(val: u16) -> usize {
    val as usize
}

fn usize_from_u32(val: u32) -> usize {
    assert!((val as u64) <= (std::usize::MAX as u64));
    val as usize
}
