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
mod mpi;
mod packets;
mod rsa;

pub use armour::parse_clearsign_armour;
pub use packets::parse_packet;
pub use packets::Packet;
pub use errors::*;


/// https://github.com/rust-lang/rust/issues/44290
fn usize_from(val: u16) -> usize {
    val as usize
}

fn usize_from_u32(val: u32) -> usize {
    assert!((val as u64) <= (std::usize::MAX as u64));
    val as usize
}
