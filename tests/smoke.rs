extern crate gpgv;

use std::io;

const HELLO_WORLD: &str = include_str!("hello-world.asc");
const EMPTY_SIG: &[u8] = include_bytes!("empty-message.inline-sig");

#[test]
fn split() {
    gpgv::parse_clearsign_armour(io::Cursor::new(HELLO_WORLD.as_bytes())).unwrap();
}

#[test]
fn packets() {
    gpgv::parse_packet(io::Cursor::new(EMPTY_SIG)).unwrap()
}
