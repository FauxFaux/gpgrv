extern crate gpgv;

use std::io;

const HELLO_WORLD: &str = include_str!("hello-world.asc");

#[test]
fn split() {
    gpgv::parse_clearsign_armour(io::Cursor::new(HELLO_WORLD.as_bytes())).unwrap();
}
