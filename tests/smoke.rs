extern crate gpgv;

use std::io;

const HELLO_WORLD: &str = include_str!("hello-world.asc");
const EMPTY_SIG: &[u8] = include_bytes!("empty-message.inline-sig");
const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");

#[test]
fn split() {
    gpgv::parse_clearsign_armour(io::Cursor::new(HELLO_WORLD.as_bytes())).unwrap();
}

#[test]
fn verify() {
    gpgv::verify_clearsign_armour(io::Cursor::new(HELLO_WORLD.as_bytes())).unwrap();
}

#[test]
fn packets_sig() {
    use gpgv::Packet::*;
    match gpgv::parse_packet(io::Cursor::new(EMPTY_SIG)).unwrap() {
        Signature(sig) => assert!(sig.issuer.is_some()),
        _ => panic!("wrong type of packet"),
    }
}

#[test]
fn packets_key() {
    use gpgv::Packet::*;
    match gpgv::parse_packet(io::Cursor::new(FAUX_KEY)).unwrap() {
        PubKey(key) => {
            match key {
                _ => {}
            }
        }
        _ => panic!("wrong type of packet"),
    }
}
