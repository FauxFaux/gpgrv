extern crate gpgrv;

use std::io;

const HELLO_WORLD: &str = include_str!("hello-world.asc");
const EMPTY_SIG: &[u8] = include_bytes!("empty-message.inline-sig");
const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");

#[test]
fn split() {
    gpgrv::parse_clearsign_armour(
        io::Cursor::new(HELLO_WORLD.as_bytes()),
        io::Cursor::new(vec![]),
    ).unwrap();
}

#[test]
fn verify() {
    let mut keyring = gpgrv::Keyring::new();
    keyring.append_keys_from(io::Cursor::new(FAUX_KEY)).unwrap();
    gpgrv::verify_clearsign_armour(
        io::Cursor::new(HELLO_WORLD.as_bytes()),
        io::Cursor::new(vec![]),
        &keyring,
    ).unwrap();
}

#[test]
fn packets_sig() {
    use gpgrv::Packet::*;
    match gpgrv::parse_packet(io::Cursor::new(EMPTY_SIG)).unwrap() {
        Some(Signature(sig)) => assert!(sig.issuer.is_some()),
        _ => panic!("wrong type of/missing packet"),
    }
}

#[test]
fn packets_key() {
    use gpgrv::Packet::*;
    match gpgrv::parse_packet(io::Cursor::new(FAUX_KEY)).unwrap() {
        Some(PubKey(key)) => match key {
            _ => {
                assert_eq!("b195e1c4779ba9b2", key.identity_hex());
            }
        },
        _ => panic!("wrong type of/missing packet"),
    }
}
