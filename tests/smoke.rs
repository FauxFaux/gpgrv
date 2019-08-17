extern crate gpgrv;

use std::io;

const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");
const FAUX_KEY_AA: &[u8] = include_bytes!("faux_pub.asc");
const HELLO_WORLD: &str = include_str!("smoke/hello-world.asc");
const REAL_WORLD_DIZZIEST: &[u8] = include_bytes!("smoke/real-world-dizziest.gpg");

#[test]
fn split() {
    gpgrv::read_doc(
        io::Cursor::new(HELLO_WORLD.as_bytes()),
        io::Cursor::new(vec![]),
    )
    .unwrap();
}

#[test]
fn verify() {
    let mut keyring = gpgrv::Keyring::new();
    keyring.append_keys_from(io::Cursor::new(FAUX_KEY)).unwrap();
    gpgrv::verify_message(
        io::Cursor::new(HELLO_WORLD.as_bytes()),
        io::Cursor::new(vec![]),
        &keyring,
    )
    .unwrap();
}

#[test]
fn verify_with_armoured_pubkey() {
    let mut keyring = gpgrv::Keyring::new();
    keyring
        .append_keys_from_armoured(io::Cursor::new(FAUX_KEY_AA))
        .unwrap();
    gpgrv::verify_message(
        io::Cursor::new(HELLO_WORLD.as_bytes()),
        io::Cursor::new(vec![]),
        &keyring,
    )
    .unwrap();
}

#[test]
fn real_world_dizziest() {
    let mut keyring = gpgrv::Keyring::new();
    keyring
        .append_keys_from(io::Cursor::new(REAL_WORLD_DIZZIEST))
        .unwrap();
}
