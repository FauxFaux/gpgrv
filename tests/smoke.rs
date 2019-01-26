extern crate gpgrv;

use std::io;
use std::io::Read;

use failure::Error;
use gpgrv::Event;
use gpgrv::Packet;

const EMPTY_SIG: &[u8] = include_bytes!("smoke/empty-message.inline-sig");
const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");
const HELLO_WORLD: &str = include_str!("smoke/hello-world.asc");
const REAL_WORLD_DIZZIEST: &[u8] = include_bytes!("smoke/real-world-dizziest.gpg");

#[test]
fn split() {
    gpgrv::read_doc(
        buffered_reader::BufferedReaderMemory::new(HELLO_WORLD.as_bytes()),
        io::Cursor::new(vec![]),
    )
    .unwrap();
}

#[test]
fn verify() {
    let mut keyring = gpgrv::Keyring::new();
    keyring
        .append_keys_from(buffered_reader::BufferedReaderMemory::new(FAUX_KEY))
        .unwrap();
    gpgrv::verify_message(
        buffered_reader::BufferedReaderMemory::new(HELLO_WORLD.as_bytes()),
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

#[test]
fn packets_sig() -> Result<(), Error> {
    use gpgrv::Packet::*;
    match parse_to_list(io::Cursor::new(EMPTY_SIG))?
        .into_iter()
        .next()
    {
        Some(Signature(sig)) => assert!(sig.issuer.is_some()),
        _ => panic!("wrong type of/missing packet"),
    }
    Ok(())
}

#[test]
fn packets_key() -> Result<(), Error> {
    use gpgrv::Packet::*;
    match parse_to_list(io::Cursor::new(FAUX_KEY))?.into_iter().next() {
        Some(PubKey(key)) => match key {
            _ => {
                assert_eq!("b195e1c4779ba9b2", key.identity_hex());
            }
        },
        _ => panic!("wrong type of/missing packet"),
    }
    Ok(())
}

fn parse_to_list<R: Read>(from: R) -> Result<Vec<Packet>, Error> {
    let mut ret = Vec::new();
    gpgrv::parse_packets(from, &mut |ev| {
        match ev {
            Event::Packet(p) => ret.push(p),
            Event::PlainData(_, _) => panic!("data"),
        }
        Ok(())
    })?;
    Ok(ret)
}
