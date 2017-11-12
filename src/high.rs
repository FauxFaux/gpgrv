use std::io;
use std::io::BufRead;

use byteorder::ByteOrder;
use byteorder::BigEndian;

use armour;
use packets;
use keyring::Keyring;

use errors::*;

use PublicKeySig;
use to_u32;

pub fn verify_clearsign_armour<R: BufRead>(from: R, keyring: &Keyring) -> Result<()> {
    let mut armour_removed = armour::parse_clearsign_armour(from)?;
    let sig_packets = io::Cursor::new(armour_removed.signature);
    let sig = match packets::parse_packet(sig_packets)? {
        Some(packets::Packet::Signature(s)) => s,
        None => bail!("no signature in signature stream"),
        other => bail!("unexpected packet in signature: {:?}", other),
    };

    match sig.sig_type {
        packets::SignatureType::CanonicalisedText => {},
        other => bail!("invalid signature type in armour: {:?}", other),
    };

    let digest = &mut armour_removed.digest;
    digest.process(&sig.authenticated_data);
    digest.process(&make_tail(sig.authenticated_data.len()));

    let hash = digest.hash();

    ensure!(
        BigEndian::read_u16(&hash) == sig.hash_hint,
        "digest hint doesn't match; digest is probably wrong"
    );

    let padded = match sig.sig {
        PublicKeySig::Rsa(ref sig) => digest.emsa_pkcs1_v1_5(&hash, sig.len())?,
        _ => bail!("unsupported signature"),
    };


    for key in keyring.as_slice() {
        if ::verify(key, &sig.sig, &padded).is_ok() {
            return Ok(())
        }
    }

    bail!("no known keys could validate the signature");
}

fn make_tail(len: usize) -> [u8; 6] {
    let mut tail = [0u8; 6];
    tail[0] = 0x04;
    tail[1] = 0xff;
    BigEndian::write_u32(&mut tail[2..], to_u32(len));
    tail
}
