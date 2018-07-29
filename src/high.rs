use std::io;
use std::io::BufRead;
use std::io::Write;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use failure::Error;

use armour;
use keyring::Keyring;
use packets;
use to_u32;
use PublicKeySig;

/// Verify the data in a clearsigned armour stream
///
/// Note that some data may be written out before the signature is verified,
/// and you must not process this until the method has returned success.
///
/// # Example
///
/// ```rust,no_run
/// extern crate tempfile;
/// extern crate gpgrv;
/// use std::io::{stdin, stdout, BufReader, Seek, SeekFrom};
///
/// fn check_stdin(keyring: &gpgrv::Keyring) {
///     let mut temp = tempfile::tempfile().unwrap();
///     gpgrv::verify_clearsign_armour(BufReader::new(stdin()), &mut temp, keyring)
///         .expect("verification");
///     temp.seek(SeekFrom::Start(0)).unwrap();
///     std::io::copy(&mut temp, &mut stdout()).unwrap();
/// }
/// ```
pub fn verify_clearsign_armour<R: BufRead, W: Write>(
    from: R,
    to: W,
    keyring: &Keyring,
) -> Result<(), Error> {
    let mut armour_removed = armour::parse_clearsign_armour(from, io::BufWriter::new(to))?;
    let sig_packets = io::Cursor::new(armour_removed.signature);
    let sig = match packets::parse_packet(sig_packets)? {
        Some(packets::Packet::Signature(s)) => s,
        None => bail!("no signature in signature stream"),
        other => bail!("unexpected packet in signature: {:?}", other),
    };

    match sig.sig_type {
        packets::SignatureType::CanonicalisedText => {}
        other => bail!("invalid signature type in armour: {:?}", other),
    };

    let digest = &mut armour_removed.digest;
    digest.process(&sig.authenticated_data);
    digest.process(&make_tail(sig.authenticated_data.len()));

    let hash = digest.clone().hash();

    {
        let actual = BigEndian::read_u16(&hash);
        ensure!(
            actual == sig.hash_hint,
            "digest hint doesn't match; digest is probably wrong, exp: {:04x}, act: {:04x}",
            sig.hash_hint,
            actual,
        );
    }

    let padded = match sig.sig {
        PublicKeySig::Rsa(ref sig) => digest.emsa_pkcs1_v1_5(&hash, sig.len())?,
        _ => bail!("unsupported signature"),
    };

    for key in keyring.keys_with_id(BigEndian::read_u64(
        &sig.issuer.ok_or_else(|| format_err!("missing issuer"))?,
    )) {
        if ::verify(key, &sig.sig, &padded).is_ok() {
            return Ok(());
        }
    }

    bail!("no known keys could validate the signature")
}

fn make_tail(len: usize) -> [u8; 6] {
    let mut tail = [0u8; 6];
    tail[0] = 0x04;
    tail[1] = 0xff;
    BigEndian::write_u32(&mut tail[2..], to_u32(len));
    tail
}
