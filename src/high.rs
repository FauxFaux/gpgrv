use std::io;
use std::io::BufRead;
use std::io::Write;

use failure::err_msg;
use failure::Error;

use crate::keyring::Keyring;
use crate::packets;

/// Verify the data in a document
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
///     gpgrv::verify_message(BufReader::new(stdin()), &mut temp, keyring)
///         .expect("verification");
///     temp.seek(SeekFrom::Start(0)).unwrap();
///     std::io::copy(&mut temp, &mut stdout()).unwrap();
/// }
/// ```
pub fn verify_message<R: BufRead, W: Write>(
    from: R,
    to: W,
    keyring: &Keyring,
) -> Result<(), Error> {
    let doc = crate::load::read_doc(from, io::BufWriter::new(to))?;

    // TODO: test all signatures
    let sig = match doc.signatures.into_iter().next() {
        Some(s) => s,
        None => bail!("no signature in signature stream"),
    };

    match sig.sig_type {
        packets::SignatureType::CanonicalisedText => {}
        other => bail!("invalid signature type in armour: {:?}", other),
    };

    let body = doc
        .body
        .ok_or_else(|| err_msg("document wasn't a message (i.e. there was no body)"))?;

    crate::verify(keyring, &sig, body.digest)
}
