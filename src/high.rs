use std::collections::HashSet;
use std::io;
use std::io::Read;
use std::io::Write;

use buffered_reader::BufferedReader;
use failure::bail;
use failure::ensure;
use failure::err_msg;
use failure::format_err;
use failure::Error;

use crate::keyring::Keyring;
use crate::packets::SignatureType;

/// Verify the data in a document
///
/// Note that some data may be written out before the signature is verified,
/// and you must not process this until the method has returned success.
///
/// # Example
///
/// ```rust,no_run
/// use std::io::{stdin, stdout, BufReader, Seek, SeekFrom};
/// use buffered_reader::BufferedReaderGeneric as BufReadGeneric;
///
/// fn check_stdin(keyring: &gpgrv::Keyring) {
///     let mut temp = tempfile::tempfile().unwrap();
///     gpgrv::verify_message(BufReadGeneric::new(stdin(), None), &mut temp, keyring)
///         .expect("verification");
///     temp.seek(SeekFrom::Start(0)).unwrap();
///     std::io::copy(&mut temp, &mut stdout()).unwrap();
/// }
/// ```
pub fn verify_message<R, B: BufferedReader<R>, W: Write>(
    from: B,
    to: W,
    keyring: &Keyring,
) -> Result<(), Error> {
    let doc = crate::read_doc(from, io::BufWriter::new(to))?;

    let body = doc
        .body
        .ok_or_else(|| err_msg("document wasn't a message (i.e. there was no body)"))?;

    let signatures_of_correct_type: Vec<_> = doc
        .signatures
        .into_iter()
        .filter(|sig| body.sig_type == sig.sig_type)
        .collect();

    ensure!(
        !signatures_of_correct_type.is_empty(),
        "no signatures are of the correct type"
    );

    crate::any_signature_valid(keyring, &signatures_of_correct_type, &body.digest)
        .map_err(|errors| format_err!("no valid signatures: {:?}", errors))
}

pub fn verify_detached<R, S: BufferedReader<R>, M: Read>(
    signature: S,
    mut message: M,
    keyring: &Keyring,
) -> Result<(), Error> {
    let doc = crate::read_doc(signature, iowrap::Ignore::new())?;
    if doc.body.is_some() {
        bail!("detached signature was a message");
    }

    let signatures = doc.signatures;

    let mut body_modes = HashSet::with_capacity(4);

    if signatures.is_empty() {
        bail!("no signatures in signature file")
    }

    for sig in &signatures {
        body_modes.insert((sig.sig_type, sig.hash_alg));
    }

    let (sig_type, hash_type) = *match body_modes.len() {
        0 => unreachable!(),
        1 => body_modes.iter().next().unwrap(),
        _ => bail!(
            "unsupported: signatures with multiple modes: {:?}",
            body_modes
        ),
    };

    match sig_type {
        SignatureType::Binary => (),
        other => bail!("unsupported: detached signature of type: {:?}", other),
    }

    let mut digest = crate::load::digestable_for(hash_type)
        .ok_or_else(|| format_err!("unsuported: hash type {:?}", hash_type))?;

    let mut buf = [0u8; 8 * 1024];

    loop {
        let read = message.read(&mut buf)?;
        if 0 == read {
            break;
        }
        let buf = &buf[..read];
        digest.process(buf);
    }

    crate::any_signature_valid(keyring, &signatures, &digest)
        .map_err(|errors| format_err!("no valid signatures: {:?}", errors))
}
