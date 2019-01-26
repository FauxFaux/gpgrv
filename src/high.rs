use std::io;
use std::io::Write;

use buffered_reader::BufferedReader;
use failure::ensure;
use failure::err_msg;
use failure::format_err;
use failure::Error;

use crate::keyring::Keyring;

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
