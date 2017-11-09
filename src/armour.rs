use std::collections::HashMap;
use std::io::BufRead;

use base64;

use digest::Digest;
use digest::FixedOutput;

use errors::*;
use Digests;

const BEGIN_SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const BEGIN_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";
const END_MESSAGE: &str = "-----END PGP SIGNATURE-----";

pub struct Signature {
    digest: Digests,
    headers: HashMap<String, String>,
    signature: Vec<u8>,
}

pub fn parse_clearsign_armour<R: BufRead>(from: R) -> Result<Signature> {
    let mut lines = from.lines();
    let first = lines.next().ok_or(
        "unexpected EOF looking for begin marker",
    )??;
    ensure!(
        first == BEGIN_SIGNED,
        "first line must be {}, not {:?}",
        first,
        BEGIN_SIGNED
    );

    let mut headers = HashMap::with_capacity(4);
    loop {
        let header = lines.next().ok_or("unexpected EOF reading headers")??;
        let header = header.trim();
        if header.is_empty() {
            break;
        }

        let (key, colon_value) = header.split_at(header.find(": ").ok_or_else(|| {
            format!("header {:?} must contain a colon space", header)
        })?);

        headers.insert(key.to_string(), colon_value[2..].to_string());
    }

    let mut sha1 = ::sha_1::Sha1::default();
    let mut sha256 = ::sha2::Sha256::default();
    let mut sha512 = ::sha2::Sha512::default();

    loop {
        let line = lines.next().ok_or("unexpected EOF looking for signature")??;

        if BEGIN_SIGNATURE == line {
            break;
        }

        let line = if line.starts_with('-') {
            ensure!(
                line.starts_with("- "),
                "incorrectly dash-escaped line: {:?}",
                line
            );
            &line[2..]
        } else {
            &line
        };

        push_line(sha1, line);
        push_line(sha256, line);
        push_line(sha512, line);
    }

    let line = lines.next().ok_or(
        "unexpected EOF reading 'headers' in signature",
    )??;

    ensure!(
        line.trim().is_empty(),
        "expecting a blank line at the start of a signature, not {:?}",
        line
    );

    let mut signature = String::with_capacity(1024);

    loop {
        let line = lines.next().ok_or("unexpected EOF reading signature")??;
        let line = line.trim();

        // checksum
        if line.len() == 5 && line.starts_with('=') {

            // TODO: Validate checksum? It's not part of the security model in any way.

            let line = lines.next().ok_or("unexpected EOF reading tail")??;

            ensure!(
                END_MESSAGE == line,
                "checksum must be immediately followed by end"
            );
            break;
        }

        if END_MESSAGE == line {
            break;
        }

        signature.push_str(line);
    }

    let signature = base64::decode(&signature)?;

    // Arrays, such sigh.
    let mut digest = Digests::default();
    digest.sha1.copy_from_slice(sha1.fixed_result().as_slice());
    digest.sha256.copy_from_slice(
        sha256.fixed_result().as_slice(),
    );
    digest.sha512.copy_from_slice(
        sha512.fixed_result().as_slice(),
    );

    Ok(Signature {
        digest,
        headers,
        signature,
    })
}

fn push_line<D: Digest>(mut digest: D, line: &str) {
    digest.process(line.as_bytes());
    digest.process(b"\r\n");
}
