use std::collections::HashMap;
use std::io::BufRead;
use std::io::Lines;

use base64;

use digestable::Digestable;
use errors::*;

const BEGIN_SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const BEGIN_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";
const END_MESSAGE: &str = "-----END PGP SIGNATURE-----";

pub struct Signature {
    pub digest: Digestable,
    pub body_headers: HashMap<String, String>,
    pub sig_headers: HashMap<String, String>,
    pub signature: Vec<u8>,
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

    let body_headers = take_headers(&mut lines)?;

    let mut digest = match body_headers.get("Hash").map(|x| x.as_str()) {
        Some("SHA1") => Digestable::Sha1(::sha_1::Sha1::default()),
        Some("SHA256") => Digestable::Sha256(::sha2::Sha256::default()),
        Some("SHA512") => Digestable::Sha512(::sha2::Sha512::default()),
        Some(other) => bail!("unsupported Hash header: {:?}", other),
        None => bail!("'Hash' header is mandatory"),
    };

    let mut first = true;

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

        // we don't want a trailing newline, apparently,
        // even though it's always there in the message
        if !first {
            digest.process(b"\r\n");
        }
        first = false;

        digest.process(line.as_bytes());
    }

    let sig_headers = take_headers(&mut lines)?;

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

    Ok(Signature {
        digest,
        body_headers,
        sig_headers,
        signature,
    })
}

fn take_headers<R: BufRead>(lines: &mut Lines<R>) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
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

    Ok(headers)
}
