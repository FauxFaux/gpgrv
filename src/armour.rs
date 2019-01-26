use std::collections::HashMap;
use std::io::BufRead;
use std::io::Lines;
use std::io::Write;

use base64;
use failure::bail;
use failure::ensure;
use failure::format_err;
use failure::Error;

use crate::digestable::Digestable;
use crate::packets::SignatureType;

pub const BEGIN_SIGNED_MESSAGE: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
pub const BEGIN_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";
const END_MESSAGE: &str = "-----END PGP SIGNATURE-----";

pub struct Message {
    pub digest: Digestable,
    pub sig_type: SignatureType,
    pub block: Vec<u8>,
}

pub fn parse_armoured_signed_message<R: BufRead, W: Write>(
    mut lines: Lines<R>,
    mut to: W,
) -> Result<Message, Error> {
    let body_headers = take_headers(&mut lines)?;

    let mut digest = match body_headers.get("Hash").map(|x| x.as_str()) {
        Some("SHA1") => Digestable::sha1(),
        Some("SHA256") => Digestable::sha256(),
        Some("SHA512") => Digestable::sha512(),
        Some(other) => bail!("unsupported Hash header: {:?}", other),
        None => bail!("'Hash' header is mandatory"),
    };

    let sig_type = SignatureType::CanonicalisedText;
    let mut first = true;

    loop {
        let line = lines
            .next()
            .ok_or_else(|| format_err!("unexpected EOF looking for signature"))??;

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
            to.write_all(b"\n")?;
            digest.process(b"\r\n");
        }
        first = false;

        to.write_all(line.as_bytes())?;
        digest.process(line.as_bytes());
    }

    let block = parse_armoured_signature_body(lines)?;

    Ok(Message {
        digest,
        sig_type,
        block,
    })
}

pub fn parse_armoured_signature_body<R: BufRead>(mut lines: Lines<R>) -> Result<Vec<u8>, Error> {
    let _sig_headers = take_headers(&mut lines)?;

    let mut signature = String::with_capacity(1024);

    loop {
        let line = lines
            .next()
            .ok_or_else(|| format_err!("unexpected EOF reading signature"))??;
        let line = line.trim();

        // checksum
        if line.len() == 5 && line.starts_with('=') {
            // TODO: Validate checksum? It's not part of the security model in any way.

            let line = lines
                .next()
                .ok_or_else(|| format_err!("unexpected EOF reading tail"))??;

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

    Ok(base64::decode(&signature)?)
}

fn take_headers<R: BufRead>(lines: &mut Lines<R>) -> Result<HashMap<String, String>, Error> {
    let mut headers = HashMap::new();
    loop {
        let header = lines
            .next()
            .ok_or_else(|| format_err!("unexpected EOF reading headers"))??;
        let header = header.trim();
        if header.is_empty() {
            break;
        }

        let (key, colon_value) = header.split_at(
            header
                .find(": ")
                .ok_or_else(|| format_err!("header {:?} must contain a colon space", header))?,
        );

        headers.insert(key.to_string(), colon_value[2..].to_string());
    }

    Ok(headers)
}
