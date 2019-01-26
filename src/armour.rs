use std::collections::HashMap;
use std::io::BufRead;
use std::io::Write;

use base64;
use failure::bail;
use failure::ensure;
use failure::err_msg;
use failure::format_err;
use failure::Error;
use failure::ResultExt;

use crate::digestable::Digestable;
use crate::load::ShortLine;
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
    mut from: R,
    mut to: W,
) -> Result<Message, Error> {
    let body_headers = take_headers(&mut from)?;

    let mut digest = match body_headers.get("Hash").map(|x| x.as_str()) {
        Some("SHA1") => Digestable::sha1(),
        Some("SHA256") => Digestable::sha256(),
        Some("SHA512") => Digestable::sha512(),
        Some(other) => bail!("unsupported Hash header: {:?}", other),
        None => bail!("'Hash' header is mandatory"),
    };

    let sig_type = SignatureType::CanonicalisedText;

    loop {
        let buf = from.fill_buf()?;
        if buf.is_empty() {
            bail!("unexpected EOF in message body");
        }

        match memchr::memchr(b'\n', buf) {
            Some(0) => (),
            Some(newline) => {
                to.write_all(&buf[..newline])?;
                digest.process(&buf[..newline]);
                from.consume(newline);
                continue;
            }
            None => {
                to.write_all(buf)?;
                digest.process(buf);
                let valid = buf.len();
                from.consume(valid);
                continue;
            }
        }

        // has at least "\n-"
        let buf = from.fill_buf()?;
        assert!(buf.len() >= 2);
        assert_eq!(b'\n', buf[0]);

        if buf[1] != b'-' {
            // if there's no dash, no special processing is necessary
            // drop the newline and continue
            from.consume("\n".len());
            to.write_all(b"\n")?;
            digest.process(b"\r\n");
            continue;
        }

        // has at least "\n--" or "\n- "
        let buf = from.fill_buf()?;

        assert!(buf.len() >= 3);
        assert_eq!(b'\n', buf[0]);
        assert_eq!(b'-', buf[1]);

        match buf[2] {
            b'-' => {
                to.write_all(b"\n")?;
                // the trailing newline is not part of the message for digest purposes
                from.consume("\n".len());
                break;
            }

            b' ' => {
                // the escape marker is not included, but the newline is
                to.write_all(b"\n")?;
                digest.process(b"\r\n");
                from.consume("\n- ".len());
            }

            other => bail!(
                "invalid line escaping: {:?} near {:?}",
                other,
                String::from_utf8_lossy(buf)
            ),
        }
    }

    let escaped_line = String::from_utf8(from.read_short_line()?)?;

    ensure!(
        escaped_line == BEGIN_SIGNATURE,
        "invalid escaped line, should be a signature start: {:?}",
        escaped_line
    );

    let block = parse_armoured_signature_body(from)
        .with_context(|_| err_msg("reading signature body after message"))?;

    Ok(Message {
        digest,
        sig_type,
        block,
    })
}

pub fn parse_armoured_signature_body<R: BufRead>(mut from: R) -> Result<Vec<u8>, Error> {
    let _sig_headers = take_headers(&mut from)?;

    let mut signature = String::with_capacity(1024);

    loop {
        let line = String::from_utf8(from.read_short_line()?)?;
        let line = line.trim();

        // checksum
        if line.len() == 5 && line.starts_with('=') {
            // TODO: Validate checksum? It's not part of the security model in any way.

            let line = String::from_utf8(from.read_short_line()?)?;

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

    Ok(base64::decode(&signature)
        .with_context(|_| format_err!("base64 decoding signature: {:?}", signature))?)
}

fn take_headers<R: BufRead>(mut from: R) -> Result<HashMap<String, String>, Error> {
    let mut headers = HashMap::new();
    loop {
        let header = String::from_utf8(from.read_short_line()?)?;
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
