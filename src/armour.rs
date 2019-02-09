use std::collections::HashMap;
use std::io;
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
use crate::load;
use crate::packets;
use crate::packets::Event;
use crate::packets::Packet;
use crate::packets::SignatureType;
use crate::short_string::ShortLine;

pub const BEGIN_SIGNED_MESSAGE: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
pub const BEGIN_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";
const END_MESSAGE: &str = "-----END PGP SIGNATURE-----";

struct Message {
    pub digest: Digestable,
    pub sig_type: SignatureType,
    pub block: Vec<u8>,
}

pub fn read_armoured_doc<R: BufRead, W: Write>(
    mut from: R,
    put_content: W,
) -> Result<load::Doc, Error> {
    match String::from_utf8(from.read_short_line()?)?.trim() {
        BEGIN_SIGNED_MESSAGE => {
            let msg = parse_armoured_signed_message(from, put_content)?;

            let signatures = read_signatures_only(io::Cursor::new(&msg.block))?;

            Ok(load::Doc {
                body: Some(load::Body {
                    digest: msg.digest,
                    sig_type: SignatureType::CanonicalisedText,
                    header: None,
                }),
                signatures,
            })
        }
        BEGIN_SIGNATURE => {
            let block = parse_armoured_signature_body(from)?;

            let signatures = read_signatures_only(io::Cursor::new(block))?;

            Ok(load::Doc {
                body: None,
                signatures,
            })
        }
        other => bail!("invalid header line: {:?}", other),
    }
}

fn parse_armoured_signed_message<R: BufRead, W: Write>(
    mut from: R,
    to: W,
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

    let last_line = String::from_utf8(canonicalise(&mut from, to, &mut digest)?)?;

    ensure!(
        last_line == BEGIN_SIGNATURE,
        "invalid last line, should be a signature start: {:?}",
        last_line
    );

    let block = parse_armoured_signature_body(from)
        .with_context(|_| err_msg("reading signature body after message"))?;

    Ok(Message {
        digest,
        sig_type,
        block,
    })
}

fn canonicalise<R: BufRead, W: Write>(
    mut from: R,
    mut to: W,
    digest: &mut Digestable,
) -> Result<Vec<u8>, Error> {
    let mut done_first = false;

    loop {
        let line = from.read_line_max(1024 * 1024)?;

        let text;
        if !line.starts_with(b"-") {
            text = &line[..];
        } else if line.starts_with(b"- ") {
            text = &line[b"- ".len()..];
        } else if line.starts_with(b"--") {
            to.write_all(b"\n")?;
            return Ok(line);
        } else {
            bail!("invalid escaping: {:?}", line);
        }

        if done_first {
            to.write_all(b"\n")?;
            digest.process(b"\r\n");
        }

        let text = trim_end(text);

        to.write_all(text)?;
        digest.process(text);

        done_first = true;
    }
}

fn parse_armoured_signature_body<R: BufRead>(mut from: R) -> Result<Vec<u8>, Error> {
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

fn read_signatures_only<R: io::Read>(from: R) -> Result<Vec<packets::Signature>, Error> {
    let mut signatures = Vec::new();

    packets::parse_packets(from, &mut |ev| match ev {
        Event::Packet(Packet::Signature(sig)) => {
            signatures.push(sig);
            Ok(())
        }
        Event::Packet(Packet::IgnoredJunk) => Ok(()),
        Event::Packet(other) => Err(format_err!(
            "unexpected packet in signature block: {:?}",
            other
        )),
        Event::PlainData(_, _) => Err(err_msg("unexpected plain data in signature doc")),
    })?;

    Ok(signatures)
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

fn trim_end(buf: &[u8]) -> &[u8] {
    for i in (0..buf.len()).rev() {
        if !is_whitespace(buf[i]) {
            return &buf[..=i];
        }
    }

    &[]
}

// gpg considers \0 whitespace during read-back, but not during writing
// I'm guessing this is a bug.
fn is_whitespace(b: u8) -> bool {
    b' ' == b || b'\r' == b || b'\t' == b || b'\0' == b
}

#[cfg(test)]
mod tests {
    use std::io;

    use byteorder::ByteOrder;
    use byteorder::BE;

    #[test]
    fn canon_one_line() {
        assert_canon(b"foo\n--\n", b"foo\n", b"foo")
    }

    #[test]
    fn canon_two_lines() {
        assert_canon(b"foo\nbar\n--\n", b"foo\nbar\n", b"foo\r\nbar")
    }

    #[test]
    fn canon_escaped() {
        assert_canon(
            b"foo\nbar\n- --baz\n--\n",
            b"foo\nbar\n--baz\n",
            b"foo\r\nbar\r\n--baz",
        )
    }

    #[test]
    fn canon_escaped_first_line() {
        assert_canon(
            b"- --foo\nbar\n- --baz\n--\n",
            b"--foo\nbar\n--baz\n",
            b"--foo\r\nbar\r\n--baz",
        )
    }

    #[test]
    fn canon_nul_inside() {
        assert_canon(b"foo\0bar\n--\n", b"foo\0bar\n", b"foo\0bar")
    }

    #[test]
    fn canon_nul_trailing() {
        assert_canon(b"foo\0\n--\n", b"foo\n", b"foo")
    }

    fn assert_canon(input: &[u8], wanted_output: &[u8], wanted_digested: &[u8]) {
        let mut actual_output = Vec::with_capacity(input.len() * 2);
        let mut digest = crate::Digestable::sha1();
        assert_eq!(
            b"--",
            super::canonicalise(io::Cursor::new(input), &mut actual_output, &mut digest)
                .unwrap()
                .as_slice()
        );
        let actual_hash = BE::read_u64(&digest.hash());

        if wanted_output != actual_output.as_slice() {
            let actual_string = String::from_utf8_lossy(&actual_output);
            let wanted_string = String::from_utf8_lossy(wanted_output);

            assert_eq!(
                wanted_string, actual_string,
                "wanted output (as string) == actual output"
            );
            assert_eq!(
                wanted_output,
                actual_output.as_slice(),
                "wanted output == actual output"
            );
        }

        assert_eq!(sha1(wanted_digested), actual_hash);
    }

    fn sha1(data: &[u8]) -> u64 {
        let mut digest = crate::Digestable::sha1();
        digest.process(data);
        BE::read_u64(&digest.hash())
    }

    #[test]
    fn check_sha1() {
        // % printf 'foo\r\nbar' | sha1sum
        //           ad489cb3657d52202c7f1709513d2cf1e0f9162a
        assert_eq!(0xad489cb3657d5220, sha1(b"foo\r\nbar"));
    }
}
