use std::collections::HashSet;
use std::io;
use std::io::BufRead;
use std::io::Write;

use failure::bail;
use failure::ensure;
use failure::err_msg;
use failure::format_err;
use failure::Error;
use failure::ResultExt;

use crate::armour;
use crate::digestable::Digestable;
use crate::packets;
use crate::packets::Event;
use crate::packets::Packet;
use crate::packets::Signature;
use crate::packets::SignatureType;

#[derive(Clone, Debug)]
pub struct Doc {
    pub body: Option<Body>,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Debug)]
pub struct Body {
    pub digest: Digestable,
    pub sig_type: SignatureType,
    pub header: Option<packets::PlainData>,
}

pub fn read_doc<R: BufRead, W: Write>(mut from: R, put_content: W) -> Result<Doc, Error> {
    let first_byte = {
        let head = from.fill_buf()?;
        ensure!(!head.is_empty(), "empty file");
        head[0]
    };

    match first_byte {
        b'-' => read_armoured_doc(from, put_content),
        _ => read_binary_doc(from, put_content),
    }
}

pub fn read_armoured_doc<R: BufRead, W: Write>(from: R, put_content: W) -> Result<Doc, Error> {
    let mut lines = from.lines();
    match lines
        .next()
        .ok_or_else(|| format_err!("unexpected EOF looking for begin marker"))??
        .trim()
    {
        armour::BEGIN_SIGNED_MESSAGE => {
            let msg = armour::parse_armoured_signed_message(lines, put_content)?;

            let signatures = read_signatures_only(io::Cursor::new(msg.block))?;

            Ok(Doc {
                body: Some(Body {
                    digest: msg.digest,
                    sig_type: SignatureType::CanonicalisedText,
                    header: None,
                }),
                signatures,
            })
        }
        armour::BEGIN_SIGNATURE => {
            let block = armour::parse_armoured_signature_body(lines)?;

            let signatures = read_signatures_only(io::Cursor::new(block))?;

            Ok(Doc {
                body: None,
                signatures,
            })
        }
        other => bail!("invalid header line: {:?}", other),
    }
}

pub fn read_binary_doc<R: BufRead, W: Write>(from: R, mut put_content: W) -> Result<Doc, Error> {
    let mut reader = iowrap::Pos::new(from);
    let mut signatures = Vec::with_capacity(16);
    let mut body = None;
    let mut body_modes = HashSet::with_capacity(4);

    packets::parse_packets(&mut reader, &mut |ev| {
        match ev {
            Event::Packet(Packet::Signature(sig)) => signatures.push(sig),
            Event::Packet(Packet::OnePassHelper(help)) => {
                body_modes.insert((help.signature_type, help.hash_type));
            }
            Event::Packet(Packet::IgnoredJunk) | Event::Packet(Packet::PubKey(_)) => (),
            Event::PlainData(header, from) => {
                if body.is_some() {
                    bail!("not supported: multiple plain data segments");
                }

                let (sig_type, hash_type) = *match body_modes.len() {
                    0 => bail!("no body mode hint provided before document"),
                    1 => body_modes.iter().next().unwrap(),
                    _ => bail!("unsupported: multiple body mode hints: {:?}", body_modes),
                };

                use super::HashAlg;
                let mut digest = match hash_type {
                    HashAlg::Sha1 => Digestable::sha1(),
                    HashAlg::Sha256 => Digestable::sha256(),
                    HashAlg::Sha512 => Digestable::sha512(),
                    other => bail!("unsupported binary hash function: {:?}", other),
                };

                use packets::SignatureType;
                match sig_type {
                    SignatureType::Binary => (),
                    other => bail!("unsupported signature type in binary doc: {:?}", other),
                };

                let mut buf = [0u8; 8 * 1024];

                loop {
                    let read = from.read(&mut buf)?;
                    if 0 == read {
                        break;
                    }
                    let buf = &buf[..read];
                    digest.process(buf);
                    put_content.write_all(buf)?;
                }

                body = Some(Body {
                    digest,
                    sig_type,
                    header: Some(header),
                });
            }
        }
        Ok(())
    })
    .with_context(|_| format_err!("parsing after at around {}", reader.position()))?;

    Ok(Doc { body, signatures })
}

pub fn read_signatures_only<R: BufRead>(from: R) -> Result<Vec<packets::Signature>, Error> {
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
