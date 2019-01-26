use std::collections::HashSet;
use std::io::Read;
use std::io::Write;

use failure::bail;
use failure::ensure;
use failure::format_err;
use failure::Error;
use failure::ResultExt;

use crate::armour;
use crate::digestable::Digestable;
use crate::manyread::ManyReader;
use crate::packets;
use crate::packets::Event;
use crate::packets::Packet;
use crate::packets::Signature;
use crate::packets::SignatureType;
use crate::HashAlg;

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

pub fn read_doc<R: Read, W: Write>(mut from: ManyReader<R>, put_content: W) -> Result<Doc, Error> {
    let first_byte = {
        let head = from.fill_at_least(1)?;
        ensure!(!head.is_empty(), "empty file");
        head[0]
    };

    match first_byte {
        b'-' => armour::read_armoured_doc(from, put_content),
        _ => read_binary_doc(from, put_content),
    }
}

fn read_binary_doc<R: Read, W: Write>(from: R, mut put_content: W) -> Result<Doc, Error> {
    let mut from = iowrap::Pos::new(from);
    let mut signatures = Vec::with_capacity(16);
    let mut body = None;
    let mut body_modes = HashSet::with_capacity(4);

    packets::parse_packets(&mut from, &mut |ev| {
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

                let mut digest = digestable_for(hash_type)
                    .ok_or_else(|| format_err!("unsupported hash type: {:?}", hash_type))?;

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
    .with_context(|_| format_err!("parsing after at around {}", from.position()))?;

    Ok(Doc { body, signatures })
}

pub fn digestable_for(hash_type: HashAlg) -> Option<Digestable> {
    Some(match hash_type {
        HashAlg::Sha1 => Digestable::sha1(),
        HashAlg::Sha256 => Digestable::sha256(),
        HashAlg::Sha512 => Digestable::sha512(),
        _ => return None,
    })
}
