use std::collections::HashMap;
use std::io;
use std::io::BufRead;
use std::io::Write;

use failure::bail;
use failure::ensure;
use failure::Error;
use failure::ResultExt;

use crate::armour;
use crate::packets;
use digestable::Digestable;
use packets::Packet;

pub struct Doc {
    pub digest: Option<Digestable>,
    pub body_headers: HashMap<String, String>,
    pub sig_headers: HashMap<String, String>,
    pub packets: Vec<Packet>,
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

pub fn read_armoured_doc<R: BufRead, W: Write>(from: R, mut put_content: W) -> Result<Doc, Error> {
    let mut lines = from.lines();
    match lines
        .next()
        .ok_or_else(|| format_err!("unexpected EOF looking for begin marker"))??
        .trim()
    {
        armour::BEGIN_SIGNED_MESSAGE => {
            let msg = armour::parse_armoured_signed_message(lines, put_content)?;

            Ok(Doc {
                digest: Some(msg.digest),
                body_headers: msg.body_headers,
                sig_headers: msg.sig_headers,
                packets: read_binary_doc(io::Cursor::new(msg.block), iowrap::Ignore::new())?
                    .packets,
            })
        }
        armour::BEGIN_SIGNATURE => {
            let (sig_headers, block) = armour::parse_armoured_signature_body(lines)?;
            let mut doc = read_binary_doc(io::Cursor::new(block), put_content)?;
            doc.sig_headers = sig_headers;
            Ok(doc)
        }
        other => bail!("invalid header line: {:?}", other),
    }
}

pub fn read_binary_doc<R: BufRead, W: Write>(from: R, put_content: W) -> Result<Doc, Error> {
    let mut reader = iowrap::Pos::new(from);
    let mut packets = Vec::with_capacity(16);
    while let Some(packet) = packets::parse_packet(&mut reader)
        .with_context(|_| format_err!("parsing after at around {}", reader.position()))?
    {
        packets.push(packet);
    }
    Ok(Doc {
        digest: None,
        body_headers: HashMap::new(),
        sig_headers: HashMap::new(),
        packets,
    })
}
