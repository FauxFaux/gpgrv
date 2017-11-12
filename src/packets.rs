use std::io;
use std::io::Read;
use std::u32;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use byteorder::ReadBytesExt;

use HashAlg;
use PublicKeySig;
use PubKey;

use errors::*;
use usize_from;
use usize_from_u32;

enum PublicKeyAlg {
    Rsa,
    Dsa,
}

#[derive(Debug)]
pub enum SignatureType {
    CanonicalisedText,
    GenericCertificationUserId,
    CasualCertificationUserId,
    PositiveCertificationUserId,
    SubkeyBinding,
    PrimaryKeyBinding,
}

#[derive(Debug)]
pub struct Signature {
    pub issuer: Option<[u8; 8]>,
    pub authenticated_data: Vec<u8>,
    pub sig: PublicKeySig,
    pub sig_type: SignatureType,
    pub hash_alg: HashAlg,
    pub hash_hint: u16,
}

#[derive(Debug)]
pub enum Packet {
    IgnoredJunk,
    PubKey(PubKey),
    Signature(Signature),
}

pub fn parse_packet<R: Read>(mut from: R) -> Result<Option<Packet>> {
    let val = match from.read_u8() {
        Ok(val) => val,
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(other) => bail!(other),
    };

    ensure!(is_bit_set(val, 7), "invalid packet tag");
    let tag;
    let len;

    if is_bit_set(val, 6) {
        // new format
        //        tag = val & 0b0011_1111;

        bail!("not supported: new format");
    } else {
        // old format
        tag = (val & 0b0011_1100) >> 2;
        let len_code = val & 0b0000_0011;
        len = match len_code {
            0 => u32::from(from.read_u8()?),
            1 => u32::from(from.read_u16::<BigEndian>()?),
            2 => from.read_u32::<BigEndian>()?,
            3 => bail!("not supported: indeterminate length packets"),
            _ => unreachable!(),
        };
    }

    let mut from = from.take(u64::from(len));

    let parsed = match tag {
        2 => Packet::Signature(parse_signature_packet(&mut from)?),
        // 6: public key
        // 14: public subkey
        6 | 14 => Packet::PubKey(parse_pubkey_packet(&mut from)?),
        // 13: user id (textual name)
        13 => {
            from.read_exact(&mut vec![0u8; usize_from_u32(len)])?;
            Packet::IgnoredJunk
        }
        other => bail!("not supported: packet tag: {}, len: {}", other, len),
    };

    ensure!(
        0 == from.limit(),
        "parser bug: failed to read {} trailing bytes",
        from.limit()
    );

    Ok(Some(parsed))
}

fn parse_signature_packet<R: Read>(mut from: R) -> Result<Signature> {
    // this would not work for version 3 packets, which we're not processing,
    // as their authenticated data section is different

    let mut authenticated_data = Vec::with_capacity(32);
    authenticated_data.resize(6, 0);
    from.read_exact(&mut authenticated_data[0..6])?;

    {
        // https://tools.ietf.org/html/rfc4880#section-5.2.3
        match authenticated_data[0] {
            3 => bail!("not supported: version 3 signatures"),
            4 => {}
            other => bail!("not supported: unrecognised signature version: {}", other),
        }
    }

    // https://tools.ietf.org/html/rfc4880#section-5.2.1
    let sig_type = match authenticated_data[1] {
        0x01 => SignatureType::CanonicalisedText,
        0x10 => SignatureType::GenericCertificationUserId,
        0x12 => SignatureType::CasualCertificationUserId,
        0x13 => SignatureType::PositiveCertificationUserId,
        0x18 => SignatureType::SubkeyBinding,
        0x19 => SignatureType::PrimaryKeyBinding,
        other => bail!("not supported: signature type: {}", other),
    };

    // https://tools.ietf.org/html/rfc4880#section-9.1
    let key_alg = match authenticated_data[2] {
        1 | 3 => PublicKeyAlg::Rsa,
        17 => PublicKeyAlg::Dsa,
        other => bail!("not supported: key algorithm: {}", other),
    };

    // https://tools.ietf.org/html/rfc4880#section-9.4
    let hash_alg = match authenticated_data[3] {
        2 => HashAlg::Sha1,
        8 => HashAlg::Sha256,
        10 => HashAlg::Sha512,
        other => bail!("not supported: hash algorithm: {}", other),
    };

    let good_subpackets_len = BigEndian::read_u16(&authenticated_data[4..6]);
    let good_subpackets_end = authenticated_data.len() + usize_from(good_subpackets_len);
    authenticated_data.resize(good_subpackets_end, 0);
    from.read_exact(&mut authenticated_data[6..])?;

    let bad_subpackets = read_u16_prefixed_data(&mut from)?;

    let issuer = find_issuer(&bad_subpackets)?;

    let hash_hint = from.read_u16::<BigEndian>()?;

    let sig = match key_alg {
        PublicKeyAlg::Rsa => PublicKeySig::Rsa(read_mpi(&mut from)?),
        PublicKeyAlg::Dsa => {
            PublicKeySig::Dsa {
                r: read_mpi(&mut from)?,
                s: read_mpi(&mut from)?,
            }
        }
    };

    Ok(Signature {
        issuer,
        authenticated_data,
        sig,
        sig_type,
        hash_hint,
        hash_alg,
    })
}

fn parse_pubkey_packet<R: Read>(mut from: R) -> Result<PubKey> {
    // https://tools.ietf.org/html/rfc4880#section-5.5.2
    match from.read_u8()? {
        3 => bail!("not supported: version 3 key packets"),
        4 => {}
        other => bail!("not supported: unrecognised key packet version: {}", other),
    }

    from.read_u32::<BigEndian>()?; // time

    Ok(match from.read_u8()? {
        1 => PubKey::Rsa {
            n: read_mpi(&mut from)?,
            e: read_mpi(&mut from)?,
        },
        other => bail!("not supported: unrecognised key type: {}", other),
    })
}

// https://tools.ietf.org/html/rfc4880#section-5.2.4.1
fn find_issuer(subpackets: &[u8]) -> Result<Option<[u8; 8]>> {
    let mut issuer = None;

    for (id, data) in parse_subpackets(&subpackets)? {
        if is_bit_set(id, 7) {
            bail!("unsupported critical subpacket: {}", id);
        }

        match id {
            16 => {
                ensure!(
                    8 == data.len(),
                    "invalid issuer packet length: {}",
                    data.len()
                );
                let mut array_sadness = [0u8; 8];
                array_sadness.copy_from_slice(data);

                issuer = Some(array_sadness);
            }
            _ => {
                // SHOULD ignore non-critical
            }
        }
    }

    return Ok(issuer);
}

// https://tools.ietf.org/html/rfc4880#section-5.2.3.1
fn parse_subpackets(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut ret = Vec::with_capacity(data.len() / 4);

    while !data.is_empty() {
        let len = usize::from(data[0]);
        ensure!(len < 192, "not supported [laziness]: long sub packets");
        ensure!(len != 0, "illegal empty subpacket");

        // data starts after the length (currently always 1 byte) and the id (one byte)
        let data_start = 1 + 1;

        // `len` includes the id byte, but not the stored length; so take the id byte off
        let data_end = data_start + len - 1;

        ensure!(data.len() >= data_start, "illegal super-short subpacket");
        ensure!(data_end <= data.len(), "packet extends outside field");

        let id = data[1];
        ret.push((id, &data[data_start..data_end]));

        data = &data[data_end..];
    }

    Ok(ret)
}

fn read_u16_prefixed_data<R: Read>(mut from: R) -> Result<Vec<u8>> {
    let len = from.read_u16::<BigEndian>()?;
    let mut data = vec![0u8; usize_from(len)];
    from.read_exact(&mut data)?;
    Ok(data)
}

/// https://tools.ietf.org/html/rfc4880#section-3.2
fn read_mpi<R: Read>(mut from: R) -> Result<Vec<u8>> {
    let bits: u16 = from.read_u16::<BigEndian>()?;
    if 0 == bits {
        // TODO: Is this a valid encoding?
        return Ok(Vec::new());
    }

    let bytes = (u32::from(bits) + 7) / 8;
    let mut data = vec![0u8; usize_from_u32(bytes)];
    from.read_exact(&mut data)?;

    let first_byte = data[0];
    let leading_bits = bits % 8;

    let first_bit_position = if 0 == leading_bits {
        0
    } else {
        (8 - leading_bits) as u8
    };

    for i in 0..first_bit_position {
        ensure!(
            !is_bit_set(first_byte, 7 - i),
            "invalid MPI encoding: leading bits must be zero"
        );
    }

    ensure!(
        is_bit_set(first_byte, 7 - first_bit_position),
        "invalid MPI encoding: first bit must be set"
    );

    Ok(data)
}

/// Check if a 0-indexed bit, counted in the traditional way, is set.
/// | 7 6 5 4 3 2 1 0 |
#[inline]
fn is_bit_set(value: u8, bit_no: u8) -> bool {
    assert!(bit_no < 8);
    (value & (1 << bit_no)) == (1 << bit_no)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Cursor;
    #[test]
    fn mpi() {
        use super::read_mpi;
        assert_eq!(vec![0x01], read_mpi(Cursor::new(vec![0, 1, 0x01])).unwrap());
        assert_eq!(
            vec![0x01, 0xff],
            read_mpi(Cursor::new(vec![0, 9, 0x01, 0xff])).unwrap()
        );

        assert_eq!(vec![0xff], read_mpi(Cursor::new(vec![0, 8, 0xff])).unwrap());

        // invalid: bit length refers to a bit that's not set
        assert!(read_mpi(Cursor::new(vec![0, 2, 0b0000_0001])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 4, 0b0000_0111])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 8, 0b0111_1111])).is_err());

        // invalid: bits set before first bit
        assert!(read_mpi(Cursor::new(vec![0, 1, 0b0000_0011])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 1, 0b0001_0001])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 1, 0b1000_0001])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 2, 0b0000_1010])).is_err());
    }
}
